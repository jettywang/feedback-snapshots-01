"""Shareable receipts for Pushgateway push/pushadd/delete operations.

A receipt tracks one operation through three distinct phases so a debugging
record attached to a ticket can distinguish them:

* ``constructed`` - the request URL, headers and body were built and the
  handler factory was invoked to produce a sender.
* ``attempted``   - the returned sender was actually invoked.
* a terminal phase - ``accepted``, ``failed`` or ``unknown``.

The :class:`PushReceipt` deliberately keeps anything sensitive local to the
machine that produced it.  Call :meth:`PushReceipt.shareable` (or
:meth:`ReceiptBook.shareable`) to obtain a redacted view that is safe to paste
into a ticket.  Credentials, the raw grouping-key values, the full request URL
and exception text never appear in the shared view; only non-reversible
fingerprints and label *names* are shared.
"""

from contextvars import ContextVar
from dataclasses import dataclass, field
import hashlib
import json
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse
from uuid import uuid4

# Lifecycle phases, in the order an operation moves through them.
PHASE_CONSTRUCTED = 'constructed'
PHASE_ATTEMPTED = 'attempted'
PHASE_ACCEPTED = 'accepted'
PHASE_FAILED = 'failed'
PHASE_UNKNOWN = 'unknown'

TERMINAL_PHASES = frozenset((PHASE_ACCEPTED, PHASE_FAILED, PHASE_UNKNOWN))

# Outcomes describe how the terminal phase was reached.
OUTCOME_ACCEPTED = 'accepted'
OUTCOME_HANDLER_ERROR = 'handler_error'
OUTCOME_HTTP_ERROR = 'http_error'
OUTCOME_UNPROVEN = 'unproven'

# Header names that may carry credentials.  Only the *name* is ever retained.
_AUTH_HEADER_MARKERS = ('authorization', 'proxy-authorization')

# The receipt for the operation currently driving a handler on this context.
current_receipt_id: ContextVar[Optional[str]] = ContextVar(
    'prometheus_pushgateway_receipt_id', default=None,
)


def _fingerprint(value: str) -> str:
    """Return a non-reversible SHA-256 fingerprint of ``value``."""
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def fingerprint_grouping_key(grouping_key: Optional[Dict[str, Any]]) -> str:
    """Fingerprint a grouping key without exposing its values.

    The whole mapping (keys *and* values, serialized deterministically) is
    hashed so two operations on the same group share a fingerprint while the
    label values themselves cannot be recovered.
    """
    material = json.dumps(
        grouping_key or {}, sort_keys=True, separators=(',', ':'),
        default=str, ensure_ascii=False,
    )
    return _fingerprint(material)


def fingerprint_url(url: str) -> str:
    """Fingerprint the full request URL, including its grouping-key path."""
    return _fingerprint(url)


def gateway_designator(gateway: str) -> str:
    """Return a credential-free designator for the gateway host.

    Only the scheme, host and port are retained.  Userinfo and any path are
    dropped so credentials embedded in the URL never leak into a receipt.
    """
    parsed = urlparse(gateway)
    scheme = parsed.scheme or 'http'
    host = parsed.hostname or ''
    port = f':{parsed.port}' if parsed.port else ''
    return f'{scheme}://{host}{port}'


def _is_auth_header(name: str) -> bool:
    return name.lower() in _AUTH_HEADER_MARKERS


def extract_status_code(result: Any) -> Optional[int]:
    """Best-effort extraction of an HTTP status code from a sender result.

    Returns ``None`` when no status code can be proven, which the caller
    treats as an unknown outcome rather than guessing.
    """
    if isinstance(result, bool):
        # bool is a subclass of int but is never an HTTP status code.
        return None
    if isinstance(result, int):
        return result
    for attr in ('status_code', 'code', 'status'):
        value = getattr(result, attr, None)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    if isinstance(result, dict):
        value = result.get('status_code', result.get('status'))
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def extract_redirect_count(result: Any) -> Optional[int]:
    """Return a redirect count advertised by a custom result, if any."""
    value = getattr(result, 'redirect_count', None)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    if isinstance(result, dict):
        value = result.get('redirect_count')
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    return None


def extract_final_url(result: Any) -> Optional[str]:
    """Return the final URL a transfer landed on, when available.

    urllib response objects expose ``geturl()``; custom results may expose a
    ``final_url`` attribute or dict key.  The value is kept local only.
    """
    getter = getattr(result, 'geturl', None)
    if callable(getter):
        try:
            value = getter()
        except Exception:
            value = None
        if isinstance(value, str):
            return value
    value = getattr(result, 'final_url', None)
    if isinstance(value, str):
        return value
    if isinstance(result, dict) and isinstance(result.get('final_url'), str):
        return result['final_url']
    return None


@dataclass
class TransferResult:
    """Optional return value for custom senders.

    A custom handler's zero-argument sender may return ``None`` (the outcome
    stays unknown), a bare status code, an object exposing ``status_code``
    (such as an :class:`http.client.HTTPResponse`), or this dataclass.
    """

    status_code: Optional[int] = None
    final_url: Optional[str] = None
    redirect_count: Optional[int] = None
    detail: Optional[str] = None


class PushReceipt:
    """A shareable, append-only record of one Pushgateway operation.

    The receipt moves forward through :data:`PHASE_CONSTRUCTED`,
    :data:`PHASE_ATTEMPTED` and finally a terminal phase.  Once terminal it is
    frozen: a late-arriving failure can never overwrite an already-accepted
    result.
    """

    def __init__(
            self,
            operation: str,
            method: str,
            gateway: str,
            url: str,
            grouping_key: Optional[Dict[str, Any]] = None,
            timeout: Optional[float] = None,
            headers: Optional[List[tuple]] = None,
            payload: Optional[bytes] = None,
    ) -> None:
        self.receipt_id: str = uuid4().hex
        self.operation: str = operation
        self.method: str = method
        self.phase: str = PHASE_CONSTRUCTED
        self.outcome: Optional[str] = None

        # Public, safe-to-share facts.
        self.gateway: str = gateway_designator(gateway)
        self.url_fingerprint: str = fingerprint_url(url)
        self.grouping_fingerprint: str = fingerprint_grouping_key(grouping_key)
        self.grouping_label_names: List[str] = sorted(
            str(key) for key in (grouping_key or {})
        )
        self.timeout: Optional[float] = timeout
        self.auth_configured: bool = any(
            _is_auth_header(name) for name, _ in (headers or [])
        )
        self.payload_bytes: Optional[int] = (
            len(payload) if payload is not None else None
        )
        self.status_code: Optional[int] = None
        self.redirect_count: Optional[int] = None
        self.supports_status: bool = False

        # Local-only facts.  These never appear in ``shareable()``.
        self._url: str = url
        self._grouping_key: Dict[str, Any] = dict(grouping_key or {})
        self._auth_header_names: List[str] = sorted({
            str(name) for name, _ in (headers or []) if _is_auth_header(name)
        })
        self._error_type: Optional[str] = None
        self._error_message: Optional[str] = None
        self._final_url: Optional[str] = None

        self.constructed_at: Optional[float] = None
        self.attempted_at: Optional[float] = None
        self.completed_at: Optional[float] = None
        self._frozen: bool = False

    # -- phase transitions -------------------------------------------------

    def mark_constructed(self, timestamp: float) -> None:
        if self._frozen:
            return
        self.phase = PHASE_CONSTRUCTED
        self.constructed_at = timestamp

    def bind_request(
            self, headers: List[tuple], payload: bytes,
    ) -> None:
        """Fill in the headers/body once request construction succeeds."""
        if self._frozen:
            return
        self.payload_bytes = len(payload) if payload is not None else None
        self.auth_configured = any(
            _is_auth_header(name) for name, _ in headers
        )
        self._auth_header_names = sorted({
            str(name) for name, _ in headers if _is_auth_header(name)
        })

    def record_construction_error(
            self, error: BaseException, timestamp: float,
    ) -> None:
        """Record a failure while building the request; never attempted."""
        if self._frozen:
            return
        self.completed_at = timestamp
        self._error_type = type(error).__name__
        self._error_message = str(error)
        # attempted_at deliberately stays None: transport was never tried.
        self._freeze(PHASE_FAILED, OUTCOME_HANDLER_ERROR)

    def mark_attempted(self, timestamp: float, headers: Optional[List[tuple]] = None) -> None:
        if self._frozen:
            return
        if headers is not None:
            # Handlers (e.g. basic_auth_handler) may add headers at send time.
            self.auth_configured = any(
                _is_auth_header(name) for name, _ in headers
            )
            self._auth_header_names = sorted({
                str(name) for name, _ in headers if _is_auth_header(name)
            })
        self.phase = PHASE_ATTEMPTED
        self.attempted_at = timestamp

    def record_result(self, result: Any, timestamp: float) -> None:
        """Record whatever the sender returned and pick a terminal phase."""
        if self._frozen:
            return
        status_code = extract_status_code(result)
        redirect_count = extract_redirect_count(result)
        final_url = extract_final_url(result)

        self.attempted_at = self.attempted_at or timestamp
        self.completed_at = timestamp
        self.supports_status = status_code is not None
        self.redirect_count = redirect_count
        self._final_url = final_url

        if status_code is None:
            # The sender gave us nothing that proves the receiver's state.
            self._freeze(PHASE_UNKNOWN, OUTCOME_UNPROVEN)
            return

        self.status_code = status_code
        if 200 <= status_code < 300:
            self._freeze(PHASE_ACCEPTED, OUTCOME_ACCEPTED)
        else:
            self._freeze(PHASE_FAILED, OUTCOME_HTTP_ERROR)

    def record_error(self, error: BaseException, timestamp: float) -> None:
        """Record a handler exception. The raw text stays local."""
        if self._frozen:
            return
        self.attempted_at = self.attempted_at or timestamp
        self.completed_at = timestamp
        self._error_type = type(error).__name__
        self._error_message = str(error)
        self._freeze(PHASE_FAILED, OUTCOME_HANDLER_ERROR)

    def _freeze(self, phase: str, outcome: str) -> None:
        self.phase = phase
        self.outcome = outcome
        self._frozen = True

    @property
    def frozen(self) -> bool:
        return self._frozen

    # -- redaction ---------------------------------------------------------

    def shareable(self) -> Dict[str, Any]:
        """Return a redacted dict safe to attach to a ticket."""
        return {
            'receipt_id': self.receipt_id,
            'operation': self.operation,
            'method': self.method,
            'phase': self.phase,
            'outcome': self.outcome,
            'gateway': self.gateway,
            'url_fingerprint': self.url_fingerprint,
            'grouping_fingerprint': self.grouping_fingerprint,
            'grouping_label_names': list(self.grouping_label_names),
            'timeout': self.timeout,
            'auth_configured': self.auth_configured,
            'payload_bytes': self.payload_bytes,
            'status_code': self.status_code,
            'supports_status': self.supports_status,
            'redirect_count': self.redirect_count,
            'error_type': self._error_type,
            'constructed_at': self.constructed_at,
            'attempted_at': self.attempted_at,
            'completed_at': self.completed_at,
        }

    def local(self) -> Dict[str, Any]:
        """Return the full record, including machine-local sensitive fields."""
        data = self.shareable()
        data.update({
            'url': self._url,
            'grouping_key': dict(self._grouping_key),
            'auth_header_names': list(self._auth_header_names),
            'error_message': self._error_message,
            'final_url': self._final_url,
        })
        return data

    def to_json(self) -> str:
        """Serialize the shareable, redacted view as JSON."""
        return json.dumps(self.shareable(), sort_keys=True, ensure_ascii=False)


class ReceiptBook:
    """Holds the receipts produced by a series of pushgateway operations.

    Receipts are keyed by their unique ``receipt_id`` rather than by grouping
    key, so interleaved operations on the same group never overwrite each
    other.
    """

    def __init__(self) -> None:
        self._receipts: Dict[str, PushReceipt] = {}

    def issue(self, receipt: PushReceipt) -> PushReceipt:
        self._receipts[receipt.receipt_id] = receipt
        return receipt

    def get(self, receipt_id: str) -> Optional[PushReceipt]:
        return self._receipts.get(receipt_id)

    def all(self) -> List[PushReceipt]:
        return list(self._receipts.values())

    def __len__(self) -> int:
        return len(self._receipts)

    def __contains__(self, receipt_id: object) -> bool:
        return receipt_id in self._receipts

    def for_group(self, grouping_fingerprint: str) -> List[PushReceipt]:
        return [
            receipt for receipt in self._receipts.values()
            if receipt.grouping_fingerprint == grouping_fingerprint
        ]

    def shareable(self) -> List[Dict[str, Any]]:
        return [receipt.shareable() for receipt in self._receipts.values()]

    def to_json(self) -> str:
        return json.dumps(
            self.shareable(), sort_keys=True, ensure_ascii=False,
        )
