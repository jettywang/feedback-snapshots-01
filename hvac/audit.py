"""Optional audit receipts for hvac calls.

This module offers an opt-in way to produce client-side audit receipts for the
HTTP requests a :class:`hvac.v1.Client` issues to Vault. A receipt carries only
the metadata needed to reconcile a call against Vault's server-side audit log
(e.g. the job id supplied by the caller and Vault's response ``request_id``).

Security guarantee
------------------
A receipt never stores request bodies, response bodies, query parameters,
headers or tokens. In particular, secret data written to or read from Vault is
never captured. The same reduced, non-sensitive set of fields is the only thing
written to the log.

State that cannot be observed (for example the status code of a call that failed
on the transport layer) is explicitly marked with :data:`UNOBSERVED` rather than
guessed or silently omitted.

Typical usage::

    with client.audit(job_id="JOB-42") as audit:
        client.secrets.kv.v2.create_or_update_secret(
            path="approved-mount/foo",
            secret={"password": "..."},
        )

    for receipt in audit.receipts:
        # Reconcile receipt.request_id with the Vault server audit log.
        print(receipt.to_dict())

The call inside the context keeps its normal return type; the receipt is
collected alongside it instead of replacing it.
"""
import dataclasses
import logging
import time
import urllib.parse

from datetime import datetime, timezone

import requests

from hvac import exceptions

logger = logging.getLogger(__name__)

#: Marker for receipt fields whose value could not be observed for a given call.
UNOBSERVED = "UNOBSERVED"

#: The call completed with a 2xx HTTP status code.
OUTCOME_SUCCESS = "success"
#: Vault answered with HTTP 403 Forbidden.
OUTCOME_PERMISSION_DENIED = "permission_denied"
#: Vault answered with any other non-2xx HTTP status code.
OUTCOME_HTTP_ERROR = "http_error"
#: No HTTP response was received (connection error, timeout, ...).
OUTCOME_TRANSPORT_ERROR = "transport_error"


def _vault_path(url):
    """Return the path portion of a full Vault URL, without a leading slash."""
    return urllib.parse.urlsplit(url).path.lstrip("/")


def _derive_mount_point(url):
    """Derive the mount point targeted by a full Vault URL.

    Vault mount paths follow ``/v1/<mount>/...`` for secrets engines and
    ``/v1/auth/<mount>/...`` for auth methods. System backend endpoints
    (``/v1/sys/...``) are not mounts, so ``None`` is returned for them.

    :param url: Full URL the request was sent to.
    :type url: str
    :return: The targeted mount point, or None when the URL does not address a
        secrets/auth mount.
    :rtype: str | None
    """
    segments = [segment for segment in _vault_path(url).split("/") if segment]
    if len(segments) < 2 or segments[0] != "v1":
        return None

    root = segments[1]
    if root == "sys":
        return None
    if root == "auth":
        return f"auth/{segments[2]}" if len(segments) > 2 else "auth"
    return root


def _response_json(response):
    """Return the parsed JSON body of a response, or None when it is not JSON.

    The Content-Type header is not relied upon: some intermediaries and test
    doubles omit it even for JSON bodies, while real Vault may append a charset
    to it. Parsing the body directly is therefore the more reliable signal.
    """
    try:
        return response.json()
    except ValueError:
        return None


def _extract_request_id(response):
    """Extract Vault's response request_id, marking it UNOBSERVED when absent."""
    body = _response_json(response)
    if isinstance(body, dict) and body.get("request_id"):
        return body["request_id"]
    return UNOBSERVED


def _extract_error_message(response):
    """Extract the non-sensitive errors list Vault returns on failed calls."""
    body = _response_json(response)
    if isinstance(body, dict) and body.get("errors"):
        return ", ".join(str(error) for error in body["errors"])
    return None


@dataclasses.dataclass
class AuditReceipt:
    """A single, secret-free audit receipt for one Vault HTTP call.

    :param job_id: Caller-supplied correlation id, if any.
    :param method: HTTP method used for the call.
    :param url: Full URL the call was sent to.
    :param path: Vault path addressed by the call (e.g. ``v1/secret/data/foo``).
    :param mount_point: Mount point derived from the path, or None for system
        backend endpoints.
    :param status_code: HTTP status code, or :data:`UNOBSERVED` when no response
        was received.
    :param request_id: Vault response ``request_id`` used to reconcile against
        the server-side audit log, or :data:`UNOBSERVED`.
    :param outcome: One of the ``OUTCOME_*`` constants.
    :param error_type: Fully qualified exception class name associated with a
        failed call, or None for successful calls.
    :param error_message: Non-sensitive error detail, or None.
    :param started_at: UTC ISO-8601 timestamp of when the call started.
    :param elapsed_ms: Wall-clock duration of the call in milliseconds.
    """

    job_id: str = None
    method: str = None
    url: str = None
    path: str = None
    mount_point: str = None
    status_code: object = UNOBSERVED
    request_id: object = UNOBSERVED
    outcome: str = None
    error_type: str = None
    error_message: str = None
    started_at: str = None
    elapsed_ms: float = None

    def to_dict(self):
        """Serialize the receipt to a plain dict for reconciliation output.

        :return: JSON-serializable representation of the receipt.
        :rtype: dict
        """
        return dataclasses.asdict(self)

    def as_log_dict(self):
        """Return the reduced, secret-free dict safe to write to logs.

        The full URL and error message are deliberately excluded: only metadata
        required for reconciliation is logged. Request/response bodies, headers,
        tokens and query parameters are never part of a receipt in the first
        place.

        :return: Non-sensitive representation of the receipt.
        :rtype: dict
        """
        return {
            "job_id": self.job_id,
            "method": self.method,
            "path": self.path,
            "mount_point": self.mount_point,
            "status_code": self.status_code,
            "request_id": self.request_id,
            "outcome": self.outcome,
            "error_type": self.error_type,
            "started_at": self.started_at,
            "elapsed_ms": self.elapsed_ms,
        }


class AuditRecorder:
    """Context manager collecting :class:`AuditReceipt` instances for a client.

    Instances are normally created through :meth:`hvac.v1.Client.audit`. While
    the context is active, the adapter's underlying session is instrumented so
    every issued call yields a receipt, including calls that raise. On exit the
    session is always restored to its original state.
    """

    def __init__(self, adapter, job_id=None, log=logger):
        """Create a recorder bound to an adapter's requests session.

        :param adapter: Adapter whose session should be instrumented.
        :type adapter: hvac.adapters.Adapter
        :param job_id: Optional caller-supplied job/correlation id attached to
            every receipt collected by this recorder.
        :type job_id: str | None
        :param log: Logger to emit secret-free receipt entries with.
        :type log: logging.Logger
        """
        self._adapter = adapter
        self.job_id = job_id
        self._logger = log
        self._receipts = []
        self._last_receipt = None
        self._original_request = None

    def __enter__(self):
        session = self._adapter.session
        self._original_request = session.request
        session.request = self._instrumented_request
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._adapter.session.request = self._original_request
        self._original_request = None
        return False

    @property
    def receipts(self):
        """Receipts collected so far, in call order.

        :return: List of collected receipts.
        :rtype: list[hvac.audit.AuditReceipt]
        """
        return self._receipts

    @property
    def last_receipt(self):
        """Most recently collected receipt, or None before the first call.

        :rtype: hvac.audit.AuditReceipt | None
        """
        return self._last_receipt

    def _instrumented_request(
        self, method, url, headers=None, allow_redirects=None, **kwargs
    ):
        started_at = time.monotonic()
        base_fields = {
            "job_id": self.job_id,
            "method": method.upper(),
            "url": url,
            "path": _vault_path(url),
            "mount_point": _derive_mount_point(url),
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            response = self._original_request(
                method=method,
                url=url,
                headers=headers,
                allow_redirects=allow_redirects,
                **kwargs,
            )
        except requests.RequestException as exc:
            receipt = self._build_receipt(
                **base_fields,
                status_code=UNOBSERVED,
                request_id=UNOBSERVED,
                outcome=OUTCOME_TRANSPORT_ERROR,
                error_type=f"{type(exc).__module__}.{type(exc).__qualname__}",
                error_message=str(exc),
                started_monotonic=started_at,
            )
            self._record(receipt)
            raise

        status_code = response.status_code
        if 200 <= status_code < 300:
            outcome = OUTCOME_SUCCESS
            error_type = None
            error_message = None
        else:
            error_type = self._exception_type_for_status(status_code)
            error_message = _extract_error_message(response)
            if status_code == 403:
                outcome = OUTCOME_PERMISSION_DENIED
            else:
                outcome = OUTCOME_HTTP_ERROR

        receipt = self._build_receipt(
            **base_fields,
            status_code=status_code,
            request_id=_extract_request_id(response),
            outcome=outcome,
            error_type=error_type,
            error_message=error_message,
            started_monotonic=started_at,
        )
        self._record(receipt)
        return response

    def _build_receipt(self, started_monotonic, **fields):
        fields["elapsed_ms"] = round(
            (time.monotonic() - started_monotonic) * 1000, 3
        )
        return AuditReceipt(**fields)

    def _record(self, receipt):
        self._receipts.append(receipt)
        self._last_receipt = receipt
        # Only the redacted field set is ever logged.
        self._logger.info("hvac audit receipt: %s", receipt.as_log_dict())

    @staticmethod
    def _exception_type_for_status(status_code):
        mapped_class = type(exceptions.VaultError.from_status(status_code))
        return f"{mapped_class.__module__}.{mapped_class.__qualname__}"
