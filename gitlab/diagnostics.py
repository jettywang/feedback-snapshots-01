"""Per-client diagnostics for python-gitlab.

The module provides the machinery behind :meth:`gitlab.Gitlab.enable_debug`.
Configuration is kept on the client instance:

* ``internal`` mode emits complete diagnostic records, including request and
  response headers and error messages, for the client that owns the sink.
* ``shared`` mode emits only the fields in :data:`APPROVED_SHARED_FIELDS` (plus
  any explicitly approved extras).  Values are redacted before they reach the
  shared sink.

Both modes are routed through a :class:`contextvars.ContextVar`, so records
produced by the ``urllib3`` connection layer can be attributed to the logical
request that caused them, even when multiple clients interleave in the same
process.  No process-wide logger level or propagation setting is modified.
"""

from __future__ import annotations

import contextvars
import dataclasses
import enum
import json
import logging
import re
import threading
import time
import urllib.parse
import uuid
from collections.abc import Iterable, Mapping
from typing import Any, Callable

#: Replacement written in place of sensitive values.
MASK = "[MASKED]"

#: Standard header names whose values are always masked.
SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "cookie",
        "job-token",
        "private-token",
        "proxy-authorization",
        "set-cookie",
        "x-gitlab-token",
    }
)

#: Fields that a shared sink may receive.  The set is deliberately small: it
#: contains request correlation, HTTP status, and transport clues only.  Bodies,
#: arbitrary headers, credentials, and free-form business objects are excluded.
APPROVED_SHARED_FIELDS: frozenset[str] = frozenset(
    {
        "client_id",
        "request_id",
        "upstream_request_id",
        "event",
        "timestamp",
        "method",
        "path",
        "attempt",
        "max_attempts",
        "streamed",
        "status_code",
        "reason",
        "duration_ms",
        "content_length",
        "outcome",
        "retry_reason",
        "wait_seconds",
        "error_type",
        "hop",
        "redirect_count",
        "redirected_from",
        "redirected_to",
        "bytes_received",
        "chunks_received",
        "complete",
        "logger",
        "level",
        "transport_message",
    }
)

#: Secrets shorter than this are not masked by plain substring replacement.
_MIN_SUBSTRING_SECRET_LENGTH = 4

_SENSITIVE_NAMES: frozenset[str] = frozenset(
    {
        "auth",
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "passwd",
        "password",
        "secret",
        "signature",
        "token",
    }
)

# Suffixes cover GitLab-prefixed variants such as ``private_token``,
# ``job_token``, and ``x_gitlab_token`` without matching unrelated words.
_SENSITIVE_SUFFIXES: tuple[str, ...] = (
    "_auth",
    "_credential",
    "_key",
    "_passwd",
    "_password",
    "_secret",
    "_signature",
    "_token",
)

_HEADER_VALUE_RE = re.compile(
    r"(?i)\b(authorization|private-token|job-token|cookie|set-cookie|"
    r"proxy-authorization|x-gitlab-token)\b(?P<sep>\s*[:=]\s*)"
    r"(?P<value>[^\r\n]*)"
)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_QUERY_PAIR_RE = re.compile(
    r"(?i)(?P<key>[A-Za-z0-9_.-]+)=(?P<value>[^\s&\"'<>]+)"
)
_BEARER_RE = re.compile(
    r"(?i)(?P<scheme>\bbearer\b)\s+(?P<value>[A-Za-z0-9._~+/=-]+)"
)
_USERINFO_RE = re.compile(
    r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)(?P<userinfo>[^/?#@]*@)"
)


class DiagnosticsMode(str, enum.Enum):
    """How a client's diagnostic records are exposed."""

    INTERNAL = "internal"
    SHARED = "shared"


Sink = Callable[[dict[str, Any]], None]


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    if lowered in SENSITIVE_HEADERS or lowered in _SENSITIVE_NAMES:
        return True
    return lowered.endswith(_SENSITIVE_SUFFIXES)


def _mask_secrets(value: str, secrets: Iterable[str]) -> str:
    for secret in secrets:
        # Very short values (for example a one-character test token) would
        # otherwise replace ordinary letters and destroy the record structure,
        # including event names.  They are still masked where they appear as a
        # credential-structured value (headers and query parameters below).
        if secret and len(secret) >= _MIN_SUBSTRING_SECRET_LENGTH:
            value = value.replace(secret, MASK)
    value = _HEADER_VALUE_RE.sub(
        lambda match: f"{match.group(1)}{match.group('sep')}{MASK}", value
    )
    value = _BEARER_RE.sub(
        lambda match: f"{match.group('scheme')} {MASK}", value
    )
    value = _QUERY_PAIR_RE.sub(
        lambda match: (
            f"{match.group('key')}={MASK}"
            if _is_sensitive_key(match.group("key"))
            else match.group(0)
        ),
        value,
    )
    return value


def sanitize_url(value: str, secrets: Iterable[str] = ()) -> str:
    """Return a URL safe for logging in a shared sink.

    User information is dropped, fragments are removed, and values of
    credential-like query parameters are masked.  Unrelated query parameters
    are kept so pagination and filtering clues remain available.
    """

    # Strip user information before parsing: masked values contain brackets,
    # which ``urlsplit`` would otherwise interpret as an invalid IPv6 host.
    value = _USERINFO_RE.sub(lambda match: match.group("scheme"), value)
    value = value.split("#", 1)[0]

    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return _mask_secrets(value, secrets)

    netloc = parsed.netloc

    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    encoded_pairs: list[str] = []
    for key, query_value in query_pairs:
        safe_key = urllib.parse.quote(key, safe="[]")
        if _is_sensitive_key(key):
            encoded_pairs.append(f"{safe_key}={urllib.parse.quote(MASK, safe='[]')}")
        else:
            encoded_pairs.append(
                f"{safe_key}="
                f"{urllib.parse.quote(_mask_secrets(query_value, secrets), safe='[]')}"
            )

    path = _mask_secrets(parsed.path, secrets)
    return urllib.parse.urlunsplit(
        (parsed.scheme, netloc, path, "&".join(encoded_pairs), "")
    )


def redact_text(value: str, secrets: Iterable[str] = ()) -> str:
    """Mask known secrets, header values, bearer tokens, and URL query values."""

    secrets = tuple(secrets)
    parts: list[str] = []
    position = 0
    for match in _URL_RE.finditer(value):
        parts.append(_mask_secrets(value[position : match.start()], secrets))
        parts.append(sanitize_url(match.group(0), secrets))
        position = match.end()
    parts.append(_mask_secrets(value[position:], secrets))
    return "".join(parts)


def redact_value(value: Any, secrets: Iterable[str] = ()) -> Any:
    """Recursively copy ``value`` with sensitive data replaced by :data:`MASK`."""

    secrets = tuple(secrets)
    if isinstance(value, str):
        return redact_text(value, secrets)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            key_str = str(key)
            if _is_sensitive_key(key_str):
                result[key_str] = MASK
            else:
                result[key_str] = redact_value(item, secrets)
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact_value(item, secrets) for item in value]
    if isinstance(value, (bytes, bytearray)):
        text = bytes(value).decode("utf-8", errors="replace")
        try:
            decoded = json.loads(text)
        except (TypeError, ValueError):
            return redact_text(text, secrets)
        if isinstance(decoded, (dict, list)):
            return _normalize_for_delivery(redact_value(decoded, secrets))
        return _normalize_for_delivery(decoded)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(str(value), secrets)[:2000]


def _normalize_for_delivery(value: Any) -> Any:
    """Return a payload copy that external sinks can serialize as JSON."""

    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", errors="replace")
    if isinstance(value, Mapping):
        return {str(key): _normalize_for_delivery(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_normalize_for_delivery(item) for item in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def _contains_secret(value: Any, secrets: Iterable[str]) -> bool:
    if isinstance(value, str):
        return any(secret and secret in value for secret in secrets)
    if isinstance(value, Mapping):
        return any(
            _contains_secret(key, secrets) or _contains_secret(item, secrets)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_contains_secret(item, secrets) for item in value)
    if isinstance(value, (bytes, bytearray)):
        text = bytes(value).decode("utf-8", errors="replace")
        return any(secret and secret in text for secret in secrets)
    return False


def _event_for_shared_sink(
    event: Mapping[str, Any],
    approved_fields: frozenset[str],
    secrets: Iterable[str],
) -> dict[str, Any]:
    secrets = tuple(secrets)
    payload: dict[str, Any] = {}
    for field in approved_fields:
        if field not in event:
            continue
        value = event[field]
        if _is_sensitive_key(field):
            continue
        redacted = redact_value(value, secrets)
        # ``redact_value`` masks credentials inside strings and containers.  If
        # any credential-shaped residue survives, drop the whole value rather
        # than risk a partial match.
        payload[field] = MASK if _contains_secret(redacted, secrets) else redacted
    return payload


def response_correlation_id(headers: Mapping[str, Any]) -> str | None:
    """Return GitLab's request correlation identifier for a response."""

    request_id = headers.get("X-Request-Id")
    if request_id:
        return str(request_id)

    meta = headers.get("X-Gitlab-Meta")
    if not meta:
        return None
    try:
        parsed = json.loads(str(meta))
    except (TypeError, ValueError):
        return None
    if isinstance(parsed, Mapping):
        correlation = parsed.get("correlation_id")
        if correlation:
            return str(correlation)
    return None


def normalize_path(path_or_url: str) -> str:
    """Return the path portion of a relative path or absolute URL."""

    if path_or_url.startswith(("http://", "https://")):
        try:
            return urllib.parse.urlsplit(path_or_url).path or "/"
        except ValueError:
            return path_or_url
    return path_or_url.split("?", 1)[0].split("#", 1)[0]


def new_client_id() -> str:
    return f"gl-{uuid.uuid4().hex[:12]}"


def new_request_id() -> str:
    return f"req-{uuid.uuid4().hex}"


@dataclasses.dataclass
class RequestContext:
    """State attached to a single logical request."""

    session_id: str
    request_id: str
    method: str
    path: str
    url: str
    streamed: bool
    max_attempts: int
    attempt: int = 1
    started: float = dataclasses.field(default_factory=time.monotonic)
    attempt_started: float = dataclasses.field(default_factory=time.monotonic)
    upstream_request_id: str | None = None
    redirect_count: int = 0

    def note_attempt(self) -> None:
        self.attempt_started = time.monotonic()

    def elapsed_ms(self) -> int:
        return max(0, round((time.monotonic() - self.attempt_started) * 1000))

    def redirect(self, source: str, target: str) -> None:
        self.redirect_count += 1
        self.url = target


_current_request: contextvars.ContextVar[RequestContext | None] = (
    contextvars.ContextVar("python_gitlab_request_context", default=None)
)

Token = contextvars.Token[RequestContext | None]


def current_request_context() -> RequestContext | None:
    return _current_request.get()


_sessions: dict[str, DebugSession] = {}
_sessions_lock = threading.Lock()


def _register_session(session: DebugSession) -> None:
    with _sessions_lock:
        _sessions[session.session_id] = session


def _unregister_session(session: DebugSession) -> None:
    with _sessions_lock:
        _sessions.pop(session.session_id, None)


def session_for_context(context: RequestContext | None) -> DebugSession | None:
    if context is None:
        return None
    with _sessions_lock:
        return _sessions.get(context.session_id)


_STREAM_ATTR = "_python_gitlab_diagnostics"


def _bound_emit(binding: tuple[str, RequestContext], event: str, **fields: Any) -> None:
    with _sessions_lock:
        session = _sessions.get(binding[0])
    if session is not None:
        token = _current_request.set(binding[1])
        try:
            session.emit(event, context=binding[1], **fields)
        finally:
            _current_request.reset(token)


def instrument_response(
    response: Any, session: DebugSession, context: RequestContext, *, streamed: bool
) -> None:
    """Report response completion against the request that produced it.

    Non-streamed responses are fully buffered by the backend, so a completion
    record is emitted immediately.  Streamed responses emit completion when
    their iterator is exhausted, keeping the terminal record tied to the same
    ``request_id``.
    """

    if not streamed:
        session.emit(
            "response_complete",
            context=context,
            status_code=getattr(response, "status_code", None),
            complete=True,
        )
        return
    _instrument_streaming_response(response, session, context)


def _instrument_streaming_response(
    response: Any, session: DebugSession, context: RequestContext
) -> None:
    """Attach request correlation and completion reporting to ``response``.

    ``requests.Response.iter_content()`` is wrapped so that every chunked or
    streamed read reports its start, progress, and completion against the same
    request context.  The response object itself is left untouched otherwise.
    """

    binding = (session.session_id, context)
    setattr(response, _STREAM_ATTR, binding)
    if getattr(response, "_python_gitlab_stream_wrapped", False):
        return
    setattr(response, "_python_gitlab_stream_wrapped", True)

    original_iter_content = response.iter_content

    def iter_content(*args: Any, **kwargs: Any) -> Any:
        return _tracked_iterator(original_iter_content(*args, **kwargs), binding)

    response.iter_content = iter_content


def _tracked_iterator(iterator: Any, binding: tuple[str, RequestContext]) -> Any:
    started = False
    completed = False
    chunks = 0
    received = 0
    try:
        started = True
        _bound_emit(binding, "stream_start")
        while True:
            token = _current_request.set(binding[1])
            try:
                try:
                    chunk = next(iterator)
                except StopIteration:
                    break
            finally:
                _current_request.reset(token)
            if not chunk:
                continue
            chunks += 1
            received += len(chunk)
            yield chunk
        completed = True
    except BaseException as exc:
        _bound_emit(
            binding,
            "stream_error",
            error_type=type(exc).__name__,
            error_message=str(exc),
            complete=False,
            chunks_received=chunks,
            bytes_received=received,
        )
        raise
    finally:
        if started:
            _bound_emit(
                binding,
                "stream_end",
                complete=completed,
                chunks_received=chunks,
                bytes_received=received,
            )


# urllib3 is the connection layer used by requests.  Its diagnostic records are
# routed to per-client handlers through the context variable above; records
# outside one of our requests are intentionally ignored.
#
# urllib3 normally drops DEBUG records before they reach handlers when its
# logger level is higher.  Rather than changing levels (which would alter the
# output of unrelated clients in the same process), a per-call ``isEnabledFor``
# shim enables DEBUG only while one of our requests is active.
_BRIDGED_LOGGERS: tuple[str, ...] = (
    "urllib3",
    "urllib3.connection",
    "urllib3.connectionpool",
    "urllib3.poolmanager",
    "urllib3.response",
    "urllib3.util.retry",
)

_bridge_lock = threading.Lock()
_bridge_count = 0
_bridge_originals: dict[str, Any] = {}


class _DispatchHandler(logging.Handler):
    """Route urllib3 records to the session owning the active request."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)

    def emit(self, record: logging.LogRecord) -> None:
        if not (record.name == "urllib3" or record.name.startswith("urllib3.")):
            return
        context = current_request_context()
        session = session_for_context(context)
        if session is None or context is None:
            return
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - logging safety net
            message = str(record.msg)
        session.emit_transport(
            level=record.levelname,
            logger_name=record.name,
            message=message,
            context=context,
        )

    def handleError(self, record: logging.LogRecord) -> None:
        # A broken diagnostics sink must never break user requests.
        pass


_dispatch_handler = _DispatchHandler()


def _make_is_enabled(logger: logging.Logger, original: Any) -> Any:
    def is_enabled_for(level: int) -> bool:
        if (
            level >= logging.DEBUG
            and not logger.disabled
            and logging.root.manager.disable < level
        ):
            context = current_request_context()
            if context is not None and session_for_context(context) is not None:
                return True
        return bool(original(level))

    return is_enabled_for


def _install_transport_handler() -> None:
    """Enable urllib3 diagnostics without changing its configured levels."""

    with _bridge_lock:
        global _bridge_count
        if _bridge_count == 0:
            for name in _BRIDGED_LOGGERS:
                logger = logging.getLogger(name)
                preexisting = logger.__dict__.get("isEnabledFor")
                _bridge_originals[name] = (
                    preexisting,
                    logger.isEnabledFor,
                )
                logger.isEnabledFor = _make_is_enabled(  # type: ignore[method-assign]
                    logger, logger.isEnabledFor
                )
            # One handler on the urllib3 root covers every child logger.
            logging.getLogger("urllib3").addHandler(_dispatch_handler)
        _bridge_count += 1


def _uninstall_transport_handler() -> None:
    with _bridge_lock:
        global _bridge_count
        _bridge_count = max(0, _bridge_count - 1)
        if _bridge_count:
            return
        logging.getLogger("urllib3").removeHandler(_dispatch_handler)
        for name in _BRIDGED_LOGGERS:
            logger = logging.getLogger(name)
            state = _bridge_originals.pop(name, None)
            if state is None:  # pragma: no cover - defensive
                continue
            preexisting, original = state
            if preexisting is None:
                logger.__dict__.pop("isEnabledFor", None)
            else:
                logger.isEnabledFor = preexisting  # type: ignore[method-assign]


class DebugSession:
    """Diagnostics configuration bound to one :class:`gitlab.Gitlab` instance."""

    def __init__(
        self,
        *,
        client_id: str,
        mode: DiagnosticsMode | str = DiagnosticsMode.INTERNAL,
        sink: Sink | None = None,
        approved_fields: Iterable[str] | None = None,
        mask_credentials: bool = True,
        capture_transport: bool = True,
    ) -> None:
        self.client_id = client_id
        self.session_id = f"{client_id}-{uuid.uuid4().hex[:8]}"
        self.mode = DiagnosticsMode(mode)
        self.sink = sink
        self.approved_fields = frozenset(APPROVED_SHARED_FIELDS)
        if approved_fields is not None:
            self.approved_fields |= frozenset(approved_fields)
        self.mask_credentials = mask_credentials
        self.capture_transport = capture_transport
        self._secrets: tuple[str, ...] = ()
        self._closed = False
        self._local = threading.local()

        self._logger = logging.getLogger(f"gitlab.debug.{self.session_id}")
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False
        self._log_handler = logging.StreamHandler()
        self._log_handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(self._log_handler)

        self._captures_transport = False
        _register_session(self)
        if self.capture_transport:
            _install_transport_handler()
            self._captures_transport = True

    # -- lifecycle ---------------------------------------------------------

    def update_credentials(self, *values: str | None) -> None:
        self._secrets = tuple(dict.fromkeys(v for v in values if v))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._captures_transport:
            _uninstall_transport_handler()
            self._captures_transport = False
        _unregister_session(self)
        self._logger.removeHandler(self._log_handler)
        self._log_handler.close()

    @property
    def closed(self) -> bool:
        return self._closed

    # -- request routing ---------------------------------------------------

    def new_request(
        self,
        *,
        method: str,
        path: str,
        url: str,
        streamed: bool,
        max_attempts: int,
    ) -> RequestContext:
        return RequestContext(
            session_id=self.session_id,
            request_id=new_request_id(),
            method=method.upper(),
            path=normalize_path(path),
            url=url,
            streamed=streamed,
            max_attempts=max_attempts,
        )

    def activate(self, context: RequestContext) -> Token:
        return _current_request.set(context)

    def deactivate(self, token: Token) -> None:
        _current_request.reset(token)

    # -- event emission ----------------------------------------------------

    def emit(
        self,
        event: str,
        *,
        context: RequestContext | None = None,
        level: int = logging.DEBUG,
        **fields: Any,
    ) -> None:
        if self._closed:
            return

        context = context or current_request_context()
        # Never emit another client's request context into this session's sink.
        if context is None or context.session_id != self.session_id:
            return

        payload: dict[str, Any] = {
            "event": event,
            "timestamp": time.time(),
            "client_id": self.client_id,
            "request_id": context.request_id,
            "method": context.method,
            "path": context.path,
            "attempt": context.attempt,
            "max_attempts": context.max_attempts,
            "streamed": context.streamed,
            "redirect_count": context.redirect_count,
        }
        if context.upstream_request_id is not None:
            payload["upstream_request_id"] = context.upstream_request_id
        payload.update(fields)
        self._deliver(payload, level)

    def emit_transport(
        self,
        *,
        level: str,
        logger_name: str,
        message: str,
        context: RequestContext,
    ) -> None:
        self.emit(
            "transport",
            context=context,
            level=level,
            logger=logger_name,
            transport_message=message,
        )

    def _deliver(self, payload: dict[str, Any], level: int) -> None:
        # A sink that logs through urllib3 could otherwise recurse into us.
        # This is per-thread state, so a slow sink never blocks other threads.
        if getattr(self._local, "emitting", False):
            return
        self._local.emitting = True
        try:
            if self.mode is DiagnosticsMode.SHARED:
                out = _event_for_shared_sink(
                    payload, self.approved_fields, self._secrets
                )
            elif self.mask_credentials:
                out = redact_value(payload, self._secrets)
            else:
                out = _normalize_for_delivery(payload)

            if not out:
                return

            if self.sink is not None:
                try:
                    self.sink(dict(out))
                except Exception:
                    self._logger.exception("diagnostic sink raised an exception")
                return

            try:
                message = json.dumps(out, default=str, sort_keys=True)
            except (TypeError, ValueError):  # pragma: no cover - defensive
                message = repr(out)
            self._logger.log(level, "%s", message)
        finally:
            self._local.emitting = False
