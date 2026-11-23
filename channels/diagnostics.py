"""
Optional, shareable connection-lifecycle diagnostics for ASGI applications.

This middleware observes the scope, the events received from the protocol
server, and the events the application sends back, and records one
*sanitized* record per stage of the connection into a :class:`DiagnosticCollector`.
The records are safe to hand to another (application) team: values that are
session- or credential-bearing (cookies, session contents, authorization
headers, message payloads, the query string) and the negotiated/private
subprotocol values are never copied into a record.

The complete, unredacted data is still written to the ``channels.diagnostics``
logger at ``DEBUG`` level, so it can be captured by the application's own
controlled logging pipeline. That logger defaults to ``WARNING`` and therefore
emits nothing unless the operator explicitly opts in.

The scope and events delivered to the wrapped application are passed through
unchanged; the middleware only observes them.
"""

import logging
import uuid

__all__ = [
    "DiagnosticCollector",
    "InMemoryDiagnosticCollector",
    "DiagnosticsMiddleware",
    "REDACTED",
]

logger = logging.getLogger("channels.diagnostics")

# Placeholder substituted for any value that is not safe to share.
REDACTED = "[redacted]"

# Header names that carry no credential/personal data and are safe to share.
# Everything else (cookie, authorization, set-cookie, ...) is dropped.
_SHARED_HEADER_NAMES = frozenset(
    {
        b"host",
        b"content-type",
        b"content-length",
        b"accept",
        b"accept-language",
        b"user-agent",
        b"origin",
    }
)


def _redacted_if_present(value):
    """Return the redaction marker when *value* holds any data."""
    if value is None or value == b"" or value == "":
        return value
    return REDACTED


def _sanitize_headers(headers):
    """Keep only allow-listed, non-credential header names and values."""
    safe_headers = []
    for name, value in headers or []:
        if isinstance(name, str):
            name = name.encode("latin1")
        if name.lower() in _SHARED_HEADER_NAMES:
            safe_headers.append((name, value))
    return safe_headers


def _sanitize_scope(scope):
    """
    Build the shareable view of a connection scope.

    Only structural, non-sensitive fields are retained; cookies, the session
    and its values, and the private subprotocol values are never copied.
    """
    shared = {
        "type": scope.get("type"),
        "path": scope.get("path"),
        "query_string": _redacted_if_present(scope.get("query_string")),
        "headers": _sanitize_headers(scope.get("headers")),
        "has_session": "session" in scope,
        "has_cookies": "cookies" in scope,
    }
    if scope.get("type") == "websocket":
        subprotocols = scope.get("subprotocols", []) or []
        # Never expose the negotiated/private subprotocol values; report only
        # how many were offered so the lifecycle stays interpretable.
        shared["subprotocol_count"] = len(subprotocols)
        shared["subprotocols"] = [REDACTED for _ in subprotocols]
    if "method" in scope:
        shared["method"] = scope["method"]
    if "http_version" in scope:
        shared["http_version"] = scope["http_version"]
    return shared


def _msg_websocket_connect(message):
    return {}


def _msg_websocket_accept(message):
    return {
        # The chosen subprotocol is private, so only its presence is reported.
        "subprotocol": _redacted_if_present(message.get("subprotocol")),
        "headers": _sanitize_headers(message.get("headers")),
    }


def _msg_websocket_receive(message):
    return {
        "text": _redacted_if_present(message.get("text")),
        "bytes": _redacted_if_present(message.get("bytes")),
    }


def _msg_websocket_send(message):
    return {
        "text": _redacted_if_present(message.get("text")),
        "bytes": _redacted_if_present(message.get("bytes")),
    }


def _msg_websocket_disconnect(message):
    return {"code": message.get("code")}


def _msg_websocket_close(message):
    return {
        "code": message.get("code"),
        "reason": _redacted_if_present(message.get("reason")),
    }


def _msg_http_request(message):
    return {
        "body": _redacted_if_present(message.get("body")),
        "more_body": message.get("more_body", False),
    }


def _msg_http_response_start(message):
    return {
        "status": message.get("status"),
        "headers": _sanitize_headers(message.get("headers")),
    }


def _msg_http_response_body(message):
    return {
        "body": _redacted_if_present(message.get("body")),
        "more_body": message.get("more_body", False),
    }


# ASGI message type -> (lifecycle phase, field-builder). The record's
# direction (in/out) is observed directly from the receive/send call.
_EVENT_PROFILES = {
    "websocket.connect": ("connect", _msg_websocket_connect),
    "websocket.accept": ("connect", _msg_websocket_accept),
    "websocket.receive": ("message", _msg_websocket_receive),
    "websocket.send": ("message", _msg_websocket_send),
    "websocket.disconnect": ("disconnect", _msg_websocket_disconnect),
    "websocket.close": ("disconnect", _msg_websocket_close),
    "http.request": ("request", _msg_http_request),
    "http.response.start": ("response", _msg_http_response_start),
    "http.response.body": ("response", _msg_http_response_body),
}


def _phase_for(scope_type):
    if scope_type == "websocket":
        return "connect"
    if scope_type == "http":
        return "request"
    return "connect"


class DiagnosticCollector:
    """
    Interface for a sink that receives shareable diagnostic records.

    Subclass this to forward records to a metrics system, a structured log or
    an external tracing backend. Every method is synchronous so it stays cheap
    and safe to call from the async middleware.
    """

    def for_connection(self, connection_id, scope):
        """Return a collector bound to a single connection."""
        return self

    def record(self, entry):
        raise NotImplementedError()

    def record_error(self, connection_id, phase, exc):
        raise NotImplementedError()


class InMemoryDiagnosticCollector(DiagnosticCollector):
    """
    Collector that keeps records in memory, grouped by connection id.

    Useful for tests and for building a short-lived, shareable snapshot of a
    connection's lifecycle.
    """

    def __init__(self):
        self.records = []
        self.errors = []

    def for_connection(self, connection_id, scope):
        return _BoundCollector(self, connection_id)

    def snapshot(self, connection_id=None):
        """Return recorded entries, optionally filtered by connection id."""
        if connection_id is None:
            return list(self.records)
        return [
            entry
            for entry in self.records
            if entry["connection_id"] == connection_id
        ]

    def errors_for(self, connection_id):
        return [
            entry
            for entry in self.errors
            if entry["connection_id"] == connection_id
        ]


class _BoundCollector:
    """Collector view that stamps every entry with the same connection id."""

    def __init__(self, parent, connection_id):
        self.parent = parent
        self.connection_id = connection_id

    def record(self, entry):
        entry = dict(entry)
        entry["connection_id"] = self.connection_id
        self.parent.records.append(entry)

    def record_error(self, connection_id, phase, exc):
        self.parent.errors.append(
            {
                "connection_id": connection_id,
                "phase": phase,
                "error_type": type(exc).__name__,
                # Never copy the raw message: it may embed session keys or
                # other user data. The exception class name is enough to
                # correlate a failure with its connection.
                "message": REDACTED,
            }
        )


class DiagnosticsMiddleware:
    """
    ASGI middleware that records a redacted, shareable view of the connection
    lifecycle while leaving the application's scope and events untouched.

    Wrap it *around* the rest of the stack so that failures raised by inner
    middleware (for example a session save error) are captured and correlated
    with the connection through ``connection_id``::

        application = DiagnosticsMiddleware(
            SessionMiddlewareStack(consumer),
            collector=my_collector,
        )
    """

    def __init__(self, inner, collector=None):
        self.inner = inner
        self.collector = collector or InMemoryDiagnosticCollector()

    async def __call__(self, scope, receive, send):
        connection_id = uuid.uuid4().hex
        connection = self.collector.for_connection(connection_id, scope)
        # The full scope, including session values and private subprotocols,
        # is only ever sent to the controlled logger, never to the collector.
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("connection %s scope %r", connection_id, scope)

        shared_scope = _sanitize_scope(scope)
        connection.record(
            {
                "phase": _phase_for(scope.get("type")),
                "direction": "in",
                "event": "scope",
                "scope": shared_scope,
                "sequence": 0,
            }
        )

        state = _ConnectionDiagnostics(
            connection_id=connection_id,
            collector=connection,
        )

        async def diagnostic_receive():
            message = await receive()
            state.observe_message(message, direction="in")
            return message

        async def diagnostic_send(message):
            state.observe_message(message, direction="out")
            return await send(message)

        try:
            return await self.inner(scope, diagnostic_receive, diagnostic_send)
        except Exception as exc:
            state.record_error(exc)
            raise


class _ConnectionDiagnostics:
    """Per-connection bookkeeping used by :class:`DiagnosticsMiddleware`."""

    def __init__(self, connection_id, collector):
        self.connection_id = connection_id
        self.collector = collector
        self.sequence = 1
        self.phase = None

    def observe_message(self, message, direction):
        message_type = message.get("type")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "connection %s %s event %r",
                self.connection_id,
                direction,
                message,
            )
        profile = _EVENT_PROFILES.get(message_type)
        if profile is None:
            # Unknown message types are recorded structurally only, without
            # copying any of their (potentially sensitive) contents.
            phase = self.phase or "message"
            data = {}
        else:
            phase, builder = profile
            data = builder(message)
        self.phase = phase
        self.collector.record(
            {
                "phase": phase,
                "direction": direction,
                "event": message_type,
                "data": data,
                "sequence": self.sequence,
            }
        )
        self.sequence += 1

    def record_error(self, exc):
        self.collector.record_error(
            self.connection_id, self.phase or "unknown", exc
        )
