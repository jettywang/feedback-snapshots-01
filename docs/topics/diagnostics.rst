Connection diagnostics
=======================

When troubleshooting WebSocket (or HTTP) connections it helps to see, per
connection, which lifecycle stage was reached and what happened there. The
``channels.diagnostics`` package provides an *optional* ASGI middleware that
records a sanitized view of each connection into a collector you control.

The output is designed to be shared with another team (for example an
application or support team): session values, cookies, authorization headers,
message payloads, the query string and the negotiated/private subprotocol
values are never copied into a record. The complete, unredacted data is only
ever written to the ``channels.diagnostics`` logger at ``DEBUG`` level, so it
stays inside your controlled logging pipeline.

The middleware is purely observational. The scope and events delivered to
your application are passed through unchanged and in their original order.


Basic usage
-----------

Wrap the middleware around the rest of your application and pass it a
collector. The default ``InMemoryDiagnosticCollector`` keeps the records in
memory and groups them by a per-connection correlation id::

    from channels.diagnostics import (
        DiagnosticsMiddleware,
        InMemoryDiagnosticCollector,
    )

    collector = InMemoryDiagnosticCollector()
    application = DiagnosticsMiddleware(your_application, collector=collector)

Every record carries the same ``connection_id`` for a given connection, a
``phase`` (``connect``, ``message``, ``disconnect`` for WebSockets;
``request`` and ``response`` for HTTP), a ``direction`` (``in`` or ``out``),
the ASGI ``event`` type and a monotonically increasing ``sequence``.

Retrieve a single connection's lifecycle with ``collector.snapshot(id)``, or
every record with ``collector.snapshot()``. Failures raised by the wrapped
application - including a session save failure - are captured on
``collector.errors`` and carry the same ``connection_id`` as the connection
they belong to, along with the ``phase`` at which they occurred and the
exception class name. The raw exception message is redacted because it may
embed session keys or other user data.


Stage-based field filtering
---------------------------

Each event only contributes the fields that are meaningful for its stage, and
each value is filtered before it is recorded:

* The shared scope keeps structural data such as ``type``, ``path`` and
  allow-listed headers. The ``query_string`` is redacted when present, cookies
  and the session are never copied (only ``has_session`` / ``has_cookies``
  flags are reported), and WebSocket subprotocols are replaced by a redaction
  marker - only ``subprotocol_count`` is shared.
* ``websocket.accept`` reports whether a subprotocol was chosen, not its
  value. ``websocket.receive`` / ``websocket.send`` redact the frame payload.
  ``websocket.close`` keeps the close ``code`` but redacts the ``reason``.
* HTTP request and response bodies are redacted; the response status and
  allow-listed headers are retained.

Header values are only kept for a small allow-list of non-credential header
names (such as ``host``, ``content-type`` and ``user-agent``). ``cookie``,
``authorization`` and ``set-cookie`` are always dropped.


Placement and session save errors
---------------------------------

To capture failures raised by other middleware, wrap ``DiagnosticsMiddleware``
around the whole stack so the exception propagates through it::

    from channels.diagnostics import DiagnosticsMiddleware
    from channels.sessions import SessionMiddlewareStack

    application = DiagnosticsMiddleware(
        SessionMiddlewareStack(consumer.as_asgi()),
        collector=collector,
    )

In this outer position the session itself is added below the observer, so the
scope reports ``has_session`` as ``False``; the error is still correlated with
the connection id and recorded with the phase that was reached.

If you want the shared view to see the parsed session (its presence, never its
contents) and the ``http.response.start`` message that triggers a session
save, place the middleware *inside* the session stack instead::

    from channels.diagnostics import DiagnosticsMiddleware
    from channels.sessions import CookieMiddleware, SessionMiddleware

    application = CookieMiddleware(
        SessionMiddleware(
            DiagnosticsMiddleware(consumer.as_asgi(), collector=collector)
        )
    )

A session that is deleted concurrently raises Django's ``SuspiciousOperation``
during the save. Either placement records that failure on
``collector.errors`` with the matching ``connection_id`` and the ``response``
phase, so the HTTP save error can be tied back to the actual connection.


Controlled logging
------------------

The full scope and events, including the values that are withheld from the
collector, are emitted on the ``channels.diagnostics`` logger at ``DEBUG``
level. The logger defaults to ``WARNING`` and therefore produces no output
unless you explicitly enable it in your logging configuration. Enable it only
where the logs are handled as controlled, access-restricted output.


Custom collectors
-----------------

Subclass ``DiagnosticCollector`` and implement ``record`` and
``record_error`` to forward records to a metrics backend, structured logging or
a tracing system. ``for_connection`` returns a per-connection view that stamps
each record with its correlation id; override it if your sink needs different
grouping behaviour.
