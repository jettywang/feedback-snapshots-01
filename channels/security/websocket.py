import asyncio
from collections import deque
from contextlib import suppress
from urllib.parse import urlparse

from django.conf import settings
from django.http.request import is_same_domain

from ..generic.websocket import AsyncWebsocketConsumer

# ASGI extension that allows rejecting a WebSocket during the handshake with a
# regular HTTP response instead of only closing the socket.
# https://asgi.readthedocs.io/en/latest/extensions.html#websocket-denial
WEBSOCKET_HTTP_RESPONSE_EXTENSION = "websocket.http.response"

DEFAULT_DENIAL_STATUS = 403
DEFAULT_DENIAL_HEADERS = [(b"content-type", b"text/plain; charset=utf-8")]
DEFAULT_DENIAL_BODY = b"Forbidden"
# Status codes and header names that a gateway may put on a public denial
# response without further configuration.
DEFAULT_APPROVED_STATUSES = (403,)
DEFAULT_APPROVED_HEADERS = (b"content-type",)


class WebsocketDenialError(Exception):
    """Base class for errors raised while denying a WebSocket handshake."""


class WebsocketHttpResponseUnavailable(WebsocketDenialError):
    """
    Raised when an HTTP handshake rejection is requested but the connected
    server does not advertise the ``websocket.http.response`` extension.
    """


class ConnectionAlreadyAccepted(WebsocketDenialError):
    """
    Raised when a denial is attempted after the connection has already been
    accepted; a handshake rejection is no longer possible.
    """


class ConnectionDisconnectRaced(WebsocketDenialError):
    """
    Raised when a ``websocket.disconnect`` event reaches the application before
    the denial could be sent. Nothing can be delivered to the client anymore.
    """

    def __init__(self, message):
        self.message = message
        super().__init__(
            "Client disconnected before the denial could be sent: %r" % message
        )


class DenialAlreadySent(WebsocketDenialError):
    """
    Raised when a second terminal event (HTTP rejection or WebSocket close) is
    attempted on a connection that already has one.
    """


class WebsocketDenial:
    """
    Encapsulates the two conventions for terminating a rejected WebSocket
    handshake.

    Newer deployments advertise the ``websocket.http.response`` extension in
    the connection scope and accept ``http.response.start`` /
    ``http.response.body`` events as the terminal response. Older deployments
    only understand the legacy ``websocket.close`` event, which drops the
    connection without an HTTP response.

    A single connection may only emit one terminal event. When the extension
    is available the configured status code and headers must be on the approved
    allow lists before they are sent.
    """

    def __init__(
        self,
        scope,
        send,
        receive=None,
        approved_statuses=DEFAULT_APPROVED_STATUSES,
        approved_headers=DEFAULT_APPROVED_HEADERS,
    ):
        self.scope = scope
        self._send = send
        self._raw_receive = receive
        self.approved_statuses = tuple(approved_statuses)
        self.approved_headers = tuple(
            name.lower() for name in approved_headers
        )
        self._accepted = False
        self._terminal_sent = False
        self._receive_buffer = deque()

    @property
    def http_response_available(self):
        """
        ``True`` when the server can express the denial as an HTTP response.
        """
        return WEBSOCKET_HTTP_RESPONSE_EXTENSION in self.scope.get(
            "extensions", {}
        )

    @property
    def accepted(self):
        """``True`` once a ``websocket.accept`` event has been sent."""
        return self._accepted

    @property
    def terminal_sent(self):
        """``True`` once a terminal denial event has been sent."""
        return self._terminal_sent

    def tracking_send(self, send):
        """
        Wrap an ASGI ``send`` callable so accept and terminal events update the
        denial state. Pass the returned callable to the inner application.
        """

        async def wrapper(message):
            message_type = message["type"]
            if message_type == "websocket.accept":
                self._accepted = True
            elif message_type in ("websocket.close", "http.response.start"):
                self._terminal_sent = True
            await send(message)

        return wrapper

    @property
    def receive(self):
        """
        ASGI ``receive`` callable that preserves any messages the disconnect
        probe had to pull out of the queue. Pass this to the inner application
        when :class:`WebsocketDenial` was given a ``receive`` callable.
        """
        if self._raw_receive is None:
            raise ValueError(
                "WebsocketDenial was not constructed with a receive callable"
            )

        async def wrapper():
            if self._receive_buffer:
                return self._receive_buffer.popleft()
            return await self._raw_receive()

        return wrapper

    async def deny(
        self,
        *,
        status=DEFAULT_DENIAL_STATUS,
        headers=DEFAULT_DENIAL_HEADERS,
        body=DEFAULT_DENIAL_BODY,
        close_code=None,
    ):
        """
        Send the terminal rejection using the convention the server supports.

        Emits the configured HTTP response when the extension is available,
        otherwise falls back to the legacy close event.
        """
        await self._ensure_deniable()
        if self.http_response_available:
            await self.http_response(status=status, headers=headers, body=body)
        else:
            await self.close(code=close_code)

    async def http_response(
        self,
        *,
        status=DEFAULT_DENIAL_STATUS,
        headers=DEFAULT_DENIAL_HEADERS,
        body=DEFAULT_DENIAL_BODY,
    ):
        """
        Reject the handshake with an explicit HTTP response.

        Raises :class:`WebsocketHttpResponseUnavailable` when the server does
        not support the extension, :class:`ConnectionAlreadyAccepted` when the
        connection is already accepted and :class:`DenialAlreadySent` when a
        terminal event was already emitted.
        """
        if not self.http_response_available:
            raise WebsocketHttpResponseUnavailable(
                "Server does not advertise the %r ASGI extension"
                % WEBSOCKET_HTTP_RESPONSE_EXTENSION
            )
        await self._ensure_deniable()
        self._validate_http_response(status, headers)
        await self._send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": list(headers),
            }
        )
        self._terminal_sent = True
        await self._send(
            {
                "type": "http.response.body",
                "body": body,
                "more_body": False,
            }
        )

    async def close(self, code=None):
        """
        Reject the handshake the legacy way, by closing the connection without
        an HTTP response.
        """
        await self._ensure_deniable()
        message = {"type": "websocket.close"}
        if code is not None:
            message["code"] = code
        await self._send(message)
        self._terminal_sent = True

    def _validate_http_response(self, status, headers):
        if status not in self.approved_statuses:
            raise ValueError(
                "Denial status %s is not in the approved statuses %r"
                % (status, self.approved_statuses)
            )
        for name, value in headers:
            if name.lower() not in self.approved_headers:
                raise ValueError(
                    "Denial header %r is not in the approved headers %r"
                    % (name, self.approved_headers)
                )

    async def _ensure_deniable(self):
        if self._terminal_sent:
            raise DenialAlreadySent("A terminal denial event was already sent")
        if self._accepted:
            raise ConnectionAlreadyAccepted(
                "Cannot deny a connection that has already been accepted"
            )
        if self._raw_receive is not None and await self._disconnect_raced():
            raise ConnectionDisconnectRaced(self._receive_buffer.pop())

    async def _disconnect_raced(self):
        """
        Drain every message that is already queued without waiting. A queued
        disconnect means the client went away before the denial was sent; any
        other handshake message is buffered and handed back to the application.
        """
        raced = False
        while True:
            task = asyncio.ensure_future(self._raw_receive())
            done, pending = await asyncio.wait({task}, timeout=0)
            if task in pending:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task
                return raced
            message = task.result()
            if message.get("type") == "websocket.disconnect":
                self._receive_buffer.append(message)
                raced = True
            else:
                self._receive_buffer.append(message)


class OriginValidator:
    """
    Validates that the incoming connection has an Origin header that
    is in an allowed list.
    """

    def __init__(
        self,
        application,
        allowed_origins,
        *,
        denial_status=DEFAULT_DENIAL_STATUS,
        denial_headers=DEFAULT_DENIAL_HEADERS,
        denial_body=DEFAULT_DENIAL_BODY,
        denial_close_code=None,
        approved_statuses=DEFAULT_APPROVED_STATUSES,
        approved_headers=DEFAULT_APPROVED_HEADERS,
    ):
        self.application = application
        self.allowed_origins = allowed_origins
        self.denial_status = denial_status
        self.denial_headers = denial_headers
        self.denial_body = denial_body
        self.denial_close_code = denial_close_code
        self.approved_statuses = approved_statuses
        self.approved_headers = approved_headers

    async def __call__(self, scope, receive, send):
        # Make sure the scope is of type websocket
        if scope["type"] != "websocket":
            raise ValueError(
                "You cannot use OriginValidator on a non-WebSocket connection"
            )
        # Extract the Origin header
        parsed_origin = None
        for header_name, header_value in scope.get("headers", []):
            if header_name == b"origin":
                try:
                    # Set ResultParse
                    parsed_origin = urlparse(header_value.decode("latin1"))
                except UnicodeDecodeError:
                    pass
        # Check to see if the origin header is valid
        if self.valid_origin(parsed_origin):
            # Pass control to the application
            return await self.application(scope, receive, send)
        else:
            # Deny the connection. Servers supporting the
            # websocket.http.response extension receive a public HTTP rejection;
            # older servers only get the legacy close event.
            denial = WebsocketDenial(
                scope,
                send,
                receive,
                approved_statuses=self.approved_statuses,
                approved_headers=self.approved_headers,
            )
            await denial.deny(
                status=self.denial_status,
                headers=self.denial_headers,
                body=self.denial_body,
                close_code=self.denial_close_code,
            )
            return

    def valid_origin(self, parsed_origin):
        """
        Checks parsed origin is None.

        Pass control to the validate_origin function.

        Returns ``True`` if validation function was successful, ``False`` otherwise.
        """
        # None is not allowed unless all hosts are allowed
        if parsed_origin is None and "*" not in self.allowed_origins:
            return False
        return self.validate_origin(parsed_origin)

    def validate_origin(self, parsed_origin):
        """
        Validate the given origin for this site.

        Check than the origin looks valid and matches the origin pattern in
        specified list ``allowed_origins``. Any pattern begins with a scheme.
        After the scheme there must be a domain. Any domain beginning with a
        period corresponds to the domain and all its subdomains (for example,
        ``http://.example.com``). After the domain there must be a port,
        but it can be omitted. ``*`` matches anything and anything
        else must match exactly.

        Note. This function assumes that the given origin has a schema, domain
        and port, but port is optional.

        Returns ``True`` for a valid host, ``False`` otherwise.
        """
        return any(
            pattern == "*" or self.match_allowed_origin(parsed_origin, pattern)
            for pattern in self.allowed_origins
        )

    def match_allowed_origin(self, parsed_origin, pattern):
        """
        Returns ``True`` if the origin is either an exact match or a match
        to the wildcard pattern. Compares scheme, domain, port of origin and pattern.

        Any pattern can be begins with a scheme. After the scheme must be a domain,
        or just domain without scheme.
        Any domain beginning with a period corresponds to the domain and all
        its subdomains (for example, ``.example.com`` ``example.com``
        and any subdomain). Also with scheme (for example, ``http://.example.com``
        ``http://example.com``). After the domain there must be a port,
        but it can be omitted.

        Note. This function assumes that the given origin is either None, a
        schema-domain-port string, or just a domain string
        """
        if parsed_origin is None:
            return False

        # Get ResultParse object
        parsed_pattern = urlparse(pattern.lower())
        if parsed_origin.hostname is None:
            return False
        if not parsed_pattern.scheme:
            pattern_hostname = urlparse("//" + pattern).hostname or pattern
            return is_same_domain(parsed_origin.hostname, pattern_hostname)
        # Get origin.port or default ports for origin or None
        origin_port = self.get_origin_port(parsed_origin)
        # Get pattern.port or default ports for pattern or None
        pattern_port = self.get_origin_port(parsed_pattern)
        # Compares hostname, scheme, ports of pattern and origin
        if (
            parsed_pattern.scheme == parsed_origin.scheme
            and origin_port == pattern_port
            and is_same_domain(parsed_origin.hostname, parsed_pattern.hostname)
        ):
            return True
        return False

    def get_origin_port(self, origin):
        """
        Returns the origin.port or port for this schema by default.
        Otherwise, it returns None.
        """
        if origin.port is not None:
            # Return origin.port
            return origin.port
        # if origin.port doesn`t exists
        if origin.scheme == "http" or origin.scheme == "ws":
            # Default port return for http, ws
            return 80
        elif origin.scheme == "https" or origin.scheme == "wss":
            # Default port return for https, wss
            return 443
        else:
            return None


def AllowedHostsOriginValidator(application):
    """
    Factory function which returns an OriginValidator configured to use
    settings.ALLOWED_HOSTS.
    """
    allowed_hosts = settings.ALLOWED_HOSTS
    if settings.DEBUG and not allowed_hosts:
        allowed_hosts = ["localhost", "127.0.0.1", "[::1]"]
    return OriginValidator(application, allowed_hosts)


class WebsocketDenier(AsyncWebsocketConsumer):
    """
    Simple application which denies all requests to it.

    This only implements the legacy rejection convention: a
    ``websocket.close`` event, which drops the connection without an HTTP
    response and is the only terminal event understood by older servers.

    For a server advertising the ``websocket.http.response`` extension, use
    :class:`WebsocketDenial` instead so the client receives an explicit HTTP
    rejection with the configured public status and headers.
    """

    async def connect(self):
        await self.close()
