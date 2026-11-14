# A boundary adapter that translates *already decoded* HTTP/2 per-stream
# events (pseudo-headers, regular headers, body chunks and end-of-stream)
# into h11 HTTP/1.1 events.
#
# This module deliberately contains no HTTP/2 parsing logic: it assumes a
# frontend has already split a stream into the input events defined below.
# Its job is to enforce the security-relevant translation rules from
# RFC 7540 section 8.3 and the HTTP/1.1 message syntax (RFC 9110 / RFC 9112)
# so that an unsafe stream can never leak a half-written request onto a
# reusable downstream HTTP/1.1 connection.

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from ._connection import Connection
from ._events import Data, EndOfMessage, Event, Request
from ._state import CLIENT
from ._util import LocalProtocolError

__all__ = [
    "H2Event",
    "H2Headers",
    "H2Data",
    "H2EndOfStream",
    "H2AdapterError",
    "H2StreamAdapter",
    "H2DownstreamConnection",
]

# The only HTTP/2 request pseudo-header fields this adapter knows. Anything
# else beginning with ":" is rejected rather than forwarded.
_KNOWN_PSEUDO_HEADERS = frozenset(
    (b":method", b":scheme", b":authority", b":path")
)

# Hop-by-hop / connection-level header fields that HTTP/2 forbids (RFC 7540
# section 8.1.2.2) and that must never be generated on an HTTP/1.1 link by
# this gateway. TE is handled separately because "trailers" is allowed.
_FORBIDDEN_HEADERS = frozenset(
    (
        b"connection",
        b"keep-alive",
        b"proxy-connection",
        b"transfer-encoding",
        b"upgrade",
        b"trailer",
    )
)

_TOKEN_CHARS = set(b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz")
_METHOD_CHARS = set(
    b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)
_SCHEME_CHARS = set(b"0123456789abcdefghijklmnopqrstuvwxyz+-.")
_HEX_CHARS = set(b"0123456789abcdefABCDEF")


class H2AdapterError(Exception):
    """A stream could not safely be translated to HTTP/1.1.

    ``error_status_hint`` suggests an HTTP status a gateway might return to
    the offending client.  Whenever this is raised the downstream connection
    is left untouched, so no partial request is ever handed to a reusable
    connection.
    """

    def __init__(self, message: str, error_status_hint: int = 400) -> None:
        super().__init__(message)
        self.error_status_hint = error_status_hint


@dataclass(frozen=True)
class H2Event:
    """Common base for the decoded HTTP/2 stream events."""


@dataclass(frozen=True)
class H2Headers(H2Event):
    """A decoded HTTP/2 HEADERS block.

    ``headers`` is a sequence of ``(name, value)`` byte-string pairs exactly
    as the HTTP/2 layer delivered them (pseudo-headers and regular headers
    interspersed, in the original lower-cased HTTP/2 spelling).
    """

    headers: Sequence[Tuple[bytes, bytes]]
    end_stream: bool = False


@dataclass(frozen=True)
class H2Data(H2Event):
    """A decoded HTTP/2 DATA frame payload."""

    data: bytes
    end_stream: bool = False


@dataclass(frozen=True)
class H2EndOfStream(H2Event):
    """The HTTP/2 stream's terminal event, optionally carrying trailers."""

    trailers: Sequence[Tuple[bytes, bytes]] = field(default_factory=tuple)


def _is_control_octet(octet: int) -> bool:
    # HTAB (0x09) is the only control octet permitted inside HTTP field
    # content; every other C0-range octet and DEL (0x7F) are rejected.
    return (octet < 0x20 and octet != 0x09) or octet == 0x7F


def _reject_encoded_controls(value: bytes, what: bytes) -> None:
    # Reject percent-encoding that decodes to an ASCII control character.
    # Frontends sometimes pass target/field values through verbatim, so an
    # injected "%0d%0a" must not reach the HTTP/1.1 wire where a downstream
    # stack could re-interpret it as a line break (request smuggling).
    index = 0
    length = len(value)
    while index < length:
        if value[index] == 0x25 and index + 2 < length:  # b"%"
            high = value[index + 1]
            low = value[index + 2]
            if high in _HEX_CHARS and low in _HEX_CHARS:
                decoded = int(value[index + 1 : index + 3], 16)
                if _is_control_octet(decoded):
                    raise H2AdapterError(
                        "encoded control character in {}".format(
                            what.decode("latin-1")
                        )
                    )
                index += 3
                continue
        index += 1


def _validate_field_name(name: bytes) -> None:
    if not name:
        raise H2AdapterError("empty header name")
    for octet in name:
        if octet not in _TOKEN_CHARS:
            raise H2AdapterError(
                "illegal or non-lowercase/ASCII header name {!r}".format(name)
            )


def _validate_field_value(value: bytes, what: bytes) -> None:
    for octet in value:
        if _is_control_octet(octet):
            raise H2AdapterError(
                "raw control character in {}".format(what.decode("latin-1"))
            )
    _reject_encoded_controls(value, what)


def _validate_token(value: bytes, what: str) -> None:
    if not value or any(octet not in _METHOD_CHARS for octet in value):
        raise H2AdapterError("illegal {} {!r}".format(what, value))


class H2StreamAdapter:
    """Translate one HTTP/2 stream into a sequence of h11 events.

    Feed the decoded events in stream order with :meth:`handle_event`.  The
    full stream is validated while it is buffered; only when the terminal
    event is accepted does :meth:`h11_events` materialise exactly one complete
    HTTP/1.1 request (a :class:`h11.Request`, zero or more :class:`h11.Data`
    and one :class:`h11.EndOfMessage`).  Any rule violation raises
    :class:`H2AdapterError` and no request events are exposed.
    """

    def __init__(self) -> None:
        self._phase = "headers"  # headers -> body -> done
        self._headers_seen = False
        self._method: Optional[bytes] = None
        self._is_connect = False
        self._target: Optional[bytes] = None
        self._regular: List[Tuple[bytes, bytes]] = []
        self._declared_length: Optional[int] = None
        self._body_chunks: List[bytes] = []
        self._received_length = 0
        self._events: Optional[List[Event]] = None

    @property
    def h11_events(self) -> List[Event]:
        if self._events is None:
            raise H2AdapterError("stream is not complete")
        return list(self._events)

    def handle_event(self, event: H2Event) -> None:
        if self._phase == "done":
            raise H2AdapterError("event received after end of stream")
        if isinstance(event, H2Headers):
            if self._phase != "headers":
                raise H2AdapterError("a second HEADERS block must be trailers")
            self._handle_headers(event)
            if event.end_stream:
                self._finish(())
        elif isinstance(event, H2Data):
            self._handle_data(event)
            if event.end_stream:
                self._finish(())
        elif isinstance(event, H2EndOfStream):
            self._finish(event.trailers)
        else:  # pragma: no cover - defensive, exhausts the input union
            raise H2AdapterError("unknown input event {!r}".format(event))

    # -- HEADERS -----------------------------------------------------------

    def _handle_headers(self, event: H2Headers) -> None:
        pseudo: Dict[bytes, bytes] = {}
        regular: List[Tuple[bytes, bytes]] = []
        seen_regular = False
        for raw_name, raw_value in event.headers:
            if not isinstance(raw_name, (bytes, bytearray)) or not isinstance(
                raw_value, (bytes, bytearray)
            ):
                raise H2AdapterError("header names and values must be bytes")
            name = bytes(raw_name)
            value = bytes(raw_value)
            if name.startswith(b":"):
                if seen_regular:
                    raise H2AdapterError(
                        "pseudo-header field after regular header field"
                    )
                if name not in _KNOWN_PSEUDO_HEADERS:
                    raise H2AdapterError(
                        "unexpected pseudo-header field {!r}".format(name)
                    )
                if name in pseudo:
                    raise H2AdapterError(
                        "duplicate pseudo-header field {!r}".format(name)
                    )
                _validate_field_value(value, name)
                pseudo[name] = value
            else:
                seen_regular = True
                _validate_field_name(name)
                _validate_field_value(value, name)
                regular.append((name, value))

        method = pseudo.get(b":method")
        if method is None:
            raise H2AdapterError("missing mandatory :method pseudo-header")
        _validate_token(method, "method")
        self._headers_seen = True
        self._method = method
        self._is_connect = method == b"CONNECT"

        if self._is_connect:
            self._target, self._regular = self._build_connect(pseudo, regular)
        else:
            (
                self._target,
                self._regular,
                self._declared_length,
            ) = self._build_origin_request(pseudo, regular)

    def _build_connect(
        self, pseudo: Dict[bytes, bytes], regular: List[Tuple[bytes, bytes]]
    ) -> Tuple[bytes, List[Tuple[bytes, bytes]]]:
        # RFC 7540 section 8.5 / RFC 9110 section 9.3.6: CONNECT uses the
        # authority-form target, carries no scheme/path and no content, and
        # is never spliced through the ordinary origin-form path builder.
        if b":scheme" in pseudo or b":path" in pseudo:
            raise H2AdapterError("CONNECT must not carry :scheme or :path")
        authority = pseudo.get(b":authority")
        if not authority:
            raise H2AdapterError("CONNECT requires a non-empty :authority")
        self._validate_authority_form(authority)

        regular = self._reject_forbidden(regular)
        host_values = [value for name, value in regular if name == b"host"]
        if len(host_values) > 1:
            raise H2AdapterError("multiple Host header fields")
        if host_values and host_values[0] != authority:
            raise H2AdapterError("Host header conflicts with :authority")
        if any(name == b"content-length" for name, _ in regular):
            raise H2AdapterError("CONNECT request must not carry a body")

        headers = [(name, value) for name, value in regular if name != b"host"]
        headers.insert(0, (b"host", authority))
        return authority, headers

    def _build_origin_request(
        self, pseudo: Dict[bytes, bytes], regular: List[Tuple[bytes, bytes]]
    ) -> Tuple[bytes, List[Tuple[bytes, bytes]], Optional[int]]:
        for required in (b":method", b":scheme", b":path"):
            if required not in pseudo:
                raise H2AdapterError(
                    "missing mandatory {} pseudo-header".format(
                        required.decode("ascii")
                    )
                )
        scheme = pseudo[b":scheme"]
        if not scheme or any(octet not in _SCHEME_CHARS for octet in scheme):
            raise H2AdapterError("illegal :scheme {!r}".format(scheme))
        target = self._validate_origin_target(pseudo[b":method"], pseudo[b":path"])

        authority = pseudo.get(b":authority")
        regular = self._reject_forbidden(regular)

        host_values = [value for name, value in regular if name == b"host"]
        if len(host_values) > 1:
            raise H2AdapterError("multiple Host header fields")
        host = host_values[0] if host_values else None
        if authority is None and host is None:
            raise H2AdapterError("request needs :authority or Host header")
        if authority is not None and host is not None and authority != host:
            raise H2AdapterError("Host header conflicts with :authority")
        effective_host = host if host is not None else authority
        assert effective_host is not None
        _validate_field_value(effective_host, b"host")

        declared_length: Optional[int] = None
        content_length_values = [
            value for name, value in regular if name == b"content-length"
        ]
        if content_length_values:
            if len(content_length_values) > 1:
                raise H2AdapterError("multiple Content-Length header fields")
            raw_length = content_length_values[0]
            if not raw_length.isdigit():
                raise H2AdapterError(
                    "non-numeric Content-Length {!r}".format(raw_length)
                )
            declared_length = int(raw_length)

        headers = [(name, value) for name, value in regular if name != b"host"]
        headers.insert(0, (b"host", effective_host))
        return target, headers, declared_length

    def _reject_forbidden(
        self, regular: List[Tuple[bytes, bytes]]
    ) -> List[Tuple[bytes, bytes]]:
        for name, value in regular:
            if name in _FORBIDDEN_HEADERS:
                raise H2AdapterError(
                    "connection-level header {!r} is not allowed".format(name)
                )
            if name == b"te" and value.lower() != b"trailers":
                raise H2AdapterError(
                    "TE header may only carry the value 'trailers'"
                )
        return regular

    def _validate_origin_target(self, method: bytes, path: bytes) -> bytes:
        if not path:
            raise H2AdapterError("empty :path pseudo-header")
        for octet in path:
            if _is_control_octet(octet):
                raise H2AdapterError("raw control character in :path")
        _reject_encoded_controls(path, b":path")
        if path == b"*":
            # asterisk-form is only valid for OPTIONS.
            if method != b"OPTIONS":
                raise H2AdapterError("asterisk-form target only valid for OPTIONS")
            return path
        # Only origin-form (plus the asterisk case above) is a legal
        # HTTP/1.1 request target for a non-CONNECT request through here;
        # authority-form is reached exclusively via the CONNECT path and
        # absolute-form is rejected rather than rewritten.
        if not path.startswith(b"/"):
            raise H2AdapterError(
                "illegal request target form; only origin-form or '*' allowed"
            )
        return path

    def _validate_authority_form(self, authority: bytes) -> None:
        _reject_encoded_controls(authority, b":authority")
        # host ":" port, with an explicit numeric port. RFC 9110 section
        # 9.3.6 mandates a CONNECT client always send the port number, and
        # rejects an empty or invalid port.
        if b"/" in authority or b" " in authority or b":" not in authority:
            raise H2AdapterError("CONNECT target must be authority-form host:port")
        host, _, port = authority.rpartition(b":")
        if not host or not port.isdigit():
            raise H2AdapterError(
                "CONNECT target has an empty or invalid port number"
            )
        for octet in authority:
            if _is_control_octet(octet) or octet == 0x20:
                raise H2AdapterError("illegal octet in CONNECT authority")

    # -- BODY --------------------------------------------------------------

    def _handle_data(self, event: H2Data) -> None:
        if not self._headers_seen:
            raise H2AdapterError("DATA frame received before HEADERS")
        if self._phase == "headers":
            self._phase = "body"
        if self._is_connect:
            raise H2AdapterError("CONNECT request must not carry DATA frames")
        chunk = bytes(event.data)
        self._received_length += len(chunk)
        if (
            self._declared_length is not None
            and self._received_length > self._declared_length
        ):
            # Refuse before the over-long bytes can be framed so a declared
            # Content-Length can never swallow the next request on the link.
            raise H2AdapterError("received body exceeds declared Content-Length")
        if chunk:
            self._body_chunks.append(chunk)

    def _finish(self, trailers: Sequence[Tuple[bytes, bytes]]) -> None:
        if not self._headers_seen:
            raise H2AdapterError("end of stream received before HEADERS")
        if self._is_connect:
            if self._received_length:
                raise H2AdapterError("CONNECT request must not carry a body")
            trailer_pairs: List[Tuple[bytes, bytes]] = []
        else:
            trailer_pairs = self._validate_trailers(trailers)
            self._check_length_consistency()

        headers = self._framed_headers(trailer_pairs)
        assert self._method is not None and self._target is not None
        events: List[Event] = [
            Request(method=self._method, target=self._target, headers=headers)
        ]
        for chunk in self._body_chunks:
            events.append(Data(chunk))
        events.append(EndOfMessage(headers=trailer_pairs))
        self._events = events
        self._phase = "done"

    def _check_length_consistency(self) -> None:
        if self._declared_length is not None and (
            self._received_length != self._declared_length
        ):
            raise H2AdapterError(
                "end of stream does not match declared Content-Length "
                "(declared {}, received {})".format(
                    self._declared_length, self._received_length
                )
            )

    def _validate_trailers(
        self, trailers: Sequence[Tuple[bytes, bytes]]
    ) -> List[Tuple[bytes, bytes]]:
        if not trailers:
            return []
        if self._declared_length is not None:
            raise H2AdapterError(
                "trailers require chunked framing, not Content-Length"
            )
        validated: List[Tuple[bytes, bytes]] = []
        for raw_name, raw_value in trailers:
            name = bytes(raw_name)
            value = bytes(raw_value)
            if name.startswith(b":"):
                raise H2AdapterError("pseudo-header field in trailers")
            _validate_field_name(name)
            _validate_field_value(value, name)
            if name in _FORBIDDEN_HEADERS or name in (b"host", b"content-length"):
                raise H2AdapterError("forbidden field {!r} in trailers".format(name))
            validated.append((name, value))
        return validated

    def _framed_headers(
        self, trailer_pairs: List[Tuple[bytes, bytes]]
    ) -> List[Tuple[bytes, bytes]]:
        headers = list(self._regular)
        if self._is_connect or self._declared_length is not None:
            return headers
        has_body = bool(self._body_chunks) or bool(trailer_pairs)
        if not has_body:
            # No framing header: h11 treats a bodyless request as
            # Content-Length: 0 and the message ends at the header block.
            return headers
        # A body of unknown length must be chunked on the HTTP/1.1 link;
        # trailers also require chunked transfer coding.
        headers.append((b"transfer-encoding", b"chunked"))
        return headers


class H2DownstreamConnection:
    """A reusable HTTP/1.1 downstream connection fed by HTTP/2 streams.

    Each successfully translated stream is appended to :attr:`outbound` as
    one self-framed HTTP/1.1 request.  Serialization is staged on a scratch
    h11 client first: if any event fails, the exception propagates and neither
    :attr:`outbound` nor the reusable connection is touched, guaranteeing a
    failing stream never leaves a half request on the wire.
    """

    def __init__(self) -> None:
        self.outbound = b""
        self.poisoned = False
        self._submitted = 0

    @property
    def request_count(self) -> int:
        return self._submitted

    def submit(self, events: Sequence[Event]) -> bytes:
        if self.poisoned:
            raise H2AdapterError(
                "downstream connection is poisoned after a prior failure"
            )
        if not events or type(events[0]) is not Request:
            raise H2AdapterError("a translated request must begin with Request")
        scratch = Connection(our_role=CLIENT)
        staged = b""
        try:
            for event in events:
                emitted = scratch.send(event)
                if emitted is not None:
                    staged += emitted
        except LocalProtocolError as error:
            self.poisoned = True
            raise H2AdapterError(
                "rejected unsafe HTTP/1.1 request: {}".format(error),
                error_status_hint=error.error_status_hint,
            ) from error
        # Commit only once the entire request serialized cleanly.
        self.outbound += staged
        self._submitted += 1
        return staged
