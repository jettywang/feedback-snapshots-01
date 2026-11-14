"""HTTP/2 ingress adapter for ordinary and extended CONNECT tunnels.

The adapter wraps a server-side :class:`h2.connection.H2Connection` and adds
the gate that a production ingress needs before turning a stream into a tunnel:

1. the request must be a well-formed CONNECT (ordinary, RFC 9113, or extended,
   RFC 8441) and, when ``:protocol`` is used, the peer must have advertised
   ``SETTINGS_ENABLE_CONNECT_PROTOCOL`` and the protocol must be in the explicit
   allow list and satisfy its negotiation policy;
2. only then is the application authorizer invoked;
3. only an authorized, resolved request triggers exactly one target-connector
   call.

Ordinary and extended CONNECT are never downgraded into one another: their
pseudo-header shapes are validated separately. Early DATA that arrives while
authorization is in flight is buffered per stream and never reaches the target.
Every rejection, cancellation or error tears down any downstream connection it
may hold, and stream state is kept in independent per-stream objects.

The authorization callback receives the validated request plus a ``resolve``
callable. It may call ``resolve(True/False)`` synchronously or retain it until
an asynchronous decision is available; frames fed in between stay buffered.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.events import (
    ConnectionTerminated,
    DataReceived,
    RequestReceived,
    StreamEnded,
    StreamReset,
    WindowUpdated,
)
from h2.exceptions import ProtocolError
from h2.settings import SettingCodes

from .errors import (
    AuthorizationError,
    ProtocolRejected,
    RejectReason,
    TargetConnectionError,
    TunnelError,
)
from .events import (
    TunnelAborted,
    TunnelAccepted,
    TunnelClosed,
    TunnelData,
    TunnelEvent,
    TunnelFailed,
    TunnelRejected,
    TunnelRequest,
    TunnelRequestReceived,
    _StreamState,
)
from .protocols import ProtocolPolicy, ProtocolRegistry
from .target import TargetHandle

#: Pseudo-header names legal in an HTTP/2 request.
_REQUEST_PSEUDO = frozenset(
    (b":method", b":scheme", b":authority", b":path", b":protocol")
)

#: HTTP status emitted for each local rejection reason.
_REJECT_STATUS = {
    RejectReason.NOT_CONNECT: 405,
    RejectReason.CONNECT_PROTOCOL_DISABLED: 400,
    RejectReason.PSEUDO_HEADER_VIOLATION: 400,
    RejectReason.UNKNOWN_PROTOCOL: 501,
    RejectReason.NEGOTIATION_FAILED: 421,
    RejectReason.UNAUTHORIZED: 403,
    RejectReason.AUTHORIZER_ERROR: 500,
}


class TunnelProtocolError(TunnelError):
    """Raised when the underlying h2 stack reports a connection-level error."""


#: Application hook invoked after local validation. It must eventually call the
#: supplied resolver with the authorization decision.
Authorizer = Callable[[TunnelRequest, "AuthorizationResolver"], None]
AuthorizationResolver = Callable[[bool], list[TunnelEvent]]
Connector = Callable[[TunnelRequest], TargetHandle]


class H2ConnectAdapter:
    """Server-side gate and state machine for CONNECT-based tunneling."""

    def __init__(
        self,
        *,
        allowed_protocols: Sequence[ProtocolPolicy | str],
        authorizer: Authorizer,
        connector: Connector,
        max_buffered_bytes: int = 1 << 20,
        h2_config: H2Configuration | None = None,
    ) -> None:
        config = h2_config or H2Configuration(
            client_side=False, header_encoding=None
        )
        if config.client_side:
            raise ValueError("H2ConnectAdapter requires a server-side h2 config")
        self._conn = H2Connection(config=config)
        self._registry = ProtocolRegistry(allowed_protocols)
        self._authorizer = authorizer
        self._connector = connector
        self._max_buffered = max_buffered_bytes
        self._streams: dict[int, _StreamState] = {}
        self._defunct = False

    # ------------------------------------------------------------------ setup
    def initiate(self) -> None:
        """Send the server preface and advertise the connect-protocol setting."""

        self._conn.initiate_connection()
        # The extended form is only usable when we advertise the setting. An
        # empty allow list still turns the flag on so requests can be rejected
        # as unknown protocols rather than treated as malformed.
        self._conn.update_settings({SettingCodes.ENABLE_CONNECT_PROTOCOL: 1})

    def data_to_send(self, amount: int | None = None) -> bytes:
        return self._conn.data_to_send(amount)

    # ------------------------------------------------------------- ingress API
    def feed(self, data: bytes) -> list[TunnelEvent]:
        """Process one inbound h2 byte chunk and return tunnel-level events."""

        emitted: list[TunnelEvent] = []
        if self._defunct:
            raise TunnelProtocolError("connection is defunct")
        try:
            h2_events = self._conn.receive_data(data)
        except ProtocolError as exc:
            self._tear_down_all(ErrorCodes.PROTOCOL_ERROR)
            self._defunct = True
            raise TunnelProtocolError(str(exc)) from exc

        for event in h2_events:
            if isinstance(event, RequestReceived):
                emitted.extend(self._on_request(event))
            elif isinstance(event, DataReceived):
                emitted.extend(self._on_data(event))
            elif isinstance(event, StreamEnded):
                emitted.extend(self._on_stream_ended(event.stream_id))
            elif isinstance(event, StreamReset):
                reset_event = self._on_stream_reset(event)
                if reset_event is not None:
                    emitted.append(reset_event)
            elif isinstance(event, ConnectionTerminated):
                emitted.extend(self._on_connection_terminated(event))
            elif isinstance(event, WindowUpdated):
                # Exposed by the wrapped h2 connection for flow control bookkeeping.
                continue
        return emitted

    # ------------------------------------------------------- authorization API
    def authorization_result(
        self, stream_id: int, allow: bool
    ) -> list[TunnelEvent]:
        """Resolve a pending authorization; called by the application.

        Idempotent per stream: a second call or a call after the stream was
        cancelled has no effect and never reaches the connector.
        """

        state = self._streams.get(stream_id)
        if state is None or state.phase != "authorizing":
            return []
        if not allow:
            return [
                self._finish_reject(
                    state, RejectReason.UNAUTHORIZED, "authorizer denied request"
                )
            ]
        return [self._open_tunnel(state)]

    # ---------------------------------------------------------------- requests
    def _on_request(self, event: RequestReceived) -> list[TunnelEvent]:
        headers = list(event.headers)
        try:
            pseudo, regular = self._split_headers(headers)
        except ProtocolRejected as rejected:
            return [self._reject(event.stream_id, rejected.reason, rejected.detail)]

        if pseudo.get(b":method") != b"CONNECT":
            # Non-CONNECT traffic is outside the tunnel gate.
            return [
                TunnelRequestReceived(
                    stream_id=event.stream_id, headers=tuple(headers)
                )
            ]

        try:
            request = self._build_connect_request(event.stream_id, pseudo, regular)
        except ProtocolRejected as rejected:
            return [self._reject(event.stream_id, rejected.reason, rejected.detail)]

        state = _StreamState(stream_id=event.stream_id, request=request, phase="authorizing")
        self._streams[event.stream_id] = state

        # Local protocol checks have passed; the application gets the final say.
        # A synchronous resolver call must not lose the events it produces.
        emitted: list[TunnelEvent] = []

        def resolver(decision: bool) -> list[TunnelEvent]:
            emitted.extend(
                self.authorization_result(event.stream_id, decision)
            )
            return emitted

        try:
            self._authorizer(request, resolver)
        except AuthorizationError as exc:
            if state.phase != "authorizing":
                return emitted  # it already resolved before raising
            return [self._finish_reject(state, RejectReason.UNAUTHORIZED, str(exc))]
        except Exception as exc:  # authorizer faults must not open a tunnel
            if state.phase != "authorizing":
                return emitted
            return [
                self._finish_reject(state, RejectReason.AUTHORIZER_ERROR, str(exc))
            ]
        return emitted

    def _build_connect_request(
        self,
        stream_id: int,
        pseudo: dict[bytes, bytes],
        regular: dict[bytes, bytes],
    ) -> TunnelRequest:
        extended = b":protocol" in pseudo
        authority = pseudo.get(b":authority")
        if not authority:
            raise ProtocolRejected(
                RejectReason.PSEUDO_HEADER_VIOLATION, "missing :authority"
            )

        if extended:
            if not self._conn.remote_settings.enable_connect_protocol:
                raise ProtocolRejected(
                    RejectReason.CONNECT_PROTOCOL_DISABLED,
                    "peer did not enable SETTINGS_ENABLE_CONNECT_PROTOCOL",
                )
            # The extended form must carry the full RFC 8441 tuple. It can never
            # be downgraded to an ordinary CONNECT, so a missing tuple is fatal.
            if b":scheme" not in pseudo or b":path" not in pseudo:
                raise ProtocolRejected(
                    RejectReason.PSEUDO_HEADER_VIOLATION,
                    "extended CONNECT requires :scheme and :path",
                )
            protocol = pseudo[b":protocol"].decode("ascii").lower()
            policy = self._registry.get(protocol)
            if policy is None:
                raise ProtocolRejected(
                    RejectReason.UNKNOWN_PROTOCOL,
                    f"protocol {protocol!r} is not allowed",
                )
            scheme = pseudo[b":scheme"].decode("ascii")
            negotiation = policy.negotiate(scheme, regular)
            if negotiation is not None:
                raise ProtocolRejected(
                    RejectReason.NEGOTIATION_FAILED, negotiation
                )
        else:
            # Ordinary CONNECT carries no scheme/path/protocol at all.
            if b":scheme" in pseudo or b":path" in pseudo:
                raise ProtocolRejected(
                    RejectReason.PSEUDO_HEADER_VIOLATION,
                    "ordinary CONNECT must not carry :scheme or :path",
                )
            protocol = None
            scheme = None

        return TunnelRequest(
            stream_id=stream_id,
            authority=authority.decode("utf-8"),
            protocol=protocol,
            scheme=scheme,
            path=pseudo.get(b":path", b"").decode("utf-8") or None,
            headers=self._header_tuple(pseudo, regular),
        )

    @staticmethod
    def _split_headers(
        headers: list[tuple[bytes, bytes]],
    ) -> tuple[dict[bytes, bytes], dict[bytes, bytes]]:
        pseudo: dict[bytes, bytes] = {}
        regular: dict[bytes, bytes] = {}
        seen_regular = False
        for name, value in headers:
            if name in _REQUEST_PSEUDO:
                if seen_regular:
                    raise ProtocolRejected(
                        RejectReason.PSEUDO_HEADER_VIOLATION,
                        "pseudo-header field after regular header field",
                    )
                if name in pseudo:
                    raise ProtocolRejected(
                        RejectReason.PSEUDO_HEADER_VIOLATION,
                        f"duplicate pseudo-header {name.decode('ascii')!r}",
                    )
                pseudo[name] = value
            else:
                seen_regular = True
                regular[name] = value
        return pseudo, regular

    @staticmethod
    def _header_tuple(
        pseudo: dict[bytes, bytes], regular: dict[bytes, bytes]
    ) -> tuple[tuple[bytes, bytes], ...]:
        return tuple(pseudo.items()) + tuple(regular.items())

    # --------------------------------------------------------------- acceptance
    def _open_tunnel(self, state: _StreamState) -> TunnelEvent:
        assert state.request is not None
        try:
            handle = self._connector(state.request)
        except TargetConnectionError as exc:
            # No handle was returned, so nothing downstream can leak; signal the
            # failure on the stream instead of accepting it.
            state.phase = "closed"
            self._safe_reset(state.stream_id, ErrorCodes.CONNECT_ERROR)
            return TunnelFailed(stream_id=state.stream_id, error=exc)

        state.target = handle
        state.phase = "open"

        # Acceptance is a single 200; the stream stays open for raw bytes.
        self._conn.send_headers(state.stream_id, [(b":status", b"200")])

        # Authorization-pending data is released now, in arrival order, and only
        # now touches the target.
        for chunk in state.buffered:
            handle.send(chunk)
        state.buffered.clear()
        state.buffered_len = 0

        event = TunnelAccepted(
            stream_id=state.stream_id, request=state.request, target=handle
        )
        if state.half_closed:
            handle.close()
        return event

    # -------------------------------------------------------------------- data
    def _on_data(self, event: DataReceived) -> list[TunnelEvent]:
        state = self._streams.get(event.stream_id)
        if state is None or state.phase == "closed":
            # Data on an ignored stream or one we already finalized.
            return []

        out: list[TunnelEvent] = []
        # Replenish the h2 flow-control window regardless of gate state: the
        # payload is held by the adapter until the tunnel is allowed to open.
        self._conn.acknowledge_received_data(
            event.flow_controlled_length, event.stream_id
        )

        if state.phase == "authorizing":
            if state.buffered_len + len(event.data) > self._max_buffered:
                self._safe_reset(event.stream_id, ErrorCodes.ENHANCE_YOUR_CALM)
                out.append(
                    self._abort(state, ErrorCodes.ENHANCE_YOUR_CALM, remote=False)
                )
                return out
            state.buffered.append(event.data)
            state.buffered_len += len(event.data)
        elif state.phase == "open":
            assert state.target is not None
            state.target.send(event.data)
            out.append(TunnelData(stream_id=event.stream_id, data=event.data))

        if event.stream_ended is not None:
            out.extend(self._on_stream_ended(event.stream_id))
        return out

    def _on_stream_ended(self, stream_id: int) -> list[TunnelEvent]:
        state = self._streams.get(stream_id)
        if state is None or state.half_closed:
            return []
        state.half_closed = True
        if state.phase == "open":
            assert state.target is not None
            state.target.close()
            return [TunnelClosed(stream_id=stream_id)]
        # While authorizing the half-close is remembered; _open_tunnel applies
        # it once the target exists.
        return []

    def _on_stream_reset(self, event: StreamReset) -> TunnelEvent | None:
        state = self._streams.get(event.stream_id)
        if state is None:
            # Unknown/ignored stream: surface the cancellation for completeness.
            return TunnelAborted(
                stream_id=event.stream_id,
                error_code=int(event.error_code),
                remote=event.remote_reset,
            )
        if state.phase == "closed":
            # A late RST after rejection or failure has nothing left to clean.
            return None
        return self._abort(state, event.error_code, event.remote_reset)

    def _on_connection_terminated(
        self, event: ConnectionTerminated
    ) -> list[TunnelEvent]:
        self._defunct = True
        return self._tear_down_all(event.error_code)

    # --------------------------------------------------------------- teardown
    def _abort(
        self, state: _StreamState, error_code: ErrorCodes | int, remote: bool
    ) -> TunnelAborted:
        target = state.target
        if target is not None:
            # Rejections/cancellations must never leave a downstream connection.
            target.abort()
        state.target = None
        state.phase = "closed"
        return TunnelAborted(
            stream_id=state.stream_id,
            error_code=int(error_code),
            remote=remote,
            target=target,
        )

    def _tear_down_all(self, error_code: ErrorCodes | int) -> list[TunnelEvent]:
        out: list[TunnelEvent] = []
        for state in list(self._streams.values()):
            if state.phase != "closed":
                out.append(self._abort(state, error_code, remote=False))
        self._streams.clear()
        return out

    def _reject(
        self, stream_id: int, reason: RejectReason, detail: str
    ) -> TunnelRejected:
        state = self._streams.get(stream_id)
        if state is not None:
            state.phase = "closed"
            state.target = None
        status = _REJECT_STATUS[reason]
        self._conn.send_headers(
            stream_id, [(b":status", str(status).encode("ascii"))], end_stream=True
        )
        return TunnelRejected(
            stream_id=stream_id,
            reason=reason,
            status_code=status,
            detail=detail,
        )

    def _finish_reject(
        self, state: _StreamState, reason: RejectReason, detail: str
    ) -> TunnelRejected:
        state.phase = "closed"
        return self._reject(state.stream_id, reason, detail)

    def _safe_reset(
        self, stream_id: int, error_code: ErrorCodes | int
    ) -> None:
        try:
            self._conn.reset_stream(stream_id, error_code)
        except ProtocolError:
            # The h2 layer may already have closed the stream on its own.
            pass

    # -------------------------------------------------------------- egress API
    def send_to_client(self, stream_id: int, data: bytes) -> None:
        """Forward raw bytes received from the target back to the h2 client."""

        self._conn.send_data(stream_id, data)

    def close_client_stream(self, stream_id: int) -> None:
        """Half-close the client side when the target closes cleanly."""

        self._conn.end_stream(stream_id)

    def reset_client_stream(
        self, stream_id: int, error_code: ErrorCodes | int = ErrorCodes.CONNECT_ERROR
    ) -> None:
        self._conn.reset_stream(stream_id, error_code)

    # ------------------------------------------------------------------ misc
    @property
    def active_streams(self) -> tuple[int, ...]:
        return tuple(
            sid
            for sid, state in self._streams.items()
            if state.phase != "closed"
        )

    def get_state(self, stream_id: int) -> str | None:
        state = self._streams.get(stream_id)
        return state.phase if state is not None else None
