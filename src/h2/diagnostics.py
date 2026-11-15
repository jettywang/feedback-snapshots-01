"""
h2/diagnostics
~~~~~~~~~~~~~~~

Optional, opt-in structured diagnostics for inbound HTTP/2 connection errors.

The objects in this module are only populated when a connection is configured
with ``enable_diagnostics=True``. They let a traffic-analysis backend point at
the exact on-wire byte range that triggered an error, while preserving:

* the on-wire frame range (absolute byte offsets that are stable no matter how
  the same bad connection is split across ``receive_data`` calls),
* the connection and stream state observed *before* the failure, and
* a boundary marking which events had actually been delivered.

Diagnostics intentionally capture only structural metadata and payload
*summaries* (frame type, stream id, lengths, flags). They never store decoded
header fields, authentication headers, request/response bodies, or raw frame
payloads, so enabling them cannot leak business data. Frames that were parsed
but whose events were never delivered are recorded as observations or errors,
never as completed actions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from hyperframe.frame import ExtensionFrame, Frame

if TYPE_CHECKING:  # pragma: no cover
    from .connection import ConnectionState

#: A frame that h2 does not natively understand (an extension frame). These are
#: legal and are delivered as :class:`~h2.events.UnknownFrameReceived` events;
#: they are recorded as non-fatal observations rather than errors.
CATEGORY_UNKNOWN_FRAME = "unknown_frame"

#: A frame whose length could not be validated before its body was parsed, for
#: example an overlong frame or a frame header that did not describe a complete
#: body. Nothing beyond the nine-byte header is consumed.
CATEGORY_LENGTH_ERROR = "length_error"

#: A frame that was structurally valid but violated the connection or stream
#: state machine, including malformed header blocks and frames interleaved into
#: a HEADERS/CONTINUATION sequence.
CATEGORY_STATE_ERROR = "state_error"

#: The HTTP/2 connection preamble did not match.
CATEGORY_PREAMBLE_ERROR = "preamble_error"

#: Attribute used to stash the wire span of a frame while it travels between
#: the frame buffer and the connection layer. Frames are short-lived parser
#: objects, so a private attribute keeps the offset bookkeeping out of their
#: public surface.
_WIRE_START_ATTR = "_h2_diag_wire_start"
_WIRE_END_ATTR = "_h2_diag_wire_end"

#: Attribute used to carry framing-level error context on a raised exception
#: before the connection layer turns it into a full diagnostic entry.
_FRAME_ERROR_ATTR = "_h2_diag_frame_error"


@dataclass(kw_only=True)
class WireRange:
    """
    A half-open ``[start, end)`` range of absolute byte offsets on the wire.

    Offsets are counted across every byte handed to
    :meth:`~h2.connection.H2Connection.receive_data`, including the connection
    preamble consumed by a server. Because the count is cumulative rather than
    relative to a single call, the same bad connection produces the same range
    regardless of how its bytes are chunked.
    """

    start: int
    """The absolute offset of the first byte of the range."""

    end: int
    """One past the absolute offset of the last byte of the range."""

    def as_tuple(self) -> tuple[int, int]:
        """Return the range as a plain ``(start, end)`` tuple."""
        return (self.start, self.end)


@dataclass(kw_only=True)
class FrameSummary:
    """
    Structural, non-sensitive information about a single wire frame.

    Only metadata is retained: frame type, stream id, flags and lengths. The
    frame payload is never copied.
    """

    frame_type: int | None
    """The numeric HTTP/2 frame type, or ``None`` if it could not be parsed."""

    stream_id: int | None
    """The frame's stream id, or ``None`` if it could not be determined."""

    declared_length: int
    """The body length advertised by the nine-byte frame header."""

    flags: tuple[str, ...] = ()
    """The decoded flag names. Empty for an extension or unparsable frame."""

    flag_byte: int | None = None
    """The raw flag byte, retained for extension frames."""

    payload_length: int | None = None
    """The number of body bytes actually present, when known."""


@dataclass(kw_only=True)
class DiagnosticEntry:
    """
    A single recorded diagnostic: either a fatal error or a non-fatal
    observation.

    A failure entry points at both the specific frame that could not be
    processed (``frame`` / ``frame_range``) and, when applicable, the complete
    HEADERS/CONTINUATION header block it belonged to (``header_block_range``).
    """

    category: str
    """One of the ``CATEGORY_*`` constants describing the kind of finding."""

    fatal: bool
    """Whether this entry describes the error that terminated processing."""

    message: str
    """The human-readable reason, matching the raised exception message."""

    frame: FrameSummary | None = None
    """Structural summary of the triggering frame, if identifiable."""

    frame_range: WireRange | None = None
    """The on-wire range of the triggering frame."""

    header_block_range: WireRange | None = None
    """
    The full HEADERS/CONTINUATION block range, when the failure relates to a
    header block. ``frame_range`` identifies the individual failing frame
    inside that block.
    """

    connection_state: str | None = None
    """The connection state machine state immediately before the failure."""

    stream_state: str | None = None
    """The relevant stream's state immediately before the failure, if known."""

    delivered_event_count: int = 0
    """How many events had been delivered before the failure."""

    delivered_wire_end: int = 0
    """The wire offset up to which all events had been delivered."""


@dataclass(kw_only=True)
class EventBoundary:
    """
    Marks how far input processing had progressed with fully delivered events.

    Events are only counted once the frame that produced them has been handled
    successfully. A frame that raises is never counted, so undelivered events
    can never appear as executed actions.
    """

    delivered_event_count: int = 0
    """Total number of events returned to the caller so far."""

    delivered_wire_end: int = 0
    """Absolute wire offset through which every event has been delivered."""


@dataclass(kw_only=True)
class StateSnapshot:
    """
    The protocol state observed immediately before a failure.
    """

    connection_state: str
    """The name of the current :class:`~h2.connection.ConnectionState`."""

    highest_inbound_stream_id: int
    """The highest stream id initiated by the remote peer."""

    open_stream_count: int
    """The number of currently open streams."""

    active_header_block: WireRange | None = None
    """A header block still open when the failure occurred, if any."""


@dataclass(kw_only=True)
class ConnectionDiagnostics:
    """
    The structured diagnostic record for one connection.

    Available as :attr:`~h2.connection.H2Connection.diagnostics` only when the
    connection was created with ``enable_diagnostics=True``. It accumulates
    non-fatal observations (such as unknown extension frames) and, when input
    processing fails, the single fatal :class:`DiagnosticEntry` describing why.
    """

    entries: list[DiagnosticEntry] = field(default_factory=list)
    """All recorded observations and the terminal error, in order."""

    boundary: EventBoundary = field(default_factory=EventBoundary)
    """The current delivered-event boundary."""

    last_error: DiagnosticEntry | None = None
    """The fatal entry, if processing has already failed."""

    @property
    def errors(self) -> list[DiagnosticEntry]:
        """All fatal entries (at most one per connection)."""
        return [entry for entry in self.entries if entry.fatal]

    @property
    def observations(self) -> list[DiagnosticEntry]:
        """All non-fatal entries, such as unknown extension frames."""
        return [entry for entry in self.entries if not entry.fatal]

    def reset(self) -> None:
        """Clear every recorded entry and the delivered-event boundary."""
        self.entries.clear()
        self.boundary = EventBoundary()
        self.last_error = None


class _DiagnosticsRecorder:
    """
    Internal bridge that owns the public :class:`ConnectionDiagnostics` object
    and the byte-offset bookkeeping shared with the frame buffer.

    A single recorder instance is shared between the
    :class:`~h2.connection.H2Connection` and its
    :class:`~h2.frame_buffer.FrameBuffer`.
    """

    def __init__(self) -> None:
        self.diagnostics = ConnectionDiagnostics()

        #: Total number of wire bytes consumed so far, including the preamble.
        #: This is the origin for every absolute :class:`WireRange`.
        self.bytes_consumed = 0

        #: Start offset of an in-progress HEADERS/PUSH_PROMISE header block, or
        #: ``None`` when no block is open.
        self._block_start: int | None = None

    # -- wire offset bookkeeping -----------------------------------------

    def consume(self, size: int) -> None:
        """Account for ``size`` wire bytes that have been consumed."""
        self.bytes_consumed += size

    def mark_frame_span(self, frame: Frame, start: int, end: int) -> None:
        """Attach an absolute wire span to a parsed frame object."""
        setattr(frame, _WIRE_START_ATTR, start)
        setattr(frame, _WIRE_END_ATTR, end)

    def frame_start(self, frame: Frame) -> int | None:
        """Return the recorded start offset of ``frame``, if any."""
        return getattr(frame, _WIRE_START_ATTR, None)

    def frame_end(self, frame: Frame) -> int | None:
        """Return the recorded end offset of ``frame``, if any."""
        return getattr(frame, _WIRE_END_ATTR, None)

    # -- header block bookkeeping ----------------------------------------

    def begin_header_block(self, start: int) -> None:
        """Record the start of a HEADERS/PUSH_PROMISE header block."""
        self._block_start = start

    def end_header_block(self) -> None:
        """Mark the currently open header block as complete."""
        self._block_start = None

    def active_header_block(self, end: int | None = None) -> WireRange | None:
        """Return the range of an open header block, if one is in progress."""
        if self._block_start is None:
            return None
        return WireRange(start=self._block_start, end=self.bytes_consumed if end is None else end)

    # -- event boundary --------------------------------------------------

    def record_delivery(self, event_count: int, wire_end: int) -> None:
        """Advance the delivered-event boundary after a successful frame."""
        boundary = self.diagnostics.boundary
        boundary.delivered_event_count = event_count
        boundary.delivered_wire_end = wire_end

    # -- entries ---------------------------------------------------------

    def record_observation(self, entry: DiagnosticEntry) -> None:
        """Append a non-fatal observation."""
        self.entries_guard(entry)

    def record_fatal(self, entry: DiagnosticEntry) -> None:
        """Record the terminal error, keeping only the first fatal entry."""
        if self.diagnostics.last_error is not None:
            return
        entry.fatal = True
        self.diagnostics.last_error = entry
        self.entries_guard(entry)

    def entries_guard(self, entry: DiagnosticEntry) -> None:
        self.diagnostics.entries.append(entry)

    # -- snapshot --------------------------------------------------------

    def snapshot(
        self,
        connection_state: ConnectionState,
        highest_inbound_stream_id: int,
        open_stream_count: int,
    ) -> StateSnapshot:
        """Capture the pre-failure protocol state."""
        return StateSnapshot(
            connection_state=connection_state.name,
            highest_inbound_stream_id=highest_inbound_stream_id,
            open_stream_count=open_stream_count,
            active_header_block=self.active_header_block(),
        )


def summarize_frame(frame: Frame, declared_length: int, payload_length: int | None = None) -> FrameSummary:
    """
    Build a payload-free :class:`FrameSummary` from a parsed frame.

    Extension frames expose a raw flag byte rather than named flags, and their
    numeric type is preserved so unknown frames remain distinguishable.
    """
    if isinstance(frame, ExtensionFrame):
        return FrameSummary(
            frame_type=frame.type,
            stream_id=frame.stream_id,
            declared_length=declared_length,
            flags=(),
            flag_byte=frame.flag_byte,
            payload_length=frame.body_len if payload_length is None else payload_length,
        )

    return FrameSummary(
        frame_type=frame.type,
        stream_id=frame.stream_id,
        declared_length=declared_length,
        flags=tuple(sorted(frame.flags)),
        payload_length=frame.body_len if payload_length is None else payload_length,
    )


@dataclass(kw_only=True)
class _FrameErrorContext:
    """Framing-level failure context carried on an exception by the buffer."""

    category: str
    summary: FrameSummary
    frame_range: WireRange
    message: str
    header_block_range: WireRange | None = None


def attach_frame_error(exc: BaseException, context: _FrameErrorContext) -> None:
    """Attach framing-level error context to an exception."""
    setattr(exc, _FRAME_ERROR_ATTR, context)


def frame_error(exc: BaseException) -> _FrameErrorContext | None:
    """Return framing-level error context attached to ``exc``, if present."""
    context: Any = getattr(exc, _FRAME_ERROR_ATTR, None)
    return context if isinstance(context, _FrameErrorContext) else None


def wire_range_of(frame: Frame) -> WireRange | None:
    """Return the recorded wire span of ``frame``, if it was annotated."""
    start = getattr(frame, _WIRE_START_ATTR, None)
    end = getattr(frame, _WIRE_END_ATTR, None)
    if start is None or end is None:
        return None
    return WireRange(start=start, end=end)
