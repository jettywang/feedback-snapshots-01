"""
h2/frame_buffer
~~~~~~~~~~~~~~~

A data structure that provides a way to iterate over a byte buffer in terms of
frames.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from hyperframe.exceptions import InvalidDataError, InvalidFrameError, InvalidPaddingError
from hyperframe.frame import ContinuationFrame, Frame, HeadersFrame, PushPromiseFrame

from . import diagnostics as _diag
from .exceptions import FrameDataMissingError, FrameTooLargeError, ProtocolError

if TYPE_CHECKING:  # pragma: no cover
    from ._typing import Buffer
    from .diagnostics import _DiagnosticsRecorder

# To avoid a DOS attack based on sending loads of continuation frames, we limit
# the maximum number we're prepared to receive. In this case, we'll set the
# limit to 64, which means the largest encoded header block we can receive by
# default is 262144 bytes long, and the largest possible *at all* is 1073741760
# bytes long.
#
# This value seems reasonable for now, but in future we may want to evaluate
# making it configurable.
CONTINUATION_BACKLOG = 64


class FrameBuffer:
    """
    A buffer data structure for HTTP/2 data that allows iteration in terms of
    H2 frames.
    """

    def __init__(self, server: bool = False, recorder: _DiagnosticsRecorder | None = None) -> None:
        self._data = bytearray()
        self.max_frame_size = 0
        self._preamble = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" if server else b""
        self._preamble_len = len(self._preamble)
        self._headers_buffer: list[HeadersFrame | ContinuationFrame | PushPromiseFrame] = []

        #: The frame currently being parsed. Retained so that a failure raised
        #: while parsing its body (e.g. invalid padding) can still be attributed
        #: to a concrete frame by the connection's diagnostic layer.
        self._frame_in_progress: Frame | None = None

        #: Optional diagnostics recorder. When present it owns the absolute
        #: wire-offset bookkeeping; when absent all diagnostic paths are inert.
        self._recorder = recorder

    def add_data(self, data: Buffer) -> None:
        """
        Add more data to the frame buffer.

        :param data: A bytestring containing the byte buffer.
        """
        data_view = memoryview(data)

        if self._preamble_len:
            data_len = len(data_view)
            of_which_preamble = min(self._preamble_len, data_len)

            if self._preamble[:of_which_preamble] != data_view[:of_which_preamble]:
                msg = "Invalid HTTP/2 preamble."
                err = ProtocolError(msg)
                self._record_preamble_error(err, of_which_preamble)
                raise err

            data_view = data_view[of_which_preamble:]
            self._preamble_len -= of_which_preamble
            self._preamble = self._preamble[of_which_preamble:]
            self._consume(of_which_preamble)

        self._data += data_view

    def _consume(self, size: int) -> None:
        """Account for wire bytes that have been consumed, if recording."""
        if self._recorder is not None:
            self._recorder.consume(size)

    def _record_preamble_error(self, err: ProtocolError, matched: int) -> None:
        """Attach preamble failure context, pointing at the bad wire bytes."""
        if self._recorder is None:
            return
        start = self._recorder.bytes_consumed
        context = _diag._FrameErrorContext(
            category=_diag.CATEGORY_PREAMBLE_ERROR,
            summary=_diag.FrameSummary(
                frame_type=None,
                stream_id=None,
                declared_length=0,
                payload_length=matched,
            ),
            frame_range=_diag.WireRange(start=start, end=start + matched),
            message=str(err),
        )
        _diag.attach_frame_error(err, context)

    def _validate_frame_length(self, length: int, frame: Frame, start: int) -> None:
        """
        Confirm that the frame is an appropriate length.
        """
        if length > self.max_frame_size:
            msg = f"Received overlong frame: length {length}, max {self.max_frame_size}"
            err = FrameTooLargeError(msg)
            self._record_frame_error(
                err,
                category=_diag.CATEGORY_LENGTH_ERROR,
                frame=frame,
                declared_length=length,
                payload_length=None,
                start=start,
                end=start + 9,
                message=msg,
            )
            raise err

    def _update_header_buffer(self, f: Frame | None) -> Frame | None:
        """
        Updates the internal header buffer. Returns a frame that should replace
        the current one. May throw exceptions if this frame is invalid.
        """
        # Check if we're in the middle of a headers block. If we are, this
        # frame *must* be a CONTINUATION frame with the same stream ID as the
        # leading HEADERS or PUSH_PROMISE frame. Anything else is a
        # ProtocolError. If the frame *is* valid, append it to the header
        # buffer.
        if self._headers_buffer:
            stream_id = self._headers_buffer[0].stream_id
            valid_frame = (
                f is not None and
                isinstance(f, ContinuationFrame) and
                f.stream_id == stream_id
            )
            if not valid_frame:
                msg = "Invalid frame during header block."
                err = ProtocolError(msg)
                self._record_header_block_failure(err, f, msg)
                raise err
            assert isinstance(f, ContinuationFrame)

            # Append the frame to the buffer.
            self._headers_buffer.append(f)
            if len(self._headers_buffer) > CONTINUATION_BACKLOG:
                msg = "Too many continuation frames received."
                err = ProtocolError(msg)
                self._record_header_block_failure(err, f, msg)
                raise err

            # If this is the end of the header block, then we want to build a
            # mutant HEADERS frame that's massive. Use the original one we got,
            # then set END_HEADERS and set its data appropriately. If it's not
            # the end of the block, lose the current frame: we can't yield it.
            if "END_HEADERS" in f.flags:
                f = self._headers_buffer[0]
                f.flags.add("END_HEADERS")
                f.data = b"".join(x.data for x in self._headers_buffer)
                self._headers_buffer = []
                self._finish_header_block(f)
            else:
                f = None
        elif (isinstance(f, (HeadersFrame, PushPromiseFrame)) and
                "END_HEADERS" not in f.flags):
            # This is the start of a headers block! Save the frame off and then
            # act like we didn't receive one.
            self._headers_buffer.append(f)
            self._begin_header_block(f)
            f = None

        return f

    def _begin_header_block(self, frame: Frame) -> None:
        """Mark the start of a header block at the frame's wire offset."""
        if self._recorder is None:
            return
        start = self._recorder.frame_start(frame)
        if start is not None:
            self._recorder.begin_header_block(start)

    def _finish_header_block(self, merged: Frame) -> None:
        """
        Close out an open header block and extend the merged frame's wire span
        to cover the full HEADERS/CONTINUATION sequence.
        """
        if self._recorder is None:
            return
        block = self._recorder.active_header_block()
        self._recorder.end_header_block()
        if block is not None:
            start = self._recorder.frame_start(merged)
            self._recorder.mark_frame_span(
                merged,
                start if start is not None else block.start,
                block.end,
            )

    def _record_header_block_failure(self, err: ProtocolError, frame: Frame | None, message: str) -> None:
        """Record a state error that interrupts an in-progress header block."""
        if self._recorder is None:
            return
        block = self._recorder.active_header_block()
        if frame is not None:
            start = self._recorder.frame_start(frame)
            end = self._recorder.frame_end(frame)
            declared = getattr(frame, "body_len", 0)
            if start is not None and end is not None:
                self._record_frame_error(
                    err,
                    category=_diag.CATEGORY_STATE_ERROR,
                    frame=frame,
                    declared_length=declared,
                    payload_length=declared,
                    start=start,
                    end=end,
                    message=message,
                    header_block_range=block,
                )
                return
        context = _diag._FrameErrorContext(
            category=_diag.CATEGORY_STATE_ERROR,
            summary=_diag.FrameSummary(
                frame_type=getattr(frame, "type", None),
                stream_id=getattr(frame, "stream_id", None),
                declared_length=0,
            ),
            frame_range=block or _diag.WireRange(
                start=self._recorder.bytes_consumed,
                end=self._recorder.bytes_consumed,
            ),
            message=message,
            header_block_range=block,
        )
        _diag.attach_frame_error(err, context)

    def _record_frame_error(
        self,
        err: ProtocolError,
        *,
        category: str,
        frame: Frame,
        declared_length: int,
        payload_length: int | None,
        start: int,
        end: int,
        message: str,
        header_block_range: _diag.WireRange | None = None,
    ) -> None:
        """Attach a payload-free frame summary and wire range to an error."""
        if self._recorder is None:
            return
        context = _diag._FrameErrorContext(
            category=category,
            summary=_diag.summarize_frame(frame, declared_length, payload_length),
            frame_range=_diag.WireRange(start=start, end=end),
            message=message,
            header_block_range=header_block_range,
        )
        _diag.attach_frame_error(err, context)

    # The methods below support the iterator protocol.
    def __iter__(self) -> FrameBuffer:
        return self

    def __next__(self) -> Frame:
        # First, check that we have enough data to successfully parse the
        # next frame header. If not, bail. Otherwise, parse it.
        if len(self._data) < 9:
            raise StopIteration

        # Absolute wire offset at which this frame begins. This is independent
        # of how the caller chunked the data, so it stays stable across splits.
        frame_start = self._recorder.bytes_consumed if self._recorder is not None else 0

        try:
            f, length = Frame.parse_frame_header(memoryview(self._data[:9]))
        except (InvalidDataError, InvalidFrameError) as err:  # pragma: no cover
            msg = f"Received frame with invalid header: {err!s}"
            protocol_err = ProtocolError(msg)
            self._record_unparsable_frame(protocol_err, frame_start, msg)
            raise protocol_err from err

        # Next, check that we have enough length to parse the frame body. If
        # not, bail, leaving the frame header data in the buffer for next time.
        if len(self._data) < length + 9:
            raise StopIteration

        # Confirm the frame has an appropriate length.
        self._validate_frame_length(length, f, frame_start)
        self._frame_in_progress = f

        frame_end = frame_start + 9 + length
        # Annotate the span before parsing the body so that a body parse error
        # (including invalid padding, which the connection re-raises) still
        # points at the full frame range.
        if self._recorder is not None:
            self._recorder.mark_frame_span(f, frame_start, frame_end)

        # Try to parse the frame body
        try:
            f.parse_body(memoryview(self._data[9:9+length]))
        except InvalidDataError as err:
            msg = "Received frame with non-compliant data"
            protocol_err = ProtocolError(msg)
            self._record_frame_error(
                protocol_err,
                category=_diag.CATEGORY_STATE_ERROR,
                frame=f,
                declared_length=length,
                payload_length=length,
                start=frame_start,
                end=frame_end,
                message=msg,
                header_block_range=self._active_block_range(),
            )
            raise protocol_err from err
        except InvalidFrameError as err:
            msg = "Frame data missing or invalid"
            frame_err = FrameDataMissingError(msg)
            self._record_frame_error(
                frame_err,
                category=_diag.CATEGORY_LENGTH_ERROR,
                frame=f,
                declared_length=length,
                payload_length=length,
                start=frame_start,
                end=frame_end,
                message=msg,
                header_block_range=self._active_block_range(),
            )
            raise frame_err from err
        except InvalidPaddingError:
            # Invalid padding is converted into a ProtocolError by the
            # connection layer. The frame span was already annotated above, so
            # simply propagate the original exception unchanged.
            raise

        # At this point, as we know we'll use or discard the entire frame, we
        # can update the data.
        # Deleting the consumed prefix mutates the bytearray in place instead
        # of copying the remaining bytes into a new object, as slicing would.
        # ``del s[i:j]`` is documented for mutable sequences in
        # https://docs.python.org/3/library/stdtypes.html#mutable-sequence-types
        # and CPython's bytearray tracks an internal offset (``ob_start`` in
        # Objects/bytearrayobject.c) that makes repeated deletes from the
        # front amortized O(1) per byte rather than O(len) per frame.
        del self._data[:9+length]
        self._consume(9 + length)

        # Pass the frame through the header buffer.
        new_frame = self._update_header_buffer(f)
        self._frame_in_progress = None

        # If we got a frame we didn't understand or shouldn't yield, rather
        # than return None it'd be better if we just tried to get the next
        # frame in the sequence instead. Recurse back into ourselves to do
        # that. This is safe because the amount of work we have to do here is
        # strictly bounded by the length of the buffer.
        return new_frame if new_frame is not None else self.__next__()

    def _active_block_range(self) -> _diag.WireRange | None:
        """Return the open header block range, if recording and one is open."""
        if self._recorder is None:
            return None
        return self._recorder.active_header_block()

    def _record_unparsable_frame(self, err: ProtocolError, start: int, message: str) -> None:
        """Record a frame whose nine-byte header itself could not be parsed."""
        if self._recorder is None:
            return
        context = _diag._FrameErrorContext(
            category=_diag.CATEGORY_LENGTH_ERROR,
            summary=_diag.FrameSummary(
                frame_type=None,
                stream_id=None,
                declared_length=0,
                payload_length=len(self._data),
            ),
            frame_range=_diag.WireRange(start=start, end=start + min(9, len(self._data))),
            message=message,
            header_block_range=self._active_block_range(),
        )
        _diag.attach_frame_error(err, context)
