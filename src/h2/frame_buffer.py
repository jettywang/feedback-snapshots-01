"""
h2/frame_buffer
~~~~~~~~~~~~~~~

A data structure that provides a way to iterate over a byte buffer in terms of
frames.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from hyperframe.exceptions import InvalidDataError, InvalidFrameError, InvalidPaddingError
from hyperframe.frame import ContinuationFrame, Frame, HeadersFrame, PushPromiseFrame

from .exceptions import FrameDataMissingError, FrameTooLargeError, ProtocolError

if TYPE_CHECKING:  # pragma: no cover
    from ._typing import Buffer

# To avoid a DOS attack based on sending loads of continuation frames, we limit
# the maximum number we're prepared to receive. In this case, we'll set the
# limit to 64, which means the largest encoded header block we can receive by
# default is 262144 bytes long, and the largest possible *at all* is 1073741760
# bytes long.
#
# This value seems reasonable for now, but in future we may want to evaluate
# making it configurable.
CONTINUATION_BACKLOG = 64

# A borrowed view keeps its entire backing object alive, even if only a small
# incomplete frame remains. When the rest of that object is at least this large,
# and copying the remainder is cheaper than the memory it releases, the
# remainder is copied so the larger object can be collected.
MAX_RETAINED_BACKING_SLACK = 64 * 1024


def _release_traceback(exc: BaseException) -> None:
    """
    Drop tracebacks that may reference a view of caller-owned memory.

    ``hyperframe`` parses frame bodies from a ``memoryview``. If parsing raises,
    its traceback keeps that view (and slices of it) alive. A live view exports
    the underlying ``bytearray``, preventing the caller from resizing or
    deleting it. The exception object itself is still chained, but its frames
    no longer pin the caller's buffer.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        current.__traceback__ = None
        current = current.__cause__ if current.__cause__ is not None else current.__context__


def _payload_size(frame: Frame) -> int:
    """Bytes hyperframe materialised as owned frame payload."""
    total = 0
    for attribute in ("data", "body", "opaque_data", "additional_data", "origin", "field"):
        value = getattr(frame, attribute, None)
        if isinstance(value, bytes | bytearray | memoryview):
            total += len(value)
    return total


@dataclass(frozen=True)
class FrameBufferStats:
    """
    A snapshot of the input-ownership decisions made by a frame buffer.

    The counters describe input staging only. ``hyperframe`` materialises each
    parsed frame payload as an owned ``bytes`` object so that events can never
    alias caller memory; those allocations are reported separately as payload
    copies.

    .. versionadded:: 4.5.0
    """

    received_bytes: int
    """Total wire bytes passed to :meth:`FrameBuffer.add_data`."""

    preamble_bytes: int
    """Bytes consumed as the HTTP/2 connection preamble."""

    borrowed_immutable_bytes: int
    """
    Frame bytes parsed directly from an immutable caller-owned object without
    staging a copy.
    """

    borrowed_mutable_bytes: int
    """
    Frame bytes parsed directly from a caller-mutable buffer during a
    synchronous receive cycle. Such a borrow never survives the cycle.
    """

    copied_input_bytes: int
    """Bytes copied into h2-owned input storage."""

    copy_operations: int
    """Number of input-copy operations."""

    payload_copy_bytes: int
    """Bytes copied to detach parsed frame payloads from the input buffer."""

    payload_copy_operations: int
    """Number of payload-detach copy operations."""

    retained_input_bytes: int
    """Logical bytes currently buffered for an incomplete frame."""

    retained_backing_bytes: int
    """
    Size of the backing object kept alive by the buffered input. For an owned
    buffer this equals the retained input; for a borrowed view it is the size
    of the root object, which can be much larger.
    """

    @property
    def borrowed_bytes(self) -> int:
        """Total bytes parsed without an input copy."""
        return self.borrowed_immutable_bytes + self.borrowed_mutable_bytes


class FrameBuffer:
    """
    A buffer data structure for HTTP/2 data that allows iteration in terms of
    H2 frames.

    Input ownership
    ---------------

    :meth:`add_data` either borrows the supplied bytes or copies them:

    * A read-only, one-dimensional, contiguous view whose root object is
      ``bytes`` cannot change for as long as the view exists. It is safe to
      parse frames directly from it, so such input is *borrowed* without a
      copy. The read-only flag alone is not enough: a read-only view over a
      ``bytearray`` still changes when another reference mutates that
      ``bytearray``, so it is copied.
    * By default every caller-mutable input is *copied* before
      :meth:`add_data` returns, because lazy iteration through a
      :class:`FrameBuffer` cannot assume the caller will keep the buffer
      stable. Only the exposed view is copied, never its whole backing object:
      a small slice of a large buffer neither copies nor retains the rest.
    * Views with a non-byte item format or a non-contiguous layout are copied
      from their logical byte representation so frame offsets stay
      unambiguous. C-contiguous views are flattened without copying.
    * ``borrow=True`` is reserved for a synchronous receive cycle that drains
      the buffer and calls :meth:`_finish_receive` before returning. Only then
      may caller-mutable input be parsed in place. Any unparsed remainder is
      copied into h2-owned storage before the caller can touch its buffer
      again, including on error paths. This is what
      :meth:`H2Connection.receive_data
      <h2.connection.H2Connection.receive_data>` does.

    Frame payloads are always materialised as owned ``bytes`` before events
    are returned. In particular, mutating or resizing a ``bytearray`` supplied
    to ``receive_data`` cannot change a :class:`DataReceived
    <h2.events.DataReceived>` event that has already been delivered, nor an
    incomplete frame prefix retained for the next call.

    When a cycle ends with an incomplete frame, retained memory is bounded to
    that suffix. If a borrowed view pins a much larger backing object, the
    suffix is copied so the larger object can be freed.
    """

    def __init__(self, server: bool = False) -> None:
        # Either h2-owned storage (bytearray) or a memoryview over borrowed or
        # h2-owned immutable bytes. ``_start`` marks the consumed prefix.
        self._data: bytearray | memoryview = bytearray()
        self._start = 0

        # ``_transient`` marks a view over caller-mutable memory that is only
        # valid for the current synchronous receive cycle.
        self._transient = False

        # ``_owned_view`` marks a view over a private copy of input bytes.
        self._owned_view = False

        # Backing size of a transient borrow. The view may expose a small
        # slice, while its root object is much larger.
        self._held_caller_bytes = 0

        self.max_frame_size = 0
        self._preamble = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" if server else b""
        self._preamble_len = len(self._preamble)
        self._headers_buffer: list[HeadersFrame | ContinuationFrame | PushPromiseFrame] = []

        self._received_bytes = 0
        self._preamble_bytes = 0
        self._borrowed_immutable_bytes = 0
        self._borrowed_mutable_bytes = 0
        self._copied_input_bytes = 0
        self._copy_operations = 0
        self._payload_copy_bytes = 0
        self._payload_copy_operations = 0

    @property
    def stats(self) -> FrameBufferStats:
        """A snapshot of the buffer's copy and retention counters."""
        return FrameBufferStats(
            received_bytes=self._received_bytes,
            preamble_bytes=self._preamble_bytes,
            borrowed_immutable_bytes=self._borrowed_immutable_bytes,
            borrowed_mutable_bytes=self._borrowed_mutable_bytes,
            copied_input_bytes=self._copied_input_bytes,
            copy_operations=self._copy_operations,
            payload_copy_bytes=self._payload_copy_bytes,
            payload_copy_operations=self._payload_copy_operations,
            retained_input_bytes=self._pending(),
            retained_backing_bytes=self._retained_backing_bytes(),
        )

    def _pending(self) -> int:
        return len(self._data) - self._start

    def _record_copy(self, size: int) -> None:
        if size:
            self._copied_input_bytes += size
            self._copy_operations += 1

    def _record_payload_copy(self, size: int) -> None:
        if size:
            self._payload_copy_bytes += size
            self._payload_copy_operations += 1

    @staticmethod
    def _root(view: memoryview) -> object:
        root: object = view.obj
        while isinstance(root, memoryview):
            root = root.obj
        return root

    @classmethod
    def _is_immutable_view(cls, view: memoryview) -> bool:
        """
        Whether the view exposes memory that cannot change through any other
        reference. A read-only view over a mutable object is not sufficient.
        """
        return view.readonly and isinstance(cls._root(view), bytes)

    @classmethod
    def _backing_bytes(cls, view: memoryview) -> int:
        root = cls._root(view)
        nbytes = getattr(root, "nbytes", None)
        if isinstance(nbytes, int):
            return nbytes
        itemsize = getattr(root, "itemsize", 1)
        if not isinstance(itemsize, int):
            itemsize = 1
        try:
            return len(root) * itemsize  # type: ignore[arg-type]
        except TypeError:  # pragma: no cover - custom buffer exporters
            # PEP 688 exporters are wrapped in an opaque object without
            # ``len``; the view's own byte count is the best available bound.
            return view.nbytes

    @staticmethod
    def _normalise(view: memoryview) -> tuple[memoryview, int]:
        """
        Return a one-dimensional, byte-oriented, contiguous view.

        The second item is the number of bytes copied to achieve that, or zero
        if the input was already usable as-is.
        """
        if view.ndim == 1 and view.itemsize == 1 and view.c_contiguous:
            return view, 0
        if view.c_contiguous:
            try:
                return view.cast("B"), 0
            except (TypeError, ValueError):  # pragma: no cover - defensive
                pass
        raw = view.tobytes()
        return memoryview(raw), len(raw)

    def _retained_backing_bytes(self) -> int:
        pending = self._pending()
        if pending == 0:
            return 0
        data = self._data
        if isinstance(data, bytearray):
            return len(data)
        if self._transient:
            return self._held_caller_bytes
        return self._backing_bytes(data)

    def add_data(self, data: Buffer, *, borrow: bool = False) -> None:
        """
        Add more data to the frame buffer.

        :param data: An object implementing the buffer protocol.
        :param borrow: Permit a caller-mutable buffer to be parsed in place
            until :meth:`_finish_receive` is called. Only a caller that drains
            the buffer synchronously and finishes it before returning may
            enable this. Immutable byte views are borrowed regardless.
        """
        view = memoryview(data)
        self._received_bytes += view.nbytes

        view, normalised_copy = self._normalise(view)
        self._record_copy(normalised_copy)

        if self._preamble_len:
            data_len = len(view)
            of_which_preamble = min(self._preamble_len, data_len)

            if self._preamble[:of_which_preamble] != view[:of_which_preamble]:
                # Do not leave an exported view behind if the caller inspects
                # the failure and then reuses its buffer.
                del view
                msg = "Invalid HTTP/2 preamble."
                raise ProtocolError(msg)

            view = view[of_which_preamble:]
            self._preamble_len -= of_which_preamble
            self._preamble = self._preamble[of_which_preamble:]
            self._preamble_bytes += of_which_preamble

        if not len(view):
            del view
            return

        if self._pending():
            self._join(view)
        else:
            self._adopt(view, borrow=borrow, normalised=bool(normalised_copy))

    def _adopt(self, view: memoryview, *, borrow: bool, normalised: bool) -> None:
        """Take ownership of a view when no earlier bytes are pending."""
        self._start = 0
        self._held_caller_bytes = 0
        if normalised:
            # ``_normalise`` already copied the bytes into h2-owned memory.
            self._data = view
            self._transient = False
            self._owned_view = True
        elif self._is_immutable_view(view):
            self._data = view
            self._transient = False
            self._owned_view = False
        elif borrow:
            # Valid only until ``_finish_receive`` copies any remainder.
            self._data = view
            self._transient = True
            self._owned_view = False
            self._held_caller_bytes = self._backing_bytes(view)
        else:
            copied = bytearray(view)
            self._record_copy(len(copied))
            self._data = copied
            self._transient = False
            self._owned_view = False

    def _join(self, view: memoryview) -> None:
        """
        Join new input with a pending incomplete frame.

        A frame split across calls must become one contiguous owned buffer.
        Only bytes that are actually pending and newly supplied are copied.
        """
        pending = self._pending()
        owned = self._data
        if isinstance(owned, bytearray):
            if self._start:
                # ``del s[i:j]`` mutates in place; no copy of the remainder and
                # no exported view is alive at this point.
                del owned[:self._start]
                self._start = 0
            owned += view
            self._record_copy(len(view))
        else:
            combined = bytearray(owned[self._start:])
            self._record_copy(pending)
            combined += view
            self._record_copy(len(view))
            self._data = combined
            self._start = 0
        self._transient = False
        self._owned_view = False
        self._held_caller_bytes = 0

    def _drop(self) -> None:
        """Release all buffered input."""
        self._data = bytearray()
        self._start = 0
        self._transient = False
        self._owned_view = False
        self._held_caller_bytes = 0

    def _copy_suffix(self) -> None:
        """Copy the pending suffix into h2-owned storage and release the view."""
        source = self._data
        assert not isinstance(source, bytearray)
        pending_view = source[self._start:]
        copied = bytearray(pending_view)
        del pending_view
        self._record_copy(len(copied))
        self._data = copied
        self._start = 0
        self._transient = False
        self._owned_view = False
        self._held_caller_bytes = 0

    def _bound_retention(self) -> None:
        """
        Copy a small suffix away from a much larger backing object.

        Copying costs ``pending`` bytes and can release ``backing - pending``.
        Do it only when the released memory is both substantial and larger than
        the copy, so honest large buffers are not copied needlessly.
        """
        pending = self._pending()
        data = self._data
        assert not isinstance(data, bytearray)
        backing = self._backing_bytes(data)
        saved = backing - pending
        if saved <= MAX_RETAINED_BACKING_SLACK or pending >= saved:
            return
        self._copy_suffix()

    def _compact(self) -> None:
        """
        Drop consumed bytes and release views that must not be retained.

        Called when iteration stops and when a connection ends a receive
        cycle, including error paths.
        """
        pending = self._pending()
        if not pending:
            self._drop()
            return
        owned = self._data
        if isinstance(owned, bytearray):
            if self._start:
                del owned[:self._start]
                self._start = 0
            return
        if self._transient:
            # Caller-mutable memory must never outlive the receive cycle.
            self._copy_suffix()
            return
        self._bound_retention()

    def _finish_receive(self, *, discard: bool = False) -> None:
        """
        End a synchronous receive cycle.

        Idempotent, and safe to call on success and error paths. After this
        returns the caller may reuse, overwrite, resize, or delete the buffer
        it supplied to :meth:`add_data`.

        :param discard: Drop buffered input instead of preserving an
            incomplete suffix. Used after a fatal protocol error, where the
            connection is unusable.
        """
        if discard:
            self._drop()
            self._headers_buffer = []
            return
        self._compact()

    def _validate_frame_length(self, length: int) -> None:
        """Confirm that the frame is an appropriate length."""
        if length > self.max_frame_size:
            msg = f"Received overlong frame: length {length}, max {self.max_frame_size}"
            raise FrameTooLargeError(msg)

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
                raise ProtocolError(msg)
            assert isinstance(f, ContinuationFrame)

            # Append the frame to the buffer.
            self._headers_buffer.append(f)
            if len(self._headers_buffer) > CONTINUATION_BACKLOG:
                msg = "Too many continuation frames received."
                raise ProtocolError(msg)

            # If this is the end of the header block, then we want to build a
            # mutant HEADERS frame that's massive. Use the original one we got,
            # then set END_HEADERS and set its data appropriately. If it's not
            # the end of the block, lose the current frame: we can't yield it.
            if "END_HEADERS" in f.flags:
                f = self._headers_buffer[0]
                f.flags.add("END_HEADERS")
                f.data = b"".join(x.data for x in self._headers_buffer)
                self._record_payload_copy(len(f.data))
                self._headers_buffer = []
            else:
                f = None
        elif (isinstance(f, (HeadersFrame, PushPromiseFrame)) and
                "END_HEADERS" not in f.flags):
            # This is the start of a headers block! Save the frame off and then
            # act like we didn't receive one.
            self._headers_buffer.append(f)
            f = None

        return f

    def _parse_next(self) -> tuple[Frame, int] | None:
        """
        Parse the frame at the current offset.

        Returns ``(frame, end_offset)``, or ``None`` when the buffered data
        does not yet contain a complete frame. The export is released before
        returning, so callers may mutate owned storage in place.
        """
        view = memoryview(self._data)
        try:
            start = self._start
            available = len(view) - start
            if available < 9:
                return None

            try:
                frame, length = Frame.parse_frame_header(view[start:start + 9])
            except (InvalidDataError, InvalidFrameError) as err:
                _release_traceback(err)
                msg = f"Received frame with invalid header: {err!s}"
                raise ProtocolError(msg) from err

            if available < length + 9:
                return None

            self._validate_frame_length(length)
            try:
                frame.parse_body(view[start + 9:start + 9 + length])
            except InvalidPaddingError as err:
                _release_traceback(err)
                raise
            except InvalidDataError as err:
                _release_traceback(err)
                msg = "Received frame with non-compliant data"
                raise ProtocolError(msg) from err
            except InvalidFrameError as err:
                _release_traceback(err)
                msg = "Frame data missing or invalid"
                raise FrameDataMissingError(msg) from err
            return frame, start + 9 + length
        finally:
            # An exported bytearray cannot be resized by its owner. Drop the
            # export on every path, including errors kept in a traceback.
            del view

    # The methods below support the iterator protocol.
    def __iter__(self) -> FrameBuffer:
        return self

    def __next__(self) -> Frame:
        while True:
            parsed = self._parse_next()
            if parsed is None:
                self._compact()
                raise StopIteration

            frame, end_offset = parsed
            span = end_offset - self._start
            if isinstance(self._data, memoryview) and not self._owned_view:
                if self._transient:
                    self._borrowed_mutable_bytes += span
                else:
                    self._borrowed_immutable_bytes += span
            self._record_payload_copy(_payload_size(frame))

            # We know we'll use or discard the entire frame, so advance past
            # it. In-place deletion keeps a bytearray's amortized left-delete
            # behavior; a borrowed view only moves an offset.
            self._start = end_offset
            owned = self._data
            if self._start == len(owned):
                self._drop()
            elif isinstance(owned, bytearray):
                del owned[:self._start]
                self._start = 0

            new_frame = self._update_header_buffer(frame)
            if new_frame is not None:
                return new_frame
            # Otherwise try the next frame in the same buffer.
