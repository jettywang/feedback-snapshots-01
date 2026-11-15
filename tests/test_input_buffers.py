"""
Tests for the ownership rules applied to HTTP/2 input buffers.

The receive path must reduce copying without ever letting a caller's later
modification of a reusable network buffer change bytes that were already
parsed, buffered, or delivered in an event. These tests cover immutable
borrowing, mandatory copies for lazy mutable input, fragmented frames, header
blocks spanning several ``receive_data`` calls, offset ``memoryview`` inputs,
retention limits, and a gateway authorisation callback that overwrites the
source buffer between checking and consuming a request.
"""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.frame_buffer
import array
import pytest
from hyperframe.frame import ContinuationFrame, DataFrame, HeadersFrame

PREAMBLE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
REQUEST_HEADERS = [
    (b":method", b"POST"),
    (b":path", b"/submit"),
    (b":authority", b"example.com"),
    (b":scheme", b"https"),
]


def server_connection(*, borrow: bool = True) -> h2.connection.H2Connection:
    return h2.connection.H2Connection(
        config=h2.config.H2Configuration(
            client_side=False,
            receive_buffer_borrowing=borrow,
        ),
    )


def request_frames(
    frame_factory,
    body: bytes,
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
    end_stream: bool = True,
) -> list[bytes]:
    headers_frame = frame_factory.build_headers_frame(
        headers or REQUEST_HEADERS,
        stream_id=1,
    )
    frames = [headers_frame.serialize()]
    if body:
        frames.append(
            frame_factory.build_data_frame(
                body,
                stream_id=1,
                flags=["END_STREAM"] if end_stream else [],
            ).serialize(),
        )
    return frames


def request_wire(
    frame_factory,
    body: bytes,
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
    end_stream: bool = True,
) -> bytes:
    return b"".join(
        request_frames(
            frame_factory,
            body,
            headers=headers,
            end_stream=end_stream,
        ),
    )


def data_events(events: list[h2.events.Event]) -> list[h2.events.DataReceived]:
    return [event for event in events if isinstance(event, h2.events.DataReceived)]


class TestBorrowAndCopyPolicy:
    def test_immutable_bytes_input_is_not_copied(self, frame_factory) -> None:
        """
        A ``bytes`` receive buffer is immutable, so its frames are parsed by
        borrowing rather than copying the input.
        """
        wire = PREAMBLE + request_wire(frame_factory, b"payload")
        connection = server_connection()

        events = connection.receive_data(wire)
        stats = connection.incoming_buffer.stats

        assert data_events(events)[0].data == b"payload"
        assert stats.received_bytes == len(wire)
        assert stats.preamble_bytes == len(PREAMBLE)
        assert stats.borrowed_immutable_bytes == len(wire) - len(PREAMBLE)
        assert stats.copied_input_bytes == 0
        assert stats.copy_operations == 0
        assert stats.retained_input_bytes == 0
        assert stats.retained_backing_bytes == 0

    def test_mutable_input_is_borrowed_only_for_the_call(self, frame_factory) -> None:
        """
        A ``bytearray`` may be parsed in place while ``receive_data`` drains
        it, but that borrow must end before the call returns.
        """
        wire = PREAMBLE + request_wire(frame_factory, b"payload")
        receive_buffer = bytearray(wire)
        connection = server_connection()

        events = connection.receive_data(receive_buffer)
        stats = connection.incoming_buffer.stats

        assert data_events(events)[0].data == b"payload"
        assert stats.borrowed_mutable_bytes == len(wire) - len(PREAMBLE)
        assert stats.copied_input_bytes == 0
        assert stats.retained_input_bytes == 0
        assert stats.retained_backing_bytes == 0

        # The caller may immediately reuse the buffer.
        receive_buffer[:] = b"\x00" * len(receive_buffer)
        assert data_events(events)[0].data == b"payload"
        assert stats.retained_backing_bytes == 0

    def test_transient_borrow_reports_caller_backing(self, frame_factory) -> None:
        """
        While a mutable view is borrowed mid-iteration, the stats report the
        whole caller object as retained, including parts outside the view.
        """
        wire = request_wire(frame_factory, b"payload")
        backing = bytearray(b"X" * 65536 + wire)
        view = memoryview(backing)[65536:]
        buffer = h2.frame_buffer.FrameBuffer()
        buffer.max_frame_size = 65535
        buffer.add_data(view, borrow=True)

        # Before iteration the view is still held.
        assert buffer.stats.retained_backing_bytes == len(backing)

        list(buffer)
        buffer._finish_receive()
        assert buffer.stats.retained_backing_bytes == 0

    def test_frame_buffer_default_copies_mutable_input(self, frame_factory) -> None:
        """
        Lazy iteration through ``FrameBuffer.add_data`` cannot assume the
        caller will keep its buffer stable, so the default copies it up front.
        """
        wire = request_wire(frame_factory, b"payload")
        mutable = bytearray(wire)
        buffer = h2.frame_buffer.FrameBuffer()
        buffer.max_frame_size = 65535

        buffer.add_data(mutable)
        mutable[:] = b"\x00" * len(mutable)

        frames = list(buffer)
        assert [frame.data for frame in frames if isinstance(frame, DataFrame)] == [b"payload"]
        assert buffer.stats.copied_input_bytes == len(wire)

    def test_read_only_view_over_mutable_object_is_copied(self) -> None:
        """
        ``memoryview.readonly`` alone does not make input immutable: a
        read-only view over a bytearray changes when the bytearray changes.
        """
        wire = DataFrame(1, data=b"payload").serialize()
        backing = bytearray(wire)
        read_only = memoryview(backing).toreadonly()
        buffer = h2.frame_buffer.FrameBuffer()
        buffer.max_frame_size = 65535

        buffer.add_data(read_only)
        assert buffer.stats.copied_input_bytes == len(wire)
        backing[:] = b"\x00" * len(backing)

        [parsed] = list(buffer)
        assert parsed.data == b"payload"

    def test_offset_memoryview_copies_only_the_exposed_slice(self, frame_factory) -> None:
        """
        A small view over a large backing object must neither copy nor retain
        bytes outside the view.
        """
        wire = PREAMBLE + request_wire(frame_factory, b"payload")
        backing = bytearray(b"X" * 8192 + wire + b"Y" * 8192)
        view = memoryview(backing)[8192:8192 + len(wire)]
        connection = server_connection()

        events = connection.receive_data(view)
        stats = connection.incoming_buffer.stats

        assert data_events(events)[0].data == b"payload"
        assert stats.borrowed_mutable_bytes == len(wire) - len(PREAMBLE)
        assert stats.copied_input_bytes == 0
        assert stats.retained_input_bytes == 0
        assert stats.retained_backing_bytes == 0

        backing[:] = b"\x00" * len(backing)
        assert data_events(events)[0].data == b"payload"

    def test_non_byte_shaped_memoryview_is_normalised(self) -> None:
        """
        Views whose elements are not wire bytes, or that are multi-dimensional,
        are copied from their logical byte representation so frame offsets stay
        unambiguous.
        """
        wire = DataFrame(1, data=b"payload").serialize()

        two_dimensional = memoryview(bytearray(wire)).cast("B", shape=(len(wire), 1))
        buffer = h2.frame_buffer.FrameBuffer()
        buffer.max_frame_size = 65535
        buffer.add_data(two_dimensional)
        [parsed] = list(buffer)
        assert parsed.data == b"payload"
        assert buffer.stats.copied_input_bytes == len(wire)

        wide_items = memoryview(bytearray(wire + b"\x00" * (len(wire) % 2))).cast("H")
        wide_buffer = h2.frame_buffer.FrameBuffer()
        wide_buffer.max_frame_size = 65535
        wide_buffer.add_data(wide_items)
        assert wide_buffer.stats.copied_input_bytes == wide_items.nbytes

    def test_non_contiguous_view_is_copied(self) -> None:
        """
        A strided view has no unambiguous byte offsets. Its logical bytes are
        copied before parsing, so later writes to the backing object cannot
        alter the parsed frame.
        """
        wire = DataFrame(1, data=b"payload").serialize()
        # Interleave each wire byte with a filler byte.
        interleaved = bytearray(2 * len(wire))
        interleaved[::2] = wire
        view = memoryview(interleaved)[::2]
        assert not view.c_contiguous

        buffer = h2.frame_buffer.FrameBuffer()
        buffer.max_frame_size = 65535
        buffer.add_data(view)
        assert buffer.stats.copied_input_bytes == len(wire)

        interleaved[:] = b"\x00" * len(interleaved)
        [parsed] = list(buffer)
        assert parsed.data == b"payload"

    def test_multi_byte_item_view_reports_backing_in_bytes(self) -> None:
        """
        A wide view exposed for the borrow cycle reports its root object size
        in bytes, not in items, so retention is not underestimated.
        """
        wire = DataFrame(1, data=b"payload").serialize()
        backing = array.array("H", wire)
        view = memoryview(backing)
        buffer = h2.frame_buffer.FrameBuffer()
        buffer.max_frame_size = 65535

        buffer.add_data(view, borrow=True)
        assert buffer.stats.retained_backing_bytes == len(backing) * backing.itemsize

        list(buffer)
        buffer._finish_receive()
        assert buffer.stats.retained_backing_bytes == 0

    def test_byte_sized_item_view_keeps_wire_offsets(self) -> None:
        """
        A C-contiguous view with a single-byte item format and a different
        format character is flattened, not reinterpreted by item.
        """
        wire = DataFrame(1, data=b"payload").serialize()
        view = memoryview(array.array("B", wire))
        assert view.format == "B"
        assert view.itemsize == 1

        buffer = h2.frame_buffer.FrameBuffer()
        buffer.max_frame_size = 65535
        buffer.add_data(view)
        [parsed] = list(buffer)
        assert parsed.data == b"payload"
        assert buffer.stats.copied_input_bytes == len(wire)

    def test_disabling_borrowing_forces_mutable_copies(self, frame_factory) -> None:
        """
        The configuration switch retains correctness but copies mutable input
        eagerly.
        """
        wire = PREAMBLE + request_wire(frame_factory, b"payload")
        receive_buffer = bytearray(wire)
        connection = server_connection(borrow=False)

        events = connection.receive_data(receive_buffer)
        stats = connection.incoming_buffer.stats

        assert data_events(events)[0].data == b"payload"
        assert stats.borrowed_mutable_bytes == 0
        assert stats.copied_input_bytes == len(wire) - len(PREAMBLE)
        receive_buffer[:] = b"\x00" * len(receive_buffer)
        assert data_events(events)[0].data == b"payload"


class TestFragmentedInput:
    @pytest.mark.parametrize("split", [1, 2, 3, 5, 8, 13, 21, 34])
    def test_split_preamble_and_request_are_consistent(self, frame_factory, split) -> None:
        """
        Legal fragmentation of the same wire bytes yields one request with
        identical body bytes, even when each chunk uses a reused mutable
        buffer that is overwritten before the next call.
        """
        wire = PREAMBLE + request_wire(frame_factory, b"fragmented payload")
        connection = server_connection()
        events: list[h2.events.Event] = []

        chunk = bytearray()
        for start in range(0, len(wire), split):
            piece = wire[start:start + split]
            chunk[:] = piece
            events.extend(connection.receive_data(chunk))
            chunk[:] = b"\x00" * len(chunk)

        received = [event for event in events if isinstance(event, h2.events.RequestReceived)]
        bodies = b"".join(event.data for event in data_events(events))
        assert len(received) == 1
        assert received[0].headers == REQUEST_HEADERS
        assert bodies == b"fragmented payload"
        stats = connection.incoming_buffer.stats
        assert stats.retained_input_bytes == 0
        assert stats.retained_backing_bytes == 0

    def test_half_frame_survives_buffer_overwrite(self, frame_factory) -> None:
        """
        An incomplete frame's prefix is copied out of a mutable input before
        the caller can overwrite it.
        """
        connection = server_connection()
        headers = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        data_frame = frame_factory.build_data_frame(b"ABCDEFGHIJ", stream_id=1)
        wire = data_frame.serialize()

        first_events = connection.receive_data(PREAMBLE + headers.serialize() + wire[:7])
        assert len(first_events) == 1
        assert isinstance(first_events[0], h2.events.RequestReceived)

        first = bytearray(wire[7:12])
        assert connection.receive_data(first) == []
        first[:] = b"Z" * len(first)

        second = bytearray(wire[12:])
        events = connection.receive_data(second)
        second[:] = b"Z" * len(second)

        assert [event.data for event in data_events(events)] == [b"ABCDEFGHIJ"]
        assert connection.incoming_buffer.stats.retained_input_bytes == 0

    def test_header_block_across_receive_calls_uses_original_bytes(self, frame_factory) -> None:
        """
        A HEADERS frame split across calls must decode the bytes that were
        originally received, not a later overwrite of the first chunk.
        """
        frame_factory.refresh_encoder()
        request = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        wire = request.serialize()
        cut = len(wire) - 3
        connection = server_connection()
        connection.receive_data(PREAMBLE)

        first = bytearray(wire[:cut])
        assert connection.receive_data(first) == []
        first[:] = b"\x00" * len(first)

        events = connection.receive_data(bytearray(wire[cut:]))

        [request_event] = [event for event in events if isinstance(event, h2.events.RequestReceived)]
        assert request_event.headers == REQUEST_HEADERS

    def test_continuation_header_block_uses_original_fragments(self, frame_factory) -> None:
        """
        A header block spread over HEADERS and CONTINUATION frames delivered
        in separate calls keeps the originally received fragments.
        """
        frame_factory.refresh_encoder()
        full = frame_factory.build_headers_frame(REQUEST_HEADERS)
        block = full.data
        headers_frame = HeadersFrame(1)
        headers_frame.data = block[:7]
        continuation = ContinuationFrame(1)
        continuation.data = block[7:]
        continuation.flags.add("END_HEADERS")

        connection = server_connection()
        connection.receive_data(PREAMBLE)

        first = bytearray(headers_frame.serialize())
        assert connection.receive_data(first) == []
        first[:] = b"\x00" * len(first)

        events = connection.receive_data(bytearray(continuation.serialize()))

        [request_event] = [event for event in events if isinstance(event, h2.events.RequestReceived)]
        assert request_event.headers == REQUEST_HEADERS


class TestRetention:
    def test_small_incomplete_tail_does_not_pin_large_immutable_input(self, frame_factory) -> None:
        """
        A large immutable input with a tiny incomplete frame at the end may
        not keep the whole input alive.
        """
        connection = server_connection()
        headers = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        connection.receive_data(PREAMBLE + headers.serialize())
        filler = frame_factory.build_settings_frame({}, ack=True).serialize() * 8000
        next_frame = frame_factory.build_data_frame(b"B" * 50, stream_id=1)
        tail = next_frame.serialize()[:5]
        huge = bytes(filler + tail)
        assert len(huge) > h2.frame_buffer.MAX_RETAINED_BACKING_SLACK

        events = connection.receive_data(huge)
        assert len(events) == 8000

        stats = connection.incoming_buffer.stats
        assert stats.retained_input_bytes == len(tail)
        assert stats.retained_backing_bytes == len(tail)

        # The incomplete suffix is still the originally received bytes.
        events = connection.receive_data(bytearray(next_frame.serialize()[5:]))
        assert data_events(events)[0].data == b"B" * 50

    def test_offset_view_does_not_retain_large_backing(self, frame_factory) -> None:
        """
        A small view at an offset into a large mutable object must not pin the
        backing object when only a few bytes remain unparsed.
        """
        connection = server_connection()
        headers = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        data_frame = frame_factory.build_data_frame(b"A" * 50, stream_id=1)
        next_frame = frame_factory.build_data_frame(b"B" * 20, stream_id=1)
        wire = PREAMBLE + headers.serialize() + data_frame.serialize()
        wire_tail = next_frame.serialize()[:5]

        backing = bytearray(b"X" * 1_000_000 + wire + wire_tail + b"Y" * 1_000_000)
        end = 1_000_000 + len(wire) + len(wire_tail)
        view = memoryview(backing)[1_000_000:end]
        events = connection.receive_data(view)

        stats = connection.incoming_buffer.stats
        assert len(events) == 2  # request headers, DATA
        assert stats.retained_input_bytes == len(wire_tail)
        assert stats.retained_backing_bytes == len(wire_tail)

        # The incomplete suffix is preserved and parses normally later.
        events = connection.receive_data(bytearray(next_frame.serialize()[5:]))
        assert data_events(events)[0].data == b"B" * 20

    def test_small_incomplete_tail_does_not_pin_large_mutable_input(self, frame_factory) -> None:
        """
        Mutable input is never retained, even when it ends with a partial
        frame, so a reusable pool buffer is released immediately.
        """
        connection = server_connection()
        headers = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        connection.receive_data(PREAMBLE + headers.serialize())
        filler = frame_factory.build_settings_frame({}, ack=True).serialize() * 8000
        next_frame = frame_factory.build_data_frame(b"B" * 50, stream_id=1)
        huge = bytearray(filler + next_frame.serialize()[:5])
        assert len(huge) > h2.frame_buffer.MAX_RETAINED_BACKING_SLACK

        connection.receive_data(huge)
        stats = connection.incoming_buffer.stats

        assert stats.retained_input_bytes == 5
        assert stats.retained_backing_bytes == 5

        huge[:] = b"\x00" * len(huge)
        events = connection.receive_data(bytearray(next_frame.serialize()[5:]))
        assert data_events(events)[0].data == b"B" * 50

    def test_error_path_does_not_retain_mutable_input(self, frame_factory) -> None:
        """
        Protocol failures must also release a borrowed mutable buffer.
        """
        connection = server_connection()
        connection.receive_data(PREAMBLE)
        frame = DataFrame(1, data=b"x")
        frame.flags.add("PADDED")
        frame.pad_length = 5
        wire = bytearray(frame.serialize())

        with pytest.raises(h2.exceptions.ProtocolError):
            connection.receive_data(wire)

        stats = connection.incoming_buffer.stats
        assert stats.retained_backing_bytes == 0
        # An exported view would make this fail with BufferError.
        wire.append(0)


def test_random_fragmentation_keeps_body_bytes(frame_factory):
    """
    Random fragmentation of a legal stream through one reused bytearray yields
    exactly the original request headers and body bytes.
    """
    rng = random.Random(7)
    bodies = [bytes([index]) * rng.randint(1, 80) for index in range(30)]
    headers = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
    wire = PREAMBLE + headers.serialize() + b"".join(
        frame_factory.build_data_frame(body, stream_id=1).serialize()
        for body in bodies
    )
    connection = server_connection()
    receive_buffer = bytearray()
    events: list[h2.events.Event] = []

    offset = 0
    while offset < len(wire):
        size = rng.randint(1, 64)
        piece = wire[offset:offset + size]
        offset += len(piece)
        receive_buffer[:] = piece
        events.extend(connection.receive_data(receive_buffer))
        receive_buffer[:] = b"\x00" * len(receive_buffer)

    [request_event] = [event for event in events if isinstance(event, h2.events.RequestReceived)]
    assert request_event.headers == REQUEST_HEADERS
    assert b"".join(event.data for event in data_events(events)) == b"".join(bodies)

    stats = connection.incoming_buffer.stats
    assert stats.retained_input_bytes == 0
    assert stats.retained_backing_bytes == 0
    # Copies are bounded by fragmentation, not by the total body size.
    assert stats.copied_input_bytes < len(wire)


@dataclass
class GatewayDecision:
    approved: bool
    digest: str
    body: bytes
    headers: list[tuple[bytes, bytes]]


@dataclass
class Gateway:
    """
    A minimal authorising gateway: it drains h2 events, computes a body
    digest, and only then invokes the downstream callback.
    """

    connection: h2.connection.H2Connection
    approved_authorities: set[bytes]
    digest: hashlib._Hash = field(default_factory=hashlib.sha256)
    headers: list[tuple[bytes, bytes]] = field(default_factory=list)
    body_parts: list[bytes] = field(default_factory=list)
    decision: GatewayDecision | None = None

    def consume(self, events: list[h2.events.Event]) -> None:
        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                self.headers = list(event.headers)
            elif isinstance(event, h2.events.DataReceived):
                self.body_parts.append(event.data)
                self.digest.update(event.data)
            elif isinstance(event, h2.events.StreamEnded):
                body = b"".join(self.body_parts)
                authority = dict(self.headers).get(b":authority", b"")
                self.decision = GatewayDecision(
                    approved=authority in self.approved_authorities,
                    digest=self.digest.hexdigest(),
                    body=body,
                    headers=self.headers,
                )


class TestGatewayAuthorization:
    def test_overwriting_buffer_cannot_substitute_approved_body(self, frame_factory) -> None:
        """
        After the gateway has checked a request and digested its body, the
        caller overwrites the original receive buffer with unauthorised
        bytes. The bytes consumed downstream must remain the approved ones.
        """
        approved_body = b"transfer=100;to=alice"
        headers = [*REQUEST_HEADERS, (b"x-request-id", b"approved")]
        approved_wire = PREAMBLE + request_wire(
            frame_factory, approved_body, headers=headers,
        )
        # Same length, different semantics: an in-place overwrite fits exactly.
        unauthorised_body = b"transfer=999;to=mallo"
        assert len(unauthorised_body) == len(approved_body)
        unauthorised_wire = request_wire(
            frame_factory, unauthorised_body, headers=headers,
        )

        receive_buffer = bytearray(approved_wire)
        connection = server_connection()
        gateway = Gateway(connection, approved_authorities={b"example.com"})

        events = connection.receive_data(receive_buffer)
        gateway.consume(events)
        assert gateway.decision is not None
        assert gateway.decision.approved
        approved_digest = gateway.decision.digest

        # Simulate the buffer being recycled and filled with an unauthorised
        # request before the downstream callback runs.
        receive_buffer[:] = b"\x00" * len(receive_buffer)
        receive_buffer[len(PREAMBLE):] = unauthorised_wire

        # Downstream consumes the already-delivered event, not the buffer.
        downstream = b"".join(gateway.body_parts)
        assert downstream == approved_body
        assert hashlib.sha256(downstream).hexdigest() == approved_digest
        assert unauthorised_body not in downstream

    def test_overwriting_buffer_cannot_launder_unauthorised_body(self, frame_factory) -> None:
        """
        The reverse substitution must also fail: a rejected body cannot be
        turned into an approved one by overwriting the source buffer after
        the check.
        """
        unauthorised_body = b"transfer=999999;to=mallory"
        approved_body = b"transfer=100;to=alice"
        unauthorised_wire = PREAMBLE + request_wire(frame_factory, unauthorised_body)
        approved_wire = request_wire(frame_factory, approved_body)

        receive_buffer = bytearray(unauthorised_wire)
        connection = server_connection()
        gateway = Gateway(connection, approved_authorities={b"example.com"})

        events = connection.receive_data(receive_buffer)
        gateway.consume(events)
        assert gateway.decision is not None
        rejected_digest = gateway.decision.digest

        receive_buffer[:] = b"\x00" * len(receive_buffer)
        receive_buffer[len(PREAMBLE):] = approved_wire

        downstream = b"".join(gateway.body_parts)
        assert downstream == unauthorised_body
        assert hashlib.sha256(downstream).hexdigest() == rejected_digest
        assert downstream != approved_body

    @pytest.mark.parametrize("split", [1, 2, 3, 5, 8, 13, 21])
    def test_fragmented_gateway_events_are_consistent(self, frame_factory, split) -> None:
        """
        Legitimate requests split over many receive calls produce the same
        headers, body digest, and bounded retention, without retaining the
        caller's buffer.
        """
        body = b"fragmented legitimate body"
        wire = PREAMBLE + request_wire(frame_factory, body)
        connection = server_connection()
        gateway = Gateway(connection, approved_authorities={b"example.com"})
        receive_buffer = bytearray()

        for start in range(0, len(wire), split):
            receive_buffer[:] = wire[start:start + split]
            gateway.consume(connection.receive_data(receive_buffer))
            receive_buffer[:] = b"\x00" * len(receive_buffer)

        assert gateway.decision is not None
        assert gateway.decision.approved
        assert gateway.decision.headers == REQUEST_HEADERS
        assert gateway.decision.body == body
        assert gateway.decision.digest == hashlib.sha256(body).hexdigest()

        stats = connection.incoming_buffer.stats
        assert stats.retained_input_bytes == 0
        assert stats.retained_backing_bytes == 0
        # Copies are bounded by fragmentation: each call copies at most its
        # chunk once while joining a split frame, never a whole accumulated
        # request.
        assert stats.copied_input_bytes <= 2 * len(wire)
        assert stats.copy_operations <= len(wire)


class TestCopyAccounting:
    """
    Directly exercise ownership transitions and assert the reported counters.
    """

    def _frames(self, frame_factory) -> tuple[bytes, int]:
        headers = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        data = frame_factory.build_data_frame(b"hello", stream_id=1)
        headers_wire = headers.serialize()
        return headers_wire + data.serialize(), len(headers_wire)

    def test_whole_aligned_cycle_borrows_every_input_byte(self, frame_factory) -> None:
        """
        Aligned, immutable input is parsed without any input copy.
        """
        wire, _ = self._frames(frame_factory)
        buffer = h2.frame_buffer.FrameBuffer()
        buffer.max_frame_size = 65535

        buffer.add_data(wire)
        parsed = list(buffer)
        buffer._finish_receive()

        assert [type(frame).__name__ for frame in parsed] == ["HeadersFrame", "DataFrame"]
        stats = buffer.stats
        assert stats.copied_input_bytes == 0
        assert stats.copy_operations == 0
        assert stats.borrowed_immutable_bytes == len(wire)
        assert stats.retained_input_bytes == 0
        assert stats.retained_backing_bytes == 0

    def test_split_join_copies_only_the_join(self, frame_factory) -> None:
        """
        When a frame is split, the borrowed pieces are joined into owned
        storage once; the rest of the input stays borrowed.
        """
        wire, headers_len = self._frames(frame_factory)
        split = headers_len + 2
        buffer = h2.frame_buffer.FrameBuffer()
        buffer.max_frame_size = 65535

        buffer.add_data(wire[:split])
        list(buffer)
        buffer._finish_receive()
        assert buffer.stats.copied_input_bytes == 0
        assert buffer.stats.retained_input_bytes == split - headers_len

        buffer.add_data(wire[split:])
        parsed = list(buffer)
        buffer._finish_receive()
        stats = buffer.stats
        assert [type(frame).__name__ for frame in parsed] == ["DataFrame"]
        assert stats.copy_operations == 2
        assert stats.copied_input_bytes == split - headers_len + (len(wire) - split)
        assert stats.retained_input_bytes == 0

    def test_owned_bytearray_append_does_not_copy_old_storage(self, frame_factory) -> None:
        """
        Appending new input to owned storage copies only the new input.
        """
        wire, _ = self._frames(frame_factory)
        buffer = h2.frame_buffer.FrameBuffer()
        buffer.max_frame_size = 65535

        buffer.add_data(bytearray(wire[:5]))
        buffer.add_data(wire[5:])
        parsed = list(buffer)
        buffer._finish_receive()

        stats = buffer.stats
        assert [type(frame).__name__ for frame in parsed] == ["HeadersFrame", "DataFrame"]
        assert stats.copied_input_bytes == len(wire)
        assert stats.copy_operations == 2

    def test_payload_copies_are_reported_separately(self, frame_factory) -> None:
        """
        Payload detachment is counted apart from input-buffer copies so the
        receive-path savings remain measurable.
        """
        wire, _ = self._frames(frame_factory)
        buffer = h2.frame_buffer.FrameBuffer()
        buffer.max_frame_size = 65535

        buffer.add_data(wire)
        parsed = list(buffer)
        buffer._finish_receive()

        stats = buffer.stats
        assert stats.copied_input_bytes == 0
        assert stats.payload_copy_operations == 2
        assert stats.payload_copy_bytes == sum(len(frame.data) for frame in parsed)

    def test_discard_drops_incomplete_input(self, frame_factory) -> None:
        """``_finish_receive(discard=True)`` releases buffered input."""
        wire, _ = self._frames(frame_factory)
        buffer = h2.frame_buffer.FrameBuffer()
        buffer.max_frame_size = 65535
        buffer.add_data(bytearray(wire[:7]))

        buffer._finish_receive(discard=True)

        stats = buffer.stats
        assert stats.retained_input_bytes == 0
        assert stats.retained_backing_bytes == 0

    def test_mutable_incomplete_suffix_copied_at_finish(self, frame_factory) -> None:
        """
        The transient borrow ends even when iteration consumed every complete
        frame and a partial frame remains.
        """
        wire, headers_len = self._frames(frame_factory)
        buffer = h2.frame_buffer.FrameBuffer()
        buffer.max_frame_size = 65535

        buffer.add_data(bytearray(wire[:headers_len + 3]), borrow=True)
        list(buffer)
        buffer._finish_receive()

        stats = buffer.stats
        assert stats.retained_input_bytes == 3
        assert stats.retained_backing_bytes == 3
        assert buffer._start == 0
        assert isinstance(buffer._data, bytearray)

    def test_invalid_padding_leaves_caller_buffer_resizable(self) -> None:
        """
        A failed receive must not leave an exported view in the exception
        traceback: an exported bytearray raises ``BufferError`` on resize.
        """
        connection = server_connection()
        connection.receive_data(PREAMBLE)
        frame = DataFrame(1, data=b"x")
        frame.flags.add("PADDED")
        frame.pad_length = 5
        wire = bytearray(frame.serialize())

        with pytest.raises(h2.exceptions.ProtocolError):
            connection.receive_data(wire)

        # ``hyperframe`` parsed the body from a memoryview of ``wire``. If that
        # view survives in a traceback, resizing raises BufferError.
        wire.append(0)
        assert len(wire)

    def test_invalid_preamble_leaves_caller_buffer_resizable(self) -> None:
        """
        An invalid preamble raises before any bytes are staged and must not
        leave an exported view of the caller's buffer behind.
        """
        buffer = h2.frame_buffer.FrameBuffer(server=True)
        wire = bytearray(b"PRI * WRONG")

        with pytest.raises(h2.exceptions.ProtocolError):
            buffer.add_data(wire)

        wire.append(0)
        assert len(wire)
        assert buffer.stats.retained_input_bytes == 0
