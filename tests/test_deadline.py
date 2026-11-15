"""
Tests for the explicit-clock deadline adapter in h2/deadline.py.

All tests advance a fake clock by hand: no real waiting, no background
threads.
"""
from __future__ import annotations

import threading

import pytest
from hyperframe.frame import (
    ContinuationFrame,
    Frame,
    GoAwayFrame,
    HeadersFrame,
    RstStreamFrame,
)

import h2.config
import h2.connection
import h2.deadline
import h2.errors
import h2.events
import h2.exceptions


class FakeClock:
    """
    A manually advanced clock. Time only moves when the test says so.
    """

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class Consumer:
    """
    Stands in for business logic that waits on streams.

    Tracks one waiter per open stream and cancels waiters when the adapter
    reports a deadline event, mirroring what a real application would do.
    """

    def __init__(self) -> None:
        self.waiters: dict[int, str] = {}
        self.completed: list[int] = []

    def handle(self, events) -> None:
        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                self.waiters[event.stream_id] = "waiting"
            elif isinstance(event, h2.events.StreamEnded):
                self.waiters.pop(event.stream_id, None)
                self.completed.append(event.stream_id)
            elif isinstance(event, h2.deadline.StreamIdleDeadlineExceeded):
                self.waiters[event.stream_id] = "cancelled"
            elif isinstance(event, h2.deadline.HeaderBlockDeadlineExceeded):
                # Connection-level failure: every waiter must be cancelled.
                for stream_id in self.waiters:
                    self.waiters[stream_id] = "cancelled"


def parse_frames(data: bytes) -> list[Frame]:
    """
    Parse a byte string of serialized frames back into frame objects.
    """
    frames = []
    while data:
        frame, length = Frame.parse_frame_header(memoryview(data[:9]))
        frame.parse_body(memoryview(data[9:9 + length]))
        frames.append(frame)
        data = data[9 + length:]
    return frames


HEADER_BLOCK_TIMEOUT = 10.0
STREAM_IDLE_TIMEOUT = 30.0

EXAMPLE_HEADERS = [
    (b":authority", b"example.com"),
    (b":path", b"/"),
    (b":scheme", b"https"),
    (b":method", b"GET"),
]


def make_server(frame_factory, clock) -> h2.deadline.DeadlineAdapter:
    """
    Build a server-side DeadlineAdapter with the handshake completed and
    all handshake bytes drained.
    """
    config = h2.config.H2Configuration(client_side=False)
    adapter = h2.deadline.DeadlineAdapter(
        h2.connection.H2Connection(config=config),
        clock,
        header_block_timeout=HEADER_BLOCK_TIMEOUT,
        stream_idle_timeout=STREAM_IDLE_TIMEOUT,
    )
    adapter.initiate_connection()
    adapter.receive_data(
        frame_factory.preamble() +
        frame_factory.build_settings_frame({}).serialize(),
    )
    adapter.data_to_send()  # Drain server SETTINGS and the SETTINGS ACK.
    return adapter


def split_header_block(frame_factory, headers, stream_id, split_at=8):
    """
    Build a HEADERS frame without END_HEADERS plus a matching CONTINUATION
    frame carrying the rest of the header block.
    """
    block = frame_factory.encoder.encode(headers)
    headers_frame = HeadersFrame(stream_id)
    headers_frame.data = block[:split_at]
    headers_frame.flags = set()
    continuation_frame = ContinuationFrame(stream_id)
    continuation_frame.data = block[split_at:]
    continuation_frame.flags = {"END_HEADERS"}
    return headers_frame, continuation_frame


class TestStreamIdleDeadline:
    def test_idle_deadline_resets_only_the_slow_stream(self, frame_factory) -> None:
        """
        A normal stream and a slow stream are interleaved. DATA on the
        normal stream and connection-level PINGs must not renew the slow
        stream's deadline: only the slow stream gets RST_STREAM, and only
        its consumer waiter is cancelled.
        """
        clock = FakeClock()
        consumer = Consumer()
        adapter = make_server(frame_factory, clock)

        # Both streams open at t=0.
        events = adapter.receive_data(
            frame_factory.build_headers_frame(EXAMPLE_HEADERS, stream_id=1).serialize() +
            frame_factory.build_headers_frame(EXAMPLE_HEADERS, stream_id=3).serialize(),
        )
        consumer.handle(events)
        assert consumer.waiters == {1: "waiting", 3: "waiting"}

        # The normal stream stays active; the attacker stays silent.
        reset_frames = []
        for _ in range(6):
            clock.advance(6)
            events = adapter.receive_data(
                frame_factory.build_data_frame(b"ok", stream_id=1).serialize() +
                frame_factory.build_ping_frame(b"12345678").serialize(),
            )
            consumer.handle(events)
            deadline_events = adapter.poll()
            consumer.handle(deadline_events)
            reset_frames.extend(
                f for f in parse_frames(adapter.data_to_send())
                if isinstance(f, (RstStreamFrame, GoAwayFrame))
            )

        # Exactly one RST_STREAM, scoped to the attacking stream only.
        assert [f.stream_id for f in reset_frames] == [3]
        assert isinstance(reset_frames[0], RstStreamFrame)
        assert reset_frames[0].error_code == h2.errors.ErrorCodes.CANCEL

        # The consumer cancelled only the attacker's waiter.
        assert consumer.waiters[3] == "cancelled"
        assert consumer.waiters[1] == "waiting"

        # The connection is still healthy: the normal stream completes and
        # a brand new stream is accepted afterwards.
        events = adapter.receive_data(
            frame_factory.build_data_frame(b"done", flags=["END_STREAM"], stream_id=1).serialize() +
            frame_factory.build_headers_frame(EXAMPLE_HEADERS, stream_id=5).serialize(),
        )
        consumer.handle(events)
        assert consumer.completed == [1]
        assert consumer.waiters[5] == "waiting"
        assert not adapter.terminated

    def test_ping_does_not_renew_stream_deadline(self, frame_factory) -> None:
        """
        Connection-level PING activity must not keep an idle stream alive.
        """
        clock = FakeClock()
        adapter = make_server(frame_factory, clock)
        adapter.receive_data(
            frame_factory.build_headers_frame(EXAMPLE_HEADERS, stream_id=1).serialize(),
        )

        for _ in range(4):
            clock.advance(7)
            adapter.receive_data(
                frame_factory.build_ping_frame(b"12345678").serialize(),
            )
            assert adapter.poll() == []

        clock.advance(7)  # t=35: stream 1 has been silent for 35s.
        events = adapter.poll()
        assert len(events) == 1
        assert isinstance(events[0], h2.deadline.StreamIdleDeadlineExceeded)
        assert events[0].stream_id == 1
        assert events[0].idle_for >= STREAM_IDLE_TIMEOUT

    def test_other_stream_data_does_not_renew_deadline(self, frame_factory) -> None:
        """
        DATA on stream 1 must not renew the deadline of idle stream 3.
        """
        clock = FakeClock()
        adapter = make_server(frame_factory, clock)
        adapter.receive_data(
            frame_factory.build_headers_frame(EXAMPLE_HEADERS, stream_id=1).serialize() +
            frame_factory.build_headers_frame(EXAMPLE_HEADERS, stream_id=3).serialize(),
        )

        clock.advance(STREAM_IDLE_TIMEOUT)
        adapter.receive_data(
            frame_factory.build_data_frame(b"busy", stream_id=1).serialize(),
        )
        events = adapter.poll()

        assert len(events) == 1
        assert events[0].stream_id == 3
        frames = parse_frames(adapter.data_to_send())
        assert [f.stream_id for f in frames if isinstance(f, RstStreamFrame)] == [3]

    def test_legit_slow_request_within_deadline_succeeds(self, frame_factory) -> None:
        """
        A request that is slow but stays inside every deadline completes
        normally and fires no deadline events.
        """
        clock = FakeClock()
        consumer = Consumer()
        adapter = make_server(frame_factory, clock)

        # Headers arrive promptly, then DATA trickles in just fast enough.
        consumer.handle(adapter.receive_data(
            frame_factory.build_headers_frame(EXAMPLE_HEADERS, stream_id=1).serialize(),
        ))
        for _ in range(3):
            clock.advance(STREAM_IDLE_TIMEOUT - 1)
            events = adapter.receive_data(
                frame_factory.build_data_frame(b"slow-but-legal", stream_id=1).serialize(),
            )
            consumer.handle(events)
            assert adapter.poll() == []

        clock.advance(STREAM_IDLE_TIMEOUT - 1)
        events = adapter.receive_data(
            frame_factory.build_data_frame(b"end", flags=["END_STREAM"], stream_id=1).serialize(),
        )
        consumer.handle(events)
        assert adapter.poll() == []

        assert consumer.completed == [1]
        assert adapter.data_to_send() == b""  # No RST_STREAM, no GOAWAY.
        assert not adapter.terminated


class TestHeaderBlockDeadline:
    def test_stalled_header_block_tears_down_connection(self, frame_factory) -> None:
        """
        A header block stuck waiting for CONTINUATION poisons the whole
        connection: the adapter must send GOAWAY (not RST_STREAM), release
        its buffers, cancel the consumer's waiters, and refuse further
        input instead of treating arbitrary frames as legal.
        """
        clock = FakeClock()
        consumer = Consumer()
        adapter = make_server(frame_factory, clock)

        # A normal request completes first.
        consumer.handle(adapter.receive_data(
            frame_factory.build_headers_frame(
                EXAMPLE_HEADERS, flags=["END_STREAM"], stream_id=1,
            ).serialize(),
        ))
        assert consumer.completed == [1]

        # The attacker opens stream 3 but never finishes the header block.
        clock.advance(1)
        headers_frame, _ = split_header_block(frame_factory, EXAMPLE_HEADERS, 3)
        assert adapter.receive_data(headers_frame.serialize()) == []
        conn = adapter._conn
        assert conn.incoming_buffer.incomplete_header_block_stream_id == 3

        # The deadline has not expired yet: no action.
        clock.advance(HEADER_BLOCK_TIMEOUT - 1)
        assert adapter.poll() == []

        # Now it has. The whole connection is torn down with GOAWAY.
        clock.advance(1)
        events = adapter.poll()
        assert len(events) == 1
        assert isinstance(events[0], h2.deadline.HeaderBlockDeadlineExceeded)
        assert events[0].stream_id == 3
        consumer.handle(events)

        frames = parse_frames(adapter.data_to_send())
        goaway_frames = [f for f in frames if isinstance(f, GoAwayFrame)]
        assert len(goaway_frames) == 1
        assert goaway_frames[0].error_code == h2.errors.ErrorCodes.PROTOCOL_ERROR
        assert not any(isinstance(f, RstStreamFrame) for f in frames)

        # Buffers held for the attacker are released.
        assert conn.incoming_buffer.incomplete_header_block_stream_id is None

        # The adapter refuses to treat any further bytes as legal input.
        assert adapter.terminated
        assert adapter.poll() == []
        with pytest.raises(h2.deadline.DeadlineExceededError):
            adapter.receive_data(
                frame_factory.build_headers_frame(EXAMPLE_HEADERS, stream_id=5).serialize(),
            )

    def test_non_continuation_frame_during_header_block_is_rejected(self, frame_factory) -> None:
        """
        While a header block is incomplete, h2 itself rejects any frame
        that is not the expected CONTINUATION. This is why resetting only
        the stream can never be a valid recovery from a stalled block.
        """
        clock = FakeClock()
        adapter = make_server(frame_factory, clock)
        headers_frame, _ = split_header_block(frame_factory, EXAMPLE_HEADERS, 1)
        adapter.receive_data(headers_frame.serialize())

        with pytest.raises(h2.exceptions.ProtocolError):
            adapter.receive_data(
                frame_factory.build_ping_frame(b"12345678").serialize(),
            )

    def test_header_block_completing_within_deadline_is_fine(self, frame_factory) -> None:
        """
        A header block delivered in two frames inside the deadline produces
        a normal RequestReceived and no deadline events.
        """
        clock = FakeClock()
        consumer = Consumer()
        adapter = make_server(frame_factory, clock)

        headers_frame, continuation_frame = split_header_block(
            frame_factory, EXAMPLE_HEADERS, 1,
        )
        adapter.receive_data(headers_frame.serialize())
        clock.advance(HEADER_BLOCK_TIMEOUT - 1)
        events = adapter.receive_data(continuation_frame.serialize())
        consumer.handle(events)

        assert adapter.poll() == []
        assert consumer.waiters == {1: "waiting"}
        assert adapter.data_to_send() == b""
        assert not adapter.terminated


class TestExplicitClock:
    def test_no_background_threads_are_started(self, frame_factory) -> None:
        """
        The adapter never starts threads or timers: time only moves when
        the application advances its own clock and calls poll().
        """
        threads_before = set(threading.enumerate())
        clock = FakeClock()
        adapter = make_server(frame_factory, clock)
        adapter.receive_data(
            frame_factory.build_headers_frame(EXAMPLE_HEADERS, stream_id=1).serialize(),
        )
        clock.advance(STREAM_IDLE_TIMEOUT * 3)
        events = adapter.poll()
        assert len(events) == 1
        assert set(threading.enumerate()) == threads_before

    def test_deadlines_do_not_fire_without_poll(self, frame_factory) -> None:
        """
        Even far past the deadline, nothing happens until poll() is called:
        the adapter is inert without explicit clock advancement.
        """
        clock = FakeClock()
        adapter = make_server(frame_factory, clock)
        adapter.receive_data(
            frame_factory.build_headers_frame(EXAMPLE_HEADERS, stream_id=1).serialize(),
        )
        clock.advance(STREAM_IDLE_TIMEOUT * 100)
        assert adapter.data_to_send() == b""  # No RST_STREAM queued yet.
        assert not adapter.terminated

        events = adapter.poll()
        assert len(events) == 1
        assert isinstance(events[0], h2.deadline.StreamIdleDeadlineExceeded)
