"""
Tests that evicting closed-stream history never makes old streams reopenable.

h2 bounds the memory spent remembering how streams were closed: once more
than ``H2Connection.MAX_CLOSED_STREAMS`` streams have closed, the oldest
entries of ``H2Connection._closed_streams`` are evicted. These tests pin
down the contract that an evicted stream must not regress to looking like
an idle stream that can be re-opened: RFC 7540 § 5.1.1 forbids reusing
stream identifiers. Both endpoint roles are covered, along with every way
a stream ID can become unavailable: cleanly ended, reset in either
direction, reserved (pushed), or skipped over without ever existing.
"""
from __future__ import annotations

import enum

import pytest

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions

REQUEST_HEADERS = [
    (":authority", "example.com"),
    (":path", "/"),
    (":scheme", "https"),
    (":method", "GET"),
]
RESPONSE_HEADERS = [
    (":status", "200"),
    ("server", "fake-serv/0.1.0"),
]

# Small enough to overflow in a handful of streams.
HISTORY_CAPACITY = 4


class StreamFate(enum.Enum):
    """How a stream ID at or below the highest seen one became unavailable."""

    NEVER_OPENED = enum.auto()  # skipped over: never existed, never in history
    END_STREAM = enum.auto()  # closed cleanly via END_STREAM
    RST_STREAM_SENT = enum.auto()  # closed by a locally sent RST_STREAM
    RST_STREAM_RECEIVED = enum.auto()  # closed by a received RST_STREAM
    RESERVED = enum.auto()  # pushed stream, reserved: not closed at all


RESET_FATES = (StreamFate.RST_STREAM_SENT, StreamFate.RST_STREAM_RECEIVED)


class FrameKind(enum.Enum):
    HEADERS = enum.auto()
    PRIORITY = enum.auto()
    RST_STREAM = enum.auto()
    WINDOW_UPDATE = enum.auto()


class ProbeOutcome(enum.Enum):
    IGNORE = enum.auto()  # dropped silently: no events, no output
    EVENT = enum.auto()  # processed normally, events may fire
    STREAM_ERROR = enum.auto()  # RST_STREAM(STREAM_CLOSED) emitted
    CONNECTION_ERROR_PROTOCOL = enum.auto()  # GOAWAY(PROTOCOL_ERROR)
    CONNECTION_ERROR_CLOSED = enum.auto()  # GOAWAY(STREAM_CLOSED)


def expected_outcome(fate, remembered, frame_kind):
    """
    Independent model of how an endpoint must treat a frame that arrives for
    a stream ID at or below the highest one it has seen.

    ``remembered`` is True while the stream's close cause is still in the
    bounded closed-stream history, and False once it has been evicted (or
    was never recorded). The crucial invariant this model encodes: no
    combination of fate, remembrance and frame kind may re-open the stream.
    """
    # RFC 7540 § 5.1: PRIORITY can be sent and received in any stream state.
    if frame_kind is FrameKind.PRIORITY:
        return ProbeOutcome.EVENT

    if fate is StreamFate.RESERVED:
        # A reserved stream is not closed and is never entered into the
        # closed-stream history, so history eviction cannot change how its
        # frames are handled.
        return ProbeOutcome.EVENT

    if frame_kind in (FrameKind.RST_STREAM, FrameKind.WINDOW_UPDATE):
        # For any stream ID at or below the highest seen, these frames are
        # dropped silently whether the stream was closed or never existed.
        return ProbeOutcome.IGNORE

    # HEADERS on such a stream ID must never open a stream
    # (RFC 7540 § 5.1.1: stream identifiers cannot be reused).
    if remembered and fate in RESET_FATES:
        # RFC 7540 § 5.1 (closed): frames after RST_STREAM are a stream
        # error of type STREAM_CLOSED.
        return ProbeOutcome.STREAM_ERROR
    if remembered and fate is StreamFate.END_STREAM:
        # RFC 7540 § 5.1 (closed): frames after END_STREAM are a connection
        # error of type STREAM_CLOSED.
        return ProbeOutcome.CONNECTION_ERROR_CLOSED
    # Never opened, or the close cause has been evicted: the endpoint can no
    # longer tell this stream ID apart from one that was skipped over, so
    # HEADERS is a connection error of type PROTOCOL_ERROR.
    return ProbeOutcome.CONNECTION_ERROR_PROTOCOL


def business_events(events):
    """Events that would indicate user-visible traffic on a stream."""
    interesting = (
        h2.events.RequestReceived,
        h2.events.ResponseReceived,
        h2.events.TrailersReceived,
        h2.events.DataReceived,
        h2.events.PushedStreamReceived,
    )
    return [event for event in events if isinstance(event, interesting)]


def server_connection(frame_factory):
    config = h2.config.H2Configuration(client_side=False)
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    conn.receive_data(frame_factory.preamble())
    conn.clear_outbound_data_buffer()
    return conn


def client_connection():
    conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True))
    conn.initiate_connection()
    conn.clear_outbound_data_buffer()
    return conn


def server_close_stream(conn, frame_factory, stream_id, fate):
    """Open one inbound stream on a server and close it as ``fate`` dictates."""
    flags = ["END_HEADERS"]
    if fate is StreamFate.END_STREAM:
        flags.append("END_STREAM")
    frame = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=stream_id, flags=flags)
    conn.receive_data(frame.serialize())
    if fate is StreamFate.END_STREAM:
        conn.send_headers(stream_id, RESPONSE_HEADERS, end_stream=True)
    elif fate is StreamFate.RST_STREAM_SENT:
        conn.reset_stream(stream_id)
    elif fate is StreamFate.RST_STREAM_RECEIVED:
        frame = frame_factory.build_rst_stream_frame(stream_id)
        conn.receive_data(frame.serialize())
    conn.clear_outbound_data_buffer()


def client_close_stream(conn, frame_factory, stream_id, fate):
    """Open one outbound stream on a client and close it as ``fate`` dictates."""
    conn.send_headers(stream_id, REQUEST_HEADERS, end_stream=fate is StreamFate.END_STREAM)
    if fate is StreamFate.END_STREAM:
        frame = frame_factory.build_headers_frame(RESPONSE_HEADERS, stream_id=stream_id, flags=["END_HEADERS", "END_STREAM"])
        conn.receive_data(frame.serialize())
    elif fate is StreamFate.RST_STREAM_SENT:
        conn.reset_stream(stream_id)
    elif fate is StreamFate.RST_STREAM_RECEIVED:
        frame = frame_factory.build_rst_stream_frame(stream_id)
        conn.receive_data(frame.serialize())
    conn.clear_outbound_data_buffer()


def evict_server_history(conn, frame_factory):
    """Open and cleanly close enough inbound streams to empty the history."""
    first = conn.highest_inbound_stream_id + 2
    for stream_id in range(first, first + 2 * (HISTORY_CAPACITY + 1), 2):
        server_close_stream(conn, frame_factory, stream_id, StreamFate.END_STREAM)


def evict_client_history(conn, frame_factory):
    """Open and cleanly close enough outbound streams to empty the history."""
    first = conn.highest_outbound_stream_id + 2
    for stream_id in range(first, first + 2 * (HISTORY_CAPACITY + 1), 2):
        client_close_stream(conn, frame_factory, stream_id, StreamFate.END_STREAM)


def send_probe(conn, frame_factory, stream_id, frame_kind):
    """Feed one probe frame for ``stream_id``; return the emitted events."""
    if frame_kind is FrameKind.HEADERS:
        frame = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=stream_id, flags=["END_HEADERS"])
    elif frame_kind is FrameKind.PRIORITY:
        frame = frame_factory.build_priority_frame(stream_id, weight=16, depends_on=0, exclusive=False)
    elif frame_kind is FrameKind.RST_STREAM:
        frame = frame_factory.build_rst_stream_frame(stream_id)
    else:
        frame = frame_factory.build_window_update_frame(stream_id, increment=1024)
    return conn.receive_data(frame.serialize())


def assert_headers_outcome(conn, frame_factory, stream_id, outcome, max_stream_id, goaway_last_stream_id):
    """
    Probe ``stream_id`` with HEADERS and assert the modelled outcome,
    including the exact error classification and the bytes on the wire.
    """
    if outcome is ProbeOutcome.STREAM_ERROR:
        events = send_probe(conn, frame_factory, stream_id, FrameKind.HEADERS)
        assert events == []
        expected = frame_factory.build_rst_stream_frame(stream_id, error_code=h2.errors.ErrorCodes.STREAM_CLOSED)
        assert conn.data_to_send() == expected.serialize()
        conn.clear_outbound_data_buffer()
        return

    if outcome is ProbeOutcome.CONNECTION_ERROR_CLOSED:
        with pytest.raises(h2.exceptions.StreamClosedError) as exc_info:
            send_probe(conn, frame_factory, stream_id, FrameKind.HEADERS)
        assert exc_info.value.stream_id == stream_id
        assert exc_info.value.error_code == h2.errors.ErrorCodes.STREAM_CLOSED
        error_code = h2.errors.ErrorCodes.STREAM_CLOSED
    elif outcome is ProbeOutcome.CONNECTION_ERROR_PROTOCOL:
        with pytest.raises(h2.exceptions.StreamIDTooLowError) as exc_info:
            send_probe(conn, frame_factory, stream_id, FrameKind.HEADERS)
        assert exc_info.value.stream_id == stream_id
        assert exc_info.value.max_stream_id == max_stream_id
        error_code = h2.errors.ErrorCodes.PROTOCOL_ERROR
    else:
        msg = f"unexpected HEADERS outcome: {outcome}"
        raise AssertionError(msg)

    expected = frame_factory.build_goaway_frame(last_stream_id=goaway_last_stream_id, error_code=error_code)
    assert conn.data_to_send() == expected.serialize()


class TestServerClosedStreamEviction:
    """
    Server role: the peer opens streams, the history of how they closed is
    evicted, and the peer then probes the old stream IDs.
    """

    @pytest.mark.parametrize("remembered", [True, False])
    @pytest.mark.parametrize(
        "fate",
        [
            StreamFate.NEVER_OPENED,
            StreamFate.END_STREAM,
            StreamFate.RST_STREAM_SENT,
            StreamFate.RST_STREAM_RECEIVED,
        ],
    )
    def test_headers_on_old_stream_id_never_reopens(self, frame_factory, monkeypatch, fate, remembered) -> None:
        """
        HEADERS for a stream ID at or below the highest seen one must never
        re-open that stream, whether or not its close cause is still
        remembered. The error classification follows the independent model.
        """
        monkeypatch.setattr(h2.connection.H2Connection, "MAX_CLOSED_STREAMS", HISTORY_CAPACITY)
        conn = server_connection(frame_factory)

        target = 1
        if fate is StreamFate.NEVER_OPENED:
            # Open a higher stream so that stream 1 is skipped over.
            server_close_stream(conn, frame_factory, 3, StreamFate.END_STREAM)
        else:
            server_close_stream(conn, frame_factory, target, fate)

        if not remembered:
            evict_server_history(conn, frame_factory)
            assert target not in conn._closed_streams

        highest_before = conn.highest_inbound_stream_id
        outcome = expected_outcome(fate, remembered, FrameKind.HEADERS)
        assert_headers_outcome(
            conn, frame_factory, target, outcome,
            max_stream_id=highest_before,
            goaway_last_stream_id=highest_before,
        )

        # The probe must not have produced a request or moved the high-water mark.
        if remembered and fate is not StreamFate.NEVER_OPENED:
            # The closed stream object may still await the periodic sweep;
            # the point is that it was not re-opened.
            assert conn.streams[target].closed
        else:
            assert target not in conn.streams
        assert conn.highest_inbound_stream_id == highest_before
        assert len(conn._closed_streams) <= HISTORY_CAPACITY

    @pytest.mark.parametrize("frame_kind", [FrameKind.PRIORITY, FrameKind.RST_STREAM, FrameKind.WINDOW_UPDATE])
    @pytest.mark.parametrize(
        "fate",
        [
            StreamFate.NEVER_OPENED,
            StreamFate.END_STREAM,
            StreamFate.RST_STREAM_SENT,
            StreamFate.RST_STREAM_RECEIVED,
        ],
    )
    def test_non_headers_frames_on_evicted_stream(self, frame_factory, monkeypatch, fate, frame_kind) -> None:
        """
        PRIORITY, RST_STREAM and WINDOW_UPDATE for an evicted stream ID are
        ignored (or, for PRIORITY, acknowledged with an event): they must
        not error the connection, emit output, or re-open the stream.
        """
        monkeypatch.setattr(h2.connection.H2Connection, "MAX_CLOSED_STREAMS", HISTORY_CAPACITY)
        conn = server_connection(frame_factory)

        target = 1
        if fate is StreamFate.NEVER_OPENED:
            server_close_stream(conn, frame_factory, 3, StreamFate.END_STREAM)
        else:
            server_close_stream(conn, frame_factory, target, fate)
        evict_server_history(conn, frame_factory)
        assert target not in conn._closed_streams

        highest_before = conn.highest_inbound_stream_id
        events = send_probe(conn, frame_factory, target, frame_kind)

        outcome = expected_outcome(fate, False, frame_kind)
        if outcome is ProbeOutcome.IGNORE:
            assert events == []
        else:
            assert outcome is ProbeOutcome.EVENT
            assert len(events) == 1
            event = events[0]
            assert isinstance(event, h2.events.PriorityUpdated)
            assert event.stream_id == target

        assert not business_events(events)
        assert conn.data_to_send() == b""
        assert target not in conn.streams
        assert conn.highest_inbound_stream_id == highest_before

        # The connection is unharmed: a genuinely new stream still works.
        new_stream_id = highest_before + 2
        frame = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=new_stream_id, flags=["END_HEADERS"])
        events = conn.receive_data(frame.serialize())
        assert isinstance(events[0], h2.events.RequestReceived)
        assert events[0].stream_id == new_stream_id

    def test_minimal_frame_sequence_exposing_idle_confusion(self, frame_factory, monkeypatch) -> None:
        """
        Shortest frame sequence that would expose a wrong idle/closed
        inference after history eviction (server role, history capacity
        forced to one entry):

            HEADERS(1, END_STREAM)   stream 1 opens and half-closes
            RST_STREAM(1)            stream 1 closes
            HEADERS(3, END_STREAM)   sweep records stream 1 in the history
            RST_STREAM(3)            stream 3 closes
            HEADERS(1)               must NOT re-open stream 1

        The final HEADERS is processed after the sweep has evicted stream 1
        from the single-entry history. If eviction made stream 1 look idle,
        h2 would emit a second RequestReceived for it; per RFC 7540 § 5.1.1
        it must instead be a connection error of type PROTOCOL_ERROR.
        """
        monkeypatch.setattr(h2.connection.H2Connection, "MAX_CLOSED_STREAMS", 1)
        conn = server_connection(frame_factory)

        events = []
        for frame in (
            frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1, flags=["END_HEADERS", "END_STREAM"]),
            frame_factory.build_rst_stream_frame(stream_id=1),
            frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=3, flags=["END_HEADERS", "END_STREAM"]),
            frame_factory.build_rst_stream_frame(stream_id=3),
        ):
            events += conn.receive_data(frame.serialize())

        requests = [e for e in events if isinstance(e, h2.events.RequestReceived)]
        assert [e.stream_id for e in requests] == [1, 3]

        with pytest.raises(h2.exceptions.StreamIDTooLowError) as exc_info:
            send_probe(conn, frame_factory, 1, FrameKind.HEADERS)
        assert exc_info.value.stream_id == 1
        assert exc_info.value.max_stream_id == 3

        expected = frame_factory.build_goaway_frame(last_stream_id=3, error_code=h2.errors.ErrorCodes.PROTOCOL_ERROR)
        assert conn.data_to_send() == expected.serialize()

        # Stream 1 was not re-opened, and the history stays bounded.
        assert 1 not in conn.streams
        assert conn.highest_inbound_stream_id == 3
        assert list(conn._closed_streams) == [3]

    def test_closed_stream_history_memory_stays_bounded(self, frame_factory, monkeypatch) -> None:
        """
        Closing arbitrarily many streams keeps the closed-stream history at
        most MAX_CLOSED_STREAMS entries, retaining only the most recent
        closures, and sweeps closed streams out of the live stream map.
        """
        monkeypatch.setattr(h2.connection.H2Connection, "MAX_CLOSED_STREAMS", HISTORY_CAPACITY)
        conn = server_connection(frame_factory)

        stream_ids = list(range(1, 2 * (3 * HISTORY_CAPACITY + 1), 2))
        for stream_id in stream_ids:
            server_close_stream(conn, frame_factory, stream_id, StreamFate.END_STREAM)
            assert len(conn._closed_streams) <= HISTORY_CAPACITY

        # Force the final sweep of closed streams out of the live map.
        assert conn.open_inbound_streams == 0

        assert list(conn._closed_streams) == stream_ids[-HISTORY_CAPACITY:]
        assert not conn.streams
        assert conn.highest_inbound_stream_id == stream_ids[-1]


class TestClientClosedStreamEviction:
    """
    Client role: the client opens streams, the history of how they closed
    is evicted, and the server then probes the old stream IDs.
    """

    @pytest.mark.parametrize("remembered", [True, False])
    @pytest.mark.parametrize(
        "fate",
        [
            StreamFate.NEVER_OPENED,
            StreamFate.END_STREAM,
            StreamFate.RST_STREAM_SENT,
            StreamFate.RST_STREAM_RECEIVED,
        ],
    )
    def test_headers_on_old_stream_id_never_reopens(self, frame_factory, monkeypatch, fate, remembered) -> None:
        """
        Response HEADERS for a stream ID at or below the highest one the
        client opened must never re-open that stream, whether or not its
        close cause is still remembered.
        """
        monkeypatch.setattr(h2.connection.H2Connection, "MAX_CLOSED_STREAMS", HISTORY_CAPACITY)
        conn = client_connection()

        target = 1
        if fate is StreamFate.NEVER_OPENED:
            # Open a higher stream so that stream 1 is skipped over.
            client_close_stream(conn, frame_factory, 3, StreamFate.END_STREAM)
        else:
            client_close_stream(conn, frame_factory, target, fate)

        if not remembered:
            evict_client_history(conn, frame_factory)
            assert target not in conn._closed_streams

        highest_outbound_before = conn.highest_outbound_stream_id
        outcome = expected_outcome(fate, remembered, FrameKind.HEADERS)
        assert_headers_outcome(
            conn, frame_factory, target, outcome,
            max_stream_id=highest_outbound_before,
            goaway_last_stream_id=conn.highest_inbound_stream_id,
        )

        # The probe must not have produced a response or moved the high-water mark.
        if remembered and fate is not StreamFate.NEVER_OPENED:
            # The closed stream object may still await the periodic sweep;
            # the point is that it was not re-opened.
            assert conn.streams[target].closed
        else:
            assert target not in conn.streams
        assert conn.highest_outbound_stream_id == highest_outbound_before
        assert len(conn._closed_streams) <= HISTORY_CAPACITY

    def test_non_headers_frames_on_evicted_stream(self, frame_factory, monkeypatch) -> None:
        """
        PRIORITY, RST_STREAM and WINDOW_UPDATE for an evicted client stream
        are ignored (or acknowledged for PRIORITY) without re-opening it.
        """
        monkeypatch.setattr(h2.connection.H2Connection, "MAX_CLOSED_STREAMS", HISTORY_CAPACITY)
        conn = client_connection()

        target = 1
        client_close_stream(conn, frame_factory, target, StreamFate.END_STREAM)
        evict_client_history(conn, frame_factory)
        assert target not in conn._closed_streams

        highest_outbound_before = conn.highest_outbound_stream_id

        events = send_probe(conn, frame_factory, target, FrameKind.PRIORITY)
        assert len(events) == 1
        assert isinstance(events[0], h2.events.PriorityUpdated)
        assert events[0].stream_id == target

        assert send_probe(conn, frame_factory, target, FrameKind.WINDOW_UPDATE) == []
        assert send_probe(conn, frame_factory, target, FrameKind.RST_STREAM) == []

        assert conn.data_to_send() == b""
        assert target not in conn.streams
        assert conn.highest_outbound_stream_id == highest_outbound_before

        # The connection is unharmed: the next client stream still works.
        events = []
        new_stream_id = highest_outbound_before + 2
        conn.send_headers(new_stream_id, REQUEST_HEADERS)
        frame = frame_factory.build_headers_frame(RESPONSE_HEADERS, stream_id=new_stream_id, flags=["END_HEADERS"])
        events += conn.receive_data(frame.serialize())
        assert isinstance(events[0], h2.events.ResponseReceived)
        assert events[0].stream_id == new_stream_id


class TestReservedStreamsDistinctFromClosed:
    """
    Reserved (pushed) streams are not closed: they never enter the
    closed-stream history, so evicting that history must not change how
    their frames are handled, and they must not be confused with either
    closed or idle streams.
    """

    def test_reserved_stream_unaffected_by_history_eviction(self, frame_factory, monkeypatch) -> None:
        """
        A reserved(remote) pushed stream keeps its full state while the
        closed-stream history around it is evicted: WINDOW_UPDATE, PRIORITY
        and the pushed response HEADERS are all still processed normally.
        """
        monkeypatch.setattr(h2.connection.H2Connection, "MAX_CLOSED_STREAMS", HISTORY_CAPACITY)
        conn = client_connection()

        conn.send_headers(1, REQUEST_HEADERS, end_stream=True)
        conn.clear_outbound_data_buffer()
        frame = frame_factory.build_push_promise_frame(stream_id=1, promised_stream_id=2, headers=REQUEST_HEADERS)
        events = conn.receive_data(frame.serialize())
        assert isinstance(events[0], h2.events.PushedStreamReceived)
        conn.clear_outbound_data_buffer()

        evict_client_history(conn, frame_factory)

        # The reserved stream was never closed, so it is not in the history
        # and eviction could not touch it.
        assert 2 not in conn._closed_streams
        assert 2 in conn.streams

        # WINDOW_UPDATE is legal on reserved streams (RFC 7540 § 5.1).
        events = send_probe(conn, frame_factory, 2, FrameKind.WINDOW_UPDATE)
        assert len(events) == 1
        assert isinstance(events[0], h2.events.WindowUpdated)
        assert events[0].stream_id == 2

        # PRIORITY is legal in any stream state.
        events = send_probe(conn, frame_factory, 2, FrameKind.PRIORITY)
        assert len(events) == 1
        assert isinstance(events[0], h2.events.PriorityUpdated)

        # HEADERS delivers the pushed response: the stream opens normally.
        frame = frame_factory.build_headers_frame(RESPONSE_HEADERS, stream_id=2, flags=["END_HEADERS"])
        events = conn.receive_data(frame.serialize())
        assert isinstance(events[0], h2.events.ResponseReceived)
        assert events[0].stream_id == 2

    def test_reset_reserved_stream_then_behaves_as_closed(self, frame_factory, monkeypatch) -> None:
        """
        Resetting a reserved stream closes it: from then on its frames
        follow the closed-stream rules (recorded in the bounded history),
        not the reserved or idle ones.
        """
        monkeypatch.setattr(h2.connection.H2Connection, "MAX_CLOSED_STREAMS", HISTORY_CAPACITY)
        conn = client_connection()

        conn.send_headers(1, REQUEST_HEADERS, end_stream=True)
        conn.clear_outbound_data_buffer()
        frame = frame_factory.build_push_promise_frame(stream_id=1, promised_stream_id=2, headers=REQUEST_HEADERS)
        conn.receive_data(frame.serialize())
        conn.clear_outbound_data_buffer()

        events = send_probe(conn, frame_factory, 2, FrameKind.RST_STREAM)
        assert len(events) == 1
        assert isinstance(events[0], h2.events.StreamReset)
        assert events[0].stream_id == 2

        # Force the sweep so the closed stream lands in the history.
        assert conn.open_inbound_streams == 0
        assert conn._closed_streams[2] is not None

        # Further RST_STREAM and WINDOW_UPDATE frames are silently dropped.
        assert send_probe(conn, frame_factory, 2, FrameKind.RST_STREAM) == []
        assert send_probe(conn, frame_factory, 2, FrameKind.WINDOW_UPDATE) == []
        assert conn.data_to_send() == b""

        # HEADERS on the reset-closed stream is a stream error STREAM_CLOSED.
        assert_headers_outcome(
            conn, frame_factory, 2, ProbeOutcome.STREAM_ERROR,
            max_stream_id=2,
            goaway_last_stream_id=2,
        )
