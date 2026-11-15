"""
Tests for the opt-in structured connection diagnostics.

These tests focus on the diagnostic record itself (wire ranges, pre-failure
state, delivered-event boundary and payload-free summaries) and on the guarantee
that enabling diagnostics never changes normal output or protocol responses.
"""
from __future__ import annotations

import pytest

import h2.config
import h2.connection
import h2.diagnostics
import h2.exceptions
import h2.settings
from hyperframe.frame import (
    ContinuationFrame,
    DataFrame,
    HeadersFrame,
    SettingsFrame,
)

REQUEST_HEADERS = [
    (b":authority", b"example.com"),
    (b":path", b"/"),
    (b":scheme", b"https"),
    (b":method", b"GET"),
]
PREAMBLE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def raw_extension_frame(frame_type: int, stream_id: int, body: bytes) -> bytes:
    """Serialize an extension frame directly, since ExtensionFrame.serialize
    does not emit a raw body."""
    header = (
        len(body).to_bytes(3, "big")
        + bytes([frame_type, 0x00])
        + stream_id.to_bytes(4, "big")
    )
    return header + body


def make_server(enable: bool = True) -> h2.connection.H2Connection:
    config = h2.config.H2Configuration(
        client_side=False,
        enable_diagnostics=enable,
    )
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    conn.receive_data(PREAMBLE)
    conn.clear_outbound_data_buffer()
    return conn


def make_client(enable: bool = True) -> h2.connection.H2Connection:
    config = h2.config.H2Configuration(
        client_side=True,
        enable_diagnostics=enable,
    )
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    conn.clear_outbound_data_buffer()
    return conn


class TestConfiguration:
    def test_disabled_by_default(self) -> None:
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False),
        )
        assert conn.diagnostics is None

    def test_enabled_exposes_record(self) -> None:
        conn = make_server()
        diagnostics = conn.diagnostics
        assert isinstance(diagnostics, h2.diagnostics.ConnectionDiagnostics)
        assert diagnostics.entries == []
        assert diagnostics.errors == []
        assert diagnostics.observations == []
        assert diagnostics.last_error is None
        assert diagnostics.boundary.delivered_event_count == 0
        assert diagnostics.boundary.delivered_wire_end == 0

    def test_must_be_bool(self) -> None:
        with pytest.raises(ValueError):
            h2.config.H2Configuration(enable_diagnostics="yes")  # type: ignore[arg-type]

    def test_reset_clears_record(self, frame_factory) -> None:
        conn = make_server()
        data = raw_extension_frame(0xFF, 0, b"\x01\x02")
        conn.receive_data(data)
        assert len(conn.diagnostics.observations) == 1

        conn.diagnostics.reset()
        assert conn.diagnostics.entries == []
        assert conn.diagnostics.boundary.delivered_event_count == 0


class TestUnknownFrame:
    def test_unknown_frame_is_observation(self) -> None:
        conn = make_server()
        body = b"secret-extension-payload"
        data = raw_extension_frame(0xFF, 3, body)

        events = conn.receive_data(data)
        assert len(events) == 1
        assert isinstance(events[0], h2.events.UnknownFrameReceived)

        diagnostics = conn.diagnostics
        assert diagnostics.errors == []
        observation = diagnostics.observations[0]
        assert observation.category == h2.diagnostics.CATEGORY_UNKNOWN_FRAME
        assert observation.fatal is False
        # The frame begins immediately after the 24-byte preamble.
        assert observation.frame_range.as_tuple() == (24, 24 + len(data))
        assert observation.frame is not None
        assert observation.frame.frame_type == 0xFF
        assert observation.frame.stream_id == 3
        assert observation.frame.declared_length == len(body)
        # The raw extension payload must not be retained.
        assert "secret-extension-payload" not in repr(diagnostics)

    def test_unknown_frame_advances_boundary(self) -> None:
        conn = make_server()
        body = b"abcd"
        data = raw_extension_frame(0x20, 0, body)
        conn.receive_data(data)
        boundary = conn.diagnostics.boundary
        assert boundary.delivered_event_count == 1
        assert boundary.delivered_wire_end == 24 + 9 + len(body)


class TestLengthErrors:
    def test_overlong_frame(self) -> None:
        conn = make_server()
        # Negotiate a small-but-legal max frame size.
        settings = SettingsFrame(0)
        settings.settings = {
            h2.settings.SettingCodes.MAX_FRAME_SIZE: 16384,
        }
        conn.receive_data(settings.serialize())
        conn.clear_outbound_data_buffer()

        header = (
            (20000).to_bytes(3, "big")
            + bytes([0x0, 0x0])
            + (1).to_bytes(4, "big")
        )
        with pytest.raises(h2.exceptions.FrameTooLargeError):
            conn.receive_data(header + b"\x00" * 20000)

        error = conn.diagnostics.last_error
        assert error is not None
        assert error.category == h2.diagnostics.CATEGORY_LENGTH_ERROR
        # The preamble (24) and the SETTINGS frame (15) precede it.
        assert error.frame_range.as_tuple() == (39, 48)
        assert error.frame is not None
        assert error.frame.declared_length == 20000

    def test_frame_data_missing_is_length_error(self) -> None:
        conn = make_server()
        # WINDOW_UPDATE declaring a 3-byte body (needs 4) -> FrameDataMissing.
        bad_window_update = b"\x00\x00\x03\x08\x00\x00\x00\x00\x00\x00\x00\x02"
        with pytest.raises(h2.exceptions.FrameDataMissingError):
            conn.receive_data(bad_window_update)

        error = conn.diagnostics.last_error
        assert error is not None
        assert error.category == h2.diagnostics.CATEGORY_LENGTH_ERROR
        assert error.frame_range is not None
        assert error.frame_range.start == 24
        assert error.frame.frame_type == 0x8


class TestStateErrors:
    def test_data_before_headers_is_state_error(self) -> None:
        conn = make_client()
        data_frame = DataFrame(1)
        data_frame.data = b"confidential body"
        with pytest.raises(h2.exceptions.ProtocolError):
            conn.receive_data(data_frame.serialize())

        error = conn.diagnostics.last_error
        assert error is not None
        assert error.category == h2.diagnostics.CATEGORY_STATE_ERROR
        assert error.frame_range is not None
        # The connection had not left the idle state before the bad input.
        assert error.connection_state == "IDLE"
        assert "confidential body" not in repr(conn.diagnostics)

    def test_pre_failure_stream_state_is_preserved(self, frame_factory) -> None:
        # HEADERS that establish then half-close a stream, followed by a naked
        # CONTINUATION rejected by the stream state machine.
        conn = make_server()
        headers_frame = frame_factory.build_headers_frame(
            REQUEST_HEADERS,
            flags=["END_STREAM"],
        )
        conn.receive_data(headers_frame.serialize())

        bad_continuation = frame_factory.build_continuation_frame(
            header_block=b"z",
        )
        with pytest.raises(h2.exceptions.ProtocolError):
            conn.receive_data(bad_continuation.serialize())

        error = conn.diagnostics.last_error
        assert error is not None
        assert error.category == h2.diagnostics.CATEGORY_STATE_ERROR
        # The stream had been half-closed (remote) before the bad transition.
        assert error.stream_state == "HALF_CLOSED_REMOTE"
        assert error.connection_state == "SERVER_OPEN"

    def test_hpack_decode_error_marks_single_frame_block(self) -> None:
        conn = make_server()
        headers_frame = HeadersFrame(1)
        headers_frame.data = b"\x00\x00\x00\x00"
        headers_frame.flags.add("END_HEADERS")
        with pytest.raises(h2.exceptions.ProtocolError):
            conn.receive_data(headers_frame.serialize())

        error = conn.diagnostics.last_error
        assert error is not None
        assert error.category == h2.diagnostics.CATEGORY_STATE_ERROR
        # A single HEADERS frame is its own header block.
        assert error.frame_range == error.header_block_range
        assert error.frame_range is not None
        assert error.frame_range.start == 24

    def test_invalid_padding(self) -> None:
        conn = make_server()
        invalid_data_frame = (
            b"\x00\x00\x05\x00\x0b\x00\x00\x00\x01\x06\x54\x65\x73\x74"
        )
        with pytest.raises(h2.exceptions.ProtocolError):
            conn.receive_data(invalid_data_frame)

        error = conn.diagnostics.last_error
        assert error is not None
        assert error.category == h2.diagnostics.CATEGORY_STATE_ERROR
        assert error.frame is not None
        assert error.frame.frame_type == 0x0
        assert error.frame_range.as_tuple() == (24, 24 + 14)


class TestPreambleError:
    def test_bad_preamble(self) -> None:
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(
                client_side=False,
                enable_diagnostics=True,
            ),
        )
        conn.initiate_connection()
        with pytest.raises(h2.exceptions.ProtocolError):
            conn.receive_data(b"PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n")

        error = conn.diagnostics.last_error
        assert error is not None
        assert error.category == h2.diagnostics.CATEGORY_PREAMBLE_ERROR
        assert error.frame_range is not None
        assert error.frame_range.start == 0

    def test_bad_preamble_after_partial_match(self) -> None:
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(
                client_side=False,
                enable_diagnostics=True,
            ),
        )
        conn.initiate_connection()
        conn.receive_data(PREAMBLE[:22])
        with pytest.raises(h2.exceptions.ProtocolError):
            conn.receive_data(b"\x00\x00")

        error = conn.diagnostics.last_error
        assert error is not None
        assert error.category == h2.diagnostics.CATEGORY_PREAMBLE_ERROR
        assert error.frame_range.start == 22


class TestContinuationBlock:
    def _build_interrupted_block(self, frame_factory):
        headers_frame = frame_factory.build_headers_frame(REQUEST_HEADERS)
        headers_frame.flags = set()  # No END_HEADERS: start a block.

        continuation = frame_factory.build_continuation_frame(
            header_block=b"abc",
        )
        continuation.flags = set()

        # A DATA frame interleaved into the open block is illegal.
        interleaved = frame_factory.build_data_frame(data=b"x")
        return headers_frame, continuation, interleaved

    def test_block_range_and_failing_frame(self, frame_factory) -> None:
        conn = make_server()
        headers_frame, continuation, interleaved = self._build_interrupted_block(
            frame_factory,
        )
        blob = (
            headers_frame.serialize()
            + continuation.serialize()
            + interleaved.serialize()
        )
        with pytest.raises(h2.exceptions.ProtocolError):
            conn.receive_data(blob)

        headers_len = len(headers_frame.serialize())
        continuation_len = len(continuation.serialize())
        interleaved_len = len(interleaved.serialize())

        error = conn.diagnostics.last_error
        assert error is not None
        assert error.category == h2.diagnostics.CATEGORY_STATE_ERROR
        # Full block begins at the HEADERS frame (right after the preamble).
        assert error.header_block_range is not None
        assert error.header_block_range.start == 24
        # The block stays open through the point the illegal frame is rejected.
        assert error.header_block_range.end == (
            24 + headers_len + continuation_len + interleaved_len
        )
        # The failing frame is the interleaved DATA frame.
        assert error.frame_range is not None
        assert error.frame_range.start == 24 + headers_len + continuation_len
        assert error.frame_range.end == (
            24 + headers_len + continuation_len + interleaved_len
        )
        assert error.frame.frame_type == 0x0

    def test_too_many_continuations(self, frame_factory) -> None:
        conn = make_server()
        headers_frame = frame_factory.build_headers_frame(REQUEST_HEADERS)
        headers_frame.flags = {"END_STREAM"}
        conn.receive_data(headers_frame.serialize())
        conn.clear_outbound_data_buffer()

        # CONTINUATION_BACKLOG is 64: the 64th continuation (HEADERS plus 63
        # already buffered) exceeds the limit and must fail.
        for _ in range(63):
            extra = frame_factory.build_continuation_frame(header_block=b"hi")
            conn.receive_data(extra.serialize())

        overflow = frame_factory.build_continuation_frame(header_block=b"hi")
        with pytest.raises(h2.exceptions.ProtocolError):
            conn.receive_data(overflow.serialize())

        error = conn.diagnostics.last_error
        assert error is not None
        assert error.category == h2.diagnostics.CATEGORY_STATE_ERROR
        assert "Too many continuation" in error.message
        assert error.header_block_range is not None
        assert error.header_block_range.start == 24
        assert error.frame is not None
        assert error.frame.frame_type == 0x9

    @pytest.mark.parametrize(
        "splitter",
        [
            lambda blob: [blob],
            lambda blob: [bytes([byte]) for byte in blob],
            lambda blob: [blob[:7], blob[7:30], blob[30:]],
            lambda blob: [blob[:1], blob[1:]],
        ],
    )
    def test_ranges_stable_across_chunking(self, frame_factory, splitter) -> None:
        headers_frame, continuation, interleaved = self._build_interrupted_block(
            frame_factory,
        )
        blob = (
            headers_frame.serialize()
            + continuation.serialize()
            + interleaved.serialize()
        )

        def ranges() -> tuple[tuple[int, int], tuple[int, int]]:
            conn = make_server()
            with pytest.raises(h2.exceptions.ProtocolError):
                for chunk in splitter(blob):
                    conn.receive_data(chunk)
            error = conn.diagnostics.last_error
            assert error is not None
            assert error.header_block_range is not None
            assert error.frame_range is not None
            return (
                error.header_block_range.as_tuple(),
                error.frame_range.as_tuple(),
            )

        expected_block_start = 24
        block_end = 24 + len(headers_frame.serialize()) + len(continuation.serialize())
        frame_end = block_end + len(interleaved.serialize())
        expected = (
            (expected_block_start, frame_end),
            (block_end, frame_end),
        )
        assert ranges() == expected


class TestDeliveredBoundary:
    def test_undelivered_events_not_counted(self, frame_factory) -> None:
        conn = make_server()
        good = frame_factory.build_headers_frame(
            REQUEST_HEADERS,
            flags=["END_STREAM"],
        )
        bad = frame_factory.build_data_frame(data=b"more")
        blob = good.serialize() + bad.serialize()

        # DATA on an END_STREAM-closed stream triggers an auto RST rather than
        # a raised connection error, but the offending frame still produces no
        # delivered request/response events.
        events = conn.receive_data(blob)
        delivered_requests = [
            event for event in events if not isinstance(event, h2.events.StreamReset)
        ]

        boundary = conn.diagnostics.boundary
        assert boundary.delivered_event_count == len(events)
        assert boundary.delivered_wire_end == 24 + len(good.serialize()) + len(bad.serialize())
        # The request events all came from the HEADERS frame.
        assert all(
            event.stream_id == 1 for event in delivered_requests
        )

    def test_successful_block_delivery_boundary(self, frame_factory) -> None:
        conn = make_server()
        headers_frame = frame_factory.build_headers_frame(REQUEST_HEADERS)
        headers_frame.flags = set()
        continuation = frame_factory.build_continuation_frame(
            header_block=b"",
            flags=["END_HEADERS"],
        )
        conn.receive_data(headers_frame.serialize() + continuation.serialize())

        boundary = conn.diagnostics.boundary
        total = len(headers_frame.serialize()) + len(continuation.serialize())
        assert boundary.delivered_wire_end == 24 + total
        assert boundary.delivered_event_count >= 1


class TestPrivacy:
    def test_authorization_header_not_captured(self, frame_factory) -> None:
        conn = make_server()
        headers = REQUEST_HEADERS + [(b"authorization", b"Bearer secret-token")]
        headers_frame = frame_factory.build_headers_frame(
            headers,
            flags=["END_STREAM"],
        )
        request_events = conn.receive_data(headers_frame.serialize())
        assert request_events
        # Follow with an out-of-state frame that raises a connection error.
        bad_continuation = frame_factory.build_continuation_frame(
            header_block=b"z",
        )
        with pytest.raises(h2.exceptions.ProtocolError):
            conn.receive_data(bad_continuation.serialize())

        rendered = repr(conn.diagnostics)
        assert "Bearer" not in rendered
        assert "secret-token" not in rendered
        # Only lengths and structural metadata are kept on the fatal entry.
        error = conn.diagnostics.last_error
        assert error is not None
        assert error.frame is not None
        assert isinstance(error.frame.payload_length, int)


class TestNonInterference:
    def _drive(self, conn, frame_factory) -> tuple[list, bytes]:
        # A representative mix of valid traffic.
        headers = frame_factory.build_headers_frame(
            REQUEST_HEADERS,
            flags=["END_STREAM"],
        )
        events = conn.receive_data(headers.serialize())
        outbound = conn.data_to_send()
        return events, outbound

    def test_events_and_output_identical(self, frame_factory) -> None:
        enabled = make_server(True)
        disabled = make_server(False)
        # Use independent encoders so each connection sees an identical first
        # header block despite stateful HPACK compression.
        enabled_events, enabled_out = self._drive(enabled, frame_factory)
        frame_factory.refresh_encoder()
        disabled_events, disabled_out = self._drive(disabled, frame_factory)

        assert repr(enabled_events) == repr(disabled_events)
        assert enabled_out == disabled_out

    def test_error_response_identical(self, frame_factory) -> None:
        enabled = make_server(True)
        disabled = make_server(False)
        bad = frame_factory.build_data_frame(data=b"boom")

        for conn in (enabled, disabled):
            with pytest.raises(h2.exceptions.ProtocolError):
                conn.receive_data(bad.serialize())

        assert enabled.data_to_send() == disabled.data_to_send()
        # Same exception type and message regardless of diagnostics.
        enabled_error = enabled.diagnostics.last_error
        assert enabled_error is not None
        assert enabled_error.message

    def test_goaway_payload_unchanged(self, frame_factory) -> None:
        enabled = make_server(True)
        disabled = make_server(False)
        invalid = b"\x00\x00\x03\x08\x00\x00\x00\x00\x00\x00\x00\x02"
        for conn in (enabled, disabled):
            with pytest.raises(h2.exceptions.FrameDataMissingError):
                conn.receive_data(invalid)
        assert enabled.data_to_send() == disabled.data_to_send()


class TestPushPromiseBlock:
    def test_push_promise_opens_and_closes_block(self, frame_factory) -> None:
        # Client side: a PUSH_PROMISE without END_HEADERS starts a block that a
        # CONTINUATION completes. Ensure offsets remain coherent end to end.
        conn = make_client()
        conn.send_headers(1, REQUEST_HEADERS, end_stream=True)
        conn.clear_outbound_data_buffer()

        push = frame_factory.build_push_promise_frame(
            stream_id=1,
            promised_stream_id=2,
            headers=REQUEST_HEADERS,
        )
        push.flags.discard("END_HEADERS")
        # The CONTINUATION shares the PUSH_PROMISE stream id (1), not the
        # promised stream id (2).
        continuation = ContinuationFrame(1)
        continuation.data = b""
        continuation.flags.add("END_HEADERS")

        events = conn.receive_data(push.serialize() + continuation.serialize())
        assert events
        boundary = conn.diagnostics.boundary
        assert boundary.delivered_wire_end > 0
