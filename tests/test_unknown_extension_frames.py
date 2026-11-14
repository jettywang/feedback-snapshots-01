"""
Mutation tests for unknown HTTP/2 extension frames.

RFC 9113 § 5.5 (like RFC 7540 § 5.5 before it) requires endpoints to ignore
frames of unknown type: they must not alter connection state, must not
change the identity, body, or end state of in-flight requests, and their
payloads must be treated as opaque bytes. These tests mutate an otherwise
ordinary request/response exchange by splicing generated extension frames
(with independently generated type, flags, stream ID, and length) into every
position where they are legal, and assert that the business-visible outcome
on both peers is indistinguishable from an unmutated baseline run.

They also assert the inverse: positions where an extension frame is *not*
legal (before the connection preface, or interleaved inside a
HEADERS/CONTINUATION block) must be rejected, and unknown frames remain
bound by the connection's maximum frame size. Payload bytes that look like
a frame header must never be re-parsed as a frame.

All comparisons run against a deterministic (fixed-seed) baseline. On
mismatch a minimal unified diff is written to ``mutation_diffs/`` (override
the location with the ``H2_MUTATION_DIFF_DIR`` environment variable).
"""
from __future__ import annotations

import difflib
import os
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from hyperframe.frame import ExtensionFrame

import h2.config
import h2.connection
import h2.events
import h2.exceptions

from . import helpers

REQUEST_HEADERS = [
    (":method", "POST"),
    (":path", "/mutation"),
    (":authority", "example.com"),
    (":scheme", "https"),
    ("user-agent", "test-client/0.1.0"),
]
RESPONSE_HEADERS = [
    (":status", "200"),
    ("server", "test-server/0.1.0"),
]
REQUEST_BODY = b"mutate-me" * 16
RESPONSE_BODY = b"mutated-ok" * 16

CLIENT_PREAMBLE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

SERVER_CONFIG = h2.config.H2Configuration(client_side=False)
CLIENT_CONFIG = h2.config.H2Configuration(client_side=True)

# The default SETTINGS_MAX_FRAME_SIZE both peers start with (RFC 9113 § 6.5.2).
DEFAULT_MAX_FRAME_SIZE = 2**14

# Boundary names for the client-to-server byte stream, whose segments are
# [preamble, SETTINGS, HEADERS, DATA], and for the server-to-client stream,
# whose segments are [SETTINGS, SETTINGS-ACK, HEADERS, DATA].
CLIENT_SEGMENTS = ("preamble", "settings", "headers", "data")
SERVER_SEGMENTS = ("settings", "settings_ack", "headers", "data")

# Positions where RFC 9113 § 5.5 permits unknown extension frames: anywhere
# between whole frames once the connection preface has been sent, including
# before the peer's first SETTINGS frame (h2 ignores them there, per the
# "implementations MUST ignore frames of unknown type" rule of § 4.1/§ 5.5).
ALLOWED_POSITIONS = [
    ("c2s", "after_preamble"),
    ("c2s", "after_settings"),
    ("c2s", "after_headers"),
    ("c2s", "after_data"),
    ("s2c", "before_settings"),
    ("s2c", "after_settings"),
    ("s2c", "after_settings_ack"),
    ("s2c", "after_headers"),
    ("s2c", "after_data"),
]

DIFF_DIR = Path(
    os.environ.get(
        "H2_MUTATION_DIFF_DIR",
        Path(__file__).resolve().parent.parent / "mutation_diffs",
    )
)


def build_extension_frame(frame_type, flag_byte, stream_id, payload):
    """
    Serialize an unknown extension frame with the given type byte, flag byte,
    stream ID, and opaque payload.
    """
    frame = ExtensionFrame(
        type=frame_type, stream_id=stream_id, flag_byte=flag_byte, body=payload,
    )
    frame.body_len = len(payload)
    return frame.serialize()


def split_frames(data):
    """
    Split a byte string of concatenated HTTP/2 frames into a list of the
    individual serialized frames.
    """
    frames = []
    while data:
        length = int.from_bytes(data[:3], "big")
        frames.append(data[:9 + length])
        data = data[9 + length:]
    return frames


def boundary_index(segments, boundary):
    """
    Map a boundary name like ``after_headers`` to the segment index at which
    injected frames should be spliced in.
    """
    if boundary.startswith("before_"):
        return segments.index(boundary[len("before_"):])
    if boundary.startswith("after_"):
        return segments.index(boundary[len("after_"):]) + 1
    msg = f"Unknown boundary: {boundary}"
    raise ValueError(msg)


def connection_state_lines(side, conn):
    """
    Render the business-relevant state of one endpoint as comparable lines.
    """
    lines = [
        f"{side}.state.connection = {conn.state_machine.state!r}",
        f"{side}.state.highest_inbound_stream_id = {conn.highest_inbound_stream_id!r}",
        f"{side}.state.highest_outbound_stream_id = {conn.highest_outbound_stream_id!r}",
        f"{side}.state.inbound_flow_control_window = {conn.inbound_flow_control_window!r}",
        f"{side}.state.outbound_flow_control_window = {conn.outbound_flow_control_window!r}",
    ]
    for stream_id, stream in sorted(conn.streams.items()):
        lines.append(
            f"{side}.state.stream[{stream_id}] = {stream.state_machine.state!r}",
        )
    lines.append(f"{side}.state.pending_outbound = {conn.data_to_send()!r}")
    return lines


def event_signature(event):
    """
    Render an event, including every populated attribute, as one comparable
    line.
    """
    fields = ", ".join(
        f"{name}={value!r}" for name, value in sorted(vars(event).items())
    )
    return f"{type(event).__name__}({fields})"


def business_outcome_lines(outcome):
    """
    Render the business-visible outcome of a run: every event except the
    expected UnknownFrameReceived notifications, plus the end state of both
    endpoints.
    """
    lines = []
    for side in ("client", "server"):
        events = [
            event for event in outcome[f"{side}_events"]
            if not isinstance(event, h2.events.UnknownFrameReceived)
        ]
        for index, event in enumerate(events):
            lines.append(f"{side}.event[{index}] = {event_signature(event)}")
        lines.extend(connection_state_lines(side, outcome[f"{side}_conn"]))
    return lines


def assert_same_business_outcome(baseline, mutated, label):
    """
    Assert that a mutated run produced the same business events and the same
    end state on both endpoints as the baseline. On mismatch, save a minimal
    unified diff to ``mutation_diffs/<label>.diff`` and fail.
    """
    baseline_lines = business_outcome_lines(baseline)
    mutated_lines = business_outcome_lines(mutated)
    if baseline_lines == mutated_lines:
        return

    diff = list(
        difflib.unified_diff(
            baseline_lines, mutated_lines,
            fromfile="baseline", tofile="mutated", n=0, lineterm="",
        )
    )
    diff_text = "\n".join(diff)
    DIFF_DIR.mkdir(parents=True, exist_ok=True)
    diff_path = DIFF_DIR / f"{label}.diff"
    diff_path.write_text(diff_text + "\n", encoding="utf-8")
    msg = (
        "Extension frame mutation changed the business-visible outcome "
        f"(minimal diff saved to {diff_path}):\n{diff_text}"
    )
    raise AssertionError(msg)


def run_round_trip(c2s=None, s2c=None):
    """
    Drive a full request/response exchange between a real client and server
    H2Connection, optionally splicing raw frames into either direction at a
    named boundary. Returns the events and both endpoint connections.
    """
    client = h2.connection.H2Connection(config=CLIENT_CONFIG)
    server = h2.connection.H2Connection(config=SERVER_CONFIG)

    client.initiate_connection()
    client_preface = client.data_to_send()
    client.send_headers(1, REQUEST_HEADERS, end_stream=False)
    client.send_data(1, REQUEST_BODY, end_stream=True)
    client_segments = (
        [client_preface[:len(CLIENT_PREAMBLE)]]
        + split_frames(client_preface[len(CLIENT_PREAMBLE):])
        + split_frames(client.data_to_send())
    )
    assert len(client_segments) == len(CLIENT_SEGMENTS)
    if c2s is not None:
        boundary, frames = c2s
        index = boundary_index(CLIENT_SEGMENTS, boundary)
        client_segments[index:index] = frames

    server.initiate_connection()
    server_preface = server.data_to_send()
    server_events = server.receive_data(b"".join(client_segments))
    server.send_headers(1, RESPONSE_HEADERS, end_stream=False)
    server.send_data(1, RESPONSE_BODY, end_stream=True)
    server_segments = split_frames(server_preface + server.data_to_send())
    if s2c is not None:
        boundary, frames = s2c
        index = boundary_index(SERVER_SEGMENTS, boundary)
        server_segments[index:index] = frames

    client_events = client.receive_data(b"".join(server_segments))

    return {
        "client_events": client_events,
        "server_events": server_events,
        "client_conn": client,
        "server_conn": server,
    }


class TestUnknownExtensionFrames:
    """
    Unknown extension frames are transparent in legal positions, rejected in
    illegal ones, and never re-parsed.
    """

    @given(
        ext_type=st.integers(min_value=0x0B, max_value=0xFF),
        ext_flags=st.integers(min_value=0x00, max_value=0xFF),
        ext_stream_id=st.integers(min_value=0, max_value=0x7FFFFFFF),
        ext_length=st.integers(min_value=0, max_value=DEFAULT_MAX_FRAME_SIZE),
        position=st.sampled_from(ALLOWED_POSITIONS),
        data=st.data(),
    )
    @settings(
        derandomize=True,
        max_examples=60,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    def test_inserted_extension_frame_is_transparent(
        self, ext_type, ext_flags, ext_stream_id, ext_length, position, data,
    ) -> None:
        """
        An unknown extension frame spliced into any legal position leaves the
        request's identity, body, and stream end states untouched on both
        peers: the mutated run's business events and end states equal the
        fixed-seed baseline's.
        """
        payload = data.draw(
            st.binary(min_size=ext_length, max_size=ext_length), label="payload",
        )
        frame = build_extension_frame(ext_type, ext_flags, ext_stream_id, payload)

        direction, boundary = position
        baseline = run_round_trip()
        mutated = run_round_trip(**{direction: (boundary, [frame])})

        # The frame arrived intact and was surfaced exactly once, with its
        # type, flags, stream ID, and payload preserved byte-for-byte.
        unknown_events = [
            event
            for side in ("client", "server")
            for event in mutated[f"{side}_events"]
            if isinstance(event, h2.events.UnknownFrameReceived)
        ]
        assert len(unknown_events) == 1
        received = unknown_events[0].frame
        assert received.type == ext_type
        assert received.flag_byte == ext_flags
        assert received.stream_id == ext_stream_id
        assert received.body == payload

        assert_same_business_outcome(
            baseline, mutated, label=f"transparent_{direction}_{boundary}",
        )

    def test_extension_frame_before_preamble_rejected(self, frame_factory) -> None:
        """
        The connection preface must come first: an extension frame arriving
        before it is a protocol error, not an extension.
        """
        server = h2.connection.H2Connection(config=SERVER_CONFIG)
        frame = build_extension_frame(0x0B, 0x00, 0, b"too-early")

        with pytest.raises(h2.exceptions.ProtocolError, match="Invalid HTTP/2 preamble"):
            server.receive_data(frame)

    @pytest.mark.parametrize("position", ["before_continuation", "between_continuations"])
    @pytest.mark.parametrize("flag_byte", [0x00, 0x04, 0xFF])
    @pytest.mark.parametrize("ext_stream_id", [0, 1, 3])
    def test_extension_frame_inside_header_block_rejected(
        self, frame_factory, position, flag_byte, ext_stream_id,
    ) -> None:
        """
        Nothing may interrupt a HEADERS/CONTINUATION sequence (RFC 9113
        § 6.2/§ 6.10): an unknown frame there is a protocol error regardless
        of its flags or stream ID.
        """
        server = h2.connection.H2Connection(config=SERVER_CONFIG)
        server.initiate_connection()

        headers = frame_factory.build_headers_frame(REQUEST_HEADERS, stream_id=1)
        headers.flags.remove("END_HEADERS")
        first_continuation = frame_factory.build_continuation_frame(
            b"\x88" * 4, flags=[], stream_id=1,
        )
        last_continuation = frame_factory.build_continuation_frame(
            b"\x87" * 4, flags=["END_HEADERS"], stream_id=1,
        )
        extension = build_extension_frame(0x0B, flag_byte, ext_stream_id, b"intruder")

        segments = [
            frame_factory.preamble(),
            frame_factory.build_settings_frame({}).serialize(),
            headers.serialize(),
        ]
        if position == "before_continuation":
            segments += [extension, last_continuation.serialize()]
        else:
            segments += [
                first_continuation.serialize(), extension, last_continuation.serialize(),
            ]

        with pytest.raises(
            h2.exceptions.ProtocolError, match="Invalid frame during header block",
        ):
            server.receive_data(b"".join(segments))

    def test_overlong_extension_frame_rejected(self, frame_factory) -> None:
        """
        Unknown type does not exempt a frame from the connection's maximum
        frame size (RFC 9113 § 4.2).
        """
        server = h2.connection.H2Connection(config=SERVER_CONFIG)
        server.initiate_connection()
        server.receive_data(
            frame_factory.preamble() + frame_factory.build_settings_frame({}).serialize(),
        )

        frame = build_extension_frame(0x0B, 0x00, 0, b"x" * (DEFAULT_MAX_FRAME_SIZE + 1))
        with pytest.raises(h2.exceptions.FrameTooLargeError):
            server.receive_data(frame)

    def test_max_size_extension_frame_accepted(self, frame_factory) -> None:
        """
        An unknown frame exactly at the maximum frame size is legal and is
        delivered intact.
        """
        server = h2.connection.H2Connection(config=SERVER_CONFIG)
        server.initiate_connection()
        server.receive_data(
            frame_factory.preamble() + frame_factory.build_settings_frame({}).serialize(),
        )

        payload = bytes(DEFAULT_MAX_FRAME_SIZE)
        events = server.receive_data(build_extension_frame(0x0B, 0x00, 0, payload))
        assert len(events) == 1
        assert isinstance(events[0], h2.events.UnknownFrameReceived)
        assert events[0].frame.body == payload

    @pytest.mark.parametrize(
        "payload_kind",
        ["headers_frame", "data_frame", "settings_ack", "client_preamble"],
    )
    def test_frame_like_payload_is_not_reparsed(self, frame_factory, payload_kind) -> None:
        """
        Payload bytes that look exactly like a frame header (or the client
        preface) are opaque: the parser consumes them as payload and never
        re-parses them into frames or events.
        """
        payloads = {
            "headers_frame": frame_factory.build_headers_frame(
                REQUEST_HEADERS, stream_id=3, flags=["END_STREAM"],
            ).serialize(),
            "data_frame": frame_factory.build_data_frame(
                b"smuggled-body", stream_id=1,
            ).serialize(),
            "settings_ack": frame_factory.build_settings_frame({}, ack=True).serialize(),
            "client_preamble": frame_factory.preamble(),
        }
        payload = payloads[payload_kind]

        server = h2.connection.H2Connection(config=SERVER_CONFIG)
        server.initiate_connection()
        server.receive_data(
            frame_factory.preamble() + frame_factory.build_settings_frame({}).serialize(),
        )

        events = server.receive_data(build_extension_frame(0xFA, 0xA5, 0, payload))
        assert len(events) == 1
        assert isinstance(events[0], h2.events.UnknownFrameReceived)
        assert events[0].frame.body == payload
        # No stream was created and no further event was fired by the
        # frame-looking payload.
        assert server.streams == {}

        # The connection is unharmed: a real request is processed normally.
        # Refresh the encoder so its dynamic table matches the server's
        # decoder, which never saw the smuggled header block.
        frame_factory.refresh_encoder()
        real_request = frame_factory.build_headers_frame(
            REQUEST_HEADERS, stream_id=1, flags=["END_STREAM"],
        )
        events = server.receive_data(real_request.serialize())
        assert isinstance(events[0], h2.events.RequestReceived)
        assert events[0].headers == [
            (name.encode(), value.encode()) for name, value in REQUEST_HEADERS
        ]
        assert isinstance(events[1], h2.events.StreamEnded)

    def test_misaligned_extension_payload_flags_extra_events(self, frame_factory) -> None:
        """
        Self-test of the comparison criterion: when a misdeclared length
        makes the parser treat extension payload bytes as the next frame, the
        extra business events that appear must be flagged, and the minimal
        diff saved.
        """
        baseline = run_round_trip()

        ping = frame_factory.build_ping_frame(b"\xde\xad\xbe\xef\x00\x00\x00\x01")
        # The sender "intends" the PING bytes to be extension payload but
        # declares a length of 0, so the parser consumes them as a real PING
        # frame and produces an extra PingReceived business event.
        misdeclared = build_extension_frame(0x0B, 0x00, 0, b"") + ping.serialize()
        mutated = run_round_trip(c2s=("after_settings", [misdeclared]))

        with pytest.raises(AssertionError, match="PingReceived"):
            assert_same_business_outcome(
                baseline, mutated, label="misaligned_payload_as_frame",
            )

        diff_path = DIFF_DIR / "misaligned_payload_as_frame.diff"
        assert diff_path.exists()
        diff_text = diff_path.read_text(encoding="utf-8")
        # The extra business event produced by the misparse shows up as an
        # added event line in the saved minimal diff.
        added_events = [
            line for line in diff_text.splitlines()
            if line.startswith("+") and "PingReceived" in line
        ]
        assert added_events
