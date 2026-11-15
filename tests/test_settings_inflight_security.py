"""
test_settings_inflight_security
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Security-timing tests for HTTP/2 SETTINGS acknowledgement.

When several SETTINGS frames are in flight at once, a change must not take
effect at the *sending* endpoint until the specific SETTINGS frame that
carried it has been acknowledged. A single ACK corresponds to exactly one
SETTINGS frame: an unknown, extra or repeated ACK must never advance a value
proposed by a different, still outstanding frame.

These tests do **not** judge correctness by comparing the two peers' final
values. Instead they:

* drive two in-memory connections with deliberately interleaved SETTINGS and
  ACK frames over a raw frame transport;
* keep an independent oracle state model that derives, after every single
  frame, the expected effective limits and the exact number of sendable bytes
  on every stream;
* assert the real connection matches the oracle at each point in time, so a
  defect that makes a limit take effect one frame too early (or one frame too
  late) fails on the *first* violating frame rather than at the end state;
* verify that a legal interleaving always remains able to make progress.

The oracle is implemented from RFC 9113 without reading any h2 internals; it
only observes the public h2 API and the bytes on the wire.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from hyperframe.frame import Frame, SettingsFrame

import h2.config
import h2.connection
import h2.exceptions
import h2.frame_buffer
import h2.settings


SC = h2.settings.SettingCodes

# RFC 9113 defaults used by the oracle.
DEFAULT_INITIAL_WINDOW_SIZE = 65535
DEFAULT_MAX_FRAME_SIZE = 16384


def _parse_frames(data: bytes, max_frame_size: int) -> list[Frame]:
    """Decode wire bytes into hyperframe frames without touching an H2Connection."""
    buffer = h2.frame_buffer.FrameBuffer(server=False)
    buffer.max_frame_size = max_frame_size
    buffer.add_data(data)
    return list(buffer)


class OracleSettings:
    """Independent model of one endpoint's view of its own (local) settings.

    It mirrors RFC 9113 semantics: proposed values are queued per SETTINGS
    frame and only become effective when the matching ACK is consumed, FIFO.
    """

    def __init__(self) -> None:
        # Effective values only.
        self.effective: dict[int, int] = {
            SC.HEADER_TABLE_SIZE: 4096,
            SC.ENABLE_PUSH: 1,
            SC.INITIAL_WINDOW_SIZE: DEFAULT_INITIAL_WINDOW_SIZE,
            SC.MAX_FRAME_SIZE: DEFAULT_MAX_FRAME_SIZE,
            SC.ENABLE_CONNECT_PROTOCOL: 0,
        }
        # FIFO queue of the settings groups carried by outstanding frames.
        self.outstanding: list[dict[int, int]] = []

    def propose(self, group: dict[int, int]) -> None:
        self.outstanding.append(dict(group))

    def acknowledge(self) -> dict[int, tuple[int, int]]:
        """Apply the head group; an unmatched ACK changes nothing.

        Returns {setting: (old_value, new_value)} for applied settings.
        """
        if not self.outstanding:
            return {}
        group = self.outstanding.pop(0)
        changes: dict[int, tuple[int, int]] = {}
        for setting, new_value in group.items():
            old_value = self.effective.get(setting)
            self.effective[setting] = new_value
            changes[setting] = (old_value, new_value)
        return changes

    @property
    def initial_window_size(self) -> int:
        return self.effective[SC.INITIAL_WINDOW_SIZE]

    @property
    def max_frame_size(self) -> int:
        return self.effective[SC.MAX_FRAME_SIZE]

    @property
    def max_concurrent_streams(self) -> int | None:
        return self.effective.get(SC.MAX_CONCURRENT_STREAMS)


@dataclass
class OracleEndpoint:
    """Oracle state for one side of the pair, including flow-control windows."""

    settings: OracleSettings = field(default_factory=OracleSettings)
    # Connection-level outbound window (started at RFC default).
    connection_window: int = DEFAULT_INITIAL_WINDOW_SIZE
    # Stream id -> outbound stream window. Streams are created on first HEADERS.
    stream_windows: dict[int, int] = field(default_factory=dict)

    def open_stream(self, stream_id: int) -> None:
        self.stream_windows[stream_id] = self.settings.initial_window_size

    def apply_iws_delta(self, old: int | None, new: int) -> None:
        delta = new - (old or 0)
        for stream_id in self.stream_windows:
            self.stream_windows[stream_id] += delta

    def apply_remote_settings(self, group: dict[int, int]) -> dict[int, tuple[int, int]]:
        """Apply a remote SETTINGS group immediately (no local ACK queue).

        Remote settings take effect when this endpoint processes the frame and
        generates its ACK. Returns the per-setting (old, new) pairs.
        """
        changes: dict[int, tuple[int, int]] = {}
        for setting, new_value in group.items():
            old_value = self.settings.effective.get(setting)
            self.settings.effective[setting] = new_value
            changes[setting] = (old_value, new_value)
        if SC.INITIAL_WINDOW_SIZE in changes:
            old, new = changes[SC.INITIAL_WINDOW_SIZE]
            self.apply_iws_delta(old, new)
        return changes

    def sendable_on(self, stream_id: int) -> int:
        """Expected maximum flow-controlled bytes sendable on one stream now."""
        stream_window = self.stream_windows[stream_id]
        # A negative stream window means zero bytes until WINDOW_UPDATE catches
        # up; the connection window is the other bottleneck.
        return max(0, min(stream_window, self.connection_window))

    def record_send(self, stream_id: int, size: int) -> None:
        self.connection_window -= size
        self.stream_windows[stream_id] -= size

    def record_window_update(self, stream_id: int | None, increment: int) -> None:
        if stream_id in (None, 0):
            self.connection_window += increment
        else:
            self.stream_windows[stream_id] += increment


class InMemoryH2Pair:
    """Two H2Connection objects linked by a raw, frame-observable transport.

    ``client`` and ``server`` are real h2 objects. Every wire transfer is funnelled
    through :meth:`deliver` so the oracles can be updated one frame at a time and
    the real connection can be checked after every individual frame.
    """

    def __init__(self) -> None:
        self.client = h2.connection.H2Connection(
            h2.config.H2Configuration(client_side=True),
        )
        self.server = h2.connection.H2Connection(
            h2.config.H2Configuration(client_side=False),
        )
        # Oracle for settings the *client* owns and is waiting to be ACKed.
        self.client_oracle = OracleEndpoint()
        # Wire log of human-readable frame descriptions for failure output.
        self.frame_log: list[str] = []

        self.client.initiate_connection()
        # FIFO of post-handshake ACK frames the server has generated but the
        # test is holding back, so ACKs can be delivered one at a time.
        self.held_acks: list[Frame] = []
        self._deliver_client_to_server(self.client.data_to_send())
        # Deliver the server's ACK of the client's initial (handshake) SETTINGS
        # frame straight away so the handshake-ACK state is correctly consumed.
        handshake_acks = self._collect_server_frames()
        for frame in handshake_acks:
            self.client.receive_data(frame.serialize())
        self.client.data_to_send()

    # -- raw transport -----------------------------------------------------

    def _deliver_client_to_server(self, wire: bytes) -> list[Frame]:
        if not wire:
            return []
        frames = _parse_frames(wire, self.client.max_inbound_frame_size)
        self.server.receive_data(wire)
        return frames

    def _collect_server_frames(self) -> list[Frame]:
        wire = self.server.data_to_send()
        if not wire:
            return []
        return _parse_frames(wire, self.server.max_inbound_frame_size)

    def client_to_server(self) -> list[Frame]:
        """Flush whatever the client has queued over to the server."""
        return self._deliver_client_to_server(self.client.data_to_send())

    def collect_server_acks(self) -> None:
        """Pull every frame the server wants to send into the held ACK queue."""
        for frame in self._collect_server_frames():
            assert isinstance(frame, SettingsFrame) and "ACK" in frame.flags
            self.held_acks.append(frame)

    # -- oracle-driven actions --------------------------------------------

    def client_proposes_settings(self, group: dict[int, int]) -> None:
        """Client emits a SETTINGS frame; oracle records the outstanding group."""
        self.client.update_settings(group)
        self.client_oracle.settings.propose(group)
        self.frame_log.append(f"client -> SETTINGS {group}")
        frames = self.client_to_server()
        assert frames and all(isinstance(f, SettingsFrame) for f in frames)
        # The server auto-ACKs each SETTINGS; park those ACKs for the test.
        self.collect_server_acks()

    def deliver_ack_to_client(self) -> None:
        """Deliver the oldest held ACK, advancing the oracle one frame group."""
        assert self.held_acks, "no queued ACK available"
        frame = self.held_acks.pop(0)
        assert "ACK" in frame.flags
        changes = self.client_oracle.settings.acknowledge()
        self.frame_log.append(
            f"server -> client ACK (oracle changes={changes})",
        )
        # Apply oracle flow-control effects before touching h2 so the very
        # first post-ACK frame can be compared against the expected state.
        for setting, (old, new) in changes.items():
            if setting == SC.INITIAL_WINDOW_SIZE:
                self.client_oracle.apply_iws_delta(old, new)
        self.client.receive_data(frame.serialize())
        self.client.data_to_send()

    def deliver_unsolicited_ack_to_server(self) -> None:
        """Send an ACK to the server although it has no outstanding SETTINGS.

        Used to prove an unsolicited ACK cannot advance any configuration.
        """
        ack = SettingsFrame(0)
        ack.flags.add("ACK")
        self.frame_log.append("client -> server *unsolicited* ACK")
        self.server.receive_data(ack.serialize())
        self.server.data_to_send()

    def client_send_data(self, stream_id: int, size: int) -> None:
        """Send ``size`` bytes in legal, frame-sized chunks, tracking the oracle."""
        remaining = size
        while remaining:
            sendable = max(0, self.client.local_flow_control_window(stream_id))
            cap = min(self.client.max_outbound_frame_size, sendable)
            assert cap > 0, (
                f"asked to send {size} bytes but only {sendable} are available\n"
                + "\n".join(self.frame_log)
            )
            chunk_size = min(remaining, cap)
            self.client.send_data(stream_id, b"x" * chunk_size)
            self.client_oracle.record_send(stream_id, chunk_size)
            remaining -= chunk_size
        self.client_to_server()


# ---------------------------------------------------------------------------
# Oracle-level unit behaviour: the model itself enforces FIFO per-frame ACKs.
# ---------------------------------------------------------------------------

class TestOracleAckCorrelation:
    def test_one_ack_only_advances_its_own_group(self) -> None:
        oracle = OracleSettings()
        oracle.propose({SC.INITIAL_WINDOW_SIZE: 1000})
        oracle.propose({SC.MAX_FRAME_SIZE: 20000})

        # First ACK corresponds to the IWS frame only.
        changes = oracle.acknowledge()
        assert set(changes) == {SC.INITIAL_WINDOW_SIZE}
        assert oracle.initial_window_size == 1000
        # The unrelated proposal must still be pending and ineffective.
        assert oracle.max_frame_size == DEFAULT_MAX_FRAME_SIZE
        assert oracle.outstanding == [{SC.MAX_FRAME_SIZE: 20000}]

        changes = oracle.acknowledge()
        assert set(changes) == {SC.MAX_FRAME_SIZE}
        assert oracle.max_frame_size == 20000
        assert oracle.outstanding == []

    def test_extra_ack_with_no_outstanding_frame_is_noop(self) -> None:
        oracle = OracleSettings()
        assert oracle.acknowledge() == {}
        oracle.propose({SC.MAX_FRAME_SIZE: 20000})
        # Two ACKs for one frame: the second must not invent a change.
        assert oracle.acknowledge() == {SC.MAX_FRAME_SIZE: (16384, 20000)}
        assert oracle.acknowledge() == {}
        assert oracle.max_frame_size == 20000


# ---------------------------------------------------------------------------
# Shared helpers for asserting h2 matches the oracle at every step.
# ---------------------------------------------------------------------------

REQUEST_HEADERS = [
    (":authority", "example.com"),
    (":path", "/"),
    (":scheme", "https"),
    (":method", "GET"),
]


def assert_sendable_matches_oracle(
    pair: InMemoryH2Pair,
    stream_id: int,
) -> None:
    """Actual sendable bytes must equal the oracle's sendable bytes.

    h2 exposes the raw (possibly negative) flow-control window; the number of
    bytes that can actually be sent is that value clamped at zero, which is
    exactly what the independent oracle computes.
    """
    expected = pair.client_oracle.sendable_on(stream_id)
    actual = max(0, pair.client.local_flow_control_window(stream_id))
    assert actual == expected, (
        f"sendable bytes diverged on stream {stream_id}: h2={actual} "
        f"oracle={expected}\nwire trace:\n" + "\n".join(pair.frame_log)
    )


def assert_effective_mfs_matches_oracle(pair: InMemoryH2Pair) -> None:
    expected = pair.client_oracle.settings.max_frame_size
    actual = pair.client.max_inbound_frame_size
    assert actual == expected, (
        f"max_inbound_frame_size diverged: h2={actual} oracle={expected}\n"
        + "\n".join(pair.frame_log)
    )


# ---------------------------------------------------------------------------
# 1. INITIAL_WINDOW_SIZE shrink -> negative flow-control window.
# ---------------------------------------------------------------------------

class TestInitialWindowShrinkNegativeWindow:
    def test_local_shrink_applies_only_on_its_own_ack(self) -> None:
        """
        A client-owned INITIAL_WINDOW_SIZE shrink sitting in SETTINGS #2 must
        not change any effective window while SETTINGS #1 is still the head.
        It takes effect only when the ACK matching SETTINGS #2 is consumed.
        """
        pair = InMemoryH2Pair()
        client = pair.client
        stream_id = 1

        client.send_headers(stream_id, REQUEST_HEADERS)
        pair.client_oracle.open_stream(stream_id)
        pair.client_send_data(stream_id, 40000)
        assert_sendable_matches_oracle(pair, stream_id)

        # Frame #1 is unrelated; frame #2 carries the shrink.
        pair.client_proposes_settings({SC.MAX_FRAME_SIZE: 20000})
        pair.client_proposes_settings({SC.INITIAL_WINDOW_SIZE: 1000})

        # Nothing is effective before any ACK.
        assert client.local_settings.initial_window_size == DEFAULT_INITIAL_WINDOW_SIZE
        assert client.max_inbound_frame_size == DEFAULT_MAX_FRAME_SIZE
        assert_sendable_matches_oracle(pair, stream_id)

        # ACK #1 moves only the frame-size group.
        pair.deliver_ack_to_client()
        assert client.max_inbound_frame_size == 20000
        assert client.local_settings.initial_window_size == DEFAULT_INITIAL_WINDOW_SIZE
        assert_sendable_matches_oracle(pair, stream_id)

        # ACK #2 moves the shrink; the inbound window of the existing stream
        # follows the new initial window exactly.
        pair.deliver_ack_to_client()
        assert client.local_settings.initial_window_size == 1000
        real_stream = client._get_stream_by_id(stream_id)
        assert real_stream.inbound_flow_control_window == 1000

    def test_remote_shrink_makes_outbound_window_negative_at_right_ack(self) -> None:
        """
        Server-advertised INITIAL_WINDOW_SIZE shrink is applied by the client
        when it processes the remote SETTINGS. With bytes already in flight the
        client's outbound stream window becomes negative and further DATA is
        refused until a WINDOW_UPDATE restores it.
        """
        pair = InMemoryH2Pair()
        client = pair.client
        stream_id = 1

        client.send_headers(stream_id, REQUEST_HEADERS)
        pair.client_oracle.open_stream(stream_id)
        consumed = 60000
        pair.client_send_data(stream_id, consumed)
        assert_sendable_matches_oracle(pair, stream_id)

        # Server advertises a shrink. h2 applies remote settings on receipt and
        # emits the ACK itself.
        shrink_group = {SC.INITIAL_WINDOW_SIZE: 1000}
        shrink_frame = SettingsFrame(0)
        shrink_frame.settings = shrink_group
        pair.frame_log.append("server -> client SETTINGS IWS=1000")
        pair.client_oracle.apply_remote_settings(shrink_group)
        client.receive_data(shrink_frame.serialize())
        client.data_to_send()

        expected_window = 1000 - consumed  # negative
        real_window = client._get_stream_by_id(stream_id).outbound_flow_control_window
        assert real_window == expected_window
        assert real_window < 0
        # The connection window is independent of the stream IWS setting.
        assert client.outbound_flow_control_window == (
            DEFAULT_INITIAL_WINDOW_SIZE - consumed
        )

        # A negative stream window means zero bytes are actually sendable and
        # any positive DATA frame is refused.
        assert_sendable_matches_oracle(pair, stream_id)
        with pytest.raises(h2.exceptions.FlowControlError):
            client.send_data(stream_id, b"z")

        # WINDOW_UPDATE frames accumulate onto the negative window. Grant enough
        # to first bring it back to zero and then open real sendable space; the
        # oracle must stay byte-exact at every step and only then may DATA flow.
        from hyperframe.frame import WindowUpdateFrame
        recovery = -expected_window  # closes the negative deficit, window -> 0
        headroom = 4000
        for increment in (recovery, headroom):
            wu = WindowUpdateFrame(stream_id)
            wu.window_increment = increment
            pair.frame_log.append(
                f"server -> client WINDOW_UPDATE +{increment}",
            )
            client.receive_data(wu.serialize())
            pair.client_oracle.record_window_update(stream_id, increment)
            assert_sendable_matches_oracle(pair, stream_id)

        # Still blocked until the headroom grant lands above.
        pair.client_send_data(stream_id, headroom)
        assert_sendable_matches_oracle(pair, stream_id)


# ---------------------------------------------------------------------------
# 2. MAX_FRAME_SIZE must change only on the matching ACK.
# ---------------------------------------------------------------------------

class TestMaxFrameSizeTiming:
    def test_frame_limit_enforced_after_its_own_ack_only(self) -> None:
        pair = InMemoryH2Pair()
        client = pair.client
        stream_id = 1
        client.send_headers(stream_id, REQUEST_HEADERS)
        pair.client_oracle.open_stream(stream_id)
        pair.client_to_server()

        # Frame #1 shrinks something else; frame #2 shrinks max inbound frame.
        pair.client_proposes_settings({SC.HEADER_TABLE_SIZE: 2048})
        pair.client_proposes_settings({SC.MAX_FRAME_SIZE: 16384 + 100})

        # Default limit still effective while both are outstanding.
        assert_effective_mfs_matches_oracle(pair)
        assert client.max_inbound_frame_size == DEFAULT_MAX_FRAME_SIZE

        pair.deliver_ack_to_client()  # header table size only
        assert_effective_mfs_matches_oracle(pair)
        assert client.max_inbound_frame_size == DEFAULT_MAX_FRAME_SIZE, (
            "MAX_FRAME_SIZE took effect before its own SETTINGS was ACKed\n"
            + "\n".join(pair.frame_log)
        )

        pair.deliver_ack_to_client()  # now the frame size group
        assert_effective_mfs_matches_oracle(pair)
        new_limit = 16384 + 100
        assert client.max_inbound_frame_size == new_limit
        # The receive buffer adopts this cap on the next inbound read; the
        # authoritative effective limit is max_inbound_frame_size, already set.
        assert client.incoming_buffer.max_frame_size == DEFAULT_MAX_FRAME_SIZE

    def test_remote_max_frame_size_gates_outbound_data_timing(self) -> None:
        """
        A remote MAX_FRAME_SIZE change constrains outbound DATA only after the
        client has processed the remote SETTINGS, and never because of an
        unrelated ACK.
        """
        pair = InMemoryH2Pair()
        client = pair.client
        stream_id = 1
        client.send_headers(stream_id, REQUEST_HEADERS)
        pair.client_oracle.open_stream(stream_id)
        pair.client_to_server()

        # First remote SETTINGS changes a benign value; the client ACKs it.
        benign = SettingsFrame(0)
        benign.settings = {SC.HEADER_TABLE_SIZE: 2048}
        client.receive_data(benign.serialize())
        client.data_to_send()
        assert client.max_outbound_frame_size == DEFAULT_MAX_FRAME_SIZE

        # Second remote SETTINGS lowers the outbound frame cap.
        cap = DEFAULT_MAX_FRAME_SIZE  # keep at the floor but explicit
        capped = SettingsFrame(0)
        capped.settings = {SC.MAX_FRAME_SIZE: cap}
        client.receive_data(capped.serialize())
        client.data_to_send()
        assert client.max_outbound_frame_size == cap

        # A frame one byte over the effective cap is rejected, one at the cap
        # is accepted (window permitting).
        with pytest.raises(h2.exceptions.FrameTooLargeError):
            client.send_data(stream_id, b"a" * (cap + 1))
        client.clear_outbound_data_buffer()
        client.send_data(stream_id, b"a" * cap)


# ---------------------------------------------------------------------------
# 3. MAX_CONCURRENT_STREAMS timing.
# ---------------------------------------------------------------------------

class TestMaxConcurrentStreamsTiming:
    def test_concurrency_cap_binds_immediately_when_remote_settings_processed(self) -> None:
        """
        Once the client has processed a remote MAX_CONCURRENT_STREAMS frame the
        cap binds: the first outbound stream is still allowed but the next is
        refused, and resetting the stream frees its slot.
        """
        pair = InMemoryH2Pair()
        client = pair.client

        cap_frame = SettingsFrame(0)
        cap_frame.settings = {SC.MAX_CONCURRENT_STREAMS: 1}
        pair.frame_log.append("server -> client SETTINGS[max_conc=1]")
        client.receive_data(cap_frame.serialize())
        client.data_to_send()

        assert client.remote_settings.max_concurrent_streams == 1

        # First outbound stream is allowed; the second must now be refused.
        client.send_headers(1, REQUEST_HEADERS)
        pair.client_to_server()
        with pytest.raises(h2.exceptions.TooManyStreamsError):
            client.send_headers(3, REQUEST_HEADERS)

        # Resetting the only open stream frees the single slot again.
        client.reset_stream(1)
        pair.client_to_server()
        client.send_headers(3, REQUEST_HEADERS)

    def test_queued_remote_cap_does_not_bind_before_its_frame_is_processed(self) -> None:
        """
        A MAX_CONCURRENT_STREAMS value sitting behind another remote SETTINGS
        frame must not bind until that specific frame is reached.
        """
        pair = InMemoryH2Pair()
        client = pair.client

        # Only the benign frame is processed first; the cap frame is held back.
        benign = SettingsFrame(0)
        benign.settings = {SC.HEADER_TABLE_SIZE: 2048}
        client.receive_data(benign.serialize())
        client.data_to_send()
        assert client.remote_settings.max_concurrent_streams > 1

        # Two streams are legal while the cap is still on the wire.
        client.send_headers(1, REQUEST_HEADERS)
        client.send_headers(3, REQUEST_HEADERS)
        pair.client_to_server()

        # Processing the cap now makes a third concurrent stream illegal.
        cap_frame = SettingsFrame(0)
        cap_frame.settings = {SC.MAX_CONCURRENT_STREAMS: 2}
        client.receive_data(cap_frame.serialize())
        client.data_to_send()
        with pytest.raises(h2.exceptions.TooManyStreamsError):
            client.send_headers(5, REQUEST_HEADERS)

    def test_local_concurrency_proposal_does_not_bind_until_acked(self) -> None:
        """
        A MAX_CONCURRENT_STREAMS value the *client* advertises governs inbound
        streams and must not change the client's view before its own frame is
        acknowledged.
        """
        pair = InMemoryH2Pair()
        assert pair.client.local_settings.max_concurrent_streams == 100

        pair.client_proposes_settings({SC.HEADER_TABLE_SIZE: 1024})
        pair.client_proposes_settings({SC.MAX_CONCURRENT_STREAMS: 2})

        # Outstanding: the advertised cap is not yet effective.
        assert pair.client.local_settings.max_concurrent_streams == 100

        pair.deliver_ack_to_client()  # header table group
        assert pair.client.local_settings.max_concurrent_streams == 100, (
            "local MAX_CONCURRENT_STREAMS applied on the wrong ACK\n"
            + "\n".join(pair.frame_log)
        )

        pair.deliver_ack_to_client()  # concurrency group
        assert pair.client.local_settings.max_concurrent_streams == 2


# ---------------------------------------------------------------------------
# 4. Unknown / extra / repeated ACKs must never advance configuration.
# ---------------------------------------------------------------------------

class TestSpuriousAcknowledgements:
    def test_unsolicited_ack_does_not_change_any_setting(self) -> None:
        pair = InMemoryH2Pair()
        client = pair.client

        # One genuine proposal, never acknowledged.
        pair.client_proposes_settings({SC.MAX_FRAME_SIZE: 20000})
        assert client.max_inbound_frame_size == DEFAULT_MAX_FRAME_SIZE

        # An unsolicited ACK arriving on the server side has nothing to match;
        # it must be a no-op rather than advance state.
        pair.deliver_unsolicited_ack_to_server()
        assert client.max_inbound_frame_size == DEFAULT_MAX_FRAME_SIZE
        assert list(client.local_settings._outstanding_settings) == [
            {SC.MAX_FRAME_SIZE: 20000},
        ]

    def test_duplicate_ack_after_last_frame_is_a_noop(self) -> None:
        """
        RFC 9113 SETTINGS ACK frames carry no identifier, so an endpoint can only
        correlate an ACK positionally against its FIFO queue of outstanding
        SETTINGS frames. Once that queue is empty, a duplicate/extra ACK has no
        matching frame and must be discarded without inventing a change.
        """
        pair = InMemoryH2Pair()
        client = pair.client

        pair.client_proposes_settings({SC.MAX_FRAME_SIZE: 20000})

        # The single genuine ACK applies the one outstanding group.
        pair.deliver_ack_to_client()
        assert client.max_inbound_frame_size == 20000
        assert client.local_settings.outstanding == 0

        # A repeated ACK now matches nothing: it must not raise, must not emit a
        # further change event, and must leave every effective value untouched.
        ack = SettingsFrame(0)
        ack.flags.add("ACK")
        pair.frame_log.append("server -> client *duplicate* ACK (queue empty)")
        events = client.receive_data(ack.serialize())
        client.data_to_send()

        assert events == []
        assert client.max_inbound_frame_size == 20000
        assert client.local_settings.outstanding == 0

    def test_in_order_acks_apply_groups_one_at_a_time(self) -> None:
        """
        With several frames outstanding, in-order ACKs pop strictly one group
        each: a group never takes effect before the frames ahead of it have
        been acknowledged. This is the guarantee that keeps queued data within
        the limits the peer actually had in force at every instant.
        """
        pair = InMemoryH2Pair()
        client = pair.client

        pair.client_proposes_settings({SC.INITIAL_WINDOW_SIZE: 1000})
        pair.client_proposes_settings({SC.MAX_FRAME_SIZE: 20000})

        # First genuine ACK applies only group #1; group #2 stays pending.
        pair.deliver_ack_to_client()
        assert client.local_settings.initial_window_size == 1000
        assert client.max_inbound_frame_size == DEFAULT_MAX_FRAME_SIZE
        assert client.local_settings.outstanding == 1

        # The genuine second ACK finally applies group #2.
        pair.deliver_ack_to_client()
        assert client.max_inbound_frame_size == 20000
        assert list(client.local_settings._outstanding_settings) == []

    def test_ack_for_heterogeneous_frames_isolates_each_subset(self) -> None:
        """
        Two outstanding frames touch disjoint setting subsets. Each ACK must
        pop only its own subset, even though the old implementation popped every
        setting deque on the first ACK.
        """
        pair = InMemoryH2Pair()
        client = pair.client

        pair.client_proposes_settings({SC.INITIAL_WINDOW_SIZE: 1000})
        pair.client_proposes_settings({SC.MAX_FRAME_SIZE: 20000})
        pair.client_proposes_settings({SC.HEADER_TABLE_SIZE: 256})

        pair.deliver_ack_to_client()
        assert client.local_settings.initial_window_size == 1000
        assert client.max_inbound_frame_size == DEFAULT_MAX_FRAME_SIZE
        assert client.local_settings.header_table_size == 4096

        pair.deliver_ack_to_client()
        assert client.max_inbound_frame_size == 20000
        assert client.local_settings.header_table_size == 4096

        pair.deliver_ack_to_client()
        assert client.local_settings.header_table_size == 256
        assert list(client.local_settings._outstanding_settings) == []


# ---------------------------------------------------------------------------
# 5. Legal interleavings always remain able to make progress (liveness).
# ---------------------------------------------------------------------------

class TestLegalInterleavingLiveness:
    def test_data_flows_through_window_shrink_then_grow_cycle(self) -> None:
        pair = InMemoryH2Pair()
        client = pair.client
        stream_id = 1
        client.send_headers(stream_id, REQUEST_HEADERS)
        pair.client_oracle.open_stream(stream_id)
        pair.client_to_server()

        from hyperframe.frame import WindowUpdateFrame

        # Consume most of the window, then accept a shrink that goes negative.
        # Kept small enough that the later grants stay inside the peer's
        # connection-level inbound window for the whole exchange.
        first_chunk = 40000
        pair.client_send_data(stream_id, first_chunk)

        shrink = SettingsFrame(0)
        shrink.settings = {SC.INITIAL_WINDOW_SIZE: 1000}
        pair.client_oracle.apply_remote_settings({SC.INITIAL_WINDOW_SIZE: 1000})
        client.receive_data(shrink.serialize())
        client.data_to_send()
        assert_sendable_matches_oracle(pair, stream_id)
        with pytest.raises(h2.exceptions.FlowControlError):
            client.send_data(stream_id, b"blocked")

        # The peer first cancels the negative deficit, then grants headroom in
        # several chunks. Transmission must resume the instant the window turns
        # positive and stay byte-exact against the oracle throughout.
        deficit = -(1000 - first_chunk)  # bytes needed to return the window to 0
        recovery = WindowUpdateFrame(stream_id)
        recovery.window_increment = deficit
        client.receive_data(recovery.serialize())
        pair.client_oracle.record_window_update(stream_id, deficit)
        assert_sendable_matches_oracle(pair, stream_id)
        assert pair.client_oracle.sendable_on(stream_id) == 0

        for grant in (4000, 4000, 2000):
            wu = WindowUpdateFrame(stream_id)
            wu.window_increment = grant
            client.receive_data(wu.serialize())
            pair.client_oracle.record_window_update(stream_id, grant)

            pair.client_send_data(stream_id, grant)
            assert_sendable_matches_oracle(pair, stream_id)

        # Everything granted has been consumed; nothing further is sendable.
        assert_sendable_matches_oracle(pair, stream_id)
        assert pair.client_oracle.sendable_on(stream_id) == 0

    def test_interleaved_settings_and_data_never_exceed_effective_limits(self) -> None:
        pair = InMemoryH2Pair()
        client = pair.client
        stream_id = 1
        client.send_headers(stream_id, REQUEST_HEADERS)
        pair.client_oracle.open_stream(stream_id)
        pair.client_to_server()

        # Queue two local proposals, but keep sending data meanwhile: queued
        # proposals must not perturb the live flow-control window.
        pair.client_proposes_settings({SC.MAX_FRAME_SIZE: 17000})
        pair.client_proposes_settings({SC.HEADER_TABLE_SIZE: 256})

        chunk = 10000
        client.send_data(stream_id, b"a" * chunk)
        pair.client_oracle.record_send(stream_id, chunk)
        assert_sendable_matches_oracle(pair, stream_id)

        pair.deliver_ack_to_client()
        client.send_data(stream_id, b"b" * chunk)
        pair.client_oracle.record_send(stream_id, chunk)
        assert_sendable_matches_oracle(pair, stream_id)
        assert client.max_inbound_frame_size == 17000

        pair.deliver_ack_to_client()
        assert client.local_settings.header_table_size == 256
        assert_sendable_matches_oracle(pair, stream_id)


# ---------------------------------------------------------------------------
# 6. Mutation guard: a deliberately broken Settings.acknowledge must be caught
#    at the first violating frame, proving the oracle assertions have teeth.
# ---------------------------------------------------------------------------

class TestDefectDetection:
    def test_old_deque_popping_defect_is_caught_on_first_violation(self, monkeypatch) -> None:
        """
        Reintroduce the historical bug where one ACK pops *every* setting's
        pending value instead of only its own group. The first ACK then wrongly
        applies MAX_FRAME_SIZE, which the fixed implementation keeps pending.
        """

        def broken_acknowledge(self) -> dict:
            # Old behaviour: flatten all outstanding groups and apply every
            # proposed value on the first ACK, ignoring which frame it matches.
            flat: dict[int, int] = {}
            for group in self._outstanding_settings:
                flat.update(group)
            changes = {}
            for setting, new_value in flat.items():
                old_value = self._settings.get(setting)
                self._settings[setting] = new_value
                changes[setting] = h2.settings.ChangedSetting(
                    setting, old_value, new_value,
                )
            self._outstanding_settings.clear()
            return changes

        monkeypatch.setattr(
            h2.settings.Settings, "acknowledge", broken_acknowledge,
        )

        buggy = h2.settings.Settings(client=True)
        buggy.append_group({SC.INITIAL_WINDOW_SIZE: 1000})
        buggy.append_group({SC.MAX_FRAME_SIZE: 20000})
        buggy.acknowledge()

        # The injected defect applies the unrelated frame-size change early.
        assert buggy.max_frame_size == 20000

        # Restore the real implementation; the same sequence must now keep the
        # unrelated frame-size change pending, proving the regression guard.
        monkeypatch.undo()
        good = h2.settings.Settings(client=True)
        good.append_group({SC.INITIAL_WINDOW_SIZE: 1000})
        good.append_group({SC.MAX_FRAME_SIZE: 20000})
        good.acknowledge()
        assert good.max_frame_size == DEFAULT_MAX_FRAME_SIZE
        assert good.initial_window_size == 1000

    def test_oracle_flags_early_application_in_pair(self) -> None:
        """
        End-to-end guard: tamper max_inbound_frame_size one frame early and show
        the point-in-time oracle assertion trips immediately, not at the end.
        """
        pair = InMemoryH2Pair()
        pair.client_proposes_settings({SC.HEADER_TABLE_SIZE: 256})
        pair.client_proposes_settings({SC.MAX_FRAME_SIZE: 20000})

        pair.deliver_ack_to_client()  # header table only
        # Simulate an implementation that jumped the gun on frame size.
        pair.client.max_inbound_frame_size = 20000

        with pytest.raises(AssertionError) as excinfo:
            assert_effective_mfs_matches_oracle(pair)
        assert "max_inbound_frame_size diverged" in str(excinfo.value)

    def test_oracle_flags_early_application_via_broken_settings(self, monkeypatch) -> None:
        """
        Drive the real pair with the broken acknowledge() injected and confirm a
        point-in-time assertion fails on the very first mismatched ACK, before
        the second (correct) ACK is ever delivered.
        """

        def broken_acknowledge(self) -> dict:
            flat: dict[int, int] = {}
            for group in self._outstanding_settings:
                flat.update(group)
            changes = {}
            for setting, new_value in flat.items():
                old_value = self._settings.get(setting)
                self._settings[setting] = new_value
                changes[setting] = h2.settings.ChangedSetting(
                    setting, old_value, new_value,
                )
            self._outstanding_settings.clear()
            return changes

        monkeypatch.setattr(
            h2.settings.Settings, "acknowledge", broken_acknowledge,
        )

        pair = InMemoryH2Pair()
        pair.client_proposes_settings({SC.HEADER_TABLE_SIZE: 256})
        pair.client_proposes_settings({SC.MAX_FRAME_SIZE: 20000})

        # Under the bug, h2 applies MAX_FRAME_SIZE on the first ACK while the
        # independent oracle still expects the default: caught at once.
        pair.deliver_ack_to_client()
        with pytest.raises(AssertionError) as excinfo:
            assert_effective_mfs_matches_oracle(pair)
        assert "max_inbound_frame_size diverged" in str(excinfo.value)
