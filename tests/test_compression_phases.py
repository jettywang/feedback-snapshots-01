"""
Phase-level regression tests for SSH compression activation.

``zlib@openssh.com`` means "zlib, but only after authentication": until auth
succeeds, no compressor may be installed and inbound compressed bytes must not
reach a decompressor. Plain ``zlib`` is the opposite: its contexts start right
after NEWKEYS, authentication or not.

These tests use a local, fully controllable peer (two Transports over a
LoopSocket pair) and recording Packetizers, so inbound and outbound compressor
installs, first calls, and wire packets are observed independently of each
other and of the negotiated algorithm name.
"""

import threading
from contextlib import contextmanager
from dataclasses import dataclass

import pytest

from paramiko import Ed25519Key, Message, Packetizer, RSAKey, Transport
from paramiko.common import (
    MSG_GLOBAL_REQUEST,
    MSG_IGNORE,
    MSG_USERAUTH_REQUEST,
    MSG_USERAUTH_SUCCESS,
    cMSG_CHANNEL_OPEN,
    cMSG_GLOBAL_REQUEST,
)
from paramiko.compress import ZlibCompressor, ZlibDecompressor
from paramiko.ssh_exception import AuthenticationException

from . import _util
from ._loop import LoopSocket
from ._util import _support, wait_until

DELAYED = "zlib@openssh.com"
EAGER = "zlib"
ZLIB_HEADER_BYTE = 0x78
COMPRESSOR = "ZlibCompressor"
DECOMPRESSOR = "ZlibDecompressor"


@dataclass(frozen=True)
class Phase:
    """Authentication and key-exchange state when something happened."""

    authenticated: bool
    initial_kex_done: bool


@dataclass(frozen=True)
class Install:
    phase: Phase
    kind: str
    instance: object


@dataclass
class Call:
    phase: Phase
    input_len: int
    output_len: int


@dataclass(frozen=True)
class PayloadRecord:
    phase: Phase
    compressed: bool
    payload: bytes


@dataclass(frozen=True)
class PacketRecord:
    phase: Phase
    data: bytes


class RecordingPacketizer(Packetizer):
    """Packetizer recording installs/calls/wire facts, per direction."""

    def __init__(self, sock):
        super().__init__(sock)
        self.owner = None
        self._record_lock = threading.RLock()
        self.inbound_installs = []
        self.outbound_installs = []
        self.inbound_calls = []
        self.outbound_calls = []
        self.sent_messages = []
        self.built_payloads = []
        self.wire_packets = []

    def _phase(self):
        return Phase(
            authenticated=bool(self.owner.authenticated),
            initial_kex_done=bool(self.owner.initial_kex_done),
        )

    def _outbound_engine(self):
        return getattr(self, "_Packetizer__compress_engine_out", None)

    def set_inbound_compressor(self, compressor):
        install = Install(
            self._phase(), type(compressor).__name__, compressor
        )
        with self._record_lock:
            self.inbound_installs.append(install)

        def recorded(data):
            call = Call(self._phase(), len(data), 0)
            with self._record_lock:
                self.inbound_calls.append(call)
            result = compressor(data)
            call.output_len = len(result)
            return result

        super().set_inbound_compressor(recorded)

    def set_outbound_compressor(self, compressor):
        install = Install(
            self._phase(), type(compressor).__name__, compressor
        )
        with self._record_lock:
            self.outbound_installs.append(install)

        def recorded(data):
            call = Call(self._phase(), len(data), 0)
            with self._record_lock:
                self.outbound_calls.append(call)
            result = compressor(data)
            call.output_len = len(result)
            return result

        super().set_outbound_compressor(recorded)

    def send_message(self, data):
        raw = data.asbytes()
        record = PayloadRecord(
            self._phase(), self._outbound_engine() is not None, raw
        )
        with self._record_lock:
            self.sent_messages.append(record)
        super().send_message(data)

    def _build_packet(self, payload):
        record = PayloadRecord(
            self._phase(), self._outbound_engine() is not None, bytes(payload)
        )
        with self._record_lock:
            self.built_payloads.append(record)
        return super()._build_packet(payload)

    def write_all(self, out):
        record = PacketRecord(self._phase(), bytes(out))
        with self._record_lock:
            self.wire_packets.append(record)
        return super().write_all(out)

    def send_payload_uncompressed(self, payload):
        """
        Put already-formed payload bytes on the wire without compressing them.

        Emulates a peer that sends plaintext after the switch, or compressed
        bytes before it, without letting our own outbound state interfere.
        """
        attr = "_Packetizer__compress_engine_out"
        saved = getattr(self, attr)
        setattr(self, attr, None)
        try:
            self.send_message(Message(payload))
        finally:
            setattr(self, attr, saved)


class RecordingTransport(Transport):
    def __init__(self, *args, **kwargs):
        kwargs.pop("packetizer_class", None)
        super().__init__(
            *args, packetizer_class=RecordingPacketizer, **kwargs
        )
        self.packetizer.owner = self


class PrematureInboundTransport(RecordingTransport):
    """
    Simulated regression: install the inbound decompressor at NEWKEYS even
    though delayed compression has not been authenticated yet.
    """

    def _activate_inbound(self):
        super()._activate_inbound()
        if self.remote_compression == DELAYED:
            self.packetizer.set_inbound_compressor(ZlibDecompressor())


class PrematureOutboundTransport(RecordingTransport):
    """Simulated regression for the outbound compressor, likewise."""

    def _activate_outbound(self):
        super()._activate_outbound()
        if self.local_compression == DELAYED:
            self.packetizer.set_outbound_compressor(ZlibCompressor())


@contextmanager
def recording_session(algorithm, server_factory=RecordingTransport):
    socks = LoopSocket()
    sockc = LoopSocket()
    sockc.link(socks)
    tc = RecordingTransport(sockc)
    ts = server_factory(socks)
    try:
        for transport in (tc, ts):
            transport.get_security_options().compression = (algorithm,)
        host_key = RSAKey.from_private_key_file(_support("rsa.key"))
        ts.add_server_key(host_key)
        event = threading.Event()
        ts.start_server(event, _util.TestServer())
        # Deliberately stop after key exchange; each test drives auth itself
        # so it can observe the pre-auth phase.
        tc.connect(hostkey=RSAKey(data=host_key.asbytes()))
        event.wait(1.0)
        assert event.is_set()
        assert tc.is_active() and ts.is_active()
        assert tc.initial_kex_done and ts.initial_kex_done
        yield tc, ts
    finally:
        for transport in (tc, ts):
            try:
                transport.close()
            except Exception:
                pass
        for sock in (sockc, socks):
            try:
                sock.close()
            except Exception:
                pass


def eventually(condition, timeout=2):
    """wait_until() expects assertion failures, not boolean predicates."""

    def check():
        assert condition()

    wait_until(check, timeout=timeout)


def wait_for_installs(tc, ts, count=1):
    eventually(
        lambda: all(
            len(t.packetizer.inbound_installs) == count
            and len(t.packetizer.outbound_installs) == count
            for t in (tc, ts)
        )
    )


def assert_delayed_dormant(tc, ts):
    """No compression state in either direction, on either side, yet."""
    for transport in (tc, ts):
        packetizer = transport.packetizer
        assert transport.local_compression == DELAYED
        assert transport.remote_compression == DELAYED
        # Inbound and outbound are observed independently.
        assert packetizer.inbound_installs == []
        assert packetizer.outbound_installs == []
        assert packetizer.inbound_calls == []
        assert packetizer.outbound_calls == []
        # The handshake did put packets on the wire, so emptiness above is
        # about compression, not a lack of traffic.
        assert packetizer.wire_packets


def assert_delayed_activated(tc, ts):
    for transport in (tc, ts):
        packetizer = transport.packetizer
        assert len(packetizer.inbound_installs) == 1
        assert len(packetizer.outbound_installs) == 1
        for install, kind in (
            (packetizer.inbound_installs[0], DECOMPRESSOR),
            (packetizer.outbound_installs[0], COMPRESSOR),
        ):
            assert install.kind == kind
            assert install.phase.authenticated is True
            assert install.phase.initial_kex_done is True


def assert_calls_authenticated(packetizer):
    for call in packetizer.inbound_calls + packetizer.outbound_calls:
        assert call.phase.authenticated is True


def _recv_exactly(channel, count):
    data = b""
    while len(data) < count:
        data += channel.recv(count - len(data))
    return data


def assert_echo(chan, schan, payload):
    chan.send(payload)
    assert _recv_exactly(schan, len(payload)) == payload
    schan.send(payload[::-1])
    assert _recv_exactly(chan, len(payload)) == payload[::-1]


def open_session(tc, ts):
    chan = tc.open_session()
    chan.settimeout(2.0)
    chan.exec_command("yes")
    schan = ts.accept(1.0)
    assert schan is not None
    schan.settimeout(2.0)
    return chan, schan


def compressed_channel_open():
    message = Message()
    message.add_byte(cMSG_CHANNEL_OPEN)
    message.add_string("session")
    message.add_int(0)
    message.add_int(32768)
    message.add_int(32768)
    return ZlibCompressor()(message.asbytes())


def built_of_type(packetizer, message_type):
    return [
        record
        for record in packetizer.built_payloads
        if record.payload[0] == message_type
    ]


def test_delayed_negotiation_alone_does_not_install_compressors():
    with recording_session(DELAYED) as (tc, ts):
        # Good negotiated name, but still no actual compression machinery.
        assert tc.local_compression == DELAYED
        assert_delayed_dormant(tc, ts)

        # Pre-auth traffic is built from the real message bytes.
        tc.send_ignore(256)
        assert tc.packetizer.built_payloads[-1].compressed is False
        assert tc.packetizer.built_payloads[-1].payload[0] == MSG_IGNORE

        tc.auth_password("slowdive", "pygmalion")
        wait_for_installs(tc, ts)
        assert_delayed_activated(tc, ts)

        # Auth itself is the boundary: USERAUTH_* go out uncompressed, and
        # the decompressor was never called for the pre-auth IGNORE.
        assert all(
            not record.compressed
            for record in built_of_type(tc.packetizer, MSG_USERAUTH_REQUEST)
        )
        assert all(
            not record.compressed
            for record in built_of_type(ts.packetizer, MSG_USERAUTH_SUCCESS)
        )
        assert ts.packetizer.inbound_calls == []
        assert tc.packetizer.outbound_calls == []

        # First post-auth call in each direction, counted on the wire too.
        wire_before = len(tc.packetizer.wire_packets)
        tc.send_ignore(256)
        sent = tc.packetizer.sent_messages[-1]
        built = tc.packetizer.built_payloads[-1]
        assert sent.compressed is True and sent.payload[0] == MSG_IGNORE
        assert built.compressed is True
        assert built.payload[0] == ZLIB_HEADER_BYTE
        assert len(tc.packetizer.wire_packets) == wire_before + 1

        eventually(lambda: len(ts.packetizer.inbound_calls) == 1)
        assert ts.packetizer.inbound_calls[0].phase.authenticated is True
        assert ts.packetizer.inbound_calls[0].input_len > 0
        assert len(tc.packetizer.outbound_calls) == 1
        assert tc.packetizer.outbound_calls[0].phase.authenticated is True

        chan, schan = open_session(tc, ts)
        assert_echo(chan, schan, b"delayed-compression-after-auth")
        assert_calls_authenticated(tc.packetizer)
        assert_calls_authenticated(ts.packetizer)
        chan.close()
        schan.close()


def test_failed_authentication_does_not_activate_delayed_compression():
    with recording_session(DELAYED) as (tc, ts):
        with pytest.raises(AuthenticationException):
            tc.auth_password("slowdive", "wrong")
        assert not tc.is_authenticated()
        assert not ts.is_authenticated()
        assert_delayed_dormant(tc, ts)

        # Same session and handler: succeed on the retry.
        tc.auth_password("slowdive", "pygmalion")
        wait_for_installs(tc, ts)
        assert_delayed_activated(tc, ts)

        chan, schan = open_session(tc, ts)
        assert_echo(chan, schan, b"after-one-failed-attempt")
        assert_calls_authenticated(tc.packetizer)
        assert_calls_authenticated(ts.packetizer)
        chan.close()
        schan.close()


def test_partial_authentication_waits_for_final_success():
    with recording_session(DELAYED) as (tc, ts):
        allowed = tc.auth_password("paranoid", "paranoid")
        assert allowed == ["publickey"]
        assert not tc.is_authenticated()
        assert not ts.is_authenticated()
        assert_delayed_dormant(tc, ts)

        key = Ed25519Key.from_private_key_file(_support("ed25519.key"))
        assert tc.auth_publickey("paranoid", key) == []
        wait_for_installs(tc, ts)
        assert_delayed_activated(tc, ts)

        chan, schan = open_session(tc, ts)
        assert_echo(chan, schan, b"after-partial-then-final")
        assert_calls_authenticated(tc.packetizer)
        assert_calls_authenticated(ts.packetizer)
        chan.close()
        schan.close()


def test_delayed_compression_across_preauth_rekey():
    with recording_session(DELAYED) as (tc, ts):
        with pytest.raises(AuthenticationException):
            tc.auth_password("slowdive", "wrong")
        old_client_H = tc.H
        old_server_H = ts.H
        wire_before = len(tc.packetizer.wire_packets)

        tc.renegotiate_keys()
        eventually(
            lambda: (
                tc.H != old_client_H
                and ts.H != old_server_H
                and tc.is_active()
                and ts.is_active()
            )
        )
        # The NEWKEYS pass for a rekey may not install either compressor.
        assert len(tc.packetizer.wire_packets) > wire_before
        assert_delayed_dormant(tc, ts)

        tc.auth_password("slowdive", "pygmalion")
        wait_for_installs(tc, ts)
        assert_delayed_activated(tc, ts)

        chan, schan = open_session(tc, ts)
        assert_echo(chan, schan, b"after-preauth-rekey")
        assert_calls_authenticated(tc.packetizer)
        assert_calls_authenticated(ts.packetizer)
        chan.close()
        schan.close()


def test_delayed_compression_rekey_keeps_existing_channel_usable():
    with recording_session(DELAYED) as (tc, ts):
        tc.auth_password("slowdive", "pygmalion")
        wait_for_installs(tc, ts)
        assert_delayed_activated(tc, ts)

        chan, schan = open_session(tc, ts)
        assert_echo(chan, schan, b"before-rekey")

        client_inbound_before = len(tc.packetizer.inbound_calls)
        client_outbound_before = len(tc.packetizer.outbound_calls)
        server_inbound_before = len(ts.packetizer.inbound_calls)
        server_outbound_before = len(ts.packetizer.outbound_calls)
        wire_before = len(tc.packetizer.wire_packets)
        old_client_H, old_server_H = tc.H, ts.H

        tc.renegotiate_keys()
        # Post-auth rekey reinitializes compression contexts (RFC 4253 6.2),
        # but only because auth is already done.
        wait_for_installs(tc, ts, count=2)
        eventually(
            lambda: (
                tc.H != old_client_H
                and ts.H != old_server_H
                and tc.is_active()
                and ts.is_active()
            )
        )
        assert tc.is_authenticated() and ts.is_authenticated()
        assert len(tc.packetizer.wire_packets) > wire_before
        for transport in (tc, ts):
            packetizer = transport.packetizer
            for install in (
                packetizer.inbound_installs
                + packetizer.outbound_installs
            ):
                assert install.phase.authenticated is True
            # A NEWKEYS pass creates fresh contexts rather than reusing the
            # old ones.
            assert (
                packetizer.inbound_installs[0].instance
                is not packetizer.inbound_installs[1].instance
            )
            assert (
                packetizer.outbound_installs[0].instance
                is not packetizer.outbound_installs[1].instance
            )

        # The pre-existing channel keeps carrying data across the switch.
        assert_echo(chan, schan, b"after-post-auth-rekey")
        assert len(ts.packetizer.inbound_calls) > server_inbound_before
        assert len(ts.packetizer.outbound_calls) > server_outbound_before
        assert len(tc.packetizer.inbound_calls) > client_inbound_before
        assert len(tc.packetizer.outbound_calls) > client_outbound_before
        assert_calls_authenticated(tc.packetizer)
        assert_calls_authenticated(ts.packetizer)
        chan.close()
        schan.close()


def test_plain_zlib_activates_at_newkeys_not_at_authentication():
    with recording_session(EAGER) as (tc, ts):
        for transport in (tc, ts):
            packetizer = transport.packetizer
            assert transport.local_compression == EAGER
            assert transport.remote_compression == EAGER
            assert len(packetizer.inbound_installs) == 1
            assert len(packetizer.outbound_installs) == 1
            for install in (
                packetizer.inbound_installs + packetizer.outbound_installs
            ):
                # The exact opposite of delayed semantics: active while
                # unauthenticated.
                assert install.phase.authenticated is False

        # Unauthenticated traffic is already compressed on the wire.
        tc.send_ignore(256)
        assert tc.packetizer.built_payloads[-1].compressed is True
        assert (
            tc.packetizer.built_payloads[-1].payload[0] == ZLIB_HEADER_BYTE
        )
        eventually(
            lambda: any(
                call.phase.authenticated is False
                for call in ts.packetizer.inbound_calls
            )
        )
        assert len(tc.packetizer.outbound_calls) == 1
        assert tc.packetizer.outbound_calls[0].phase.authenticated is False
        # First call each direction is likewise pre-auth, not just the
        # install record.
        assert tc.packetizer.inbound_calls[0].phase.authenticated is False
        assert ts.packetizer.outbound_calls[0].phase.authenticated is False

        tc.auth_password("slowdive", "pygmalion")
        # Auth must not install plain zlib; it was already active.
        assert all(
            len(t.packetizer.inbound_installs) == 1
            and len(t.packetizer.outbound_installs) == 1
            for t in (tc, ts)
        )

        chan, schan = open_session(tc, ts)
        assert_echo(chan, schan, b"plain-zlib")
        for transport in (tc, ts):
            phases = [
                call.phase
                for call in (
                    transport.packetizer.inbound_calls
                    + transport.packetizer.outbound_calls
                )
            ]
            assert any(phase.authenticated is False for phase in phases)
            assert any(phase.authenticated is True for phase in phases)
        chan.close()
        schan.close()


DIRECTIONS = ("client-to-server", "server-to-client")


@pytest.mark.parametrize("direction", DIRECTIONS)
def test_compressed_bytes_before_auth_never_reach_decompressor(direction):
    with recording_session(DELAYED) as (tc, ts):
        sender, receiver = (
            (tc, ts) if direction == "client-to-server" else (ts, tc)
        )
        assert_delayed_dormant(tc, ts)
        wire_before = len(sender.packetizer.wire_packets)
        payload = compressed_channel_open()
        assert payload[0] == ZLIB_HEADER_BYTE

        # Put compressed bytes on the wire while the receiver has no inbound
        # compressor at all.
        sender.packetizer.send_payload_uncompressed(payload)
        assert len(sender.packetizer.wire_packets) == wire_before + 1

        # Wrong-phase data is rejected, not quietly accepted: whichever side
        # receives it must die without touching a decompressor.
        eventually(lambda: not receiver.is_active())
        assert receiver.packetizer.inbound_installs == []
        assert receiver.packetizer.inbound_calls == []
        assert not receiver.is_authenticated()
        if receiver.server_mode:
            assert receiver.accept(0.1) is None
        assert receiver.get_exception() is not None


@pytest.mark.parametrize("direction", DIRECTIONS)
def test_plaintext_after_switch_is_rejected_by_decompressor(direction):
    with recording_session(DELAYED) as (tc, ts):
        tc.auth_password("slowdive", "pygmalion")
        wait_for_installs(tc, ts)
        sender, receiver = (
            (tc, ts) if direction == "client-to-server" else (ts, tc)
        )
        calls_before = len(receiver.packetizer.inbound_calls)

        message = Message()
        message.add_byte(cMSG_GLOBAL_REQUEST)
        message.add_string("keepalive@openssh.com")
        message.add_boolean(True)
        # Conversely, plaintext after the switch is fed to the decompressor,
        # which rejects it.
        sender.packetizer.send_payload_uncompressed(message.asbytes())
        assert sender.packetizer.built_payloads[-1].compressed is False
        assert (
            sender.packetizer.built_payloads[-1].payload[0]
            == MSG_GLOBAL_REQUEST
        )

        eventually(lambda: not receiver.is_active())
        assert len(receiver.packetizer.inbound_calls) == calls_before + 1
        assert (
            receiver.packetizer.inbound_calls[-1].phase.authenticated is True
        )
        assert receiver.get_exception() is not None


def test_harness_detects_premature_inbound_decompressor_install():
    """
    Prove the dormancy assertions are sensitive to the regression they guard
    against: a build installing the decompressor at NEWKEYS shows an
    unauthenticated inbound install and *does* decompress pre-auth bytes.
    """
    with recording_session(
        DELAYED, server_factory=PrematureInboundTransport
    ) as (tc, ts):
        installs = ts.packetizer.inbound_installs
        assert installs
        assert installs[0].kind == DECOMPRESSOR
        assert installs[0].phase.authenticated is False

        tc.packetizer.send_payload_uncompressed(compressed_channel_open())
        eventually(lambda: ts.packetizer.inbound_calls)
        assert ts.packetizer.inbound_calls[0].phase.authenticated is False
        # And the real regression assertion would fail, as intended.
        with pytest.raises(AssertionError):
            assert_delayed_dormant(tc, ts)


def test_harness_detects_premature_outbound_compressor_install():
    """Same negative control for the independently observed outbound side."""
    with recording_session(
        DELAYED, server_factory=PrematureOutboundTransport
    ) as (tc, ts):
        installs = ts.packetizer.outbound_installs
        assert installs
        assert installs[0].kind == COMPRESSOR
        assert installs[0].phase.authenticated is False

        ts.send_ignore(256)
        assert ts.packetizer.outbound_calls
        assert ts.packetizer.outbound_calls[0].phase.authenticated is False
        with pytest.raises(AssertionError):
            assert_delayed_dormant(tc, ts)
