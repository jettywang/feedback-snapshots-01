"""
Tests for the configurable overall deadline on key renegotiation (rekey).

These tests deliberately avoid real ``time.sleep`` waits.  A fake clock is
injected into the transports (``Transport._time``) together with a
``ControlledLoopSocket`` whose recv timeouts are retried in lock-step with the
clock, so advancing the clock deterministically drives every 0.1s polling wait
inside the transport without any per-call sleeping.
"""

import socket
import threading
import time

import pytest

from paramiko import (
    RSAKey,
    RenegotiationError,
    SSHException,
    Transport,
)
from paramiko.common import cMSG_IGNORE
from paramiko.kex_curve25519 import KexCurve25519
from paramiko.message import Message

from ._loop import LoopSocket
from ._util import TestServer, _support

KEX_NAME = "curve25519-sha256@libssh.org"
# Short enough to keep the tests fast, long enough to stay out of the way of
# the normal (successful) exchanges.
DEADLINE = 5.0


class FakeClock:
    """Deterministic, thread-safe monotonic clock measured in fake seconds."""

    def __init__(self):
        self._lock = threading.RLock()
        self._now = 1000.0

    def time(self):
        with self._lock:
            return self._now

    def step(self, seconds):
        with self._lock:
            self._now += seconds


class ControlledLoopSocket(LoopSocket):
    """
    LoopSocket that turns a recv timeout into a retry instead of propagating
    ``socket.timeout``.

    The real transport relies on a short socket timeout to periodically wake
    up and re-check ``active``/deadlines.  Under a fake clock nothing would
    ever wake a blocking recv, so we retry timeouts here and let the transport
    loop re-evaluate its conditions.
    """

    def recv(self, n):
        while True:
            try:
                data = super().recv(n)
            except socket.timeout:
                if self._closed or self._LoopSocket__mate is None:
                    raise EOFError()
                # Otherwise just loop and block again; the test advances real
                # state (and the fake clock) from other threads.
                continue
            # LoopSocket returns empty bytes (rather than raising) once the
            # mate has been unlinked; surface that as an EOF like a real socket
            # so the transport thread notices a dropped peer.
            if data == b"" and self._LoopSocket__mate is None:
                raise EOFError()
            return data


class ClosingGate:
    """
    Gate that blocks until explicitly opened, but wakes periodically.

    A plain ``threading.Event`` parked forever would also freeze the server
    transport thread inside the kex engine, so it could never return to its
    read loop and notice a dropped socket.  ``wait`` therefore times out every
    ``poll`` seconds; callers simply re-enter until the gate is opened, and a
    torn-down socket surfaces as an EOF once the engine proceeds.
    """

    def __init__(self, poll=0.02, release_on_deadline=False):
        self._event = threading.Event()
        self._poll = poll
        # When True, a frozen engine is released as soon as its transport's
        # renegotiation deadline elapses, letting a *passive* peer's transport
        # thread reach its own run-loop deadline handling.  When False (the
        # default), the engine stays parked until the link drops or the gate
        # is opened, which keeps initiator-side tests deterministic.
        self._release_on_deadline = release_on_deadline

    def wait(self, transport):
        # Park until opened, or until the underlying link goes away.  With
        # release_on_deadline, a passive peer frozen inside its kex engine is
        # released at its deadline by raising rather than completing the
        # exchange, so the run loop records a RenegotiationError root cause
        # instead of spuriously finishing the key switch.
        while not self._event.wait(self._poll):
            if getattr(transport.sock, "_closed", False):
                return
            if self._release_on_deadline and transport._renegotiation_timed_out():
                raise RenegotiationError(
                    "Pausable kex engine released by renegotiation deadline"
                )

    def open(self):
        self._event.set()


class PausableKex(KexCurve25519):
    """
    Curve25519 kex engine whose *server* side can be frozen mid-exchange.

    Once the initial handshake is done, every renegotiation blocks on a shared
    gate just before the server emits its KEX reply, leaving the peer stuck in
    ``in_kex`` until the test opens the gate (or tears the connection down).

    State lives in class attributes (mirroring how ``Transport._kex_info``
    stores engine *classes*), and is reset explicitly by each test.
    """

    gate = None
    initial_kex_seen = False

    def _parse_kexecdh_init(self, m):
        if PausableKex.initial_kex_seen and PausableKex.gate is not None:
            PausableKex.gate.wait(self.transport)
        return super()._parse_kexecdh_init(m)


def _install_pausable_kex(tc, ts):
    # _kex_info is a class attribute mapping algo name -> engine class, so the
    # pausable engine has to be installed on the class itself (an instance
    # copy would be shadowed by the class lookup in _parse_kex_init).
    assert Transport._kex_info[KEX_NAME] is KexCurve25519
    Transport._kex_info[KEX_NAME] = PausableKex
    tc.get_security_options().kex = (KEX_NAME,)
    ts.get_security_options().kex = (KEX_NAME,)
    PausableKex.initial_kex_seen = False
    PausableKex.gate = None


def _restore_kex():
    Transport._kex_info[KEX_NAME] = KexCurve25519
    PausableKex.gate = None
    PausableKex.initial_kex_seen = False


class PausableServerTransport(Transport):
    def _parse_newkeys(self, m):
        PausableKex.initial_kex_seen = True
        return super()._parse_newkeys(m)


def _install_clock(transport, clock):
    transport._time = clock.time


def _make_pair(
    clock,
    *,
    renegotiation_timeout=DEADLINE,
    server_renegotiation_timeout=None,
    pausable=True,
):
    """Build an authenticated client/server transport pair on loop sockets."""
    socks = ControlledLoopSocket()
    sockc = ControlledLoopSocket()
    sockc.link(socks)

    server_factory = PausableServerTransport if pausable else Transport
    ts = server_factory(socks)
    tc = Transport(sockc)
    _install_clock(tc, clock)
    _install_clock(ts, clock)
    tc.renegotiation_timeout = renegotiation_timeout
    ts.renegotiation_timeout = (
        renegotiation_timeout
        if server_renegotiation_timeout is None
        else server_renegotiation_timeout
    )

    host_key = RSAKey.from_private_key_file(_support("rsa.key"))
    ts.add_server_key(host_key)

    if pausable:
        # Force both sides onto the pausable curve25519 engine.
        _install_pausable_kex(tc, ts)

    event = threading.Event()
    ts.start_server(event, TestServer())
    tc.connect(
        hostkey=RSAKey(data=host_key.asbytes()),
        username="slowdive",
        password="pygmalion",
    )
    event.wait(2.0)
    assert event.is_set()
    assert tc.is_active() and ts.is_active()
    return tc, ts, sockc, socks


def _wait_for(condition, *, timeout=2.0):
    """Poll a real-time condition without sleeping inside the fake clock."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if condition():
            return
        time.sleep(0.01)
    raise AssertionError("condition not reached within {}s".format(timeout))


def _join_threads(threads, timeout=5.0):
    for thread in threads:
        thread.join(timeout)
        assert not thread.is_alive(), "thread {} did not exit".format(
            thread.name
        )


class TestRenegotiationTimeout:
    def teardown_method(self):
        # Gates may still be closed if an assertion failed early; open them so
        # the daemon transport threads can unwind instead of leaking, and put
        # the kex registry back to its real engine.
        _restore_kex()

    def test_successful_renegotiation_keeps_channel_and_messages(self):
        clock = FakeClock()
        tc, ts, sockc, socks = _make_pair(clock)
        try:
            chan = tc.open_session()
            chan.exec_command("yes")
            schan = ts.accept(1.0)

            # A normal, un-paused renegotiation must complete under the
            # deadline even as the fake clock advances in small steps.
            tc.renegotiate_keys()
            assert not tc.in_kex and not ts.in_kex
            assert tc.is_active() and ts.is_active()

            # Existing channels survive the renegotiation and no in-flight
            # application data is lost.
            payload = b"rekey-still-delivers" * 16
            chan.send(payload)
            got = b""
            while len(got) < len(payload):
                chunk = schan.recv(len(payload))
                assert chunk
                got += chunk
            assert got == payload

            schan.close()
            chan.close()
        finally:
            tc.close()
            ts.close()
            sockc.close()
            socks.close()

    def test_simultaneous_rekey_times_out_and_closes_consistently(self):
        clock = FakeClock()
        gate = ClosingGate()
        # The initiator fails first and deterministically; the frozen server
        # only has a longer budget and learns of the failure via the dropped
        # link.
        tc, ts, sockc, socks = _make_pair(
            clock,
            renegotiation_timeout=DEADLINE,
            server_renegotiation_timeout=DEADLINE * 4,
        )
        PausableKex.gate = gate
        try:
            chan = tc.open_session()
            schan = ts.accept(1.0)

            results = {}

            def do_client_rekey():
                try:
                    tc.renegotiate_keys()
                except Exception as error:  # noqa: BLE001
                    results["client_rekey"] = error

            rekey_thread = threading.Thread(
                target=do_client_rekey, name="client-renegotiate"
            )
            rekey_thread.start()

            # Both sides initiate a rekey; the server's engine freezes before
            # emitting its reply, so both transports stay in_kex.
            _wait_for(lambda: tc.in_kex and ts.in_kex)

            # Block one sender on the send window and one channel opener and
            # one global request while the exchange is stuck.
            def record(name, fn):
                try:
                    fn()
                except Exception as error:  # noqa: BLE001
                    # Anything raised here is a valid "the waiter exited"; the
                    # assertions below check the precise root cause where the
                    # contract promises one.
                    results[name] = error

            def do_send():
                chan.send(b"x" * 4096)

            def do_open():
                tc.open_channel("session")

            def do_global():
                tc.global_request("acceptable")

            send_thread = threading.Thread(
                target=lambda: record("send", do_send), name="sender"
            )
            open_thread = threading.Thread(
                target=lambda: record("open", do_open), name="channel-open"
            )
            global_thread = threading.Thread(
                target=lambda: record("global", do_global),
                name="global-request",
            )
            send_thread.start()
            open_thread.start()
            global_thread.start()

            # The sender must actually be parked on clear_to_send.
            _wait_for(
                lambda: not tc.clear_to_send.is_set() and send_thread.is_alive()
            )
            assert open_thread.is_alive() and global_thread.is_alive()

            # Walk the fake clock past the deadline in small steps: no single
            # sleep anywhere, and the deadline is what fires the shutdown.
            for _ in range(int(DEADLINE * 20) + 1):
                clock.step(0.05)

            _join_threads(
                [rekey_thread, send_thread, open_thread, global_thread]
            )

            # The client's own shorter deadline fired, so every waiter sees
            # the precise RenegotiationError root cause.  Read directly
            # because get_exception() clears it.
            assert isinstance(tc.saved_exception, RenegotiationError)
            assert isinstance(results["client_rekey"], RenegotiationError)
            assert isinstance(results["open"], RenegotiationError)
            assert isinstance(results["global"], RenegotiationError)
            # The plain sender exits (its packet is dropped on a dead
            # transport) rather than hanging on the send window.
            assert "send" not in results

            # The whole client session is shut down and the old keys cannot be
            # used to send further application data.
            assert not tc.is_active()
            with pytest.raises(SSHException):
                tc.open_channel("session")
            assert chan.closed or not tc.is_active()

            # The peer's engine is frozen on the gate, so it only learns the
            # client went away once its link drops.  Simulate that drop and
            # confirm its transport thread exits instead of lingering.
            socks.close()
            _wait_for(lambda: not ts.is_active())
            assert not ts.is_active()

            schan.close()
        finally:
            gate.open()
            tc.close()
            ts.close()
            sockc.close()
            socks.close()

    def test_unrelated_packets_do_not_renew_the_deadline(self):
        clock = FakeClock()
        gate = ClosingGate()
        tc, ts, sockc, socks = _make_pair(
            clock,
            renegotiation_timeout=DEADLINE,
            server_renegotiation_timeout=DEADLINE * 4,
        )
        PausableKex.gate = gate
        try:
            result = {}

            def do_rekey():
                try:
                    tc.renegotiate_keys()
                except Exception as error:  # noqa: BLE001
                    result["error"] = error

            thread = threading.Thread(target=do_rekey, name="renegotiate")
            thread.start()
            _wait_for(lambda: tc.in_kex and ts.in_kex)

            # Flood MSG_IGNORE packets while crawling the clock.  These are
            # explicitly allowed during kex and must not push the deadline out.
            ignore = Message()
            ignore.add_byte(cMSG_IGNORE)
            ignore.add_bytes(b"noise")
            steps = int(DEADLINE * 20) + 5
            for i in range(steps):
                if i % 4 == 0:
                    ts._send_message(ignore)
                clock.step(0.05)

            _join_threads([thread])
            assert isinstance(result.get("error"), RenegotiationError)
            assert not tc.is_active()
            assert isinstance(tc.saved_exception, RenegotiationError)
        finally:
            gate.open()
            tc.close()
            ts.close()
            sockc.close()
            socks.close()

    def test_peer_disconnect_mid_renegotiation_preserves_root_cause(self):
        clock = FakeClock()
        gate = ClosingGate()
        tc, ts, sockc, socks = _make_pair(clock)
        PausableKex.gate = gate
        try:
            result = {}

            def do_rekey():
                try:
                    tc.renegotiate_keys()
                except Exception as error:  # noqa: BLE001
                    result["error"] = error

            thread = threading.Thread(target=do_rekey, name="renegotiate")
            thread.start()
            _wait_for(lambda: tc.in_kex and ts.in_kex)

            # The peer vanishes halfway through the exchange, before the
            # deadline is reached.
            ts.stop_thread()
            socks.close()

            _join_threads([thread])
            error = result.get("error")
            assert isinstance(error, (EOFError, OSError, SSHException))
            assert not tc.is_active()
            # The stored root cause is the connection loss, not the timeout.
            assert not isinstance(tc.saved_exception, RenegotiationError)

            # And the deadline must not have been reached on the fake clock.
            assert clock.time() < 1000.0 + DEADLINE
        finally:
            gate.open()
            tc.close()
            ts.close()
            sockc.close()
            socks.close()

    def test_passive_peer_rekey_times_out_in_run_loop(self):
        # The peer (here the server) does not call renegotiate_keys itself; it
        # is dragged into an exchange by the client's MSG_KEXINIT and then the
        # client freezes.  Its *transport thread* must still notice the
        # deadline in its run loop and shut the session down consistently.
        clock = FakeClock()
        # The passive server gets the short budget; the gate releases its
        # engine once that deadline elapses so the run loop can raise.
        gate = ClosingGate(release_on_deadline=True)
        tc, ts, sockc, socks = _make_pair(
            clock,
            renegotiation_timeout=DEADLINE * 4,
            server_renegotiation_timeout=DEADLINE,
        )
        PausableKex.gate = gate
        try:
            chan = tc.open_session()
            schan = ts.accept(1.0)

            # Kick off from the client side, then freeze the server's engine.
            result = {}

            def do_rekey():
                try:
                    tc.renegotiate_keys()
                except Exception as error:  # noqa: BLE001
                    result["error"] = error

            rekey_thread = threading.Thread(
                target=do_rekey, name="client-renegotiate", daemon=True
            )
            rekey_thread.start()
            _wait_for(lambda: tc.in_kex and ts.in_kex)

            # Crawl the fake clock; the server has no application waiter, so
            # only its run-loop deadline check can fire.
            for _ in range(int(DEADLINE * 20) + 2):
                clock.step(0.05)

            # The passive server's run-loop deadline fires first and tears its
            # own session down.
            _wait_for(lambda: not ts.is_active())
            assert isinstance(ts.saved_exception, RenegotiationError)

            # The client, whose peer has dropped, unwinds with a connection
            # failure root cause (its own longer timeout has not fired yet).
            rekey_thread.join(5.0)
            assert not rekey_thread.is_alive()
            # The thread's wait returns on the dead socket; the transport then
            # flips active on its own shutdown, so wait for that too.
            _wait_for(lambda: not tc.is_active())
            assert not tc.is_active()
            assert isinstance(
                result.get("error"), (EOFError, OSError, SSHException)
            )
            assert not isinstance(result.get("error"), RenegotiationError)

            schan.close()
            chan.close()
        finally:
            gate.open()
            tc.close()
            ts.close()
            sockc.close()
            socks.close()

    def test_deadline_is_configurable_per_transport(self):
        clock = FakeClock()
        tc, ts, sockc, socks = _make_pair(
            clock, renegotiation_timeout=1.25, pausable=False
        )
        try:
            assert tc.renegotiation_timeout == 1.25
            # Arming happens only for post-initial renegotiations.
            assert tc._renegotiation_deadline is None
            tc.renegotiate_keys()
            assert tc._renegotiation_deadline is None
            assert tc.is_active()
        finally:
            tc.close()
            ts.close()
            sockc.close()
            socks.close()

    def test_deadline_covers_whole_exchange_not_each_packet(self):
        # Regression guard: the deadline is armed once per exchange, so
        # unrelated traffic must not restart the budget.  Assert the internal
        # deadline value stays constant across mid-exchange packets.
        clock = FakeClock()
        gate = ClosingGate()
        tc, ts, sockc, socks = _make_pair(clock)
        PausableKex.gate = gate
        try:
            thread = threading.Thread(
                target=tc.renegotiate_keys, name="renegotiate"
            )
            thread.start()
            _wait_for(lambda: tc.in_kex and ts.in_kex)

            armed = tc._renegotiation_deadline
            assert armed == 1000.0 + DEADLINE

            ignore = Message()
            ignore.add_byte(cMSG_IGNORE)
            ignore.add_bytes(b"noise")
            for _ in range(5):
                ts._send_message(ignore)
                clock.step(0.5)

            # Same absolute deadline despite packets + clock movement.
            assert tc._renegotiation_deadline == armed
            assert thread.is_alive()
        finally:
            gate.open()
            _join_threads([thread], timeout=2.0)
            tc.close()
            ts.close()
            sockc.close()
            socks.close()
