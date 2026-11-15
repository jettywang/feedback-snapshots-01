"""
Tests for the bounded channel result collector.

These use a real Paramiko Transport/Channel pair over the in-memory loop
socket, with a deliberately tiny channel window, so output larger than one
window reproduces the classic ``recv_exit_status`` deadlock if the collector
ever waits for the exit status before draining stdout/stderr.
"""

import threading
import time
from unittest.mock import patch

import pytest

from paramiko import RSAKey, Transport
from paramiko.bounded import (
    BoundedResult,
    ResultReason,
    ResultStatus,
    collect_bounded,
)
from paramiko.channel import Channel
from paramiko.common import MIN_WINDOW_SIZE

from ._loop import LoopSocket
from ._util import TestServer as BaseServer
from ._util import _support, wait_until


class ExecServer(BaseServer):
    """Accept any exec command; individual tests drive the output."""

    def check_channel_exec_request(self, channel, command):
        return True


class LocalSSH:
    """Minimal local client/server pair with a small receive window."""

    def __init__(self, window_size=MIN_WINDOW_SIZE):
        self.socks = LoopSocket()
        self.sockc = LoopSocket()
        self.sockc.link(self.socks)
        self.tc = Transport(self.sockc, default_window_size=window_size)
        self.ts = Transport(self.socks, default_window_size=window_size)
        self.server = ExecServer()
        self.event = threading.Event()

    def __enter__(self):
        host_key = RSAKey.from_private_key_file(_support("rsa.key"))
        self.ts.add_server_key(host_key)
        self.ts.start_server(self.event, self.server)
        self.tc.connect(username="slowdive", password="pygmalion")
        assert self.event.wait(2.0)
        return self

    def __exit__(self, *exc_info):
        self.tc.close()
        self.ts.close()
        self.socks.close()
        self.sockc.close()

    def open(self, command="fixed-check"):
        channel = self.tc.open_session()
        channel.exec_command(command)
        return channel

    def accept(self, timeout=2.0):
        channel = self.ts.accept(timeout)
        assert channel is not None
        return channel


def payload(size, marker):
    """Deterministic, stream-distinct bytes."""
    return bytes(((i * 31 + marker) % 251) for i in range(size))


def run_in_thread(target):
    errors = []

    def wrapper():
        try:
            target()
        except (OSError, EOFError):
            # Expected whenever the client closes the channel or transport
            # while the server is still writing.
            pass
        except BaseException as e:  # pragma: no cover - surfaced below
            errors.append(e)

    thread = threading.Thread(target=wrapper, daemon=True)
    thread.start()
    return thread, errors


def bounded_threads():
    return [
        thread
        for thread in threading.enumerate()
        if thread.name.startswith("paramiko-bounded-")
    ]


def assert_released(channel, transport):
    assert channel.closed
    wait_until(
        lambda: all(
            chan is not channel for chan in transport._channels.values()
        )
    )
    wait_until(lambda: bounded_threads() == [])


def interleave(schannel, out_data, err_data, out_chunk=4000, err_chunk=3000):
    out_pos = err_pos = 0
    while out_pos < len(out_data) or err_pos < len(err_data):
        if out_pos < len(out_data):
            sent = schannel.send(out_data[out_pos : out_pos + out_chunk])
            if sent == 0:
                return
            out_pos += sent
        if err_pos < len(err_data):
            sent = schannel.send_stderr(
                err_data[err_pos : err_pos + err_chunk]
            )
            if sent == 0:
                return
            err_pos += sent


def test_large_interleaved_output_is_complete_without_waiting_for_status():
    out_data = payload(200_000, 7)
    err_data = payload(150_000, 11)

    with LocalSSH() as ssh:
        channel = ssh.open()
        schannel = ssh.accept()

        def produce():
            interleave(schannel, out_data, err_data)
            schannel.send_exit_status(0)
            schannel.close()

        thread, errors = run_in_thread(produce)

        # If collect_bounded ever called this before draining, the remote
        # side would stall on the channel window and this call would hang.
        with patch.object(
            Channel,
            "recv_exit_status",
            side_effect=AssertionError("must not block on exit status"),
        ):
            result = collect_bounded(
                channel, max_bytes=1_000_000, timeout=10
            )

        thread.join(5.0)
        assert not thread.is_alive()
        assert errors == []
        assert result.status is ResultStatus.COMPLETE
        assert result.reason is ResultReason.EXITED_ZERO
        assert result.complete
        assert result.exit_status == 0
        assert result.stdout == out_data
        assert result.stderr == err_data
        assert not result.truncated
        assert_released(channel, ssh.tc)


def test_output_limit_fails_and_does_not_report_truncation_as_complete():
    out_data = payload(80_000, 3)
    err_data = payload(80_000, 5)
    budget = 4096

    with LocalSSH() as ssh:
        channel = ssh.open()
        schannel = ssh.accept()

        def produce():
            interleave(schannel, out_data, err_data)
            schannel.send_exit_status(0)
            schannel.close()

        thread, errors = run_in_thread(produce)
        result = collect_bounded(channel, max_bytes=budget, timeout=10)
        thread.join(5.0)

        assert errors == []
        assert isinstance(result, BoundedResult)
        assert result.status is ResultStatus.FAILED
        assert result.reason is ResultReason.OUTPUT_LIMIT
        assert not result.complete
        assert result.truncated
        assert result.stdout_truncated or result.stderr_truncated
        assert len(result.stdout) + len(result.stderr) <= budget
        assert_released(channel, ssh.tc)

        # A failing channel must not poison the transport for other channels.
        other = ssh.open("second-channel")
        other_server = ssh.accept()
        other_server.send(b"fine")
        other_server.send_stderr(b"also fine")
        other_server.send_exit_status(0)
        other_server.close()
        other_result = collect_bounded(other, max_bytes=1024, timeout=10)
        assert other_result.status is ResultStatus.COMPLETE
        assert other_result.stdout == b"fine"
        assert other_result.stderr == b"also fine"
        assert_released(other, ssh.tc)


def test_nonzero_exit_status_is_failed_with_complete_bytes():
    with LocalSSH() as ssh:
        channel = ssh.open()
        schannel = ssh.accept()
        schannel.send(b"checked")
        schannel.send_stderr(b"warning")
        schannel.send_exit_status(42)
        schannel.close()

        result = collect_bounded(channel, max_bytes=1024, timeout=10)

        assert result.status is ResultStatus.FAILED
        assert result.reason is ResultReason.EXITED_NONZERO
        assert result.exit_status == 42
        assert result.stdout == b"checked"
        assert result.stderr == b"warning"
        assert not result.truncated
        assert_released(channel, ssh.tc)


def test_missing_exit_status_is_unknown_not_success():
    with LocalSSH() as ssh:
        channel = ssh.open()
        schannel = ssh.accept()
        schannel.send(b"some output")
        schannel.send_stderr(b"some warning")
        schannel.close()  # no send_exit_status

        result = collect_bounded(
            channel, max_bytes=1024, timeout=10, status_grace=0.1
        )

        assert result.status is ResultStatus.UNKNOWN
        assert result.reason is ResultReason.MISSING_EXIT_STATUS
        assert result.exit_status is None
        assert not result.complete
        assert result.stdout == b"some output"
        assert_released(channel, ssh.tc)


def test_transport_disconnect_is_unknown():
    with LocalSSH() as ssh:
        channel = ssh.open()
        schannel = ssh.accept()

        def produce_and_drop():
            schannel.send(b"partial output")
            time.sleep(0.05)
            ssh.ts.close()

        thread, errors = run_in_thread(produce_and_drop)
        result = collect_bounded(channel, max_bytes=1024, timeout=10)
        thread.join(5.0)

        assert errors == []
        assert result.status is ResultStatus.UNKNOWN
        assert result.reason is ResultReason.DISCONNECTED
        assert not result.complete
        assert result.exit_status is None
        assert_released(channel, ssh.tc)


def test_deadline_is_unknown_and_releases_channel():
    release = threading.Event()

    with LocalSSH() as ssh:
        channel = ssh.open()
        schannel = ssh.accept()

        def produce_then_hold():
            try:
                schannel.send(b"partial")
                release.wait(5.0)
            finally:
                release.set()

        thread, errors = run_in_thread(produce_then_hold)
        result = collect_bounded(channel, max_bytes=1024, timeout=0.3)
        release.set()
        thread.join(5.0)

        assert errors == []
        assert result.status is ResultStatus.UNKNOWN
        assert result.reason is ResultReason.DEADLINE_EXCEEDED
        assert not result.complete
        assert_released(channel, ssh.tc)


def test_cancellation_is_unknown_and_leaves_other_channels_alone():
    release = threading.Event()

    with LocalSSH() as ssh:
        channel = ssh.open()
        schannel = ssh.accept()

        def produce_until_stopped():
            try:
                sent = 0
                while not release.is_set():
                    chunk = b"x" * 4096
                    if schannel.send(chunk) == 0:
                        return
                    sent += len(chunk)
                    time.sleep(0.005)
            finally:
                pass

        thread, errors = run_in_thread(produce_until_stopped)
        cancel = threading.Event()
        timer = threading.Timer(0.15, cancel.set)
        timer.start()
        try:
            result = collect_bounded(
                channel, max_bytes=5_000_000, timeout=10, cancel=cancel
            )
        finally:
            timer.cancel()
            release.set()
        thread.join(5.0)

        assert errors == []
        assert result.status is ResultStatus.UNKNOWN
        assert result.reason is ResultReason.CANCELLED
        assert not result.complete
        assert_released(channel, ssh.tc)

        # The transport must still be usable for an unrelated channel.
        other = ssh.open("after-cancel")
        other_server = ssh.accept()
        other_server.send(b"still alive")
        other_server.send_exit_status(0)
        other_server.close()
        other_result = collect_bounded(other, max_bytes=1024, timeout=10)
        assert other_result.status is ResultStatus.COMPLETE
        assert other_result.stdout == b"still alive"
        assert_released(other, ssh.tc)


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(max_bytes=0, timeout=1),
        dict(max_bytes=-1, timeout=1),
        dict(max_bytes=10, timeout=0),
        dict(max_bytes=10, timeout=None),
    ],
)
def test_invalid_arguments_are_rejected(kwargs):
    with LocalSSH() as ssh:
        channel = ssh.open()
        ssh.accept()
        with pytest.raises(ValueError):
            collect_bounded(channel, **kwargs)


def test_exit_status_before_final_output_does_not_stop_draining():
    early = payload(90_000, 17)
    late = payload(90_000, 19)

    with LocalSSH() as ssh:
        channel = ssh.open()
        schannel = ssh.accept()

        def produce():
            # Send just enough stdout/stderr to move the window, then report
            # the exit status while output is still pending.  A collector
            # that treats exit_status_ready() as "done" would drop `late`.
            interleave(
                schannel,
                early[:30_000],
                early[30_000:60_000],
                out_chunk=10_000,
                err_chunk=10_000,
            )
            schannel.send_exit_status(0)
            interleave(schannel, late, early[60_000:])
            schannel.close()

        thread, errors = run_in_thread(produce)
        result = collect_bounded(channel, max_bytes=1_000_000, timeout=10)
        thread.join(5.0)

        assert errors == []
        assert result.status is ResultStatus.COMPLETE
        assert result.exit_status == 0
        assert result.stdout == early[:30_000] + late
        assert result.stderr == early[30_000:60_000] + early[60_000:]
        assert_released(channel, ssh.tc)


def test_output_exactly_at_budget_is_complete():
    out_data = b"a" * 512
    err_data = b"b" * 512

    with LocalSSH() as ssh:
        channel = ssh.open()
        schannel = ssh.accept()
        schannel.send(out_data)
        schannel.send_stderr(err_data)
        schannel.send_exit_status(0)
        schannel.close()

        result = collect_bounded(
            channel, max_bytes=len(out_data) + len(err_data), timeout=10
        )

        assert result.status is ResultStatus.COMPLETE
        assert not result.truncated
        assert result.stdout == out_data
        assert result.stderr == err_data
        assert_released(channel, ssh.tc)


def test_deadline_while_waiting_for_missing_status_is_deadline():
    with LocalSSH() as ssh:
        channel = ssh.open()
        schannel = ssh.accept()
        schannel.send(b"output")
        # Leave the channel open, produce no exit-status, and keep the
        # connection healthy; the overall deadline is the decisive event.
        result = collect_bounded(
            channel,
            max_bytes=1024,
            timeout=0.2,
            status_grace=5.0,
        )
        schannel.close()

        assert result.status is ResultStatus.UNKNOWN
        assert result.reason is ResultReason.DEADLINE_EXCEEDED
        assert result.stdout == b"output"
        assert not result.complete
        assert_released(channel, ssh.tc)


def test_reader_thread_start_failure_is_reported_and_cleaned_up():
    with LocalSSH() as ssh:
        channel = ssh.open()
        ssh.accept()

        # Fail the second reader's start.  The first must still be joined and
        # the channel closed; the original error must be reported rather than
        # hidden by joining a never-started thread.
        from paramiko import bounded

        real_thread = bounded.threading.Thread
        calls = []

        class FlakyThread(real_thread):
            def start(self):
                calls.append(self.name)
                if len(calls) == 2:
                    raise RuntimeError("simulated start failure")
                super().start()

        with patch.object(bounded.threading, "Thread", FlakyThread):
            result = collect_bounded(channel, max_bytes=1024, timeout=5)

        assert result.status is ResultStatus.UNKNOWN
        assert result.reason is ResultReason.CHANNEL_ERROR
        assert isinstance(result.error, RuntimeError)
        assert_released(channel, ssh.tc)


def test_non_integer_budget_is_rejected():
    with LocalSSH() as ssh:
        channel = ssh.open()
        ssh.accept()
        with pytest.raises(TypeError):
            collect_bounded(channel, max_bytes=10.5, timeout=1)


def test_large_stderr_alone_is_drained_and_completes():
    # stderr alone exceeds the small channel window.  A collector that only
    # read stdout would leave the stderr window full and never see the
    # exit-status or channel close.
    err_data = payload(250_000, 23)

    with LocalSSH() as ssh:
        assert ssh.tc.default_window_size == MIN_WINDOW_SIZE
        channel = ssh.open()
        schannel = ssh.accept()

        def produce():
            pos = 0
            while pos < len(err_data):
                sent = schannel.send_stderr(err_data[pos : pos + 8192])
                if sent == 0:
                    return
                pos += sent
            schannel.send_exit_status(0)
            schannel.close()

        thread, errors = run_in_thread(produce)
        result = collect_bounded(channel, max_bytes=1_000_000, timeout=10)
        thread.join(5.0)

        assert errors == []
        assert result.status is ResultStatus.COMPLETE
        assert result.stdout == b""
        assert result.stderr == err_data
        assert_released(channel, ssh.tc)
