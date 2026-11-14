# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""Tests for the cancellation & cleanup contract of handler hooks.

A slow MAIL/RCPT/DATA hook (e.g. a recipient policy query) must not be able
to affect a transaction -- or trigger delivery -- once the connection that
owns the transaction is gone (disconnect, timeout) or once the hook failed.

These tests drive the SMTP protocol directly (no sockets) so that the
client disconnect can be triggered at exact await points of pausable hooks.
"""

import asyncio
import logging

from contextlib import suppress
from typing import List, Optional, Tuple

import pytest

from aiosmtpd.smtp import SMTP as Server, Envelope


BCRLF = b"\r\n"
S_250_OK = b"250 OK\r\n"
S_503_RCPT = b"503 Error: need RCPT command\r\n"
S_503_MAIL = b"503 Error: need MAIL command\r\n"


# region #### Helpers #################################################################


class FakeTransport:
    """Minimal in-memory transport recording everything written to it."""

    def __init__(self) -> None:
        self.responses: List[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.responses.append(data)

    def close(self) -> None:
        self.closed = True

    def is_closing(self) -> bool:
        return self.closed

    def get_extra_info(self, name, default=None):
        return default


def make_protocol(
    loop: asyncio.AbstractEventLoop, handler, **kwargs
) -> Tuple[Server, FakeTransport]:
    transport = FakeTransport()
    proto = Server(handler, loop=loop, **kwargs)
    proto.connection_made(transport)
    return proto, transport


async def settle(rounds: int = 10) -> None:
    """Let all ready tasks run to their next suspension points."""
    for _ in range(rounds):
        await asyncio.sleep(0.001)


def stray_tasks() -> List[asyncio.Task]:
    current = asyncio.current_task()
    return [
        task
        for task in asyncio.all_tasks()
        if task is not current and not task.done()
    ]


class PolicyHandler:
    """Handler with a pausable RCPT 'policy query', tracking envelopes.

    Every envelope the RCPT hook touches is recorded, so tests can verify
    that results of aborted hooks never leak into another transaction or
    connection, and that only confirmed recipients get delivered to.
    """

    def __init__(self, swallow_cancel: bool = False) -> None:
        self.swallow = swallow_cancel
        self.rcpt_entered = asyncio.Event()
        self.rcpt_release = asyncio.Event()
        self.seen_envelopes: List[Envelope] = []
        self.cancelled = 0
        self.deliveries: List[Tuple[Envelope, List[str]]] = []

    async def handle_RCPT(self, server, session, envelope, address, options):
        self.seen_envelopes.append(envelope)
        self.rcpt_entered.set()
        try:
            await self.rcpt_release.wait()
        except asyncio.CancelledError:
            self.cancelled += 1
            if not self.swallow:
                raise
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        self.deliveries.append((envelope, list(envelope.rcpt_tos)))
        return "250 OK"


# endregion


class TestLateHookResults:
    """Late MAIL/RCPT/DATA hook results must not mutate transactions."""

    def test_slow_rcpt_hook_still_completes(self, temp_event_loop):
        """A legitimate slow policy query finishes normally."""
        async def main():
            handler = PolicyHandler()
            proto, transport = make_protocol(temp_event_loop, handler)
            proto.data_received(BCRLF.join([
                b"HELO example.org",
                b"MAIL FROM: <anne@example.com>",
                b"RCPT TO: <bart@example.com>",
                b"",
            ]))
            await handler.rcpt_entered.wait()
            # The policy query is still running: no response yet.
            assert transport.responses[-1] == S_250_OK  # MAIL's response
            handler.rcpt_release.set()
            await settle()
            assert transport.responses[-1] == S_250_OK  # RCPT's response
            assert proto.envelope.rcpt_tos == ["bart@example.com"]
            proto.data_received(BCRLF.join([b"DATA", b"hi", b".", b"QUIT", b""]))
            with suppress(asyncio.CancelledError):
                await proto._handler_coroutine
            assert len(handler.deliveries) == 1
            assert handler.deliveries[0][1] == ["bart@example.com"]
            assert transport.responses[-2] == S_250_OK  # DATA accepted
        temp_event_loop.run_until_complete(main())

    def test_disconnect_during_rcpt_hook_swallowed_cancel(self, temp_event_loop):
        """Disconnect while the policy query is in flight; the hook ignores
        the cancellation and completes late.  Its result must be discarded."""
        async def main():
            handler = PolicyHandler(swallow_cancel=True)
            proto, transport = make_protocol(temp_event_loop, handler)
            proto.data_received(BCRLF.join([
                b"HELO example.org",
                b"MAIL FROM: <anne@example.com>",
                b"RCPT TO: <bart@example.com>",
                b"",
            ]))
            await handler.rcpt_entered.wait()
            responses_before = len(transport.responses)
            # Client goes away while the hook is still waiting.
            proto.connection_lost(None)
            # The policy query finally answers, ignoring the cancellation.
            handler.rcpt_release.set()
            await settle()
            # No late (success) response may be sent to the dead connection,
            assert transport.responses[responses_before:] == []
            # ... the unconfirmed recipient must not linger,
            assert proto.envelope.rcpt_tos == []
            # ... no delivery may have happened,
            assert handler.deliveries == []
            # ... and no handler task may be left behind.
            assert proto._handler_coroutine.done()
            assert stray_tasks() == []
        temp_event_loop.run_until_complete(main())

    def test_disconnect_during_rcpt_hook_cooperative(self, temp_event_loop):
        """A well-behaved hook is cancelled promptly on disconnect."""
        async def main():
            handler = PolicyHandler()
            proto, transport = make_protocol(temp_event_loop, handler)
            proto.data_received(BCRLF.join([
                b"HELO example.org",
                b"MAIL FROM: <anne@example.com>",
                b"RCPT TO: <bart@example.com>",
                b"",
            ]))
            await handler.rcpt_entered.wait()
            responses_before = len(transport.responses)
            proto.connection_lost(None)
            await settle()
            assert handler.cancelled == 1
            assert transport.responses[responses_before:] == []
            assert proto.envelope.rcpt_tos == []
            assert handler.deliveries == []
            assert proto._handler_coroutine.done()
            assert stray_tasks() == []
        temp_event_loop.run_until_complete(main())

    def test_timeout_during_rcpt_hook(self, temp_event_loop):
        """A session timeout while the hook is in flight discards the
        late hook result as well."""
        async def main():
            handler = PolicyHandler(swallow_cancel=True)
            proto, transport = make_protocol(
                temp_event_loop, handler, timeout=30)
            proto.data_received(BCRLF.join([
                b"HELO example.org",
                b"MAIL FROM: <anne@example.com>",
                b"RCPT TO: <bart@example.com>",
                b"",
            ]))
            await handler.rcpt_entered.wait()
            responses_before = len(transport.responses)
            # The inactivity timeout fires and the transport goes down.
            proto._timeout_cb()
            proto.connection_lost(None)
            handler.rcpt_release.set()
            await settle()
            assert transport.responses[responses_before:] == []
            assert proto.envelope.rcpt_tos == []
            assert handler.deliveries == []
            assert stray_tasks() == []
        temp_event_loop.run_until_complete(main())

    def test_eof_during_mail_hook(self, temp_event_loop):
        """Client EOF while the MAIL hook is in flight: the half-established
        sender must not survive."""
        class MailHandler(PolicyHandler):
            async def handle_MAIL(self, server, session, envelope,
                                  address, options):
                self.rcpt_entered.set()
                try:
                    await self.rcpt_release.wait()
                except asyncio.CancelledError:
                    self.cancelled += 1
                    if not self.swallow:
                        raise
                envelope.mail_from = address
                return "250 OK"

        async def main():
            handler = MailHandler(swallow_cancel=True)
            proto, transport = make_protocol(temp_event_loop, handler)
            proto.data_received(BCRLF.join([
                b"HELO example.org",
                b"MAIL FROM: <anne@example.com>",
                b"",
            ]))
            await handler.rcpt_entered.wait()
            responses_before = len(transport.responses)
            proto.eof_received()
            handler.rcpt_release.set()
            await settle()
            assert transport.responses[responses_before:] == []
            assert proto.envelope.mail_from is None
            assert stray_tasks() == []
        temp_event_loop.run_until_complete(main())

    def test_aborted_hook_does_not_leak_into_new_connection(
        self, temp_event_loop
    ):
        """A late result from an aborted connection must not affect a new
        connection sharing the same handler."""
        async def main():
            handler = PolicyHandler(swallow_cancel=True)
            proto1, transport1 = make_protocol(temp_event_loop, handler)
            proto1.data_received(BCRLF.join([
                b"HELO example.org",
                b"MAIL FROM: <anne@example.com>",
                b"RCPT TO: <bart@example.com>",
                b"",
            ]))
            await handler.rcpt_entered.wait()
            proto1.connection_lost(None)
            aborted_envelope = proto1.envelope

            # A new connection arrives while the old hook is still stuck.
            handler.rcpt_entered.clear()
            proto2, transport2 = make_protocol(temp_event_loop, handler)
            proto2.data_received(BCRLF.join([
                b"HELO example.org",
                b"MAIL FROM: <cate@example.com>",
                b"RCPT TO: <dave@example.com>",
                b"",
            ]))
            await handler.rcpt_entered.wait()
            handler.rcpt_release.set()
            await settle()
            # The second connection's transaction completed on its own
            # envelope, untouched by the aborted connection's late result.
            assert proto2.envelope.rcpt_tos == ["dave@example.com"]
            assert proto2.envelope.mail_from == "cate@example.com"
            assert aborted_envelope.rcpt_tos == []
            proto2.data_received(
                BCRLF.join([b"DATA", b"hi", b".", b"QUIT", b""]))
            with suppress(asyncio.CancelledError):
                await proto2._handler_coroutine
            assert len(handler.deliveries) == 1
            delivered_envelope, rcpt_tos = handler.deliveries[0]
            assert delivered_envelope is not aborted_envelope
            assert rcpt_tos == ["dave@example.com"]
            assert stray_tasks() == []
        temp_event_loop.run_until_complete(main())

    def test_concurrent_hooks_are_not_serialized(self, temp_event_loop):
        """Slow hooks of independent connections overlap; no global lock."""
        async def main():
            handler1 = PolicyHandler()
            handler2 = PolicyHandler()
            proto1, _ = make_protocol(temp_event_loop, handler1)
            proto2, _ = make_protocol(temp_event_loop, handler2)
            for proto, rcpt in (
                (proto1, b"RCPT TO: <bart@example.com>"),
                (proto2, b"RCPT TO: <dave@example.com>"),
            ):
                proto.data_received(BCRLF.join([
                    b"HELO example.org",
                    b"MAIL FROM: <anne@example.com>",
                    rcpt,
                    b"",
                ]))
            # Both policy queries are in flight at the same time.
            await asyncio.wait_for(handler1.rcpt_entered.wait(), 1)
            await asyncio.wait_for(handler2.rcpt_entered.wait(), 1)
            handler1.rcpt_release.set()
            handler2.rcpt_release.set()
            await settle()
            assert proto1.envelope.rcpt_tos == ["bart@example.com"]
            assert proto2.envelope.rcpt_tos == ["dave@example.com"]
            for proto in (proto1, proto2):
                proto.data_received(BCRLF.join([b"QUIT", b""]))
                with suppress(asyncio.CancelledError):
                    await proto._handler_coroutine
            assert stray_tasks() == []
        temp_event_loop.run_until_complete(main())


class TestAcceptedVsPendingRecipients:
    """Explicitly accepted recipients must be distinguishable from ones
    whose hook never confirmed them."""

    def test_failed_rcpt_hook_rolls_back_only_pending_recipient(
        self, temp_event_loop
    ):
        class FlakyHandler(PolicyHandler):
            def __init__(self):
                super().__init__()
                self.fail_next = True

            async def handle_RCPT(self, server, session, envelope,
                                  address, options):
                if self.fail_next and address == "bart@example.com":
                    self.fail_next = False
                    envelope.rcpt_tos.append(address)
                    raise RuntimeError("policy backend exploded")
                envelope.rcpt_tos.append(address)
                return "250 OK"

        async def main():
            handler = FlakyHandler()
            proto, transport = make_protocol(temp_event_loop, handler)
            proto.data_received(BCRLF.join([
                b"HELO example.org",
                b"MAIL FROM: <anne@example.com>",
                b"RCPT TO: <cate@example.com>",   # accepted (250)
                b"RCPT TO: <bart@example.com>",   # hook fails after append
                b"",
            ]))
            await settle()
            assert transport.responses[3] == S_250_OK
            assert transport.responses[4].startswith(b"500 ")
            # Only the never-confirmed recipient was rolled back; the
            # explicitly accepted one is untouched.
            assert proto.envelope.rcpt_tos == ["cate@example.com"]
            proto.data_received(BCRLF.join([b"DATA", b"hi", b".", b"QUIT", b""]))
            with suppress(asyncio.CancelledError):
                await proto._handler_coroutine
            # Delivery happens to the accepted recipient only.
            assert len(handler.deliveries) == 1
            assert handler.deliveries[0][1] == ["cate@example.com"]
        temp_event_loop.run_until_complete(main())

    def test_failed_mail_hook_clears_sender(self, temp_event_loop):
        class ClumsyMailHandler:
            async def handle_MAIL(self, server, session, envelope,
                                  address, options):
                envelope.mail_from = address
                raise RuntimeError("policy backend exploded")

        async def main():
            handler = ClumsyMailHandler()
            proto, transport = make_protocol(temp_event_loop, handler)
            proto.data_received(BCRLF.join([
                b"HELO example.org",
                b"MAIL FROM: <anne@example.com>",
                b"RCPT TO: <bart@example.com>",
                b"",
            ]))
            await settle()
            assert transport.responses[2].startswith(b"500 ")
            # The half-established sender was rolled back, so the
            # transaction cannot continue.
            assert proto.envelope.mail_from is None
            assert transport.responses[3] == S_503_MAIL
            proto.data_received(BCRLF.join([b"QUIT", b""]))
            with suppress(asyncio.CancelledError):
                await proto._handler_coroutine
        temp_event_loop.run_until_complete(main())


class TestDataHookCleanup:
    """Cleanup after a failed DATA hook: state reset, original error kept,
    no belated success response."""

    def test_data_hook_exception_resets_transaction(self, temp_event_loop):
        class FailingDataHandler:
            def __init__(self):
                self.fail = True
                self.deliveries = []

            async def handle_DATA(self, server, session, envelope):
                if self.fail:
                    self.fail = False
                    raise RuntimeError("boom")
                self.deliveries.append(
                    (envelope.mail_from, list(envelope.rcpt_tos),
                     envelope.content))
                return "250 OK"

        async def main():
            handler = FailingDataHandler()
            proto, transport = make_protocol(temp_event_loop, handler)
            proto.data_received(BCRLF.join([
                b"HELO example.org",
                b"MAIL FROM: <anne@example.com>",
                b"RCPT TO: <bart@example.com>",
                b"DATA",
                b"first message",
                b".",
                b"",
            ]))
            await settle()
            assert transport.responses[5].startswith(b"500 ")
            # The failed transaction was cleaned up: no sender, no
            # recipients, no content left over.
            assert proto.envelope.mail_from is None
            assert proto.envelope.rcpt_tos == []
            assert proto.envelope.content is None
            # A bare DATA must not resurrect the aborted transaction.
            proto.data_received(BCRLF.join([b"DATA", b""]))
            await settle()
            assert transport.responses[6] == S_503_RCPT
            assert handler.deliveries == []
            # A fresh, complete transaction still works and delivers only
            # its own data to its own recipients.
            proto.data_received(BCRLF.join([
                b"MAIL FROM: <cate@example.com>",
                b"RCPT TO: <dave@example.com>",
                b"DATA",
                b"second message",
                b".",
                b"QUIT",
                b"",
            ]))
            with suppress(asyncio.CancelledError):
                await proto._handler_coroutine
            assert handler.deliveries == [
                ("cate@example.com", ["dave@example.com"], b"second message\r\n")
            ]
        temp_event_loop.run_until_complete(main())

    def test_cleanup_failure_does_not_mask_original_error(
        self, temp_event_loop, caplog
    ):
        class FailingDataHandler:
            async def handle_DATA(self, server, session, envelope):
                raise ValueError("original rejection")

        async def main():
            handler = FailingDataHandler()
            proto, transport = make_protocol(temp_event_loop, handler)
            with caplog.at_level(logging.ERROR):
                proto.data_received(BCRLF.join([
                    b"HELO example.org",
                    b"MAIL FROM: <anne@example.com>",
                    b"RCPT TO: <bart@example.com>",
                    b"DATA",
                    b"hi",
                    b"",
                ]))
                await settle()
                # Make the post-failure state reset blow up once the DATA
                # hook has failed.
                def broken_envelope():
                    raise RuntimeError("cleanup exploded")
                proto._create_envelope = broken_envelope
                proto.data_received(BCRLF.join([b".", b""]))
                await settle()
            # The client sees the original rejection, not the cleanup error.
            assert transport.responses[5] == (
                b"500 Error: (ValueError) original rejection\r\n")
            # The cleanup failure was logged, not propagated.
            assert any(
                "cleanup exploded" in record.getMessage()
                or "Error resetting state" in record.getMessage()
                for record in caplog.records
            )
            proto.data_received(BCRLF.join([b"QUIT", b""]))
            with suppress(asyncio.CancelledError):
                await proto._handler_coroutine
        temp_event_loop.run_until_complete(main())

    def test_disconnect_during_data_hook_sends_no_late_success(
        self, temp_event_loop
    ):
        class SlowDataHandler:
            def __init__(self):
                self.entered = asyncio.Event()
                self.release = asyncio.Event()
                self.delivered = 0

            async def handle_DATA(self, server, session, envelope):
                self.entered.set()
                try:
                    await self.release.wait()
                except asyncio.CancelledError:
                    pass  # ignores the cancellation and finishes anyway
                self.delivered += 1
                return "250 OK"

        async def main():
            handler = SlowDataHandler()
            proto, transport = make_protocol(temp_event_loop, handler)
            proto.data_received(BCRLF.join([
                b"HELO example.org",
                b"MAIL FROM: <anne@example.com>",
                b"RCPT TO: <bart@example.com>",
                b"DATA",
                b"hi",
                b".",
                b"",
            ]))
            await handler.entered.wait()
            responses_before = len(transport.responses)
            # Client disconnects while the delivery hook is in flight.
            proto.connection_lost(None)
            # The hook finishes late, ignoring the cancellation.
            handler.release.set()
            await settle()
            # No belated success (or any) response to the dead connection.
            assert transport.responses[responses_before:] == []
            assert proto._handler_coroutine.done()
            assert stray_tasks() == []
        temp_event_loop.run_until_complete(main())
