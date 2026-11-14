# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""
Tests for the injectable authentication attempt budget and delay policy.

These tests drive the protocol over an in-memory transport instead of real
sockets, use a fake clock for every delay, and verify response ordering,
authenticator call counts and how abandoned attempts are settled.
"""

import asyncio
import logging
from base64 import b64encode
from contextlib import suppress
from typing import Any, List, Optional

import pytest

from aiosmtpd.auth_policy import (
    AuthOutcome,
    AuthRateLimitPolicy,
    FakeClock,
    linear_delay,
    normalize_principal,
)
from aiosmtpd.handlers import Sink
from aiosmtpd.smtp import SMTP as Server
from aiosmtpd.smtp import AuthResult


MAIL_LOG = logging.getLogger("mail.log")
B64 = lambda raw: b64encode(raw).decode()


def plain_payload(login: str, password: str) -> str:
    return B64(b"\x00" + login.encode() + b"\x00" + password.encode())


# region #### In-memory transport harness ###########################################


class FakeTransport:
    def __init__(self, protocol: asyncio.Protocol, loop: asyncio.AbstractEventLoop):
        self._protocol = protocol
        self._loop = loop
        self.written: List[bytes] = []
        self.closed = False
        self.aborted = False
        self._hard_closed = False

    def write(self, data: bytes) -> None:
        self.written.append(data)

    def writelines(self, data: Any) -> None:
        for chunk in data:
            self.write(chunk)

    def write_eof(self) -> None:
        pass

    def can_write_eof(self) -> bool:
        return False

    def close(self) -> None:
        # Mark closing without tearing the protocol down synchronously: queued
        # command lines must still be processed, mirroring a real transport
        # whose socket is shut down after the current write. Explicit teardown
        # happens in FakeServer.stop()/drop_during_challenge().
        self.closed = True

    def hard_close(self) -> None:
        if self.aborted or self._hard_closed:
            return
        self._hard_closed = True
        self.closed = True
        self._loop.call_soon(self._protocol.connection_lost, None)

    def abort(self) -> None:
        self.aborted = True
        self.hard_close()

    def is_closing(self) -> bool:
        return self.closed

    def set_protocol(self, protocol: asyncio.Protocol) -> None:
        self._protocol = protocol

    def get_protocol(self) -> asyncio.Protocol:
        return self._protocol

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        if name == "peername":
            return ("127.0.0.1", 44444)
        return default

    def drain(self) -> None:  # pragma: no cover - writer never pauses
        return None


class FakeServer:
    """Drives an SMTP protocol through an in-memory transport."""

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        handler: Any,
        policy: Optional[AuthRateLimitPolicy] = None,
        clock: Optional[FakeClock] = None,
        **kwargs: Any,
    ):
        self.loop = loop
        self.clock = clock or FakeClock()
        self.protocol = Server(
            handler,
            loop=loop,
            auth_require_tls=False,
            auth_policy=policy,
            auth_clock=self.clock,
            timeout=3600,
            **kwargs,
        )
        self.transport = FakeTransport(self.protocol, loop)
        self.protocol.connection_made(self.transport)
        self.handler_task = self.protocol._handler_coroutine

    def _protocol_parked(self) -> bool:
        """True when the protocol cannot progress without new external input."""
        task = self.handler_task
        if task is None or task.done():
            return True
        # Parked inside _apply_auth_delay waiting on the (fake) clock future.
        if getattr(self.protocol, "_auth_delay_in_progress", False):
            return True
        stack = task.get_stack()
        if not stack:
            return True
        # Parked at the main command loop waiting for the next command line.
        if stack[0].f_code.co_name == "readuntil":
            return True
        # A challenge readline() is NOT a stable stop: the AUTH method still
        # has to process that response and emit a final status.
        return False

    async def _pump(self) -> None:
        """Run event-loop turns until the protocol parks on input or a delay."""
        for _ in range(50):
            await asyncio.sleep(0)
            if self._protocol_parked():
                return

    async def send(self, data: bytes) -> List[bytes]:
        """Feed one complete command line and return the responses it produced."""
        start = len(self.responses)
        if isinstance(data, str):
            data = data.encode()
        if not data.endswith(b"\r\n"):
            data = data + b"\r\n"
        # Deliver the whole line in one data_received(), like a real TCP
        # segment; the following pump lets the protocol run until it parks on
        # the next read.
        self.protocol.data_received(data)
        await self._pump()
        return self.responses[start:]

    @property
    def responses(self) -> List[bytes]:
        return [chunk.removesuffix(b"\r\n") for chunk in self.transport.written]

    def response_text(self) -> List[str]:
        return [chunk.decode() for chunk in self.responses]

    async def drop_during_challenge(self) -> None:
        """Simulate disconnect while the protocol awaits a challenge response."""
        self.transport.hard_close()
        await self._pump()
        with suppress(asyncio.CancelledError):
            await self.handler_task

    async def stop(self) -> None:
        self.transport.hard_close()
        await self._pump()
        with suppress(asyncio.CancelledError):
            await self.handler_task


# endregion


class CountingHandler(Sink):
    def __init__(self, accept: bool = False):
        self.accept = accept
        self.authenticator_calls = 0
        self.last_login: Optional[bytes] = None

    def authenticator(self, server, session, envelope, mechanism, auth_data):
        self.authenticator_calls += 1
        login, password = auth_data
        self.last_login = login
        if self.accept:
            return AuthResult(success=True, auth_data=auth_data)
        # handled=False asks smtp_AUTH to emit the standard 535 itself.
        return AuthResult(success=False, handled=False)


class CallbackHandler(Sink):
    def __init__(self):
        self.calls = 0

    def callback(self, mechanism, login, password) -> bool:
        self.calls += 1
        return login == b"goodlogin" and password == b"goodpasswd"


@pytest.fixture
def event_loop_policy_runner():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


def run(loop: asyncio.AbstractEventLoop, coro) -> Any:
    return loop.run_until_complete(coro)


# region #### Policy unit tests #####################################################


class TestPolicyUnit:
    def test_normalize_principal_casefolds(self):
        assert normalize_principal(b"Alice@Example.COM") == "alice@example.com"
        assert normalize_principal(None) is None

    def test_fake_clock_runs_due_callbacks_only(self):
        clock = FakeClock()
        fired = []
        clock.call_later(5, lambda: fired.append(clock.time()))
        clock.advance(4)
        assert fired == []
        assert clock.pending() == 1
        clock.advance(1)
        assert fired == [5.0]

    def test_fake_clock_cancel_removes_timer(self):
        clock = FakeClock()
        handle = clock.call_later(1, lambda: None)
        handle.cancel()
        assert clock.pending() == 0
        assert clock.advance(5) == 0
        assert clock.cancelled == 1

    def test_outcomes_are_classified(self):
        clock = FakeClock()
        policy = AuthRateLimitPolicy(connection_limit=10, clock=clock)
        policy.register(1, AuthOutcome.SUCCESS, "PLAIN", b"alice")
        policy.register(1, AuthOutcome.CREDENTIAL_FAILURE, "PLAIN", b"alice")
        policy.register(1, AuthOutcome.MALFORMED, "LOGIN", None)
        policy.register(1, AuthOutcome.CANCELLED, "LOGIN", None)
        outcomes = [attempt.outcome for attempt in policy.attempts]
        assert outcomes == [
            AuthOutcome.SUCCESS,
            AuthOutcome.CREDENTIAL_FAILURE,
            AuthOutcome.MALFORMED,
            AuthOutcome.CANCELLED,
        ]
        # Success does not consume the budget.
        assert policy.connection_failures(1) == 3
        # No secret material is retained on the records.
        assert all("password" not in repr(a) for a in policy.attempts)

    def test_principal_budget_accumulates_separately(self):
        clock = FakeClock()
        policy = AuthRateLimitPolicy(
            connection_limit=10, principal_limit=2, clock=clock
        )
        policy.register(1, AuthOutcome.CREDENTIAL_FAILURE, "PLAIN", b"Alice")
        second = policy.register(
            1, AuthOutcome.CREDENTIAL_FAILURE, "LOGIN", b"alice"
        )
        # Case-insensitive identity maps onto the same principal bucket.
        assert second.principal == "alice"
        assert policy.principal_failures("alice") == 2
        assert policy.principal_exhausted(second)
        # A different identity still has budget.
        other = policy.register(
            1, AuthOutcome.CREDENTIAL_FAILURE, "PLAIN", b"bob"
        )
        assert not policy.principal_exhausted(other)

    def test_cancelled_and_abandoned_not_charged_to_principal(self):
        clock = FakeClock()
        policy = AuthRateLimitPolicy(
            connection_limit=10, principal_limit=2, clock=clock
        )
        policy.register(1, AuthOutcome.CANCELLED, "LOGIN", b"alice")
        policy.register(1, AuthOutcome.ABANDONED, "LOGIN", b"alice")
        assert policy.principal_failures("alice") == 0
        assert policy.connection_failures(1) == 2

    def test_linear_delay_uses_fake_clock_time(self):
        clock = FakeClock()
        policy = AuthRateLimitPolicy(
            connection_limit=10,
            clock=clock,
            delay_policy=linear_delay(2.0, maximum=5.0),
        )
        first = policy.register(
            1, AuthOutcome.CREDENTIAL_FAILURE, "PLAIN", b"alice"
        )
        second = policy.register(
            1, AuthOutcome.CREDENTIAL_FAILURE, "PLAIN", b"alice"
        )
        third = policy.register(
            1, AuthOutcome.CREDENTIAL_FAILURE, "PLAIN", b"alice"
        )
        success = policy.register(1, AuthOutcome.SUCCESS, "PLAIN", b"alice")
        assert first.delay == 2.0
        assert second.delay == 4.0
        assert third.delay == 5.0  # capped
        assert success.delay == 0.0

    def test_forget_connection_keeps_principal_history(self):
        clock = FakeClock()
        policy = AuthRateLimitPolicy(
            connection_limit=2, principal_limit=5, clock=clock
        )
        policy.register(1, AuthOutcome.CREDENTIAL_FAILURE, "PLAIN", b"alice")
        policy.forget_connection(1)
        assert policy.connection_failures(1) == 0
        assert policy.principal_failures("alice") == 1


# endregion


# region #### Protocol integration (in-memory) ######################################


class TestAuthProtocol:
    def test_success_and_failure_classification(self, event_loop_policy_runner):
        loop = event_loop_policy_runner
        clock = FakeClock()
        policy = AuthRateLimitPolicy(connection_limit=10, clock=clock)
        handler = CallbackHandler()
        server = FakeServer(
            loop, handler, policy, clock, authenticator=None,
            auth_callback=handler.callback,
        )

        async def scenario():
            await server.send(b"EHLO example.com")
            await server.send(
                "AUTH PLAIN " + plain_payload("goodlogin", "goodpasswd")
            )
            assert server.responses[-1].startswith(b"235")
            # A second connection on the same policy records the failure.
            other = FakeServer(
                loop, handler, policy, clock, auth_callback=handler.callback
            )
            await other.send(b"EHLO example.com")
            await other.send(
                "AUTH PLAIN " + plain_payload("badlogin", "goodpasswd")
            )
            return other

        other = run(loop, scenario())
        try:
            assert any(r.startswith("235") for r in server.response_text())
            assert any(r.startswith("535") for r in other.response_text())
            outcomes = [a.outcome for a in policy.attempts]
            assert outcomes == [AuthOutcome.SUCCESS, AuthOutcome.CREDENTIAL_FAILURE]
            assert handler.calls == 2
            assert server.protocol._auth_attempts == 1
            assert other.protocol._auth_attempts == 1
        finally:
            run(loop, server.stop())
            run(loop, other.stop())

    def test_login_round_trip_is_one_attempt_and_one_authenticator_call(
        self, event_loop_policy_runner
    ):
        loop = event_loop_policy_runner
        clock = FakeClock()
        policy = AuthRateLimitPolicy(connection_limit=10, clock=clock)
        handler = CountingHandler(accept=True)

        async def scenario():
            server = FakeServer(
                loop, handler, policy, clock, authenticator=handler.authenticator
            )
            await server.send(b"EHLO example.com")
            await server.send(b"AUTH LOGIN")
            assert server.responses[-1] == b"334 " + B64(b"User Name\x00").encode()
            await server.send(B64(b"goodlogin"))
            assert server.responses[-1] == b"334 " + B64(b"Password\x00").encode()
            await server.send(B64(b"goodpasswd"))
            await server.stop()
            return server

        server = run(loop, scenario())
        attempt = policy.attempts[0]
        assert attempt.outcome is AuthOutcome.SUCCESS
        assert attempt.mechanism == "LOGIN"
        assert attempt.principal == "goodlogin"
        assert handler.authenticator_calls == 1
        assert server.protocol._auth_attempts == 1

    def test_cancel_distinct_from_credentials_and_malformed(
        self, event_loop_policy_runner
    ):
        loop = event_loop_policy_runner
        clock = FakeClock()
        policy = AuthRateLimitPolicy(connection_limit=10, clock=clock)
        handler = CountingHandler(accept=False)
        server = FakeServer(
            loop, handler, policy, clock, authenticator=handler.authenticator
        )

        async def scenario():
            await server.send(b"EHLO example.com")
            # Client abort during the username challenge.
            await server.send(b"AUTH LOGIN")
            await server.send(b"*")
            assert server.responses[-1] == b"501 5.7.0 Auth aborted"
            # Illegal base64 in an initial response.
            produced = await server.send("AUTH PLAIN ab@%")
            assert produced == [b"501 5.5.2 Can't decode base64"]
            # Genuine credential rejection still reaches the authenticator.
            produced = await server.send(
                "AUTH PLAIN " + plain_payload("badlogin", "badpasswd")
            )
            assert produced == [b"535 5.7.8 Authentication credentials invalid"]

        run(loop, scenario())
        try:
            assert [a.outcome for a in policy.attempts] == [
                AuthOutcome.CANCELLED,
                AuthOutcome.MALFORMED,
                AuthOutcome.CREDENTIAL_FAILURE,
            ]
            # Only the well-formed attempt invoked the authenticator.
            assert handler.authenticator_calls == 1
        finally:
            run(loop, server.stop())

    def test_rset_ehlo_and_mechanism_switch_keep_failures(
        self, event_loop_policy_runner
    ):
        loop = event_loop_policy_runner
        clock = FakeClock()
        policy = AuthRateLimitPolicy(connection_limit=3, clock=clock)
        handler = CountingHandler(accept=False)
        server = FakeServer(
            loop, handler, policy, clock, authenticator=handler.authenticator
        )

        async def scenario():
            await server.send(b"EHLO example.com")
            await server.send(
                "AUTH PLAIN " + plain_payload("u1", "pw")
            )
            await server.send(b"RSET")
            await server.send(b"EHLO example.com")
            await server.send(
                "AUTH LOGIN " + B64(b"u2")
            )
            await server.send(B64(b"pw"))
            assert policy.connection_failures(
                server.protocol._auth_connection_id
            ) == 2
            mechanisms = {a.mechanism for a in policy.attempts}
            assert mechanisms == {"PLAIN", "LOGIN"}
            # The budget allows three attempts; the third is still processed.
            produced = await server.send(
                "AUTH PLAIN " + plain_payload("u3", "pw")
            )
            assert produced[-1] == b"535 5.7.8 Authentication credentials invalid"
            assert policy.connection_failures(
                server.protocol._auth_connection_id
            ) == 3
            # The fourth attempt is refused up front by the budget gate.
            produced = await server.send(
                "AUTH PLAIN " + plain_payload("u4", "pw")
            )
            assert produced[-1].decode().startswith("421")
            assert server.transport.is_closing()
            # The authenticator is never called once the budget is exhausted.
            assert handler.authenticator_calls == 3

        run(loop, scenario())
        run(loop, server.stop())

    def test_connection_limit_closes_and_blocks_further_attempts(
        self, event_loop_policy_runner
    ):
        loop = event_loop_policy_runner
        clock = FakeClock()
        policy = AuthRateLimitPolicy(connection_limit=2, clock=clock)
        handler = CountingHandler(accept=False)
        server = FakeServer(
            loop, handler, policy, clock, authenticator=handler.authenticator
        )

        async def scenario():
            await server.send(b"EHLO example.com")
            for idx in range(2):
                await server.send(
                    "AUTH PLAIN " + plain_payload(f"user{idx}", "pw")
                )

        run(loop, scenario())
        assert len(policy.attempts) == 2
        exhausted = run(
            loop,
            server.send("AUTH PLAIN " + plain_payload("user2", "pw")),
        )
        assert exhausted[-1].startswith(b"421")
        try:
            assert server.response_text()[-1].startswith("421")
            assert server.transport.is_closing()
            assert handler.authenticator_calls == 2
        finally:
            run(loop, server.stop())

    def test_principal_limit_closes_connection(self, event_loop_policy_runner):
        loop = event_loop_policy_runner
        clock = FakeClock()
        policy = AuthRateLimitPolicy(
            connection_limit=10, principal_limit=2, clock=clock
        )
        handler = CountingHandler(accept=False)
        server = FakeServer(
            loop, handler, policy, clock, authenticator=handler.authenticator
        )

        async def scenario():
            await server.send(b"EHLO example.com")
            await server.send("AUTH PLAIN " + plain_payload("alice", "pw"))
            await server.send("AUTH PLAIN " + plain_payload("ALICE", "pw"))

        run(loop, scenario())
        try:
            assert server.transport.is_closing()
            assert policy.principal_failures("alice") == 2
            assert server.response_text()[-1].startswith("421")
        finally:
            run(loop, server.stop())

    def test_abandoned_challenge_is_settled_once(self, event_loop_policy_runner):
        loop = event_loop_policy_runner
        clock = FakeClock()
        policy = AuthRateLimitPolicy(connection_limit=10, clock=clock)
        handler = CountingHandler(accept=True)
        server = FakeServer(
            loop, handler, policy, clock, authenticator=handler.authenticator
        )

        async def scenario():
            await server.send(b"EHLO example.com")
            await server.send(b"AUTH LOGIN")
            # Disconnect before answering the username challenge.
            await server.drop_during_challenge()

        run(loop, scenario())
        try:
            assert len(policy.attempts) == 1
            attempt = policy.attempts[0]
            assert attempt.outcome is AuthOutcome.ABANDONED
            assert handler.authenticator_calls == 0
            # The pending slot is released; a second settlement is a no-op.
            server.protocol._settle_pending_auth()
            assert len(policy.attempts) == 1
            assert server.protocol._auth_exchange is None
        finally:
            run(loop, server.stop())

    def test_disconnect_during_delay_cancels_timer_and_settles(
        self, event_loop_policy_runner
    ):
        loop = event_loop_policy_runner
        clock = FakeClock()
        policy = AuthRateLimitPolicy(
            connection_limit=10,
            clock=clock,
            delay_policy=linear_delay(1000.0),
        )
        handler = CountingHandler(accept=False)
        server = FakeServer(
            loop, handler, policy, clock, authenticator=handler.authenticator
        )

        async def scenario():
            await server.send(b"EHLO example.com")
            await server.send(
                "AUTH PLAIN " + plain_payload("alice", "pw")
            )
            # The failure is already recorded; the protocol is parked on delay.
            assert server.protocol._auth_delay_in_progress
            assert clock.pending() == 1
            await server.drop_during_challenge()

        run(loop, scenario())
        try:
            # The delay timer is cancelled and the attempt is not double booked.
            assert clock.pending() == 0
            assert len(policy.attempts) == 1
            assert policy.attempts[0].outcome is AuthOutcome.CREDENTIAL_FAILURE
            assert server.protocol._auth_exchange is None
        finally:
            run(loop, server.stop())

    def test_no_secret_in_logs_or_records(self, caplog, event_loop_policy_runner):
        loop = event_loop_policy_runner
        caplog.set_level(logging.DEBUG, logger="mail.log")
        clock = FakeClock()
        policy = AuthRateLimitPolicy(connection_limit=10, clock=clock)
        handler = CallbackHandler()
        server = FakeServer(
            loop, handler, policy, clock, auth_callback=handler.callback
        )
        secret = "super-secret-password"

        async def scenario():
            await server.send(b"EHLO example.com")
            await server.send(
                "AUTH PLAIN " + plain_payload("goodlogin", secret)
            )

        run(loop, scenario())
        try:
            for record in caplog.record_tuples:
                assert secret not in record[-1]
                assert B64(secret.encode()) not in record[-1]
            assert all(secret not in repr(a) for a in policy.attempts)
            assert all(secret not in str(a) for a in policy.attempts)
        finally:
            run(loop, server.stop())


# endregion


# region #### Concurrency: two interleaved connections ##############################


class TestInterleavedConnections:
    def test_limited_connection_does_not_block_legitimate_one(
        self, event_loop_policy_runner
    ):
        loop = event_loop_policy_runner
        clock = FakeClock()
        # Per-connection policy: the attacker's limit does not affect the
        # legitimate connection's budget.
        attacker_policy = AuthRateLimitPolicy(
            connection_limit=2,
            clock=clock,
            delay_policy=linear_delay(1000.0),
        )
        victim_policy = AuthRateLimitPolicy(connection_limit=5, clock=clock)
        bad_handler = CountingHandler(accept=False)
        good_handler = CountingHandler(accept=True)
        bad = FakeServer(loop, bad_handler, attacker_policy, clock,
                         authenticator=bad_handler.authenticator)
        good = FakeServer(loop, good_handler, victim_policy, clock,
                          authenticator=good_handler.authenticator)
        order: List[str] = []

        async def attacker_first_failure():
            await bad.send(b"EHLO example.com")
            produced = await bad.send(
                "AUTH PLAIN " + plain_payload("attacker0", "pw")
            )
            order.append(f"attacker:{produced[-1].decode()[:3]}")

        async def victim_login():
            await good.send(b"EHLO example.com")
            produced = await good.send(
                "AUTH PLAIN " + plain_payload("goodlogin", "goodpasswd")
            )
            order.append(f"victim:{produced[-1].decode()[:3]}")

        async def scenario():
            # 1. The attacker burns its first attempt; a delay is now scheduled.
            await attacker_first_failure()
            assert clock.pending() == 1
            assert bad._protocol_parked()

            # 2. While the attacker is parked on its clock-driven delay, the
            #    legitimate connection completes a full login on the same loop.
            victim_task = asyncio.create_task(victim_login())
            await victim_task
            assert good.responses[-1] == b"235 2.7.0 Authentication successful"
            order.append("victim-done")
            # The attacker's delay timer is still pending; nothing advanced it.
            assert clock.pending() == 1

            # 3. Release the attacker's delay, then exhaust its connection budget.
            clock.advance(10_000)
            assert clock.pending() == 0
            produced = await bad.send(
                "AUTH PLAIN " + plain_payload("attacker1", "pw")
            )
            order.append(f"attacker:{produced[-1].decode()[:3]}")
            clock.advance(10_000)
            produced = await bad.send(
                "AUTH PLAIN " + plain_payload("attacker2", "pw")
            )
            order.append(f"attacker:{produced[-1].decode()[:3]}")

        run(loop, scenario())
        try:
            assert good_handler.authenticator_calls == 1
            assert bad_handler.authenticator_calls == 2
            # Response ordering: victim finishes while attacker is still delayed.
            assert order.index("victim:235") < order.index("victim-done")
            assert order.index("victim-done") < order.index("attacker:421")
            assert bad.response_text()[-1].startswith("421")
            assert bad.transport.is_closing()
            assert not good.transport.is_closing()
            assert clock.pending() == 0
        finally:
            run(loop, bad.stop())
            run(loop, good.stop())

    def test_independent_connections_have_independent_connection_budgets(
        self, event_loop_policy_runner
    ):
        loop = event_loop_policy_runner
        clock = FakeClock()

        def make_policy():
            return AuthRateLimitPolicy(connection_limit=1, clock=clock)

        first_handler = CountingHandler(accept=False)
        second_handler = CountingHandler(accept=True)
        first = FakeServer(
            loop, first_handler, make_policy(), clock,
            authenticator=first_handler.authenticator,
        )
        second = FakeServer(
            loop, second_handler, make_policy(), clock,
            authenticator=second_handler.authenticator,
        )

        async def scenario():
            await first.send(b"EHLO example.com")
            await first.send("AUTH PLAIN " + plain_payload("x", "pw"))
            await second.send(b"EHLO example.com")
            await second.send(
                "AUTH PLAIN " + plain_payload("goodlogin", "goodpasswd")
            )

        run(loop, scenario())
        try:
            # The first connection's next attempt is refused by its own policy.
            produced = run(
                loop,
                first.send("AUTH PLAIN " + plain_payload("x", "pw")),
            )
            assert produced[-1].startswith(b"421")
            assert first.transport.is_closing()
            assert not second.transport.is_closing()
            assert second.responses[-1] == b"235 2.7.0 Authentication successful"
        finally:
            run(loop, first.stop())
            run(loop, second.stop())


# endregion
