# Copyright 2014-2021 The aiosmtpd Developers
# SPDX-License-Identifier: Apache-2.0

"""
Pluggable authentication attempt budgeting and delay policies.

The policy implemented here limits how often a client (and, optionally, a
normalized authentication identity) can *attempt* authentication, regardless of
which AUTH mechanism is used or at which stage of a challenge/response exchange
the attempt ends.  Delays are scheduled on the event loop through an injectable
clock instead of blocking it, and none of the bookkeeping objects ever retain
submitted secrets.
"""

import enum
import functools
import heapq
import itertools
from dataclasses import dataclass
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    List,
    Optional,
    Protocol,
    Tuple,
)

from public import public


# region #### Clock ###################################################################


class TimerHandle(Protocol):
    def cancel(self) -> None:
        ...


class Clock(Protocol):
    """Abstracts the time source and delayed scheduling used by the policy."""

    def time(self) -> float:
        ...

    def call_later(
        self, delay: float, callback: Callable[..., Any], *args: Any
    ) -> TimerHandle:
        ...


@public
class LoopClock:
    """Clock adapter backed by a running :class:`asyncio.AbstractEventLoop`."""

    def __init__(self, loop: Any):
        self._loop = loop

    def time(self) -> float:
        return self._loop.time()

    def call_later(
        self, delay: float, callback: Callable[..., Any], *args: Any
    ) -> TimerHandle:
        return self._loop.call_later(delay, callback, *args)


@public
class FakeClock:
    """
    Deterministic clock for tests. Time only moves when :meth:`advance` is
    called, and due callbacks run there instead of on a wall clock.
    """

    def __init__(self, start: float = 0.0):
        self._now = float(start)
        self._counter = itertools.count()
        self._scheduled: List[Tuple[float, int, Callable[[], Any]]] = []
        self.cancelled: int = 0

    def time(self) -> float:
        return self._now

    def call_later(
        self, delay: float, callback: Callable[..., Any], *args: Any
    ) -> "FakeTimer":
        scheduled = functools.partial(callback, *args)
        timer = FakeTimer(
            self, (self._now + delay, next(self._counter), scheduled)
        )
        heapq.heappush(self._scheduled, timer._entry)
        return timer

    def advance(self, seconds: float) -> int:
        """Move the clock forward, running every callback that becomes due."""
        if seconds < 0:
            raise ValueError("FakeClock cannot move backwards")
        self._now += seconds
        fired = 0
        while self._scheduled and self._scheduled[0][0] <= self._now:
            _when, _seq, callback = heapq.heappop(self._scheduled)
            callback()
            fired += 1
        return fired

    def pending(self) -> int:
        return len(self._scheduled)

    def _discard(self, entry: Tuple[float, int, Callable[[], Any]]) -> None:
        self.cancelled += 1
        try:
            self._scheduled.remove(entry)
        except ValueError:
            return
        heapq.heapify(self._scheduled)


class FakeTimer:
    def __init__(self, clock: FakeClock, entry: Tuple[float, int, Callable[[], Any]]):
        self._clock = clock
        self._entry = entry
        self._cancelled = False

    def cancel(self) -> None:
        if self._cancelled:
            return
        self._cancelled = True
        self._clock._discard(self._entry)


# endregion


# region #### Attempt classification #################################################


@public
class AuthOutcome(enum.Enum):
    """How a single AUTH attempt ended."""

    SUCCESS = "success"
    """The authenticator accepted the credentials."""

    CREDENTIAL_FAILURE = "credential_failure"
    """The exchange completed but the authenticator rejected the credentials."""

    MALFORMED = "malformed"
    """Client sent illegal encoding or a value that cannot be parsed."""

    CANCELLED = "cancelled"
    """Client aborted the exchange with '*' per RFC 4954."""

    ABANDONED = "abandoned"
    """The connection dropped or was reset before the exchange completed."""


_DEFAULT_COUNTED: FrozenSet[AuthOutcome] = frozenset(
    {
        AuthOutcome.CREDENTIAL_FAILURE,
        AuthOutcome.MALFORMED,
        AuthOutcome.CANCELLED,
        AuthOutcome.ABANDONED,
    }
)
_DEFAULT_PRINCIPAL_COUNTED: FrozenSet[AuthOutcome] = frozenset(
    {
        AuthOutcome.CREDENTIAL_FAILURE,
        AuthOutcome.MALFORMED,
    }
)


@public
@dataclass(frozen=True)
class AuthAttempt:
    """
    Record of one finished AUTH attempt. It deliberately stores no secret
    material; ``principal`` is the normalized identity (or ``None`` when the
    client never supplied a usable one).
    """

    outcome: AuthOutcome
    mechanism: str
    principal: Optional[str]
    at: float
    connection: int
    response: Optional[str] = None
    delay: float = 0.0

    @property
    def counted(self) -> bool:
        return self.outcome is not AuthOutcome.SUCCESS


@public
@dataclass
class AuthDecision:
    """Result of an authorization check before an attempt starts."""

    allowed: bool
    reason: Optional[str] = None
    response: Optional[str] = None


# endregion


# region #### Principal normalization ################################################


PrincipalNormalizer = Callable[[Optional[bytes]], Optional[str]]


@public
def normalize_principal(login: Optional[bytes]) -> Optional[str]:
    """
    Default identity normalization: decode leniently and case-fold so that
    attempts against the same identity accumulate together. Returns ``None``
    when no login was presented.
    """
    if login is None:
        return None
    return login.decode("utf-8", "surrogateescape").casefold()


# endregion


# region #### Rate limit policy ######################################################


DelayPolicy = Callable[[AuthOutcome, int, Optional[str]], float]


@public
def no_delay(outcome: AuthOutcome, failures: int, principal: Optional[str]) -> float:
    return 0.0


@public
def linear_delay(step: float, maximum: Optional[float] = None) -> DelayPolicy:
    """Delay grows linearly with the number of failed attempts."""

    def policy(outcome: AuthOutcome, failures: int, principal: Optional[str]) -> float:
        if outcome is AuthOutcome.SUCCESS:
            return 0.0
        delay = step * failures
        if maximum is not None and delay > maximum:
            return maximum
        return delay

    return policy


@public
class AuthRateLimitPolicy:
    """
    Injectable budget and delay policy.

    Budgets are tracked per connection and, when a normalized principal can be
    determined, per principal. RSET, re-EHLO and mechanism switches never clear
    the counters because the policy object outlives individual commands.
    """

    def __init__(
        self,
        *,
        connection_limit: Optional[int] = 5,
        principal_limit: Optional[int] = None,
        clock: Optional[Clock] = None,
        delay_policy: Optional[DelayPolicy] = None,
        count_outcomes: FrozenSet[AuthOutcome] = _DEFAULT_COUNTED,
        principal_count_outcomes: FrozenSet[AuthOutcome] = _DEFAULT_PRINCIPAL_COUNTED,
        principal_normalizer: PrincipalNormalizer = normalize_principal,
        limit_response: str = "421 4.7.0 Too many authentication attempts",
    ):
        self._connection_limit = connection_limit
        self._principal_limit = principal_limit
        self._clock = clock
        self._delay_policy = delay_policy or no_delay
        self._count_outcomes = frozenset(count_outcomes)
        self._principal_count_outcomes = frozenset(principal_count_outcomes)
        self._normalize = principal_normalizer
        self.limit_response = limit_response
        self._connection_failures: Dict[int, int] = {}
        self._principal_failures: Dict[str, int] = {}
        self.attempts: List[AuthAttempt] = []

    @property
    def clock(self) -> Optional[Clock]:
        return self._clock

    def bind_clock(self, clock: Clock) -> None:
        """Attach the loop-backed clock when no explicit clock was given."""
        if self._clock is None:
            self._clock = clock

    def normalize(self, login: Optional[bytes]) -> Optional[str]:
        return self._normalize(login)

    def _now(self) -> float:
        return self._clock.time() if self._clock is not None else 0.0

    def connection_failures(self, connection: int) -> int:
        return self._connection_failures.get(connection, 0)

    def principal_failures(self, principal: str) -> int:
        return self._principal_failures.get(principal, 0)

    def check(self, connection: int) -> AuthDecision:
        """Gate the start of a new AUTH attempt on this connection."""
        if self._connection_limit is None:
            return AuthDecision(allowed=True)
        failures = self._connection_failures.get(connection, 0)
        if failures >= self._connection_limit:
            return AuthDecision(
                allowed=False,
                reason="connection_limit",
                response=self.limit_response,
            )
        return AuthDecision(allowed=True)

    def register(
        self,
        connection: int,
        outcome: AuthOutcome,
        mechanism: str,
        login: Optional[bytes] = None,
        response: Optional[str] = None,
    ) -> AuthAttempt:
        """Settle a finished attempt and return its recorded entry."""
        principal = self._normalize(login)
        connection_failures = self._connection_failures.get(connection, 0)
        if outcome in self._count_outcomes:
            connection_failures += 1
            self._connection_failures[connection] = connection_failures
        principal_failures = 0
        if principal is not None and outcome in self._principal_count_outcomes:
            principal_failures = self._principal_failures.get(principal, 0) + 1
            self._principal_failures[principal] = principal_failures
        delay = self._delay_policy(outcome, connection_failures, principal)
        attempt = AuthAttempt(
            outcome=outcome,
            mechanism=mechanism,
            principal=principal,
            at=self._now(),
            connection=connection,
            response=response,
            delay=delay,
        )
        self.attempts.append(attempt)
        return attempt

    def principal_exhausted(self, attempt: AuthAttempt) -> bool:
        if (
            self._principal_limit is None
            or attempt.principal is None
            or attempt.outcome not in self._principal_count_outcomes
        ):
            return False
        return (
            self._principal_failures.get(attempt.principal, 0) >= self._principal_limit
        )

    def forget_connection(self, connection: int) -> None:
        """Drop per-connection counters; principal counters intentionally stay."""
        self._connection_failures.pop(connection, None)

    def reset(self) -> None:
        self._connection_failures.clear()
        self._principal_failures.clear()
        self.attempts.clear()


# endregion
