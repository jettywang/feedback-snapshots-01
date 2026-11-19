"""
Total deadline support.

A deadline is an overall, monotonic time budget for a request exchange.
It spans the initial request send, any authentication interactions and
redirect hops, and -- when the caller opts in via non-streaming requests or
an explicit extension -- consumption of the response body.

Per-operation connect/read/write/pool timeouts are always intersected with
the remaining deadline budget before every network operation, so the
deadline can neither be reset by an individual hop nor extended by it.
"""

from __future__ import annotations

import time
import typing

from ._exceptions import TotalDeadlineExceeded
from ._types import AsyncByteStream, SyncByteStream

__all__ = ["Deadline", "DeadlineAsyncStream", "DeadlineSyncStream"]

# Name of the request extension carrying the overall deadline, in seconds
# measured against the monotonic clock.
DEADLINE_EXTENSION = "deadline"

# Name of an optional request extension overriding the clock used to evaluate
# the deadline. Intended for deterministic testing; not part of the public API.
CLOCK_EXTENSION = "deadline_clock"


def _minimum(left: float | None, right: float | None) -> float | None:
    if left is None:
        return right
    if right is None:
        return left
    return min(left, right)


class Deadline:
    """
    A monotonic total deadline shared across every hop of a request exchange.

    The deadline is created once per top-level `send()` and never restarts:
    authentication retries and redirects observe the same absolute cutoff.
    """

    def __init__(
        self,
        budget: float | None,
        *,
        clock: typing.Callable[[], float] = time.monotonic,
    ) -> None:
        self._clock = clock
        self._expires_at: float | None = (
            None if budget is None else clock() + budget
        )

    @property
    def enabled(self) -> bool:
        return self._expires_at is not None

    def remaining(self) -> float | None:
        if self._expires_at is None:
            return None
        return self._expires_at - self._clock()

    def raise_if_expired(self, request: typing.Any = None) -> None:
        remaining = self.remaining()
        if remaining is not None and remaining <= 0:
            raise TotalDeadlineExceeded(
                "The total deadline for the request exchange was exceeded.",
                request=request,
            )

    def effective_timeouts(
        self, base_timeouts: dict[str, float | None]
    ) -> dict[str, float | None]:
        """
        Return the per-operation timeouts intersected with the remaining
        deadline budget. When no deadline is configured, the original
        per-operation timeouts are returned unchanged.

        The deadline's own configuration key is excluded, since it is not a
        per-operation timeout and must never be shortened by the mechanism.
        """
        operation_timeouts = {
            key: value
            for key, value in base_timeouts.items()
            if key != DEADLINE_EXTENSION
        }
        remaining = self.remaining()
        if remaining is None:
            return dict(operation_timeouts)
        if remaining <= 0:
            return {key: 0.0 for key in operation_timeouts}
        return {
            key: _minimum(value, remaining)
            for key, value in operation_timeouts.items()
        }


class DeadlineSyncStream(SyncByteStream):
    """
    Wraps a synchronous response stream so that reading the body is also
    bounded by the total deadline. If the deadline expires while the body is
    being consumed, the underlying stream is closed before the exception
    propagates.
    """

    def __init__(self, stream: SyncByteStream, deadline: Deadline) -> None:
        self._stream = stream
        self._deadline = deadline

    def __iter__(self) -> typing.Iterator[bytes]:
        self._deadline.raise_if_expired()
        try:
            for chunk in self._stream:
                self._deadline.raise_if_expired()
                yield chunk
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        self._stream.close()


class DeadlineAsyncStream(AsyncByteStream):
    """
    Async counterpart of `DeadlineSyncStream`.
    """

    def __init__(self, stream: AsyncByteStream, deadline: Deadline) -> None:
        self._stream = stream
        self._deadline = deadline

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        self._deadline.raise_if_expired()
        try:
            async for chunk in self._stream:
                self._deadline.raise_if_expired()
                yield chunk
        except BaseException:
            await self.aclose()
            raise

    async def aclose(self) -> None:
        await self._stream.aclose()
