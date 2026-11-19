"""Revocable streaming of sensitive data with ``web.StreamResponse``.

This example shows how to stream long-running, sensitive responses under a
caller-controlled, explicit authorization state (:class:`AuthorizationGrant`)
that can be revoked at any moment -- locally, without any online auth
service.

Guarantee boundaries
--------------------
Revocation can only ever stop data that has NOT been written yet:

1. **Revoked before ``prepare()``** -- nothing is sent. The handler answers
   ``403`` and the producer is never started, so no sensitive chunk is even
   pulled. Revocation is total.
2. **Revoked while bytes sit in local buffers** -- chunks already passed to
   ``StreamResponse.write()`` were accepted by the asyncio transport and
   typically copied into kernel buffers. ``await write()`` returning means
   "accepted by the transport", NEVER "received by the peer" -- but for
   revocation purposes those bytes must be treated as exposed. Only chunks
   not yet written can still be blocked.
3. **Revoked after bytes were committed to the wire** -- they cannot be
   recalled. Revocation still stops every future pull and write.

What :func:`pump_sensitive` guarantees once the grant is revoked:

* no further chunk is pulled from the producer (an in-flight pull is
  cancelled, so the producer is not asked for more sensitive data);
* no further chunk is written;
* the producer is always closed (``aclose()``) -- on revocation, producer
  error, task cancellation, and clean completion alike -- so the resource
  behind it (DB cursor, file handle, ...) is released in every case.

What the client observes on mid-stream revocation: a truncated stream. The
handler aborts without ``write_eof()``, so aiohttp closes the connection
without the terminating chunk and the peer fails loudly instead of
mistaking a partial body for a complete one.

Run ``python examples/revocable_stream.py`` for a demo that drives the same
pump against a pausable in-memory transport and revokes at each boundary,
recording exactly how many bytes entered the transport and how many times
the producer was called.
"""

import asyncio
import contextlib
from collections.abc import AsyncGenerator, Awaitable, Callable, Sequence
from typing import Any, Protocol, TypeVar

from aiohttp import web

__all__ = (
    "AuthorizationGrant",
    "AuthorizationRevoked",
    "MemoryTransport",
    "SensitiveRecordProducer",
    "build_app",
    "pump_sensitive",
    "run_demo",
    "stream_sensitive",
)

_T = TypeVar("_T")


class AuthorizationRevoked(Exception):
    """The grant was revoked; streaming must stop immediately."""


class AuthorizationGrant:
    """Explicit, caller-controlled authorization state.

    The streaming loop checks this object before every pull and every
    write. Revocation is a one-way latch: once revoked, never authorized
    again. Whoever owns the grant (an admin endpoint, a watchdog, a
    signal handler, ...) decides when to call :meth:`revoke`.
    """

    def __init__(self) -> None:
        self._revoked = False
        self._revoked_event = asyncio.Event()

    @property
    def authorized(self) -> bool:
        return not self._revoked

    def revoke(self) -> None:
        if not self._revoked:
            self._revoked = True
            self._revoked_event.set()

    def raise_if_revoked(self) -> None:
        if self._revoked:
            raise AuthorizationRevoked("authorization has been revoked")

    async def wait_revoked(self) -> None:
        await self._revoked_event.wait()


class _ChunkWriter(Protocol):
    async def write(self, data: bytes) -> None: ...


async def _race_with_revocation(
    operation: Awaitable[_T], grant: AuthorizationGrant
) -> _T:
    """Await *operation*, abandoning the wait if the grant is revoked first.

    Used for both producer pulls and writes so that a revoke landing while
    the transport applies backpressure (or the producer is slow) still
    stops the stream promptly. Cancelling the wait on a write does NOT
    unsend bytes the transport already accepted -- those are exposed.
    """
    op_task = asyncio.ensure_future(operation)
    revoke_task = asyncio.ensure_future(grant.wait_revoked())
    try:
        done, _pending = await asyncio.wait(
            (op_task, revoke_task), return_when=asyncio.FIRST_COMPLETED
        )
        if revoke_task in done and op_task not in done:
            raise AuthorizationRevoked("authorization revoked while waiting")
        return op_task.result()
    finally:
        for task in (op_task, revoke_task):
            task.cancel()
        await asyncio.gather(op_task, revoke_task, return_exceptions=True)


async def pump_sensitive(
    writer: _ChunkWriter,
    producer: AsyncGenerator[bytes, None],
    grant: AuthorizationGrant,
) -> None:
    """Pull chunks from *producer* and write them while *grant* allows.

    Raises :class:`AuthorizationRevoked` once the grant is revoked;
    re-raises producer errors and cancellation. The producer is closed in
    every case, releasing the resource behind it.
    """
    try:
        while True:
            grant.raise_if_revoked()
            try:
                chunk = await _race_with_revocation(anext(producer), grant)
            except StopAsyncIteration:
                return
            # A pull that was already in flight may complete after
            # revocation; its chunk is discarded, never written.
            grant.raise_if_revoked()
            await _race_with_revocation(writer.write(chunk), grant)
    finally:
        await producer.aclose()


async def stream_sensitive(
    request: web.Request,
    producer: AsyncGenerator[bytes, None],
    grant: AuthorizationGrant,
    *,
    headers: dict[str, str] | None = None,
) -> web.StreamResponse:
    """Stream *producer*'s sensitive chunks under *grant* (embeddable handler).

    * revoked before ``prepare()`` -> ``403``, zero body bytes leave;
    * revoked mid-stream -> the connection is aborted without
      ``write_eof()`` so the client sees a truncated stream (fail-closed);
    * peer disconnect (``ConnectionResetError``) and cancellation both stop
      the pump and release the producer.
    """
    if not grant.authorized:
        await producer.aclose()
        raise web.HTTPForbidden(text="authorization revoked before streaming")
    resp = web.StreamResponse(
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            **(headers or {}),
        }
    )
    await resp.prepare(request)
    try:
        await pump_sensitive(resp, producer, grant)
    except AuthorizationRevoked:
        # Fail closed: re-raise so aiohttp aborts the connection instead of
        # sending a clean-looking terminating chunk for a partial body.
        raise
    except ConnectionResetError:
        pass  # The peer went away; nothing left to send or to protect.
    else:
        await resp.write_eof()
    return resp


class SensitiveRecordProducer:
    """Stands in for a cursor over a sensitive data source.

    ``pull_count`` records how many chunks were actually pulled;
    ``released`` flips to True exactly once, when the underlying resource
    would be released (cursor closed, file handle freed) -- on completion,
    revocation, producer error, or cancellation alike.
    """

    def __init__(self, records: Sequence[bytes]) -> None:
        self.records = records
        self.pull_count = 0
        self.released = False
        # Test/demo hooks: block before yielding record ``gate_before``
        # until ``gate`` is set, or fail at record ``fail_at``.
        self.gate: asyncio.Event | None = None
        self.gate_before: int | None = None
        self.waiting_at_gate = False
        self.fail_at: int | None = None

    async def stream(self) -> AsyncGenerator[bytes, None]:
        try:
            for index, record in enumerate(self.records):
                if self.gate is not None and index == self.gate_before:
                    self.waiting_at_gate = True
                    await self.gate.wait()
                    self.waiting_at_gate = False
                if self.fail_at is not None and index == self.fail_at:
                    raise RuntimeError("sensitive source failed")
                self.pull_count += 1
                yield record
        finally:
            self.released = True


class MemoryTransport:
    """Pausable in-memory byte sink modeling a transport's commit boundary.

    * ``buffer`` -- bytes accepted by ``write()`` but not yet committed.
      Only a pre-commit staging layer (like this one) can still drop them;
      with a real socket they are already in the kernel, so treat them as
      exposed.
    * ``transmitted`` -- bytes committed to the "wire". Unrecoverable.

    ``pause()`` stops the pump from buffer to transmitted; ``write()``
    then blocks once the buffer exceeds ``high_water`` (backpressure),
    exactly like a real transport that stopped draining.
    """

    def __init__(self, *, high_water: int = 65536) -> None:
        self.high_water = high_water
        self.buffer = bytearray()
        self.transmitted = bytearray()
        self.paused = False
        self.closed = False
        self.write_calls = 0
        self._waiters: set[asyncio.Future[None]] = set()

    async def write(self, data: bytes) -> None:
        if self.closed:
            raise ConnectionResetError("memory transport is closed")
        self.write_calls += 1
        self.buffer += data
        self._commit()
        while len(self.buffer) > self.high_water:
            waiter = asyncio.get_running_loop().create_future()
            self._waiters.add(waiter)
            try:
                await waiter
            finally:
                self._waiters.discard(waiter)
            if self.closed:
                raise ConnectionResetError("memory transport is closed")

    def pause(self) -> None:
        self.paused = True

    def resume(self) -> None:
        self.paused = False
        self._commit()

    def discard_buffer(self) -> int:
        """Drop uncommitted bytes; returns how many. Pre-commit only."""
        discarded = len(self.buffer)
        self.buffer.clear()
        self._commit()
        return discarded

    def close(self) -> None:
        self.closed = True
        self._commit()

    def _commit(self) -> None:
        if not self.paused and self.buffer:
            self.transmitted += self.buffer
            self.buffer.clear()
        if len(self.buffer) <= self.high_water:
            for waiter in self._waiters:
                if not waiter.done():
                    waiter.set_result(None)


def build_app() -> web.Application:
    """Minimal embeddable app: a sensitive stream plus a local revoke hook.

    The grant lives entirely in-process -- no online auth service needed.
    ``POST /revoke`` is the caller explicitly withdrawing authorization.
    """
    records = [f"secret-record-{i:02d}\n".encode() for i in range(10)]
    grants: dict[str, AuthorizationGrant] = {}

    async def stream_handler(request: web.Request) -> web.StreamResponse:
        grant = grants.setdefault("demo", AuthorizationGrant())
        producer = SensitiveRecordProducer(records)
        return await stream_sensitive(request, producer.stream(), grant)

    async def revoke_handler(request: web.Request) -> web.Response:
        grant = grants.get("demo")
        if grant is None:
            return web.Response(text="no active grant\n")
        grant.revoke()
        return web.Response(text="revoked\n")

    app = web.Application()
    app.router.add_get("/stream", stream_handler)
    app.router.add_post("/revoke", revoke_handler)
    return app


async def _wait_for(condition: Callable[[], bool], timeout: float = 5.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not condition():
        if loop.time() > deadline:
            raise TimeoutError("condition not met in time")
        await asyncio.sleep(0.001)


def _report(
    title: str, producer: SensitiveRecordProducer, transport: MemoryTransport
) -> None:
    entered = transport.write_calls
    print(f"--- {title} ---")
    print(f"  producer pulls ........ {producer.pull_count}")
    print(f"  producer released ..... {producer.released}")
    print(f"  entered transport ..... {entered} write(s)")
    print(f"  committed to peer ..... {len(transport.transmitted)} bytes")
    print(f"  left in buffer ........ {len(transport.buffer)} bytes")


async def _scenario_revoke_before_prepare() -> None:
    grant = AuthorizationGrant()
    transport = MemoryTransport()
    producer = SensitiveRecordProducer([b"secret-a", b"secret-b"])
    grant.revoke()
    with contextlib.suppress(AuthorizationRevoked):
        await pump_sensitive(transport, producer.stream(), grant)
    _report("Scenario A: revoked before prepare", producer, transport)
    print("  -> nothing was pulled or sent; revocation is total.\n")


async def _scenario_revoke_while_buffered() -> None:
    grant = AuthorizationGrant()
    chunk = b"s" * 32
    transport = MemoryTransport(high_water=len(chunk))
    transport.pause()
    producer = SensitiveRecordProducer([chunk] * 5)
    task = asyncio.ensure_future(
        pump_sensitive(transport, producer.stream(), grant)
    )
    await _wait_for(lambda: transport.write_calls == 2)
    grant.revoke()
    with contextlib.suppress(AuthorizationRevoked):
        await task
    discarded = transport.discard_buffer()
    _report("Scenario B: revoked while buffered", producer, transport)
    print(f"  dropped from buffer ... {discarded} bytes")
    print(
        "  -> chunks 3-5 were never pulled. The 64 buffered bytes model\n"
        "     data already handed to a real transport: only a pre-commit\n"
        "     staging layer can still drop them; with a real socket you\n"
        "     must treat them as exposed.\n"
    )


async def _scenario_revoke_after_commit() -> None:
    grant = AuthorizationGrant()
    chunks = [f"secret-{i}\n".encode() for i in range(5)]
    transport = MemoryTransport()
    producer = SensitiveRecordProducer(chunks)
    producer.gate = asyncio.Event()
    producer.gate_before = 2
    task = asyncio.ensure_future(
        pump_sensitive(transport, producer.stream(), grant)
    )
    await _wait_for(lambda: producer.waiting_at_gate)
    grant.revoke()
    with contextlib.suppress(AuthorizationRevoked):
        await task
    _report("Scenario C: revoked after commit", producer, transport)
    print(f"  unrecoverable ......... {bytes(transport.transmitted)!r}")
    print(
        "  -> the committed bytes cannot be recalled; revocation stopped\n"
        "     every later chunk (the in-flight pull was cancelled).\n"
    )


async def run_demo() -> None:
    """Drive the pump against a pausable in-memory transport, revoking at
    each guarantee boundary and recording bytes and producer calls."""
    await _scenario_revoke_before_prepare()
    await _scenario_revoke_while_buffered()
    await _scenario_revoke_after_commit()
    print(__doc__)


if __name__ == "__main__":
    asyncio.run(run_demo())
