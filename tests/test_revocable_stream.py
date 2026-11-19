"""Tests for the revocable-streaming example (examples/revocable_stream.py)."""

import asyncio
import importlib.util
from collections.abc import Callable
from pathlib import Path
from unittest import mock

import pytest

from aiohttp import web
from aiohttp.abc import AbstractStreamWriter
from aiohttp.test_utils import make_mocked_request


def _load_example():
    path = Path(__file__).resolve().parent.parent / "examples" / "revocable_stream.py"
    spec = importlib.util.spec_from_file_location("revocable_stream", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


revocable_stream = _load_example()

CHUNKS = [f"secret-record-{i}\n".encode() for i in range(5)]


async def wait_until(condition: Callable[[], bool], timeout: float = 5.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not condition():
        assert loop.time() < deadline, "condition not met in time"
        await asyncio.sleep(0.001)


def make_recording_writer() -> tuple[AbstractStreamWriter, list[bytes]]:
    """A payload writer recording every chunk StreamResponse hands it."""
    written: list[bytes] = []
    writer = mock.create_autospec(AbstractStreamWriter, spec_set=True)

    async def write(data: bytes) -> None:
        written.append(bytes(data))

    writer.write.side_effect = write
    return writer, written


async def test_revoke_before_prepare_sends_nothing() -> None:
    grant = revocable_stream.AuthorizationGrant()
    transport = revocable_stream.MemoryTransport()
    producer = revocable_stream.SensitiveRecordProducer(CHUNKS)
    grant.revoke()
    with pytest.raises(revocable_stream.AuthorizationRevoked):
        await revocable_stream.pump_sensitive(transport, producer.stream(), grant)
    assert producer.pull_count == 0
    # The producer never started, so it never acquired anything to release.
    assert not producer.released
    assert transport.write_calls == 0
    assert bytes(transport.transmitted) == b""


async def test_revoke_while_buffered_blocks_unpulled_chunks() -> None:
    grant = revocable_stream.AuthorizationGrant()
    transport = revocable_stream.MemoryTransport(high_water=len(CHUNKS[0]))
    transport.pause()
    producer = revocable_stream.SensitiveRecordProducer(CHUNKS)
    task = asyncio.ensure_future(
        revocable_stream.pump_sensitive(transport, producer.stream(), grant)
    )
    await wait_until(lambda: transport.write_calls == 2)
    grant.revoke()
    with pytest.raises(revocable_stream.AuthorizationRevoked):
        await task
    # Two chunks were pulled and accepted by the transport; the rest of the
    # producer was never touched after revocation.
    assert producer.pull_count == 2
    assert producer.released
    assert bytes(transport.transmitted) == b""
    # A pre-commit staging layer can still drop buffered bytes ...
    assert transport.discard_buffer() == len(CHUNKS[0]) + len(CHUNKS[1])
    assert bytes(transport.transmitted) == b""
    await asyncio.sleep(0.01)
    assert producer.pull_count == 2


async def test_revoke_after_commit_cannot_recall_transmitted() -> None:
    grant = revocable_stream.AuthorizationGrant()
    transport = revocable_stream.MemoryTransport()
    producer = revocable_stream.SensitiveRecordProducer(CHUNKS)
    producer.gate = asyncio.Event()
    producer.gate_before = 2
    task = asyncio.ensure_future(
        revocable_stream.pump_sensitive(transport, producer.stream(), grant)
    )
    await wait_until(lambda: producer.waiting_at_gate)
    grant.revoke()
    with pytest.raises(revocable_stream.AuthorizationRevoked):
        await task
    # Committed bytes are unrecoverable ...
    assert bytes(transport.transmitted) == CHUNKS[0] + CHUNKS[1]
    # ... but the in-flight pull for chunk 3 was cancelled at the gate and
    # no further chunk was pulled from the producer.
    assert producer.pull_count == 2
    assert producer.released


async def test_write_return_is_not_delivery() -> None:
    grant = revocable_stream.AuthorizationGrant()
    transport = revocable_stream.MemoryTransport(high_water=1024)
    transport.pause()
    producer = revocable_stream.SensitiveRecordProducer(CHUNKS[:1])
    await revocable_stream.pump_sensitive(transport, producer.stream(), grant)
    # write() returned and the pump completed ...
    assert transport.write_calls == 1
    # ... but the peer received nothing: the chunk only sits in the buffer.
    assert bytes(transport.buffer) == CHUNKS[0]
    assert bytes(transport.transmitted) == b""


async def test_clean_stream_completes() -> None:
    grant = revocable_stream.AuthorizationGrant()
    transport = revocable_stream.MemoryTransport()
    producer = revocable_stream.SensitiveRecordProducer(CHUNKS)
    await revocable_stream.pump_sensitive(transport, producer.stream(), grant)
    assert bytes(transport.transmitted) == b"".join(CHUNKS)
    assert producer.pull_count == len(CHUNKS)
    assert producer.released


async def test_producer_error_releases_resource() -> None:
    grant = revocable_stream.AuthorizationGrant()
    transport = revocable_stream.MemoryTransport()
    producer = revocable_stream.SensitiveRecordProducer(CHUNKS)
    producer.fail_at = 1
    with pytest.raises(RuntimeError, match="sensitive source failed"):
        await revocable_stream.pump_sensitive(transport, producer.stream(), grant)
    assert producer.released
    assert bytes(transport.transmitted) == CHUNKS[0]


async def test_cancellation_releases_resource() -> None:
    grant = revocable_stream.AuthorizationGrant()
    transport = revocable_stream.MemoryTransport()
    producer = revocable_stream.SensitiveRecordProducer(CHUNKS)
    producer.gate = asyncio.Event()
    producer.gate_before = 1
    task = asyncio.ensure_future(
        revocable_stream.pump_sensitive(transport, producer.stream(), grant)
    )
    await wait_until(lambda: producer.waiting_at_gate)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert producer.released


async def test_handler_forbidden_when_revoked_before_prepare() -> None:
    grant = revocable_stream.AuthorizationGrant()
    grant.revoke()
    producer = revocable_stream.SensitiveRecordProducer(CHUNKS)
    request = make_mocked_request("GET", "/")
    with pytest.raises(web.HTTPForbidden):
        await revocable_stream.stream_sensitive(
            request, producer.stream(), grant
        )
    assert producer.pull_count == 0


async def test_handler_aborts_stream_on_revoke_without_clean_eof() -> None:
    grant = revocable_stream.AuthorizationGrant()
    producer = revocable_stream.SensitiveRecordProducer(CHUNKS)
    producer.gate = asyncio.Event()
    producer.gate_before = 1
    writer, written = make_recording_writer()
    request = make_mocked_request("GET", "/", writer=writer)
    task = asyncio.ensure_future(
        revocable_stream.stream_sensitive(request, producer.stream(), grant)
    )
    await wait_until(lambda: producer.waiting_at_gate)
    grant.revoke()
    # The handler re-raises instead of returning a response, which is what
    # makes aiohttp abort the connection: the client then fails loudly on a
    # truncated payload instead of accepting a short body as complete.
    with pytest.raises(revocable_stream.AuthorizationRevoked):
        await task
    # Chunk 1 was committed to the transport (unrecoverable), chunk 2 was
    # never pulled, and no clean-looking EOF was emitted.
    assert written == [CHUNKS[0]]
    assert writer.write_eof.call_count == 0
    assert producer.pull_count == 1
    assert producer.released
