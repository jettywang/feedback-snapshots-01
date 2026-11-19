import asyncio
from unittest import mock

import pytest

from aiohttp._websocket.models import WSMessageBinary, WSMessageText
from aiohttp._websocket.reader import WebSocketDataQueue
from aiohttp.base_protocol import BaseProtocol
from aiohttp.streams import EofStream


@pytest.fixture
def protocol() -> BaseProtocol:
    return mock.create_autospec(BaseProtocol, spec_set=True, instance=True, _reading_paused=False)  # type: ignore[no-any-return]


@pytest.fixture
def buffer(
    event_loop: asyncio.AbstractEventLoop, protocol: BaseProtocol
) -> WebSocketDataQueue:
    return WebSocketDataQueue(protocol, limit=1, loop=event_loop)


class TestWebSocketDataQueue:
    def test_feed_pause(self, buffer: WebSocketDataQueue) -> None:
        buffer._protocol._reading_paused = False
        for _ in range(3):
            buffer.feed_data(WSMessageBinary(b"x", size=1))

        assert buffer._protocol.pause_reading.called  # type: ignore[attr-defined]

    async def test_resume_on_read(self, buffer: WebSocketDataQueue) -> None:
        buffer.feed_data(WSMessageBinary(b"x", size=1))

        buffer._protocol._reading_paused = True
        await buffer.read()
        assert buffer._protocol.resume_reading.called  # type: ignore[attr-defined]

    async def test_feed_then_cancel_keeps_message_and_clears_waiter(
        self, buffer: WebSocketDataQueue
    ) -> None:
        # Waking the waiter and immediately cancelling must not drop the
        # already-parsed message: it stays buffered and is handed to the next
        # reader exactly once.
        read_task = asyncio.create_task(buffer.read())
        await asyncio.sleep(0)
        assert buffer._waiter is not None

        buffer.feed_data(WSMessageText("secret", size=6, extra=""))
        read_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await read_task

        assert buffer._waiter is None
        assert [msg.data for msg in buffer._buffer] == ["secret"]

        msg = await buffer.read()
        assert msg.data == "secret"
        assert len(buffer._buffer) == 0

    async def test_cancel_then_feed_keeps_message_and_clears_waiter(
        self, buffer: WebSocketDataQueue
    ) -> None:
        read_task = asyncio.create_task(buffer.read())
        await asyncio.sleep(0)

        read_task.cancel()
        buffer.feed_data(WSMessageText("secret", size=6, extra=""))
        with pytest.raises(asyncio.CancelledError):
            await read_task

        assert buffer._waiter is None
        msg = await buffer.read()
        assert msg.data == "secret"

    async def test_cancel_then_exception_leaves_no_waiter(
        self, buffer: WebSocketDataQueue
    ) -> None:
        read_task = asyncio.create_task(buffer.read())
        await asyncio.sleep(0)

        read_task.cancel()
        buffer.set_exception(ConnectionResetError("lost"))
        with pytest.raises(asyncio.CancelledError):
            await read_task

        assert buffer._waiter is None
        assert buffer.is_eof()
        with pytest.raises(ConnectionResetError):
            await buffer.read()

    async def test_exception_then_cancel_leaves_no_waiter(
        self, buffer: WebSocketDataQueue
    ) -> None:
        read_task = asyncio.create_task(buffer.read())
        await asyncio.sleep(0)

        buffer.set_exception(ConnectionResetError("lost"))
        read_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await read_task

        assert buffer._waiter is None
        with pytest.raises(ConnectionResetError):
            await buffer.read()

    async def test_eof_then_cancel_leaves_no_waiter(
        self, buffer: WebSocketDataQueue
    ) -> None:
        read_task = asyncio.create_task(buffer.read())
        await asyncio.sleep(0)

        buffer.feed_eof()
        read_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await read_task

        assert buffer._waiter is None
        with pytest.raises(EofStream):
            await buffer.read()
