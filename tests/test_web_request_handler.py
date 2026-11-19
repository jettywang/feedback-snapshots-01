import asyncio
from math import ceil
from unittest import mock

import pytest

from aiohttp import web
from aiohttp.web_protocol import shutdown_deadline


async def serve(request: web.BaseRequest) -> web.Response:
    assert False


async def test_repr() -> None:
    manager = web.Server(serve)
    handler = manager()

    assert "<RequestHandler disconnected>" == repr(handler)

    with mock.patch.object(handler, "transport", autospec=True):
        assert "<RequestHandler connected>" == repr(handler)


async def test_connections() -> None:
    manager = web.Server(serve)
    assert manager.connections == []

    handler = mock.Mock(spec_set=web.RequestHandler)
    handler._task_handler = None
    transport = object()
    manager.connection_made(handler, transport)  # type: ignore[arg-type]
    assert manager.connections == [handler]

    manager.connection_lost(handler, None)
    assert manager.connections == []


async def make_handler(
    manager: web.Server[web.Request],
    *,
    shutdown: mock.AsyncMock | None = None,
) -> mock.Mock:
    handler = mock.Mock(spec_set=web.RequestHandler)
    handler._task_handler = None
    handler.shutdown = shutdown or mock.AsyncMock(return_value=mock.Mock())
    manager.connection_made(handler, mock.Mock())
    return handler


async def test_shutdown_no_timeout() -> None:
    manager = web.Server(serve)
    handler = await make_handler(manager)

    await manager.shutdown()

    manager.connection_lost(handler, None)
    assert manager.connections == []
    handler.shutdown.assert_awaited_once_with(None, deadline=None)


async def test_shutdown_timeout_shares_one_deadline() -> None:
    manager = web.Server(serve)

    handlers = [await make_handler(manager) for _ in range(3)]

    await manager.shutdown(timeout=0.1)

    deadlines = set()
    for handler in handlers:
        handler.shutdown.assert_awaited_once()
        call = handler.shutdown.call_args
        assert call.args == (0.1,)
        deadlines.add(call.kwargs["deadline"])
    # Every connection counts down from the same instant, so the batch has one
    # overall budget instead of one timeout per connection.
    assert len(deadlines) == 1
    assert manager.connections == []


async def test_shutdown_keeps_cleaning_after_connection_error() -> None:
    manager = web.Server(serve)

    broken = await make_handler(
        manager, shutdown=mock.AsyncMock(side_effect=RuntimeError("boom"))
    )
    healthy = await make_handler(manager)

    await manager.shutdown()

    broken.shutdown.assert_awaited_once()
    healthy.shutdown.assert_awaited_once()
    assert manager.connections == []


async def test_shutdown_propagates_cancellation() -> None:
    manager = web.Server(serve)
    cancelled = await make_handler(
        manager, shutdown=mock.AsyncMock(side_effect=asyncio.CancelledError())
    )

    with pytest.raises(asyncio.CancelledError):
        await manager.shutdown()

    cancelled.shutdown.assert_awaited_once()


async def test_shutdown_zero_timeout_gives_no_deadline() -> None:
    manager = web.Server(serve)
    handler = await make_handler(manager)

    await manager.shutdown(timeout=0)

    handler.shutdown.assert_awaited_once_with(0, deadline=None)


async def test_shutdown_deadline_applies_ceil_rule() -> None:
    loop = asyncio.get_running_loop()
    now = loop.time()

    for timeout in (None, 0, -1):
        assert shutdown_deadline(timeout, loop) is None

    for timeout in (0.5, 4.9):
        # Short timeouts keep sub-second precision.
        assert shutdown_deadline(timeout, loop) == pytest.approx(now + timeout)
    for timeout in (5.0, 30.0):
        # Documented ceil rule: values above the threshold land on the next
        # whole second, and only the shared deadline is ceiled once.
        assert shutdown_deadline(timeout, loop) == pytest.approx(ceil(now + timeout))
