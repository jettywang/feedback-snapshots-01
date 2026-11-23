import asyncio
from importlib import import_module

import pytest
from asgiref.sync import async_to_sync, sync_to_async
from django.conf import settings
from django.contrib.auth import get_user_model

from channels.auth import AuthMiddlewareStack, login
from channels.generic.websocket import AsyncWebsocketConsumer, WebsocketConsumer
from channels.sessions import save_session
from channels.testing import WebsocketCommunicator

INSTANCES = []


@pytest.fixture(autouse=True)
def clear_instances():
    INSTANCES.clear()
    yield
    INSTANCES.clear()


@pytest.fixture
def user_bob():
    return get_user_model().objects.create(username="bob", email="bob@example.com")


class RecordingMixin:
    """
    Consumer mixin that pauses the confirmation phase so a test can queue a
    business message before the session has been saved.
    """

    connection_confirmation = True
    mode = "ok"
    user = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handled = []
        self.handler_session_id = None
        self.handler_user_id = None
        self.handler_user_authenticated = None
        self.handler_session_marker = None
        self.confirm_session_id = None
        self.confirm_user_id = None
        self.confirm_session_key = None
        self.confirm_started = asyncio.Event()
        self.release_confirm = asyncio.Event()
        INSTANCES.append(self)

    async def confirm_connection(self):
        self.confirm_started.set()
        await self.release_confirm.wait()
        if self.mode == "fail":
            raise RuntimeError("session store unavailable")
        if self.mode == "cancel":
            raise asyncio.CancelledError()
        if self.mode == "hang":
            await asyncio.Event().wait()
        self.confirm_session_id = id(self.scope["session"])
        self.confirm_user_id = id(self.scope["user"])
        await save_session(self.scope)
        self.confirm_session_key = self.scope["session"].session_key

    def _record(self, text_data):
        self.handled.append(text_data)
        self.handler_session_id = id(self.scope["session"])
        self.handler_user_id = id(self.scope["user"])
        user = self.scope["user"]
        self.handler_user_authenticated = getattr(user, "is_authenticated", False)
        self.handler_session_marker = self.scope["session"].get("marker")


def make_sync_app(mode="ok", user=None, confirmation=True):
    class _Consumer(RecordingMixin, WebsocketConsumer):
        connection_confirmation = confirmation

        def connect(self):
            self.accept()
            self.scope["session"]["marker"] = "from-connect"
            if self.user is not None:
                async_to_sync(login)(self.scope, self.user)

        def receive(self, text_data=None, bytes_data=None):
            self._record(text_data)
            self.send(text_data="handled:" + text_data)

    _Consumer.mode = mode
    _Consumer.user = user
    return AuthMiddlewareStack(_Consumer.as_asgi())


def make_async_app(mode="ok", user=None, confirmation=True):
    class _Consumer(RecordingMixin, AsyncWebsocketConsumer):
        connection_confirmation = confirmation

        async def connect(self):
            await self.accept()
            self.scope["session"]["marker"] = "from-connect"
            if self.user is not None:
                await login(self.scope, self.user)

        async def receive(self, text_data=None, bytes_data=None):
            self._record(text_data)
            await self.send(text_data="handled:" + text_data)

    _Consumer.mode = mode
    _Consumer.user = user
    return AuthMiddlewareStack(_Consumer.as_asgi())


APP_FACTORIES = [
    pytest.param(make_sync_app, id="sync"),
    pytest.param(make_async_app, id="async"),
]


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
@pytest.mark.parametrize("make_app", APP_FACTORIES)
async def test_confirmation_save_success(make_app, user_bob):
    """
    With the save paused, the first business message is queued. Once the save
    succeeds the handler runs, against the same session and user that the
    login wrote to, and the client receives the business reply.
    """
    app = make_app(user=user_bob)
    communicator = WebsocketCommunicator(app, "/test/")
    connected, _ = await communicator.connect()
    assert connected

    instance = INSTANCES[-1]
    await instance.confirm_started.wait()

    await communicator.send_to(text_data="hello")
    assert await communicator.receive_nothing(timeout=0.1)
    assert instance.handled == []

    instance.release_confirm.set()
    response = await communicator.receive_from()
    assert response == "handled:hello"
    assert instance.handled == ["hello"]

    assert instance.handler_session_id == instance.confirm_session_id
    assert instance.handler_user_id == instance.confirm_user_id
    assert instance.handler_session_marker == "from-connect"
    assert instance.handler_user_authenticated is True
    assert instance.confirm_session_key
    assert instance.connection_confirmed is True
    assert instance.confirmation_error is None

    SessionStore = _session_store()
    stored = SessionStore(session_key=instance.confirm_session_key)
    assert await sync_to_async(stored.get)("marker") == "from-connect"

    await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
@pytest.mark.parametrize("make_app", APP_FACTORIES)
async def test_confirmation_save_failure(make_app, user_bob):
    """
    A failed save closes with the dedicated confirmation code. The queued
    business message is never handled and no business reply is sent.
    """
    app = make_app(mode="fail", user=user_bob)
    communicator = WebsocketCommunicator(app, "/test/")
    connected, _ = await communicator.connect()
    assert connected

    instance = INSTANCES[-1]
    await instance.confirm_started.wait()

    await communicator.send_to(text_data="hello")
    assert await communicator.receive_nothing(timeout=0.1)

    instance.release_confirm.set()
    close = await communicator.receive_output()
    assert close["type"] == "websocket.close"
    assert close["code"] == instance.connection_confirmation_failed_close_code
    assert close["code"] != 1000
    assert instance.handled == []
    assert instance.connection_confirmed is False
    assert isinstance(instance.confirmation_error, RuntimeError)

    # the application has finished; nothing else (in particular no
    # websocket.send carrying a business reply) was emitted.
    await communicator.wait()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
@pytest.mark.parametrize("make_app", APP_FACTORIES)
async def test_confirmation_save_cancelled(make_app, user_bob):
    """
    Cancelling the save is neither success nor a confirmation failure: the
    handler never runs, no business confirmation is emitted, and the
    connection is not marked confirmed.
    """
    app = make_app(mode="cancel", user=user_bob)
    communicator = WebsocketCommunicator(app, "/test/")
    connected, _ = await communicator.connect()
    assert connected

    instance = INSTANCES[-1]
    await instance.confirm_started.wait()

    await communicator.send_to(text_data="hello")
    assert await communicator.receive_nothing(timeout=0.1)

    instance.release_confirm.set()
    await communicator.wait()

    assert instance.handled == []
    assert instance.connection_confirmed is False
    assert instance.confirmation_error is None
    # No close frame is sent for a cancellation, and nothing was queued for
    # the client either; the connection simply ends.
    assert communicator.output_queue.empty()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
@pytest.mark.parametrize("make_app", APP_FACTORIES)
async def test_confirmation_is_opt_in(make_app):
    """
    Without opting in, the confirmation phase is skipped: no save is made and
    the message is handled immediately.
    """
    app = make_app(confirmation=False)
    communicator = WebsocketCommunicator(app, "/test/")
    connected, _ = await communicator.connect()
    assert connected

    instance = INSTANCES[-1]
    await communicator.send_to(text_data="hello")
    response = await communicator.receive_from()
    assert response == "handled:hello"
    assert instance.handled == ["hello"]
    assert instance.connection_confirmed is False

    await communicator.disconnect()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_save_session_helper_requires_session():
    with pytest.raises(ValueError, match="no session in scope"):
        await save_session({})


def _session_store():
    return import_module(settings.SESSION_ENGINE).SessionStore


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
@pytest.mark.parametrize("make_app", APP_FACTORIES)
async def test_confirmation_externally_cancelled(make_app, user_bob):
    """
    Cancelling the whole application while the save is paused does not let the
    queued business message run and never marks the connection confirmed.
    """
    app = make_app(mode="hang", user=user_bob)
    communicator = WebsocketCommunicator(app, "/test/")
    connected, _ = await communicator.connect()
    assert connected

    instance = INSTANCES[-1]
    await instance.confirm_started.wait()

    await communicator.send_to(text_data="hello")
    assert await communicator.receive_nothing(timeout=0.1)

    # Cancel the ASGI application task itself; the gate is never released.
    communicator.future.cancel()
    with pytest.raises(asyncio.CancelledError):
        await communicator.future

    assert instance.handled == []
    assert instance.connection_confirmed is False



@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [False, True], ids=["sync", "async"])
async def test_confirmation_failure_leaves_groups(is_async):
    """
    A failed confirmation stops the consumer without a normal disconnect, so
    it must still leave any groups joined during connect.
    """
    from channels.layers import get_channel_layer

    channel_layer = get_channel_layer()
    group = "confirmation-cleanup"
    channel_layer.groups.pop(group, None)

    class _GatedSync(WebsocketConsumer):
        connection_confirmation = True
        groups = [group]

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.confirm_started = asyncio.Event()
            self.release_confirm = asyncio.Event()
            INSTANCES.append(self)

        def connect(self):
            self.accept()

        async def confirm_connection(self):
            self.confirm_started.set()
            await self.release_confirm.wait()
            raise RuntimeError("session store unavailable")

    class _GatedAsync(AsyncWebsocketConsumer):
        connection_confirmation = True
        groups = [group]

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.confirm_started = asyncio.Event()
            self.release_confirm = asyncio.Event()
            INSTANCES.append(self)

        async def connect(self):
            await self.accept()

        async def confirm_connection(self):
            self.confirm_started.set()
            await self.release_confirm.wait()
            raise RuntimeError("session store unavailable")

    consumer_class = _GatedAsync if is_async else _GatedSync
    app = AuthMiddlewareStack(consumer_class.as_asgi())
    communicator = WebsocketCommunicator(app, "/test/")
    connected, _ = await communicator.connect()
    assert connected

    instance = INSTANCES[-1]
    await instance.confirm_started.wait()
    assert instance.channel_name in channel_layer.groups[group]

    instance.release_confirm.set()
    close = await communicator.receive_output()
    assert close["type"] == "websocket.close"
    assert close["code"] == 4401
    await communicator.wait()

    assert instance.channel_name not in channel_layer.groups.get(group, set())



class _LegacySessionObject:
    """
    Minimal session stand-in without ``asave()`` so the helper must take the
    thread-based save path, like a custom Django session backend.
    """

    def __init__(self):
        self.saved = 0
        self.session_key = "legacy-key"

    def save(self):
        self.saved += 1


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [False, True], ids=["sync", "async"])
async def test_confirmation_threaded_session_save(is_async):
    """
    A session without ``asave()`` is saved in a thread. The sync consumer runs
    ``async_to_sync`` from its worker thread, so this also guards against a
    deadlock on asgiref's thread-sensitive executor.
    """
    from channels.testing import ApplicationCommunicator

    session = _LegacySessionObject()

    class _SyncConsumer(WebsocketConsumer):
        connection_confirmation = True

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            INSTANCES.append(self)

        def connect(self):
            self.accept()

    class _AsyncConsumer(AsyncWebsocketConsumer):
        connection_confirmation = True

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            INSTANCES.append(self)

        async def connect(self):
            await self.accept()

    consumer_class = _AsyncConsumer if is_async else _SyncConsumer
    app = consumer_class.as_asgi()
    scope = {
        "type": "websocket",
        "path": "/test/",
        "query_string": b"",
        "headers": [],
        "subprotocols": [],
        "session": session,
    }
    communicator = ApplicationCommunicator(app, scope)
    await communicator.send_input({"type": "websocket.connect"})
    response = await asyncio.wait_for(communicator.receive_output(), 5)
    assert response["type"] == "websocket.accept"

    instance = INSTANCES[-1]
    # The confirmation runs after the accept; wait for it to settle.
    for _ in range(50):
        if instance.connection_confirmed:
            break
        await asyncio.sleep(0.01)
    assert instance.connection_confirmed is True
    assert session.saved == 1
    await communicator.wait()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
@pytest.mark.parametrize("is_async", [False, True], ids=["sync", "async"])
async def test_default_confirmation_persists_login(is_async, user_bob):
    """
    Without overriding ``confirm_connection()`` the built-in session save runs
    after ``connect()`` logs the user in, before the first message handler.
    """
    seen = {}

    class _SyncConsumer(WebsocketConsumer):
        connection_confirmation = True

        def connect(self):
            self.accept()
            async_to_sync(login)(self.scope, user_bob)
            self.scope["session"]["marker"] = "connect"

        def receive(self, text_data=None, bytes_data=None):
            seen["user"] = self.scope["user"]
            seen["marker"] = self.scope["session"].get("marker")
            seen["key"] = self.scope["session"].session_key
            self.send(text_data="ok")

    class _AsyncConsumer(AsyncWebsocketConsumer):
        connection_confirmation = True

        async def connect(self):
            await self.accept()
            await login(self.scope, user_bob)
            self.scope["session"]["marker"] = "connect"

        async def receive(self, text_data=None, bytes_data=None):
            seen["user"] = self.scope["user"]
            seen["marker"] = self.scope["session"].get("marker")
            seen["key"] = self.scope["session"].session_key
            await self.send(text_data="ok")

    consumer_class = _AsyncConsumer if is_async else _SyncConsumer
    app = AuthMiddlewareStack(consumer_class.as_asgi())
    communicator = WebsocketCommunicator(app, "/test/")
    connected, _ = await communicator.connect()
    assert connected

    await communicator.send_to(text_data="hi")
    assert await communicator.receive_from() == "ok"
    assert seen["user"] == user_bob
    assert seen["marker"] == "connect"

    stored = _session_store()(session_key=seen["key"])
    assert await sync_to_async(stored.get)("marker") == "connect"

    await communicator.disconnect()
