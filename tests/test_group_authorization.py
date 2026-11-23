import asyncio
from importlib import import_module

import pytest
from asgiref.sync import sync_to_async
from django.conf import settings
from django.contrib.auth import (
    BACKEND_SESSION_KEY,
    HASH_SESSION_KEY,
    SESSION_KEY,
    get_user_model,
)

from channels import DEFAULT_CHANNEL_LAYER
from channels.generic.websocket import AsyncWebsocketConsumer, WebsocketConsumer
from channels.layers import InMemoryChannelLayer, channel_layers
from channels.sessions import SessionMiddlewareStack
from channels.testing import WebsocketCommunicator


class RecordingChannelLayer(InMemoryChannelLayer):
    """
    In-memory layer that records the group membership it actually commits.

    ``hold`` can delay a ``group_add`` so a test can cancel a connection
    while the join is in flight.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.added = []
        self.discarded = []
        self.hold = None

    async def group_add(self, group, channel):
        if self.hold is not None:
            await self.hold.wait()
        await super().group_add(group, channel)
        self.added.append((group, channel))

    async def group_discard(self, group, channel):
        await super().group_discard(group, channel)
        self.discarded.append((group, channel))


@pytest.fixture
def users():
    User = get_user_model()
    return (
        User.objects.create(username="group-alice", is_staff=True),
        User.objects.create(username="group-bob"),
    )


def make_session(user):
    """Create a DB-backed session logged in as ``user``."""
    SessionStore = import_module(settings.SESSION_ENGINE).SessionStore
    session = SessionStore()
    session[SESSION_KEY] = user._meta.pk.value_to_string(user)
    session[BACKEND_SESSION_KEY] = settings.AUTHENTICATION_BACKENDS[0]
    session[HASH_SESSION_KEY] = user.get_session_auth_hash()
    session.save()
    return session


def session_cookie(session):
    return [
        (
            b"cookie",
            f"{settings.SESSION_COOKIE_NAME}={session.session_key}".encode("latin1"),
        )
    ]


class GroupConsumerMixin:
    groups = ["observers"]
    identity_groups = ["staff", "members"]

    async def authorize_group(self, group, user):
        if group == "staff":
            return user.is_staff
        if group == "members":
            return user.username.endswith("alice")
        return False


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_two_users_join_their_own_identity_groups(users):
    """
    One consumer class, two users and two sessions: each connection submits
    and joins the groups its own identity is authorised for.
    """
    alice, bob = users

    class Consumer(GroupConsumerMixin, AsyncWebsocketConsumer):
        async def connect(self):
            await self.accept()

    layer = RecordingChannelLayer()
    previous = channel_layers.set(DEFAULT_CHANNEL_LAYER, layer)
    try:
        alice_session = await sync_to_async(make_session)(alice)
        bob_session = await sync_to_async(make_session)(bob)
        app = SessionMiddlewareStack(Consumer.as_asgi())

        alice_comm = WebsocketCommunicator(
            app, "/ws/", headers=session_cookie(alice_session)
        )
        bob_comm = WebsocketCommunicator(
            app, "/ws/", headers=session_cookie(bob_session)
        )

        assert (await alice_comm.connect())[0]
        # Alice is staff and ends in "alice"; Bob is neither.
        assert (await bob_comm.connect())[0]

        assert set(layer.groups) == {"observers", "staff", "members"}
        assert len(layer.groups["observers"]) == 2
        (alice_channel,) = layer.groups["staff"]
        (members_channel,) = layer.groups["members"]
        assert alice_channel == members_channel
        bob_channel = next(
            channel
            for channel in layer.groups["observers"]
            if channel != alice_channel
        )
        assert bob_channel != alice_channel

        await alice_comm.disconnect()
        await bob_comm.disconnect()
        assert layer.groups == {}
    finally:
        channel_layers.set(DEFAULT_CHANNEL_LAYER, previous)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_declaration_does_not_grant_anonymous_membership(users):
    """
    Without a session, identity groups stay pending and are neither submitted
    nor joined, while ordinary observer groups still apply.
    """

    snapshots = {}

    class Consumer(GroupConsumerMixin, AsyncWebsocketConsumer):
        async def connect(self):
            await self.accept()

        async def snapshot(self, event):
            snapshots["membership"] = self.group_membership
            await self.send(text_data="snapshot")

    layer = RecordingChannelLayer()
    previous = channel_layers.set(DEFAULT_CHANNEL_LAYER, layer)
    try:
        # No session middleware at all: configuration is still declared, but
        # identity groups wait for a reliable session conclusion.
        comm = WebsocketCommunicator(Consumer.as_asgi(), "/ws/")
        assert (await comm.connect())[0]
        assert set(layer.groups) == {"observers"}

        channel = list(layer.groups["observers"])[0]
        await layer.send(channel, {"type": "snapshot"})
        assert await comm.receive_from() == "snapshot"
        membership = snapshots["membership"]
        assert membership["declared"] == {
            "groups": ["observers"],
            "identity_groups": ["staff", "members"],
        }
        assert membership["submitted"] == ["observers"]
        assert membership["joined"] == ["observers"]
        assert set(membership["pending"]) == {"staff", "members"}
        assert membership["denied"] == {}
        await comm.disconnect()
        assert layer.groups == {}
    finally:
        channel_layers.set(DEFAULT_CHANNEL_LAYER, previous)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_anonymous_session_is_a_reliable_denial():
    """
    A session that reliably resolves to an anonymous user does not leave
    identity groups pending: they are denied and never submitted.
    """

    class Consumer(GroupConsumerMixin, AsyncWebsocketConsumer):
        async def connect(self):
            await self.accept()

    layer = RecordingChannelLayer()
    previous = channel_layers.set(DEFAULT_CHANNEL_LAYER, layer)
    try:
        app = SessionMiddlewareStack(Consumer.as_asgi())
        comm = WebsocketCommunicator(app, "/ws/")
        assert (await comm.connect())[0]
        assert set(layer.groups) == {"observers"}
        assert layer.added == [("observers", next(iter(layer.groups["observers"])))]
        await comm.disconnect()
    finally:
        channel_layers.set(DEFAULT_CHANNEL_LAYER, previous)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_cancelled_connect_discards_only_this_channel(users):
    """
    A connect cancelled between group_add and accept must leave no membership
    behind, and must not disturb a later connection in the same groups.
    """
    alice, _ = users
    release = asyncio.Event()

    class Consumer(GroupConsumerMixin, AsyncWebsocketConsumer):
        async def connect(self):
            if self.scope["path"] == "/first/":
                await release.wait()
            await self.accept()

    layer = RecordingChannelLayer()
    previous = channel_layers.set(DEFAULT_CHANNEL_LAYER, layer)
    try:
        alice_session = await sync_to_async(make_session)(alice)
        app = SessionMiddlewareStack(Consumer.as_asgi())

        first = WebsocketCommunicator(
            app, "/first/", headers=session_cookie(alice_session)
        )
        task = asyncio.create_task(first.connect())
        for _ in range(100):
            if set(layer.groups) == {"observers", "staff", "members"}:
                break
            await asyncio.sleep(0.01)
        assert set(layer.groups) == {"observers", "staff", "members"}
        # Cancel the application task itself, as a server would when the
        # connection is torn down before accept().
        first.future.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        for _ in range(100):
            if layer.groups == {}:
                break
            await asyncio.sleep(0.01)
        assert layer.groups == {}

        # A later connection enters the same groups and survives its own
        # disconnect; cleanup of the cancelled one did not touch it.
        second = WebsocketCommunicator(
            app, "/second/", headers=session_cookie(alice_session)
        )
        assert (await second.connect())[0]
        assert set(layer.groups) == {"observers", "staff", "members"}
        await second.disconnect()
        assert layer.groups == {}
    finally:
        channel_layers.set(DEFAULT_CHANNEL_LAYER, previous)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_identity_groups_reject_and_deliver_messages(users):
    """
    An unauthorised identity gets neither membership nor messages, while the
    authorised connection still receives its group's message normally.
    """
    alice, bob = users

    class Consumer(GroupConsumerMixin, AsyncWebsocketConsumer):
        async def connect(self):
            await self.accept()

        async def notice(self, event):
            await self.send(text_data=event["text"])

    layer = RecordingChannelLayer()
    previous = channel_layers.set(DEFAULT_CHANNEL_LAYER, layer)
    try:
        alice_session = await sync_to_async(make_session)(alice)
        bob_session = await sync_to_async(make_session)(bob)
        app = SessionMiddlewareStack(Consumer.as_asgi())

        alice_comm = WebsocketCommunicator(
            app, "/alice/", headers=session_cookie(alice_session)
        )
        bob_comm = WebsocketCommunicator(
            app, "/bob/", headers=session_cookie(bob_session)
        )
        assert (await alice_comm.connect())[0]
        assert (await bob_comm.connect())[0]

        assert len(layer.groups["staff"]) == 1
        await layer.group_send("staff", {"type": "notice", "text": "hello"})
        assert await alice_comm.receive_from() == "hello"
        assert await bob_comm.receive_nothing(timeout=0.2) is True

        await alice_comm.disconnect()
        await bob_comm.disconnect()
    finally:
        channel_layers.set(DEFAULT_CHANNEL_LAYER, previous)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_sync_consumer_uses_same_authorization_contract(users):
    """
    The synchronous generic consumer exposes the same declaration split,
    identity checks and membership bookkeeping.
    """
    alice, bob = users

    class Consumer(GroupConsumerMixin, WebsocketConsumer):
        def connect(self):
            self.accept()

        def notice(self, event):
            self.send(text_data=event["text"])

    layer = RecordingChannelLayer()
    previous = channel_layers.set(DEFAULT_CHANNEL_LAYER, layer)
    try:
        alice_session = await sync_to_async(make_session)(alice)
        bob_session = await sync_to_async(make_session)(bob)
        app = SessionMiddlewareStack(Consumer.as_asgi())

        alice_comm = WebsocketCommunicator(
            app, "/alice/", headers=session_cookie(alice_session)
        )
        bob_comm = WebsocketCommunicator(
            app, "/bob/", headers=session_cookie(bob_session)
        )
        assert (await alice_comm.connect())[0]
        assert (await bob_comm.connect())[0]

        assert len(layer.groups["staff"]) == 1
        await layer.group_send("staff", {"type": "notice", "text": "hello"})
        assert await alice_comm.receive_from() == "hello"
        assert await bob_comm.receive_nothing(timeout=0.2) is True

        await alice_comm.disconnect()
        await bob_comm.disconnect()
        assert layer.groups == {}
    finally:
        channel_layers.set(DEFAULT_CHANNEL_LAYER, previous)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_authorization_error_and_partial_approval_are_inspectable(users):
    """
    A hook failure is recorded per group and does not block other approved
    groups; the connection's snapshot explains what was actually submitted.
    """
    alice, _ = users
    snapshots = {}

    class Consumer(AsyncWebsocketConsumer):
        groups = ["observers"]
        identity_groups = ["staff", "broken", "members"]

        async def authorize_group(self, group, user):
            if group == "broken":
                raise RuntimeError("policy unavailable")
            return group == "staff"

        async def connect(self):
            await self.accept()

        async def snapshot(self, event):
            snapshots["membership"] = self.group_membership
            await self.send(text_data="snapshot")

    layer = RecordingChannelLayer()
    previous = channel_layers.set(DEFAULT_CHANNEL_LAYER, layer)
    try:
        alice_session = await sync_to_async(make_session)(alice)
        app = SessionMiddlewareStack(Consumer.as_asgi())
        comm = WebsocketCommunicator(
            app, "/ws/", headers=session_cookie(alice_session)
        )
        assert (await comm.connect())[0]
        # The authorised group is joined; the failing one is not, and the
        # connection still gets a usable result.
        assert set(layer.groups) == {"observers", "staff"}

        channel = next(iter(layer.groups["observers"]))
        await layer.send(channel, {"type": "snapshot"})
        assert await comm.receive_from() == "snapshot"

        membership = snapshots["membership"]
        assert membership["submitted"] == ["observers", "staff"]
        assert membership["joined"] == ["observers", "staff"]
        assert membership["failed"] == {"broken": "policy unavailable"}
        assert membership["denied"] == {"members": "not authorized"}

        await comm.disconnect()
        assert layer.groups == {}
    finally:
        channel_layers.set(DEFAULT_CHANNEL_LAYER, previous)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_session_failure_is_reported_not_treated_as_anonymous():
    """
    When the session cannot produce a conclusion, identity groups are reported
    as failed and no membership is submitted; observing groups still join.
    """

    snapshots = {}

    class Consumer(GroupConsumerMixin, AsyncWebsocketConsumer):
        async def connect(self):
            await self.accept()

        async def snapshot(self, event):
            snapshots["membership"] = self.group_membership
            await self.send(text_data="snapshot")

    layer = RecordingChannelLayer()
    previous = channel_layers.set(DEFAULT_CHANNEL_LAYER, layer)
    try:
        # SessionMiddleware supplies a session object, but loading it raises.
        scope_override = {"session": BrokenSession()}
        app = _ScopeInjector(Consumer.as_asgi(), scope_override)
        comm = WebsocketCommunicator(app, "/ws/")
        assert (await comm.connect())[0]
        assert set(layer.groups) == {"observers"}

        channel = next(iter(layer.groups["observers"]))
        await layer.send(channel, {"type": "snapshot"})
        assert await comm.receive_from() == "snapshot"
        membership = snapshots["membership"]
        assert set(membership["failed"]) == {"staff", "members"}
        assert membership["submitted"] == ["observers"]
        assert membership["pending"] == []

        await comm.disconnect()
    finally:
        channel_layers.set(DEFAULT_CHANNEL_LAYER, previous)


class BrokenSession:
    """Session stand-in whose user lookup fails."""

    def __getitem__(self, key):
        raise RuntimeError("session store unavailable")

    def get(self, key, default=None):
        return default

    def __contains__(self, key):
        raise RuntimeError("session store unavailable")


class _ScopeInjector:
    """Minimal ASGI middleware adding entries to the scope for a test."""

    def __init__(self, app, extra):
        self.app = app
        self.extra = extra

    async def __call__(self, scope, receive, send):
        scope = dict(scope)
        scope.update(self.extra)
        return await self.app(scope, receive, send)


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_cancelled_midway_reports_only_submitted_members(users):
    """
    Cancelling while a later identity group is still being checked reports and
    cleans only the memberships actually submitted, leaving a later connection
    with the same declarations intact.
    """
    alice, _ = users
    blocking = asyncio.Event()
    captured = {}

    class Consumer(GroupConsumerMixin, AsyncWebsocketConsumer):
        async def authorize_group(self, group, user):
            if group == "members" and not captured.get("release"):
                captured["membership"] = self.group_membership
                blocking.set()
                await asyncio.Event().wait()
            return group == "staff" or group == "members"

        async def connect(self):
            await self.accept()

    layer = RecordingChannelLayer()
    previous = channel_layers.set(DEFAULT_CHANNEL_LAYER, layer)
    try:
        alice_session = await sync_to_async(make_session)(alice)
        app = SessionMiddlewareStack(Consumer.as_asgi())

        first = WebsocketCommunicator(
            app, "/first/", headers=session_cookie(alice_session)
        )
        task = asyncio.create_task(first.connect())
        for _ in range(100):
            if blocking.is_set():
                break
            await asyncio.sleep(0.01)
        assert blocking.is_set()
        membership = captured["membership"]
        # "staff" was approved and submitted; "members" was never submitted.
        assert membership["submitted"] == ["observers", "staff"]
        assert membership["joined"] == ["observers", "staff"]

        first.future.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        for _ in range(100):
            if layer.groups == {}:
                break
            await asyncio.sleep(0.01)
        assert layer.groups == {}

        # The same declarations still work on a fresh connection.
        captured["release"] = True
        second = WebsocketCommunicator(
            app, "/second/", headers=session_cookie(alice_session)
        )
        assert (await second.connect())[0]
        assert set(layer.groups) == {"observers", "staff", "members"}
        await second.disconnect()
        assert layer.groups == {}
    finally:
        channel_layers.set(DEFAULT_CHANNEL_LAYER, previous)
