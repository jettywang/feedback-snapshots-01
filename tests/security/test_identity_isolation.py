"""Runtime isolation regressions for ASGI identity handling.

These tests deliberately use low-level in-memory communicators so that the
exact scope template and scheduling of each connection are observable.
"""

import asyncio
import json

import pytest
from django.urls import path
from django.utils.functional import LazyObject

from channels import auth as channels_auth
from channels.auth import AuthMiddleware, UserLazyObject
from channels.routing import URLRouter
from channels.testing import ApplicationCommunicator


CONNECT = {"type": "websocket.connect"}
SCOPE_REQUEST = {"type": "websocket.receive", "text": "scope"}
DISCONNECT = {"type": "websocket.disconnect", "code": 1000}


class AsyncBarrier:
    """Small Python 3.10-compatible barrier for deterministic scheduling."""

    def __init__(self, parties):
        self.parties = parties
        self.waiting = 0
        self.release = asyncio.Event()

    async def wait(self):
        self.waiting += 1
        if self.waiting == self.parties:
            self.release.set()
        await self.release.wait()


SCOPE_TEMPLATE = {
    "type": "websocket",
    "path": "/w/template/rooms/lobby/",
    "headers": [(b"host", b"identity-isolation.test")],
}


class Principal:
    def __init__(self, name):
        self.name = name
        self.username = name
        self.is_authenticated = True

    def get_username(self):
        return self.name


class IdentityWrapper(LazyObject):
    """Application-provided explicit identity, distinct from scope['user']."""

    def __init__(self, principal):
        super().__init__()
        self.__dict__["label"] = principal.name
        self.__dict__["bindings"] = []
        self._wrapped = principal

    def bind(self, connection_id):
        self.bindings.append(connection_id)
        return self


class SharedIdentityDouble(IdentityWrapper):
    """Canary that fails when one connection uses another connection's wrapper."""

    def __init__(self, principal, owner):
        super().__init__(principal)
        self.__dict__["owner"] = owner

    def bind(self, connection_id):
        assert connection_id == self.owner, (
            "deliberately shared identity wrapper was claimed by "
            f"{connection_id!r}; its owner is {self.owner!r}"
        )
        return super().bind(connection_id)


class IdentityGuardMiddleware:
    """Test version of the application's custom ASGI identity component."""

    def __init__(self, inner, observed_scopes=None):
        self.inner = inner
        self.observed_scopes = observed_scopes if observed_scopes is not None else []

    async def __call__(self, scope, receive, send):
        self.observed_scopes.append(scope)
        barrier = scope.get("identity_barrier")
        if barrier is not None:
            await barrier.wait()

        identity = scope.get("identity")
        if identity is not None:
            identity.bind(scope["connection_id"])

        return await self.inner(scope, receive, send)


class IdentityScopeEndpoint:
    def __init__(self, seen_scopes):
        self.seen_scopes = seen_scopes

    async def __call__(self, scope, receive, send):
        connect = await receive()
        assert connect["type"] == "websocket.connect"

        self.seen_scopes.append(scope)
        await send({"type": "websocket.accept"})

        while True:
            event = await receive()
            if event["type"] == "websocket.disconnect":
                return
            if event["type"] != "websocket.receive":
                continue

            user = scope["user"]
            identity = scope.get("identity")
            await send(
                {
                    "type": "websocket.send",
                    "text": json.dumps(
                        {
                            "connection_id": scope["connection_id"],
                            "scope_id": id(scope),
                            "who": scope["url_route"]["kwargs"]["who"],
                            "room": scope["url_route"]["kwargs"]["room"],
                            "explicit_identity": identity.label if identity else None,
                            "auth_user": user.username,
                            "auth_authenticated": user.is_authenticated,
                            "auth_user_is_lazy": isinstance(user, UserLazyObject),
                        }
                    ),
                }
            )


class FakeAuthResolver:
    def __init__(self, monkeypatch):
        self.principals = {}
        self.calls = []
        self.barrier = None
        monkeypatch.setattr(channels_auth, "get_user", self)

    async def __call__(self, scope):
        connection_id = scope["connection_id"]
        self.calls.append(connection_id)
        if self.barrier is not None:
            await self.barrier.wait()

        principal = self.principals[connection_id]
        if isinstance(principal, BaseException):
            raise principal
        return principal


def build_application(seen_scopes, guard_scopes=None):
    endpoint = IdentityScopeEndpoint(seen_scopes)
    inner_router = URLRouter([path("rooms/<str:room>/", endpoint)])
    outer_router = URLRouter([path("w/<str:who>/", inner_router)])
    identity_guard = IdentityGuardMiddleware(outer_router, guard_scopes)
    return AuthMiddleware(identity_guard)


def make_scope(connection_id, identity, *, barrier=None):
    scope = dict(SCOPE_TEMPLATE)
    scope["headers"] = list(SCOPE_TEMPLATE["headers"])
    scope["path"] = f"/w/{connection_id}/rooms/lobby/"
    scope["connection_id"] = connection_id
    scope["session"] = {}
    scope["identity"] = identity
    if barrier is not None:
        scope["identity_barrier"] = barrier
    return scope


def make_communicator(
    connection_id, identity, seen_scopes, *, barrier=None, guard_scopes=None
):
    return ApplicationCommunicator(
        build_application(seen_scopes, guard_scopes),
        make_scope(connection_id, identity, barrier=barrier),
    )


async def complete_connection(communicator):
    await communicator.send_input(CONNECT)
    accepted = await communicator.receive_output(timeout=1)
    assert accepted == {"type": "websocket.accept"}

    await communicator.send_input(SCOPE_REQUEST)
    message = await communicator.receive_output(timeout=1)
    assert message["type"] == "websocket.send"
    snapshot = json.loads(message["text"])

    await communicator.send_input(DISCONNECT)
    await communicator.wait(timeout=1)
    return snapshot


async def expect_failure(communicator, exception_type, match):
    with pytest.raises(exception_type, match=match):
        await communicator.send_input(CONNECT)
        await communicator.wait(timeout=1)


def effective_scope(seen_scopes, connection_id):
    return next(
        scope for scope in seen_scopes if scope["connection_id"] == connection_id
    )


def test_unresolved_lazy_user_reports_setup_error():
    lazy_user = UserLazyObject()

    with pytest.raises(ValueError, match="Accessing scope user before it is ready"):
        lazy_user.username


@pytest.fixture
def auth_resolver(monkeypatch):
    return FakeAuthResolver(monkeypatch)


@pytest.mark.asyncio
async def test_nested_urlrouter_scope_separates_explicit_and_auth_identity(
    auth_resolver,
):
    seen_scopes = []
    guard_scopes = []
    auth_resolver.principals["alice"] = Principal("auth-alice")
    explicit_identity = IdentityWrapper(Principal("explicit-alice"))
    communicator = make_communicator(
        "alice",
        explicit_identity,
        seen_scopes,
        guard_scopes=guard_scopes,
    )

    snapshot = await complete_connection(communicator)

    assert snapshot["connection_id"] == "alice"
    assert snapshot["who"] == "alice"
    assert snapshot["room"] == "lobby"
    assert snapshot["explicit_identity"] == "explicit-alice"
    assert snapshot["auth_user"] == "auth-alice"
    assert snapshot["auth_authenticated"] is True
    assert snapshot["auth_user_is_lazy"] is True

    scope = effective_scope(seen_scopes, "alice")
    assert scope["url_route"]["kwargs"] == {"who": "alice", "room": "lobby"}
    assert scope["identity"] is explicit_identity
    assert isinstance(scope["user"], UserLazyObject)
    assert scope["user"]._wrapped is auth_resolver.principals["alice"]
    assert scope["user"].username == "auth-alice"
    assert scope["path_remaining"] == ""

    # AuthMiddleware and URLRouter pass copied scopes inward.
    assert "path_remaining" not in guard_scopes[0]
    assert guard_scopes[0] is not scope
    assert guard_scopes[0]["user"] is scope["user"]
    assert "user" not in communicator.scope
    assert scope is not communicator.scope


@pytest.mark.asyncio
async def test_real_auth_middleware_resolves_anonymous_session():
    seen_scopes = []
    identity = IdentityWrapper(Principal("explicit-anonymous"))
    communicator = make_communicator("anonymous", identity, seen_scopes)

    snapshot = await complete_connection(communicator)

    assert snapshot["explicit_identity"] == "explicit-anonymous"
    assert snapshot["auth_authenticated"] is False
    assert snapshot["auth_user_is_lazy"] is True
    scope = effective_scope(seen_scopes, "anonymous")
    assert scope["user"].is_anonymous is True


@pytest.mark.asyncio
async def test_same_input_scope_template_runs_two_independent_connections(
    auth_resolver,
):
    seen_scopes = []
    auth_resolver.principals["twin"] = Principal("auth-twin")
    auth_resolver.barrier = AsyncBarrier(2)

    shared_scope = make_scope("twin", IdentityWrapper(Principal("explicit-twin")))
    first = ApplicationCommunicator(build_application(seen_scopes), shared_scope)
    second = ApplicationCommunicator(build_application(seen_scopes), shared_scope)

    first_snapshot, second_snapshot = await asyncio.gather(
        complete_connection(first),
        complete_connection(second),
    )

    assert first_snapshot["connection_id"] == "twin"
    assert second_snapshot["connection_id"] == "twin"
    assert first_snapshot["scope_id"] != second_snapshot["scope_id"]
    assert first_snapshot["auth_user"] == "auth-twin"
    assert second_snapshot["auth_user"] == "auth-twin"

    first_scope, second_scope = seen_scopes
    assert first_scope is not second_scope
    assert first_scope["user"] is not second_scope["user"]
    assert first_scope["url_route"] is not second_scope["url_route"]
    assert "user" not in shared_scope


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "order",
    ["failure-first", "success-first", "interleaved"],
)
async def test_authentication_failure_does_not_change_other_identity(
    auth_resolver, order
):
    seen_scopes = []
    good_identity = IdentityWrapper(Principal("explicit-good"))
    good = make_communicator("good", good_identity, seen_scopes)
    bad_identity = IdentityWrapper(Principal("explicit-bad"))
    bad = make_communicator("bad", bad_identity, seen_scopes)

    auth_resolver.principals["good"] = Principal("auth-good")
    auth_resolver.principals["bad"] = PermissionError("authentication rejected")
    if order == "interleaved":
        auth_resolver.barrier = AsyncBarrier(2)

    if order == "failure-first":
        await expect_failure(bad, PermissionError, "authentication rejected")
        snapshot = await complete_connection(good)
    elif order == "success-first":
        snapshot = await complete_connection(good)
        await expect_failure(bad, PermissionError, "authentication rejected")
    else:
        bad_result, snapshot = await asyncio.gather(
            expect_failure(bad, PermissionError, "authentication rejected"),
            complete_connection(good),
        )
        assert bad_result is None

    assert snapshot["explicit_identity"] == "explicit-good"
    assert snapshot["auth_user"] == "auth-good"
    good_scope = effective_scope(seen_scopes, "good")
    assert good_scope["identity"] is good_identity
    assert good_scope["user"]._wrapped.name == "auth-good"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "order",
    ["assertion-first", "success-first", "interleaved"],
)
async def test_shared_identity_wrapper_assertion_is_contained(
    auth_resolver, order
):
    seen_scopes = []
    shared_identity = SharedIdentityDouble(
        Principal("shared-explicit"), owner="good"
    )
    barrier = AsyncBarrier(2) if order == "interleaved" else None
    bad = make_communicator(
        "intruder", shared_identity, seen_scopes, barrier=barrier
    )
    good = make_communicator(
        "good", shared_identity, seen_scopes, barrier=barrier
    )

    auth_resolver.principals["good"] = Principal("auth-good")
    auth_resolver.principals["intruder"] = Principal("auth-intruder")

    if order == "assertion-first":
        await expect_failure(bad, AssertionError, "was claimed by 'intruder'")
        snapshot = await complete_connection(good)
    elif order == "success-first":
        snapshot = await complete_connection(good)
        await expect_failure(bad, AssertionError, "was claimed by 'intruder'")
    else:
        bad_result, snapshot = await asyncio.gather(
            expect_failure(bad, AssertionError, "was claimed by 'intruder'"),
            complete_connection(good),
        )
        assert bad_result is None

    assert snapshot["explicit_identity"] == "shared-explicit"
    assert snapshot["auth_user"] == "auth-good"
    assert shared_identity.bindings == ["good"]

    good_scope = effective_scope(seen_scopes, "good")
    assert good_scope["identity"] is shared_identity
    assert good_scope["user"]._wrapped.name == "auth-good"
