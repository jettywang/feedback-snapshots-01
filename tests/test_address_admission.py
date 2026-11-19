"""Address admission tests for TCPConnector.

Every test is hermetic: a fake resolver supplies candidate IPs and a fake
socket factory supplies connected socket stand-ins.  No real socket is
created, connected or bound.
"""

import asyncio
import socket
from collections.abc import Sequence
from typing import Any
from unittest import mock

import pytest
from yarl import URL

import aiohttp
from aiohttp import ClientTimeout, TCPConnector
from aiohttp.abc import AbstractResolver, ResolveResult
from aiohttp.address_admission import (
    AllCandidatesRejectedError,
    ConnectionTarget,
    PeerRejectedError,
    SocketFactoryPeerNotObservableError,
    select_candidates,
)
from aiohttp.client_reqrep import ConnectionKey
from aiohttp.connector import Connection

ALLOWED = "198.51.100.10"
DENIED = "198.51.100.20"
ALTERNATE = "198.51.100.30"
SECOND_HOST = "redirect.example"
PORT = 80


def result(host: str, port: int = PORT) -> ResolveResult:
    return {
        "hostname": "example.com",
        "host": host,
        "port": port,
        "family": socket.AF_INET,
        "proto": 0,
        "flags": socket.AI_NUMERICHOST,
    }


class ScriptedResolver(AbstractResolver):
    def __init__(self, *scripts: list[ResolveResult]) -> None:
        self._scripts = list(scripts)
        self.calls: list[tuple[str, int]] = []

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list[ResolveResult]:
        self.calls.append((host, port))
        if not self._scripts:
            raise AssertionError(f"unexpected resolution of {host!r}")
        return self._scripts.pop(0)

    async def close(self) -> None:
        return None


class FakeSocket:
    """Connected socket stand-in created by FakeFactory."""

    def __init__(self, addr_info: Any) -> None:
        self._peer = addr_info[4]
        self.family = addr_info[0]
        self.type = addr_info[1]
        self.proto = addr_info[2]
        self.closed = False

    def setblocking(self, _flag: bool) -> None:
        return None

    def setsockopt(self, *_args: Any) -> None:
        return None

    def bind(self, _addr: Any) -> None:
        return None

    async def connect(self, _addr: Any) -> None:
        await asyncio.sleep(0)

    def getpeername(self) -> tuple:
        return self._peer

    def close(self) -> None:
        self.closed = True


class FakeFactory:
    """Fake socket factory that records every candidate it dials."""

    observes_peer = True

    def __init__(self, denied: set[str] | None = None) -> None:
        self.denied = denied or set()
        self.attempted: list[tuple] = []
        self.sockets: list[FakeSocket] = []

    def __call__(self, addr_info: Any) -> FakeSocket:
        peer = addr_info[4]
        self.attempted.append(peer)
        if peer[0] in self.denied:
            raise OSError(f"connect refused for {peer[0]}")
        sock = FakeSocket(addr_info)
        self.sockets.append(sock)
        return sock


class Policy:
    """Records every consultation and filters by an allowed IP set."""

    def __init__(self, allowed: set[str]) -> None:
        self.allowed = set(allowed)
        self.candidate_calls: list[tuple[ConnectionTarget, tuple[str, ...]]] = []
        self.peer_calls: list[tuple[ConnectionTarget, tuple]] = []

    def admit_candidates(
        self, target: ConnectionTarget, candidates: Sequence[ResolveResult]
    ) -> list[ResolveResult]:
        self.candidate_calls.append((target, tuple(c["host"] for c in candidates)))
        return [c for c in candidates if c["host"] in self.allowed]

    def admit_peer(self, target: ConnectionTarget, peer: tuple) -> None:
        self.peer_calls.append((target, peer))
        if peer[0] not in self.allowed:
            raise PeerRejectedError(target, peer)


async def _install_transport(
    monkeypatch: pytest.MonkeyPatch, factory: FakeFactory
) -> None:
    """Make create_connection build a mock transport around the fake socket."""

    async def fake_create_connection(
        loop: Any, protocol_factory: Any, *args: Any, **kwargs: Any
    ) -> tuple[Any, Any]:
        proto = protocol_factory()
        sock = kwargs["sock"]
        transport = mock.MagicMock()
        transport.is_closing.return_value = False

        def close() -> None:
            sock.close()
            transport.is_closing.return_value = True

        transport.close.side_effect = close
        transport.abort.side_effect = close
        transport.get_extra_info.return_value = sock
        proto.connection_made(transport)
        return transport, proto

    async def fake_sock_connect(sock: Any, address: Any) -> None:
        await sock.connect(address)

    monkeypatch.setattr("aiohttp.connector.create_connection", fake_create_connection)
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "sock_connect", fake_sock_connect)


def make_connector(
    resolver: AbstractResolver,
    admission: Any,
    factory: Any | None = None,
    **kwargs: Any,
) -> TCPConnector:
    kwargs.setdefault("happy_eyeballs_delay", None)
    return TCPConnector(
        resolver=resolver,
        address_admission=admission,
        socket_factory=factory if factory is not None else FakeFactory(),
        **kwargs,
    )


async def _connect(
    connector: TCPConnector, make_client_request: Any, url: str = "http://example.com"
) -> Connection:
    req = make_client_request("GET", URL(url))
    return await connector.connect(req, [], ClientTimeout())


# ---------------------------------------------------------------------------
# Capability and API surface
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flag", [False, None, 0, "yes", mock.Mock()])
async def test_custom_factory_must_declare_peer_observation(flag: Any) -> None:
    class Factory:
        observes_peer = flag

        def __call__(self, addr_info: Any) -> socket.socket:
            raise AssertionError("must not be constructed during setup")

    with pytest.raises(SocketFactoryPeerNotObservableError):
        TCPConnector(socket_factory=Factory(), address_admission=Policy({ALLOWED}))


async def test_factory_without_admission_is_unconstrained() -> None:
    class Factory:
        def __call__(self, addr_info: Any) -> socket.socket:
            raise AssertionError("not used")

    connector = TCPConnector(socket_factory=Factory())
    assert connector.address_admission is None
    await connector.close()


async def test_both_alias_names_rejected() -> None:
    policy = Policy({ALLOWED})
    with pytest.raises(ValueError):
        TCPConnector(address_admission=policy, addr_admission=policy)


async def test_addr_admission_alias_selects_candidates(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    await _install_transport(monkeypatch, FakeFactory())
    factory = FakeFactory()
    connector = TCPConnector(
        resolver=ScriptedResolver([result(ALLOWED)]),
        addr_admission=Policy({ALLOWED}),
        socket_factory=factory,
        happy_eyeballs_delay=None,
    )
    conn = await _connect(connector, make_client_request)
    assert factory.attempted == [(ALLOWED, PORT)]
    conn.close()
    await connector.close()


# ---------------------------------------------------------------------------
# Candidate filtering, DNS cache and multiple candidates
# ---------------------------------------------------------------------------


async def test_denied_candidate_is_never_dialed(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)
    policy = Policy({ALLOWED})
    connector = make_connector(
        ScriptedResolver([result(DENIED), result(ALLOWED)]), policy, factory
    )
    conn = await _connect(connector, make_client_request)

    assert factory.attempted == [(ALLOWED, PORT)]
    target, candidates = policy.candidate_calls[0]
    assert target == ConnectionTarget("example.com", PORT, False, None, None)
    assert candidates == (DENIED, ALLOWED)
    assert policy.peer_calls == [(target, (ALLOWED, PORT))]
    conn.close()
    await connector.close()


async def test_all_candidates_rejected_never_touches_socket_factory(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)
    connector = make_connector(
        ScriptedResolver([result(DENIED), result(ALTERNATE)]),
        Policy({ALLOWED}),
        factory,
    )

    with pytest.raises(AllCandidatesRejectedError) as exc_info:
        await _connect(connector, make_client_request)

    assert factory.attempted == []
    assert [c["host"] for c in exc_info.value.candidates] == [DENIED, ALTERNATE]
    await connector.close()


async def test_policy_cannot_inject_unresolved_address(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)

    class InjectingPolicy:
        def admit_candidates(
            self, target: ConnectionTarget, candidates: Sequence[ResolveResult]
        ) -> Sequence[ResolveResult]:
            return [result(DENIED), *candidates]

        def admit_peer(self, target: ConnectionTarget, peer: tuple) -> None:
            return None

    connector = make_connector(
        ScriptedResolver([result(ALLOWED)]), InjectingPolicy(), factory
    )
    conn = await _connect(connector, make_client_request)

    assert factory.attempted == [(ALLOWED, PORT)]
    conn.close()
    await connector.close()


async def test_boolean_policy_answers(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)

    class AllowingPolicy:
        def admit_candidates(
            self, target: ConnectionTarget, candidates: Sequence[ResolveResult]
        ) -> bool:
            return True

        def admit_peer(self, target: ConnectionTarget, peer: tuple) -> None:
            return None

    connector = make_connector(
        ScriptedResolver([result(ALLOWED)]), AllowingPolicy(), factory
    )
    conn = await _connect(connector, make_client_request)
    assert factory.attempted == [(ALLOWED, PORT)]
    conn.close()
    await connector.close()


async def test_async_policy_is_awaited(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)

    class AsyncPolicy:
        def __init__(self) -> None:
            self.candidates = 0
            self.peers = 0

        async def admit_candidates(
            self, target: ConnectionTarget, candidates: Sequence[ResolveResult]
        ) -> Sequence[ResolveResult]:
            await asyncio.sleep(0)
            self.candidates += 1
            return candidates

        async def admit_peer(self, target: ConnectionTarget, peer: tuple) -> None:
            await asyncio.sleep(0)
            self.peers += 1

    policy = AsyncPolicy()
    connector = make_connector(ScriptedResolver([result(ALLOWED)]), policy, factory)
    conn = await _connect(connector, make_client_request)
    assert (policy.candidates, policy.peers) == (1, 1)
    conn.close()
    await connector.close()


async def test_dns_cache_result_is_filtered_on_every_connect(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)
    resolver = ScriptedResolver([result(DENIED), result(ALLOWED)])
    policy = Policy({ALLOWED})
    connector = make_connector(resolver, policy, factory, use_dns_cache=True)

    first = await _connect(connector, make_client_request)
    first.close()
    second = await _connect(connector, make_client_request)

    assert resolver.calls == [("example.com", PORT)]
    assert len(policy.candidate_calls) == 2
    assert all(peer[0] != DENIED for peer in factory.attempted)
    assert second is not None
    second.close()
    await connector.close()


async def test_changed_cache_result_is_re_admitted(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)
    resolver = ScriptedResolver([result(ALLOWED)], [result(DENIED), result(ALLOWED)])
    policy = Policy({ALLOWED})
    connector = make_connector(
        resolver, policy, factory, use_dns_cache=True, ttl_dns_cache=0
    )

    first = await _connect(connector, make_client_request)
    assert policy.candidate_calls[0][1] == (ALLOWED,)
    first.close()

    # The cache entry expires and the resolver now returns a denied address
    # first. It must be filtered before the rotation hands it to the dialer.
    connector.clear_dns_cache()
    second = await _connect(connector, make_client_request)

    assert policy.candidate_calls[1][1] == (DENIED, ALLOWED)
    assert all(peer[0] != DENIED for peer in factory.attempted)
    second.close()
    await connector.close()


# ---------------------------------------------------------------------------
# Happy Eyeballs and peer confirmation
# ---------------------------------------------------------------------------


async def test_happy_eyeballs_skips_denied_candidate(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)
    policy = Policy({ALLOWED, ALTERNATE})
    connector = make_connector(
        ScriptedResolver([result(DENIED), result(ALTERNATE), result(ALLOWED)]),
        policy,
        factory,
        happy_eyeballs_delay=0.01,
    )

    conn = await _connect(connector, make_client_request)

    dialed = {peer[0] for peer in factory.attempted}
    assert DENIED not in dialed
    assert dialed <= {ALLOWED, ALTERNATE}
    conn.close()
    await connector.close()


async def test_peer_rejection_closes_socket_and_tries_remaining(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)

    class RejectFirstPeer(Policy):
        def admit_peer(self, target: ConnectionTarget, peer: tuple) -> None:
            self.peer_calls.append((target, peer))
            if len(self.peer_calls) == 1:
                raise PeerRejectedError(target, peer)

    policy = RejectFirstPeer({ALLOWED, ALTERNATE})
    connector = make_connector(
        ScriptedResolver([result(ALTERNATE), result(ALLOWED)]), policy, factory
    )

    conn = await _connect(connector, make_client_request)

    assert factory.attempted == [(ALTERNATE, PORT), (ALLOWED, PORT)]
    assert factory.sockets[0].closed is True
    assert factory.sockets[1].closed is False
    conn.close()
    await connector.close()


async def test_false_peer_answer_rejects_connection(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    await _install_transport(monkeypatch, FakeFactory())
    factory = FakeFactory()

    class DenyPeer:
        def admit_candidates(
            self, target: ConnectionTarget, candidates: Sequence[ResolveResult]
        ) -> Sequence[ResolveResult]:
            return candidates

        def admit_peer(self, target: ConnectionTarget, peer: tuple) -> bool:
            return False

    connector = make_connector(ScriptedResolver([result(ALLOWED)]), DenyPeer(), factory)
    with pytest.raises(PeerRejectedError) as exc_info:
        await _connect(connector, make_client_request)
    assert exc_info.value.peer == (ALLOWED, PORT)
    assert factory.sockets[0].closed is True
    await connector.close()


async def test_last_rejected_peer_is_reported(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)

    class DenyEveryPeer:
        def admit_candidates(
            self, target: ConnectionTarget, candidates: Sequence[ResolveResult]
        ) -> Sequence[ResolveResult]:
            return candidates

        def admit_peer(self, target: ConnectionTarget, peer: tuple) -> None:
            raise PeerRejectedError(target, peer, "blocked")

    connector = make_connector(
        ScriptedResolver([result(ALLOWED)]), DenyEveryPeer(), factory
    )
    with pytest.raises(PeerRejectedError) as exc_info:
        await _connect(connector, make_client_request)
    assert exc_info.value.reason == "blocked"
    assert all(sock.closed for sock in factory.sockets)
    await connector.close()


# ---------------------------------------------------------------------------
# Redirect/target changes and pool reuse
# ---------------------------------------------------------------------------


async def test_new_target_gets_independent_admission(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)
    resolver = ScriptedResolver([result(ALLOWED, PORT)], [result(DENIED, 8080)])
    policy = Policy({ALLOWED})
    connector = make_connector(resolver, policy, factory)

    first = await _connect(connector, make_client_request)
    first.close()

    with pytest.raises(AllCandidatesRejectedError):
        await _connect(connector, make_client_request, "http://redirect.example:8080")

    assert [call[0].host for call in policy.candidate_calls] == [
        "example.com",
        "redirect.example",
    ]
    assert factory.attempted == [(ALLOWED, PORT)]
    await connector.close()


async def test_pooled_connection_is_reused_when_peer_still_admitted(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)
    policy = Policy({ALLOWED})
    connector = make_connector(ScriptedResolver([result(ALLOWED)]), policy, factory)

    first = await _connect(connector, make_client_request)
    sock = first.transport.get_extra_info("socket")
    first.release()
    second = await _connect(connector, make_client_request)

    assert second.transport.get_extra_info("socket") is sock
    assert len(factory.attempted) == 1
    assert len(policy.peer_calls) == 2
    second.close()
    await connector.close()


async def test_pooled_connection_is_discarded_when_policy_tightens(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)
    policy = Policy({ALLOWED, ALTERNATE})
    connector = make_connector(
        ScriptedResolver([result(ALLOWED)], [result(ALTERNATE)]), policy, factory
    )

    first = await _connect(connector, make_client_request)
    pooled_sock = first.transport.get_extra_info("socket")
    first.release()

    policy.allowed.discard(ALLOWED)
    connector.clear_dns_cache()
    second = await _connect(connector, make_client_request)

    assert pooled_sock.closed is True
    new_sock = second.transport.get_extra_info("socket")
    assert new_sock is not pooled_sock
    assert new_sock.getpeername() == (ALTERNATE, PORT)
    second.close()
    await connector.close()


async def test_pooled_connection_without_inspectable_socket_is_not_reused(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)
    connector = make_connector(
        ScriptedResolver([result(ALLOWED)], [result(ALTERNATE)]),
        Policy({ALLOWED, ALTERNATE}),
        factory,
    )

    first = await _connect(connector, make_client_request)
    pooled_sock = first.transport.get_extra_info("socket")
    first.protocol.transport.get_extra_info = lambda name: None
    first.release()

    second = await _connect(connector, make_client_request)
    assert second.transport.get_extra_info("socket") is not pooled_sock
    second.close()
    await connector.close()


# ---------------------------------------------------------------------------
# Existing connection policy is preserved without admission
# ---------------------------------------------------------------------------


async def test_no_policy_keeps_regular_pooling(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)
    connector = TCPConnector(
        resolver=ScriptedResolver([result(ALLOWED)]),
        socket_factory=factory,
        happy_eyeballs_delay=None,
    )

    first = await _connect(connector, make_client_request)
    sock = first.transport.get_extra_info("socket")
    first.release()
    second = await _connect(connector, make_client_request)

    assert second.transport.get_extra_info("socket") is sock
    assert connector.address_admission is None
    second.close()
    await connector.close()


def test_select_candidates_preserves_input_order_and_duplicates() -> None:
    candidates = [result(ALLOWED), result(DENIED), result(ALLOWED)]
    admitted = [result(ALLOWED)]
    assert select_candidates(candidates, admitted) == [result(ALLOWED)]


async def test_runtime_unobservable_peer_is_reported(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    class OpaqueSocket:
        observes_peer = True

        def __call__(self, addr_info: Any) -> FakeSocket:
            sock = FakeSocket(addr_info)
            sock.getpeername = mock.Mock(  # type: ignore[method-assign]
                side_effect=OSError("not connected")
            )
            return sock

    factory = OpaqueSocket()
    await _install_transport(monkeypatch, factory)
    connector = make_connector(
        ScriptedResolver([result(ALLOWED)]), Policy({ALLOWED}), factory
    )
    with pytest.raises(SocketFactoryPeerNotObservableError):
        await _connect(connector, make_client_request)
    await connector.close()


async def test_peer_not_in_resolved_candidates_is_rejected(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    class SwappingSocket(FakeSocket):
        def __init__(self, addr_info: Any) -> None:
            super().__init__(addr_info)
            self._peer = (DENIED, PORT)

    class SwappingFactory(FakeFactory):
        observes_peer = True

        def __call__(self, addr_info: Any) -> FakeSocket:
            self.attempted.append(addr_info[4])
            sock = SwappingSocket(addr_info)
            self.sockets.append(sock)
            return sock

    factory = SwappingFactory()
    await _install_transport(monkeypatch, factory)
    connector = make_connector(
        ScriptedResolver([result(ALLOWED)]), Policy({ALLOWED, DENIED}), factory
    )
    with pytest.raises(PeerRejectedError) as exc_info:
        await _connect(connector, make_client_request)
    assert exc_info.value.peer == (DENIED, PORT)
    assert factory.sockets[0].closed is True
    await connector.close()


async def test_peer_admission_uses_actual_connected_port(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    calls: list[tuple] = []

    class PortPolicy(Policy):
        def admit_peer(self, target: ConnectionTarget, peer: tuple) -> None:
            calls.append(peer)
            self.peer_calls.append((target, peer))

    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)
    connector = make_connector(
        ScriptedResolver([result(ALLOWED)]), PortPolicy({ALLOWED}), factory
    )
    conn = await _connect(connector, make_client_request)
    assert calls == [(ALLOWED, PORT)]
    conn.close()
    await connector.close()


async def test_base_connector_pool_has_no_admission_side_effects(
    make_client_request: Any,
) -> None:
    connector = aiohttp.BaseConnector()
    proto = mock.MagicMock()
    proto.is_connected.return_value = True
    key = ConnectionKey("example.com", PORT, False, True, None, None)
    connector._conns[key].append((proto, asyncio.get_running_loop().time()))

    conn = await connector._get_for_request(
        key, [], make_client_request("GET", URL("http://example.com"))
    )

    assert conn is not None
    assert conn.protocol is proto
    conn.close()
    await connector.close()


async def test_pool_admission_error_closes_connection(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)

    class RaisingPoolPolicy(Policy):
        def admit_peer(self, target: ConnectionTarget, peer: tuple) -> None:
            if self.peer_calls:
                raise RuntimeError("policy failure")
            super().admit_peer(target, peer)

    policy = RaisingPoolPolicy({ALLOWED})
    connector = make_connector(ScriptedResolver([result(ALLOWED)]), policy, factory)
    first = await _connect(connector, make_client_request)
    first.release()

    with pytest.raises(RuntimeError, match="policy failure"):
        await _connect(connector, make_client_request)
    await connector.close()


async def test_proxy_target_is_the_dialed_proxy_endpoint(
    monkeypatch: pytest.MonkeyPatch, make_client_request: Any
) -> None:
    factory = FakeFactory()
    await _install_transport(monkeypatch, factory)
    resolver = ScriptedResolver([result(ALLOWED)])
    policy = Policy({ALLOWED})
    connector = make_connector(resolver, policy, factory)

    req = make_client_request(
        "GET",
        URL("http://origin.example"),
        proxy=URL("http://proxy.example:3128"),
    )
    conn = await connector.connect(req, [], ClientTimeout())

    target, candidates = policy.candidate_calls[0]
    assert target == ConnectionTarget(
        "proxy.example", 3128, False, None, "http://proxy.example:3128"
    )
    assert candidates == (ALLOWED,)
    assert factory.attempted == [(ALLOWED, PORT)]
    assert policy.peer_calls == [(target, (ALLOWED, PORT))]
    conn.close()
    await connector.close()
