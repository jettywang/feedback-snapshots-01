"""Application-controlled admission for outbound TCP addresses.

An :class:`AddressAdmission` policy is consulted for every new connection
attempt. It receives the concrete candidates produced by resolution and,
after a socket connects, the concrete peer that won the Happy Eyeballs
race. This lets an application enforce policies on IP addresses rather
than on the host name string carried in a URL.

Authorization is scoped to one target and one resolution result. The
connector never retries an address that the policy did not admit, and a
custom ``socket_factory`` used with admission must explicitly declare that
it returns real sockets whose peer can be inspected.
"""

from __future__ import annotations

import inspect
import ipaddress
import socket
from collections.abc import Awaitable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from .abc import ResolveResult
from .client_exceptions import ClientConnectionError

__all__ = (
    "AddressAdmission",
    "AddressAdmissionError",
    "AllCandidatesRejectedError",
    "ConnectionTarget",
    "PeerRejectedError",
    "SocketFactoryPeerNotObservableError",
)


PeerAddress = tuple[Any, ...]


@dataclass(frozen=True, slots=True)
class ConnectionTarget:
    """The destination a connection attempt is authorized for.

    :param host: Host name or IP literal used for this connection.
    :param port: Port used for this connection.
    :param is_ssl: Whether this connection is wrapped in TLS.
    :param server_hostname: SNI override, if any.
    :param proxy: Proxy URL when this connection goes through a proxy.
    """

    host: str
    port: int
    is_ssl: bool
    server_hostname: str | None = None
    proxy: str | None = None


class AddressAdmissionError(ClientConnectionError):
    """Base class for failures caused by an address admission policy."""


class AllCandidatesRejectedError(AddressAdmissionError):
    """Raised when a policy rejects every resolved candidate."""

    def __init__(
        self, target: ConnectionTarget, candidates: Sequence[ResolveResult]
    ) -> None:
        self._target = target
        self._candidates = tuple(candidates)
        super().__init__(
            "Address admission rejected every candidate for "
            f"{target.host}:{target.port}"
        )

    @property
    def target(self) -> ConnectionTarget:
        """Target whose candidates were rejected."""
        return self._target

    @property
    def candidates(self) -> tuple[ResolveResult, ...]:
        """Resolution results presented to the policy."""
        return self._candidates


class PeerRejectedError(AddressAdmissionError):
    """Raised when a policy rejects the peer of a connected socket."""

    def __init__(
        self,
        target: ConnectionTarget,
        peer: PeerAddress,
        reason: str | None = None,
    ) -> None:
        self._target = target
        self._peer = tuple(peer)
        self._reason = reason
        message = (
            f"Address admission rejected peer {peer!r} for {target.host}:{target.port}"
        )
        if reason:
            message = f"{message}: {reason}"
        super().__init__(message)

    @property
    def target(self) -> ConnectionTarget:
        """Target whose peer was rejected."""
        return self._target

    @property
    def peer(self) -> PeerAddress:
        """Peer returned by ``socket.getpeername()``."""
        return self._peer

    @property
    def reason(self) -> str | None:
        """Optional policy-provided explanation."""
        return self._reason


class SocketFactoryPeerNotObservableError(AddressAdmissionError):
    """Raised when a custom socket factory cannot expose the final peer.

    Address admission can only be enforced when the connector can inspect
    the peer of the socket it connects. A custom ``socket_factory`` must
    opt in by setting ``observes_peer = True`` and must return a real
    socket whose ``getpeername()`` reports the peer the connector reached.
    """

    def __init__(self, factory: object | None = None) -> None:
        self._factory = factory
        super().__init__(
            "Address admission requires the connected peer to be observable, "
            "but the configured socket_factory does not declare that it "
            "returns such sockets. Set 'observes_peer = True' on the factory "
            "and return real sockets whose getpeername() reports the peer "
            "the connector reached."
        )

    @property
    def factory(self) -> object | None:
        """The factory that could not expose its peer, if known."""
        return self._factory


@runtime_checkable
class AddressAdmission(Protocol):
    """Application policy authorizing outbound addresses.

    Both methods may be synchronous or return awaitables. The connector
    calls ``admit_candidates`` after resolution (including DNS-cache
    results) and before opening any socket, then calls ``admit_peer`` on
    the socket that actually connected.
    """

    def admit_candidates(
        self, target: ConnectionTarget, candidates: Sequence[ResolveResult]
    ) -> (
        Awaitable[Sequence[ResolveResult] | bool | None]
        | Sequence[ResolveResult]
        | bool
        | None
    ):
        """Return the candidates admitted for this target.

        Return a subset of ``candidates`` to deny individual addresses,
        ``False`` to deny the whole resolution result, or ``True``/``None``
        to admit every candidate. Entries that were not part of
        ``candidates`` are ignored so a policy cannot inject an unchecked
        address. Returning an empty result fails the attempt with
        :class:`AllCandidatesRejectedError`.
        """
        ...

    def admit_peer(
        self, target: ConnectionTarget, peer: PeerAddress
    ) -> Awaitable[bool | None] | bool | None:
        """Confirm the peer of a connected socket.

        Return ``False`` to deny the peer, or ``True``/``None`` to admit
        it. Raising :class:`PeerRejectedError` is also supported. A denied
        socket is closed before TLS or HTTP work starts.
        """
        ...


async def await_if_needed(value: Any) -> Any:
    """Await *value* when it is awaitable, otherwise return it unchanged."""

    if inspect.isawaitable(value):
        return await value
    return value


def factory_observes_peer(factory: object | None) -> bool:
    """Return whether *factory* explicitly declares it exposes connected peers.

    Only the literal ``True`` opts in. This keeps a mock, a sentinel or any
    other truthy placeholder from silently claiming a capability the
    factory does not have.
    """

    return factory is None or getattr(factory, "observes_peer", False) is True


def _normalized_ip(value: str) -> object:
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return value
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _peer_port(peer: tuple[Any, ...]) -> int | None:
    if len(peer) < 2:
        return None
    try:
        return int(peer[1])
    except (TypeError, ValueError):
        return None


def peer_matches_candidates(
    peer: tuple[Any, ...], candidates: Sequence[ResolveResult]
) -> bool:
    """Return whether the connected peer is one of the admitted candidates.

    A socket factory or the operating system could otherwise connect to an
    address that was never presented to the admission policy. Both the
    normalized IP and the port must match a candidate.
    """

    if not peer:
        return False
    peer_host = _normalized_ip(str(peer[0]))
    peer_port = _peer_port(peer)
    for candidate in candidates:
        if _normalized_ip(str(candidate.get("host", ""))) != peer_host:
            continue
        if peer_port is not None and candidate.get("port") != peer_port:
            continue
        return True
    return False


def candidate_from_peer(
    target: ConnectionTarget, peer: tuple[Any, ...]
) -> ResolveResult:
    """Build the resolution-shaped record used to re-admit a pooled peer."""

    host = str(peer[0]) if peer else ""
    port = target.port
    if len(peer) > 1:
        try:
            port = int(peer[1])
        except (TypeError, ValueError):
            pass
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    return {
        "hostname": target.host,
        "host": host,
        "port": port,
        "family": family,
        "proto": 0,
        "flags": socket.AI_NUMERICHOST,
    }


def select_candidates(
    candidates: Sequence[ResolveResult], admitted: Any
) -> list[ResolveResult]:
    """Intersect a policy result with the candidates it was given.

    Only entries that correspond to an original resolution result are
    returned, in their original order. This prevents a policy from
    introducing an address that was never resolved and therefore never
    checked.
    """

    if admitted is None or admitted is True:
        return list(candidates)
    if admitted is False:
        return []
    if isinstance(admitted, (Mapping, str)):
        admitted = [admitted]

    # Index the original candidates by normalized host (and port when the
    # policy supplies one). Answers are then resolved back to the original
    # resolution records, so a policy cannot inject an unchecked address.
    index: dict[tuple[object, int | None], list[int]] = {}
    for position, candidate in enumerate(candidates):
        key = (
            _normalized_ip(str(candidate.get("host", ""))),
            candidate.get("port"),
        )
        index.setdefault(key, []).append(position)

    selected_positions: set[int] = set()
    used: dict[tuple[object, int | None], int] = {}
    for item in admitted:
        if isinstance(item, Mapping):
            host = _normalized_ip(str(item.get("host", "")))
            port = item.get("port")
        elif isinstance(item, str):
            host = _normalized_ip(item)
            port = None
        else:
            raise TypeError(
                "address admission candidates must be mapping objects or "
                f"IP strings, got {type(item).__name__}"
            )
        keys = (
            ((host, port),)
            if port is not None
            else tuple(key for key in index if key[0] == host)
        )
        for key in keys:
            positions = index.get(key)
            if not positions:
                continue
            offset = used.get(key, 0)
            if offset >= len(positions):
                continue
            used[key] = offset + 1
            selected_positions.add(positions[offset])
            break

    return [
        candidate
        for position, candidate in enumerate(candidates)
        if position in selected_positions
    ]
