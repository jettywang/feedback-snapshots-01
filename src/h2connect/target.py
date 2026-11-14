"""Target connector protocol plus an in-memory fake for tests and dry runs."""

from __future__ import annotations

from collections import deque
from collections.abc import Collection
from dataclasses import dataclass, field
from typing import Protocol

from .errors import TargetConnectionError
from .events import TunnelRequest


class TargetConnector(Protocol):
    """Callable that opens exactly one downstream connection for a request."""

    def __call__(self, request: TunnelRequest) -> "TargetHandle": ...


@dataclass
class TargetHandle:
    """A downstream connection handle.

    Concrete deployments wrap a socket here. The handle owns the lifecycle of
    the downstream connection: ``send`` writes bytes toward the target and
    ``close``/``abort`` release it without leaving dangling connections.
    """

    request: TunnelRequest
    sink: "FakeTarget | None" = None

    def send(self, data: bytes) -> None:
        if self.sink is not None:
            self.sink.ingress.append(data)

    def close(self) -> None:
        if self.sink is not None:
            self.sink.closed = True

    def abort(self) -> None:
        if self.sink is not None:
            self.sink.aborted = True
            self.sink.closed = True


@dataclass
class FakeTarget:
    """Records what the adapter did with one fake downstream connection."""

    request: TunnelRequest
    ingress: deque[bytes] = field(default_factory=deque)
    closed: bool = False
    aborted: bool = False

    @property
    def received(self) -> bytes:
        return b"".join(self.ingress)


class FakeTargetConnector:
    """Connector test double: counts connection attempts per request.

    A request whose authority appears in ``deny`` raises
    :class:`TargetConnectionError`, simulating an unreachable target. The
    connector is only ever invoked *after* local validation and application
    authorization have both succeeded, so refused requests never reach it.
    """

    def __init__(self, deny: Collection[str] | None = None) -> None:
        self.deny = set(deny or ())
        self.calls: list[TunnelRequest] = []
        self.targets: dict[int, FakeTarget] = {}

    @property
    def connection_count(self) -> int:
        return len(self.calls)

    def __call__(self, request: TunnelRequest) -> TargetHandle:
        self.calls.append(request)
        if request.authority in self.deny:
            raise TargetConnectionError(f"target refused: {request.authority}")
        target = FakeTarget(request=request)
        self.targets[request.stream_id] = target
        return TargetHandle(request=request, sink=target)
