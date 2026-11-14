"""Public objects describing tunnel requests and per-stream tunnel events."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .errors import RejectReason


@dataclass(frozen=True, kw_only=True)
class TunnelRequest:
    """The validated, immutable view of a CONNECT request handed to the app.

    ``protocol`` is ``None`` for an ordinary CONNECT and a lower-case string
    for an extended CONNECT (RFC 8441).
    """

    stream_id: int
    authority: str
    protocol: str | None
    scheme: str | None
    path: str | None
    headers: tuple[tuple[bytes, bytes], ...]


@dataclass(frozen=True, kw_only=True)
class TunnelEvent:
    """Base type for events emitted by :class:`H2ConnectAdapter`."""

    stream_id: int


@dataclass(frozen=True, kw_only=True)
class TunnelRequestReceived(TunnelEvent):
    """A non-CONNECT request arrived; the adapter does not manage this stream."""

    headers: tuple[tuple[bytes, bytes], ...]


@dataclass(frozen=True, kw_only=True)
class TunnelAccepted(TunnelEvent):
    """Authorization succeeded and exactly one target connection was made."""

    request: TunnelRequest
    target: Any


@dataclass(frozen=True, kw_only=True)
class TunnelRejected(TunnelEvent):
    """The stream was refused locally or by the app; no target was connected."""

    reason: RejectReason
    status_code: int
    detail: str = ""


@dataclass(frozen=True, kw_only=True)
class TunnelData(TunnelEvent):
    """Raw, byte-for-byte payload that belongs to an established tunnel."""

    data: bytes


@dataclass(frozen=True, kw_only=True)
class TunnelClosed(TunnelEvent):
    """The client half-closed the stream (END_STREAM); no more inbound data."""


@dataclass(frozen=True, kw_only=True)
class TunnelAborted(TunnelEvent):
    """The stream was reset or errored before or during tunneling."""

    error_code: int
    remote: bool
    target: Any = None


@dataclass(frozen=True, kw_only=True)
class TunnelFailed(TunnelEvent):
    """The target connector raised; the downstream connection was cleaned up."""

    error: BaseException


@dataclass(kw_only=True)
class _StreamState:
    """Mutable per-stream bookkeeping; never shared between streams."""

    stream_id: int
    request: TunnelRequest | None = None
    phase: str = "pending"  # pending | authorizing | open | closed
    target: Any = None
    buffered: list[bytes] = field(default_factory=list)
    buffered_len: int = 0
    half_closed: bool = False
