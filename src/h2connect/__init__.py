"""Ingress adapter for ordinary and extended HTTP/2 CONNECT tunneling."""

from __future__ import annotations

from .adapter import H2ConnectAdapter, TunnelProtocolError
from .errors import (
    AuthorizationError,
    ProtocolRejected,
    RejectReason,
    TargetConnectionError,
    TunnelError,
)
from .events import (
    TunnelAborted,
    TunnelAccepted,
    TunnelClosed,
    TunnelData,
    TunnelEvent,
    TunnelFailed,
    TunnelRejected,
    TunnelRequest,
    TunnelRequestReceived,
)
from .protocols import ProtocolPolicy, ProtocolRegistry
from .target import FakeTarget, FakeTargetConnector, TargetHandle, TargetConnector

__all__ = [
    "H2ConnectAdapter",
    "TunnelProtocolError",
    "AuthorizationError",
    "ProtocolRejected",
    "RejectReason",
    "TargetConnectionError",
    "TunnelError",
    "TunnelAborted",
    "TunnelAccepted",
    "TunnelClosed",
    "TunnelData",
    "TunnelEvent",
    "TunnelFailed",
    "TunnelRejected",
    "TunnelRequest",
    "TunnelRequestReceived",
    "ProtocolPolicy",
    "ProtocolRegistry",
    "FakeTarget",
    "FakeTargetConnector",
    "TargetHandle",
    "TargetConnector",
]
