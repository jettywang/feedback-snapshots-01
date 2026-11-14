"""Domain errors raised by the extended CONNECT ingress adapter."""

from __future__ import annotations

import enum


class RejectReason(enum.Enum):
    """Why a CONNECT stream was refused before any target connection was made."""

    NOT_CONNECT = "not-connect"
    #: The request used :protocol but the peer never enabled the setting.
    CONNECT_PROTOCOL_DISABLED = "connect-protocol-disabled"
    #: :protocol named a protocol that is not in the adapter allow list.
    UNKNOWN_PROTOCOL = "unknown-protocol"
    #: Ordinary/extended CONNECT shape rules from RFC 9113 were violated.
    PSEUDO_HEADER_VIOLATION = "pseudo-header-violation"
    #: Negotiation preconditions for the chosen protocol were not met.
    NEGOTIATION_FAILED = "negotiation-failed"
    #: The application authorizer denied the target.
    UNAUTHORIZED = "unauthorized"
    #: The application authorizer itself raised unexpectedly.
    AUTHORIZER_ERROR = "authorizer-error"


class TunnelError(Exception):
    """Base class for adapter-level errors."""


class ProtocolRejected(TunnelError):
    """Raised internally when a request fails local protocol validation."""

    def __init__(self, reason: RejectReason, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason.value}: {detail}" if detail else reason.value)


class AuthorizationError(TunnelError):
    """Raised by an authorizer to deny a tunnel request."""


class TargetConnectionError(TunnelError):
    """Raised by a target connector when the downstream target cannot open."""
