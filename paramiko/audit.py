"""
Structured security-audit events for SSH transport handshakes.

This module defines :class:`AuditEvent`, the payload delivered to a
transport's audit hook (see ``Transport.set_audit_hook``).  Events are
emitted along the real handshake and rekey code paths so that an auditor
can reconstruct, for every stage of an SSH session, exactly which
algorithms were offered, which were agreed, which host identity was
verified, and when each direction's packet protection actually changed.

Only public, non-secret information is ever placed in an event: algorithm
names, host key *fingerprints*, verification decisions, and the session
identifier.  Private keys, key-exchange shared secrets, and derived
session keys never appear in any event field.
"""

from dataclasses import dataclass, field
from typing import Any, Dict


# Event types, in the order they occur during a successful handshake.
#: Both sides' KEXINIT algorithm candidate lists, as sent on the wire.
AUDIT_KEX_PROPOSALS = "kex-proposals"
#: The final negotiated algorithms for both directions.
AUDIT_KEX_AGREEMENT = "kex-agreement"
#: Host key fingerprint and the signature verification decision.
AUDIT_HOST_KEY = "host-key"
#: Newly negotiated keys took effect in one direction (inbound/outbound).
AUDIT_KEYS_ACTIVATED = "keys-activated"
#: A handshake (initial or rekey) completed; both directions protected.
AUDIT_HANDSHAKE_COMPLETE = "handshake-complete"
#: A handshake failed; carries the last confirmed stage, never success.
AUDIT_HANDSHAKE_FAILED = "handshake-failed"

AUDIT_EVENT_TYPES = (
    AUDIT_KEX_PROPOSALS,
    AUDIT_KEX_AGREEMENT,
    AUDIT_HOST_KEY,
    AUDIT_KEYS_ACTIVATED,
    AUDIT_HANDSHAKE_COMPLETE,
    AUDIT_HANDSHAKE_FAILED,
)

#: Phase tag for the very first key exchange on a connection.
PHASE_INITIAL = "initial"
#: Phase tag for every subsequent (rekey) exchange; the session
#: identifier never changes across these.
PHASE_REKEY = "rekey"


@dataclass(frozen=True)
class AuditEvent:
    """
    A single structured audit record.

    ``type`` is one of the ``AUDIT_*`` constants; ``phase`` is
    ``"initial"`` for the first key exchange and ``"rekey"`` for all
    later ones; ``details`` holds type-specific, non-secret fields
    (algorithm names, fingerprints, directions, the session identifier,
    error descriptions).
    """

    type: str
    phase: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain-``dict`` copy suitable for JSON serialization."""
        return {
            "type": self.type,
            "phase": self.phase,
            "details": dict(self.details),
        }

    def __repr__(self):
        return "AuditEvent(type={!r}, phase={!r}, details={!r})".format(
            self.type, self.phase, self.details
        )
