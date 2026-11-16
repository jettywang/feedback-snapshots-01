"""Offline, host-independent discretionary access decision auditing.

This module answers a narrow question:

    Given an explicit token SID set, an object type and a requested access
    mask, what can the DACL of a parsed NTFS security descriptor *prove*
    about the decision?

It deliberately does **not** read the current host user, the host's privilege
set, group memberships, logon session data or claims. Everything needed for an
evaluation must be supplied by the caller. When the descriptor contains an ACE
that cannot be fully evaluated from that supplied context (callback/conditional
ACEs, compound ACEs, property-scoped object ACEs, central access policies,
privilege-only rights), the result is :data:`Decision.UNDECIDED` rather than a
silently optimistic allow.

The implementation follows the discretionary (DACL) portion of the Windows
access check algorithm as documented in MS-DTYP and the Windows SDK:

* generic rights are mapped to object-specific standard/specific rights first;
* ACEs are examined in their stored order;
* deny ACEs take effect at the position they appear in;
* inherit-only ACEs do not apply to the object itself;
* a ``NULL`` DACL and an empty DACL are different states.

Only the DACL is modelled. See :data:`AccessDecision.coverage` and the module
README for the Windows semantics that this interface deliberately cannot cover.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.sid import write_sid

from dissect.ntfs.c_ntfs import ACE_TYPE, c_ntfs
from dissect.ntfs.secure import ACE, SecurityDescriptor

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

__all__ = [
    "ACCESS_SYSTEM_SECURITY",
    "MAXIMUM_ALLOWED",
    "Decision",
    "ObjectType",
    "AceSpec",
    "AccessDecision",
    "TraceEntry",
    "build_descriptor",
    "build_null_dacl_descriptor",
    "build_empty_dacl_descriptor",
    "evaluate_descriptor",
    "evaluate_descriptor_bytes",
    "map_generic_access",
    "mask_names",
]

# Single bit values we need directly.
ACCESS_SYSTEM_SECURITY = 0x01000000
MAXIMUM_ALLOWED = 0x02000000
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
GENERIC_EXECUTE = 0x20000000
GENERIC_ALL = 0x10000000
GENERIC_MASK = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000

# The well-known OWNER RIGHTS SID. When present in a DACL it overrides the
# implicit READ_CONTROL/WRITE_DAC normally granted to the owner.
OWNER_RIGHTS_SID = "S-1-3-4"

# Generic mapping for file and directory objects (Winnt.h FILE_GENERIC_* /
# FILE_ALL_ACCESS). NTFS files and directories share the same mapping.
_FILE_GENERIC_MAPPING = {
    GENERIC_READ: 0x120089,
    GENERIC_WRITE: 0x116,
    GENERIC_EXECUTE: 0x1200A0,
    GENERIC_ALL: 0x1F01FF,
}


class ObjectType(str, Enum):
    """Object types whose generic-right mapping is known to this module."""

    FILE = "file"
    DIRECTORY = "directory"


_GENERIC_MAPPINGS = {
    ObjectType.FILE: _FILE_GENERIC_MAPPING,
    ObjectType.DIRECTORY: _FILE_GENERIC_MAPPING,
}


class Decision(str, Enum):
    """Three-valued outcome of an offline DACL evaluation.

    Attributes:
        ALLOW: The DACL proves every requested (non-privilege) bit is granted.
        DENY: The DACL proves at least one requested bit is denied or not
            granted. This is a hard result, even when other ACEs are
            unevaluable.
        UNDECIDED: At least one applicable ACE cannot be evaluated with the
            supplied context and a definite allow cannot be proven.
    """

    ALLOW = "allow"
    DENY = "deny"
    UNDECIDED = "undecided"


# Names for individual access mask bits, roughly MS-DTYP / Winnt.h order.
_BIT_NAMES = {
    0x00000001: "FILE_READ_DATA/FILE_LIST_DIRECTORY",
    0x00000002: "FILE_WRITE_DATA/FILE_ADD_FILE",
    0x00000004: "FILE_APPEND_DATA/FILE_ADD_SUBDIRECTORY",
    0x00000008: "FILE_READ_EA",
    0x00000010: "FILE_WRITE_EA",
    0x00000020: "FILE_EXECUTE/FILE_TRAVERSE",
    0x00000040: "FILE_DELETE_CHILD",
    0x00000080: "FILE_READ_ATTRIBUTES",
    0x00000100: "FILE_WRITE_ATTRIBUTES",
    0x00010000: "DELETE",
    0x00020000: "READ_CONTROL",
    0x00040000: "WRITE_DAC",
    0x00080000: "WRITE_OWNER",
    0x00100000: "SYNCHRONIZE",
    0x01000000: "ACCESS_SYSTEM_SECURITY",
    0x02000000: "MAXIMUM_ALLOWED",
    0x10000000: "GENERIC_ALL",
    0x20000000: "GENERIC_EXECUTE",
    0x40000000: "GENERIC_WRITE",
    0x80000000: "GENERIC_READ",
}

# ACE types that participate in the discretionary access check.
_DENY_TYPES = frozenset(
    {
        ACE_TYPE.ACCESS_DENIED,
        ACE_TYPE.ACCESS_DENIED_OBJECT,
        ACE_TYPE.ACCESS_DENIED_CALLBACK,
        ACE_TYPE.ACCESS_DENIED_CALLBACK_OBJECT,
    }
)
_ALLOW_TYPES = frozenset(
    {
        ACE_TYPE.ACCESS_ALLOWED,
        ACE_TYPE.ACCESS_ALLOWED_OBJECT,
        ACE_TYPE.ACCESS_ALLOWED_CALLBACK,
        ACE_TYPE.ACCESS_ALLOWED_CALLBACK_OBJECT,
        ACE_TYPE.ACCESS_ALLOWED_COMPOUND,
    }
)
_CALLBACK_TYPES = frozenset(
    {
        ACE_TYPE.ACCESS_ALLOWED_CALLBACK,
        ACE_TYPE.ACCESS_DENIED_CALLBACK,
        ACE_TYPE.ACCESS_ALLOWED_CALLBACK_OBJECT,
        ACE_TYPE.ACCESS_DENIED_CALLBACK_OBJECT,
    }
)
_OBJECT_TYPES = frozenset(
    {
        ACE_TYPE.ACCESS_ALLOWED_OBJECT,
        ACE_TYPE.ACCESS_DENIED_OBJECT,
        ACE_TYPE.ACCESS_ALLOWED_CALLBACK_OBJECT,
        ACE_TYPE.ACCESS_DENIED_CALLBACK_OBJECT,
    }
)


def mask_names(mask: int) -> list[str]:
    """Return the human-readable names of the single bits set in ``mask``."""
    return [name for bit, name in _BIT_NAMES.items() if mask & bit]


def map_generic_access(mask: int, object_type: ObjectType | str) -> int:
    """Map the generic bits of an access mask to file/directory rights.

    Generic bits are replaced by their mapped standard/specific bits while all
    already-specific bits are preserved. The special ``MAXIMUM_ALLOWED`` and
    ``ACCESS_SYSTEM_SECURITY`` bits are left untouched.

    Args:
        mask: The raw access mask.
        object_type: The object type controlling the mapping.

    Raises:
        ValueError: If ``object_type`` is not a supported :class:`ObjectType`.
    """
    object_type = ObjectType(object_type)
    mapping = _GENERIC_MAPPINGS[object_type]

    mapped = mask & ~GENERIC_MASK
    for generic_bit, specific_mask in mapping.items():
        if mask & generic_bit:
            mapped |= specific_mask
    return mapped


@dataclass
class TraceEntry:
    """A single, re-computable step of the DACL walk.

    Attributes:
        index: Zero-based position of the ACE in the stored DACL.
        ace_type: ACE type name.
        sid: Trustee SID string, or ``None`` when not applicable.
        raw_mask: Access mask as stored in the ACE.
        effective_mask: Mask after generic mapping, intersected with the bits
            still relevant to the request.
        ace_flags: Raw ACE inheritance/audit flags.
        action: What the evaluator did with this ACE.
        detail: Human-readable explanation for ``action``.
    """

    index: int
    ace_type: str
    sid: str | None
    raw_mask: int | None
    effective_mask: int | None
    ace_flags: int | None
    action: str
    detail: str

    def render(self) -> str:
        """Render this trace entry as a single human-readable line."""
        raw = "none" if self.raw_mask is None else f"0x{self.raw_mask:08x}"
        effective = "ignored" if self.effective_mask is None else f"0x{self.effective_mask:08x}"
        sid = self.sid or "-"
        return (
            f"[{self.index}] {self.ace_type:<32} sid={sid:<20} raw={raw} "
            f"effective={effective} -> {self.action}: {self.detail}"
        )


@dataclass
class AccessDecision:
    """Result of an offline DACL evaluation.

    Attributes:
        decision: The three-valued conclusion.
        requested_mask: The requested mask after generic mapping.
        maximum_allowed: Whether the request used ``MAXIMUM_ALLOWED``.
        granted_mask: Bits proven granted.
        denied_mask: Bits proven denied.
        undecided_mask: Bits whose state cannot be proven.
        remaining_mask: Bits still neither granted nor denied at the end.
        dacl_state: One of ``null``, ``empty`` or ``present``.
        trace: Ordered list of :class:`TraceEntry` steps.
        reasons: Human-readable reasons contributing to the decision.
        coverage: Windows access-control semantics not modelled here.
    """

    decision: Decision
    requested_mask: int
    maximum_allowed: bool
    granted_mask: int
    denied_mask: int
    undecided_mask: int
    remaining_mask: int
    dacl_state: str
    trace: list[TraceEntry] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    coverage: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        """Whether the conclusion is a definite allow."""
        return self.decision == Decision.ALLOW

    def render_path(self) -> str:
        """Render the full re-computable decision path."""
        lines = [
            f"dacl_state={self.dacl_state} maximum_allowed={self.maximum_allowed}",
            f"requested=0x{self.requested_mask:08x} {mask_names(self.requested_mask)}",
            f"granted=0x{self.granted_mask:08x} denied=0x{self.denied_mask:08x} "
            f"undecided=0x{self.undecided_mask:08x} remaining=0x{self.remaining_mask:08x}",
            "decision path:",
        ]
        lines.extend(f"  {entry.render()}" for entry in self.trace)
        if self.reasons:
            lines.append("reasons:")
            lines.extend(f"  - {reason}" for reason in self.reasons)
        lines.append(f"decision={self.decision.value}")
        return "\n".join(lines)


# Windows semantics that this interface does not model.
_COVERAGE_LIMITATIONS = [
    "Privileges are not modelled (SeBackup, SeRestore, SeSecurity, SeTakeOwnership, ...); "
    "ACCESS_SYSTEM_SECURITY always yields UNDECIDED.",
    "SACL auditing and SYSTEM_* ACEs (mandatory labels, resource attributes, scoped policy "
    "IDs, process trust labels, access filters/central access policies) are not evaluated.",
    "Mandatory integrity check (token integrity level vs. mandatory label ACE, no-read-up/"
    "no-execute-up policy) is not evaluated.",
    "Callback/conditional ACEs are not evaluated because token claims, device attributes and "
    "conditional expressions are not supplied; they yield UNDECIDED when applicable.",
    "Compound ACEs (client/server impersonation) require a server identity and yield UNDECIDED "
    "when the client SID matches.",
    "Property/attribute-scoped object ACEs require an active property GUID and yield UNDECIDED; "
    "object ACEs are a Directory Services construct and are unusual on NTFS files.",
    "Share ACLs, parent-folder inheritance at creation time, owner-creation defaulting and "
    "effective-percentage aggregation are out of scope.",
    "Only FILE and DIRECTORY generic mappings are known; other object manager types are rejected.",
]


def _normalize_sids(token_sids: Iterable[str]) -> set[str]:
    return {sid for sid in token_sids if sid}


def _evaluate_ace(
    ace: ACE,
    index: int,
    token_sids: set[str],
    requested_specific: int,
    *,
    maximum_allowed: bool,
    owner_sid: str | None,
    trace: list[TraceEntry],
) -> tuple[str, int, int | None]:
    """Evaluate a single DACL ACE.

    Returns a tuple ``(effect, effective_mask, undecided_mask)`` where effect
    is one of ``allow``, ``deny``, ``undecided`` or ``skip``.
    """
    ace_type = ace.type
    flags = int(ace.header.AceFlags)
    type_name = ace_type.name
    sid = ace.sid

    # Inherit-only ACEs protect children, not the object carrying the DACL.
    if flags & int(c_ntfs.ACE_FLAGS.INHERIT_ONLY_ACE):
        trace.append(
            TraceEntry(
                index,
                type_name,
                sid,
                ace.mask,
                None,
                flags,
                "skip",
                "INHERIT_ONLY_ACE: applies to children, not this object",
            )
        )
        return "skip", 0, None

    # System ACEs do not participate in the discretionary check.
    if ace_type not in _ALLOW_TYPES and ace_type not in _DENY_TYPES:
        trace.append(
            TraceEntry(
                index,
                type_name,
                sid,
                ace.mask,
                None,
                flags,
                "skip",
                "system/non-discretionary ACE: not part of the DACL access check",
            )
        )
        return "skip", 0, None

    # Compound ACEs need the server identity of an impersonation chain.
    if ace_type == ACE_TYPE.ACCESS_ALLOWED_COMPOUND:
        applies = sid in token_sids or (ace.server_sid and ace.server_sid in token_sids)
        if applies:
            trace.append(
                TraceEntry(
                    index,
                    type_name,
                    sid,
                    ace.mask,
                    None,
                    flags,
                    "undecided",
                    "compound impersonation ACE needs a server identity that is not provided offline",
                )
            )
            return "undecided", 0, requested_specific
        trace.append(
            TraceEntry(
                index, type_name, sid, ace.mask, 0, flags, "skip", "compound ACE trustee SIDs are not in the token"
            )
        )
        return "skip", 0, None

    # OWNER RIGHTS represents the rights retained by the current owner; it
    # applies when the token carries the descriptor's owner.
    is_owner_rights = sid == OWNER_RIGHTS_SID and owner_sid and owner_sid in token_sids
    if sid not in token_sids and not is_owner_rights:
        trace.append(TraceEntry(index, type_name, sid, ace.mask, 0, flags, "skip", "trustee SID not present in token"))
        return "skip", 0, None

    # Object ACEs may be scoped to a property/attribute set.
    if ace_type in _OBJECT_TYPES:
        object_guid = ace.object_type
        inherited_guid = ace.inherited_object_type
        if object_guid is not None:
            trace.append(
                TraceEntry(
                    index,
                    type_name,
                    sid,
                    ace.mask,
                    None,
                    flags,
                    "undecided",
                    f"object ACE scoped to property/attribute {object_guid}; no active property " "GUID was supplied",
                )
            )
            return "undecided", 0, requested_specific
        detail = "object ACE without an ObjectType GUID; treated as a plain ACE"
        if inherited_guid is not None:
            detail += f" (InheritedObjectType={inherited_guid} ignored for this object)"
    else:
        detail = "trustee SID matches token"

    # Conditional/callback ACEs need claims and a condition expression.
    if ace_type in _CALLBACK_TYPES and ace.application_data:
        trace.append(
            TraceEntry(
                index,
                type_name,
                sid,
                ace.mask,
                None,
                flags,
                "undecided",
                "callback ACE carries condition/application data; no token claims supplied",
            )
        )
        return "undecided", 0, requested_specific

    effective = map_generic_access(ace.mask or 0, ObjectType.FILE)
    if not maximum_allowed:
        effective &= requested_specific
    else:
        effective &= ~(GENERIC_MASK | MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY)

    if ace_type in _DENY_TYPES:
        action = "deny"
        effect = "deny"
        detail += "; deny applied at this ACE position"
    else:
        action = "allow"
        effect = "allow"
        detail += "; allow accumulated"

    trace.append(TraceEntry(index, type_name, sid, ace.mask, effective, flags, action, detail))
    return effect, effective, None


def evaluate_descriptor(
    descriptor: SecurityDescriptor,
    token_sids: Iterable[str],
    requested_access: int,
    object_type: ObjectType | str = ObjectType.FILE,
) -> AccessDecision:
    """Evaluate a parsed :class:`SecurityDescriptor` against an explicit token.

    Args:
        descriptor: A security descriptor parsed by dissect.ntfs.
        token_sids: The complete set of SIDs in the requesting token (user,
            groups, aliases). Host memberships are never consulted.
        requested_access: The requested access mask, possibly containing
            generic bits or ``MAXIMUM_ALLOWED``.
        object_type: :class:`ObjectType` controlling generic mapping.

    Returns:
        A fully traceable :class:`AccessDecision`.
    """
    object_type = ObjectType(object_type)
    sids = _normalize_sids(token_sids)

    raw_request = int(requested_access)
    maximum_allowed = bool(raw_request & MAXIMUM_ALLOWED)

    reasons: list[str] = []
    trace: list[TraceEntry] = []

    # ACCESS_SYSTEM_SECURITY is gated on SeSecurityPrivilege, never modelled.
    if raw_request & ACCESS_SYSTEM_SECURITY:
        mapped_request = map_generic_access(raw_request, object_type)
        reasons.append("ACCESS_SYSTEM_SECURITY requires SeSecurityPrivilege, which is not modelled offline")
        return AccessDecision(
            Decision.UNDECIDED,
            requested_mask=mapped_request,
            maximum_allowed=maximum_allowed,
            granted_mask=0,
            denied_mask=0,
            undecided_mask=ACCESS_SYSTEM_SECURITY,
            remaining_mask=mapped_request,
            dacl_state=_dacl_state(descriptor),
            trace=trace,
            reasons=reasons,
            coverage=list(_COVERAGE_LIMITATIONS),
        )

    requested_specific = map_generic_access(raw_request, object_type)
    # The two policy/meta bits are not themselves grantable file rights.
    requested_specific &= ~(MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY)

    control = int(descriptor.header.Control)
    dacl_present = bool(control & int(c_ntfs.SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PRESENT))

    # NULL DACL: the Dacl offset/pointer is absent even if the flag is set.
    if not dacl_present or descriptor.dacl is None:
        trace.append(
            TraceEntry(-1, "NULL_DACL", None, None, None, None, "allow", "NULL DACL grants every access to every token")
        )
        if maximum_allowed:
            granted = _FILE_GENERIC_MAPPING[GENERIC_ALL]
            return AccessDecision(
                Decision.ALLOW,
                requested_specific,
                True,
                granted,
                0,
                0,
                0,
                "null",
                trace,
                ["NULL DACL: full access (FILE_ALL_ACCESS) returned"],
                list(_COVERAGE_LIMITATIONS),
            )
        return AccessDecision(
            Decision.ALLOW,
            requested_specific,
            False,
            requested_specific,
            0,
            0,
            0,
            "null",
            trace,
            ["NULL DACL: all requested bits granted"],
            list(_COVERAGE_LIMITATIONS),
        )

    dacl = descriptor.dacl
    if not dacl.ace:
        # Empty but present DACL: nobody is granted anything.
        trace.append(
            TraceEntry(-1, "EMPTY_DACL", None, None, None, None, "deny", "present DACL with zero ACEs grants nothing")
        )
        if maximum_allowed:
            # MAXIMUM_ALLOWED against an empty DACL completes with an empty mask.
            return AccessDecision(
                Decision.ALLOW,
                requested_specific,
                True,
                0,
                0,
                0,
                0,
                "empty",
                trace,
                ["MAXIMUM_ALLOWED against an empty DACL yields a zero granted mask"],
                list(_COVERAGE_LIMITATIONS),
            )
        return AccessDecision(
            Decision.DENY,
            requested_specific,
            False,
            0,
            requested_specific,
            0,
            0,
            "empty",
            trace,
            ["empty DACL: no ACE grants the requested bits"],
            list(_COVERAGE_LIMITATIONS),
        )

    granted = 0
    denied = 0
    undecided = 0
    hard_deny = False
    saw_undecided = False

    # The owner implicitly receives READ_CONTROL and WRITE_DAC unless an
    # OWNER RIGHTS ACE constrains them.
    owner_sid = descriptor.owner
    has_owner_rights_ace = any(ace.sid == OWNER_RIGHTS_SID for ace in dacl.ace if getattr(ace, "sid", None))
    if owner_sid and owner_sid in sids and not has_owner_rights_ace:
        implicit = READ_CONTROL | WRITE_DAC
        if maximum_allowed:
            granted |= implicit
            trace.append(
                TraceEntry(
                    -1,
                    "OWNER_IMPLICIT",
                    owner_sid,
                    None,
                    implicit,
                    None,
                    "allow",
                    "owner implicitly receives READ_CONTROL|WRITE_DAC",
                )
            )
        else:
            apply = implicit & requested_specific
            granted |= apply
            trace.append(
                TraceEntry(
                    -1,
                    "OWNER_IMPLICIT",
                    owner_sid,
                    None,
                    apply,
                    None,
                    "allow",
                    "owner implicitly receives READ_CONTROL|WRITE_DAC",
                )
            )

    for index, ace in enumerate(dacl.ace):
        effect, effective, undecided_bits = _evaluate_ace(
            ace,
            index,
            sids,
            requested_specific,
            maximum_allowed=maximum_allowed,
            owner_sid=owner_sid,
            trace=trace,
        )

        if effect == "undecided":
            saw_undecided = True
            undecided |= undecided_bits or requested_specific
            continue
        if effect == "skip":
            continue

        if effect == "deny":
            if maximum_allowed:
                # MAXIMUM_ALLOWED computes the union of grants; deny ACEs do
                # not shrink the returned mask in the documented algorithm.
                trace[-1] = TraceEntry(
                    index,
                    ace.type.name,
                    ace.sid,
                    ace.mask,
                    effective,
                    int(ace.header.AceFlags),
                    "note",
                    "deny ACE does not reduce a MAXIMUM_ALLOWED grant",
                )
                continue
            # A deny is final for these bits: later ACEs cannot restore them.
            effective &= requested_specific
            denied |= effective
            granted &= ~effective
            if effective:
                hard_deny = True
        elif effect == "allow":
            granted |= effective & ~denied

    if maximum_allowed:
        # Report every grantable file right, regardless of the request width.
        granted &= _FILE_GENERIC_MAPPING[GENERIC_ALL]
        if saw_undecided:
            decision = Decision.UNDECIDED
            reasons.append("an applicable ACE could not be evaluated; full grant cannot be proven")
        else:
            decision = Decision.ALLOW
            reasons.append("MAXIMUM_ALLOWED: union of all proven grants returned")
        return AccessDecision(
            decision,
            requested_specific,
            True,
            granted,
            0,
            undecided & _FILE_GENERIC_MAPPING[GENERIC_ALL],
            0,
            "present",
            trace,
            reasons,
            list(_COVERAGE_LIMITATIONS),
        )

    remaining = requested_specific & ~(granted | denied)
    undecided &= requested_specific

    if hard_deny:
        decision = Decision.DENY
        reasons.append("at least one requested bit was removed by a matching deny ACE")
    elif saw_undecided and (undecided or remaining):
        decision = Decision.UNDECIDED
        reasons.append("an applicable ACE could not be evaluated and an allow cannot be proven")
    elif remaining:
        decision = Decision.DENY
        reasons.append("no ACE grants all requested bits; the remainder is implicitly denied")
    elif undecided:
        decision = Decision.UNDECIDED
        reasons.append("an applicable ACE could not be evaluated")
    else:
        decision = Decision.ALLOW
        reasons.append("every requested bit was granted by the DACL")

    return AccessDecision(
        decision,
        requested_specific,
        False,
        granted,
        denied,
        undecided,
        remaining,
        "present",
        trace,
        reasons,
        list(_COVERAGE_LIMITATIONS),
    )


def _dacl_state(descriptor: SecurityDescriptor) -> str:
    control = int(descriptor.header.Control)
    if not (control & int(c_ntfs.SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PRESENT)) or descriptor.dacl is None:
        return "null"
    if not descriptor.dacl.ace:
        return "empty"
    return "present"


def evaluate_descriptor_bytes(
    descriptor_bytes: bytes | BinaryIO,
    token_sids: Iterable[str],
    requested_access: int,
    object_type: ObjectType | str = ObjectType.FILE,
) -> AccessDecision:
    """Parse a self-relative security descriptor and evaluate it.

    Args:
        descriptor_bytes: Raw self-relative security descriptor bytes or a
            binary stream positioned at the descriptor.
        token_sids: Complete set of token SIDs.
        requested_access: Requested access mask.
        object_type: Object type controlling generic mapping.
    """
    if hasattr(descriptor_bytes, "read"):
        descriptor = SecurityDescriptor(descriptor_bytes)
    else:
        descriptor = SecurityDescriptor(io.BytesIO(descriptor_bytes))
    return evaluate_descriptor(descriptor, token_sids, requested_access, object_type)


# ---------------------------------------------------------------------------
# Minimal self-relative security descriptor builder (for offline test corpus).
# ---------------------------------------------------------------------------


@dataclass
class AceSpec:
    """Declarative ACE specification used by :func:`build_descriptor`.

    Args:
        ace_type: An :class:`ACE_TYPE` value or its name.
        sid: Trustee SID.
        mask: Access mask (generic bits allowed).
        ace_flags: Optional raw ACE flags (inheritance bits).
        application_data: Optional callback/conditional data blob.
    """

    ace_type: ACE_TYPE | str
    sid: str
    mask: int
    ace_flags: int = 0
    application_data: bytes | None = None


def _build_ace(spec: AceSpec) -> bytes:
    ace_type = spec.ace_type if isinstance(spec.ace_type, ACE_TYPE) else ACE_TYPE[spec.ace_type]
    sid_bytes = write_sid(spec.sid)
    body = c_ntfs.DWORD.dumps(spec.mask) + sid_bytes
    if spec.application_data:
        body += spec.application_data
    ace_size = len(c_ntfs._ACE_HEADER) + len(body)
    header = c_ntfs._ACE_HEADER(
        AceType=ace_type,
        AceFlags=c_ntfs.ACE_FLAGS(spec.ace_flags),
        AceSize=ace_size,
    )
    return header.dumps() + body


def build_descriptor(
    aces: Sequence[AceSpec],
    *,
    owner: str | None = None,
    group: str | None = None,
    dacl_protected: bool = False,
) -> bytes:
    """Build a self-relative security descriptor with a present DACL.

    An empty ``aces`` sequence produces an *empty* DACL. Use
    :func:`build_null_dacl_descriptor` for a ``NULL`` DACL.
    """
    control = int(c_ntfs.SECURITY_DESCRIPTOR_CONTROL.SE_SELF_RELATIVE)
    control |= int(c_ntfs.SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PRESENT)
    if dacl_protected:
        control |= int(c_ntfs.SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PROTECTED)
    return _assemble_descriptor(aces, owner=owner, group=group, control=control)


def build_empty_dacl_descriptor(owner: str | None = None, group: str | None = None) -> bytes:
    """Build a descriptor whose DACL is present but contains no ACEs."""
    return build_descriptor([], owner=owner, group=group)


def build_null_dacl_descriptor(owner: str | None = None, group: str | None = None) -> bytes:
    """Build a descriptor with no DACL at all (the ``NULL`` DACL case)."""
    control = int(c_ntfs.SECURITY_DESCRIPTOR_CONTROL.SE_SELF_RELATIVE)
    return _assemble_descriptor([], owner=owner, group=group, control=control, include_dacl=False)


def _assemble_descriptor(
    aces: Sequence[AceSpec],
    *,
    owner: str | None,
    group: str | None,
    control: int,
    include_dacl: bool = True,
) -> bytes:
    header_size = len(c_ntfs._SECURITY_DESCRIPTOR_RELATIVE)
    owner_bytes = write_sid(owner) if owner else b""
    group_bytes = write_sid(group) if group else b""

    offset = header_size
    owner_offset = offset if owner_bytes else 0
    offset += len(owner_bytes)
    group_offset = offset if group_bytes else 0
    offset += len(group_bytes)

    dacl_offset = 0
    acl_blob = b""
    if include_dacl:
        dacl_offset = offset
        ace_blobs = b"".join(_build_ace(spec) for spec in aces)
        acl_size = len(c_ntfs._ACL) + len(ace_blobs)
        acl_header = c_ntfs._ACL(
            AclRevision=2,
            Sbz1=0,
            AclSize=acl_size,
            AceCount=len(aces),
            Sbz2=0,
        )
        acl_blob = acl_header.dumps() + ace_blobs

    header = c_ntfs._SECURITY_DESCRIPTOR_RELATIVE(
        Revision=1,
        Sbz1=0,
        Control=c_ntfs.SECURITY_DESCRIPTOR_CONTROL(control),
        Owner=owner_offset,
        Group=group_offset,
        Sacl=0,
        Dacl=dacl_offset,
    )
    return header.dumps() + owner_bytes + group_bytes + acl_blob
