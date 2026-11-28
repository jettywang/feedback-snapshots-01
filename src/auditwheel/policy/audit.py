"""Approval registry and audit trail for the platform tags auditwheel emits.

The internal network this tool runs in only allows a fixed set of explicitly
registered Linux tags.  The *registry* is the allow-list of tags that have been
approved for publication; by default it is every canonical policy name plus the
legacy *aliases* recorded in the shipped policy JSON files, but a stricter
allow-list can be supplied to model a network that has only registered a subset.

The module answers three questions for the approving party:

1. Which *strategy* did auditwheel pick for a given request (the requested
   target, the policy that was proven compatible, and the graft policy used to
   bound the number of vendored libraries)?
2. Which concrete tags (canonical name + aliases) may end up published, and is
   each one on the registry?
3. If a request cannot be satisfied with registered tags, exactly which
   unapproved tag blocks the release so it can be located before a fix?

The requested target and the compatibility actually proven are both retained,
independently of one another.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from auditwheel.error import AuditwheelError

if TYPE_CHECKING:
    from collections.abc import Iterable

    from auditwheel.policy import Policy, WheelPolicies

# Sentinel used by ``auditwheel repair --plat auto``: no human requested a
# specific tag, so the proven policy alone decides what gets advertised.
AUTO_POLICY = "auto"


class UnregisteredTagError(AuditwheelError):
    """Raised when a repair would publish a tag that is not on the registry.

    The message lists every offending tag and the wheel it came from so the
    release can be blocked and the request located for re-approval.
    """


@dataclass(frozen=True)
class TagRegistry:
    """The set of platform tags approved for publication on this network."""

    tags: frozenset[str]

    @classmethod
    def from_policies(cls, policies: WheelPolicies) -> TagRegistry:
        """Build a registry containing every canonical name and alias."""
        tags: set[str] = set()
        for policy in policies:
            tags.add(policy.name)
            tags.update(policy.aliases)
        return cls(frozenset(tags))

    def allows(self, tag: str) -> bool:
        return tag in self.tags


@dataclass(frozen=True)
class TagDecision:
    """Approval verdict for a single concrete platform tag."""

    tag: str
    kind: str  # "canonical" or "alias"
    canonical: str
    approved: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "tag": self.tag,
            "kind": self.kind,
            "canonical": self.canonical,
            "approved": self.approved,
        }


@dataclass(frozen=True)
class PolicyAudit:
    """Everything an approver needs to review one repair request.

    ``requested`` preserves the operator's literal target (including an alias
    or ``auto``); ``proven_policy`` preserves the compatibility auditwheel
    actually demonstrated, independently of what was asked for.
    """

    wheel: str
    requested: str | None
    strategy: str
    requested_policy: str | None
    proven_policy: str
    proven_is_compatible: bool
    graft_policy: str
    tags: tuple[TagDecision, ...]
    unapproved: tuple[str, ...] = field(default=())

    @property
    def approved(self) -> bool:
        return not self.unapproved

    def as_dict(self) -> dict[str, object]:
        return {
            "wheel": self.wheel,
            "requested": self.requested,
            "strategy": self.strategy,
            "requested_policy": self.requested_policy,
            "proven_policy": self.proven_policy,
            "proven_is_compatible": self.proven_is_compatible,
            "graft_policy": self.graft_policy,
            "approved": self.approved,
            "unapproved_tags": list(self.unapproved),
            "tags": [decision.as_dict() for decision in self.tags],
        }


def _decide_tags(registry: TagRegistry, policy: Policy) -> tuple[TagDecision, ...]:
    decisions = [
        TagDecision(
            tag=policy.name,
            kind="canonical",
            canonical=policy.name,
            approved=registry.allows(policy.name),
        ),
    ]
    for alias in policy.aliases:
        decisions.append(
            TagDecision(
                tag=alias,
                kind="alias",
                canonical=policy.name,
                approved=registry.allows(alias),
            ),
        )
    return tuple(decisions)


def _unapproved(decisions: tuple[TagDecision, ...]) -> tuple[str, ...]:
    return tuple(decision.tag for decision in decisions if not decision.approved)


def audit_request(
    policies: WheelPolicies,
    *,
    wheel_name: str,
    requested: str | None,
    requested_policy: Policy | None,
    proven_policy: Policy,
    proven_is_compatible: bool,
    graft_policy: Policy,
    registry: TagRegistry | None = None,
) -> PolicyAudit:
    """Build the approval audit record for one analyzed wheel.

    The set of publishable tags mirrors ``main_repair``: the proven policy is
    advertised first (with its aliases), followed by the explicitly requested
    policy (with its aliases) when it is a stricter, lower-priority target.
    """
    registry = registry or TagRegistry.from_policies(policies)

    if requested is None or requested == AUTO_POLICY:
        strategy = "auto"
        requested_label = None
        publish_policies = [proven_policy]
    else:
        strategy = "requested"
        requested_label = requested_policy.name if requested_policy is not None else requested
        publish_policies = [proven_policy]
        if requested_policy is not None and requested_policy != proven_policy:
            publish_policies.append(requested_policy)

    decisions: list[TagDecision] = []
    seen: set[str] = set()
    for policy in publish_policies:
        for decision in _decide_tags(registry, policy):
            if decision.tag not in seen:
                seen.add(decision.tag)
                decisions.append(decision)

    return PolicyAudit(
        wheel=wheel_name,
        requested=requested,
        strategy=strategy,
        requested_policy=requested_label,
        proven_policy=proven_policy.name,
        proven_is_compatible=proven_is_compatible,
        graft_policy=graft_policy.name,
        tags=tuple(decisions),
        unapproved=_unapproved(tuple(decisions)),
    )


def ensure_approved(audit: PolicyAudit) -> None:
    """Raise :class:`UnregisteredTagError` if the audit found unapproved tags."""
    if audit.approved:
        return
    listed = ", ".join(audit.unapproved)
    msg = (
        f"Refusing to repair {audit.wheel!r}: the following platform tags are "
        "not registered for publication and need re-approval before the wheel "
        f"can be released: {listed}."
    )
    raise UnregisteredTagError(msg)


def _base_name(tag: str, architecture_suffix: str) -> str:
    """Strip the trailing ``_<arch>`` suffix from a fully-qualified tag."""
    if tag.endswith(architecture_suffix):
        return tag[: -len(architecture_suffix)]
    return tag


def restrict_registry(
    policies: WheelPolicies,
    allowed_base_names: Iterable[str],
) -> TagRegistry:
    """Build a registry limited to the given policy base names and aliases.

    ``allowed_base_names`` contains base names *without* the architecture
    suffix (e.g. ``"manylinux2014"`` or ``"manylinux_2_17"``).  Every matching
    canonical policy and its aliases for those policies are admitted.  This is
    the helper a locked-down network uses to declare the subset it registered.
    """
    wanted = set(allowed_base_names)
    arch_suffix = f"_{policies.architecture.value}"
    tags: set[str] = set()
    for policy in policies:
        base_names = {
            _base_name(policy.name, arch_suffix),
            *(_base_name(alias, arch_suffix) for alias in policy.aliases),
        }
        if wanted & base_names:
            tags.add(policy.name)
            tags.update(policy.aliases)
    return TagRegistry(frozenset(tags))
