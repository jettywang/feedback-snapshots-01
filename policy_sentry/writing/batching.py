"""
Release planning for IAM policies that are too large for a single policy document.

A fully approved policy sometimes cannot be installed in one shot because every AWS
policy document is bounded:

* a managed policy document is capped at 6,144 bytes,
* a document can hold at most 20 statements and 100 action/resource entries,
* identity entities also have an aggregate inline-policy size ceiling.

This module turns *one* approved policy into an ordered list of smaller policy
documents ("batches") that can be installed one after another. The planner is
constrained by three safety rules, each of which is verified before a plan is returned:

1. No intermediate state may be more permissive than the approved policy. Every batch
   contains only fragments of the original statements, so any allowed (action,
   resource) pair always stays within the approved envelope.
2. Explicit Denies - including conditional Denies - are installed in the first batch.
   Splitting or deferring a Deny would leave the deny window open while the Allows are
   already live, so Deny statements are never split and always go first.
3. Once every batch is installed, the effective permissions must be identical to the
   original policy. This is checked both structurally (same fragments, same union) and
   by replaying concrete requests through the in-memory rule engine.

When the limits make a safe plan impossible (typically because a single atomic
statement cannot fit one document), the planner raises :class:`InfeasiblePlanError`
with a reviewable list of blockers instead of emitting an unsafe plan.
"""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from typing import Any

import orjson

from policy_sentry.writing.rule_engine import (
    AccessRequest,
    effective_permissions,
    evaluate_policies,
    requests_from_policy,
)

logger = logging.getLogger(__name__)

# AWS IAM documented quotas, used as defaults unless the caller overrides them.
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html
MANAGED_POLICY_MAX_BYTES = 6144
MAX_STATEMENTS_PER_DOCUMENT = 20
MAX_ACTION_ENTRIES_PER_DOCUMENT = 100
MAX_RESOURCE_ENTRIES_PER_DOCUMENT = 100

POLICY_LANGUAGE_VERSION = "2012-10-17"


class InfeasiblePlanError(ValueError):
    """Raised when no safe batch plan exists under the requested document limits."""

    def __init__(self, blockers: list[str]):
        self.blockers = blockers
        super().__init__("No safe batch plan is possible: " + "; ".join(blockers))


@dataclass(frozen=True)
class BatchLimits:
    """The capacity and structural limits that every generated document must respect."""

    max_bytes: int = MANAGED_POLICY_MAX_BYTES
    max_statements: int = MAX_STATEMENTS_PER_DOCUMENT
    max_action_entries: int | None = MAX_ACTION_ENTRIES_PER_DOCUMENT
    max_resource_entries: int | None = MAX_RESOURCE_ENTRIES_PER_DOCUMENT
    deny_first_batch: bool = True

    @classmethod
    def managed_policy(cls) -> "BatchLimits":
        """Defaults matching an AWS managed policy document."""
        return cls()

    @classmethod
    def role_inline(cls) -> "BatchLimits":
        """Defaults matching the aggregate inline policy ceiling for a role."""
        return cls(max_bytes=10240)

    @classmethod
    def user_inline(cls) -> "BatchLimits":
        """Defaults matching the aggregate inline policy ceiling for a user."""
        return cls(max_bytes=2048)


@dataclass
class Fragment:
    """A piece of an original statement that can be placed into a batch document."""

    source_index: int
    fragment_index: int
    statement: dict[str, Any]
    splittable: bool

    @property
    def key(self) -> str:
        return f"statement-{self.source_index}-fragment-{self.fragment_index}"


@dataclass
class Batch:
    """One installable policy document and the fragments it contains."""

    sequence: int
    fragments: list[Fragment] = field(default_factory=list)

    def to_policy(self) -> dict[str, Any]:
        return {
            "Version": POLICY_LANGUAGE_VERSION,
            "Statement": [fragment.statement for fragment in self.fragments],
        }


@dataclass
class ReleasePlan:
    """The full, verified release plan for one approved policy."""

    source_policy: dict[str, Any]
    limits: BatchLimits
    batches: list[Batch]
    blockers: list[str] = field(default_factory=list)

    @property
    def feasible(self) -> bool:
        return not self.blockers

    def documents(self) -> list[dict[str, Any]]:
        """The ordered list of policy dictionaries to install."""
        return [batch.to_policy() for batch in self.batches]

    def verify(self) -> None:
        """Re-run the safety invariants against this (possibly modified) plan."""
        verify_plan(self)

    def to_manifest(self) -> dict[str, Any]:
        """A reviewable manifest describing install order, contents and rollback."""
        return {
            "feasible": self.feasible,
            "limits": {
                "max_bytes": self.limits.max_bytes,
                "max_statements": self.limits.max_statements,
                "max_action_entries": self.limits.max_action_entries,
                "max_resource_entries": self.limits.max_resource_entries,
                "deny_first_batch": self.limits.deny_first_batch,
            },
            "source_statement_count": len(_as_list(self.source_policy.get("Statement", []))),
            "batch_count": len(self.batches),
            "total_bytes": sum(document_size(document) for document in self.documents()),
            "batches": [
                {
                    "sequence": batch.sequence,
                    "install": f"batch-{batch.sequence:02d}.json",
                    "rollback": f"batch-{batch.sequence:02d}.json",
                    "bytes": document_size(batch.to_policy()),
                    "fragments": [
                        {
                            "fragment": fragment.key,
                            "source_statement": fragment.source_index,
                            "effect": fragment.statement.get("Effect", "Allow"),
                        }
                        for fragment in batch.fragments
                    ],
                }
                for batch in self.batches
            ],
            "blockers": self.blockers,
        }


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def document_size(policy: dict[str, Any]) -> int:
    """Byte length of a policy as AWS counts it: compact UTF-8 encoded JSON."""
    return len(orjson.dumps(policy))


def _count_entries(statement: dict[str, Any], key: str, not_key: str) -> int:
    if key in statement:
        return len(_as_list(statement[key]))
    if not_key in statement:
        return len(_as_list(statement[not_key]))
    return 0


def statement_limits(statement: dict[str, Any]) -> dict[str, int]:
    """Structural resource usage of a single statement."""
    return {
        "statements": 1,
        "action_entries": _count_entries(statement, "Action", "NotAction"),
        "resource_entries": _count_entries(statement, "Resource", "NotResource"),
    }


def _fits(usage: dict[str, int], limits: BatchLimits) -> bool:
    if limits.max_action_entries is not None and usage["action_entries"] > limits.max_action_entries:
        return False
    if limits.max_resource_entries is not None and usage["resource_entries"] > limits.max_resource_entries:
        return False
    return usage["statements"] <= limits.max_statements and usage["bytes"] <= limits.max_bytes


def batch_usage(batch: Batch) -> dict[str, int]:
    """Measure a batch document against every configured limit."""
    policy = batch.to_policy()
    usage = {"statements": 0, "action_entries": 0, "resource_entries": 0}
    for fragment in batch.fragments:
        fragment_usage = statement_limits(fragment.statement)
        for key, value in fragment_usage.items():
            usage[key] += value
    usage["bytes"] = document_size(policy)
    return usage


def _is_deny(statement: dict[str, Any]) -> bool:
    return statement.get("Effect", "Allow") == "Deny"


def _is_splittable(statement: dict[str, Any]) -> bool:
    """
    Only plain Allow statements with explicit Action and Resource lists may be split.

    Denies (conditional or not), NotAction/NotResource constructs, Principal-bearing
    resource policies and Condition-bearing allows are treated as atomic: splitting any
    of them would change their semantics and could widen the envelope mid-rollout.
    """
    if _is_deny(statement):
        return False
    if "Principal" in statement or "NotPrincipal" in statement:
        return False
    if "NotAction" in statement or "NotResource" in statement:
        return False
    if "Condition" in statement:
        return False
    if not isinstance(statement.get("Action"), list) or not isinstance(statement.get("Resource"), list):
        return False
    return len(statement["Action"]) >= 1 and len(statement["Resource"]) >= 1


def _fragments_for(statement: dict[str, Any], source_index: int, limits: BatchLimits) -> list[Fragment]:
    """
    Split a splittable statement along resources first, then actions if needed.

    Resource splitting is preferred because the resource ARNs are usually the long part
    of a statement. A per-resource fragment that still cannot fit one document is broken
    down further into per-action pieces; a per-action piece that still overflows is
    reported as an infeasibility rather than silently widened.
    """
    if not _is_splittable(statement):
        return [Fragment(source_index, 0, copy.deepcopy(statement), False)]

    fragments: list[Fragment] = []
    actions = list(statement["Action"])
    resources = list(statement["Resource"])
    fragment_index = 0

    for resource in resources:
        base = {key: copy.deepcopy(value) for key, value in statement.items() if key not in ("Action", "Resource")}
        base["Resource"] = [resource]

        whole = Fragment(source_index, fragment_index, {**base, "Action": list(actions)}, True)
        if _fragment_fits_alone(whole, limits):
            fragments.append(whole)
            fragment_index += 1
            continue

        for action in actions:
            fragments.append(Fragment(source_index, fragment_index, {**base, "Action": [action]}, True))
            fragment_index += 1
    return fragments


def _annotate_sid(fragment: Fragment) -> None:
    # Unsplit statements keep their original Sid; only real fragments get a suffix.
    if fragment.fragment_index == 0 and not fragment.splittable:
        return
    statement = fragment.statement
    existing_sid = statement.get("Sid")
    if existing_sid:
        statement["Sid"] = f"{existing_sid}-f{fragment.fragment_index}"
    else:
        statement["Sid"] = f"Src{fragment.source_index}Frag{fragment.fragment_index}"


def _without_sid(statement: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in statement.items() if key != "Sid"}


def _fragment_fits_alone(fragment: Fragment, limits: BatchLimits) -> bool:
    probe = Batch(0, [fragment])
    return _fits(batch_usage(probe), limits)


def _can_add(batch: Batch, fragment: Fragment, limits: BatchLimits) -> bool:
    candidate = Batch(batch.sequence, [*batch.fragments, fragment])
    return _fits(batch_usage(candidate), limits)


def _pack(fragments: list[Fragment], limits: BatchLimits) -> list[Batch]:
    """
    Greedy, order-preserving packing; fragments never leave their priority group.

    When ``deny_first_batch`` is set, the group boundary between Deny and Allow forces
    a fresh document so the denies occupy batch one on their own and no allow window can
    open in the same installation step.
    """
    batches: list[Batch] = []
    current = Batch(1)
    previous_was_deny = False
    for fragment in fragments:
        is_deny = _is_deny(fragment.statement)
        boundary = (
            limits.deny_first_batch
            and current.fragments
            and previous_was_deny
            and not is_deny
        )
        if boundary or (current.fragments and not _can_add(current, fragment, limits)):
            batches.append(current)
            current = Batch(len(batches) + 1)
        current.fragments.append(fragment)
        previous_was_deny = is_deny
    if current.fragments:
        batches.append(current)
    return batches


def _collect_fragments(
    policy: dict[str, Any], limits: BatchLimits
) -> tuple[list[Fragment], list[Fragment]]:
    deny_fragments: list[Fragment] = []
    allow_fragments: list[Fragment] = []
    for index, statement in enumerate(_as_list(policy.get("Statement", []))):
        fragments = _fragments_for(statement, index, limits)
        for fragment in fragments:
            _annotate_sid(fragment)
        if _is_deny(statement):
            deny_fragments.extend(fragments)
        else:
            allow_fragments.extend(fragments)
    return deny_fragments, allow_fragments


def build_release_plan(policy: dict[str, Any], limits: BatchLimits | None = None) -> ReleasePlan:
    """
    Plan a safe, multi-batch rollout for a single approved IAM policy.

    Arguments:
        policy: the approved policy document that is too large to install at once.
        limits: per-document byte and structural limits; managed-policy defaults apply.

    Returns:
        ReleasePlan: an ordered, verified plan.

    Raises:
        InfeasiblePlanError: when a statement that must stay atomic cannot fit one
        document, or a minimal fragment still exceeds the limits.
    """
    limits = limits or BatchLimits()
    source = copy.deepcopy(policy)
    if "Statement" not in source:
        raise ValueError("The supplied policy has no Statement element")
    deny_fragments, allow_fragments = _collect_fragments(source, limits)

    blockers: list[str] = []
    for fragment in [*deny_fragments, *allow_fragments]:
        if not _fragment_fits_alone(fragment, limits):
            kind = "Deny" if _is_deny(fragment.statement) else "Allow"
            blockers.append(
                f"{kind} statement {fragment.source_index} cannot fit one document even as a minimal "
                f"fragment ({document_size(_wrap_fragment(fragment))} bytes); reduce the approved policy "
                f"or raise the limits"
            )
    if blockers:
        raise InfeasiblePlanError(blockers)

    # Denies lead the rollout so no allow window is ever open without the guard rails.
    ordered = [*deny_fragments, *allow_fragments]
    batches = _pack(ordered, limits)
    plan = ReleasePlan(source_policy=source, limits=limits, batches=batches)

    verify_plan(plan)
    return plan


def _wrap_fragment(fragment: Fragment) -> dict[str, Any]:
    return {"Version": POLICY_LANGUAGE_VERSION, "Statement": [fragment.statement]}


def verify_plan(plan: ReleasePlan) -> None:
    """
    Assert the three safety invariants of a plan; raise :class:`InfeasiblePlanError`
    with reviewable blockers if any invariant fails.
    """
    blockers: list[str] = []
    documents = plan.documents()

    for index, document in enumerate(documents, start=1):
        usage = batch_usage(plan.batches[index - 1])
        if not _fits(usage, plan.limits):
            blockers.append(f"batch {index} violates the requested limits: {usage}")

    _verify_deny_ordering(plan, blockers)
    _verify_fragment_coverage(plan, blockers)
    _verify_equivalence(plan, blockers)

    if blockers:
        raise InfeasiblePlanError(blockers)


def _verify_deny_ordering(plan: ReleasePlan, blockers: list[str]) -> None:
    deny_seen = False
    allow_seen = False
    for batch in plan.batches:
        for fragment in batch.fragments:
            if _is_deny(fragment.statement):
                if allow_seen:
                    blockers.append(
                        f"Deny fragment {fragment.key} is installed after an Allow; the deny window "
                        "would stay open during the early batches"
                    )
                deny_seen = True
            else:
                allow_seen = True
    source_denies = [s for s in _as_list(plan.source_policy.get("Statement", [])) if _is_deny(s)]
    if source_denies and not deny_seen:
        blockers.append("the source policy contains Deny statements but none were placed in the plan")


def _verify_fragment_coverage(plan: ReleasePlan, blockers: list[str]) -> None:
    """The union of the fragments must reconstruct every source statement exactly."""
    source_statements = _as_list(plan.source_policy.get("Statement", []))
    grouped: dict[int, list[Fragment]] = {}
    for batch in plan.batches:
        for fragment in batch.fragments:
            grouped.setdefault(fragment.source_index, []).append(fragment)

    if sorted(grouped) != list(range(len(source_statements))):
        blockers.append("fragment coverage does not match the source statement indexes")
        return

    for index, statement in enumerate(source_statements):
        fragments = grouped[index]
        if not _is_splittable(statement):
            if len(fragments) != 1 or _without_sid(fragments[0].statement) != _without_sid(statement):
                blockers.append(f"atomic statement {index} was altered during planning")
            continue
        # Fragments are a resource x action Cartesian decomposition. The union of
        # (action, resource) pairs must equal the original Cartesian product, even when
        # some fragments hold several actions on the same resource.
        pairs = {
            (str(action), str(resource))
            for fragment in fragments
            for action in _as_list(fragment.statement["Action"])
            for resource in _as_list(fragment.statement["Resource"])
        }
        expected_pairs = {
            (str(action), str(resource))
            for action in statement["Action"]
            for resource in statement["Resource"]
        }
        if pairs != expected_pairs:
            blockers.append(
                f"split statement {index} fragments do not reconstruct the original action/resource pairs"
            )
        for fragment in fragments:
            for key in ("Effect", "Condition", "Principal", "NotPrincipal", "NotAction", "NotResource"):
                if fragment.statement.get(key) != statement.get(key):
                    blockers.append(f"fragment of statement {index} changed the {key} clause")


def _verify_equivalence(plan: ReleasePlan, blockers: list[str]) -> None:
    """Replay concrete requests: every prefix state is within envelope; final state equals source."""
    probes = requests_from_policy(plan.source_policy)
    # Add probes that exercise denies explicitly so an ordering bug cannot hide.
    for statement in _as_list(plan.source_policy.get("Statement", [])):
        if _is_deny(statement) and "Action" in statement:
            for action in _as_list(statement["Action"]):
                resources = _as_list(statement.get("Resource")) or ["*"]
                for resource in resources:
                    probes.append(AccessRequest(str(action), str(resource)))

    source_decisions = effective_permissions([plan.source_policy], probes)
    installed: list[dict[str, Any]] = []
    for index, document in enumerate(plan.documents(), start=1):
        installed.append(document)
        prefix_decisions = effective_permissions(installed, probes)
        for request in probes:
            marker = (request.action, request.resource)
            if prefix_decisions[marker] == "Allow" and source_decisions[marker] != "Allow":
                blockers.append(
                    f"batch {index} widens permissions beyond the approved policy for {marker}"
                )
    final_decisions = effective_permissions(installed, probes)
    if final_decisions != source_decisions:
        drift = [marker for marker in source_decisions if final_decisions[marker] != source_decisions[marker]]
        blockers.append(f"fully installed plan diverges from the source policy on {drift}")


def evaluate_request(plan: ReleasePlan, request: AccessRequest, installed_batches: int) -> str:
    """Rule-engine hook used by demos/tests: decision after installing N batches."""
    documents = plan.documents()[:installed_batches]
    return evaluate_policies(documents, request)


def explain_rollback(plan: ReleasePlan, failed_batch: int) -> dict[str, Any]:
    """
    Describe what to remove when batch ``failed_batch`` (1-based) fails to install.

    Batches are immutable documents attached in order. On failure the safe move is to
    detach the failed document (nothing of it was applied) and, if the operator wants to
    return to the pre-release state, detach the already installed batches in reverse
    order. No earlier batch is edited in place, so the deny-first ordering is preserved.
    """
    if not 1 <= failed_batch <= len(plan.batches):
        raise ValueError(f"failed_batch must be between 1 and {len(plan.batches)}")
    return {
        "failed_batch": failed_batch,
        "detach": [f"batch-{failed_batch:02d}.json"],
        "full_rollback_order": [
            f"batch-{sequence:02d}.json" for sequence in range(failed_batch - 1, 0, -1)
        ],
        "note": "Deny statements live in batch-01, so partial rollouts never lose their guard rails.",
    }
