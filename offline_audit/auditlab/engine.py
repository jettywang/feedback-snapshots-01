"""Offline IAM effective-permission analyzer built on the Policy Sentry data set.

The engine never calls AWS. It combines:
  * inline policies
  * attached managed policies that were actually retrieved
  * an optional permission boundary snapshot (which may itself be incomplete)
and explains, per (action, resource, condition) target, whether the conclusion is
determined or still needs more evidence.

Verdicts
--------
DENY_EXPLICIT        an explicit Deny statement matches (determined).
ALLOW_EFFECTIVE      an identity Allow matches AND the boundary Allow matches,
                     and every condition involved could be evaluated (determined).
PENDING_CONDITION    the permission shape matches, but at least one condition
                     cannot be evaluated offline (a request/resource value is
                     missing or the boundary is condition-based).
PENDING_MISSING_DATA a required input document is absent (e.g. an attached
                     policy not retrieved, or no boundary snapshot), so an
                     effective allow cannot be proven.
IMPLICIT_DENY        every available document was evaluated and none allows the
                     action on the resource (determined, relative to the snapshot).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

from policy_sentry.querying.actions import get_action_data
from policy_sentry.querying.conditions import get_condition_key_details

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


@dataclass
class Statement:
    source: str
    source_kind: str  # inline | attached | boundary
    present: bool
    sid: str
    effect: str
    actions: list[str]
    resources: list[str]
    conditions: dict[str, dict[str, Any]]
    condition_sources: dict[str, str] = field(default_factory=dict)


@dataclass
class Bundle:
    role: str
    snapshot: str
    statements: list[Statement]
    missing_inputs: list[dict[str, str]]
    boundary_present: bool
    boundary_completeness: str


def _coerce_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def _load_policy(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _parse_statements(policy: dict[str, Any], source: str, kind: str,
                      present: bool) -> list[Statement]:
    statements: list[Statement] = []
    raw = policy.get("Statement", [])
    if isinstance(raw, dict):
        raw = [raw]
    for index, stmt in enumerate(raw):
        sid = stmt.get("Sid", f"Statement{index}")
        condition_block = stmt.get("Condition", {}) or {}
        flat_conditions: dict[str, dict[str, Any]] = {}
        condition_sources: dict[str, str] = {}
        for operator, keys in condition_block.items():
            for key, operands in keys.items():
                flat_conditions[key] = {
                    "operator": operator,
                    "operands": _coerce_list(operands),
                }
                condition_sources[key] = f"{source}/{sid}:{operator}"
        statements.append(
            Statement(
                source=source,
                source_kind=kind,
                present=present,
                sid=sid,
                effect=stmt.get("Effect", ""),
                actions=_coerce_list(stmt.get("Action")),
                resources=_coerce_list(stmt.get("Resource")),
                conditions=flat_conditions,
                condition_sources=condition_sources,
            )
        )
    return statements


def load_bundle(manifest_path: str) -> Bundle:
    base_dir = os.path.dirname(os.path.abspath(manifest_path))
    manifest = _load_policy(manifest_path)
    statements: list[Statement] = []
    missing: list[dict[str, str]] = []

    for item in manifest.get("inline_policies", []):
        if not item.get("present", True):
            missing.append({"input": item["name"], "kind": "inline",
                            "note": item.get("note", "")})
            continue
        policy = _load_policy(os.path.join(base_dir, item["path"]))
        statements.extend(_parse_statements(
            policy, item["name"], "inline", True))

    for item in manifest.get("attached_managed_policies", []):
        if not item.get("present", True):
            missing.append({"input": item["name"], "kind": "attached",
                            "note": item.get("note", "")})
            continue
        policy = _load_policy(os.path.join(base_dir, item["path"]))
        statements.extend(_parse_statements(
            policy, item["name"], "attached", True))

    boundary = manifest.get("permission_boundary") or {}
    boundary_present = bool(boundary.get("present", False))
    boundary_completeness = boundary.get("completeness", "unknown")
    if boundary_present:
        policy = _load_policy(os.path.join(base_dir, boundary["path"]))
        statements.extend(_parse_statements(
            policy, boundary["name"], "boundary", True))
    else:
        missing.append({"input": boundary.get("name", "permission-boundary"),
                        "kind": "boundary", "note": boundary.get("note", "")})

    return Bundle(
        role=manifest["role"],
        snapshot=manifest.get("snapshot", "unknown"),
        statements=statements,
        missing_inputs=missing,
        boundary_present=boundary_present,
        boundary_completeness=boundary_completeness,
    )


# ---------------------------------------------------------------------------
# Action and ARN matching
# ---------------------------------------------------------------------------

def _expand_action(pattern: str) -> list[str]:
    service, action = pattern.split(":", 1)
    if action == "*":
        data = get_action_data(service, "*")
        return sorted(row["action"] for row in data.get(service, []))
    return [pattern]


def action_matches(pattern: str, action: str) -> bool:
    if "*" not in pattern:
        return pattern.lower() == action.lower()
    return any(action.lower() == expanded.lower()
               for expanded in _expand_action(pattern))


def _arn_segments(arn: str) -> list[str]:
    parts = arn.split(":")
    if len(parts) < 6 or not arn.startswith("arn:"):
        return [arn]
    # resource part may itself be path-like; keep it as one segment
    return parts[:5] + [":".join(parts[5:])]


def _iam_glob(pattern: str, text: str) -> bool:
    """IAM policy wildcard semantics: '*' matches any number of any chars
    (including '/' and ':'), '?' matches one character."""
    regex = ""
    for char in pattern:
        if char == "*":
            regex += ".*"
        elif char == "?":
            regex += "."
        else:
            regex += re.escape(char)
    return re.fullmatch(regex, text) is not None


def arn_matches(pattern: str, resource: str) -> bool:
    if pattern == "*":
        return True
    if "*" not in pattern and "?" not in pattern:
        return pattern == resource
    pattern_parts = _arn_segments(pattern)
    resource_parts = _arn_segments(resource)
    if len(pattern_parts) != len(resource_parts):
        return False
    for pat, res in zip(pattern_parts, resource_parts):
        if not _iam_glob(pat, res):
            return False
    return True

# ---------------------------------------------------------------------------
# Condition evaluation
# ---------------------------------------------------------------------------

# Operators whose truth value we can decide when the context value is present.
_KNOWN_OPERATORS = {
    "StringEquals", "StringNotEquals", "StringLike", "StringNotLike",
    "NumericEquals", "NumericNotEquals", "NumericLessThan",
    "NumericGreaterThan", "Bool", "ArnEquals", "ArnLike", "ArnNotLike",
    "ForAllValues:StringEquals", "ForAnyValue:StringEquals",
}


def _context_value(key: str, target: dict[str, Any]) -> tuple[bool, Any, str]:
    request_ctx = target.get("request_context", {}) or {}
    resource_facts = target.get("resource_facts", {}) or {}
    tags = resource_facts.get("tags", {}) or {}

    if key in request_ctx:
        return True, request_ctx[key], "request_context"
    if key.startswith("aws:ResourceTag/"):
        tag_name = key.split("/", 1)[1]
        if tag_name in tags:
            return True, tags[tag_name], "resource_facts.tags"
    return False, None, "missing"


def _apply_operator(operator: str, actual: Any, operands: list[str]) -> bool:
    base = operator.split(":", 1)[-1] if operator.startswith(("ForAll", "ForAny")) else operator
    if base in ("StringEquals", "NumericEquals", "ArnEquals", "Bool"):
        return str(actual) in [str(o) for o in operands]
    if base in ("StringNotEquals", "NumericNotEquals"):
        return str(actual) not in [str(o) for o in operands]
    if base in ("StringLike", "ArnLike"):
        return any(_iam_glob(str(o), str(actual)) for o in operands)
    if base == "StringNotLike":
        return all(not _iam_glob(str(o), str(actual)) for o in operands)
    if base == "NumericLessThan":
        return float(actual) < float(operands[0])
    if base == "NumericGreaterThan":
        return float(actual) > float(operands[0])
    return False


def _condition_key_known(service: str, key: str) -> bool:
    """Validate a condition key against the offline Policy Sentry data set.

    Tag-style keys carry an instance suffix (e.g. aws:ResourceTag/env) and are
    checked against the parameterised template (aws:ResourceTag/${TagKey}).
    Global aws:* keys are shared across services, so an empty lookup is not
    treated as an error for them.
    """
    if key.startswith("aws:"):
        return True
    details = get_condition_key_details(service, key)
    if details:
        return True
    # Retry with the parameterised template for tag/context-style keys.
    base = key.split("/", 1)[0].split(":", 1)[0]
    candidate = f"{base}:${{{'TagKey'}}}" if "/" in key else key
    return bool(get_condition_key_details(service, candidate))


def evaluate_conditions(stmt: Statement, target: dict[str, Any]
                        ) -> tuple[str, list[dict[str, str]]]:
    """Return ('satisfied'|'unsatisfiable'|'indeterminate', evidence list)."""
    evidence: list[dict[str, str]] = []
    if not stmt.conditions:
        return "satisfied", evidence

    service = target["action"].split(":", 1)[0]
    for key, rule in stmt.conditions.items():
        operator = rule["operator"]
        operands = rule["operands"]

        if not _condition_key_known(service, key):
            evidence.append({
                "condition_key": key, "operator": operator,
                "expected": ",".join(operands), "actual": "<metadata check>",
                "origin": stmt.condition_sources.get(key, ""),
                "status": "INDETERMINATE",
                "reason": f"condition key {key} is not recognised for service "
                          f"{service} in the offline Policy Sentry data set",
            })
            return "indeterminate", evidence

        present, actual, origin = _context_value(key, target)
        if not present:
            evidence.append({
                "condition_key": key, "operator": operator,
                "expected": ",".join(operands), "actual": "<not provided>",
                "origin": stmt.condition_sources.get(key, ""),
                "status": "INDETERMINATE",
                "reason": f"no value for {key} in request_context or resource_facts",
            })
            return "indeterminate", evidence
        if operator not in _KNOWN_OPERATORS:
            evidence.append({
                "condition_key": key, "operator": operator,
                "expected": ",".join(operands), "actual": str(actual),
                "origin": stmt.condition_sources.get(key, ""),
                "status": "INDETERMINATE",
                "reason": f"operator {operator} is not evaluated offline",
            })
            return "indeterminate", evidence

        satisfied = _apply_operator(operator, actual, operands)
        evidence.append({
            "condition_key": key, "operator": operator,
            "expected": ",".join(operands), "actual": str(actual),
            "origin": stmt.condition_sources.get(key, ""),
            "status": "SATISFIED" if satisfied else "FAILED",
            "reason": f"{origin} -> {operator} compared against supplied value",
        })
        if not satisfied:
            return "unsatisfiable", evidence
    return "satisfied", evidence


# ---------------------------------------------------------------------------
# Statement matching against a target
# ---------------------------------------------------------------------------


def _statement_matches(stmt: Statement, target: dict[str, Any]
                       ) -> tuple[bool, list[dict[str, str]]]:
    if not any(action_matches(pattern, target["action"]) for pattern in stmt.actions):
        return False, []
    if not any(arn_matches(pattern, target["resource"]) for pattern in stmt.resources):
        return False, []
    condition_state, evidence = evaluate_conditions(stmt, target)
    if condition_state == "unsatisfiable":
        return False, evidence
    if condition_state == "indeterminate":
        return None, evidence  # type: ignore[return-value]
    return True, evidence


def analyze_target(bundle: Bundle, target: dict[str, Any]) -> dict[str, Any]:
    deny_hits: list[dict[str, Any]] = []
    allow_hits: list[dict[str, Any]] = []
    boundary_hits: list[dict[str, Any]] = []
    identity_pending: list[dict[str, Any]] = []
    boundary_pending: list[dict[str, Any]] = []

    for stmt in bundle.statements:
        matched, evidence = _statement_matches(stmt, target)
        record = {"source": stmt.source, "kind": stmt.source_kind,
                  "sid": stmt.sid, "effect": stmt.effect, "evidence": evidence}
        if matched is None:
            if stmt.effect == "Deny":
                # A conditional deny whose condition cannot be evaluated is not
                # a determined deny: keep it visible as an identity-side risk.
                identity_pending.append(record)
            elif stmt.source_kind == "boundary":
                boundary_pending.append(record)
            else:
                identity_pending.append(record)
            continue
        if not matched:
            continue
        if stmt.effect == "Deny":
            deny_hits.append(record)
        elif stmt.source_kind == "boundary":
            boundary_hits.append(record)
        else:
            allow_hits.append(record)

    identity_allow = bool(allow_hits)
    boundary_allow = bool(boundary_hits)
    indeterminate = identity_pending + boundary_pending
    missing_attached = [m for m in bundle.missing_inputs if m["kind"] == "attached"]

    # 1. An explicit deny with a fully evaluated condition always wins.
    if deny_hits:
        return _verdict("DENY_EXPLICIT", target, deny_hits=deny_hits,
                        allow_hits=allow_hits, boundary_hits=boundary_hits,
                        indeterminate=indeterminate, relevant_gaps=[])

    # 2. A boundary condition we cannot evaluate blocks a determined allow.
    if boundary_pending:
        affected = sorted({rec["source"] for rec in boundary_pending})
        return _verdict(
            "PENDING_CONDITION", target, allow_hits=allow_hits,
            boundary_hits=boundary_hits, indeterminate=indeterminate,
            relevant_gaps=[{
                "input": ", ".join(affected),
                "scope": f"{target['action']} on {target['resource']}",
                "reason": "boundary condition cannot be evaluated offline; "
                          "effective allow is not provable yet",
            }])

    # 3. Identity-side condition (e.g. an inline constrained allow) unevaluable.
    if identity_pending and not identity_allow:
        affected = sorted({rec["source"] for rec in identity_pending})
        return _verdict(
            "PENDING_CONDITION", target, allow_hits=allow_hits,
            boundary_hits=boundary_hits, indeterminate=indeterminate,
            relevant_gaps=[{
                "input": ", ".join(affected),
                "scope": f"{target['action']} on {target['resource']}",
                "reason": "identity policy condition cannot be evaluated offline",
            }])

    # 4. No boundary snapshot at all means the boundary side is unprovable.
    if identity_allow and not bundle.boundary_present:
        return _verdict(
            "PENDING_MISSING_DATA", target, allow_hits=allow_hits,
            boundary_hits=boundary_hits, indeterminate=indeterminate,
            relevant_gaps=[{
                "input": "permission-boundary",
                "scope": f"{target['action']} on {target['resource']}",
                "reason": "permission boundary snapshot not provided",
            }])

    # 5. Identity allows it but a complete boundary provably does not.
    if identity_allow and not boundary_allow:
        return _verdict("IMPLICIT_DENY", target, allow_hits=allow_hits,
                        boundary_hits=boundary_hits, indeterminate=indeterminate,
                        relevant_gaps=[],
                        gap="identity allows it but the boundary does not")

    # 6. Boundary allows it but the identity side has no visible allow. A
    #    missing attached policy could still supply that allow.
    if not identity_allow and boundary_allow and missing_attached:
        return _verdict(
            "PENDING_MISSING_DATA", target, allow_hits=allow_hits,
            boundary_hits=boundary_hits, indeterminate=indeterminate,
            relevant_gaps=[{
                "input": ", ".join(m["input"] for m in missing_attached),
                "scope": f"{target['action']} on {target['resource']}",
                "reason": "no visible identity allow; an unretrieved attached "
                          "policy may grant it",
            }])

    # 7. Both sides structurally allow and every condition was evaluated.
    if identity_allow and boundary_allow:
        return _verdict("ALLOW_EFFECTIVE", target, allow_hits=allow_hits,
                        boundary_hits=boundary_hits, indeterminate=indeterminate,
                        relevant_gaps=[])

    return _verdict("IMPLICIT_DENY", target, allow_hits=allow_hits,
                    boundary_hits=boundary_hits, indeterminate=indeterminate,
                    relevant_gaps=[],
                    gap="no identity-side or boundary allow in the snapshot")


def _verdict(name: str, target: dict[str, Any], *,
             deny_hits=None, allow_hits=None, boundary_hits=None,
             indeterminate=None, relevant_gaps=None, gap: str = "") -> dict[str, Any]:
    return {
        "target_id": target["id"],
        "action": target["action"],
        "resource": target["resource"],
        "verdict": name,
        "determined": name in ("DENY_EXPLICIT", "ALLOW_EFFECTIVE", "IMPLICIT_DENY"),
        "explicit_deny": deny_hits or [],
        "identity_allows": allow_hits or [],
        "boundary_allows": boundary_hits or [],
        "indeterminate_conditions": indeterminate or [],
        "relevant_gaps": relevant_gaps or [],
        "gap": gap,
    }


def run(manifest_path: str, targets_path: str) -> dict[str, Any]:
    bundle = load_bundle(manifest_path)
    with open(targets_path, encoding="utf-8") as handle:
        targets = json.load(handle)["targets"]
    results = [analyze_target(bundle, target) for target in targets]
    return {
        "role": bundle.role,
        "snapshot": bundle.snapshot,
        "boundary_present": bundle.boundary_present,
        "boundary_completeness": bundle.boundary_completeness,
        "missing_inputs": bundle.missing_inputs,
        "results": results,
    }
