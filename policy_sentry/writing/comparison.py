"""
Compare two rendered artifacts of the same template.

Approvers need to answer "what moved because the catalog moved?" without
re-reading two full policies.  The comparison is deliberately conservative:

* a statement/action pair is *unchanged* only when it carries the same basis
  fingerprint, which includes the documented access level, the correction (if
  any), the origin (template section/ARN), and the condition keys; and
* anything that is not provably unchanged is reported as changed, together with
  the catalog entries or correction approvals that caused the change.

Catalog changes that only touch actions the template never asks for are kept
apart, so they can be confirmed as irrelevant instead of being mistaken for an
empty diff.
"""

from __future__ import annotations

from typing import Any

UNCHANGED = "unchanged"
CATALOG_CHANGED = "catalog_changed"
CORRECTION_CHANGED = "correction_changed"
STATEMENT_CHANGED = "statement_changed"
ADDED = "added"
REMOVED = "removed"


def _by_action(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {record["action"].lower(): record for record in records}


def _statement_map(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {statement.get("Sid"): statement for statement in policy.get("Statement", [])}


def _correction_identity(record: dict[str, Any]) -> dict[str, Any] | None:
    """The parts of a correction that describe *who approved what*, not the catalog snapshot."""
    correction = record.get("correction")
    if not correction:
        return None
    return {
        "id": correction.get("id"),
        "corrected_access_level": correction.get("corrected_access_level"),
        "approval": record.get("approval"),
    }


def _approval_changed(before: dict[str, Any] | None, after: dict[str, Any] | None) -> bool:
    if (before is None) != (after is None):
        return True
    if before is None or after is None:
        return False
    return _correction_identity(before) != _correction_identity(after)


def _catalog_changed(before: dict[str, Any], after: dict[str, Any]) -> bool:
    keys = (
        "documented_access_level",
        "effective_access_level",
        "resource_type",
        "resource_type_arn",
        "service_prefix",
        "embedded_override",
    )
    return any(before["catalog"].get(key) != after["catalog"].get(key) for key in keys)


def compare_rendered_artifacts(
    baseline: Any,
    candidate: Any,
    correction_set: Any,
) -> dict[str, Any]:
    """Compare two :class:`~policy_sentry.writing.provenance.RenderedArtifact` objects."""
    baseline_actions = _by_action(baseline.records)
    candidate_actions = _by_action(candidate.records)
    baseline_statements = _statement_map(baseline.policy)
    candidate_statements = _statement_map(candidate.policy)

    entries: list[dict[str, Any]] = []
    for action in sorted(set(baseline_actions) | set(candidate_actions)):
        before = baseline_actions.get(action)
        after = candidate_actions.get(action)

        if before is None:
            entries.append(
                {
                    "action": after["action"],
                    "status": ADDED,
                    "permissions_changed": True,
                    "basis_changed": True,
                    "before": None,
                    "after": after,
                    "causes": _causes_for_added(after),
                }
            )
            continue
        if after is None:
            entries.append(
                {
                    "action": before["action"],
                    "status": REMOVED,
                    "permissions_changed": True,
                    "basis_changed": True,
                    "before": before,
                    "after": None,
                    "causes": _causes_for_removed(before),
                }
            )
            continue

        if before["basis_fingerprint"] == after["basis_fingerprint"]:
            status = UNCHANGED
            causes: list[dict[str, Any]] = []
        elif _catalog_changed(before, after):
            # A documented value moved underneath an (optionally corrected) rule.
            status = CATALOG_CHANGED
            causes = _catalog_causes(before, after)
            if _approval_changed(before, after):
                causes.extend(_correction_causes(before, after))
        elif _approval_changed(before, after):
            status = CORRECTION_CHANGED
            causes = _correction_causes(before, after)
        else:
            status = STATEMENT_CHANGED
            causes = _statement_causes(before, after)

        statement_before = before["statement"]
        statement_after = after["statement"]
        entries.append(
            {
                "action": after["action"],
                "status": status,
                "permissions_changed": statement_before != statement_after,
                "basis_changed": status != UNCHANGED,
                "before": before,
                "after": after,
                "causes": causes,
            }
        )

    statement_entries = _compare_statements(baseline_statements, candidate_statements, entries)

    changed = [entry for entry in entries if entry["status"] != UNCHANGED]
    unchanged = [entry for entry in entries if entry["status"] == UNCHANGED]

    policy_actions = {record["action"] for record in baseline.records} | {
        record["action"] for record in candidate.records
    }
    catalog_delta = summarize_catalog_delta(baseline.catalog, candidate.catalog, policy_actions)
    approvals = approval_review(baseline, candidate, correction_set)

    return {
        "baseline": baseline.label,
        "catalog": candidate.label,
        "catalog_versions": {
            "baseline": baseline.catalog_version.to_dict(),
            "catalog": candidate.catalog_version.to_dict(),
        },
        "artifacts": {
            "baseline": {
                "label": baseline.label,
                "policy_sha256": baseline.policy_sha256,
                "template_sha256": baseline.template_sha256,
            },
            "catalog": {
                "label": candidate.label,
                "policy_sha256": candidate.policy_sha256,
                "template_sha256": candidate.template_sha256,
            },
            "policies_identical": baseline.policy_sha256 == candidate.policy_sha256,
        },
        "summary": {
            "actions_total": len(entries),
            "actions_changed": len(changed),
            "actions_unchanged": len(unchanged),
            "permissions_changed": sum(1 for entry in changed if entry["permissions_changed"]),
            "basis_changed_only": sum(1 for entry in changed if not entry["permissions_changed"]),
            "statements_changed": sum(
                1 for entry in statement_entries if entry["status"] not in (UNCHANGED, "basis_changed")
            ),
            "statements_basis_changed": sum(1 for entry in statement_entries if entry["status"] == "basis_changed"),
            "records_reused": len(unchanged),
            "catalog_changes_outside_template": len(catalog_delta["not_used_by_template"]),
            "approvals_to_reopen": len(approvals["reopen"]),
        },
        "actions": changed,
        "unchanged": [
            {
                "action": entry["action"],
                "statement": entry["after"]["statement"],
                "basis_fingerprint": entry["after"]["basis_fingerprint"],
                "record_id": entry["after"]["record_id"],
                "superseded_record_id": entry["before"]["record_id"],
                "reused_basis": True,
            }
            for entry in unchanged
        ],
        "statements": statement_entries,
        "catalog_delta": catalog_delta,
        "approvals": approvals,
        "verdict": _verdict(changed, statement_entries, catalog_delta),
    }


def _compare_statements(
    baseline_statements: dict[str, dict[str, Any]],
    candidate_statements: dict[str, dict[str, Any]],
    entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    results = []
    for sid in sorted(set(baseline_statements) | set(candidate_statements), key=str):
        before_statement = baseline_statements.get(sid)
        after_statement = candidate_statements.get(sid)
        before_actions = sorted(before_statement.get("Action", [])) if before_statement else []
        after_actions = sorted(after_statement.get("Action", [])) if after_statement else []
        if before_statement is None:
            state = ADDED
        elif after_statement is None:
            state = REMOVED
        changed_actions = sorted(
            entry["action"]
            for entry in entries
            if entry["status"] != UNCHANGED
            and (
                (entry["before"] or {}).get("statement", {}).get("sid") == sid
                or (entry["after"] or {}).get("statement", {}).get("sid") == sid
            )
        )
        permissions_changed = (
            before_statement is None
            or after_statement is None
            or before_actions != after_actions
            or before_statement.get("Resource") != after_statement.get("Resource")
            or before_statement.get("Effect") != after_statement.get("Effect")
        )
        if before_statement is None:
            state = ADDED
        elif after_statement is None:
            state = REMOVED
        elif permissions_changed:
            state = "changed"
        elif changed_actions:
            state = "basis_changed"
        else:
            state = UNCHANGED
        results.append(
            {
                "sid": sid,
                "status": state,
                "permissions_changed": permissions_changed,
                "before_actions": before_actions,
                "after_actions": after_actions,
                "before_resources": before_statement.get("Resource", []) if before_statement else [],
                "after_resources": after_statement.get("Resource", []) if after_statement else [],
                "changed_actions": changed_actions,
            }
        )
    return results


def summarize_catalog_delta(
    baseline_catalog: dict[str, Any],
    candidate_catalog: dict[str, Any],
    policy_actions: set[str],
) -> dict[str, Any]:
    """Catalog access-level changes, split into template-used and unused actions."""
    lower_policy_actions = {action.lower() for action in policy_actions}
    used: list[dict[str, Any]] = []
    unused: list[dict[str, Any]] = []
    services_added: list[str] = []
    services_removed: list[str] = []

    baseline_services = {
        key for key, value in baseline_catalog.items() if isinstance(value, dict) and "privileges" in value
    }
    candidate_services = {
        key for key, value in candidate_catalog.items() if isinstance(value, dict) and "privileges" in value
    }
    services_added = sorted(candidate_services - baseline_services)
    services_removed = sorted(baseline_services - candidate_services)

    for service in sorted(baseline_services & candidate_services):
        before_privileges = baseline_catalog[service].get("privileges", {})
        after_privileges = candidate_catalog[service].get("privileges", {})
        for action in sorted(set(before_privileges) & set(after_privileges)):
            before_entry = before_privileges[action]
            after_entry = after_privileges[action]
            before_level = before_entry.get("access_level")
            after_level = after_entry.get("access_level")
            before_documented = before_entry.get("access_level_documented", before_level)
            after_documented = after_entry.get("access_level_documented", after_level)
            before_types = sorted(before_entry.get("resource_types", {}))
            after_types = sorted(after_entry.get("resource_types", {}))
            if (
                before_level == after_level
                and before_documented == after_documented
                and before_types == after_types
            ):
                continue
            qualified = f"{service}:{action}"
            change = {
                "action": qualified,
                "access_level": {"before": before_level, "after": after_level},
                "documented_access_level": {"before": before_documented, "after": after_documented},
                "resource_types": {"before": before_types, "after": after_types},
            }
            if qualified.lower() in lower_policy_actions:
                used.append(change)
            else:
                unused.append(change)

    return {
        "used_by_template": used,
        "not_used_by_template": unused,
        "services_added": services_added,
        "services_removed": services_removed,
    }


def approval_review(
    baseline: Any,
    candidate: Any,
    correction_set: Any,
    without_rule: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Decide which corrections used by the baseline still hold, and which need a
    fresh approval because the documented value they overrode has moved.
    """
    still_applies: list[dict[str, Any]] = []
    reopen: list[dict[str, Any]] = []
    used_ids = {
        record["correction"]["id"]
        for record in baseline.records
        if record.get("correction") is not None
    }
    corrections = {correction.id: correction for correction in correction_set if correction.id in used_ids}
    for correction_id, correction in sorted(corrections.items()):
        baseline_level = _documented_level(baseline.catalog, correction.service, correction.action)
        candidate_level = _documented_level(candidate.catalog, correction.service, correction.action)
        payload = {
            "correction_id": correction_id,
            "action": correction.qualified_action,
            "corrected_access_level": correction.corrected_access_level,
            "documented_access_level": {"baseline": baseline_level, "catalog": candidate_level},
            "approval": correction.approval.to_dict(),
        }
        if without_rule and correction_id in without_rule:
            payload["without_rule"] = without_rule[correction_id]
        if baseline_level != candidate_level:
            payload["reason"] = "the catalog value this rule overrode has changed"
            reopen.append(payload)
        else:
            payload["reason"] = "the catalog value this rule overrode is unchanged"
            still_applies.append(payload)
    return {"still_applies": still_applies, "reopen": reopen}


def _documented_level(catalog: dict[str, Any], service: str, action: str) -> str | None:
    service_data = catalog.get(service.lower())
    if not isinstance(service_data, dict):
        return None
    canonical = service_data.get("privileges_lower_name", {}).get(action.lower(), action)
    entry = service_data.get("privileges", {}).get(canonical)
    if entry is None:
        return None
    return entry.get("access_level_documented", entry.get("access_level"))


def _verdict(
    changed: list[dict[str, Any]],
    statements: list[dict[str, Any]],
    catalog_delta: dict[str, Any],
) -> str:
    if any(entry["permissions_changed"] for entry in changed) or any(
        statement["status"] in (ADDED, REMOVED, "changed") for statement in statements
    ):
        return "policy_changed"
    if changed:
        return "basis_changed"
    if catalog_delta["not_used_by_template"]:
        return "catalog_changed_outside_template"
    return "no_change"


def _correction_causes(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    causes = []
    before_correction = before.get("correction") or {}
    after_correction = after.get("correction") or {}
    if before_correction.get("id") != after_correction.get("id"):
        causes.append(
            {
                "type": "correction_membership",
                "correction_id": after_correction.get("id") or before_correction.get("id"),
                "before": before_correction or None,
                "after": after_correction or None,
            }
        )
    if before.get("approval") != after.get("approval"):
        causes.append(
            {
                "type": "approval",
                "correction_id": after_correction.get("id") or before_correction.get("id"),
                "before": before.get("approval"),
                "after": after.get("approval"),
            }
        )
    return causes


def _catalog_causes(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    causes = []
    for key in ("documented_access_level", "resource_type", "resource_type_arn", "service_prefix", "service_name"):
        if before["catalog"].get(key) != after["catalog"].get(key):
            causes.append(
                {
                    "type": "catalog_entry",
                    "field": key,
                    "before": before["catalog"].get(key),
                    "after": after["catalog"].get(key),
                }
            )
    if before["conditions"].get("keys") != after["conditions"].get("keys"):
        causes.append(
            {
                "type": "catalog_conditions",
                "before": before["conditions"].get("keys"),
                "after": after["conditions"].get("keys"),
            }
        )
    return causes


def _statement_causes(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    causes = []
    if before["statement"] != after["statement"]:
        causes.append(
            {
                "type": "statement",
                "before": before["statement"],
                "after": after["statement"],
            }
        )
    if before["origin"] != after["origin"]:
        causes.append({"type": "origin", "before": before["origin"], "after": after["origin"]})
    return causes


def _causes_for_added(after: dict[str, Any]) -> list[dict[str, Any]]:
    causes: list[dict[str, Any]] = []
    if after.get("correction"):
        causes.append({"type": "correction", "correction_id": after["correction"].get("id")})
    causes.append(
        {
            "type": "catalog_entry",
            "field": "documented_access_level",
            "before": None,
            "after": after["catalog"].get("documented_access_level"),
        }
    )
    return causes


def _causes_for_removed(before: dict[str, Any]) -> list[dict[str, Any]]:
    causes: list[dict[str, Any]] = []
    if before.get("correction"):
        causes.append({"type": "correction", "correction_id": before["correction"].get("id")})
    causes.append(
        {
            "type": "catalog_entry",
            "field": "documented_access_level",
            "before": before["catalog"].get("documented_access_level"),
            "after": None,
        }
    )
    return causes
