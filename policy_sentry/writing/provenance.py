"""
Verifiable provenance for generated policies.

A provenance report answers, for every action that actually appears in a
rendered policy:

* which statement (Sid) carries it;
* why it is there (which template section, ARN, access level, or dependency);
* which catalog version documented its access level;
* which human correction, if any, changed that access level, and whether that
  correction was approved; and
* which condition keys the catalog associates with the action/resource pair.

Reports are scoped to one template: corrections, catalog services and template
sections that the template does not reach are not included.  Unapproved
corrections that *would* affect the template are called out explicitly, along
with the template parts that therefore cannot be published under that rule.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import orjson

from policy_sentry.shared.iam_data import (
    get_iam_definition_fingerprint,
    use_iam_definition,
)
from policy_sentry.util.file import read_yaml_file
from policy_sentry.writing.corrections import (
    AppliedCorrection,
    Correction,
    CorrectionSet,
    CorrectionView,
    apply_corrections,
    empty_correction_set,
)

logger = logging.getLogger(__name__)

REPORT_SCHEMA = "policy-sentry/provenance-report@1"
ARTIFACT_SCHEMA = "policy-sentry/provenance-artifact@1"


class ProvenanceError(ValueError):
    """Raised when a provenance report cannot be produced faithfully."""


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_json(payload: Any) -> bytes:
    """Deterministic JSON bytes, used for fingerprints."""
    return orjson.dumps(payload, option=orjson.OPT_SORT_KEYS)


@dataclass
class CatalogVersion:
    """Identity of a catalog, independent of how it was loaded."""

    label: str
    fingerprint: str
    schema_version: str | None
    source: str | None = None
    services: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "fingerprint": self.fingerprint,
            "schema_version": self.schema_version,
            "source": self.source,
            "services": self.services,
        }


def describe_catalog(
    catalog: dict[str, Any], label: str, source: str | None, services: Iterable[str]
) -> CatalogVersion:
    service_list = sorted({service for service in services if service in catalog})
    return CatalogVersion(
        label=label,
        fingerprint=get_iam_definition_fingerprint(catalog),
        schema_version=catalog.get("policy_sentry_schema_version"),
        source=source,
        services=service_list,
    )


@dataclass
class RenderedArtifact:
    """A rendered policy plus the state needed to explain it."""

    label: str
    catalog: dict[str, Any]
    catalog_version: CatalogVersion
    correction_set: CorrectionSet
    correction_view: CorrectionView
    template: dict[str, Any]
    template_sha256: str
    policy: dict[str, Any]
    sid_group: Any  # SidGroup - kept untyped to avoid an import cycle
    statements: list[dict[str, Any]] = field(default_factory=list)
    records: list[dict[str, Any]] = field(default_factory=list)

    @property
    def policy_sha256(self) -> str:
        return _sha256_bytes(canonical_json(self.policy))


def _render(template: dict[str, Any], catalog: dict[str, Any], minimize: int | None) -> tuple[dict[str, Any], Any]:
    # Imported lazily to keep module import order simple.
    from policy_sentry.writing.sid_group import SidGroup

    with use_iam_definition(catalog):
        sid_group = SidGroup()
        policy = sid_group.process_template(template, minimize)
    return policy, sid_group


def _find_group_for_statement(sid_group: Any, statement: dict[str, Any]) -> dict[str, Any] | None:
    """The SID group whose resource list became this statement."""
    for candidate in sid_group.sids.values():
        if candidate["arn"] == statement.get("Resource"):
            return candidate
    return None


def _find_group(sid_group: Any, statement: dict[str, Any], action: str) -> dict[str, Any] | None:
    group = sid_group.sids.get(statement.get("Sid"))
    if group and any(existing.lower() == action.lower() for existing in group["actions"]):
        return group
    for candidate in sid_group.sids.values():
        if candidate["arn"] == statement.get("Resource") and any(
            existing.lower() == action.lower() for existing in candidate["actions"]
        ):
            return candidate
    return None


def _resource_type_for_arn(service_data: dict[str, Any], raw_arn: str) -> str | None:
    for name, resource in service_data.get("resources", {}).items():
        if str(resource.get("arn", "")).lower() == raw_arn.lower():
            return name
    return None


def _condition_keys(service_data: dict[str, Any], entry: dict[str, Any], resource_type: str | None) -> list[str]:
    keys: set[str] = set()
    if resource_type:
        for key, resource_entry in entry.get("resource_types", {}).items():
            if key.lower() == resource_type.lower() or (
                resource_entry.get("resource_type", "").lower() == resource_type.lower()
            ):
                keys.update(resource_entry.get("condition_keys", []))
        resource = service_data.get("resources", {}).get(resource_type)
        if not resource:
            for name, candidate in service_data.get("resources", {}).items():
                if name.lower() == resource_type.lower():
                    resource = candidate
                    break
        if resource:
            keys.update(resource.get("condition_keys", []))
    else:
        for key, resource_entry in entry.get("resource_types", {}).items():
            if key == "":
                keys.update(resource_entry.get("condition_keys", []))
    return sorted(keys)


def _canonical_action(service_data: dict[str, Any], action: str) -> tuple[str, str]:
    service, name = action.split(":", 1)
    canonical = service_data.get("privileges_lower_name", {}).get(name.lower(), name)
    return service, canonical


def _correction_payload(
    correction: Correction | None, applied: AppliedCorrection | None, effective_level: str | None
) -> dict[str, Any] | None:
    if correction is None:
        return None
    payload: dict[str, Any] = correction.to_dict()
    payload["effective_access_level"] = effective_level
    if applied is not None:
        payload["documented_access_level_before_rule"] = applied.documented_access_level
    return payload


def _record_id(record: dict[str, Any]) -> str:
    basis = {
        "statement": record["statement"],
        "action": record["action"],
        "origin": record["origin"],
        "catalog": {
            key: record["catalog"].get(key)
            for key in (
                "service_prefix",
                "documented_access_level",
                "resource_type",
                "resource_type_arn",
            )
        },
        "correction": record["correction"],
        "conditions": record["conditions"],
    }
    return _sha256_bytes(canonical_json(basis))[:20]


def basis_fingerprint(record: dict[str, Any]) -> str:
    """
    Fingerprint of the *reasoning* behind a record, excluding artifact labels
    and catalog-global fingerprints.  Two artifacts that share this value made
    the same decision from the same documented basis.
    """
    basis = {
        "statement": record["statement"],
        "action": record["action"],
        "origin": record["origin"],
        "catalog": {
            "service_prefix": record["catalog"].get("service_prefix"),
            "documented_access_level": record["catalog"].get("documented_access_level"),
            "resource_type": record["catalog"].get("resource_type"),
            "resource_type_arn": record["catalog"].get("resource_type_arn"),
        },
        "correction": record["correction"],
        "conditions": record["conditions"],
    }
    return _sha256_bytes(canonical_json(basis))


def _build_records(artifact: RenderedArtifact) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    applied_by_action = artifact.correction_view.applied_by_action()
    # Record against the *effective* view, so a corrected action reports the
    # access level that actually produced its statement.
    effective_catalog = artifact.correction_view.catalog
    for statement in artifact.policy.get("Statement", []):
        group = _find_group_for_statement(artifact.sid_group, statement)
        backing = artifact.sid_group.rendered_actions.get(statement.get("Sid", ""), [])
        pairs = (
            [(entry["action"], entry["pattern"]) for entry in backing]
            if backing
            else [(action, action) for action in statement.get("Action", [])]
        )
        for action, rendered_pattern in pairs:
            service, action_name = action.split(":", 1)
            service_data = effective_catalog.get(service, {})
            canonical_service, canonical_name = _canonical_action(service_data, action)
            entry = service_data.get("privileges", {}).get(canonical_name, {})
            raw_arn = group["arn_format"] if group else "*"
            resource_type = _resource_type_for_arn(service_data, raw_arn) if raw_arn != "*" else None
            origin = artifact.sid_group.origin_tracker.get(statement.get("Sid", ""), action)
            applied = applied_by_action.get((canonical_service.lower(), canonical_name.lower()))
            correction = applied.correction if applied else None
            effective_level = entry.get("access_level")
            documented_level = (
                applied.documented_access_level
                if applied
                else entry.get("access_level_documented", effective_level)
            )
            embedded_override = entry.get("access_level_override")
            record = {
                "artifact": artifact.label,
                "statement": {
                    "sid": statement.get("Sid"),
                    "effect": statement.get("Effect"),
                    "resources": statement.get("Resource", []),
                },
                "action": f"{canonical_service}:{canonical_name}",
                "rendered_action": rendered_pattern,
                "origin": origin.to_dict() if origin else {"kind": "unknown", "template_section": "unknown"},
                "catalog": {
                    "version": artifact.catalog_version.label,
                    "fingerprint": artifact.catalog_version.fingerprint,
                    "schema_version": artifact.catalog_version.schema_version,
                    "source": artifact.catalog_version.source,
                    "service_prefix": canonical_service,
                    "service_name": service_data.get("service_name"),
                    "service_authorization_url": service_data.get("service_authorization_url"),
                    "documented_access_level": documented_level,
                    "effective_access_level": effective_level,
                    "resource_type": resource_type,
                    "resource_type_arn": None if raw_arn == "*" else raw_arn,
                    "api_documentation_link": entry.get("api_documentation_link"),
                    "embedded_override": embedded_override,
                },
                "correction": _correction_payload(correction, applied, effective_level),
                "approval": (
                    correction.approval.to_dict()
                    if correction
                    else {
                        "status": "catalog_documented",
                        "approver": None,
                        "approved_at": None,
                        "reference": None,
                    }
                ),
                "conditions": {
                    "keys": _condition_keys(service_data, entry, resource_type),
                    "source": "catalog",
                    "statement_conditions": statement.get("Condition"),
                },
            }
            record["basis_fingerprint"] = basis_fingerprint(record)
            record["record_id"] = _record_id(record)
            records.append(record)
    return records


def _statement_summaries(policy: dict[str, Any], records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_sid: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        by_sid.setdefault(record["statement"]["sid"], []).append(record)
    summaries = []
    for statement in policy.get("Statement", []):
        sid = statement.get("Sid")
        statements_records = by_sid.get(sid, [])
        summaries.append(
            {
                "sid": sid,
                "effect": statement.get("Effect"),
                "resources": statement.get("Resource", []),
                "actions": statement.get("Action", []),
                "record_ids": [record["record_id"] for record in statements_records],
                "template_sections": sorted(
                    {record["origin"].get("template_section", "unknown") for record in statements_records}
                ),
                "correction_ids": sorted(
                    {record["correction"]["id"] for record in statements_records if record["correction"]}
                ),
            }
        )
    return summaries


def render_artifact(
    template: dict[str, Any],
    catalog: dict[str, Any],
    correction_set: CorrectionSet,
    label: str,
    *,
    catalog_source: str | None = None,
    include_unapproved: bool = False,
    minimize: int | None = None,
) -> RenderedArtifact:
    """Render ``template`` against ``catalog`` and attach per-action provenance."""
    correction_view = apply_corrections(catalog, correction_set, include_unapproved=include_unapproved)
    policy, sid_group = _render(template, correction_view.catalog, minimize)

    used_services = sorted(
        {action.split(":", 1)[0] for statement in policy.get("Statement", []) for action in statement.get("Action", [])}
    )
    artifact = RenderedArtifact(
        label=label,
        catalog=catalog,
        catalog_version=describe_catalog(catalog, label, catalog_source, used_services),
        correction_set=correction_set,
        correction_view=correction_view,
        template=template,
        template_sha256=_sha256_bytes(canonical_json(template)),
        policy=policy,
        sid_group=sid_group,
    )
    artifact.records = _build_records(artifact)
    artifact.statements = _statement_summaries(policy, artifact.records)
    return artifact


def _template_sha_from_path(path: str | Path) -> str:
    return _sha256_bytes(Path(path).read_bytes())


def _load_template(path: str | Path) -> tuple[dict[str, Any], str]:
    template = read_yaml_file(path)
    return template, _template_sha_from_path(path)


def _pending_detail(
    correction: Correction,
    baseline: RenderedArtifact,
    hypothetical: RenderedArtifact,
) -> dict[str, Any] | None:
    """Explain how an unapproved correction would touch the template, if at all."""
    action = correction.qualified_action
    baseline_groups = baseline.sid_group.origin_tracker.origins_for_action(action)
    hypothetical_groups = hypothetical.sid_group.origin_tracker.origins_for_action(action)
    if not baseline_groups and not hypothetical_groups:
        return None

    baseline_statement = _statement_for_action(baseline.policy, action)
    hypothetical_statement = _statement_for_action(hypothetical.policy, action)
    baseline_record = next((r for r in baseline.records if r["action"].lower() == action.lower()), None)

    if baseline_statement is not None and hypothetical_statement is not None:
        if (
            baseline_statement.get("Sid") == hypothetical_statement.get("Sid")
            and baseline_statement.get("Resource") == hypothetical_statement.get("Resource")
        ):
            # The rule is already reflected by the catalog, so approval changes
            # the recorded basis but not the rendered permission.
            effect = "basis_only"
        else:
            effect = "statement_moves"
    elif baseline_statement is not None:
        effect = "would_remove_action"
    else:
        effect = "would_add_action"

    origins = hypothetical_groups or baseline_groups
    template_parts = []
    for sid, origin in origins:
        payload = origin.to_dict()
        payload["sid"] = sid
        template_parts.append(payload)

    detail = {
        "correction_id": correction.id,
        "action": action,
        "approval_status": correction.approval.status,
        "reason": correction.approval.reference or correction.rationale,
        "corrected_access_level": correction.corrected_access_level,
        "documented_access_level": (baseline_record or {}).get("catalog", {}).get("documented_access_level"),
        "effect_if_approved": effect,
        "template_parts": template_parts,
        "artifact_statements": {
            "current": _statement_ref(baseline.policy, action),
            "if_correction_applied": _statement_ref(hypothetical.policy, action),
        },
        "current_basis": (baseline_record or {}).get("basis_fingerprint"),
        "record_id": (baseline_record or {}).get("record_id"),
    }
    detail["message"] = _pending_message(detail, correction)
    return detail


def _statement_ref(policy: dict[str, Any], action: str) -> dict[str, Any] | None:
    statement = _statement_for_action(policy, action)
    if statement is None:
        return None
    return {
        "sid": statement.get("Sid"),
        "effect": statement.get("Effect"),
        "resources": statement.get("Resource", []),
    }


def _statement_for_action(policy: dict[str, Any], action: str) -> dict[str, Any] | None:
    wanted = action.lower()
    for statement in policy.get("Statement", []):
        for existing in statement.get("Action", []):
            candidate = existing.lower()
            if candidate == wanted:
                return statement
            # Minimized statements use safe wildcards such as ``ssm:getpar*``.
            if "*" in candidate and fnmatch.fnmatchcase(wanted, candidate):
                return statement
    return None


def _pending_message(detail: dict[str, Any], correction: Correction) -> str:
    parts = detail["template_parts"]
    sections = sorted({part.get("template_section", "unknown") for part in parts})
    section_text = ", ".join(sections) if sections else "the template"
    effect = detail["effect_if_approved"]
    if effect == "would_add_action":
        verdict = "the action is not in the current artifact; approving the rule would add it"
    elif effect == "would_remove_action":
        verdict = "the action is in the current artifact; approving the rule would remove it"
    elif effect == "statement_moves":
        verdict = "the action would move to a different statement/resource"
    else:
        verdict = "the catalog already matches the rule, so only the recorded basis would change"
    return (
        f"{correction.qualified_action} is governed by correction {correction.id}, whose approval is "
        f"'{correction.approval.status}'. Template section(s) {section_text} cannot be published under that rule; "
        f"{verdict}. The current artifact keeps the catalog-documented basis instead."
    )


def build_report(
    template_path: str | Path,
    catalog_paths: list[tuple[str, str | Path]],
    corrections_path: str | Path | None = None,
    *,
    generated_at: str | None = None,
    minimize: int | None = None,
) -> dict[str, Any]:
    """
    Build a provenance report for one template across one or more catalogs.

    ``catalog_paths`` is an ordered list of ``(label, path)`` pairs; the first
    entry is the baseline.  Every catalog is rendered against the same template
    and corrections file, and each later catalog is compared to the baseline.
    """
    if not catalog_paths:
        raise ProvenanceError("at least one catalog is required")

    template, template_sha = _load_template(template_path)
    if corrections_path is None:
        correction_set = empty_correction_set()
        corrections_source = None
    else:
        from policy_sentry.writing.corrections import load_corrections

        correction_set = load_corrections(corrections_path)
        corrections_source = str(corrections_path)

    artifacts: list[RenderedArtifact] = []
    for label, path in catalog_paths:
        from policy_sentry.shared.iam_data import load_iam_definition

        catalog = load_iam_definition(path)
        artifacts.append(
            render_artifact(
                template,
                catalog,
                correction_set,
                label,
                catalog_source=str(path),
                minimize=minimize,
            )
        )

    baseline = artifacts[0]
    policy_actions = {
        record["action"].lower() for artifact in artifacts for record in artifact.records
    }

    # One what-if render answers both questions: which rules could touch the
    # template, and which template parts each still-pending rule would move.
    hypothetical = render_artifact(
        template,
        baseline.catalog,
        correction_set,
        f"{baseline.label}:hypothetical",
        include_unapproved=True,
        minimize=minimize,
    )
    touched_by_hypothetical = hypothetical.sid_group.origin_tracker.actions()
    touched_by_hypothetical |= baseline.sid_group.origin_tracker.actions()
    irrelevant_corrections = [
        correction.to_dict()
        for correction in correction_set
        if correction.qualified_action.lower() not in policy_actions
        and correction.qualified_action.lower() not in touched_by_hypothetical
    ]
    blocked = []
    for correction in correction_set:
        if correction.is_approved:
            continue
        detail = _pending_detail(correction, baseline, hypothetical)
        if detail is not None:
            blocked.append(detail)

    comparisons = []
    for candidate in artifacts[1:]:
        comparison = compare_artifacts(baseline, candidate, correction_set)
        comparison["approvals"] = _annotate_without_rule(
            comparison["approvals"],
            baseline,
            candidate,
            template,
            correction_set,
            minimize,
        )
        comparisons.append(comparison)

    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "template": {
            "path": str(template_path),
            "sha256": template_sha,
            "name": template.get("name"),
            "mode": template.get("mode"),
            "minimize": minimize,
            "sections_used": sorted(
                {
                    record["origin"].get("template_section", "unknown")
                    for artifact in artifacts
                    for record in artifact.records
                }
            ),
        },
        "corrections": {
            "path": corrections_source,
            "sha256": correction_set.sha256,
            "relevant_ids": sorted(
                {
                    record["correction"]["id"]
                    for artifact in artifacts
                    for record in artifact.records
                    if record["correction"]
                }
            ),
            "unapproved": [
                correction.to_dict() for correction in correction_set if not correction.is_approved
                and correction.qualified_action.lower() in policy_actions
            ],
            "irrelevant_ids": sorted(correction["id"] for correction in irrelevant_corrections),
        },
        "artifacts": [artifact_payload(artifact) for artifact in artifacts],
        "comparisons": comparisons,
        "blocked_by_unapproved_rules": blocked,
        "scope": {
            "policy_actions": len(policy_actions),
            "statements": {artifact.label: len(artifact.statements) for artifact in artifacts},
        },
    }
    if generated_at is not None:
        report["generated_at"] = generated_at
    return report


def artifact_payload(artifact: RenderedArtifact) -> dict[str, Any]:
    """Serialize one rendered artifact for the report and for standalone review."""
    return {
        "schema": ARTIFACT_SCHEMA,
        "label": artifact.label,
        "template_sha256": artifact.template_sha256,
        "policy_sha256": artifact.policy_sha256,
        "catalog": artifact.catalog_version.to_dict(),
        "corrections_sha256": artifact.correction_set.sha256,
        "policy": artifact.policy,
        "statements": artifact.statements,
        "records": artifact.records,
        "correction_issues": [
            entry.to_dict() for entry in artifact.correction_view.issues
        ],
    }


def write_artifacts(report: dict[str, Any], output_dir: str | Path) -> list[Path]:
    """Write each artifact and the report as standalone, hash-addressable files."""
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    manifest: dict[str, Any] = {
        "schema": "policy-sentry/provenance-manifest@1",
        "files": {},
    }
    for artifact in report["artifacts"]:
        label = artifact["label"].replace("/", "_").replace(":", "_")
        artifact_dir = destination / label
        artifact_dir.mkdir(parents=True, exist_ok=True)
        policy_path = artifact_dir / "policy.json"
        policy_bytes = json.dumps(artifact["policy"], indent=2, sort_keys=True).encode() + b"\n"
        policy_path.write_bytes(policy_bytes)
        provenance_path = artifact_dir / "provenance.json"
        provenance_bytes = json.dumps(artifact, indent=2, sort_keys=True).encode() + b"\n"
        provenance_path.write_bytes(provenance_bytes)
        written.extend([policy_path, provenance_path])
        manifest["files"][str(policy_path.relative_to(destination))] = _sha256_bytes(policy_bytes)
        manifest["files"][str(provenance_path.relative_to(destination))] = _sha256_bytes(provenance_bytes)

    report_path = destination / "report.json"
    report_bytes = json.dumps(report, indent=2, sort_keys=True).encode() + b"\n"
    report_path.write_bytes(report_bytes)
    written.append(report_path)
    manifest["files"][report_path.name] = _sha256_bytes(report_bytes)

    manifest_path = destination / "manifest.json"
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
    manifest_path.write_bytes(manifest_bytes)
    written.append(manifest_path)
    return written


def _annotate_without_rule(
    approvals: dict[str, Any],
    baseline: RenderedArtifact,
    candidate: RenderedArtifact,
    template: dict[str, Any],
    correction_set: CorrectionSet,
    minimize: int | None = None,
) -> dict[str, Any]:
    """
    Show what each corrected action would look like if its rule were withdrawn.

    This is what lets an approver decide whether a reopened approval still
    needs the rule: if the action stays in the same statement with the same
    resource, the rule is currently load-bearing for the *reason* recorded, and
    the note says so.
    """
    rule_ids = {entry["correction_id"] for entry in approvals["reopen"]} | {
        entry["correction_id"] for entry in approvals["still_applies"]
    }
    if not rule_ids:
        return approvals
    without = _correction_set_without(correction_set, rule_ids)
    for snapshot, label in ((baseline, "baseline"), (candidate, "catalog")):
        stripped = render_artifact(
            template,
            snapshot.catalog,
            without,
            f"{snapshot.label}:without-rules",
            minimize=minimize,
        )
        for entry in approvals["reopen"] + approvals["still_applies"]:
            action = entry["action"]
            with_rule = _statement_ref(snapshot.policy, action)
            ruleless = _statement_ref(stripped.policy, action)
            if ruleless is None:
                effect = "withdrawing_the_rule_removes_the_action"
            elif with_rule is None:
                effect = "withdrawing_the_rule_adds_the_action"
            elif ruleless == with_rule:
                effect = "withdrawing_the_rule_changes_nothing"
            else:
                effect = "withdrawing_the_rule_moves_the_action"
            entry.setdefault("without_rule", {})[label] = {
                "statement": ruleless,
                "same_statement_as_with_rule": ruleless == with_rule,
                "effect": effect,
            }
    return approvals


def _correction_set_without(correction_set: CorrectionSet, excluded_ids: set[str]) -> CorrectionSet:
    """A copy of ``correction_set`` with some rules removed, keeping the file hash."""
    from policy_sentry.writing.corrections import CorrectionSet

    return CorrectionSet(
        corrections=[c for c in correction_set if c.id not in excluded_ids],
        sha256=correction_set.sha256,
        source=correction_set.source,
    )


def compare_artifacts(
    baseline: RenderedArtifact,
    candidate: RenderedArtifact,
    correction_set: CorrectionSet,
) -> dict[str, Any]:
    """Compare two rendered artifacts, statement by statement and action by action."""
    from policy_sentry.writing.comparison import compare_rendered_artifacts

    return compare_rendered_artifacts(baseline, candidate, correction_set)
