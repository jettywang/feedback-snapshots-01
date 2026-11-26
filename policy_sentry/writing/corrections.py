"""Manual correction rules for catalog metadata, plus their approval state.

The catalog that ships with Policy Sentry is an *observation* of the AWS
documentation.  Security teams routinely keep a separate list of corrections to
that observation (for example, "``ssm:PutParameter`` is really a ``Write``
action, not ``Tagging``").  Those corrections need an approval trail, because a
published policy should be able to answer two questions:

* which rule, if any, changed the catalog value for this action; and
* which approvals should be revisited when the catalog moves underneath them.

This module only models and applies the rules.  It deliberately does not build
provenance records or comparisons - see :mod:`policy_sentry.writing.provenance`
and :mod:`policy_sentry.writing.comparison`.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import orjson

from policy_sentry.util.file import read_yaml_file

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "policy-sentry/corrections@1"
APPROVAL_STATUSES = ("approved", "pending", "rejected")
ACCESS_LEVELS = ("Read", "Write", "List", "Tagging", "Permissions management")


class CorrectionError(ValueError):
    """Raised when a corrections file cannot be trusted or safely applied."""


@dataclass(frozen=True)
class Approval:
    """The approval state attached to a correction rule."""

    status: str
    approver: str | None = None
    approved_at: str | None = None
    reference: str | None = None

    @property
    def is_approved(self) -> bool:
        return self.status == "approved"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "approver": self.approver,
            "approved_at": self.approved_at,
            "reference": self.reference,
        }


@dataclass(frozen=True)
class Correction:
    """A single human correction to one service action's access level."""

    id: str
    service: str
    action: str
    corrected_access_level: str
    rationale: str
    approval: Approval
    requested_by: str | None = None
    requested_at: str | None = None
    source_index: int = -1

    @property
    def qualified_action(self) -> str:
        return f"{self.service}:{self.action}"

    @property
    def key(self) -> tuple[str, str]:
        return (self.service.lower(), self.action.lower())

    @property
    def is_approved(self) -> bool:
        return self.approval.is_approved

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "service": self.service,
            "action": self.action,
            "corrected_access_level": self.corrected_access_level,
            "rationale": self.rationale,
            "requested_by": self.requested_by,
            "requested_at": self.requested_at,
            "approval": self.approval.to_dict(),
        }


@dataclass
class CorrectionSet:
    """A validated set of corrections, with a stable content hash."""

    corrections: list[Correction]
    sha256: str
    source: str | None = None

    def __iter__(self) -> Iterable[Correction]:
        return iter(self.corrections)

    def __len__(self) -> int:
        return len(self.corrections)

    def by_action(self) -> dict[tuple[str, str], Correction]:
        return {correction.key: correction for correction in self.corrections}

    def for_action(self, service: str, action: str) -> Correction | None:
        wanted = (service.lower(), action.lower())
        for correction in self.corrections:
            if correction.key == wanted:
                return correction
        return None

    def relevant_to_actions(self, actions: Iterable[str]) -> list[Correction]:
        wanted = {action.lower() for action in actions}
        return [correction for correction in self.corrections if correction.qualified_action.lower() in wanted]

    def for_service(self, service: str) -> list[Correction]:
        wanted = service.lower()
        return [correction for correction in self.corrections if correction.service.lower() == wanted]


@dataclass
class AppliedCorrection:
    """The outcome of applying one correction to a catalog view."""

    correction: Correction
    documented_access_level: str | None
    effective_access_level: str | None
    changed: bool
    canonical_action: str | None = None
    issue: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.correction.id,
            "action": f"{self.correction.service}:{self.canonical_action or self.correction.action}",
            "documented_access_level": self.documented_access_level,
            "corrected_access_level": self.correction.corrected_access_level,
            "effective_access_level": self.effective_access_level,
            "changed_catalog_value": self.changed,
            "approval_status": self.correction.approval.status,
            "issue": self.issue,
        }


@dataclass
class CorrectionView:
    """A catalog view with approved corrections applied, plus what happened."""

    catalog: dict[str, Any]
    applied: list[AppliedCorrection] = field(default_factory=list)
    skipped: list[AppliedCorrection] = field(default_factory=list)

    @property
    def issues(self) -> list[AppliedCorrection]:
        return [entry for entry in self.applied + self.skipped if entry.issue]

    def applied_by_action(self) -> dict[tuple[str, str], AppliedCorrection]:
        return {
            (entry.correction.service.lower(), (entry.canonical_action or entry.correction.action).lower()): entry
            for entry in self.applied
        }

    def effective_level(self, service: str, action: str) -> str | None:
        """The access level in this view for an action (corrected, else documented)."""
        service_data = self.catalog.get(service)
        if not isinstance(service_data, dict):
            return None
        canonical = service_data.get("privileges_lower_name", {}).get(action.lower(), action)
        entry = service_data.get("privileges", {}).get(canonical)
        return None if entry is None else entry.get("access_level")


def _require_string(mapping: dict[str, Any], key: str, index: int) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise CorrectionError(f"corrections[{index}] is missing a non-empty '{key}'")
    return value.strip()


def _parse_approval(raw: Any, index: int) -> Approval:
    if not isinstance(raw, dict):
        raise CorrectionError(f"corrections[{index}].approval must be a mapping with a 'status'")
    status = raw.get("status")
    if status not in APPROVAL_STATUSES:
        raise CorrectionError(
            f"corrections[{index}].approval.status must be one of {', '.join(APPROVAL_STATUSES)}; got {status!r}"
        )
    return Approval(
        status=status,
        approver=raw.get("approver"),
        approved_at=raw.get("approved_at"),
        reference=raw.get("reference"),
    )


def parse_corrections(raw: Any, source: str | None = None) -> CorrectionSet:
    """Validate a parsed corrections document and return a :class:`CorrectionSet`."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise CorrectionError("the corrections file must be a mapping with a 'corrections' list")

    version = raw.get("schema", SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        raise CorrectionError(f"unsupported corrections schema {version!r}; expected {SCHEMA_VERSION!r}")

    entries = raw.get("corrections", [])
    if not isinstance(entries, list):
        raise CorrectionError("'corrections' must be a list")

    corrections: list[Correction] = []
    seen_ids: set[str] = set()
    seen_actions: dict[tuple[str, str], Correction] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise CorrectionError(f"corrections[{index}] must be a mapping")
        correction_id = _require_string(entry, "id", index)
        service = _require_string(entry, "service", index)
        action = _require_string(entry, "action", index)
        level = entry.get("corrected_access_level")
        if level not in ACCESS_LEVELS:
            raise CorrectionError(
                f"corrections[{index}].corrected_access_level must be one of {', '.join(ACCESS_LEVELS)}; got {level!r}"
            )
        rationale = _require_string(entry, "rationale", index)

        if correction_id in seen_ids:
            raise CorrectionError(f"duplicate correction id {correction_id!r}")
        seen_ids.add(correction_id)

        correction = Correction(
            id=correction_id,
            service=service,
            action=action,
            corrected_access_level=level,
            rationale=rationale,
            approval=_parse_approval(entry.get("approval"), index),
            requested_by=entry.get("requested_by"),
            requested_at=entry.get("requested_at"),
            source_index=index,
        )
        previous = seen_actions.get(correction.key)
        if previous is not None and previous.corrected_access_level != correction.corrected_access_level:
            raise CorrectionError(
                f"{correction.qualified_action} has conflicting corrections: "
                f"{previous.id} says {previous.corrected_access_level}, "
                f"{correction.id} says {correction.corrected_access_level}"
            )
        seen_actions[correction.key] = correction
        corrections.append(correction)

    fingerprint = hashlib.sha256(
        orjson.dumps(raw, option=orjson.OPT_SORT_KEYS)
    ).hexdigest()
    return CorrectionSet(corrections=corrections, sha256=fingerprint, source=source)


def load_corrections(path: str | Path) -> CorrectionSet:
    """Load and validate a corrections YAML file."""
    raw = read_yaml_file(path)
    return parse_corrections(raw, source=str(path))


def empty_correction_set() -> CorrectionSet:
    """A correction set with no rules, suitable for catalogs without corrections."""
    return parse_corrections({"corrections": []})


def apply_corrections(
    catalog: dict[str, Any],
    correction_set: CorrectionSet,
    *,
    include_unapproved: bool = False,
) -> CorrectionView:
    """
    Apply approved corrections to a *copy* of ``catalog``.

    Pending and rejected corrections never change generation.  Each correction
    that cannot be matched to the catalog is reported in ``skipped`` instead of
    being silently ignored, because an audit record must not claim a rule was
    used when the catalog could not support it.

    ``include_unapproved`` is for *what-if* analysis only (for example, "which
    template parts would this pending rule move?").  It must not be used to
    produce a publishable policy.

    Service dictionaries, privilege maps and the touched action entries are
    copied so the caller's catalog (and any other view) stays untouched.
    """
    view: dict[str, Any] = dict(catalog)
    applied: list[AppliedCorrection] = []
    skipped: list[AppliedCorrection] = []

    for correction in correction_set:
        if not correction.is_approved and not include_unapproved:
            continue

        service = correction.service.lower()
        service_data = view.get(service)
        if not isinstance(service_data, dict) or "privileges" not in service_data:
            skipped.append(
                AppliedCorrection(
                    correction=correction,
                    documented_access_level=None,
                    effective_access_level=None,
                    changed=False,
                    issue=f"service {service!r} is not present in this catalog",
                )
            )
            continue

        privileges_lower = service_data.get("privileges_lower_name", {})
        canonical = privileges_lower.get(correction.action.lower())
        privileges = service_data["privileges"]
        if not canonical or canonical not in privileges:
            skipped.append(
                AppliedCorrection(
                    correction=correction,
                    documented_access_level=None,
                    effective_access_level=None,
                    changed=False,
                    issue=f"action {correction.qualified_action} is not present in this catalog",
                )
            )
            continue

        entry = privileges[canonical]
        documented = entry.get("access_level")
        changed = documented != correction.corrected_access_level

        # Copy only the path we mutate.  This keeps catalog switching cheap even
        # for the ~19 MB bundled definition.
        new_service = dict(service_data)
        new_privileges = dict(privileges)
        new_entry = dict(entry)
        new_entry["access_level"] = correction.corrected_access_level
        new_privileges[canonical] = new_entry
        new_service["privileges"] = new_privileges
        view[service] = new_service

        applied.append(
            AppliedCorrection(
                correction=correction,
                documented_access_level=documented,
                effective_access_level=correction.corrected_access_level,
                changed=changed,
                canonical_action=canonical,
            )
        )

    return CorrectionView(catalog=view, applied=applied, skipped=skipped)


def list_unapproved_corrections(correction_set: CorrectionSet) -> list[Correction]:
    """Corrections that have not been approved, in file order."""
    return [correction for correction in correction_set if not correction.is_approved]
