"""Role handover support for Policy Sentry CRUD templates.

A role handover lets a colleague operate one approved project for a bounded time window.
The template keeps two kinds of declarations separate:

* the standing (formal) permission declared at the top level of the CRUD template, and
* temporary project permissions declared under ``handover.projects``.

Temporary permission is only effective while the approval names the project *and* the
evaluation timestamp falls inside the approved window. Standing permission is never
derived from the temporary declarations, so removing the handover block (or letting the
window expire) cannot remove the role's formal duties.

Every effective permission carries provenance back to the declaration(s) that granted it.
When the template asks for a combination that cannot be represented clearly (for example a
temporary action on a wildcard resource, or a formal ``Deny`` mixed with temporary
``Allow``), the evaluator reports a conflict that a human must resolve instead of merging
silently.
"""

from __future__ import annotations

import copy
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from policy_sentry.writing.sid_group import SidGroup
from policy_sentry.writing.validate import check_handover_schema

logger = logging.getLogger(__name__)

STANDING = "standing"
TEMPORARY = "temporary"

STATUS_NOT_APPROVED = "not-approved"
STATUS_SCHEDULED = "scheduled"
STATUS_ACTIVE = "active"
STATUS_EXPIRED = "expired"
STATUS_INVALID_WINDOW = "invalid-window"

SID_SANITIZE_PATTERN = re.compile(r"[^A-Za-z0-9]+")


class HandoverConfigError(ValueError):
    """Raised when a handover cannot be evaluated at all (as opposed to a template conflict)."""


@dataclass(frozen=True)
class Permission:
    """A single (action, resource) pair together with where it came from."""

    action: str
    resource: str
    origin: str
    project: str | None = None

    def source(self, approval: dict[str, str] | None) -> dict[str, Any]:
        """Describe the declaration that contributed this permission."""
        if self.origin == STANDING:
            return {"origin": STANDING}
        source: dict[str, Any] = {"origin": TEMPORARY, "project": self.project}
        if approval is not None:
            source["approval"] = dict(approval)
        return source


def _parse_timestamp(value: Any, field: str) -> datetime:
    """Parse an ISO-8601 timestamp and return a timezone-aware UTC datetime."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as error:
            raise ValueError(f"{field} is not a valid ISO-8601 timestamp: {value!r}") from error
    else:
        raise ValueError(f"{field} must be an ISO-8601 timestamp string, got: {value!r}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _isoformat(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _deduplicate(permissions: list[Permission]) -> list[Permission]:
    seen: dict[tuple[str, str, str, str | None], Permission] = {}
    for permission in permissions:
        seen.setdefault(
            (permission.action, permission.resource, permission.origin, permission.project),
            permission,
        )
    return list(seen.values())


def _scope_from_crud(
    cfg: dict[str, Any],
    origin: str,
    project: str | None = None,
) -> tuple[list[Permission], list[dict[str, Any]]]:
    """Render a CRUD config and turn its statements into (action, resource) permissions."""
    rendered = SidGroup().process_template(copy.deepcopy(cfg))
    permissions: list[Permission] = []
    denied: list[dict[str, Any]] = []
    for statement in rendered.get("Statement", []):
        resources = statement.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if statement.get("Effect") == "Deny":
            denied.extend({"action": action, "resource": resource} for action in actions for resource in resources)
            continue
        permissions.extend(
            Permission(action=action, resource=resource, origin=origin, project=project)
            for action in actions
            for resource in resources
        )
    return _deduplicate(permissions), denied


def _project_access_config(project: dict[str, Any]) -> dict[str, Any]:
    access = copy.deepcopy(project.get("access") or {})
    access["mode"] = "crud"
    return access


def _split_cfg(cfg: dict[str, Any]) -> dict[str, Any]:
    """Return the standing CRUD config with the handover block removed."""
    return {key: value for key, value in cfg.items() if key != "handover"}


def _collect_conflicts(
    handover: dict[str, Any],
    approval: dict[str, Any] | None,
    projects: list[dict[str, Any]],
    standing_effect: str,
) -> list[dict[str, Any]]:
    conflicts: list[dict[str, Any]] = []

    def add(code: str, message: str, **details: Any) -> None:
        conflicts.append({"code": code, "message": message, "details": details})

    if approval is None:
        if projects:
            add(
                "approval-missing",
                "Projects are declared but no handover approval names the one project that may be operated.",
                declared_projects=[project.get("name") for project in projects],
            )
        return conflicts

    approved_project = approval.get("project")
    project_names = [project.get("name") for project in projects]
    duplicates = {name for name in project_names if project_names.count(name) > 1}
    if duplicates:
        add("duplicate-project", "Project names must be unique inside a handover.", projects=sorted(duplicates))
    if not approved_project:
        add("approval-project-missing", "The handover approval must name the approved project.")
    elif approved_project not in project_names:
        add(
            "approval-unknown-project",
            "The handover approval names a project that is not declared under handover.projects.",
            approved_project=approved_project,
            declared_projects=project_names,
        )
    if not projects:
        add("projects-missing", "The handover approval names a project but no project access is declared.")

    if standing_effect != "Allow":
        add(
            "effect-not-expressible",
            "A formal Deny combined with a temporary Allow cannot be represented as one policy; "
            "resolve the formal effect before handing over.",
            standing_effect=standing_effect,
        )
    for project in projects:
        project_effect = (project.get("access") or {}).get("effect", "Allow")
        if project_effect != "Allow":
            add(
                "effect-not-expressible",
                "Temporary project access must be Allow to combine with the standing role; "
                "temporary Deny is not representable in this evaluation.",
                project=project.get("name"),
                effect=project_effect,
            )
    return conflicts


def _window(
    approval: dict[str, Any],
) -> tuple[datetime | None, datetime | None, list[dict[str, Any]]]:
    conflicts: list[dict[str, Any]] = []
    try:
        start = _parse_timestamp(approval.get("start"), "handover.approval.start")
        end = _parse_timestamp(approval.get("end"), "handover.approval.end")
    except ValueError as error:
        conflicts.append({"code": "invalid-window", "message": str(error), "details": {}})
        return None, None, conflicts
    if start >= end:
        conflicts.append(
            {
                "code": "invalid-window",
                "message": "The handover window must end after it starts.",
                "details": {"start": _isoformat(start), "end": _isoformat(end)},
            }
        )
        return None, None, conflicts
    return start, end, conflicts


def _status_for(start: datetime | None, end: datetime | None, moment: datetime) -> str:
    if start is None or end is None:
        return STATUS_INVALID_WINDOW
    if moment < start:
        return STATUS_SCHEDULED
    if moment >= end:
        return STATUS_EXPIRED
    return STATUS_ACTIVE


def _project_permissions(
    project: dict[str, Any],
) -> tuple[list[Permission], list[dict[str, Any]]]:
    """Build temporary permissions for one approved project, flagging unbounded resources."""
    name = project.get("name")
    permissions, denied = _scope_from_crud(_project_access_config(project), TEMPORARY, str(name))
    conflicts: list[dict[str, Any]] = []
    bounded: list[Permission] = []
    for permission in permissions:
        if permission.resource in ("*", "arn:*"):
            conflicts.append(
                {
                    "code": "temporary-resource-unbounded",
                    "message": (
                        "Temporary permission cannot be tied to the approved project because the action "
                        "is granted on a wildcard resource; narrow it in the project access block or "
                        "handle it as a manual exception."
                    ),
                    "details": {
                        "project": name,
                        "action": permission.action,
                        "resource": permission.resource,
                    },
                }
            )
            continue
        bounded.append(permission)
    for entry in denied:
        conflicts.append(
            {
                "code": "effect-not-expressible",
                "message": "Temporary project Deny statements cannot be combined with the standing role.",
                "details": {"project": name, **entry},
            }
        )
    return bounded, conflicts


def _resolve(cfg: dict[str, Any], moment: datetime) -> dict[str, Any]:
    """Internal working result shared by the public evaluators."""
    if not isinstance(cfg.get("handover"), dict):
        raise HandoverConfigError("The template does not declare a `handover` block.")

    check_handover_schema(cfg)

    handover = cfg["handover"]
    approval = handover.get("approval")
    projects = list(handover.get("projects") or [])
    standing_cfg = _split_cfg(cfg)
    standing_effect = str(standing_cfg.get("effect", "Allow"))

    standing_permissions, standing_denied = _scope_from_crud(standing_cfg, STANDING)
    conflicts = _collect_conflicts(handover, approval, projects, standing_effect)

    approved_project = approval.get("project") if approval else None
    start = end = None
    status = STATUS_NOT_APPROVED
    temporary_permissions: list[Permission] = []
    active_projects: list[str] = []

    if approval is not None:
        start, end, window_conflicts = _window(approval)
        conflicts.extend(window_conflicts)
        status = _status_for(start, end, moment)
        if status == STATUS_ACTIVE:
            duplicate_names = {project.get("name") for project in projects}
            duplicate_names = {
                name for name in duplicate_names if [p.get("name") for p in projects].count(name) > 1
            }
            if approved_project not in duplicate_names:
                for project in projects:
                    if project.get("name") != approved_project:
                        continue
                    project_permissions, project_conflicts = _project_permissions(project)
                    temporary_permissions.extend(project_permissions)
                    conflicts.extend(project_conflicts)
                    active_projects.append(str(project.get("name")))

    temporary_permissions = _deduplicate(temporary_permissions)

    available: dict[tuple[str, str], list[dict[str, Any]]] = {}

    def record(permission: Permission, approval_ref: dict[str, str] | None) -> None:
        key = (permission.action, permission.resource)
        source = permission.source(approval_ref)
        sources = available.setdefault(key, [])
        if source not in sources:
            sources.append(source)

    for permission in standing_permissions:
        record(permission, None)
    for permission in temporary_permissions:
        record(permission, approval)

    available_rows = [
        {
            "action": action,
            "resource": resource,
            "origins": sorted({source["origin"] for source in sources}),
            "sources": sorted(
                sources,
                key=lambda source: (source["origin"], str(source.get("project")), str(source.get("approval"))),
            ),
        }
        for (action, resource), sources in sorted(available.items())
    ]

    denied_rows = [
        {"action": entry["action"], "resource": entry["resource"], "origin": STANDING}
        for entry in sorted(standing_denied, key=lambda entry: (entry["action"], entry["resource"]))
    ]

    approval_view = None
    if approval is not None:
        approval_view = {
            "project": approval.get("project"),
            "start": _isoformat(start) if start else approval.get("start"),
            "end": _isoformat(end) if end else approval.get("end"),
            "start_inclusive": True,
            "end_exclusive": True,
        }

    return {
        "role": cfg.get("name", ""),
        "evaluated_at": _isoformat(moment),
        "handover": {
            "approval": approval_view,
            "status": status,
            "active_projects": sorted(active_projects),
            "declared_projects": sorted(str(project.get("name")) for project in projects),
        },
        "standing_scope": [
            {"action": permission.action, "resource": permission.resource}
            for permission in sorted(standing_permissions, key=lambda p: (p.action, p.resource))
        ],
        "temporary_scope": [
            {"action": permission.action, "resource": permission.resource, "project": permission.project}
            for permission in sorted(temporary_permissions, key=lambda p: (p.action, p.resource))
        ],
        "available_permissions": available_rows,
        "denied_permissions": denied_rows,
        "conflicts": conflicts,
    }


def _summarize(result: dict[str, Any]) -> dict[str, int]:
    rows = result["available_permissions"]
    return {
        "available": len(rows),
        "standing_only": sum(1 for row in rows if row["origins"] == [STANDING]),
        "temporary_only": sum(1 for row in rows if row["origins"] == [TEMPORARY]),
        "shared_origin": sum(1 for row in rows if len(row["origins"]) > 1),
        "conflicts": len(result["conflicts"]),
    }


def evaluate_handover(
    cfg: dict[str, Any],
    at: datetime | str | None = None,
) -> dict[str, Any]:
    """Evaluate the permissions available to the role at a point in time.

    Arguments:
        cfg: A loaded CRUD-mode template, optionally with a ``handover`` block.
        at: When to evaluate. Accepts a timezone-aware datetime or an ISO-8601 string.
            Defaults to the current UTC time.
    Returns:
        Dictionary: The approval status, each available permission with its declaration
        sources, the standing and temporary scopes separately, denied permissions, and
        conflicts that require human handling.
    """
    moment = datetime.now(timezone.utc) if at is None else _parse_timestamp(at, "evaluated_at")
    result = _resolve(cfg, moment)
    result["summary"] = _summarize(result)
    return result


def usable_permissions(cfg: dict[str, Any], at: datetime | str | None = None) -> list[dict[str, Any]]:
    """Return only the available permission rows at a point in time."""
    return evaluate_handover(cfg, at)["available_permissions"]


def render_temporary_policy(cfg: dict[str, Any], at: datetime | str | None = None) -> dict[str, Any]:
    """Render the policy contributed by the temporary approval at a point in time.

    The result is empty outside the approved window, so removing the temporary policy
    leaves the standing policy untouched.
    """
    moment = datetime.now(timezone.utc) if at is None else _parse_timestamp(at, "evaluated_at")
    result = _resolve(cfg, moment)
    actions_by_resource: dict[str, list[str]] = {}
    for row in result["temporary_scope"]:
        actions_by_resource.setdefault(row["resource"], []).append(row["action"])

    statements = []
    for index, (resource, actions) in enumerate(sorted(actions_by_resource.items()), start=1):
        statements.append(
            {
                "Sid": f"TemporaryHandover{index}",
                "Effect": "Allow",
                "Action": sorted(set(actions)),
                "Resource": [resource],
            }
        )
    return {"Version": "2012-10-17", "Statement": statements}


def render_effective_policy(
    cfg: dict[str, Any],
    at: datetime | str | None = None,
) -> dict[str, Any]:
    """Merge the standing and active temporary permissions into one reviewable policy."""
    result = evaluate_handover(cfg, at)
    actions_by_resource: dict[str, list[str]] = {}
    for row in result["available_permissions"]:
        actions_by_resource.setdefault(row["resource"], []).append(row["action"])

    statements = []
    for index, (resource, actions) in enumerate(sorted(actions_by_resource.items()), start=1):
        statements.append(
            {
                "Sid": f"EffectiveHandover{index}",
                "Effect": "Allow",
                "Action": sorted(set(actions)),
                "Resource": [resource],
            }
        )
    return {"Version": "2012-10-17", "Statement": statements}
