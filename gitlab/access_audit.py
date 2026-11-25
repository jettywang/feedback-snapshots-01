"""Read-only evidence collector for project access reviews.

The module deliberately separates three questions:

* Does the user have a direct project membership?
* Does ``/projects/:id/members/all`` show effective access inherited from an
  ancestor group or granted through a group invite/project share?
* Is there an unapproved access request or invitation?

Call basis in this repository:

* ``GET /projects/:id/members`` and ``GET /projects/:id/members/all``:
  ``gitlab/v4/objects/members.py`` and ``docs/gl_objects/projects.rst``.
* ``GET /groups/:id/members``:
  ``gitlab/v4/objects/members.py`` and ``docs/gl_objects/groups.rst``.
* ``GET /projects/:id/access_requests``:
  ``gitlab/v4/objects/access_requests.py``.
* ``GET /users/:id/memberships``:
  ``gitlab/v4/objects/users.py``; this endpoint is administrator-only.

Only GET/list operations are used.
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, NoReturn

__all__ = [
    "EvidenceStatus",
    "QuerySpec",
    "Evidence",
    "ProvenSource",
    "AccessFinding",
    "AuditReport",
    "PROJECT_DIRECT",
    "PROJECT_ALL",
    "PROJECT_ACCESS_REQUESTS",
    "PROJECT_INVITATIONS",
    "USER_MEMBERSHIPS",
    "group_direct_key",
    "collect_query",
    "audit_evidence",
    "build_gitlab_specs",
    "demo_report",
    "render_markdown",
    "main",
]

PROJECT_DIRECT = "project_direct"
PROJECT_ALL = "project_all"
PROJECT_ACCESS_REQUESTS = "project_access_requests"
PROJECT_INVITATIONS = "project_invitations"
USER_MEMBERSHIPS = "user_memberships"

PageCall = Callable[[int, int], Iterable[Any]]


class EvidenceStatus(str, Enum):
    """State of one independently collected evidence source."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    DENIED = "denied"
    ERROR = "error"


def group_direct_key(group_id: int | str) -> str:
    return f"group_direct:{group_id}"


@dataclass(frozen=True)
class QuerySpec:
    """A page-by-page read-only query and its call basis."""

    key: str
    title: str
    method: str
    endpoint: str
    list_page: PageCall
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class Evidence:
    key: str
    title: str
    method: str
    endpoint: str
    status: EvidenceStatus
    items: list[dict[str, Any]] = field(default_factory=list)
    pages_completed: list[int] = field(default_factory=list)
    per_page: int | None = None
    error: str | None = None
    error_code: int | None = None
    error_kind: EvidenceStatus | None = None

    @property
    def count(self) -> int:
        return len(self.items)

    @property
    def usable(self) -> bool:
        return self.status in (EvidenceStatus.COMPLETE, EvidenceStatus.PARTIAL)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "method": self.method,
            "endpoint": self.endpoint,
            "status": self.status.value,
            "usable": self.usable,
            "count": self.count,
            "pages_completed": list(self.pages_completed),
            "per_page": self.per_page,
            "error": self.error,
            "error_code": self.error_code,
            "error_kind": self.error_kind.value if self.error_kind else None,
            "items": self.items,
        }


@dataclass
class ProvenSource:
    kind: str
    description: str
    evidence_key: str
    endpoint: str
    method: str
    source_id: Any = None
    access_level: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "description": self.description,
            "evidence_key": self.evidence_key,
            "endpoint": self.endpoint,
            "method": self.method,
            "source_id": self.source_id,
            "access_level": self.access_level,
        }


@dataclass
class AccessFinding:
    user_id: int | str | None
    username: str | None = None
    effective_access: bool | None = None
    direct_access: bool | None = None
    inherited_access: bool | None = None
    pending_approval: bool | None = None
    pending_invitation: bool | None = None
    highest_known_access_level: int | None = None
    proven_sources: list[ProvenSource] = field(default_factory=list)
    unresolved_observations: list[dict[str, Any]] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "effective_access": self.effective_access,
            "direct_access": self.direct_access,
            "inherited_access": self.inherited_access,
            "pending_approval": self.pending_approval,
            "pending_invitation": self.pending_invitation,
            "highest_known_access_level": self.highest_known_access_level,
            "proven_sources": [source.to_dict() for source in self.proven_sources],
            "unresolved_observations": self.unresolved_observations,
            "missing_evidence": self.missing_evidence,
        }


@dataclass
class AuditReport:
    target: dict[str, Any]
    completeness: str
    evidence: list[Evidence]
    finding: AccessFinding
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "completeness": self.completeness,
            "limitations": self.limitations,
            "finding": self.finding.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
        }

    def to_json(self, indent: int = 2) -> str:
        import json

        return json.dumps(
            self.to_dict(), ensure_ascii=False, indent=indent, default=str
        )


def _as_mapping(item: Any) -> dict[str, Any]:
    attributes = getattr(item, "attributes", None)
    if isinstance(attributes, Mapping):
        return dict(attributes)
    if isinstance(item, Mapping):
        return dict(item)
    return {"value": item}


def _response_code(exc: BaseException) -> int | None:
    code = getattr(exc, "response_code", None)
    if code is None and exc.__cause__ is not None:
        code = getattr(exc.__cause__, "response_code", None)
    if code is None and exc.__context__ is not None:
        code = getattr(exc.__context__, "response_code", None)
    try:
        return int(code) if code is not None else None
    except (TypeError, ValueError):
        return None


def _classify_error(exc: BaseException) -> tuple[EvidenceStatus, int | None]:
    code = _response_code(exc)
    if code in (404, 501):
        return EvidenceStatus.UNSUPPORTED, code
    if code in (401, 403):
        return EvidenceStatus.DENIED, code
    return EvidenceStatus.ERROR, code


def collect_query(
    spec: QuerySpec, *, per_page: int = 100, max_pages: int = 10_000
) -> Evidence:
    """Collect one query page by page without discarding completed pages."""

    evidence = Evidence(
        key=spec.key,
        title=spec.title,
        method=spec.method,
        endpoint=spec.endpoint,
        status=EvidenceStatus.ERROR,
        per_page=per_page,
    )

    try:
        for page in range(1, max_pages + 1):
            raw_page = spec.list_page(page, per_page)
            page_items = [_as_mapping(item) for item in raw_page]
            evidence.pages_completed.append(page)
            evidence.items.extend(page_items)

            if len(page_items) < per_page:
                evidence.status = EvidenceStatus.COMPLETE
                return evidence

        evidence.status = EvidenceStatus.ERROR
        evidence.error = f"Exceeded max_pages={max_pages} without a short page"
        evidence.error_kind = EvidenceStatus.ERROR
    except Exception as exc:  # One source must not abort other independent queries.
        kind, code = _classify_error(exc)
        evidence.error = str(exc) or exc.__class__.__name__
        evidence.error_code = code
        evidence.error_kind = kind
        evidence.status = EvidenceStatus.PARTIAL if evidence.items else kind

    return evidence


def _id_equal(value: Any, expected: int | str | None) -> bool:
    if expected is None or value is None:
        return False
    return str(value) == str(expected)


def _matches_target(
    item: Mapping[str, Any],
    *,
    user_id: int | str | None,
    username: str | None,
    email: str | None,
    user_scoped: bool,
) -> bool:
    if user_scoped:
        return True
    if user_id is not None and (
        _id_equal(item.get("id"), user_id)
        or _id_equal(item.get("user_id"), user_id)
    ):
        return True
    if username is not None and item.get("username") == username:
        return True
    if email is not None:
        candidates = {item.get("email"), item.get("invite_email")}
        if email in candidates:
            return True
    return False


def _matching_items(
    evidence: Evidence | None,
    *,
    user_id: int | str | None,
    username: str | None,
    email: str | None,
) -> list[dict[str, Any]]:
    if evidence is None or not evidence.usable:
        return []
    user_scoped = bool(evidence.key == USER_MEMBERSHIPS)
    return [
        item
        for item in evidence.items
        if _matches_target(
            item,
            user_id=user_id,
            username=username,
            email=email,
            user_scoped=user_scoped,
        )
    ]


def _access_level(item: Mapping[str, Any]) -> int | None:
    value = item.get("access_level")
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _add_level(finding: AccessFinding, item: Mapping[str, Any]) -> None:
    level = _access_level(item)
    if level is not None:
        finding.highest_known_access_level = max(
            finding.highest_known_access_level or level, level
        )


def _is_pending_state(item: Mapping[str, Any]) -> bool:
    state = str(item.get("state", "pending")).strip().lower()
    if state in {"approved", "active", "accepted", "rejected", "denied", "expired"}:
        return False
    return True


def _proven_source(
    evidence: Evidence,
    *,
    kind: str,
    description: str,
    source_id: Any = None,
    item: Mapping[str, Any] | None = None,
) -> ProvenSource:
    return ProvenSource(
        kind=kind,
        description=description,
        evidence_key=evidence.key,
        endpoint=evidence.endpoint,
        method=evidence.method,
        source_id=source_id,
        access_level=_access_level(item or {}),
    )


def audit_evidence(
    specs: Sequence[QuerySpec],
    *,
    user_id: int | str | None = None,
    username: str | None = None,
    email: str | None = None,
    project_id: int | str | None = None,
    ancestor_group_ids: Sequence[int | str] = (),
    per_page: int = 100,
) -> AuditReport:
    """Collect all specs independently and classify the requested principal."""

    evidence_list = [collect_query(spec, per_page=per_page) for spec in specs]
    evidence = {source.key: source for source in evidence_list}

    finding = AccessFinding(user_id=user_id, username=username)
    limitations: list[str] = []

    for source in evidence_list:
        if source.status != EvidenceStatus.COMPLETE:
            code = (
                f" HTTP {source.error_code}"
                if source.error_code is not None
                else ""
            )
            limitations.append(
                f"{source.key}: {source.status.value}{code}; "
                f"{source.count} item(s) retained from pages "
                f"{source.pages_completed}"
            )

    def ev(key: str) -> Evidence | None:
        return evidence.get(key)

    def matches(key: str) -> list[dict[str, Any]]:
        return _matching_items(
            ev(key), user_id=user_id, username=username, email=email
        )

    direct_evidence = ev(PROJECT_DIRECT)
    direct_matches = matches(PROJECT_DIRECT)
    if direct_matches:
        finding.direct_access = True
        for item in direct_matches:
            _add_level(finding, item)
            finding.proven_sources.append(
                _proven_source(
                    direct_evidence,  # type: ignore[arg-type]
                    kind="direct_project",
                    description="Direct membership on the project",
                    source_id=project_id,
                    item=item,
                )
            )
    elif (
        direct_evidence is not None
        and direct_evidence.status == EvidenceStatus.COMPLETE
    ):
        finding.direct_access = False
    elif direct_evidence is None:
        finding.missing_evidence.append(f"{PROJECT_DIRECT}: not queried")
    else:
        finding.missing_evidence.append(
            f"{PROJECT_DIRECT}: {direct_evidence.status.value}"
        )

    ancestor_specs = [
        spec
        for spec in specs
        if spec.metadata.get("kind") == "ancestor_group_direct"
    ]
    ancestor_ids = {str(group_id) for group_id in ancestor_group_ids}
    ancestor_ids.update(
        str(spec.metadata.get("group_id"))
        for spec in ancestor_specs
        if spec.metadata.get("group_id") is not None
    )

    for spec in ancestor_specs:
        source_evidence = evidence[spec.key]
        group_id = spec.metadata.get("group_id")
        group_matches = matches(spec.key)
        if group_matches:
            finding.inherited_access = True
            for item in group_matches:
                if finding.username is None:
                    finding.username = item.get("username")
                _add_level(finding, item)
                finding.proven_sources.append(
                    _proven_source(
                        source_evidence,
                        kind="inherited_ancestor_group",
                        description=(
                            f"Direct membership in ancestor group {group_id}; "
                            "access is inherited by the project"
                        ),
                        source_id=group_id,
                        item=item,
                    )
                )
        elif source_evidence.status != EvidenceStatus.COMPLETE:
            finding.missing_evidence.append(
                f"{spec.key}: cannot finish ancestor-group source check "
                f"({source_evidence.status.value})"
            )

    if (
        finding.inherited_access is None
        and ancestor_specs
        and all(
            evidence[spec.key].status == EvidenceStatus.COMPLETE
            for spec in ancestor_specs
        )
    ):
        finding.inherited_access = False

    membership_evidence = ev(USER_MEMBERSHIPS)
    membership_matches = matches(USER_MEMBERSHIPS)
    if membership_evidence is not None and membership_evidence.usable:
        for item in membership_matches:
            source_type = item.get("source_type")
            source_id = item.get("source_id")
            _add_level(finding, item)
            if source_type == "Project" and _id_equal(source_id, project_id):
                finding.direct_access = True
                finding.proven_sources.append(
                    _proven_source(
                        membership_evidence,
                        kind="direct_project_user_membership",
                        description=(
                            "User memberships endpoint reports direct project access"
                        ),
                        source_id=source_id,
                        item=item,
                    )
                )
            elif source_type == "Namespace" and str(source_id) in ancestor_ids:
                finding.inherited_access = True
                finding.proven_sources.append(
                    _proven_source(
                        membership_evidence,
                        kind="inherited_ancestor_group_user_membership",
                        description=(
                            "User memberships endpoint reports direct membership "
                            f"in ancestor group {source_id}"
                        ),
                        source_id=source_id,
                        item=item,
                    )
                )
            elif source_type == "Namespace":
                finding.unresolved_observations.append(
                    {
                        "kind": "other_namespace_membership",
                        "source_id": source_id,
                        "source_name": item.get("source_name"),
                        "reason": (
                            "This may explain a group invite/share, but the "
                            "project-to-group link was not collected"
                        ),
                    }
                )

    all_evidence = ev(PROJECT_ALL)
    all_matches = matches(PROJECT_ALL)
    if all_matches and all_evidence is not None:
        for item in all_matches:
            if finding.username is None:
                finding.username = item.get("username")
            _add_level(finding, item)
            if (
                finding.direct_access is not True
                and finding.inherited_access is not True
            ):
                finding.unresolved_observations.append(
                    {
                        "kind": "effective_non_direct_project_member",
                        "evidence_key": PROJECT_ALL,
                        "endpoint": all_evidence.endpoint,
                        "access_level": _access_level(item),
                        "reason": (
                            "projects/:id/members/all proves effective access but "
                            "does not by itself distinguish ancestor inheritance "
                            "from an invited group or project share"
                        ),
                    }
                )
    if all_evidence is None:
        finding.missing_evidence.append(f"{PROJECT_ALL}: not queried")
    elif all_evidence.status != EvidenceStatus.COMPLETE:
        finding.missing_evidence.append(
            f"{PROJECT_ALL}: {all_evidence.status.value}; "
            "retained entries are usable, but absence cannot be proven"
        )

    request_evidence = ev(PROJECT_ACCESS_REQUESTS)
    if request_evidence is None:
        finding.missing_evidence.append(
            f"{PROJECT_ACCESS_REQUESTS}: pending requests were not checked"
        )
    else:
        request_matches = [
            item for item in matches(PROJECT_ACCESS_REQUESTS) if _is_pending_state(item)
        ]
        if request_matches:
            finding.pending_approval = True
            if finding.username is None:
                finding.username = request_matches[0].get("username")
        elif request_evidence.status == EvidenceStatus.COMPLETE:
            finding.pending_approval = False
        else:
            finding.pending_approval = None
            finding.missing_evidence.append(
                f"{PROJECT_ACCESS_REQUESTS}: {request_evidence.status.value}"
            )

    invitation_evidence = ev(PROJECT_INVITATIONS)
    if invitation_evidence is None:
        finding.pending_invitation = None
    else:
        invitation_matches = matches(PROJECT_INVITATIONS)
        if invitation_matches:
            finding.pending_invitation = True
        elif invitation_evidence.status == EvidenceStatus.COMPLETE:
            finding.pending_invitation = False
        else:
            finding.pending_invitation = None
            finding.missing_evidence.append(
                f"{PROJECT_INVITATIONS}: {invitation_evidence.status.value}"
            )

    if finding.direct_access is True or finding.inherited_access is True:
        finding.effective_access = True
    elif all_matches:
        finding.effective_access = True
    elif (
        all_evidence is not None
        and all_evidence.status == EvidenceStatus.COMPLETE
        and not all_matches
    ):
        finding.effective_access = False
    else:
        finding.effective_access = None

    if finding.inherited_access is not True and all_matches:
        has_unresolved = any(
            observation["kind"] == "effective_non_direct_project_member"
            for observation in finding.unresolved_observations
        )
        if has_unresolved and not any(
            "ancestor-group" in gap or USER_MEMBERSHIPS in gap
            for gap in finding.missing_evidence
        ):
            finding.missing_evidence.append(
                "source_attribution: query each ancestor group's /members or "
                "admin-only /users/:id/memberships, and collect /projects/:id/groups "
                "to check invited-group links"
            )

    if not evidence_list:
        completeness = "no_evidence"
    elif all(item.status == EvidenceStatus.COMPLETE for item in evidence_list):
        completeness = "complete"
    elif any(item.usable for item in evidence_list):
        completeness = "partial"
    else:
        completeness = "unavailable"

    if completeness == EvidenceStatus.COMPLETE.value and finding.missing_evidence:
        completeness = EvidenceStatus.PARTIAL.value

    target = {
        "user_id": user_id,
        "username": username,
        "email": email,
        "project_id": project_id,
        "ancestor_group_ids": sorted(ancestor_ids),
    }
    return AuditReport(
        target=target,
        completeness=completeness,
        evidence=evidence_list,
        finding=finding,
        limitations=limitations,
    )


def _manager_page_call(manager: Any) -> PageCall:
    def list_page(page: int, per_page: int) -> Iterable[Any]:
        return list(manager.list(page=page, per_page=per_page, get_all=False))

    return list_page


def build_gitlab_specs(
    gl: Any,
    project_id: int | str,
    *,
    ancestor_group_ids: Sequence[int | str] = (),
    user_id: int | str | None = None,
    include_access_requests: bool = True,
    include_invitations: bool = False,
    include_user_memberships: bool = False,
) -> list[QuerySpec]:
    """Build specs backed by the existing python-gitlab managers.

    Lazy objects do not perform GETs in this function; only the page callbacks
    issued by :func:`collect_query` touch the network.
    """

    project = gl.projects.get(project_id, lazy=True)
    specs = [
        QuerySpec(
            key=PROJECT_DIRECT,
            title="Direct project members",
            method="project.members.list(page=..., per_page=..., get_all=False)",
            endpoint=f"GET /projects/{project_id}/members",
            list_page=_manager_page_call(project.members),
        ),
        QuerySpec(
            key=PROJECT_ALL,
            title="All project members, including inherited/invited",
            method="project.members_all.list(page=..., per_page=..., get_all=False)",
            endpoint=f"GET /projects/{project_id}/members/all",
            list_page=_manager_page_call(project.members_all),
        ),
    ]

    for group_id in ancestor_group_ids:
        group = gl.groups.get(group_id, lazy=True)
        specs.append(
            QuerySpec(
                key=group_direct_key(group_id),
                title=f"Direct members of ancestor group {group_id}",
                method="group.members.list(page=..., per_page=..., get_all=False)",
                endpoint=f"GET /groups/{group_id}/members",
                list_page=_manager_page_call(group.members),
                metadata={"kind": "ancestor_group_direct", "group_id": group_id},
            )
        )

    if include_access_requests:
        specs.append(
            QuerySpec(
                key=PROJECT_ACCESS_REQUESTS,
                title="Pending project access requests",
                method=(
                    "project.accessrequests.list(page=..., per_page=..., "
                    "get_all=False)"
                ),
                endpoint=f"GET /projects/{project_id}/access_requests",
                list_page=_manager_page_call(project.accessrequests),
            )
        )

    if include_invitations:
        specs.append(
            QuerySpec(
                key=PROJECT_INVITATIONS,
                title="Pending project invitations",
                method=(
                    "project.invitations.list(page=..., per_page=..., "
                    "get_all=False)"
                ),
                endpoint=f"GET /projects/{project_id}/invitations",
                list_page=_manager_page_call(project.invitations),
            )
        )

    if include_user_memberships:
        if user_id is None:
            raise ValueError("user_id is required for user memberships evidence")
        user = gl.users.get(user_id, lazy=True)
        specs.append(
            QuerySpec(
                key=USER_MEMBERSHIPS,
                title="Direct memberships for the target user (admin-only)",
                method="user.memberships.list(page=..., per_page=..., get_all=False)",
                endpoint=f"GET /users/{user_id}/memberships",
                list_page=_manager_page_call(user.memberships),
                metadata={"user_scoped": True},
            )
        )

    return specs


class _DictPageSource:
    """Local test double for a pageable endpoint."""

    def __init__(
        self,
        pages: Sequence[list[dict[str, Any]]],
        *,
        fail_page: int | None = None,
        status_code: int = 500,
        message: str = "simulated page failure",
    ) -> None:
        self.pages = list(pages)
        self.fail_page = fail_page
        self.status_code = status_code
        self.message = message

    def __call__(self, page: int, per_page: int) -> list[dict[str, Any]]:
        if self.fail_page == page:
            error = RuntimeError(self.message)
            error.response_code = self.status_code  # type: ignore[attr-defined]
            raise error
        index = page - 1
        return self.pages[index] if index < len(self.pages) else []


def demo_specs(
    *, unsupported_all: bool = False, fail_all_page_two: bool = False
) -> list[QuerySpec]:
    alice = {
        "id": 42,
        "username": "alice",
        "name": "Alice Example",
        "state": "active",
        "access_level": 30,
    }
    parent_alice = {**alice, "access_level": 30}
    carol_request = {
        "id": 44,
        "username": "carol",
        "name": "Carol Example",
        "state": "pending",
        "access_level": 20,
    }

    def unsupported(page: int, per_page: int) -> NoReturn:
        error = RuntimeError("404 Not Found")
        error.response_code = 404  # type: ignore[attr-defined]
        raise error

    all_source: PageCall
    if unsupported_all:
        all_source = unsupported
    elif fail_all_page_two:
        first_page = [alice]
        all_source = _DictPageSource(
            [first_page], fail_page=2, status_code=500, message="page 2 failed"
        )
    else:
        all_source = _DictPageSource([[alice]])

    return [
        QuerySpec(
            key=PROJECT_DIRECT,
            title="Direct project members (Alice's direct grant was removed)",
            method="project.members.list(...)",
            endpoint="GET /projects/7/members",
            list_page=_DictPageSource([[]]),
        ),
        QuerySpec(
            key=PROJECT_ALL,
            title="All project members",
            method="project.members_all.list(...)",
            endpoint="GET /projects/7/members/all",
            list_page=all_source,
        ),
        QuerySpec(
            key=group_direct_key(1),
            title="Direct parent-group members",
            method="parent_group.members.list(...)",
            endpoint="GET /groups/1/members",
            list_page=_DictPageSource([[parent_alice]]),
            metadata={"kind": "ancestor_group_direct", "group_id": 1},
        ),
        QuerySpec(
            key=PROJECT_ACCESS_REQUESTS,
            title="Pending project access requests",
            method="project.accessrequests.list(...)",
            endpoint="GET /projects/7/access_requests",
            list_page=_DictPageSource([[carol_request]]),
        ),
    ]


def demo_report(
    *,
    user_id: int | str = 42,
    unsupported_all: bool = False,
    fail_all_page_two: bool = False,
) -> AuditReport:
    return audit_evidence(
        demo_specs(
            unsupported_all=unsupported_all,
            fail_all_page_two=fail_all_page_two,
        ),
        user_id=user_id,
        project_id=7,
        per_page=1 if fail_all_page_two else 100,
    )


def render_markdown(report: AuditReport) -> str:
    finding = report.finding
    lines = [
        "# Project access audit",
        "",
        f"- Project: `{report.target.get('project_id')}`",
        f"- User: `{finding.user_id}` ({finding.username or 'username unknown'})",
        f"- Evidence completeness: **{report.completeness}**",
        f"- Effective access: `{finding.effective_access}`",
        f"- Direct access: `{finding.direct_access}`",
        f"- Inherited access: `{finding.inherited_access}`",
        f"- Pending approval: `{finding.pending_approval}`",
        "",
        "## Proven sources",
    ]
    if finding.proven_sources:
        for source in finding.proven_sources:
            lines.append(
                f"- `{source.kind}` via `{source.endpoint}` — {source.description}"
            )
    else:
        lines.append("- None")

    lines.extend(["", "## Missing or incomplete evidence"])
    gaps = finding.missing_evidence or ["None"]
    lines.extend(f"- {gap}" for gap in gaps)

    lines.extend(["", "## Query evidence"])
    for evidence in report.evidence:
        lines.append(
            f"- `{evidence.key}`: `{evidence.status.value}`, "
            f"{evidence.count} item(s), pages {evidence.pages_completed or 'none'} "
            f"— `{evidence.endpoint}`"
        )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--demo", action="store_true", help="run the local test double")
    parser.add_argument("--demo-user", type=int, default=42)
    parser.add_argument("--demo-unsupported-all", action="store_true")
    parser.add_argument("--demo-pagination-failure", action="store_true")
    parser.add_argument("--url", default=os.getenv("GITLAB_URL"))
    parser.add_argument("--token", default=os.getenv("GITLAB_PRIVATE_TOKEN"))
    parser.add_argument("--project", type=int)
    parser.add_argument("--user", type=int)
    parser.add_argument("--parent-group", action="append", type=int, default=[])
    parser.add_argument(
        "--user-memberships",
        action="store_true",
        help="also query admin-only GET /users/:id/memberships",
    )
    parser.add_argument(
        "--invitations",
        action="store_true",
        help="also query GET /projects/:id/invitations",
    )
    parser.add_argument("--per-page", type=int, default=100)
    parser.add_argument(
        "--json", action="store_true", help="print JSON instead of Markdown"
    )
    args = parser.parse_args(argv)

    if args.demo or args.demo_unsupported_all or args.demo_pagination_failure:
        report = demo_report(
            user_id=args.demo_user,
            unsupported_all=args.demo_unsupported_all,
            fail_all_page_two=args.demo_pagination_failure,
        )
    else:
        if not args.url or not args.token or args.project is None or args.user is None:
            parser.error(
                "real audit requires --url, --token/GITLAB_PRIVATE_TOKEN, "
                "--project, and --user"
            )
        import gitlab

        gl = gitlab.Gitlab(args.url, private_token=args.token)
        specs = build_gitlab_specs(
            gl,
            args.project,
            ancestor_group_ids=args.parent_group,
            user_id=args.user,
            include_invitations=args.invitations,
            include_user_memberships=args.user_memberships,
        )
        report = audit_evidence(
            specs,
            user_id=args.user,
            project_id=args.project,
            ancestor_group_ids=args.parent_group,
            per_page=args.per_page,
        )

    print(report.to_json() if args.json else render_markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
