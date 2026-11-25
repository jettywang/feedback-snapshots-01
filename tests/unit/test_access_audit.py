"""Tests for the read-only project access audit and local doubles."""

from __future__ import annotations

import pytest
import responses

import gitlab
from gitlab.access_audit import (
    PROJECT_ACCESS_REQUESTS,
    PROJECT_ALL,
    PROJECT_DIRECT,
    EvidenceStatus,
    QuerySpec,
    USER_MEMBERSHIPS,
    _DictPageSource,
    audit_evidence,
    build_gitlab_specs,
    collect_query,
    demo_report,
    group_direct_key,
)

ALICE = {
    "id": 42,
    "username": "alice",
    "state": "active",
    "access_level": 30,
}
CAROL_REQUEST = {
    "id": 44,
    "username": "carol",
    "state": "pending",
    "access_level": 20,
}


def local_specs(*, all_source=None, include_requests=True):
    specs = [
        QuerySpec(
            key=PROJECT_DIRECT,
            title="direct",
            method="project.members.list",
            endpoint="GET /projects/7/members",
            list_page=_DictPageSource([[]]),
        ),
        QuerySpec(
            key=PROJECT_ALL,
            title="all",
            method="project.members_all.list",
            endpoint="GET /projects/7/members/all",
            list_page=all_source or _DictPageSource([[ALICE]]),
        ),
        QuerySpec(
            key=group_direct_key(1),
            title="parent",
            method="group.members.list",
            endpoint="GET /groups/1/members",
            list_page=_DictPageSource([[ALICE]]),
            metadata={"kind": "ancestor_group_direct", "group_id": 1},
        ),
    ]
    if include_requests:
        specs.append(
            QuerySpec(
                key=PROJECT_ACCESS_REQUESTS,
                title="requests",
                method="project.accessrequests.list",
                endpoint="GET /projects/7/access_requests",
                list_page=_DictPageSource([[CAROL_REQUEST]]),
            )
        )
    return specs


def test_direct_revoked_but_parent_group_proves_inherited_access():
    report = audit_evidence(
        local_specs(), user_id=42, project_id=7, per_page=100
    )

    finding = report.finding
    assert report.completeness == "complete"
    assert finding.effective_access is True
    assert finding.direct_access is False
    assert finding.inherited_access is True
    assert finding.pending_approval is False
    assert finding.highest_known_access_level == 30
    assert finding.missing_evidence == []

    kinds = {(source.kind, source.source_id) for source in finding.proven_sources}
    assert ("inherited_ancestor_group", 1) in kinds
    assert any(
        source.endpoint == "GET /groups/1/members"
        for source in finding.proven_sources
    )


def test_pending_access_request_is_not_effective_access():
    report = audit_evidence(
        local_specs(
            all_source=_DictPageSource([[]]),
        ),
        user_id=44,
        project_id=7,
    )

    finding = report.finding
    assert finding.pending_approval is True
    assert finding.effective_access is False
    assert finding.direct_access is False
    assert finding.inherited_access is False
    assert finding.proven_sources == []


def test_unsupported_members_all_keeps_parent_proof_and_explains_gap():
    def unsupported(page, per_page):
        error = gitlab.exceptions.GitlabListError(
            "404 Not Found", response_code=404
        )
        raise error

    specs = local_specs(all_source=unsupported)
    report = audit_evidence(specs, user_id=42, project_id=7)

    all_evidence = next(item for item in report.evidence if item.key == PROJECT_ALL)
    assert all_evidence.status == EvidenceStatus.UNSUPPORTED
    assert all_evidence.error_code == 404
    assert report.finding.effective_access is True
    assert report.finding.inherited_access is True
    assert report.completeness == "partial"
    assert any(PROJECT_ALL in gap for gap in report.finding.missing_evidence)


def test_pagination_failure_retains_completed_page():
    source = _DictPageSource(
        [[ALICE]], fail_page=2, status_code=500, message="boom"
    )
    spec = QuerySpec(
        key=PROJECT_ALL,
        title="all",
        method="project.members_all.list",
        endpoint="GET /projects/7/members/all",
        list_page=source,
    )

    evidence = collect_query(spec, per_page=1)

    assert evidence.status == EvidenceStatus.PARTIAL
    assert evidence.pages_completed == [1]
    assert evidence.count == 1
    assert evidence.items[0]["username"] == "alice"
    assert evidence.error_kind == EvidenceStatus.ERROR
    assert "boom" in (evidence.error or "")


def test_mid_pagination_failure_marks_absence_unprovable_but_positive_found():
    source = _DictPageSource(
        [[ALICE]], fail_page=2, status_code=502, message="page failed"
    )
    specs = [
        QuerySpec(
            key=PROJECT_DIRECT,
            title="direct",
            method="project.members.list",
            endpoint="GET /projects/7/members",
            list_page=_DictPageSource([[]]),
        ),
        QuerySpec(
            key=PROJECT_ALL,
            title="all",
            method="project.members_all.list",
            endpoint="GET /projects/7/members/all",
            list_page=source,
        ),
    ]

    report = audit_evidence(specs, user_id=42, project_id=7, per_page=1)

    assert report.completeness == "partial"
    assert report.finding.effective_access is True
    assert report.finding.direct_access is False
    assert report.finding.inherited_access is None
    assert any(PROJECT_ALL in gap for gap in report.finding.missing_evidence)


def test_project_all_without_parent_evidence_is_explicitly_unresolved():
    specs = [
        QuerySpec(
            key=PROJECT_DIRECT,
            title="direct",
            method="project.members.list",
            endpoint="GET /projects/7/members",
            list_page=_DictPageSource([[]]),
        ),
        QuerySpec(
            key=PROJECT_ALL,
            title="all",
            method="project.members_all.list",
            endpoint="GET /projects/7/members/all",
            list_page=_DictPageSource([[ALICE]]),
        ),
    ]

    report = audit_evidence(specs, user_id=42, project_id=7)

    assert report.finding.effective_access is True
    assert report.finding.direct_access is False
    assert report.finding.inherited_access is None
    assert report.completeness == "partial"
    assert report.finding.unresolved_observations
    assert any(
        "source_attribution" in gap for gap in report.finding.missing_evidence
    )


def test_admin_user_memberships_can_independently_prove_parent_source():
    def unsupported(page, per_page):
        raise gitlab.exceptions.GitlabListError("404", response_code=404)

    specs = [
        QuerySpec(
            key=PROJECT_DIRECT,
            title="direct",
            method="project.members.list",
            endpoint="GET /projects/7/members",
            list_page=_DictPageSource([[]]),
        ),
        QuerySpec(
            key=PROJECT_ALL,
            title="all",
            method="project.members_all.list",
            endpoint="GET /projects/7/members/all",
            list_page=unsupported,
        ),
        QuerySpec(
            key=USER_MEMBERSHIPS,
            title="user memberships",
            method="user.memberships.list",
            endpoint="GET /users/42/memberships",
            list_page=_DictPageSource(
                [
                    [
                        {
                            "source_id": 1,
                            "source_name": "parent-group",
                            "source_type": "Namespace",
                            "access_level": "30",
                        }
                    ]
                ]
            ),
        ),
    ]

    report = audit_evidence(
        specs,
        user_id=42,
        project_id=7,
        ancestor_group_ids=[1],
    )

    assert report.finding.effective_access is True
    assert report.finding.inherited_access is True
    assert report.finding.direct_access is False
    assert any(
        source.kind == "inherited_ancestor_group_user_membership"
        for source in report.finding.proven_sources
    )
    assert any(PROJECT_ALL in gap for gap in report.finding.missing_evidence)


def test_demo_covers_full_unsupported_and_partial_cases():
    full = demo_report()
    unsupported = demo_report(unsupported_all=True)
    partial = demo_report(fail_all_page_two=True)

    assert full.completeness == "complete"
    assert full.finding.inherited_access is True
    assert unsupported.completeness == "partial"
    assert partial.completeness == "partial"
    all_evidence = next(
        item for item in partial.evidence if item.key == PROJECT_ALL
    )
    assert all_evidence.status == EvidenceStatus.PARTIAL
    assert all_evidence.count == 1


@pytest.fixture
def http_gl():
    return gitlab.Gitlab(
        "http://localhost", private_token="token", api_version="4"
    )


def test_gitlab_manager_specs_use_member_endpoints(http_gl):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET,
            "http://localhost/api/v4/projects/7/members",
            json=[],
            status=200,
        )
        rsps.add(
            responses.GET,
            "http://localhost/api/v4/projects/7/members/all",
            json=[ALICE],
            status=200,
        )
        rsps.add(
            responses.GET,
            "http://localhost/api/v4/groups/1/members",
            json=[ALICE],
            status=200,
        )
        rsps.add(
            responses.GET,
            "http://localhost/api/v4/projects/7/access_requests",
            json=[],
            status=200,
        )

        specs = build_gitlab_specs(
            http_gl, 7, ancestor_group_ids=[1], user_id=42
        )
        report = audit_evidence(specs, user_id=42, project_id=7)

    assert report.completeness == "complete"
    assert report.finding.direct_access is False
    assert report.finding.inherited_access is True
    assert report.finding.effective_access is True
    endpoints = {item.endpoint for item in report.evidence}
    assert "GET /projects/7/members/all" in endpoints
    assert "GET /groups/1/members" in endpoints


def test_gitlab_manager_404_is_unsupported_and_direct_query_still_works(http_gl):
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET,
            "http://localhost/api/v4/projects/7/members",
            json=[],
            status=200,
        )
        rsps.add(
            responses.GET,
            "http://localhost/api/v4/projects/7/members/all",
            json={"message": "404 Not found"},
            status=404,
        )

        project = http_gl.projects.get(7, lazy=True)
        direct = project.members.list(get_all=True)
        assert direct == []

        with pytest.raises(gitlab.exceptions.GitlabListError) as exc_info:
            project.members_all.list(get_all=True)
        assert exc_info.value.response_code == 404

        specs = build_gitlab_specs(
            http_gl, 7, include_access_requests=False
        )
        report = audit_evidence(specs, user_id=42, project_id=7)

    statuses = {item.key: item.status for item in report.evidence}
    assert statuses[PROJECT_DIRECT] == EvidenceStatus.COMPLETE
    assert statuses[PROJECT_ALL] == EvidenceStatus.UNSUPPORTED
    assert report.completeness == "partial"
