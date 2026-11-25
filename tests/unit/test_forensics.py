from __future__ import annotations

import copy
import hashlib
import json

import pytest
import responses

import gitlab
from gitlab import forensics
from gitlab.v4.objects import ProjectRelease

OLD_SHA = "1" * 40
NEW_SHA = "2" * 40
OLD_PIPELINE_ID = 101
NEW_PIPELINE_ID = 202
OLD_JOB_ID = 9001
NEW_JOB_ID = 9002

PROJECT_ID = 1
TAG_NAME = "v1.2.3"
RELEASE_ID = 3

RELEASE_URL = (
    f"http://localhost/api/v4/projects/{PROJECT_ID}/releases/{TAG_NAME}"
)
TAG_URL = (
    f"http://localhost/api/v4/projects/{PROJECT_ID}/repository/tags/{TAG_NAME}"
)
LINKS_URL = (
    f"http://localhost/api/v4/projects/{PROJECT_ID}/releases/"
    f"{TAG_NAME}/assets/links"
)
JOB_URL = "http://localhost/api/v4/projects/{project_id}/jobs/{job_id}"


def _release_body(sha: str = OLD_SHA) -> dict:
    return {
        "id": RELEASE_ID,
        "tag_name": TAG_NAME,
        "name": "demo",
        "description": "demo release",
        "released_at": "2026-01-01T00:00:00Z",
        "commit": {"id": sha, "short_id": sha[:8]},
        "assets": {
            "count": 2,
            "links": [],
        },
    }


def _tag_body(sha: str) -> dict:
    return {
        "name": TAG_NAME,
        "message": "",
        "target": sha,
        "commit": {
            "id": sha,
            "short_id": sha[:8],
            "created_at": "2026-01-01T00:00:00Z",
            "title": "release",
        },
    }


def _link(link_id: int, job_id: int) -> dict:
    return {
        "id": link_id,
        "name": f"bin-{link_id}",
        "url": (
            f"https://gitlab.example.com/group/project/-/jobs/{job_id}"
            "/artifacts/raw/bin/tool"
        ),
        "direct_asset_url": (
            f"https://gitlab.example.com/group/project/-/releases/"
            f"{TAG_NAME}/downloads/bin-{link_id}"
        ),
        "link_type": "other",
    }


def _job_body(job_id: int, pipeline_id: int, sha: str) -> dict:
    return {
        "id": job_id,
        "name": "build",
        "ref": TAG_NAME,
        "pipeline": {"id": pipeline_id, "sha": sha, "ref": TAG_NAME},
        "commit": {"id": sha},
    }


def _json(number: int = 200) -> dict:
    return {"status": number, "content_type": "application/json"}


def _add_json(rsps, url, body, *, number=200, headers=None, match=None):
    kwargs = _json(number)
    kwargs.update(json=body)
    if headers is not None:
        kwargs["headers"] = headers
    if match is not None:
        kwargs["match"] = match
    rsps.add(method=responses.GET, url=url, **kwargs)


def _page_headers(
    *, page: int, per_page: int, total: int, next_page: int | None
) -> dict:
    total_pages = max(1, (total + per_page - 1) // per_page)
    return {
        "X-Page": str(page),
        "X-Prev-Page": str(page - 1) if page > 1 else "",
        "X-Next-Page": str(next_page) if next_page else "",
        "X-Per-Page": str(per_page),
        "X-Total": str(total),
        "X-Total-Pages": str(total_pages),
    }


def _register_tag_migration_scenario(rsps) -> None:
    """Register a fake API where the tag moves between the first and second read.

    Reading order is fixed so that the migration happens *between* the tag
    read before the asset links and the tag re-read afterwards.
    """
    # 1. Release object, captured while the old build is still current.
    _add_json(rsps, RELEASE_URL, _release_body(OLD_SHA))
    # 2. First tag read: old SHA.
    _add_json(rsps, TAG_URL, _tag_body(OLD_SHA))
    # 3. Asset links: the page still points at the old job, which was built
    #    from the old pipeline. The tag has already moved, but the link is
    #    the historical one users downloaded.
    _add_json(
        rsps,
        LINKS_URL,
        [_link(11, OLD_JOB_ID), _link(12, NEW_JOB_ID)],
        headers=_page_headers(page=1, per_page=100, total=2, next_page=None),
        match=[
            responses.matchers.query_param_matcher({"page": "1", "per_page": "100"})
        ],
    )
    # 4. Tag re-read: new SHA after the rebuild.
    _add_json(rsps, TAG_URL, _tag_body(NEW_SHA))
    # 5. Old job still resolves to the old pipeline and SHA.
    _add_json(
        rsps,
        JOB_URL.format(project_id=PROJECT_ID, job_id=OLD_JOB_ID),
        _job_body(OLD_JOB_ID, OLD_PIPELINE_ID, OLD_SHA),
    )
    # 6. New job resolves to the new pipeline and SHA.
    _add_json(
        rsps,
        JOB_URL.format(project_id=PROJECT_ID, job_id=NEW_JOB_ID),
        _job_body(NEW_JOB_ID, NEW_PIPELINE_ID, NEW_SHA),
    )


@pytest.fixture
def ordered_rsps():
    with responses.RequestsMock(
        registry=responses.registries.OrderedRegistry
    ) as rsps:
        yield rsps


@pytest.fixture
def gl():
    return gitlab.Gitlab(
        "http://localhost",
        private_token="private_token",
        ssl_verify=True,
        api_version="4",
    )


def _collect(gl) -> dict:
    release = ProjectRelease(
        gl.projects.get(PROJECT_ID, lazy=True).releases,
        {"tag_name": TAG_NAME},
        lazy=True,
    )
    return release.forensic_export()


def test_export_preserves_both_tag_versions_and_locates_old_pipeline(ordered_rsps, gl):
    _register_tag_migration_scenario(ordered_rsps)

    document = _collect(gl)

    assert document["schema"] == forensics.SCHEMA
    assert document["schema_version"] == forensics.SCHEMA_VERSION
    assert document["subject"]["project_id"] == PROJECT_ID
    assert document["subject"]["tag_name"] == TAG_NAME

    tag_observation_ids = [
        step["observations"]
        for step in document["steps"]
        if step["step"] in ("tag:initial", "tag:reread")
    ]
    assert len(tag_observation_ids) == 2

    observations = {
        observation["observation_id"]: observation
        for observation in document["observations"]
    }
    tag_bodies = [
        json.loads(observations[observation_id]["response"]["body"]["text"])
        for ids in tag_observation_ids
        for observation_id in ids
    ]
    assert [body["commit"]["id"] for body in tag_bodies] == [OLD_SHA, NEW_SHA]
    requested_at = [
        observations[observation_id]["requested_at"]
        for ids in tag_observation_ids
        for observation_id in ids
    ]
    assert requested_at[0] <= requested_at[1]
    assert requested_at[0].endswith("Z")

    summary = document["cross_checks"]["summary"]
    assert summary["divergence_detected"] is True
    assert summary["detected_at_step"] == "tag:reread"

    tag_moved = [
        finding
        for finding in document["cross_checks"]["findings"]
        if finding["code"] == "tag_moved"
    ]
    assert len(tag_moved) == 1
    assert tag_moved[0]["details"]["before_sha"] == OLD_SHA
    assert tag_moved[0]["details"]["after_sha"] == NEW_SHA

    located = {
        (entry["pipeline_id"], entry["sha"]): entry
        for entry in document["cross_checks"]["located_pipelines"]
    }
    old_entry = located[(OLD_PIPELINE_ID, OLD_SHA)]
    assert old_entry["relation"] == "historical"
    assert OLD_JOB_ID in old_entry["job_ids"]
    assert 11 in old_entry["asset_link_ids"]
    assert old_entry["tag_observation_id"] == (
        next(
            step["observations"][0]
            for step in document["steps"]
            if step["step"] == "tag:initial"
        )
    )

    new_entry = located[(NEW_PIPELINE_ID, NEW_SHA)]
    assert new_entry["relation"] == "current"

    historical = [
        finding
        for finding in document["cross_checks"]["findings"]
        if finding["code"] == "historical_pipeline_located"
    ]
    assert len(historical) == 1
    assert historical[0]["details"]["pipeline_id"] == OLD_PIPELINE_ID
    assert cross_check_step(document)["divergence_detected"] is True


def cross_check_step(document):
    return next(
        step for step in document["steps"] if step["step"] == "cross-check"
    )


def test_export_step_by_step_exposes_where_divergence_was_found(ordered_rsps, gl):
    _register_tag_migration_scenario(ordered_rsps)
    document = _collect(gl)

    step_names = [step["step"] for step in document["steps"]]
    assert step_names == [
        "release",
        "tag:initial",
        "release-links",
        "tag:reread",
        "jobs",
        "cross-check",
    ]
    for step in document["steps"]:
        assert step["status"] == "ok"
        assert step["evidence_gaps"] == []

    divergence = document["cross_checks"]["divergences"]
    assert len(divergence) == 1
    assert divergence[0]["detected_at_step"] == "tag:reread"
    assert divergence[0]["before"]["sha"] == OLD_SHA
    assert divergence[0]["after"]["sha"] == NEW_SHA
    assert divergence[0]["before"]["observation_id"] == (
        next(
            step
            for step in document["steps"]
            if step["step"] == "tag:initial"
        )["observations"][0]
    )


def test_export_is_offline_verifiable_and_detects_tampering(ordered_rsps, gl):
    _register_tag_migration_scenario(ordered_rsps)
    document = _collect(gl)

    verification = forensics.verify_forensic_export(document)
    assert verification.ok is True
    assert verification.problems == []
    assert verification.summary["verified_body_count"] == 6

    # Tamper with a stored body: the per-body digest must catch it.
    tampered = copy.deepcopy(document)
    tampered["observations"][1]["response"]["body"]["text"] = tampered[
        "observations"
    ][1]["response"]["body"]["text"].replace(OLD_SHA, NEW_SHA)
    result = forensics.verify_forensic_export(tampered)
    assert result.ok is False
    codes = {problem["code"] for problem in result.problems}
    assert "body_sha256_mismatch" in codes
    assert "manifest_sha256_mismatch" in codes

    # Tamper with a finding only (body digests stay valid): the manifest digest
    # must still catch it, proving gaps/findings are covered.
    tampered = copy.deepcopy(document)
    tampered["cross_checks"]["findings"][0]["message"] = "nothing to see here"
    result = forensics.verify_forensic_export(tampered)
    assert result.ok is False
    assert {problem["code"] for problem in result.problems} == {
        "manifest_sha256_mismatch"
    }


def test_export_roundtrips_through_file(ordered_rsps, gl, tmp_path):
    _register_tag_migration_scenario(ordered_rsps)
    release = ProjectRelease(
        gl.projects.get(PROJECT_ID, lazy=True).releases,
        {"tag_name": TAG_NAME},
        lazy=True,
    )
    output = tmp_path / "evidence.json"
    document = release.forensic_export(output_file=str(output))

    on_disk = json.loads(output.read_text(encoding="utf-8"))
    assert on_disk == document
    assert forensics.verify_forensic_export(output).ok is True
    assert forensics.verify_forensic_export(str(output)).ok is True

    summary = forensics.summarize_export(on_disk)
    assert summary["cross_checks"]["detected_at_step"] == "tag:reread"
    assert summary["manifest_sha256"] == document["integrity"]["manifest_sha256"]


def _register_permission_limited_scenario(rsps):
    # Release read is allowed.
    _add_json(rsps, RELEASE_URL, _release_body(OLD_SHA))
    # Tag read is allowed.
    _add_json(rsps, TAG_URL, _tag_body(OLD_SHA))
    # Asset links: first page works and points at jobs, second page is 403.
    _add_json(
        rsps,
        LINKS_URL,
        [_link(11, OLD_JOB_ID)],
        headers=_page_headers(page=1, per_page=1, total=2, next_page=2),
        match=[
            responses.matchers.query_param_matcher({"page": "1", "per_page": "1"})
        ],
    )
    _add_json(
        rsps,
        LINKS_URL,
        {"message": "403 Forbidden"},
        number=403,
        match=[
            responses.matchers.query_param_matcher({"page": "2", "per_page": "1"})
        ],
    )
    # Tag re-read is allowed.
    _add_json(rsps, TAG_URL, _tag_body(OLD_SHA))
    # Job lookup for the first page is allowed.
    _add_json(
        rsps,
        JOB_URL.format(project_id=PROJECT_ID, job_id=OLD_JOB_ID),
        _job_body(OLD_JOB_ID, OLD_PIPELINE_ID, OLD_SHA),
    )


def test_permission_limited_collection_lists_evidence_gaps(gl):
    with responses.RequestsMock(
        registry=responses.registries.OrderedRegistry
    ) as rsps:
        _register_permission_limited_scenario(rsps)
        release = ProjectRelease(
            gl.projects.get(PROJECT_ID, lazy=True).releases,
            {"tag_name": TAG_NAME},
            lazy=True,
        )
        document = release.forensic_export(per_page=1)

    assert document["cross_checks"]["summary"]["divergence_detected"] is False
    gaps = document["evidence_gaps"]
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap["code"] == "pagination_aborted"
    assert gap["status"] == 403
    assert gap["permission_denied"] is True
    assert gap["blocking"] is True
    assert gap["details"]["page"] == 2
    assert gap["details"]["total"] == 2
    assert gap["observation_id"] is not None

    links_step = next(
        step for step in document["steps"] if step["step"] == "release-links"
    )
    assert links_step["status"] == "incomplete"
    assert links_step["evidence_gaps"] == ["pagination_aborted"]

    # The failed page raw body is still preserved for review.
    failed = next(
        observation
        for observation in document["observations"]
        if observation["observation_id"] == gap["observation_id"]
    )
    assert failed["response"]["status"] == 403
    assert json.loads(failed["response"]["body"]["text"]) == {
        "message": "403 Forbidden"
    }

    verification = forensics.verify_forensic_export(document)
    assert verification.ok is True
    assert verification.summary["evidence_gap_count"] == 1


def test_job_lookup_permission_gap_marks_link_unresolved(ordered_rsps, gl):
    # Release, tag, links, tag re-read are all available.
    _add_json(ordered_rsps, RELEASE_URL, _release_body(OLD_SHA))
    _add_json(ordered_rsps, TAG_URL, _tag_body(OLD_SHA))
    _add_json(
        ordered_rsps,
        LINKS_URL,
        [_link(11, OLD_JOB_ID)],
        headers=_page_headers(page=1, per_page=100, total=1, next_page=None),
        match=[
            responses.matchers.query_param_matcher({"page": "1", "per_page": "100"})
        ],
    )
    _add_json(ordered_rsps, TAG_URL, _tag_body(NEW_SHA))
    _add_json(
        ordered_rsps,
        JOB_URL.format(project_id=PROJECT_ID, job_id=OLD_JOB_ID),
        {"message": "403 Forbidden"},
        number=403,
    )

    document = _collect(gl)

    assert len(document["evidence_gaps"]) == 1
    gap = document["evidence_gaps"][0]
    assert gap["code"] == "job_forbidden"
    assert gap["details"]["job_id"] == OLD_JOB_ID
    assert gap["permission_denied"] is True

    link = document["cross_checks"]["asset_links"][0]
    assert link["relation"] == "unresolved"
    assert link["gap_code"] == "job_forbidden"
    assert any(
        finding["code"] == "asset_link_pipeline_unresolved"
        for finding in document["cross_checks"]["findings"]
    )
    # The tag migration is still detected and kept.
    assert document["cross_checks"]["summary"]["divergence_detected"] is True


def test_collector_does_not_abort_when_release_is_forbidden(gl):
    with responses.RequestsMock(
        registry=responses.registries.OrderedRegistry
    ) as rsps:
        _add_json(rsps, RELEASE_URL, {"message": "403 Forbidden"}, number=403)
        _add_json(rsps, TAG_URL, _tag_body(OLD_SHA))
        _add_json(
            rsps,
            LINKS_URL,
            [],
            headers=_page_headers(page=1, per_page=100, total=0, next_page=None),
            match=[
                responses.matchers.query_param_matcher(
                    {"page": "1", "per_page": "100"}
                )
            ],
        )
        _add_json(rsps, TAG_URL, _tag_body(OLD_SHA))
        document = forensics.ReleaseForensicCollector(
            gl, PROJECT_ID, TAG_NAME, include_jobs=False
        ).collect()

    gap = document["evidence_gaps"][0]
    assert gap["code"] == "release_forbidden"
    assert gap["step"] == "release"
    assert gap["blocking"] is True
    release_step = next(
        step for step in document["steps"] if step["step"] == "release"
    )
    assert release_step["status"] == "incomplete"
    assert document["cross_checks"]["summary"]["divergence_detected"] is False


def test_collector_records_invalid_json_and_pagination_limits(gl):
    with responses.RequestsMock(
        registry=responses.registries.OrderedRegistry
    ) as rsps:
        _add_json(rsps, RELEASE_URL, _release_body(OLD_SHA))
        _add_json(rsps, TAG_URL, _tag_body(OLD_SHA))
        # A full page without pagination headers: unverifiable, but not fatal.
        rsps.add(
            method=responses.GET,
            url=LINKS_URL,
            body="not json",
            content_type="application/json",
            status=200,
            match=[
                responses.matchers.query_param_matcher(
                    {"page": "1", "per_page": "100"}
                )
            ],
        )
        _add_json(rsps, TAG_URL, _tag_body(OLD_SHA))
        document = forensics.ReleaseForensicCollector(
            gl, PROJECT_ID, TAG_NAME, include_jobs=False
        ).collect()

    assert document["evidence_gaps"][0]["code"] == "links_invalid_response"
    assert document["evidence_gaps"][0]["blocking"] is True
    # The raw invalid body is preserved so the reviewer can see what arrived.
    links_step = next(
        step for step in document["steps"] if step["step"] == "release-links"
    )
    observation_id = links_step["observations"][0]
    observation = next(
        item
        for item in document["observations"]
        if item["observation_id"] == observation_id
    )
    assert observation["response"]["body"]["text"] == "not json"
    assert forensics.verify_forensic_export(document).ok is True


def test_manager_level_forensic_export_supports_cli_string_options(gl):
    with responses.RequestsMock(
        registry=responses.registries.OrderedRegistry,
        assert_all_requests_are_fired=False,
    ) as rsps:
        _register_tag_migration_scenario(rsps)
        manager = gl.projects.get(PROJECT_ID, lazy=True).releases
        document = manager.forensic_export(
            TAG_NAME,
            include_jobs="false",
            recheck_tag="true",
            per_page="100",
        )

    assert document["cross_checks"]["summary"]["divergence_detected"] is True
    assert "jobs" not in [step["step"] for step in document["steps"]]
    assert document["cross_checks"]["asset_links"][0]["relation"] == "unresolved"
    assert document["evidence_gaps"][0]["code"] == "job_provenance_disabled"
    assert document["evidence_gaps"][0]["blocking"] is False


@pytest.mark.parametrize(
    "value,expected",
    [("true", True), ("0", False), ("yes", True), ("off", False)],
)
def test_coerce_bool(value, expected):
    assert forensics._coerce_bool(value, default=not expected) is expected


def test_verify_reports_malformed_and_dangling_references():
    assert forensics.verify_forensic_export("{not json").ok is False

    document = {
        "schema": forensics.SCHEMA,
        "schema_version": forensics.SCHEMA_VERSION,
        "observations": [
            {
                "observation_id": "obs-001",
                "response": {
                    "body": {
                        "encoding": "utf-8",
                        "text": "{}",
                        "size": 2,
                        "sha256": hashlib.sha256(b"{}").hexdigest(),
                    }
                },
            }
        ],
        "steps": [{"step": "release", "observations": ["obs-404"]}],
        "evidence_gaps": [],
        "cross_checks": {},
    }
    document["integrity"] = {
        "algorithm": "sha256",
        "canonicalization": "json-sorted-utf8",
        "manifest_sha256": forensics._manifest_digest(document),
    }

    result = forensics.verify_forensic_export(document)
    assert result.ok is False
    assert [problem["code"] for problem in result.problems] == [
        "dangling_observation_reference"
    ]


def test_verify_rejects_unsupported_schema():
    result = forensics.verify_forensic_export(
        {"schema": "something/else", "schema_version": 99, "observations": []}
    )
    codes = {problem["code"] for problem in result.problems}
    assert "schema_unsupported" in codes
    assert "schema_version_unsupported" in codes
    assert "missing_integrity" in codes


def test_cli_forensic_export_writes_summary_json(gl, tmp_path, capsys):
    from gitlab.v4 import cli as v4_cli

    output = tmp_path / "cli-evidence.json"
    with responses.RequestsMock(
        registry=responses.registries.OrderedRegistry
    ) as rsps:
        _register_tag_migration_scenario(rsps)
        v4_cli.run(
            gl,
            "project-release",
            "forensic-export",
            {
                "project_id": "1",
                "tag_name": TAG_NAME,
                "output_file": str(output),
            },
            verbose=False,
            output="json",
            fields=[],
        )

    printed = json.loads(capsys.readouterr().out)
    assert printed["schema"] == forensics.SCHEMA
    assert printed["subject"]["tag_name"] == TAG_NAME
    assert (
        printed["cross_checks"]["summary"]["detected_at_step"] == "tag:reread"
    )
    assert output.exists()
    assert forensics.verify_forensic_export(output).ok is True


def _register_single_tag_read_scenario(rsps, job_sha: str) -> None:
    _add_json(rsps, RELEASE_URL, _release_body(job_sha))
    _add_json(rsps, TAG_URL, _tag_body(OLD_SHA))
    _add_json(
        rsps,
        LINKS_URL,
        [_link(11, OLD_JOB_ID)],
        headers=_page_headers(page=1, per_page=100, total=1, next_page=None),
        match=[
            responses.matchers.query_param_matcher({"page": "1", "per_page": "100"})
        ],
    )
    _add_json(
        rsps,
        JOB_URL.format(project_id=PROJECT_ID, job_id=OLD_JOB_ID),
        _job_body(OLD_JOB_ID, OLD_PIPELINE_ID, job_sha),
    )


def test_single_tag_read_with_mismatching_job_is_not_accused(gl):
    """Without a re-read, a mismatch must be reported as unverified, not critical."""
    other_sha = "3" * 40
    with responses.RequestsMock(
        registry=responses.registries.OrderedRegistry
    ) as rsps:
        _register_single_tag_read_scenario(rsps, other_sha)
        document = forensics.ReleaseForensicCollector(
            gl, PROJECT_ID, TAG_NAME, recheck_tag=False
        ).collect()

    link = document["cross_checks"]["asset_links"][0]
    assert link["relation"] == "unobserved"
    codes = {
        finding["code"] for finding in document["cross_checks"]["findings"]
    }
    assert "asset_link_pipeline_mismatch" not in codes
    assert "asset_link_pipeline_unverified" in codes
    assert document["cross_checks"]["summary"]["divergence_detected"] is False


def test_release_commit_mismatch_is_flagged(gl):
    with responses.RequestsMock(
        registry=responses.registries.OrderedRegistry
    ) as rsps:
        # Release still references the old commit, but both tag reads see a new
        # one: the release object itself is stale relative to the tag.
        _add_json(rsps, RELEASE_URL, _release_body(OLD_SHA))
        _add_json(rsps, TAG_URL, _tag_body(NEW_SHA))
        _add_json(
            rsps,
            LINKS_URL,
            [],
            headers=_page_headers(page=1, per_page=100, total=0, next_page=None),
            match=[
                responses.matchers.query_param_matcher(
                    {"page": "1", "per_page": "100"}
                )
            ],
        )
        _add_json(rsps, TAG_URL, _tag_body(NEW_SHA))
        document = forensics.ReleaseForensicCollector(
            gl, PROJECT_ID, TAG_NAME, include_jobs=False
        ).collect()

    codes = [finding["code"] for finding in document["cross_checks"]["findings"]]
    assert "tag_moved" not in codes
    assert "release_commit_mismatch" in codes
    assert document["cross_checks"]["summary"]["divergence_detected"] is False


def test_connection_error_is_recorded_as_gap(gl):
    with responses.RequestsMock(
        registry=responses.registries.OrderedRegistry
    ) as rsps:
        _add_json(rsps, RELEASE_URL, _release_body(OLD_SHA))
        _add_json(rsps, TAG_URL, _tag_body(OLD_SHA))
        rsps.add(
            method=responses.GET,
            url=LINKS_URL,
            body=responses.ConnectionError("boom"),
            status=200,
            match=[
                responses.matchers.query_param_matcher(
                    {"page": "1", "per_page": "100"}
                )
            ],
        )
        _add_json(rsps, TAG_URL, _tag_body(OLD_SHA))
        document = forensics.ReleaseForensicCollector(
            gl, PROJECT_ID, TAG_NAME, include_jobs=False
        ).collect()

    gap = document["evidence_gaps"][0]
    assert gap["code"] == "links_unavailable"
    assert gap["permission_denied"] is False
    assert gap["observation_id"] is not None
    assert forensics.verify_forensic_export(document).ok is True


def test_page_headers_are_preserved_in_observation(ordered_rsps, gl):
    _register_tag_migration_scenario(ordered_rsps)
    document = _collect(gl)

    links_step = next(
        step for step in document["steps"] if step["step"] == "release-links"
    )
    observation = next(
        item
        for item in document["observations"]
        if item["observation_id"] == links_step["observations"][0]
    )
    headers = observation["response"]["headers"]
    assert headers["x-total"] == "2"
    assert headers["x-page"] == "1"
    assert headers["x-next-page"] == ""


def test_divergence_is_bound_to_cross_check_finding(ordered_rsps, gl):
    _register_tag_migration_scenario(ordered_rsps)
    document = _collect(gl)

    steps = {step["step"]: step for step in document["steps"]}
    assert steps["tag:reread"]["divergence_detected"] is True
    assert steps["cross-check"]["divergence_detected"] is True
    assert steps["tag:reread"]["findings"] == []
    assert steps["tag:initial"]["findings"] == []
    assert "F1" in steps["cross-check"]["findings"]

    divergence = document["cross_checks"]["divergences"][0]
    assert divergence["detected_at_step"] == "tag:reread"
    # The finding lives on the cross-check step but cites both raw tag reads.
    tag_moved = next(
        finding
        for finding in document["cross_checks"]["findings"]
        if finding["code"] == "tag_moved"
    )
    assert tag_moved["step"] == "cross-check"
    assert tag_moved["observations"] == [
        divergence["before"]["observation_id"],
        divergence["after"]["observation_id"],
    ]
