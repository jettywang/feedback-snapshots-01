from __future__ import annotations

import json

import pytest

from hatch.env.lock_audit import (
    AuditReport,
    CandidateResult,
    CandidateSpec,
    PatchCheck,
    build_candidates,
    evaluate_candidate,
    load_evidence,
    report_from_dict,
    report_to_dict,
    run_audit,
    verify_evidence,
    write_evidence,
)
from hatch.env.lockers.memory import MemoryLocker
from hatch.project.core import Project


@pytest.fixture(autouse=True)
def _reset_memory_locker():
    MemoryLocker.reset()
    yield
    MemoryLocker.reset()


def _make_project(temp_dir, config_file, envs):
    config_file.model.template.plugins["default"]["tests"] = False
    config_file.save()
    config = {
        "project": {"name": "audit-demo", "version": "0.1.0", "dependencies": []},
        "tool": {"hatch": {"envs": envs}},
    }
    (temp_dir / "pyproject.toml").write_text("[project]\nname = 'audit-demo'\nversion = '0.1.0'\n")
    return Project(temp_dir, config=config)


def _env_config(*, locker="memory", target="wheel", marker="", dependencies=None):
    return {
        "type": "virtual",
        "skip-install": True,
        "locked": True,
        "locker": locker,
        "lock-targets": [target],
        "lock-marker": marker,
        "dependencies": dependencies or ["urllib3>=2.2.2"],
    }


def test_two_environments_different_markers_one_late_failure(
    temp_dir, config_file, isolated_data_dir, temp_application
):
    project = _make_project(
        temp_dir,
        config_file,
        {
            "linux": _env_config(marker="python_version >= '3'", target="wheel"),
            "macos": _env_config(marker="sys_platform != 'nonexistent'", target="sdist"),
        },
    )
    project.set_app(temp_application)
    temp_application.project = project
    temp_application.data_dir = isolated_data_dir
    temp_application.config_file = config_file

    MemoryLocker.configure("linux", {"urllib3": "2.5.0"})
    MemoryLocker.configure("macos", fail_at="report", error="index unavailable")

    linux = project.get_environment("linux")
    macos = project.get_environment("macos")
    candidates = build_candidates(linux) + build_candidates(macos)
    assert [candidate.target for candidate in candidates] == ["wheel", "sdist"]

    report = run_audit(project, ["linux", "macos"], [PatchCheck.parse("urllib3>=2.2.2")])

    by_env = {result.candidate.environment: result for result in report.results}
    assert by_env["linux"].status == "passed"
    assert by_env["linux"].version_of("urllib3") == "2.5.0"
    assert by_env["macos"].status == "failed"
    assert "index unavailable" in by_env["macos"].error
    assert not report.passed
    assert [result.candidate.environment for result in report.failing] == ["macos"]


def test_previous_pass_is_not_proof_for_current_candidate(temp_dir):
    patch = PatchCheck.parse("urllib3>=2.2.2")
    candidate = CandidateSpec(
        environment="linux",
        target="wheel",
        marker="",
        locker="memory",
        lockfile=str(temp_dir / "pylock.linux.toml"),
        inputs=["urllib3>=2.2.2"],
    )
    previous = report_to_dict(
        AuditReport(
            patches=[patch],
            results=[CandidateResult(candidate=candidate, status="passed", versions={"urllib3": "2.5.0"})],
        )
    )
    loaded = report_from_dict(previous)
    assert loaded.passed

    class BrokenLocker:
        PLUGIN_NAME = "memory"

        @classmethod
        def report_versions(cls, *_args, **_kwargs):
            raise RuntimeError("registry offline")

    import hatch.env.lock as lock_module

    original = lock_module.get_locker_plugin_class
    lock_module.get_locker_plugin_class = lambda *_a, **_k: BrokenLocker
    try:
        result = evaluate_candidate(object(), candidate, [patch])
    finally:
        lock_module.get_locker_plugin_class = original

    assert result.status == "failed"
    assert result.previous_status == ""


def test_retained_lockfile_is_reviewable_but_never_passes(temp_dir):
    lockfile = temp_dir / "pylock.legacy.toml"
    lockfile.write_text('lock-version = "1.0"\n[[packages]]\nname = "urllib3"\nversion = "2.5.0"\n', encoding="utf-8")
    candidate = CandidateSpec(
        environment="legacy",
        target="wheel",
        marker="",
        locker="memory",
        lockfile=str(lockfile),
        inputs=["urllib3>=2.2.2"],
    )

    class BrokenLocker:
        PLUGIN_NAME = "memory"

        @classmethod
        def report_versions(cls, *_args, **_kwargs):
            raise RuntimeError("boom")

    import hatch.env.lock as lock_module

    original = lock_module.get_locker_plugin_class
    lock_module.get_locker_plugin_class = lambda *_a, **_k: BrokenLocker
    try:
        result = evaluate_candidate(object(), candidate, [PatchCheck.parse("urllib3>=2.2.2")])
    finally:
        lock_module.get_locker_plugin_class = original

    assert result.status == "failed"
    assert result.retained_versions == {"urllib3": "2.5.0"}
    assert result.retained_source == str(lockfile)
    report = AuditReport(patches=[PatchCheck.parse("urllib3>=2.2.2")], results=[result])
    assert not report.passed
    assert verify_evidence(report)


def test_marker_inactive_candidate_is_not_counted(temp_dir, config_file, isolated_data_dir, temp_application):
    project = _make_project(
        temp_dir,
        config_file,
        {"windows": _env_config(marker="sys_platform == 'win32'", target="wheel")},
    )
    project.set_app(temp_application)
    temp_application.project = project
    temp_application.data_dir = isolated_data_dir
    temp_application.config_file = config_file

    MemoryLocker.configure("windows", {"urllib3": "1.0.0"})
    report = run_audit(project, ["windows"], [PatchCheck.parse("urllib3>=2.2.2")])

    assert len(report.results) == 1
    assert report.results[0].status == "inactive"
    assert not report.passed


def test_package_outside_lock_inputs_is_not_required_but_does_not_verify(
    temp_dir, config_file, isolated_data_dir, temp_application
):
    project = _make_project(
        temp_dir,
        config_file,
        {"docs": _env_config(target="wheel", dependencies=["sphinx>=8"])},
    )
    project.set_app(temp_application)
    temp_application.project = project
    temp_application.data_dir = isolated_data_dir
    temp_application.config_file = config_file

    MemoryLocker.configure("docs", {"sphinx": "8.2.3"})
    report = run_audit(project, ["docs"], [PatchCheck.parse("urllib3>=2.2.2")])

    result = report.results[0]
    assert result.status == "not-required"
    assert result.covered
    # Nothing actually contained the patch, so this is not a verification.
    assert not report.passed
    assert not report.verified


def test_required_patch_package_missing_is_unpatched(temp_dir, config_file, isolated_data_dir, temp_application):
    project = _make_project(
        temp_dir,
        config_file,
        {
            "api": _env_config(target="wheel", dependencies=["urllib3>=2.2.2", "sphinx>=8"]),
        },
    )
    project.set_app(temp_application)
    temp_application.project = project
    temp_application.data_dir = isolated_data_dir
    temp_application.config_file = config_file

    MemoryLocker.configure("api", {"sphinx": "8.2.3"})
    report = run_audit(project, ["api"], [PatchCheck.parse("urllib3>=2.2.2")])

    result = report.results[0]
    assert result.status == "unpatched"
    assert "urllib3" in result.error
    assert not report.passed


def test_evidence_round_trip_and_offline_verify(temp_dir):
    patch = PatchCheck.parse("urllib3>=2.2.2")
    candidate = CandidateSpec(
        environment="linux",
        target="wheel",
        marker="",
        locker="memory",
        lockfile=str(temp_dir / "pylock.linux.toml"),
        inputs=["urllib3>=2.2.2"],
    )
    lockfile = temp_dir / "pylock.linux.toml"
    lockfile.write_text('lock-version = "1.0"\n[[packages]]\nname = "urllib3"\nversion = "2.5.0"\n')
    from hatch.env.lock_audit import lockfile_digest

    report = AuditReport(
        patches=[patch],
        results=[
            CandidateResult(
                candidate=candidate,
                status="passed",
                versions={"urllib3": "2.5.0"},
                lockfile_sha256=lockfile_digest(lockfile),
            )
        ],
    )
    path = write_evidence(temp_dir / ".hatch" / "lock-audit.json", report)

    loaded = load_evidence(path)
    assert loaded is not None
    assert verify_evidence(loaded) == []
    assert json.loads(path.read_text())["passed"] is True

    data = json.loads(path.read_text())
    data["candidates"][0]["versions"]["urllib3"] = "2.0.0"
    path.write_text(json.dumps(data))
    loaded = load_evidence(path)
    assert verify_evidence(loaded)
