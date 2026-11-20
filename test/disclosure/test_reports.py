import json
from pathlib import Path

import pytest
from packaging.version import Version

import pip_audit._fix as fix
import pip_audit._service as service
from pip_audit._disclosure import (
    DisclosureError,
    DisclosurePolicy,
    assert_public_report_safe,
    build_internal_report,
    build_public_report,
    clear_public_report,
    private_names,
    project_public_inputs,
    sensitive_strings,
    write_public_report,
)

PUBLIC_DEP = service.ResolvedDependency(name="public-lib", version=Version("1.0.0"))
PRIVATE_DEP = service.ResolvedDependency(
    name="internal-payments-lib", version=Version("1.2.3")
)
BROKEN_DEP = service.SkippedDependency(
    name="internal-broken-lib",
    skip_reason="Package has invalid version: /srv/private/internal-broken-lib",
)

PUBLIC_VULN = service.VulnerabilityResult(
    id="PYSEC-2099-0001",
    description="ADVISORY-DESCRIPTION-MARKER mentions internal-payments-lib and /srv/private",
    fix_versions=[Version("1.0.1")],
    aliases={"CVE-2099-0001"},
)
PRIVATE_VULN = service.VulnerabilityResult(
    id="PYSEC-2099-0002",
    description="PRIVATE-ADVISORY-MARKER internal only",
    fix_versions=[Version("1.2.4")],
    aliases=set(),
)

RESULT = {
    PUBLIC_DEP: [PUBLIC_VULN],
    PRIVATE_DEP: [PRIVATE_VULN],
    BROKEN_DEP: [],
}


@pytest.fixture
def policy():
    return DisclosurePolicy.from_names(["public-lib"])


def test_policy_canonicalizes_and_rejects_unsafe_names():
    assert DisclosurePolicy.from_names(["Public_Lib"]).public_dependencies == {"public-lib"}

    with pytest.raises(DisclosureError):
        DisclosurePolicy.from_names(["../private-pkg"])
    with pytest.raises(DisclosureError):
        DisclosurePolicy.from_names(["# only a comment"])
    with pytest.raises(DisclosureError):
        DisclosurePolicy.from_file(Path("/nonexistent/allowlist"))


def test_public_report_names_only_allowlisted_dependencies(policy):
    inputs = project_public_inputs(RESULT, [], policy)
    report = build_public_report(inputs)

    assert [dep["name"] for dep in report["public_dependencies"]] == ["public-lib"]
    serialized = json.dumps(report)
    assert "internal-payments-lib" not in serialized
    assert "internal-broken-lib" not in serialized
    assert "/srv/private" not in serialized


def test_public_report_omits_descriptions_skip_reasons_and_errors(policy):
    inputs = project_public_inputs(RESULT, [], policy)
    report = build_public_report(inputs)

    serialized = json.dumps(report)
    assert "ADVISORY-DESCRIPTION-MARKER" not in serialized
    assert "PRIVATE-ADVISORY-MARKER" not in serialized
    assert "skip_reason" not in serialized
    assert "description" not in serialized
    assert "error" not in serialized

    vuln = report["public_dependencies"][0]["vulnerabilities"][0]
    assert set(vuln) == {"id", "aliases", "fix_versions"}


def test_public_report_publishes_skipped_public_dependency_without_reason():
    skipped_public = service.SkippedDependency(
        name="public-lib", skip_reason="editable at /srv/private/public-lib"
    )
    policy = DisclosurePolicy.from_names(["public-lib"])
    report = build_public_report(project_public_inputs({skipped_public: []}, [], policy))

    entry = report["public_dependencies"][0]
    assert entry == {"name": "public-lib", "audited": False}
    assert "skip_reason" not in json.dumps(report)


def test_public_report_has_no_private_aggregate_counts(policy):
    report = build_public_report(project_public_inputs(RESULT, [], policy))

    assert report["audit"] == {
        "status": "complete",
        "public_dependencies": 1,
        "vulnerable_dependencies": 1,
        "vulnerabilities": 1,
    }


def test_public_report_withholds_failed_and_private_fixes():
    policy = DisclosurePolicy.from_names(["public-lib"])
    fixes = [
        fix.SkippedFixVersion(PUBLIC_DEP, "failed to upgrade: /srv/private/index"),
        fix.ResolvedFixVersion(PRIVATE_DEP, Version("1.2.4")),
        fix.ResolvedFixVersion(PUBLIC_DEP, Version("1.0.1")),
    ]
    report = build_public_report(project_public_inputs(RESULT, fixes, policy))

    assert report["fixes"] == [
        {"name": "public-lib", "old_version": "1.0.0", "new_version": "1.0.1"}
    ]
    assert "/srv/private/index" not in json.dumps(report)


def test_internal_report_contains_every_detail(policy):
    fixes = [
        fix.ResolvedFixVersion(PUBLIC_DEP, Version("1.0.1")),
        fix.SkippedFixVersion(PRIVATE_DEP, "cannot upgrade /srv/private/index"),
    ]
    report = build_internal_report(RESULT, fixes, policy, exit_code=1)

    names = [dep["name"] for dep in report["dependencies"]]
    assert names == ["internal-broken-lib", "internal-payments-lib", "public-lib"]
    by_name = {dep["name"]: dep for dep in report["dependencies"]}
    assert by_name["internal-payments-lib"]["visibility"] == "private"
    assert by_name["internal-payments-lib"]["vulnerabilities"][0]["description"] == (
        "PRIVATE-ADVISORY-MARKER internal only"
    )
    broken_reason = by_name["internal-broken-lib"]["skip_reason"]
    assert broken_reason.endswith("/srv/private/internal-broken-lib")
    assert by_name["public-lib"]["vulnerabilities"][0]["description"] == (
        "ADVISORY-DESCRIPTION-MARKER mentions internal-payments-lib and /srv/private"
    )
    assert report["fixes"][1]["skip_reason"] == "cannot upgrade /srv/private/index"


def test_internal_report_records_failure(policy):
    error = RuntimeError("Could not connect to OSV's vulnerability feed")
    try:
        raise error
    except RuntimeError as caught:
        report = build_internal_report({}, [], policy, error=caught, exit_code=1)

    assert report["audit"]["status"] == "failed"
    assert report["audit"]["exit_code"] == 1
    assert report["error"]["type"] == "RuntimeError"
    assert report["error"]["message"] == "Could not connect to OSV's vulnerability feed"
    assert "traceback" in report["error"]


def test_public_report_validation_catches_wiring_mistakes(policy):
    report = {"public_dependencies": [{"name": "internal-payments-lib"}]}
    with pytest.raises(DisclosureError):
        assert_public_report_safe(report, policy)

    report = {"public_dependencies": [{"name": "public-lib", "description": "leak"}]}
    with pytest.raises(DisclosureError):
        assert_public_report_safe(report, policy)

    report = {"public_dependencies": [{"name": "public-lib", "vulnerabilities": [
        {"id": "PYSEC-1", "aliases": [], "fix_versions": ["1.0.1"]}
    ]}]}
    assert_public_report_safe(report, policy)


def test_public_report_validation_checks_private_names_and_text(policy):
    inputs = project_public_inputs(RESULT, [], policy)
    report = build_public_report(inputs)
    assert_public_report_safe(
        report,
        policy,
        private_dependency_names=private_names(RESULT, policy),
        sensitive_text=sensitive_strings(RESULT, []),
    )

    with pytest.raises(DisclosureError):
        assert_public_report_safe(
            {
                "public_dependencies": [
                    {"name": "public-lib", "vulnerabilities": [{"id": "internal-payments-lib"}]}
                ]
            },
            policy,
            private_dependency_names=["internal-payments-lib"],
            sensitive_text=[],
        )
    with pytest.raises(DisclosureError):
        assert_public_report_safe(
            {
                "public_dependencies": [{"name": "public-lib", "vulnerabilities": []}],
                "audit": {"status": "ADVISORY-DESCRIPTION-MARKER mentions internal-payments-lib"},
            },
            policy,
            private_dependency_names=[],
            sensitive_text=["ADVISORY-DESCRIPTION-MARKER mentions internal-payments-lib"],
        )


def test_clear_public_report_removes_stale_artifact(tmp_path):
    target = tmp_path / "public.json"
    target.write_text("stale")
    clear_public_report(target)
    assert not target.exists()
    clear_public_report(target)


def test_write_public_report_refuses_unsafe_report(tmp_path, policy):
    target = tmp_path / "public.json"
    target.write_text('{"stale": true}')

    with pytest.raises(DisclosureError):
        write_public_report(
            target,
            {"public_dependencies": [{"name": "internal-payments-lib"}]},
            policy,
        )

    assert json.loads(target.read_text()) == {"stale": True}


def test_write_public_report_is_atomic(tmp_path, policy):
    target = tmp_path / "public.json"
    report = build_public_report(project_public_inputs(RESULT, [], policy))
    write_public_report(
        target,
        report,
        policy,
        private_dependency_names=private_names(RESULT, policy),
        sensitive_text=sensitive_strings(RESULT, []),
    )

    assert json.loads(target.read_text()) == report
    assert not list(tmp_path.glob(".public.json.*.tmp"))


def test_description_equal_to_version_is_never_copied(policy):
    # A description that happens to equal a token cannot leak into the public
    # report: the public builder never sees the description field at all.
    vuln = service.VulnerabilityResult(
        id="PYSEC-2099-0003",
        description="1.0.1",
        fix_versions=[Version("1.0.1")],
        aliases=set(),
    )
    result = {PUBLIC_DEP: [vuln]}
    report = build_public_report(project_public_inputs(result, [], policy))

    assert report["public_dependencies"][0]["vulnerabilities"][0]["fix_versions"] == ["1.0.1"]
    assert "description" not in json.dumps(report)
    assert_public_report_safe(
        report,
        policy,
        private_dependency_names=[],
        sensitive_text=["1.0.1"],
    )
