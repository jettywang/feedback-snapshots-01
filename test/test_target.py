from __future__ import annotations

import json
from pathlib import Path

import pytest
from packaging.version import Version

from pip_audit._dependency_source import PyLockSource
from pip_audit._service import Dependency, VulnerabilityResult, VulnerabilityService
from pip_audit._target import TargetEnvironment, TargetEnvironmentError
from pip_audit._target_audit import audit_targets

_ASSETS = Path(__file__).parent / "assets"

LINUX = "linux:sys_platform=linux,platform_system=Linux,python_version=3.12"
MACOS = "macos:sys_platform=darwin,platform_system=Darwin,python_version=3.12"


class FakeAdvisoryService(VulnerabilityService):
    """
    A fake announcement feed.

    It records every query it receives so tests can prove which packages were
    audited for which target.
    """

    def __init__(self, advisories: dict[tuple[str, str], list[VulnerabilityResult]]):
        self.advisories = advisories
        self.queries: list[tuple[str, str]] = []

    def query(self, spec: Dependency):
        if spec.is_skipped():
            return spec, []
        spec = spec  # type: ignore[assignment]
        name, version = spec.canonical_name, str(spec.version)  # type: ignore[attr-defined]
        self.queries.append((name, version))
        return spec, list(self.advisories.get((name, version), []))


def _advisory(vuln_id: str, fixed: str) -> VulnerabilityResult:
    return VulnerabilityResult(
        id=vuln_id,
        description="fake advisory",
        fix_versions=[Version(fixed)],
        aliases=set(),
    )


@pytest.fixture
def source() -> PyLockSource:
    return PyLockSource([_ASSETS / "pylock.targets.toml"])


@pytest.fixture
def service() -> FakeAdvisoryService:
    return FakeAdvisoryService(
        {("jinja2", "3.1.4"): [_advisory("CVE-2024-9999", "3.1.5")]}
    )


def test_target_parse():
    target = TargetEnvironment.parse(LINUX)
    assert target.name == "linux"
    assert target.environment["sys_platform"] == "linux"
    assert target.environment["python_full_version"] == "3.12.0"
    assert target.marker_environment()["extras"] == frozenset()


def test_target_parse_full_version_derives_short_version():
    target = TargetEnvironment.parse("t:python_full_version=3.11.4")
    assert target.environment["python_version"] == "3.11"


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ("", "expected NAME:KEY=VALUE"),
        ("linux", "expected NAME:KEY=VALUE"),
        ("linux:", "expected NAME:KEY=VALUE"),
        ("linux:sys_platform", "expected KEY=VALUE"),
        ("linux:sys_platform=linux,sys_platform=darwin", "duplicate key"),
        ("linux:bogus=1", "unknown environment marker variable"),
        ("linux:extras=foo", "fixed by the lockfile evaluation context"),
        ("bad name:sys_platform=linux", "invalid target name"),
        ("linux:python_version=three", "invalid python version"),
    ],
)
def test_target_parse_errors(spec, message):
    with pytest.raises(TargetEnvironmentError, match=message):
        TargetEnvironment.parse(spec)


def test_targets_see_platform_specific_packages(source):
    linux = source.collect_for_target(TargetEnvironment.parse(LINUX))
    macos = source.collect_for_target(TargetEnvironment.parse(MACOS))

    linux_names = {dep.canonical_name for dep in linux.dependencies}
    macos_names = {dep.canonical_name for dep in macos.dependencies}

    assert "uvloop" in linux_names
    assert "uvloop" not in macos_names
    assert "pyobjc-core" in macos_names
    assert "pyobjc-core" not in linux_names
    assert linux.excluded and macos.excluded


def test_targets_keep_multiple_versions_separate(source):
    linux = source.collect_for_target(TargetEnvironment.parse(LINUX))
    macos = source.collect_for_target(TargetEnvironment.parse(MACOS))

    linux_certifi = next(dep for dep in linux.dependencies if dep.name == "certifi")
    macos_certifi = next(dep for dep in macos.dependencies if dep.name == "certifi")

    assert str(linux_certifi.version) == "2024.2.2"
    assert str(macos_certifi.version) == "2024.8.30"
    assert linux.error is None
    assert macos.error is None


def test_condition_packages_not_counted_for_target(source):
    linux = source.collect_for_target(TargetEnvironment.parse(LINUX))

    excluded = {condition.name for condition in linux.excluded}
    assert "pyobjc-core" in excluded
    assert "tomli" in excluded

    # Conditional entries never reach the audit set.
    assert "pyobjc-core" not in {dep.canonical_name for dep in linux.dependencies}


def test_undetermined_marker_reports_explicit_reason(source):
    collection = source.collect_for_target(TargetEnvironment.parse(LINUX))

    undetermined = {condition.name: condition for condition in collection.undetermined}
    assert "legacy-ctypes" in undetermined
    reason = undetermined["legacy-ctypes"].reason
    assert "platform_machine" in reason
    assert "cannot determine" in reason


def test_undetermined_target_has_explicit_reason(source):
    # This target omits `sys_platform`, which the lockfile's environments use.
    target = TargetEnvironment.parse("mystery:python_version=3.12")
    collection = source.collect_for_target(target)

    assert collection.dependencies == ()
    assert collection.error is not None
    assert "cannot determine whether target 'mystery' is covered" in collection.error
    assert "sys_platform" in collection.error


def test_target_outside_lockfile_has_explicit_reason(source):
    target = TargetEnvironment.parse(
        "windows:sys_platform=win32,platform_system=Windows,python_version=3.12"
    )
    collection = source.collect_for_target(target)

    assert collection.dependencies == ()
    assert collection.error is not None
    assert "is not covered by any lockfile" in collection.error


def test_evidence_is_independent_of_target_order(source, service):
    forward = audit_targets(
        source,
        service,
        [TargetEnvironment.parse(LINUX), TargetEnvironment.parse(MACOS)],
    )
    backward = audit_targets(
        source,
        service,
        [TargetEnvironment.parse(MACOS), TargetEnvironment.parse(LINUX)],
    )

    by_name_forward = {item.target.name: item.to_dict() for item in forward}
    by_name_backward = {item.target.name: item.to_dict() for item in backward}
    assert by_name_forward == by_name_backward

    # And the same evidence run twice in the same order is byte-stable.
    again = audit_targets(
        source,
        service,
        [TargetEnvironment.parse(LINUX), TargetEnvironment.parse(MACOS)],
    )
    assert [item.to_dict() for item in forward] == [item.to_dict() for item in again]


def test_queries_do_not_leak_across_targets(source):
    linux_service = FakeAdvisoryService({})
    audit_targets(source, linux_service, [TargetEnvironment.parse(LINUX)])
    linux_names = {name for name, _ in linux_service.queries}
    assert "uvloop" in linux_names
    assert "pyobjc-core" not in linux_names

    macos_service = FakeAdvisoryService({})
    audit_targets(source, macos_service, [TargetEnvironment.parse(MACOS)])
    macos_names = {name for name, _ in macos_service.queries}
    assert "pyobjc-core" in macos_names
    assert "uvloop" not in macos_names

    # Shared packages are queried once per target run, never deduped across targets
    # in a way that would let one target's result stand in for another's.
    assert ("attrs", "25.1.0") in linux_service.queries
    assert ("attrs", "25.1.0") in macos_service.queries


def test_vulnerable_package_fails_its_target_gate(tmp_path, source):
    # A minimal lockfile without undetermined markers, so the gate is decided
    # purely by vulnerabilities.
    simple = tmp_path / "pylock.simple.toml"
    simple.write_text(
        "lock-version = '1.0'\n"
        "environments = [\"sys_platform == 'linux'\"]\n"
        "[[packages]]\nname = 'jinja2'\nversion = '3.1.4'\n"
    )
    simple_source = PyLockSource([simple])
    target = TargetEnvironment.parse(LINUX)

    clean_evidence = audit_targets(simple_source, FakeAdvisoryService({}), [target])[0]
    assert clean_evidence.vulnerable_packages == []
    assert clean_evidence.is_gate_passed()

    vulnerable = FakeAdvisoryService(
        {("jinja2", "3.1.4"): [_advisory("CVE-2024-9999", "3.1.5")]}
    )
    vuln_evidence = audit_targets(simple_source, vulnerable, [target])[0]
    assert not vuln_evidence.is_gate_passed()
    assert vuln_evidence.vulnerable_packages == ["jinja2"]
    assert vuln_evidence.to_dict()["vulnerabilities"][0]["vulns"][0]["id"] == "CVE-2024-9999"


def test_undetermined_package_fails_gate(source, service):
    evidence = audit_targets(source, service, [TargetEnvironment.parse(LINUX)])[0]
    assert evidence.undetermined
    assert not evidence.is_gate_passed()


def test_target_not_covered_fails_gate_with_reason(source, service):
    target = TargetEnvironment.parse("windows:sys_platform=win32,python_version=3.12")
    evidence = audit_targets(source, service, [target])[0]

    assert evidence.error is not None
    assert not evidence.is_gate_passed()
    payload = evidence.to_dict()
    assert payload["error"] == evidence.error
    assert payload["dependencies"] == []
    assert payload["fingerprint"]


def test_evidence_payload_is_json_roundtrippable(source, service):
    evidence = audit_targets(
        source, service, [TargetEnvironment.parse(LINUX), TargetEnvironment.parse(MACOS)]
    )

    for item in evidence:
        encoded = json.dumps(item.to_dict(), sort_keys=True)
        decoded = json.loads(encoded)
        assert decoded["target"]["name"] == item.target.name
        assert decoded["gate_passed"] == item.is_gate_passed()
        assert decoded["excluded"]


def test_multiple_lockfiles_merge_by_target(tmp_path):
    common = tmp_path / "pylock.common.toml"
    common.write_text(
        "lock-version = '1.0'\n"
        "environments = [\"sys_platform == 'linux'\", \"sys_platform == 'darwin'\"]\n"
        "[[packages]]\nname = 'attrs'\nversion = '25.1.0'\n"
    )
    macos_only = tmp_path / "pylock.macos.toml"
    macos_only.write_text(
        "lock-version = '1.0'\n"
        "environments = [\"sys_platform == 'darwin'\"]\n"
        "[[packages]]\nname = 'pyobjc-core'\nversion = '10.3.2'\n"
    )

    source = PyLockSource([common, macos_only])
    linux = source.collect_for_target(TargetEnvironment.parse(LINUX))
    macos = source.collect_for_target(TargetEnvironment.parse(MACOS))

    assert {dep.canonical_name for dep in linux.dependencies} == {"attrs"}
    assert {dep.canonical_name for dep in macos.dependencies} == {"attrs", "pyobjc-core"}
    assert linux.error is None
    assert macos.error is None


def test_conflicting_versions_across_lockfiles_are_reported(tmp_path):
    first = tmp_path / "pylock.a.toml"
    first.write_text(
        "lock-version = '1.0'\n[[packages]]\nname = 'attrs'\nversion = '24.0.0'\n"
    )
    second = tmp_path / "pylock.b.toml"
    second.write_text(
        "lock-version = '1.0'\n[[packages]]\nname = 'attrs'\nversion = '25.1.0'\n"
    )

    collection = PyLockSource([first, second]).collect_for_target(
        TargetEnvironment.parse(LINUX)
    )

    assert collection.error is not None
    assert "conflicting versions selected for 'attrs'" in collection.error


def test_ambiguous_package_for_one_target_is_error(tmp_path):
    lock = tmp_path / "pylock.ambiguous.toml"
    lock.write_text(
        "lock-version = '1.0'\n"
        "[[packages]]\nname = 'attrs'\nversion = '24.0.0'\n"
        "[[packages]]\nname = 'attrs'\nversion = '25.1.0'\n"
    )

    collection = PyLockSource([lock]).collect_for_target(TargetEnvironment.parse(LINUX))

    assert collection.error is not None
    assert "multiple entries for 'attrs'" in collection.error


def test_undefined_operand_short_circuits_known_false():
    from packaging.markers import Marker

    from pip_audit._target import evaluate_marker

    target = TargetEnvironment.parse("t:sys_platform=win32,python_version=3.12")

    # `and` with an already-false known operand is false, even though
    # `platform_machine` is unspecified.
    assert (
        evaluate_marker(
            Marker("python_version == '3.9' and platform_machine == 'x86_64'"), target
        )
        is False
    )
    # `or` with an already-true known operand is true.
    assert (
        evaluate_marker(
            Marker("sys_platform == 'win32' or platform_machine == 'x86_64'"), target
        )
        is True
    )
    # Otherwise the result genuinely depends on the unknown value.
    with pytest.raises(Exception, match="platform_machine"):
        evaluate_marker(
            Marker("sys_platform == 'linux' or platform_machine == 'x86_64'"), target
        )


def test_evidence_targets_have_distinct_fingerprints_even_when_clean(tmp_path):
    lock = tmp_path / "pylock.shared.toml"
    lock.write_text(
        "lock-version = '1.0'\n"
        "environments = [\"sys_platform == 'linux'\", \"sys_platform == 'darwin'\"]\n"
        "[[packages]]\nname = 'attrs'\nversion = '25.1.0'\n"
    )
    source = PyLockSource([lock])
    evidence = audit_targets(
        source,
        FakeAdvisoryService({}),
        [TargetEnvironment.parse(LINUX), TargetEnvironment.parse(MACOS)],
    )

    assert all(item.is_gate_passed() for item in evidence)
    assert evidence[0].fingerprint() != evidence[1].fingerprint()


def test_lockfile_requires_python_without_target_version_is_undetermined(tmp_path):
    lock = tmp_path / "pylock.pyreq.toml"
    lock.write_text(
        "lock-version = '1.0'\n"
        "requires-python = '>=3.10'\n"
        "[[packages]]\nname = 'attrs'\nversion = '25.1.0'\n"
    )
    collection = PyLockSource([lock]).collect_for_target(
        TargetEnvironment.parse("noderedhat:sys_platform=linux")
    )

    assert collection.error is not None
    assert "cannot determine whether target 'noderedhat' is covered" in collection.error
    assert "python_full_version" in collection.error
