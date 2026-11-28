from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

from tox.tox_env.errors import Fail
from tox.tox_env.python.patch_gate import (
    Approval,
    Fix,
    Resolution,
    Stage,
    Verdict,
    approvals_from_config,
    evaluate,
    evaluate_with_resolver,
    fixes_from_config,
    resolutions_from_requirements,
)
from tox.tox_env.python.pylock import Pylock


def _fix(dependency: str = "urllib3", version: str = ">=2.2.2", *, stages: tuple[Stage, ...] = ()) -> Fix:
    return Fix(
        fix_id=f"CVE-{dependency}",
        dependency=canonicalize_name(dependency),
        specifier=SpecifierSet(version),
        stages=frozenset(stages),
    )


def _resolution(name: str = "urllib3", version: str = "2.2.2", source: str = "index") -> Resolution:
    return Resolution(name=canonicalize_name(name), version=version, source=source)


def test_fix_config_parsing() -> None:
    raw = {
        "fixes": [
            {"id": "CVE-1", "dependency": "urllib3", "version": ">=2.2.2"},
            {
                "id": "CVE-2",
                "dependency": "setuptools",
                "version": "<70",
                "stages": ["package_build"],
                "source": "pypi",
            },
        ],
        "approvals": [{"dependency": "virtualenv", "version": "<21", "project": "legacy", "reason": "approved"}],
    }

    fixes = fixes_from_config(raw)
    approvals = approvals_from_config(raw)

    assert [(fix.fix_id, fix.dependency, str(fix.specifier)) for fix in fixes] == [
        ("CVE-1", "urllib3", ">=2.2.2"),
        ("CVE-2", "setuptools", "<70"),
    ]
    assert fixes[1].stages == frozenset({Stage.PACKAGE_BUILD})
    assert approvals[0].project == "legacy"


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param("%s", id="not-a-table"),
        pytest.param("fixes = 'nope'", id="fixes-not-a-table"),
        pytest.param("fixes = 1", id="fixes-not-a-list"),
        pytest.param("fixes = [{ id = 'x', dependency = 'urllib3' }]", id="no-version"),
        pytest.param("fixes = [{ id = 'x', dependency = 'urllib3', version = 'nope' }]", id="bad-version"),
        pytest.param(
            "fixes = [{ id = 'x', dependency = 'urllib3', version = '>=1', stages = ['nope'] }]", id="bad-stage"
        ),
    ],
)
def test_invalid_fix_config_reports(raw: str) -> None:
    payload = tomllib.loads(raw) if "=" in raw else raw
    with pytest.raises(Fail):
        fixes_from_config(payload)


def test_ledger_separates_same_name_across_stages() -> None:
    fix = _fix()
    stages = {
        Stage.BOOTSTRAP: [_resolution(version="2.2.1")],
        Stage.PACKAGE_BUILD: [_resolution(version="2.2.2")],
        Stage.TARGET: [_resolution(version="2.2.2")],
    }

    ledger = evaluate([fix], stages)

    assert ledger.unfixed_stages() == (Stage.BOOTSTRAP,)
    assert [fix.fix.fix_id for fix in ledger.unfixed_at(Stage.BOOTSTRAP)] == ["CVE-urllib3"]
    assert [entry.stage for entry in ledger.unfixed_at(Stage.BOOTSTRAP)[0].stages] == [
        Stage.BOOTSTRAP,
        Stage.PACKAGE_BUILD,
        Stage.TARGET,
    ]
    assert {entry.stage: entry.verdict for entry in ledger.fixes[0].stages} == {
        Stage.BOOTSTRAP: Verdict.UNSATISFIED,
        Stage.PACKAGE_BUILD: Verdict.SATISFIED,
        Stage.TARGET: Verdict.SATISFIED,
    }
    assert "bootstrap" in ledger.summary()


def test_same_name_from_two_sources_is_not_one_installation() -> None:
    fix = _fix()
    target = [
        Resolution(name=canonicalize_name("urllib3"), version="2.2.2", source="pylock"),
        Resolution(name=canonicalize_name("urllib3"), version="2.2.2", source="index"),
    ]

    ledger = evaluate([fix], {Stage.TARGET: target}, inspected=[Stage.TARGET])

    evidence = ledger.fixes[0].stages[0]
    assert evidence.verdict is Verdict.SATISFIED
    assert ledger.as_dict()["fixes"][0]["stages"][0]["source"] == "pylock"


def test_stage_scoped_fix_ignores_other_stages() -> None:
    fix = _fix(stages=(Stage.TARGET,))
    stages = {Stage.BOOTSTRAP: [_resolution(version="1.0")], Stage.TARGET: [_resolution(version="2.2.2")]}

    ledger = evaluate([fix], stages)

    assert ledger.satisfied
    assert [entry.stage for entry in ledger.fixes[0].stages] == [Stage.TARGET]


def test_source_mismatch_is_unsatisfied() -> None:
    fix = Fix(
        fix_id="CVE-1",
        dependency=canonicalize_name("urllib3"),
        specifier=SpecifierSet(">=2"),
        source="index",
    )
    stages = {Stage.TARGET: [Resolution(name=canonicalize_name("urllib3"), version="2.2.2", source="pylock")]}

    ledger = evaluate([fix], stages, inspected=[Stage.TARGET])

    assert not ledger.satisfied
    assert ledger.fixes[0].stages[0].verdict is Verdict.UNSATISFIED


def test_unresolved_version_does_not_count_as_fixed() -> None:
    fix = _fix()
    stages = {Stage.TARGET: [Resolution(name=canonicalize_name("urllib3"), version=None, source="directory")]}

    ledger = evaluate([fix], stages, inspected=[Stage.TARGET])

    assert ledger.fixes[0].stages[0].verdict is Verdict.UNRESOLVED
    assert not ledger.satisfied


def test_approval_covers_a_stage_below_the_fix() -> None:
    fix = _fix()
    approvals = [
        Approval(
            dependency=canonicalize_name("urllib3"),
            specifier=SpecifierSet("<2.2.2"),
            stages=frozenset({Stage.TARGET}),
            project="legacy",
            reason="approved until month end",
        )
    ]
    stages = {Stage.BOOTSTRAP: [_resolution(version="2.2.2")], Stage.TARGET: [_resolution(version="2.2.1")]}

    ledger = evaluate([fix], stages, approvals=approvals, project="legacy", inspected=[Stage.BOOTSTRAP, Stage.TARGET])

    assert ledger.satisfied
    assert ledger.fixes[0].stages[1].verdict is Verdict.APPROVED


def test_approval_scoped_to_another_project_does_not_apply() -> None:
    fix = _fix()
    approvals = [Approval(dependency=canonicalize_name("urllib3"), specifier=SpecifierSet("<2.2.2"), project="other")]
    stages = {Stage.TARGET: [_resolution(version="2.2.1")]}

    ledger = evaluate([fix], stages, approvals=approvals, project="legacy", inspected=[Stage.BOOTSTRAP, Stage.TARGET])

    assert not ledger.satisfied


def test_resolver_swaps_only_the_selected_stage() -> None:
    fix = _fix()
    versions = {Stage.BOOTSTRAP: "2.2.1", Stage.TARGET: "2.2.2"}

    def resolver(stage: Stage, dependency: str) -> Resolution | None:
        return Resolution(name=canonicalize_name(dependency), version=versions[stage], source="fake")

    ledger = evaluate_with_resolver([fix], resolver, inspected=[Stage.BOOTSTRAP, Stage.TARGET])

    assert ledger.unfixed_stages() == (Stage.BOOTSTRAP,)


def test_resolver_returns_none_when_stage_does_not_install() -> None:
    fix = _fix()

    ledger = evaluate_with_resolver([fix], lambda stage, dependency: None)

    assert ledger.satisfied
    assert {entry.verdict for entry in ledger.fixes[0].stages} == {Verdict.NOT_INSTALLED}


def test_ledger_serializes_stage_attribution() -> None:
    fix = _fix()
    ledger = evaluate(
        [fix],
        {
            Stage.BOOTSTRAP: [_resolution(version="1.0")],
            Stage.PACKAGE_BUILD: [_resolution(version="2.2.2")],
            Stage.TARGET: [_resolution(version="1.9")],
        },
    )

    payload = ledger.as_dict()

    assert payload["unfixed_stages"] == ["bootstrap", "target"]
    fix_payload = payload["fixes"][0]
    assert fix_payload["unfixed_stages"] == ["bootstrap", "target"]
    assert [stage["stage"] for stage in fix_payload["stages"]] == ["bootstrap", "package_build", "target"]


def test_pylock_exposes_version_and_source(tmp_path: Path) -> None:
    lock = tmp_path / "pylock.toml"
    lock.write_text(
        """\
        lock-version = "1.0"
        requires-python = ">=3.11"
        created-by = "test"

        [[packages]]
        name = "urllib3"
        version = "2.2.2"

        [packages.sdist]
        name = "urllib3-2.2.2.tar.gz"
        url = "https://files.pythonhosted.org/urllib3-2.2.2.tar.gz"
        hashes = { sha256 = "aaaa" }

        [[packages]]
        name = "localpkg"
        version = "0.1"

        [packages.directory]
        path = "."
        editable = true
        """,
        encoding="utf-8",
    )
    pylock = Pylock(path=lock)

    resolutions = {entry.name: entry for entry in pylock.resolutions()}

    assert resolutions["urllib3"].version == "2.2.2"
    assert resolutions["urllib3"].source == "pylock"
    assert resolutions["urllib3"].pinned
    assert resolutions["localpkg"].version is None
    assert resolutions["localpkg"].source == "directory"
    assert resolutions["localpkg"].pinned


def test_resolutions_from_requirements_keep_sources() -> None:
    resolutions = resolutions_from_requirements(["urllib3>=2", "pytest"], "bootstrap", pinned=True)

    assert [entry.name for entry in resolutions] == ["urllib3", "pytest"]
    assert {entry.source for entry in resolutions} == {"bootstrap"}
    assert all(entry.pinned for entry in resolutions)


def _run_tox(project, *args: str) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    source = str(Path(__file__).parents[1] / "src")
    environment["PYTHONPATH"] = os.pathsep.join(filter(None, (source, environment.get("PYTHONPATH"))))
    return subprocess.run(
        [sys.executable, "-m", "tox", *args],
        cwd=project,
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )


def _write_project(root: Path, config: str) -> Path:
    (root / "tox.toml").write_text(config, encoding="utf-8")
    (root / "pyproject.toml").write_text('[project]\nname = "demo"\nversion = "0.1"\n', encoding="utf-8")
    return root


def test_collect_uses_configured_resolutions(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        """\
        [env_run_base]
        package = "skip"
        deps = ["urllib3"]

        [patch-check]
        fixes = [{ id = "CVE-1", dependency = "urllib3", version = ">=2.2.2" }]
        resolutions = [
          { stage = "target", dependency = "urllib3", version = "2.2.1", source = "index" },
        ]
        """,
    )
    outcome = _run_tox(project, "patch-check")

    assert outcome.returncode == 1
    assert "patch gate failed" in outcome.stdout


def test_command_reports_stage_attribution(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        """\
        [env_run_base]
        package = "skip"
        deps = ["urllib3"]

        [patch-check]
        fixes = [{ id = "CVE-1", dependency = "urllib3", version = ">=2.2.2" }]
        resolutions = [
          { stage = "target", dependency = "urllib3", version = "1.9", source = "index" },
        ]
        """,
    )

    outcome = _run_tox(project, "patch-check")

    assert outcome.returncode == 1
    assert "patch gate failed" in outcome.stdout
    assert "target" in outcome.stdout


def test_command_waives_stage_the_project_does_not_have(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        """\
        [env_run_base]
        package = "skip"

        [patch-check]
        fixes = [{ id = "CVE-1", dependency = "setuptools", version = ">=70", stages = ["package_build"] }]
        """,
    )

    outcome = _run_tox(project, "patch-check")

    assert outcome.returncode == 0, outcome.stderr
    assert "patch gate satisfied" in outcome.stdout


def test_command_reports_missing_version_as_unfixed(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        """\
        [env_run_base]
        package = "skip"
        deps = ["urllib3"]

        [patch-check]
        fixes = [{ id = "CVE-1", dependency = "urllib3", version = ">=2.2.2" }]
        """,
    )

    outcome = _run_tox(project, "patch-check")

    assert outcome.returncode == 1
    assert "CVE-1" in outcome.stdout
    assert "target" in outcome.stdout


def test_command_reads_locked_target_version(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        """\
        [env_run_base]
        package = "skip"
        pylock = "pylock.toml"

        [patch-check]
        fixes = [{ id = "CVE-1", dependency = "urllib3", version = ">=2.2.2" }]
        """,
    )
    (project / "pylock.toml").write_text(
        """\
        lock-version = "1.0"
        requires-python = ">=3.11"
        created-by = "test"

        [[packages]]
        name = "urllib3"
        version = "2.2.1"

        [packages.sdist]
        name = "urllib3-2.2.1.tar.gz"
        url = "https://files.pythonhosted.org/urllib3-2.2.1.tar.gz"
        hashes = { sha256 = "aaaa" }
        """,
        encoding="utf-8",
    )
    ledger = tmp_path / "ledger.json"

    outcome = _run_tox(project, "patch-check", "-o", str(ledger))

    assert outcome.returncode == 1, outcome.stderr
    payload = ledger.read_text()
    assert '"version": "2.2.1"' in payload
    assert '"source": "pylock"' in payload


def test_command_writes_journal_with_stage_attribution(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        """\
        [env_run_base]
        package = "skip"
        deps = ["urllib3"]

        [patch-check]
        fixes = [{ id = "CVE-1", dependency = "urllib3", version = ">=2.2.2" }]
        resolutions = [{ stage = "target", dependency = "urllib3", version = "1.9", source = "index" }]
        """,
    )
    journal = tmp_path / "journal.json"

    outcome = _run_tox(project, "patch-check", "-e", "py", "--result-json", str(journal))

    assert outcome.returncode == 1, outcome.stderr
    payload = json.loads(journal.read_text())
    ledger = payload["testenvs"]["py"]["patch_check"]
    assert ledger["unfixed_stages"] == ["target"]
    assert ledger["fixes"][0]["unfixed_stages"] == ["target"]


def test_command_writes_ledger_json(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        """\
        [env_run_base]
        package = "skip"
        deps = ["urllib3"]

        [patch-check]
        fixes = [{ id = "CVE-1", dependency = "urllib3", version = ">=2.2.2" }]
        resolutions = [
          { stage = "target", dependency = "urllib3", version = "2.2.2", source = "index" },
        ]
        """,
    )
    ledger = tmp_path / "ledger.json"

    outcome = _run_tox(project, "patch-check", "-o", str(ledger))

    assert outcome.returncode == 0
    payload = ledger.read_text()
    assert '"satisfied": true' in payload
    assert '"target"' in payload


def test_applicable_stages_follow_config(tmp_path: Path) -> None:
    project = _write_project(
        tmp_path,
        """\
        [env_run_base]
        package = "skip"
        """,
    )
    outcome = _run_tox(project, "patch-check")

    assert outcome.returncode == 0, outcome.stderr
    assert "patch gate satisfied" in outcome.stdout
