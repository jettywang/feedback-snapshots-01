from __future__ import annotations

import json
from pathlib import Path

import pytest
from packaging.version import Version

from pip_audit import _fix_plan
from pip_audit._dependency_source import requirement
from pip_audit._fix import ResolvedFixVersion
from pip_audit._fix_plan import (
    FixPlanInvalid,
    FixPlanStale,
    apply_fix_plan,
    create_fix_plan,
    load_fix_plan,
    write_fix_plan,
)
from pip_audit._service import ResolvedDependency, VulnerabilityResult


def _write(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _fix(name: str, old: str, new: str) -> ResolvedFixVersion:
    return ResolvedFixVersion(
        dep=ResolvedDependency(name=name, version=Version(old)),
        version=Version(new),
    )


def _vuln(vuln_id: str, *fix_versions: str) -> list[VulnerabilityResult]:
    return [
        VulnerabilityResult(
            id=vuln_id,
            description="test advisory",
            fix_versions=[Version(v) for v in fix_versions],
            aliases={"CVE-0000-0000"},
        )
    ]


def _plan_for(
    req_paths: list[Path],
    fixes: list[ResolvedFixVersion],
    result: dict,
    root: Path,
):
    source = requirement.RequirementSource(req_paths)
    return create_fix_plan(
        source,
        result,
        fixes,
        [],
        tool_version="test",
        root=root,
    )


def _roundtrip(plan) -> _fix_plan.FixPlan:
    return _fix_plan.FixPlan.from_json(plan.to_json())


def test_valid_plan_records_targets_evidence_and_diff(tmp_path):
    req_path = tmp_path / "requirements.txt"
    _write(req_path, "flask==0.5\nrequests==2.0\n")

    fix = _fix("flask", "0.5", "1.0")
    result = {fix.dep: _vuln("PYSEC-2019-179", "1.0")}
    plan = _plan_for([req_path], [fix], result, tmp_path)

    # Generating a plan must not touch the workspace.
    assert _read(req_path) == "flask==0.5\nrequests==2.0\n"

    document = json.loads(plan.to_json())
    assert document["plan_version"] == 1
    assert document["root"] == str(tmp_path)
    change = document["changes"][0]
    assert change["dependency"] == {"name": "flask", "version": "0.5"}
    assert change["fix_version"] == "1.0"
    assert change["evidence"][0]["id"] == "PYSEC-2019-179"
    assert change["evidence"][0]["fix_versions"] == ["1.0"]

    edit = change["edits"][0]
    assert edit["path"] == str(req_path)
    assert edit["before_sha256"] != edit["after_sha256"]
    assert "-flask==0.5" in edit["diff"]
    assert "+flask==1.0" in edit["diff"]

    # The serialized plan can be loaded back with everything needed to apply it.
    reloaded = _roundtrip(plan)
    apply_fix_plan(reloaded)
    assert _read(req_path) == "flask==1.0\nrequests==2.0\n"


def test_plan_apply_is_all_or_nothing_across_files(tmp_path):
    first = tmp_path / "requirements.txt"
    second = tmp_path / "constraints.txt"
    _write(first, "flask==0.5\n")
    _write(second, "requests==2.0\nflask==0.5\n")

    fix = _fix("flask", "0.5", "1.0")
    plan = _plan_for([first, second], [fix], {fix.dep: _vuln("PYSEC-1", "1.0")}, tmp_path)

    apply_fix_plan(_roundtrip(plan))

    assert _read(first) == "flask==1.0\n"
    assert _read(second) == "requests==2.0\nflask==1.0\n"


def test_second_apply_is_rejected_as_already_applied(tmp_path):
    req_path = tmp_path / "requirements.txt"
    _write(req_path, "flask==0.5\n")

    fix = _fix("flask", "0.5", "1.0")
    plan = _roundtrip(_plan_for([req_path], [fix], {fix.dep: _vuln("PYSEC-1", "1.0")}, tmp_path))

    apply_fix_plan(plan)
    with pytest.raises(FixPlanStale, match="already applied"):
        apply_fix_plan(plan)

    # The failed re-apply leaves the fixed file untouched.
    assert _read(req_path) == "flask==1.0\n"


def test_modified_target_is_rejected_before_any_write(tmp_path):
    first = tmp_path / "requirements.txt"
    second = tmp_path / "constraints.txt"
    _write(first, "flask==0.5\n")
    _write(second, "flask==0.5\n")

    fix = _fix("flask", "0.5", "1.0")
    plan = _roundtrip(
        _plan_for([first, second], [fix], {fix.dep: _vuln("PYSEC-1", "1.0")}, tmp_path)
    )

    # A human edited the second file after the plan was approved.
    _write(second, "flask==0.5\nboto3==1.34.0\n")

    with pytest.raises(FixPlanStale, match="changed since the plan was created"):
        apply_fix_plan(plan)

    # Neither file is touched: the first target would have been written had
    # verification not run before any write.
    assert _read(first) == "flask==0.5\n"
    assert _read(second) == "flask==0.5\nboto3==1.34.0\n"


def test_missing_target_is_rejected(tmp_path):
    req_path = tmp_path / "requirements.txt"
    _write(req_path, "flask==0.5\n")

    fix = _fix("flask", "0.5", "1.0")
    plan = _roundtrip(_plan_for([req_path], [fix], {fix.dep: _vuln("PYSEC-1", "1.0")}, tmp_path))
    req_path.unlink()

    with pytest.raises(FixPlanStale, match="no longer exists"):
        apply_fix_plan(plan)


def test_mid_apply_write_failure_restores_both_files(tmp_path, monkeypatch):
    first = tmp_path / "requirements.txt"
    second = tmp_path / "constraints.txt"
    before_first = "flask==0.5\n"
    before_second = "flask==0.5\nrequests==2.0\n"
    _write(first, before_first)
    _write(second, before_second)

    fix = _fix("flask", "0.5", "1.0")
    plan = _roundtrip(
        _plan_for([first, second], [fix], {fix.dep: _vuln("PYSEC-1", "1.0")}, tmp_path)
    )

    real_replace = _fix_plan.os.replace
    calls = []

    def flaky_replace(src, dst):
        # The first swap succeeds; the second fails, after the first file has
        # already been written.
        calls.append(dst)
        if len(calls) == 2:
            raise OSError("disk full")
        return real_replace(src, dst)

    monkeypatch.setattr(_fix_plan.os, "replace", flaky_replace)

    with pytest.raises(OSError, match="disk full"):
        apply_fix_plan(plan)

    assert len(calls) >= 2
    assert _read(first) == before_first
    assert _read(second) == before_second

    # Recovery must not leave staged files behind.
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.endswith(".pip-audit")]
    assert leftovers == []


def test_failed_recovery_reports_original_error(tmp_path, monkeypatch):
    req_path = tmp_path / "requirements.txt"
    before = "flask==0.5\n"
    _write(req_path, before)

    fix = _fix("flask", "0.5", "1.0")
    plan = _roundtrip(_plan_for([req_path], [fix], {fix.dep: _vuln("PYSEC-1", "1.0")}, tmp_path))

    # Fail the swap itself; the restore path then runs but also cannot write.
    def always_fail(src, dst):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(_fix_plan.os, "replace", always_fail)

    with pytest.raises(OSError, match="read-only filesystem"):
        apply_fix_plan(plan)

    # The target was never swapped, so its pre-application contents survive.
    assert _read(req_path) == before


def test_plan_json_roundtrip_is_stable(tmp_path):
    req_path = tmp_path / "requirements.txt"
    _write(req_path, "flask==0.5\n")

    fix = _fix("flask", "0.5", "1.0")
    plan = _plan_for([req_path], [fix], {fix.dep: _vuln("PYSEC-1", "1.0")}, tmp_path)

    first = plan.to_json()
    assert _roundtrip(plan).to_json() == first


def test_invalid_plan_versions_are_rejected():
    with pytest.raises(FixPlanInvalid, match="unsupported fix plan version"):
        _fix_plan.FixPlan.from_json(json.dumps({"plan_version": 999, "changes": []}))

    with pytest.raises(FixPlanInvalid, match="not valid JSON"):
        _fix_plan.FixPlan.from_json("{")

    tampered = {
        "plan_version": 1,
        "changes": [
            {
                "dependency": {"name": "flask", "version": "0.5"},
                "fix_version": "1.0",
                "edits": [
                    {
                        "path": "requirements.txt",
                        "before_sha256": "0" * 64,
                        "after_sha256": "1" * 64,
                        "before": "Zmxhc2s9PTAuNQo=",
                        "after": "Zmxhc2s9PTEuMAo=",
                        "diff": "",
                    }
                ],
            }
        ],
    }
    with pytest.raises(FixPlanInvalid, match="does not match its recorded digest"):
        _fix_plan.FixPlan.from_json(json.dumps(tampered))


def test_write_and_load_plan(tmp_path):
    req_path = tmp_path / "requirements.txt"
    _write(req_path, "flask==0.5\n")
    fix = _fix("flask", "0.5", "1.0")
    plan = _plan_for([req_path], [fix], {fix.dep: _vuln("PYSEC-1", "1.0")}, tmp_path)

    plan_path = tmp_path / "fix-plan.json"
    write_fix_plan(plan, plan_path)
    loaded = load_fix_plan(plan_path)

    apply_fix_plan(loaded)
    assert _read(req_path) == "flask==1.0\n"


def test_plan_with_no_changes_is_a_noop(tmp_path):
    req_path = tmp_path / "requirements.txt"
    _write(req_path, "flask==1.0\n")
    plan = _plan_for([req_path], [], {}, tmp_path)
    assert plan.changes == ()
    apply_fix_plan(plan)
    assert _read(req_path) == "flask==1.0\n"


def _run_cli(monkeypatch, argv: list[str]) -> int:
    import pip_audit._cli as cli

    class FakeService:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def query(self, spec):
            return spec, []

    vuln = VulnerabilityResult(
        id="PYSEC-2019-179",
        description="an old flask",
        fix_versions=[Version("1.0")],
        aliases={"CVE-2019-0001"},
    )
    results = [
        (ResolvedDependency("flask", Version("0.5")), [vuln]),
        (ResolvedDependency("requests", Version("2.0")), []),
    ]

    monkeypatch.setattr(cli, "PyPIService", FakeService)
    monkeypatch.setattr(cli, "Auditor", lambda *a, **kw: pretend_auditor(results))
    monkeypatch.setattr(cli, "_parse_args", lambda *a: cli._parser().parse_args(argv))

    try:
        cli.audit()
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


def pretend_auditor(results):
    return type("Auditor", (), {"audit": lambda self, source: iter(results)})()


def test_cli_creates_plan_then_applies_it(tmp_path, monkeypatch):
    req_path = tmp_path / "requirements.txt"
    _write(req_path, "flask==0.5\nrequests==2.0\n")
    plan_path = tmp_path / "fix-plan.json"

    code = _run_cli(monkeypatch, ["-r", str(req_path), "--fix-plan", str(plan_path)])
    assert code == 0

    # Creating the plan must leave the requirements file untouched.
    assert _read(req_path) == "flask==0.5\nrequests==2.0\n"
    plan_document = json.loads(plan_path.read_text())
    assert plan_document["changes"][0]["evidence"][0]["id"] == "PYSEC-2019-179"

    code = _run_cli(monkeypatch, ["--apply-fix-plan", str(plan_path)])
    assert code == 0
    assert _read(req_path) == "flask==1.0\nrequests==2.0\n"

    # Applying the same approved plan again fails closed.
    code = _run_cli(monkeypatch, ["--apply-fix-plan", str(plan_path)])
    assert code == 1
    assert _read(req_path) == "flask==1.0\nrequests==2.0\n"


def test_cli_apply_rejects_stale_workspace(tmp_path, monkeypatch):
    req_path = tmp_path / "requirements.txt"
    _write(req_path, "flask==0.5\n")
    plan_path = tmp_path / "fix-plan.json"

    assert _run_cli(monkeypatch, ["-r", str(req_path), "--fix-plan", str(plan_path)]) == 0

    _write(req_path, "flask==0.5\nboto3==1.34.0\n")
    code = _run_cli(monkeypatch, ["--apply-fix-plan", str(plan_path)])
    assert code == 1
    assert _read(req_path) == "flask==0.5\nboto3==1.34.0\n"


def test_cli_rejects_plan_and_fix_together(tmp_path, monkeypatch):
    import pip_audit._cli as cli

    parser = cli._parser()
    args = parser.parse_args(
        ["-r", str(tmp_path / "requirements.txt"), "--fix", "--fix-plan", "p.json"]
    )
    monkeypatch.setattr(cli, "_parse_args", lambda *a: args)

    with pytest.raises(SystemExit):
        cli.audit()


def test_pyproject_plan_and_apply(tmp_path):
    import tomli

    from pip_audit._dependency_source import pyproject

    pyproject_path = tmp_path / "pyproject.toml"
    _write(
        pyproject_path,
        '[project]\nname = "demo"\ndependencies = ["flask==0.5", "requests==2.0"]\n',
    )

    fix = _fix("Flask", "0.5", "1.0")
    source = pyproject.PyProjectSource(pyproject_path)
    plan = create_fix_plan(
        source,
        {fix.dep: _vuln("PYSEC-1", "1.0")},
        [fix],
        [],
        tool_version="test",
        root=tmp_path,
    )

    assert _read(pyproject_path).count("flask==0.5") == 1

    apply_fix_plan(_roundtrip(plan))

    data = tomli.loads(_read(pyproject_path))
    assert data["project"]["dependencies"] == ["flask==1.0", "requests==2.0"]
