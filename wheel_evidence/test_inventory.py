from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from wheel_evidence import render
from wheel_evidence.cli import main
from wheel_evidence.core import (
    DIGEST_MISMATCH,
    MISSING_FROM_ARCHIVE,
    SOURCE_REQUIRED,
    UNVERIFIED,
    VERIFIED,
    analyze_wheel,
    lookup_command,
    normalize_command_name,
    urlsafe_nopad_digest,
)

DIST = "demo-1.0.dist-info"


def build_wheel(
    tmp_path: Path,
    filename: str = "demo-1.0-py3-none-any.whl",
    files: dict[str, bytes] | None = None,
    entry_points: str | None = None,
    bad_hash: set[str] | None = None,
    unlisted: set[str] | None = None,
    record_only_members: tuple[str, ...] = (),
    exec_modes: dict[str, int] | None = None,
) -> Path:
    members = dict(files or {})
    members.setdefault("demo/__init__.py", b"__version__ = '1.0'\n")
    members[f"{DIST}/METADATA"] = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n"
    members[f"{DIST}/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: test\n"
    if entry_points is not None:
        members[f"{DIST}/entry_points.txt"] = entry_points.encode()

    bad_hash = bad_hash or set()
    unlisted = unlisted or set()
    record_lines: list[str] = []
    for name, data in members.items():
        if name in unlisted:
            continue
        if name in bad_hash:
            digest = urlsafe_nopad_digest(b"some other bytes")
        else:
            digest = urlsafe_nopad_digest(data)
        record_lines.append(f"{name},sha256={digest},{len(data)}")
    for name in record_only_members:
        record_lines.append(f"{name},sha256={'A' * 43},1")
    record_lines.append(f"{DIST}/RECORD,,")
    record_data = ("\n".join(record_lines) + "\n").encode()

    wheel_path = tmp_path / filename
    with zipfile.ZipFile(wheel_path, "w") as zf:
        for name, data in members.items():
            info = zipfile.ZipInfo(name)
            if exec_modes and name in exec_modes:
                info.external_attr = exec_modes[name] << 16
            zf.writestr(info, data)
        zf.writestr(f"{DIST}/RECORD", record_data)
    return wheel_path


def test_normalize_command_name():
    assert normalize_command_name("My_Cool.Command") == "my-cool-command"
    assert normalize_command_name("a--b__c..d") == "a-b-c-d"


def test_verified_member_and_record_self_unverified(tmp_path):
    wheel = build_wheel(tmp_path)
    report = analyze_wheel(wheel)
    assert report["trust"]["code"] == "record_consistent"
    record = report["record"]
    assert record["verdict"] == UNVERIFIED
    assert record["reason_code"] == "record_self_hash_absent"
    assert report["record_audit"]["verified"] >= 3


def test_digest_mismatch_is_conflict_with_expected_and_actual(tmp_path):
    target = "demo/__init__.py"
    wheel = build_wheel(tmp_path, bad_hash={target})
    report = analyze_wheel(wheel)
    assert report["trust"]["code"] == "record_conflict"
    mismatch = report["record_audit"]["digest_mismatch"]
    assert len(mismatch) == 1
    ev = mismatch[0]
    assert ev["member"] == target
    assert ev["verdict"] == DIGEST_MISMATCH
    assert ev["digest_record"] != ev["digest_actual"]
    assert ev["record_line"] == 1


def test_unlisted_member_has_no_usable_evidence(tmp_path):
    ghost = "demo/ghost.py"
    wheel = build_wheel(tmp_path, files={ghost: b"# unlisted\n"}, unlisted={ghost})
    report = analyze_wheel(wheel)
    item = next(i for i in report["record_audit"]["unverified"] if i["member"] == ghost)
    assert item["reason_code"] == "not_listed_in_record"
    assert ghost in report["record_audit"]["unlisted_members"]


def test_recorded_but_missing_member_is_conflict(tmp_path):
    wheel = build_wheel(tmp_path, record_only_members=("demo/gone.py",))
    report = analyze_wheel(wheel)
    missing = report["record_audit"]["missing_from_archive"]
    assert [m["member"] for m in missing] == ["demo/gone.py"]
    assert missing[0]["verdict"] == MISSING_FROM_ARCHIVE


def test_unlisted_script_command_is_present_but_unverified(tmp_path):
    ghost = "demo-1.0.data/scripts/ghost-cmd"
    wheel = build_wheel(
        tmp_path,
        files={ghost: b"#!/bin/sh\n"},
        unlisted={ghost},
        exec_modes={ghost: 0o755},
    )
    report = analyze_wheel(wheel)
    result = lookup_command(report, "ghost-cmd")
    assert result["found"] is True
    assert result["overall_confidence"] == "indeterminate"
    claim = result["claims"][0]
    assert claim["kind"] == "archived_script"
    assert claim["verdict"] == UNVERIFIED
    assert claim["record_line"] is None
    assert claim["evidence_refs"][-1] == "RECORD:no-row-for-member"


EP = """[console_scripts]
probe = demo.cli:main

[demo.plugins]
probe = demo.plugin:make

"""


def test_same_name_three_kinds_coexist_and_source_required(tmp_path):
    script_member = "demo-1.0.data/scripts/probe"
    wheel = build_wheel(
        tmp_path,
        files={
            "demo/cli.py": b"def main():\n    return 0\n",
            "demo/plugin.py": b"def make():\n    return object()\n",
            script_member: b"#!/usr/bin/env python3\nprint('hi')\n",
        },
        entry_points=EP,
        exec_modes={script_member: 0o755},
    )
    report = analyze_wheel(wheel)
    normalized = lookup_command(report, "PROBE")
    assert normalized["normalized_query"] == "probe"
    assert normalized["found"] is True
    result = lookup_command(report, "probe")
    assert result["found"] is True
    assert result["same_name_coexists"] is True
    assert set(result["coexisting_kinds"]) == {
        "console_entry",
        "plugin_entry",
        "archived_script",
    }
    by_kind = {c["kind"]: c for c in result["claims"]}

    console = by_kind["console_entry"]
    assert console["declaration_verdict"] == VERIFIED
    assert console["target_module_member"] == "demo/cli.py"
    assert console["target_module_verdict"] == VERIFIED
    assert console["callable_verdict"] == SOURCE_REQUIRED
    assert any("entry_points.txt:L2" in ref for ref in console["evidence_refs"])
    assert any(ref.startswith("RECORD:L") for ref in console["evidence_refs"])

    plugin = by_kind["plugin_entry"]
    assert plugin["section"] == "demo.plugins"
    assert plugin["declaration_verdict"] == VERIFIED

    script = by_kind["archived_script"]
    assert script["member"] == script_member
    assert script["verdict"] == VERIFIED
    assert script["executable_bit"] is True
    assert script["executable_mode"] == "0755"


def test_script_stem_normalization_matches_py_suffix(tmp_path):
    member = "demo-1.0.data/scripts/probe.py"
    wheel = build_wheel(tmp_path, files={member: b"#!/bin/sh\n"}, entry_points=None)
    report = analyze_wheel(wheel)
    result = lookup_command(report, "probe")
    assert result["found"] is True
    claim = result["claims"][0]
    assert claim["match_basis"] == "normalized-stem"


def test_reports_never_contain_machine_absolute_paths(tmp_path, capsys):
    wheel = build_wheel(tmp_path)
    report = analyze_wheel(wheel)
    blob = json.dumps(report, ensure_ascii=False)
    assert str(tmp_path) not in blob
    assert "/Users/" not in blob
    for text in (
        render.render_inventory(report),
        render.render_verify(report),
        render.render_scripts(report),
        render.render_entry_points(report),
    ):
        assert str(tmp_path) not in text
        assert "/Users/" not in text

    rc = main(["inventory", str(wheel)])
    assert rc == 0
    out = capsys.readouterr().out
    assert str(tmp_path) not in out

    rc = main(["inventory", str(tmp_path / "missing.whl"), "--json"])
    assert rc == 2
    captured = capsys.readouterr()
    assert str(tmp_path) not in captured.out
    assert str(tmp_path) not in captured.err


def test_cli_section_filter(tmp_path, capsys):
    wheel = build_wheel(tmp_path, entry_points=EP)
    rc = main(["entry-points", str(wheel), "--section", "console_scripts"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "[console_scripts]" in out
    assert "demo.plugins" not in out


def test_command_not_found(tmp_path):
    wheel = build_wheel(tmp_path)
    report = analyze_wheel(wheel)
    result = lookup_command(report, "does-not-exist")
    assert result["found"] is False
    assert result["overall_confidence"] == "no_evidence"
