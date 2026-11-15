"""Behavioural tests for the BAM/DAM attribution tool and its fixture."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from dissect.regf import regf

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent
FIXTURE = PACKAGE / "fixtures" / "SYSTEM_fixture"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


builder = _load_module("build_fixture_hive", PACKAGE / "fixtures" / "build_fixture_hive.py")
investigate = _load_module("bam_dam_investigate", PACKAGE / "bam_dam_investigate.py")


@pytest.fixture(scope="module")
def report():
    with FIXTURE.open("rb") as handle:
        context = investigate.open_hive(handle, str(FIXTURE))
        evidence = investigate.investigate(context, 1970, 2100)
        return investigate.build_report(context, evidence, 1970, 2100)


def test_fixture_is_a_valid_regf_hive():
    with FIXTURE.open("rb") as handle:
        hive = regf.RegistryHive(handle)
        names = {node.name for node in hive.root().subkeys()}
    assert {"ControlSet001", "ControlSet002", "Select"} <= names


def test_fixture_can_be_reproduced_from_source(tmp_path):
    target = tmp_path / "SYSTEM_fixture"
    target.write_bytes(builder.HiveWriter().build(builder.build_tree()))
    assert target.read_bytes() == FIXTURE.read_bytes()


def test_select_marks_current_control_set(report):
    assert report["input"]["current_control_set"] == "ControlSet001"
    current = [e for e in report["evidence"] if e["identity"]["control_set_is_current"]]
    assert current and all(e["identity"]["control_set"] == "ControlSet001" for e in current)


def test_all_nine_records_are_present_across_services_and_control_sets(report):
    assert report["counts"]["evidence_records"] == 9
    identities = {tuple(e["identity"][k] for k in ("control_set", "service")) for e in report["evidence"]}
    assert ("ControlSet001", "bam") in identities
    assert ("ControlSet001", "dam") in identities
    assert ("ControlSet002", "bam") in identities
    assert ("ControlSet002", "dam") not in identities


def test_shared_program_path_keeps_two_independent_sid_records(report):
    shared = r"\Device\HarddiskVolume3\Program Files\SharedApp\app.exe"
    matches = [
        e
        for e in report["evidence"]
        if e["identity"]["control_set"] == "ControlSet001"
        and e["identity"]["service"] == "bam"
        and e["identity"]["program_path"] == shared
    ]
    sids = {e["identity"]["sid_key"] for e in matches}
    assert len(matches) == 2
    assert len(sids) == 2
    assert report["shared_program_path_groups"][0]["distinct_sid_count"] == 2


def test_evidence_chain_runs_from_key_path_to_binary_filetime(report):
    record = report["evidence"][0]
    chain = "\n".join(record["evidence_chain"])
    assert "key:ControlSet001\\Services\\bam\\UserSettings\\" in chain
    assert "raw_binary(hex):" in chain
    assert "filetime_qword_offset_8:" in chain
    assert "key_last_write_time_utc(separate_field):" in chain


def test_malformed_sid_is_flagged_but_record_is_kept(report):
    weird = next(e for e in report["evidence"] if "weird.exe" in e["identity"]["program_path"])
    assert weird["identity"]["sid_valid"] is False
    assert any(reason.startswith("sid_malformed") for reason in weird["uncertainty_reasons"])
    assert weird["value"]["filetime_utc"] is not None


def test_zero_and_future_filetimes_are_invalid(report):
    zero = next(e for e in report["evidence"] if "zero.exe" in e["identity"]["program_path"])
    future = next(e for e in report["evidence"] if "future.exe" in e["identity"]["program_path"])
    assert zero["value"]["filetime_utc"] is None
    assert any("invalid_filetime_zero" in r for r in zero["uncertainty_reasons"])
    assert future["value"]["filetime_utc"] is None
    assert any("filetime_outside_expected_window" in r for r in future["uncertainty_reasons"])


def test_short_binary_cannot_yield_a_filetime(report):
    short = next(e for e in report["evidence"] if "short.exe" in e["identity"]["program_path"])
    assert short["value"]["filetime_raw_qword"] is None
    assert any("binary_too_short_for_filetime" in r for r in short["uncertainty_reasons"])
    # The key last-write time must remain separate and never substitute.
    assert short["key_last_write_time_utc"]
    assert short["value"]["filetime_utc"] is None


def test_unknown_trailing_bytes_are_preserved_not_interpreted(report):
    cmd = next(e for e in report["evidence"] if "cmd.exe" in e["identity"]["program_path"])
    assert cmd["value"]["unknown_trailing_hex"] == "aabbccdd"
    assert cmd["value"]["unknown_trailing_length"] == 4
    assert any("unknown_trailing_data" in r for r in cmd["uncertainty_reasons"])


def test_report_uses_neutral_wording_only(report):
    rendered = repr(report).lower()
    for forbidden in ("logon success", "successful logon", "malicious execution", "malware"):
        assert forbidden not in rendered
