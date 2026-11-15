"""Regression tests for the synthetic IFEO/SilentProcessExit samples."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from analyze import analyse_hive
from build_samples import HiveBuilder, KeySpec, ValueSpec, REG_SZ, sz, write_samples

SAMPLES = write_samples(Path(__file__).parent / "samples")
ASSUMPTIONS = {"SystemRoot": r"C:\Windows", "ProgramFiles": r"C:\Program Files"}


def _image(report_name: str, view: str, image: str) -> dict:
    report = analyse_hive(SAMPLES[report_name], ASSUMPTIONS)
    found = [
        item for item in next(v for v in report["views"] if v["view"] == view)["images"] if item["image"] == image
    ]
    assert len(found) == 1
    return found[0]


def test_monitor_path_alone_is_not_a_complete_chain() -> None:
    image = _image("A_monitor_only", "native", "monitor-only.exe")
    assert image["monitor"]["valid"] is True
    assert image["monitor_association_complete"] is False
    assert image["mechanisms"] == ["MONITOR_WITHOUT_FLAG_ORPHAN"]
    assert "IFEO 映像键" in image["missing_associations"]


def test_complete_chain_requires_flag_and_monitor() -> None:
    image = _image("B_full_chain", "native", "full-chain.exe")
    assert image["global_flag"]["bit_0x200"] is True
    assert image["monitor"]["valid"] is True
    assert image["monitor_association_complete"] is True
    assert "SILENT_PROCESS_EXIT_MONITOR_CANDIDATE" in image["mechanisms"]
    assert "IFEO_DEBUGGER_REDIRECT_CANDIDATE" in image["mechanisms"]


def test_two_views_are_not_merged() -> None:
    for view, debugger, monitor, count in (
        ("native", r"C:\Tools\dbg64.exe", r"%SystemRoot%\Tools\monitor64.exe", 2),
        ("wow6432", r"C:\Tools\dbg32.exe", r"C:\Tools\monitor32.exe", 1),
    ):
        image = _image("C_two_views", view, "dual-view.exe")
        assert image["debugger"]["raw"] == debugger
        assert image["monitor"]["raw"] == monitor
        assert len(image["filters"]) == count
        assert image["monitor_association_complete"] is True


def test_environment_variables_remain_visible() -> None:
    image = _image("B_full_chain", "native", "full-chain.exe")
    env = image["monitor"]["environment"]
    assert env["has_environment_variables"] is True
    assert env["variables"] == ["SystemRoot"]
    assert env["expanded_candidate"] == r"C:\Windows\Tools\monitor64.exe"
    assert env["candidate_only"] is True

    unresolved = _image("D_ambiguous", "native", "env-missing.exe")["monitor"]["environment"]
    assert unresolved["unresolved"] == ["MISSING_VAR"]
    assert unresolved["expanded_candidate"] is None


def test_invalid_flag_type_is_excluded_from_mechanism() -> None:
    image = _image("D_ambiguous", "native", "bad-flag-type.exe")
    assert image["global_flag"]["valid"] is False
    assert image["monitor_association_complete"] is False
    assert "SILENT_PROCESS_EXIT_MONITOR_CANDIDATE" not in image["mechanisms"]
    assert any(issue["code"] == "WRONG_TYPE" for issue in image["issues"])


def test_duplicate_filter_conditions_are_retained() -> None:
    image = _image("D_ambiguous", "native", "multi-filter.exe")
    assert len(image["filters"]) == 2
    assert {condition["subkey"] for condition in image["filters"]} == {"filter-1", "filter-2"}
    assert image["monitor_association_complete"] is False


def test_duplicate_value_names_are_retained() -> None:
    image = _image("D_ambiguous", "native", "duplicate.exe")
    assert len(image["values"]["ifeo"]) == 3
    assert any(issue["code"] == "DUPLICATE_VALUE_NAME" for issue in image["issues"])


def test_misplaced_monitor_in_ifeo_subkey_is_not_an_association() -> None:
    image = _image("D_ambiguous", "native", "subkey-conflict.exe")
    assert image["monitor_association_complete"] is False
    assert any(issue["code"] == "MISPLACED_ASSOCIATION_VALUE" for issue in image["issues"])


def test_duplicate_usefilter_marks_filter_state_ambiguous() -> None:
    image = _image("D_ambiguous", "native", "duplicate.exe")
    assert image["use_filter"]["ambiguous"] is True
    assert image["use_filter"]["enabled"] is False
    assert any(issue["code"] == "DUPLICATE_VALUE_NAME" for issue in image["issues"])


def test_filter_conditions_are_reported_not_collapsed() -> None:
    image = _image("D_ambiguous", "native", "multi-filter.exe")
    sources = {condition["source"] for condition in image["filters"]}
    assert sources == {"filter-subkey"}
    assert image["issues"] == [] or all("DUPLICATE_FILTER_CONDITION" not in issue["code"] for issue in image["issues"])


def test_case_variant_duplicate_keys_are_all_retained() -> None:
    root = KeySpec(
        "ROOT",
        children=[
            KeySpec(
                "Microsoft",
                children=[
                    KeySpec(
                        "Windows NT",
                        children=[
                            KeySpec(
                                "CurrentVersion",
                                children=[
                                    KeySpec(
                                        "Image File Execution Options",
                                        children=[
                                            KeySpec("case-variant.exe", values=[ValueSpec("Debugger", REG_SZ, sz(r"C:\a.exe"))]),
                                            KeySpec("CASE-VARIANT.EXE", values=[ValueSpec("Debugger", REG_SZ, sz(r"C:\b.exe"))]),
                                        ],
                                    )
                                ],
                            )
                        ],
                    )
                ],
            )
        ],
    )
    builder = HiveBuilder()
    builder.build_key(root)
    path = Path(__file__).parent / "samples" / "_test_case_variant.hive"
    path.write_bytes(builder.write())
    try:
        report = analyse_hive(path, {})
        images = next(view for view in report["views"] if view["view"] == "native")["images"]
        assert len(images) == 2
        assert {image["debugger"]["raw"] for image in images} == {r"C:\a.exe", r"C:\b.exe"}
        assert all(image["pairing_ambiguous"] is True for image in images)
    finally:
        path.unlink()
