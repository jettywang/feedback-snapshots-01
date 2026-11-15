from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests._utils import absolute_path

EXPERIMENT = Path(__file__).resolve().parent.parent / "experiment"


@pytest.fixture(scope="module")
def outputs(tmp_path_factory: pytest.TempPathFactory) -> dict:
    out = tmp_path_factory.mktemp("conversion")
    proc = subprocess.run(
        [sys.executable, str(EXPERIMENT / "forensic_conversion.py"), "run", "--out", str(out)],
        cwd=EXPERIMENT.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    summary = json.loads((out / "summary.json").read_text())
    summary["_out"] = str(out)
    return summary


def hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_source_segments_are_not_rewritten(outputs: dict) -> None:
    """The experiment must never modify the committed EWF test data."""
    expected = {
        "image.E01": "fbc3da213475f9692be6bf00fb68eb87adaab3195c204f21ea42efc3b2b35097",
    }
    single = absolute_path("_data/ewf/single/image.E01")
    assert hash_file(single) == expected["image.E01"]


def test_derived_stream_matches_source(outputs: dict) -> None:
    for case in ("normal", "variant"):
        item = outputs[case]
        assert item["asdf_stream_sha256"] == item["source_stream_sha256"]
        assert item["footer_ok"] is True
        assert item["blocks_ok"] is True


def test_error_range_is_not_treated_as_confirmed_content(outputs: dict) -> None:
    ranges = outputs["variant"]["error_ranges"]
    assert ranges
    for item in ranges:
        assert item["placeholder_matches_declaration"] is True
        assert item["observed_unique_bytes"] == [0]


def test_incomplete_source_produces_no_asdf(outputs: dict) -> None:
    incomplete = outputs["incomplete"]
    assert incomplete["refused"] is True
    assert incomplete["derived_output"] == "无"
    assert not (Path(outputs["_out"]) / "incomplete.asdf").exists()
    assert incomplete["preflight"]["declared_chunks"] > incomplete["preflight"]["covered_chunks"]


def test_variant_is_synthetic_and_isolated(outputs: dict) -> None:
    """The variant must be built only from copies in the output directory."""
    out = Path(outputs["_out"])
    anchors = json.loads((out / "SHA256SUMS.json").read_text())
    recorded = anchors["source_segments"]

    for index in range(1, 6):
        name = f"image.E0{index}"
        original = absolute_path(f"_data/ewf/segmented/{name}")
        assert hash_file(original) == recorded[name], f"source segment {name} was modified"

    variant_dir = out / "variant-source"
    assert variant_dir.is_dir()
    variant_files = sorted(variant_dir.glob("*.E0*"))
    assert len(variant_files) == len(recorded)
    modified = [p for p in variant_files if hash_file(p) != recorded[p.name]]
    assert modified, "variant should differ from the source segments"
