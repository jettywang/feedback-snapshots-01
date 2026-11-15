from __future__ import annotations

import io
from pathlib import Path

import pytest

from dissect.evidence.asdf import AsdfSnapshot, AsdfWriter
from dissect.evidence.asdf.recompose import PROVENANCE_MANIFEST, open_snapshot
from dissect.evidence.tools.asdf import recompose as recompose_tool

BLOCK = 4096


def _write_source(path: Path) -> None:
    with path.open("wb") as fh:
        writer = AsdfWriter(fh)
        writer.add_bytes(bytes(v & 0xFF for v in range(BLOCK)), idx=0, base=0)
        writer.add_bytes(b"P" * 1000, idx=0, base=BLOCK * 4)
        writer.close()


def test_recompose_cli_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "source.asdf"
    destination = tmp_path / "derived.asdf"
    _write_source(source)

    monkeypatch.setattr(
        "sys.argv",
        [
            "asdf-recompose",
            str(source),
            "-w",
            str(destination),
            "-r",
            "0:4096",
            "-r",
            f"{BLOCK * 4}:1000",
        ],
    )
    assert recompose_tool.main() == 0
    assert destination.exists()

    snapshot = open_snapshot(destination.open("rb"))
    manifest = snapshot.metadata.open(PROVENANCE_MANIFEST).read()
    assert b"asdf-recompose/v1" in manifest
    assert len(AsdfSnapshot(io.BytesIO(destination.read_bytes())).table[0]) == 2


def test_recompose_cli_rejects_gap_and_removes_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "source.asdf"
    destination = tmp_path / "derived.asdf"
    _write_source(source)

    monkeypatch.setattr(
        "sys.argv",
        ["asdf-recompose", str(source), "-w", str(destination), "-r", f"{BLOCK}:{BLOCK * 3}"],
    )
    assert recompose_tool.main() == 1
    assert not destination.exists()


def test_recompose_cli_rejects_corrupt_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "source.asdf"
    destination = tmp_path / "derived.asdf"
    _write_source(source)

    raw = bytearray(source.read_bytes())
    snapshot = AsdfSnapshot(io.BytesIO(bytes(raw)))
    data_offset = snapshot.table[0][0][3]
    raw[data_offset] ^= 0xFF
    source.write_bytes(bytes(raw))

    monkeypatch.setattr("sys.argv", ["asdf-recompose", str(source), "-w", str(destination), "-r", "0:4096"])
    assert recompose_tool.main() == 1
    assert not destination.exists()
