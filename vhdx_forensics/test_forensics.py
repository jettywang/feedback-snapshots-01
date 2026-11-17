"""Self-contained tests for the read-only VHDX forensic toolkit."""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from dissect.hypervisor.disk.vhdx import VHDX  # noqa: E402

from make_synthetic import write_variants  # noqa: E402
from safe_replay import UnsafeReplayError, build_recovered_view  # noqa: E402
from vhdx_audit import audit  # noqa: E402


def _make(tmp: Path) -> dict[str, Path]:
    return write_variants(tmp)


def test_clean_is_applied(tmp_path: Path) -> None:
    paths = _make(tmp_path)
    report = audit(str(paths["clean"]))
    assert report.integrity_class()[0] == "APPLIED / clean"
    with open(paths["clean"], "rb") as fh:
        assert VHDX(fh).read(8) == b"COMMITTE"


def test_active_log_is_confirmed_but_not_applied(tmp_path: Path) -> None:
    paths = _make(tmp_path)
    path = str(paths["active"])
    report = audit(path)
    assert report.integrity_class()[0] == "CONFIRMED-BUT-NOT-APPLIED"

    # Direct read returns the stale committed bytes, not the pending update.
    with open(path, "rb") as fh:
        direct = VHDX(fh).read(32)
    assert direct.startswith(b"COMMITTED-BYTE")

    # Replayed in-memory view carries the pending update.
    image, changes = build_recovered_view(path)
    assert any("wrote 512B data" in c for c in changes)
    recovered = image[0x400000:0x400000 + 32]
    assert recovered.startswith(b"PENDING-LOG-UPDATE")


def test_orphan_log_cannot_be_replayed(tmp_path: Path) -> None:
    paths = _make(tmp_path)
    path = str(paths["orphan"])
    report = audit(path)
    assert report.integrity_class()[0] == "INSUFFICIENT-MATERIAL"
    assert report.log_guid_link_valid is False
    try:
        build_recovered_view(path)
    except UnsafeReplayError:
        pass
    else:  # pragma: no cover
        raise AssertionError("orphan log must not be replayable")


def test_corrupt_log_is_insufficient_material(tmp_path: Path) -> None:
    paths = _make(tmp_path)
    report = audit(str(paths["corrupt"]))
    assert report.integrity_class()[0] == "INSUFFICIENT-MATERIAL"
    assert report.entry_checksums_valid is False


def test_bat_remap_recovered_view(tmp_path: Path) -> None:
    paths = _make(tmp_path)
    path = str(paths["bat_pending"])
    report = audit(path)
    assert report.integrity_class()[0] == "CONFIRMED-BUT-NOT-APPLIED"
    image, changes = build_recovered_view(path)
    assert any("BAT update" in c for c in changes)
    (bat_raw,) = struct.unpack_from("<Q", image, report.bat_offset)
    data_mb = bat_raw >> 20
    assert bytes(image[data_mb * 1024 * 1024:data_mb * 1024 * 1024 + 32]).startswith(b"REMAP-TARGET")


def test_evidence_file_is_never_modified(tmp_path: Path) -> None:
    paths = _make(tmp_path)
    path = str(paths["active"])
    before = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    audit(path)
    build_recovered_view(path)
    after = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    assert before == after
