"""Runnable state comparison: direct read vs. auditor verdict vs. safe replay.

Demonstrates the central finding on the three synthetic variants and on any
real VHDX passed as an argument. The same committed payload sector is read
through the production dissect.hypervisor VHDX reader, while the auditor
explains why the identical bytes cannot carry the same integrity promise
once a non-empty, not-yet-applied log is present.

Usage:
    python run_comparison.py [extra.vhdx ...]
"""
from __future__ import annotations

import sys
import struct
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dissect.hypervisor.disk.vhdx import VHDX  # noqa: E402

from safe_replay import UnsafeReplayError, build_recovered_view  # noqa: E402
from vhdx_audit import audit  # noqa: E402

SYNTHETIC = [
    "clean.vhdx",
    "active.vhdx",
    "orphan.vhdx",
    "bat_pending.vhdx",
    "corrupt.vhdx",
]


def direct_read(path: str) -> bytes:
    with open(path, "rb") as fh:
        disk = VHDX(fh)
        return disk.read(32)


def recovered_read(path: str, sector_off: int = 0) -> tuple[bytes | None, str]:
    try:
        image, _changes = build_recovered_view(path)
    except UnsafeReplayError as exc:
        return None, f"REPLAY REFUSED: {exc}"
    # Re-read the (possibly remapped) BAT slot from the recovered image itself.
    report = audit(path)
    (bat_raw,) = struct.unpack_from("<Q", image, report.bat_offset)
    data_mb = bat_raw >> 20
    off = data_mb * 1024 * 1024 + sector_off
    return bytes(image[off:off + 32]), "replayed in memory (evidence file untouched)"


def main(targets: list[str]) -> int:
    base = Path(__file__).resolve().parent / "synthetic"
    paths = [str(base / name) for name in SYNTHETIC] + targets

    header = f"{'file':<28}{'direct read (current service)':<34}{'integrity class':<28}recovered view"
    print(header)
    print("-" * len(header))

    for path in paths:
        name = Path(path).name
        direct = direct_read(path)
        report = audit(path)
        cls, _reason = report.integrity_class()
        recovered, note = recovered_read(path)

        print(f"{name:<28}{direct[:31].decode('latin1')!r:<34}{cls:<28}", end="")
        if recovered is None:
            print(note)
        else:
            print(f"{recovered[:31].decode('latin1')!r}  [{note}]")

    print()
    print("Key: direct read always returns the COMMITTED bytes; only the clean and")
    print("replayed views are crash-consistent. The active-log direct read is a stale")
    print("pre-update image; the orphan log is scannable but must never be replayed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
