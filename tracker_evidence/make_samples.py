"""Generate synthetic LNK files exercising TrackerDataBlock correlation cases.

All samples are minimal but spec-valid SHELL_LINKs (flags=0: no IDList, no
LinkInfo, no StringData; EXTRA_DATA follows the header directly), except
zeta_truncated.lnk whose tracker block is deliberately cut short.
"""

from __future__ import annotations

import struct
from pathlib import Path
from uuid import UUID

SAMPLES_DIR = Path(__file__).parent / "samples"

LINK_CLSID = UUID("00021401-0000-0000-c000-000000000046").bytes_le
TRACKER_SIGNATURE = 0xA0000003

ZERO = UUID(int=0)

# Stable identities used across the sample set
VB1 = UUID("11111111-2222-3333-4444-555555555555")  # birth volume droid of the "alpha" file
FB1 = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")  # birth file droid of the "alpha" file
VC2 = UUID("66666666-7777-8888-9999-000000000000")  # volume the file was later moved to
FC2 = UUID("ffff0000-1111-2222-3333-444444444444")  # file droid after the move
VG1 = UUID("01234567-89ab-cdef-0123-456789abcdef")  # unrelated volume (gamma)
FG1 = UUID("fedcba98-7654-3210-fedc-ba9876543210")  # unrelated file (gamma)
FD1 = UUID("0badf00d-dead-beef-cafe-0123456789ab")  # unrelated file on alpha's volume (delta)
VB_D = UUID("d0d0d0d0-e1e1-4242-8383-040404040404")  # delta's own birth volume
FB_D = UUID("5eed5eed-6eed-4eed-aeed-beedbeedbeed")  # delta's own birth file


def header() -> bytes:
    return struct.pack("<I", 0x4C) + LINK_CLSID + struct.pack("<I", 0) + b"\x00" * (0x4C - 0x18)


def tracker_block(
    machine: str,
    volume_droid: UUID,
    file_droid: UUID,
    volume_droid_birth: UUID,
    file_droid_birth: UUID,
) -> bytes:
    machine_id = machine.encode("ascii")[:15] + b"\x00"
    machine_id = machine_id.ljust(16, b"\x00")
    body = struct.pack("<II", 0x58, 0)
    body += machine_id
    body += volume_droid.bytes_le
    body += file_droid.bytes_le
    body += volume_droid_birth.bytes_le
    body += file_droid_birth.bytes_le
    assert len(body) == 0x58
    return struct.pack("<II", 0x60, TRACKER_SIGNATURE) + body


def lnk(tracker: bytes) -> bytes:
    return header() + tracker + struct.pack("<I", 0)  # terminal block


def main() -> None:
    SAMPLES_DIR.mkdir(exist_ok=True)
    samples = {
        # Freshly created shortcut: current droids == birth droids.
        "alpha_created.lnk": lnk(tracker_block("DESKTOP-ALPHA01", VB1, FB1, VB1, FB1)),
        # Byte-identical tracker identity: a copy of the same shortcut.
        "alpha_duplicate.lnk": lnk(tracker_block("DESKTOP-ALPHA01", VB1, FB1, VB1, FB1)),
        # Same birth identity as alpha, but the object was moved: current pair differs.
        "beta_moved.lnk": lnk(tracker_block("DESKTOP-ALPHA01", VC2, FC2, VB1, FB1)),
        # Same machine name only; every droid is different.
        "gamma_same_machine_name.lnk": lnk(tracker_block("DESKTOP-ALPHA01", VG1, FG1, VG1, FG1)),
        # Shares only alpha's current *volume* droid; file droids and birth pair differ.
        "delta_shared_volume.lnk": lnk(tracker_block("DESKTOP-BETA02", VB1, FD1, VB_D, FB_D)),
        # All droid fields zeroed: no identity to correlate on.
        "epsilon_zeroed.lnk": lnk(tracker_block("DESKTOP-GAMMA03", ZERO, ZERO, ZERO, ZERO)),
    }
    for name, data in samples.items():
        (SAMPLES_DIR / name).write_bytes(data)

    # Truncated tracker block: declares 0x60 bytes, file ends after file_droid.
    full = tracker_block("DESKTOP-DELTA04", VB1, FB1, VB1, FB1)
    truncated = header() + full[: 8 + 0x38]  # header+length+version+machine+vol+file droids
    (SAMPLES_DIR / "zeta_truncated.lnk").write_bytes(truncated)

    for p in sorted(SAMPLES_DIR.iterdir()):
        print(f"{p.name}: {p.stat().st_size} bytes")


if __name__ == "__main__":
    main()
