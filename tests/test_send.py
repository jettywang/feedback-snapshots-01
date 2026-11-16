from __future__ import annotations

import gzip
import uuid
from pathlib import Path
from typing import BinaryIO

import pytest

from dissect.btrfs.btrfs import Btrfs
from dissect.btrfs.exceptions import BaselineMismatchError, UnknownRegionError
from dissect.btrfs.send import (
    Baseline,
    Clone,
    Mkfile,
    Rename,
    SendReplay,
    Snapshot,
    SourceKind,
    Truncate,
    Unparsed,
    Write,
)

NEW_UUID = uuid.UUID("11111111-2222-3333-4444-555555555555")
STRANGER_UUID = uuid.UUID("99999999-8888-7777-6666-555555555555")


class WriteGuard:
    """Proxy that proves the host filesystem is never written to."""

    def __init__(self, fh: BinaryIO):
        self._fh = fh

    def __getattr__(self, name: str):
        if name in ("write", "writelines", "truncate"):
            raise AssertionError(f"Attempted to write to the host filesystem via {name}()")
        return getattr(self._fh, name)


@pytest.fixture
def snapshot_fs() -> Btrfs:
    with gzip.GzipFile(Path(__file__).parent / "_data/btrfs-subvolume-snapshot.bin.gz") as fh:
        yield Btrfs(WriteGuard(fh))


@pytest.fixture
def baselines(snapshot_fs: Btrfs) -> dict[str, Baseline]:
    return {
        "subvol": Baseline(snapshot_fs.find_subvolume("subvol")),
        "snapshot": Baseline(snapshot_fs.find_subvolume("subvol-snapshot")),
    }


def clone_then_overwrite(clone_uuid: uuid.UUID, clone_ctransid: int) -> list:
    """A very short command sequence: clone a baseline file, then partially overwrite it."""
    return [
        Snapshot("recv", NEW_UUID, 100, clone_uuid, clone_ctransid),
        Mkfile("recv/file.txt"),
        Clone("recv/file.txt", 0, 18, clone_uuid, clone_ctransid, "small.txt", 0),
        Write("recv/file.txt", 5, b"HOST"),
    ]


def test_clone_then_partial_overwrite(baselines: dict[str, Baseline], tmp_path: Path) -> None:
    baseline = baselines["subvol"]
    commands = clone_then_overwrite(baseline.identity.uuid, baseline.identity.ctransid)

    vfs = SendReplay([baseline]).replay(commands)

    # Virtual read resolves the known bytes: baseline, inline write, baseline
    assert vfs.read("file.txt") == b"file HOSTubvolume\n"
    assert not vfs.degraded

    provenance = vfs.get("file.txt").provenance()
    assert [(seg.start, seg.length, seg.source.kind) for seg in provenance] == [
        (0, 5, SourceKind.BASELINE),
        (5, 4, SourceKind.WRITE),
        (9, 9, SourceKind.BASELINE),
    ]
    assert provenance[0].source.path == "small.txt"
    assert provenance[0].source.offset == 0
    assert provenance[1].source.command_index == 3
    assert provenance[2].source.offset == 9

    # The host filesystem was only ever read (WriteGuard) and nothing was created on disk
    assert list(tmp_path.iterdir()) == []


def test_identical_content_different_identity(baselines: dict[str, Baseline]) -> None:
    # Both subvolumes contain the same small.txt content, but have different identities
    subvol, snapshot = baselines["subvol"], baselines["snapshot"]
    assert subvol.identity != snapshot.identity
    assert subvol.read("small.txt", 0, 18) == snapshot.read("small.txt", 0, 18)

    commands = clone_then_overwrite(subvol.identity.uuid, subvol.identity.ctransid)

    # Admitted against the matching baseline
    vfs = SendReplay([subvol]).replay(commands)
    assert vfs.read("file.txt") == b"file HOSTubvolume\n"

    # Rejected against the content-identical but identity-different baseline
    with pytest.raises(BaselineMismatchError):
        SendReplay([snapshot]).replay(commands)

    # A forged transaction id is equally rejected
    forged = clone_then_overwrite(subvol.identity.uuid, subvol.identity.ctransid + 1)
    with pytest.raises(BaselineMismatchError):
        SendReplay([subvol]).replay(forged)


def test_unparsed_command_poisons_scope(baselines: dict[str, Baseline]) -> None:
    baseline = baselines["subvol"]
    commands = clone_then_overwrite(baseline.identity.uuid, baseline.identity.ctransid)

    # File-scoped failure: only that file becomes unknown
    vfs = SendReplay([baseline]).replay([*commands, Unparsed("crc mismatch", path="recv/file.txt")])
    assert vfs.degraded
    with pytest.raises(UnknownRegionError):
        vfs.read("file.txt")
    assert all(seg.source.kind == SourceKind.UNKNOWN for seg in vfs.get("file.txt").provenance())

    # Stream-scoped failure: the whole virtual filesystem becomes unknown
    vfs = SendReplay([baseline]).replay([*commands, Mkfile("recv/other.txt"), Unparsed("crc mismatch")])
    assert vfs.degraded
    with pytest.raises(UnknownRegionError):
        vfs.read("file.txt")

    # A clone from an unadmitted subvolume also yields an unknown range, not fake bytes
    forged = clone_then_overwrite(baseline.identity.uuid, baseline.identity.ctransid)
    forged[2] = Clone("recv/file.txt", 0, 18, STRANGER_UUID, 1, "small.txt", 0)
    vfs = SendReplay([baseline]).replay(forged)
    assert vfs.degraded
    with pytest.raises(UnknownRegionError):
        vfs.read("file.txt")


def test_rename_and_truncate(baselines: dict[str, Baseline]) -> None:
    baseline = baselines["subvol"]
    identity = baseline.identity
    commands = [
        Snapshot("recv", NEW_UUID, 100, identity.uuid, identity.ctransid),
        Mkfile("recv/file.txt"),
        Clone("recv/file.txt", 0, 18, identity.uuid, identity.ctransid, "small.txt", 0),
        Rename("recv/file.txt", "recv/moved.txt"),
        Truncate("recv/moved.txt", 9),
        Truncate("recv/moved.txt", 12),
        Write("recv/moved.txt", 12, b"!"),
    ]

    vfs = SendReplay([baseline]).replay(commands)

    assert "file.txt" not in vfs.files
    # Truncation cuts the tail, extension is a zero-filled hole, the write lands after it
    assert vfs.read("moved.txt") == b"file in s" + b"\x00" * 3 + b"!"

    provenance = vfs.get("moved.txt").provenance()
    assert [(seg.start, seg.length, seg.source.kind) for seg in provenance] == [
        (0, 9, SourceKind.BASELINE),
        (9, 3, SourceKind.HOLE),
        (12, 1, SourceKind.WRITE),
    ]
