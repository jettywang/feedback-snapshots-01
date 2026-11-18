from __future__ import annotations

import gzip
from uuid import UUID

import pytest

from dissect.apfs.apfs import APFS
from dissect.apfs.c_apfs import c_apfs
from dissect.apfs.exception import (
    FirmlinkConflictError,
    FirmlinkTargetError,
    UnionFileNotFoundError,
    UnionNotADirectoryError,
    UnionPathTraversalError,
    UnionVolumeUnavailableError,
    VolumeGroupIdentityError,
    VolumeGroupMismatchError,
    VolumeGroupRoleError,
    VolumeGroupSelectionError,
)
from dissect.apfs.objects.fs import FS
from dissect.apfs.union import FirmlinkMapping, UnionNode, VolumeGroupView, parse_firmlinks
from tests.conftest import absolute_path

GROUP_ID = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
SYSTEM_PATH = "_data/case_sensitive_beta.bin.gz"
DATA_PATH = "_data/case_insensitive_beta.bin.gz"


def _open_volume(path: str, role: c_apfs.APFS_VOL_ROLE, group_id: UUID | None = GROUP_ID) -> FS:
    fh = gzip.open(absolute_path(path), "rb")
    volume = APFS(fh).volumes[0]
    volume.role = role
    volume.volume_group_id = group_id
    # Keep the underlying file handle alive for the lifetime of the volume.
    volume._test_fh = fh
    return volume


@pytest.fixture()
def system_volume() -> FS:
    return _open_volume(SYSTEM_PATH, c_apfs.APFS_VOL_ROLE.SYSTEM)


@pytest.fixture()
def data_volume() -> FS:
    return _open_volume(DATA_PATH, c_apfs.APFS_VOL_ROLE.DATA)


@pytest.fixture()
def view(system_volume: FS, data_volume: FS) -> VolumeGroupView:
    return VolumeGroupView(system_volume, data_volume, [FirmlinkMapping("/dir", "dir")])


def test_volume_group_identity(view: VolumeGroupView) -> None:
    assert view.complete
    assert view.group_id == GROUP_ID
    assert view.scope.system_uuid == view.system.uuid
    assert view.scope.data_uuid == view.data.uuid
    assert view.scope.system_role == "SYSTEM"
    assert view.scope.data_role == "DATA"


def test_volume_group_role_rejected(system_volume: FS, data_volume: FS) -> None:
    with pytest.raises(VolumeGroupRoleError) as excinfo:
        VolumeGroupView(data_volume, system_volume, [FirmlinkMapping("/dir", "dir")])
    assert excinfo.value.details["role"] == "DATA"

    with pytest.raises(VolumeGroupRoleError) as excinfo:
        VolumeGroupView(system_volume, system_volume, [FirmlinkMapping("/dir", "dir")])
    assert excinfo.value.details["role"] == "SYSTEM"


def test_volume_group_identity_required(system_volume: FS, data_volume: FS) -> None:
    data_volume.volume_group_id = None
    with pytest.raises(VolumeGroupIdentityError):
        VolumeGroupView(system_volume, data_volume)


def test_volume_group_mismatch(system_volume: FS, data_volume: FS) -> None:
    data_volume.volume_group_id = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    with pytest.raises(VolumeGroupMismatchError) as excinfo:
        VolumeGroupView(system_volume, data_volume)
    assert excinfo.value.details["system_group_id"] == str(GROUP_ID)
    assert excinfo.value.details["data_group_id"] == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


def test_expected_group_id(system_volume: FS, data_volume: FS) -> None:
    with pytest.raises(VolumeGroupMismatchError):
        VolumeGroupView(system_volume, data_volume, group_id=UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"))

    view = VolumeGroupView(system_volume, data_volume, group_id=GROUP_ID)
    assert view.group_id == GROUP_ID


def test_same_volume_rejected(system_volume: FS, data_volume: FS) -> None:
    data_volume.uuid = system_volume.uuid
    with pytest.raises(VolumeGroupIdentityError):
        VolumeGroupView(system_volume, data_volume)

    with pytest.raises(VolumeGroupRoleError):
        VolumeGroupView(system_volume, system_volume)


def test_from_candidates_selects_pair(system_volume: FS, data_volume: FS) -> None:
    view = VolumeGroupView.from_candidates([system_volume, data_volume])
    assert view.system is system_volume
    assert view.data is data_volume


def test_from_candidates_rejects_cross_group(system_volume: FS, data_volume: FS) -> None:
    data_volume.volume_group_id = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    with pytest.raises(VolumeGroupSelectionError) as excinfo:
        VolumeGroupView.from_candidates([system_volume, data_volume])
    assert len(excinfo.value.details["candidates"]) == 2


def test_firmlink_mapping_normalization() -> None:
    assert FirmlinkMapping("/Library", "Library").target_parts == ("Library",)
    assert FirmlinkMapping("/Library", "/Library").target_parts == ("Library",)
    assert FirmlinkMapping("/Library", "/System/Volumes/Data/Library").target_parts == ("Library",)
    assert FirmlinkMapping("/Library", "System/Volumes/Data/Library").target_parts == ("Library",)
    assert FirmlinkMapping("/System/Volumes/Data", "Library").target_parts == ("Library",)
    with pytest.raises(FirmlinkConflictError):
        FirmlinkMapping("Library", "Library")
    with pytest.raises(FirmlinkConflictError):
        FirmlinkMapping("/Library", "/../etc")


def test_parse_firmlinks() -> None:
    mappings = parse_firmlinks("/Library\tLibrary\n/Users -> Users\n# comment\n/opt = opt\n")
    assert [(mapping.source, mapping.target) for mapping in mappings] == [
        ("/Library", "Library"),
        ("/Users", "Users"),
        ("/opt", "opt"),
    ]
    assert parse_firmlinks({"/Users": "Users"})[0].source == "/Users"
    assert parse_firmlinks([("/Users", "Users")])[0].target == "Users"


def test_conflicting_mappings_rejected(system_volume: FS, data_volume: FS) -> None:
    with pytest.raises(FirmlinkConflictError):
        VolumeGroupView(
            system_volume,
            data_volume,
            [FirmlinkMapping("/dir", "dir"), FirmlinkMapping("/dir", "other")],
        )


def test_overlapping_mappings_rejected(system_volume: FS, data_volume: FS) -> None:
    with pytest.raises(FirmlinkConflictError):
        VolumeGroupView(
            system_volume,
            data_volume,
            [FirmlinkMapping("/dir", "dir"), FirmlinkMapping("/dir/sub", "other")],
        )


def test_mapping_wrong_volume_rejected(system_volume: FS, data_volume: FS) -> None:
    with pytest.raises(FirmlinkConflictError):
        VolumeGroupView(
            system_volume,
            data_volume,
            [
                FirmlinkMapping(
                    "/dir",
                    "dir",
                    source_volume_uuid=UUID("dddddddd-dddd-dddd-dddd-dddddddddddd"),
                )
            ],
        )
    with pytest.raises(FirmlinkConflictError):
        VolumeGroupView(
            system_volume,
            data_volume,
            [
                FirmlinkMapping(
                    "/dir",
                    "dir",
                    target_volume_uuid=UUID("dddddddd-dddd-dddd-dddd-dddddddddddd"),
                )
            ],
        )


def test_mapped_read_reports_data_volume(view: VolumeGroupView) -> None:
    node = view.lookup("/dir/file")
    assert isinstance(node, UnionNode)
    assert node.union_path == "/dir/file"
    assert node.volume is view.data
    assert node.volume_uuid == view.data.uuid
    assert node.volume_role == "DATA"
    assert node.volume_path == "/dir/file"
    assert node.open().read() == b"\xef\xa3\xbf File System\n"

    kinds = [hop.kind for hop in node.trace]
    assert kinds == ["system-root", "firmlink-source", "firmlink", "data-path"]
    firmlink = node.trace[2]
    assert firmlink.mapping["source"] == "/dir"
    assert firmlink.mapping["target"] == "dir"


def test_unmapped_read_stays_on_system(view: VolumeGroupView) -> None:
    node = view.lookup("/empty")
    assert node.volume is view.system
    assert node.volume_role == "SYSTEM"
    assert node.volume_path == "/empty"
    assert node.open().read() == b""
    assert [hop.kind for hop in node.trace] == ["system-root", "system"]


def test_same_name_conflict_evidence(view: VolumeGroupView) -> None:
    node = view.lookup("/dir/file")
    candidates = node.alternatives
    assert len(candidates) == 2

    system_candidate, data_candidate = candidates
    assert system_candidate.volume_uuid == view.system.uuid
    assert system_candidate.volume_role == "SYSTEM"
    assert system_candidate.is_firmlink_source
    assert not system_candidate.selected
    assert data_candidate.volume_uuid == view.data.uuid
    assert data_candidate.volume_role == "DATA"
    assert data_candidate.selected

    evidence = view.evidence("/dir/file")
    assert evidence["node"]["volume"]["role"] == "DATA"
    assert evidence["node"]["volume"]["uuid"] == str(view.data.uuid)
    assert [candidate["volume_role"] for candidate in evidence["candidates"]] == ["SYSTEM", "DATA"]


def test_mapping_source_must_exist(system_volume: FS, data_volume: FS) -> None:
    view = VolumeGroupView(system_volume, data_volume, [FirmlinkMapping("/missing", "missing")])
    assert view.validate_mappings()[0]["status"] == "missing-source"
    with pytest.raises(FirmlinkTargetError) as excinfo:
        view.lookup("/missing")
    assert excinfo.value.details["mapping"]["source"] == "/missing"


def test_mapping_target_must_exist(system_volume: FS, data_volume: FS) -> None:
    view = VolumeGroupView(system_volume, data_volume, [FirmlinkMapping("/dir", "missing")])
    assert view.validate_mappings()[0]["status"] == "missing-target"
    with pytest.raises(FirmlinkTargetError):
        view.lookup("/dir/file")


def test_symbolic_link_is_not_a_firmlink(view: VolumeGroupView) -> None:
    link = view.lstat("/symlink-file")
    assert link.is_symlink()
    assert not link.is_firmlink()
    assert link.readlink() == "dir/file"
    assert link.volume_role == "SYSTEM"

    resolved = view.lookup("/symlink-file")
    assert resolved.union_path == "/dir/file"
    assert resolved.volume_role == "DATA"
    assert [hop.kind for hop in resolved.trace] == [
        "system-root",
        "system",
        "symlink",
        "firmlink-source",
        "firmlink",
        "data-path",
    ]


def test_absolute_data_mount_link_uses_data_volume(view: VolumeGroupView) -> None:
    link = view.lstat("/symlink-file")
    link.inode.readlink = lambda: "/System/Volumes/Data/dir/compressed-zlib-fork"

    node = view.lookup("/symlink-file")
    assert node.volume is view.data
    assert node.volume_path == "/dir/compressed-zlib-fork"
    kinds = [hop.kind for hop in node.trace]
    assert "data-mount" in kinds

    explicit = view.lookup("/System/Volumes/Data/dir/file")
    assert explicit.volume_role == "DATA"
    assert explicit.volume_path == "/dir/file"
    assert explicit.open().read() == b"\xef\xa3\xbf File System\n"


def test_missing_data_volume_scope(system_volume: FS) -> None:
    view = VolumeGroupView(system_volume, None, [FirmlinkMapping("/dir", "dir")])
    assert not view.complete
    assert view.scope.visible == ("/",)
    assert view.scope.unavailable == ("/dir",)
    assert view.lookup("/empty").volume_role == "SYSTEM"

    with pytest.raises(UnionVolumeUnavailableError) as excinfo:
        view.lookup("/dir/file")
    assert excinfo.value.scope.complete is False
    assert "Data volume is required" in str(excinfo.value)

    roots = {record["union_path"]: record for record in view.visible_roots()}
    assert roots["/"]["available"] is True
    assert roots["/dir"]["available"] is False


def test_missing_data_volume_listdir_reports_unavailable(system_volume: FS) -> None:
    view = VolumeGroupView(system_volume, None, [FirmlinkMapping("/dir", "dir")])
    entries = view.listdir("/")
    assert entries["dir"].available is False
    assert isinstance(entries["dir"].error, UnionVolumeUnavailableError)
    assert entries["empty"].available is True


def test_missing_system_volume_scope(data_volume: FS) -> None:
    view = VolumeGroupView(None, data_volume, [FirmlinkMapping("/dir", "dir")])
    assert not view.complete
    assert view.scope.visible == ("/dir",)
    assert view.scope.unavailable == ("/",)
    assert view.lookup("/dir/file").volume_role == "DATA"
    assert view.lookup("/dir/file").open().read() == b"\xef\xa3\xbf File System\n"

    with pytest.raises(UnionFileNotFoundError):
        view.lookup("/empty")


def test_missing_file_does_not_fall_through(view: VolumeGroupView) -> None:
    with pytest.raises(UnionFileNotFoundError):
        view.lookup("/does-not-exist")

    with pytest.raises(FirmlinkTargetError):
        view.lookup("/dir/does-not-exist")

    with pytest.raises(UnionNotADirectoryError):
        view.lookup("/dir/file/nested")


def test_path_traversal_rejected(view: VolumeGroupView) -> None:
    with pytest.raises(UnionPathTraversalError):
        view.lookup("/../etc/passwd")

    with pytest.raises(UnionPathTraversalError):
        view.lookup("/dir/../../etc/passwd")


def test_symlink_loop_rejected(view: VolumeGroupView) -> None:
    node = view.lstat("/symlink-dir")
    node.inode.readlink = lambda: "/symlink-dir"

    from dissect.apfs.exception import UnionSymlinkLoopError

    with pytest.raises(UnionSymlinkLoopError):
        view.lookup("/symlink-dir")


def test_readlink_requires_symlink(view: VolumeGroupView) -> None:
    from dissect.apfs.exception import NotASymlinkError

    with pytest.raises(NotASymlinkError):
        view.readlink("/dir")


def test_firmlink_marker_mismatch(system_volume: FS, data_volume: FS) -> None:
    inode = system_volume.get("/dir")
    inode.firmlink_target = "other"
    view = VolumeGroupView(system_volume, data_volume, [FirmlinkMapping("/dir", "dir")])
    assert view.validate_mappings()[0]["status"] == "marker-mismatch"
    with pytest.raises(FirmlinkConflictError):
        view.lookup("/dir/file")


def test_data_only_listdir_reports_mapping_roots(data_volume: FS) -> None:
    view = VolumeGroupView(None, data_volume, [FirmlinkMapping("/dir", "dir")])
    entries = view.listdir("/")
    assert set(entries) == {"dir"}
    assert entries["dir"].volume_role == "DATA"
    assert entries["dir"].union_path == "/dir"


def test_full_view_listdir_includes_union_entries(view: VolumeGroupView) -> None:
    entries = view.listdir("/")
    assert entries["dir"].available
    assert entries["dir"].volume_role == "DATA"
    assert entries["dir"].union_path == "/dir"
    assert entries["empty"].volume_role == "SYSTEM"
