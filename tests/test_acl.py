from __future__ import annotations

import io
import stat
import struct
from types import SimpleNamespace

import pytest

from dissect.xfs.acl import (
    ACL,
    ACL_GROUP,
    ACL_GROUP_OBJ,
    ACL_MASK,
    ACL_OTHER,
    ACL_USER,
    ACL_USER_OBJ,
    ACLEntry,
    ACLFormatError,
    Verdict,
    check_access,
    evaluate,
    render_report,
)
from dissect.xfs.c_xfs import c_xfs
from dissect.xfs.exceptions import Error
from dissect.xfs.xfs import parse_leaf_attrs, parse_shortform_attrs

UNDEFINED_ID = 0xFFFFFFFF


def acl_xattr(entries: list[tuple[int, int, int | None]]) -> bytes:
    """Build a Linux posix_acl_xattr value."""
    buf = struct.pack("<I", 2)
    for tag, perm, entry_id in entries:
        buf += struct.pack("<HHI", tag, perm, UNDEFINED_ID if entry_id is None else entry_id)
    return buf


class FakeNode:
    """Minimal INode stand-in carrying offline permission evidence."""

    def __init__(
        self,
        filename: str | None,
        filetype: int,
        mode: int,
        uid: int,
        gid: int,
        xattrs: dict[str, bytes] | None = None,
        children: list[FakeNode] | None = None,
        xattr_error: Exception | None = None,
    ):
        self.filename = filename
        self.filetype = filetype
        self.inum = 1000
        self.inode = SimpleNamespace(di_mode=filetype | mode, di_uid=uid, di_gid=gid)
        self.xattrs = xattrs or {}
        self.children = children or []
        self.xattr_error = xattr_error

    def iterdir(self):
        return iter(self.children)

    def get_xattr(self, name: str) -> bytes | None:
        if self.xattr_error is not None:
            raise self.xattr_error
        return self.xattrs.get(name)


def directory(mode: int, uid: int, gid: int, **kwargs) -> FakeNode:
    return FakeNode(None, stat.S_IFDIR, mode, uid, gid, **kwargs)


def regular_file(mode: int, uid: int, gid: int, **kwargs) -> FakeNode:
    return FakeNode(None, stat.S_IFREG, mode, uid, gid, **kwargs)


# --- Scenario A: mode looks permissive, ACL mask tightens -------------------


def test_mask_tightens_group_class() -> None:
    # mode 0770 suggests rwx for the group class, but mask::r-- caps it
    acl = ACL.from_xattr(
        acl_xattr(
            [
                (ACL_USER_OBJ, 7, None),
                (ACL_USER, 7, 1000),
                (ACL_GROUP_OBJ, 7, None),
                (ACL_MASK, 4, None),
                (ACL_OTHER, 0, None),
            ]
        )
    )
    result = evaluate(
        mode=0o770, uid=500, gid=600, access_acl=acl, want=0b010, fsuid=1001, fsgids={600}
    )
    assert result.verdict is Verdict.DENY
    assert result.granted == 0b100

    # The same request against the bare mode would have been allowed
    mode_only = evaluate(
        mode=0o770, uid=500, gid=600, access_acl=None, want=0b010, fsuid=1001, fsgids={600}
    )
    assert mode_only.verdict is Verdict.ALLOW

    # Read is still granted through the mask
    read = evaluate(mode=0o770, uid=500, gid=600, access_acl=acl, want=0b100, fsuid=1001, fsgids={600})
    assert read.verdict is Verdict.ALLOW


def test_mask_tightens_named_user() -> None:
    acl = ACL.from_xattr(
        acl_xattr(
            [
                (ACL_USER_OBJ, 7, None),
                (ACL_USER, 7, 1000),
                (ACL_GROUP_OBJ, 0, None),
                (ACL_MASK, 4, None),
                (ACL_OTHER, 0, None),
            ]
        )
    )
    result = evaluate(
        mode=0o770, uid=500, gid=600, access_acl=acl, want=0b010, fsuid=1000, fsgids={1000}
    )
    assert result.verdict is Verdict.DENY
    assert result.granted == 0b100


# --- Scenario B: group class merging ----------------------------------------


def test_group_class_merging() -> None:
    # fsuid 1000 belongs to the owning group (600) and two named groups
    acl = ACL.from_xattr(
        acl_xattr(
            [
                (ACL_USER_OBJ, 7, None),
                (ACL_GROUP_OBJ, 4, None),  # group::r--
                (ACL_GROUP, 2, 601),  # group:601:-w-
                (ACL_GROUP, 1, 602),  # group:602:--x
                (ACL_MASK, 7, None),
                (ACL_OTHER, 0, None),
            ]
        )
    )
    kwargs = dict(mode=0o070, uid=500, gid=600, access_acl=acl, fsuid=1000, fsgids={600, 601, 602})

    # Any single matching entry that covers the request suffices
    assert evaluate(want=0b100, **kwargs).verdict is Verdict.ALLOW  # via group::r--
    assert evaluate(want=0b010, **kwargs).verdict is Verdict.ALLOW  # via group:601:-w-
    assert evaluate(want=0b001, **kwargs).verdict is Verdict.ALLOW  # via group:602:--x

    # No single entry grants r+w together: bits are not unioned across entries
    rw = evaluate(want=0b110, **kwargs)
    assert rw.verdict is Verdict.DENY
    assert rw.granted == 0b111  # union of effective bits, reported for evidence


def test_group_class_mask_applies_to_merged_entries() -> None:
    acl = ACL.from_xattr(
        acl_xattr(
            [
                (ACL_USER_OBJ, 7, None),
                (ACL_GROUP_OBJ, 4, None),
                (ACL_GROUP, 6, 601),
                (ACL_MASK, 4, None),  # mask caps every group class entry
                (ACL_OTHER, 0, None),
            ]
        )
    )
    result = evaluate(
        mode=0o070, uid=500, gid=600, access_acl=acl, want=0b010, fsuid=1000, fsgids={600, 601}
    )
    assert result.verdict is Verdict.DENY
    assert result.granted == 0b100


# --- Scenario C: parent directory blocks traversal --------------------------


def build_tree() -> SimpleNamespace:
    secret = regular_file(0o644, 500, 500)
    secret.filename = "secret"
    dir_b = directory(0o700, 500, 500, children=[secret])
    dir_b.filename = "b"
    dir_a = directory(0o755, 0, 0, children=[dir_b])
    dir_a.filename = "a"
    root = directory(0o755, 0, 0, children=[dir_a])
    return SimpleNamespace(root=root)


def test_parent_directory_blocks_search() -> None:
    fs = build_tree()
    report = check_access(fs, "/a/b/secret", 0b100, 1000, {1000})

    assert report.verdict is Verdict.DENY
    # Walk stops at /a/b; the target file is never evaluated
    assert [step.component for step in report.steps] == ["/", "a", "b"]
    assert report.steps[0].verdict is Verdict.ALLOW
    assert report.steps[1].verdict is Verdict.ALLOW
    assert report.steps[2].verdict is Verdict.DENY
    assert report.steps[2].want == 0b001  # search bit on the directory

    text = render_report(report)
    assert "mode=0700" in text
    assert "other:: ---" in text
    assert "最终结论: deny" in text


def test_parent_directory_acl_grants_search() -> None:
    acl = acl_xattr(
        [
            (ACL_USER_OBJ, 7, None),
            (ACL_USER, 1, 1000),  # user:1000:--x
            (ACL_GROUP_OBJ, 0, None),
            (ACL_MASK, 1, None),
            (ACL_OTHER, 0, None),
        ]
    )
    secret = regular_file(0o644, 500, 500)
    secret.filename = "secret"
    dir_b = directory(0o700, 500, 500, xattrs={"posix_acl_access": acl}, children=[secret])
    dir_b.filename = "b"
    root = directory(0o755, 0, 0, children=[dir_b])

    report = check_access(SimpleNamespace(root=root), "/b/secret", 0b100, 1000, {1000})
    assert [step.component for step in report.steps] == ["/", "b", "secret"]
    assert report.steps[1].verdict is Verdict.ALLOW  # search via named user entry
    assert report.steps[2].verdict is Verdict.ALLOW  # read via other::r--
    assert report.verdict is Verdict.ALLOW


# --- Indeterminate cases -----------------------------------------------------


def test_root_uid_is_indeterminate() -> None:
    result = evaluate(mode=0o000, uid=500, gid=500, access_acl=None, want=0b100, fsuid=0, fsgids={0})
    assert result.verdict is Verdict.INDETERMINATE


def test_missing_identity_is_indeterminate() -> None:
    fs = build_tree()
    assert check_access(fs, "/a/b/secret", 0b100, None, {1000}).verdict is Verdict.INDETERMINATE
    assert check_access(fs, "/a/b/secret", 0b100, 1000, None).verdict is Verdict.INDETERMINATE


def test_malformed_access_acl_is_indeterminate() -> None:
    node = regular_file(0o777, 500, 500, xattrs={"posix_acl_access": b"\x03\x00\x00\x00garbage"})
    root = directory(0o755, 0, 0, children=[node])
    node.filename = "file"
    report = check_access(SimpleNamespace(root=root), "/file", 0b100, 1000, {1000})
    assert report.verdict is Verdict.INDETERMINATE
    assert "access ACL 解析失败" in report.steps[-1].note


def test_unreadable_xattrs_are_indeterminate() -> None:
    node = regular_file(0o777, 500, 500, xattr_error=Error("unsupported attribute fork"))
    node.filename = "file"
    root = directory(0o755, 0, 0, children=[node])
    report = check_access(SimpleNamespace(root=root), "/file", 0b100, 1000, {1000})
    assert report.verdict is Verdict.INDETERMINATE
    assert "权限材料缺失" in report.steps[-1].note


def test_symlink_is_indeterminate() -> None:
    link = FakeNode("link", stat.S_IFLNK, 0o777, 500, 500)
    root = directory(0o755, 0, 0, children=[link])
    report = check_access(SimpleNamespace(root=root), "/link", 0b100, 1000, {1000})
    assert report.verdict is Verdict.INDETERMINATE
    assert "符号链接" in report.steps[-1].note


def test_default_acl_is_not_used_for_access_decisions() -> None:
    # A generous default ACL must not grant access to the existing object
    default_acl = acl_xattr(
        [
            (ACL_USER_OBJ, 7, None),
            (ACL_USER, 7, 1000),
            (ACL_GROUP_OBJ, 7, None),
            (ACL_MASK, 7, None),
            (ACL_OTHER, 7, None),
        ]
    )
    node = regular_file(0o600, 500, 500, xattrs={"posix_acl_default": default_acl})
    node.filename = "file"
    root = directory(0o755, 0, 0, children=[node])

    report = check_access(SimpleNamespace(root=root), "/file", 0b100, 1000, {1000})
    assert report.verdict is Verdict.DENY  # falls back to mode 0600, other::---
    step = report.steps[-1]
    assert step.default_acl is not None
    assert step.access_acl is None
    assert step.acl_source == "mode"
    assert "不参与本判定" in render_report(report)


# --- ACL parsing -------------------------------------------------------------


def test_acl_from_mode() -> None:
    acl = ACL.from_mode(0o754)
    assert acl.entries == (
        ACLEntry(ACL_USER_OBJ, 7),
        ACLEntry(ACL_GROUP_OBJ, 5),
        ACLEntry(ACL_OTHER, 4),
    )
    assert acl.mask is None


def test_acl_from_xattr_roundtrip() -> None:
    raw = acl_xattr(
        [
            (ACL_USER_OBJ, 7, None),
            (ACL_USER, 5, 1000),
            (ACL_GROUP_OBJ, 4, None),
            (ACL_GROUP, 6, 601),
            (ACL_MASK, 6, None),
            (ACL_OTHER, 0, None),
        ]
    )
    acl = ACL.from_xattr(raw)
    assert acl.entries[1] == ACLEntry(ACL_USER, 5, 1000)
    assert acl.entries[3] == ACLEntry(ACL_GROUP, 6, 601)
    assert acl.mask == 6
    assert acl.render() == "user::rwx, user:1000:r-x, group::r--, group:601:rw-, mask::rw-, other::---"


@pytest.mark.parametrize(
    "entries",
    [
        [(ACL_USER_OBJ, 7, None), (ACL_GROUP_OBJ, 4, None)],  # missing other
        [(ACL_GROUP_OBJ, 4, None), (ACL_USER_OBJ, 7, None), (ACL_OTHER, 0, None)],  # bad order
        [(ACL_USER_OBJ, 7, None), (ACL_USER, 5, 1000), (ACL_GROUP_OBJ, 4, None), (ACL_OTHER, 0, None)],  # no mask
        [(ACL_USER_OBJ, 8, None), (ACL_GROUP_OBJ, 4, None), (ACL_OTHER, 0, None)],  # bad perm bits
    ],
)
def test_acl_validate_rejects_malformed(entries: list[tuple[int, int, int | None]]) -> None:
    with pytest.raises(ACLFormatError):
        ACL.from_xattr(acl_xattr(entries))


# --- xattr fork parsing -------------------------------------------------------


def test_parse_shortform_attrs() -> None:
    name, value = b"posix_acl_access", b"\x02\x00\x00\x00"
    entry = bytes([len(name), len(value), 0]) + name + value
    buf = struct.pack(">HB", len(entry), 1) + entry

    attrs = list(parse_shortform_attrs(io.BytesIO(buf)))
    assert len(attrs) == 1
    assert attrs[0].name == "posix_acl_access"
    assert attrs[0].fullname == "user.posix_acl_access"
    assert attrs[0].value == value


def test_parse_shortform_attrs_namespaces() -> None:
    entries = b""
    for name, flags in ((b"myattr", 0), (b"keys", c_xfs.XFS_ATTR_ROOT), (b"label", c_xfs.XFS_ATTR_SECURE)):
        entries += bytes([len(name), 1, flags]) + name + b"v"
    buf = struct.pack(">HB", len(entries), 3) + entries

    attrs = list(parse_shortform_attrs(io.BytesIO(buf)))
    assert [attr.fullname for attr in attrs] == ["user.myattr", "trusted.keys", "security.label"]


def test_parse_leaf_attrs() -> None:
    block = bytearray(4096)
    name, value = b"posix_acl_access", b"\x02\x00\x00\x00payload"
    nameidx = 0x100

    # xfs_da_blkinfo: forw, back, magic, pad
    struct.pack_into(">IIHH", block, 0, 0, 0, c_xfs.XFS_ATTR_LEAF_MAGIC, 0)
    # count, usedbytes, firstused, holes, pad1
    struct.pack_into(">HHHBB", block, 12, 1, 0, nameidx, 0, 0)
    # freemap[8] left zeroed; leaf entry at offset 12 + 8 + 32 = 52
    struct.pack_into(">IHBB", block, 52, 0xDEADBEEF, nameidx, c_xfs.XFS_ATTR_LOCAL, 0)
    # local name header + name + value
    struct.pack_into(">HB", block, nameidx, len(value), len(name))
    block[nameidx + 3 : nameidx + 3 + len(name)] = name
    block[nameidx + 3 + len(name) : nameidx + 3 + len(name) + len(value)] = value

    attrs = list(parse_leaf_attrs(io.BytesIO(bytes(block))))
    assert len(attrs) == 1
    assert attrs[0].name == "posix_acl_access"
    assert attrs[0].value == value


def test_parse_leaf_attrs_rejects_remote_values() -> None:
    block = bytearray(4096)
    struct.pack_into(">IIHH", block, 0, 0, 0, c_xfs.XFS_ATTR_LEAF_MAGIC, 0)
    struct.pack_into(">HHHBB", block, 12, 1, 0, 0x100, 0, 0)
    struct.pack_into(">IHBB", block, 52, 0, 0x100, 0, 0)  # no XFS_ATTR_LOCAL flag

    from dissect.xfs.exceptions import UnsupportedDataforkException

    with pytest.raises(UnsupportedDataforkException):
        list(parse_leaf_attrs(io.BytesIO(bytes(block))))
