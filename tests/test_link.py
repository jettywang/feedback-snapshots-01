from __future__ import annotations

import stat
from typing import BinaryIO

import pytest

from dissect.btrfs import (
    Btrfs,
    InodeIdentity,
    LinkBudgetExceeded,
    LinkHop,
    LinkHopStatus,
    LinkLoopError,
    LinkNotADirectoryError,
    LinkResolutionError,
    LinkStatus,
    resolve_link,
)
from dissect.btrfs.btrfs import INode, Subvolume
from dissect.btrfs.link import _lookup


def test_resolve_relative_link(btrfs_default: BinaryIO) -> None:
    fs = Btrfs(btrfs_default)

    result = resolve_link(fs, "link.txt")

    assert result.ok
    assert result.status is LinkStatus.RESOLVED
    assert result.final is not None
    assert result.final.inum == 4160
    assert result.final.path == "path/to/a/file.txt"
    assert len(result) == 1

    hop = result.steps[0]
    assert hop.status is LinkHopStatus.FOLLOWED
    assert hop.target == "path/to/a/file.txt"
    assert hop.absolute is False
    assert hop.link.inum == 4161
    assert hop.result is not None and hop.result.inum == 4160
    assert hop.base_path == ""


def test_resolve_link_inode_and_follow_final(btrfs_default: BinaryIO) -> None:
    fs = Btrfs(btrfs_default)
    link = fs.get("link.txt")

    assert isinstance(link, INode)
    assert link.is_symlink()

    followed = link.resolve_link()
    assert followed.ok
    assert followed.final is not None and followed.final.inum == 4160

    not_followed = resolve_link(fs, "link.txt", follow_final=False)
    assert not_followed.ok
    assert not_followed.final == link
    assert not_followed.steps == []


def test_resolve_cross_subvolume_relative_parent(btrfs_subvolume: BinaryIO) -> None:
    fs = Btrfs(btrfs_subvolume)

    result = resolve_link(fs, "subvol/cross-volume-link.txt")

    assert result.ok
    assert result.final is not None and result.final.inum == 4160
    assert [hop.target for hop in result] == ["../link.txt", "path/to/a/file.txt"]

    first, second = result.steps
    assert first.link.root_objectid == 256
    assert first.root.objectid == 256
    assert first.absolute is False
    assert first.base_path == "subvol"
    assert first.result is not None and first.result.root_objectid == 5
    assert second.link.root_objectid == 5


def test_resolve_absolute_inside_evidence_root(btrfs_subvolume: BinaryIO) -> None:
    fs = Btrfs(btrfs_subvolume)
    subvol = fs.open_subvolume(256)

    # The absolute target "/link.txt" must be interpreted against the chosen
    # subvolume root, not the host path or the default subvolume.
    result = resolve_link(fs, "/link.txt", root=subvol)

    assert not result.ok
    assert result.status is LinkStatus.NOT_FOUND
    assert result.evidence_root is subvol.root
    assert result.steps == []


def test_resolve_absolute_from_selected_root(btrfs_subvolume: BinaryIO) -> None:
    fs = Btrfs(btrfs_subvolume)

    result = resolve_link(fs, "/subvol/../link.txt")

    assert result.ok
    assert result.final is not None and result.final.inum == 4160


def test_resolve_absolute_target_stays_inside_evidence_root(btrfs_subvolume: BinaryIO) -> None:
    fs = Btrfs(btrfs_subvolume)

    # An absolute target starts at the evidence root and ".." cannot leave
    # it. The only artifact is that ".." at the root clamps there, so this
    # resolves inside subvolume 256 instead of reaching subvolume 5.
    result = resolve_link(fs, "/../volume", root=fs.open_subvolume(256))

    assert not result.ok
    assert result.status is LinkStatus.NOT_FOUND
    assert result.evidence_root is fs.open_subvolume(256).root


def test_resolve_dangling_keeps_completed_steps(btrfs_subvolume: BinaryIO) -> None:
    fs = Btrfs(btrfs_subvolume)

    result = resolve_link(fs, "subvol/some/more/dirs")
    assert result.ok
    assert result.final is not None and result.final.inum == 262

    result = resolve_link(fs, "subvol/some/more/dirs/missing.txt")
    assert not result.ok
    assert result.status is LinkStatus.NOT_FOUND
    assert result.steps == []
    assert isinstance(result.error, LinkResolutionError)


def test_resolve_links_are_bounded_by_root_and_inode(btrfs_subvolume_snapshot: BinaryIO) -> None:
    fs = Btrfs(btrfs_subvolume_snapshot)

    # Subvolume 256 and its snapshot 257 both contain an inode numbered 257
    # named cross-volume-link.txt. They are different objects and must not be
    # treated as a loop, even though the numbers match.
    root = fs.open_subvolume(256)
    snapshot = fs.open_subvolume(257)

    first = root.resolve_link("cross-volume-link.txt")
    second = snapshot.resolve_link("cross-volume-link.txt")

    assert first.ok and second.ok
    assert first.steps[0].link.inum == 257
    assert second.steps[0].link.inum == 257
    assert first.steps[0].link.root_objectid == 256
    assert second.steps[0].link.root_objectid == 257
    assert first.steps[0].link != second.steps[0].link


def test_resolve_nested_subvolume_uses_real_parent_context(btrfs_subvolume_nested: BinaryIO) -> None:
    fs = Btrfs(btrfs_subvolume_nested)

    default = fs.open_subvolume(257)

    # "volume" is a nested subvolume mounted inside "default". A relative
    # target from inside it must use that containing directory as context.
    result = resolve_link(default, "volume/../volume", max_hops=4)

    assert result.ok
    assert result.final is not None
    assert result.final.subvolume.objectid == 258
    assert result.final.inum == 256


def test_resolve_absolute_ignores_starting_node(btrfs_subvolume: BinaryIO) -> None:
    fs = Btrfs(btrfs_subvolume)

    result = resolve_link(
        fs,
        "/link.txt",
        node=fs.get("subvol"),
        root=fs.open_subvolume(5),
    )

    assert result.ok
    assert result.final is not None and result.final.inum == 4160


def test_resolve_dangling_link_keeps_hop(btrfs_default: BinaryIO) -> None:
    fs = Btrfs(btrfs_default)
    root = fs.root
    dangling = _SyntheticLink(root.subvolume, 999, "does-not-exist", root)

    original = _lookup
    import dissect.btrfs.link as link_module

    link_module._lookup = lambda directory, name: dangling if name == "dangling" else original(directory, name)
    try:
        from dissect.btrfs.link import _Resolver

        result = _Resolver(fs, root, max_hops=4, follow_final=True).follow_inode(dangling)
    finally:
        link_module._lookup = original

    assert not result.ok
    assert result.status is LinkStatus.DANGLING
    assert len(result.steps) == 1
    hop = result.steps[0]
    assert hop.link.inum == 999
    assert hop.target == "does-not-exist"
    assert hop.status is LinkHopStatus.DANGLING
    assert hop.result is None
    assert isinstance(result.error, LinkResolutionError)
    assert result.error.result is result


def test_resolve_strict_raises_with_partial_chain(btrfs_default: BinaryIO) -> None:
    fs = Btrfs(btrfs_default)
    root = fs.root
    dangling = _SyntheticLink(root.subvolume, 999, "does-not-exist", root)

    original = _lookup
    import dissect.btrfs.link as link_module

    link_module._lookup = lambda directory, name: dangling if name == "dangling" else original(directory, name)
    try:
        from dissect.btrfs.link import _Resolver

        resolver = _Resolver(fs, root, max_hops=4, follow_final=True)
    finally:
        link_module._lookup = original

    with pytest.raises(LinkResolutionError) as exc_info:
        resolver.follow_inode(dangling).raise_for_status()

    assert exc_info.value.result is not None
    assert exc_info.value.result.steps[0].target == "does-not-exist"


def test_resolve_budget_is_caller_supplied(btrfs_default: BinaryIO) -> None:
    fs = Btrfs(btrfs_default)

    result = resolve_link(fs, "link.txt", max_hops=0)

    assert not result.ok
    assert result.status is LinkStatus.BUDGET_EXHAUSTED
    assert result.max_hops == 0
    assert len(result.steps) == 1
    assert result.steps[0].status is LinkHopStatus.BUDGET_EXHAUSTED
    assert isinstance(result.error, LinkBudgetExceeded)

    ok = resolve_link(fs, "link.txt", max_hops=1)
    assert ok.ok
    assert ok.hops == 1

    with pytest.raises(LinkBudgetExceeded):
        resolve_link(fs, "link.txt", max_hops=0, strict=True)


def test_resolve_rejects_invalid_budget(btrfs_default: BinaryIO) -> None:
    fs = Btrfs(btrfs_default)

    for value in (-1, True, 1.5, "2"):
        with pytest.raises(ValueError):
            resolve_link(fs, "link.txt", max_hops=value)


class _SyntheticLink(INode):
    """An in-memory symlink used to test loop detection without crafting an image."""

    def __init__(self, subvolume: Subvolume, inum: int, target: str, parent: INode | None):
        super().__init__(subvolume, inum, stat.S_IFLNK, parent)
        self._target = target

    def is_symlink(self) -> bool:
        return True

    @property
    def link(self) -> str:
        return self._target

    def open(self):  # type: ignore[no-untyped-def]
        raise AssertionError("synthetic links must never read file data")


def test_resolve_real_loop_is_bounded(btrfs_default: BinaryIO) -> None:
    fs = Btrfs(btrfs_default)
    root = fs.root

    first = _SyntheticLink(root.subvolume, 999, "second", root)
    second = _SyntheticLink(root.subvolume, 1000, "first", root)

    original = _lookup
    import dissect.btrfs.link as link_module

    def fake_lookup(directory: INode, name: str) -> INode:
        if name == "first":
            return first
        if name == "second":
            return second
        return original(directory, name)

    link_module._lookup = fake_lookup
    try:
        from dissect.btrfs.link import _Resolver

        resolver = _Resolver(fs, root, max_hops=8, follow_final=True)
        result = resolver.follow_inode(first)
    finally:
        link_module._lookup = original

    assert not result.ok
    assert result.status is LinkStatus.LOOP
    assert isinstance(result.error, LinkLoopError)
    assert [hop.status for hop in result.steps] == [
        LinkHopStatus.FOLLOWED,
        LinkHopStatus.FOLLOWED,
        LinkHopStatus.LOOP,
    ]
    assert result.steps[0].result is not None and result.steps[0].result.inum == 1000
    assert result.steps[1].result is not None and result.steps[1].result.inum == 999
    assert result.steps[2].result is None
    assert result.steps[2].link.inum == 999


def test_hop_is_evidence_only(btrfs_default: BinaryIO) -> None:
    fs = Btrfs(btrfs_default)
    result = resolve_link(fs, "link.txt")

    hop = result.steps[0]
    assert isinstance(hop, LinkHop)
    assert isinstance(hop.link, InodeIdentity)
    assert hop.result is not None
    assert hop.link == InodeIdentity.from_inode(fs.get("link.txt"))
    assert hop.result == InodeIdentity.from_inode(fs.get("path/to/a/file.txt"))
    assert hop.result.root_uuid == hop.link.root_uuid


def test_resolve_path_through_symlinked_directory(btrfs_default: BinaryIO) -> None:
    fs = Btrfs(btrfs_default)

    result = resolve_link(fs, "link.txt")

    assert result.ok
    assert result.final is not None
    assert result.final.open().read() == b"file in dir\n"


def test_resolve_not_a_directory(btrfs_default: BinaryIO) -> None:
    fs = Btrfs(btrfs_default)

    result = resolve_link(fs, "small.txt/child")

    assert not result.ok
    assert result.status is LinkStatus.NOT_A_DIRECTORY
    assert isinstance(result.error, LinkNotADirectoryError)
