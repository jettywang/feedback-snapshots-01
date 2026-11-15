from __future__ import annotations

import gzip
import hashlib
import io

import pytest

from dissect.archive.wim.relationships import (
    ContentState,
    DirectoryEntryState,
    HardLinkState,
    RelationshipView,
    SecurityState,
)
from dissect.archive.wim.wim import WIM, Image
from tests._tools.wim._synth import Node, build_wim
from tests._util import absolute_path

SHARED = b"same bytes, different files\n"
LINKED = b"one inode, two paths\n"
SEC_MISMATCH = b"same group, different security records\n"
CROSS_GROUP = b"same content, two hard link identities\n"


def _image() -> Image:
    # same_a/same_b: identical content, no shared identity.
    # pair_a/pair_b: a real hard link group (id 7).
    # bad_a/bad_b: same declared group (id 9) but different entry hashes and security ids.
    # empty.txt / orphan.txt: security ids that must not borrow a neighbour's descriptor.
    root = Node(
        "",
        kind="root",
        security_id=0,
        children=[
            Node("same_a.txt", content=SHARED, security_id=1, creation_time=111),
            Node("same_b.txt", content=SHARED, security_id=2, creation_time=222),
            Node("pair_a.txt", content=LINKED, security_id=3, hard_link=7),
            Node("pair_b.txt", content=LINKED, security_id=3, hard_link=7),
            Node("bad_a.txt", content=b"first variant\n", security_id=3, hard_link=9),
            Node("bad_b.txt", content=b"second variant\n", security_id=4, hard_link=9),
            Node("sec_a.txt", content=SEC_MISMATCH, security_id=1, hard_link=11),
            Node("sec_b.txt", content=SEC_MISMATCH, security_id=2, hard_link=11),
            Node("mix_a.txt", content=CROSS_GROUP, security_id=1, hard_link=12),
            Node("mix_b.txt", content=CROSS_GROUP, security_id=2, hard_link=13),
            Node("empty.txt", content=b"empty security slot\n", security_id=5),
            Node("orphan.txt", content=b"past the security block\n", security_id=9),
        ],
    )
    descriptors = [
        b"\x01\x00\x04\x80root-descriptor",
        b"\x01\x00\x04\x80same-a-descriptor",
        b"\x01\x00\x04\x80same-b-descriptor",
        b"\x01\x00\x04\x80pair-descriptor",
        b"\x01\x00\x04\x80bad-b-descriptor",
        None,
    ]
    return next(WIM(io.BytesIO(build_wim(root, descriptors))).images())


@pytest.fixture()
def view() -> RelationshipView:
    return _image().relationships


def test_view_is_one_record_per_directory_entry(view: RelationshipView) -> None:
    assert [record.path for record in view] == [
        "",
        "same_a.txt",
        "same_b.txt",
        "pair_a.txt",
        "pair_b.txt",
        "bad_a.txt",
        "bad_b.txt",
        "sec_a.txt",
        "sec_b.txt",
        "mix_a.txt",
        "mix_b.txt",
        "empty.txt",
        "orphan.txt",
    ]
    assert view.get("pair_a.txt").entry_offset < view.get("pair_b.txt").entry_offset


def test_shared_content_is_not_a_hard_link(view: RelationshipView) -> None:
    record_a = view.get("same_a.txt")
    record_b = view.get("same_b.txt")

    assert record_a.stream_hashes == record_b.stream_hashes
    assert record_a.hard_link_state == HardLinkState.NONE
    assert record_b.hard_link_state == HardLinkState.NONE
    assert record_a.group_id is None
    assert record_b.group_id is None

    group = next(group for group in view.content_groups if group.hash == record_a.stream_hashes[0])
    assert group.paths == ("same_a.txt", "same_b.txt")
    assert group.crosses_identities
    assert len(group.resources) == 1


def test_per_path_timestamps_survive_shared_content(view: RelationshipView) -> None:
    a = view.get("same_a.txt")
    b = view.get("same_b.txt")

    assert a.stream_hashes == b.stream_hashes
    assert a.creation_time_ns != b.creation_time_ns
    assert a.creation_time_ns == (111 * 100) - 11644473600000000000
    assert b.creation_time_ns == (222 * 100) - 11644473600000000000
    assert a.entry is not b.entry


def test_content_group_carries_resource_table_evidence(view: RelationshipView) -> None:
    group = next(group for group in view.content_groups if group.hash == hashlib.sha1(SHARED).digest())

    assert group.state == ContentState.RESOLVED
    assert group.resources[0].is_metadata is False
    assert group.resources[0].size == len(SHARED)
    assert group.resources[0].hash == hashlib.sha1(SHARED).digest()
    assert group.resources[0].index >= 0


def test_real_hard_link_group_keeps_each_path(view: RelationshipView) -> None:
    group = next(group for group in view.hard_link_groups if group.group_id == 7)

    assert group.state == HardLinkState.LINKED
    assert group.consistent
    assert group.paths == ("pair_a.txt", "pair_b.txt")
    assert len(group.entry_hashes) == 1
    assert group.security_ids == (3,)

    for member in group.members:
        assert member.record.path == member.path
        assert member.record.security_id == 3
        assert member.record.entry_offset >= 0


def test_shared_content_within_one_group_does_not_cross_identities(view: RelationshipView) -> None:
    group = next(group for group in view.content_groups if group.hash == hashlib.sha1(LINKED).digest())

    assert group.paths == ("pair_a.txt", "pair_b.txt")
    assert group.group_ids == (7,)
    assert not group.crosses_identities


def test_conflicting_group_is_kept_as_conflict(view: RelationshipView) -> None:
    group = next(group for group in view.hard_link_groups if group.group_id == 9)

    assert group.state == HardLinkState.CONFLICT
    assert not group.consistent
    assert group.conflicts == ("entry_hash", "content", "security_id")
    assert group.paths == ("bad_a.txt", "bad_b.txt")
    assert {member.record.security_id for member in group.members} == {3, 4}
    assert len(group.entry_hashes) == 2


def test_security_mismatch_within_group_is_a_conflict(view: RelationshipView) -> None:
    group = next(group for group in view.hard_link_groups if group.group_id == 11)

    assert group.state == HardLinkState.CONFLICT
    assert group.conflicts == ("security_id",)
    assert group.paths == ("sec_a.txt", "sec_b.txt")
    assert group.security_ids == (1, 2)

    # Content is genuinely the same, but it is one hard link identity; the security
    # disagreement must not turn it into two content identities.
    content = next(group for group in view.content_groups if group.hash == hashlib.sha1(SEC_MISMATCH).digest())
    assert content.group_ids == (11,)
    assert not content.crosses_identities
    assert content.paths == ("sec_a.txt", "sec_b.txt")


def test_content_shared_by_two_groups_crosses_identities(view: RelationshipView) -> None:
    content = next(group for group in view.content_groups if group.hash == hashlib.sha1(CROSS_GROUP).digest())

    assert content.group_ids == (12, 13)
    assert content.crosses_identities
    assert content.security_ids == (1, 2)

    # Each one-path group remains a separate, single-member declaration.
    for group_id in (12, 13):
        group = next(group for group in view.hard_link_groups if group.group_id == group_id)
        assert group.state == HardLinkState.SINGLE
        assert len(group.members) == 1


def test_group_member_metadata_is_not_deduplicated(view: RelationshipView) -> None:
    group = next(group for group in view.hard_link_groups if group.group_id == 9)
    a, b = group.members

    assert a.record.entry_offset != b.record.entry_offset
    assert a.record.security_id != b.record.security_id
    assert a.record.security.data != b.record.security.data
    assert a.record.entry is not b.record.entry


def test_empty_security_slot_is_not_filled_from_neighbour(view: RelationshipView) -> None:
    record = view.get("empty.txt")

    assert record.security_id == 5
    assert record.security_state == SecurityState.EMPTY
    assert record.security is not None
    assert record.security.is_empty
    assert record.security.data is None
    assert record.security.index == 5


def test_out_of_range_security_id_is_not_filled_from_neighbour(view: RelationshipView) -> None:
    record = view.get("orphan.txt")

    assert record.security_id == 9
    assert record.security_state == SecurityState.OUT_OF_RANGE
    assert record.security is None


def test_security_groups_keep_references_per_path(view: RelationshipView) -> None:
    groups = {group.security_id: group for group in view.security_groups}

    assert groups[3].paths == ("pair_a.txt", "pair_b.txt", "bad_a.txt")
    assert groups[4].paths == ("bad_b.txt",)
    assert groups[5].state == SecurityState.EMPTY
    assert groups[5].security_entry.data is None

    # A reference past the security block stays visible as an unresolved reference; it is
    # not assigned the descriptor of the last real entry.
    assert groups[9].state == SecurityState.OUT_OF_RANGE
    assert groups[9].security_entry is None
    assert groups[9].paths == ("orphan.txt",)

    # Security id 0 is a real reference to the first descriptor, not a sentinel.
    assert "" in groups[0].paths


def test_missing_resource_is_reported_as_unresolved() -> None:
    digest = hashlib.sha1(SHARED).digest()
    root = Node(
        "",
        kind="root",
        children=[Node("missing.txt", content=SHARED)],
    )
    view = next(WIM(io.BytesIO(build_wim(root, [b"descriptor"], omit_content={digest}))).images()).relationships

    record = view.get("missing.txt")
    assert record.stream_hashes == (digest,)
    assert record.streams[0].resource is None

    group = next(group for group in view.content_groups if group.hash == digest)
    assert group.state == ContentState.UNRESOLVED
    assert group.resources == ()


def test_metadata_resource_is_recorded(view: RelationshipView) -> None:
    metadata = view.metadata_resource

    assert metadata is not None
    assert metadata.is_metadata
    assert metadata.hash in {record.hash for record in view.resource_records}
    assert view.get("same_a.txt").entry_offset < metadata.original_size


def test_view_as_dict_has_evidence_tables(view: RelationshipView) -> None:
    data = view.as_dict()

    assert {group["group_id"] for group in data["hard_link_groups"]} == {7, 9, 11, 12, 13}
    assert len(data["directory_entries"]) == len(view)
    assert data["security_entries"][5]["empty"] is True
    assert data["content_groups"]
    assert data["security_groups"][0]["security_id"] == 0
    for entry in data["directory_entries"]:
        assert isinstance(entry["entry_offset"], int)
        assert isinstance(entry["security_id"], int)


def test_untouched_parser_api_still_works() -> None:
    image = _image()

    assert image.get("pair_a.txt").is_file()
    assert image.get("pair_a.txt").open().read() == LINKED
    assert image.security.descriptors[5] == b""
    assert image.security.get(9) is None
    assert image.security.get(3).data == b"\x01\x00\x04\x80pair-descriptor"


@pytest.mark.parametrize("filename", ["basic4k.wim.gz", "basic8k.wim.gz", "basic16k.wim.gz", "basic32k.wim.gz"])
def test_real_sample_relationships(filename: str) -> None:
    with gzip.open(absolute_path(f"_data/wim/{filename}")) as fh:
        view = next(WIM(fh).images()).relationships

    assert len(view) == 6
    assert view.get("file.txt").stream_hashes == (bytes.fromhex("0aaa8266648364d68b67be77c53f708a77fda84c"),)
    assert view.get("file.txt").hard_link_state == HardLinkState.NONE
    assert view.get("link.txt").state == DirectoryEntryState.REPARSE_POINT
    assert view.get("link.txt").hard_link_state == HardLinkState.NOT_APPLICABLE

    # The sample has no real hard links; identical resource hashes are content sharing
    # evidence only, and the metadata entry is not reported as a file.
    assert view.hard_link_groups == ()
    metadata = view.metadata_resource
    assert metadata is not None
    assert metadata.is_metadata
    assert all(record.hard_link_state != HardLinkState.LINKED for record in view)

    # ``file.txt`` and ``dir/another.txt`` share security id 2, which is one descriptor.
    groups = {group.security_id: group for group in view.security_groups}
    assert groups[2].paths == ("file.txt", "dir\\another.txt")
    assert groups[2].security_entry.data

    data = view.as_dict()
    assert data["content_resources"]
