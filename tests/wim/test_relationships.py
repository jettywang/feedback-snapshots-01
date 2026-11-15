from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from dissect.archive.wim.c_wim import FILE_ATTRIBUTE, NO_SECURITY_DESC
from dissect.archive.wim.wim import ContentReferenceStatus, HardlinkAnomaly, SecurityReferenceStatus
from tests._tools.wim._synth import ImageSpec, Node, build_wim, build_wim_images, load

if TYPE_CHECKING:
    from dissect.archive.wim.wim import WIM, ImageRelationships

SHARED = b"same bytes, different identities"
LINKED = b"one file, two names"
OTHER = b"an unrelated file"

CONTENTS = {
    hashlib.sha1(SHARED).digest(): SHARED,
    hashlib.sha1(LINKED).digest(): LINKED,
    hashlib.sha1(OTHER).digest(): OTHER,
}

ROOT = Node(
    "",
    attributes=FILE_ATTRIBUTE.DIRECTORY,
    security_id=NO_SECURITY_DESC,
    children=[
        # Two independent files with identical content. Same hash, different directory entries.
        Node("shared_a.txt", security_id=2, streams={"": SHARED}),
        Node("shared_b.txt", security_id=1, streams={"": SHARED}),
        # A real hardlink pair: same HardLink id, same content resource.
        Node("link_a.txt", security_id=4, hard_link=0x1234, streams={"": LINKED}),
        Node("link_b.txt", security_id=4, hard_link=0x1234, streams={"": LINKED}),
        # A group id claimed once, and pointing at a different content resource.
        Node("odd_one.txt", security_id=3, hard_link=0x4242, streams={"": OTHER}),
        # A contradictory group: same id, different security id, no content.
        Node("empty_a.txt", security_id=0, hard_link=0x5151, streams={}),
        Node("empty_b.txt", security_id=1, hard_link=0x5151, streams={}),
        # A group id shared by two entries that do not reference the same content.
        Node("mixed_a.txt", security_id=3, hard_link=0x6161, streams={"": SHARED}),
        Node("mixed_b.txt", security_id=3, hard_link=0x6161, streams={"": OTHER}),
    ],
)

# Slot 1 is empty on purpose: a zero-length descriptor must not shift later indices.
SECURITY_DESCRIPTORS = [b"descriptor zero", None, b"descriptor two", b"descriptor three", b"descriptor four"]


@pytest.fixture
def wim() -> WIM:
    return load(build_wim(ROOT, SECURITY_DESCRIPTORS))


@pytest.fixture
def relationships(wim: WIM) -> ImageRelationships:
    return next(wim.relationships())


def test_shared_content_does_not_create_hardlinks(relationships: ImageRelationships) -> None:
    records = {record.path: record for record in relationships.entries}
    assert records["shared_a.txt"].hardlink_id == 0
    assert records["shared_b.txt"].hardlink_id == 0
    assert records["shared_a.txt"].hardlink_group is None
    assert records["shared_b.txt"].hardlink_group is None

    content_hash = hashlib.sha1(SHARED).digest()
    resource = relationships.content_resources[content_hash]
    assert resource.is_shared
    assert resource.paths == ["shared_a.txt", "shared_b.txt", "mixed_a.txt"]
    assert resource.resource_indices == [records["shared_a.txt"].content[0].resource_index]

    # Both directory entries are preserved with their own security reference.
    assert records["shared_a.txt"].security_id == 2
    assert records["shared_a.txt"].security.descriptor == b"descriptor two"
    assert records["shared_b.txt"].security_id == 1
    assert records["shared_b.txt"].security.status is SecurityReferenceStatus.EMPTY
    assert records["shared_b.txt"].security.descriptor is None


def test_real_hardlink_group(relationships: ImageRelationships) -> None:
    group = relationships.hardlink_groups[0x1234]
    assert [member.path for member in group.members] == ["link_a.txt", "link_b.txt"]
    assert group.security_ids == {4}
    assert group.content_hashes == {hashlib.sha1(LINKED).digest()}
    assert group.is_consistent

    for member in group.members:
        assert member.security.descriptor == b"descriptor four"
        assert member.content[0].status is ContentReferenceStatus.RESOLVED
        assert member.content[0].resource.index is not None


def test_group_identifier_conflict_is_not_merged_by_content(relationships: ImageRelationships) -> None:
    group = relationships.hardlink_groups[0x4242]
    assert [member.path for member in group.members] == ["odd_one.txt"]
    assert HardlinkAnomaly.SINGLE_MEMBER in group.anomalies
    assert not group.is_consistent

    content_hash = hashlib.sha1(OTHER).digest()
    other = relationships.content_resources[content_hash]
    assert other.is_shared
    assert other.paths == ["odd_one.txt", "mixed_b.txt"]


def test_group_content_conflict_keeps_both_entries(relationships: ImageRelationships) -> None:
    group = relationships.hardlink_groups[0x6161]
    assert [member.path for member in group.members] == ["mixed_a.txt", "mixed_b.txt"]
    assert group.content_hashes == {hashlib.sha1(SHARED).digest(), hashlib.sha1(OTHER).digest()}
    assert HardlinkAnomaly.CONTENT_CONFLICT in group.anomalies
    assert group.security_ids == {3}
    assert not group.is_consistent

    # Both paths remain first-class content references instead of being collapsed into one.
    assert relationships.content_resources[hashlib.sha1(SHARED).digest()].paths == [
        "shared_a.txt",
        "shared_b.txt",
        "mixed_a.txt",
    ]
    assert relationships.content_resources[hashlib.sha1(OTHER).digest()].paths == ["odd_one.txt", "mixed_b.txt"]


def test_group_security_conflict_keeps_each_entry(relationships: ImageRelationships) -> None:
    group = relationships.hardlink_groups[0x5151]
    assert [member.path for member in group.members] == ["empty_a.txt", "empty_b.txt"]
    assert group.security_ids == {0, 1}
    assert HardlinkAnomaly.SECURITY_ID_CONFLICT in group.anomalies
    assert HardlinkAnomaly.SECURITY_UNRESOLVED in group.anomalies

    records = {record.path: record for record in relationships.entries}
    assert records["empty_a.txt"].security.status is SecurityReferenceStatus.RESOLVED
    assert records["empty_a.txt"].security.descriptor == b"descriptor zero"
    assert records["empty_b.txt"].security.status is SecurityReferenceStatus.EMPTY
    assert records["empty_b.txt"].security.descriptor is None


def test_security_references_preserve_table_indices(relationships: ImageRelationships) -> None:
    references = {reference.path: reference for reference in relationships.security_references}

    # Slot 1 is an empty placeholder. Entries after it must resolve their own indices, not shift.
    assert references["shared_b.txt"].index == 1
    assert references["shared_b.txt"].status is SecurityReferenceStatus.EMPTY
    assert references["shared_b.txt"].offset is not None

    assert references["shared_a.txt"].index == 2
    assert references["shared_a.txt"].descriptor == b"descriptor two"
    assert references["odd_one.txt"].index == 3
    assert references["odd_one.txt"].descriptor == b"descriptor three"

    # The synthetic table has five slots. An out-of-range id must not borrow descriptor four.
    extra = Node("beyond.txt", security_id=5, streams={"": b"beyond"})
    built = build_wim(
        Node("", attributes=FILE_ATTRIBUTE.DIRECTORY, children=[extra]),
        SECURITY_DESCRIPTORS,
    )
    beyond = next(load(built).relationships()).get("beyond.txt")
    assert beyond.security.status is SecurityReferenceStatus.OUT_OF_RANGE
    assert beyond.security.descriptor is None
    assert beyond.security.index == 5


def test_entry_records_keep_paths_and_metadata(relationships: ImageRelationships) -> None:
    assert sorted(record.path for record in relationships.entries) == [
        "",
        "empty_a.txt",
        "empty_b.txt",
        "link_a.txt",
        "link_b.txt",
        "mixed_a.txt",
        "mixed_b.txt",
        "odd_one.txt",
        "shared_a.txt",
        "shared_b.txt",
    ]

    record = relationships.get("link_b.txt")
    assert record.entry.name == "link_b.txt"
    assert record.entry.offset != relationships.get("link_a.txt").entry.offset
    assert record.content[0].hash == hashlib.sha1(LINKED).digest()


def test_metadata_resource_evidence(wim: WIM, relationships: ImageRelationships) -> None:
    assert relationships.metadata_hash is not None
    assert relationships.metadata_resource_index is not None
    metadata = wim.resource_entries[relationships.metadata_resource_index]
    assert metadata.is_metadata
    assert metadata.hash == relationships.metadata_hash

    # Every resolved content reference must point at a table row and be readable.
    for resource in relationships.content_resources.values():
        for reference in resource.references:
            assert reference.resource_index is not None
            assert reference.resource.hash == reference.hash
            with reference.resource.open() as fh:
                assert fh.read() == CONTENTS[reference.hash]


def test_hardlink_groups_are_scoped_to_one_image() -> None:
    first = Node("", attributes=FILE_ATTRIBUTE.DIRECTORY, children=[Node("a.txt", security_id=0, hard_link=7)])
    second = Node("", attributes=FILE_ATTRIBUTE.DIRECTORY, children=[Node("a.txt", security_id=0, hard_link=7)])
    wim = load(build_wim_images([ImageSpec(first, [b"first image"]), ImageSpec(second, [b"second image"])]))

    views = list(wim.relationships())
    assert len(views) == 2

    for view in views:
        group = view.hardlink_groups[7]
        assert [member.path for member in group.members] == ["a.txt"]
        assert HardlinkAnomaly.SINGLE_MEMBER in group.anomalies
        assert group.members[0].security.descriptor in (b"first image", b"second image")

    # Same identifier, different directory entries and different image security tables.
    assert views[0].entries[1].entry is not views[1].entries[1].entry
    assert views[0].entries[1].security.descriptor != views[1].entries[1].security.descriptor


def test_same_hash_across_images_is_shared_content_not_identity() -> None:
    first = Node("", attributes=FILE_ATTRIBUTE.DIRECTORY, children=[Node("a.txt", streams={"": SHARED})])
    second = Node("", attributes=FILE_ATTRIBUTE.DIRECTORY, children=[Node("b.txt", streams={"": SHARED})])
    wim = load(build_wim_images([ImageSpec(first), ImageSpec(second)]))

    digest = hashlib.sha1(SHARED).digest()
    rows = [resource for resource in wim.resource_entries if resource.hash == digest]
    assert len(rows) == 1

    for view in wim.relationships():
        assert view.hardlink_groups == {}
        content = view.content_resources[digest]
        assert content.paths == [view.entries[1].path]
        assert not content.is_shared


def test_missing_resource_is_kept_as_unresolved_reference() -> None:
    ghost_hash = bytes.fromhex("11" * 20)
    root = Node(
        "",
        attributes=FILE_ATTRIBUTE.DIRECTORY,
        children=[
            Node("ghost.txt", streams={"": b"bytes without a resource row"}, stream_hashes={"": ghost_hash}),
            Node("real.txt", streams={"": SHARED}),
        ],
    )
    view = next(load(build_wim(root, [])).relationships())

    ghost = view.get("ghost.txt")
    assert ghost.content[0].status is ContentReferenceStatus.MISSING
    assert ghost.content[0].resource is None
    assert ghost.content[0].resource_index is None

    # The missing hash still appears as a content key, but only with its unresolved reference.
    resource = view.content_resources[ghost_hash]
    assert resource.resources == []
    assert resource.resource_indices == []
    assert resource.paths == ["ghost.txt"]
    assert not resource.is_shared

    # A real neighbouring resource is unaffected by the unresolved one.
    assert view.get("real.txt").content[0].status is ContentReferenceStatus.RESOLVED
