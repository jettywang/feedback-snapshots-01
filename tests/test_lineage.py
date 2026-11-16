from __future__ import annotations

import uuid
from typing import BinaryIO

from dissect.btrfs.btrfs import Btrfs
from dissect.btrfs.c_btrfs import c_btrfs
from dissect.btrfs.lineage import EdgeKind, EdgeStatus, Lineage, RootRecord

UUID_A = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
UUID_B = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
UUID_C = uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")
UUID_D = uuid.UUID("dddddddd-dddd-dddd-dddd-dddddddddddd")
UUID_GONE = uuid.UUID("deadbeef-dead-beef-dead-beefdeadbeef")


def make_root_record(
    objectid: int,
    uuid_: uuid.UUID | None = None,
    parent_uuid: uuid.UUID | None = None,
    received_uuid: uuid.UUID | None = None,
    ctransid: int = 0,
    otransid: int = 0,
    stransid: int = 0,
    rtransid: int = 0,
    generation: int = 1,
    flags: int = 0,
    name: str | None = None,
) -> RootRecord:
    """Build a :class:`RootRecord` from genuine ``btrfs_root_item`` metadata bytes."""
    root_item = c_btrfs.btrfs_root_item(bytearray(len(c_btrfs.btrfs_root_item)))
    root_item.uuid = (uuid_ or uuid.UUID(int=0)).bytes
    root_item.parent_uuid = (parent_uuid or uuid.UUID(int=0)).bytes
    root_item.received_uuid = (received_uuid or uuid.UUID(int=0)).bytes
    root_item.ctransid = ctransid
    root_item.otransid = otransid
    root_item.stransid = stransid
    root_item.rtransid = rtransid
    root_item.generation = generation
    root_item.flags = flags
    return RootRecord.from_root_item(objectid, c_btrfs.btrfs_root_item(root_item.dumps()), name)


def test_root_record_preserves_metadata_fields() -> None:
    record = make_root_record(
        256,
        uuid_=UUID_A,
        parent_uuid=UUID_B,
        received_uuid=UUID_C,
        ctransid=11,
        otransid=7,
        stransid=5,
        rtransid=9,
        generation=13,
        flags=0x1,
        name="some-name",
    )
    assert record.objectid == 256
    assert record.uuid == UUID_A
    assert record.parent_uuid == UUID_B
    assert record.received_uuid == UUID_C
    assert (record.ctransid, record.otransid, record.stransid, record.rtransid) == (11, 7, 5, 9)
    assert record.generation == 13
    assert record.flags == 0x1
    assert record.name == "some-name"


def test_root_record_absent_uuids() -> None:
    record = make_root_record(5)
    assert record.uuid is None
    assert record.parent_uuid is None
    assert record.received_uuid is None


def test_lineage_local_snapshot() -> None:
    parent = make_root_record(256, uuid_=UUID_A, name="data")
    snapshot = make_root_record(257, uuid_=UUID_B, parent_uuid=UUID_A, otransid=42, name="data-snapshot")
    view = Lineage([parent, snapshot])

    edges = view.edges_for(257)
    assert len(edges) == 1
    edge = edges[0]
    assert edge.kind is EdgeKind.SNAPSHOT
    assert edge.status is EdgeStatus.RESOLVED
    assert edge.resolved
    assert edge.claimed_uuid == UUID_A
    assert edge.targets == (256,)
    assert view.edges_for(256) == []


def test_lineage_received_copy() -> None:
    source = make_root_record(256, uuid_=UUID_A, name="data")
    received = make_root_record(
        300, uuid_=UUID_C, received_uuid=UUID_A, stransid=8, rtransid=20, name="data-backup"
    )
    view = Lineage([source, received])

    edges = view.edges_for(300)
    assert len(edges) == 1
    edge = edges[0]
    assert edge.kind is EdgeKind.RECEIVED
    assert edge.status is EdgeStatus.RESOLVED
    assert edge.targets == (256,)

    # A receive claim is not a local snapshot claim, even when it resolves locally
    assert edge.kind is not EdgeKind.SNAPSHOT


def test_lineage_missing_parent_keeps_claim() -> None:
    orphan = make_root_record(257, uuid_=UUID_B, parent_uuid=UUID_GONE, otransid=42, name="data-snapshot")
    view = Lineage([orphan])

    (edge,) = view.edges_for(257)
    assert edge.kind is EdgeKind.SNAPSHOT
    assert edge.status is EdgeStatus.DANGLING
    assert not edge.resolved
    assert edge.targets == ()
    # The original claim is preserved verbatim
    assert edge.claimed_uuid == UUID_GONE
    assert view.records[257].parent_uuid == UUID_GONE


def test_lineage_incomplete_receive_record_keeps_claim() -> None:
    received = make_root_record(300, uuid_=UUID_C, received_uuid=UUID_GONE, stransid=8, rtransid=20)
    view = Lineage([received])

    (edge,) = view.edges_for(300)
    assert edge.kind is EdgeKind.RECEIVED
    assert edge.status is EdgeStatus.DANGLING
    assert edge.claimed_uuid == UUID_GONE
    assert edge.targets == ()


def test_lineage_identifier_conflict_is_candidate_only() -> None:
    first = make_root_record(256, uuid_=UUID_A, name="data")
    second = make_root_record(400, uuid_=UUID_A, name="data-copy")
    snapshot = make_root_record(257, uuid_=UUID_B, parent_uuid=UUID_A)
    view = Lineage([first, second, snapshot])

    (edge,) = view.edges_for(257)
    assert edge.status is EdgeStatus.CANDIDATE
    assert not edge.resolved
    assert edge.targets == (256, 400)


def test_lineage_same_name_is_not_identity() -> None:
    first = make_root_record(256, uuid_=UUID_A, name="data")
    second = make_root_record(257, uuid_=UUID_B, name="data")
    view = Lineage([first, second])

    # Identical names must not create any relation
    assert view.edges == []
    assert view.edges_for(256) == []
    assert view.edges_for(257) == []


def test_lineage_report_marks_candidate_and_dangling_edges() -> None:
    records = [
        make_root_record(256, uuid_=UUID_A, name="data"),
        make_root_record(400, uuid_=UUID_A, name="data-copy"),
        make_root_record(257, uuid_=UUID_B, parent_uuid=UUID_A, name="data-snapshot"),
        make_root_record(300, uuid_=UUID_C, received_uuid=UUID_GONE, stransid=8, rtransid=20),
        make_root_record(301, uuid_=UUID_D, parent_uuid=UUID_GONE),
    ]
    report = Lineage(records).report()

    assert "root 256" in report
    assert f"uuid {UUID_A}" in report
    assert "candidate only" in report
    assert "256, 400" in report
    assert "dangling" in report
    assert str(UUID_GONE) in report
    assert "received from send-side source" in report
    assert "local snapshot of" in report
    assert "never by name" in report


def test_btrfs_lineage_snapshot_image(btrfs_subvolume_snapshot: BinaryIO) -> None:
    fs = Btrfs(btrfs_subvolume_snapshot)
    view = fs.lineage()

    # Internal trees are not subvolumes and must not appear
    assert set(view.records) == {5, 256, 257}

    fs_tree = view.records[5]
    assert fs_tree.uuid == uuid.UUID("9d52ca28-1a1f-458c-ab8c-de2455086a2e")
    assert fs_tree.name is None

    source = view.records[256]
    assert source.uuid == uuid.UUID("52d98098-5a3c-4d4a-8024-043c68c3ddb1")
    assert source.parent_uuid is None
    assert source.received_uuid is None
    assert source.name == "subvol"
    assert source.ctransid == 16
    assert source.otransid == 8

    snapshot = view.records[257]
    assert snapshot.parent_uuid == source.uuid
    assert snapshot.received_uuid is None
    assert snapshot.name == "subvol-snapshot"
    assert snapshot.ctransid == 17
    assert snapshot.otransid == 14

    (edge,) = view.edges_for(257)
    assert edge.kind is EdgeKind.SNAPSHOT
    assert edge.status is EdgeStatus.RESOLVED
    assert edge.targets == (256,)

    assert view.edges_for(256) == []
    assert view.edges_for(5) == []
