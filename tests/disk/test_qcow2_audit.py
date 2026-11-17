from __future__ import annotations

import gzip
import io
import struct

import pytest

from dissect.hypervisor.disk.c_qcow2 import QCOW2_MAGIC, c_qcow2
from dissect.hypervisor.disk.qcow2 import QCow2
from dissect.hypervisor.disk.qcow2_audit import (
    ClusterKind,
    Occupancy,
    RefcountTable,
    audit,
    render_text,
)
from dissect.hypervisor.exceptions import Error
from tests._util import absolute_path

CLUSTER_BITS = 9
CLUSTER_SIZE = 1 << CLUSTER_BITS
VIRTUAL_SIZE = 64 * CLUSTER_SIZE

COPIED = c_qcow2.QCOW_OFLAG_COPIED
COMPRESSED = c_qcow2.QCOW_OFLAG_COMPRESSED

# Fixed cluster layout of the synthetic images
CLUSTER_REFCOUNT_TABLE = 1
CLUSTER_REFCOUNT_BLOCK = 2
CLUSTER_L1 = 3
CLUSTER_L2 = 4


def pack_refcount_block(values: dict[int, int], width: int) -> bytes:
    """Pack refcount entries MSB-first into a single refcount block."""
    if not values:
        return bytes(CLUSTER_SIZE)
    count = max(values) + 1
    acc = 0
    for index in range(count):
        acc = (acc << width) | values.get(index, 0)
    acc <<= CLUSTER_SIZE * 8 - count * width
    return acc.to_bytes(CLUSTER_SIZE, "big")


def pack_l2(entries: dict[int, int]) -> bytes:
    table = bytearray(CLUSTER_SIZE)
    for index, value in entries.items():
        struct.pack_into(">Q", table, index * 8, value)
    return bytes(table)


def normal_entry(cluster: int, *, copied: bool = True) -> int:
    return (COPIED if copied else 0) | (cluster << CLUSTER_BITS)


def compressed_entry(offset: int, nb_csectors: int) -> int:
    csize_shift = 62 - (CLUSTER_BITS - 8)
    return COMPRESSED | offset | ((nb_csectors - 1) << csize_shift)


def build_image(
    *,
    refcount_order: int = 4,
    refcounts: dict[int, int] | None = None,
    active_l2: dict[int, int] | None = None,
    snapshots: list[tuple[str, str, dict[int, int]]] | None = None,
) -> io.BytesIO:
    """Build a tiny synthetic QCOW2 image with a single refcount block and one L1/L2 pair per root."""
    refcounts = refcounts or {}
    active_l2 = active_l2 or {}
    snapshots = snapshots or []

    clusters: dict[int, bytes] = {}

    refcount_table = bytearray(CLUSTER_SIZE)
    struct.pack_into(">Q", refcount_table, 0, CLUSTER_REFCOUNT_BLOCK * CLUSTER_SIZE)
    clusters[CLUSTER_REFCOUNT_TABLE] = bytes(refcount_table)
    clusters[CLUSTER_REFCOUNT_BLOCK] = pack_refcount_block(refcounts, 1 << refcount_order)

    clusters[CLUSTER_L1] = struct.pack(">Q", CLUSTER_L2 * CLUSTER_SIZE) + bytes(CLUSTER_SIZE - 8)
    clusters[CLUSTER_L2] = pack_l2(active_l2)

    next_cluster = 5
    snapshot_blob = b""
    for snap_id, snap_name, snap_l2 in snapshots:
        l1_cluster = next_cluster
        l2_cluster = next_cluster + 1
        next_cluster += 2
        clusters[l1_cluster] = struct.pack(">Q", l2_cluster * CLUSTER_SIZE) + bytes(CLUSTER_SIZE - 8)
        clusters[l2_cluster] = pack_l2(snap_l2)
        header = c_qcow2.QCowSnapshotHeader(
            l1_table_offset=l1_cluster * CLUSTER_SIZE,
            l1_size=1,
            id_str_size=len(snap_id),
            name_size=len(snap_name),
        )
        entry = header.dumps() + snap_id.encode() + snap_name.encode()
        snapshot_blob += entry + bytes(-len(entry) % 8)

    snapshots_offset = 0
    if snapshots:
        snapshots_offset = next_cluster * CLUSTER_SIZE
        clusters[next_cluster] = snapshot_blob.ljust(CLUSTER_SIZE, b"\x00")
        next_cluster += 1

    referenced_clusters = []
    for l2 in [active_l2, *(snap[2] for snap in snapshots)]:
        for entry in l2.values():
            if entry & COMPRESSED:
                referenced_clusters.append((entry & ((1 << 61) - 1)) >> CLUSTER_BITS)
            elif entry & c_qcow2.L2E_OFFSET_MASK:
                referenced_clusters.append((entry & c_qcow2.L2E_OFFSET_MASK) >> CLUSTER_BITS)

    total = max([next_cluster, *refcounts, *referenced_clusters]) + 1
    image = bytearray(total * CLUSTER_SIZE)
    for cluster, data in clusters.items():
        image[cluster * CLUSTER_SIZE : (cluster + 1) * CLUSTER_SIZE] = data

    header = c_qcow2.QCowHeader(
        magic=QCOW2_MAGIC,
        version=3,
        cluster_bits=CLUSTER_BITS,
        size=VIRTUAL_SIZE,
        l1_size=1,
        l1_table_offset=CLUSTER_L1 * CLUSTER_SIZE,
        refcount_table_offset=CLUSTER_REFCOUNT_TABLE * CLUSTER_SIZE,
        refcount_table_clusters=1,
        nb_snapshots=len(snapshots),
        snapshots_offset=snapshots_offset,
        refcount_order=refcount_order,
        header_length=104,
    )
    image[0 : len(header.dumps())] = header.dumps()
    return io.BytesIO(bytes(image))


def finding_for(report, cluster: int):
    for finding in report.findings:
        if finding.cluster == cluster:
            return finding
    raise AssertionError(f"no finding for cluster {cluster}")


@pytest.mark.parametrize(
    ("refcount_order", "width"),
    [(0, 1), (1, 2), (2, 4), (4, 16), (5, 32), (6, 64)],
)
def test_refcount_widths(refcount_order: int, width: int) -> None:
    max_value = (1 << width) - 1
    values = {0: 1, 5: min(7, max_value), 63: max_value}
    fh = build_image(refcount_order=refcount_order, refcounts=values)
    table = RefcountTable(QCow2(fh))

    assert table.width == width
    for cluster, value in values.items():
        assert table.get(cluster) == value

    location = table.locate(5)
    assert location.table_index == 0
    assert location.block_offset == CLUSTER_REFCOUNT_BLOCK * CLUSTER_SIZE
    assert location.block_index == 5
    assert location.byte_offset == (5 * width) // 8
    assert location.bit_offset == (5 * width) % 8
    assert location.width == width

    # Out-of-range clusters have no refcount
    assert table.get(10_000_000) == 0
    assert table.locate(10_000_000).block_offset is None


def test_metadata_clusters() -> None:
    fh = build_image(refcounts={0: 1, 1: 1, 2: 1, 3: 1, 4: 1})
    report = audit(QCow2(fh))

    for cluster, entry in [
        (0, "header"),
        (CLUSTER_REFCOUNT_TABLE, "refcount table"),
        (CLUSTER_REFCOUNT_BLOCK, "refcount block"),
        (CLUSTER_L1, "L1 table"),
        (CLUSTER_L2, "L2 table"),
    ]:
        finding = finding_for(report, cluster)
        assert finding.occupancy == Occupancy.EXCLUSIVE
        assert all(reference.kind == ClusterKind.METADATA for reference in finding.references)
        assert any(entry in reference.entry for reference in finding.references)


def test_exclusive_occupancy() -> None:
    fh = build_image(
        refcounts={0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 6: 1},
        active_l2={0: normal_entry(6)},
    )
    report = audit(QCow2(fh))

    finding = finding_for(report, 6)
    assert finding.occupancy == Occupancy.EXCLUSIVE
    assert finding.refcount == 1
    assert len(finding.references) == 1
    reference = finding.references[0]
    assert reference.kind == ClusterKind.DATA
    assert reference.root == "active"
    assert "L2[0]" in reference.entry
    # Traceable back to the exact refcount bits
    assert finding.location.block_offset == CLUSTER_REFCOUNT_BLOCK * CLUSTER_SIZE
    assert finding.location.block_index == 6
    assert finding.location.width == 16


def test_shared_occupancy_with_snapshot() -> None:
    fh = build_image(
        refcounts={0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 9: 2},
        active_l2={0: normal_entry(9)},
        snapshots=[("1", "snap", {0: normal_entry(9, copied=False)})],
    )
    report = audit(QCow2(fh), snapshots=["1"])

    assert report.coverage_complete
    assert report.roots_traversed == ["active", "snapshot:1"]

    finding = finding_for(report, 9)
    assert finding.occupancy == Occupancy.SHARED
    assert finding.refcount == 2
    assert {reference.root for reference in finding.references} == {"active", "snapshot:1"}


def test_contradictory_occupancy() -> None:
    fh = build_image(
        refcounts={0: 1, 1: 1, 2: 1, 3: 1, 4: 1},
        active_l2={0: normal_entry(6)},
    )
    report = audit(QCow2(fh))

    finding = finding_for(report, 6)
    assert finding.occupancy == Occupancy.CONTRADICTORY
    # Both sides of the evidence are reported: the referencing entry and the zero refcount bits
    assert len(finding.references) == 1
    assert "L2[0]" in finding.references[0].entry
    assert finding.refcount == 0
    assert finding.location.block_offset == CLUSTER_REFCOUNT_BLOCK * CLUSTER_SIZE
    assert any("refcount is 0" in note for note in finding.notes)


def test_contradictory_occupancy_one_bit_refcounts() -> None:
    # A 1-bit packed refcount table can still show exclusive vs contradictory occupancy
    fh = build_image(
        refcount_order=0,
        refcounts={0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 6: 1},
        active_l2={0: normal_entry(6), 1: normal_entry(7)},
    )
    report = audit(QCow2(fh))

    assert report.refcount_width == 1
    assert finding_for(report, 6).occupancy == Occupancy.EXCLUSIVE
    contradictory = finding_for(report, 7)
    assert contradictory.occupancy == Occupancy.CONTRADICTORY
    assert contradictory.location.width == 1
    assert contradictory.location.byte_offset == 0
    assert contradictory.location.bit_offset == 7


def test_coverage_limit_for_untraversed_snapshot() -> None:
    fh = build_image(
        refcounts={0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 9: 1},
        snapshots=[("1", "snap", {0: normal_entry(9)})],
    )

    report = audit(QCow2(fh))
    assert not report.coverage_complete
    assert report.roots_untraversed == ["snapshot:1"]

    finding = finding_for(report, 9)
    assert finding.occupancy == Occupancy.UNACCOUNTED
    assert any("coverage is limited" in note for note in finding.notes)

    fh.seek(0)
    report = audit(QCow2(fh), snapshots=["1"])
    assert report.coverage_complete
    assert finding_for(report, 9).occupancy == Occupancy.EXCLUSIVE


def test_unreferenced_cluster_full_coverage() -> None:
    fh = build_image(refcounts={0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 9: 1})
    report = audit(QCow2(fh))

    finding = finding_for(report, 9)
    assert finding.occupancy == Occupancy.UNREFERENCED
    assert finding.references == []


def test_compressed_range() -> None:
    # Compressed data at cluster 6 spanning into cluster 7
    fh = build_image(
        refcounts={0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 6: 1, 7: 1},
        active_l2={0: compressed_entry(6 * CLUSTER_SIZE, 2)},
    )
    report = audit(QCow2(fh))

    for cluster in (6, 7):
        finding = finding_for(report, cluster)
        assert finding.occupancy == Occupancy.EXCLUSIVE
        assert finding.references[0].kind == ClusterKind.COMPRESSED
        assert "L2[0]" in finding.references[0].entry


def test_copied_bit_is_only_a_hint() -> None:
    # Copied bit claims exclusivity, but the refcount says otherwise: the refcount wins
    fh = build_image(
        refcounts={0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1, 7: 1, 9: 2},
        active_l2={0: normal_entry(9, copied=True)},
        snapshots=[("1", "snap", {0: normal_entry(9, copied=False)})],
    )
    report = audit(QCow2(fh), snapshots=["1"])

    finding = finding_for(report, 9)
    assert finding.occupancy == Occupancy.SHARED
    assert any("copied bit set" in note and "hint only" in note for note in finding.notes)


def test_unknown_snapshot_id() -> None:
    fh = build_image(refcounts={0: 1, 1: 1, 2: 1, 3: 1, 4: 1})
    with pytest.raises(Error, match="Unknown snapshot id"):
        audit(QCow2(fh), snapshots=["nope"])


def test_audit_is_read_only() -> None:
    class GuardedBytesIO(io.BytesIO):
        def write(self, *args, **kwargs):
            raise AssertionError("audit wrote to the image")

    fh = build_image(
        refcounts={0: 1, 1: 1, 2: 1, 3: 1, 4: 1, 6: 1},
        active_l2={0: normal_entry(6)},
    )
    guarded = GuardedBytesIO(fh.getvalue())
    report = audit(QCow2(guarded))
    assert finding_for(report, 6).occupancy == Occupancy.EXCLUSIVE


def test_render_text() -> None:
    fh = build_image(
        refcounts={0: 1, 1: 1, 2: 1, 3: 1, 4: 1},
        active_l2={0: normal_entry(6)},
    )
    report = audit(QCow2(fh))
    output = render_text(report)

    assert "refcount width: 16 bits" in output
    assert "contradictory" in output
    assert "cluster 6" in output
    assert "refcount bits:" in output
    assert "L2[0]" in output


def test_audit_real_image() -> None:
    with gzip.open(absolute_path("_data/disk/qcow2/snapshot.qcow2.gz"), "rb") as fh:
        qcow2 = QCow2(fh)
        assert qcow2.header.refcount_order == 4

        report = audit(qcow2, snapshots=["1", "2"])
        assert report.coverage_complete
        assert report.refcount_width == 16
        assert report.clusters_examined > 0

        kinds = {reference.kind for finding in report.findings for reference in finding.references}
        assert ClusterKind.METADATA in kinds
        assert ClusterKind.DATA in kinds

        # Every finding must be traceable to refcount bits inside the file
        for finding in report.findings:
            assert finding.location.block_offset is not None

        # A clean image has no contradictions or leaks
        assert Occupancy.CONTRADICTORY not in report.summary()
        assert Occupancy.UNREFERENCED not in report.summary()

        fh.seek(0)
        qcow2 = QCow2(fh)
        partial = audit(qcow2, snapshots=["1"])
        assert not partial.coverage_complete
        assert partial.roots_untraversed == ["snapshot:2"]
