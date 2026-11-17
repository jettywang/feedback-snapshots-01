from __future__ import annotations

import io
import random
from dataclasses import dataclass, field

import pytest

from dissect.hypervisor.disk.c_qcow2 import QCOW2_MAGIC, c_qcow2
from dissect.hypervisor.disk.qcow2 import QCow2, QCow2Stream
from dissect.hypervisor.exceptions import Error

QCOW_OFLAG_ZERO = c_qcow2.QCOW_OFLAG_ZERO

CLUSTER_BITS = 9
CLUSTER_SIZE = 1 << CLUSTER_BITS  # 512 bytes, small enough to keep the fixture tiny
L2_BITS = CLUSTER_BITS - 3  # 8 byte L2 entries -> 64 entries per L2 table
L2_ENTRIES = 1 << L2_BITS
# Virtual geometry: 2 L1 entries, each covering 64 clusters
ACTIVE_DISK_SIZE = 2 * L2_ENTRIES * CLUSTER_SIZE
# snap-two declares a smaller disk that still reaches into its forked L2 region
SNAP2_DISK_SIZE = 69 * CLUSTER_SIZE

# Logical cluster states for the independent reference disk model
UNALLOCATED = "unallocated"
ZERO = "zero"
DATA = "data"


def l2_entry(offset: int) -> int:
    return offset & c_qcow2.L2E_OFFSET_MASK


def data_pattern(view: str, cluster: int) -> bytes:
    # Deterministic, non-zero fill: avoids relying on PYTHONHASHSEED and never emits a zero byte
    seed = (sum(view.encode()) + cluster * 31) & 0xFF or 0x01
    return bytes([seed]) * CLUSTER_SIZE


@dataclass
class LogicalDisk:
    """Reference model of what a single view should expose, independent of QCow2 parsing."""

    size: int
    clusters: dict[int, str] = field(default_factory=dict)
    data: dict[int, bytes] = field(default_factory=dict)
    name: str = "model"

    def read(self, offset: int, length: int) -> bytes:
        result = bytearray()
        end = min(offset + length, self.size)
        for pos in range(offset, end):
            cluster = pos // CLUSTER_SIZE
            state = self.clusters.get(cluster, UNALLOCATED)
            if state == DATA:
                result.append(self.data[cluster][pos % CLUSTER_SIZE])
            else:
                result.append(0)
        return bytes(result)


class Qcow2Builder:
    """Minimal, explicit QCOW2 (v3) image builder with internal snapshots.

    Every metadata table and data cluster is placed and written by this class, so the
    resulting image exercises distinct L1 roots, shared and forked L2 tables, explicit
    zero / unallocated / data clusters, legacy snapshot extra data and declared disk sizes.
    """

    def __init__(self) -> None:
        self.buf = bytearray()

    def allocate(self, payload: bytes) -> int:
        assert len(payload) % CLUSTER_SIZE == 0
        # Host offset 0 means "unallocated" in QCOW2, so reserve the first cluster
        if not self.buf:
            self.buf.extend(b"\x00" * CLUSTER_SIZE)
        offset = len(self.buf)
        assert offset % CLUSTER_SIZE == 0
        self.buf.extend(payload)
        return offset

    def write_u64_table(self, entries: list[int]) -> int:
        payload = b"".join(c_qcow2.uint64.dumps(entry) for entry in entries)
        return self.allocate(payload.ljust(CLUSTER_SIZE, b"\x00"))

    def build_snapshot_entry(
        self,
        snapshot_id: str,
        name: str,
        l1_offset: int,
        l1_size: int,
        disk_size: int,
        *,
        legacy_extra: bool = False,
    ) -> bytes:
        id_bytes = snapshot_id.encode()
        name_bytes = name.encode()

        if legacy_extra:
            # Version 2 style snapshots carry no extra data block at all
            extra = b""
        else:
            extra = c_qcow2.QCowSnapshotExtraData(
                vm_state_size_large=0,
                disk_size=disk_size,
                icount=0,
            ).dumps()

        header = c_qcow2.QCowSnapshotHeader(
            l1_table_offset=l1_offset,
            l1_size=l1_size,
            id_str_size=len(id_bytes),
            name_size=len(name_bytes),
            date_sec=0,
            date_nsec=0,
            vm_clock_nsec=0,
            vm_state_size=0,
            extra_data_size=len(extra),
        ).dumps()

        entry = header + extra + id_bytes + name_bytes
        padding = (-len(entry)) % 8
        return entry + b"\x00" * padding

    def build(
        self,
        *,
        active_size: int = ACTIVE_DISK_SIZE,
        snapshots_offset: int | None = None,
        nb_snapshots: int | None = None,
        snap1_l1_entries: int = 2,
    ) -> bytes:
        # --- L2 tables -------------------------------------------------------------------
        # L2A (logical clusters 0-63): a single table shared by both snapshot L1 roots
        # L2B (logical clusters 64-127): a forked, private table per view
        shared_l2 = [0] * L2_ENTRIES
        snap1_l2b = [0] * L2_ENTRIES
        snap2_l2b = [0] * L2_ENTRIES
        active_l2a = [0] * L2_ENTRIES
        active_l2b = [0] * L2_ENTRIES

        def place_data(view: str, cluster: int) -> int:
            return self.allocate(data_pattern(view, cluster))

        # Shared region (clusters < 64): identical for both snapshots
        shared_layout = {
            0: DATA,
            1: ZERO,
            2: DATA,
            3: UNALLOCATED,
            4: DATA,
            5: ZERO,
            7: DATA,
        }
        # Forked region (clusters >= 64): the two snapshots diverge here
        snap1_fork = {
            64: DATA,
            65: ZERO,
            66: UNALLOCATED,
        }
        snap2_fork = {
            64: ZERO,  # snap1 had DATA here
            66: DATA,  # snap1 left this unallocated
            67: DATA,
            68: ZERO,
        }
        active_layout = {
            0: DATA,
            1: DATA,  # active overwrote the snapshot zero cluster with real data
            2: DATA,
            3: DATA,  # active allocated what snapshots leave unallocated
            4: DATA,
            5: DATA,
            6: ZERO,
            7: UNALLOCATED,
            8: DATA,
            9: ZERO,
            10: DATA,
            65: DATA,
            70: ZERO,
            90: UNALLOCATED,
        }

        def populate(layout: dict[int, str], table: list[int], view: str) -> None:
            for cluster, state in layout.items():
                if state == DATA:
                    table[cluster % L2_ENTRIES] = l2_entry(place_data(view, cluster))
                elif state == ZERO:
                    table[cluster % L2_ENTRIES] = QCOW_OFLAG_ZERO
                else:
                    table[cluster % L2_ENTRIES] = 0

        populate(shared_layout, shared_l2, "snap1")
        populate(snap1_fork, snap1_l2b, "snap1")
        populate(snap2_fork, snap2_l2b, "snap2")
        populate({k: v for k, v in active_layout.items() if k < L2_ENTRIES}, active_l2a, "active")
        populate({k: v for k, v in active_layout.items() if k >= L2_ENTRIES}, active_l2b, "active")

        shared_l2_offset = self.write_u64_table(shared_l2)
        snap1_l2b_offset = self.write_u64_table(snap1_l2b)
        snap2_l2b_offset = self.write_u64_table(snap2_l2b)
        active_l2a_offset = self.write_u64_table(active_l2a)
        active_l2b_offset = self.write_u64_table(active_l2b)

        # --- L1 roots (one independent root per view) ------------------------------------
        snap1_l1_offsets = [l2_entry(shared_l2_offset)]
        if snap1_l1_entries > 1:
            snap1_l1_offsets.append(l2_entry(snap1_l2b_offset))
        snap1_l1_offset = self.write_u64_table(snap1_l1_offsets)
        snap2_l1_offset = self.write_u64_table(
            [l2_entry(shared_l2_offset), l2_entry(snap2_l2b_offset)]
        )
        active_l1_offset = self.write_u64_table(
            [l2_entry(active_l2a_offset), l2_entry(active_l2b_offset)]
        )

        # --- Snapshot table --------------------------------------------------------------
        snap1_entry = self.build_snapshot_entry(
            "1", "snap-one", snap1_l1_offset, snap1_l1_entries, ACTIVE_DISK_SIZE, legacy_extra=True
        )
        snap2_entry = self.build_snapshot_entry(
            "2", "snap-two", snap2_l1_offset, 2, SNAP2_DISK_SIZE
        )
        snapshot_table = snap1_entry + snap2_entry
        snapshot_table_offset = self.allocate(snapshot_table.ljust(CLUSTER_SIZE, b"\x00"))

        # --- Header (cluster 0) ----------------------------------------------------------
        header = c_qcow2.QCowHeader(
            magic=QCOW2_MAGIC,
            version=3,
            backing_file_offset=0,
            backing_file_size=0,
            cluster_bits=CLUSTER_BITS,
            size=active_size,
            crypt_method=0,
            l1_size=2,
            l1_table_offset=active_l1_offset,
            refcount_table_offset=0,
            refcount_table_clusters=0,
            nb_snapshots=2 if nb_snapshots is None else nb_snapshots,
            snapshots_offset=snapshot_table_offset if snapshots_offset is None else snapshots_offset,
            incompatible_features=0,
            compatible_features=0,
            autoclear_features=0,
            refcount_order=4,
            header_length=len(c_qcow2.QCowHeader),
            compression_type=c_qcow2.QCOW2_COMPRESSION_TYPE_ZLIB,
            padding=b"\x00" * 7,
        ).dumps()
        end_ext = c_qcow2.QCowExtension(magic=c_qcow2.QCOW2_EXT_MAGIC_END, len=0).dumps()
        header_cluster = (header + end_ext).ljust(CLUSTER_SIZE, b"\x00")

        image = bytearray(CLUSTER_SIZE) + bytes(self.buf[CLUSTER_SIZE:])
        image[0 : len(header_cluster)] = header_cluster
        return bytes(image)


def build_models() -> tuple[LogicalDisk, LogicalDisk, LogicalDisk]:
    active = LogicalDisk(size=ACTIVE_DISK_SIZE, name="active")
    # snap-one uses legacy (v2) extra data: its declared size falls back to the image size
    snap1 = LogicalDisk(size=ACTIVE_DISK_SIZE, name="snap1")
    snap2 = LogicalDisk(size=SNAP2_DISK_SIZE, name="snap2")

    active.clusters = {
        0: DATA, 1: DATA, 2: DATA, 3: DATA, 4: DATA, 5: DATA,
        6: ZERO, 8: DATA, 9: ZERO, 10: DATA, 65: DATA, 70: ZERO,
    }
    # Both snapshots share L2A (clusters 0-63); snap1 then diverges from snap2 in L2B
    shared_clusters = {0: DATA, 1: ZERO, 2: DATA, 4: DATA, 5: ZERO, 7: DATA}
    snap1.clusters = {**shared_clusters, 64: DATA, 65: ZERO}
    snap2.clusters = {**shared_clusters, 64: ZERO, 66: DATA, 67: DATA, 68: ZERO}

    # Shared L2A clusters hold snap1-owned payloads visible to both snapshots
    for cluster in (c for c, state in shared_clusters.items() if state == DATA):
        snap1.data[cluster] = data_pattern("snap1", cluster)
        snap2.data[cluster] = data_pattern("snap1", cluster)
    # Forked L2B payloads are private to each snapshot
    snap1.data[64] = data_pattern("snap1", 64)
    for cluster in (66, 67):
        snap2.data[cluster] = data_pattern("snap2", cluster)
    # Active data clusters all carry the active view's own payload
    for cluster in (c for c, state in active.clusters.items() if state == DATA):
        active.data[cluster] = data_pattern("active", cluster)

    return active, snap1, snap2


@pytest.fixture(scope="module")
def image_bytes() -> bytes:
    return Qcow2Builder().build()


@pytest.fixture
def qcow2(image_bytes: bytes) -> QCow2:
    return QCow2(io.BytesIO(image_bytes))


def test_snapshot_metadata(qcow2: QCow2) -> None:
    # The regression must not stop at listing names: but metadata sanity is the entry point.
    assert len(qcow2.snapshots) == 2
    assert [s.name for s in qcow2.snapshots] == ["snap-one", "snap-two"]
    assert [s.id for s in qcow2.snapshots] == ["1", "2"]

    snap1, snap2 = qcow2.snapshots
    # Legacy (v2) extra data is padded; disk size falls back to the image size
    assert snap1.extra.disk_size == 0
    assert snap1.disk_size == qcow2.header.size
    # Modern snapshot carries an explicit, smaller declared disk size
    assert snap2.disk_size == SNAP2_DISK_SIZE
    # Independent L1 roots
    assert snap1.l1_table != snap2.l1_table
    assert snap1.l1_table != qcow2.l1_table


def test_each_view_matches_independent_model_page_by_page(qcow2: QCow2) -> None:
    active_model, snap1_model, snap2_model = build_models()
    views: list[tuple[QCow2Stream, LogicalDisk]] = [
        (qcow2.open(), active_model),
        (qcow2.snapshots[0].open(), snap1_model),
        (qcow2.snapshots[1].open(), snap2_model),
    ]

    page = CLUSTER_SIZE
    for stream, model in views:
        assert stream.size == model.size
        for offset in range(0, model.size, page):
            assert stream.read(page) == model.read(offset, page), (
                f"{model.name} mismatch at {offset:#x}"
            )
        # Reading past the declared size yields nothing
        assert stream.read(page) == b""


def test_interleaved_views_do_not_share_state(qcow2: QCow2) -> None:
    active_model, snap1_model, snap2_model = build_models()
    active = qcow2.open()
    snap1 = qcow2.snapshots[0].open()
    snap2 = qcow2.snapshots[1].open()

    # Two independent handles on the same snapshot must not inherit each other's position/cache
    snap1_again = qcow2.snapshots[0].open()

    streams = {
        "active": (active, active_model),
        "snap1": (snap1, snap1_model),
        "snap1_again": (snap1_again, snap1_model),
        "snap2": (snap2, snap2_model),
    }

    rng = random.Random(1337)
    for _ in range(400):
        name = rng.choice(list(streams))
        stream, model = streams[name]
        offset = rng.randrange(0, model.size)
        length = rng.choice([1, 7, CLUSTER_SIZE // 2, CLUSTER_SIZE, CLUSTER_SIZE + 31])
        length = min(length, model.size - offset)

        stream.seek(offset)
        got = stream.read(length)
        assert got == model.read(offset, length), f"{name} diverged at {offset:#x} len {length}"
        assert stream.tell() == offset + length

    # Explicit fork check: logical cluster 64 lives in each snapshot's private L2B
    fork_cluster = 64 * CLUSTER_SIZE
    snap1.seek(fork_cluster)
    snap2.seek(fork_cluster)
    assert snap1.read(CLUSTER_SIZE) == data_pattern("snap1", 64)
    assert snap2.read(CLUSTER_SIZE) == b"\x00" * CLUSTER_SIZE

    # Shared L2A cluster: both snapshots must see the exact same underlying payload
    shared_cluster = 4 * CLUSTER_SIZE
    snap1.seek(shared_cluster)
    snap2.seek(shared_cluster)
    assert snap1.read(CLUSTER_SIZE) == snap2.read(CLUSTER_SIZE) == data_pattern("snap1", 4)

    # Active overwrote a cluster that snapshots see as zero
    active.seek(CLUSTER_SIZE)
    snap1.seek(CLUSTER_SIZE)
    assert active.read(CLUSTER_SIZE) == data_pattern("active", 1)
    assert snap1.read(CLUSTER_SIZE) == b"\x00" * CLUSTER_SIZE


def test_snapshot_l1_bounds_are_independent_of_active_header() -> None:
    # snap-one is given a single-entry L1: its second L1 region is outside its own L1 table,
    # even though the active header advertises an L1 size of 2. Reads there must resolve to
    # unallocated zeros instead of indexing past the snapshot's L1 table.
    image = Qcow2Builder().build(snap1_l1_entries=1)
    qcow2 = QCow2(io.BytesIO(image))

    snap1 = qcow2.snapshots[0]
    assert snap1.header.l1_size == 1
    assert qcow2.header.l1_size == 2

    with snap1.open() as stream:
        # Its first (and only reachable) L2 region still reads real data
        assert stream.readoffset(0, CLUSTER_SIZE) == data_pattern("snap1", 0)
        # Cluster 64 maps to L1 index 1, which is beyond this snapshot's L1 -> unallocated
        assert stream.readoffset(64 * CLUSTER_SIZE, CLUSTER_SIZE) == b"\x00" * CLUSTER_SIZE

    # The active disk's own two-entry L1 is unaffected and still reaches cluster 64
    with qcow2.open() as active:
        assert active.readoffset(65 * CLUSTER_SIZE, CLUSTER_SIZE) == data_pattern("active", 65)


def test_truncated_snapshot_l1_is_attributed_and_other_views_survive(image_bytes: bytes) -> None:
    qcow2 = QCow2(io.BytesIO(image_bytes))
    snap1, _ = qcow2.snapshots

    # Corrupt only snapshot 1's L1 table by inflating its declared size past end of file
    field_offset = snap1.offset + c_qcow2.QCowSnapshotHeader.fields["l1_size"].offset
    corrupted = bytearray(image_bytes)
    corrupted[field_offset : field_offset + 4] = c_qcow2.uint32.dumps(snap1.header.l1_size + 1000)

    broken = QCow2(io.BytesIO(bytes(corrupted)))
    broken_snap1, intact_snap2 = broken.snapshots

    with pytest.raises(Error, match=r"Snapshot 'snap-one'.*truncated L1 table"):
        broken_snap1.open().read(CLUSTER_SIZE)

    # The other snapshot and the active disk still produce their full, correct results
    _, _, snap2_model = build_models()
    with intact_snap2.open() as stream:
        assert stream.read() == snap2_model.read(0, snap2_model.size)

    with broken.open() as stream:
        assert stream.read(CLUSTER_SIZE) == data_pattern("active", 0)


def test_header_cannot_forge_snapshot_support(image_bytes: bytes) -> None:
    # Claim snapshots that the image does not contain, pointing at an unused/zero region
    forged = bytearray(image_bytes)
    nb_offset = c_qcow2.QCowHeader.fields["nb_snapshots"].offset
    off_offset = c_qcow2.QCowHeader.fields["snapshots_offset"].offset
    forged[nb_offset : nb_offset + 4] = c_qcow2.uint32.dumps(1)
    # Point into a zeroed hole beyond all real data
    bogus_offset = (len(forged) + CLUSTER_SIZE) & ~(CLUSTER_SIZE - 1)
    forged[off_offset : off_offset + 8] = c_qcow2.uint64.dumps(bogus_offset)

    qcow2 = QCow2(io.BytesIO(bytes(forged)))
    with pytest.raises((Error, EOFError)):
        qcow2.snapshots[0].open()

    # Conversely, hiding the snapshot table must expose zero snapshots, not fabricated ones
    hidden = bytearray(image_bytes)
    hidden[nb_offset : nb_offset + 4] = c_qcow2.uint32.dumps(0)
    hidden_qcow2 = QCow2(io.BytesIO(bytes(hidden)))
    assert hidden_qcow2.snapshots == []

    # Active disk remains readable regardless of snapshot header tampering
    with qcow2.open() as stream:
        assert stream.read(CLUSTER_SIZE) == data_pattern("active", 0)
