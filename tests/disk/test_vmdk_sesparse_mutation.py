"""Directed mutation tests for the SESparse grain mapping of VMDK.

These tests guard against interpreting a 64-bit SESparse grain-table entry as a
plain (32-bit) sparse entry. In plain sparse VMDK the entry value is directly a
sector offset and ``0`` means "not present". SESparse instead stores a 4-bit
grain type in the most significant nibble and an interleaved physical cluster
address in the remaining bits. Reusing plain sparse semantics therefore reads
the wrong region (for example a ``ZERO``/``FALLTHROUGH`` marker, whose low bits
are all zero, would be dereferenced as cluster zero) and a corrupted allocated
address could be mistaken for a legitimate parent-disk page fault.

The tests construct synthetic SESparse images from a valid grain
directory/table and independently mutate the type nibble and the physical
address bits. A self-contained reference model (kept separate from the
production parser) and a deliberately naive plain-sparse model act as oracles:
every mutated entry is evaluated against both, full and cross-grain reads are
checked byte for byte, and every counterexample keeps the exact table entry and
request range that produced it.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from struct import pack_into

import pytest

from dissect.hypervisor.disk import c_vmdk
from dissect.hypervisor.disk.c_vmdk import SECTOR_SIZE
from dissect.hypervisor.disk.vmdk import SparseDisk

# ---------------------------------------------------------------------------
# Layout of the synthetic SESparse image (one grain directory, one grain table)
# ---------------------------------------------------------------------------
GRAIN_SIZE = 8  # sectors per grain (4 KiB), matching the reference fixture
GRAIN_COUNT = 8  # small disk: capacity == GRAIN_COUNT * GRAIN_SIZE sectors
CAPACITY = GRAIN_COUNT * GRAIN_SIZE

HEADER_SECTORS = 1
GRAIN_DIRECTORY_OFFSET = 8
GRAIN_DIRECTORY_SECTORS = 1
GRAIN_TABLES_OFFSET = 16
GRAIN_TABLE_SECTORS = 1
GRAINS_OFFSET = 24

# A grain directory entry only loads its table when the upper 32 bits are
# exactly this marker (strict check in qemu/block/vmdk.c, mirrored by the parser).
DIRECTORY_ALLOCATED = 0x1000000000000000

# SESparse grain-type nibble (top nibble of a uint64 entry).
TYPE_MASK = c_vmdk.c_vmdk.SESPARSE_GRAIN_TYPE_MASK
TYPE_UNALLOCATED = c_vmdk.c_vmdk.SESPARSE_GRAIN_TYPE_UNALLOCATED
TYPE_FALLTHROUGH = c_vmdk.c_vmdk.SESPARSE_GRAIN_TYPE_FALLTHROUGH
TYPE_ZERO = c_vmdk.c_vmdk.SESPARSE_GRAIN_TYPE_ZERO
TYPE_ALLOCATED = c_vmdk.c_vmdk.SESPARSE_GRAIN_TYPE_ALLOCATED

# Distinct, non-overlapping content so no two data sources can be confused.
ALLOC_MARKER = 0x40  # allocated grain data: ALLOC_MARKER ^ cluster_index
PARENT_BASE = 0x80  # parent data: PARENT_BASE ^ sector


class RecordingParent:
    """Minimal parent disk recording every request and returning traceable data."""

    def __init__(self) -> None:
        self.calls: list[tuple[int, int]] = []

    def read_sectors(self, sector: int, count: int) -> bytes:
        self.calls.append((sector, count))
        return bytes((PARENT_BASE ^ (sector + idx)) & 0xFF for idx in range(count))


def expected_parent_bytes(sector: int, sector_count: int) -> bytes:
    """Independent copy of :class:`RecordingParent` content for oracle comparisons."""
    return bytes((PARENT_BASE ^ (sector + idx)) & 0xFF for idx in range(sector_count))


# ---------------------------------------------------------------------------
# Independent encoding/decoding of a SESparse allocated entry
# ---------------------------------------------------------------------------
def encode_allocated_entry(cluster: int) -> int:
    """Build an allocated entry whose interleaved address points at ``cluster``."""
    return (
        TYPE_ALLOCATED
        | ((cluster & 0x0FFF) << 48)
        | ((cluster >> 12) & 0x0000FFFFFFFFFFFF)
    )


def decode_allocated_cluster(entry: int) -> int:
    """Inverse of :func:`encode_allocated_entry`, independent of the parser."""
    high = (entry & 0x0FFF000000000000) >> 48
    low = (entry & 0x0000FFFFFFFFFFFF) << 12
    return high | low


def grain_type(entry: int) -> int:
    return entry & TYPE_MASK


def build_image(
    entries: list[int], directory_entry: int = DIRECTORY_ALLOCATED
) -> bytes:
    """Serialize a SESparse image with the supplied grain-table ``entries``."""
    header = c_vmdk.c_vmdk.VMDKSESparseConstHeader()
    header.magic = c_vmdk.c_vmdk.SESPARSE_CONST_HEADER_MAGIC
    header.version = 0x200000001
    header.capacity = CAPACITY
    header.grain_size = GRAIN_SIZE
    header.grain_table_size = GRAIN_TABLE_SECTORS
    header.flags = 0
    header.grain_directory_offset = GRAIN_DIRECTORY_OFFSET
    header.grain_directory_size = GRAIN_DIRECTORY_SECTORS
    header.grain_tables_offset = GRAIN_TABLES_OFFSET
    header.grain_tables_size = GRAIN_TABLE_SECTORS
    header.grains_offset = GRAINS_OFFSET
    header.grains_size = CAPACITY

    image_size = (GRAINS_OFFSET + GRAIN_COUNT * GRAIN_SIZE) * SECTOR_SIZE
    image = bytearray(image_size)
    image[0 : HEADER_SECTORS * SECTOR_SIZE] = header.dumps()

    pack_into("<Q", image, GRAIN_DIRECTORY_OFFSET * SECTOR_SIZE, directory_entry)

    table_offset = GRAIN_TABLES_OFFSET * SECTOR_SIZE
    for index, entry in enumerate(entries):
        pack_into("<Q", image, table_offset + index * 8, entry)

    # Back every distinct in-range allocated cluster with identifiable grain data.
    for entry in entries:
        if grain_type(entry) == TYPE_ALLOCATED:
            cluster = decode_allocated_cluster(entry)
            if cluster < GRAIN_COUNT:
                start = (GRAINS_OFFSET + cluster * GRAIN_SIZE) * SECTOR_SIZE
                marker = (ALLOC_MARKER ^ cluster) & 0xFF
                image[start : start + GRAIN_SIZE * SECTOR_SIZE] = bytes([marker]) * (
                    GRAIN_SIZE * SECTOR_SIZE
                )

    return bytes(image)


def open_disk(
    entries: list[int],
    *,
    parent: RecordingParent | None = None,
    directory_entry: int = DIRECTORY_ALLOCATED,
) -> SparseDisk:
    return SparseDisk(io.BytesIO(build_image(entries, directory_entry)), parent=parent)


# ---------------------------------------------------------------------------
# Reference model: correct SESparse semantics, independently implemented
# ---------------------------------------------------------------------------
# A read plan is a per-sector label describing where each sector comes from.
# ("parent", sector) / ("zero",) / ("physical", absolute_sector) / ("error",)
@dataclass(frozen=True)
class Counterexample:
    grain: int
    request_sector: int
    request_count: int
    raw_entry: int
    type_nibble: int
    address_cluster: int
    mutation: str
    reference_plan: list
    naive_plan: list


def reference_lookup(grain: int, entries: list[int], directory_entry: int) -> tuple:
    """Return a semantic label for ``grain`` using correct SESparse rules."""
    if (
        directory_entry == 0
        or directory_entry & 0xFFFFFFFF00000000 != 0x1000000000000000
    ):
        # Strict directory check failed: the grain table is not loaded.
        return ("unmapped", grain * GRAIN_SIZE)

    entry = entries[grain]
    gtype = grain_type(entry)
    if gtype in (TYPE_UNALLOCATED, TYPE_FALLTHROUGH):
        return ("unmapped", grain * GRAIN_SIZE)
    if gtype == TYPE_ZERO:
        return ("zero", None)
    if gtype == TYPE_ALLOCATED:
        cluster = decode_allocated_cluster(entry)
        return ("allocated", cluster)
    # Reserved/unknown type nibble: the real parser refuses this entry.
    return ("error", None)


def naive_sparse_lookup(grain: int, entries: list[int]) -> tuple:
    """Model a parser that wrongly reuses plain sparse entry interpretation.

    Plain sparse treats the raw entry as a direct offset: ``0`` is "not present",
    every other value points at physical data. The SESparse type nibble and the
    interleaved address encoding are completely ignored.
    """
    entry = entries[grain]
    if entry == 0:
        return ("unmapped", grain * GRAIN_SIZE)
    # Treat the raw entry's low 48 bits as an ordinary cluster number, without
    # stripping the type nibble or undoing the SESparse interleave.
    return ("allocated", entry & 0x0000FFFFFFFFFFFF)


def build_plan(
    sector: int,
    count: int,
    entries: list[int],
    *,
    directory_entry: int,
    parent: RecordingParent | None,
    naive: bool,
) -> list:
    """Derive the per-sector provenance labels for an independent read model."""
    last_sector = sector + count
    plan: list = []

    grain_start_sector = (sector // GRAIN_SIZE) * GRAIN_SIZE
    grain = grain_start_sector // GRAIN_SIZE
    cursor = sector

    while cursor < last_sector:
        grain_begin = grain * GRAIN_SIZE
        grain_end = grain_begin + GRAIN_SIZE
        chunk_end = min(last_sector, grain_end)
        chunk_sectors = chunk_end - cursor

        if naive:
            label = naive_sparse_lookup(grain, entries)
        else:
            label = reference_lookup(grain, entries, directory_entry)
        kind = label[0]

        if kind == "unmapped":
            if parent is not None:
                for offset in range(chunk_sectors):
                    plan.append(("parent", cursor + offset))
            else:
                plan.extend([("zero",)] * chunk_sectors)
        elif kind == "zero":
            plan.extend([("zero",)] * chunk_sectors)
        elif kind == "allocated":
            cluster = label[1]
            if cluster >= GRAIN_COUNT:
                # Corrupt/out-of-range address: parser seeks beyond EOF and gets a
                # short read. It must never be reinterpreted as a parent fault.
                plan.extend([("short",)] * chunk_sectors)
            else:
                absolute = GRAINS_OFFSET + cluster * GRAIN_SIZE + (cursor - grain_begin)
                for offset in range(chunk_sectors):
                    plan.append(("physical", absolute + offset))
        elif kind == "error":
            plan.extend([("error",)] * chunk_sectors)
        else:  # pragma: no cover
            raise AssertionError(f"unexpected label {label!r}")

        cursor = chunk_end
        grain += 1

    return plan


def materialize(plan: list, image: bytes, sector: int) -> bytes:
    """Turn a read plan into actual bytes, reading physical sectors from ``image``."""
    chunks = []
    for index, label in enumerate(plan):
        target_sector = sector + index
        if label[0] == "zero":
            chunks.append(b"\x00" * SECTOR_SIZE)
        elif label[0] == "parent":
            chunks.append(expected_parent_bytes(target_sector, 1))
        elif label[0] == "physical":
            start = label[1] * SECTOR_SIZE
            chunks.append(image[start : start + SECTOR_SIZE])
        elif label[0] == "short":
            chunks.append(b"")
        elif label[0] == "error":
            raise ValueError("Unknown grain type")
        else:  # pragma: no cover
            raise AssertionError(f"unexpected label {label!r}")
    return b"".join(chunks)


# Baseline valid configuration exercising every documented state, including an
# allocated entry whose cluster differs from its grain index (proves the address
# bits, not the grain index, select the physical region).
BASELINE_ENTRIES = [
    encode_allocated_entry(0),  # grain 0 -> cluster 0
    TYPE_ZERO,  # grain 1 -> explicit zero
    TYPE_UNALLOCATED,  # grain 2 -> unmapped
    TYPE_FALLTHROUGH,  # grain 3 -> scsi unmapped, fallthrough
    encode_allocated_entry(3),  # grain 4 -> cluster 3 (non-identity mapping)
    TYPE_ZERO,  # grain 5 -> explicit zero
    encode_allocated_entry(6),  # grain 6 -> cluster 6
    TYPE_UNALLOCATED,  # grain 7 -> unmapped
]

# Cross-grain request ranges, deliberately unaligned relative to grain borders.
READ_REQUESTS = [
    (0, CAPACITY),  # full disk
    (1, CAPACITY - 2),  # unaligned full span
    (GRAIN_SIZE - 2, 5),  # cross grain0/grain1 boundary
    (3 * GRAIN_SIZE + 3, 9),  # cross fallthrough -> allocated boundary
    (4 * GRAIN_SIZE, GRAIN_SIZE),  # single non-identity allocated grain
    (6 * GRAIN_SIZE + 1, 7),  # allocated -> unmapped tail
]


@pytest.mark.parametrize("use_parent", [False, True], ids=["no-parent", "with-parent"])
@pytest.mark.parametrize("read_request", READ_REQUESTS)
def test_sesparse_full_and_cross_grain_reads_match_reference(read_request, use_parent):
    sector, count = read_request
    parent = RecordingParent() if use_parent else None
    image = build_image(BASELINE_ENTRIES)
    disk = SparseDisk(io.BytesIO(image), parent=parent)

    expected_plan = build_plan(
        sector,
        count,
        BASELINE_ENTRIES,
        directory_entry=DIRECTORY_ALLOCATED,
        parent=parent,
        naive=False,
    )
    expected = materialize(expected_plan, image, sector)
    actual = disk.read_sectors(sector, count)

    assert actual == expected


def test_sesparse_explicit_zero_differs_from_unmapped_parent():
    # With a parent present, an explicit zero grain yields zeroes while an
    # unmapped grain yields parent data; the two must never be conflated.
    parent = RecordingParent()
    disk = open_disk(BASELINE_ENTRIES, parent=parent)

    zero_grain = disk.read_sectors(1 * GRAIN_SIZE, GRAIN_SIZE)
    unmapped_grain = disk.read_sectors(2 * GRAIN_SIZE, GRAIN_SIZE)

    assert zero_grain == b"\x00" * (GRAIN_SIZE * SECTOR_SIZE)
    assert unmapped_grain == expected_parent_bytes(2 * GRAIN_SIZE, GRAIN_SIZE)
    assert zero_grain != unmapped_grain


def test_parent_only_serves_unmapped_grains():
    parent = RecordingParent()
    disk = open_disk(BASELINE_ENTRIES, parent=parent)

    disk.read_sectors(0, CAPACITY)

    requested_sectors = set()
    for call_sector, call_count in parent.calls:
        requested_sectors.update(range(call_sector, call_sector + call_count))

    # Only the unmapped grains (2, 3, 7) may reach the parent.
    expected_parent_sectors = set()
    for grain in (2, 3, 7):
        expected_parent_sectors.update(
            range(grain * GRAIN_SIZE, (grain + 1) * GRAIN_SIZE)
        )

    assert requested_sectors == expected_parent_sectors
    # Allocated and explicit-zero grains never trigger a parent read.
    for grain in (0, 1, 4, 5, 6):
        assert requested_sectors.isdisjoint(
            range(grain * GRAIN_SIZE, (grain + 1) * GRAIN_SIZE)
        )


def test_unknown_grain_type_raises_and_never_touches_parent():
    entries = list(BASELINE_ENTRIES)
    unknown_entry = 0x4000000000000000 | encode_allocated_entry(2)
    entries[1] = unknown_entry  # grain 1 gets a reserved type nibble with an address
    parent = RecordingParent()
    disk = open_disk(entries, parent=parent)

    with pytest.raises(ValueError, match="Unknown grain type"):
        disk._lookup_grain(1)
    with pytest.raises(ValueError, match="Unknown grain type"):
        disk.read_sectors(GRAIN_SIZE, GRAIN_SIZE)

    disk.read_sectors(0, GRAIN_SIZE)  # an adjacent valid grain still works
    assert (
        parent.calls == []
    )  # the unknown-type grain must not fall through to the parent


def test_corrupt_allocated_address_is_not_a_parent_fault():
    # An allocated entry whose interleaved address points far beyond the image.
    corrupt_cluster = GRAIN_COUNT * 1024
    entries = list(BASELINE_ENTRIES)
    entries[4] = encode_allocated_entry(corrupt_cluster)
    parent = RecordingParent()
    disk = open_disk(entries, parent=parent)

    corrupt_range = (4 * GRAIN_SIZE, GRAIN_SIZE)
    before_calls = len(parent.calls)
    data = disk.read_sectors(*corrupt_range)

    # No parent involvement and no full-length zero/parent buffer: the corrupt
    # address drives a short physical read, not a legitimate parent page fault.
    assert len(parent.calls) == before_calls
    assert len(data) < GRAIN_SIZE * SECTOR_SIZE
    assert data != expected_parent_bytes(corrupt_range[0], GRAIN_SIZE)
    assert data != b"\x00" * (GRAIN_SIZE * SECTOR_SIZE)


def test_grain_directory_strict_check():
    # Only the exact 0x10000000.... marker loads a grain table.
    entries = BASELINE_ENTRIES
    assert (
        open_disk(entries, directory_entry=DIRECTORY_ALLOCATED)._lookup_grain_table(0)
        is not None
    )

    for mutated in (0x0, 0x2000000000000000, 0x9000000000000000, 0x0000000000000001):
        disk = open_disk(entries, directory_entry=mutated)
        disk._lookup_grain_table.cache_clear()
        assert disk._lookup_grain_table(0) is None
        # A missing table makes every grain unmapped (zero without a parent),
        # rather than dereferencing garbage.
        assert disk._lookup_grain(0) == 0
        assert disk.read_sectors(0, GRAIN_SIZE) == b"\x00" * (GRAIN_SIZE * SECTOR_SIZE)


def test_directed_type_and_address_mutations_naive_model_diverges():
    # Independently mutate the type nibble and the physical address bits. Each
    # case is evaluated with the correct SESparse model and a naive plain-sparse
    # model; conflating the two interpretations must produce a counterexample.
    address_mutations = {
        "identity-cluster": 0,
        "mapped-cluster": 3,
        "high-cluster": 0xABC,
        "out-of-range-cluster": GRAIN_COUNT * 256,
    }
    type_nibbles = [
        TYPE_UNALLOCATED,
        TYPE_FALLTHROUGH,
        TYPE_ZERO,
        TYPE_ALLOCATED,
        0x4000000000000000,  # reserved / unknown
        0xF000000000000000,  # reserved / unknown
    ]

    target_grain = 1
    request = (target_grain * GRAIN_SIZE, GRAIN_SIZE)
    counterexamples: list[Counterexample] = []
    naive_agreements = 0

    for mutation_name, cluster in address_mutations.items():
        for nibble in type_nibbles:
            entry = nibble | (encode_allocated_entry(cluster) & ~TYPE_MASK)
            entries = list(BASELINE_ENTRIES)
            entries[target_grain] = entry

            sector, count = request
            reference_plan = build_plan(
                sector,
                count,
                entries,
                directory_entry=DIRECTORY_ALLOCATED,
                parent=None,
                naive=False,
            )
            naive_plan = build_plan(
                sector,
                count,
                entries,
                directory_entry=DIRECTORY_ALLOCATED,
                parent=None,
                naive=True,
            )

            if reference_plan != naive_plan:
                counterexamples.append(
                    Counterexample(
                        grain=target_grain,
                        request_sector=sector,
                        request_count=count,
                        raw_entry=entry,
                        type_nibble=nibble,
                        address_cluster=cluster,
                        mutation=mutation_name,
                        reference_plan=reference_plan,
                        naive_plan=naive_plan,
                    )
                )
            else:
                naive_agreements += 1

            # The correct model must agree with the real parser on every case.
            image = build_image(entries)
            disk = SparseDisk(io.BytesIO(image))
            if nibble in (0x4000000000000000, 0xF000000000000000):
                with pytest.raises(ValueError, match="Unknown grain type"):
                    disk.read_sectors(sector, count)
            else:
                expected = materialize(reference_plan, image, sector)
                assert disk.read_sectors(sector, count) == expected

    # At least one status-bit/physical-address conflation must be detected, and
    # the mutation set must contain both agreeing and disagreeing variants so the
    # divergence is meaningful rather than vacuous.
    assert (
        counterexamples
    ), "expected the naive sparse model to misread SESparse entries"
    assert naive_agreements > 0
    conflated_address = [c for c in counterexamples if c.address_cluster != 0]
    assert conflated_address, "need a counterexample that conflates address bits"

    # Every retained counterexample carries a locatable entry and request range.
    for case in counterexamples:
        assert 0 <= case.grain < GRAIN_COUNT
        assert case.request_count == GRAIN_SIZE
        assert case.raw_entry & TYPE_MASK == case.type_nibble
        assert case.reference_plan != case.naive_plan


def test_directed_mutations_keep_locatable_table_entry_and_range():
    # A focused, named set of confusions with explicit, human-checkable locators.
    named_cases = [
        ("zero-marker-read-as-cluster", TYPE_ZERO, 0),
        ("fallthrough-marker-read-as-cluster", TYPE_FALLTHROUGH, 0),
        ("unallocated-with-garbage-address", TYPE_UNALLOCATED, 0x1234),
        ("allocated-remapped-to-other-cluster", TYPE_ALLOCATED, 3),
        ("allocated-corrupt-high-address", TYPE_ALLOCATED, GRAIN_COUNT * 512),
        ("unknown-nibble-valid-looking-address", 0x5000000000000000, 2),
    ]
    grain = 4
    sector, count = grain * GRAIN_SIZE, GRAIN_SIZE

    for name, nibble, cluster in named_cases:
        entry = nibble | (encode_allocated_entry(cluster) & ~TYPE_MASK)
        entries = list(BASELINE_ENTRIES)
        entries[grain] = entry

        reference_plan = build_plan(
            sector,
            count,
            entries,
            directory_entry=DIRECTORY_ALLOCATED,
            parent=None,
            naive=False,
        )
        naive_plan = build_plan(
            sector,
            count,
            entries,
            directory_entry=DIRECTORY_ALLOCATED,
            parent=None,
            naive=True,
        )

        assert (
            reference_plan != naive_plan
        ), f"{name} should distinguish interpretations"

        image = build_image(entries)
        disk = SparseDisk(io.BytesIO(image))
        if nibble not in (
            TYPE_UNALLOCATED,
            TYPE_FALLTHROUGH,
            TYPE_ZERO,
            TYPE_ALLOCATED,
        ):
            with pytest.raises(ValueError, match="Unknown grain type"):
                disk.read_sectors(sector, count)
        else:
            assert disk.read_sectors(sector, count) == materialize(
                reference_plan, image, sector
            )
