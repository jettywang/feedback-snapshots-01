from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

import pytest

from dissect.hypervisor.disk.asif import ASIF

HEADER_SIGNATURE = 0x73686477
ENTRY_DIRTY = 1 << 62
CONTENT_DIRTY = 1 << 63
DIRTY_MASK = ENTRY_DIRTY | CONTENT_DIRTY
CHUNK_NUMBER_MASK = (1 << 55) - 1

TABLE_CHUNK_BASE = 1
STALE_TABLE_CHUNK_BASE = 0x40
DATA_CHUNK_BASE = 0x100
STALE_DATA_CHUNK_BASE = 0x2000
SENTINEL_CHUNK_BASE = 0x8000


@dataclass(frozen=True)
class Geometry:
    """ASIF geometry derived from the header, independent from the implementation."""

    block_size: int
    chunk_size: int
    size: int
    max_size: int

    def __post_init__(self) -> None:
        if self.chunk_size % self.block_size:
            raise ValueError("chunk size must be a multiple of the block size")
        if self.size > self.max_size:
            raise ValueError("logical size must not exceed max size")
        if self.groups < 1:
            raise ValueError("block/chunk combination has no complete table group")

    @property
    def blocks_per_chunk(self) -> int:
        return self.chunk_size // self.block_size

    @property
    def reserved_entries(self) -> int:
        """Number of data entries before the reserved entry of a group (four blocks' worth of chunks)."""
        return 4 * self.block_size

    @property
    def entries_per_table(self) -> int:
        return self.chunk_size // 8

    @property
    def groups(self) -> int:
        return self.entries_per_table // (self.reserved_entries + 1)

    @property
    def table_entries(self) -> int:
        return self.groups * (self.reserved_entries + 1)

    @property
    def usable_entries(self) -> int:
        return self.groups * self.reserved_entries

    @property
    def table_span(self) -> int:
        return self.usable_entries * self.chunk_size

    @property
    def table_count(self) -> int:
        return (self.max_size + self.table_span - 1) // self.table_span

    def split(self, offset: int) -> tuple[int, int, int]:
        table = offset // self.table_span
        within_table = offset - table * self.table_span
        return table, within_table // self.chunk_size, within_table % self.chunk_size


@dataclass(frozen=True)
class Marker:
    """Unique, deterministic content for one physical chunk."""

    kind: str
    table: int
    slot: int
    chunk: int

    @property
    def header(self) -> bytes:
        return f"{self.kind}:{self.table}:{self.slot}:{self.chunk}|".encode()

    def data(self, offset: int, length: int) -> bytes:
        header = self.header
        start = offset % len(header)
        repeats = (start + length + len(header) - 1) // len(header)
        return (header * repeats)[start : start + length]


class SyntheticASIF:
    """In-memory sparse ASIF image with unique markers for every physical data chunk."""

    def __init__(
        self,
        block_size: int,
        chunk_size: int,
        size: int | None = None,
        max_size: int | None = None,
    ) -> None:
        # Probe the geometry first, then use sizes that span several tables and end off-chunk.
        probe = Geometry(block_size=block_size, chunk_size=chunk_size, size=0, max_size=1)
        self.geometry = Geometry(
            block_size=block_size,
            chunk_size=chunk_size,
            size=probe.table_span + 3 * chunk_size if size is None else size,
            max_size=3 * probe.table_span + 5 * block_size if max_size is None else max_size,
        )

        self.pos = 0
        self.chunk_data: dict[int, bytes] = {}
        self.markers: dict[int, Marker] = {}
        self.allocations: dict[tuple[int, int], int] = {}
        self.stale_allocations: dict[tuple[int, int], int] = {}
        self.tables: list[list[int]] = []
        self._next_chunk = DATA_CHUNK_BASE
        self._build()

    @property
    def chunk_size(self) -> int:
        return self.geometry.chunk_size

    @property
    def physical_size(self) -> int:
        last_chunk = max(*self.chunk_data, *self.markers, 0)
        return (last_chunk + 1) * self.chunk_size

    def _build(self) -> None:
        geom = self.geometry
        table_entries = geom.table_entries
        reserved = geom.reserved_entries
        usable = geom.usable_entries

        self.tables = [[0] * table_entries for _ in range(geom.table_count)]
        stale_tables = [[0] * table_entries for _ in range(geom.table_count)]

        # Every real data slot gets a distinct physical chunk and marker.
        for table in range(geom.table_count):
            slots = set(range(min(6, usable)))
            slots.update(range(max(0, reserved - 2), min(usable, reserved + 3)))
            slots.update(range(max(0, 2 * reserved - 2), min(usable, 2 * reserved + 3)))
            slots.update(range(max(0, usable - 4), usable))
            slots.update(range(0, usable, max(1, usable // 7)))
            if table == 1:
                slots.add(3)
                slots.add(4)
            if table == geom.table_count - 1:
                last = (geom.max_size - 1 - table * geom.table_span) // self.chunk_size
                if 0 <= last < usable:
                    slots.add(last)

            for slot in sorted(slots):
                chunk = self._next_chunk
                self._next_chunk += 1
                flags = (ENTRY_DIRTY, CONTENT_DIRTY, DIRTY_MASK)[(table + slot) % 3]
                self.tables[table][slot + slot // reserved] = chunk | flags
                self.allocations[(table, slot)] = chunk
                self.markers[chunk] = Marker("DATA", table, slot, chunk)

        # The one reserved entry in every group is not part of the logical data mapping.
        for table in range(geom.table_count):
            for group in range(geom.groups):
                index = group * (reserved + 1) + reserved
                chunk = SENTINEL_CHUNK_BASE + table * 0x100 + group
                self.tables[table][index] = chunk | DIRTY_MASK
                self.markers[chunk] = Marker("RESERVED", table, group, chunk)

        # A stale directory points at a different, complete set of tables.
        for table in range(geom.table_count):
            self.chunk_data[TABLE_CHUNK_BASE + table] = self._pack(self.tables[table])

            stale_table = stale_tables[table]
            stale_slots = sorted(set(range(min(4, usable))) | {reserved - 1, reserved, usable - 1})
            for slot in stale_slots:
                if not 0 <= slot < usable:
                    continue
                chunk = STALE_DATA_CHUNK_BASE + table * 0x100 + slot
                stale_table[slot + slot // reserved] = chunk
                self.stale_allocations[(table, slot)] = chunk
                self.markers[chunk] = Marker("STALE", table, slot, chunk)
            self.chunk_data[STALE_TABLE_CHUNK_BASE + table] = self._pack(stale_table)

        # Both directories live in the header chunk, the active one has the highest version.
        chunk0 = bytearray(self.chunk_size)
        active_offset = 512
        stale_offset = self._align_up(active_offset + 8 + 8 * geom.table_count, geom.block_size)

        header = struct.pack(
            ">IIIIQQ16sQQIHHQ16sIII",
            HEADER_SIGNATURE,
            1,
            512,
            0,
            active_offset,
            stale_offset,
            bytes(range(16)),
            geom.size // geom.block_size,
            geom.max_size // geom.block_size,
            geom.chunk_size,
            geom.block_size,
            0,
            0,
            b"\x00" * 16,
            0,
            0,
            0,
        )
        chunk0[: len(header)] = header

        active_dir = struct.pack(">Q", 2) + b"".join(
            struct.pack(">Q", TABLE_CHUNK_BASE + table) for table in range(geom.table_count)
        )
        stale_dir = struct.pack(">Q", 1) + b"".join(
            struct.pack(">Q", STALE_TABLE_CHUNK_BASE + table) for table in range(geom.table_count)
        )
        chunk0[active_offset : active_offset + len(active_dir)] = active_dir
        chunk0[stale_offset : stale_offset + len(stale_dir)] = stale_dir
        self.chunk_data[0] = bytes(chunk0)

    @staticmethod
    def _pack(entries: list[int]) -> bytes:
        return b"".join(struct.pack(">Q", entry) for entry in entries)

    @staticmethod
    def _align_up(value: int, alignment: int) -> int:
        return (value + alignment - 1) // alignment * alignment

    def chunk_bytes(self, chunk: int, offset: int, length: int) -> bytes:
        data = self.chunk_data.get(chunk)
        if data is not None:
            return data[offset : offset + length].ljust(length, b"\x00")

        marker = self.markers.get(chunk)
        if marker is not None:
            return marker.data(offset, length)

        # Sparse holes and the zero chunk number read as zeroes.
        return b"\x00" * length

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.pos

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            self.pos = offset
        elif whence == 1:
            self.pos += offset
        elif whence == 2:
            self.pos = self.physical_size + offset
        else:
            raise ValueError(f"invalid whence {whence}")
        return self.pos

    def read(self, length: int = -1) -> bytes:
        if length < 0:
            length = max(0, self.physical_size - self.pos)

        result = []
        while length:
            chunk, offset = divmod(self.pos, self.chunk_size)
            read_length = min(length, self.chunk_size - offset)
            result.append(self.chunk_bytes(chunk, offset, read_length))
            self.pos += read_length
            length -= read_length
        return b"".join(result)


class Fault(Enum):
    NONE = "none"
    RESERVED_SLOTS = "reserved-slots"
    LOGICAL_EOF = "logical-eof"
    DIRTY_BITS = "dirty-bits"


class IndexModel:
    """Independent two-level logical-to-physical index for an ASIF data view."""

    def __init__(self, image: SyntheticASIF):
        self.image = image
        self.geometry = image.geometry

    def read(
        self,
        offset: int,
        length: int,
        *,
        reserved: bool = False,
        fault: Fault = Fault.NONE,
    ) -> bytes:
        view_size = self.geometry.max_size if reserved or fault is Fault.LOGICAL_EOF else self.geometry.size
        if offset >= view_size or length <= 0:
            return b""

        length = min(length, view_size - offset)
        result = []
        while length:
            table, slot, chunk_offset = self.geometry.split(offset)
            entry_index = slot if fault is Fault.RESERVED_SLOTS else slot + slot // self.geometry.reserved_entries
            entry = self.image.tables[table][entry_index] if table < self.geometry.table_count else 0
            physical_chunk = entry if fault is Fault.DIRTY_BITS else entry & CHUNK_NUMBER_MASK

            read_length = min(length, self.geometry.chunk_size - chunk_offset)
            if physical_chunk == 0:
                # A zero entry denotes a sparse chunk, not the header at physical chunk zero.
                result.append(b"\x00" * read_length)
            else:
                result.append(self.image.chunk_bytes(physical_chunk, chunk_offset, read_length))
            offset += read_length
            length -= read_length

        return b"".join(result)


def _sequential_cases(image: SyntheticASIF, *, reserved: bool) -> list[tuple[int, int]]:
    geom = image.geometry
    slots = set(range(min(6, geom.usable_entries)))
    slots.update(range(max(0, geom.reserved_entries - 3), min(geom.usable_entries, geom.reserved_entries + 4)))
    slots.update(range(max(0, geom.usable_entries - 4), geom.usable_entries))

    view_size = geom.max_size if reserved else geom.size
    cases = [
        (table * geom.table_span + slot * geom.chunk_size, geom.chunk_size)
        for table in range(geom.table_count)
        for slot in slots
        if table * geom.table_span + slot * geom.chunk_size < view_size
    ]
    return sorted(cases)


def _short_cases(image: SyntheticASIF, *, reserved: bool) -> list[tuple[int, int]]:
    geom = image.geometry
    view_size = geom.max_size if reserved else geom.size
    cases = []

    for table in range(1, geom.table_count + 1):
        base = table * geom.table_span
        cases.extend(
            [
                (base - 2 * geom.block_size, 4 * geom.block_size),
                (base - geom.block_size, 2 * geom.block_size),
                (base - geom.chunk_size // 2, geom.chunk_size + 3 * geom.block_size),
            ]
        )

    for table in range(geom.table_count):
        for slot in (geom.reserved_entries, 2 * geom.reserved_entries, geom.usable_entries - 1):
            if slot >= geom.usable_entries:
                continue
            base = table * geom.table_span + slot * geom.chunk_size
            cases.extend(
                [
                    (base - geom.block_size, 2 * geom.block_size),
                    (base - 1, geom.block_size + 2),
                    (base, geom.chunk_size + 1),
                ]
            )

    return sorted({(offset, length) for offset, length in cases if 0 <= offset < view_size})


class ReadableStream(Protocol):
    def seek(self, offset: int, whence: int = 0) -> int: ...

    def read(self, length: int = -1) -> bytes: ...


def _assert_matches(stream: ReadableStream, model: IndexModel, cases: list[tuple[int, int]], *, reserved: bool) -> None:
    for index, (offset, length) in enumerate(cases):
        stream.seek(offset)
        actual = stream.read(length)
        expected = model.read(offset, length, reserved=reserved)
        assert actual == expected, (
            f"read {index} at {offset:#x} ({length:#x} bytes, reserved={reserved}) differs: "
            f"actual={actual[:32]!r} expected={expected[:32]!r}"
        )


def _sizes(block_size: int, chunk_size: int, layout: str) -> tuple[int, int]:
    """Return a logical/max size pair for a layout, always block aligned."""
    span = Geometry(block_size=block_size, chunk_size=chunk_size, size=0, max_size=1).table_span
    if layout == "grow":
        return span + 3 * chunk_size, 3 * span + 5 * block_size
    if layout == "equal":
        size = (2 * span + chunk_size + block_size) // block_size * block_size
        return size, size
    if layout == "empty":
        return 0, 2 * span + 3 * block_size
    if layout == "single":
        return span - block_size, span + 7 * chunk_size + 3 * block_size
    raise ValueError(f"unknown layout {layout}")


@pytest.mark.parametrize(
    ("block_size", "chunk_size", "layout"),
    [
        (512, 32 * 1024, "grow"),
        (512, 64 * 1024, "grow"),
        (1024, 64 * 1024, "grow"),
        (4096, 256 * 1024, "grow"),
        (512, 1024 * 1024, "grow"),
        (512, 64 * 1024, "equal"),
        (512, 64 * 1024, "empty"),
        (4096, 256 * 1024, "single"),
    ],
)
def test_asif_index_model(block_size: int, chunk_size: int, layout: str) -> None:
    """Compare every logical read with an independent index model on a synthetic image."""
    size, max_size = _sizes(block_size, chunk_size, layout)
    image = SyntheticASIF(block_size, chunk_size, size=size, max_size=max_size)
    geom = image.geometry
    asif = ASIF(image)
    model = IndexModel(image)

    assert asif.block_size == block_size
    assert asif.chunk_size == chunk_size
    assert asif.size == geom.size == size
    assert asif.max_size == geom.max_size == max_size
    assert asif._num_table_entries == geom.table_entries
    assert asif._size_per_table == geom.table_span
    assert asif._num_directory_entries == geom.table_count
    assert [directory.version for directory in asif.directories] == [2, 1]
    assert asif.active_directory.entries[: geom.table_count] == [
        TABLE_CHUNK_BASE + table for table in range(geom.table_count)
    ]

    # Every active table entry has dirty flag bits that must not influence the chunk number.
    for (table, slot), chunk in image.allocations.items():
        entry = image.tables[table][slot + slot // geom.reserved_entries]
        assert entry & CHUNK_NUMBER_MASK == chunk
        assert entry & DIRTY_MASK

    # The stale directory points at different physical tables with different markers.
    assert asif.active_directory.entries[: geom.table_count] != [
        STALE_TABLE_CHUNK_BASE + table for table in range(geom.table_count)
    ]

    with asif.open() as stream:
        _assert_matches(stream, model, _sequential_cases(image, reserved=False), reserved=False)
        _assert_matches(stream, model, list(reversed(_sequential_cases(image, reserved=False))), reserved=False)
        _assert_matches(stream, model, _short_cases(image, reserved=False), reserved=False)

        stream.seek(geom.size)
        assert stream.read(geom.chunk_size) == b""

    with asif.open(reserved=True) as stream:
        _assert_matches(stream, model, _sequential_cases(image, reserved=True), reserved=True)
        _assert_matches(stream, model, list(reversed(_sequential_cases(image, reserved=True))), reserved=True)
        _assert_matches(stream, model, _short_cases(image, reserved=True), reserved=True)

        stream.seek(geom.max_size)
        assert stream.read(geom.chunk_size) == b""

    # Reads at every real data chunk start with that chunk's unique marker.
    for (table, slot), chunk in sorted(image.allocations.items()):
        offset = table * geom.table_span + slot * geom.chunk_size
        view_size = geom.max_size if offset >= geom.size else geom.size
        if offset >= view_size:
            continue
        with asif.open(reserved=offset >= geom.size) as stream:
            stream.seek(offset)
            assert stream.read(len(image.markers[chunk].header)) == image.markers[chunk].header


def _minimal_image() -> SyntheticASIF:
    # This chunk size has three complete groups, so the first reserved entry sits between real slots.
    return SyntheticASIF(512, 64 * 1024)


def test_reserved_entry_is_not_a_logical_slot() -> None:
    """Forgetting the interspersed reserved entry reads its sentinel at the first group boundary."""
    image = _minimal_image()
    geom = image.geometry
    model = IndexModel(image)
    assert geom.groups >= 2

    slot = geom.reserved_entries
    data_chunk = image.allocations[(0, slot)]
    sentinel_chunk = SENTINEL_CHUNK_BASE

    assert image.tables[0][slot] & CHUNK_NUMBER_MASK == sentinel_chunk
    assert image.tables[0][slot + 1] & CHUNK_NUMBER_MASK == data_chunk

    offset = slot * geom.chunk_size
    correct = model.read(offset, geom.chunk_size)
    faulty = model.read(offset, geom.chunk_size, fault=Fault.RESERVED_SLOTS)

    assert correct.startswith(image.markers[data_chunk].header)
    assert faulty.startswith(image.markers[sentinel_chunk].header)
    assert correct != faulty

    with ASIF(image).open() as stream:
        stream.seek(offset)
        assert stream.read(geom.chunk_size) == correct


def test_normal_view_does_not_cross_logical_eof() -> None:
    """The normal view stops at size; only the explicit reserved view sees the backing tail."""
    image = _minimal_image()
    geom = image.geometry
    model = IndexModel(image)

    # The layout places this slot exactly at the logical size boundary.
    assert geom.size % geom.table_span == 3 * geom.chunk_size
    assert (geom.size - geom.table_span) // geom.chunk_size == 3

    data_chunk = image.allocations[(1, 3)]
    marker = image.markers[data_chunk]
    assert marker.header.startswith(b"DATA:1:3:")

    asif = ASIF(image)
    assert model.read(geom.size, geom.chunk_size) == b""
    assert model.read(geom.size - geom.block_size, 2 * geom.block_size) == image.chunk_bytes(
        image.allocations[(1, 2)], geom.chunk_size - geom.block_size, geom.block_size
    )

    faulty = model.read(geom.size, geom.chunk_size, fault=Fault.LOGICAL_EOF)
    assert faulty.startswith(marker.header)

    with asif.open() as stream:
        stream.seek(geom.size)
        assert stream.read(geom.chunk_size) == b""

        # A short read that straddles the logical EOF is truncated, not padded from the reserved area.
        stream.seek(geom.size - geom.block_size)
        straddling = stream.read(geom.chunk_size)
        assert straddling == model.read(geom.size - geom.block_size, geom.chunk_size)
        assert len(straddling) == geom.block_size
        assert not straddling.startswith(marker.header)

    with asif.open(reserved=True) as stream:
        stream.seek(geom.size)
        tail = stream.read(geom.chunk_size)
        assert tail == model.read(geom.size, geom.chunk_size, reserved=True)
        assert tail.startswith(marker.header)
        assert tail != b"\x00" * geom.chunk_size

        stream.seek(geom.max_size)
        assert stream.read(geom.chunk_size) == b""


def test_dirty_bits_are_not_part_of_the_physical_chunk_number() -> None:
    """Using the raw entry as a chunk number lands far outside the stored markers."""
    image = _minimal_image()
    geom = image.geometry
    model = IndexModel(image)

    # This slot carries both dirty bits.
    entry = image.tables[0][2]
    chunk = image.allocations[(0, 2)]
    assert entry & DIRTY_MASK == DIRTY_MASK
    assert entry & CHUNK_NUMBER_MASK == chunk
    assert entry != chunk

    offset = 2 * geom.chunk_size
    marker = image.markers[chunk]
    correct = model.read(offset, geom.chunk_size)
    faulty = model.read(offset, geom.chunk_size, fault=Fault.DIRTY_BITS)

    assert correct.startswith(marker.header)
    assert faulty == b"\x00" * geom.chunk_size
    assert faulty != correct

    with ASIF(image).open() as stream:
        stream.seek(offset)
        assert stream.read(geom.chunk_size) == correct
