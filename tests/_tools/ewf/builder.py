"""Small deterministic EWF builder for chunk integrity regression tests.

The builder writes real EWF section descriptors and a table section so tests can pin down the
exact physical range of every chunk. Checksums are calculated here, independently from the code
under test.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

from dissect.evidence.ewf import c_ewf

SEGMENT_HEADER_SIZE = len(c_ewf.SegmentHeader)
SECTION_DESCRIPTOR_SIZE = len(c_ewf.SectionDescriptor)
TABLE_HEADER_SIZE = len(c_ewf.TableSection)


def adler32(data: bytes) -> int:
    """Calculate the Adler-32 checksum used by EWF chunk and entry checksums."""
    return zlib.adler32(data) & 0xFFFFFFFF


@dataclass
class ChunkSpec:
    """A chunk to store in an EWF image."""

    data: bytes
    compressed: bool = False
    # Store this chunk after the table metadata inside the table section
    in_table: bool = False
    # Optional override for the trailing checksum of an uncompressed chunk
    stored_checksum: int | None = None
    # Optional override for the physically stored bytes (compressed or uncompressed)
    stored_stream: bytes | None = None


@dataclass
class EWFImage:
    """A built EWF segment and the independently calculated physical ranges of its chunks."""

    data: bytes
    chunk_size: int
    chunk_ranges: list[tuple[int, int]]
    table_offset: int
    table_size: int
    sectors_offset: int


def _descriptor(section_type: str, next_offset: int, size: int) -> bytes:
    body = struct.pack("<16sQQ", section_type.encode(), next_offset, size) + b"\x00" * 40
    return body + struct.pack("<I", adler32(body))


def _section(section_type: str, payload: bytes, next_offset: int) -> bytes:
    size = SECTION_DESCRIPTOR_SIZE + len(payload)
    return _descriptor(section_type, next_offset, size) + payload


def _volume_section(number_of_chunks: int, chunk_size: int, total_size: int) -> bytes:
    # VolumeSectionSmart is 94 bytes; the code uses the descriptor size to select it
    body = bytearray(94)
    struct.pack_into(
        "<IIIII",
        body,
        0,
        0,
        number_of_chunks,
        chunk_size,  # sectors per chunk, with a byte per sector
        1,  # bytes per sector
        total_size,  # number of sectors
    )
    body[89:94] = b"STD\x00\x00"
    struct.pack_into("<I", body, 90, adler32(bytes(body[:90])))
    return bytes(body)


def build_ewf(chunks: list[ChunkSpec]) -> EWFImage:
    """Build a single segment EWF image with the given chunks.

    Layout: segment header, volume section, sectors section, table section, done section.
    Chunks with ``in_table`` set are stored after the table metadata in the table section, all
    other chunks are stored in the sectors section placed before the table.
    """
    if not chunks:
        raise ValueError("Need at least one chunk")

    chunk_size = max(len(spec.data) for spec in chunks)
    total_size = sum(len(spec.data) for spec in chunks)

    header = c_ewf.SegmentHeader(
        signature=b"EVF\x09\x0d\x0a\xff\x00", fields_start=1, segment_number=1, fields_end=0
    ).dumps()
    volume = _volume_section(len(chunks), chunk_size, total_size)

    # Serialize each chunk exactly as it should be stored
    stored: list[bytes] = []
    for spec in chunks:
        if spec.stored_stream is not None:
            stored.append(spec.stored_stream)
        elif spec.compressed:
            stored.append(zlib.compress(spec.data))
        elif spec.stored_checksum is not None:
            stored.append(spec.data + struct.pack("<I", spec.stored_checksum))
        else:
            stored.append(spec.data + struct.pack("<I", adler32(spec.data)))

    volume_offset = SEGMENT_HEADER_SIZE
    volume_size = SECTION_DESCRIPTOR_SIZE + len(volume)
    sectors_offset = volume_offset + volume_size

    # Partition chunks between the sectors section and the table section
    sectors_data = b""
    sector_offsets: dict[int, int] = {}
    for idx, spec in enumerate(chunks):
        if not spec.in_table:
            sector_offsets[idx] = len(sectors_data)
            sectors_data += stored[idx]

    sectors_size = SECTION_DESCRIPTOR_SIZE + len(sectors_data)
    table_offset = sectors_offset + sectors_size

    # Table payload: header, entries, checksum over entries, then in-table chunk data
    table_prefix_size = TABLE_HEADER_SIZE + 4 * len(chunks) + 4
    table_data_cursor = table_offset + SECTION_DESCRIPTOR_SIZE + table_prefix_size

    in_table_offsets: dict[int, int] = {}
    for idx, spec in enumerate(chunks):
        if spec.in_table:
            in_table_offsets[idx] = table_data_cursor
            table_data_cursor += len(stored[idx])

    entries: list[int] = []
    for idx, spec in enumerate(chunks):
        if spec.in_table:
            relative = in_table_offsets[idx] - sectors_offset
        else:
            relative = sector_offsets[idx] + SECTION_DESCRIPTOR_SIZE
        entries.append(relative | (0x80000000 if spec.compressed else 0))

    table_entries = b"".join(struct.pack("<I", entry) for entry in entries)
    table_payload = struct.pack("<IIQII", len(chunks), 0, sectors_offset, 0, 0)
    table_payload += table_entries
    table_payload += struct.pack("<I", adler32(table_entries))
    table_payload += b"".join(stored[idx] for idx in in_table_offsets)

    table_size = SECTION_DESCRIPTOR_SIZE + len(table_payload)
    done_offset = table_offset + table_size

    data = header
    data += _section("volume", volume, sectors_offset)
    data += _section("sectors", sectors_data, table_offset)
    data += _section("table", table_payload, done_offset)
    data += _section("done", b"", done_offset)

    # Record physical ranges independently of the parser
    ranges: list[tuple[int, int]] = []
    for idx in range(len(chunks)):
        if idx in in_table_offsets:
            start = in_table_offsets[idx]
        else:
            start = sectors_offset + SECTION_DESCRIPTOR_SIZE + sector_offsets[idx]
        ranges.append((start, start + len(stored[idx])))

    return EWFImage(
        data=data,
        chunk_size=chunk_size,
        chunk_ranges=ranges,
        table_offset=table_offset,
        table_size=table_size,
        sectors_offset=sectors_offset,
    )
