"""A minimal, dependency-free EWF writer used to build controlled integrity test sets.

The emitted bytes use the same on-disk structures the production parser consumes
(see :mod:`dissect.evidence.ewf.c_ewf`): a 13-byte segment header, 76-byte section
descriptors, a full ``volume``/``data`` section, a sectors region and a ``table`` section.
Checksums are not validated by the parser and are therefore written as zero, keeping the
helper focused on the structural relationships the integrity checks rely on.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field
from io import BytesIO

from dissect.evidence.ewf.c_ewf import c_ewf

EVF_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
DESCRIPTOR_SIZE = len(c_ewf.SectionDescriptor)


def _descriptor(section_type: bytes, next_offset: int, size: int) -> bytes:
    descriptor = c_ewf.SectionDescriptor()
    descriptor.type = section_type
    descriptor.next = next_offset
    descriptor.size = size
    descriptor.pad = b"\x00" * 40
    descriptor.checksum = 0
    return descriptor.dumps()


def _segment_header(number: int) -> bytes:
    header = c_ewf.SegmentHeader()
    header.signature = EVF_SIGNATURE
    header.fields_start = 1
    header.segment_number = number
    header.fields_end = 0
    return header.dumps()


def _identity_body(
    *,
    number_of_chunks: int,
    sectors_per_chunk: int,
    sector_size: int,
    number_of_sectors: int,
    set_identifier: bytes,
    smart: bool = False,
) -> bytes:
    if smart:
        # The Smart volume variant has no set identifier field; it cannot provide a common identity.
        body = c_ewf.VolumeSectionSmart()
        body.reserved_1 = 0
        body.number_of_chunks = number_of_chunks
        body.sectors_per_chunk = sectors_per_chunk
        body.bytes_per_sector = sector_size
        body.number_of_sectors = number_of_sectors
        body.reserved = b"\x00" * 20
        body.pad = b"\x00" * 45
        body.signature = b"\x00" * 5
        body.checksum = 0
        return body.dumps()

    body = c_ewf.VolumeSection()
    body.media_type = c_ewf.MediaType.Fixed
    body.reserved_1 = b"\x00" * 3
    body.number_of_chunks = number_of_chunks
    body.sectors_per_chunk = sectors_per_chunk
    body.bytes_per_sector = sector_size
    body.number_of_sectors = number_of_sectors
    body.chs_cylinders = 0
    body.chs_heads = 0
    body.chs_sectors = 0
    body.media_flags = c_ewf.MediaFlags.Image
    body.unknown_1 = b"\x00" * 3
    body.palm_volume_start_sector = 0
    body.unknown_2 = 0
    body.smart_logs_start_sector = 0
    body.compression_level = getattr(c_ewf.CompressionLevel, "None")
    body.unknown_3 = b"\x00" * 3
    body.error_granularity = 0
    body.unknown_4 = 0
    body.set_identifier = set_identifier
    body.pad = b"\x00" * 963
    body.signature = b"\x00" * 5
    body.checksum = 0
    return body.dumps()


@dataclass
class ChunkSpec:
    """A chunk to place in a segment.

    Args:
        data: The uncompressed chunk payload (padded to the chunk size by the writer).
        bad_offset: When set, override the table entry offset to point outside the segment.
        compressed: Whether the chunk should be stored compressed.
        raw: Store ``data`` verbatim without padding, e.g. to simulate a corrupt compressed chunk.
    """

    data: bytes
    bad_offset: int | None = None
    compressed: bool = False
    raw: bool = False


@dataclass
class SegmentSpec:
    """A segment to write.

    Args:
        number: The embedded segment number (1-based).
        chunks: The chunks belonging to this segment.
        set_identifier: The acquisition set identifier recorded in the volume/data section.
        is_first: Whether the segment carries a ``volume`` section instead of a ``data`` section.
        is_last: Whether the segment is terminated with a ``done`` section.
        volume_overrides: Optional overrides for the volume parameters recorded by this segment.
        header2: Emit a textual header section on the first segment.
        smart: Use the Smart volume variant on the first segment, which records no set identifier.
    """

    number: int
    chunks: list[ChunkSpec] = field(default_factory=list)
    set_identifier: bytes = b"\x01" * 16
    is_first: bool = False
    is_last: bool = False
    volume_overrides: dict | None = None
    header2: bool = True
    smart: bool = False


@dataclass
class EWFWriteConfig:
    """Shared parameters describing the logical disk behind a segment collection."""

    number_of_chunks: int
    sectors_per_chunk: int = 64
    sector_size: int = 512
    set_identifier: bytes = b"\x01" * 16

    @property
    def chunk_size(self) -> int:
        return self.sectors_per_chunk * self.sector_size

    @property
    def number_of_sectors(self) -> int:
        return self.number_of_chunks * self.sectors_per_chunk


def _pad(data: bytes, size: int) -> bytes:
    if len(data) > size:
        return data[:size]
    return data + b"\x00" * (size - len(data))


def _padded_type(name: str) -> bytes:
    return name.encode().ljust(16, b"\x00")


def write_segment(spec: SegmentSpec, config: EWFWriteConfig) -> bytes:
    """Serialize a single EWF segment according to ``spec`` and the shared ``config``."""
    out = BytesIO()
    out.write(_segment_header(spec.number))

    def reserve_descriptor() -> int:
        offset = out.tell()
        out.write(b"\x00" * DESCRIPTOR_SIZE)
        return offset

    if spec.is_first and spec.header2:
        header2_offset = reserve_descriptor()
        out.write(b"advisory header")

    params = {
        "number_of_chunks": config.number_of_chunks,
        "sectors_per_chunk": config.sectors_per_chunk,
        "sector_size": config.sector_size,
        "number_of_sectors": config.number_of_sectors,
        "set_identifier": spec.set_identifier,
    }
    if spec.volume_overrides:
        params.update(spec.volume_overrides)
    if spec.smart:
        params["smart"] = True
    identity_body = _identity_body(**params)
    identity_type = _padded_type("volume") if spec.is_first else _padded_type("data")
    identity_offset = reserve_descriptor()
    out.write(identity_body)

    sectors_descriptor_offset = reserve_descriptor()

    chunk_payloads: list[bytes] = []
    for chunk in spec.chunks:
        payload = chunk.data if chunk.raw else _pad(chunk.data, config.chunk_size)
        if chunk.compressed and not chunk.raw:
            payload = zlib.compress(payload)
        elif not chunk.compressed:
            # Uncompressed chunks are followed by a 4-byte chunk checksum the reader strips off.
            payload += b"\x00" * 4
        chunk_payloads.append(payload)

    chunk_offsets: list[int] = []
    for payload in chunk_payloads:
        chunk_offsets.append(out.tell())
        out.write(payload)

    table_descriptor_offset = reserve_descriptor()
    table = c_ewf.TableSection()
    table.number_of_entries = len(spec.chunks)
    table._ = 0
    table.base_offset = 0
    table.checksum = 0
    out.write(table.dumps())
    for chunk, chunk_offset in zip(spec.chunks, chunk_offsets, strict=True):
        entry_offset = chunk.bad_offset if chunk.bad_offset is not None else chunk_offset
        flag = 0x80000000 if chunk.compressed else 0
        out.write(c_ewf.uint32.dumps(flag | entry_offset))

    terminator_type = _padded_type("done") if spec.is_last else _padded_type("next")
    terminator_offset = out.tell()
    out.write(_descriptor(terminator_type, terminator_offset, 0))

    def patch(offset: int, section_type: bytes, next_offset: int, size: int) -> None:
        out.seek(offset)
        out.write(_descriptor(section_type, next_offset, size))

    if spec.is_first and spec.header2:
        patch(header2_offset, _padded_type("header2"), identity_offset, identity_offset - header2_offset)

    patch(
        identity_offset,
        identity_type,
        sectors_descriptor_offset,
        sectors_descriptor_offset - identity_offset,
    )
    patch(
        sectors_descriptor_offset,
        _padded_type("sectors"),
        table_descriptor_offset,
        table_descriptor_offset - sectors_descriptor_offset,
    )
    patch(
        table_descriptor_offset,
        _padded_type("table"),
        terminator_offset,
        terminator_offset - table_descriptor_offset,
    )

    out.seek(0, 2)
    return out.getvalue()
