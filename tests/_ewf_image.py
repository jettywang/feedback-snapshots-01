from __future__ import annotations

import zlib
from dataclasses import dataclass
from io import BytesIO
from typing import TYPE_CHECKING

from dissect.evidence.ewf.c_ewf import c_ewf, c_ewf_error

if TYPE_CHECKING:
    from dissect.evidence.ewf.ewf import AcquisitionError

SECTOR_SIZE = 512
SECTORS_PER_CHUNK = 64
CHUNK_SIZE = SECTOR_SIZE * SECTORS_PER_CHUNK
SECTOR_COUNT = SECTORS_PER_CHUNK * 2
SEGMENT_SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"


@dataclass(frozen=True, slots=True)
class SyntheticError:
    """A minimal stand-in for AcquisitionError when constructing synthetic images."""

    __test__ = False

    first_sector: int
    sector_count: int


def _section_descriptor(section_type: str, next_offset: int, data_size: int) -> bytes:
    return c_ewf.SectionDescriptor(
        type=section_type.encode().ljust(16, b"\x00"),
        next=next_offset,
        size=len(c_ewf.SectionDescriptor) + data_size,
        checksum=0,
    ).dumps()


def _volume_section() -> bytes:
    volume = c_ewf.VolumeSection(
        media_type=c_ewf.MediaType.Fixed,
        number_of_chunks=SECTOR_COUNT // SECTORS_PER_CHUNK,
        sectors_per_chunk=SECTORS_PER_CHUNK,
        bytes_per_sector=SECTOR_SIZE,
        number_of_sectors=SECTOR_COUNT,
        compression_level=c_ewf.CompressionLevel.Best,
        error_granularity=SECTORS_PER_CHUNK,
    )
    data = volume.dumps()
    return _section_descriptor("volume", 0, len(data)) + data


def _chunk(chunk_index: int, *, zero: bool = False) -> bytes:
    if zero:
        return b"\x00" * CHUNK_SIZE
    return bytes([chunk_index % 256]) * CHUNK_SIZE


def build_ewf(
    errors: list[AcquisitionError] | None = None,
    *,
    zero_chunks: tuple[int, ...] = (),
    include_errors_section: bool = False,
) -> BytesIO:
    """Build a minimal single-segment EWF image in memory.

    The image follows the classic libewf section ordering, including an ``errors`` section placed
    between the chunk data (``sectors``) and the ``table`` section. This keeps the synthetic image
    representative of images produced by real acquisition tools.

    Args:
        errors: Acquisition error entries to record. Implies an errors section is written.
        zero_chunks: Chunk indices whose data is written as all zero bytes, to prove zero-filled
            data is not confused with acquisition errors.
        include_errors_section: Force an empty errors section to be written even when ``errors`` is
            empty.
    """
    errors = errors or []
    has_errors_section = include_errors_section or bool(errors)
    buf = BytesIO()

    buf.write(
        c_ewf.SegmentHeader(
            signature=SEGMENT_SIGNATURE,
            fields_start=1,
            segment_number=1,
            fields_end=0,
        ).dumps()
    )

    # Placeholder offsets; sections are patched together once their positions are known.
    volume_offset = buf.tell()
    volume_section = _volume_section()
    buf.write(volume_section)

    sectors_offset = buf.tell()
    chunk_data = []
    for chunk_index in range(SECTOR_COUNT // SECTORS_PER_CHUNK):
        raw = _chunk(chunk_index, zero=chunk_index in zero_chunks)
        compressed = zlib.compress(raw)
        chunk_data.append(compressed)
    sectors_data = b"".join(chunk_data)
    sectors_descriptor_offset = buf.tell()
    buf.write(b"\x00" * len(c_ewf.SectionDescriptor))
    chunk_offsets = []
    relative = 0
    for data in chunk_data:
        chunk_offsets.append(relative)
        relative += len(data)
    buf.write(sectors_data)

    errors_offset = None
    if has_errors_section:
        errors_offset = buf.tell()
        header = c_ewf_error.ErrorSection(
            number_of_errors=len(errors),
            sector_count=sum(error.sector_count for error in errors),
        ).dumps()
        entries = b"".join(
            c_ewf_error.ErrorSectionEntry(
                sector_count=error.sector_count,
                first_sector=error.first_sector,
            ).dumps()
            for error in errors
        )
        errors_data = header + entries
        errors_descriptor_offset = buf.tell()
        buf.write(b"\x00" * len(c_ewf.SectionDescriptor))
        buf.write(errors_data)

    table_offset = buf.tell()
    table = c_ewf.TableSection(
        number_of_entries=len(chunk_data),
        base_offset=sectors_offset + len(c_ewf.SectionDescriptor),
        checksum=0,
    ).dumps()
    table_entries = b"".join((offset | 0x80000000).to_bytes(4, "little") for offset in chunk_offsets)
    table_data = table + table_entries
    table_descriptor_offset = buf.tell()
    buf.write(b"\x00" * len(c_ewf.SectionDescriptor))
    buf.write(table_data)

    done_offset = buf.tell()
    done_descriptor = c_ewf.SectionDescriptor(
        type=b"done".ljust(16, b"\x00"),
        next=done_offset,
        size=0,
        checksum=0,
    ).dumps()
    buf.write(done_descriptor)

    # Patch the section descriptors with their "next section" offsets.
    def patch(offset: int, descriptor: bytes) -> None:
        buf.seek(offset)
        buf.write(descriptor)

    next_after_sectors = errors_offset if has_errors_section else table_offset
    patch(
        sectors_descriptor_offset,
        _section_descriptor("sectors", next_after_sectors, len(sectors_data)),
    )
    if has_errors_section:
        patch(
            errors_descriptor_offset,
            _section_descriptor("errors", table_offset, len(errors_data)),
        )
    patch(table_descriptor_offset, _section_descriptor("table", done_offset, len(table_data)))
    patch(volume_offset, _section_descriptor("volume", sectors_offset, len(volume_section)))

    buf.seek(0)
    return buf


def build_truncated_errors_ewf() -> BytesIO:
    """Build an EWF image whose errors section declares more entries than it contains."""
    # Start from an image with a valid, empty errors section, then corrupt the entry count.
    buf = build_ewf(include_errors_section=True)
    raw = buf.getvalue()
    descriptor_offset = raw.index(b"errors")
    data_offset = descriptor_offset + len(c_ewf.SectionDescriptor)
    bogus_header = c_ewf_error.ErrorSection(number_of_errors=2, sector_count=0).dumps()
    buf.seek(data_offset)
    buf.write(bogus_header)
    buf.seek(0)
    return buf
