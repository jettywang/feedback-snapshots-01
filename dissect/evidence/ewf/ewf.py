from __future__ import annotations

import codecs
import zlib
from bisect import bisect_right
from functools import cached_property, lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.evidence.adcrypt.adcrypt import ADCrypt, is_adcrypt
from dissect.evidence.ewf import c_ewf
from dissect.evidence.ewf.stream import EWFStream
from dissect.evidence.exception import EWFError

if TYPE_CHECKING:
    from types import TracebackType

    from typing_extensions import Self

MAX_OPEN_SEGMENTS = 128

CHUNK_OFFSET_MASK = 0x7FFFFFFF


def find_files(path: str | Path) -> list[Path]:
    """Find all related EWF files from the given path."""
    if not isinstance(path, Path):
        path = Path(path)

    path = path.resolve()
    ext = path.suffix

    if ext[1].upper() not in "ELS":
        raise ValueError(f"Invalid EWF file: {path}")

    ewfglob = f"[{ext[1]}-{'Z' if ext[1].isupper() else 'z'}]" if len(ext) == 4 else f"{ext[1]}[x-z]"

    return sorted(path.parent.glob(f"{path.stem}.{ewfglob}[0-9A-Za-z][0-9A-Za-z]"))


class EWF:
    """Expert Witness Disk Image Format.

    Args:
        fh: A file handle, list of file handles, path or list of paths to the EWF segment files.
            If a path is provided, all related segment files will be automatically discovered.
    """

    def __init__(self, fh: BinaryIO | list[BinaryIO] | Path | list[Path]):
        fhs = find_files(fh) if isinstance(fh, Path) else [fh] if not isinstance(fh, list) else fh

        self.fh = fhs
        self.header: HeaderSection | None = None
        self.volume: VolumeSection | None = None

        self.chunk_size = 0
        self.size = 0

        self._segments: dict[int, Segment] = {}
        self._segment_lru: list[int] = []

        self._chunk_lookup: list[int] = []
        self._chunk_map: list[tuple[int, int]] = []

        if not self.fh:
            raise ValueError("No segment files provided for EWF container")

        self.adcrypt = None

        first_segment = self.segment(0)
        if is_adcrypt(first_segment.fh):
            self.adcrypt = ADCrypt(first_segment.fh)
        else:
            self._open_ewf()

        self.read_chunk = lru_cache(128)(self.read_chunk)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self.close()

    def is_adcrypt(self) -> bool:
        """Return whether the EWF container is ADCRYPT encrypted."""
        return self.adcrypt is not None

    def is_locked(self) -> bool:
        """Return whether the ADCRYPT container is locked."""
        return self.is_adcrypt() and self.adcrypt.is_locked()

    def segment(self, idx: int) -> Segment:
        """Open a segment by index.

        Implements a simple LRU cache to limit the number of open segments.

        Args:
            idx: Index of the segment to open.
        """
        # Poor mans LRU
        if idx in self._segments:
            self._segment_lru.remove(idx)
            self._segment_lru.append(idx)
            return self._segments[idx]

        if len(self._segment_lru) >= MAX_OPEN_SEGMENTS:
            oldest_idx = self._segment_lru.pop(0)
            oldest_segment = self._segments.pop(oldest_idx)

            # Only close file handles that we opened ourselves
            if isinstance(self.fh[oldest_idx], Path):
                oldest_segment.fh.close()

            del oldest_segment

        fh = self.fh[idx]
        if isinstance(fh, Path):
            fh = fh.open("rb")

        if self.is_adcrypt() and not self.is_locked():
            fh = self.adcrypt.wrap(fh, idx)

        segment = Segment(fh)
        self._segments[idx] = segment
        self._segment_lru.append(idx)

        return segment

    def unlock(self, *, passphrase: str | bytes | None = None, private_key: Path | bytes | None = None) -> None:
        """Unlock the ADCRYPT container with a given passphrase or private key.

        Args:
            passphrase: The passphrase to unlock the container.
            private_key: The private key to unlock the container.

        Raises:
            RuntimeError: If required dependencies are missing.
            ValueError: If unlocking failed.
        """
        self.adcrypt.unlock(passphrase=passphrase, private_key=private_key)

        # Reset LRU
        self._segments = {}
        self._segment_lru = []

        # Open the EWF
        self._open_ewf()

    def _open_ewf(self) -> None:
        """Open the EWF container and initialize the volume and chunk information."""
        self.volume = None

        chunk = 0
        for i in range(len(self.fh)):
            segment = self.segment(i)
            if segment.header.signature not in (b"EVF\x09\x0d\x0a\xff\x00", b"LVF\x09\x0d\x0a\xff\x00"):
                raise ValueError(f"Invalid EWF signature in segment {i}, got {segment.header.signature!r}")

            if segment.number != i + 1:
                raise ValueError(f"Invalid EWF segment number in segment {i}, got {segment.number}, expected {i + 1}")

            if not self.volume and segment.volume:
                self.volume = segment.volume
                self.chunk_size = self.volume.sectors_per_chunk * self.volume.sector_size
            elif not self.volume and not segment.volume:
                raise ValueError("Missing expected volume section in first segment")

            for j, table in enumerate(segment.tables):
                chunk += table.number_of_entries
                self._chunk_lookup.append(chunk)
                self._chunk_map.append((i, j))

        max_size = self.volume.number_of_chunks * self.chunk_size
        last_chunk = self.read_chunk(self.volume.number_of_chunks - 1)

        self.size = max_size - (self.chunk_size - len(last_chunk))

    def read_chunk(self, chunk: int) -> bytes:
        """Read a chunk of data from the EWF container.

        The returned data is only ever bytes that have been verified against the format's own
        integrity information: uncompressed chunks against their trailing Adler-32, compressed
        chunks against a complete zlib stream with the expected decompressed length.

        Args:
            chunk: The chunk index to read.

        Raises:
            IndexError: If the chunk index is out of range.
            EWFError: If the chunk cannot be read or its integrity verification fails.
        """
        lookup_idx = bisect_right(self._chunk_lookup, chunk)
        if lookup_idx >= len(self._chunk_map):
            raise IndexError(f"Chunk {chunk} out of range")

        segment_idx, table_idx = self._chunk_map[lookup_idx]

        segment = self.segment(segment_idx)
        table = segment.tables[table_idx]

        chunk_offset = 0 if lookup_idx == 0 else self._chunk_lookup[lookup_idx - 1]
        relative_chunk = chunk - chunk_offset

        if relative_chunk < 0 or relative_chunk >= table.number_of_entries:
            raise IndexError(f"Chunk {chunk} out of range")

        entry = table.entries[relative_chunk]
        offset_of_chunk = table.base_offset + (entry & CHUNK_OFFSET_MASK)
        compressed = entry >> 31 == 1

        if offset_of_chunk > segment.size:
            raise EWFError(f"Chunk {chunk} data offset {offset_of_chunk:#x} exceeds segment size {segment.size:#x}")

        end_of_chunk = self._chunk_end_of_chunk(segment, table, relative_chunk, offset_of_chunk)

        if end_of_chunk < offset_of_chunk:
            raise EWFError(f"Negative size for chunk {chunk}: data range {offset_of_chunk:#x}-{end_of_chunk:#x}")

        # Verify the physical range against the segment so a bad offset cannot read beyond the file
        if end_of_chunk > segment.size:
            raise EWFError(
                f"Chunk {chunk} data range {offset_of_chunk:#x}-{end_of_chunk:#x} "
                f"exceeds segment size {segment.size:#x}"
            )

        size_of_chunk = end_of_chunk - offset_of_chunk
        if size_of_chunk == 0:
            raise EWFError(f"Chunk {chunk} has an empty data range at {offset_of_chunk:#x}")

        segment.fh.seek(offset_of_chunk)
        buf = segment.fh.read(size_of_chunk)
        if len(buf) != size_of_chunk:
            raise EWFError(
                f"Truncated chunk {chunk} at {offset_of_chunk:#x}-{end_of_chunk:#x}: "
                f"expected {size_of_chunk} bytes, got {len(buf)}"
            )

        expected_size = self._expected_chunk_size(chunk)
        if compressed:
            return self._decode_compressed_chunk(chunk, buf, expected_size, offset_of_chunk, end_of_chunk)

        return self._decode_raw_chunk(chunk, buf, expected_size, offset_of_chunk, end_of_chunk)

    def _expected_chunk_size(self, chunk: int) -> int | None:
        """Return the required decompressed size of a chunk, or ``None`` for the final chunk."""
        if chunk == self.volume.number_of_chunks - 1:
            # The last chunk contains the remainder of the media and is allowed to be shorter
            return None

        return self.chunk_size

    def _chunk_end_of_chunk(
        self, segment: Segment, table: TableSection, relative_chunk: int, offset_of_chunk: int
    ) -> int:
        """Determine the end offset of a chunk from the next chunk or the containing section."""
        section = self._section_for_offset(segment, offset_of_chunk)
        if section is None:
            raise EWFError(f"Chunk data offset {offset_of_chunk:#x} does not belong to a section")

        section_start = section.descriptor.offset
        section_end = section_start + section.descriptor.raw_size

        if isinstance(section, TableSection) and offset_of_chunk < self._table_data_end(section):
            raise EWFError(f"Chunk data offset {offset_of_chunk:#x} overlaps table section metadata of {section!r}")

        if relative_chunk < table.number_of_entries - 1:
            next_offset = table.base_offset + (table.entries[relative_chunk + 1] & CHUNK_OFFSET_MASK)

            if next_offset <= offset_of_chunk:
                raise EWFError(
                    f"Invalid chunk offsets in {table!r}: chunk {relative_chunk} at {offset_of_chunk:#x} "
                    f"is followed by {next_offset:#x}"
                )

            next_section = self._section_for_offset(segment, next_offset)
            if next_section is None:
                raise EWFError(
                    f"Invalid chunk offsets in {table!r}: chunk {relative_chunk + 1} at {next_offset:#x} "
                    f"does not belong to a section"
                )

            if isinstance(next_section, TableSection) and next_offset < self._table_data_end(next_section):
                # The next entry points into table metadata, not chunk data
                raise EWFError(
                    f"Invalid chunk offsets in {table!r}: chunk {relative_chunk + 1} at {next_offset:#x} "
                    f"overlaps table section metadata of {next_section!r}"
                )

            if next_section is section:
                # The next chunk is in the same section, so it marks the end of this chunk
                return next_offset

            # The next chunk is stored in another section (usually the table section), so this
            # chunk ends where the containing section ends
            return section_end

        # The chunk size of the last entry in a table can't be derived from the next entry.
        # The data is either stored in a data section (usually the sectors section) or within
        # the table section itself. Use the end of the section that physically contains the
        # chunk as the end of its range.
        if table.number_of_entries > 1:
            previous_offset = table.base_offset + (table.entries[-2] & CHUNK_OFFSET_MASK)
            if offset_of_chunk <= previous_offset:
                raise EWFError(
                    f"Invalid chunk offsets in {table!r}: last chunk at {offset_of_chunk:#x} "
                    f"is not after {previous_offset:#x}"
                )

        if isinstance(section, TableSection) and offset_of_chunk < self._table_data_end(section):
            raise EWFError(f"Last chunk offset {offset_of_chunk:#x} overlaps table section metadata of {section!r}")

        # A chunk stored in a data section can also be followed by another table's chunk in that
        # same section, so use the next known chunk offset as the end if it is inside the section
        for next_offset in segment.chunk_offsets:
            if next_offset <= offset_of_chunk:
                continue
            if next_offset >= section_end:
                break
            return next_offset

        return section_end

    def _section_for_offset(self, segment: Segment, offset: int) -> Section | None:
        """Return the section that physically contains an offset."""
        for section in segment.sections:
            start = section.descriptor.offset
            if start <= offset < start + section.descriptor.raw_size:
                return section
        return None

    def _table_data_end(self, table: TableSection) -> int:
        """Return the offset where a table section's own metadata ends and chunk data can start."""
        return (
            table.descriptor.offset
            + len(c_ewf.SectionDescriptor)
            + len(c_ewf.TableSection)
            + table.number_of_entries * 4
            + 4
        )

    def _decode_raw_chunk(self, chunk: int, buf: bytes, expected_size: int | None, start: int, end: int) -> bytes:
        """Verify and return an uncompressed chunk.

        Uncompressed chunks are stored as their data followed by a 4 byte little-endian Adler-32
        checksum over that data.
        """
        if len(buf) < 4:
            raise EWFError(f"Truncated uncompressed chunk {chunk} at {start:#x}-{end:#x}: missing trailing checksum")

        data = buf[:-4]
        stored_checksum = int.from_bytes(buf[-4:], "little")

        if expected_size is None:
            if len(data) > self.chunk_size:
                raise EWFError(
                    f"Uncompressed chunk {chunk} is {len(data)} bytes, larger than chunk size {self.chunk_size}"
                )
        elif len(data) != expected_size:
            raise EWFError(f"Uncompressed chunk {chunk} has size {len(data)}, expected {expected_size}")

        if len(data) == 0:
            raise EWFError(f"Uncompressed chunk {chunk} contains no data")

        actual_checksum = zlib.adler32(data) & 0xFFFFFFFF
        if actual_checksum != stored_checksum:
            raise EWFError(
                f"Checksum mismatch for uncompressed chunk {chunk} at {start:#x}-{end:#x}: "
                f"stored {stored_checksum:#x}, calculated {actual_checksum:#x}"
            )

        return data

    def _decode_compressed_chunk(
        self, chunk: int, buf: bytes, expected_size: int | None, start: int, end: int
    ) -> bytes:
        """Verify and return a zlib compressed chunk.

        A compressed chunk must be a single, complete zlib stream that consumes its entire
        physical range and decompresses to exactly the expected chunk size.
        """
        decompressor = zlib.decompressobj()

        # Bound the output to catch chunks that decompress beyond the chunk size. Use the full
        # chunk size as limit so a complete stream can be detected even when a final chunk is
        # expected to be shorter.
        max_length = self.chunk_size + 1
        try:
            data = decompressor.decompress(buf, max_length)
            data += decompressor.flush()
        except zlib.error as e:
            raise EWFError(f"Unable to decompress chunk {chunk} at {start:#x}-{end:#x}: {e}") from e

        if decompressor.unconsumed_tail:
            raise EWFError(f"Compressed chunk {chunk} at {start:#x}-{end:#x} decompresses beyond the expected size")

        if not decompressor.eof:
            raise EWFError(f"Truncated zlib stream in compressed chunk {chunk} at {start:#x}-{end:#x}")

        if decompressor.unused_data:
            raise EWFError(
                f"Compressed chunk {chunk} at {start:#x}-{end:#x} has {len(decompressor.unused_data)} bytes "
                f"of trailing data after the zlib stream"
            )

        if expected_size is None:
            if len(data) > self.chunk_size:
                raise EWFError(
                    f"Compressed chunk {chunk} decompressed to {len(data)} bytes, "
                    f"larger than chunk size {self.chunk_size}"
                )
        elif len(data) != expected_size:
            raise EWFError(f"Compressed chunk {chunk} decompressed to {len(data)} bytes, expected {expected_size}")

        return data

    def open(self) -> BinaryIO:
        """Open a stream to read the EWF container contents."""
        if self.is_locked():
            raise ValueError("EWF container is locked by ADCRYPT")

        return EWFStream(self)

    def close(self) -> None:
        """Close all segment file handles that we opened ourselves and clear the segment cache."""
        for idx, segment in self._segments.items():
            if isinstance(self.fh[idx], Path):
                segment.fh.close()

        self._segments = {}
        self._segment_lru = []


class Segment:
    """EWF segment."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh

        self.fh.seek(0, 2)
        self.size = self.fh.tell()

        self.fh.seek(0)
        self.header = c_ewf.SegmentHeader(fh)
        self.number = self.header.segment_number

    @cached_property
    def sections(self) -> list[Section]:
        """Return all sections in this segment."""
        result = []

        offset = len(c_ewf.SegmentHeader)
        while True:
            self.fh.seek(offset)
            section = Section.from_fh(self.fh)
            result.append(section)

            if section.descriptor.next == offset or section.descriptor.type == b"done":
                break

            offset = section.descriptor.next

        return result

    @cached_property
    def headers(self) -> list[HeaderSection]:
        """Return all header sections in this segment."""
        return [section for section in self.sections if isinstance(section, HeaderSection)]

    @cached_property
    def tables(self) -> list[TableSection]:
        """Return all table sections in this segment."""
        return [section for section in self.sections if type(section) is TableSection]  # Ignore Table2Section

    @cached_property
    def chunk_offsets(self) -> list[int]:
        """Return the sorted physical start offsets of all chunks in this segment."""
        offsets = []
        for table in self.tables:
            base_offset = table.base_offset
            offsets.extend(base_offset + (entry & CHUNK_OFFSET_MASK) for entry in table.entries)
        return sorted(offsets)

    @cached_property
    def volume(self) -> VolumeSection | None:
        """Return the volume section in this segment, if present."""
        for section in self.sections:
            if isinstance(section, VolumeSection):
                return section
        return None


class SectionDescriptor:
    """EWF section descriptor."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh

        self.offset = fh.tell()
        self.descriptor = c_ewf.SectionDescriptor(fh)

    def __repr__(self) -> str:
        return (
            f"<SectionDescriptor "
            f"type={self.type!r} size={self.size:#x} offset={self.offset:#x} checksum={self.checksum:#x}>"
        )

    @property
    def type(self) -> str:
        """The type of the section."""
        return self.descriptor.type.rstrip(b"\x00").decode()

    @property
    def next(self) -> int:
        """The offset of the next section."""
        return self.descriptor.next

    @property
    def raw_size(self) -> int:
        """The raw size of the section, including the descriptor."""
        return self.descriptor.size

    @property
    def size(self) -> int:
        """The size of the section data."""
        return (self.descriptor.size - len(c_ewf.SectionDescriptor)) if self.descriptor.size else 0

    @property
    def data(self) -> bytes:
        """The raw data of the section."""
        self.fh.seek(self.offset + len(c_ewf.SectionDescriptor))
        return self.fh.read(self.size)

    @property
    def checksum(self) -> int:
        """The checksum of the section data."""
        return self.descriptor.checksum


class Section:
    """EWF section."""

    def __init__(self, descriptor: SectionDescriptor):
        self.descriptor = descriptor

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} type={self.descriptor.type!r} size={self.descriptor.size:#x}>"

    @classmethod
    def from_fh(
        cls, fh: BinaryIO
    ) -> Section | HeaderSection | VolumeSection | DataSection | TableSection | Table2Section | HashSection:
        """Open a section from a file-like object."""
        descriptor = SectionDescriptor(fh)

        if descriptor.type in ("header", "header2"):
            return HeaderSection(descriptor)

        if descriptor.type in ("disk", "volume"):
            return VolumeSection(descriptor)

        if descriptor.type == "data":
            return DataSection(descriptor)

        if descriptor.type == "table":
            return TableSection(descriptor)

        if descriptor.type == "table2":
            return Table2Section(descriptor)

        if descriptor.type == "hash":
            return HashSection(descriptor)

        return Section(descriptor)

    @property
    def type(self) -> str:
        """The type of the section."""
        return self.descriptor.type

    @cached_property
    def data(self) -> bytes:
        """The raw data of the section."""
        return self.descriptor.data


class HeaderSection(Section):
    """EWF header section."""

    @cached_property
    def data(self) -> str:
        """The header data."""
        data = zlib.decompress(self.descriptor.data)
        return data.decode("utf16") if data[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE) else data.decode()


class VolumeSection(Section):
    """EWF volume section."""

    @cached_property
    def data(self) -> c_ewf.VolumeSection | c_ewf.VolumeSectionSmart:
        """The volume data."""
        return (c_ewf.VolumeSection if self.descriptor.size == len(c_ewf.VolumeSection) else c_ewf.VolumeSectionSmart)(
            self.descriptor.data
        )

    @property
    def number_of_chunks(self) -> int:
        """The number of chunks in the volume."""
        return self.data.number_of_chunks

    @property
    def sectors_per_chunk(self) -> int:
        """The number of sectors per chunk."""
        return self.data.sectors_per_chunk

    @property
    def sector_size(self) -> int:
        """The size of a sector in bytes."""
        return self.data.bytes_per_sector


class DataSection(Section):
    """EWF data section."""

    @cached_property
    def data(self) -> c_ewf.DataSection:
        """The data section."""
        return c_ewf.DataSection(self.descriptor.data)


class TableSection(Section):
    """EWF table section."""

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"type={self.descriptor.type!r} size={self.descriptor.size:#x} "
            f"number_of_entries={self.number_of_entries} base_offset={self.base_offset:#x}>"
        )

    @cached_property
    def data(self) -> c_ewf.TableSection:
        """The table section."""
        self.descriptor.fh.seek(self.descriptor.offset + len(c_ewf.SectionDescriptor))
        return c_ewf.TableSection(self.descriptor.fh)

    @cached_property
    def entries(self) -> list[int]:
        """The table entries."""
        self.descriptor.fh.seek(self.descriptor.offset + len(c_ewf.SectionDescriptor) + len(c_ewf.TableSection))
        return c_ewf.uint32[self.number_of_entries](self.descriptor.fh)

    @property
    def number_of_entries(self) -> int:
        """The number of entries in the table."""
        return self.data.number_of_entries

    @property
    def base_offset(self) -> int:
        """The base offset of the table."""
        return self.data.base_offset


class Table2Section(TableSection):
    """EWF table2 section."""


class HashSection(Section):
    """EWF hash section."""

    @cached_property
    def data(self) -> c_ewf.HashSection:
        """The hash section."""
        return c_ewf.HashSection(self.descriptor.data)

    @property
    def md5(self) -> str:
        """The MD5 hash of the section."""
        return self.data.md5.hex()
