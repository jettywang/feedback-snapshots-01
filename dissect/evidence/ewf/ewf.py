from __future__ import annotations

import codecs
import zlib
from bisect import bisect_right
from dataclasses import dataclass
from functools import cached_property, lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.evidence.adcrypt.adcrypt import ADCrypt, is_adcrypt
from dissect.evidence.ewf import c_ewf
from dissect.evidence.ewf.c_ewf import c_ewf_error
from dissect.evidence.ewf.stream import EWFStream

if TYPE_CHECKING:
    from types import TracebackType

    from typing_extensions import Self

MAX_OPEN_SEGMENTS = 128


@dataclass(frozen=True, slots=True)
class AcquisitionError:
    """A single unreadable sector range as recorded by the acquisition tool.

    These values are parsed verbatim from the EWF ``errors`` sections. They describe ranges of the
    source media that failed to read during acquisition; the corresponding bytes in the container
    (often zero-filled) are not evidence of the original disk contents.

    All sector addressing is relative to the start of the imaged volume, in sectors of
    :attr:`EWF.sector_size` bytes.

    Args:
        segment: Index of the segment file containing the source ``errors`` section.
        first_sector: First (lowest numbered) sector of the unreadable range.
        sector_count: Number of consecutive unreadable sectors.
    """

    segment: int
    first_sector: int
    sector_count: int

    @property
    def last_sector(self) -> int:
        """The last sector covered by this error entry (inclusive)."""
        return self.first_sector + self.sector_count - 1


@dataclass(frozen=True, slots=True)
class ErrorRange:
    """A contiguous range of unreadable sectors.

    Returned by :meth:`EWF.error_ranges`, adjacent or overlapping :class:`AcquisitionError` entries
    are merged into a single range.

    Args:
        first_sector: First sector of the merged range.
        sector_count: Number of sectors in the merged range.
        sources: The original, unmerged :class:`AcquisitionError` entries that make up this range.
    """

    first_sector: int
    sector_count: int
    sources: tuple[AcquisitionError, ...]

    @property
    def last_sector(self) -> int:
        """The last sector covered by this range (inclusive)."""
        return self.first_sector + self.sector_count - 1


@dataclass(frozen=True, slots=True)
class ErrorOverlap:
    """The intersection of a logical read with the recorded acquisition errors.

    Args:
        first_sector: First sector of the overlap, clipped to the queried read and to the volume.
        sector_count: Number of sectors covered by the overlap.
        errors: The original :class:`AcquisitionError` entries responsible for this overlap.
    """

    first_sector: int
    sector_count: int
    errors: tuple[AcquisitionError, ...]

    @property
    def last_sector(self) -> int:
        """The last sector covered by this overlap (inclusive)."""
        return self.first_sector + self.sector_count - 1


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

    @property
    def sector_size(self) -> int:
        """The size of a single sector in bytes, as declared by the volume section."""
        return self.volume.sector_size

    @property
    def number_of_sectors(self) -> int:
        """The number of sectors covered by the imaged volume, as declared by the volume section."""
        return self.volume.data.number_of_sectors

    @cached_property
    def acquisition_errors(self) -> tuple[AcquisitionError, ...]:
        """Return the acquisition errors recorded in the container's ``errors`` sections.

        Every returned entry is parsed directly from an ``errors`` section and preserves the
        original ordering of the sections, i.e. acquisition order across segments. Values are sector
        counts relative to the start of the volume.

        An empty result only means the container contains no ``errors`` sections (or only empty
        ones). It is not proof that the source media had no bad sectors: an acquisition tool is not
        required to record every read failure. Zero-filled data on its own is never treated as an
        acquisition error either; only the explicit error tables are interpreted as such.
        """
        result = []
        for segment_idx in range(len(self.fh)):
            for error_section in self.segment(segment_idx).errors:
                result.extend(
                    AcquisitionError(
                        segment=segment_idx,
                        first_sector=entry.first_sector,
                        sector_count=entry.sector_count,
                    )
                    for entry in error_section.entries
                )
        return tuple(result)

    @cached_property
    def error_ranges(self) -> tuple[ErrorRange, ...]:
        """Return the recorded acquisition errors as merged, contiguous sector ranges.

        Adjacent or overlapping :attr:`acquisition_errors` entries are merged into a single
        :class:`ErrorRange`. Each range keeps references to the original, unmerged
        :class:`AcquisitionError` entries it was derived from. The ranges are clipped to the volume
        boundary (``0`` to :attr:`number_of_sectors`` exclusive).
        """
        return self._merge_error_ranges(self.acquisition_errors, self.number_of_sectors)

    def overlapping_errors(self, first_sector: int, sector_count: int) -> tuple[ErrorOverlap, ...]:
        """Return the recorded acquisition errors that overlap a logical sector read.

        Use this to determine whether a read contains bytes that the acquisition tool could not read
        from the source media. The query is expressed in the same sector units as the error table
        (sectors of :attr:`sector_size` bytes, relative to the start of the volume).

        Args:
            first_sector: First sector of the logical read.
            sector_count: Number of sectors in the logical read.

        Returns:
            One :class:`ErrorOverlap` per contiguous overlap, clipped to both the queried read and
            the volume boundary. Each overlap references the original :class:`AcquisitionError`
            entries responsible for it. An empty tuple means the read does not touch any recorded
            error range.

        Raises:
            ValueError: If ``first_sector`` is negative or ``sector_count`` is not positive.
        """
        if first_sector < 0:
            raise ValueError("first_sector must be a non-negative sector number")
        if sector_count <= 0:
            raise ValueError("sector_count must be a positive number of sectors")

        read_first = first_sector
        read_last = first_sector + sector_count - 1

        overlaps = []
        for error in self.acquisition_errors:
            overlap_first = max(read_first, error.first_sector)
            overlap_last = min(read_last, error.last_sector, self.number_of_sectors - 1)
            if overlap_first <= overlap_last:
                overlaps.append(
                    ErrorOverlap(
                        first_sector=overlap_first,
                        sector_count=overlap_last - overlap_first + 1,
                        errors=(error,),
                    )
                )

        return self._merge_overlaps(overlaps)

    @staticmethod
    def _merge_error_ranges(errors: tuple[AcquisitionError, ...], boundary: int) -> tuple[ErrorRange, ...]:
        ranges = []
        current_first = None
        current_last = None
        current_sources = []

        for error in sorted(errors, key=lambda item: (item.first_sector, item.last_sector)):
            first = max(error.first_sector, 0)
            last = min(error.last_sector, boundary - 1)
            if first > last:
                continue

            if current_first is None or first > current_last + 1:
                if current_first is not None:
                    ranges.append(
                        ErrorRange(
                            first_sector=current_first,
                            sector_count=current_last - current_first + 1,
                            sources=tuple(current_sources),
                        )
                    )
                current_first = first
                current_last = last
                current_sources = [error]
            else:
                current_last = max(current_last, last)
                current_sources.append(error)

        if current_first is not None:
            ranges.append(
                ErrorRange(
                    first_sector=current_first,
                    sector_count=current_last - current_first + 1,
                    sources=tuple(current_sources),
                )
            )

        return tuple(ranges)

    @staticmethod
    def _merge_overlaps(overlaps: list[ErrorOverlap]) -> tuple[ErrorOverlap, ...]:
        merged = []
        current_first = None
        current_last = None
        current_errors = []

        for overlap in sorted(overlaps, key=lambda item: item.first_sector):
            if current_first is None or overlap.first_sector > current_last + 1:
                if current_first is not None:
                    merged.append(
                        ErrorOverlap(
                            first_sector=current_first,
                            sector_count=current_last - current_first + 1,
                            errors=tuple(current_errors),
                        )
                    )
                current_first = overlap.first_sector
                current_last = overlap.last_sector
                current_errors = list(overlap.errors)
            else:
                current_last = max(current_last, overlap.last_sector)
                current_errors.extend(overlap.errors)

        if current_first is not None:
            merged.append(
                ErrorOverlap(
                    first_sector=current_first,
                    sector_count=current_last - current_first + 1,
                    errors=tuple(current_errors),
                )
            )

        return tuple(merged)

    def read_chunk(self, chunk: int) -> bytes:
        """Read a chunk of data from the EWF container.

        Args:
            chunk: The chunk index to read.
        """
        lookup_idx = bisect_right(self._chunk_lookup, chunk)
        if lookup_idx >= len(self._chunk_map):
            raise IndexError(f"Chunk {chunk} out of range")

        segment_idx, table_idx = self._chunk_map[lookup_idx]

        segment = self.segment(segment_idx)
        table = segment.tables[table_idx]

        chunk_offset = 0 if lookup_idx == 0 else self._chunk_lookup[lookup_idx - 1]
        relative_chunk = chunk - chunk_offset

        entry = table.entries[relative_chunk]
        offset_of_chunk = table.base_offset + (entry & 0x7FFFFFFF)
        compressed = entry >> 31 == 1

        # We don't know the chunk size, so try to determine it using the offset of the next chunk
        # When it's the last chunk in the table though, this becomes trickier
        # We have to check if the chunk data is preceding the table, or if it's contained within the table section
        if relative_chunk == table.number_of_entries - 1:
            # The chunk data is stored before the table section (probably in a sectors section).
            # Sections such as "errors" may sit between the chunk data and the table, so the end of
            # the chunk is the first section boundary after the chunk, not necessarily the table.
            section_offsets = (
                section.descriptor.offset
                for section in segment.sections
                if section.descriptor.offset >= offset_of_chunk
            )
            end_of_chunk = next(section_offsets, None)
            if end_of_chunk is None or end_of_chunk <= offset_of_chunk:
                raise ValueError("Unknown size of last chunk")
        else:
            end_of_chunk = table.base_offset + (table.entries[relative_chunk + 1] & 0x7FFFFFFF)

        size_of_chunk = end_of_chunk - offset_of_chunk

        # Uncompressed chunks have a 4 byte checksum at the end
        if not compressed:
            size_of_chunk -= 4

        segment.fh.seek(offset_of_chunk)
        buf = segment.fh.read(size_of_chunk)
        if compressed:
            buf = zlib.decompress(buf)

        return buf

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
    def errors(self) -> list[ErrorSection]:
        """Return all error sections in this segment."""
        return [section for section in self.sections if isinstance(section, ErrorSection)]

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
    ) -> (
        Section
        | HeaderSection
        | VolumeSection
        | DataSection
        | TableSection
        | Table2Section
        | ErrorSection
        | HashSection
    ):
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

        if descriptor.type == "errors":
            return ErrorSection(descriptor)

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


class ErrorSection(Section):
    """EWF errors section.

    Errors sections are the only EWF sections whose numeric fields are stored in big-endian byte
    order. They list the sectors that could not be read from the source media during acquisition.
    """

    @cached_property
    def data(self) -> c_ewf_error.ErrorSection:
        """The errors section header."""
        self.descriptor.fh.seek(self.descriptor.offset + len(c_ewf.SectionDescriptor))
        return c_ewf_error.ErrorSection(self.descriptor.fh)

    @property
    def number_of_errors(self) -> int:
        """The number of error entries in this section."""
        return self.data.number_of_errors

    @cached_property
    def entries(self) -> list[c_ewf_error.ErrorSectionEntry]:
        """The error entries, each describing an unreadable sector range on the source media."""
        minimum_size = len(c_ewf_error.ErrorSection) + self.number_of_errors * len(c_ewf_error.ErrorSectionEntry)
        if self.descriptor.size < minimum_size:
            raise ValueError(
                f"Invalid errors section at offset {self.descriptor.offset:#x}: "
                f"declares {self.number_of_errors} entries but only has {self.descriptor.size} bytes of data"
            )

        entries_offset = (
            self.descriptor.offset + len(c_ewf.SectionDescriptor) + len(c_ewf_error.ErrorSection)
        )
        self.descriptor.fh.seek(entries_offset)
        return c_ewf_error.ErrorSectionEntry[self.number_of_errors](self.descriptor.fh)


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
