from __future__ import annotations

import struct
from typing import TYPE_CHECKING, BinaryIO

from dissect.ntfs.c_ntfs import (
    ATTRIBUTE_TYPE_CODE,
    IO_REPARSE_TAG,
    WOF_CHUNK_SIZE,
    WOF_CHUNK_TABLE_ENTRY_SIZE,
    WOF_COMPRESSED_DATA_HEADER_SIZE,
    WOF_COMPRESSED_DATA_SIGNATURE,
    WOF_PROVIDER_FILE,
    c_ntfs,
)
from dissect.ntfs.exceptions import (
    BrokenWofDataError,
    UnsupportedWofAlgorithmError,
    UnsupportedWofProviderError,
    WofError,
)
from dissect.util import lzxpress, lzxpress_huffman
from dissect.util.stream import AlignedStream

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.ntfs.mft import MftRecord

# WOF FILE provider compression algorithm -> decompression function
# Algorithms 0-2 use plain XPRESS (MS-XCA), algorithm 3 uses the Huffman variant of XPRESS
WOF_DECOMPRESSORS = {
    0x00: lzxpress.decompress,
    0x01: lzxpress.decompress,
    0x02: lzxpress.decompress,
    0x03: lzxpress_huffman.decompress,
}


class WofFile:
    """Explicit entry point for the logical content of a WOF compressed file.

    A WOF compressed file is an NTFS reparse point (``IO_REPARSE_TAG_WOF``) whose default ``$DATA`` stream does not
    hold the logical content. Instead it contains a ``WofCompressedData`` stream: a small header, a chunk offset
    table and one compressed chunk per fixed-size block of the logical file.

    Only the WOF ``FILE`` provider (``WOF_PROVIDER_FILE``) is implemented. The ``WIM`` and ``CLOUD`` providers use
    different storage layouts and raise :class:`~dissect.ntfs.exceptions.UnsupportedWofProviderError`.

    This class never contacts any cloud service and never alters the meaning of the raw ``$DATA`` attribute, which
    remains available through :meth:`MftRecord.open`.

    Args:
        record: The MFT record of the WOF compressed file.
        name: The name of the ``$DATA`` stream that holds the ``WofCompressedData`` stream.
    """

    def __init__(self, record: MftRecord, name: str = ""):
        reparse_attrs = record.attributes[ATTRIBUTE_TYPE_CODE.REPARSE_POINT]
        if not reparse_attrs or reparse_attrs.tag != IO_REPARSE_TAG.WOF:
            raise WofError(f"{record!r} is not a WOF reparse point")

        reparse = reparse_attrs[0]
        if len(reparse.buffer) < len(c_ntfs._WOF_REPARSE_BUFFER):
            raise BrokenWofDataError("WOF reparse point is missing its WOF reparse buffer")

        reparse_buffer = c_ntfs._WOF_REPARSE_BUFFER(reparse.buffer)
        self.version = reparse_buffer.WofVersion
        self.provider = reparse_buffer.WofProvider

        if self.provider != WOF_PROVIDER_FILE:
            raise UnsupportedWofProviderError(
                f"Only the WOF FILE provider ({WOF_PROVIDER_FILE:#x}) is supported: it stores a self-contained "
                f"WofCompressedData stream in the file's own $DATA attribute. Record {record!r} uses provider "
                f"{self.provider:#x}, whose payload lives outside this file (a WIM container or a cloud sync "
                f"engine) and cannot be reconstructed from this record alone."
            )

        self.record = record
        self.name = name
        # The ReparsePoint attribute keeps the full on-disk reparse information for evidence traceability
        self.reparse_point = reparse
        # The raw $DATA attribute is the WofCompressedData stream, opened through the regular code path
        self.data_attribute = record._get_stream_attributes(name, ATTRIBUTE_TYPE_CODE.DATA)[0]
        self._fh = self.data_attribute.open()

        header_data = self._fh.read(WOF_COMPRESSED_DATA_HEADER_SIZE)
        if len(header_data) < WOF_COMPRESSED_DATA_HEADER_SIZE:
            raise BrokenWofDataError("WofCompressedData stream is too small for its header")

        self.header = c_ntfs._WOF_COMPRESSED_DATA_HEADER(header_data)
        if bytes(self.header.Signature) != WOF_COMPRESSED_DATA_SIGNATURE:
            raise BrokenWofDataError(
                f"Invalid WofCompressedData signature: {bytes(self.header.Signature)!r}, expected "
                f"{WOF_COMPRESSED_DATA_SIGNATURE!r}"
            )

        self.algorithm = self.header.CompressionAlgorithm
        if self.algorithm not in WOF_CHUNK_SIZE:
            raise UnsupportedWofAlgorithmError(f"Unsupported WOF compression algorithm: {self.algorithm:#x}")
        self.chunk_size = WOF_CHUNK_SIZE[self.algorithm]

        self.compressed_size = self._fh.size
        if self.compressed_size < WOF_COMPRESSED_DATA_HEADER_SIZE + WOF_CHUNK_TABLE_ENTRY_SIZE:
            raise BrokenWofDataError("WofCompressedData stream is too small to contain a chunk table")

        chunk_count = self._chunk_count_from_table()
        if chunk_count == 0:
            raise BrokenWofDataError("WofCompressedData chunk table references no chunks")

        self.chunk_offsets = self._read_chunk_offsets(chunk_count)
        self._validate_chunk_offsets()

        # The logical size is derived from the actual chunks; it is not stored in the WofCompressedData stream
        self.size = (chunk_count - 1) * self.chunk_size + len(self._read_chunk(chunk_count - 1))

    def __repr__(self) -> str:
        return f"<WofFile {self.record!r} provider={self.provider:#x} algorithm={self.algorithm:#x} size={self.size}>"

    def _chunk_count_from_table(self) -> int:
        # The first chunk table entry is the absolute offset (relative to the start of the WofCompressedData stream)
        # of the first compressed chunk, so it also tells us how many ULONG entries the table contains
        first_offset = struct.unpack("<I", self._read_at(WOF_COMPRESSED_DATA_HEADER_SIZE, 4))[0]
        if first_offset < WOF_COMPRESSED_DATA_HEADER_SIZE + WOF_CHUNK_TABLE_ENTRY_SIZE:
            raise BrokenWofDataError(f"WofCompressedData chunk table has an invalid first offset: {first_offset:#x}")

        table_size = first_offset - WOF_COMPRESSED_DATA_HEADER_SIZE
        if table_size % WOF_CHUNK_TABLE_ENTRY_SIZE:
            raise BrokenWofDataError(f"WofCompressedData chunk table is not aligned: {table_size} bytes")

        return table_size // WOF_CHUNK_TABLE_ENTRY_SIZE

    def _read_chunk_offsets(self, chunk_count: int) -> tuple[int, ...]:
        table_size = chunk_count * WOF_CHUNK_TABLE_ENTRY_SIZE
        table_data = self._read_at(WOF_COMPRESSED_DATA_HEADER_SIZE, table_size)
        if len(table_data) != table_size:
            raise BrokenWofDataError("WofCompressedData chunk table extends beyond the $DATA stream")

        return struct.unpack(f"<{chunk_count}I", table_data)

    def _validate_chunk_offsets(self) -> None:
        previous = WOF_COMPRESSED_DATA_HEADER_SIZE
        for index, offset in enumerate(self.chunk_offsets):
            if offset < previous or offset > self.compressed_size:
                raise BrokenWofDataError(
                    f"Invalid chunk table entry {index}: offset {offset:#x} outside of "
                    f"[{previous:#x}, {self.compressed_size:#x}]"
                )
            previous = offset

        # Every chunk but the last must start strictly before the end of the stream, otherwise the table promises
        # a payload that the on-disk $DATA attribute cannot contain
        if self.chunk_offsets[-1] >= self.compressed_size:
            raise BrokenWofDataError(
                f"Final chunk table entry {self.chunk_offsets[-1]:#x} leaves no payload in a "
                f"{self.compressed_size:#x} byte WofCompressedData stream"
            )

    def _read_at(self, offset: int, length: int) -> bytes:
        self._fh.seek(offset)
        data = self._fh.read(length)
        if len(data) != length:
            raise BrokenWofDataError(
                f"Short read on WofCompressedData stream at offset {offset:#x}: "
                f"wanted {length} bytes, got {len(data)}"
            )
        return data

    def _chunk_payload(self, index: int) -> bytes:
        start = self.chunk_offsets[index]
        end = self.chunk_offsets[index + 1] if index + 1 < len(self.chunk_offsets) else self.compressed_size
        if end < start:
            raise BrokenWofDataError(f"Chunk {index} has a negative payload size")

        return self._read_at(start, end - start)

    def _read_chunk(self, index: int) -> bytes:
        # Chunks that don't compress below their logical size are stored raw, matching the WOF convention
        payload = self._chunk_payload(index)
        if len(payload) >= self.chunk_size:
            if len(payload) != self.chunk_size:
                raise BrokenWofDataError(
                    f"WOF chunk {index} payload ({len(payload)} bytes) exceeds the chunk size "
                    f"({self.chunk_size} bytes)"
                )
            return payload

        decompress = WOF_DECOMPRESSORS[self.algorithm]
        try:
            data = decompress(payload)
        except Exception as e:
            raise BrokenWofDataError(f"Failed to decompress WOF chunk {index}: {e}") from e

        if len(data) > self.chunk_size:
            raise BrokenWofDataError(
                f"Decompressed WOF chunk {index} ({len(data)} bytes) exceeds the chunk size ({self.chunk_size} bytes)"
            )

        # Every chunk except the last must decompress to the full chunk size. A short result here means the
        # compressed payload is corrupt or truncated; returning it would silently turn evidence into zeros.
        is_last_chunk = index == len(self.chunk_offsets) - 1
        if not is_last_chunk and len(data) != self.chunk_size:
            raise BrokenWofDataError(
                f"WOF chunk {index} decompressed to {len(data)} bytes, expected the full chunk size "
                f"({self.chunk_size} bytes)"
            )
        return data

    def chunk_offset(self, index: int) -> int:
        """Return the logical file offset at which chunk ``index`` starts."""
        return index * self.chunk_size

    def evidence_ranges(self) -> Iterator[tuple[int, int, int]]:
        """Yield ``(logical_offset, compressed_offset, compressed_length)`` for every chunk.

        The offsets are relative to, and traceable through, the raw ``$DATA`` attribute exposed by
        :attr:`data_attribute`. A full-sized payload means the chunk was stored uncompressed.
        """
        for index, compressed_offset in enumerate(self.chunk_offsets):
            end = self.chunk_offsets[index + 1] if index + 1 < len(self.chunk_offsets) else self.compressed_size
            yield self.chunk_offset(index), compressed_offset, end - compressed_offset

    def open(self) -> BinaryIO:
        """Open a seekable, chunk-wise readable file-like object for the logical content."""
        return WofCompressedStream(self)


class WofCompressedStream(AlignedStream):
    """Random-access logical view of a :class:`WofFile`.

    Reads are aligned to the WOF chunk size, so a small random read only decompresses the chunk(s) it touches
    instead of the whole file. Decompression or truncation errors are always raised, never substituted with zero
    bytes.

    Args:
        wof_file: The parsed :class:`WofFile` to read from.
    """

    def __init__(self, wof_file: WofFile):
        super().__init__(wof_file.size, wof_file.chunk_size)
        self.wof_file = wof_file

    def _read(self, offset: int, length: int) -> bytes:
        if length <= 0:
            return b""

        chunk_size = self.wof_file.chunk_size
        first_chunk = offset // chunk_size
        last_chunk = (offset + length - 1) // chunk_size

        blocks = [self.wof_file._read_chunk(index) for index in range(first_chunk, last_chunk + 1)]

        start = offset - first_chunk * chunk_size
        return b"".join(blocks)[start : start + length]
