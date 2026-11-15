from __future__ import annotations

import io
from bisect import bisect_right
from typing import BinaryIO

from dissect.util.stream import AlignedStream

from dissect.fve.crypto import create_cipher


class CryptStream(AlignedStream):
    """Transparently decrypting stream.

    Args:
        fh: The original file-like object, usually the encrypted disk.
        cipher: The cipher name/specification.
        key: The encryption key.
        key_size: Optional key size hint.
        offset: Optional base offset to the encrypted region. Segment offset in LUKS.
        size: Optional size hint. If ``None`` or ``"dynamic"``, determine the size by seeking to the end of ``fh``.
        iv_tweak: Optional IV tweak, or offset.
        sector_size: Optional sector size. Defaults to 512.
    """

    def __init__(
        self,
        fh: BinaryIO,
        cipher: str,
        key: bytes,
        key_size: int | None = None,
        offset: int = 0,
        size: int | str | None = None,
        iv_tweak: int = 0,
        sector_size: int = 512,
    ):
        self.fh = fh
        self.cipher = create_cipher(cipher, key, key_size or len(key) * 8, sector_size, 512)
        self.offset = offset
        self.iv_tweak = iv_tweak
        self.sector_size = sector_size

        if size in (None, "dynamic"):
            size = fh.seek(0, io.SEEK_END) - offset

        super().__init__(size)

    def _read(self, offset: int, length: int) -> bytes:
        self.fh.seek(self.offset + offset)
        buf = bytearray(self.fh.read(length))
        self.cipher.decrypt(buf, (offset // 512) + self.iv_tweak, buf)
        return bytes(buf)


class SegmentStream:
    """Read-only crypt stream for one independently encrypted segment.

    A segment keeps its own physical range, cipher configuration, sector size and IV start. Reads that only
    cover a part of a sector decrypt the enclosing sector(s) and return the requested slice.

    Args:
        fh: The original file-like object, usually the encrypted disk.
        id: The segment identifier from the volume metadata.
        cipher: The cipher name/specification for this segment.
        key: The segment encryption key.
        key_size: Optional key size hint.
        offset: The physical offset of this segment in ``fh``.
        size: The size of this segment in bytes.
        iv_tweak: The IV sector offset for this segment.
        sector_size: The sector size of this segment.
    """

    def __init__(
        self,
        fh: BinaryIO,
        id: int,
        cipher: str,
        key: bytes,
        key_size: int | None = None,
        offset: int = 0,
        size: int = 0,
        iv_tweak: int = 0,
        sector_size: int = 512,
    ):
        self.fh = fh
        self.id = id
        self.cipher = create_cipher(cipher, key, key_size or len(key) * 8, sector_size, 512)
        self.offset = offset
        self.size = size
        self.iv_tweak = iv_tweak
        self.sector_size = sector_size

    def read(self, offset: int, length: int) -> bytes:
        """Read ``length`` bytes at segment-local ``offset``.

        Args:
            offset: Segment-local offset to read from.
            length: Number of bytes to read.
        """
        if offset < 0 or offset > self.size or length < 0:
            raise ValueError(f"Invalid read for segment {self.id}: offset={offset} length={length} size={self.size}")

        length = min(length, self.size - offset)
        if not length:
            return b""

        sector_size = self.sector_size
        sector_start = offset - (offset % sector_size)
        read_length = ((offset + length - sector_start + sector_size - 1) // sector_size) * sector_size

        self.fh.seek(self.offset + sector_start)
        buf = self.fh.read(read_length)
        if len(buf) != read_length:
            raise ValueError(f"Unable to read the full ciphertext for segment {self.id}")

        buf = bytearray(buf)
        # IV sector numbers are always in units of 512 bytes, even for larger encryption sectors
        self.cipher.decrypt(buf, (sector_start // 512) + self.iv_tweak, buf)
        relative_offset = offset - sector_start
        return bytes(buf[relative_offset : relative_offset + length])


class SegmentedCryptStream(AlignedStream):
    """Read-only logical view over multiple independently encrypted segments.

    Segments are presented in the order they are supplied. Every segment keeps its own physical location,
    size, cipher configuration, sector size and IV start; reads crossing segment boundaries are split and
    handled by the respective segment.

    Args:
        segments: The segments that make up this logical view, in logical order.
    """

    def __init__(self, segments: list[SegmentStream]):
        if not segments:
            raise ValueError("A segmented stream requires at least one segment")

        self.segments = segments
        self._starts = []
        self._ends = []

        start = 0
        for segment in segments:
            self._starts.append(start)
            start += segment.size
            self._ends.append(start)

        super().__init__(start, align=512)

    def _segment_at(self, offset: int) -> int:
        return bisect_right(self._starts, offset) - 1

    def writable(self) -> bool:
        """Indicate that this view is read-only."""
        return False

    def write(self, b: bytes) -> int:
        """Reject writes; the segmented view is read-only."""
        raise io.UnsupportedOperation("SegmentedCryptStream is read-only")

    def truncate(self, size: int | None = None) -> int:
        """Reject truncation; the segmented view is read-only."""
        raise io.UnsupportedOperation("SegmentedCryptStream is read-only")

    def _read(self, offset: int, length: int) -> bytes:
        result = []
        end = offset + length

        while offset < end:
            index = self._segment_at(offset)
            if index < 0:
                raise ValueError("Read starts before the first segment")

            segment = self.segments[index]
            segment_start = self._starts[index]
            segment_end = self._ends[index]
            chunk_end = min(end, segment_end)

            result.append(segment.read(offset - segment_start, chunk_end - offset))
            offset = chunk_end

        return b"".join(result)

    def segment_for_offset(self, offset: int) -> SegmentStream | None:
        """Return the segment containing the given logical offset.

        Args:
            offset: Logical offset in this view.
        """
        if offset < 0 or offset >= self.size:
            return None

        return self.segments[self._segment_at(offset)]
