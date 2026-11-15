from __future__ import annotations

import io
from bisect import bisect_right
from threading import RLock
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import AlignedStream

from dissect.fve.crypto import create_cipher

if TYPE_CHECKING:
    from dissect.fve.crypto.base import Cipher


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
    """Read-only decrypting view of a single physical data segment.

    Unlike :class:`CryptStream`, this does not buffer reads on a fixed alignment. Every read is expanded to the
    segment's own sector size, decrypted with the segment's own cipher and IV offset, and then trimmed to the
    requested range. This makes it suitable for composing multiple segments with different crypto parameters into
    one logical stream.

    Args:
        fh: The original file-like object, usually the encrypted disk.
        offset: Physical byte offset of the segment in ``fh``.
        size: Size of the segment in bytes. Must be a multiple of ``sector_size``.
        cipher: Cipher object for this segment.
        encryption: Cipher specification this segment was created with, for introspection.
        iv_tweak: IV sector offset of this segment.
        sector_size: Crypto sector size of this segment.
        index: Optional segment identifier from the LUKS metadata.
        logical_offset: Logical byte offset of this segment in a composed stream.
        lock: Optional shared lock for serializing access to ``fh``.
    """

    def __init__(
        self,
        fh: BinaryIO,
        offset: int,
        size: int,
        cipher: Cipher,
        encryption: str,
        iv_tweak: int = 0,
        sector_size: int = 512,
        index: int | None = None,
        logical_offset: int = 0,
        lock: RLock | None = None,
    ):
        self.fh = fh
        self.offset = offset
        self.size = size
        self.cipher = cipher
        self.encryption = encryption
        self.iv_tweak = iv_tweak
        self.sector_size = sector_size
        self.index = index
        self.logical_offset = logical_offset
        self._lock = lock or RLock()

    @property
    def physical_range(self) -> tuple[int, int]:
        """Return the physical ``(offset, size)`` of this segment."""
        return self.offset, self.size

    def read(self, offset: int, length: int) -> bytes:
        """Read ``length`` decrypted bytes at segment-relative ``offset``."""
        if offset < 0 or length < 0:
            raise ValueError("Negative read offset or length")

        if length == 0 or offset >= self.size:
            return b""

        length = min(length, self.size - offset)

        # dm-crypt works on complete sectors. Expand the read to the segment's sector boundaries so every byte
        # that is returned is decrypted with the correct IV for its sector.
        sector_size = self.sector_size
        start = offset - (offset % sector_size)
        end = min(self.size, ((offset + length + sector_size - 1) // sector_size) * sector_size)
        read_size = end - start

        with self._lock:
            self.fh.seek(self.offset + start)
            buf = self.fh.read(read_size)

        if len(buf) != read_size:
            raise ValueError(
                f"Short read from segment {self.index if self.index is not None else self.offset}: "
                f"expected {read_size} bytes at physical offset {self.offset + start}, got {len(buf)}"
            )

        data = bytearray(buf)
        self.cipher.decrypt(data, (start // 512) + self.iv_tweak, data)

        relative = offset - start
        return bytes(data[relative : relative + length])


class MultiSegmentStream(io.RawIOBase):
    """Read-only logical stream composed of multiple independently encrypted segments.

    Segments are exposed in the order given to the constructor. Reads that cross a segment boundary are split at
    the boundary and each part is decrypted using the parameters of its own segment.

    Args:
        segments: The segments that make up this stream, in logical order.
        fh: Optional original file-like object. Defaults to the file handle of the first segment.
    """

    def __init__(self, segments: list[SegmentStream], fh: BinaryIO | None = None):
        super().__init__()
        if not segments:
            raise ValueError("At least one segment is required")

        self.segments = list(segments)
        self.fh = fh or self.segments[0].fh
        self._lock = RLock()

        self._starts = []
        logical_offset = 0
        for segment in self.segments:
            segment.logical_offset = logical_offset
            self._starts.append(logical_offset)
            logical_offset += segment.size

        self.size = logical_offset
        self._pos = 0

    @property
    def offsets(self) -> list[int]:
        """Return the logical start offset of every segment."""
        return list(self._starts)

    def readable(self) -> bool:
        """Return whether this stream is readable."""
        return True

    def seekable(self) -> bool:
        """Return whether this stream is seekable."""
        return True

    def tell(self) -> int:
        """Return the current logical position."""
        return self._pos

    def seek(self, pos: int, whence: int = io.SEEK_SET) -> int:
        """Seek to a logical position in this stream."""
        if whence == io.SEEK_SET:
            if pos < 0:
                raise ValueError(f"negative seek position {pos}")
        elif whence == io.SEEK_CUR:
            pos = max(0, self._pos + pos)
        elif whence == io.SEEK_END:
            pos = max(0, self.size + pos)
        else:
            raise ValueError("invalid whence value")

        self._pos = pos
        return pos

    def read(self, n: int = -1) -> bytes:
        """Read up to ``n`` decrypted bytes from the logical stream."""
        if n is not None and n < -1:
            raise ValueError("invalid number of bytes to read")

        with self._lock:
            if self._pos >= self.size:
                return b""

            if n == -1:
                n = self.size - self._pos
            else:
                n = min(n, self.size - self._pos)

            if n == 0:
                return b""

            parts = []
            pos = self._pos
            remaining = n

            while remaining:
                index = bisect_right(self._starts, pos) - 1
                segment = self.segments[index]
                relative = pos - segment.logical_offset
                read_size = min(remaining, segment.size - relative)

                parts.append(segment.read(relative, read_size))

                pos += read_size
                remaining -= read_size

            self._pos = pos
            return b"".join(parts)

    def readinto(self, b: bytearray) -> int:
        """Read bytes into a pre-allocated bytes-like object."""
        buf = self.read(len(b))
        length = len(buf)
        b[:length] = buf
        return length

    def readall(self) -> bytes:
        """Read until the end of the logical stream."""
        return self.read()

    def readoffset(self, offset: int, length: int) -> bytes:
        """Read ``length`` bytes at logical ``offset``."""
        self.seek(offset)
        return self.read(length)

    def peek(self, n: int) -> bytes:
        """Read up to ``n`` bytes without advancing the current position."""
        pos = self._pos
        data = self.read(n)
        self._pos = pos
        return data
