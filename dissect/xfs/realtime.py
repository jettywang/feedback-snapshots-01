"""Realtime device support for XFS.

An XFS filesystem can have a separate *realtime device*. Realtime allocations
are not part of the data device address space: extent start blocks in a
realtime inode address the realtime device, while the inode and its extent
list metadata still live on the data device. A realtime device is therefore
separate evidence and must be supplied explicitly to
:class:`dissect.xfs.xfs.XFS`; there is no fallback to the data device.

Units and terminology
=====================

* The realtime device is divided into *realtime blocks*. A realtime block has
  the same size as a normal filesystem block (``sb_blocksize``).
* A *realtime extent* is the allocation unit of the realtime allocator. It
  spans ``sb_rextsize`` realtime blocks, or ``sb_rextsize * sb_blocksize``
  bytes. Extent records in the inode use realtime block numbers, not realtime
  extent numbers, so they must not be interpreted as block numbers on the data
  device.
* ``sb_rblocks`` is the size of the realtime device in realtime blocks and
  ``sb_rextents`` is the number of realtime extents. A consistent superblock
  has ``sb_rextents == ceil(sb_rblocks / sb_rextsize)``.
* The realtime bitmap inode (``sb_rbmino``) lives on the data device and has
  one bit per realtime *block* (``sb_rblocks`` bits in total). Allocation is
  performed in whole realtime extents, so the bits covering one extent are
  normally set or clear together. Legacy bitmaps are a flat bit array;
  bitmaps whose inode has the ``NEWRTBM`` flag store an
  :class:`~dissect.xfs.c_xfs.xfs_rtbuf_blkinfo` header in every bitmap block.

File logical offsets are always relative to the file, in bytes. Logical holes
(no extent) read as zeroes, unwritten extents read as zeroes, and the last
range is truncated at ``di_size``.
"""

from __future__ import annotations

import io
import math
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, BinaryIO

from dissect.xfs.c_xfs import c_xfs
from dissect.xfs.exceptions import Error, RealtimeDeviceMissingException, RealtimeRangeError

if TYPE_CHECKING:
    from dissect.xfs.xfs import XFS, INode


class RealtimeBitmapState(str, Enum):
    """Availability of the realtime allocation bitmap."""

    AVAILABLE = "available"
    NOT_CONFIGURED = "not_configured"
    MISSING_INODE = "missing_inode"
    INVALID_INODE = "invalid_inode"
    INVALID_FORMAT = "invalid_format"
    TRUNCATED = "truncated"


class RealtimeRangeStatus(str, Enum):
    """Status of a logical range in a realtime file.

    ``ALLOCATED``, ``MISSING_BITMAP``, ``UNWRITTEN`` and ``HOLE`` contribute
    bytes to a file read: allocated blocks are read from the realtime device,
    holes and unwritten extents read as zeroes, and ``MISSING_BITMAP`` means
    the range is mapped but the allocation bitmap was unavailable to verify it.
    All other statuses mark evidence that must not be silently treated as
    readable file content.
    """

    ALLOCATED = "allocated"
    MISSING_BITMAP = "missing_bitmap"
    UNALLOCATED = "unallocated"
    UNWRITTEN = "unwritten"
    HOLE = "hole"
    MISSING_DEVICE = "missing_device"
    OUT_OF_BOUNDS = "out_of_bounds"
    TRUNCATED = "truncated"
    OVERLAP = "overlap"
    MISALIGNED = "misaligned"
    NO_REALTIME_VOLUME = "no_realtime_volume"
    INVALID_GEOMETRY = "invalid_geometry"

    @property
    def readable(self) -> bool:
        """Whether this range can contribute bytes to a file read."""
        return self in (
            RealtimeRangeStatus.ALLOCATED,
            RealtimeRangeStatus.MISSING_BITMAP,
            RealtimeRangeStatus.UNWRITTEN,
            RealtimeRangeStatus.HOLE,
        )

    @property
    def mapped(self) -> bool:
        """Whether this range claims blocks on the realtime device."""
        return self not in (RealtimeRangeStatus.HOLE,)

    @property
    def is_contradiction(self) -> bool:
        """Whether this range contradicts the mapping or its allocation state."""
        return self in (
            RealtimeRangeStatus.UNALLOCATED,
            RealtimeRangeStatus.OUT_OF_BOUNDS,
            RealtimeRangeStatus.TRUNCATED,
            RealtimeRangeStatus.OVERLAP,
            RealtimeRangeStatus.MISALIGNED,
            RealtimeRangeStatus.NO_REALTIME_VOLUME,
            RealtimeRangeStatus.INVALID_GEOMETRY,
        )


@dataclass(frozen=True)
class RealtimeGeometry:
    """Geometry of the realtime volume, as described by the superblock.

    Args:
        block_size: Size of a realtime block in bytes.
        extent_size: Number of realtime blocks in one realtime extent.
        nr_blocks: Number of realtime blocks (``sb_rblocks``).
        nr_extents: Number of realtime extents (``sb_rextents``).
        bitmap_blocks: Number of blocks in the realtime bitmap (``sb_rbmblocks``).
        bitmap_ino: Inode number of the realtime bitmap (``sb_rbmino``).
        summary_ino: Inode number of the realtime summary (``sb_rsumino``).
    """

    block_size: int
    extent_size: int
    nr_blocks: int
    nr_extents: int
    bitmap_blocks: int
    bitmap_ino: int
    summary_ino: int

    @classmethod
    def from_superblock(cls, sb: c_xfs.xfs_sb, block_size: int) -> RealtimeGeometry:
        """Create a geometry from a parsed XFS superblock."""
        return cls(
            block_size=block_size,
            extent_size=sb.sb_rextsize,
            nr_blocks=sb.sb_rblocks,
            nr_extents=sb.sb_rextents,
            bitmap_blocks=sb.sb_rbmblocks,
            bitmap_ino=sb.sb_rbmino,
            summary_ino=sb.sb_rsumino,
        )

    @property
    def configured(self) -> bool:
        """Whether a realtime volume is described by the superblock."""
        return self.nr_blocks > 0 or self.nr_extents > 0

    @property
    def usable(self) -> bool:
        """Whether the geometry is sufficient to address the realtime device."""
        return self.configured and self.block_size > 0 and self.extent_size > 0

    @property
    def consistent(self) -> bool:
        """Whether the realtime extent counters agree.

        A filesystem can still be read when this is false; the individual
        ranges then carry explicit statuses based on the usable geometry.
        """
        if not self.usable:
            return False
        return self.nr_extents == self.expected_nr_extents

    @property
    def expected_nr_extents(self) -> int:
        """Number of realtime extents implied by ``nr_blocks`` and ``extent_size``."""
        if self.extent_size <= 0:
            return 0
        return math.ceil(self.nr_blocks / self.extent_size)

    @property
    def extent_size_bytes(self) -> int:
        """Size of one realtime extent in bytes."""
        return self.extent_size * self.block_size

    @property
    def size_bytes(self) -> int:
        """Nominal size of the realtime volume in bytes."""
        return self.nr_blocks * self.block_size

    def is_start_aligned(self, rt_block: int) -> bool:
        """Whether a realtime extent starts on a realtime extent boundary.

        The final extent of a file may cover fewer than ``extent_size`` blocks
        when the file ends inside it, so only the start block must be aligned.
        """
        if self.extent_size <= 0:
            return False
        return rt_block % self.extent_size == 0

    def extent_index(self, rt_block: int) -> int:
        """Return the realtime extent index containing ``rt_block``."""
        return rt_block // self.extent_size


class RealtimeBitmap:
    """Read-only access to the realtime allocation bitmap.

    Bits are read MSB-first within each byte, matching the on-disk big-endian
    word layout. There is one bit per realtime extent, indexed by
    ``rt_block // extent_size``. A set bit means the extent is allocated.
    """

    def __init__(self, device: RealtimeDevice):
        self.device = device
        self._fh: BinaryIO | None = None
        self._inode: INode | None = None
        self._state = RealtimeBitmapState.NOT_CONFIGURED
        self._new_format = False
        self._header_size = 0
        self._bits_per_block = 0
        self._block_cache: dict[int, bytes] = {}

        self._load()

    @property
    def state(self) -> RealtimeBitmapState:
        """Availability state of the bitmap."""
        return self._state

    @property
    def available(self) -> bool:
        """Whether the bitmap can answer allocation questions."""
        return self._state == RealtimeBitmapState.AVAILABLE

    @property
    def inode(self) -> INode | None:
        """The bitmap inode, if it could be resolved."""
        return self._inode

    @property
    def bits_per_block(self) -> int:
        """Number of realtime blocks described by one bitmap block."""
        return self._bits_per_block

    @property
    def covered_blocks(self) -> int:
        """Number of realtime blocks covered by the usable bitmap payload."""
        return min(self.device.geometry.nr_blocks, self._bits_per_block * self._nr_bitmap_blocks())

    @property
    def covered_extents(self) -> int:
        """Number of realtime extents fully covered by the usable bitmap payload."""
        geometry = self.device.geometry
        if geometry.extent_size <= 0:
            return 0
        return min(geometry.nr_extents, self.covered_blocks // geometry.extent_size)

    def _load(self) -> None:
        geometry = self.device.geometry
        if not geometry.configured:
            self._state = RealtimeBitmapState.NOT_CONFIGURED
            return
        if not geometry.usable:
            self._state = RealtimeBitmapState.INVALID_FORMAT
            return
        if not geometry.bitmap_ino:
            self._state = RealtimeBitmapState.MISSING_INODE
            return

        try:
            self._inode = self.device.xfs.get_inode(geometry.bitmap_ino)
            di_flags = self._inode.inode.di_flags
        except Error:
            self._state = RealtimeBitmapState.MISSING_INODE
            return
        except Exception:
            self._state = RealtimeBitmapState.INVALID_INODE
            return

        self._new_format = bool(di_flags & c_xfs.XFS_DIFLAG_NEWRTBM)
        self._header_size = len(c_xfs.xfs_rtbuf_blkinfo) if self._new_format else 0
        self._bits_per_block = (geometry.block_size - self._header_size) * 8
        if self._bits_per_block <= 0:
            self._state = RealtimeBitmapState.INVALID_FORMAT
            return

        try:
            self._fh = self._open_inode()
        except Exception:
            self._state = RealtimeBitmapState.INVALID_INODE
            return

        required_size = self._required_size()
        size = getattr(self._fh, "size", None)
        if size is not None and size < required_size:
            self._state = RealtimeBitmapState.TRUNCATED
            return

        if self._new_format:
            try:
                self._read_bitmap_block(0)
            except Error:
                self._state = RealtimeBitmapState.INVALID_FORMAT
                return

        self._state = RealtimeBitmapState.AVAILABLE

    def _open_inode(self) -> BinaryIO:
        """Open the bitmap inode, tolerating ``di_size == 0`` with allocated extents.

        Some images (and forensic fixtures) leave the bitmap inode size at zero
        while its extent list still describes the bitmap blocks. In that case
        the extent capacity is the only usable size information.
        """
        inode = self._inode
        if inode.inode.di_size == 0 and inode.data_extents:
            capacity = sum(count for block, count in inode.dataruns if block is not None)
            if capacity:
                from dissect.util.stream import RunlistStream

                return RunlistStream(
                    self.device.xfs.fh,
                    inode.dataruns,
                    capacity * self.device.geometry.block_size,
                    self.device.geometry.block_size,
                )

        return inode.open()

    def _nr_bitmap_blocks(self) -> int:
        geometry = self.device.geometry
        required = math.ceil(geometry.nr_blocks / self._bits_per_block)
        return max(geometry.bitmap_blocks, required)

    def _required_size(self) -> int:
        geometry = self.device.geometry
        if self._new_format:
            return self._nr_bitmap_blocks() * geometry.block_size
        return math.ceil(geometry.nr_blocks / 8)

    def _read_bitmap_block(self, block_index: int, length: int | None = None) -> bytes:
        block_size = self.device.geometry.block_size
        read_length = block_size if length is None else min(length, block_size)
        self._fh.seek(block_index * block_size)
        data = self._fh.read(read_length)

        if self._new_format:
            if len(data) != read_length:
                raise RealtimeRangeError(f"Short read of realtime bitmap block {block_index}")
            header = c_xfs.xfs_rtbuf_blkinfo(io.BytesIO(data))
            if header.rt_magic != c_xfs.XFS_RTBITMAP_MAGIC:
                raise RealtimeRangeError(
                    f"Realtime bitmap block {block_index} has invalid magic: 0x{header.rt_magic:x}"
                )

        return data

    def _read_byte(self, offset: int) -> int:
        block_size = self.device.geometry.block_size
        block_index = offset // block_size
        block = self._block_cache.get(block_index)
        if block is None:
            if self._new_format:
                block = self._read_bitmap_block(block_index)
            else:
                # Legacy bitmaps may be smaller than a block (even inline).
                block = self._read_bitmap_block(block_index, block_size)
            self._block_cache[block_index] = block

        index = offset % block_size
        if index >= len(block):
            raise RealtimeRangeError(f"Short read of realtime bitmap at offset {offset}")
        return block[index]

    def is_allocated(self, rt_block: int) -> bool | None:
        """Return whether a realtime block is marked allocated.

        Returns ``None`` when the bitmap is unavailable or the block is outside
        the realtime volume.
        """
        geometry = self.device.geometry
        if not self.available or rt_block < 0 or rt_block >= geometry.nr_blocks:
            return None

        block_index, bit_index = divmod(rt_block, self._bits_per_block)
        byte_index, bit_in_byte = divmod(bit_index, 8)
        offset = block_index * geometry.block_size + self._header_size + byte_index
        return bool(self._read_byte(offset) & (0x80 >> bit_in_byte))

    def is_extent_allocated(self, extent_index: int) -> bool | None:
        """Return whether every block of a realtime extent is marked allocated.

        Returns ``None`` when the bitmap is unavailable or the extent is outside
        the realtime volume.
        """
        geometry = self.device.geometry
        if not self.available or geometry.extent_size <= 0:
            return None
        if extent_index < 0 or extent_index >= geometry.nr_extents:
            return None

        start = extent_index * geometry.extent_size
        length = min(geometry.extent_size, geometry.nr_blocks - start)
        return self.all_allocated(start, length)

    def all_allocated(self, rt_block: int, block_count: int) -> bool | None:
        """Return whether every realtime block in a range is marked allocated.

        Returns ``True`` for an empty range, ``False`` if any covered bit is
        clear, and ``None`` when the bitmap is unavailable or the range is not
        fully covered by the realtime volume.
        """
        geometry = self.device.geometry
        if not self.available:
            return None
        if block_count == 0:
            return True
        if rt_block < 0 or block_count < 0 or rt_block + block_count > geometry.nr_blocks:
            return None

        return all(self.is_allocated(block) for block in range(rt_block, rt_block + block_count))

    def allocated_extents(self) -> list[int]:
        """Return the indices of all extents marked allocated in the bitmap."""
        if not self.available:
            return []
        geometry = self.device.geometry
        return [index for index in range(geometry.nr_extents) if self.is_extent_allocated(index)]


class RealtimeDevice:
    """A realtime volume, its geometry and its allocation bitmap.

    Args:
        xfs: The filesystem the realtime volume belongs to.
        fh: The explicitly supplied realtime device, or ``None`` if absent.
        geometry: Realtime geometry from the superblock.
    """

    def __init__(self, xfs: XFS, fh: BinaryIO | None, geometry: RealtimeGeometry):
        self.xfs = xfs
        self.fh = fh
        self.geometry = geometry
        self._size: int | None = None
        self._size_known = False
        self._bitmap: RealtimeBitmap | None = None

    @property
    def present(self) -> bool:
        """Whether a realtime device was supplied by the caller."""
        return self.fh is not None

    @property
    def bitmap(self) -> RealtimeBitmap:
        """The realtime allocation bitmap."""
        if self._bitmap is None:
            self._bitmap = RealtimeBitmap(self)
        return self._bitmap

    @property
    def size(self) -> int | None:
        """Actual size of the supplied device in bytes, if it can be determined."""
        if not self._size_known:
            self._size_known = True
            if self.fh is not None:
                try:
                    position = self.fh.tell()
                    self.fh.seek(0, io.SEEK_END)
                    self._size = self.fh.tell()
                    self.fh.seek(position)
                except (OSError, ValueError):
                    self._size = None

        return self._size


@dataclass(frozen=True)
class RealtimeRange:
    """A contiguous logical range of a realtime file.

    Args:
        status: Interpretation of the range.
        logical_offset: Start offset in the file in bytes.
        length: Number of visible file bytes in this range.
        block_size: Filesystem/realtime block size in bytes.
        rt_block: First realtime block, if the range is mapped.
        block_count: Number of realtime blocks covering this range.
        extent_index: Zero-based index of the source extent, if any.
        allocated: Bitmap result for the mapped range (``None`` if unknown).
        extent_aligned: Whether the mapped range is aligned to the realtime
            extent unit (``None`` for holes/unmapped ranges).
        unwritten: Whether the source extent is marked unwritten.
    """

    status: RealtimeRangeStatus
    logical_offset: int
    length: int
    block_size: int
    rt_block: int | None = None
    block_count: int = 0
    extent_index: int | None = None
    allocated: bool | None = None
    extent_aligned: bool | None = None
    unwritten: bool = False

    @property
    def logical_block(self) -> int:
        """Start block of this range in file logical block units."""
        return self.logical_offset // self.block_size

    @property
    def logical_end(self) -> int:
        """End offset of this range in the file (exclusive)."""
        return self.logical_offset + self.length

    @property
    def physical_offset(self) -> int | None:
        """Byte offset of the range on the realtime device, if mapped."""
        if self.rt_block is None:
            return None
        return self.rt_block * self.block_size


class RealtimeStream:
    """A read-only file-like view of a realtime file.

    Bytes are served from the realtime device at ``rt_block * block_size`` for
    each mapped range. Holes, unwritten extents and the region beyond
    ``di_size`` read as zeroes. Ranges with a status that is not readable cause
    the stream to refuse the read instead of returning data from another
    device. Short reads past the end of the realtime device are also refused.

    Args:
        device: The realtime volume to read from.
        ranges: The logical ranges of the file, as returned by
            :attr:`dissect.xfs.xfs.INode.realtime_ranges`.
        size: Logical file size in bytes.
        block_size: Filesystem/realtime block size in bytes.
    """

    def __init__(
        self,
        device: RealtimeDevice,
        ranges: list[RealtimeRange],
        size: int,
        block_size: int,
    ):
        self.device = device
        self.ranges = ranges
        self.size = size
        self.block_size = block_size
        self._pos = 0

    def readable(self) -> bool:
        """Indicate that this stream is readable."""
        return True

    def seekable(self) -> bool:
        """Indicate that this stream is seekable."""
        return True

    def tell(self) -> int:
        """Return the current logical file position."""
        return self._pos

    def seek(self, pos: int, whence: int = io.SEEK_SET) -> int:
        """Seek to a logical file position."""
        if whence == io.SEEK_SET:
            pass
        elif whence == io.SEEK_CUR:
            pos = self._pos + pos
        elif whence == io.SEEK_END:
            pos = self.size + pos
        else:
            raise ValueError(f"invalid whence: {whence}")

        if pos < 0:
            raise ValueError(f"negative seek position: {pos}")

        self._pos = pos
        return pos

    def readall(self) -> bytes:
        """Read until the end of the file."""
        return self.read()

    def readinto(self, buffer: bytearray) -> int:
        """Read bytes into a pre-allocated buffer, returning the number read."""
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def read(self, n: int = -1) -> bytes:
        """Read up to ``n`` bytes, or to the end of the file if ``n`` is ``-1``."""
        if n is None or n < -1:
            raise ValueError(f"invalid number of bytes to read: {n}")

        if n == -1:
            n = max(0, self.size - self._pos)
        else:
            n = min(n, max(0, self.size - self._pos))

        if n == 0:
            return b""

        result: list[bytes] = []
        offset = self._pos
        remaining = n

        while remaining > 0:
            current_range = self._range_at(offset)

            if current_range is None:
                result.append(b"\x00" * remaining)
                offset += remaining
                remaining = 0
                break

            range_offset = offset - current_range.logical_offset
            read_count = min(remaining, current_range.length - range_offset)

            # A later overlapping/contradictory range bounds this read so the
            # stream can report it instead of serving whichever range is first.
            conflict = self._next_contradiction(offset)
            if conflict is not None:
                read_count = min(read_count, conflict - offset)

            status = current_range.status
            if status in (RealtimeRangeStatus.HOLE, RealtimeRangeStatus.UNWRITTEN):
                result.append(b"\x00" * read_count)
            elif status.is_contradiction:
                raise RealtimeRangeError(
                    f"Realtime range at logical offset {current_range.logical_offset} is not readable: {status.value}"
                )
            elif not self.device.present or self.device.fh is None:
                raise RealtimeDeviceMissingException(
                    f"Realtime device required to read range at logical offset {current_range.logical_offset}"
                )
            elif current_range.rt_block is None:
                raise RealtimeRangeError(
                    f"Realtime range at logical offset {current_range.logical_offset} has no device block"
                )
            else:
                device_offset = current_range.rt_block * self.block_size + range_offset
                result.append(self._read_device(device_offset, read_count))

            offset += read_count
            remaining -= read_count

        self._pos = offset
        return b"".join(result)

    def _read_device(self, offset: int, length: int) -> bytes:
        device = self.device
        size = device.size
        if size is not None and offset + length > size:
            raise RealtimeRangeError(
                f"Realtime device short read: range [{offset}, {offset + length}) exceeds device size {size}"
            )

        device.fh.seek(offset)
        data = device.fh.read(length)
        if len(data) != length:
            raise RealtimeRangeError(
                f"Realtime device short read at offset {offset}: expected {length} bytes, got {len(data)}"
            )

        return data

    def _range_at(self, offset: int) -> RealtimeRange | None:
        match = None
        for current in self.ranges:
            if current.logical_offset <= offset < current.logical_end:
                if current.status.is_contradiction:
                    return current
                if match is None:
                    match = current
            elif current.logical_offset > offset:
                break
        return match

    def _next_contradiction(self, offset: int) -> int | None:
        for current in self.ranges:
            if current.logical_offset > offset and current.status.is_contradiction:
                return current.logical_offset
        return None
