from __future__ import annotations

import io
import zlib
from dataclasses import dataclass
from enum import Enum

from dissect.clfs.c_clfs import SECTOR_SIZE, c_clfs

LOG_BLOCK_HEADER_SIZE = 0x70
LOG_BLOCK_CHECKSUM_OFFSET = 0x0C

#: Block versions for which the checksum coverage described below has been
#: empirically confirmed against reference samples. Blocks with any other
#: version are reported as :attr:`BlockIntegrityStatus.UNVERIFIED_VERSION`.
CONFIRMED_VERSIONS = frozenset({(0x15, 0x00)})


class BlockIntegrityStatus(Enum):
    """Outcome of an integrity check on a single raw log block."""

    #: Stored checksum matches the recomputed checksum of the raw block.
    VERIFIED = "verified"
    #: Stored checksum does not match the recomputed checksum of the raw block.
    CHECKSUM_MISMATCH = "checksum-mismatch"
    #: Block version for which the checksum coverage could not be confirmed.
    UNVERIFIED_VERSION = "unverified-version"
    #: Block is structurally unusable (truncated or inconsistent sector count).
    INVALID_BLOCK = "invalid-block"


@dataclass(frozen=True)
class BlockIntegrity:
    """Result of verifying one raw (on-disk, encoded) log block.

    A ``VERIFIED`` status only means the raw block bytes are consistent with
    the checksum stored inside the block. The checksum is a plain CRC-32: it
    is not keyed and not cryptographic, so it detects accidental corruption
    but cannot authenticate the origin of the log or detect deliberate
    forgery.
    """

    status: BlockIntegrityStatus
    stored_checksum: int
    computed_checksum: int | None
    major_version: int
    minor_version: int
    total_sectors: int
    valid_sectors: int

    @property
    def verified(self) -> bool:
        return self.status is BlockIntegrityStatus.VERIFIED

    @property
    def torn(self) -> bool:
        """Whether fewer sectors are marked valid than the block spans.

        Reported for information only: available format material does not
        confirm how a reader must treat this state, so it is not enforced.
        """
        return self.valid_sectors < self.total_sectors


def _parse_header(raw: bytes) -> c_clfs.CLFS_LOG_BLOCK_HEADER:
    return c_clfs.CLFS_LOG_BLOCK_HEADER(io.BytesIO(raw))


def block_checksum(raw: bytes | bytearray) -> int:
    """Return the checksum of a raw log block as stored in its header.

    The checksum is a CRC-32 (the zlib variant) over the entire raw on-disk
    block (``TotalSectors * 512`` bytes) with the 4-byte ``Checksum`` field
    itself treated as zero. Everything else is covered: the block header,
    the record data, the per-sector trailing signatures and the fixup array.

    The input is the raw (encoded) view, i.e. the bytes exactly as stored,
    before any sector fixup is applied. The input buffer is never modified.
    """
    view = bytearray(raw)
    view[LOG_BLOCK_CHECKSUM_OFFSET : LOG_BLOCK_CHECKSUM_OFFSET + 4] = b"\x00" * 4
    return zlib.crc32(view) & 0xFFFFFFFF


def verify_block(raw: bytes | bytearray) -> BlockIntegrity:
    """Verify the integrity of one raw log block, before any fixup is applied.

    This is phase one of reading a block and must be performed on the raw
    on-disk bytes. Verifying a restored (fixed-up) view instead would check
    different content than the checksum was computed over.
    """
    raw = bytes(raw)
    if len(raw) < LOG_BLOCK_HEADER_SIZE:
        return BlockIntegrity(BlockIntegrityStatus.INVALID_BLOCK, 0, None, 0, 0, 0, 0)

    header = _parse_header(raw)
    version = (header.MajorVersion, header.MinorVersion)

    if header.TotalSectors == 0 or len(raw) != header.TotalSectors * SECTOR_SIZE:
        return BlockIntegrity(
            BlockIntegrityStatus.INVALID_BLOCK,
            header.Checksum,
            None,
            header.MajorVersion,
            header.MinorVersion,
            header.TotalSectors,
            header.ValidSectors,
        )

    computed = block_checksum(raw)

    if version not in CONFIRMED_VERSIONS:
        status = BlockIntegrityStatus.UNVERIFIED_VERSION
    elif computed != header.Checksum:
        status = BlockIntegrityStatus.CHECKSUM_MISMATCH
    else:
        status = BlockIntegrityStatus.VERIFIED

    return BlockIntegrity(
        status,
        header.Checksum,
        computed,
        header.MajorVersion,
        header.MinorVersion,
        header.TotalSectors,
        header.ValidSectors,
    )


def apply_fixup(raw: bytes | bytearray) -> bytes:
    """Return the restored view of a raw log block by applying the sector fixup.

    This is phase two of reading a block. The last 2 bytes of every sector
    are replaced with the corresponding entry of the fixup array located at
    ``FixupOffset``. The input buffer is never modified; the restored view
    is returned as a new object.
    """
    raw = bytes(raw)
    header = _parse_header(raw)

    data = bytearray(raw)
    fixup_offset = header.FixupOffset
    if fixup_offset + header.TotalSectors * 2 > len(data):
        raise ValueError("Fixup array extends beyond the end of the block")

    for sector in range(header.TotalSectors):
        tail = sector * SECTOR_SIZE + SECTOR_SIZE - 2
        data[tail : tail + 2] = data[fixup_offset + sector * 2 : fixup_offset + sector * 2 + 2]

    return bytes(data)


def verify_and_restore(raw: bytes | bytearray) -> tuple[BlockIntegrity, bytes]:
    """Verify a raw log block and return its restored view, in that order.

    The checksum is verified on the raw bytes exactly as stored; the fixup
    is applied to a separate copy afterwards. The two views are never mixed:
    the verification result always describes the raw block, and the input
    buffer is left unmodified.
    """
    result = verify_block(raw)
    restored = apply_fixup(raw)
    return result, restored
