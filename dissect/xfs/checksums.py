"""Checksum verification for XFS v5 metadata.

XFS v5 stores a CRC32c (Castagnoli) value in every metadata object.  The CRC is
calculated over a format-specific byte range after the four byte CRC field
itself has been treated as zero.  This module deliberately reports the exact
byte range that was hashed (and the field that was zeroed) instead of returning
a single unscoped "verified" boolean.

A checksum is an integrity check against accidental corruption.  It is not an
authentication mechanism: the CRC is keyless and can be recalculated by anyone
who modifies the object.  The UUID and owner fields checked here are likewise
self-declared metadata and are reported separately from the CRC result.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING
from uuid import UUID

from dissect.xfs.c_xfs import c_xfs

if TYPE_CHECKING:
    from collections.abc import Iterable

# Reflected CRC32c (Castagnoli) polynomial, as used by Linux for XFS.
CRC32C_POLYNOMIAL = 0x82F63B78
CRC32C_INITIAL = 0xFFFFFFFF
CRC32C_XOROUT = 0xFFFFFFFF


# Offsets of the CRC and identity fields are taken from the format definitions
# in c_xfs so this module cannot drift from the parsed layouts.
def _field_offset(structure: type, field: str) -> int:
    return structure.fields[field].offset


INODE_CRC_OFFSET = _field_offset(c_xfs.xfs_dinode, "di_crc")
AGF_CRC_OFFSET = _field_offset(c_xfs.xfs_agf, "agf_crc")
AGI_CRC_OFFSET = _field_offset(c_xfs.xfs_agi, "agi_crc")
AGFL_CRC_OFFSET = _field_offset(c_xfs.xfs_agfl, "agfl_crc")
SBLOCK_CRC_OFFSET = _field_offset(c_xfs.xfs_btree_sblock_crc, "bb_crc")
LBLOCK_CRC_OFFSET = _field_offset(c_xfs.xfs_btree_lblock_crc, "bb_crc")

# Offsets of the identity fields reported separately from the CRC.
INODE_UUID_OFFSET = _field_offset(c_xfs.xfs_dinode, "di_uuid")
INODE_INO_OFFSET = _field_offset(c_xfs.xfs_dinode, "di_ino")
AGF_UUID_OFFSET = _field_offset(c_xfs.xfs_agf, "agf_uuid")
AGF_SEQNO_OFFSET = _field_offset(c_xfs.xfs_agf, "agf_seqno")
AGI_UUID_OFFSET = _field_offset(c_xfs.xfs_agi, "agi_uuid")
AGI_SEQNO_OFFSET = _field_offset(c_xfs.xfs_agi, "agi_seqno")
AGFL_UUID_OFFSET = _field_offset(c_xfs.xfs_agfl, "agfl_uuid")
AGFL_SEQNO_OFFSET = _field_offset(c_xfs.xfs_agfl, "agfl_seqno")
SBLOCK_UUID_OFFSET = _field_offset(c_xfs.xfs_btree_sblock_crc, "bb_uuid")
SBLOCK_OWNER_OFFSET = _field_offset(c_xfs.xfs_btree_sblock_crc, "bb_owner")
LBLOCK_UUID_OFFSET = _field_offset(c_xfs.xfs_btree_lblock_crc, "bb_uuid")
LBLOCK_OWNER_OFFSET = _field_offset(c_xfs.xfs_btree_lblock_crc, "bb_owner")

# Magic numbers of the CRC-enabled btree block formats.
SHORT_BLOCK_MAGICS = frozenset(
    {
        c_xfs.XFS_ABTB_CRC_MAGIC,
        c_xfs.XFS_ABTC_CRC_MAGIC,
        c_xfs.XFS_IBT_CRC_MAGIC,
        c_xfs.XFS_FIBT_CRC_MAGIC,
    }
)
LONG_BLOCK_MAGICS = frozenset({c_xfs.XFS_BMAP_CRC_MAGIC})


def _build_crc32c_table() -> tuple[int, ...]:
    table = []
    for index in range(256):
        value = index
        for _ in range(8):
            value = (value >> 1) ^ (CRC32C_POLYNOMIAL if value & 1 else 0)
        table.append(value)
    return tuple(table)


_CRC32C_TABLE = _build_crc32c_table()


def crc32c(data: bytes, crc: int = CRC32C_INITIAL) -> int:
    """Calculate the XFS CRC32c of ``data``.

    Args:
        data: Bytes to checksum.
        crc: Running CRC state as returned by :func:`crc32c_update`, or the
            initial state for a fresh checksum.
    """
    return crc32c_update(crc, data) ^ CRC32C_XOROUT


def crc32c_update(crc: int, data: bytes) -> int:
    """Update a running XFS CRC32c with ``data`` without applying the final XOR."""
    table = _CRC32C_TABLE
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc


@dataclass(frozen=True)
class ChecksumResult:
    """Result of a CRC calculation over one explicitly defined byte range.

    Attributes:
        kind: Metadata format that defined the calculation, e.g. ``"inode"``.
        algorithm: Checksum algorithm name, currently always ``"crc32c"``.
        checksum_offset: Offset of the stored CRC field relative to the object.
        coverage: ``(start, end)`` byte span, relative to the object, that was
            passed to the CRC.  The CRC field inside this span is zeroed.
        zeroed: ``(start, end)`` span of the CRC field that was replaced with
            zero bytes before hashing.
        stored: The CRC value read from the object, in host byte order.
        calculated: The CRC value calculated over ``coverage``.
        magic: Metadata magic number, if the format has one.
    """

    kind: str
    algorithm: str
    checksum_offset: int
    coverage: tuple[int, int]
    zeroed: tuple[int, int]
    stored: int
    calculated: int
    magic: int | None = None

    @property
    def valid(self) -> bool:
        """Whether the stored CRC matches the calculated CRC."""
        return self.stored == self.calculated

    @property
    def covered_length(self) -> int:
        return self.coverage[1] - self.coverage[0]


@dataclass(frozen=True)
class ProvenanceResult:
    """Self-declared UUID and owner fields, reported separately from the CRC.

    A match only says that the object's metadata fields agree with the expected
    values.  It is not proof of origin or authenticity: both the payload and
    these fields can be rewritten together.
    """

    uuid: UUID | None
    expected_uuid: UUID | None
    owner: int | None
    expected_owner: int | None

    @property
    def uuid_match(self) -> bool | None:
        if self.uuid is None or self.expected_uuid is None:
            return None
        return self.uuid == self.expected_uuid

    @property
    def owner_match(self) -> bool | None:
        if self.owner is None or self.expected_owner is None:
            return None
        return self.owner == self.expected_owner

    @property
    def matches(self) -> bool | None:
        """Whether all provided identity expectations match.

        ``None`` means no identity expectation was supplied and no conclusion
        can be drawn.  This property does not authenticate the metadata.
        """
        checks = [check for check in (self.uuid_match, self.owner_match) if check is not None]
        if not checks:
            return None
        return all(checks)


@dataclass(frozen=True)
class MetadataVerification:
    """CRC result and provenance result for one metadata object.

    ``checksum`` and ``provenance`` are intentionally separate.  A valid CRC
    only means the covered bytes were internally consistent; it does not
    establish who wrote them.
    """

    checksum: ChecksumResult
    provenance: ProvenanceResult
    source_offset: int | None = None

    @property
    def integrity_ok(self) -> bool:
        return self.checksum.valid

    @property
    def provenance_ok(self) -> bool | None:
        return self.provenance.matches

    @property
    def source_range(self) -> tuple[int, int] | None:
        """Absolute ``(start, end)`` byte range in the backing file, if known."""
        if self.source_offset is None:
            return None
        start, end = self.checksum.coverage
        return self.source_offset + start, self.source_offset + end

    def with_source(self, offset: int) -> MetadataVerification:
        """Return a copy of this result annotated with its absolute file offset."""
        return replace(self, source_offset=offset)


def _crc_for_zeroed_field(buf: bytes, offset: int, length: int) -> int:
    """Calculate CRC32c over ``buf[offset:offset + length]`` with the four bytes at
    ``offset`` zeroed.  ``offset`` is relative to ``buf``.
    """
    crc = crc32c_update(CRC32C_INITIAL, buf[:offset])
    crc = crc32c_update(crc, b"\x00\x00\x00\x00")
    crc = crc32c_update(crc, buf[offset + 4 : offset + length])
    return crc ^ CRC32C_XOROUT


def _read_u32(buf: bytes, offset: int) -> int:
    return int.from_bytes(buf[offset : offset + 4], "big")


def _read_u64(buf: bytes, offset: int) -> int:
    return int.from_bytes(buf[offset : offset + 8], "big")


def _read_uuid(buf: bytes, offset: int) -> UUID | None:
    if len(buf) < offset + 16:
        return None
    return UUID(bytes=bytes(buf[offset : offset + 16]))


def _checksum(kind: str, buf: bytes, crc_offset: int, length: int, magic: int | None = None) -> ChecksumResult:
    if len(buf) < length:
        raise ValueError(f"{kind} buffer too small: need {length} bytes, got {len(buf)}")
    if crc_offset + 4 > length:
        raise ValueError(f"{kind} CRC field at {crc_offset:#x} is outside the {length:#x} byte coverage")

    return ChecksumResult(
        kind=kind,
        algorithm="crc32c",
        checksum_offset=crc_offset,
        coverage=(0, length),
        zeroed=(crc_offset, crc_offset + 4),
        stored=int.from_bytes(buf[crc_offset : crc_offset + 4], "little"),
        calculated=_crc_for_zeroed_field(buf, crc_offset, length),
        magic=magic,
    )


def verify_inode(
    buf: bytes,
    *,
    size: int | None = None,
    expected_ino: int | None = None,
    expected_uuid: UUID | None = None,
) -> MetadataVerification:
    """Verify a v3 (CRC enabled) inode.

    The CRC covers the whole on-disk inode as configured by
    ``sb_inodesize``, not merely the fixed ``xfs_dinode`` core.  The ``di_crc``
    field at offset ``0x64`` is zeroed for the calculation.

    Args:
        buf: Raw inode bytes.
        size: Actual inode size from ``sb_inodesize``.  Defaults to ``len(buf)``.
        expected_ino: Expected absolute inode number for ``di_ino``.
        expected_uuid: Expected metadata UUID for ``di_uuid``.
    """
    length = len(buf) if size is None else size
    if length > len(buf):
        raise ValueError(f"inode buffer too small: need {length} bytes, got {len(buf)}")
    if length < INODE_CRC_OFFSET + 4:
        raise ValueError("inode is too small to contain a v3 CRC field")
    if buf[4] < 3:
        raise ValueError("inode version does not contain a CRC field")

    result = _checksum("inode", buf, INODE_CRC_OFFSET, length, magic=int.from_bytes(buf[0:2], "big"))
    provenance = ProvenanceResult(
        uuid=_read_uuid(buf, INODE_UUID_OFFSET),
        expected_uuid=expected_uuid,
        owner=_read_u64(buf, INODE_INO_OFFSET),
        expected_owner=expected_ino,
    )
    return MetadataVerification(checksum=result, provenance=provenance)


_AG_HEADER_LAYOUT = {
    "agf": (AGF_CRC_OFFSET, AGF_UUID_OFFSET, AGF_SEQNO_OFFSET, 4),
    "agi": (AGI_CRC_OFFSET, AGI_UUID_OFFSET, AGI_SEQNO_OFFSET, 4),
    "agfl": (AGFL_CRC_OFFSET, AGFL_UUID_OFFSET, AGFL_SEQNO_OFFSET, 4),
}


def verify_ag_header(
    kind: str,
    buf: bytes,
    *,
    size: int | None = None,
    expected_uuid: UUID | None = None,
    expected_owner: int | None = None,
) -> MetadataVerification:
    """Verify an AGF, AGI or AGFL sector.

    AG header CRCs cover one filesystem sector (``sb_sectsize``), not a whole
    filesystem block.  Any bytes between the structure and the end of the
    sector are part of the calculation.

    Args:
        kind: One of ``"agf"``, ``"agi"`` or ``"agfl"``.
        buf: Raw header sector bytes.
        size: Sector size from ``sb_sectsize``.  Defaults to ``len(buf)``.
        expected_uuid: Expected metadata UUID.
        expected_owner: Expected allocation group number (``*_seqno``).
    """
    try:
        crc_offset, uuid_offset, owner_offset, owner_size = _AG_HEADER_LAYOUT[kind]
    except KeyError:
        raise ValueError(f"unknown allocation group header: {kind}") from None

    length = len(buf) if size is None else size
    if length > len(buf):
        raise ValueError(f"{kind} buffer too small: need {length} bytes, got {len(buf)}")
    if length < crc_offset + 4:
        raise ValueError(f"{kind} header is too small to contain a CRC field")

    owner = int.from_bytes(buf[owner_offset : owner_offset + owner_size], "big")
    result = _checksum(kind, buf, crc_offset, length, magic=_read_u32(buf, 0))
    provenance = ProvenanceResult(
        uuid=_read_uuid(buf, uuid_offset),
        expected_uuid=expected_uuid,
        owner=owner,
        expected_owner=expected_owner,
    )
    return MetadataVerification(checksum=result, provenance=provenance)


def verify_btree_block(
    buf: bytes,
    *,
    size: int | None = None,
    expected_uuid: UUID | None = None,
    expected_owner: int | None = None,
    long_format: bool | None = None,
) -> MetadataVerification:
    """Verify a CRC-enabled btree block.

    The CRC covers the entire on-disk block (``sb_blocksize``), including the
    record area and any tail padding.  Short format blocks store a 32 bit
    ``bb_owner``; long format (bmbt) blocks store a 64 bit ``bb_owner``.

    Args:
        buf: Raw btree block bytes.
        size: Block size from ``sb_blocksize``.  Defaults to ``len(buf)``.
        expected_uuid: Expected metadata UUID for ``bb_uuid``.
        expected_owner: Expected owner for ``bb_owner`` (AG number for AG
            btrees, inode number for bmap btrees).
        long_format: Force the long (bmbt) header layout.  When omitted, the
            magic number selects the layout.
    """
    length = len(buf) if size is None else size
    if length > len(buf):
        raise ValueError(f"btree buffer too small: need {length} bytes, got {len(buf)}")
    if length < 8:
        raise ValueError("btree block is too small to contain a magic number")

    magic = _read_u32(buf, 0)
    if long_format is None:
        if magic in SHORT_BLOCK_MAGICS:
            long_format = False
        elif magic in LONG_BLOCK_MAGICS:
            long_format = True
        else:
            raise ValueError(f"not a CRC-enabled btree block magic: {magic:#x}")

    if long_format:
        kind = "btree_lblock"
        crc_offset = LBLOCK_CRC_OFFSET
        uuid_offset = LBLOCK_UUID_OFFSET
        owner_offset = LBLOCK_OWNER_OFFSET
        owner_size = 8
    else:
        kind = "btree_sblock"
        crc_offset = SBLOCK_CRC_OFFSET
        uuid_offset = SBLOCK_UUID_OFFSET
        owner_offset = SBLOCK_OWNER_OFFSET
        owner_size = 4

    if length < crc_offset + 4:
        raise ValueError(f"{kind} block is too small to contain a CRC field")

    owner = int.from_bytes(buf[owner_offset : owner_offset + owner_size], "big")
    result = _checksum(kind, buf, crc_offset, length, magic=magic)
    provenance = ProvenanceResult(
        uuid=_read_uuid(buf, uuid_offset),
        expected_uuid=expected_uuid,
        owner=owner,
        expected_owner=expected_owner,
    )
    return MetadataVerification(checksum=result, provenance=provenance)


@dataclass(frozen=True)
class VerificationReport:
    """Aggregate report that keeps integrity and provenance conclusions apart.

    ``integrity_ok`` answers "did the stored CRC match the covered bytes?".
    ``provenance_ok`` answers "did the self-declared UUID and owner fields match
    the expected values?".  Neither answer authenticates the metadata: the CRC
    is keyless, and both the payload and the identity fields can be rewritten
    together.
    """

    results: tuple[MetadataVerification, ...]

    @property
    def integrity_ok(self) -> bool:
        return all(result.integrity_ok for result in self.results)

    @property
    def provenance_ok(self) -> bool | None:
        checks = [result.provenance_ok for result in self.results]
        if any(check is False for check in checks):
            return False
        if checks and all(check is True for check in checks):
            return True
        return None

    def by_kind(self, kind: str) -> tuple[MetadataVerification, ...]:
        return tuple(result for result in self.results if result.checksum.kind == kind)

    def summary(self) -> dict[str, object]:
        """Machine readable summary with separate integrity and provenance keys."""
        return {
            "integrity": {
                "crc32c_ok": self.integrity_ok,
                "objects_checked": len(self.results),
            },
            "provenance": {
                "uuid_owner_match": self.provenance_ok,
                "authenticated": False,
            },
            "objects": [
                {
                    "kind": result.checksum.kind,
                    "crc32c_ok": result.integrity_ok,
                    "coverage": list(result.checksum.coverage),
                    "source_range": list(result.source_range) if result.source_range else None,
                    "zeroed": list(result.checksum.zeroed),
                    "uuid_match": result.provenance.uuid_match,
                    "owner_match": result.provenance.owner_match,
                }
                for result in self.results
            ],
        }


def build_report(results: Iterable[MetadataVerification]) -> VerificationReport:
    """Build a report without collapsing CRC and provenance into one verdict."""
    return VerificationReport(results=tuple(results))


def verify_metadata_objects(results: Iterable[MetadataVerification]) -> VerificationReport:
    """Alias for :func:`build_report` kept as a descriptive entry point."""
    return build_report(results)
