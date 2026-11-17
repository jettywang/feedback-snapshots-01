from __future__ import annotations

import io
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID

import pytest

from dissect.xfs.checksums import (
    build_report,
    verify_ag_header,
    verify_btree_block,
    verify_inode,
)
from dissect.xfs.xfs import XFS

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import BinaryIO

    from dissect.xfs.checksums import MetadataVerification

# The reference implementation and the offsets below are intentionally
# duplicated here instead of imported from dissect.xfs.checksums.  The tests
# must compute expected checksums from the format definitions without sharing
# the parser's coverage function, otherwise a coverage bug would be invisible.
CRC32C_POLYNOMIAL = 0x82F63B78

INODE_CRC_OFFSET = 0x64
AGF_CRC_OFFSET = 0xD8
AGI_CRC_OFFSET = 0x138
AGFL_CRC_OFFSET = 0x20
SBLOCK_CRC_OFFSET = 0x34
LBLOCK_CRC_OFFSET = 0x40

TEST_UUID = UUID("12345678-1234-5678-1234-567812345678")
TEST_INO = 0x2B40


def crc32c_reference(data: bytes) -> int:
    """Bitwise CRC32c reference implementation, independent of the module under test."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (CRC32C_POLYNOMIAL if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def expected_crc(buf: bytes, crc_offset: int) -> int:
    """CRC32c over the whole buffer with the four byte checksum field zeroed."""
    zeroed = bytearray(buf)
    zeroed[crc_offset : crc_offset + 4] = b"\x00\x00\x00\x00"
    return crc32c_reference(bytes(zeroed))


def install_crc(buf: bytearray, crc_offset: int) -> None:
    struct.pack_into("<I", buf, crc_offset, expected_crc(bytes(buf), crc_offset))


def pattern(size: int, seed: int) -> bytearray:
    return bytearray(((index * 31 + seed * 17) & 0xFF) for index in range(size))


def build_inode(size: int = 512, *, seed: int = 1) -> bytearray:
    buf = pattern(size, seed)
    struct.pack_into(">H", buf, 0x00, 0x494E)
    buf[0x04] = 3
    buf[0x05] = 2
    struct.pack_into(">Q", buf, 0x98, TEST_INO)
    buf[0xA0:0xB0] = TEST_UUID.bytes
    install_crc(buf, INODE_CRC_OFFSET)
    return buf


def build_ag_header(kind: str, size: int = 512, *, seed: int = 2) -> bytearray:
    layouts = {
        "agf": (0x58414746, AGF_CRC_OFFSET, 0x40, 0x08),
        "agi": (0x58414749, AGI_CRC_OFFSET, 0x128, 0x08),
        "agfl": (0x5841464C, AGFL_CRC_OFFSET, 0x08, 0x04),
    }
    magic, crc_offset, uuid_offset, seqno_offset = layouts[kind]
    buf = pattern(size, seed)
    struct.pack_into(">I", buf, 0x00, magic)
    struct.pack_into(">I", buf, seqno_offset, 0)
    buf[uuid_offset : uuid_offset + 16] = TEST_UUID.bytes
    install_crc(buf, crc_offset)
    return buf


def build_sblock(size: int = 512, *, seed: int = 3) -> bytearray:
    buf = pattern(size, seed)
    struct.pack_into(">I", buf, 0x00, 0x41423342)  # XFS_ABTB_CRC_MAGIC
    struct.pack_into(">H", buf, 0x04, 0)
    struct.pack_into(">H", buf, 0x06, 2)
    buf[0x20:0x30] = TEST_UUID.bytes
    struct.pack_into(">I", buf, 0x30, 0)
    install_crc(buf, SBLOCK_CRC_OFFSET)
    return buf


def build_lblock(size: int = 512, *, seed: int = 4) -> bytearray:
    buf = pattern(size, seed)
    struct.pack_into(">I", buf, 0x00, 0x424D4133)  # XFS_BMAP_CRC_MAGIC
    struct.pack_into(">H", buf, 0x04, 0)
    struct.pack_into(">H", buf, 0x06, 2)
    buf[0x28:0x38] = TEST_UUID.bytes
    struct.pack_into(">Q", buf, 0x38, 0)
    install_crc(buf, LBLOCK_CRC_OFFSET)
    return buf


def _verify_inode(buf: bytes) -> MetadataVerification:
    return verify_inode(buf, size=len(buf), expected_ino=TEST_INO, expected_uuid=TEST_UUID)


def _verify_ag_header(kind: str) -> Callable[[bytes], MetadataVerification]:
    return lambda buf: verify_ag_header(kind, buf, size=len(buf), expected_uuid=TEST_UUID, expected_owner=0)


def _verify_btree(buf: bytes) -> MetadataVerification:
    return verify_btree_block(buf, size=len(buf), expected_uuid=TEST_UUID, expected_owner=0)


@dataclass(frozen=True)
class Vector:
    name: str
    data: bytes
    crc_offset: int
    body_offset: int
    verify: Callable[[bytes], MetadataVerification]


VECTORS = [
    Vector("inode", bytes(build_inode(1024)), INODE_CRC_OFFSET, 0x200, _verify_inode),
    Vector("agf", bytes(build_ag_header("agf")), AGF_CRC_OFFSET, 0x100, _verify_ag_header("agf")),
    Vector("agi", bytes(build_ag_header("agi")), AGI_CRC_OFFSET, 0x100, _verify_ag_header("agi")),
    Vector("agfl", bytes(build_ag_header("agfl")), AGFL_CRC_OFFSET, 0x100, _verify_ag_header("agfl")),
    Vector("btree_sblock", bytes(build_sblock()), SBLOCK_CRC_OFFSET, 0x100, _verify_btree),
    Vector("btree_lblock", bytes(build_lblock()), LBLOCK_CRC_OFFSET, 0x100, _verify_btree),
]


def test_crc32c_known_vector() -> None:
    assert crc32c_reference(b"123456789") == 0xE3069283


@pytest.mark.parametrize("vector", VECTORS, ids=[vector.name for vector in VECTORS])
@pytest.mark.parametrize("mutation", ["normal", "crc_field_only", "body"])
def test_short_vector_cases(vector: Vector, mutation: str) -> None:
    buf = bytearray(vector.data)
    if mutation == "crc_field_only":
        buf[vector.crc_offset] ^= 0xFF
    elif mutation == "body":
        buf[vector.body_offset] ^= 0xFF

    result = vector.verify(bytes(buf))
    assert result.integrity_ok is (mutation == "normal")


@pytest.mark.parametrize("vector", VECTORS, ids=[vector.name for vector in VECTORS])
def test_coverage_and_zeroed_field_are_reported(vector: Vector) -> None:
    result = vector.verify(vector.data)

    assert result.checksum.kind
    assert result.checksum.algorithm == "crc32c"
    assert result.checksum.coverage == (0, len(vector.data))
    assert result.checksum.covered_length == len(vector.data)
    assert result.checksum.zeroed == (vector.crc_offset, vector.crc_offset + 4)
    assert result.checksum.checksum_offset == vector.crc_offset


def test_crc_field_must_be_zeroed_before_hashing() -> None:
    buf = build_ag_header("agf")
    stored = struct.unpack_from("<I", buf, AGF_CRC_OFFSET)[0]

    assert expected_crc(bytes(buf), AGF_CRC_OFFSET) == stored
    # Hashing the buffer as-is includes the stored checksum itself and does not
    # reproduce the on-disk value, which is what forces the zeroing rule.
    assert crc32c_reference(bytes(buf)) != stored


def test_inode_crc_covers_configured_inode_size_not_core_struct() -> None:
    buf = build_inode(1024)

    assert verify_inode(buf, size=1024, expected_ino=TEST_INO, expected_uuid=TEST_UUID).integrity_ok
    # The same bytes checked with the default 512 byte inode size use different
    # coverage and must not validate.
    assert not verify_inode(buf, size=512, expected_ino=TEST_INO, expected_uuid=TEST_UUID).integrity_ok

    # A byte beyond the fixed inode core but inside the configured inode size is
    # still covered (data fork / inode tail).
    mutated = bytearray(buf)
    mutated[0xB0 + 7] ^= 0xFF
    assert not verify_inode(mutated, size=1024, expected_ino=TEST_INO, expected_uuid=TEST_UUID).integrity_ok


def test_btree_crc_covers_full_block_including_tail() -> None:
    for block in (build_sblock(512), build_lblock(512)):
        mutated = bytearray(block)
        mutated[-1] ^= 0xFF
        assert not _verify_btree(bytes(mutated)).integrity_ok


def test_ag_header_crc_covers_one_sector_not_whole_block() -> None:
    sector = bytes(build_ag_header("agf"))
    assert verify_ag_header("agf", sector, size=512, expected_uuid=TEST_UUID, expected_owner=0).integrity_ok

    extended = sector + bytes(512)
    assert not verify_ag_header("agf", extended, size=1024, expected_uuid=TEST_UUID, expected_owner=0).integrity_ok


def test_sector_and_block_checksums_are_not_interchangeable() -> None:
    # An AG header CRC is computed over one sector.  Copying that checksum into
    # the same object embedded in a full block and hashing the whole block must
    # not validate, even though the first 512 bytes are byte-identical.
    sector = build_ag_header("agf")
    full_block = bytes(sector) + bytes(512)
    result = verify_ag_header("agf", full_block, size=1024, expected_uuid=TEST_UUID, expected_owner=0)

    assert not result.integrity_ok
    assert result.checksum.stored == struct.unpack_from("<I", sector, AGF_CRC_OFFSET)[0]
    assert result.checksum.coverage == (0, 1024)


@pytest.mark.parametrize(
    ("verify", "size"),
    [
        (_verify_inode, 0x40),
        (_verify_ag_header("agf"), 0x10),
        (_verify_btree, 0x08),
    ],
    ids=["inode", "agf", "btree"],
)
def test_short_objects_are_rejected(verify: Callable[[bytes], MetadataVerification], size: int) -> None:
    with pytest.raises(ValueError):
        verify(bytes(size))


def test_inode_version_without_crc_is_rejected() -> None:
    buf = build_inode(512)
    buf[0x04] = 2
    with pytest.raises(ValueError, match="version"):
        _verify_inode(bytes(buf))


def test_unknown_btree_magic_is_rejected() -> None:
    buf = bytearray(build_sblock())
    struct.pack_into(">I", buf, 0, 0x41425442)  # non-CRC XFS_ABTB_MAGIC
    with pytest.raises(ValueError, match="magic"):
        _verify_btree(bytes(buf))


def test_recomputing_a_different_object_crc_does_not_mask_tampering() -> None:
    inode = build_inode(1024)
    agi = build_ag_header("agi")
    assert _verify_inode(bytes(inode)).integrity_ok
    assert _verify_ag_header("agi")(bytes(agi)).integrity_ok

    # Change inode payload and recompute the AGI checksum instead.  The AGI
    # remains valid, but the inode checksum still fails because the two
    # objects use independent coverage.
    tampered_inode = bytearray(inode)
    tampered_inode[0x200] ^= 0xFF
    refreshed_agi = bytearray(agi)
    install_crc(refreshed_agi, AGI_CRC_OFFSET)

    assert _verify_ag_header("agi")(bytes(refreshed_agi)).integrity_ok
    assert not _verify_inode(bytes(tampered_inode)).integrity_ok


def test_report_separates_integrity_from_provenance() -> None:
    buf = build_inode(512)
    result = verify_inode(buf, size=512, expected_ino=TEST_INO + 1, expected_uuid=UUID(int=0))

    assert result.integrity_ok
    assert result.provenance.uuid_match is False
    assert result.provenance.owner_match is False
    assert result.provenance_ok is False

    report = build_report([result])
    assert report.integrity_ok is True
    assert report.provenance_ok is False

    summary = report.summary()
    assert summary["integrity"] == {"crc32c_ok": True, "objects_checked": 1}
    assert summary["provenance"] == {"uuid_owner_match": False, "authenticated": False}


def test_report_does_not_claim_provenance_without_expectations() -> None:
    result = verify_inode(build_inode(512), size=512)

    assert result.integrity_ok
    assert result.provenance.uuid_match is None
    assert result.provenance.owner_match is None
    assert result.provenance_ok is None

    summary = build_report([result]).summary()
    assert summary["provenance"] == {"uuid_owner_match": None, "authenticated": False}


@pytest.mark.parametrize("fixture", ["xfs_bin", "xfs_sparse_bin", "xfs_bigtime_bin"])
def test_bundled_image_metadata_verifies(fixture: str, request: pytest.FixtureRequest) -> None:
    fh: BinaryIO = request.getfixturevalue(fixture)
    xfs = XFS(fh)
    ag = xfs.ag[0]

    results = [
        ag.verify_agf(),
        ag.verify_agi(),
        ag.verify_agfl(),
        *ag.verify_btree_roots(),
        xfs.root.verify(),
    ]

    assert all(result.integrity_ok for result in results)
    assert all(result.provenance.uuid_match for result in results)
    assert all(result.provenance.owner_match for result in results)
    assert {result.checksum.kind for result in results} == {
        "agf",
        "agi",
        "agfl",
        "btree_sblock",
        "inode",
    }


def test_bundled_image_reports_absolute_coverage(xfs_bin: BinaryIO) -> None:
    xfs = XFS(xfs_bin)
    sector_size = xfs.sb.sb_sectsize
    block_size = xfs.block_size

    agf = xfs.ag[0].verify_agf()
    assert agf.source_range == (sector_size, 2 * sector_size)

    agi = xfs.ag[0].verify_agi()
    assert agi.source_range == (2 * sector_size, 3 * sector_size)

    agfl = xfs.ag[0].verify_agfl()
    assert agfl.source_range == (3 * sector_size, 4 * sector_size)

    btree_roots = xfs.ag[0].verify_btree_roots()
    for result in btree_roots:
        start, end = result.source_range
        assert start % block_size == 0
        assert end - start == block_size

    inode = xfs.root.verify()
    assert inode.source_range == (
        xfs.root.relative_inum * xfs.sb.sb_inodesize,
        (xfs.root.relative_inum + 1) * xfs.sb.sb_inodesize,
    )


def test_ag_report_counts_all_metadata(xfs_bin: BinaryIO) -> None:
    report = XFS(xfs_bin).ag[0].verify_all()
    summary = report.summary()

    objects = summary["objects"]
    assert summary["integrity"]["crc32c_ok"] is True
    assert summary["integrity"]["objects_checked"] == len(objects)
    assert len(objects) >= 5
    assert summary["provenance"] == {"uuid_owner_match": True, "authenticated": False}
    assert all(obj["source_range"] is not None for obj in objects)
    assert {"agf", "agi", "agfl", "btree_sblock", "inode"} <= {obj["kind"] for obj in objects}


def test_bundled_image_tampering_is_detected(xfs_bin: BinaryIO) -> None:
    raw = bytearray(xfs_bin.read())
    xfs = XFS(io.BytesIO(raw))
    inode = xfs.root
    inode_offset = inode.relative_inum * inode.ag.sb.sb_inodesize
    inode_size = inode.ag.sb.sb_inodesize

    # Flip a byte in the inode's literal/fork area, beyond the fixed core.
    raw[inode_offset + 0xB0] ^= 0xFF

    tampered = XFS(io.BytesIO(raw))
    assert not tampered.root.verify().integrity_ok
    # AG headers were not touched and must still verify.
    assert tampered.ag[0].verify_agf().integrity_ok
    assert tampered.ag[0].verify_agi().integrity_ok
    assert tampered.ag[0].verify_agfl().integrity_ok
    assert inode_size > 0xB0


def test_tampering_with_other_objects_checkum_cannot_pass(xfs_bin: BinaryIO) -> None:
    raw = bytearray(xfs_bin.read())
    xfs = XFS(io.BytesIO(raw))
    block_size = xfs.block_size
    sector_size = xfs.sb.sb_sectsize

    # Corrupt an AGF payload byte and then recompute the AGI checksum over its
    # (unchanged) sector.  The AGI remains valid, the AGF must not.
    agf_offset = sector_size
    agi_offset = 2 * sector_size
    raw[agf_offset + 0x60] ^= 0xFF
    agi_sector = bytearray(raw[agi_offset : agi_offset + sector_size])
    install_crc(agi_sector, AGI_CRC_OFFSET)
    raw[agi_offset : agi_offset + sector_size] = agi_sector

    tampered = XFS(io.BytesIO(raw))
    assert not tampered.ag[0].verify_agf().integrity_ok
    assert tampered.ag[0].verify_agi().integrity_ok
    assert block_size > sector_size
