from __future__ import annotations

import io
import struct
from typing import BinaryIO

from dissect.clfs.blf import BLF
from dissect.clfs.c_clfs import CLFS_CONTROL_RECORD_MAGIC_VALUE, SECTOR_SIZE
from dissect.clfs.integrity import (
    BlockIntegrityStatus,
    apply_fixup,
    block_checksum,
    verify_and_restore,
    verify_block,
)

CONTROL_BLOCK_CHECKSUM = 0xC64C824B
BASE_RECORD_BLOCK_OFFSET = 0x8200
BASE_RECORD_BLOCK_SECTORS = 61


def build_block(
    *,
    major: int = 0x15,
    minor: int = 0x00,
    total_sectors: int = 2,
    valid_sectors: int | None = None,
    fixup_values: list[int] | None = None,
    tail_signatures: list[int] | None = None,
    record: bytes = b"",
) -> bytes:
    """Build a small synthetic raw log block with a self-consistent checksum."""
    if valid_sectors is None:
        valid_sectors = total_sectors
    if fixup_values is None:
        fixup_values = [0xAAAA + i for i in range(total_sectors)]
    if tail_signatures is None:
        tail_signatures = [0x0150 + i for i in range(total_sectors)]

    size = total_sectors * SECTOR_SIZE
    fixup_offset = size - 8
    block = bytearray(size)

    struct.pack_into("<BBBBHHIIII", block, 0x00, major, minor, 1, 0, total_sectors, valid_sectors, 0, 0, 1, 0)
    struct.pack_into("<I", block, 0x28, 0x70)  # RecordOffsets[0]
    struct.pack_into("<I", block, 0x68, fixup_offset)  # FixupOffset

    block[0x70 : 0x70 + len(record)] = record

    for sector, signature in enumerate(tail_signatures):
        struct.pack_into("<H", block, sector * SECTOR_SIZE + SECTOR_SIZE - 2, signature)
    for index, value in enumerate(fixup_values):
        struct.pack_into("<H", block, fixup_offset + index * 2, value)

    struct.pack_into("<I", block, 0x0C, block_checksum(block))
    return bytes(block)


def mutate(data: bytes, offset: int) -> bytes:
    """Return a copy of data with a single byte flipped at offset."""
    mutated = bytearray(data)
    mutated[offset] ^= 0xFF
    return bytes(mutated)


def read_block(fh: BinaryIO, offset: int, total_sectors: int) -> bytes:
    fh.seek(offset)
    return fh.read(total_sectors * SECTOR_SIZE)


def test_verify_control_block(control_record_blf: BinaryIO) -> None:
    raw = control_record_blf.read()

    result = verify_block(raw)

    assert result.status is BlockIntegrityStatus.VERIFIED
    assert result.verified
    assert result.stored_checksum == CONTROL_BLOCK_CHECKSUM
    assert result.computed_checksum == CONTROL_BLOCK_CHECKSUM
    assert (result.major_version, result.minor_version) == (0x15, 0x00)
    assert result.total_sectors == result.valid_sectors == 2
    assert not result.torn


def test_verify_base_record_block(dummy_blf: BinaryIO) -> None:
    raw = read_block(dummy_blf, BASE_RECORD_BLOCK_OFFSET, BASE_RECORD_BLOCK_SECTORS)

    result = verify_block(raw)

    assert result.status is BlockIntegrityStatus.VERIFIED
    assert result.total_sectors == result.valid_sectors == BASE_RECORD_BLOCK_SECTORS


def test_verification_does_not_modify_raw_bytes(control_record_blf: BinaryIO) -> None:
    raw = bytearray(control_record_blf.read())
    snapshot = bytes(raw)

    result, restored = verify_and_restore(raw)

    assert result.status is BlockIntegrityStatus.VERIFIED
    assert bytes(raw) == snapshot
    assert restored != snapshot


def test_checksum_covers_raw_view_not_restored_view(control_record_blf: BinaryIO) -> None:
    raw = control_record_blf.read()
    restored = apply_fixup(raw)

    # The restored view differs from the raw view only in the sector tails.
    assert restored != raw
    differences = [i for i, (a, b) in enumerate(zip(raw, restored)) if a != b]
    assert differences == [0x1FE, 0x1FF, 0x3FE, 0x3FF]

    # The checksum was computed over the raw view: the restored view must not verify.
    assert block_checksum(restored) != CONTROL_BLOCK_CHECKSUM
    assert verify_block(restored).status is BlockIntegrityStatus.CHECKSUM_MISMATCH


def test_two_phase_verify_then_restore(control_record_blf: BinaryIO) -> None:
    raw = control_record_blf.read()

    result, restored = verify_and_restore(raw)

    # Phase one: integrity of the raw block.
    assert result.status is BlockIntegrityStatus.VERIFIED

    # Phase two: the sector tails are restored from the fixup array.
    fixup_offset = struct.unpack_from("<I", raw, 0x68)[0]
    for sector in range(result.total_sectors):
        expected = raw[fixup_offset + sector * 2 : fixup_offset + sector * 2 + 2]
        tail = sector * SECTOR_SIZE + SECTOR_SIZE - 2
        assert restored[tail : tail + 2] == expected

    # The restored view still yields a readable record with a valid magic.
    record_magic = struct.unpack_from("<Q", restored, 0x78)[0]
    assert record_magic == CLFS_CONTROL_RECORD_MAGIC_VALUE


def test_synthetic_block_roundtrip() -> None:
    fixup_values = [0xAAAA, 0xBBBB]
    block = build_block(fixup_values=fixup_values)

    result, restored = verify_and_restore(block)

    assert result.status is BlockIntegrityStatus.VERIFIED
    assert struct.unpack_from("<H", restored, 0x1FE)[0] == 0xAAAA
    assert struct.unpack_from("<H", restored, 0x3FE)[0] == 0xBBBB


def test_mutation_sector_tail_signature_detected() -> None:
    block = build_block()

    assert verify_block(mutate(block, 0x1FE)).status is BlockIntegrityStatus.CHECKSUM_MISMATCH
    assert verify_block(mutate(block, 0x3FF)).status is BlockIntegrityStatus.CHECKSUM_MISMATCH


def test_mutation_fixup_array_detected() -> None:
    block = build_block()
    fixup_offset = struct.unpack_from("<I", block, 0x68)[0]

    assert verify_block(mutate(block, fixup_offset)).status is BlockIntegrityStatus.CHECKSUM_MISMATCH
    assert verify_block(mutate(block, fixup_offset + 3)).status is BlockIntegrityStatus.CHECKSUM_MISMATCH


def test_mutation_record_data_detected() -> None:
    record = struct.pack("<QQ", 1, CLFS_CONTROL_RECORD_MAGIC_VALUE) + b"\xAA" * 0x40
    block = build_block(record=record)

    mutated = mutate(block, 0x90)

    assert verify_block(mutated).status is BlockIntegrityStatus.CHECKSUM_MISMATCH
    # The record structure itself is untouched and still reads back fine.
    _, restored = verify_and_restore(mutated)
    assert struct.unpack_from("<Q", restored, 0x78)[0] == CLFS_CONTROL_RECORD_MAGIC_VALUE


def test_mutation_checksum_field_detected() -> None:
    block = build_block()

    assert verify_block(mutate(block, 0x0C)).status is BlockIntegrityStatus.CHECKSUM_MISMATCH


def test_unconfirmed_version_marked_unverified() -> None:
    # The checksum is recomputed and internally consistent, but this version
    # is not covered by the confirmed format material, so no VERIFIED claim.
    block = build_block(major=0x16)

    result = verify_block(block)

    assert result.status is BlockIntegrityStatus.UNVERIFIED_VERSION
    assert not result.verified
    assert result.computed_checksum == result.stored_checksum


def test_torn_block_reported_not_enforced() -> None:
    # ValidSectors < TotalSectors is reported as torn; available format
    # material does not confirm the required reader behaviour for this state.
    block = build_block(valid_sectors=1)

    result = verify_block(block)

    assert result.status is BlockIntegrityStatus.VERIFIED
    assert result.torn


def test_counterexample_valid_magic_but_broken_integrity(control_record_blf: BinaryIO) -> None:
    # Flip one record data byte (Reserved1 of the control record). The record
    # stays fully readable and the magic still matches, but the raw block no
    # longer matches its stored checksum: a valid magic is not an integrity
    # check.
    mutated = mutate(control_record_blf.read(), 0x81)

    blf = BLF(fh=io.BytesIO(mutated))
    assert blf.c_record.valid

    assert verify_block(mutated).status is BlockIntegrityStatus.CHECKSUM_MISMATCH


def test_invalid_control_record_sample_fails_integrity(invalid_control_record_blf: BinaryIO) -> None:
    # This sample has a corrupted magic and a stale checksum field; the
    # integrity check catches it independently of the magic check.
    assert verify_block(invalid_control_record_blf.read()).status is BlockIntegrityStatus.CHECKSUM_MISMATCH
