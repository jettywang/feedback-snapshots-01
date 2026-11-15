from __future__ import annotations

import hashlib
import io
import struct
from typing import BinaryIO

import pytest

from dissect.clfs.blf import BLF
from dissect.clfs.c_clfs import (
    SECTOR_SIZE,
    BlockHeader,
    SectorFixup,
    c_clfs,
)
from dissect.clfs.exceptions import InvalidRecordBlockError

FLAGS_ENCODED = 0x1
FLAGS_DECODED = 0x2


def build_block(
    total_sectors: int,
    *,
    fixup_byte: int = 0x27,
    valid_sectors: int | None = None,
    flags: int = FLAGS_ENCODED,
    fixup_offset: int | None = None,
    originals: list[bytes] | None = None,
    signature_base: int = 0x10,
) -> bytearray:
    """Build a synthetic but format-correct ENCODED/DECODED log block.

    Every sector is filled with a recognizable per-sector pattern so that any
    unintended modification shows up in a byte-by-byte comparison.
    """
    size = total_sectors * SECTOR_SIZE
    block = bytearray(size)
    for sector in range(total_sectors):
        block[sector * SECTOR_SIZE : (sector + 1) * SECTOR_SIZE] = bytes([sector + 1]) * SECTOR_SIZE

    block[0] = 0x15  # MajorVersion
    block[2] = fixup_byte
    struct.pack_into("<H", block, 4, total_sectors)
    struct.pack_into("<H", block, 6, total_sectors if valid_sectors is None else valid_sectors)
    struct.pack_into("<I", block, 16, flags)
    struct.pack_into("<I", block, 0x28, 0x70)  # RecordOffsets[0]

    if fixup_offset is None:
        fixup_offset = size - 2 - total_sectors * 2
    struct.pack_into("<I", block, 0x68, fixup_offset)

    if originals is None:
        originals = [bytes([0xA0 + i, 0xB0 + i]) for i in range(total_sectors)]
    for i, original in enumerate(originals):
        block[fixup_offset + 2 * i : fixup_offset + 2 * i + 2] = original

    if flags & FLAGS_ENCODED:
        for sector in range(total_sectors):
            low = signature_base
            if sector == 0:
                low |= 0x40
            if sector == total_sectors - 1:
                low |= 0x20
            tail = sector * SECTOR_SIZE + SECTOR_SIZE - 2
            block[tail] = low
            block[tail + 1] = fixup_byte

    return block


def test_two_sector_block_restore(control_record_blf: BinaryIO) -> None:
    """Two-sector sample: restore succeeds and every fixup position is accounted for."""
    raw_bytes = control_record_blf.read()
    control_record_blf.seek(0)
    logblock = BlockHeader(fh=control_record_blf, offset=0)

    # Physical bytes are preserved untouched, the restored view is separate.
    assert logblock.raw == raw_bytes
    assert logblock.data != logblock.raw
    assert len(logblock.data) == 2 * SECTOR_SIZE

    # Byte-by-byte explanation of the corrected positions:
    # - fixup array lives at FixupOffset 0x3F8 and holds 2 entries of 2 bytes: 00 00 | 00 00
    # - entry 0 (00 00) restores the tail of sector 0 at block offset 0x1FE
    # - entry 1 (00 00) restores the tail of sector 1 at block offset 0x3FE
    assert logblock.fixups == (
        SectorFixup(sector=0, offset=0x1FE, signature=bytes.fromhex("5001"), original=bytes.fromhex("0000")),
        SectorFixup(sector=1, offset=0x3FE, signature=bytes.fromhex("3001"), original=bytes.fromhex("0000")),
    )
    assert logblock.raw[0x1FE] == 0x50 and logblock.raw[0x1FF] == 0x01  # on-disk signature sector 0
    assert logblock.raw[0x3FE] == 0x30 and logblock.raw[0x3FF] == 0x01  # on-disk signature sector 1
    assert logblock.data[0x1FE] == 0x00 and logblock.data[0x1FF] == 0x00  # restored sector 0 tail
    assert logblock.data[0x3FE] == 0x00 and logblock.data[0x3FF] == 0x00  # restored sector 1 tail

    # Exactly the 4 signature bytes differ between raw and restored view, nothing else.
    changed = {i for i, (a, b) in enumerate(zip(logblock.raw, logblock.data)) if a != b}
    assert changed == {0x1FE, 0x1FF, 0x3FE, 0x3FF}


def test_multi_sector_block_restore() -> None:
    """Multi-sector (4) sample: each sector tail is restored from its own fixup entry."""
    originals = [b"AB", b"CD", b"EF", b"GH"]
    block = build_block(4, originals=originals)
    logblock = BlockHeader(fh=io.BytesIO(block), offset=0)

    # Byte-by-byte explanation of the corrected positions (fixup array at 0x7F6):
    # - entry 0 "AB" (0x7F6) -> sector 0 tail at 0x1FE, on-disk signature 50 27
    # - entry 1 "CD" (0x7F8) -> sector 1 tail at 0x3FE, on-disk signature 10 27
    # - entry 2 "EF" (0x7FA) -> sector 2 tail at 0x5FE, on-disk signature 10 27
    # - entry 3 "GH" (0x7FC) -> sector 3 tail at 0x7FE, on-disk signature 30 27
    assert logblock.fixups == (
        SectorFixup(sector=0, offset=0x1FE, signature=b"\x50\x27", original=b"AB"),
        SectorFixup(sector=1, offset=0x3FE, signature=b"\x10\x27", original=b"CD"),
        SectorFixup(sector=2, offset=0x5FE, signature=b"\x10\x27", original=b"EF"),
        SectorFixup(sector=3, offset=0x7FE, signature=b"\x30\x27", original=b"GH"),
    )

    tails = {0x1FE, 0x1FF, 0x3FE, 0x3FF, 0x5FE, 0x5FF, 0x7FE, 0x7FF}
    for i, (raw_byte, data_byte) in enumerate(zip(logblock.raw, logblock.data)):
        if i in tails:
            continue
        assert raw_byte == data_byte, f"byte {i:#x} outside the sector tails was modified"

    for fixup, original in zip(logblock.fixups, originals):
        assert logblock.data[fixup.offset] == original[0]
        assert logblock.data[fixup.offset + 1] == original[1]


def test_multi_sector_real_block_restore(dummy_blf: BinaryIO) -> None:
    """Real 61-sector base record block from a Windows BLF restores cleanly."""
    logblock = BlockHeader(fh=dummy_blf, offset=0x800)

    assert len(logblock.fixups) == 61
    assert logblock.fixups[0].signature == bytes.fromhex("5011")
    assert logblock.fixups[-1].signature == bytes.fromhex("3011")
    assert all(f.signature == bytes.fromhex("1011") for f in logblock.fixups[1:-1])
    # All 61 original tail bytes are 0x0000 in this block.
    assert all(f.original == b"\x00\x00" for f in logblock.fixups)
    assert logblock.data[0x1FE:0x200] == b"\x00\x00"
    assert logblock.data[-2:] == b"\x00\x00"


def test_container_signature_base(dummy_container: BinaryIO) -> None:
    """Container log blocks use signature base 0x04 and must validate as well."""
    logblock = BlockHeader(fh=dummy_container, offset=0x9000)

    assert logblock.header.TotalSectors == 1
    assert logblock.fixups == (
        SectorFixup(sector=0, offset=0x1FE, signature=bytes.fromhex("6401"), original=bytes.fromhex("0000")),
    )


def test_decoded_block_passes_through() -> None:
    """A DECODED block already holds plain data: no fixup is applied."""
    block = build_block(2, flags=FLAGS_DECODED)
    logblock = BlockHeader(fh=io.BytesIO(block), offset=0)

    assert logblock.fixups == ()
    assert logblock.data == logblock.raw == bytes(block)


def test_reject_zero_total_sectors() -> None:
    """A block declaring zero sectors makes zero progress and must not be zero-filled."""
    block = build_block(2)
    struct.pack_into("<H", block, 4, 0)
    with pytest.raises(InvalidRecordBlockError, match="zero total sectors"):
        BlockHeader(fh=io.BytesIO(block), offset=0)


def test_reject_zero_valid_sectors() -> None:
    block = build_block(2, valid_sectors=0)
    with pytest.raises(InvalidRecordBlockError, match="valid sector count"):
        BlockHeader(fh=io.BytesIO(block), offset=0)


def test_reject_valid_sectors_exceeding_total() -> None:
    block = build_block(2, valid_sectors=3)
    with pytest.raises(InvalidRecordBlockError, match="valid sector count"):
        BlockHeader(fh=io.BytesIO(block), offset=0)


def test_reject_truncated_block() -> None:
    """A truncated block must be rejected, not padded with zeros into a normal block."""
    block = build_block(3)[: 2 * SECTOR_SIZE + 100]
    with pytest.raises(InvalidRecordBlockError, match="Truncated block"):
        BlockHeader(fh=io.BytesIO(block), offset=0)


def test_reject_fixup_array_overlapping_header() -> None:
    block = build_block(2)
    struct.pack_into("<I", block, 0x68, 0x10)  # FixupOffset inside the block header
    with pytest.raises(InvalidRecordBlockError, match="overlaps the block header"):
        BlockHeader(fh=io.BytesIO(block), offset=0)


def test_reject_fixup_array_out_of_bounds() -> None:
    block = build_block(2, fixup_offset=2 * SECTOR_SIZE - 2)
    with pytest.raises(InvalidRecordBlockError, match="past the end of the block"):
        BlockHeader(fh=io.BytesIO(block), offset=0)


def test_reject_fixup_array_covering_signature() -> None:
    # Array at 0x1FC..0x200 covers the sector 0 tail signature at 0x1FE.
    block = build_block(2, fixup_offset=0x1FC)
    with pytest.raises(InvalidRecordBlockError, match="covers the signature of sector 0"):
        BlockHeader(fh=io.BytesIO(block), offset=0)


def test_reject_signature_sequence_mismatch() -> None:
    block = build_block(2)
    block[0x1FF] = 0x99  # high byte of sector 0 signature no longer matches the Fixup byte
    with pytest.raises(InvalidRecordBlockError, match="Sector 0 signature sequence mismatch"):
        BlockHeader(fh=io.BytesIO(block), offset=0)


def test_reject_signature_position_mismatch() -> None:
    block = build_block(3)
    block[0x3FE] = 0x50  # sector 1 is not the first sector of the block
    with pytest.raises(InvalidRecordBlockError, match="Sector 1 signature position mismatch"):
        BlockHeader(fh=io.BytesIO(block), offset=0)


def test_reject_signature_base_mismatch() -> None:
    block = build_block(3)
    block[0x3FE] = 0x14  # sector 1 signature base deviates from the rest of the block
    with pytest.raises(InvalidRecordBlockError, match="Sector 1 signature base mismatch"):
        BlockHeader(fh=io.BytesIO(block), offset=0)


def test_reject_ambiguous_flags() -> None:
    for flags in (FLAGS_ENCODED | FLAGS_DECODED, 0x0):
        block = build_block(2, flags=flags)
        with pytest.raises(InvalidRecordBlockError, match="Invalid log block flags"):
            BlockHeader(fh=io.BytesIO(block), offset=0)


def test_bad_fixup_does_not_affect_neighbouring_blocks() -> None:
    """A bad fixup in one block must not change the visible content of adjacent blocks."""
    good_first = build_block(2, fixup_byte=0x11, originals=[b"AA", b"BB"])
    bad_middle = build_block(2, fixup_byte=0x33, originals=[b"XX", b"YY"])
    bad_middle[0x1FF] = 0xDE  # corrupt sector 0 signature sequence of the middle block
    good_last = build_block(2, fixup_byte=0x77, originals=[b"CC", b"DD"])

    buffer = bytes(good_first + bad_middle + good_last)
    digest_before = hashlib.sha256(buffer).hexdigest()

    fh = io.BytesIO(buffer)
    first = BlockHeader(fh=fh, offset=0)
    with pytest.raises(InvalidRecordBlockError, match="signature sequence mismatch"):
        BlockHeader(fh=fh, offset=2 * SECTOR_SIZE)
    last = BlockHeader(fh=fh, offset=4 * SECTOR_SIZE)

    # The neighbouring blocks still decode to exactly the same content as in isolation.
    assert first.data == BlockHeader(fh=io.BytesIO(good_first), offset=0).data
    assert last.data == BlockHeader(fh=io.BytesIO(good_last), offset=0).data
    assert first.data[0x1FE:0x200] == b"AA" and first.data[0x3FE:0x400] == b"BB"
    assert last.data[0x1FE:0x200] == b"CC" and last.data[0x3FE:0x400] == b"DD"

    # The input itself was never modified.
    assert hashlib.sha256(buffer).hexdigest() == digest_before
    fh.seek(0)
    assert fh.read() == buffer


def test_input_hash_unmodified(dummy_blf: BinaryIO) -> None:
    """Parsing must never write to the input file-like object."""
    raw_bytes = dummy_blf.read()
    digest_before = hashlib.sha256(raw_bytes).hexdigest()

    dummy_blf.seek(0)
    blf = BLF(fh=dummy_blf)
    list(blf.base_records())

    assert hashlib.sha256(raw_bytes).hexdigest() == digest_before


def test_base_records_only_consume_validated_views(dummy_blf: BinaryIO) -> None:
    """A bad sector signature in a later base record aborts parsing of that record only."""
    pristine = dummy_blf.read()
    corrupted = bytearray(pristine)
    corrupted[0x8200 + 10 * SECTOR_SIZE + SECTOR_SIZE - 2] ^= 0xFF  # sector 10 tail of the shadow base block

    clean_records = list(BLF(fh=io.BytesIO(pristine)).base_records())
    assert len(clean_records) == 2

    records = []
    with pytest.raises(InvalidRecordBlockError, match="Sector 10 signature"):
        for record in BLF(fh=io.BytesIO(corrupted)).base_records():
            records.append(record)

    # The good base record preceding the corrupt one is parsed identically.
    assert len(records) == 1
    assert records[0].streams == clean_records[0].streams
    assert records[0].containers == clean_records[0].containers


def test_control_record_rejects_bad_signature(bad_control_record_blf: BinaryIO) -> None:
    """The bad control record sample is now rejected at the block header level."""
    with pytest.raises(InvalidRecordBlockError, match="signature"):
        BLF(fh=bad_control_record_blf)


def test_open_returns_restored_view(control_record_blf: BinaryIO) -> None:
    logblock = BlockHeader(fh=control_record_blf, offset=0)
    buf = logblock.open()

    assert buf.read() == logblock.data
    # The restored view is consumable by the cstruct definitions downstream.
    buf.seek(logblock.header.RecordOffsets[0])
    record = c_clfs.CLFS_CONTROL_RECORD(buf)
    assert record.Magic == 0xC1F5C1F500005F1C
