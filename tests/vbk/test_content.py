from __future__ import annotations

import gzip
import hashlib
import io
import pickle

import pytest

from dissect.archive.exception import IsADirectoryError
from dissect.archive.vbk.c_vbk import c_vbk
from dissect.archive.vbk.content import ContentStatus, ReportStatus
from dissect.archive.vbk.exception import ContentChangedError, IncompleteContentError
from dissect.archive.vbk.vbk import VBK, VBKError
from tests._util import absolute_path
from tests.vbk._synth import (
    ARCHIVED,
    NORMAL,
    RESERVED,
    SPARSE,
    UNKNOWN_TYPE,
    FibBlock,
    FileSpec,
    StoredBlock,
    VBKBuilder,
    lz4_block,
)

BLOCK_SIZE = 0x1000
LZ4 = int(c_vbk.CompressionType.LZ4)


def open_vbk(data: bytes) -> VBK:
    return VBK(io.BytesIO(data))


def mixed_file(**overrides: object) -> bytes:
    """A five block file: LZ4 data, declared sparse, unknown type, archived, plain data."""
    secret = b"SECRET!!" * (BLOCK_SIZE // 8)
    spec = FileSpec(
        name="mixed.bin",
        blocks=[
            FibBlock(type=NORMAL, data=b"A" * BLOCK_SIZE, block_id=0, block_size=BLOCK_SIZE),
            FibBlock(type=SPARSE, data=b"\x00" * BLOCK_SIZE, block_id=0, block_size=BLOCK_SIZE),
            # The unknown block's ID points at real stored bytes: they must never be
            # mistaken for readable content of this file.
            FibBlock(type=UNKNOWN_TYPE, data=secret, block_id=1, block_size=BLOCK_SIZE),
            FibBlock(type=ARCHIVED, block_id=0x800 | (7 << 32), block_size=BLOCK_SIZE),
            FibBlock(type=NORMAL, data=b"C" * BLOCK_SIZE, block_id=2, block_size=BLOCK_SIZE),
        ],
        storage=[
            StoredBlock(data=lz4_block(b"A" * BLOCK_SIZE), compression=LZ4),
            StoredBlock(data=secret),
            StoredBlock(data=lz4_block(b"C" * BLOCK_SIZE), compression=LZ4),
        ],
    )
    return VBKBuilder(block_size=BLOCK_SIZE).build([spec], **overrides)


def test_mixed_blocks_are_classified_by_descriptor() -> None:
    vbk = open_vbk(mixed_file())
    report = vbk.inspect("mixed.bin")

    assert report.logical_size == 5 * BLOCK_SIZE
    assert [extent.status for extent in report] == [
        ContentStatus.READABLE,
        ContentStatus.SPARSE,
        ContentStatus.UNSUPPORTED_BLOCK,
        ContentStatus.UNSUPPORTED_ARCHIVED,
        ContentStatus.READABLE,
    ]
    assert [(extent.start, extent.stop) for extent in report] == [
        (0, BLOCK_SIZE),
        (BLOCK_SIZE, 2 * BLOCK_SIZE),
        (2 * BLOCK_SIZE, 3 * BLOCK_SIZE),
        (3 * BLOCK_SIZE, 4 * BLOCK_SIZE),
        (4 * BLOCK_SIZE, 5 * BLOCK_SIZE),
    ]
    assert report.readable_bytes == 2 * BLOCK_SIZE
    assert report.sparse_bytes == BLOCK_SIZE
    assert report.missing_bytes == 2 * BLOCK_SIZE
    assert report.status is ReportStatus.PARTIAL
    assert not report.complete


def test_unknown_block_bytes_do_not_enter_partial_export() -> None:
    vbk = open_vbk(mixed_file())
    report = vbk.inspect("mixed.bin")
    recovered = report.export(allow_incomplete=True)

    assert not recovered.complete
    assert b"SECRET" not in recovered
    assert recovered[0:BLOCK_SIZE] == b"A" * BLOCK_SIZE
    assert recovered[BLOCK_SIZE : 2 * BLOCK_SIZE] == b"\x00" * BLOCK_SIZE
    # Unknown and archived ranges are placeholders, even though the block store
    # still holds real bytes at the unknown block's storage index.
    assert recovered[2 * BLOCK_SIZE : 4 * BLOCK_SIZE] == b"\x00" * (2 * BLOCK_SIZE)
    assert recovered[4 * BLOCK_SIZE :] == b"C" * BLOCK_SIZE
    assert [gap.status for gap in recovered.gaps] == [
        ContentStatus.UNSUPPORTED_BLOCK,
        ContentStatus.UNSUPPORTED_ARCHIVED,
    ]


def test_partial_export_requires_explicit_opt_in() -> None:
    report = open_vbk(mixed_file()).inspect("mixed.bin")

    with pytest.raises(IncompleteContentError, match="not completely recoverable"):
        report.export()


def test_gaps_are_reported_not_summarised_as_success() -> None:
    report = open_vbk(mixed_file()).inspect("mixed.bin")

    assert [(gap.start, gap.stop) for gap in report.gaps] == [
        (2 * BLOCK_SIZE, 3 * BLOCK_SIZE),
        (3 * BLOCK_SIZE, 4 * BLOCK_SIZE),
    ]
    summary = report.summary()
    assert "partial" in summary
    assert "gap 0x2000-0x3000 unsupported_block" in summary
    assert "gap 0x3000-0x4000 unsupported_archived" in summary

    payload = report.as_dict()
    assert payload["status"] == "partial"
    assert [gap["status"] for gap in payload["gaps"]] == ["unsupported_block", "unsupported_archived"]


def test_all_readable_file_is_complete_and_recomputable() -> None:
    blocks = [b"0123456789abcdef" * 256, b"fedcba9876543210" * 128]
    spec = FileSpec(
        name="plain.bin",
        blocks=[
            FibBlock(type=NORMAL, data=blocks[0], block_id=0, block_size=len(blocks[0])),
            FibBlock(type=NORMAL, data=blocks[1], block_id=1, block_size=len(blocks[1])),
        ],
        storage=[StoredBlock(data=blocks[0]), StoredBlock(data=blocks[1])],
    )
    vbk = open_vbk(VBKBuilder(block_size=len(blocks[0])).build([spec]))
    report = vbk.inspect("plain.bin")

    assert report.complete
    assert report.status is ReportStatus.COMPLETE
    assert report.missing_bytes == 0
    assert report.export() == b"".join(blocks)
    merged = report.ranges(ContentStatus.READABLE)
    assert len(merged) == 1
    assert (merged[0].start, merged[0].stop) == (0, len(b"".join(blocks)))


def test_sparse_is_only_sparse_when_the_descriptor_says_so() -> None:
    zero = b"\x00" * BLOCK_SIZE
    spec = FileSpec(
        name="zeros.bin",
        blocks=[
            FibBlock(type=NORMAL, data=zero, block_id=0, block_size=BLOCK_SIZE),
            FibBlock(type=SPARSE, data=zero, block_id=0, block_size=BLOCK_SIZE),
        ],
        storage=[StoredBlock(data=zero)],
    )
    report = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec])).inspect("zeros.bin")

    assert [extent.status for extent in report] == [ContentStatus.READABLE, ContentStatus.SPARSE]
    assert report.readable_bytes == BLOCK_SIZE
    assert report.sparse_bytes == BLOCK_SIZE


def test_storage_source_size_mismatch_is_a_gap() -> None:
    data = b"D" * BLOCK_SIZE
    spec = FileSpec(
        name="short.bin",
        blocks=[FibBlock(type=NORMAL, data=data, block_id=0, block_size=BLOCK_SIZE)],
        storage=[StoredBlock(data=data, source_size=BLOCK_SIZE * 2)],
    )
    report = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec])).inspect("short.bin")

    assert report.status is ReportStatus.UNRECOVERABLE
    assert report.gaps
    assert report.gaps[0].status is ContentStatus.CORRUPT
    assert "does not match FIB block size" in report.gaps[0].detail
    assert b"D" not in report.export(allow_incomplete=True)


def test_storage_digest_mismatch_is_a_gap() -> None:
    data = b"E" * BLOCK_SIZE
    spec = FileSpec(
        name="tampered.bin",
        blocks=[FibBlock(type=NORMAL, data=data, block_id=0, block_size=BLOCK_SIZE)],
        storage=[StoredBlock(data=data)],
    )
    vbk = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec]))
    # Flip a byte of the stored payload without updating any descriptor.
    block = vbk.block_store.get(0)
    buf = bytearray(vbk.fh.getvalue())
    buf[block.offset + 8] ^= 0xFF

    report = open_vbk(bytes(buf)).inspect("tampered.bin")

    assert report.status is ReportStatus.UNRECOVERABLE
    assert report.gaps[0].status is ContentStatus.CORRUPT
    assert "digest mismatch" in report.gaps[0].detail
    assert report.gaps[0].digest_ok is False


def test_storage_digest_mismatch_can_be_skipped() -> None:
    data = b"E" * BLOCK_SIZE
    spec = FileSpec(
        name="tampered.bin",
        blocks=[FibBlock(type=NORMAL, data=data, block_id=0, block_size=BLOCK_SIZE)],
        storage=[StoredBlock(data=data)],
    )
    vbk = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec]))
    block = vbk.block_store.get(0)
    buf = bytearray(vbk.fh.getvalue())
    buf[block.offset + 8] ^= 0xFF

    unchecked = open_vbk(bytes(buf)).inspect("tampered.bin", verify=False)
    assert unchecked.complete
    assert unchecked.extents[0].digest_ok is None


def test_storage_offset_beyond_the_file_is_a_gap() -> None:
    data = b"F" * BLOCK_SIZE
    spec = FileSpec(
        name="beyond.bin",
        blocks=[FibBlock(type=NORMAL, data=data, block_id=0, block_size=BLOCK_SIZE)],
        storage=[StoredBlock(data=data, offset=0x100000)],
    )
    report = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec])).inspect("beyond.bin")

    assert report.gaps[0].status is ContentStatus.MISSING_DATA
    assert "exceeds available data" in report.gaps[0].detail


def test_missing_storage_descriptor_is_a_gap() -> None:
    data = b"G" * BLOCK_SIZE
    spec = FileSpec(
        name="missing.bin",
        blocks=[FibBlock(type=NORMAL, data=data, block_id=99, block_size=BLOCK_SIZE)],
        storage=[StoredBlock(data=data)],
    )
    report = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec])).inspect("missing.bin")

    assert report.gaps[0].status is ContentStatus.MISSING_DATA
    assert "not in the block store" in report.gaps[0].detail


def test_unsupported_compression_is_a_gap() -> None:
    data = b"H" * BLOCK_SIZE
    spec = FileSpec(
        name="zlib.bin",
        blocks=[FibBlock(type=NORMAL, data=data, block_id=0, block_size=BLOCK_SIZE)],
        storage=[StoredBlock(data=data, compression=int(c_vbk.CompressionType.ZLH))],
    )
    report = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec])).inspect("zlib.bin")

    assert report.status is ReportStatus.UNRECOVERABLE
    assert report.gaps[0].status is ContentStatus.UNSUPPORTED_COMPRESSION
    assert "unsupported compression" in report.gaps[0].detail


def test_reserved_block_is_a_gap_not_empty_content() -> None:
    spec = FileSpec(
        name="reserved.bin",
        blocks=[
            FibBlock(type=RESERVED, block_id=0, block_size=BLOCK_SIZE),
            FibBlock(type=NORMAL, data=b"I" * BLOCK_SIZE, block_id=0, block_size=BLOCK_SIZE),
        ],
        storage=[StoredBlock(data=b"I" * BLOCK_SIZE)],
    )
    report = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec])).inspect("reserved.bin")

    assert report.gaps[0].status is ContentStatus.RESERVED
    assert report.extents[1].status is ContentStatus.READABLE
    assert report.export(allow_incomplete=True)[:BLOCK_SIZE] == b"\x00" * BLOCK_SIZE


def test_lz4_crc_mismatch_is_a_gap() -> None:
    data = b"J" * BLOCK_SIZE
    spec = FileSpec(
        name="crc.bin",
        blocks=[FibBlock(type=NORMAL, data=data, block_id=0, block_size=BLOCK_SIZE)],
        storage=[StoredBlock(data=lz4_block(data), compression=LZ4)],
    )
    vbk = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec]))
    block = vbk.block_store.get(0)
    descriptor = vbk.get("crc.bin").inspect().extents[0]

    buf = bytearray(vbk.fh.getvalue())
    buf[block.offset + 4] ^= 0xFF  # Lz4BlockHeader.CRC

    report = open_vbk(bytes(buf)).inspect("crc.bin")
    assert report.status is ReportStatus.UNRECOVERABLE
    assert "CRC mismatch" in report.gaps[0].detail
    assert descriptor.storage_offset == block.offset


def test_file_without_blocks_is_entirely_a_gap() -> None:
    spec = FileSpec(name="noblocks.bin", blocks=[], size=BLOCK_SIZE)
    report = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec])).inspect("noblocks.bin")

    assert report.status is ReportStatus.UNRECOVERABLE
    assert report.gaps[0].status is ContentStatus.UNCOVERED
    assert report.gaps[0].logical_length == BLOCK_SIZE
    assert report.export(allow_incomplete=True) == b"\x00" * BLOCK_SIZE


def test_short_file_covers_less_than_the_fib_declares() -> None:
    data = b"K" * BLOCK_SIZE
    spec = FileSpec(
        name="declared.bin",
        blocks=[
            FibBlock(type=NORMAL, data=data, block_id=0, block_size=BLOCK_SIZE),
            FibBlock(type=NORMAL, data=data, block_id=1, block_size=BLOCK_SIZE),
        ],
        storage=[StoredBlock(data=data), StoredBlock(data=data)],
        size=3 * BLOCK_SIZE,
    )
    report = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec])).inspect("declared.bin")

    assert report.status is ReportStatus.PARTIAL
    assert report.extents[-1].status is ContentStatus.UNCOVERED
    assert report.gaps[-1].start == 2 * BLOCK_SIZE
    assert report.gaps[-1].stop == 3 * BLOCK_SIZE
    assert "cover" in report.issues[0]


def test_fib_table_block_size_mismatch_is_an_issue() -> None:
    data = b"T" * BLOCK_SIZE
    spec = FileSpec(
        name="table.bin",
        blocks=[FibBlock(type=NORMAL, data=data, block_id=0, block_size=BLOCK_SIZE)],
        storage=[StoredBlock(data=data)],
    )
    report = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec], fib_table_block_size=BLOCK_SIZE * 2)).inspect(
        "table.bin"
    )

    assert not report.complete
    assert any("FIB tables declare block size" in issue for issue in report.issues)


def test_fib_table_entry_count_mismatch_is_an_issue() -> None:
    data = b"U" * BLOCK_SIZE
    spec = FileSpec(
        name="entries.bin",
        blocks=[FibBlock(type=NORMAL, data=data, block_id=0, block_size=BLOCK_SIZE)],
        storage=[StoredBlock(data=data)],
    )
    report = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec], fib_table_count=0)).inspect("entries.bin")

    assert not report.complete
    assert any("FIB tables hold" in issue for issue in report.issues)


def test_fib_with_more_bytes_than_the_file_is_an_issue() -> None:
    data = b"L" * BLOCK_SIZE
    spec = FileSpec(
        name="overrun.bin",
        blocks=[
            FibBlock(type=NORMAL, data=data, block_id=0, block_size=BLOCK_SIZE),
            FibBlock(type=NORMAL, data=data, block_id=1, block_size=BLOCK_SIZE),
        ],
        storage=[StoredBlock(data=data), StoredBlock(data=data)],
        size=BLOCK_SIZE,
    )
    report = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec])).inspect("overrun.bin")

    assert not report.complete
    assert any("declares" in issue for issue in report.issues)


def test_block_size_mismatch_is_an_issue() -> None:
    data = b"M" * BLOCK_SIZE
    spec = FileSpec(
        name="shorts.bin",
        blocks=[
            FibBlock(type=NORMAL, data=data, block_id=0, block_size=BLOCK_SIZE),
            FibBlock(type=NORMAL, data=data, block_id=0, block_size=BLOCK_SIZE // 2),
            FibBlock(type=NORMAL, data=data, block_id=0, block_size=BLOCK_SIZE),
        ],
        storage=[StoredBlock(data=data)],
    )
    report = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec])).inspect("shorts.bin")

    assert not report.complete
    assert any("block size" in issue for issue in report.issues)


def test_partial_export_marks_gaps_and_keeps_all_bytes() -> None:
    report = open_vbk(mixed_file()).inspect("mixed.bin")
    recovered = report.export(allow_incomplete=True)

    # Gaps are placeholders, but the logical file length is preserved and the
    # readable and sparse ranges keep their real content.
    assert len(recovered) == report.logical_size
    assert isinstance(recovered, bytes)
    assert recovered[0:4] == b"AAAA"
    assert recovered[4 * BLOCK_SIZE : 4 * BLOCK_SIZE + 4] == b"CCCC"
    assert report.counts["unsupported_block"] == BLOCK_SIZE


def test_external_item_reports_missing_content() -> None:
    spec = FileSpec(name="external.bin", type=int(c_vbk.DirItemType.ExtFib), size=0x1234)
    vbk = open_vbk(VBKBuilder().build([spec]))
    entry = vbk.get("external.bin")
    report = entry.inspect()

    assert entry.is_external_file()
    assert report.status is ReportStatus.UNRECOVERABLE
    assert report.gaps[0].status is ContentStatus.MISSING_EXTERNAL
    assert report.gaps[0].logical_length == 0x1234
    assert report.export(allow_incomplete=True) == b"\x00" * 0x1234


def test_patch_item_is_reported_as_unsupported() -> None:
    spec = FileSpec(name="patch.bin", type=int(c_vbk.DirItemType.Patch), size=0x200)
    vbk = open_vbk(VBKBuilder().build([spec]))
    report = vbk.inspect("patch.bin")

    assert report.gaps[0].status is ContentStatus.UNSUPPORTED_PATCH
    with pytest.raises(IncompleteContentError):
        report.export()

    entry = vbk.get("patch.bin")
    with pytest.raises(IsADirectoryError):
        entry.open()


def test_increment_item_is_reported_as_unsupported() -> None:
    spec = FileSpec(name="increment.bin", type=int(c_vbk.DirItemType.Increment), size=0x400)
    report = open_vbk(VBKBuilder().build([spec])).inspect("increment.bin")

    assert report.gaps[0].status is ContentStatus.UNSUPPORTED_INCREMENT
    assert report.missing_bytes == 0x400


def test_real_sample_reports_are_recomputable() -> None:
    with gzip.open(absolute_path("_data/vbk/test9.vbk.gz")) as fh:
        vbk = VBK(fh)
        report = vbk.inspect(
            "6745a759-2205-4cd2-b172-8ec8f7e60ef8 "
            "(78a5467d-87f5-8540-9a84-7569ae2849ad_2d1bb20f-49c1-485d-a689-696693713a5a)/DEV__dev_nvme1n1"
        )

        assert report.complete
        assert report.readable_bytes == 0x200000
        assert report.sparse_bytes == 0x200000
        assert hashlib.sha256(report.export()).hexdigest() == (
            "337350cac29d2ed34c23ce9fc675950badf85fd2b694791abe6999d36f0dc1b3"
        )

    with gzip.open(absolute_path("_data/vbk/test13.vbk.gz")) as fh:
        vbk = VBK(fh)
        report = vbk.inspect(
            "6745a759-2205-4cd2-b172-8ec8f7e60ef8 (3c834d56-37ac-8bd3-b946-30113c55c4b5)"
            "/8b14f74c-360d-4d7a-98f7-7f4c5e737eb7"
        )

        assert report.complete
        assert report.readable_bytes == 0x314200
        assert report.sparse_bytes == 0
        assert hashlib.sha256(report.export()).hexdigest() == (
            "e9ed281cf9c2fe1745e4eb9c926c1a64bd47569c48be511c5fdf6fd5793e5a77"
        )


def test_real_sample_sparse_blocks_carry_zero_digests() -> None:
    # test9's sparse blocks record the digest of a zero-filled block. The checker
    # verifies that digest, so a sparse declaration cannot hide nonzero content.
    with gzip.open(absolute_path("_data/vbk/test9.vbk.gz")) as fh:
        report = VBK(fh).inspect(
            "6745a759-2205-4cd2-b172-8ec8f7e60ef8 "
            "(78a5467d-87f5-8540-9a84-7569ae2849ad_2d1bb20f-49c1-485d-a689-696693713a5a)/DEV__dev_nvme1n1"
        )

        for extent in report:
            if extent.status is ContentStatus.SPARSE:
                assert extent.digest == hashlib.md5(b"\x00" * extent.block_size).digest()
                assert extent.digest_ok is True


def test_legacy_read_contract_is_unchanged_for_normal_and_sparse_blocks() -> None:
    vbk = open_vbk(mixed_file())
    entry = vbk.get("mixed.bin")

    with entry.open() as fh:
        assert fh.read(BLOCK_SIZE) == b"A" * BLOCK_SIZE
        assert fh.read(BLOCK_SIZE) == b"\x00" * BLOCK_SIZE
        with pytest.raises(VBKError, match="Unsupported block type"):
            fh.read(BLOCK_SIZE)

    # The legacy path still reports unsupported blocks instead of inventing content;
    # it does not use inspect()'s opt-in partial export.
    assert entry.is_internal_file()
    with pytest.raises(VBKError):
        entry.open().read()


def test_inspect_is_available_on_the_vbk_root_path() -> None:
    vbk = open_vbk(mixed_file())
    by_path = vbk.inspect("mixed.bin")
    by_item = vbk.get("mixed.bin").inspect()

    assert by_path.as_dict(include_extents=False) == by_item.as_dict(include_extents=False)


def test_unreadable_fib_vector_is_reported_as_a_gap() -> None:
    data = b"V" * BLOCK_SIZE
    spec = FileSpec(
        name="vector.bin",
        blocks=[FibBlock(type=NORMAL, data=data, block_id=0, block_size=BLOCK_SIZE)],
        storage=[StoredBlock(data=data)],
    )
    vbk = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec]))
    entry = vbk.get("vector.bin")
    # Point the FIB block vector at a page that was never populated.
    entry.entry.Data = c_vbk.IntFibHeader(
        BlocksVector=c_vbk.BlocksVectorHeader(RootPage=0xFFFF, Count=1),
        FibSize=BLOCK_SIZE,
        Size=0xFFFFFFFFFFFFFFFF,
    ).dumps()
    entry.__dict__.pop("size", None)

    report = entry.inspect()

    assert report.status is ReportStatus.UNRECOVERABLE
    assert report.gaps[0].status is ContentStatus.MISSING_DATA
    assert report.gaps[0].logical_length == BLOCK_SIZE
    assert "block vector" in report.issues[0]


def test_inspecting_a_directory_is_rejected() -> None:
    vbk = open_vbk(mixed_file())

    with pytest.raises(IsADirectoryError):
        vbk.inspect("/")


def test_sparse_descriptor_with_nonzero_content_is_not_claimed_as_zeros() -> None:
    # A sparse declaration whose digest does not match a zero block is a descriptor
    # contradiction: it cannot be exported as confidently sparse zeros.
    not_zero = b"Z" * BLOCK_SIZE
    spec = FileSpec(
        name="contradiction.bin",
        blocks=[FibBlock(type=SPARSE, digest=hashlib.md5(not_zero).digest(), block_size=BLOCK_SIZE)],
    )
    report = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec])).inspect("contradiction.bin")

    assert report.gaps[0].status is ContentStatus.CORRUPT
    assert not report.complete


def test_plain_block_with_wrong_compressed_size_is_a_gap() -> None:
    data = b"N" * BLOCK_SIZE
    spec = FileSpec(
        name="sizefield.bin",
        blocks=[FibBlock(type=NORMAL, data=data, block_id=0, block_size=BLOCK_SIZE)],
        storage=[StoredBlock(data=data, compressed_size=BLOCK_SIZE // 2)],
    )
    report = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec])).inspect("sizefield.bin")

    assert report.gaps[0].status is ContentStatus.CORRUPT
    assert "plain block stores" in report.gaps[0].detail


def test_read_stored_returns_raw_bytes_and_read_source_the_verified_data() -> None:
    vbk = open_vbk(mixed_file())
    report = vbk.inspect("mixed.bin")
    first = report.extents[0]

    raw = first.read_stored(vbk)
    assert raw[:4] == b"\x0f\x00\x00\xf8"
    assert first.read_source() == b"A" * BLOCK_SIZE

    with pytest.raises(ValueError, match="not readable data"):
        report.extents[2].read_source()
    with pytest.raises(ValueError, match="no stored range"):
        report.extents[2].read_stored(vbk)


def test_export_refuses_content_that_changed_after_inspection() -> None:
    # A file change between inspection and export must not smuggle unverified
    # bytes into a reconstruction: the per-block checks run again.
    data = b"P" * BLOCK_SIZE
    spec = FileSpec(
        name="stable.bin",
        blocks=[FibBlock(type=NORMAL, data=data, block_id=0, block_size=BLOCK_SIZE)],
        storage=[StoredBlock(data=data)],
    )
    vbk = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec]))
    report = vbk.inspect("stable.bin")

    block = vbk.block_store.get(0)
    vbk.fh.seek(block.offset)
    vbk.fh.write(b"Q" * BLOCK_SIZE)

    with pytest.raises(ContentChangedError, match="digest"):
        report.export()


def test_partial_export_with_gaps_survives_pickle() -> None:
    # Evidence replies are often serialised; a partial export keeps its flags and
    # gap descriptors without dragging a live VBK stream along.
    report = open_vbk(mixed_file()).inspect("mixed.bin")
    recovered = report.export(allow_incomplete=True)

    restored = pickle.loads(pickle.dumps(recovered))
    assert restored.complete is False
    assert len(restored) == len(recovered)
    assert [gap.status for gap in restored.gaps] == [gap.status for gap in recovered.gaps]
    assert restored.gaps[0].start == recovered.gaps[0].start


def test_inspection_keeps_descriptors_not_block_content() -> None:
    # Large files must not be held in memory after inspection; export re-reads.
    data = b"R" * BLOCK_SIZE
    spec = FileSpec(
        name="stream.bin",
        blocks=[FibBlock(type=NORMAL, data=data, block_id=0, block_size=BLOCK_SIZE)],
        storage=[StoredBlock(data=data)],
    )
    report = open_vbk(VBKBuilder(block_size=BLOCK_SIZE).build([spec])).inspect("stream.bin")

    assert not hasattr(report.extents[0], "_data")
    assert report.extents[0].storage_offset is not None
    assert report.export() == data
