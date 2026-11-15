from __future__ import annotations

import zlib
from io import BytesIO

import pytest

from dissect.evidence.asdf.asdf import (
    BLOCK_MAGIC,
    AsdfSnapshot,
    AsdfWriter,
    BlockSource,
    BlockStatus,
)
from dissect.evidence.asdf.c_asdf import c_asdf
from dissect.evidence.asdf.stream import CompressedStream, Crc32Stream, HashedStream
from dissect.evidence.exception import InvalidSnapshot


def test_asdf(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x00" * 0x1000, idx=0, base=0)
    asdf_writer.add_bytes(b"\x02" * 0x1000, idx=0, base=0x4000)
    asdf_writer.add_bytes(b"\x04" * 0x1000, idx=0, base=0x8000)
    asdf_writer.add_bytes(b"\x06" * 0x1000, idx=0, base=0x10000)
    asdf_writer.add_bytes(b"\xff" * 0x1000, idx=0, base=0x14000)

    asdf_writer.add_bytes(b"\x08" * 0x1000, idx=1, base=0x2000)
    asdf_writer.add_bytes(b"\x10" * 0x1000, idx=1, base=0x5000)
    asdf_writer.add_bytes(b"\x12" * 0x1000, idx=1, base=0x8000)
    asdf_writer.add_bytes(b"\x14" * 0x1000, idx=1, base=0xB000)
    asdf_writer.add_bytes(b"\xff" * 0x1000, idx=1, base=0xE000)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream_0 = reader.open(0)
    assert [(run_start, run_size) for run_start, run_size, _, _ in stream_0.table] == [
        (0, 0x1000),
        (0x4000, 0x1000),
        (0x8000, 0x1000),
        (0x10000, 0x1000),
        (0x14000, 0x1000),
    ]

    assert stream_0.read(0x1000) == b"\x00" * 0x1000
    assert stream_0.read(0x1000) == (b"\xa5\xdf" * (0x1000 // 2))
    assert stream_0.read(0x4000) == (b"\xa5\xdf" * (0x2000 // 2)) + (b"\x02" * 0x1000) + (b"\xa5\xdf" * (0x1000 // 2))

    stream_0.seek(0)
    assert stream_0.read() == b"".join(
        [
            (b"\x00" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\x02" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\x04" * 0x1000),
            (b"\xa5\xdf" * (0x7000 // 2)),
            (b"\x06" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\xff" * 0x1000),
        ]
    )

    stream_1 = reader.open(1)
    assert stream_1.read(0x4000) == (b"\xa5\xdf" * (0x2000 // 2)) + (b"\x08" * 0x1000) + (b"\xa5\xdf" * (0x1000 // 2))


def test_asdf_overlap(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 100, base=0)
    asdf_writer.add_bytes(b"\x02" * 100, base=200)
    assert asdf_writer._table_lookup[0] == [0, 200]

    asdf_writer.add_bytes(b"\x03" * 100, base=50)
    assert asdf_writer._table_lookup[0] == [0, 100, 200]

    asdf_writer.add_bytes(b"\x04" * 150, base=100)
    assert asdf_writer._table_lookup[0] == [0, 100, 150, 200]

    asdf_writer.add_bytes(b"\x05" * 50, base=25)
    assert asdf_writer._table_lookup[0] == [0, 100, 150, 200]

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 100),
        (100, 50),
        (150, 50),
        (200, 100),
    ]
    assert stream.read() == (b"\x01" * 100) + (b"\x03" * 50) + (b"\x04" * 50) + (b"\x02" * 100)


def test_asdf_overlap_all(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 100, base=0)
    asdf_writer.add_bytes(b"\x02" * 100, base=200)
    asdf_writer.add_bytes(b"\x03" * 100, base=50)
    asdf_writer.add_bytes(b"\x04" * 150, base=100)
    assert asdf_writer._table_lookup[0] == [0, 100, 150, 200]
    asdf_writer.add_bytes(b"\x06" * 400, base=0)
    assert asdf_writer._table_lookup[0] == [0, 100]

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 100),
        (100, 300),
    ]
    assert stream.read() == (b"\x01" * 100) + (b"\x06" * 300)


def test_asdf_overlap_contiguous(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 100, base=0)
    asdf_writer.add_bytes(b"\x02" * 100, base=100)
    assert asdf_writer._table_lookup[0] == [0, 100]

    asdf_writer.add_bytes(b"\x03" * 75, base=50)
    assert asdf_writer._table_lookup[0] == [0, 100]

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 100),
        (100, 100),
    ]
    assert stream.read() == (b"\x01" * 100) + (b"\x02" * 100)


def test_asdf_overlap_seek(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x00" * 100, base=0)
    asdf_writer.add_bytes(b"\x00" * 100, base=200)
    asdf_writer.add_bytes(bytes(range(200)), base=50)
    assert asdf_writer._table_lookup[0] == [0, 100, 200]

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 100),
        (100, 100),
        (200, 100),
    ]
    assert stream.read() == (b"\x00" * 100) + bytes(range(50, 150)) + (b"\x00" * 100)


def test_asdf_mid_run(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(bytes([v & 0xFF for v in range(4096)]), base=0)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)
    stream.align = 512

    stream.seek(1100)
    assert stream.read(512) == bytes([v & 0xFF for v in range(1100, 1100 + 512)])


def test_asdf_metadata(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_metadata_file("file", BytesIO(b"content"))
    asdf_writer.add_metadata_file("dir/file", BytesIO(b"content here too"))

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)

    assert reader.metadata.names() == ["file", "dir/file"]
    assert reader.metadata.open("file").read() == b"content"
    assert reader.metadata.open("dir/file").read() == b"content here too"

    with pytest.raises(KeyError):
        reader.metadata.open("nonexistent")


def test_asdf_stream_crc32() -> None:
    fh = BytesIO()
    stream = Crc32Stream(fh)
    stream.write(b"srt was here")
    stream.finalize()

    assert fh.getvalue() == b"srt was here\x2f\x0e\x60\xa4"


def test_asdf_stream_compressed() -> None:
    fh = BytesIO()
    stream = CompressedStream(fh)
    stream.write(b"srt was here" * 100)
    stream.finalize()

    assert zlib.decompress(fh.getvalue()) == b"srt was here" * 100


def test_asdf_stream_hashed() -> None:
    fh = BytesIO()
    stream = HashedStream(fh)
    stream.write(b"srt was here")
    assert stream.hexdigest() == "cd7bd850d261f8fa39a41d0963b42dae5f303615db19ac79e5044586d0825b7b"


def test_asdf_stream_combined() -> None:
    fh = BytesIO()
    stream = Crc32Stream(fh)
    stream = CompressedStream(stream)
    stream = HashedStream(stream)

    stream.write(b"srt was here" * 100)
    stream.finalize()

    assert stream.hexdigest() == "ba40ab3ee826d6aa0f085dfccbb72d8feefa72548015c4456c1fd741d0266a94"
    assert fh.getvalue() == bytes.fromhex("789c2b2e2a51284f2c56c8482d4a2d1e658fb247d9a3ec41cc06004445c530665f35fc")


def test_asdf_scrape(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x00" * 0x1000, idx=0, base=0)
    asdf_writer.add_bytes(b"\x02" * 0x1000, idx=0, base=0x4000)
    asdf_writer.add_bytes(b"\x04" * 0x1000, idx=0, base=0x8000)
    asdf_writer.add_bytes(b"\x06" * 0x1000, idx=0, base=0x10000)
    asdf_writer.add_bytes(b"\xff" * 0x1000, idx=0, base=0x14000)

    # Don't close so we don't have a footer and block table
    asdf_writer._fh.seek(0)

    with pytest.raises(InvalidSnapshot):
        AsdfSnapshot(asdf_writer._fh)

    asdf_writer._fh.seek(0)
    reader = AsdfSnapshot(asdf_writer._fh, recover=True)
    stream = reader.open(0)

    assert [(run_start, run_size) for run_start, run_size, _, _ in stream.table] == [
        (0, 0x1000),
        (0x4000, 0x1000),
        (0x8000, 0x1000),
        (0x10000, 0x1000),
        (0x14000, 0x1000),
    ]

    assert stream.read() == b"".join(
        [
            (b"\x00" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\x02" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\x04" * 0x1000),
            (b"\xa5\xdf" * (0x7000 // 2)),
            (b"\x06" * 0x1000),
            (b"\xa5\xdf" * (0x3000 // 2)),
            (b"\xff" * 0x1000),
        ]
    )


def _multi_index_snapshot() -> bytes:
    """Build a closed, valid ASDF snapshot spanning two disks and a metadata stream."""
    fh = BytesIO()
    fh.close = lambda: None
    writer = AsdfWriter(fh)
    writer.add_bytes(b"\x00" * 0x1000, idx=0, base=0)
    writer.add_bytes(b"\x02" * 0x1000, idx=0, base=0x4000)
    writer.add_bytes(b"\x04" * 0x1000, idx=0, base=0x8000)
    writer.add_bytes(b"\x08" * 0x1000, idx=1, base=0x2000)
    writer.add_metadata_file("info", BytesIO(b"forensic metadata"))
    writer.close()
    return fh.getvalue()


def _table_offset(data: bytes) -> int:
    return c_asdf.footer(data[-len(c_asdf.footer) :]).table_offset


def test_asdf_report_valid_footer() -> None:
    data = _multi_index_snapshot()
    reader = AsdfSnapshot(BytesIO(data))

    report = reader.report
    assert report.footer_valid is True
    assert report.recovered is False
    assert report.complete is True
    assert report.source is BlockSource.FOOTER_TABLE
    assert {block.source for block in report.blocks} == {BlockSource.FOOTER_TABLE}
    assert all(block.status is BlockStatus.VERIFIED for block in report.blocks)

    coverage = report.coverage[0]
    assert coverage.extent == (0, 0x9000)
    assert coverage.verified_ranges == [(0, 0x1000), (0x4000, 0x1000), (0x8000, 0x1000)]
    # The holes between captured blocks are reported as sparse gaps, not as lost data.
    assert coverage.sparse_gaps == [(0x1000, 0x3000), (0x5000, 0x3000)]
    assert coverage.partial_ranges == []
    assert coverage.rejected_ranges == []


def test_asdf_recover_without_footer_matches_snapshot() -> None:
    data = _multi_index_snapshot()
    original = AsdfSnapshot(BytesIO(data))
    original_0 = original.open(0).read()
    original_1 = original.open(1).read()

    # Interrupted writer: blocks are present but the block table and footer were never written.
    interrupted = data[: _table_offset(data)]
    reader = AsdfSnapshot(BytesIO(interrupted), recover=True)
    report = reader.report

    assert report.footer_valid is False
    assert report.recovered is True
    # A recovery scan can never claim a complete, proven mirror.
    assert report.complete is False
    assert report.source is BlockSource.RECOVERY_SCAN
    assert {block.source for block in report.blocks} == {BlockSource.RECOVERY_SCAN}
    assert all(block.status is BlockStatus.VERIFIED for block in report.blocks)
    assert all(block.crc_valid is True for block in report.blocks)

    # Recovered bytes must be segment-for-segment identical to the healthy snapshot.
    assert reader.open(0).read() == original_0
    assert reader.open(1).read() == original_1


def test_asdf_recover_rejects_fake_block_header() -> None:
    data = _multi_index_snapshot()
    interrupted = data[: _table_offset(data)]

    # Embed a plausible but bogus block header inside the second block's payload. Its magic bytes
    # are found by the scraper, but it cannot survive checksum / nesting validation.
    fake_header = c_asdf.block(
        magic=BLOCK_MAGIC,
        flags=c_asdf.BLOCK_FLAG.CRC32,
        idx=0,
        offset=999,
        size=1234,
    ).dumps()
    # Second block header starts after the first block (48 header + 4096 payload + 4 CRC).
    embed_pos = 48 + 24 + 4096 + 4 + 24 + 64
    corrupted = interrupted[:embed_pos] + fake_header + interrupted[embed_pos + len(fake_header) :]

    reader = AsdfSnapshot(BytesIO(corrupted), recover=True)
    fake_evidence = [block for block in reader.report.blocks if block.file_offset == embed_pos]

    assert len(fake_evidence) == 1
    assert fake_evidence[0].status is BlockStatus.REJECTED
    assert fake_evidence[0].selected_range is None
    # The fake record must not create a readable stream range.
    assert all(block.selected_range != (999, 1234) for block in reader.report.blocks)

    # The first, untouched block is still fully usable.
    stream = reader.open(0)
    assert stream.read(0x1000) == b"\x00" * 0x1000


def test_asdf_recover_truncated_tail_block() -> None:
    data = _multi_index_snapshot()
    interrupted = data[: _table_offset(data)]
    healthy = AsdfSnapshot(BytesIO(data))

    # The metadata block is the last block on disk. Cut it so the header and a short payload
    # prefix remain, but the rest of the payload and the checksum are gone.
    last_evidence = max(healthy.report.blocks, key=lambda block: block.file_offset)
    cut_pos = last_evidence.file_offset + 24 + 128
    truncated = interrupted[:cut_pos]

    reader = AsdfSnapshot(BytesIO(truncated), recover=True)
    tail = [block for block in reader.report.blocks if block.file_offset == last_evidence.file_offset]
    assert len(tail) == 1
    assert tail[0].status is BlockStatus.PARTIAL
    assert tail[0].readable_size == 128
    assert reader.report.undetermined(last_evidence.idx) == [tail[0].claimed_range]

    # Earlier, fully captured blocks are still byte identical to the healthy snapshot.
    assert reader.open(0).read() == healthy.open(0).read()
    assert reader.open(1).read() == healthy.open(1).read()


def test_asdf_recover_corrupt_tail_checksum_is_rejected() -> None:
    data = _multi_index_snapshot()
    interrupted = bytearray(data[: _table_offset(data)])
    healthy = AsdfSnapshot(BytesIO(data))

    # Flip a payload byte in the last block while keeping its (now wrong) checksum in place. This is
    # data corruption, not truncation, so the block must be rejected rather than marked partial.
    last_evidence = max(healthy.report.blocks, key=lambda block: block.file_offset)
    interrupted[last_evidence.file_offset + 24 + 10] ^= 0xFF

    reader = AsdfSnapshot(BytesIO(interrupted), recover=True)
    tail = [block for block in reader.report.blocks if block.file_offset == last_evidence.file_offset]
    assert tail[0].status is BlockStatus.REJECTED
    assert tail[0].crc_valid is False


def test_asdf_recover_records_overlap_selection() -> None:
    fh = BytesIO()
    fh.close = lambda: None
    writer = AsdfWriter(fh)
    writer.add_bytes(b"\x01" * 100, base=0)
    writer.add_bytes(b"\x02" * 100, base=200)
    writer.add_bytes(b"\x03" * 100, base=50)
    writer.add_bytes(b"\x06" * 400, base=0)

    reader = AsdfSnapshot(BytesIO(fh.getvalue()), recover=True)
    by_claim = {block.claimed_range: block for block in reader.report.blocks}

    # The last block claims (0, 400); overlap resolution keeps only the part not already covered
    # by earlier blocks, shrinking it to (150, 250). The decision is recorded, not hidden.
    assert by_claim[(100, 300)].status is BlockStatus.VERIFIED
    assert by_claim[(100, 300)].selected_range == (150, 250)
    assert by_claim[(0, 100)].selected_range == (0, 100)
    assert by_claim[(100, 50)].selected_range == (100, 50)

    stream = reader.open(0)
    assert stream.read() == (b"\x01" * 100) + (b"\x03" * 50) + (b"\x06" * 250)


def test_asdf_recover_does_not_mutate_source() -> None:
    data = _multi_index_snapshot()
    interrupted = data[: _table_offset(data)]
    original_bytes = bytearray(interrupted)

    reader = AsdfSnapshot(BytesIO(interrupted), recover=True)
    # Reading streams must not rewrite or append a footer to the underlying file.
    for stream in reader.streams():
        stream.read()

    assert bytes(interrupted) == bytes(original_bytes)
