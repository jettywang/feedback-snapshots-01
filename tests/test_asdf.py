from __future__ import annotations

import zlib
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.evidence.asdf.asdf import AsdfSnapshot, RangeStatus
from dissect.evidence.asdf.c_asdf import c_asdf
from dissect.evidence.asdf.stream import CompressedStream, Crc32Stream, HashedStream
from dissect.evidence.exception import InvalidSnapshot

if TYPE_CHECKING:
    from dissect.evidence.asdf.asdf import AsdfStream, AsdfWriter, ReadRange


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


def _range_summary(ranges: list[ReadRange]) -> list[tuple[int, int, RangeStatus]]:
    return [(r.offset, r.length, r.status) for r in ranges]


def test_asdf_read_ranges_holes(asdf_writer: AsdfWriter) -> None:
    # Captured data that looks like SPARSE_BYTES, all-zero captured data, and
    # captured data between a leading and a middle hole.
    asdf_writer.add_bytes(b"\xa5\xdf" * 0x800, idx=0, base=0x2000)
    asdf_writer.add_bytes(b"\x00" * 0x1000, idx=0, base=0x6000)
    asdf_writer.add_bytes(b"\x02" * 0x1000, idx=0, base=0xC000)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert stream.size == 0xD000

    # Leading hole: nothing before the first block is captured
    ranges = stream.read_ranges(0, 0x1000)
    assert _range_summary(ranges) == [(0, 0x1000, RangeStatus.UNCAPTURED)]
    assert ranges[0].data is None
    assert ranges[0].source is None
    assert ranges[0].file_offset is None

    # Reading from the middle of the leading hole
    ranges = stream.read_ranges(0x800, 0x1000)
    assert _range_summary(ranges) == [(0x800, 0x1000, RangeStatus.UNCAPTURED)]

    # Real captured data equal to the placeholder pattern is still captured
    ranges = stream.read_ranges(0x2000, 0x1000)
    assert _range_summary(ranges) == [(0x2000, 0x1000, RangeStatus.CAPTURED)]
    assert ranges[0].data == b"\xa5\xdf" * 0x800
    assert ranges[0].source is not None
    assert ranges[0].source.idx == 0
    assert ranges[0].source.offset == 0x2000
    assert ranges[0].source.size == 0x1000

    # Captured all-zero data is still captured
    ranges = stream.read_ranges(0x6000, 0x1000)
    assert _range_summary(ranges) == [(0x6000, 0x1000, RangeStatus.CAPTURED)]
    assert ranges[0].data == b"\x00" * 0x1000

    # Middle hole between blocks
    ranges = stream.read_ranges(0x3400, 0x800)
    assert _range_summary(ranges) == [(0x3400, 0x800, RangeStatus.UNCAPTURED)]


def test_asdf_read_ranges_cross_block(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 0x1000, idx=0, base=0x1000)
    asdf_writer.add_bytes(b"\x02" * 0x1000, idx=0, base=0x6000)
    asdf_writer.add_bytes(b"\x03" * 0x1000, idx=0, base=0xB000)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    # A single contiguous read across captured block and following hole
    ranges = stream.read_ranges(0x1800, 0x1000)
    assert _range_summary(ranges) == [
        (0x1800, 0x800, RangeStatus.CAPTURED),
        (0x2000, 0x800, RangeStatus.UNCAPTURED),
    ]
    assert ranges[0].data == b"\x01" * 0x800
    assert ranges[0].source is not None
    assert ranges[0].source.file_offset is not None
    assert ranges[1].data is None

    # A read spanning captured block, middle hole and next captured block
    ranges = stream.read_ranges(0x1800, 0x5000)
    assert [(r.offset, r.length, r.status) for r in ranges] == [
        (0x1800, 0x800, RangeStatus.CAPTURED),
        (0x2000, 0x4000, RangeStatus.UNCAPTURED),
        (0x6000, 0x800, RangeStatus.CAPTURED),
    ]
    assert ranges[0].data == b"\x01" * 0x800
    assert ranges[1].data is None
    assert ranges[2].data == b"\x02" * 0x800

    # Reading up to end of stream
    ranges = stream.read_ranges(0xB800)
    assert _range_summary(ranges) == [
        (0xB800, 0x800, RangeStatus.CAPTURED),
    ]
    assert ranges[0].data == b"\x03" * 0x800


def _corrupt_block_magic(reader: AsdfSnapshot, stream: AsdfStream, table_index: int) -> None:
    file_offset = stream.table[table_index][2]
    _corrupt(reader.fh, file_offset, b"\x00" * 4)


def _corrupt_block_data(reader: AsdfSnapshot, stream: AsdfStream, table_index: int) -> None:
    data_offset = stream.table[table_index][3]
    reader.fh.seek(data_offset)
    current = reader.fh.read(1)
    _corrupt(reader.fh, data_offset, bytes([current[0] ^ 0xFF]))


def _corrupt(fh: BytesIO, offset: int, data: bytes) -> None:
    fh.seek(offset)
    fh.write(data)


def test_asdf_read_ranges_corrupt_block(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 0x1000, idx=0, base=0x1000)
    asdf_writer.add_bytes(b"\x02" * 0x1000, idx=0, base=0x6000)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    # Damage the CRC-protected data of the first block
    _corrupt_block_data(reader, stream, 0)

    ranges = stream.read_ranges(0x1000, 0x6000)
    assert [(r.offset, r.length, r.status) for r in ranges] == [
        (0x1000, 0x1000, RangeStatus.CORRUPTED),
        (0x2000, 0x4000, RangeStatus.UNCAPTURED),
        (0x6000, 0x1000, RangeStatus.CAPTURED),
    ]
    assert ranges[0].data is None
    assert ranges[0].source is None
    assert ranges[0].file_offset is None
    assert ranges[0].error is not None
    assert ranges[2].data == b"\x02" * 0x1000

    # A failure in one block does not prevent other captured blocks from being reported
    ranges = stream.read_ranges(0x1000, 0x1000)
    assert _range_summary(ranges) == [(0x1000, 0x1000, RangeStatus.CORRUPTED)]
    assert ranges[0].data is None
    assert ranges[0].error is not None

    ranges = stream.read_ranges(0x6000, 0x1000)
    assert _range_summary(ranges) == [(0x6000, 0x1000, RangeStatus.CAPTURED)]
    assert ranges[0].data == b"\x02" * 0x1000

    # The convenience read does not verify the CRC and returns the damaged bytes as-is
    stream.seek(0x1000)
    assert stream.read(0x1000) == b"\xfe" + b"\x01" * 0xFFF


def test_asdf_read_ranges_invalid_block_magic(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 0x1000, idx=0, base=0)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    _corrupt_block_magic(reader, stream, 0)

    ranges = stream.read_ranges(0, 0x1000)
    assert _range_summary(ranges) == [(0, 0x1000, RangeStatus.CORRUPTED)]
    assert ranges[0].error is not None


def test_asdf_read_ranges_no_false_captured_from_pattern(asdf_writer: AsdfWriter) -> None:
    # An uncaptured range filled with SPARSE_BYTES by read() must not be classified as captured
    asdf_writer.add_bytes(b"\x01" * 0x1000, idx=0, base=0x1000)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    legacy = stream.read(0x1000)
    assert legacy == b"\xa5\xdf" * 0x800

    ranges = stream.read_ranges(0, 0x1000)
    assert _range_summary(ranges) == [(0, 0x1000, RangeStatus.UNCAPTURED)]
    assert ranges[0].data is None


def test_asdf_read_ranges_compressed(asdf_writer: AsdfWriter) -> None:
    asdf_writer.block_compress = True
    asdf_writer.add_bytes(bytes(range(256)) * 16, idx=0, base=0x1000)
    asdf_writer.add_bytes(b"\xa5\xdf" * 0x800, idx=0, base=0x6000)
    # Leave the metadata stream uncompressed so the snapshot remains openable
    asdf_writer.block_compress = False

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    ranges = stream.read_ranges(0x1000, 0x1000)
    assert _range_summary(ranges) == [(0x1000, 0x1000, RangeStatus.CAPTURED)]
    assert ranges[0].data == bytes(range(256)) * 16
    # Compressed data lives elsewhere in the file, so there is no direct data offset
    assert ranges[0].file_offset is None
    assert ranges[0].source is not None
    assert ranges[0].source.offset == 0x1000

    ranges = stream.read_ranges(0x6000, 0x1000)
    assert _range_summary(ranges) == [(0x6000, 0x1000, RangeStatus.CAPTURED)]
    assert ranges[0].data == b"\xa5\xdf" * 0x800


def test_asdf_read_ranges_idx_isolation(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 0x1000, idx=0, base=0)
    asdf_writer.add_bytes(b"\x02" * 0x1000, idx=1, base=0)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream_0 = reader.open(0)
    stream_1 = reader.open(1)

    ranges_0 = stream_0.read_ranges(0, 0x1000)
    assert _range_summary(ranges_0) == [(0, 0x1000, RangeStatus.CAPTURED)]
    assert ranges_0[0].data == b"\x01" * 0x1000
    assert ranges_0[0].source.idx == 0

    ranges_1 = stream_1.read_ranges(0, 0x1000)
    assert _range_summary(ranges_1) == [(0, 0x1000, RangeStatus.CAPTURED)]
    assert ranges_1[0].data == b"\x02" * 0x1000
    assert ranges_1[0].source.idx == 1


def test_asdf_read_ranges_zero_and_oob(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 0x1000, idx=0, base=0)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    assert stream.read_ranges(0, 0) == []
    assert stream.read_ranges(0x1000, 0x1000) == []
    assert _range_summary(stream.read_ranges(0, 0x2000)) == [(0, 0x1000, RangeStatus.CAPTURED)]

    with pytest.raises(ValueError, match="negative offset"):
        stream.read_ranges(-1, 1)
    with pytest.raises(ValueError, match="negative length"):
        stream.read_ranges(0, -2)

    # -1 means read to the end of the stream, like stream.read()
    ranges = stream.read_ranges(0, -1)
    assert _range_summary(ranges) == [(0, 0x1000, RangeStatus.CAPTURED)]


class _FailingFile:
    """Wrap a file-like object and fail reads that overlap a given range."""

    def __init__(self, fh: BytesIO, fail_offset: int, fail_length: int):
        self.fh = fh
        self.fail_offset = fail_offset
        self.fail_end = fail_offset + fail_length

    def seek(self, pos: int, whence: int = 0) -> int:
        return self.fh.seek(pos, whence)

    def tell(self) -> int:
        return self.fh.tell()

    def read(self, n: int = -1) -> bytes:
        pos = self.fh.tell()
        data = self.fh.read(n)
        if n > 0 and self.fail_offset <= pos < self.fail_end:
            raise OSError("simulated read failure")
        return data


def test_asdf_read_ranges_read_error(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 0x1000, idx=0, base=0x1000)
    asdf_writer.add_bytes(b"\x02" * 0x1000, idx=0, base=0x6000)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)
    second_data_offset = stream.table[1][3]

    failing = _FailingFile(asdf_writer._fh, second_data_offset, 0x1000)
    reader.fh = failing
    stream.fh = failing

    ranges = stream.read_ranges(0x1000, 0x6000)
    assert [(r.offset, r.length, r.status) for r in ranges] == [
        (0x1000, 0x1000, RangeStatus.CAPTURED),
        (0x2000, 0x4000, RangeStatus.UNCAPTURED),
        (0x6000, 0x1000, RangeStatus.CORRUPTED),
    ]
    assert ranges[0].data == b"\x01" * 0x1000
    assert ranges[1].data is None
    assert ranges[2].data is None
    assert "simulated read failure" in ranges[2].error


def test_asdf_snapshot_read_ranges(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x00" * 0x1000, idx=0, base=0x2000)
    asdf_writer.add_bytes(b"\xa5\xdf" * 0x800, idx=0, base=0x8000)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)

    # The snapshot-level wrapper returns the same information as the stream
    ranges = reader.read_ranges(0, 0x1000, 0x8000)
    assert [(r.offset, r.length, r.status) for r in ranges] == [
        (0x1000, 0x1000, RangeStatus.UNCAPTURED),
        (0x2000, 0x1000, RangeStatus.CAPTURED),
        (0x3000, 0x5000, RangeStatus.UNCAPTURED),
        (0x8000, 0x1000, RangeStatus.CAPTURED),
    ]
    assert [r.data for r in ranges] == [None, b"\x00" * 0x1000, None, b"\xa5\xdf" * 0x800]

    with pytest.raises(IndexError, match="invalid stream idx"):
        reader.read_ranges(42)


def _content_hits(ranges: list[ReadRange]) -> list[tuple[int, bytes]]:
    """Emulate a scanner backend that only submits captured ranges to content rules."""
    return [(r.offset, r.data) for r in ranges if r.status is RangeStatus.CAPTURED]


def test_asdf_scanner_gets_only_captured(asdf_writer: AsdfWriter) -> None:
    # Head hole (0x0000-0x1FFF), captured block at 0x2000 with zero content,
    # captured block at 0x4000 that equals the placeholder pattern, middle hole
    # (0x5000-0x7FFF), captured block at 0x8000.
    asdf_writer.add_bytes(b"\x00" * 0x1000, idx=0, base=0x2000)
    asdf_writer.add_bytes(b"\xa5\xdf" * 0x800, idx=0, base=0x4000)
    asdf_writer.add_bytes(b"\x03" * 0x1000, idx=0, base=0x8000)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    hits = _content_hits(stream.read_ranges(0, stream.size))
    assert hits == [
        (0x2000, b"\x00" * 0x1000),
        (0x4000, b"\xa5\xdf" * 0x800),
        (0x8000, b"\x03" * 0x1000),
    ]

    # The placeholder pattern appears in the legacy read for the head and middle
    # holes, but it is not submitted as acquired content.
    legacy = reader.read_ranges(0, 0, stream.size)
    stream.seek(0)
    legacy_bytes = stream.read()
    assert legacy_bytes[:0x1000] == b"\xa5\xdf" * 0x800
    assert legacy_bytes[0x5000:0x8000] == b"\xa5\xdf" * (0x3000 // 2)
    assert _range_summary(legacy)[0] == (0, 0x2000, RangeStatus.UNCAPTURED)
    assert _range_summary(legacy)[-2] == (0x5000, 0x3000, RangeStatus.UNCAPTURED)


def test_asdf_read_ranges_corrupted_placeholder_value(asdf_writer: AsdfWriter) -> None:
    # A captured block that contains only the placeholder pattern is still captured,
    # but if its checksum is damaged it must be reported as corrupted, not captured
    # and not uncaptured. The classification never depends on the byte values.
    asdf_writer.add_bytes(b"\xa5\xdf" * 0x800, idx=0, base=0x3000)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    ranges = stream.read_ranges(0x3000, 0x1000)
    assert _range_summary(ranges) == [(0x3000, 0x1000, RangeStatus.CAPTURED)]
    assert ranges[0].data == b"\xa5\xdf" * 0x800

    # Damage the trailing CRC32 of the block, so the values still look like the
    # placeholder pattern, yet the block is corrupt
    _corrupt(reader.fh, stream.table[0][2] + len(c_asdf.block) + 0x1000, b"\x00\x00\x00\x00")

    ranges = stream.read_ranges(0x3000, 0x1000)
    assert _range_summary(ranges) == [(0x3000, 0x1000, RangeStatus.CORRUPTED)]
    assert ranges[0].data is None
    assert ranges[0].error is not None


def test_asdf_read_ranges_overlap(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 100, base=0)
    asdf_writer.add_bytes(b"\x02" * 100, base=200)
    asdf_writer.add_bytes(b"\x03" * 100, base=50)
    asdf_writer.add_bytes(b"\x04" * 150, base=100)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)

    # The trimmed block table entries must still resolve to the correct file data
    ranges = stream.read_ranges(0, stream.size)
    assert [r.data for r in ranges] == [
        b"\x01" * 100,
        b"\x03" * 50,
        b"\x04" * 50,
        b"\x02" * 100,
    ]
    assert [(r.offset, r.length) for r in ranges] == [(0, 100), (100, 50), (150, 50), (200, 100)]


def test_asdf_read_ranges_does_not_move_position(asdf_writer: AsdfWriter) -> None:
    asdf_writer.add_bytes(b"\x01" * 0x1000, idx=0, base=0)
    asdf_writer.add_bytes(b"\x02" * 0x1000, idx=0, base=0x2000)

    asdf_writer.close()
    asdf_writer._fh.seek(0)

    reader = AsdfSnapshot(asdf_writer._fh)
    stream = reader.open(0)
    stream.seek(0x3000)

    assert _range_summary(stream.read_ranges(0x2000, 0x1000)) == [(0x2000, 0x1000, RangeStatus.CAPTURED)]
    assert stream.tell() == 0x3000
