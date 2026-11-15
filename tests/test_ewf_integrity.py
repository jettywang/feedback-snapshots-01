from __future__ import annotations

from io import BytesIO

import pytest

from dissect.evidence.ewf import EWF, EWFError
from tests._tools.ewf.builder import ChunkSpec, adler32, build_ewf


def _open(image: bytes) -> EWF:
    return EWF(BytesIO(image))


def _patch(image: bytes, offset: int, data: bytes) -> bytes:
    buf = bytearray(image)
    buf[offset : offset + len(data)] = data
    return bytes(buf)


def test_normal_uncompressed_chunks() -> None:
    image = build_ewf(
        [
            ChunkSpec(b"A" * 64),
            ChunkSpec(b"B" * 64),
            ChunkSpec(b"C" * 22),
        ]
    )

    assert image.chunk_ranges == [(0x103, 0x147), (0x147, 0x18B), (0x18B, 0x1A5)]

    e = _open(image.data)
    assert e.chunk_size == 64
    assert e.size == 64 + 64 + 22

    assert e.read_chunk(0) == b"A" * 64
    assert e.read_chunk(1) == b"B" * 64
    assert e.read_chunk(2) == b"C" * 22

    stream = e.open()
    assert stream.read() == b"A" * 64 + b"B" * 64 + b"C" * 22
    assert stream.read() == b""


def test_normal_compressed_chunks() -> None:
    image = build_ewf(
        [
            ChunkSpec(b"A" * 64, compressed=True),
            ChunkSpec(b"B" * 64, compressed=True),
            ChunkSpec(b"C" * 22),
        ]
    )

    e = _open(image.data)
    assert e.read_chunk(0) == b"A" * 64
    assert e.read_chunk(1) == b"B" * 64
    assert e.read_chunk(2) == b"C" * 22

    # Compressed sizes are smaller than the chunk size, and ranges come from the builder
    assert image.chunk_ranges[0][1] - image.chunk_ranges[0][0] < 64


def test_last_chunk_in_table_section() -> None:
    image = build_ewf(
        [
            ChunkSpec(b"A" * 64),
            ChunkSpec(b"B" * 30, in_table=True),
        ]
    )

    # Last chunk starts after the table metadata and inside the table section
    start, end = image.chunk_ranges[-1]
    assert start > image.table_offset
    assert start + 30 + 4 == end
    assert end == image.table_offset + image.table_size

    e = _open(image.data)
    assert e.size == 64 + 30
    assert e.read_chunk(0) == b"A" * 64
    assert e.read_chunk(1) == b"B" * 30
    assert e.open().read() == b"A" * 64 + b"B" * 30


def test_last_chunk_in_table_compressed() -> None:
    image = build_ewf(
        [
            ChunkSpec(b"A" * 64, compressed=True),
            ChunkSpec(b"B" * 30, in_table=True, compressed=True),
        ]
    )

    e = _open(image.data)
    assert e.read_chunk(0) == b"A" * 64
    assert e.read_chunk(1) == b"B" * 30


@pytest.mark.parametrize("index", [0, 1])
def test_uncompressed_bad_checksum_rejected(index: int) -> None:
    image = build_ewf(
        [
            ChunkSpec(b"A" * 64),
            ChunkSpec(b"B" * 64),
            ChunkSpec(b"C" * 22),
        ]
    )

    # Flip the stored checksum, not the data, so only the checksum is wrong
    start, end = image.chunk_ranges[index]
    # Independently confirm the original trailing checksum before tampering with it
    assert int.from_bytes(image.data[end - 4 : end], "little") == adler32(image.data[start : end - 4])
    tampered = _patch(image.data, end - 4, b"\x00\x00\x00\x00")

    e = _open(tampered)
    with pytest.raises(EWFError, match="Checksum mismatch"):
        e.read_chunk(index)

    # The normal stream must not return the damaged chunk as valid disk content
    stream = e.open()
    stream.seek(index * image.chunk_size)
    with pytest.raises(EWFError, match="Checksum mismatch"):
        stream.read(image.chunk_size)


def test_uncompressed_bad_checksum_last_chunk_rejected_at_open() -> None:
    image = build_ewf(
        [
            ChunkSpec(b"A" * 64),
            ChunkSpec(b"B" * 22),
        ]
    )

    start, end = image.chunk_ranges[-1]
    tampered = _patch(image.data, end - 4, b"\x00\x00\x00\x00")

    # The last chunk is read during open to calculate the logical size
    with pytest.raises(EWFError, match="Checksum mismatch"):
        _open(tampered)


def test_truncated_zlib_stream_rejected() -> None:
    data = b"A" * 64
    original = build_ewf([ChunkSpec(data, compressed=True)])
    start, end = original.chunk_ranges[0]
    stored = original.data[start:end]

    # Drop the zlib trailer so the stream ends prematurely but still produces data
    image = build_ewf([ChunkSpec(data, compressed=True, stored_stream=stored[:-4])])

    # The last chunk is read at open time
    with pytest.raises(EWFError, match="Truncated zlib stream"):
        _open(image.data)


def test_truncated_zlib_stream_middle_chunk_rejected() -> None:
    first = build_ewf(
        [
            ChunkSpec(b"B" * 64, compressed=True),
            ChunkSpec(b"C" * 22),
        ]
    )
    stored = first.data[first.chunk_ranges[0][0] : first.chunk_ranges[0][1]]

    image = build_ewf(
        [
            ChunkSpec(b"A" * 64, compressed=True, stored_stream=stored[:-4]),
            ChunkSpec(b"B" * 64, compressed=True),
            ChunkSpec(b"C" * 22),
        ]
    )

    e = _open(image.data)
    with pytest.raises(EWFError, match="Truncated zlib stream"):
        e.read_chunk(0)

    with pytest.raises(EWFError, match="Truncated zlib stream"):
        e.open().read()


def test_compressed_trailing_data_rejected() -> None:
    import zlib

    valid = build_ewf([ChunkSpec(b"A" * 64, compressed=True)])
    start, end = valid.chunk_ranges[0]
    stored = valid.data[start:end]
    stream = zlib.decompress(stored)

    # The stored range has one valid stream plus extra bytes inside the same physical range
    image = build_ewf([ChunkSpec(b"A" * 64, compressed=True, stored_stream=stored + b"JUNK")])

    assert image.chunk_ranges[0] == (start, end + 4)
    assert zlib.decompress(stored) == stream

    with pytest.raises(EWFError, match="trailing data"):
        _open(image.data)


def test_compressed_trailing_zlib_stream_rejected() -> None:
    import zlib

    valid = build_ewf([ChunkSpec(b"A" * 64, compressed=True)])
    start, end = valid.chunk_ranges[0]
    stored = valid.data[start:end]

    image = build_ewf([ChunkSpec(b"A" * 64, compressed=True, stored_stream=stored + zlib.compress(b"extra"))])

    with pytest.raises(EWFError, match="trailing data"):
        _open(image.data)


def test_compressed_wrong_length_rejected() -> None:
    import zlib

    # A complete, valid zlib stream that decompresses to the wrong length
    image = build_ewf(
        [
            ChunkSpec(b"A" * 64, compressed=True, stored_stream=zlib.compress(b"A" * 63)),
            ChunkSpec(b"B" * 64, compressed=True),
        ]
    )

    e = _open(image.data)
    with pytest.raises(EWFError, match="decompressed to 63 bytes, expected 64"):
        e.read_chunk(0)


def test_compressed_expands_past_chunk_size_rejected() -> None:
    import zlib

    oversized = zlib.compress(b"A" * 65)

    image = build_ewf(
        [
            ChunkSpec(b"A" * 64, compressed=True, stored_stream=oversized),
            ChunkSpec(b"B" * 64, compressed=True),
        ]
    )

    # Independently show the stream itself is valid zlib with a 65 byte payload
    probe = zlib.decompressobj()
    assert probe.decompress(oversized) + probe.flush() == b"A" * 65
    assert probe.eof

    e = _open(image.data)
    with pytest.raises(EWFError, match="decompresses beyond the expected size|decompressed to 65 bytes"):
        e.read_chunk(0)


def test_uncompressed_wrong_length_rejected() -> None:
    short_data = b"A" * 63
    checksum = adler32(short_data).to_bytes(4, "little")

    # A self-consistent shorter chunk: checksum matches, but it is not a full chunk
    image = build_ewf(
        [
            ChunkSpec(b"A" * 64, stored_stream=short_data + checksum),
            ChunkSpec(b"B" * 64),
        ]
    )

    e = _open(image.data)
    with pytest.raises(EWFError, match="has size 63, expected 64"):
        e.read_chunk(0)


def test_adjacent_offsets_going_backwards_rejected() -> None:
    image = build_ewf(
        [
            ChunkSpec(b"A" * 64),
            ChunkSpec(b"B" * 64),
            ChunkSpec(b"C" * 22),
        ]
    )

    table = image.table_offset + 76 + 24  # section descriptor + table header
    # Entries: [first, second, third]; set second entry to the first entry's offset
    first_entry = int.from_bytes(image.data[table : table + 4], "little")
    tampered = _patch(image.data, table + 4, first_entry.to_bytes(4, "little"))
    # Fix the table's trailing checksum so the table itself remains structurally coherent
    entries = tampered[table : table + 12]
    tampered = tampered[: table + 12] + adler32(entries).to_bytes(4, "little") + tampered[table + 16 :]

    e = _open(tampered)
    with pytest.raises(EWFError, match="Invalid chunk offsets"):
        e.read_chunk(0)


def test_last_chunk_inside_table_metadata_rejected() -> None:
    image = build_ewf(
        [
            ChunkSpec(b"A" * 64),
            ChunkSpec(b"B" * 22),
        ]
    )

    # Point the last chunk at the table descriptor, which must not be interpreted as sector data.
    # The last chunk is validated when opening the container.
    table = image.table_offset + 76 + 24
    descriptor_offset = image.table_offset - image.sectors_offset
    tampered = _patch(image.data, table + 4, descriptor_offset.to_bytes(4, "little"))
    entries = tampered[table : table + 8]
    tampered = tampered[: table + 8] + adler32(entries).to_bytes(4, "little") + tampered[table + 12 :]

    with pytest.raises(EWFError, match="overlaps table section metadata|Invalid chunk offsets"):
        _open(tampered)


def test_physical_range_exceeds_segment_rejected() -> None:
    image = build_ewf(
        [
            ChunkSpec(b"A" * 64),
            ChunkSpec(b"B" * 64),
        ]
    )

    table = image.table_offset + 76 + 24
    # Point the last chunk far past the end of the file; it is validated when opening
    tampered = _patch(image.data, table + 4, (0xFFFFFFF).to_bytes(4, "little"))
    entries = tampered[table : table + 8]
    tampered = tampered[: table + 8] + adler32(entries).to_bytes(4, "little") + tampered[table + 12 :]

    with pytest.raises(EWFError, match="exceeds segment size"):
        _open(tampered)


def test_stream_length_and_eof_preserved() -> None:
    image = build_ewf(
        [
            ChunkSpec(b"A" * 64),
            ChunkSpec(b"B" * 64),
            ChunkSpec(b"C" * 22),
        ]
    )
    e = _open(image.data)

    stream = e.open()
    assert stream.size == 150

    assert stream.read(1) == b"A"
    assert stream.read(63) == b"A" * 63
    assert stream.read(64) == b"B" * 64
    assert stream.read(22) == b"C" * 22
    # EOF behaviour unchanged: no zero padding
    assert stream.read(1) == b""
    assert stream.read() == b""


def test_compressed_truncated_at_open_rejected() -> None:
    valid = build_ewf([ChunkSpec(b"A" * 64, compressed=True)])
    start, end = valid.chunk_ranges[0]
    stored = valid.data[start:end]

    image = build_ewf([ChunkSpec(b"A" * 64, compressed=True, stored_stream=stored[:-2])])

    # The last chunk is read during open to determine the logical size
    with pytest.raises(EWFError, match="Truncated zlib stream"):
        _open(image.data)


def test_integrity_failure_is_not_zero_filled() -> None:
    image = build_ewf(
        [
            ChunkSpec(b"A" * 64),
            ChunkSpec(b"B" * 64),
            ChunkSpec(b"C" * 22),
        ]
    )

    # Flip a data byte in the middle chunk, keep its checksum stale
    start, _ = image.chunk_ranges[1]
    tampered = _patch(image.data, start, b"\x00")

    e = _open(tampered)
    with pytest.raises(EWFError):
        e.read_chunk(1)

    # Reading around the bad chunk must not silently include zeros or the bad data
    stream = e.open()
    assert stream.read(64) == b"A" * 64
    with pytest.raises(EWFError):
        stream.read(64)
