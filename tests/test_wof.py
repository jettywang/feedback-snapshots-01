from __future__ import annotations

import io
import struct
from typing import BinaryIO

import pytest

from dissect.ntfs.c_ntfs import (
    ATTRIBUTE_TYPE_CODE,
    FILE_RECORD_SEGMENT_IN_USE,
    IO_REPARSE_TAG,
    WOF_CHUNK_SIZE,
    WOF_COMPRESSED_DATA_HEADER_SIZE,
    WOF_COMPRESSED_DATA_SIGNATURE,
    WOF_PROVIDER_CLOUD,
    WOF_PROVIDER_FILE,
    WOF_PROVIDER_WIM,
    c_ntfs,
)
from dissect.ntfs.exceptions import (
    BrokenWofDataError,
    UnsupportedWofAlgorithmError,
    UnsupportedWofProviderError,
    WofError,
)
from dissect.ntfs.mft import MftRecord
from tests._helpers.xpress_encoder import compress as xpress_compress

CLUSTER_SIZE = 4096
SECTOR_SIZE = 512
RECORD_SIZE = 1024
VOLUME_CLUSTERS = 256


def _build_boot_sector() -> bytes:
    boot = bytearray(SECTOR_SIZE)
    boot[0:3] = b"\xeb\x52\x90"
    boot[3:11] = b"NTFS    "
    struct.pack_into("<H", boot, 0x0B, SECTOR_SIZE)
    boot[0x0D] = CLUSTER_SIZE // SECTOR_SIZE  # sectors per cluster
    struct.pack_into("<Q", boot, 0x28, VOLUME_CLUSTERS)
    struct.pack_into("<Q", boot, 0x30, 0x40)  # $MFT start LCN
    boot[0x40] = 0xF6  # signed -10: 2^10 = 1024 byte MFT records
    boot[510:512] = b"\x55\xaa"
    return bytes(boot)


def _resident_attribute(type_code: int, value: bytes, name: str = "", instance: int = 0) -> bytes:
    name_bytes = name.encode("utf-16-le")
    # Resident header is 24 bytes; value follows the optional name and is 8-byte aligned
    value_offset = (24 + len(name_bytes) + 7) & ~7
    record_length = (value_offset + len(value) + 7) & ~7

    header = bytearray(24)
    struct.pack_into("<I", header, 0x00, type_code)
    struct.pack_into("<I", header, 0x04, record_length)
    header[0x08] = 0  # FormCode: resident
    header[0x09] = len(name_bytes) // 2
    struct.pack_into("<H", header, 0x0A, 0x18 if name_bytes else 0)  # NameOffset
    struct.pack_into("<H", header, 0x0C, 0)  # Flags
    struct.pack_into("<H", header, 0x0E, instance)
    struct.pack_into("<I", header, 0x10, len(value))  # ValueLength
    struct.pack_into("<H", header, 0x14, value_offset)  # ValueOffset

    body = bytearray(record_length)
    body[0:24] = header
    body[24 : 24 + len(name_bytes)] = name_bytes
    body[value_offset : value_offset + len(value)] = value
    return bytes(body)


def _nonresident_data_attribute(
    payload: bytes,
    logical_file_size: int,
    run_lcn: int,
    instance: int = 0,
) -> bytes:
    run_clusters = (len(payload) + CLUSTER_SIZE - 1) // CLUSTER_SIZE
    # Single datarun: header byte (offset_len, size_len), one-byte cluster count, 3-byte LCN
    run = bytes([0x31]) + bytes([run_clusters]) + struct.pack("<Q", run_lcn)[:3]
    mapping_offset = 64
    record_length = (mapping_offset + len(run) + 1 + 7) & ~7  # +1 for the terminating zero

    header = bytearray(mapping_offset)
    struct.pack_into("<I", header, 0x00, ATTRIBUTE_TYPE_CODE.DATA)
    struct.pack_into("<I", header, 0x04, record_length)
    header[0x08] = 1  # FormCode: non-resident
    header[0x09] = 0  # NameLength
    struct.pack_into("<H", header, 0x0A, 0)  # NameOffset
    struct.pack_into("<H", header, 0x0C, 0)  # Flags
    struct.pack_into("<H", header, 0x0E, instance)
    struct.pack_into("<Q", header, 0x10, 0)  # LowestVcn
    struct.pack_into("<Q", header, 0x18, 0)  # HighestVcn
    struct.pack_into("<H", header, 0x20, mapping_offset)  # MappingPairsOffset
    header[0x22] = 0  # CompressionUnit
    header[0x23:0x28] = b"\x00" * 5  # Reserved
    allocated = run_clusters * CLUSTER_SIZE
    struct.pack_into("<Q", header, 0x28, allocated)  # AllocatedLength
    struct.pack_into("<Q", header, 0x30, logical_file_size)  # FileSize
    struct.pack_into("<Q", header, 0x38, logical_file_size)  # ValidDataLength
    # TotalAllocated would start at 0x40, which is exactly MappingPairsOffset, so it is omitted

    body = bytearray(record_length)
    body[0:mapping_offset] = header
    body[mapping_offset : mapping_offset + len(run)] = run
    body[mapping_offset + len(run)] = 0  # mapping pairs terminator
    return bytes(body)


def _reparse_attribute(version: int, provider: int, instance: int = 0) -> bytes:
    buffer = struct.pack("<II", version, provider)
    data_buffer = c_ntfs._REPARSE_DATA_BUFFER(
        ReparseTag=IO_REPARSE_TAG.WOF, ReparseDataLength=len(buffer), Reserved=0
    ).dumps()
    return _resident_attribute(
        ATTRIBUTE_TYPE_CODE.REPARSE_POINT, data_buffer + buffer, instance=instance
    )


def _build_wof_record(
    wof_stream: bytes,
    logical_size: int,
    provider: int = WOF_PROVIDER_FILE,
    version: int = 1,
    data_lcn: int = 0x100,
) -> bytes:
    reparse = _reparse_attribute(version, provider)
    data_attr = _nonresident_data_attribute(wof_stream, len(wof_stream), data_lcn)

    # Minimal $STANDARD_INFORMATION (resident, no special flags needed)
    si = _resident_attribute(
        ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION,
        b"\x00" * len(c_ntfs._STANDARD_INFORMATION),
        instance=0,
    )

    attrs = si + reparse + data_attr
    end_marker = struct.pack("<I", ATTRIBUTE_TYPE_CODE.END)

    first_attr_offset = 0x38
    bytes_in_use = first_attr_offset + len(attrs) + len(end_marker)
    assert bytes_in_use <= RECORD_SIZE

    record = bytearray(RECORD_SIZE)
    record[0:4] = b"FILE"
    # Update sequence array at 0x30: the sequence number itself is the sample matched at every sector end
    struct.pack_into("<HH", record, 4, 0x30, 3)  # offset and size (number + two sector entries)
    record[0x30:0x32] = b"\xaa\x55"
    struct.pack_into("<Q", record, 8, 0)  # LSN
    struct.pack_into("<HH", record, 0x10, 1, 1)  # sequence number, reference count
    struct.pack_into("<HH", record, 0x14, first_attr_offset, FILE_RECORD_SEGMENT_IN_USE)
    struct.pack_into("<II", record, 0x18, bytes_in_use, RECORD_SIZE)
    record[0x20:0x28] = b"\x00" * 8  # base record reference
    struct.pack_into("<H", record, 0x28, 0)  # next attribute instance

    record[first_attr_offset : first_attr_offset + len(attrs)] = attrs
    record[first_attr_offset + len(attrs) : first_attr_offset + len(attrs) + 4] = end_marker

    # Apply NTFS fixup: snapshot the original end-of-sector bytes and replace them with the sequence sample
    update_offset = 0x30
    first_end = SECTOR_SIZE - 2
    second_end = 2 * SECTOR_SIZE - 2
    record[update_offset + 2 : update_offset + 4] = bytes(record[first_end : first_end + 2])
    record[update_offset + 4 : update_offset + 6] = bytes(record[second_end : second_end + 2])
    record[first_end : first_end + 2] = b"\xaa\x55"
    record[second_end : second_end + 2] = b"\xaa\x55"
    return bytes(record)


def _build_volume(wof_stream: bytes, logical_size: int, **kwargs) -> tuple[BinaryIO, MftRecord]:
    volume = bytearray(VOLUME_CLUSTERS * CLUSTER_SIZE)
    boot = _build_boot_sector()
    volume[0 : len(boot)] = boot

    data_lcn = 0x80
    data_start = data_lcn * CLUSTER_SIZE
    volume[data_start : data_start + len(wof_stream)] = wof_stream

    mft_record = _build_wof_record(wof_stream, logical_size, data_lcn=data_lcn, **kwargs)

    # Keep the MFT as its own contiguous block: segment reads and absolute LCN data reads then use separate
    # file handles, which avoids needing a self-describing $MFT record or any position-remapping view.
    target_segment = 64
    mft_block = bytearray((target_segment + 1) * RECORD_SIZE)
    mft_block[target_segment * RECORD_SIZE : (target_segment + 1) * RECORD_SIZE] = mft_record
    mft_fh = io.BytesIO(bytes(mft_block))
    volume_fh = io.BytesIO(bytes(volume))

    from types import SimpleNamespace

    from dissect.ntfs.mft import Mft

    ntfs_context = SimpleNamespace(
        fh=volume_fh, cluster_size=CLUSTER_SIZE, mft=None, _record_size=RECORD_SIZE
    )
    mft = Mft(mft_fh, ntfs=ntfs_context)
    ntfs_context.mft = mft
    return volume_fh, mft.get(target_segment)


def _build_wof_stream(chunks: list[bytes], algorithm: int) -> bytes:
    block_size = WOF_CHUNK_SIZE[algorithm]
    payloads = [xpress_compress(chunk) for chunk in chunks]
    # A chunk is stored raw only when its compressed form is not smaller than the algorithm's fixed block size.
    # Partial final chunks are smaller than block_size and therefore always keep their compressed form.
    stored = [chunk if len(payload) >= block_size else payload for chunk, payload in zip(chunks, payloads)]

    header = WOF_COMPRESSED_DATA_SIGNATURE + bytes([algorithm, 0, 0, 0])
    table_start = WOF_COMPRESSED_DATA_HEADER_SIZE
    first_offset = table_start + 4 * len(chunks)
    offsets = []
    cursor = first_offset
    for payload in stored:
        offsets.append(cursor)
        cursor += len(payload)

    table = b"".join(struct.pack("<I", offset) for offset in offsets)
    return header + table + b"".join(stored)


def _make_chunks(chunk_size: int, chunk_count: int, last_length: int) -> list[bytes]:
    chunks = []
    for index in range(chunk_count):
        size = chunk_size if index < chunk_count - 1 else last_length
        # Distinct, compressible per-chunk content with a repeating forensic marker
        marker = f"EVIDENCE-CHUNK-{index:04d}-".encode()
        chunks.append((marker * (size // len(marker) + 1))[:size])
    return chunks


@pytest.mark.parametrize(
    ("algorithm", "chunk_size"),
    [
        (0x00, 4096),
        (0x01, 8192),
        (0x02, 16384),
    ],
)
def test_wof_sequential_and_random_reads(algorithm: int, chunk_size: int) -> None:
    chunks = _make_chunks(chunk_size, 4, chunk_size // 3)
    logical = b"".join(chunks)
    wof_stream = _build_wof_stream(chunks, algorithm)

    _, record = _build_volume(wof_stream, len(logical))

    assert record.is_wof_file()
    wof = record.wof()
    assert wof.algorithm == algorithm
    assert wof.provider == WOF_PROVIDER_FILE
    assert wof.version == 1
    assert wof.chunk_size == chunk_size
    assert wof.size == len(logical)

    stream = record.open_wof()
    # Full sequential read
    assert stream.read() == logical

    # Small random reads and cross-chunk slices at several boundaries
    stream.seek(0)
    for offset in (0, 1, chunk_size - 5, chunk_size, chunk_size + 7, 2 * chunk_size - 3, len(logical) - 11):
        for length in (1, 7, chunk_size, chunk_size + 13):
            stream.seek(offset)
            assert stream.read(length) == logical[offset : offset + length]

    # Read across every chunk boundary in one call
    middle = chunk_size - 100
    stream.seek(middle)
    assert stream.read(200) == logical[middle : middle + 200]


@pytest.mark.parametrize(
    "last_length",
    [1, 7, 100, 1023, 4095, 4096],
)
def test_wof_varying_final_block_length(last_length: int) -> None:
    # A fixed 4 KiB compression unit with several final block lengths, including empty-adjacent and full-size ends
    chunks = _make_chunks(4096, 3, last_length)
    logical = b"".join(chunks)
    wof_stream = _build_wof_stream(chunks, 0x00)

    _, record = _build_volume(wof_stream, len(logical))
    wof = record.wof()

    # The derived logical size must follow the actual final block length, not a rounded chunk multiple
    assert wof.size == 2 * 4096 + last_length
    assert record.open_wof().read() == logical

    # Random slice that starts in the penultimate block and ends inside the variable final block
    start = 2 * 4096 - 50
    stream = record.open_wof()
    stream.seek(start)
    assert stream.read(50 + last_length) == logical[start : start + 50 + last_length]


def test_wof_algorithm_3_uses_huffman_decompressor(monkeypatch: pytest.MonkeyPatch) -> None:
    # Algorithm 3 (32 KiB chunks, "LZX" in compact.exe terminology) routes to the XPRESS Huffman decompressor.
    # The decompressor is stubbed because the test helper only encodes plain XPRESS.
    import dissect.ntfs.wof as wof_module

    chunks = _make_chunks(32768, 2, 4096)
    logical = b"".join(chunks)
    wof_stream = _build_wof_stream(chunks, 0x00)
    # Relabel the header byte to claim algorithm 3; the stub ignores the actual payload format
    wof_stream = wof_stream[:4] + bytes([0x03]) + wof_stream[5:]

    seen: list[bytes] = []

    # Map each stored payload back to its logical chunk so the stub is idempotent under repeated reads
    offsets = [struct.unpack_from("<I", wof_stream, 8 + 4 * i)[0] for i in range(2)]
    payloads = [
        wof_stream[offsets[0] : offsets[1]],
        wof_stream[offsets[1] :],
    ]
    payload_to_chunk = dict(zip(payloads, chunks))

    def fake_huffman(payload: bytes) -> bytes:
        seen.append(payload)
        return payload_to_chunk[payload]

    monkeypatch.setitem(wof_module.WOF_DECOMPRESSORS, 0x03, fake_huffman)

    _, record = _build_volume(wof_stream, len(logical))
    wof = record.wof()
    assert wof.algorithm == 0x03
    assert wof.chunk_size == 32768
    assert record.open_wof().read() == logical
    assert seen  # the Huffman decompressor stub was actually invoked


def test_wof_evidence_ranges_and_raw_data_preserved() -> None:
    chunks = _make_chunks(4096, 3, 1234)
    logical = b"".join(chunks)
    wof_stream = _build_wof_stream(chunks, 0x00)
    fh, record = _build_volume(wof_stream, len(logical))

    wof = record.wof()
    ranges = list(wof.evidence_ranges())
    assert len(ranges) == 3
    # Offsets are relative to the raw $DATA attribute and cover the WofCompressedData payload contiguously
    assert ranges[0][1] == WOF_COMPRESSED_DATA_HEADER_SIZE + 4 * 3
    for (logical_offset, _, _), index in zip(ranges, range(3)):
        assert logical_offset == index * 4096
        assert wof.chunk_offset(index) == logical_offset
    # Each compressed range is non-empty and the ranges abut one another up to the end of the stream
    assert all(compressed_length > 0 for _, _, compressed_length in ranges)
    assert ranges[-1][1] + ranges[-1][2] == wof.compressed_size

    # The original raw DATA read is unchanged and returns the compressed WofCompressedData stream
    raw = record.open().read()
    assert raw == wof_stream
    assert raw != logical
    fh.seek(0)
    assert wof.data_attribute.open().read() == wof_stream

    # Reparse information stays available on the entry
    assert wof.reparse_point.tag == IO_REPARSE_TAG.WOF
    assert wof.reparse_point.buffer == struct.pack("<II", 1, WOF_PROVIDER_FILE)


def test_wof_uncompressed_raw_chunks() -> None:
    # Incompressible full chunks are stored raw: their encoded size is >= chunk_size, which is the only shape a
    # raw payload can have on a real WOF volume. The final partial chunk stays compressible.
    import random

    random.seed(7)
    chunks = [
        bytes(random.randrange(256) for _ in range(4096)),
        bytes(random.randrange(256) for _ in range(4096)),
        (b"FINAL-PARTIAL-CHUNK-" * 30)[:507],
    ]
    logical = b"".join(chunks)
    wof_stream = _build_wof_stream(chunks, 0x00)

    # Confirm the two full chunks were indeed stored raw at exactly the chunk size
    offsets = [struct.unpack_from("<I", wof_stream, WOF_COMPRESSED_DATA_HEADER_SIZE + 4 * i)[0] for i in range(3)]
    assert offsets[1] - offsets[0] == 4096
    assert offsets[2] - offsets[1] == 4096

    _, record = _build_volume(wof_stream, len(logical))
    assert record.open_wof().read() == logical


def test_wof_unsupported_provider() -> None:
    wof_stream = _build_wof_stream(_make_chunks(4096, 2, 100), 0x00)
    _, wim_record = _build_volume(wof_stream, 0, provider=WOF_PROVIDER_WIM)
    _, cloud_record = _build_volume(wof_stream, 0, provider=WOF_PROVIDER_CLOUD)

    for record, provider in ((wim_record, WOF_PROVIDER_WIM), (cloud_record, WOF_PROVIDER_CLOUD)):
        assert record.is_wof_file()
        with pytest.raises(UnsupportedWofProviderError) as exc_info:
            record.wof()
        message = str(exc_info.value)
        assert f"{provider:#x}" in message
        assert "FILE provider" in message


def test_wof_unsupported_algorithm() -> None:
    chunks = _make_chunks(4096, 2, 100)
    wof_stream = _build_wof_stream(chunks, 0x00)
    # Corrupt the algorithm byte in the header
    wof_stream = wof_stream[:4] + bytes([0x7F]) + wof_stream[5:]

    _, record = _build_volume(wof_stream, 0)
    with pytest.raises(UnsupportedWofAlgorithmError):
        record.wof()


def test_wof_broken_signature() -> None:
    wof_stream = _build_wof_stream(_make_chunks(4096, 2, 100), 0x00)
    wof_stream = b"NOPE" + wof_stream[4:]

    _, record = _build_volume(wof_stream, 0)
    with pytest.raises(BrokenWofDataError):
        record.wof()


def test_wof_broken_chunk_table() -> None:
    chunks = _make_chunks(4096, 3, 100)
    wof_stream = bytearray(_build_wof_stream(chunks, 0x00))

    # Make the second chunk table entry point backwards, violating the strictly increasing offset invariant
    struct.pack_into("<I", wof_stream, WOF_COMPRESSED_DATA_HEADER_SIZE + 4, WOF_COMPRESSED_DATA_HEADER_SIZE)

    _, record = _build_volume(bytes(wof_stream), 0)
    with pytest.raises(BrokenWofDataError):
        record.wof()


def test_wof_chunk_table_extends_beyond_stream() -> None:
    chunks = _make_chunks(4096, 2, 100)
    wof_stream = bytearray(_build_wof_stream(chunks, 0x00))

    # Point the only payload offset beyond the end of the $DATA stream
    struct.pack_into("<I", wof_stream, WOF_COMPRESSED_DATA_HEADER_SIZE, len(wof_stream) + 100)

    _, record = _build_volume(bytes(wof_stream), 0)
    with pytest.raises(BrokenWofDataError):
        record.wof()


def test_wof_truncated_payload_raises() -> None:
    chunks = _make_chunks(4096, 3, 200)
    logical = b"".join(chunks)
    wof_stream = _build_wof_stream(chunks, 0x00)

    # Keep only a couple of bytes of the final chunk's payload: the fragment cannot be a valid XPRESS stream
    last_chunk_offset = struct.unpack_from(
        "<I", wof_stream, WOF_COMPRESSED_DATA_HEADER_SIZE + 4 * 2
    )[0]
    truncated = wof_stream[: last_chunk_offset + 2]

    _, record = _build_volume(truncated, len(logical))
    # The corruption is detected while parsing the WofCompressedData layout (the logical size requires the final
    # chunk to be decompressed), so opening the entry already raises instead of producing a zero-filled file
    with pytest.raises(BrokenWofDataError):
        record.wof()

    # The same guarantee holds for the convenience entry point
    with pytest.raises(BrokenWofDataError):
        record.open_wof()


def test_wof_corrupt_chunk_raises_instead_of_zeros() -> None:
    chunks = _make_chunks(4096, 3, 200)
    logical = b"".join(chunks)
    wof_stream = bytearray(_build_wof_stream(chunks, 0x00))
    # Overwrite the second chunk's XPRESS flag word and following token with bytes that reference an
    # out-of-range match offset, which the decompressor cannot satisfy
    second_chunk_start = struct.unpack_from(
        "<I", wof_stream, WOF_COMPRESSED_DATA_HEADER_SIZE + 4
    )[0]
    third_chunk_start = struct.unpack_from(
        "<I", wof_stream, WOF_COMPRESSED_DATA_HEADER_SIZE + 8
    )[0]
    # Replace the second chunk's payload with bytes that decode to an empty (zero-length) block
    for index in range(second_chunk_start, third_chunk_start):
        wof_stream[index] = 0xFF

    _, record = _build_volume(bytes(wof_stream), len(logical))
    stream = record.open_wof()

    # Reading the damaged second chunk raises instead of returning a logically sized zero-filled region
    with pytest.raises(BrokenWofDataError):
        stream.read()

    with pytest.raises(BrokenWofDataError):
        stream.seek(4096)
        stream.read(10)


def test_wof_not_a_reparse_point() -> None:
    # A plain record with a non-WOF reparse point must not be accepted as a WofFile
    symlink_buffer = c_ntfs._SYMBOLIC_LINK_REPARSE_BUFFER(
        SubstituteNameOffset=0,
        SubstituteNameLength=0,
        PrintNameOffset=0,
        PrintNameLength=0,
        Flags=c_ntfs.SYMLINK_FLAG.ABSOLUTE,
    ).dumps()
    data_buffer = c_ntfs._REPARSE_DATA_BUFFER(
        ReparseTag=IO_REPARSE_TAG.SYMLINK, ReparseDataLength=len(symlink_buffer), Reserved=0
    ).dumps()
    reparse = _resident_attribute(ATTRIBUTE_TYPE_CODE.REPARSE_POINT, data_buffer + symlink_buffer)
    si = _resident_attribute(ATTRIBUTE_TYPE_CODE.STANDARD_INFORMATION, b"\x00" * len(c_ntfs._STANDARD_INFORMATION))

    raw = bytearray(RECORD_SIZE)
    raw[0:4] = b"FILE"
    struct.pack_into("<HH", raw, 4, 0x30, 3)
    raw[0x30:0x32] = b"\xaa\x55"
    struct.pack_into("<HH", raw, 0x14, 0x38, FILE_RECORD_SEGMENT_IN_USE)
    body = si + reparse + struct.pack("<I", ATTRIBUTE_TYPE_CODE.END)
    raw[0x38 : 0x38 + len(body)] = body
    # fixup
    raw[0x32:0x34] = bytes(raw[510:512])
    raw[0x34:0x36] = bytes(raw[1022:1024])
    raw[510:512] = b"\xaa\x55"
    raw[1022:1024] = b"\xaa\x55"

    plain = MftRecord.from_bytes(bytes(raw))
    assert not plain.is_wof_file()
    assert plain.is_reparse_point()
    with pytest.raises(WofError):
        plain.wof()
