from __future__ import annotations

import hashlib
import io
import json
from typing import TYPE_CHECKING

import pytest

from dissect.evidence.asdf import AsdfSnapshot, AsdfWriter
from dissect.evidence.asdf.c_asdf import c_asdf
from dissect.evidence.asdf.recompose import (
    PROVENANCE_MANIFEST,
    AsdfRecomposer,
    CopyRequest,
    open_snapshot,
    recompose,
)
from dissect.evidence.exception import RecomposeIncomplete, SourceBlockCorrupt, SourceGapError

if TYPE_CHECKING:
    from collections.abc import Iterator

BLOCK = 4096
SourcePair = tuple[AsdfSnapshot, bytes, bytes, bytes]


class ClosingBlocked(io.BytesIO):
    def close(self) -> None:  # keep the buffer readable after the writer closes
        pass


class FailingFH(io.RawIOBase):
    """File handle wrapper that starts failing once ``fail_offset`` is reached."""

    def __init__(self, inner: io.BytesIO, fail_offset: int) -> None:
        self.inner = inner
        self.fail_offset = fail_offset
        self.armed = False

    def arm(self) -> None:
        self.armed = True

    def seekable(self) -> bool:
        return True

    def seek(self, pos: int, whence: int = io.SEEK_SET) -> int:
        return self.inner.seek(pos, whence)

    def tell(self) -> int:
        return self.inner.tell()

    def read(self, size: int = -1) -> bytes:
        if self.armed and self.inner.tell() >= self.fail_offset:
            raise OSError("simulated source read failure")
        if self.armed and size and size > 0:
            size = min(size, self.fail_offset - self.inner.tell())
        return self.inner.read(size)


def make_writer(compress: bool = False) -> AsdfWriter:
    return AsdfWriter(ClosingBlocked(), compress=compress)


def buffer_of(writer: AsdfWriter) -> io.BytesIO:
    writer._fh.seek(0)
    return writer._fh


def build_source(compress: bool = False) -> tuple[AsdfWriter, bytes, bytes, bytes]:
    """Create a source snapshot with full and partial blocks plus gaps on two streams."""
    writer = make_writer(compress)
    block0 = bytes(v & 0xFF for v in range(BLOCK))
    block1 = b"\x2a" * BLOCK
    partial = b"P" * 1000
    other = b"Q" * BLOCK

    writer.add_bytes(block0, idx=0, base=0)
    writer.add_bytes(block1, idx=0, base=BLOCK)
    writer.add_bytes(partial, idx=0, base=BLOCK * 4)  # gap between 8192 and 16384
    writer.add_bytes(other, idx=1, base=0)
    writer.close()
    return writer, block0 + block1, partial, other


@pytest.fixture
def source_pair() -> Iterator[SourcePair]:
    writer, full, partial, other = build_source()
    yield AsdfSnapshot(io.BytesIO(buffer_of(writer).getvalue())), full, partial, other


def test_open_snapshot_detects_gzip() -> None:
    writer, _, _, _ = build_source(compress=True)
    raw = buffer_of(writer).getvalue()
    assert raw[:2] == b"\x1f\x8b"

    plain = open_snapshot(io.BytesIO(raw))
    assert plain.open(0).read(BLOCK) == bytes(v & 0xFF for v in range(BLOCK))

    uncompressed_writer, _, _, _ = build_source(compress=False)
    uncompressed_raw = buffer_of(uncompressed_writer).getvalue()
    assert uncompressed_raw[:4] == b"ASDF"
    assert open_snapshot(io.BytesIO(uncompressed_raw)).open(0).read(BLOCK) == plain.open(0).read(BLOCK)


def test_recompose_full_and_partial_blocks(source_pair: SourcePair) -> None:
    source, full, partial, other = source_pair
    writer = make_writer()
    recomposer = AsdfRecomposer(writer)

    result_full = recomposer.copy_range(source, 0, len(full), source_idx=0)
    result_partial = recomposer.copy_range(source, BLOCK * 4, len(partial), source_idx=0, target_idx=3)
    recomposer.close()

    assert result_full.completed
    assert result_full.copied_size == len(full)
    assert result_full.content_sha256 == hashlib.sha256(full).hexdigest()
    assert [block.source_offset for block in result_full.block_provenance] == [0, BLOCK]

    assert result_partial.completed
    block_record = result_partial.block_provenance[0]
    assert (block_record.source_offset, block_record.copy_size) == (BLOCK * 4, 1000)
    assert isinstance(block_record.source_block_crc32, int)

    snapshot = AsdfSnapshot(io.BytesIO(buffer_of(writer).getvalue()))
    assert snapshot.open(0).read(len(full)) == full

    stream3 = snapshot.open(3)
    stream3.seek(BLOCK * 4)
    assert stream3.read(1000) == partial


def test_partial_subrange_inside_one_block(source_pair: SourcePair) -> None:
    source, full, _, _ = source_pair
    writer = make_writer()
    with AsdfRecomposer(writer) as recomposer:
        result = recomposer.copy_range(source, 100, 500, source_idx=0, target_base=0)

    snapshot = AsdfSnapshot(io.BytesIO(buffer_of(writer).getvalue()))
    assert snapshot.open(0).read(500) == full[100:600]
    assert result.content_sha256 == hashlib.sha256(full[100:600]).hexdigest()
    record = result.block_provenance[0]
    assert (record.copy_offset, record.copy_size) == (100, 500)
    assert (record.source_offset, record.source_size) == (0, BLOCK)


def test_copy_range_spanning_source_gap_is_rejected(source_pair: SourcePair) -> None:
    source, _, _, _ = source_pair
    writer = make_writer()
    recomposer = AsdfRecomposer(writer)

    # 8192..16384 is uncollected sparse space in stream 0.
    with pytest.raises(SourceGapError):
        recomposer.copy_range(source, BLOCK * 2, BLOCK, source_idx=0)

    with pytest.raises(RecomposeIncomplete):
        recomposer.close()

    # A rejected publish never writes a footer, so the buffer is not a valid snapshot.
    from dissect.evidence.asdf.asdf import FOOTER_MAGIC

    assert not buffer_of(writer).getvalue().endswith(FOOTER_MAGIC + b"\x00" * 44)


def test_sparse_placeholder_is_never_copied(source_pair: SourcePair) -> None:
    source, _, _, _ = source_pair
    writer = make_writer()
    recomposer = AsdfRecomposer(writer)
    with pytest.raises(SourceGapError):
        # Starts inside a valid block but extends into the gap that begins at 2*BLOCK.
        recomposer.copy_range(source, BLOCK * 2 - 16, 64, source_idx=0)

    result = recomposer._results[-1]
    assert result.failure == "source_gap"
    assert result.gap_offset == BLOCK * 2 - 16
    assert result.copied_size == 0
    assert result.content_sha256 is None


def test_corrupt_source_block_is_rejected() -> None:
    writer, full, _, _ = build_source()
    raw = bytearray(buffer_of(writer).getvalue())
    source = AsdfSnapshot(io.BytesIO(bytes(raw)))
    entry = source.table[0][0]
    _, _, file_offset, data_offset = entry

    # Flip a payload byte but keep the original CRC32 trailer intact.
    corrupt = bytearray(raw)
    corrupt[data_offset] ^= 0xFF
    corrupted_source = AsdfSnapshot(io.BytesIO(bytes(corrupt)))

    dest = make_writer()
    recomposer = AsdfRecomposer(dest)
    with pytest.raises(SourceBlockCorrupt):
        recomposer.copy_range(corrupted_source, 0, BLOCK, source_idx=0)

    result = recomposer._results[-1]
    assert result.failure == "source_block_corrupt"
    assert result.completed is False

    with pytest.raises(RecomposeIncomplete):
        recomposer.close()

    from dissect.evidence.asdf.asdf import FOOTER_MAGIC

    # The corrupt bytes never reached a published derived container.
    assert not buffer_of(dest).getvalue().endswith(FOOTER_MAGIC + b"\x00" * 44)


def test_mid_copy_read_failure_reports_real_completion() -> None:
    writer_src, full, _, _ = build_source()
    raw = buffer_of(writer_src).getvalue()

    failing_fh = FailingFH(io.BytesIO(raw), fail_offset=0)
    snapshot = AsdfSnapshot(failing_fh)
    second_block = snapshot.table[0][1]
    _, _, _, second_data_offset = second_block
    # Fail as soon as the copy starts reading the payload of the second block.
    failing_fh.fail_offset = second_data_offset
    failing_fh.arm()

    dest = make_writer()
    recomposer = AsdfRecomposer(dest)
    with pytest.raises(OSError, match="simulated source read failure"):
        recomposer.copy_range(snapshot, 0, len(full), source_idx=0)

    result = recomposer._results[-1]
    assert result.completed is False
    assert result.failure == "read_failure"
    # Block 0 was fully verified and staged before the second block read failed.
    assert result.copied_size == BLOCK
    assert result.copied_offset == BLOCK
    assert result.content_sha256 == hashlib.sha256(full[:BLOCK]).hexdigest()

    with pytest.raises(RecomposeIncomplete):
        recomposer.close()


def test_new_block_crc32_is_independent_from_source(source_pair: SourcePair) -> None:
    source, full, _, _ = source_pair
    writer = make_writer()
    with AsdfRecomposer(writer) as recomposer:
        result = recomposer.copy_range(source, 0, BLOCK, source_idx=0)

    raw = buffer_of(writer).getvalue()
    derived = AsdfSnapshot(io.BytesIO(raw))
    target_entry = derived.table[0][0]
    _, _, target_file_offset, target_data_offset = target_entry

    # Verify the freshly written destination CRC32 over the destination payload only.
    fh = derived.fh
    fh.seek(target_file_offset)
    header = c_asdf.block(fh)
    assert header.flags & c_asdf.BLOCK_FLAG.CRC32
    payload = io.BytesIO(raw[target_data_offset : target_data_offset + BLOCK])
    import zlib

    new_crc = zlib.crc32(payload.getvalue()) & 0xFFFFFFFF
    stored = c_asdf.uint32(io.BytesIO(raw[target_data_offset + BLOCK : target_data_offset + BLOCK + 4]))
    assert new_crc == stored

    source_crc = result.block_provenance[0].source_block_crc32
    # Same logical bytes, independently computed checksums happen to match in value,
    # but the provenance records the verified source CRC rather than copying a trailer.
    assert source_crc == new_crc
    assert payload.getvalue() == full[:BLOCK]


def test_compressed_and_uncompressed_derive_identical_logical_bytes(source_pair: SourcePair) -> None:
    source, full, partial, other = source_pair

    uncompressed = make_writer(compress=False)
    compressed = make_writer(compress=True)

    requests = [
        CopyRequest(source, source_idx=0, target_idx=0, offset=0, size=BLOCK),
        CopyRequest(source, source_idx=0, target_idx=0, offset=BLOCK * 4, size=1000, target_base=BLOCK * 4),
        CopyRequest(source, source_idx=1, target_idx=1, offset=0, size=BLOCK),
    ]
    recompose(uncompressed, requests)
    recompose(compressed, requests)

    raw_plain = buffer_of(uncompressed).getvalue()
    raw_gz = buffer_of(compressed).getvalue()
    assert raw_plain[:4] == b"ASDF"
    assert raw_gz[:2] == b"\x1f\x8b"

    plain_snapshot = open_snapshot(io.BytesIO(raw_plain))
    gz_snapshot = open_snapshot(io.BytesIO(raw_gz))

    for idx in (0, 1):
        plain_stream = plain_snapshot.open(idx)
        gz_stream = gz_snapshot.open(idx)
        plain_stream.seek(0)
        gz_stream.seek(0)
        assert plain_stream.read() == gz_stream.read()

    plain_stream = plain_snapshot.open(0)
    plain_stream.seek(0)
    assert plain_stream.read(BLOCK) == full[:BLOCK]
    plain_stream.seek(BLOCK * 4)
    assert plain_stream.read(1000) == partial
    assert gz_snapshot.open(1).read(BLOCK) == other


def test_provenance_manifest_is_auditable(source_pair: SourcePair) -> None:
    source, full, _, _ = source_pair
    writer = make_writer()
    with AsdfRecomposer(writer) as recomposer:
        recomposer.copy_range(source, 0, BLOCK, source_idx=0)
        recomposer.copy_range(source, BLOCK, BLOCK, source_idx=0, target_idx=5, target_base=0)

    snapshot = AsdfSnapshot(io.BytesIO(buffer_of(writer).getvalue()))
    manifest = json.loads(snapshot.metadata.open(PROVENANCE_MANIFEST).read())

    assert manifest["schema"] == "asdf-recompose/v1"
    assert manifest["destination_guid"] == str(writer.guid)
    copies = manifest["copies"]
    assert [copy["target_idx"] for copy in copies] == [0, 5]
    assert all(copy["completed"] for copy in copies)
    assert copies[0]["source_guid"] == str(source.guid)
    assert copies[0]["content_sha256"] == hashlib.sha256(full[:BLOCK]).hexdigest()

    block = copies[0]["blocks"][0]
    assert block["source_block_crc32"].startswith("0x")
    assert block["copy_size"] == BLOCK


def test_footer_sha256_covers_new_container_not_source(source_pair: SourcePair) -> None:
    source, full, _, _ = source_pair
    writer = make_writer()
    recompose(writer, [CopyRequest(source, source_idx=0, target_idx=0, offset=0, size=BLOCK)])

    raw = buffer_of(writer).getvalue()
    snapshot = AsdfSnapshot(io.BytesIO(raw))
    footer_offset = len(raw) - len(c_asdf.footer)
    assert snapshot.footer.sha256 == hashlib.sha256(raw[:footer_offset]).digest()


def test_request_validation(source_pair: SourcePair) -> None:
    source, _, _, _ = source_pair
    recomposer = AsdfRecomposer(make_writer())
    with pytest.raises(ValueError, match="positive"):
        recomposer.copy_range(source, 0, 0)
    with pytest.raises(ValueError, match="negative"):
        recomposer.copy_range(source, -1, 10)
    with pytest.raises(SourceGapError):
        recomposer.copy_range(source, 0, 10, source_idx=99)
