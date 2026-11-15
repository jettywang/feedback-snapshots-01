"""Recompose collected ASDF data into a new forensic snapshot.

This module provides a restricted, auditable block-level interface for deriving a
new :class:`~dissect.evidence.asdf.asdf.AsdfWriter` snapshot from one or more existing
:class:`~dissect.evidence.asdf.asdf.AsdfSnapshot` containers.

Three distinct integrity values are involved and they never cover the same bytes:

- The **source block checksum** is the CRC32 stored in the source container. It covers
  only the stored data bytes of one source block (the payload between the block header
  and the trailing 4 CRC bytes), as they exist in the source file.
- The **new block checksum** is a freshly computed CRC32 written by the destination
  writer. It covers only the payload bytes of the corresponding block in the new
  container. A source checksum value is never copied into the new container.
- The **logical content hash** is a SHA256 computed by this module over the logical
  stream bytes that were actually copied, in logical offset order. Sparse placeholder
  bytes (``SPARSE_BYTES``) are never read or hashed: only confirmed collected data
  participates.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
from bisect import bisect_right
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, BinaryIO
from zlib import crc32

from dissect.evidence.asdf import asdf
from dissect.evidence.asdf.c_asdf import c_asdf
from dissect.evidence.exception import (
    RecomposeIncomplete,
    SourceBlockCorrupt,
    SourceGapError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from hashlib import _Hash as Hash
    from types import TracebackType

PROVENANCE_MANIFEST = "asdf-recompose/provenance.json"
COPY_CHUNK_SIZE = io.DEFAULT_BUFFER_SIZE


@dataclass(slots=True)
class CopyRequest:
    """A single block-level copy request between two streams.

    Args:
        source: Snapshot to copy from.
        source_idx: Stream index inside the source snapshot.
        target_idx: Stream index inside the destination snapshot.
        offset: Logical byte offset where the range starts.
        size: Requested range size in bytes.
        target_base: Logical destination offset. Defaults to ``offset``.
    """

    source: asdf.AsdfSnapshot
    source_idx: int
    target_idx: int
    offset: int
    size: int
    target_base: int | None = None


@dataclass(slots=True)
class BlockProvenance:
    """Auditable record of one source block that contributed bytes.

    Args:
        source_guid: GUID of the source snapshot.
        source_idx: Stream index inside the source snapshot.
        target_idx: Stream index inside the destination snapshot.
        source_offset: Logical offset of the full block in the source stream.
        source_size: Logical size of the full block in the source stream.
        copy_offset: Logical offset where the copied subrange starts.
        copy_size: Number of logical bytes copied from this block.
        target_offset: Logical offset where the bytes land in the destination stream.
        source_block_crc32: Verified CRC32 of the stored source block payload.
    """

    source_guid: str
    source_idx: int
    target_idx: int
    source_offset: int
    source_size: int
    copy_offset: int
    copy_size: int
    target_offset: int
    source_block_crc32: int


@dataclass(slots=True)
class CopyResult:
    """Result of a copy request, describing what was actually completed.

    Args:
        request: The originating copy request.
        completed: Whether the full requested range was copied and verified.
        copied_offset: Logical offset up to which bytes were copied (exclusive).
        copied_size: Number of logical bytes that were copied.
        block_provenance: Per-source-block provenance records, in copy order.
        content_sha256: SHA256 over the logical bytes that were actually copied.
        failure: Short machine-readable reason when the copy did not complete.
        gap_offset: Logical offset of the first uncollected byte, if a gap was hit.
    """

    request: CopyRequest
    completed: bool
    copied_offset: int
    copied_size: int
    block_provenance: list[BlockProvenance] = field(default_factory=list)
    content_sha256: str | None = None
    failure: str | None = None
    gap_offset: int | None = None

    def as_manifest_entry(self) -> dict[str, object]:
        """Serialize this result into a JSON-serializable provenance entry."""
        request = self.request
        return {
            "completed": self.completed,
            "failure": self.failure,
            "source_guid": str(request.source.guid),
            "source_idx": request.source_idx,
            "target_idx": request.target_idx,
            "requested_offset": request.offset,
            "requested_size": request.size,
            "copied_offset": self.copied_offset,
            "copied_size": self.copied_size,
            "gap_offset": self.gap_offset,
            "content_sha256": self.content_sha256,
            "blocks": [
                {
                    "source_guid": block.source_guid,
                    "source_idx": block.source_idx,
                    "target_idx": block.target_idx,
                    "source_offset": block.source_offset,
                    "source_size": block.source_size,
                    "copy_offset": block.copy_offset,
                    "copy_size": block.copy_size,
                    "target_offset": block.target_offset,
                    "source_block_crc32": f"0x{block.source_block_crc32:08x}",
                }
                for block in self.block_provenance
            ],
        }


def open_snapshot(fh: BinaryIO) -> asdf.AsdfSnapshot:
    """Open an ASDF snapshot, transparently unwrapping whole-file gzip containers.

    The ASDF reader does not detect gzip itself; a compressed snapshot starts with the
    gzip magic rather than the ASDF magic. This helper inspects the first two bytes and
    wraps the file in a :class:`gzip.GzipFile` when needed, without changing how
    uncompressed snapshots are opened.

    Args:
        fh: A seekable file-like object positioned at the start of the snapshot.

    Returns:
        An opened :class:`~dissect.evidence.asdf.asdf.AsdfSnapshot`.
    """
    head = fh.read(2)
    fh.seek(0)
    if head == b"\x1f\x8b":
        fh = gzip.GzipFile(fileobj=fh, mode="rb")
    return asdf.AsdfSnapshot(fh)


def _iter_covering_blocks(stream: asdf.AsdfStream, offset: int, size: int) -> Iterator[tuple[int, int, int, int]]:
    """Yield table entries covering every logical byte of ``[offset, offset + size)``.

    Raises :class:`SourceGapError` at the first logical byte that is not backed by a
    collected block. Placeholder (sparse) regions therefore never reach the copy path.

    Args:
        stream: The source stream to resolve against.
        offset: Start of the requested logical range.
        size: Size of the requested logical range.
    """
    table = stream.table
    lookup = stream._table_lookup

    cursor = offset
    end = offset + size
    while cursor < end:
        run_idx = bisect_right(lookup, cursor) - 1
        if run_idx < 0:
            raise SourceGapError(f"uncollected byte at logical offset {cursor}")

        run_start, run_size, _, _ = table[run_idx]
        run_end = run_start + run_size
        if cursor >= run_end:
            raise SourceGapError(f"uncollected byte at logical offset {cursor}")

        yield table[run_idx]
        cursor = run_end


def _verify_source_block(stream: asdf.AsdfStream, entry: tuple[int, int, int, int]) -> int:
    """Verify a source block against its own stored CRC32 and return that CRC32.

    The CRC32 covers the stored payload bytes only: everything between the block header
    and the trailing 4-byte CRC. A block without a CRC32 flag cannot be validated and is
    rejected rather than trusted.

    Args:
        stream: The source stream owning the block.
        entry: The parsed block table entry ``(run_start, run_size, file_offset, data_offset)``.

    Raises:
        SourceBlockCorrupt: When the block has no CRC32, its magic is bad, or the CRC mismatches.
    """
    run_start, run_size, run_file_offset, run_data_offset = entry
    fh = stream.fh

    fh.seek(run_file_offset)
    block_header = c_asdf.block(fh)
    if block_header.magic != asdf.BLOCK_MAGIC:
        raise SourceBlockCorrupt(f"invalid block magic at file offset {run_file_offset}")
    if not block_header.flags & c_asdf.BLOCK_FLAG.CRC32:
        raise SourceBlockCorrupt(f"source block at logical offset {run_start} has no CRC32 to validate")

    payload_size = run_size
    fh.seek(run_data_offset)
    crc = 0
    remaining = payload_size
    while remaining > 0:
        chunk = fh.read(min(COPY_CHUNK_SIZE, remaining))
        if not chunk:
            raise SourceBlockCorrupt(f"short read while verifying block at logical offset {run_start}")
        crc = crc32(chunk, crc) & 0xFFFFFFFF
        remaining -= len(chunk)

    stored_crc = c_asdf.uint32(fh)
    if crc != stored_crc:
        raise SourceBlockCorrupt(
            f"block at logical offset {run_start} failed CRC32: expected 0x{stored_crc:08x}, got 0x{crc:08x}"
        )
    return crc


class AsdfRecomposer:
    """Build a new ASDF snapshot by copying validated ranges out of existing snapshots.

    The recomposer never trusts source metadata blindly: every source block is checked
    against its own CRC32 before any byte is copied, and only bytes backed by a real
    collected block are eligible. The destination writer computes its own block CRC32
    values and whole-file SHA256, so the new container carries independent integrity
    material rather than reused source values.

    Args:
        writer: The destination :class:`~dissect.evidence.asdf.asdf.AsdfWriter`.
    """

    def __init__(self, writer: asdf.AsdfWriter) -> None:
        self.writer = writer
        self._results: list[CopyResult] = []
        self._closed = False

    def copy_range(
        self,
        source: asdf.AsdfSnapshot,
        offset: int,
        size: int,
        source_idx: int = 0,
        target_idx: int | None = None,
        target_base: int | None = None,
    ) -> CopyResult:
        """Copy one validated logical range from a source snapshot into the new snapshot.

        The call is all-or-nothing at the block level: the requested range must be fully
        covered by collected, CRC-valid source blocks. If a source gap, corrupt block or
        read failure is encountered, nothing is written to the destination for the failed
        portion and the returned :class:`CopyResult` records the real completed prefix.

        Args:
            source: The source snapshot to read from.
            offset: Logical byte offset where the range starts in the source stream.
            size: Number of logical bytes to copy.
            source_idx: Stream index inside the source snapshot.
            target_idx: Stream index inside the destination. Defaults to ``source_idx``.
            target_base: Logical destination offset. Defaults to ``offset``.

        Raises:
            SourceGapError: The requested range includes uncollected (sparse) bytes.
            SourceBlockCorrupt: A covering source block fails its stored CRC32.
            OSError: The source could not be fully read.
        """
        if self._closed:
            raise RecomposeIncomplete("recomposer is already closed")
        if size <= 0:
            raise ValueError("size must be a positive number of bytes")
        if offset < 0:
            raise ValueError("offset must not be negative")
        if target_idx is None:
            target_idx = source_idx
        if target_base is None:
            target_base = offset

        if not source.contains(source_idx):
            raise SourceGapError(f"source snapshot does not contain stream idx {source_idx}")

        request = CopyRequest(source, source_idx, target_idx, offset, size, target_base)
        stream = source.open(source_idx)
        digest = hashlib.sha256()
        provenance: list[BlockProvenance] = []
        staged: list[bytes] = []

        try:
            covering = list(_iter_covering_blocks(stream, offset, size))
        except SourceGapError:
            self._record_incomplete(request, 0, provenance, digest, "source_gap", offset)
            raise

        # Phase 1: resolve coverage, verify every source block against its own CRC32 and
        # stage the bytes in memory. The destination writer is not touched until the whole
        # range is known to be valid collected data, so a failure cannot leave a half-copied
        # range inside the new container.
        cursor = offset
        end = offset + size
        try:
            for entry in covering:
                run_start, run_size, _, run_data_offset = entry
                run_end = run_start + run_size
                block_crc = _verify_source_block(stream, entry)

                part_start = max(cursor, run_start)
                part_end = min(end, run_end)
                part_size = part_end - part_start
                in_block_pos = part_start - run_start

                stream.fh.seek(run_data_offset + in_block_pos)
                remaining = part_size
                while remaining > 0:
                    chunk = stream.fh.read(min(COPY_CHUNK_SIZE, remaining))
                    if not chunk:
                        raise OSError(
                            f"short read from source block at logical offset {run_start}; "
                            f"completed {cursor - offset} of {size} requested bytes"
                        )
                    digest.update(chunk)
                    staged.append(chunk)
                    remaining -= len(chunk)
                    cursor += len(chunk)

                provenance.append(
                    BlockProvenance(
                        source_guid=str(source.guid),
                        source_idx=source_idx,
                        target_idx=target_idx,
                        source_offset=run_start,
                        source_size=run_size,
                        copy_offset=part_start,
                        copy_size=part_size,
                        target_offset=target_base + (part_start - offset),
                        source_block_crc32=block_crc,
                    )
                )
        except SourceBlockCorrupt:
            self._record_incomplete(request, cursor - offset, provenance, digest, "source_block_corrupt", cursor)
            raise
        except OSError:
            self._record_incomplete(request, cursor - offset, provenance, digest, "read_failure", cursor)
            raise

        # Phase 2: the entire requested range is verified. Write it into the destination,
        # which computes brand new block CRC32 values over these bytes.
        payload = b"".join(staged)
        self.writer.add_bytes(payload, idx=target_idx, base=target_base)

        result = CopyResult(
            request=request,
            completed=True,
            copied_offset=end,
            copied_size=size,
            block_provenance=provenance,
            content_sha256=digest.hexdigest(),
        )
        self._results.append(result)
        return result

    def close(self) -> None:
        """Finalize and close the destination snapshot with its provenance manifest.

        The provenance manifest is added to the destination metadata tar before the
        writer is closed, so it is covered by the new container's own block CRC32 values
        and whole-file SHA256.

        Raises:
            RecomposeIncomplete: If any recorded copy did not fully complete.
        """
        if self._closed:
            return

        incomplete = [result for result in self._results if not result.completed]
        if incomplete:
            self._closed = True
            raise RecomposeIncomplete(
                f"refusing to publish derived snapshot: {len(incomplete)} copy operation(s) did not complete"
            )

        manifest = {
            "schema": "asdf-recompose/v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "destination_guid": str(self.writer.guid),
            "copies": [result.as_manifest_entry() for result in self._results],
        }
        manifest_fh = io.BytesIO(json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"))
        self.writer.add_metadata_file(PROVENANCE_MANIFEST, manifest_fh)

        self.writer.close()
        self._closed = True

    def __enter__(self) -> AsdfRecomposer:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._closed:
            return
        if exc_type is not None:
            # A copy already failed; do not mask the original error with a publish failure.
            self._closed = True
            return
        self.close()

    def _record_incomplete(
        self,
        request: CopyRequest,
        copied_size: int,
        provenance: Sequence[BlockProvenance],
        digest: Hash,
        failure: str,
        gap_offset: int,
    ) -> CopyResult:
        result = CopyResult(
            request=request,
            completed=False,
            copied_offset=request.offset + copied_size,
            copied_size=copied_size,
            block_provenance=list(provenance),
            content_sha256=digest.hexdigest() if copied_size else None,
            failure=failure,
            gap_offset=gap_offset,
        )
        self._results.append(result)
        return result


def recompose(
    writer: asdf.AsdfWriter,
    requests: Sequence[CopyRequest],
) -> list[CopyResult]:
    """Run a sequence of copy requests through a recomposer and publish the snapshot.

    This is the convenience wrapper around :class:`AsdfRecomposer`. If every request
    completes, the destination is closed (and its provenance manifest written). Any
    :class:`SourceGapError`, :class:`SourceBlockCorrupt` or read failure aborts the run
    and prevents a complete derived snapshot from being published.

    Args:
        writer: The destination writer.
        requests: Ordered copy requests to perform.

    Returns:
        One :class:`CopyResult` per request, in order.
    """
    with AsdfRecomposer(writer) as recomposer:
        results = []
        for request in requests:
            results.append(
                recomposer.copy_range(
                    request.source,
                    request.offset,
                    request.size,
                    source_idx=request.source_idx,
                    target_idx=request.target_idx,
                    target_base=request.target_base,
                )
            )
        return results
