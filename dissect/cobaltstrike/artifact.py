"""
This module is responsible for dumping payloads from `ArtifactKit`_ generated executables.

.. _ArtifactKit: https://www.cobaltstrike.com/blog/what-is-a-stageless-payload-artifact/
"""

from __future__ import annotations

import contextlib
import enum
import io
import logging
import sys
from typing import BinaryIO, Iterator, Optional

from dissect.cobaltstrike import utils

logger = logging.getLogger(__name__)

#: Size in bytes of the ArtifactKit metadata header that precedes the payload:
#: 4-byte self pointer + 4-byte size + 4-byte xor key + 8-byte loader hints.
HEADER_SIZE = 20
#: Size in bytes of the little-endian self pointer that opens an ArtifactKit header.
POINTER_SIZE = 4
#: Default chunk size used while scanning a file for ArtifactKit candidates.
DEFAULT_SCAN_CHUNK_SIZE = 1 << 16
#: Overlap carried between scan chunks: the final ``POINTER_SIZE`` bytes of a
#: chunk are re-examined together with the next chunk so a pointer that starts
#: in the last bytes of one chunk and completes in the next is still observed.
#: Repeated offsets are suppressed with an explicit scan boundary below, so the
#: overlap never produces duplicate candidates.
SCAN_OVERLAP = POINTER_SIZE


class ArtifactKitCandidateKind(enum.Enum):
    """Classification of an ArtifactKit scan candidate.

    A candidate is only ever *evidence*: the loader ``hints`` and the decoded
    bytes are recorded for further analysis, but never executed, and the hints
    alone are not sufficient to conclude that a candidate is a Beacon.
    """

    SELF_POINTER = "self_pointer"
    """Only the 4-byte self pointer matched: the header is (partly) missing or no payload is declared."""

    TRUNCATED = "truncated"
    """A full header was found and payload bytes are present, but fewer than the declared ``size``."""

    COMPLETE = "complete"
    """A full header was found and exactly ``size`` payload bytes could be read."""


class ArtifactKitPayload(io.BytesIO):
    """Decoded ArtifactKit payload with its metadata.

    The :attr:`kind` attribute distinguishes three situations that the previous
    scanner collapsed together:

    - :attr:`ArtifactKitCandidateKind.COMPLETE` candidates carry the full
      declared payload in :attr:`payload`.
    - :attr:`ArtifactKitCandidateKind.TRUNCATED` candidates carry the bytes
      that were actually available (possibly none); :attr:`declared_size` is
      then larger than ``len(payload)``.
    - :attr:`ArtifactKitCandidateKind.SELF_POINTER` candidates are bare
      self-pointer hits without a full header or declared payload.

    Decoded content is stored for inspection only and is never executed.
    """

    def __init__(
        self,
        offset: int,
        size: int,
        xorkey: bytes,
        hints: bytes,
        payload: bytes,
        kind: ArtifactKitCandidateKind = ArtifactKitCandidateKind.COMPLETE,
        declared_size: Optional[int] = None,
    ):
        super().__init__(payload)
        self.offset = offset
        """Offset of the ArtifactKit metadata in the file"""
        self.size = size
        """Size of the payload bytes that were actually read and decoded"""
        self.declared_size = self.size if declared_size is None else declared_size
        """Payload size declared in the header, which may exceed the available bytes when truncated"""
        self.xorkey = xorkey
        """4-byte random xor mask (empty for bare self-pointer hits)"""
        self.hints = hints
        """Loader hints (GetModuleHandleA, GetProcAddress); evidence only, never executed"""
        self.payload = payload
        """Decoded ArtifactKit payload bytes that were actually available"""
        self.kind = kind
        """Classification of this candidate, see :class:`ArtifactKitCandidateKind`"""
        self.fh = io.BytesIO(payload)

    @property
    def is_complete(self) -> bool:
        """True when the full declared payload was read and decoded."""
        return self.kind is ArtifactKitCandidateKind.COMPLETE

    @property
    def is_truncated(self) -> bool:
        """True when a full header was found but the declared payload runs past the available data."""
        return self.kind is ArtifactKitCandidateKind.TRUNCATED

    @property
    def is_self_pointer_only(self) -> bool:
        """True when only the 4-byte self pointer matched."""
        return self.kind is ArtifactKitCandidateKind.SELF_POINTER

    @classmethod
    def self_pointer(cls, offset: int, header: bytes = b"") -> "ArtifactKitPayload":
        """Create a bare self-pointer candidate at ``offset`` with the (partial) ``header`` observed."""
        return cls(
            offset=offset,
            size=0,
            xorkey=b"",
            hints=b"",
            payload=header,
            kind=ArtifactKitCandidateKind.SELF_POINTER,
            declared_size=0,
        )

    def __repr__(self) -> str:
        return (
            f"<ArtifactKitPayload kind={self.kind.value} offset=0x{self.offset:x} "
            f"size={self.size}/{self.declared_size} xorkey={self.xorkey!r}>"
        )

    def get_name(self) -> str:
        return "ArtifactKitPayload"


def _file_size(fobj: BinaryIO) -> Optional[int]:
    """Return the size of a seekable file-like object, or ``None`` when it is not seekable."""
    try:
        pos = fobj.tell()
        fobj.seek(0, io.SEEK_END)
        size = fobj.tell()
        fobj.seek(pos)
    except (OSError, ValueError):
        return None
    return size


def _read_at_most(fobj: BinaryIO, size: int) -> bytes:
    """Read up to ``size`` bytes from ``fobj`` at its current position, tolerating short reads."""
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = fobj.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _iter_candidate_offsets(
    fobj: BinaryIO,
    start: int,
    scan_end: Optional[int],
    read_end: Optional[int],
    chunk_size: int,
) -> Iterator[int]:
    """Yield every absolute offset whose 4-byte little-endian value equals the offset itself.

    The file is read in bounded chunks of ``chunk_size`` bytes with a
    :data:`SCAN_OVERLAP` byte carry-over, so a self pointer that straddles a
    chunk boundary is still observed. Two distinct boundaries are honoured:

    - ``scan_end``: the highest offset at which a candidate may *start*
      (i.e. ``maxrange``, inclusive);
    - ``read_end``: the highest byte that may be read to materialise a pointer
      (usually the data end). A pointer that starts within ``scan_end`` can
      therefore extend past it without being silently truncated.

    Each offset is yielded exactly once: an explicit ``examined`` boundary
    suppresses windows re-introduced by the carried-over tail, so overlapping
    candidates are never merged, dropped or duplicated.
    """
    window_start = start
    carry = b""
    # Offsets strictly below this boundary have already been inspected in a
    # previous chunk; windows in the carried-over tail are skipped accordingly.
    examined = start
    while True:
        if scan_end is not None and window_start > scan_end:
            break
        fobj.seek(window_start)
        read_size = chunk_size
        if read_end is not None:
            # Include the byte at ``read_end`` itself.
            read_size = min(chunk_size, read_end - window_start + 1)
        block = fobj.read(read_size)
        if not block:
            break

        data = carry + block
        data_base = window_start - len(carry)
        last_start = len(data) - POINTER_SIZE
        for rel in range(last_start + 1):
            offset = data_base + rel
            if offset < examined:
                continue
            if scan_end is not None and offset > scan_end:
                break
            if utils.u32(data[rel : rel + POINTER_SIZE]) == offset:
                yield offset

        if len(block) < read_size:
            # Short read: the underlying data ends here.
            break
        # Everything inside this block (up to its last full pointer window) is
        # now examined; only the tail needs re-scanning for a straddling pointer.
        examined = window_start + len(block) - (POINTER_SIZE - 1)
        carry = data[-SCAN_OVERLAP:] if len(data) >= SCAN_OVERLAP else data
        window_start += len(block)


def _build_candidate(fobj: BinaryIO, offset: int, file_size: Optional[int]) -> ArtifactKitPayload:
    """Read and decode the candidate located at ``offset`` using strictly bounded reads."""
    fobj.seek(offset)
    header = _read_at_most(fobj, HEADER_SIZE)
    if len(header) < HEADER_SIZE:
        # Not enough bytes for a full header (size, xor key, hints); keep the
        # raw observation as a self-pointer-only candidate.
        return ArtifactKitPayload.self_pointer(offset, header=header)

    declared_size = utils.u32(header[4:8])
    xorkey = header[8:12]
    hints = header[12:20]

    # Bound the payload read by what the backing data actually contains.
    # A forged, oversized length can never trigger a read past the data end.
    read_limit = declared_size
    if file_size is not None:
        available = max(0, file_size - (offset + HEADER_SIZE))
        read_limit = min(declared_size, available)

    encoded = _read_at_most(fobj, read_limit) if read_limit else b""
    payload = utils.xor(encoded, xorkey)

    if declared_size == 0:
        # A full header that declares no payload explains nothing beyond the
        # self-pointer match itself.
        return ArtifactKitPayload.self_pointer(offset, header=header)
    if len(encoded) < declared_size:
        kind = ArtifactKitCandidateKind.TRUNCATED
    else:
        kind = ArtifactKitCandidateKind.COMPLETE

    return ArtifactKitPayload(
        offset=offset,
        size=len(payload),
        xorkey=xorkey,
        hints=hints,
        payload=payload,
        kind=kind,
        declared_size=declared_size,
    )


def iter_artifactkit_payloads(
    fobj: BinaryIO,
    start_offset: Optional[int] = 0,
    maxrange: Optional[int] = None,
    chunk_size: int = DEFAULT_SCAN_CHUNK_SIZE,
) -> Iterator[ArtifactKitPayload]:
    """Iterate over found :class:`ArtifactKitPayload` by scanning `fobj` for possible ArtifactKit payloads.

    Side effects: file position due to seeking

    The scan window has an explicit boundary: it covers every offset from
    ``start_offset`` up to and including ``maxrange`` (or the end of the data
    when ``maxrange`` is ``None``). Reads are bounded in two ways:

    - scanning proceeds in fixed ``chunk_size`` chunks with a small overlap so
      a self pointer or header that straddles a chunk boundary is not missed;
    - the payload read for a candidate is capped at the bytes that are actually
      available, so a forged, oversized declared size can never trigger a huge
      read or be reported as a fully extracted payload.

    Every self-pointer match is retained as an explainable candidate, but
    candidates are classified via :class:`ArtifactKitCandidateKind` as
    complete, truncated, or self-pointer-only. The decoded bytes and loader
    hints are recorded for inspection only: nothing is executed, and matching
    hints alone is not treated as proof that the candidate is a Beacon.

    .. note::
        No additional checks are done on the ArtifactKit payloads to ensure that what is found is actually correct.

    Args:
        fobj: file-like object (must support ``seek``/``tell``)
        start_offset: starting offset to search for ArtifactKit payloads,
          if `None` it will search from current offset. (default: 0)
        maxrange: highest file offset that a candidate may start at,
          if `None` it will search the entire file (default: `None`)
        chunk_size: size in bytes of each scan chunk (default: 64 KiB)

    Yields:
        :class:`ArtifactKitPayload`
    """
    if start_offset is not None:
        fobj.seek(start_offset)
    start = fobj.tell()
    if chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")

    file_size = _file_size(fobj)
    # ``read_end`` bounds the bytes that may physically be read (data end),
    # while ``scan_end`` (maxrange) only bounds where a candidate may start.
    read_end = None if file_size is None else file_size - 1
    if maxrange is None:
        scan_end = read_end
    elif read_end is None:
        # Non-seekable-to-EOF streams: maxrange is the only available boundary.
        scan_end = maxrange
    else:
        # ``maxrange`` is inclusive; a value past the data collapses to the data end.
        scan_end = min(maxrange, read_end)

    if scan_end is not None and start > scan_end:
        return

    for offset in _iter_candidate_offsets(fobj, start, scan_end, read_end, chunk_size):
        candidate = _build_candidate(fobj, offset, file_size)
        logger.debug("ArtifactKit candidate at 0x%x: %r", offset, candidate)
        yield candidate


@utils.catch_sigpipe
def main():
    """Entrypoint for :doc:`/tools/beacon-artifact`"""

    import argparse

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("input", metavar="FILE", help="FILE to decode")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="verbosity level (-v for INFO, -vv for DEBUG)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=argparse.FileType("wb"),
        default="-",
        help="write decoded ArtifactKit payload to FILE",
    )
    args = parser.parse_args()

    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(len(levels) - 1, args.verbose)]
    logging.basicConfig(level=level)

    if args.input in ("-", "/dev/stdin"):
        finput = io.BytesIO(sys.stdin.buffer.read())
    else:
        finput = open(args.input, "rb")

    foutput = args.output.buffer if hasattr(args.output, "buffer") else args.output

    with contextlib.closing(finput):
        dumped = False
        saw_candidate = False
        for artifact in iter_artifactkit_payloads(finput):
            saw_candidate = True
            logger.info("FOUND possible ArtifactKit offset: %s", artifact.offset)
            logger.info("  - kind: %s", artifact.kind.value)
            logger.info("  - size: %s (declared: %s)", artifact.size, artifact.declared_size)
            logger.info("  - 4-byte xorkey: %r", artifact.xorkey)
            logger.info("  - hints: %r", artifact.hints)
            logger.info("  - payload (preview): %r", artifact.payload[:20])
            if artifact.is_truncated:
                logger.info(
                    "  - truncated: declared %s bytes but only %s are available",
                    artifact.declared_size,
                    artifact.size,
                )
            if artifact.is_self_pointer_only:
                logger.info("  - self-pointer hit only, no payload declared or available")
            # Only dump candidates that actually carry payload bytes; bare
            # self-pointer hits and empty declarations are reported, not dumped.
            if not dumped and artifact.size > 0:
                foutput.write(artifact.payload)
                dumped = True

    if not saw_candidate:
        return f"{args.input}: No ArtifactKit payload found"
    if not dumped:
        return f"{args.input}: ArtifactKit candidates found but none carried a payload"

    return 0


if __name__ == "__main__":
    sys.exit(main())
