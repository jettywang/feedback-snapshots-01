from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

from dissect.clfs.c_clfs import SECTOR_SIZE, BlockHeader, c_clfs
from dissect.clfs.exceptions import InvalidChainStartError

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping
    from typing import BinaryIO

    from dissect.clfs.blf import Stream

# Terminating LSN values as defined by CLFS (clfslsn.h / clfs.h).
# These are reserved sentinels, not references to records, and always end a chain cleanly.
CLFS_LSN_NULL = 0x0000000000000000
CLFS_LSN_RESERVED = 0xFFFFFFFFFFFFFFFF


def lsn_container_id(lsn: int) -> int:
    """Return the container (log segment) identifier encoded in the high 32 bits of an LSN."""
    return (lsn >> 32) & 0xFFFFFFFF


class ChainKind(enum.Enum):
    """The two explicit LSN chains stored in every record header.

    Both chains are kept separately. Records that are physically adjacent in the container file
    are NOT implied to be steps of the same transaction; only the explicit references stored in
    the record headers themselves are followed.
    """

    PREVIOUS = "previous"
    UNDO_NEXT = "undo_next"


class TerminationReason(enum.Enum):
    """Reason a chain walk stopped.

    NULL_LSN and RESERVED_LSN are clean ends of a chain. Every other reason is a breakpoint:
    the walk returns the confirmed portion up to that point and does not guess beyond it.
    """

    NULL_LSN = "null_lsn"
    RESERVED_LSN = "reserved_lsn"
    OUT_OF_RANGE = "out_of_range"
    CROSS_CONTAINER = "cross_container"
    MISSING_TARGET = "missing_target"
    IDENTITY_MISMATCH = "identity_mismatch"
    LOOP = "loop"


@dataclass(frozen=True)
class RecordNode:
    """A single scanned record with the raw header values preserved as evidence."""

    lsn: int
    offset: int
    lsn_previous: int
    lsn_undo_next: int
    record_type: int
    record_flags: int
    data_size: int
    is_compensation: bool = False
    data: bytes = field(default=b"", repr=False)

    @property
    def is_restart(self) -> bool:
        """Whether this record is a restart record."""
        return bool(self.record_type & int(c_clfs.RecordType.ClfsRestartRecord))

    @property
    def is_data(self) -> bool:
        """Whether this record carries client data."""
        return bool(self.record_type & int(c_clfs.RecordType.ClfsDataRecord))


@dataclass(frozen=True)
class ChainEdge:
    """One resolved reference between two records.

    Carries the raw reference exactly as stored in the source record header, plus the
    resolved target record as evidence. Edges are only created for resolved targets;
    an unresolvable reference becomes the termination of the walk instead.
    """

    source_lsn: int
    raw_reference: int
    target: RecordNode


@dataclass(frozen=True)
class ChainTermination:
    """Why a chain walk stopped.

    Holds the source record and the raw reference that could not (or cleanly) be followed,
    so the breakpoint itself is preserved as evidence.
    """

    reason: TerminationReason
    source_lsn: int
    raw_reference: int
    detail: str


@dataclass(frozen=True)
class ChainResult:
    """Result of walking one explicit LSN chain.

    ``nodes`` is the confirmed portion of the chain in walk order. ``termination`` describes
    how the walk ended. No committed/undone transaction state is inferred: records that cannot
    be related through explicit references are simply not part of any chain.
    """

    kind: ChainKind
    start_lsn: int
    nodes: tuple[RecordNode, ...]
    edges: tuple[ChainEdge, ...]
    termination: ChainTermination

    @property
    def complete(self) -> bool:
        """Whether the chain ended on a clean terminating LSN instead of a breakpoint."""
        return self.termination.reason in (TerminationReason.NULL_LSN, TerminationReason.RESERVED_LSN)

    @property
    def lsns(self) -> list[int]:
        """Return the LSNs of the confirmed portion in walk order."""
        return [node.lsn for node in self.nodes]


RECORD_HEADER_SIZE = 0x28
# Known RecordType flag bits (ClfsNullRecord .. ClfsLastRecord).
_KNOWN_RECORD_TYPE_MASK = 0x3F
# Sanity bounds for plausible log blocks during a scan.
_MAX_BLOCK_SECTORS = 64


def _parse_block_records(
    log_block: BlockHeader, block_offset: int, is_compensation: Callable[[object, bytes], bool] | None
) -> Iterator[RecordNode]:
    """Yield the records of one log block, following both the record offset table and
    the contiguous record layout (each record's DataSize leads to the next record).
    """
    buf = log_block.open()
    block_size = len(log_block.data)
    starts = sorted({offset for offset in log_block.header.RecordOffsets if offset})

    for start in starts:
        record_offset = start
        while RECORD_HEADER_SIZE <= record_offset <= block_size - RECORD_HEADER_SIZE:
            buf.seek(record_offset)
            try:
                header = c_clfs.RECORD_HEADER(buf)
            except EOFError:
                break

            data_size = int(header.DataSize)
            if (
                data_size < RECORD_HEADER_SIZE
                or data_size > block_size
                or int(header.Type) & ~_KNOWN_RECORD_TYPE_MASK
                or int(header.Type) == 0
            ):
                break

            data = buf.read(data_size - RECORD_HEADER_SIZE)

            yield RecordNode(
                lsn=int(header.LsnVirtual),
                offset=block_offset + record_offset,
                lsn_previous=int(header.LsnPrevious),
                lsn_undo_next=int(header.LsnUndoNext),
                record_type=int(header.Type),
                record_flags=int(header.RecordFlags),
                data_size=data_size,
                is_compensation=bool(is_compensation(header, data)) if is_compensation else False,
                data=data,
            )

            record_offset += data_size


def scan_records(
    fh: BinaryIO,
    offset: int = 0,
    is_compensation: Callable[[object, bytes], bool] | None = None,
) -> dict[int, RecordNode]:
    """Scan a container file and index every plausible record header by its virtual LSN.

    Blocks in a container are not necessarily contiguous, so the file is probed at sector
    granularity from ``offset`` onwards. A candidate block is only accepted when its block
    header and first record header pass plausibility checks; every accepted record is kept
    as evidence with its raw header values. The scan is read-only; no rollback or any other
    write operation is ever performed.

    Compensation records are a client-level concept, so callers can supply ``is_compensation``
    to classify records from their header and data. The first record found for an LSN wins;
    later duplicates are kept out of the index.

    Args:
        fh: A file-like object to a container file.
        offset: Offset to start scanning from.
        is_compensation: Optional classifier called with (record header, record data).

    Returns:
        A mapping of virtual LSN to :class:`RecordNode`.
    """
    records: dict[int, RecordNode] = {}

    fh.seek(0, 2)
    size = fh.tell()

    block_offset = offset
    while block_offset + SECTOR_SIZE <= size:
        try:
            log_block = BlockHeader(fh=fh, offset=block_offset)
        except (EOFError, ValueError, AttributeError):
            block_offset += SECTOR_SIZE
            continue

        total_sectors = log_block.header.TotalSectors
        record_offsets = [offset for offset in log_block.header.RecordOffsets if offset]
        block_size = total_sectors * SECTOR_SIZE
        if (
            not 1 <= total_sectors <= _MAX_BLOCK_SECTORS
            or not record_offsets
            or not all(RECORD_HEADER_SIZE <= offset <= block_size - RECORD_HEADER_SIZE for offset in record_offsets)
        ):
            block_offset += SECTOR_SIZE
            continue

        for node in _parse_block_records(log_block, block_offset, is_compensation):
            records.setdefault(node.lsn, node)

        block_offset += SECTOR_SIZE

    return records


class ChainWalker:
    """Walk the explicit previous-LSN and undo-next-LSN chains of scanned container records.

    The walker is bound to a caller-specified stream by means of the valid log range
    (``lsn_base`` .. ``lsn_last``) and the container (log segment) the records were scanned
    from. Chain entries outside that stream or range are rejected. The walker never mutates
    anything; in particular it performs no rollback.

    Args:
        records: Mapping of LSN to :class:`RecordNode`, e.g. from :func:`scan_records`.
        lsn_base: First LSN of the valid log range of the stream.
        lsn_last: Last LSN of the valid log range of the stream.
        container_id: Container (log segment) identifier the records belong to.
            Derived from ``lsn_base`` when not given.
    """

    def __init__(
        self,
        records: Mapping[int, RecordNode],
        lsn_base: int,
        lsn_last: int,
        container_id: int | None = None,
    ):
        self.records = dict(records)
        self.lsn_base = lsn_base
        self.lsn_last = lsn_last
        self.container_id = container_id if container_id is not None else lsn_container_id(lsn_base)

    @classmethod
    def for_stream(cls, records: Mapping[int, RecordNode], stream: Stream) -> ChainWalker:
        """Create a walker bound to the valid log range of the given stream."""

        def _lsn_value(value: object) -> int:
            # Real streams carry CLFS_LSN unions; tests may use plain integers.
            return int(getattr(value, "PhysicalOffset", value))

        return cls(records, lsn_base=_lsn_value(stream.lsn_base), lsn_last=_lsn_value(stream.lsn_last))

    def _check_entry(self, lsn: int) -> None:
        if lsn in (CLFS_LSN_NULL, CLFS_LSN_RESERVED):
            raise InvalidChainStartError(f"Chain entry {lsn:#x} is a reserved terminating LSN, not a record")
        if lsn_container_id(lsn) != self.container_id:
            raise InvalidChainStartError(
                f"Chain entry {lsn:#x} belongs to container {lsn_container_id(lsn)}, not {self.container_id}"
            )
        if not self.lsn_base <= lsn <= self.lsn_last:
            raise InvalidChainStartError(
                f"Chain entry {lsn:#x} is outside the valid log range {self.lsn_base:#x}..{self.lsn_last:#x}"
            )
        if lsn not in self.records:
            raise InvalidChainStartError(f"Chain entry {lsn:#x} has no record in the scanned container")

    def walk(self, start_lsn: int, kind: ChainKind) -> ChainResult:
        """Walk one explicit chain from ``start_lsn``.

        Loop detection is scoped to this single walk: a record shared between the previous
        chain and the undo-next chain (or between two separate walks) is not a loop. Only
        genuinely revisiting a record within the same walk terminates with
        :attr:`TerminationReason.LOOP`.

        Returns:
            ChainResult with the confirmed portion of the chain and the termination evidence.
        """
        self._check_entry(start_lsn)

        nodes: list[RecordNode] = []
        edges: list[ChainEdge] = []
        visited: set[int] = set()

        current = self.records[start_lsn]
        while True:
            nodes.append(current)
            visited.add(current.lsn)

            raw = current.lsn_previous if kind is ChainKind.PREVIOUS else current.lsn_undo_next

            if raw == CLFS_LSN_NULL:
                termination = ChainTermination(
                    TerminationReason.NULL_LSN, current.lsn, raw, "Reached the null terminating LSN"
                )
                break
            if raw == CLFS_LSN_RESERVED:
                termination = ChainTermination(
                    TerminationReason.RESERVED_LSN, current.lsn, raw, "Reached the reserved terminating LSN"
                )
                break
            if lsn_container_id(raw) != self.container_id:
                termination = ChainTermination(
                    TerminationReason.CROSS_CONTAINER,
                    current.lsn,
                    raw,
                    f"Reference points to container {lsn_container_id(raw)}, outside container {self.container_id}",
                )
                break
            if not self.lsn_base <= raw <= self.lsn_last:
                termination = ChainTermination(
                    TerminationReason.OUT_OF_RANGE,
                    current.lsn,
                    raw,
                    f"Reference is outside the valid log range {self.lsn_base:#x}..{self.lsn_last:#x}",
                )
                break

            target = self.records.get(raw)
            if target is None:
                termination = ChainTermination(
                    TerminationReason.MISSING_TARGET,
                    current.lsn,
                    raw,
                    "Referenced record is not present in the scanned container",
                )
                break
            if target.lsn != raw:
                termination = ChainTermination(
                    TerminationReason.IDENTITY_MISMATCH,
                    current.lsn,
                    raw,
                    f"Record found for reference identifies itself as {target.lsn:#x}",
                )
                break

            edges.append(ChainEdge(source_lsn=current.lsn, raw_reference=raw, target=target))

            if target.lsn in visited:
                nodes.append(target)
                termination = ChainTermination(
                    TerminationReason.LOOP,
                    current.lsn,
                    raw,
                    f"Reference closes a genuine loop back to {target.lsn:#x}",
                )
                break

            current = target

        return ChainResult(
            kind=kind,
            start_lsn=start_lsn,
            nodes=tuple(nodes),
            edges=tuple(edges),
            termination=termination,
        )
