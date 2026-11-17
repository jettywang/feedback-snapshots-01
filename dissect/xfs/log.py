"""Read-only parser for the internal XFS journal (write-ahead log).

The journal is a circular buffer that is overwritten in place. A single logical
record may therefore be split across several physical segments that wrap around
the end of the log, and records belonging to different log generations can be
present at the same time. This module reconstructs that logical ordering from
the record headers (LSN cycle and block) instead of sorting entries by their
physical offset.

Everything here is strictly read-only. Redo payloads are described, never
replayed onto the evidence volume; the regular file accessors in
:mod:`dissect.xfs.xfs` keep reading the original volume unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import RangeStream

from dissect.xfs.c_xfs import c_xfs
from dissect.xfs.exceptions import Error

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.xfs.xfs import XFS

# Basic log blocks are always 512 bytes, independent of the filesystem block size.
LOG_BASIC_BLOCK_SIZE = 512
RECORD_HEADER_SIZE = c_xfs.xlog_rec_header.size
OP_HEADER_SIZE = c_xfs.xlog_op_header.size


@dataclass(frozen=True)
class LogSegment:
    """One contiguous physical piece of a logical log record.

    A record that runs past the end of the log produces two segments: one at the
    tail of the physical buffer and another at the beginning. Both carry the
    record's log generation so they can be told apart from older material.
    """

    offset: int
    size: int
    generation: int

    def __repr__(self) -> str:
        return f"<log segment offset=0x{self.offset:x} size={self.size} generation={self.generation}>"


@dataclass
class LogOperation:
    """A single logged redo item (one ``xlog_op_header`` plus its payload)."""

    tid: int
    operation_type: str
    type_code: int | None
    payload_size: int
    flags: int
    source: LogSegment
    unmount: bool = False

    def __repr__(self) -> str:
        return f"<log operation tid={self.tid} type={self.operation_type} payload={self.payload_size}>"


@dataclass
class LogRecord:
    """A logical log record reconstructed from one or more physical segments."""

    lsn: int
    tid: int
    record_type: str
    record_flags: int
    source: list[LogSegment]
    generation: int
    physical_offset: int
    operations: list[LogOperation] = field(default_factory=list)
    truncated: bool = False
    header_only: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def is_commit(self) -> bool:
        return self.record_flags & c_xfs.XLOG_COMMIT_TRANS != 0

    @property
    def is_continuation(self) -> bool:
        return self.record_flags & c_xfs.XLOG_CONTINUE_TRANS != 0

    @property
    def starts_transaction(self) -> bool:
        return self.record_flags & c_xfs.XLOG_START_TRANS != 0

    def __repr__(self) -> str:
        return f"<log record lsn={format_lsn(self.lsn)} tid={self.tid} type={self.record_type}>"


@dataclass
class TransactionSummary:
    """All log records that belong to a single transaction."""

    tid: int
    start_lsn: int
    last_lsn: int
    records: list[LogRecord] = field(default_factory=list)
    commit_record: LogRecord | None = None
    truncated: bool = False

    @property
    def status(self) -> str:
        if self.commit_record is not None:
            return "committed"
        if self.truncated or any(record.truncated for record in self.records):
            return "truncated"
        return "uncommitted"

    @property
    def operations(self) -> list[LogOperation]:
        operations: list[LogOperation] = []
        for record in self.records:
            operations.extend(record.operations)
        return operations

    @property
    def operation_types(self) -> list[str]:
        seen: list[str] = []
        for operation in self.operations:
            if operation.operation_type not in seen:
                seen.append(operation.operation_type)
        return seen

    def __repr__(self) -> str:
        return f"<transaction tid={self.tid} status={self.status} records={len(self.records)}>"


# Human readable names for the documented 16-bit log item format identifiers.
OPERATION_TYPE_NAMES = {
    c_xfs.XLOG_LI_EFI: "extent_free_intent",
    c_xfs.XLOG_LI_EFD: "extent_free_done",
    c_xfs.XLOG_LI_IUNLINK: "inode_unlink",
    c_xfs.XLOG_LI_INODE: "inode",
    c_xfs.XLOG_LI_BUF: "metadata_buffer",
    c_xfs.XLOG_LI_DQUOT: "dquot",
    c_xfs.XLOG_LI_QUOTAOFF: "quota_off",
    c_xfs.XLOG_LI_ICREATE: "inode_create",
    c_xfs.XLOG_LI_RUI: "rmap_intent",
    c_xfs.XLOG_LI_RUD: "rmap_done",
    c_xfs.XLOG_LI_CUI: "refcount_intent",
    c_xfs.XLOG_LI_CUD: "refcount_done",
    c_xfs.XLOG_LI_BUI: "bmap_intent",
    c_xfs.XLOG_LI_BUD: "bmap_done",
    c_xfs.XLOG_LI_ATTRI: "attribute_intent",
    c_xfs.XLOG_LI_ATTRD: "attribute_done",
    c_xfs.XLOG_LI_INTEGRITY: "integrity",
    c_xfs.XLOG_LI_RFCE: "refcount_intent_v2",
}

# Four byte item magics used by v5 item headers and buffer formats.
MAGIC_OPERATION_TYPES = {
    b"ICRM": "commit",
    b"XFSB": "metadata_buffer",
    b"XAGI": "agi_header",
    b"XAGF": "agf_header",
    b"XAFL": "agfl_header",
    b"AB3B": "alloc_btree_bno",
    b"AB3C": "alloc_btree_cnt",
    b"IAB3": "inode_btree",
    b"FIB3": "free_inode_btree",
    b"BMA3": "bmap_btree",
    b"XDB3": "dir_block",
    b"XDD3": "dir_data",
    b"XDF3": "dir_free",
    b"XSLM": "symlink",
    b"NART": "inode_unlink",
}


def format_lsn(lsn: int) -> str:
    """Render an LSN as ``cycle/block`` the way XFS tooling presents it."""
    cycle, block = split_lsn(lsn)
    return f"{cycle}/{block}"


def split_lsn(lsn: int) -> tuple[int, int]:
    return lsn >> 32, lsn & 0xFFFFFFFF


def join_lsn(cycle: int, block: int) -> int:
    return (cycle << 32) | (block & 0xFFFFFFFF)


def _record_type_name(flags: int) -> str:
    names = []
    if flags & c_xfs.XLOG_START_TRANS:
        names.append("start")
    if flags & c_xfs.XLOG_COMMIT_TRANS:
        names.append("commit")
    if flags & c_xfs.XLOG_CONTINUE_TRANS:
        names.append("continuation")
    if flags & c_xfs.XLOG_WAS_CONT_TRANS:
        names.append("was_continuation")
    return "|".join(names) if names else "unknown"


class TruncatedLogError(Error):
    """Raised internally when referenced log material is missing from the capture."""


class XFSJournal:
    """Read-only view over the internal journal of an XFS filesystem.

    Args:
        xfs: The parsed filesystem whose journal should be read.
    """

    def __init__(self, xfs: XFS):
        self.xfs = xfs
        sb = xfs.sb
        self.available = bool(sb.sb_logstart and sb.sb_logblocks)
        self._records: list[LogRecord] | None = None
        self._transactions: list[TransactionSummary] | None = None
        if not self.available:
            self._fh: BinaryIO | None = None
            self.log_size = 0
            self.log_basic_blocks = 0
            self.start_offset = 0
            return

        self.log_size = sb.sb_logblocks * sb.sb_blocksize
        self.log_basic_blocks = self.log_size // LOG_BASIC_BLOCK_SIZE
        self.start_offset = sb.sb_logstart * sb.sb_blocksize
        self._fh = RangeStream(xfs.fh, self.start_offset, self.log_size)

    def _read(self, offset: int, size: int) -> bytes:
        self._fh.seek(offset)
        return self._fh.read(size)

    def _read_circular(self, offset: int, size: int) -> bytes:
        """Read bytes from the circular log, transparently crossing the wrap."""
        chunks: list[bytes] = []
        cursor = offset % self.log_size
        remaining = size
        while remaining:
            piece = min(remaining, self.log_size - cursor)
            chunks.append(self._read(cursor, piece))
            remaining -= piece
            cursor = (cursor + piece) % self.log_size
        return b"".join(chunks)

    def _candidate_headers(self) -> list[tuple[int, c_xfs.xfs_rec_header]]:
        """Find every plausible record header, including ones at wrap boundaries."""
        scan = self._read(0, self.log_size)
        candidates: list[tuple[int, c_xfs.xfs_rec_header]] = []
        for offset in range(0, self.log_size - RECORD_HEADER_SIZE + 1, 4):
            if int.from_bytes(scan[offset : offset + 4], "big") != c_xfs.XLOG_HEADER_MAGIC:
                continue
            try:
                header = c_xfs.xlog_rec_header(scan[offset : offset + RECORD_HEADER_SIZE])
            except EOFError:
                continue
            if self._header_is_plausible(header, offset):
                candidates.append((offset, header))
        return candidates

    def _header_is_plausible(self, header: c_xfs.xfs_rec_header, offset: int) -> bool:
        if offset % LOG_BASIC_BLOCK_SIZE:
            return False
        flags = header.h_type & c_xfs.XLOG_REC_TYPES_MASK
        if flags == 0:
            return False
        if header.h_type & c_xfs.XLOG_ENDIAN_LITTLE:
            return False
        if header.h_len % LOG_BASIC_BLOCK_SIZE or header.h_len > self.log_size:
            return False
        if header.h_lsn_block >= self.log_basic_blocks or header.h_lsn_cycle == 0:
            return False
        return True

    def _segments_for(self, offset: int, length: int, generation: int) -> tuple[list[LogSegment], bool]:
        """Split a logical write into physical segments, honouring the wrap.

        A record is only considered truncated when its declared length cannot fit
        in the circular buffer; a normal wrap around the end of the log yields
        two complete segments and is not truncation.
        """
        if length <= 0:
            return [], False
        if length > self.log_size:
            return ([], True)
        segments: list[LogSegment] = []
        cursor = offset
        remaining = length
        while remaining > 0:
            piece = min(remaining, self.log_size - cursor)
            segments.append(LogSegment(cursor, piece, generation))
            remaining -= piece
            cursor = (cursor + piece) % self.log_size
        return segments, False

    def _build_records(self) -> list[LogRecord]:
        if not self.available:
            return []

        records: list[LogRecord] = []
        seen_lsn: set[int] = set()
        for offset, header in self._candidate_headers():
            lsn = join_lsn(header.h_lsn_cycle, header.h_lsn_block)
            if lsn in seen_lsn:
                # Continuation fragments can repeat an LSN; keep the first copy.
                continue
            seen_lsn.add(lsn)
            flags = header.h_type & c_xfs.XLOG_REC_TYPES_MASK
            segments, truncated = self._segments_for(offset, header.h_len, header.h_lsn_cycle)
            record = LogRecord(
                lsn=lsn,
                tid=header.h_tid,
                record_type=_record_type_name(flags),
                record_flags=flags,
                source=segments,
                generation=header.h_lsn_cycle,
                physical_offset=offset,
                truncated=truncated,
                header_only=header.h_len == 0,
            )
            if header.h_len:
                try:
                    record.operations = list(self._parse_operations(offset, header.h_len, record))
                    if self._record_tail_is_missing(offset, header.h_len, record.operations):
                        record.truncated = True
                        record.notes.append("declared record extends beyond the material present in the capture")
                except TruncatedLogError as exc:
                    record.truncated = True
                    record.notes.append(str(exc))
                if not record.operations and self._record_body_is_blank(offset, header.h_len):
                    record.truncated = True
                    record.notes.append("record declares payload operations but only the header material is present")
            records.append(record)

        records.sort(key=lambda item: (split_lsn(item.lsn)[0], split_lsn(item.lsn)[1]))
        self._annotate_ordering(records)
        return records

    def _parse_operations(self, start: int, length: int, record: LogRecord) -> Iterator[LogOperation]:
        # Walk the record relative to its start so a record that wraps around the
        # end of the circular log is handled transparently.
        relative = RECORD_HEADER_SIZE
        seen_operation = False
        while relative + OP_HEADER_SIZE <= length:
            cursor = (start + relative) % self.log_size
            data = self._read_circular(cursor, OP_HEADER_SIZE)
            if len(data) < OP_HEADER_SIZE:
                raise TruncatedLogError(
                    f"operation header at journal offset 0x{cursor:x} is cut off by the capture boundary"
                )
            op_header = c_xfs.xlog_op_header(data)
            tid = op_header.oh_tid
            payload_len = op_header.oh_len
            clientid = op_header.oh_clientid
            op_flags = op_header.oh_flags
            if tid == 0 and payload_len == 0 and clientid == 0 and op_flags == 0:
                if seen_operation:
                    # Zero padding after the last operation fills the rest of the
                    # declared log sector; the usable record ends here.
                    break
                # Leading zeroed region (e.g. the legacy embedded op header).
                relative += 4
                continue
            if payload_len == 0:
                # A zero-length operation carries no redo material; these appear as
                # embedded markers rather than real logged items, so skip them.
                relative += OP_HEADER_SIZE
                continue
            seen_operation = True
            if relative + OP_HEADER_SIZE + payload_len > length:
                # The operation claims bytes beyond the material actually present,
                # which is genuine truncation of the record's tail.
                raise TruncatedLogError(
                    f"operation header at journal offset 0x{cursor:x} references payload missing from the capture"
                )
            payload_offset = (cursor + OP_HEADER_SIZE) % self.log_size
            operation_type, type_code = self._identify_operation(payload_offset, payload_len)
            segment = LogSegment(cursor, OP_HEADER_SIZE + payload_len, record.generation)
            yield LogOperation(
                tid=tid,
                operation_type=operation_type,
                type_code=type_code,
                payload_size=payload_len,
                flags=op_flags,
                source=segment,
                unmount=bool(op_flags & c_xfs.XLOG_UNMOUNT_TRANS),
            )
            relative = self._align8(relative + OP_HEADER_SIZE + payload_len)

    def _record_tail_is_missing(
        self, start: int, declared_length: int, operations: list[LogOperation]
    ) -> bool:
        """Detect a declared record whose trailing material was never captured.

        A complete record ends with at most one sector of zero padding. When the
        region after the last parsed operation spans more than one full basic
        block of zeroes, the record has been cut short rather than merely padded.
        """
        if not operations:
            return False
        last = operations[-1]
        last_end_physical = (last.source.offset + last.source.size) % self.log_size
        record_end_physical = (start + declared_length) % self.log_size
        if record_end_physical <= last_end_physical:
            return False
        tail = self._read_circular(last_end_physical, record_end_physical - last_end_physical)
        if not tail:
            return False
        return tail.count(0) == len(tail) and len(tail) > LOG_BASIC_BLOCK_SIZE

    def _record_body_is_blank(self, start: int, declared_length: int) -> bool:
        """Return whether a record's payload region contains only zeroes.

        Header-only void records have no body bytes beyond the 320 byte header;
        any record that declares a full sector (or more) of body but presents only
        zeroes has lost the operation material it was meant to carry.
        """
        body_length = declared_length - RECORD_HEADER_SIZE
        if body_length <= 0:
            return False
        body = self._read_circular((start + RECORD_HEADER_SIZE) % self.log_size, body_length)
        return bool(body) and body.count(0) == len(body)

    def _identify_operation(self, payload_offset: int, payload_len: int) -> tuple[str, int | None]:
        if payload_len <= 0:
            return "empty", None
        head = self._read_circular(payload_offset, min(payload_len, 8))
        if len(head) >= 4 and head[:4] in MAGIC_OPERATION_TYPES:
            magic = head[:4]
            return MAGIC_OPERATION_TYPES[magic], int.from_bytes(magic, "big")
        if len(head) >= 2:
            type_code = int.from_bytes(head[:2], "big")
            if type_code in OPERATION_TYPE_NAMES:
                return OPERATION_TYPE_NAMES[type_code], type_code
        return "unknown", None

    @staticmethod
    def _align8(value: int) -> int:
        return (value + 7) & ~7

    def _annotate_ordering(self, records: list[LogRecord]) -> None:
        previous: LogRecord | None = None
        for record in records:
            if previous is None:
                previous = record
                continue
            prev_cycle, prev_block = split_lsn(previous.lsn)
            cycle, block = split_lsn(record.lsn)
            if cycle < prev_cycle:
                record.notes.append("LSN cycle returns to an older log generation")
            elif cycle == prev_cycle and block <= prev_block:
                record.notes.append("LSN block does not advance within the same generation")
            previous = record

    @property
    def records(self) -> list[LogRecord]:
        if self._records is None:
            self._records = self._build_records()
        return self._records

    def transactions(self) -> list[TransactionSummary]:
        """Group parsed records into transactions ordered by their first LSN."""
        if self._transactions is not None:
            return self._transactions

        grouped: dict[int, TransactionSummary] = {}
        order: list[int] = []
        for record in self.records:
            if record.header_only and not record.operations:
                continue
            summary = grouped.get(record.tid)
            if summary is None:
                summary = TransactionSummary(
                    tid=record.tid,
                    start_lsn=record.lsn,
                    last_lsn=record.lsn,
                )
                grouped[record.tid] = summary
                order.append(record.tid)
            summary.records.append(record)
            summary.last_lsn = max(summary.last_lsn, record.lsn)
            if record.is_commit:
                summary.commit_record = record
            if record.truncated:
                summary.truncated = True

        self._transactions = [grouped[tid] for tid in order]
        return self._transactions

    def summary(self) -> JournalSummary:
        return JournalSummary(self)


@dataclass
class JournalSummary:
    """Materialised, presentable view of a parsed journal."""

    journal: XFSJournal
    records: list[LogRecord] = field(default_factory=list)
    transactions: list[TransactionSummary] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.journal.available:
            self.notes.append("filesystem does not declare an internal journal")
            return
        self.records = list(self.journal.records)
        self.transactions = list(self.journal.transactions())
        self.notes.append("records are ordered by LSN (cycle, block), not by physical offset")
        self.notes.append("redo payloads are described only; nothing is replayed onto the evidence volume")
        if any(record.truncated for record in self.records):
            self.notes.append("at least one record references material missing from the captured log")
        if any(transaction.status == "uncommitted" for transaction in self.transactions):
            self.notes.append("some transactions have no commit record in the available material")
        if any(transaction.status == "truncated" for transaction in self.transactions):
            self.notes.append("some transactions are only partially present due to log truncation")

    def render_text(self) -> str:
        """Return a human readable, investigator-facing summary."""
        lines = ["XFS journal summary", "=" * 20]
        if not self.journal.available:
            lines.append("No internal journal declared in the superblock.")
            return "\n".join(lines)

        end = self.journal.start_offset + self.journal.log_size
        lines.append(f"journal physical range: 0x{self.journal.start_offset:x}..0x{end:x}")
        lines.append(f"log basic blocks: {self.journal.log_basic_blocks}")
        lines.append(f"logical records: {len(self.records)}")
        lines.append(f"transactions: {len(self.transactions)}")
        lines.append("")
        lines.append("Records (LSN order):")
        for record in self.records:
            ranges = ", ".join(
                f"0x{segment.offset:x}+0x{segment.size:x}(gen {segment.generation})"
                for segment in record.source
            ) or "header-only"
            status = "truncated" if record.truncated else ("commit" if record.is_commit else "partial")
            lines.append(
                f"  lsn={format_lsn(record.lsn)} tid={record.tid} type={record.record_type} "
                f"source=[{ranges}] operations={len(record.operations)} status={status}"
            )
            for operation in record.operations:
                lines.append(
                    f"      - tid={operation.tid} operation={operation.operation_type} "
                    f"payload={operation.payload_size} source=0x{operation.source.offset:x}"
                )
            for note in record.notes:
                lines.append(f"      note: {note}")

        lines.append("")
        lines.append("Transactions:")
        for transaction in self.transactions:
            types = ",".join(transaction.operation_types) or "-"
            lines.append(
                f"  tid={transaction.tid} lsn={format_lsn(transaction.start_lsn)}.."
                f"{format_lsn(transaction.last_lsn)} status={transaction.status} operations={types}"
            )

        lines.append("")
        lines.append("Notes:")
        for note in self.notes:
            lines.append(f"  - {note}")
        return "\n".join(lines)
