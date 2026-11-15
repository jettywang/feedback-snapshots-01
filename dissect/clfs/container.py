from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

from dissect.clfs.c_clfs import SECTOR_SIZE, BlockHeader, c_clfs
from dissect.clfs.exceptions import InvalidRecordBlockError
from dissect.clfs.records import LSN, LogRecord, RecordCategory, classify_record_type

if TYPE_CHECKING:
    from collections.abc import Iterator


class Container:
    """Main class for parsing the containers that belong to a BLF file parsed in an earlier stage.

    Args:
        fh: A file handle to a container file.
        offset: The offset to start parsing the container records.
    """

    def __init__(self, fh: BinaryIO, offset: int):
        self.fh = fh
        self.offset = offset

    def _open_block(self, offset: int) -> tuple[BinaryIO, int, BlockHeader]:
        """Open the block header of every block that is present within the given container.

        Returns:
            A tuple of a file-like object of the log block, the offset of the first record within
            that block and the parsed :class:`BlockHeader`.
        """
        try:
            log_block = BlockHeader(fh=self.fh, offset=offset)
        except EOFError:
            raise InvalidRecordBlockError("Invalid container block header, possibly corrupt/empty")

        cur_record_offset = log_block.header.RecordOffsets[0]

        buf = log_block.open()
        buf.seek(cur_record_offset)

        return buf, cur_record_offset, log_block

    def log_records(self) -> Iterator[LogRecord]:
        """Parse and classify every record present in the container.

        Each yielded :class:`~dissect.clfs.records.LogRecord` keeps its raw record type bits, an
        explicit category, its virtual / undo-next / previous LSN relationships and the raw,
        uninterpreted payload. Restart records are recovery information, not client data, and
        unknown type combinations are preserved as evidence instead of being treated as data.

        Records that reference an associated fragment or restart record that is missing from the
        container are yielded with ``complete=False`` so the caller can keep an open investigation.
        """
        seen_records: list[LogRecord] = []
        seen_lsns: set[int] = set()

        log_block_offset = self.offset
        visited_blocks: set[int] = set()

        while log_block_offset not in visited_blocks:
            visited_blocks.add(log_block_offset)
            try:
                buf, first_record_offset, log_block = self._open_block(log_block_offset)
            except InvalidRecordBlockError:
                # The first block must be readable; a referenced predecessor that is missing or
                # truncated ends the walk instead, leaving referencing records marked incomplete.
                if log_block_offset == self.offset:
                    raise
                break
            block_size = log_block.header.TotalSectors * SECTOR_SIZE

            block_records: list[LogRecord] = []
            cursor = first_record_offset
            block_previous_lsn: LSN | None = None
            has_last_record = False

            while cursor < block_size:
                buf.seek(cursor)
                try:
                    record_header = c_clfs.RECORD_HEADER(buf)
                except EOFError:
                    break

                payload_size = record_header.DataSize - record_header.Offset
                if payload_size < 0 or cursor + record_header.DataSize > block_size:
                    # The header claims data that does not fit the block; keep what is readable as
                    # evidence rather than raising and losing the surrounding records.
                    payload = buf.read(max(0, block_size - cursor))
                    truncated = True
                else:
                    payload = buf.read(payload_size)
                    truncated = False

                type_info = classify_record_type(int(record_header.Type))
                record = LogRecord(
                    offset=log_block_offset + cursor,
                    block_offset=log_block_offset,
                    type_info=type_info,
                    lsn_virtual=LSN.from_value(record_header.LsnVirtual),
                    lsn_undo_next=LSN.from_value(record_header.LsnUndoNext),
                    lsn_previous=LSN.from_value(record_header.LsnPrevious),
                    data_size=record_header.DataSize,
                    header_size=record_header.Offset,
                    record_flags=record_header.RecordFlags,
                    unknown=record_header.Unknown,
                    payload=payload,
                    complete=not truncated,
                    incomplete_reason="record payload extends beyond the log block" if truncated else None,
                )
                block_records.append(record)
                seen_lsns.add(record.lsn_virtual.value)

                if record_header.Type & c_clfs.RecordType.ClfsLastRecord:
                    has_last_record = True
                    block_previous_lsn = record.lsn_previous

                if record_header.DataSize <= record_header.Offset:
                    break
                cursor += record_header.DataSize

            self._mark_fragment_completeness(block_records)
            seen_records.extend(block_records)

            # A block without a closing last record (e.g. a truncated or synthetic block) cannot
            # reliably name its predecessor, so the walk ends here instead of looping.
            if not has_last_record:
                break

            # A null (0) or sentinel LSN means there is no preceding block to recover.
            if block_previous_lsn is None or block_previous_lsn.value == 0 or block_previous_lsn.is_null:
                break
            log_block_offset = block_previous_lsn.value - 1

        self._mark_restart_chain_completeness(seen_records, seen_lsns)
        yield from seen_records

    @staticmethod
    def _mark_fragment_completeness(block_records: list[LogRecord]) -> None:
        """Flag multi-fragment records whose start/continuation/end association is incomplete."""
        for index, record in enumerate(block_records):
            if record.category not in (RecordCategory.DATA, RecordCategory.RESTART):
                continue

            has_start = bool(record.raw_type & c_clfs.RecordType.ClfsStartRecord)
            has_end = bool(record.raw_type & c_clfs.RecordType.ClfsEndRecord)
            has_continuation = bool(record.raw_type & c_clfs.RecordType.ClfsContinuationRecord)

            if has_continuation and not (has_start or has_end):
                block_records[index] = record._replace(
                    complete=False,
                    incomplete_reason="continuation fragment without its start/end record in this block",
                )

    @staticmethod
    def _mark_restart_chain_completeness(records: list[LogRecord], known_lsns: set[int]) -> None:
        """Flag restart records whose previous restart LSN points outside the container.

        A restart position only carries the log state required for client recovery. A dangling
        reference means the recovery state cannot be fully reconstructed, but it must never be
        promoted into a claim that an application transaction committed.
        """
        for index, record in enumerate(records):
            if record.category is not RecordCategory.RESTART:
                continue
            previous = record.lsn_previous
            if previous.value == 0 or previous.is_null:
                continue
            if previous.value not in known_lsns:
                records[index] = record._replace(
                    complete=False,
                    incomplete_reason=f"previous restart LSN {previous.value:#018x} is not present in the container",
                )

    def records(self) -> Iterator[tuple[int, bytes, bytes]]:
        """Yield the legacy ``(offset, record_data, block_data)`` tuples.

        Kept for backwards compatibility; new consumers should use :meth:`log_records`, which keeps
        the record type bits, category, LSN relationships and payload as separate, typed fields.
        """
        block_data_by_offset: dict[int, bytes] = {}
        first_record_offset_by_block: dict[int, int] = {}

        for record in self.log_records():
            # The start-of-record (data) fragment carries the block data for the block it lives in.
            if record.raw_type & c_clfs.RecordType.ClfsStartRecord:
                block_data_by_offset[record.block_offset] = record.payload

            # Remember the offset of the first record header within each block.
            first_record_offset_by_block.setdefault(record.block_offset, record.offset)

            # The last record of a block closes the sequence and yields the block's pair.
            if record.raw_type & c_clfs.RecordType.ClfsLastRecord:
                yield (
                    first_record_offset_by_block[record.block_offset],
                    record.payload,
                    block_data_by_offset.pop(record.block_offset, b""),
                )
