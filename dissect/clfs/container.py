from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

from dissect.clfs.c_clfs import BlockHeader, c_clfs
from dissect.clfs.exceptions import InvalidRecordBlockError

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

    def _open_block(self, offset: int) -> tuple[BinaryIO, int]:
        """Open the blockheader of every block that is present within the given container.

        Returns:
            buf, cur_record_offset: Tuple containing a file-like object of the log block and the current offset.
        """
        try:
            log_block = BlockHeader(fh=self.fh, offset=offset)
        except EOFError:
            raise InvalidRecordBlockError("Invalid container block header, possibly corrupt/empty")

        cur_record_offset = log_block.header.RecordOffsets[0]

        buf = log_block.open()
        buf.seek(cur_record_offset)

        return buf, cur_record_offset

    def records(self) -> Iterator[tuple[int, bytes, bytes]]:
        """Parse the records that are present within the log block."""
        log_block_offset = self.offset
        cur_block_offset = log_block_offset

        buf, cur_record_offset = self._open_block(log_block_offset)
        cur_record_header = c_clfs.RECORD_HEADER(buf)
        cur_block_data = None

        while True:
            # Data block
            if cur_record_header.Type & c_clfs.RecordType.ClfsDataRecord:
                cur_block_data = buf.read(cur_record_header.DataSize - cur_record_header.Offset)

            # Start of record header
            if cur_record_header.Type & c_clfs.RecordType.ClfsStartRecord:
                """
                This may seem odd to do, but the actual data offset is present in the start record for the record block.

                The record data is placed right after the header itself, meaning that if you read the entire block, you
                can subtract the offset (size of header) from the data size itself and be left with the record data.
                """

                # A start record has to be preceded by a data record within the same block, block data of a
                # previously visited block may never be reused as the payload of the current record
                if cur_block_data is None:
                    raise InvalidRecordBlockError("Start record without preceding data record in the same block")

                # Advance to the next RECORD_HEADER
                next_record_header = c_clfs.RECORD_HEADER(buf)

                # The record data is present right after the record header, subtract the header size (offset field)
                # from the data size
                cur_record_data = buf.read(next_record_header.DataSize - next_record_header.Offset)

                yield log_block_offset + cur_record_offset, cur_record_data, cur_block_data

                # End of log sequence
                if next_record_header.LsnPrevious == 0:
                    break

                # A start record has to be followed by the last record of the block, a second start record
                # within the same block is not a valid continuation of the record sequence
                if next_record_header.Type & c_clfs.RecordType.ClfsStartRecord:
                    raise InvalidRecordBlockError("Duplicate start record within the same block")

                # Set the new block offset
                log_block_offset = next_record_header.LsnPrevious - 1
                cur_record_header = next_record_header
                continue

            # End of block, pointer to new block
            if cur_record_header.Type & c_clfs.RecordType.ClfsLastRecord:
                # The last record has to point to a different block, otherwise no progress can be made
                if log_block_offset == cur_block_offset:
                    raise InvalidRecordBlockError("Last record does not point to a new block")

                cur_block_offset = log_block_offset
                buf, cur_record_offset = self._open_block(log_block_offset)
                cur_record_header = c_clfs.RECORD_HEADER(buf)

                # Block data is only valid within the block it was read from
                cur_block_data = None
                continue

            # No state transition applies to this record, so no progress can be made
            raise InvalidRecordBlockError(f"Invalid record type: {cur_record_header.Type!r}")
