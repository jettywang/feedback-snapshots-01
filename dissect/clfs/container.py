from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

from dissect.clfs.c_clfs import BlockHeader, c_clfs
from dissect.clfs.exceptions import InvalidRecordBlockError
from dissect.clfs.lsn import interpret_lsn

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
        log_block = self._read_block(offset)
        cur_record_offset = log_block.header.RecordOffsets[0]

        buf = log_block.open()
        buf.seek(cur_record_offset)

        return buf, cur_record_offset

    def _read_block(self, offset: int) -> BlockHeader:
        """Read a log block and reject an unreadable header.

        Args:
            offset: Offset of the log block inside the container.
        """
        try:
            return BlockHeader(fh=self.fh, offset=offset)
        except (EOFError, ValueError):
            raise InvalidRecordBlockError("Invalid container block header, possibly corrupt/empty")

    def _verify_block(self, offset: int, expected_lsn: int) -> None:
        """Verify that the block at ``offset`` declares the referenced LSN itself.

        A previous-LSN reference identifies a segment and a block offset. Merely finding a
        parseable block header at that offset is not enough: the block must declare the same
        container and block offset before its records may be followed.

        Args:
            offset: Offset of the referenced log block inside the container.
            expected_lsn: The raw LSN that referenced this block.
        """
        expected = interpret_lsn(expected_lsn)
        declared = interpret_lsn(int(self._read_block(offset).header.CurrentLsn.PhysicalOffset))
        if not declared.valid or declared.container_id != expected.container_id or declared.block_offset != offset:
            raise InvalidRecordBlockError(f"Block at {offset:#x} does not declare the referenced LSN {expected_lsn:#x}")

    def records(self) -> Iterator[tuple[int, bytes, bytes]]:
        """Parse the records that are present within the log block."""
        log_block_offset = self.offset

        buf, cur_record_offset = self._open_block(log_block_offset)
        cur_record_header = c_clfs.RECORD_HEADER(buf)

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

                # Advance to the next RECORD_HEADER
                next_record_header = c_clfs.RECORD_HEADER(buf)

                # The record data is present right after the record header, subtract the header size (offset field)
                # from the data size
                cur_record_data = buf.read(next_record_header.DataSize - next_record_header.Offset)

                yield log_block_offset + cur_record_offset, cur_record_data, cur_block_data

                # End of log sequence
                if next_record_header.LsnPrevious == 0:
                    break

                # The previous LSN identifies the block; its record sequence is not a byte offset
                previous = interpret_lsn(int(next_record_header.LsnPrevious))
                if previous.is_invalid:
                    break
                if previous.is_null or not previous.valid or previous.block_offset is None:
                    raise InvalidRecordBlockError(
                        f"Record references an unusable previous LSN {int(next_record_header.LsnPrevious):#x}"
                    )

                # Verify the referenced block's own identity before following the chain
                log_block_offset = previous.block_offset
                self._verify_block(log_block_offset, int(next_record_header.LsnPrevious))
                cur_record_header = next_record_header
                continue

            # End of block, pointer to new block
            if cur_record_header.Type & c_clfs.RecordType.ClfsLastRecord:
                buf, cur_record_offset = self._open_block(log_block_offset)
                cur_record_header = c_clfs.RECORD_HEADER(buf)
