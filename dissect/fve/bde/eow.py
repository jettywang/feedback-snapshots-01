# References:
# - fvevol.sys

from __future__ import annotations

from binascii import crc32
from functools import cached_property
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.fve.bde.c_bde import (
    EOW_BM_SIGNATURE,
    EOW_BR_SIGNATURE,
    EOW_SIGNATURE,
    c_bde,
)
from dissect.fve.exception import InvalidHeaderError, UnknownStateError

if TYPE_CHECKING:
    from collections.abc import Iterator


class EowInformation:
    """Bitlocker EOW Information."""

    def __init__(self, fh: BinaryIO, offset: int):
        self.fh = fh
        self.offset = offset
        fh.seek(offset)

        self.header = c_bde.FVE_EOW_INFORMATION(fh)
        if self.header.HeaderSignature != EOW_SIGNATURE:
            raise InvalidHeaderError("Invalid EOW information signature")

        _crc32 = self.header.Crc32
        self.header.Crc32 = 0
        self._valid_checksum = crc32(self.header.dumps()) == _crc32
        self.header.Crc32 = _crc32

    def is_valid(self) -> bool:
        return self._valid_checksum

    @property
    def size(self) -> int:
        return self.header.Size

    @property
    def chunk_size(self) -> int:
        return self.header.ChunkSize

    @property
    def conv_log_size(self) -> int:
        return self.header.ConvLogSize

    @cached_property
    def bitmaps(self) -> list[EowBitmap]:
        return [EowBitmap(self.fh, offset) for offset in self.header.BitmapOffsets]


class EowBitmap:
    """Bitlocker EOW Bitmap.

    A bitmap contains multiple bitmap records, but only one record is active. The active record is
    determined by the Lsn field in the header. The record with the highest Lsn is the active record.

    It looks like the number of bitmap records is hardcoded to 2, but let's keep the implementation
    flexible.
    """

    def __init__(self, fh: BinaryIO, offset: int):
        self.fh = fh
        self.offset = offset
        fh.seek(offset)

        self.header = c_bde.FVE_EOW_BITMAP(fh)
        if self.header.HeaderSignature != EOW_BM_SIGNATURE:
            raise ValueError("Invalid EOW bitmap signature")

        _crc32 = self.header.Crc32
        self.header.Crc32 = 0
        remainder = fh.read(self.header.RecordOffset[0] - self.header.HeaderSize)
        self._valid_checksum = crc32(self.header.dumps() + remainder) == _crc32
        self.header.Crc32 = _crc32

        self._record_data = fh.read(self.header.Size - self.header.RecordOffset[0])

    def __repr__(self) -> str:
        return f"<EowBitmap index={self.index} region_offset={self.region_offset:#x} region_size={self.region_size:#x}>"

    def is_valid(self) -> bool:
        return self._valid_checksum

    def runs(self, chunk: int, length: int) -> Iterator[tuple[int, int]]:
        yield from self.active_record.runs(chunk, length)

    @property
    def size(self) -> int:
        return self.header.Size

    @property
    def index(self) -> int:
        return self.header.Index

    @property
    def region_offset(self) -> int:
        return self.header.RegionOffset

    @property
    def region_size(self) -> int:
        return self.header.RegionSize

    @property
    def conv_log_offset(self) -> int:
        return self.header.ConvLogOffset

    @cached_property
    def active_record(self) -> EowBitmapRecord:
        latest_record = None

        for record in self.records:
            if latest_record is None:
                latest_record = record
                continue

            if record.sequence_number > latest_record.sequence_number:
                latest_record = record

        return latest_record

    @cached_property
    def records(self) -> list[EowBitmapRecord]:
        result = []

        buf = BytesIO(self._record_data)
        base = self.header.RecordOffset[0]
        for offset in self.header.RecordOffset:
            buf.seek(offset - base)
            result.append(EowBitmapRecord(buf))

        return result


class EowBitmapRecord:
    """Bitlocker EOW Bitmap Record.

    The record holding the actual bitmap. Each bit indicates a chunk with the size defined by
    the EOW information. The Lsn is the sequence number of that record.

    The flags are currently unknown, but seem related to an encrypted/decrypted state.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.header = c_bde.FVE_EOW_BITMAP_RECORD(fh)
        if self.header.HeaderSignature != EOW_BR_SIGNATURE:
            raise ValueError("Invalid EOW bitmap record signature")

        _crc32 = self.header.Crc32
        self.header.Crc32 = 0
        self._data = memoryview(fh.read(self.header.Size - self.header.HeaderSize))
        self._valid_checksum = crc32(self.header.dumps() + self._data) == _crc32
        self.header.Crc32 = _crc32

    def __repr__(self) -> str:
        return (
            f"<EowBitmapRecord sequence_number={self.sequence_number} bitmap_size={self.bitmap_size:#x}"
            f" flags={self.flags:#x}>"
        )

    def is_valid(self) -> bool:
        return self._valid_checksum

    def runs(self, chunk: int, length: int) -> Iterator[tuple[int, int]]:
        yield from _iter_bitmap(self.bitmap, self.bitmap_size, chunk, length)

    @property
    def size(self) -> int:
        return self.header.Size

    @property
    def bitmap(self) -> bytes:
        return self._data

    @property
    def bitmap_size(self) -> int:
        return self.header.BitmapSize

    @property
    def flags(self) -> int:
        return self.header.Flags

    @property
    def sequence_number(self) -> int:
        return self.header.SequenceNumber


def _iter_bitmap(bitmap: bytes, size: int, start: int, count: int) -> Iterator[tuple[int, int]]:
    """Iterate over ``count`` bits of a bitmap, starting at bit ``start``.

    ``size`` is the number of valid bits in the bitmap. Runs are yielded as ``(bit_value, bit_count)`` tuples.

    A bitmap can be shorter than the region it describes. Requesting a bit that is not present in the bitmap is
    treated as an unknown state and raises an :class:`UnknownStateError`, instead of silently treating it as zero.
    """
    if start < 0:
        raise ValueError("Negative bitmap start")

    if count <= 0 or start >= size:
        return

    end = min(size, start + count)
    current_bit = None
    current_count = 0

    for bit_offset in range(start, end):
        byte_idx, bit_idx = divmod(bit_offset, 8)
        if byte_idx >= len(bitmap):
            raise UnknownStateError(
                f"EOW bitmap is truncated: bit {bit_offset} requested, but only {len(bitmap)} bytes are available"
            )

        bit_value = (bitmap[byte_idx] >> bit_idx) & 1
        if bit_value == current_bit:
            current_count += 1
        else:
            if current_count:
                yield (current_bit, current_count)

            current_bit = bit_value
            current_count = 1

    if current_count:
        yield (current_bit, current_count)
