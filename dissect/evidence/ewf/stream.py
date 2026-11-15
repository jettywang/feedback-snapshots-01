from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.util.stream import AlignedStream

if TYPE_CHECKING:
    from dissect.evidence.ewf.ewf import EWF, ErrorOverlap


class EWFStream(AlignedStream):
    """Provide a stitched stream over all EWF segments."""

    def __init__(self, ewf: EWF):
        self.ewf = ewf
        super().__init__(ewf.size, ewf.chunk_size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        chunk, offset_in_chunk = divmod(offset, self.ewf.chunk_size)

        while length > 0:
            buf = self.ewf.read_chunk(chunk)
            read_size = min(length, self.ewf.chunk_size - offset_in_chunk)
            result.append(buf[offset_in_chunk : offset_in_chunk + read_size])

            offset_in_chunk = 0
            offset += read_size
            length -= read_size
            chunk += 1

        return b"".join(result)

    def overlapping_errors(self, offset: int, length: int) -> tuple[ErrorOverlap, ...]:
        """Return the recorded acquisition errors overlapping a byte-oriented logical read.

        This is a convenience wrapper around :meth:`EWF.overlapping_errors` for callers that think in
        stream offsets. The byte range is translated to whole sectors using the container's sector
        size, so an unaligned read still reports every sector it touches. The returned
        :class:`~dissect.evidence.ewf.ewf.ErrorOverlap` objects keep using sector units.

        Args:
            offset: Byte offset of the logical read relative to the start of the stream.
            length: Number of bytes in the logical read.
        """
        if offset < 0:
            raise ValueError("offset must be a non-negative byte offset")
        if length <= 0:
            raise ValueError("length must be a positive number of bytes")

        sector_size = self.ewf.sector_size
        first_sector = offset // sector_size
        last_sector = (offset + length - 1) // sector_size

        return self.ewf.overlapping_errors(first_sector, last_sector - first_sector + 1)
