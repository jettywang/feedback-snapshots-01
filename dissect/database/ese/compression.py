from __future__ import annotations

import struct

from dissect.util.compression import lzxpress, sevenbit

from dissect.database.ese.c_ese import COMPRESSION_SCHEME


def decompress(buf: bytes) -> bytes:
    """Decompress the given bytes according to the encoded compression scheme.

    Args:
        buf: The compressed bytes to decompress.

    Raises:
        ValueError: If the buffer is empty, has a truncated compression header, a mismatched decompressed size
            or is compressed with an unknown compression algorithm.
        NotImplementedError: If the buffer is compressed with an unsupported compression algorithm (XPRESS9/XPRESS10).
    """
    if not buf:
        raise ValueError("Empty compressed data: missing compression header")

    identifier = buf[0] >> 3
    if identifier == COMPRESSION_SCHEME.COMPRESS_NONE:
        return buf
    if identifier == COMPRESSION_SCHEME.COMPRESS_7BITASCII:
        return sevenbit.decompress(buf[1:])
    if identifier == COMPRESSION_SCHEME.COMPRESS_7BITUNICODE:
        return sevenbit.decompress(buf[1:], wide=True)
    if identifier == COMPRESSION_SCHEME.COMPRESS_XPRESS:
        declared_size = decompress_size(buf)
        data = lzxpress.decompress(buf[3:])
        if len(data) != declared_size:
            raise ValueError(f"Decompressed size does not match declared size: {len(data)} != {declared_size}")
        return data
    if identifier in (
        COMPRESSION_SCHEME.COMPRESS_SCRUB,
        COMPRESSION_SCHEME.COMPRESS_XPRESS9,
        COMPRESSION_SCHEME.COMPRESS_XPRESS10,
    ):
        raise NotImplementedError(f"Compression not yet implemented: {COMPRESSION_SCHEME(identifier)}")
    raise ValueError(f"Unknown compression scheme: {identifier:#x}")


def decompress_size(buf: bytes) -> int | None:
    """Return the decompressed size of the given bytes according to the encoded compression scheme.

    Args:
        buf: The compressed bytes to return the decompressed size of.

    Raises:
        ValueError: If the buffer is empty, has a truncated compression header or is compressed with an unknown
            compression algorithm.
        NotImplementedError: If the buffer is compressed with an unsupported compression algorithm (XPRESS9/XPRESS10).
    """
    if not buf:
        raise ValueError("Empty compressed data: missing compression header")

    identifier = buf[0] >> 3
    if identifier == COMPRESSION_SCHEME.COMPRESS_NONE:
        return None
    if identifier == COMPRESSION_SCHEME.COMPRESS_7BITASCII:
        return ((buf[0] & 7) + (8 * len(buf))) // 7
    if identifier == COMPRESSION_SCHEME.COMPRESS_7BITUNICODE:
        return 2 * (((buf[0] & 7) + (8 * len(buf))) // 7)
    if identifier == COMPRESSION_SCHEME.COMPRESS_XPRESS:
        if len(buf) < 3:
            raise ValueError("Truncated XPRESS compression header")
        return struct.unpack("<H", buf[1:3])[0]
    if identifier in (
        COMPRESSION_SCHEME.COMPRESS_SCRUB,
        COMPRESSION_SCHEME.COMPRESS_XPRESS9,
        COMPRESSION_SCHEME.COMPRESS_XPRESS10,
    ):
        raise NotImplementedError(f"Compression not yet implemented: {COMPRESSION_SCHEME(identifier)}")
    raise ValueError(f"Unknown compression scheme: {identifier:#x}")
