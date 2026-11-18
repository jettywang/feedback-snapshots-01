#-------------------------------------------------------------------------------
# elftools: common/compression.py
#
# Helpers for decompressing ELF section data.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

from typing import Any

import zlib

from .exceptions import ELFCompressionError

# Decompress in bounded chunks so a bogus uncompressed size cannot cause a
# huge allocation before the actual stream size is known.
_CHUNK_SIZE = 64 * 1024

_zstd_module: Any = None
_zstd_error: str | None = None


def _get_zstd() -> Any:
    """ Return the available zstd module.

        Python 3.14 provides compression.zstd in the standard library. Older
        versions can use the compatible backports.zstd module.
    """
    global _zstd_module, _zstd_error
    if _zstd_module is None:
        if _zstd_error is not None:
            raise ELFCompressionError(_zstd_error)
        try:
            from compression import zstd
        except ImportError:
            try:
                from backports import zstd
            except ImportError as e:
                _zstd_error = ('Zstandard compression requires Python 3.14 '
                               'or the backports-zstd package')
                raise ELFCompressionError(_zstd_error) from e
        _zstd_module = zstd
    return _zstd_module


def _check_size(size: int, expected_size: int) -> None:
    if size != expected_size:
        raise ELFCompressionError(
            f'Decompressed data is {size} bytes long, should be '
            f'{expected_size} bytes long')


def _check_size_overflow(size: int, expected_size: int) -> None:
    if size > expected_size:
        raise ELFCompressionError(
            f'Decompressed data is at least {size} bytes long, should be '
            f'{expected_size} bytes long')


def _output_limit(expected_size: int, produced: int) -> int:
    # Leave room for one byte so an undersized expected size is detected
    # instead of silently truncating the output.
    return min(expected_size + 1 - produced, _CHUNK_SIZE)


def decompress_zlib(data: bytes, expected_size: int) -> bytes:
    """ Decompress one zlib stream, validating its exact output size.
    """
    decompressor = zlib.decompressobj()
    result = bytearray()
    pending = b''
    pos = 0
    try:
        while not decompressor.eof:
            if pending:
                chunk_in = pending
            elif pos < len(data):
                chunk_in = data[pos:pos + _CHUNK_SIZE]
                pos += len(chunk_in)
            else:
                chunk_in = b''

            limit = _output_limit(expected_size, len(result))
            if limit <= 0:
                _check_size_overflow(len(result), expected_size)
            chunk = decompressor.decompress(chunk_in, limit)
            pending = decompressor.unconsumed_tail
            result += chunk
            _check_size_overflow(len(result), expected_size)

            if not chunk and not pending and pos >= len(data):
                # No more input and no progress: the stream is incomplete.
                break
    except zlib.error as e:
        raise ELFCompressionError(f'Invalid zlib compressed data: {e}') from e

    if not decompressor.eof:
        raise ELFCompressionError('Compressed data is truncated')
    if decompressor.unused_data:
        raise ELFCompressionError('Trailing data after compressed stream')
    _check_size(len(result), expected_size)
    return bytes(result)


def decompress_zstd(data: bytes, expected_size: int) -> bytes:
    """ Decompress one Zstandard frame, validating its exact output size.
    """
    zstd = _get_zstd()
    decompressor = zstd.ZstdDecompressor()
    result = bytearray()
    pos = 0
    try:
        while not decompressor.eof:
            if decompressor.needs_input and pos < len(data):
                chunk_in = data[pos:pos + _CHUNK_SIZE]
                pos += len(chunk_in)
            else:
                chunk_in = b''

            limit = _output_limit(expected_size, len(result))
            if limit <= 0:
                _check_size_overflow(len(result), expected_size)
            try:
                chunk = decompressor.decompress(chunk_in, limit)
            except EOFError:
                # The frame ended exactly at the previous call's boundary.
                break
            result += chunk
            _check_size_overflow(len(result), expected_size)

            if (not chunk and decompressor.needs_input and
                    pos >= len(data)):
                # No more input and no progress: the frame is incomplete.
                break
    except zstd.ZstdError as e:
        raise ELFCompressionError(f'Invalid Zstandard compressed data: {e}') from e

    if not decompressor.eof:
        raise ELFCompressionError('Compressed data is truncated')
    if decompressor.unused_data:
        raise ELFCompressionError('Trailing data after compressed stream')
    _check_size(len(result), expected_size)
    return bytes(result)
