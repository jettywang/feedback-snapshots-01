"""
Handlers for Content-Encoding.

See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding
"""

from __future__ import annotations

import codecs
import io
import typing
import zlib

from ._exceptions import DecodingError

# Brotli support is optional
try:
    # The C bindings in `brotli` are recommended for CPython.
    import brotli
except ImportError:  # pragma: no cover
    try:
        # The CFFI bindings in `brotlicffi` are recommended for PyPy
        # and other environments.
        import brotlicffi as brotli
    except ImportError:
        brotli = None


# Zstandard support is optional
try:
    import zstandard
except ImportError:  # pragma: no cover
    zstandard = None  # type: ignore


class ContentDecoder:
    """
    Decoders are used incrementally, with `decode()` called for each
    portion of raw content, and a final `flush()` once the stream ends.

    Decoders support bounded output through the optional `max_length`
    argument. When it is used, at most `max_length` bytes are returned,
    and any remaining undecoded input is retained internally, as
    indicated by `has_pending`. The retained input is decoded by
    subsequent `decode()` calls before any new content is consumed.
    This ensures that decoding cannot buffer an unbounded amount of
    data, even for highly compressed content.
    """

    def decode(self, data: bytes, max_length: int | None = None) -> bytes:
        raise NotImplementedError()  # pragma: no cover

    def flush(self) -> bytes:
        raise NotImplementedError()  # pragma: no cover

    @property
    def has_pending(self) -> bool:
        """
        Whether the decoder is retaining undecoded input from a
        previous bounded `decode()` call.
        """
        return False


class IdentityDecoder(ContentDecoder):
    """
    Handle unencoded data.
    """

    def __init__(self) -> None:
        self._pending = b""

    @property
    def has_pending(self) -> bool:
        return bool(self._pending)

    def decode(self, data: bytes, max_length: int | None = None) -> bytes:
        if self._pending:
            data = self._pending + data
            self._pending = b""
        if max_length is not None and len(data) > max_length:
            self._pending = data[max_length:]
            return data[:max_length]
        return data

    def flush(self) -> bytes:
        data, self._pending = self._pending, b""
        return data


class DeflateDecoder(ContentDecoder):
    """
    Handle 'deflate' decoding.

    See: https://stackoverflow.com/questions/1838699
    """

    def __init__(self) -> None:
        self.first_attempt = True
        self.decompressor = zlib.decompressobj()
        self._pending = b""

    @property
    def has_pending(self) -> bool:
        return bool(self._pending)

    def decode(self, data: bytes, max_length: int | None = None) -> bytes:
        was_first_attempt = self.first_attempt
        self.first_attempt = False
        if self._pending:
            data = self._pending + data
            self._pending = b""
        try:
            if max_length is None:
                return self.decompressor.decompress(data)
            decoded = self.decompressor.decompress(data, max_length)
            self._pending = self.decompressor.unconsumed_tail
            return decoded
        except zlib.error as exc:
            if was_first_attempt:
                self.decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
                return self.decode(data, max_length)
            raise DecodingError(str(exc)) from exc

    def flush(self) -> bytes:
        try:
            decoded = self.decompressor.decompress(self._pending)
            self._pending = b""
            return decoded + self.decompressor.flush()
        except zlib.error as exc:  # pragma: no cover
            raise DecodingError(str(exc)) from exc


class GZipDecoder(ContentDecoder):
    """
    Handle 'gzip' decoding.

    See: https://stackoverflow.com/questions/1838699
    """

    def __init__(self) -> None:
        self.decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)
        self._pending = b""

    @property
    def has_pending(self) -> bool:
        return bool(self._pending)

    def decode(self, data: bytes, max_length: int | None = None) -> bytes:
        if self._pending:
            data = self._pending + data
            self._pending = b""
        try:
            if max_length is None:
                return self.decompressor.decompress(data)
            decoded = self.decompressor.decompress(data, max_length)
            self._pending = self.decompressor.unconsumed_tail
            return decoded
        except zlib.error as exc:
            raise DecodingError(str(exc)) from exc

    def flush(self) -> bytes:
        try:
            decoded = self.decompressor.decompress(self._pending)
            self._pending = b""
            return decoded + self.decompressor.flush()
        except zlib.error as exc:  # pragma: no cover
            raise DecodingError(str(exc)) from exc


class BrotliDecoder(ContentDecoder):
    """
    Handle 'brotli' decoding.

    Requires `pip install brotlipy`. See: https://brotlipy.readthedocs.io/
        or   `pip install brotli`. See https://github.com/google/brotli
    Supports both 'brotlipy' and 'Brotli' packages since they share an import
    name. The top branches are for 'brotlipy' and bottom branches for 'Brotli'
    """

    def __init__(self) -> None:
        if brotli is None:  # pragma: no cover
            raise ImportError(
                "Using 'BrotliDecoder', but neither of the 'brotlicffi' or 'brotli' "
                "packages have been installed. "
                "Make sure to install httpx using `pip install httpx[brotli]`."
            ) from None

        self.decompressor = brotli.Decompressor()
        self.seen_data = False
        self._decompress: typing.Callable[[bytes], bytes]
        if hasattr(self.decompressor, "decompress"):
            # The 'brotlicffi' package.
            self._decompress = self.decompressor.decompress  # pragma: no cover
        else:
            # The 'brotli' package.
            self._decompress = self.decompressor.process  # pragma: no cover

    def decode(self, data: bytes, max_length: int | None = None) -> bytes:
        # The brotli interface does not support bounded output, so
        # `max_length` cannot be enforced here. Buffering is still
        # bounded by the raw layer, which limits each `decode()` call
        # to a single chunk of compressed content.
        if not data:
            return b""
        self.seen_data = True
        try:
            return self._decompress(data)
        except brotli.error as exc:
            raise DecodingError(str(exc)) from exc

    def flush(self) -> bytes:
        if not self.seen_data:
            return b""
        try:
            if hasattr(self.decompressor, "finish"):
                # Only available in the 'brotlicffi' package.

                # As the decompressor decompresses eagerly, this
                # will never actually emit any data. However, it will potentially throw
                # errors if a truncated or damaged data stream has been used.
                self.decompressor.finish()  # pragma: no cover
            return b""
        except brotli.error as exc:  # pragma: no cover
            raise DecodingError(str(exc)) from exc


class ZStandardDecoder(ContentDecoder):
    """
    Handle 'zstd' RFC 8878 decoding.

    Requires `pip install zstandard`.
    Can be installed as a dependency of httpx using `pip install httpx[zstd]`.
    """

    # inspired by the ZstdDecoder implementation in urllib3
    def __init__(self) -> None:
        if zstandard is None:  # pragma: no cover
            raise ImportError(
                "Using 'ZStandardDecoder', ..."
                "Make sure to install httpx using `pip install httpx[zstd]`."
            ) from None

        self.decompressor = zstandard.ZstdDecompressor().decompressobj()
        self.seen_data = False

    def decode(self, data: bytes, max_length: int | None = None) -> bytes:
        # The zstandard interface does not support bounded output, so
        # `max_length` cannot be enforced here. Buffering is still
        # bounded by the raw layer, which limits each `decode()` call
        # to a single chunk of compressed content.
        assert zstandard is not None
        self.seen_data = True
        output = io.BytesIO()
        try:
            output.write(self.decompressor.decompress(data))
            while self.decompressor.eof and self.decompressor.unused_data:
                unused_data = self.decompressor.unused_data
                self.decompressor = zstandard.ZstdDecompressor().decompressobj()
                output.write(self.decompressor.decompress(unused_data))
        except zstandard.ZstdError as exc:
            raise DecodingError(str(exc)) from exc
        return output.getvalue()

    def flush(self) -> bytes:
        if not self.seen_data:
            return b""
        ret = self.decompressor.flush()  # note: this is a no-op
        if not self.decompressor.eof:
            raise DecodingError("Zstandard data is incomplete")  # pragma: no cover
        return bytes(ret)


class MultiDecoder(ContentDecoder):
    """
    Handle the case where multiple encodings have been applied.
    """

    def __init__(self, children: typing.Sequence[ContentDecoder]) -> None:
        """
        'children' should be a sequence of decoders in the order in which
        each was applied.
        """
        # Note that we reverse the order for decoding.
        self.children = list(reversed(children))

    @property
    def has_pending(self) -> bool:
        return any(child.has_pending for child in self.children)

    def decode(self, data: bytes, max_length: int | None = None) -> bytes:
        # Bounded output is not enforced across the decoder chain.
        # Buffering is still bounded by the raw layer, which limits
        # each `decode()` call to a single chunk of compressed content.
        for child in self.children:
            data = child.decode(data)
        return data

    def flush(self) -> bytes:
        data = b""
        for child in self.children:
            data = child.decode(data) + child.flush()
        return data


class ByteChunker:
    """
    Handles returning byte content in fixed-size chunks.
    """

    def __init__(self, chunk_size: int | None = None) -> None:
        self._buffer = io.BytesIO()
        self._chunk_size = chunk_size

    def decode(self, content: bytes) -> list[bytes]:
        if self._chunk_size is None:
            return [content] if content else []

        self._buffer.write(content)
        if self._buffer.tell() >= self._chunk_size:
            value = self._buffer.getvalue()
            chunks = [
                value[i : i + self._chunk_size]
                for i in range(0, len(value), self._chunk_size)
            ]
            if len(chunks[-1]) == self._chunk_size:
                self._buffer.seek(0)
                self._buffer.truncate()
                return chunks
            else:
                self._buffer.seek(0)
                self._buffer.write(chunks[-1])
                self._buffer.truncate()
                return chunks[:-1]
        else:
            return []

    def flush(self) -> list[bytes]:
        value = self._buffer.getvalue()
        self._buffer.seek(0)
        self._buffer.truncate()
        return [value] if value else []


class TextChunker:
    """
    Handles returning text content in fixed-size chunks.
    """

    def __init__(self, chunk_size: int | None = None) -> None:
        self._buffer = io.StringIO()
        self._chunk_size = chunk_size

    def decode(self, content: str) -> list[str]:
        if self._chunk_size is None:
            return [content] if content else []

        self._buffer.write(content)
        if self._buffer.tell() >= self._chunk_size:
            value = self._buffer.getvalue()
            chunks = [
                value[i : i + self._chunk_size]
                for i in range(0, len(value), self._chunk_size)
            ]
            if len(chunks[-1]) == self._chunk_size:
                self._buffer.seek(0)
                self._buffer.truncate()
                return chunks
            else:
                self._buffer.seek(0)
                self._buffer.write(chunks[-1])
                self._buffer.truncate()
                return chunks[:-1]
        else:
            return []

    def flush(self) -> list[str]:
        value = self._buffer.getvalue()
        self._buffer.seek(0)
        self._buffer.truncate()
        return [value] if value else []


class TextDecoder:
    """
    Handles incrementally decoding bytes into text
    """

    def __init__(self, encoding: str = "utf-8") -> None:
        self.decoder = codecs.getincrementaldecoder(encoding)(errors="replace")

    def decode(self, data: bytes) -> str:
        return self.decoder.decode(data)

    def flush(self) -> str:
        return self.decoder.decode(b"", True)


class LineDecoder:
    """
    Handles incrementally reading lines from text.

    Has the same behaviour as the stdllib splitlines,
    but handling the input iteratively.
    """

    def __init__(self) -> None:
        self.buffer: list[str] = []
        self.trailing_cr: bool = False

    def decode(self, text: str) -> list[str]:
        # See https://docs.python.org/3/library/stdtypes.html#str.splitlines
        NEWLINE_CHARS = "\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"

        # We always push a trailing `\r` into the next decode iteration.
        if self.trailing_cr:
            text = "\r" + text
            self.trailing_cr = False
        if text.endswith("\r"):
            self.trailing_cr = True
            text = text[:-1]

        if not text:
            # NOTE: the edge case input of empty text doesn't occur in practice,
            # because other httpx internals filter out this value
            return []  # pragma: no cover

        trailing_newline = text[-1] in NEWLINE_CHARS
        lines = text.splitlines()

        if len(lines) == 1 and not trailing_newline:
            # No new lines, buffer the input and continue.
            self.buffer.append(lines[0])
            return []

        if self.buffer:
            # Include any existing buffer in the first portion of the
            # splitlines result.
            lines = ["".join(self.buffer) + lines[0]] + lines[1:]
            self.buffer = []

        if not trailing_newline:
            # If the last segment of splitlines is not newline terminated,
            # then drop it from our output and start a new buffer.
            self.buffer = [lines.pop()]

        return lines

    def flush(self) -> list[str]:
        if not self.buffer and not self.trailing_cr:
            return []

        lines = ["".join(self.buffer)]
        self.buffer = []
        self.trailing_cr = False
        return lines


SUPPORTED_DECODERS = {
    "identity": IdentityDecoder,
    "gzip": GZipDecoder,
    "deflate": DeflateDecoder,
    "br": BrotliDecoder,
    "zstd": ZStandardDecoder,
}


if brotli is None:
    SUPPORTED_DECODERS.pop("br")  # pragma: no cover
if zstandard is None:
    SUPPORTED_DECODERS.pop("zstd")  # pragma: no cover
