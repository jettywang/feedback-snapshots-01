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
    def decode(self, data: bytes) -> bytes:
        raise NotImplementedError()  # pragma: no cover

    def flush(self) -> bytes:
        raise NotImplementedError()  # pragma: no cover

    def check_finished(self) -> None:
        """
        Verify that the encoded stream reached a *legal* end.

        This is an independent termination criterion: it must be called once
        every raw byte has been fed through ``decode`` and ``flush`` has run.
        A decoder raises ``DecodingError`` if the stream was truncated before
        its natural end, or if any bytes remain that the encoding does not
        account for (trailing garbage, a half-consumed concatenated member, or
        bytes left over from an inner layer). It must never rely solely on the
        outer transport signalling end-of-stream.
        """
        raise NotImplementedError()  # pragma: no cover


class IdentityDecoder(ContentDecoder):
    """
    Handle unencoded data.
    """

    def decode(self, data: bytes) -> bytes:
        return data

    def flush(self) -> bytes:
        return b""

    def check_finished(self) -> None:
        # Identity data has no framing of its own, so end-of-stream is always
        # a legal end. Unsupported encodings must never be folded into this.
        return None


class DeflateDecoder(ContentDecoder):
    """
    Handle 'deflate' decoding.

    See: https://stackoverflow.com/questions/1838699

    The stream may be either RFC 1950 zlib-wrapped data or a bare RFC 1951
    raw stream. The first successful decompression fixes which variant is in
    use, so fragmented streams whose initial chunks carry no usable header
    still work instead of being misclassified on the first byte.
    """

    def __init__(self) -> None:
        self.decompressor = zlib.decompressobj()
        self.seen_data = False
        # While `undecided` we have not yet confirmed whether the stream is
        # zlib-wrapped or raw. The full prefix is retained in `_pending` (so a
        # later raw retry sees every byte), while each new delta is fed to the
        # probing decompressor only once.
        self.undecided = True
        self._pending = b""

    def _commit_raw(self) -> bytes:
        self.decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
        try:
            output = self.decompressor.decompress(self._pending)
        except zlib.error as exc:
            raise DecodingError(str(exc)) from exc
        self.undecided = False
        self._pending = b""
        return output

    def decode(self, data: bytes) -> bytes:
        if data:
            self.seen_data = True
        if not self.undecided:
            try:
                return self.decompressor.decompress(data)
            except zlib.error as exc:
                raise DecodingError(str(exc)) from exc

        self._pending += data
        try:
            output = self.decompressor.decompress(data)
        except zlib.error:
            # The bytes seen so far are not a valid zlib stream: reinterpret
            # the whole retained prefix as a raw RFC 1951 stream.
            return self._commit_raw()

        if output or self.decompressor.eof:
            # A real output (or a finished stream) confirms zlib wrapping.
            self.undecided = False
            self._pending = b""
        # Otherwise the decompressor is still holding an incomplete header in
        # its own buffer; stay undecided and keep accumulating bytes.
        return output

    def flush(self) -> bytes:
        if self.undecided:
            if self._pending:
                # End of stream with no confirmed output: try raw deflate once.
                output = self._commit_raw()
                return output + self.decompressor.flush()
            return b""
        try:
            return self.decompressor.flush()
        except zlib.error as exc:  # pragma: no cover
            raise DecodingError(str(exc)) from exc

    def check_finished(self) -> None:
        # An empty body is a legal (zero-length) deflate response.
        if not self.seen_data:
            return None
        if self.undecided:
            # Bytes were received but never formed a decodable stream.
            raise DecodingError("Deflate stream is incomplete")
        if not self.decompressor.eof:
            raise DecodingError("Deflate stream is incomplete")
        if self.decompressor.unused_data:
            raise DecodingError(
                "Received trailing data after the end of the deflate stream"
            )


class GZipDecoder(ContentDecoder):
    """
    Handle 'gzip' decoding.

    See: https://stackoverflow.com/questions/1838699

    A gzip stream may consist of several concatenated members (RFC 1952,
    section 2.2), which are all decoded. Any bytes that cannot be consumed as
    complete gzip members are reported rather than silently discarded.
    """

    def __init__(self) -> None:
        self.decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)
        self.seen_data = False

    def _decompress_chain(self, data: bytes) -> bytes:
        # Keep feeding concatenated members to fresh decompressors until the
        # current member either needs more data or leaves unparseable bytes.
        output = io.BytesIO()
        pending = data
        while pending:
            try:
                output.write(self.decompressor.decompress(pending))
            except zlib.error as exc:
                raise DecodingError(str(exc)) from exc
            if not self.decompressor.eof:
                break
            pending = self.decompressor.unused_data
            if not pending:
                break
            self.decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)
        return output.getvalue()

    def decode(self, data: bytes) -> bytes:
        if data:
            self.seen_data = True
        return self._decompress_chain(data)

    def flush(self) -> bytes:
        try:
            return self.decompressor.flush()
        except zlib.error as exc:  # pragma: no cover
            raise DecodingError(str(exc)) from exc

    def check_finished(self) -> None:
        # An empty body is a legal (zero-length) gzip response.
        if not self.seen_data:
            return None
        if not self.decompressor.eof:
            raise DecodingError("GZip stream is incomplete")
        if self.decompressor.unused_data:
            raise DecodingError(
                "Received trailing data after the end of the gzip stream"
            )


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

    def decode(self, data: bytes) -> bytes:
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

    def check_finished(self) -> None:
        # An empty body is a legal (zero-length) brotli response.
        if not self.seen_data:
            return None
        # The brotli decompressor is eager: it consumes the whole logical
        # stream on each call and raises if the input is truncated or corrupt.
        try:
            if hasattr(self.decompressor, "finish"):
                # 'brotlicffi' exposes an explicit end-of-stream check.
                self.decompressor.finish()  # pragma: no cover
            elif not self.decompressor.eof:
                # The 'brotli' package reports an unfinished stream this way.
                raise DecodingError("Brotli stream is incomplete")
        except brotli.error as exc:
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

    def decode(self, data: bytes) -> bytes:
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
        return bytes(ret)

    def check_finished(self) -> None:
        # An empty body is a legal (zero-length) zstd response.
        if not self.seen_data:
            return None
        if not self.decompressor.eof:
            raise DecodingError("Zstandard data is incomplete")
        # `decode` chains concatenated frames via `unused_data`, so reaching
        # eof with no residue guarantees every byte belonged to a valid frame.
        if self.decompressor.unused_data:
            raise DecodingError(
                "Received trailing data after the end of the zstandard stream"
            )


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

    def decode(self, data: bytes) -> bytes:
        for child in self.children:
            data = child.decode(data)
        return data

    def flush(self) -> bytes:
        data = b""
        for child in self.children:
            data = child.decode(data) + child.flush()
        return data

    def check_finished(self) -> None:
        # Each layer has its own framing, so each one must independently prove
        # it consumed a complete, well-formed stream. Checking only the
        # outermost layer would let truncation or trailing garbage hidden by an
        # inner layer surface as a seemingly complete response.
        for child in self.children:
            child.check_finished()


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
