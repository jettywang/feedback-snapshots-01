import asyncio
import base64
import gzip
import io
import json
import pathlib
import sys
from collections.abc import AsyncIterator
from types import TracebackType
from typing import Self
from unittest import mock

import pytest
from multidict import CIMultiDict

import aiohttp
from aiohttp import payload
from aiohttp.abc import AbstractStreamWriter
from aiohttp.compression_utils import ZLibBackend
from aiohttp.hdrs import (
    CONTENT_DISPOSITION,
    CONTENT_ENCODING,
    CONTENT_TRANSFER_ENCODING,
    CONTENT_TYPE,
)
from aiohttp.helpers import DEFAULT_CHUNK_SIZE, HeadersDictProxy, parse_mimetype
from aiohttp.multipart import (
    BodyPartReader,
    BodyPartReaderPayload,
    MultipartReader,
    MultipartResponseWrapper,
)
from aiohttp.streams import StreamReader
from aiohttp.web_exceptions import HTTPRequestEntityTooLarge

BOUNDARY: bytes = b"--:"


@pytest.fixture
def buf() -> bytearray:
    return bytearray()


@pytest.fixture
def stream(buf: bytearray) -> AbstractStreamWriter:
    writer = mock.create_autospec(AbstractStreamWriter, instance=True, spec_set=True)

    async def write(chunk: bytes) -> None:
        buf.extend(chunk)

    writer.write.side_effect = write
    return writer  # type: ignore[no-any-return]


@pytest.fixture
def buf2() -> bytearray:
    return bytearray()


@pytest.fixture
def stream2(buf2: bytearray) -> mock.Mock:
    writer = mock.Mock()

    async def write(chunk: bytes) -> None:
        buf2.extend(chunk)

    writer.write.side_effect = write
    return writer


@pytest.fixture
def writer() -> aiohttp.MultipartWriter:
    return aiohttp.MultipartWriter(boundary=":")


class Stream(StreamReader):
    def __init__(self, content: bytes) -> None:
        self.content = io.BytesIO(content)

    async def read(self, size: int | None = None) -> bytes:
        return self.content.read(size)

    def at_eof(self) -> bool:
        with self.content.getbuffer() as buf:
            return self.content.tell() == len(buf)

    async def readline(self, *, max_line_length: int | None = None) -> bytes:
        return self.content.readline()

    def unread_data(self, data: bytes) -> None:
        self.content = io.BytesIO(data + self.content.read())

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.content.close()


class Response:
    def __init__(self, headers: HeadersDictProxy, content: Stream) -> None:
        self.headers = headers
        self.content = content


class StreamWithShortenRead(Stream):
    def __init__(self, content: bytes) -> None:
        self._first = True
        super().__init__(content)

    async def read(self, size: int | None = None) -> bytes:
        if size is not None and self._first:
            self._first = False
            size = size // 2
        return await super().read(size)


class TestMultipartResponseWrapper:
    async def test_at_eof(self) -> None:
        m_resp = mock.create_autospec(aiohttp.ClientResponse, spec_set=True)
        m_stream = mock.create_autospec(MultipartReader, spec_set=True)
        wrapper = MultipartResponseWrapper(m_resp, m_stream)
        wrapper.at_eof()
        assert m_resp.content.at_eof.called

    async def test_next(self) -> None:
        m_resp = mock.create_autospec(aiohttp.ClientResponse, spec_set=True)
        m_stream = mock.create_autospec(MultipartReader, spec_set=True)
        wrapper = MultipartResponseWrapper(m_resp, m_stream)
        m_stream.next.return_value = b""
        m_stream.at_eof.return_value = False
        await wrapper.next()
        assert m_stream.next.called

    async def test_release(self) -> None:
        m_resp = mock.create_autospec(aiohttp.ClientResponse, spec_set=True)
        m_stream = mock.create_autospec(MultipartReader, spec_set=True)
        wrapper = MultipartResponseWrapper(m_resp, m_stream)
        await wrapper.release()
        assert m_resp.release.called

    async def test_release_when_stream_at_eof(self) -> None:
        m_resp = mock.create_autospec(aiohttp.ClientResponse, spec_set=True)
        m_stream = mock.create_autospec(MultipartReader, spec_set=True)
        wrapper = MultipartResponseWrapper(m_resp, m_stream)
        m_stream.next.return_value = b""
        m_stream.at_eof.return_value = True
        await wrapper.next()
        assert m_stream.next.called
        assert m_resp.release.called


class TestPartReader:
    async def test_next(self) -> None:
        with Stream(b"Hello, world!\r\n--:") as stream:
            d = HeadersDictProxy(CIMultiDict())
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            result = await obj.next()
            assert b"Hello, world!" == result
            assert obj.at_eof()

    async def test_next_next(self) -> None:
        with Stream(b"Hello, world!\r\n--:") as stream:
            d = HeadersDictProxy(CIMultiDict())
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            result = await obj.next()
            assert b"Hello, world!" == result
            assert obj.at_eof()
            result = await obj.next()
            assert result is None

    async def test_read(self) -> None:
        with Stream(b"Hello, world!\r\n--:") as stream:
            d = HeadersDictProxy(CIMultiDict())
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            result = await obj.read()
            assert b"Hello, world!" == result
            assert obj.at_eof()

    async def test_read_chunk_at_eof(self) -> None:
        with Stream(b"--:") as stream:
            d = HeadersDictProxy(CIMultiDict())
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            obj._at_eof = True
            result = await obj.read_chunk()
        assert b"" == result

    async def test_read_chunk_without_content_length(self) -> None:
        with Stream(b"Hello, world!\r\n--:") as stream:
            d = HeadersDictProxy(CIMultiDict())
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            c1 = await obj.read_chunk(8)
            c2 = await obj.read_chunk(8)
            c3 = await obj.read_chunk(8)
        assert c1 + c2 == b"Hello, world!"
        assert c3 == b""

    async def test_read_chunk_with_zero_content_length(self) -> None:
        with Stream(b"\r\n--:--\r\n") as stream:
            d = HeadersDictProxy(CIMultiDict({"Content-Length": "0"}))
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            result = await obj.read_chunk(4)
            assert obj.at_eof()
        assert b"" == result

    async def test_read_incomplete_chunk(self) -> None:
        with Stream(b"") as stream:

            def prepare(data: bytes) -> bytes:
                return data

            with mock.patch.object(
                stream,
                "read",
                side_effect=[
                    prepare(b"Hello, "),
                    prepare(b"World"),
                    prepare(b"!\r\n--:"),
                    prepare(b""),
                ],
            ):
                d = HeadersDictProxy(CIMultiDict())
                obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
                c1 = await obj.read_chunk(8)
                assert c1 == b"Hello, "
                c2 = await obj.read_chunk(8)
                assert c2 == b"World"
                c3 = await obj.read_chunk(8)
                assert c3 == b"!"

    async def test_read_all_at_once(self) -> None:
        with Stream(b"Hello, World!\r\n--:--\r\n") as stream:
            d = HeadersDictProxy(CIMultiDict())
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            result = await obj.read_chunk()
            assert b"Hello, World!" == result
            result = await obj.read_chunk()
            assert b"" == result
            assert obj.at_eof()

    async def test_read_incomplete_body_chunked(self) -> None:
        with Stream(b"Hello, World!\r\n-") as stream:
            d = HeadersDictProxy(CIMultiDict())
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            result = b""
            with pytest.raises(ValueError):
                for _ in range(4):  # pragma: no branch
                    result += await obj.read_chunk(7)
        assert b"Hello, World!\r\n-" == result

    async def test_read_with_content_length_malformed_crlf(self) -> None:
        # Content-Length is correct but data after content is not \r\n
        content = b"Hello"
        h = HeadersDictProxy(CIMultiDict({"CONTENT-LENGTH": str(len(content))}))
        # Malformed: "XX" instead of "\r\n" after content
        with Stream(content + b"XX--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            with pytest.raises(ValueError, match="malformed"):
                await obj.read()

    async def test_read_boundary_with_incomplete_chunk(self) -> None:
        with Stream(b"") as stream:

            def prepare(data: bytes) -> bytes:
                return data

            with mock.patch.object(
                stream,
                "read",
                side_effect=[
                    prepare(b"Hello, World"),
                    prepare(b"!\r\n"),
                    prepare(b"--:"),
                    prepare(b""),
                ],
            ):
                d = HeadersDictProxy(CIMultiDict())
                obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
                c1 = await obj.read_chunk(12)
                assert c1 == b"Hello, World"
                c2 = await obj.read_chunk(8)
                assert c2 == b"!"
                c3 = await obj.read_chunk(8)
                assert c3 == b""

    async def test_multi_read_chunk(self) -> None:
        with Stream(b"Hello,\r\n--:\r\n\r\nworld!\r\n--:--") as stream:
            d = HeadersDictProxy(CIMultiDict())
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            result = await obj.read_chunk(8)
            assert b"Hello," == result
            result = await obj.read_chunk(8)
            assert b"" == result
            assert obj.at_eof()

    @pytest.mark.parametrize("value", ["-1", "+5", "1_0", " 5", "0x5", "５"])
    async def test_rejects_malformed_content_length(self, value: str) -> None:
        h = HeadersDictProxy(CIMultiDict({"CONTENT-LENGTH": value}))
        with Stream(b"Hello, world!\r\n--:--") as stream:
            with pytest.raises(ValueError, match="Content-Length"):
                aiohttp.BodyPartReader(BOUNDARY, h, stream)

    async def test_read_chunk_properly_counts_read_bytes(self) -> None:
        expected = b"." * 10
        size = len(expected)
        h = HeadersDictProxy(CIMultiDict({"CONTENT-LENGTH": str(size)}))
        with StreamWithShortenRead(expected + b"\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = bytearray()
            while True:
                chunk = await obj.read_chunk()
                if not chunk:
                    break
                result.extend(chunk)
        assert size == len(result)
        assert b"." * size == result
        assert obj.at_eof()

    async def test_read_does_not_read_boundary(self) -> None:
        with Stream(b"Hello, world!\r\n--:") as stream:
            d = HeadersDictProxy(CIMultiDict())
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            result = await obj.read()
            assert b"Hello, world!" == result
            assert b"--:" == (await stream.read())

    async def test_multiread(self) -> None:
        with Stream(b"Hello,\r\n--:\r\n\r\nworld!\r\n--:--") as stream:
            d = HeadersDictProxy(CIMultiDict())
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            result = await obj.read()
            assert b"Hello," == result
            result = await obj.read()
            assert b"" == result
            assert obj.at_eof()

    async def test_read_multiline(self) -> None:
        with Stream(b"Hello\n,\r\nworld!\r\n--:--") as stream:
            d = HeadersDictProxy(CIMultiDict())
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            result = await obj.read()
            assert b"Hello\n,\r\nworld!" == result
            result = await obj.read()
            assert b"" == result
            assert obj.at_eof()

    async def test_read_respects_content_length(self) -> None:
        h = HeadersDictProxy(CIMultiDict({"CONTENT-LENGTH": "100500"}))
        with Stream(b"." * 100500 + b"\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = await obj.read()
            assert b"." * 100500 == result
            assert obj.at_eof()

    async def test_read_with_content_encoding_gzip(self) -> None:
        h = HeadersDictProxy(CIMultiDict({CONTENT_ENCODING: "gzip"}))
        with Stream(
            b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x0b\xc9\xccMU"
            b"(\xc9W\x08J\xcdI\xacP\x04\x00$\xfb\x9eV\x0e\x00\x00\x00"
            b"\r\n--:--"
        ) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = await obj.read(decode=True)
        assert b"Time to Relax!" == result

    async def test_read_with_content_encoding_deflate(self) -> None:
        content = b"A" * 1_000_000  # Large enough to exceed max_length.
        compressed = ZLibBackend.compress(content, wbits=-ZLibBackend.MAX_WBITS)

        h = HeadersDictProxy(CIMultiDict({CONTENT_ENCODING: "deflate"}))
        with Stream(compressed + b"\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = await obj.read(decode=True)
        assert len(result) == len(content)  # Simplifies diff on failure
        assert result == content

    async def test_read_with_content_encoding_identity(self) -> None:
        thing = (
            b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x0b\xc9\xccMU"
            b"(\xc9W\x08J\xcdI\xacP\x04\x00$\xfb\x9eV\x0e\x00\x00\x00"
            b"\r\n"
        )
        h = HeadersDictProxy(CIMultiDict({CONTENT_ENCODING: "identity"}))
        with Stream(thing + b"--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = await obj.read(decode=True)
        assert thing[:-2] == result

    async def test_read_with_content_encoding_unknown(self) -> None:
        h = HeadersDictProxy(CIMultiDict({CONTENT_ENCODING: "snappy"}))
        with Stream(b"\x0e4Time to Relax!\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            with pytest.raises(RuntimeError):
                await obj.read(decode=True)

    async def test_read_decode_compressed_exceeds_max_size(self) -> None:
        # Compressed data is small, but decompresses beyond client_max_size.
        original = b"A" * 1024
        compressed = gzip.compress(original)
        h = HeadersDictProxy(CIMultiDict({CONTENT_ENCODING: "gzip"}))
        with Stream(compressed + b"\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(
                BOUNDARY,
                h,
                stream,
                client_max_size=256,
                max_size_error_cls=HTTPRequestEntityTooLarge,
            )
            with pytest.raises(HTTPRequestEntityTooLarge):
                await obj.read(decode=True)

    async def test_read_with_content_transfer_encoding_base64(self) -> None:
        h = HeadersDictProxy(CIMultiDict({CONTENT_TRANSFER_ENCODING: "base64"}))
        with Stream(b"VGltZSB0byBSZWxheCE=\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = await obj.read(decode=True)
        assert b"Time to Relax!" == result

    async def test_decode_with_content_transfer_encoding_base64(self) -> None:
        h = HeadersDictProxy(CIMultiDict({CONTENT_TRANSFER_ENCODING: "base64"}))
        with Stream(b"VG\r\r\nltZSB0byBSZ\r\nWxheCE=\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = b""
            while not obj.at_eof():
                chunk = await obj.read_chunk(size=8)
                result += obj.decode(chunk)
        assert b"Time to Relax!" == result

    async def test_decode_iter_with_content_transfer_encoding_base64(self) -> None:
        h = HeadersDictProxy(CIMultiDict({CONTENT_TRANSFER_ENCODING: "base64"}))
        with Stream(b"VG\r\r\nltZSB0byBSZ\r\nWxheCE=\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = b""
            while not obj.at_eof():
                chunk = await obj.read_chunk(size=8)
                async for decoded_chunk in obj.decode_iter(chunk):
                    result += decoded_chunk
        assert b"Time to Relax!" == result

    async def test_read_chunk_base64_content_length_no_overread(self) -> None:
        # A base64 part whose Content-Length is not a multiple of 4 must not
        # let the base64 realignment loop read past the declared length into
        # the boundary and the parts that follow (regression for a negative
        # `_read_chunk_from_length` chunk_size / StreamReader.read(-1) bypass
        # of client_max_size).
        b64 = b"VGltZSB0byBSZWxheCE"  # 19 chars, 19 % 4 == 3 (unpadded)
        secret = b"secret-from-next-part"
        rest = b"\r\n--:\r\nContent-Length: %d\r\n\r\n%s\r\n--:--\r\n" % (
            len(secret),
            secret,
        )
        h = HeadersDictProxy(
            CIMultiDict(
                {"CONTENT-LENGTH": str(len(b64)), CONTENT_TRANSFER_ENCODING: "base64"}
            )
        )
        with Stream(b64 + rest) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            chunk = await obj.read_chunk(8192)
            assert chunk == b64
            assert obj.at_eof()
            assert secret not in chunk
            # The following part is left intact on the stream.
            assert secret in await stream.read()

    async def test_read_chunk_base64_bounded_by_requested_size(self) -> None:
        # Whole quartets are handed back and the trailing partial quartet is
        # carried into the next read, so size acts as a cap rather than a
        # starting point. The carry is subtracted from the next read instead
        # of being pushed back, so nothing accumulates over a long part: the
        # lookahead would otherwise gain a couple of bytes on every call.
        payload = b"x" * 8192
        h = HeadersDictProxy(CIMultiDict({CONTENT_TRANSFER_ENCODING: "base64"}))
        body = base64.encodebytes(payload).replace(b"\n", b"\r\n")
        with Stream(body + b"\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            decoded = b""
            chunks = []
            carried = 0
            while not obj.at_eof():
                chunks.append(await obj.read_chunk(64))
                decoded += obj.decode(chunks[-1])
                carried += bool(obj._b64_carry)
                assert len(obj._prev_chunk or b"") <= 64
                assert len(obj._b64_carry) < 64
        assert decoded == payload
        assert all(len(c) <= 64 for c in chunks[:-1])
        # The bound above is only meaningful if the carry is exercised, and
        # over enough calls for a per-call drift to become visible.
        assert len(chunks) > 100
        assert carried > len(chunks) // 2

    async def test_read_chunk_base64_padding_run_does_not_amplify(self) -> None:
        # A part padded with a long run of insignificant bytes used to make a
        # single call swallow the whole run. Such a run holds no whole quartet,
        # so this covers the branch that hands the chunk straight back: it must
        # still cap the chunk at the size asked for, and must hand back
        # something every time so callers looping on a truthy chunk make
        # progress. Nothing is carried here, so this says nothing about the
        # deferral path -- that is bounded by
        # test_read_chunk_base64_bounded_by_requested_size.
        h = HeadersDictProxy(CIMultiDict({CONTENT_TRANSFER_ENCODING: "base64"}))
        body = b"A" + b" " * (64 * 1024) + b"BBB\r\n--:--"
        with Stream(body) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            while not obj.at_eof():
                chunk = await obj.read_chunk(8192)
                assert chunk
                assert len(chunk) <= 8192

    async def test_read_chunk_base64_length_delimited_carries_quartet(self) -> None:
        # A length-delimited part has no lookahead (_prev_chunk stays None), so
        # this covers carrying a partial quartet on that path. The carry is
        # subtracted from the next read, which the Content-Length accounting
        # has to agree with, or the part overruns its declared length and the
        # trailing CRLF check rejects it. Sizes are chosen to land mid-quartet.
        payload = b"z" * 300
        b64 = base64.b64encode(payload)
        h = HeadersDictProxy(
            CIMultiDict(
                {"CONTENT-LENGTH": str(len(b64)), CONTENT_TRANSFER_ENCODING: "base64"}
            )
        )
        for size in (6, 7, 9, 13):
            with Stream(b64 + b"\r\n--:--") as stream:
                obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
                assert obj._prev_chunk is None
                decoded = b""
                carried = 0
                while not obj.at_eof():
                    decoded += obj.decode(await obj.read_chunk(size))
                    carried += bool(obj._b64_carry)
                assert decoded == payload, size
                # Guard against this quietly becoming a no-op: the point is
                # that the carry is exercised, not merely that reading works.
                assert carried > 10, (size, carried)

    @pytest.mark.parametrize("size", (5, 6, 7, 8))
    async def test_read_chunk_base64_small_size_carry_drains(self, size: int) -> None:
        # _read_chunk_from_stream refuses to read fewer than boundary_len
        # bytes, so for a size this small the carry cannot always be
        # subtracted from the next read. The chunk then has to be allowed over
        # size: capping it back would read more than it hands back on every
        # call, and the carry would climb without ever draining.
        payload = b"q" * 600
        h = HeadersDictProxy(CIMultiDict({CONTENT_TRANSFER_ENCODING: "base64"}))
        body = base64.encodebytes(payload).replace(b"\n", b"\r\n")
        with Stream(body + b"\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            decoded = b""
            while not obj.at_eof():
                decoded += obj.decode(await obj.read_chunk(size))
                assert len(obj._b64_carry) <= size + obj._boundary_len
        assert decoded == payload

    async def test_decode_with_content_encoding_deflate(self) -> None:
        h = HeadersDictProxy(CIMultiDict({CONTENT_ENCODING: "deflate"}))
        data = b"\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00"
        with Stream(data + b"\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            chunk = await obj.read_chunk(size=len(data))
            result = obj.decode(chunk)
        assert b"Time to Relax!" == result

    async def test_decode_with_content_encoding_identity(self) -> None:
        h = HeadersDictProxy(CIMultiDict({CONTENT_ENCODING: "identity"}))
        data = b"Time to Relax!"
        with Stream(data + b"\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            chunk = await obj.read_chunk(size=len(data))
            result = obj.decode(chunk)
        assert data == result

    async def test_decode_with_content_encoding_unknown(self) -> None:
        h = HeadersDictProxy(CIMultiDict({CONTENT_ENCODING: "snappy"}))
        data = b"Time to Relax!"
        with Stream(data + b"\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            chunk = await obj.read_chunk(size=len(data))
            with pytest.raises(RuntimeError, match="unknown content encoding"):
                obj.decode(chunk)

    async def test_read_with_content_transfer_encoding_quoted_printable(self) -> None:
        h = HeadersDictProxy(
            CIMultiDict({CONTENT_TRANSFER_ENCODING: "quoted-printable"})
        )
        with Stream(
            b"=D0=9F=D1=80=D0=B8=D0=B2=D0=B5=D1=82, =D0=BC=D0=B8=D1=80!\r\n--:--"
        ) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = await obj.read(decode=True)
        expected = (
            b"\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82,"
            b" \xd0\xbc\xd0\xb8\xd1\x80!"
        )
        assert result == expected

    @pytest.mark.parametrize("encoding", ("binary", "8bit", "7bit"))
    async def test_read_with_content_transfer_encoding_binary(
        self, encoding: str
    ) -> None:
        data = (
            b"\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82,"
            b" \xd0\xbc\xd0\xb8\xd1\x80!"
        )
        h = HeadersDictProxy(CIMultiDict({CONTENT_TRANSFER_ENCODING: encoding}))
        with Stream(data + b"\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = await obj.read(decode=True)
        assert data == result

    async def test_read_with_content_transfer_encoding_unknown(self) -> None:
        h = HeadersDictProxy(CIMultiDict({CONTENT_TRANSFER_ENCODING: "unknown"}))
        with Stream(b"\x0e4Time to Relax!\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            with pytest.raises(RuntimeError):
                await obj.read(decode=True)

    async def test_read_text(self) -> None:
        with Stream(b"Hello, world!\r\n--:--") as stream:
            d = HeadersDictProxy(CIMultiDict())
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            result = await obj.text()
        assert "Hello, world!" == result

    async def test_read_text_default_encoding(self) -> None:
        with Stream("Привет, Мир!\r\n--:--".encode()) as stream:
            d = HeadersDictProxy(CIMultiDict())
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            result = await obj.text()
        assert "Привет, Мир!" == result

    async def test_read_text_encoding(self) -> None:
        with Stream("Привет, Мир!\r\n--:--".encode("cp1251")) as stream:
            d = HeadersDictProxy(CIMultiDict())
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            result = await obj.text(encoding="cp1251")
        assert "Привет, Мир!" == result

    async def test_read_text_guess_encoding(self) -> None:
        h = HeadersDictProxy(CIMultiDict({CONTENT_TYPE: "text/plain;charset=cp1251"}))
        with Stream("Привет, Мир!\r\n--:--".encode("cp1251")) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = await obj.text()
        assert "Привет, Мир!" == result

    async def test_read_text_compressed(self) -> None:
        h = HeadersDictProxy(
            CIMultiDict({CONTENT_ENCODING: "deflate", CONTENT_TYPE: "text/plain"})
        )
        with Stream(b"\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = await obj.text()
        assert "Time to Relax!" == result

    async def test_read_text_while_closed(self) -> None:
        h = HeadersDictProxy(CIMultiDict({CONTENT_TYPE: "text/plain"}))
        with Stream(b"") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            obj._at_eof = True
            result = await obj.text()
        assert "" == result

    async def test_read_json(self) -> None:
        h = HeadersDictProxy(CIMultiDict({CONTENT_TYPE: "application/json"}))
        with Stream(b'{"test": "passed"}\r\n--:--') as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = await obj.json()
        assert {"test": "passed"} == result

    async def test_read_json_encoding(self) -> None:
        h = HeadersDictProxy(CIMultiDict({CONTENT_TYPE: "application/json"}))
        with Stream('{"тест": "пассед"}\r\n--:--'.encode("cp1251")) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = await obj.json(encoding="cp1251")
        assert {"тест": "пассед"} == result

    async def test_read_json_guess_encoding(self) -> None:
        h = HeadersDictProxy(
            CIMultiDict({CONTENT_TYPE: "application/json; charset=cp1251"})
        )
        with Stream('{"тест": "пассед"}\r\n--:--'.encode("cp1251")) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = await obj.json()
        assert {"тест": "пассед"} == result

    async def test_read_json_compressed(self) -> None:
        h = HeadersDictProxy(
            CIMultiDict({CONTENT_ENCODING: "deflate", CONTENT_TYPE: "application/json"})
        )
        with Stream(b"\xabV*I-.Q\xb2RP*H,.NMQ\xaa\x05\x00\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = await obj.json()
        assert {"test": "passed"} == result

    async def test_read_json_while_closed(self) -> None:
        h = HeadersDictProxy(CIMultiDict({CONTENT_TYPE: "application/json"}))
        with Stream(b"") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            obj._at_eof = True
            result = await obj.json()
        assert result is None

    async def test_read_form(self) -> None:
        h = HeadersDictProxy(
            CIMultiDict({CONTENT_TYPE: "application/x-www-form-urlencoded"})
        )
        with Stream(b"foo=bar&foo=baz&boo=\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = await obj.form()
        assert [("foo", "bar"), ("foo", "baz"), ("boo", "")] == result

    async def test_read_form_invalid_utf8(self) -> None:
        h = HeadersDictProxy(
            CIMultiDict({CONTENT_TYPE: "application/x-www-form-urlencoded"})
        )
        with Stream(b"\xff\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            with pytest.raises(
                ValueError, match="data cannot be decoded with utf-8 encoding"
            ):
                await obj.form()

    async def test_read_form_encoding(self) -> None:
        h = HeadersDictProxy(
            CIMultiDict({CONTENT_TYPE: "application/x-www-form-urlencoded"})
        )
        with Stream("foo=bar&foo=baz&boo=\r\n--:--".encode("cp1251")) as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = await obj.form(encoding="cp1251")
        assert [("foo", "bar"), ("foo", "baz"), ("boo", "")] == result

    async def test_read_form_guess_encoding(self) -> None:
        h = HeadersDictProxy(
            CIMultiDict(
                {CONTENT_TYPE: "application/x-www-form-urlencoded; charset=utf-8"}
            )
        )
        with Stream(b"foo=bar&foo=baz&boo=\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            result = await obj.form()
        assert [("foo", "bar"), ("foo", "baz"), ("boo", "")] == result

    async def test_read_form_while_closed(self) -> None:
        h = HeadersDictProxy(
            CIMultiDict({CONTENT_TYPE: "application/x-www-form-urlencoded"})
        )
        with Stream(b"") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            obj._at_eof = True
            result = await obj.form()
        assert not result

    async def test_readline(self) -> None:
        with Stream(b"Hello\n,\r\nworld!\r\n--:--") as stream:
            d = HeadersDictProxy(CIMultiDict())
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            result = await obj.readline()
            assert b"Hello\n" == result
            result = await obj.readline()
            assert b",\r\n" == result
            result = await obj.readline()
            assert b"world!" == result
            result = await obj.readline()
            assert b"" == result
            assert obj.at_eof()

    async def test_release(self) -> None:
        with Stream(b"Hello,\r\n--:\r\n\r\nworld!\r\n--:--") as stream:
            d = HeadersDictProxy(CIMultiDict())
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            await obj.release()
            assert obj.at_eof()
            assert b"--:\r\n\r\nworld!\r\n--:--" == stream.content.read()

    async def test_release_respects_content_length(self) -> None:
        h = HeadersDictProxy(CIMultiDict({"CONTENT-LENGTH": "100500"}))
        with Stream(b"." * 100500 + b"\r\n--:--") as stream:
            obj = aiohttp.BodyPartReader(BOUNDARY, h, stream)
            await obj.release()
            assert obj.at_eof()

    async def test_release_release(self) -> None:
        with Stream(b"Hello,\r\n--:\r\n\r\nworld!\r\n--:--") as stream:
            d = HeadersDictProxy(CIMultiDict())
            obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
            await obj.release()
            await obj.release()
            assert b"--:\r\n\r\nworld!\r\n--:--" == stream.content.read()

    async def test_filename(self) -> None:
        h = HeadersDictProxy(
            CIMultiDict({CONTENT_DISPOSITION: "attachment; filename=foo.html"})
        )
        part = aiohttp.BodyPartReader(BOUNDARY, h, mock.Mock())
        assert "foo.html" == part.filename

    async def test_reading_long_part(self) -> None:
        size = 2 * DEFAULT_CHUNK_SIZE
        protocol = mock.Mock(_reading_paused=False)
        stream = StreamReader(
            protocol, DEFAULT_CHUNK_SIZE, loop=asyncio.get_running_loop()
        )
        stream.feed_data(b"0" * size + b"\r\n--:--")
        stream.feed_eof()
        d = HeadersDictProxy(CIMultiDict())
        obj = aiohttp.BodyPartReader(BOUNDARY, d, stream)
        data = await obj.read()
        assert len(data) == size


class TestMultipartReader:
    def test_from_response(self) -> None:
        h = HeadersDictProxy(
            CIMultiDict({CONTENT_TYPE: 'multipart/related;boundary=":"'})
        )
        with Stream(b"--:\r\n\r\nhello\r\n--:--") as stream:
            resp = Response(h, stream)
            res = aiohttp.MultipartReader.from_response(resp)  # type: ignore[arg-type]
        assert isinstance(res, MultipartResponseWrapper)
        assert isinstance(res.stream, aiohttp.MultipartReader)

    def test_bad_boundary(self) -> None:
        h = HeadersDictProxy(
            CIMultiDict({CONTENT_TYPE: "multipart/related;boundary=" + "a" * 80})
        )
        with Stream(b"") as stream:
            resp = Response(h, stream)
            with pytest.raises(ValueError):
                aiohttp.MultipartReader.from_response(resp)  # type: ignore[arg-type]

    def test_dispatch(self) -> None:
        h = HeadersDictProxy(CIMultiDict({CONTENT_TYPE: "text/plain"}))
        with Stream(b"--:\r\n\r\necho\r\n--:--") as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            res = reader._get_part_reader(h)
        assert isinstance(res, reader.part_reader_cls)

    def test_dispatch_bodypart(self) -> None:
        h = HeadersDictProxy(CIMultiDict({CONTENT_TYPE: "text/plain"}))
        with Stream(b"--:\r\n\r\necho\r\n--:--") as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            res = reader._get_part_reader(h)
        assert isinstance(res, reader.part_reader_cls)

    def test_dispatch_multipart(self) -> None:
        h = HeadersDictProxy(
            CIMultiDict({CONTENT_TYPE: "multipart/related;boundary=--:--"})
        )
        with Stream(
            b"----:--\r\n"
            b"\r\n"
            b"test\r\n"
            b"----:--\r\n"
            b"\r\n"
            b"passed\r\n"
            b"----:----\r\n"
            b"--:--"
        ) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            res = reader._get_part_reader(h)
        assert isinstance(res, reader.__class__)

    def test_dispatch_custom_multipart_reader(self) -> None:
        class CustomReader(aiohttp.MultipartReader):
            pass

        h = HeadersDictProxy(
            CIMultiDict({CONTENT_TYPE: "multipart/related;boundary=--:--"})
        )
        with Stream(
            b"----:--\r\n"
            b"\r\n"
            b"test\r\n"
            b"----:--\r\n"
            b"\r\n"
            b"passed\r\n"
            b"----:----\r\n"
            b"--:--"
        ) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            reader.multipart_reader_cls = CustomReader
            res = reader._get_part_reader(h)
        assert isinstance(res, CustomReader)

    async def test_emit_next(self) -> None:
        h = HeadersDictProxy(
            CIMultiDict({CONTENT_TYPE: 'multipart/related;boundary=":"'})
        )
        with Stream(b"--:\r\n\r\necho\r\n--:--") as stream:
            reader = aiohttp.MultipartReader(h, stream)
            res = await reader.next()
        assert isinstance(res, reader.part_reader_cls)

    async def test_invalid_boundary(self) -> None:
        with Stream(b"---:\r\n\r\necho\r\n---:--") as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            with pytest.raises(ValueError):
                await reader.next()

    async def test_read_boundary_across_chunks(self) -> None:
        class SplitBoundaryStream(StreamReader):
            def __init__(self) -> None:
                self.content = [
                    b"--foobar\r\n\r\n",
                    b"Hello,\r\n-",
                    b"-fo",
                    b"ob",
                    b"ar\r\n",
                    b"\r\nwor",
                    b"ld!",
                    b"\r\n--f",
                    b"oobar--",
                ]

            async def read(self, size: int | None = None) -> bytes:
                chunk = self.content.pop(0)
                assert size is not None and len(chunk) <= size
                return chunk

            def at_eof(self) -> bool:
                return not self.content

            async def readline(self, *, max_line_length: int | None = None) -> bytes:
                line = b""
                while self.content and b"\n" not in line:
                    line += self.content.pop(0)
                line, *extra = line.split(b"\n", maxsplit=1)
                if extra and extra[0]:
                    self.content.insert(0, extra[0])
                return line + b"\n"

            def unread_data(self, data: bytes) -> None:
                if self.content:
                    self.content[0] = data + self.content[0]
                else:
                    self.content.append(data)

        stream = SplitBoundaryStream()
        reader = aiohttp.MultipartReader(
            {CONTENT_TYPE: 'multipart/related;boundary="foobar"'}, stream
        )
        part = await anext(reader)
        assert isinstance(part, BodyPartReader)
        result = await part.read_chunk(10)
        assert result == b"Hello,"
        result = await part.read_chunk(10)
        assert result == b""
        assert part.at_eof()

        part = await anext(reader)
        assert isinstance(part, BodyPartReader)
        result = await part.read_chunk(10)
        assert result == b"world!"
        result = await part.read_chunk(10)
        assert result == b""
        assert part.at_eof()

        with pytest.raises(StopAsyncIteration):
            await anext(reader)

    async def test_release(self) -> None:
        with Stream(
            b"--:\r\n"
            b"Content-Type: multipart/related;boundary=--:--\r\n"
            b"\r\n"
            b"----:--\r\n"
            b"\r\n"
            b"test\r\n"
            b"----:--\r\n"
            b"\r\n"
            b"passed\r\n"
            b"----:----\r\n"
            b"\r\n"
            b"--:--"
        ) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/mixed;boundary=":"'},
                stream,
            )
            await reader.release()
            assert reader.at_eof()

    async def test_release_release(self) -> None:
        with Stream(b"--:\r\n\r\necho\r\n--:--") as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            await reader.release()
            assert reader.at_eof()
            await reader.release()
            assert reader.at_eof()

    async def test_release_next(self) -> None:
        with Stream(b"--:\r\n\r\necho\r\n--:--") as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            await reader.release()
            assert reader.at_eof()
            res = await reader.next()
            assert res is None

    async def test_second_next_releases_previous_object(self) -> None:
        with Stream(b"--:\r\n\r\ntest\r\n--:\r\n\r\npassed\r\n--:--") as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            first = await reader.next()
            assert isinstance(first, aiohttp.BodyPartReader)
            second = await reader.next()
            assert second is not None
            assert first.at_eof()
            assert not second.at_eof()

    async def test_release_without_read_the_last_object(self) -> None:
        with Stream(b"--:\r\n\r\ntest\r\n--:\r\n\r\npassed\r\n--:--") as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            first = await reader.next()
            second = await reader.next()
            third = await reader.next()

            assert first is not None
            assert second is not None
            assert first.at_eof()
            assert second.at_eof()
            assert second.at_eof()
            assert third is None

    async def test_read_chunk_by_length_doesnt_break_reader(self) -> None:
        with Stream(
            b"--:\r\n"
            b"Content-Length: 4\r\n\r\n"
            b"test"
            b"\r\n--:\r\n"
            b"Content-Length: 6\r\n\r\n"
            b"passed"
            b"\r\n--:--"
        ) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            body_parts = []
            while True:
                read_part = b""
                part = await reader.next()
                if part is None:
                    break
                assert isinstance(part, BodyPartReader)
                while not part.at_eof():
                    read_part += await part.read_chunk(3)
                body_parts.append(read_part)

        assert body_parts == [b"test", b"passed"]

    async def test_read_chunk_from_stream_doesnt_break_reader(self) -> None:
        with Stream(
            b"--:\r\n"
            b"\r\n"
            b"chunk"
            b"\r\n--:\r\n"
            b"\r\n"
            b"two_chunks"
            b"\r\n--:--"
        ) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            body_parts = []
            while True:
                read_part = b""
                part = await reader.next()
                if part is None:
                    break
                assert isinstance(part, BodyPartReader)
                while not part.at_eof():
                    chunk = await part.read_chunk(5)
                    assert chunk
                    read_part += chunk
                body_parts.append(read_part)

        assert body_parts == [b"chunk", b"two_chunks"]

    async def test_reading_skips_prelude(self) -> None:
        with Stream(
            b"Multi-part data is not supported.\r\n"
            b"\r\n"
            b"--:\r\n"
            b"\r\n"
            b"test\r\n"
            b"--:\r\n"
            b"\r\n"
            b"passed\r\n"
            b"--:--"
        ) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            first = await reader.next()
            assert isinstance(first, aiohttp.BodyPartReader)
            second = await reader.next()

            assert isinstance(second, BodyPartReader)
            assert first.at_eof()
            assert not second.at_eof()

    async def test_read_empty_body_part(self) -> None:
        with Stream(b"--:\r\n\r\n--:--") as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            body_parts = []
            async for part in reader:
                assert isinstance(part, BodyPartReader)
                body_parts.append(await part.read())

        assert body_parts == [b""]

    async def test_read_body_part_headers_only(self) -> None:
        with Stream(b"--:\r\nContent-Type: text/plain\r\n\r\n--:--") as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/related;boundary=":"'},
                stream,
            )
            body_parts = []
            async for part in reader:
                assert isinstance(part, BodyPartReader)
                assert "Content-Type" in part.headers
                body_parts.append(await part.read())

        assert body_parts == [b""]

    async def test_read_form_default_encoding(self) -> None:
        with Stream(
            b"--:\r\n"
            b'Content-Disposition: form-data; name="_charset_"\r\n\r\n'
            b"ascii"
            b"\r\n"
            b"--:\r\n"
            b'Content-Disposition: form-data; name="field1"\r\n\r\n'
            b"foo"
            b"\r\n"
            b"--:\r\n"
            b"Content-Type: text/plain;charset=UTF-8\r\n"
            b'Content-Disposition: form-data; name="field2"\r\n\r\n'
            b"foo"
            b"\r\n"
            b"--:\r\n"
            b'Content-Disposition: form-data; name="field3"\r\n\r\n'
            b"foo"
            b"\r\n"
        ) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/form-data;boundary=":"'},
                stream,
            )
            field1 = await reader.next()
            assert isinstance(field1, BodyPartReader)
            assert field1.name == "field1"
            assert field1.get_charset("default") == "ascii"
            field2 = await reader.next()
            assert isinstance(field2, BodyPartReader)
            assert field2.name == "field2"
            assert field2.get_charset("default") == "UTF-8"
            field3 = await reader.next()
            assert isinstance(field3, BodyPartReader)
            assert field3.name == "field3"
            assert field3.get_charset("default") == "ascii"

    async def test_read_form_invalid_default_encoding(self) -> None:
        with Stream(
            b"--:\r\n"
            b'Content-Disposition: form-data; name="_charset_"\r\n\r\n'
            b"this-value-is-too-long-to-be-a-charset"
            b"\r\n"
            b"--:\r\n"
            b'Content-Disposition: form-data; name="field1"\r\n\r\n'
            b"foo"
            b"\r\n"
        ) as stream:
            reader = aiohttp.MultipartReader(
                {CONTENT_TYPE: 'multipart/form-data;boundary=":"'},
                stream,
            )
            with pytest.raises(RuntimeError, match="Invalid default charset"):
                await reader.next()


async def test_writer(writer: aiohttp.MultipartWriter) -> None:
    assert writer.size == 7
    assert writer.boundary == ":"


async def test_writer_serialize_io_chunk(
    buf: bytearray, stream: AbstractStreamWriter, writer: aiohttp.MultipartWriter
) -> None:
    with io.BytesIO(b"foobarbaz") as file_handle:
        writer.append(file_handle)
        await writer.write(stream)
    assert (
        buf == b"--:\r\nContent-Type: application/octet-stream"
        b"\r\nContent-Length: 9\r\n\r\nfoobarbaz\r\n--:--\r\n"
    )


async def test_writer_serialize_json(
    buf: bytearray, stream: AbstractStreamWriter, writer: aiohttp.MultipartWriter
) -> None:
    writer.append_json({"привет": "мир"})
    await writer.write(stream)
    assert (
        b'{"\\u043f\\u0440\\u0438\\u0432\\u0435\\u0442":'
        b' "\\u043c\\u0438\\u0440"}' in buf
    )


async def test_writer_serialize_form(
    buf: bytearray, stream: AbstractStreamWriter, writer: aiohttp.MultipartWriter
) -> None:
    data = [("foo", "bar"), ("foo", "baz"), ("boo", "zoo")]
    writer.append_form(data)
    await writer.write(stream)

    assert b"foo=bar&foo=baz&boo=zoo" in buf


async def test_writer_serialize_form_dict(
    buf: bytearray, stream: AbstractStreamWriter, writer: aiohttp.MultipartWriter
) -> None:
    data = {"hello": "мир"}
    writer.append_form(data)
    await writer.write(stream)

    assert b"hello=%D0%BC%D0%B8%D1%80" in buf


async def test_writer_write(
    buf: bytearray, stream: AbstractStreamWriter, writer: aiohttp.MultipartWriter
) -> None:
    writer.append("foo-bar-baz")
    writer.append_json({"test": "passed"})
    writer.append_form({"test": "passed"})
    writer.append_form([("one", "1"), ("two", "2")])

    sub_multipart = aiohttp.MultipartWriter(boundary="::")
    sub_multipart.append("nested content")
    sub_multipart.headers["X-CUSTOM"] = "test"
    writer.append(sub_multipart)
    await writer.write(stream)

    assert (
        b"--:\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Length: 11\r\n\r\n"
        b"foo-bar-baz"
        b"\r\n"
        b"--:\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 18\r\n\r\n"
        b'{"test": "passed"}'
        b"\r\n"
        b"--:\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 11\r\n\r\n"
        b"test=passed"
        b"\r\n"
        b"--:\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 11\r\n\r\n"
        b"one=1&two=2"
        b"\r\n"
        b"--:\r\n"
        b'Content-Type: multipart/mixed; boundary="::"\r\n'
        b"X-CUSTOM: test\r\nContent-Length: 93\r\n\r\n"
        b"--::\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Length: 14\r\n\r\n"
        b"nested content\r\n"
        b"--::--\r\n"
        b"\r\n"
        b"--:--\r\n"
    ) == bytes(buf)


async def test_writer_write_no_close_boundary(
    buf: bytearray, stream: AbstractStreamWriter
) -> None:
    writer = aiohttp.MultipartWriter(boundary=":")
    writer.append("foo-bar-baz")
    writer.append_json({"test": "passed"})
    writer.append_form({"test": "passed"})
    writer.append_form([("one", "1"), ("two", "2")])
    await writer.write(stream, close_boundary=False)

    assert (
        b"--:\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Length: 11\r\n\r\n"
        b"foo-bar-baz"
        b"\r\n"
        b"--:\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 18\r\n\r\n"
        b'{"test": "passed"}'
        b"\r\n"
        b"--:\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 11\r\n\r\n"
        b"test=passed"
        b"\r\n"
        b"--:\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 11\r\n\r\n"
        b"one=1&two=2"
        b"\r\n"
    ) == bytes(buf)


async def test_writer_write_no_parts(
    buf: bytearray, stream: AbstractStreamWriter, writer: aiohttp.MultipartWriter
) -> None:
    await writer.write(stream)
    assert b"--:--\r\n" == bytes(buf)


@pytest.mark.usefixtures("parametrize_zlib_backend")
async def test_writer_serialize_with_content_encoding_gzip(
    buf: bytearray,
    stream: AbstractStreamWriter,
    writer: aiohttp.MultipartWriter,
) -> None:
    writer.append("Time to Relax!", {CONTENT_ENCODING: "gzip"})
    await writer.write(stream)
    headers, message = bytes(buf).split(b"\r\n\r\n", 1)

    assert (
        b"--:\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Encoding: gzip" == headers
    )

    decompressor = ZLibBackend.decompressobj(wbits=16 + ZLibBackend.MAX_WBITS)
    data = decompressor.decompress(message.split(b"\r\n")[0])
    data += decompressor.flush()
    assert b"Time to Relax!" == data


async def test_writer_serialize_with_content_encoding_deflate(
    buf: bytearray, stream: AbstractStreamWriter, writer: aiohttp.MultipartWriter
) -> None:
    writer.append("Time to Relax!", {CONTENT_ENCODING: "deflate"})
    await writer.write(stream)
    headers, message = bytes(buf).split(b"\r\n\r\n", 1)

    assert (
        b"--:\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Encoding: deflate" == headers
    )

    thing = b"\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00\r\n--:--\r\n"
    assert thing == message


async def test_writer_serialize_with_content_encoding_identity(
    buf: bytearray, stream: AbstractStreamWriter, writer: aiohttp.MultipartWriter
) -> None:
    thing = b"\x0b\xc9\xccMU(\xc9W\x08J\xcdI\xacP\x04\x00"
    writer.append(thing, {CONTENT_ENCODING: "identity"})
    await writer.write(stream)
    headers, message = bytes(buf).split(b"\r\n\r\n", 1)

    assert (
        b"--:\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Encoding: identity\r\n"
        b"Content-Length: 16" == headers
    )

    assert thing == message.split(b"\r\n")[0]


def test_writer_serialize_with_content_encoding_unknown(
    buf: bytearray, stream: AbstractStreamWriter, writer: aiohttp.MultipartWriter
) -> None:
    with pytest.raises(RuntimeError):
        writer.append("Time to Relax!", {CONTENT_ENCODING: "snappy"})


async def test_writer_with_content_transfer_encoding_base64(
    buf: bytearray, stream: AbstractStreamWriter, writer: aiohttp.MultipartWriter
) -> None:
    writer.append("Time to Relax!", {CONTENT_TRANSFER_ENCODING: "base64"})
    await writer.write(stream)
    headers, message = bytes(buf).split(b"\r\n\r\n", 1)

    assert (
        b"--:\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64" == headers
    )

    assert b"VGltZSB0byBSZWxheCE=" == message.split(b"\r\n")[0]


async def test_writer_content_transfer_encoding_quote_printable(
    buf: bytearray, stream: AbstractStreamWriter, writer: aiohttp.MultipartWriter
) -> None:
    writer.append("Привет, мир!", {CONTENT_TRANSFER_ENCODING: "quoted-printable"})
    await writer.write(stream)
    headers, message = bytes(buf).split(b"\r\n\r\n", 1)

    assert (
        b"--:\r\nContent-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: quoted-printable" == headers
    )

    assert (
        b"=D0=9F=D1=80=D0=B8=D0=B2=D0=B5=D1=82,"
        b" =D0=BC=D0=B8=D1=80!" == message.split(b"\r\n")[0]
    )


def test_writer_content_transfer_encoding_unknown(
    buf: bytearray, stream: AbstractStreamWriter, writer: aiohttp.MultipartWriter
) -> None:
    with pytest.raises(RuntimeError):
        writer.append("Time to Relax!", {CONTENT_TRANSFER_ENCODING: "unknown"})


class TestMultipartWriter:
    def test_default_subtype(self, writer: aiohttp.MultipartWriter) -> None:
        mimetype = parse_mimetype(writer.headers.get(CONTENT_TYPE))

        assert "multipart" == mimetype.type
        assert "mixed" == mimetype.subtype

    def test_unquoted_boundary(self) -> None:
        writer = aiohttp.MultipartWriter(boundary="abc123")
        expected = {CONTENT_TYPE: "multipart/mixed; boundary=abc123"}
        assert expected == writer.headers

    def test_quoted_boundary(self) -> None:
        writer = aiohttp.MultipartWriter(boundary=R"\"")
        expected = {CONTENT_TYPE: R'multipart/mixed; boundary="\\\""'}
        assert expected == writer.headers

    def test_bad_boundary(self) -> None:
        with pytest.raises(ValueError):
            aiohttp.MultipartWriter(boundary="тест")
        with pytest.raises(ValueError):
            aiohttp.MultipartWriter(boundary="test\n")
        with pytest.raises(ValueError):
            aiohttp.MultipartWriter(boundary="X" * 71)

    def test_default_headers(self, writer: aiohttp.MultipartWriter) -> None:
        expected = {CONTENT_TYPE: 'multipart/mixed; boundary=":"'}
        assert expected == writer.headers

    def test_iter_parts(self, writer: aiohttp.MultipartWriter) -> None:
        writer.append("foo")
        writer.append("bar")
        writer.append("baz")
        assert 3 == len(list(writer))

    def test_append(self, writer: aiohttp.MultipartWriter) -> None:
        assert 0 == len(writer)
        writer.append("hello, world!")
        assert 1 == len(writer)
        assert isinstance(writer._parts[0][0], payload.Payload)

    def test_append_with_headers(self, writer: aiohttp.MultipartWriter) -> None:
        writer.append("hello, world!", {"x-foo": "bar"})
        assert 1 == len(writer)
        assert "x-foo" in writer._parts[0][0].headers
        assert writer._parts[0][0].headers["x-foo"] == "bar"

    def test_append_json(self, writer: aiohttp.MultipartWriter) -> None:
        writer.append_json({"foo": "bar"})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == "application/json"

    def test_append_part(self, writer: aiohttp.MultipartWriter) -> None:
        part = payload.get_payload("test", headers={CONTENT_TYPE: "text/plain"})
        writer.append(part, {CONTENT_TYPE: "test/passed"})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == "test/passed"

    def test_append_json_overrides_content_type(
        self, writer: aiohttp.MultipartWriter
    ) -> None:
        writer.append_json({"foo": "bar"}, {CONTENT_TYPE: "test/passed"})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == "test/passed"

    def test_append_form(self, writer: aiohttp.MultipartWriter) -> None:
        writer.append_form({"foo": "bar"}, {CONTENT_TYPE: "test/passed"})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == "test/passed"

    def test_append_multipart(self, writer: aiohttp.MultipartWriter) -> None:
        subwriter = aiohttp.MultipartWriter(boundary=":")
        subwriter.append_json({"foo": "bar"})
        writer.append(subwriter, {CONTENT_TYPE: "test/passed"})
        assert 1 == len(writer)
        part = writer._parts[0][0]
        assert part.headers[CONTENT_TYPE] == "test/passed"

    def test_set_content_disposition_after_append(self) -> None:
        writer = aiohttp.MultipartWriter("form-data")
        part = writer.append("some-data")
        part.set_content_disposition("form-data", name="method")
        assert 'name="method"' in part.headers[CONTENT_DISPOSITION]

    def test_automatic_content_disposition(self) -> None:
        writer = aiohttp.MultipartWriter("form-data")
        writer.append_json(())
        part = payload.StringPayload("foo")
        part.set_content_disposition("form-data", name="second")
        writer.append_payload(part)
        writer.append("foo")

        disps = tuple(p[0].headers[CONTENT_DISPOSITION] for p in writer._parts)
        assert 'name="section-0"' in disps[0]
        assert 'name="second"' in disps[1]
        assert 'name="section-2"' in disps[2]

    def test_with(self) -> None:
        with aiohttp.MultipartWriter(boundary=":") as writer:
            writer.append("foo")
            writer.append(b"bar")
            writer.append_json({"baz": True})
        assert 3 == len(writer)

    def test_append_int_not_allowed(self) -> None:
        with pytest.raises(TypeError):
            with aiohttp.MultipartWriter(boundary=":") as writer:
                writer.append(1)

    def test_append_float_not_allowed(self) -> None:
        with pytest.raises(TypeError):
            with aiohttp.MultipartWriter(boundary=":") as writer:
                writer.append(1.1)

    def test_append_none_not_allowed(self) -> None:
        with pytest.raises(TypeError):
            with aiohttp.MultipartWriter(boundary=":") as writer:
                writer.append(None)

    async def test_write_preserves_content_disposition(
        self, buf: bytearray, stream: AbstractStreamWriter
    ) -> None:
        with aiohttp.MultipartWriter(boundary=":") as writer:
            part = writer.append(b"foo", headers={CONTENT_TYPE: "test/passed"})
            part.set_content_disposition("form-data", filename="bug")
        await writer.write(stream)

        headers, message = bytes(buf).split(b"\r\n\r\n", 1)

        assert headers == (
            b"--:\r\n"
            b"Content-Type: test/passed\r\n"
            b"Content-Length: 3\r\n"
            b"Content-Disposition:"
            b' form-data; filename="bug"'
        )
        assert message == b"foo\r\n--:--\r\n"

    async def test_preserve_content_disposition_header(
        self, buf: bytearray, stream: AbstractStreamWriter
    ) -> None:
        # https://github.com/aio-libs/aiohttp/pull/3475#issuecomment-451072381
        with pathlib.Path(__file__).open("rb") as fobj:
            with aiohttp.MultipartWriter("form-data", boundary=":") as writer:
                part = writer.append(
                    fobj,
                    headers={
                        CONTENT_DISPOSITION: 'attachments; filename="bug.py"',
                        CONTENT_TYPE: "text/python",
                    },
                )
            await writer.write(stream)

        assert part.headers[CONTENT_TYPE] == "text/python"
        assert part.headers[CONTENT_DISPOSITION] == ('attachments; filename="bug.py"')

        headers, _ = bytes(buf).split(b"\r\n\r\n", 1)

        assert headers == (
            b"--:\r\n"
            b"Content-Type: text/python\r\n"
            b'Content-Disposition: attachments; filename="bug.py"'
        )

    async def test_set_content_disposition_override(
        self, buf: bytearray, stream: AbstractStreamWriter
    ) -> None:
        # https://github.com/aio-libs/aiohttp/pull/3475#issuecomment-451072381
        with pathlib.Path(__file__).open("rb") as fobj:
            with aiohttp.MultipartWriter("form-data", boundary=":") as writer:
                part = writer.append(
                    fobj,
                    headers={
                        CONTENT_DISPOSITION: 'attachments; filename="bug.py"',
                        CONTENT_TYPE: "text/python",
                    },
                )
            await writer.write(stream)

        assert part.headers[CONTENT_TYPE] == "text/python"
        assert part.headers[CONTENT_DISPOSITION] == ('attachments; filename="bug.py"')

        headers, _ = bytes(buf).split(b"\r\n\r\n", 1)

        assert headers == (
            b"--:\r\n"
            b"Content-Type: text/python\r\n"
            b'Content-Disposition: attachments; filename="bug.py"'
        )

    async def test_reset_content_disposition_header(
        self, buf: bytearray, stream: AbstractStreamWriter
    ) -> None:
        # https://github.com/aio-libs/aiohttp/pull/3475#issuecomment-451072381
        with pathlib.Path(__file__).open("rb") as fobj:
            with aiohttp.MultipartWriter("form-data", boundary=":") as writer:
                part = writer.append(
                    fobj,
                    headers={CONTENT_TYPE: "text/plain"},
                )

            assert CONTENT_DISPOSITION in part.headers

            part.set_content_disposition("attachments", filename="bug.py")

            await writer.write(stream)

        headers, _ = bytes(buf).split(b"\r\n\r\n", 1)

        assert headers == (
            b"--:\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Disposition:"
            b' attachments; filename="bug.py"'
        )


async def test_async_for_reader() -> None:
    data: tuple[dict[str, str], int, bytes, bytes, bytes] = (
        {"test": "passed"},
        42,
        b"plain text",
        b"aiohttp\n",
        b"no epilogue",
    )
    with Stream(
        b"\r\n".join(
            [
                b"--:",
                b"Content-Type: application/json",
                b"",
                json.dumps(data[0]).encode(),
                b"--:",
                b"Content-Type: application/json",
                b"",
                json.dumps(data[1]).encode(),
                b"--:",
                b'Content-Type: multipart/related; boundary="::"',
                b"",
                b"--::",
                b"Content-Type: text/plain",
                b"",
                data[2],
                b"--::",
                b'Content-Disposition: attachment; filename="aiohttp"',
                b"Content-Type: text/plain",
                b"Content-Length: 28",
                b"Content-Encoding: gzip",
                b"",
                b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03K\xcc\xcc\xcf())"
                b"\xe0\x02\x00\xd6\x90\xe2O\x08\x00\x00\x00",
                b"--::",
                b'Content-Type: multipart/related; boundary=":::"',
                b"",
                b"--:::",
                b"Content-Type: text/plain",
                b"",
                data[4],
                b"--:::--",
                b"--::--",
                b"",
                b"--:--",
                b"",
            ]
        )
    ) as stream:
        reader = aiohttp.MultipartReader(
            headers={CONTENT_TYPE: 'multipart/mixed; boundary=":"'},
            content=stream,
        )
        idata = iter(data)

        async def check(reader: aiohttp.MultipartReader) -> None:
            async for part in reader:
                assert part is not None
                if isinstance(part, aiohttp.BodyPartReader):
                    if part.headers[CONTENT_TYPE] == "application/json":
                        assert next(idata) == (await part.json())
                    else:
                        assert next(idata) == await part.read(decode=True)
                else:
                    await check(part)

        await check(reader)


async def test_async_for_bodypart() -> None:
    h = HeadersDictProxy(CIMultiDict())
    with Stream(b"foobarbaz\r\n--:--") as stream:
        part = aiohttp.BodyPartReader(boundary=b"--:", headers=h, content=stream)
        async for data in part:
            assert data == b"foobarbaz"


async def test_multipart_writer_reusability(
    buf: bytearray,
    stream: mock.Mock,
    buf2: bytearray,
    stream2: mock.Mock,
    writer: aiohttp.MultipartWriter,
) -> None:
    """Test that MultipartWriter can be written multiple times."""
    # Add some parts
    writer.append("text content")
    writer.append(b"binary content", {"Content-Type": "application/octet-stream"})
    writer.append_json({"key": "value"})

    # Test as_bytes multiple times
    bytes1 = await writer.as_bytes()
    bytes2 = await writer.as_bytes()
    bytes3 = await writer.as_bytes()

    # All as_bytes calls should return identical data
    assert bytes1 == bytes2 == bytes3

    # Verify content is there
    assert b"text content" in bytes1
    assert b"binary content" in bytes1
    assert b'"key": "value"' in bytes1

    # First write
    buf.clear()
    await writer.write(stream)
    result1 = bytes(buf)

    # Second write - should produce identical output
    buf2.clear()
    await writer.write(stream2)
    result2 = bytes(buf2)

    # Results should be identical
    assert result1 == result2

    # Third write to ensure continued reusability
    buf.clear()
    await writer.write(stream)
    result3 = bytes(buf)

    assert result1 == result3

    # as_bytes should still work after writes
    bytes4 = await writer.as_bytes()
    assert bytes1 == bytes4


async def test_multipart_writer_reusability_with_io_payloads(
    buf: bytearray,
    stream: mock.Mock,
    buf2: bytearray,
    stream2: mock.Mock,
    writer: aiohttp.MultipartWriter,
) -> None:
    """Test that MultipartWriter with IO payloads can be reused."""
    # Create IO objects
    bytes_io = io.BytesIO(b"bytes io content")
    string_io = io.StringIO("string io content")

    # Add IO payloads
    writer.append(bytes_io, {"Content-Type": "application/octet-stream"})
    writer.append(string_io, {"Content-Type": "text/plain"})

    # Test as_bytes multiple times
    bytes1 = await writer.as_bytes()
    bytes2 = await writer.as_bytes()

    # All as_bytes calls should return identical data
    assert bytes1 == bytes2
    assert b"bytes io content" in bytes1
    assert b"string io content" in bytes1

    # First write
    buf.clear()
    await writer.write(stream)
    result1 = bytes(buf)

    assert b"bytes io content" in result1
    assert b"string io content" in result1

    # Reset IO objects for reuse
    bytes_io.seek(0)
    string_io.seek(0)

    # Second write
    buf2.clear()
    await writer.write(stream2)
    result2 = bytes(buf2)

    # Should produce identical results
    assert result1 == result2

    # Test as_bytes after writes (IO objects should auto-reset)
    bytes3 = await writer.as_bytes()
    assert bytes1 == bytes3


async def test_body_part_reader_payload_as_bytes() -> None:
    """Test that BodyPartReaderPayload.as_bytes raises TypeError."""
    # Create a mock BodyPartReader
    headers = HeadersDictProxy(CIMultiDict({CONTENT_TYPE: "text/plain"}))
    protocol = mock.Mock(_reading_paused=False)
    stream = StreamReader(protocol, 2**16, loop=asyncio.get_running_loop())
    body_part = BodyPartReader(BOUNDARY, headers, stream)

    # Create the payload
    payload = BodyPartReaderPayload(body_part)

    # Test that as_bytes raises TypeError
    with pytest.raises(TypeError, match="Unable to read body part as bytes"):
        await payload.as_bytes()

    # Test that decode also raises TypeError
    with pytest.raises(TypeError, match="Unable to decode"):
        payload.decode()


async def test_body_part_reader_payload_write() -> None:
    content = b"A" * 1_000_000  # Large enough to exceed max_length.
    compressed = ZLibBackend.compress(content, wbits=-ZLibBackend.MAX_WBITS)
    output = b""

    async def write(inp: bytes) -> None:
        nonlocal output
        output += inp

    h = HeadersDictProxy(CIMultiDict({CONTENT_ENCODING: "deflate"}))
    if sys.version_info >= (3, 12):
        writer = mock.create_autospec(
            AbstractStreamWriter, write=write, spec_set=True, instance=True
        )
    else:
        writer = mock.create_autospec(
            AbstractStreamWriter, spec_set=True, instance=True
        )
        writer.write.side_effect = write
    with Stream(compressed + b"\r\n--:--") as stream:
        body_part = aiohttp.BodyPartReader(BOUNDARY, h, stream)
        payload = BodyPartReaderPayload(body_part)
        await payload.write(writer)

    assert len(output) == len(content)  # Simplifies diff on failure
    assert output == content


async def test_multipart_writer_close_with_exceptions() -> None:
    """Test that MultipartWriter.close() continues closing all parts even if one raises."""
    writer = aiohttp.MultipartWriter()

    # Create mock payloads
    # First part will raise during close
    part1 = mock.Mock()
    part1.autoclose = False
    part1.consumed = False
    part1.close = mock.AsyncMock(side_effect=RuntimeError("Part 1 close failed"))

    # Second part should still get closed
    part2 = mock.Mock()
    part2.autoclose = False
    part2.consumed = False
    part2.close = mock.AsyncMock()

    # Third part with autoclose=True should not be closed
    part3 = mock.Mock()
    part3.autoclose = True
    part3.consumed = False
    part3.close = mock.AsyncMock()

    # Fourth part already consumed should not be closed
    part4 = mock.Mock()
    part4.autoclose = False
    part4.consumed = True
    part4.close = mock.AsyncMock()

    # Add parts to writer's internal list
    writer._parts = [
        (part1, "", ""),
        (part2, "", ""),
        (part3, "", ""),
        (part4, "", ""),
    ]

    # Close the writer - should not raise despite part1 failing
    await writer.close()

    # Verify close was called on appropriate parts
    part1.close.assert_called_once()
    part2.close.assert_called_once()  # Should still be called despite part1 failing
    part3.close.assert_not_called()  # autoclose=True
    part4.close.assert_not_called()  # consumed=True

    # Verify writer is marked as consumed
    assert writer._consumed is True

    # Calling close again should do nothing
    await writer.close()
    assert part1.close.call_count == 1
    assert part2.close.call_count == 1


async def test_multipart_writer_consumed_follows_parts() -> None:
    """A writer holding an unreplayable part must report itself as consumed."""

    async def gen() -> AsyncIterator[bytes]:
        yield b"chunk1"
        yield b"chunk2"

    writer = aiohttp.MultipartWriter()
    writer.append(b"replayable")
    assert writer.consumed is False

    part = writer.append(gen())
    assert writer.consumed is False

    stream = mock.Mock()
    stream.write = mock.AsyncMock()
    await part.write_with_length(stream, None)

    assert part.consumed is True
    assert writer.consumed is True


async def test_body_part_reader_payload_consumed_after_write() -> None:
    """A drained body part reader must report itself as consumed."""
    with Stream(b"Hello, world!\r\n--:--") as stream:
        body_part = aiohttp.BodyPartReader(
            BOUNDARY, HeadersDictProxy(CIMultiDict()), stream
        )
        payload = BodyPartReaderPayload(body_part)
        assert payload.consumed is False

        writer = mock.Mock()
        writer.write = mock.AsyncMock()
        await payload.write(writer)

        assert payload.consumed is True


async def test_multipart_writer_consumed_follows_body_part_reader() -> None:
    """A writer holding a drained body part reader must report itself consumed."""
    with Stream(b"Hello, world!\r\n--:--") as stream:
        body_part = aiohttp.BodyPartReader(
            BOUNDARY, HeadersDictProxy(CIMultiDict()), stream
        )
        writer = aiohttp.MultipartWriter()
        part = writer.append(body_part)
        assert writer.consumed is False

        out = mock.Mock()
        out.write = mock.AsyncMock()
        await part.write_with_length(out, None)

        assert part.consumed is True
        assert writer.consumed is True




# --- Boundary-aware mutation tests -----------------------------------------
#
# Layouts below are assembled from raw bytes rather than MultipartWriter, so the
# expected partition into parts is fixed before the reader runs: part identity
# and body bytes are stated up front, not recovered from the reader. Every valid
# rendering of a layout must produce the same answer, no matter how the input is
# sliced or how a part is consumed.

_CRLF = b"\r\n"


def _render_part(
    boundary: bytes,
    headers: list[tuple[str, str]],
    body: bytes,
) -> bytes:
    """Serialise a part starting at its delimiter and ending after *body*."""
    out = [b"--", boundary, _CRLF]
    for name, value in headers:
        out += [name.encode("ascii"), b": ", value.encode("ascii"), _CRLF]
    out += [_CRLF, body, _CRLF]
    return b"".join(out)


def _render_multipart(
    boundary: bytes,
    parts: list[tuple[list[tuple[str, str]], bytes]],
    *,
    close_padding: bytes = b"",
    preface: bytes = b"",
    epilogue: bytes = b"",
) -> bytes:
    """Serialise a whole body: each part, then the closing delimiter."""
    out = [preface]
    for headers, body in parts:
        out.append(_render_part(boundary, headers, body))
    out += [b"--", boundary, b"--", close_padding, _CRLF, epilogue]
    return b"".join(out)


def _slices(data: bytes, sizes: tuple[int, ...]) -> list[bytes]:
    """Cut *data* into a repeating pattern of slice sizes."""
    out = []
    pos = 0
    i = 0
    while pos < len(data):
        n = sizes[i % len(sizes)]
        out.append(data[pos : pos + n])
        pos += n
        i += 1
    return out


class SliceStream(Stream):
    """Stream fed as a list of byte slices, capped by the requested size."""

    def __init__(self, slices: list[bytes]) -> None:
        super().__init__(b"".join(slices))
        self._slices = [s for s in slices if s]

    async def read(self, size: int | None = None) -> bytes:
        if not self._slices:
            return b""
        data = self._slices.pop(0)
        if size is not None and len(data) > size:
            self._slices.insert(0, data[size:])
            data = data[:size]
        return data

    async def readline(self, *, max_line_length: int | None = None) -> bytes:
        line = b""
        while self._slices and b"\n" not in line:
            head = self._slices.pop(0)
            newline = head.find(b"\n")
            if newline >= 0:
                line += head[: newline + 1]
                if head[newline + 1 :]:
                    self._slices.insert(0, head[newline + 1 :])
            else:
                line += head
        return line

    def unread_data(self, data: bytes) -> None:
        if data:
            self._slices.insert(0, data)

    def at_eof(self) -> bool:
        return not self._slices

    def remaining(self) -> bytes:
        return b"".join(self._slices)


async def _walk(reader: MultipartReader, size: int | None) -> list:
    """Consume a reader tree, recording identity, headers and body bytes."""

    async def take(part: BodyPartReader) -> bytes:
        if size is None:
            return bytes(await part.read())
        out = bytearray()
        while True:
            chunk = await part.read_chunk(size)
            out += chunk
            if part.at_eof():
                return bytes(out)
            assert chunk, "reader made no progress"

    result = []
    while True:
        part = await reader.next()
        if part is None:
            break
        if isinstance(part, MultipartReader):
            result.append(("nested", await _walk(part, size)))
        else:
            result.append(
                (
                    "part",
                    part.headers.get(CONTENT_TYPE),
                    part.headers.get(CONTENT_DISPOSITION),
                    await take(part),
                )
            )
    return result


def _entry(headers: list[tuple[str, str]], body: bytes) -> tuple:
    return (
        "part",
        dict(headers).get(CONTENT_TYPE),
        dict(headers).get(CONTENT_DISPOSITION),
        body,
    )


_INNER = b"boundary-inner"
_OUTER = b"boundary"

_INNER_PARTS: list[tuple[list[tuple[str, str]], bytes]] = [
    (
        [
            ("Content-Type", "text/plain"),
            ("Content-Disposition", 'attachment; filename="a.txt"'),
        ],
        b"alpha\r\n--boundary-innerx stays text\r\n--boundaryx stays text",
    ),
    (
        [
            ("Content-Type", "text/plain"),
            ("Content-Disposition", 'attachment; filename="b.txt"'),
        ],
        b"beta\r\n--boundary-inner--not-a-close\r\n--boundary--not-a-close",
    ),
]

_OUTER_THIRD = (
    [
        ("Content-Type", "text/plain"),
        ("Content-Disposition", 'attachment; filename="c.txt"'),
    ],
    b"tail\r\n--boundaryx still text\r\n--boundary-innerx unrelated",
)


def _outer_parts() -> list[tuple[list[tuple[str, str]], bytes]]:
    return [
        (
            [("Content-Type", f"multipart/related; boundary={_INNER.decode()}")],
            _render_multipart(_INNER, _INNER_PARTS, preface=b"inner preface\r\n"),
        ),
        _OUTER_THIRD,
        (
            [
                ("Content-Type", "text/plain"),
                ("Content-Disposition", 'attachment; filename="d.txt"'),
            ],
            b"end\r\n\r\n--boundary-innerx unrelated",
        ),
    ]


def _outer_bytes(**kwargs) -> bytes:
    return _render_multipart(_OUTER, _outer_parts(), **kwargs)


def _expected_tree() -> list:
    return [
        ("nested", [_entry(headers, body) for headers, body in _INNER_PARTS]),
        _entry(*_OUTER_THIRD),
        _entry(*_outer_parts()[2]),
    ]


@pytest.mark.parametrize(
    "sizes",
    [(1,), (2, 3), (5,), (7, 1, 11), (64,), None],
)
@pytest.mark.parametrize("body_chunk", [None, 20, 32])
async def test_boundary_layout_partition_is_slice_invariant(
    sizes: tuple[int, ...] | None, body_chunk: int | None
) -> None:
    data = _outer_bytes(preface=b"outer preface\r\n", epilogue=b"outer epilogue\r\n")
    slices = [data] if sizes is None else _slices(data, sizes)
    stream = SliceStream(slices)
    reader = MultipartReader(
        {CONTENT_TYPE: f'multipart/mixed; boundary="{_OUTER.decode()}"'}, stream
    )
    assert await _walk(reader, body_chunk) == _expected_tree()
    assert reader.at_eof()
    assert stream.remaining() == b""


async def test_boundary_layout_alternate_valid_paddings() -> None:
    data = _outer_bytes(close_padding=b" \t", epilogue=b"")
    reference = _outer_bytes(close_padding=b"", epilogue=b"discarded\r\n")
    stream = SliceStream(_slices(data, (3,)))
    reader = MultipartReader(
        {CONTENT_TYPE: f'multipart/mixed; boundary="{_OUTER.decode()}"'}, stream
    )
    assert await _walk(reader, None) == _expected_tree()
    # A padded close still ends the stream exactly where the unpadded one does.
    assert stream.remaining() == b""
    other = SliceStream(_slices(reference, (4,)))
    reader = MultipartReader(
        {CONTENT_TYPE: f'multipart/mixed; boundary="{_OUTER.decode()}"'}, other
    )
    assert await _walk(reader, None) == _expected_tree()
    assert other.remaining() == b""


@pytest.mark.parametrize(
    "suffix",
    [
        b"x",
        b"-",
        b"---",
        b"--tail",
        b" not a delimiter",
        b"\tx",
        b"x\r\n\r\n--boundary-inner",
    ],
)
async def test_boundary_prefix_in_body_stays_in_body(suffix: bytes) -> None:
    body = (
        b"head\r\n--boundary"
        + suffix
        + b"\r\nmid\r\n--boundary"
        + suffix
        + b"\r\n\r\n--boundary-innerx"
    )
    data = _render_multipart(
        _OUTER,
        [
            ([("Content-Type", "text/plain")], body),
            ([("Content-Type", "text/plain")], b"next"),
        ],
    )
    for sizes in ((1,), (3, 4), None):
        stream = SliceStream([data] if sizes is None else _slices(data, sizes))
        reader = MultipartReader(
            {CONTENT_TYPE: f'multipart/mixed; boundary="{_OUTER.decode()}"'}, stream
        )
        first = await reader.next()
        assert isinstance(first, BodyPartReader)
        assert await first.read() == body
        second = await reader.next()
        assert isinstance(second, BodyPartReader)
        assert await second.read() == b"next"
        assert await reader.next() is None


@pytest.mark.parametrize("closing", [b"--", b"--\r\n", b"-- \t\r\n"])
async def test_closing_boundary_variants(closing: bytes) -> None:
    data = (
        b"--boundary\r\nContent-Type: text/plain\r\n\r\nbody\r\n--boundary"
        + closing
    )
    stream = SliceStream(_slices(data, (2, 5, 1)))
    reader = MultipartReader(
        {CONTENT_TYPE: 'multipart/mixed; boundary="boundary"'}, stream
    )
    part = await reader.next()
    assert isinstance(part, BodyPartReader)
    assert await part.read() == b"body"
    assert await reader.next() is None
    assert reader.at_eof()
    assert stream.remaining() == b""


@pytest.mark.parametrize(
    "layout",
    [
        b"--:\r\nContent-Type: text/plain\r\n\r\nab\r\n--:",
        b"--:\r\nContent-Type: text/plain\r\n\r\nab\r\n"
        b"--:\r\nContent-Type: text/plain\r\n\r\n",
    ],
)
async def test_truncated_boundary_is_not_a_delimiter(layout: bytes) -> None:
    stream = SliceStream(_slices(layout, (1, 2)))
    reader = MultipartReader({CONTENT_TYPE: 'multipart/mixed; boundary=":"'}, stream)
    with pytest.raises(ValueError):
        while await reader.next() is not None:
            pass


@pytest.mark.parametrize("body_chunk", [None, 20])
async def test_nested_lookahead_stays_within_inner_part(body_chunk: int | None) -> None:
    data = _outer_bytes()
    stream = SliceStream(_slices(data, (1, 4, 2, 7)))
    reader = MultipartReader(
        {CONTENT_TYPE: f'multipart/mixed; boundary="{_OUTER.decode()}"'}, stream
    )
    nested = await reader.next()
    assert isinstance(nested, MultipartReader)
    first = await nested.next()
    assert isinstance(first, BodyPartReader)
    # Stop mid-part: only the inner reader may consume the inner remainder.
    seen = b""
    while len(seen) < 20:
        chunk = await first.read_chunk(20)
        assert chunk
        seen += chunk
    assert seen == _INNER_PARTS[0][1][: len(seen)]
    second = await nested.next()
    assert isinstance(second, BodyPartReader)
    assert await second.read() == _INNER_PARTS[1][1]
    assert await nested.next() is None
    third = await reader.next()
    assert isinstance(third, BodyPartReader)
    assert await third.read() == _OUTER_THIRD[1]
    last = await reader.next()
    assert isinstance(last, BodyPartReader)
    assert await last.read() == _outer_parts()[2][1]
    assert await reader.next() is None


async def test_prefix_only_match_is_not_a_delimiter() -> None:
    """Negative control: a matcher treating a prefix as the boundary fails."""
    boundary = b"x"
    body = b"body\r\n--xx"
    data = _render_multipart(
        boundary,
        [
            ([("Content-Type", "text/plain")], body),
            ([("Content-Type", "text/plain")], b"next"),
        ],
    )
    stream = SliceStream(_slices(data, (2, 3)))
    reader = MultipartReader({CONTENT_TYPE: 'multipart/mixed; boundary="x"'}, stream)
    first = await reader.next()
    assert isinstance(first, BodyPartReader)
    assert await first.read() == body
    assert isinstance(await reader.next(), BodyPartReader)


@pytest.mark.parametrize(
    "sizes",
    [(1,), (3,), (5,), (13, 2), None],
)
async def test_release_leaves_nothing_for_the_parent(
    sizes: tuple[int, ...] | None,
) -> None:
    data = _outer_bytes()
    stream = SliceStream([data] if sizes is None else _slices(data, sizes))
    reader = MultipartReader(
        {CONTENT_TYPE: f'multipart/mixed; boundary="{_OUTER.decode()}"'}, stream
    )
    await reader.release()
    assert reader.at_eof()
    assert stream.remaining() == b""
    assert await reader.next() is None
