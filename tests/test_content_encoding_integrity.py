"""
Independent termination-criterion tests for the HTTP content-encoding chain.

The production decoders are *not* used as the reference answer here. Every
"good" payload is built from short, independently constructed byte streams and
verified against the standard library's own decompressors, while truncated and
trailing-garbage payloads are proven to be rejected no matter how the bytes are
split across chunks.

A set of deliberately broken decoder variants (outermost-layer-only checks,
missing flush checks, trailing-data ignoring) is driven through the same
streams to prove the suite actually catches each class of defect.
"""

from __future__ import annotations

import gzip as stdlib_gzip
import typing
import zlib

import pytest

import httpx
from httpx import _decoders
from httpx._decoders import (
    ContentDecoder,
    DeflateDecoder,
    GZipDecoder,
    IdentityDecoder,
    MultiDecoder,
)


# ---------------------------------------------------------------------------
# Independent short-stream constructors.
#
# These deliberately do not call any httpx decoder. Compression uses the
# standard library only, so the expected output is an independent oracle.
# ---------------------------------------------------------------------------

PLAINTEXT = b"the quick brown fox jumps over the lazy dog"


def gzip_stream(payload: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    return compressor.compress(payload) + compressor.flush()


def zlib_wrapped_stream(payload: bytes) -> bytes:
    # 'deflate' may be an RFC 1950 zlib-wrapped stream.
    return zlib.compress(payload)


def raw_deflate_stream(payload: bytes) -> bytes:
    # 'deflate' may also be a bare RFC 1951 raw stream.
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return compressor.compress(payload) + compressor.flush()


def gzip_members(*payloads: bytes) -> bytes:
    return b"".join(gzip_stream(payload) for payload in payloads)


def fragment(data: bytes, sizes: typing.Iterable[int]) -> list[bytes]:
    """Split data into the requested chunk sizes (each fully consumes data)."""
    chunks: list[bytes] = []
    offset = 0
    for size in sizes:
        if offset >= len(data):
            break
        chunks.append(data[offset : offset + size])
        offset += min(size, len(data) - offset)
    if offset < len(data):
        chunks.append(data[offset:])
    assert b"".join(chunks) == data, "fragment pattern must reproduce the stream"
    return chunks


# Every fragmentation pattern below is a complete partition of the input.
FRAGMENT_PATTERNS: tuple[tuple[int, ...], ...] = (
    (10**9,),            # whole stream in a single chunk
    (1, 1, 1, 10**9),     # byte-by-byte start then the remainder
    (3, 5, 2, 10**9),     # irregular small chunks
    (7, 7, 7, 10**9),     # fixed small chunks
    (10**9, 1, 1),        # bulk first, trailing single bytes
)


def drive_decoder(decoder: ContentDecoder, chunks: typing.Iterable[bytes]) -> bytes:
    """Run the full decoder lifecycle, including every layer's flush/finish."""
    output = b""
    for chunk in chunks:
        output += decoder.decode(chunk)
    output += decoder.flush()
    decoder.check_finished()
    return output


def drive_response(
    header: bytes, chunks: typing.Iterable[bytes]
) -> tuple[bytes, bytes]:
    """Read a streaming Response both sync and async, returning each body."""
    def sync_source() -> typing.Iterator[bytes]:
        for chunk in chunks:
            yield chunk

    sync_response = httpx.Response(
        200, headers=[(b"Content-Encoding", header)], content=sync_source()
    )
    sync_body = sync_response.read()

    async def async_source() -> typing.AsyncIterator[bytes]:
        for chunk in chunks:
            yield chunk

    async def read_async() -> bytes:
        async_response = httpx.Response(
            200,
            headers=[(b"Content-Encoding", header)],
            content=async_source(),
        )
        return await async_response.aread()

    import asyncio

    async_body = asyncio.run(read_async())
    return sync_body, async_body


# ---------------------------------------------------------------------------
# Independent oracle: decompression via the standard library alone.
# ---------------------------------------------------------------------------


def oracle_gzip(data: bytes) -> bytes:
    return stdlib_gzip.decompress(data)


def oracle_deflate(data: bytes) -> bytes:
    try:
        return zlib.decompress(data)
    except zlib.error:
        return zlib.decompress(data, -zlib.MAX_WBITS)


# ---------------------------------------------------------------------------
# gzip: legal streams decode identically regardless of fragmentation.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pattern", FRAGMENT_PATTERNS)
def test_gzip_valid_stream_is_fragmentation_invariant(pattern: tuple[int, ...]):
    stream = gzip_stream(PLAINTEXT)
    chunks = fragment(stream, pattern)

    assert drive_decoder(GZipDecoder(), chunks) == PLAINTEXT
    # Cross-check the payload itself with the independent stdlib oracle.
    assert oracle_gzip(stream) == PLAINTEXT

    sync_body, async_body = drive_response(b"gzip", chunks)
    assert sync_body == PLAINTEXT
    assert async_body == PLAINTEXT


@pytest.mark.parametrize("pattern", FRAGMENT_PATTERNS)
def test_gzip_truncation_is_rejected_for_every_fragmentation(pattern):
    stream = gzip_stream(PLAINTEXT)[:-4]

    with pytest.raises(httpx.DecodingError):
        drive_decoder(GZipDecoder(), fragment(stream, pattern))

    with pytest.raises(httpx.DecodingError):
        drive_response(b"gzip", fragment(stream, pattern))


@pytest.mark.parametrize("pattern", FRAGMENT_PATTERNS)
def test_gzip_trailing_garbage_is_rejected_for_every_fragmentation(pattern):
    stream = gzip_stream(PLAINTEXT) + b"\x00not-a-gzip-member\xff"

    with pytest.raises(httpx.DecodingError):
        drive_decoder(GZipDecoder(), fragment(stream, pattern))

    with pytest.raises(httpx.DecodingError):
        drive_response(b"gzip", fragment(stream, pattern))


def test_gzip_concatenated_members_are_all_decoded():
    stream = gzip_members(b"foo", b"bar", b"baz")
    assert stdlib_gzip.decompress(stream) == b"foobarbaz"

    for pattern in FRAGMENT_PATTERNS:
        assert drive_decoder(GZipDecoder(), fragment(stream, pattern)) == b"foobarbaz"

    sync_body, async_body = drive_response(b"gzip", fragment(stream, (5, 5, 10**9)))
    assert sync_body == async_body == b"foobarbaz"


def test_gzip_member_chain_with_truncated_final_member_is_rejected():
    # The first member is complete; the second is cut off mid-stream.
    stream = gzip_members(b"foo", b"bar")[:-3]

    with pytest.raises(httpx.DecodingError):
        drive_decoder(GZipDecoder(), [stream])


def test_gzip_member_chain_with_trailing_garbage_is_rejected():
    stream = gzip_members(b"foo", b"bar") + b"JUNK"

    with pytest.raises(httpx.DecodingError):
        drive_decoder(GZipDecoder(), [stream])


def test_gzip_empty_input_is_a_legal_finished_stream():
    # Zero-length bodies, even when delivered as several empty flushes.
    assert drive_decoder(GZipDecoder(), [b"", b"", b""]) == b""

    sync_body, async_body = drive_response(b"gzip", [b"", b""])
    assert sync_body == async_body == b""


@pytest.mark.parametrize(
    "make_stream",
    (
        lambda: gzip_stream(PLAINTEXT),
        lambda: gzip_members(b"alpha", b"beta"),
    ),
    ids=("single", "multimember"),
)
def test_gzip_every_two_piece_split_gives_identical_result(make_stream):
    # Exhaust over every single split boundary: output and integrity status
    # must not depend on where the transport happens to fragment the bytes.
    stream = make_stream()
    reference = stdlib_gzip.decompress(stream)
    for cut in range(len(stream) + 1):
        result = drive_decoder(GZipDecoder(), [stream[:cut], stream[cut:]])
        assert result == reference

    # The same independence holds for a truncated stream: every split rejects.
    truncated = stream[:-2]
    for cut in range(len(truncated) + 1):
        with pytest.raises(httpx.DecodingError):
            drive_decoder(GZipDecoder(), [truncated[:cut], truncated[cut:]])


# ---------------------------------------------------------------------------
# deflate: both zlib-wrapped and raw RFC 1951 streams.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "builder", (zlib_wrapped_stream, raw_deflate_stream), ids=("zlib", "raw")
)
@pytest.mark.parametrize("pattern", FRAGMENT_PATTERNS)
def test_deflate_valid_stream_is_fragmentation_invariant(builder, pattern):
    stream = builder(PLAINTEXT)

    assert drive_decoder(DeflateDecoder(), fragment(stream, pattern)) == PLAINTEXT
    assert oracle_deflate(stream) == PLAINTEXT

    sync_body, async_body = drive_response(b"deflate", fragment(stream, pattern))
    assert sync_body == async_body == PLAINTEXT


@pytest.mark.parametrize(
    "builder", (zlib_wrapped_stream, raw_deflate_stream), ids=("zlib", "raw")
)
@pytest.mark.parametrize("pattern", FRAGMENT_PATTERNS)
def test_deflate_truncation_is_rejected_for_every_fragmentation(builder, pattern):
    stream = builder(PLAINTEXT)[:-3]

    with pytest.raises(httpx.DecodingError):
        drive_decoder(DeflateDecoder(), fragment(stream, pattern))

    with pytest.raises(httpx.DecodingError):
        drive_response(b"deflate", fragment(stream, pattern))


@pytest.mark.parametrize(
    "builder", (zlib_wrapped_stream, raw_deflate_stream), ids=("zlib", "raw")
)
def test_deflate_trailing_data_is_rejected(builder):
    stream = builder(PLAINTEXT) + b"X"

    with pytest.raises(httpx.DecodingError):
        drive_decoder(DeflateDecoder(), [stream])


def test_deflate_empty_input_is_a_legal_finished_stream():
    assert drive_decoder(DeflateDecoder(), [b"", b""]) == b""

    sync_body, async_body = drive_response(b"deflate", [b""])
    assert sync_body == async_body == b""


@pytest.mark.parametrize(
    "builder", (zlib_wrapped_stream, raw_deflate_stream), ids=("zlib", "raw")
)
def test_deflate_every_split_boundary_decodes_the_same(builder):
    # Raw and zlib-wrapped streams must both survive a split at any byte,
    # which exercises the decoder's header-detection buffering.
    stream = builder(PLAINTEXT)
    for cut in range(len(stream) + 1):
        assert (
            drive_decoder(DeflateDecoder(), [stream[:cut], stream[cut:]])
            == PLAINTEXT
        )


# ---------------------------------------------------------------------------
# Multi-layer chains: every layer must independently reach a legal end.
# ---------------------------------------------------------------------------


def build_chain(payload: bytes) -> tuple[bytes, list[ContentDecoder]]:
    """Apply deflate, then gzip, then gzip again. Returns bytes + decoders."""
    encoded = raw_deflate_stream(payload)
    encoded = gzip_stream(encoded)
    encoded = gzip_stream(encoded)
    # Decoders are listed in application order; MultiDecoder reverses them.
    decoders = [DeflateDecoder(), GZipDecoder(), GZipDecoder()]
    return encoded, decoders


@pytest.mark.parametrize("pattern", FRAGMENT_PATTERNS)
def test_multilayer_valid_chain_is_fragmentation_invariant(pattern):
    stream, decoders = build_chain(PLAINTEXT)

    assert drive_decoder(MultiDecoder(decoders), fragment(stream, pattern)) == PLAINTEXT

    sync_body, async_body = drive_response(
        b"deflate, gzip, gzip", fragment(stream, pattern)
    )
    assert sync_body == async_body == PLAINTEXT


def test_multilayer_truncated_outer_layer_is_rejected():
    stream, decoders = build_chain(PLAINTEXT)

    with pytest.raises(httpx.DecodingError):
        drive_decoder(MultiDecoder(decoders), [stream[:-5]])


def test_multilayer_truncated_inner_layer_cannot_hide_behind_valid_outer():
    # The outer gzip layer is perfectly complete; only the inner deflate
    # payload is truncated. An outermost-only check would miss this.
    truncated_inner = raw_deflate_stream(PLAINTEXT)[:-3]
    hidden = gzip_stream(gzip_stream(truncated_inner))
    decoders = [DeflateDecoder(), GZipDecoder(), GZipDecoder()]

    with pytest.raises(httpx.DecodingError):
        drive_decoder(MultiDecoder(decoders), [hidden])


def test_multilayer_inner_trailing_data_cannot_hide_behind_valid_outer():
    dirty_inner = raw_deflate_stream(PLAINTEXT) + b"trailing"
    hidden = gzip_stream(gzip_stream(dirty_inner))
    decoders = [DeflateDecoder(), GZipDecoder(), GZipDecoder()]

    with pytest.raises(httpx.DecodingError):
        drive_decoder(MultiDecoder(decoders), [hidden])


def test_multilayer_empty_input_finishes_every_layer():
    decoders = [DeflateDecoder(), GZipDecoder(), IdentityDecoder()]

    assert drive_decoder(MultiDecoder(decoders), [b"", b""]) == b""


# ---------------------------------------------------------------------------
# Unsupported encodings keep an explicit error state, never become identity.
# ---------------------------------------------------------------------------


def test_unsupported_encoding_is_not_treated_as_identity():
    # Bytes-backed responses decode eagerly, so the error surfaces at build.
    with pytest.raises(httpx.DecodingError):
        httpx.Response(
            200,
            headers=[(b"Content-Encoding", b"x-unknown-compression")],
            content=gzip_stream(PLAINTEXT),
        )


def test_unsupported_encoding_inside_a_chain_is_rejected():
    with pytest.raises(httpx.DecodingError):
        httpx.Response(
            200,
            headers=[(b"Content-Encoding", b"gzip, x-unknown-compression")],
            content=gzip_stream(PLAINTEXT),
        )


def test_optional_backend_absence_is_not_silently_identity(monkeypatch):
    # Simulate an optional backend being unavailable by removing its entry
    # from the registry, exactly as the module does on ImportError.
    monkeypatch.delitem(_decoders.SUPPORTED_DECODERS, "br", raising=False)

    with pytest.raises(httpx.DecodingError):
        httpx.Response(
            200, headers=[(b"Content-Encoding", b"br")], content=b"\x8b\x03\x80x"
        )


# ---------------------------------------------------------------------------
# Optional backends that are actually installed get the same guarantees.
# ---------------------------------------------------------------------------


def test_brotli_backend_integrity_when_installed():
    brotli = pytest.importorskip("brotli")

    body = PLAINTEXT
    stream = brotli.compress(body)
    headers = [(b"Content-Encoding", b"br")]

    for pattern in FRAGMENT_PATTERNS:
        response = httpx.Response(
            200, headers=headers, content=iter(fragment(stream, pattern))
        )
        assert response.read() == body

    with pytest.raises(httpx.DecodingError):
        httpx.Response(200, headers=headers, content=stream[:-2])

    empty = httpx.Response(200, headers=headers, content=b"")
    assert empty.read() == b""


def test_zstandard_backend_integrity_when_installed():
    zstd = pytest.importorskip("zstandard")

    body = PLAINTEXT
    stream = zstd.compress(body)
    headers = [(b"Content-Encoding", b"zstd")]

    for pattern in FRAGMENT_PATTERNS:
        response = httpx.Response(
            200, headers=headers, content=iter(fragment(stream, pattern))
        )
        assert response.read() == body

    with pytest.raises(httpx.DecodingError):
        httpx.Response(200, headers=headers, content=stream[1:4])

    empty = httpx.Response(200, headers=headers, content=b"")
    assert empty.read() == b""

    # Concatenated frames, including a skippable frame, must all be consumed.
    skippable = bytes.fromhex(
        "502a4d18" "07000000" "00000000000000"
    )
    multi = zstd.compress(b"foo") + skippable + zstd.compress(b"bar")
    chained = httpx.Response(200, headers=headers, content=multi)
    assert chained.read() == b"foobar"

    with pytest.raises(httpx.DecodingError):
        httpx.Response(200, headers=headers, content=multi + b"JUNK")


# ---------------------------------------------------------------------------
# Deliberately broken decoder variants.
#
# Each one models a real defect class. Driven through the same short streams,
# every variant must accept a corrupted input that the correct implementation
# rejects. This proves the tests above cannot be satisfied by an outermost-only
# check, a skipped flush, or ignored trailing data.
# ---------------------------------------------------------------------------


class BrokenOuterOnlyGZipDecoder(ContentDecoder):
    """Only checks the outermost framing; inner layers are never verified."""

    def __init__(self) -> None:
        self.outer = GZipDecoder()
        # A second, deliberately unchecked gzip layer.
        self.inner = GZipDecoder()

    def decode(self, data: bytes) -> bytes:
        return self.inner.decode(self.outer.decode(data))

    def flush(self) -> bytes:
        return self.inner.decode(self.outer.flush()) + self.inner.flush()

    def check_finished(self) -> None:
        # Defect: verifies the outer layer only.
        self.outer.check_finished()


class BrokenNoFlushGZipDecoder(ContentDecoder):
    """Decodes chunks but forgets the end-of-stream flush/finish check."""

    def __init__(self) -> None:
        self.decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)

    def decode(self, data: bytes) -> bytes:
        try:
            return self.decompressor.decompress(data)
        except zlib.error as exc:
            raise httpx.DecodingError(str(exc)) from exc

    def flush(self) -> bytes:
        # Defect: silently returns without driving the flush.
        return b""

    def check_finished(self) -> None:
        # Defect: no independent termination criterion at all.
        return None


class BrokenIgnoreTrailingGZipDecoder(ContentDecoder):
    """Consumes the first member and silently drops everything after it."""

    def __init__(self) -> None:
        self.decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)

    def decode(self, data: bytes) -> bytes:
        try:
            return self.decompressor.decompress(data)
        except zlib.error as exc:
            raise httpx.DecodingError(str(exc)) from exc

    def flush(self) -> bytes:
        return self.decompressor.flush()

    def check_finished(self) -> None:
        # Defect: ignores unused_data and a missing eof.
        return None


def test_outer_only_variant_misses_inner_truncation():
    # Explicit end-to-end demonstration of the layered hiding attack. The cut
    # is large enough to remove fully-emitted bytes, not just buffered flush.
    hidden = gzip_stream(gzip_stream(PLAINTEXT)[:-12])

    # The correct MultiDecoder rejects it, because every layer is checked...
    good = MultiDecoder([GZipDecoder(), GZipDecoder()])
    with pytest.raises(httpx.DecodingError):
        drive_decoder(good, [hidden])

    # ...while the outermost-only variant completes without error and returns
    # a silently truncated body that still looks like a normal response.
    broken = BrokenOuterOnlyGZipDecoder()
    result = drive_decoder(broken, [hidden])
    assert result and result != PLAINTEXT
    assert PLAINTEXT.startswith(result)


def test_no_flush_variant_misses_truncation():
    good = gzip_stream(PLAINTEXT)

    with pytest.raises(httpx.DecodingError):
        drive_decoder(GZipDecoder(), [good[:-12]])

    # The no-flush variant returns the decodable prefix and never notices the
    # stream ended early.
    result = drive_decoder(BrokenNoFlushGZipDecoder(), [good[:-12]])
    assert result and result != PLAINTEXT
    assert PLAINTEXT.startswith(result)


def test_ignore_trailing_variant_misses_garbage_and_extra_members():
    good = gzip_stream(PLAINTEXT)

    # The correct decoder rejects both raw trailing bytes and unconsumed
    # members...
    with pytest.raises(httpx.DecodingError):
        drive_decoder(GZipDecoder(), [good + b"JUNK"])
    with pytest.raises(httpx.DecodingError):
        drive_decoder(GZipDecoder(), [gzip_members(b"foo", b"bar") + b"JUNK"])

    # ...while the trailing-ignoring variant silently drops the junk and keeps
    # only the first member, reporting success either way.
    assert (
        drive_decoder(BrokenIgnoreTrailingGZipDecoder(), [good + b"JUNK"])
        == PLAINTEXT
    )
    assert drive_decoder(BrokenIgnoreTrailingGZipDecoder(), [gzip_members(b"foo", b"bar")]) == b"foo"


def test_each_broken_variant_is_less_strict_than_the_real_decoder():
    # A consolidated mutation guard: for every defect class there must exist a
    # short stream the matching production decoder rejects but the broken
    # variant does not. If any variant starts rejecting everything the model
    # has drifted and these tests must be revisited.
    good = gzip_stream(PLAINTEXT)
    cases = (
        # Two-layer corruption is judged against the real two-layer chain.
        (
            BrokenOuterOnlyGZipDecoder,
            MultiDecoder([GZipDecoder(), GZipDecoder()]),
            gzip_stream(gzip_stream(PLAINTEXT)[:-12]),
        ),
        (BrokenNoFlushGZipDecoder, GZipDecoder(), good[:-12]),
        (BrokenIgnoreTrailingGZipDecoder, GZipDecoder(), good + b"JUNK"),
    )
    for broken_cls, reference, payload in cases:
        with pytest.raises(httpx.DecodingError):
            drive_decoder(reference, [payload])
        # No exception: the broken variant swallows the corruption.
        drive_decoder(broken_cls(), [payload])


def test_response_read_path_invokes_the_finish_criterion(monkeypatch):
    # A variant that never calls its finish check would let truncation
    # through. The production read path must invoke check_finished(), so swap
    # in a decoder that records the call and fails if it is never made.
    stream = gzip_stream(PLAINTEXT)

    class RecordingDecoder(ContentDecoder):
        finish_called = False

        def __init__(self) -> None:
            self._inner = GZipDecoder()

        def decode(self, data: bytes) -> bytes:
            return self._inner.decode(data)

        def flush(self) -> bytes:
            return self._inner.flush()

        def check_finished(self) -> None:
            type(self).finish_called = True

    monkeypatch.setitem(_decoders.SUPPORTED_DECODERS, "gzip", RecordingDecoder)

    def source() -> typing.Iterator[bytes]:
        for chunk in fragment(stream, (4, 4, 10**9)):
            yield chunk

    response = httpx.Response(
        200,
        headers=[(b"Content-Encoding", b"gzip")],
        content=source(),
    )
    response.read()
    assert RecordingDecoder.finish_called is True

    # The async read path must invoke the same independent criterion.
    RecordingDecoder.finish_called = False

    async def async_source() -> typing.AsyncIterator[bytes]:
        for chunk in fragment(stream, (4, 4, 10**9)):
            yield chunk

    import asyncio

    async def read_async() -> None:
        async_response = httpx.Response(
            200,
            headers=[(b"Content-Encoding", b"gzip")],
            content=async_source(),
        )
        await async_response.aread()

    asyncio.run(read_async())
    assert RecordingDecoder.finish_called is True

    # The same truncated bytes are rejected by the real criterion.
    with pytest.raises(httpx.DecodingError):
        drive_decoder(GZipDecoder(), [stream[:-4]])
