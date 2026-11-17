from __future__ import annotations

import hashlib
import typing
import zlib

import pytest

import httpx

# A fixed gzip encoded response body: b"HTTPX digest demo\n"
GZIP_RAW = bytes.fromhex(
    "1f8b0800000000000213f3080909885048c94c4f2d2e514849cdcde702000467a6fc12000000"
)
DECODED = b"HTTPX digest demo\n"
RAW_SHA256 = hashlib.sha256(GZIP_RAW).hexdigest()
DECODED_SHA256 = hashlib.sha256(DECODED).hexdigest()
RAW_SHA256_BYTES = hashlib.sha256(GZIP_RAW).digest()
RAW_SHA256_BASE64 = __import__("base64").b64encode(RAW_SHA256_BYTES).decode()

GZIP_HEADERS = {"Content-Encoding": "gzip"}


def gzip_bytes(body: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    return compressor.compress(body) + compressor.flush()


def streaming_body() -> typing.Iterator[bytes]:
    yield b"Hello, "
    yield b"world!"


async def async_streaming_body() -> typing.AsyncIterator[bytes]:
    yield b"Hello, "
    yield b"world!"


class AsyncBody(httpx.AsyncByteStream):
    """
    An explicit async iterable (not an async generator), so cancellation tests
    do not leave an unexhausted generator for the event loop to finalize.
    """

    def __init__(self, chunks: typing.Sequence[bytes]) -> None:
        self._chunks = list(chunks)
        self.closed = False

    def __aiter__(self) -> AsyncBody:
        return self

    async def __anext__(self) -> bytes:
        if not self._chunks:
            raise StopAsyncIteration
        return self._chunks.pop(0)

    async def aclose(self) -> None:
        self.closed = True


def test_fixed_gzip_response_has_distinct_raw_and_decoded_digests():
    assert RAW_SHA256 != DECODED_SHA256

    response = httpx.Response(200, headers=GZIP_HEADERS, content=GZIP_RAW)
    assert response.content == DECODED

    raw = response.verify_digest(RAW_SHA256, scope="raw")
    raw.require_verified()
    assert raw.status is httpx.DigestStatus.VERIFIED
    assert raw.actual_digest == RAW_SHA256
    assert raw.read_raw() == GZIP_RAW

    decoded = response.verify_digest(DECODED_SHA256, scope="decoded")
    decoded.require_verified()
    assert decoded.status is httpx.DigestStatus.VERIFIED
    assert decoded.actual_digest == DECODED_SHA256
    assert decoded.read() == DECODED


def test_raw_digest_does_not_verify_a_decoded_digest():
    response = httpx.Response(200, headers=GZIP_HEADERS, content=GZIP_RAW)

    verifier = response.verify_digest(DECODED_SHA256, scope="raw")
    assert verifier.status is httpx.DigestStatus.MISMATCH
    assert verifier.actual_digest == RAW_SHA256
    with pytest.raises(httpx.DigestMismatchError):
        verifier.require_verified()


def test_decoded_digest_does_not_verify_a_raw_digest():
    response = httpx.Response(200, headers=GZIP_HEADERS, content=GZIP_RAW)

    verifier = response.verify_digest(RAW_SHA256, scope="decoded")
    assert verifier.status is httpx.DigestStatus.MISMATCH
    assert verifier.actual_digest == DECODED_SHA256


@pytest.mark.parametrize(
    "expected_digest, algorithm",
    [
        ("sha256=" + RAW_SHA256, None),
        (RAW_SHA256, "sha256"),
        ("SHA-256:" + RAW_SHA256_BASE64 + ":", None),
        (RAW_SHA256_BYTES, "sha256"),
    ],
)
def test_digest_value_formats(expected_digest, algorithm):
    response = httpx.Response(200, headers=GZIP_HEADERS, content=GZIP_RAW)
    verifier = response.verify_digest(
        expected_digest, scope="raw", algorithm=algorithm
    )
    assert verifier.status is httpx.DigestStatus.VERIFIED
    assert verifier.expected_digest == RAW_SHA256
    assert verifier.algorithm == "sha256"


def test_invalid_digest_arguments():
    response = httpx.Response(200, content=b"Hello, world!")

    with pytest.raises(httpx.DigestError):
        response.verify_digest("not-a-digest", scope="decoded")
    with pytest.raises(httpx.DigestError):
        response.verify_digest(hashlib.sha256(b"x").hexdigest(), scope="other")
    with pytest.raises(httpx.DigestError):
        response.verify_digest(
            "sha256=" + hashlib.sha256(b"x").hexdigest(),
            scope="decoded",
            algorithm="sha512",
        )
    with pytest.raises(httpx.DigestError):
        response.verify_digest(
            hashlib.sha256(b"x").hexdigest(), scope="decoded", algorithm="nope"
        )


def test_content_length_is_not_a_substitute_for_a_digest():
    body = b"HTTPX digest demo\n"
    digest = hashlib.sha256(body).hexdigest()

    response = httpx.Response(
        200,
        headers={"Content-Length": str(len(body))},
        content=body,
    )
    verifier = response.verify_digest(digest, scope="decoded")
    assert verifier.verified

    # A matching length, but a different body, must not verify.
    other = httpx.Response(
        200,
        headers={"Content-Length": str(len(body))},
        content=b"HTTPX digest demp\n",
    )
    verifier = other.verify_digest(digest, scope="decoded")
    assert verifier.status is httpx.DigestStatus.MISMATCH


def test_streaming_decoded_digest_sync():
    response = httpx.Response(200, content=streaming_body())
    verifier = response.verify_digest(
        hashlib.sha256(b"Hello, world!").hexdigest(), scope="decoded"
    )

    assert verifier.status is httpx.DigestStatus.PENDING
    parts = []
    for part in verifier.iter_bytes():
        parts.append(part)
        assert verifier.status is httpx.DigestStatus.PENDING
    assert b"".join(parts) == b"Hello, world!"
    assert verifier.status is httpx.DigestStatus.VERIFIED
    assert response.content == b"Hello, world!"


@pytest.mark.anyio
async def test_streaming_decoded_digest_async():
    response = httpx.Response(200, content=async_streaming_body())
    verifier = response.verify_digest(
        hashlib.sha256(b"Hello, world!").hexdigest(), scope="decoded"
    )

    parts = []
    async for part in verifier.aiter_bytes():
        parts.append(part)
        assert verifier.status is httpx.DigestStatus.PENDING
    assert b"".join(parts) == b"Hello, world!"
    assert verifier.status is httpx.DigestStatus.VERIFIED
    assert response.content == b"Hello, world!"


def test_streaming_truncated_response_is_incomplete():
    def truncated_body() -> typing.Iterator[bytes]:
        yield b"Hello, "
        # The complete expected body is "Hello, world!"
        # but the stream ends early.

    response = httpx.Response(
        200, content=truncated_body(), headers={"Content-Length": "13"}
    )
    verifier = response.verify_digest(
        hashlib.sha256(b"Hello, world!").hexdigest(), scope="decoded"
    )

    with pytest.raises(httpx.DigestIncompleteError):
        list(verifier.iter_bytes())
    assert verifier.status is httpx.DigestStatus.INCOMPLETE
    assert isinstance(verifier.error, httpx.DigestIncompleteError)
    assert not hasattr(response, "_content")


def test_truncated_gzip_response_is_incomplete():
    truncated = gzip_bytes(b"HTTPX digest demo\n")[:-4]

    def truncated_stream() -> typing.Iterator[bytes]:
        yield truncated

    response = httpx.Response(
        200, headers=GZIP_HEADERS, content=truncated_stream()
    )
    verifier = response.verify_digest(DECODED_SHA256, scope="decoded")

    with pytest.raises(httpx.DigestIncompleteError):
        list(verifier.iter_bytes())
    assert verifier.status is httpx.DigestStatus.INCOMPLETE


def test_truncated_gzip_raw_digest_is_incomplete():
    full = gzip_bytes(b"HTTPX digest demo\n")
    truncated = full[:-4]

    def truncated_stream() -> typing.Iterator[bytes]:
        yield truncated

    response = httpx.Response(
        200, headers=GZIP_HEADERS, content=truncated_stream()
    )
    verifier = response.verify_digest(
        hashlib.sha256(full).hexdigest(), scope="raw"
    )

    with pytest.raises(httpx.DigestIncompleteError):
        list(verifier.iter_raw())
    assert verifier.status is httpx.DigestStatus.INCOMPLETE
    assert verifier.actual_digest is None


def test_truncation_with_matching_content_length_is_incomplete():
    body = b"Hello, world!"
    digest = hashlib.sha256(body).hexdigest()

    def short_body() -> typing.Iterator[bytes]:
        yield b"Hello, worm!"

    response = httpx.Response(
        200,
        headers={"Content-Length": str(len(body))},
        content=short_body(),
    )
    verifier = response.verify_digest(digest, scope="decoded")
    with pytest.raises(httpx.DigestIncompleteError):
        list(verifier.iter_bytes())
    assert verifier.status is httpx.DigestStatus.INCOMPLETE
    assert isinstance(verifier.error, httpx.DigestIncompleteError)


def test_cancelled_stream_is_incomplete():
    response = httpx.Response(200, content=streaming_body())
    verifier = response.verify_digest(
        hashlib.sha256(b"Hello, world!").hexdigest(), scope="decoded"
    )

    with verifier as stream:
        iterator = stream.iter_bytes()
        assert next(iterator) == b"Hello, "

    assert verifier.status is httpx.DigestStatus.INCOMPLETE
    assert verifier.error is not None
    assert not hasattr(response, "_content")
    assert response.is_closed


def test_generator_exit_marks_incomplete():
    response = httpx.Response(200, content=streaming_body())
    verifier = response.verify_digest(
        hashlib.sha256(b"Hello, world!").hexdigest(), scope="decoded"
    )

    iterator = verifier.iter_bytes()
    assert next(iterator) == b"Hello, "
    iterator.close()

    assert verifier.status is httpx.DigestStatus.INCOMPLETE
    assert isinstance(verifier.error, httpx.DigestIncompleteError)


def test_partial_consumption_reports_not_verified():
    response = httpx.Response(200, content=streaming_body())
    verifier = response.verify_digest(
        hashlib.sha256(b"Hello, world!").hexdigest(), scope="decoded"
    )
    iterator = verifier.iter_bytes()
    assert next(iterator) == b"Hello, "

    assert verifier.pending
    assert not verifier.verified
    assert not verifier.failed
    with pytest.raises(httpx.DigestIncompleteError):
        verifier.require_verified()


def test_decode_failure_marks_error():
    broken = b"xxxxxxxxxxxxxx"

    def broken_stream() -> typing.Iterator[bytes]:
        yield broken

    response = httpx.Response(200, headers=GZIP_HEADERS, content=broken_stream())
    verifier = response.verify_digest(
        hashlib.sha256(b"whatever").hexdigest(), scope="decoded"
    )

    with pytest.raises(httpx.DecodingError):
        list(verifier.iter_bytes())
    assert verifier.status is httpx.DigestStatus.ERROR
    assert isinstance(verifier.error, httpx.DecodingError)
    assert verifier.actual_digest is None


def test_repeat_read_without_new_consumption_is_rejected():
    response = httpx.Response(200, content=streaming_body())
    verifier = response.verify_digest(
        hashlib.sha256(b"Hello, world!").hexdigest(), scope="decoded"
    )
    assert verifier.read() == b"Hello, world!"
    assert verifier.status is httpx.DigestStatus.VERIFIED
    assert verifier.read() == b"Hello, world!"


def test_streaming_response_cannot_be_consumed_twice():
    response = httpx.Response(200, content=streaming_body())
    first = response.verify_digest(
        hashlib.sha256(b"Hello, world!").hexdigest(), scope="decoded"
    )
    assert first.read() == b"Hello, world!"

    # Verified content is cached on the response, so a new verifier may be
    # checked against the same bytes without re-consuming the stream.
    second = response.verify_digest(
        hashlib.sha256(b"Hello, world!").hexdigest(), scope="decoded"
    )
    assert second.read() == b"Hello, world!"
    assert second.verified


def test_verified_stream_is_cached_as_content():
    response = httpx.Response(200, content=streaming_body())
    verifier = response.verify_digest(
        hashlib.sha256(b"Hello, world!").hexdigest(), scope="decoded"
    )
    assert verifier.read() == b"Hello, world!"
    assert response.content == b"Hello, world!"


def test_unfinished_stream_is_not_cached():
    response = httpx.Response(200, content=streaming_body())
    verifier = response.verify_digest(
        hashlib.sha256(b"Hello, world!").hexdigest(), scope="decoded"
    )

    iterator = verifier.iter_bytes()
    assert next(iterator) == b"Hello, "
    iterator.close()

    assert not hasattr(response, "_content")
    with pytest.raises(httpx.StreamConsumed):
        response.read()


def test_raise_on_mismatch_can_be_disabled():
    response = httpx.Response(200, content=b"Hello, world!")
    verifier = response.verify_digest(
        hashlib.sha256(b"other").hexdigest(),
        scope="decoded",
        raise_on_mismatch=False,
    )
    assert verifier.read() == b"Hello, world!"
    assert verifier.status is httpx.DigestStatus.MISMATCH
    with pytest.raises(httpx.DigestMismatchError):
        verifier.require_verified()


def test_sha512_and_base64_digest():
    import base64

    body = b"Hello, world!"
    digest = hashlib.sha512(body).digest()
    encoded = base64.b64encode(digest).decode()

    response = httpx.Response(200, content=body)
    verifier = response.verify_digest(
        encoded, scope="decoded", algorithm="sha512"
    )
    assert verifier.verified
    assert verifier.algorithm == "sha512"


@pytest.mark.anyio
async def test_async_cancelled_stream_is_incomplete():
    stream = AsyncBody([b"Hello, ", b"world!"])
    response = httpx.Response(200, stream=stream)
    verifier = response.verify_digest(
        hashlib.sha256(b"Hello, world!").hexdigest(), scope="decoded"
    )

    async with verifier as stream:
        iterator = stream.aiter_bytes()
        assert await iterator.__anext__() == b"Hello, "
        await iterator.aclose()

    assert verifier.status is httpx.DigestStatus.INCOMPLETE
    assert not hasattr(response, "_content")
    assert response.is_closed


@pytest.mark.anyio
async def test_async_decode_failure_marks_error():
    stream = AsyncBody([b"invalidgzip"])
    response = httpx.Response(200, headers=GZIP_HEADERS, stream=stream)
    verifier = response.verify_digest(
        hashlib.sha256(b"whatever").hexdigest(), scope="decoded"
    )

    with pytest.raises(httpx.DecodingError):
        [part async for part in verifier.aiter_bytes()]
    assert verifier.status is httpx.DigestStatus.ERROR
    assert isinstance(verifier.error, httpx.DecodingError)


def test_aread_caches_only_after_successful_verification():
    response = httpx.Response(200, content=streaming_body())
    verifier = response.verify_digest(
        hashlib.sha256(b"Hello, world!").hexdigest(), scope="decoded"
    )
    assert verifier.read() == b"Hello, world!"
    assert response.content == b"Hello, world!"


def test_read_raw_on_unencoded_response():
    body = b"Hello, world!"
    response = httpx.Response(200, content=body)
    verifier = response.verify_digest(
        hashlib.sha256(body).hexdigest(), scope="raw"
    )
    assert verifier.verified
    assert verifier.read_raw() == body


def test_raw_digest_unavailable_after_streamed_decode():
    response = httpx.Response(200, headers=GZIP_HEADERS, content=GZIP_RAW)
    assert response.content == DECODED

    verifier = response.verify_digest(RAW_SHA256, scope="raw")
    assert verifier.verified
    assert verifier.read_raw() == GZIP_RAW


def test_missing_content_length_is_allowed():
    response = httpx.Response(
        200,
        content=streaming_body(),
        headers={"Transfer-Encoding": "chunked"},
    )
    verifier = response.verify_digest(
        hashlib.sha256(b"Hello, world!").hexdigest(), scope="decoded"
    )
    assert verifier.read() == b"Hello, world!"
    assert verifier.verified


def test_head_response_digest_of_empty_content():
    response = httpx.Response(
        200,
        content=b"",
        request=httpx.Request("HEAD", "https://example.org"),
    )
    verifier = response.verify_digest(
        hashlib.sha256(b"").hexdigest(), scope="decoded"
    )
    assert verifier.verified
