from __future__ import annotations

import hashlib
import typing

import pytest

import httpx

BODY = b"Hello, world!"
DIGEST = hashlib.sha256(BODY).hexdigest()


def streaming_body() -> typing.Iterator[bytes]:
    yield b"Hello, "
    yield b"world!"


class AsyncBody(httpx.AsyncByteStream):
    """
    An explicit async iterable, avoiding unexhausted async generators when a
    test cancels a stream.
    """

    def __init__(self, chunks: typing.Sequence[bytes]) -> None:
        self._chunks = list(chunks)

    def __aiter__(self) -> AsyncBody:
        return self

    async def __anext__(self) -> bytes:
        if not self._chunks:
            raise StopAsyncIteration
        return self._chunks.pop(0)


def sync_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=streaming_body())


async def async_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, stream=AsyncBody([b"Hello, ", b"world!"]))


def test_client_stream_digest_sync():
    with httpx.Client(transport=httpx.MockTransport(sync_handler)) as client:
        with client.stream("GET", "https://example.org/") as response:
            verifier = response.verify_digest(DIGEST, scope="decoded")
            assert verifier.status is httpx.DigestStatus.PENDING

            chunks = list(verifier.iter_bytes())

    assert b"".join(chunks) == BODY
    assert verifier.status is httpx.DigestStatus.VERIFIED
    assert response.content == BODY


def test_client_stream_digest_cancelled_by_leaving_context():
    with httpx.Client(transport=httpx.MockTransport(sync_handler)) as client:
        with client.stream("GET", "https://example.org/") as response:
            verifier = response.verify_digest(DIGEST, scope="decoded")
            iterator = verifier.iter_bytes()
            assert next(iterator) == b"Hello, "

    assert verifier.status is httpx.DigestStatus.INCOMPLETE
    assert not hasattr(response, "_content")


def test_client_digest_mismatch_does_not_cache():
    with httpx.Client(transport=httpx.MockTransport(sync_handler)) as client:
        with client.stream("GET", "https://example.org/") as response:
            verifier = response.verify_digest(
                hashlib.sha256(b"different").hexdigest(), scope="decoded"
            )
            with pytest.raises(httpx.DigestMismatchError):
                verifier.read()

    assert verifier.status is httpx.DigestStatus.MISMATCH
    assert not hasattr(response, "_content")


@pytest.mark.anyio
async def test_client_stream_digest_async():
    transport = httpx.MockTransport(async_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        async with client.stream("GET", "https://example.org/") as response:
            verifier = response.verify_digest(DIGEST, scope="decoded")
            chunks = [part async for part in verifier.aiter_bytes()]

    assert b"".join(chunks) == BODY
    assert verifier.status is httpx.DigestStatus.VERIFIED
    assert response.content == BODY


@pytest.mark.anyio
async def test_client_stream_digest_cancelled_async():
    transport = httpx.MockTransport(async_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        async with client.stream("GET", "https://example.org/") as response:
            verifier = response.verify_digest(DIGEST, scope="decoded")
            iterator = verifier.aiter_bytes()
            assert await iterator.__anext__() == b"Hello, "
            await iterator.aclose()

    assert verifier.status is httpx.DigestStatus.INCOMPLETE
    assert not hasattr(response, "_content")


def test_response_hook_can_verify_buffered_response():
    verified: list[bool] = []

    def verify(response: httpx.Response) -> None:
        verifier = response.verify_digest(DIGEST, scope="decoded")
        verified.append(verifier.verified)

    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, content=BODY)
    )
    client = httpx.Client(
        transport=transport,
        event_hooks={"response": [verify]},
    )
    response = client.get("https://example.org/")
    assert response.content == BODY
    assert verified == [True]


def test_response_hook_streaming_response_stays_pending():
    states: list[httpx.DigestStatus] = []
    verifiers: list[httpx.DigestVerifier] = []

    def verify(response: httpx.Response) -> None:
        verifier = response.verify_digest(DIGEST, scope="decoded")
        states.append(verifier.status)
        verifiers.append(verifier)

    client = httpx.Client(
        transport=httpx.MockTransport(sync_handler),
        event_hooks={"response": [verify]},
    )
    with client.stream("GET", "https://example.org/") as response:
        assert states == [httpx.DigestStatus.PENDING]
        assert verifiers[0].read() == BODY

    assert verifiers[0].status is httpx.DigestStatus.VERIFIED


def test_head_response_with_content_length_is_not_verified_as_body():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Length": "13"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    response = client.head("https://example.org/")
    verifier = response.verify_digest(
        hashlib.sha256(b"").hexdigest(), scope="decoded"
    )
    assert verifier.verified


def test_204_response_ignores_content_length():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(204, headers={"Content-Length": "10"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    response = client.get("https://example.org/")
    verifier = response.verify_digest(
        hashlib.sha256(b"").hexdigest(), scope="decoded"
    )
    assert verifier.verified


def test_missing_raw_body_for_already_decoded_streaming_response():
    compressed = __import__("gzip").compress(BODY, mtime=0)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"Content-Encoding": "gzip"}, content=[compressed]
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with client.stream("GET", "https://example.org/") as response:
        response.read()

        verifier = response.verify_digest(
            hashlib.sha256(BODY).hexdigest(), scope="raw"
        )
        assert verifier.status is httpx.DigestStatus.INCOMPLETE
        with pytest.raises(httpx.DigestIncompleteError):
            verifier.read_raw()
