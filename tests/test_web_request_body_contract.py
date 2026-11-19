"""Consumption contract tests for the request body APIs.

A signature middleware and the business handler must observe the same
actual body bytes no matter which combination of read()/text()/json()/
post()/multipart()/request.content they use. Irreversible consumption
must fail loudly instead of handing later consumers an empty or partial
body that still looks like a complete parse.
"""

import asyncio
import hashlib
import hmac
from typing import Any
from unittest import mock

import pytest

from aiohttp import web
from aiohttp.streams import StreamReader
from aiohttp.test_utils import make_mocked_request

SIGNING_KEY = b"contract-test-key"

JSON_BODY = b'{"signed": "payload"}'
JSON_HEADERS = {"Content-Type": "application/json"}

FORM_BODY = b"a=1&b=2&b=3"
FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}

MULTIPART_BODY = (
    b"--boundary123\r\n"
    b'Content-Disposition: form-data; name="field1"\r\n'
    b"\r\n"
    b"value1\r\n"
    b"--boundary123\r\n"
    b'Content-Disposition: form-data; name="file1"; filename="a.txt"\r\n'
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"file-content\r\n"
    b"--boundary123--\r\n"
)
MULTIPART_HEADERS = {"Content-Type": "multipart/form-data; boundary=boundary123"}


def sign(body: bytes) -> str:
    """Independent digest used to stand in for signature verification."""
    return hmac.new(SIGNING_KEY, body, hashlib.sha256).hexdigest()


class MeteredStreamReader(StreamReader):
    """StreamReader that records the net byte ranges leaving the buffer."""

    def __init__(self, protocol: mock.Mock, loop: asyncio.AbstractEventLoop) -> None:
        self._consumed_log = bytearray()
        super().__init__(protocol, 2**16, loop=loop)

    def _read_nowait_chunk(self, n: int) -> bytes:
        data = super()._read_nowait_chunk(n)
        if data:
            self._consumed_log += data
        return data

    def unread_data(self, data: bytes) -> None:
        # Boundary pushback returns bytes to the stream; they are not consumed.
        if data:
            del self._consumed_log[len(self._consumed_log) - len(data) :]
        super().unread_data(data)

    @property
    def consumed(self) -> bytes:
        return bytes(self._consumed_log)


@pytest.fixture
def protocol() -> mock.Mock:
    return mock.Mock(_reading_paused=False)


def make_request(
    protocol: mock.Mock,
    body: bytes,
    *,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> tuple[web.Request, MeteredStreamReader]:
    payload = MeteredStreamReader(protocol, asyncio.get_running_loop())
    if body:
        payload.feed_data(body)
    payload.feed_eof()
    req = make_mocked_request("POST", "/", headers=headers, payload=payload, **kwargs)
    return req, payload


async def observed_bytes(req: web.Request, api: str) -> bytes:
    if api == "read":
        return await req.read()
    if api == "text":
        return (await req.text()).encode("utf-8")
    raise AssertionError(f"unknown api {api}")


@pytest.mark.parametrize("middleware_api", ["read", "text"])
@pytest.mark.parametrize("handler_api", ["read", "text"])
async def test_read_text_interleaving_same_bytes(
    protocol: mock.Mock, middleware_api: str, handler_api: str
) -> None:
    req, metered = make_request(protocol, JSON_BODY, headers=JSON_HEADERS)
    middleware_view = await observed_bytes(req, middleware_api)
    middleware_sig = sign(middleware_view)

    handler_view = await observed_bytes(req, handler_api)

    assert handler_view == JSON_BODY
    assert sign(handler_view) == middleware_sig == sign(JSON_BODY)
    # The stream was drained exactly once; the second call hit the cache.
    assert metered.consumed == JSON_BODY


async def test_read_returns_cached_object(protocol: mock.Mock) -> None:
    req, metered = make_request(protocol, JSON_BODY, headers=JSON_HEADERS)
    first = await req.read()
    second = await req.read()
    assert second is first
    assert metered.consumed == JSON_BODY


async def test_json_then_read_then_text_share_body(protocol: mock.Mock) -> None:
    req, metered = make_request(protocol, JSON_BODY, headers=JSON_HEADERS)
    assert await req.json() == {"signed": "payload"}
    assert await req.read() == JSON_BODY
    assert await req.text() == '{"signed": "payload"}'
    assert metered.consumed == JSON_BODY


async def test_signature_middleware_then_json_handler(protocol: mock.Mock) -> None:
    req, metered = make_request(protocol, JSON_BODY, headers=JSON_HEADERS)
    # Signature middleware runs first and digests the raw body.
    middleware_sig = sign(await req.read())
    # Business handler still sees the parsed view of the same bytes.
    assert await req.json() == {"signed": "payload"}
    # ... and can re-verify the raw evidence independently.
    assert sign(await req.read()) == middleware_sig == sign(JSON_BODY)
    assert metered.consumed == JSON_BODY


async def test_post_urlencoded_then_read(protocol: mock.Mock) -> None:
    req, metered = make_request(protocol, FORM_BODY, headers=FORM_HEADERS)
    middleware_view = await req.post()
    assert list(middleware_view.items()) == [("a", "1"), ("b", "2"), ("b", "3")]

    handler_body = await req.read()
    assert handler_body == FORM_BODY
    assert sign(handler_body) == sign(FORM_BODY)
    assert metered.consumed == FORM_BODY
    # Repeated post() is the cached parse, not a re-read.
    assert await req.post() is middleware_view
    assert metered.consumed == FORM_BODY


async def test_read_then_post_urlencoded(protocol: mock.Mock) -> None:
    req, metered = make_request(protocol, FORM_BODY, headers=FORM_HEADERS)
    middleware_sig = sign(await req.read())

    handler_view = await req.post()
    assert list(handler_view.items()) == [("a", "1"), ("b", "2"), ("b", "3")]
    assert sign(await req.read()) == middleware_sig == sign(FORM_BODY)
    # post() was served from the cache; nothing extra left the stream.
    assert metered.consumed == FORM_BODY


async def test_read_then_post_multipart_served_from_cache(
    protocol: mock.Mock,
) -> None:
    req, metered = make_request(protocol, MULTIPART_BODY, headers=MULTIPART_HEADERS)
    middleware_sig = sign(await req.read())

    fields = await req.post()
    assert fields["field1"] == "value1"
    file1 = fields["file1"]
    assert isinstance(file1, web.FileField)
    assert file1.file.read() == b"file-content"

    assert middleware_sig == sign(MULTIPART_BODY)
    # post() parsed the cached copy; it did not touch the drained stream.
    assert metered.consumed == MULTIPART_BODY
    req._finish()  # Closes the temp files of the parsed file fields.


async def test_read_then_multipart_reader_served_from_cache(
    protocol: mock.Mock,
) -> None:
    req, metered = make_request(protocol, MULTIPART_BODY, headers=MULTIPART_HEADERS)
    middleware_sig = sign(await req.read())

    reader = await req.multipart()
    part = await reader.next()
    assert part is not None
    assert part.name == "field1"
    assert await part.read() == b"value1"
    part = await reader.next()
    assert part is not None
    assert part.name == "file1"
    assert await part.read() == b"file-content"
    assert await reader.next() is None

    assert middleware_sig == sign(MULTIPART_BODY)
    assert metered.consumed == MULTIPART_BODY


async def test_post_multipart_then_read_raises(protocol: mock.Mock) -> None:
    req, metered = make_request(protocol, MULTIPART_BODY, headers=MULTIPART_HEADERS)
    fields = await req.post()
    assert fields["field1"] == "value1"

    # The stream is gone; read() must not silently report an empty body.
    with pytest.raises(RuntimeError, match="already consumed"):
        await req.read()
    assert metered.consumed == MULTIPART_BODY
    req._finish()  # Closes the temp files of the parsed file fields.


async def test_multipart_partially_consumed_then_read_raises(
    protocol: mock.Mock,
) -> None:
    req, metered = make_request(protocol, MULTIPART_BODY, headers=MULTIPART_HEADERS)
    reader = await req.multipart()
    part = await reader.next()
    assert part is not None
    await part.read()

    with pytest.raises(RuntimeError, match="already consumed"):
        await req.read()
    assert 0 < len(metered.consumed) < len(MULTIPART_BODY)


async def test_second_multipart_after_consumption_raises(
    protocol: mock.Mock,
) -> None:
    req, _ = make_request(protocol, MULTIPART_BODY, headers=MULTIPART_HEADERS)
    reader = await req.multipart()
    part = await reader.next()
    assert part is not None
    await part.read()

    with pytest.raises(RuntimeError, match="already consumed"):
        await req.multipart()


async def test_partial_content_read_then_read_raises(protocol: mock.Mock) -> None:
    req, metered = make_request(protocol, JSON_BODY, headers=JSON_HEADERS)
    prefix = await req.content.read(7)
    assert prefix == b'{"signe'

    with pytest.raises(RuntimeError, match="already consumed"):
        await req.read()
    # No half-complete cache: a retry keeps failing instead of returning
    # the remainder as if it were the whole body.
    with pytest.raises(RuntimeError, match="already consumed"):
        await req.read()
    assert metered.consumed == prefix


async def test_partial_content_readany_then_text_raises(protocol: mock.Mock) -> None:
    req, metered = make_request(protocol, JSON_BODY, headers=JSON_HEADERS)
    chunk = await req.content.readany()
    assert chunk == JSON_BODY[: len(chunk)]

    with pytest.raises(RuntimeError, match="already consumed"):
        await req.text()
    assert metered.consumed == chunk


async def test_partial_content_read_then_post_urlencoded_raises(
    protocol: mock.Mock,
) -> None:
    req, metered = make_request(protocol, FORM_BODY, headers=FORM_HEADERS)
    prefix = await req.content.read(3)
    assert prefix == b"a=1"

    with pytest.raises(RuntimeError, match="already consumed"):
        await req.post()
    assert metered.consumed == prefix


async def test_partial_content_read_then_post_multipart_raises(
    protocol: mock.Mock,
) -> None:
    req, metered = make_request(protocol, MULTIPART_BODY, headers=MULTIPART_HEADERS)
    prefix = await req.content.read(10)

    with pytest.raises(RuntimeError, match="already consumed"):
        await req.post()
    assert metered.consumed == prefix


async def test_partial_content_read_then_multipart_raises(
    protocol: mock.Mock,
) -> None:
    req, metered = make_request(protocol, MULTIPART_BODY, headers=MULTIPART_HEADERS)
    prefix = await req.content.read(10)

    with pytest.raises(RuntimeError, match="already consumed"):
        await req.multipart()
    assert metered.consumed == prefix


async def test_read_then_raw_content_is_exhausted(protocol: mock.Mock) -> None:
    # Documented limitation: request.content is the raw stream, so after a
    # full read() it is drained. Cached APIs (read/text/json/post) remain
    # the contract for downstream consumers.
    req, metered = make_request(protocol, JSON_BODY, headers=JSON_HEADERS)
    assert await req.read() == JSON_BODY
    assert await req.content.read() == b""
    assert metered.consumed == JSON_BODY


async def test_divergent_signature_variant_fails_loudly(
    protocol: mock.Mock,
) -> None:
    # "Signature verifies bytes A, business logic reads bytes B" must not
    # pass silently.
    body = b"signed-body-content"
    req, metered = make_request(protocol, body)
    prefix = await req.content.read(6)
    assert prefix == b"signed"
    middleware_sig = sign(body)

    with pytest.raises(RuntimeError, match="already consumed"):
        await req.read()

    # Only the prefix ever left the stream; nothing was cached.
    assert metered.consumed == prefix
    # Had the remainder been handed over as "the body", the signature
    # would not have matched.
    assert sign(body[len(prefix) :]) != middleware_sig


async def test_clone_after_read_raises(protocol: mock.Mock) -> None:
    req, _ = make_request(protocol, JSON_BODY, headers=JSON_HEADERS)
    await req.read()
    with pytest.raises(RuntimeError, match="Cannot clone"):
        req.clone()


async def test_clone_after_empty_body_read_raises(protocol: mock.Mock) -> None:
    req, _ = make_request(protocol, b"")
    assert await req.read() == b""
    with pytest.raises(RuntimeError, match="Cannot clone"):
        req.clone()


async def test_clone_after_partial_content_read_raises(protocol: mock.Mock) -> None:
    req, metered = make_request(protocol, JSON_BODY, headers=JSON_HEADERS)
    prefix = await req.content.read(4)
    with pytest.raises(RuntimeError, match="Cannot clone"):
        req.clone()
    assert metered.consumed == prefix


async def test_clone_after_post_multipart_raises(protocol: mock.Mock) -> None:
    req, _ = make_request(protocol, MULTIPART_BODY, headers=MULTIPART_HEADERS)
    await req.post()
    with pytest.raises(RuntimeError, match="Cannot clone"):
        req.clone()
    req._finish()  # Closes the temp files of the parsed file fields.


async def test_clone_drains_shared_stream_once(protocol: mock.Mock) -> None:
    req, metered = make_request(protocol, JSON_BODY, headers=JSON_HEADERS)
    clone = req.clone()

    assert await clone.read() == JSON_BODY
    # The clone consumed the shared stream; the original must not present
    # an empty body as if it were complete.
    with pytest.raises(RuntimeError, match="already consumed"):
        await req.read()
    assert metered.consumed == JSON_BODY


async def test_connection_error_mid_body_never_caches_partial(
    protocol: mock.Mock,
) -> None:
    payload = MeteredStreamReader(protocol, asyncio.get_running_loop())
    payload.feed_data(b"chunk1chunk2")
    req = make_mocked_request("POST", "/", payload=payload)

    assert await req.content.read(6) == b"chunk1"
    payload.set_exception(ConnectionError("connection lost"))

    with pytest.raises(ConnectionError):
        await req.read()
    # The failure is sticky for every later consumer; no partial cache.
    with pytest.raises(ConnectionError):
        await req.read()
    with pytest.raises(ConnectionError):
        await req.text()
    assert payload.consumed == b"chunk1"


async def test_cancelled_payload_raises_for_all_consumers(
    protocol: mock.Mock,
) -> None:
    req, metered = make_request(protocol, JSON_BODY, headers=JSON_HEADERS)
    req._cancel(asyncio.CancelledError())

    with pytest.raises(asyncio.CancelledError):
        await req.read()
    with pytest.raises(asyncio.CancelledError):
        await req.read()
    assert metered.consumed == b""


async def test_text_bad_encoding_raises_but_read_preserves_raw(
    protocol: mock.Mock,
) -> None:
    body = b"\xff\xfe not utf-8"
    req, metered = make_request(
        protocol, body, headers={"Content-Type": "text/plain; charset=utf-8"}
    )
    with pytest.raises(web.HTTPUnsupportedMediaType):
        await req.text()

    # The raw evidence is still intact for the handler.
    raw = await req.read()
    assert raw == body
    assert sign(raw) == sign(body)
    assert metered.consumed == body


async def test_text_unknown_charset_raises_but_read_preserves_raw(
    protocol: mock.Mock,
) -> None:
    body = b"some body"
    req, metered = make_request(
        protocol, body, headers={"Content-Type": "text/plain; charset=no-such-codec"}
    )
    with pytest.raises(web.HTTPUnsupportedMediaType):
        await req.text()

    assert await req.read() == body
    assert metered.consumed == body


async def test_post_bad_charset_raises_but_read_preserves_raw(
    protocol: mock.Mock,
) -> None:
    body = b"a=\xff"
    req, metered = make_request(protocol, body, headers=FORM_HEADERS)
    with pytest.raises(web.HTTPUnsupportedMediaType):
        await req.post()

    assert await req.read() == body
    assert sign(await req.read()) == sign(body)
    assert metered.consumed == body


async def test_size_limit_error_is_terminal(protocol: mock.Mock) -> None:
    body = b"x" * 32
    req, metered = make_request(protocol, body, client_max_size=8)
    with pytest.raises(web.HTTPRequestEntityTooLarge):
        await req.read()

    # The limit violation must not leave a partial body cached as complete.
    with pytest.raises(RuntimeError, match="already consumed"):
        await req.read()
    assert 0 < len(metered.consumed) <= len(body)


async def test_read_then_post_multipart_keeps_field_limit(
    protocol: mock.Mock,
) -> None:
    req, _ = make_request(
        protocol, MULTIPART_BODY, headers=MULTIPART_HEADERS, client_max_fields=1
    )
    middleware_sig = sign(await req.read())
    assert middleware_sig == sign(MULTIPART_BODY)

    # Limits still apply when the parse is served from the cached body.
    with pytest.raises(web.HTTPRequestEntityTooLarge):
        await req.post()
