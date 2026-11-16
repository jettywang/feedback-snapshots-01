"""
Byte-level contract tests for pre-signed URL request construction.

A pre-signed URL (eg. AWS SigV4 or GCS signed URLs) embeds a signature that
covers the *exact bytes* of the request target (path + query) and, typically,
the `Host` header. Two URLs that display the same text can still sign
different bytes (`/a%2Fb` vs `/a/b`), so "looks identical" is not good enough.

These tests pin the contract that:

* Copying a URL, adding unrelated request options, and sending the request
  through a client + transport never silently rewrites the signed bytes.
* Re-encoding only happens when the user explicitly asks for it
  (`params=...`, `copy_with(path=...)`, ...), and those rewrites are visible
  in tests rather than silent.
* Invalid authorities are rejected with `InvalidURL`, never silently repaired.

The expected values below are independent byte literals, derived by hand from
RFC 3986 and UTF-8, not from httpx's own encoding output.
"""

import hashlib
import hmac
import typing

import pytest

import httpx


def sign(raw_target: bytes, host: bytes) -> bytes:
    """
    A toy signature, standing in for SigV4-style coverage of the exact
    wire bytes of the request target and `Host` header.
    """
    message = host + b"\n" + raw_target
    return hmac.new(b"test-secret", message, hashlib.sha256).hexdigest().encode("ascii")


# Each sample is a pre-signed URL string together with the exact bytes that
# must appear on the wire: the request target (`url.raw_path`) and the
# `Host` header. Written as independent literals, covering encoded slashes,
# duplicate query keys, empty values, plus signs, percent-encoding case,
# and non-ASCII input in both pre-encoded and literal form.
SIGNED_URL_SAMPLES: typing.List[typing.Tuple[str, bytes, bytes]] = [
    # Encoded slashes in the path must not be decoded or re-encoded.
    (
        "https://signed.example.com/bucket/a%2Fb%2Fc"
        "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=deadbeef",
        b"/bucket/a%2Fb%2Fc"
        b"?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=deadbeef",
        b"signed.example.com",
    ),
    # Lowercase percent-encoding in the query keeps its exact case.
    (
        "https://signed.example.com/bucket/key"
        "?X-Amz-Credential=ak%2f2026%2fus-east-1%2fs3",
        b"/bucket/key?X-Amz-Credential=ak%2f2026%2fus-east-1%2fs3",
        b"signed.example.com",
    ),
    # Duplicate query keys are preserved, in order.
    (
        "https://signed.example.com/bucket/key"
        "?versionId=aaa&versionId=bbb&X-Amz-Signature=s",
        b"/bucket/key?versionId=aaa&versionId=bbb&X-Amz-Signature=s",
        b"signed.example.com",
    ),
    # Empty values and bare keys are preserved as written.
    (
        "https://signed.example.com/bucket/key?acl=&uploads&X-Amz-Signature=s",
        b"/bucket/key?acl=&uploads&X-Amz-Signature=s",
        b"signed.example.com",
    ),
    # '+' in the query is a literal plus byte, not a space, not '%2B'.
    (
        "https://signed.example.com/bucket/key?marker=a+b+c",
        b"/bucket/key?marker=a+b+c",
        b"signed.example.com",
    ),
    # Mixed percent-encoding case across path and query is preserved.
    (
        "https://signed.example.com/b%2Fucket/k%2fey?x=%2F",
        b"/b%2Fucket/k%2fey?x=%2F",
        b"signed.example.com",
    ),
    # Pre-encoded non-ASCII bytes are preserved exactly.
    (
        "https://signed.example.com/bucket/%C3%A9?prefix=%E4%B8%AD%2F",
        b"/bucket/%C3%A9?prefix=%E4%B8%AD%2F",
        b"signed.example.com",
    ),
    # Literal non-ASCII input is encoded once, as uppercase UTF-8 escapes.
    (
        "https://signed.example.com/bucket/é/中?k=值",
        b"/bucket/%C3%A9/%E4%B8%AD?k=%E5%80%BC",
        b"signed.example.com",
    ),
    # A trailing '?' is significant and must survive to the wire.
    (
        "https://signed.example.com/bucket?",
        b"/bucket?",
        b"signed.example.com",
    ),
    # A non-default port is part of the signed `Host` header.
    (
        "https://signed.example.com:8443/bucket/key?x=1",
        b"/bucket/key?x=1",
        b"signed.example.com:8443",
    ),
]


# Pairs of URLs whose *decoded* display is identical, but whose signed bytes
# differ. Textual equality of `.path` or `.params` must never be mistaken
# for byte equality of the wire target.
SEMANTICALLY_SIMILAR_PAIRS: typing.List[typing.Tuple[str, str]] = [
    # Encoded slash vs path separator: `.path` is "/a/b" for both.
    (
        "https://signed.example.com/a%2Fb",
        "https://signed.example.com/a/b",
    ),
    # '+' vs '%20' in the query: `.params` decodes both to "a b".
    (
        "https://signed.example.com/?x=a+b",
        "https://signed.example.com/?x=a%20b",
    ),
    # Percent-encoding case: both decode to "/".
    (
        "https://signed.example.com/?x=%2f",
        "https://signed.example.com/?x=%2F",
    ),
    # Empty value vs bare key: `parse_qs` treats both as "".
    (
        "https://signed.example.com/?a=&b=2",
        "https://signed.example.com/?a&b=2",
    ),
]


class TargetCapture:
    """
    A transport handler that records the exact bytes a request would
    be sent with: the request target and the `Host` header.
    """

    def __init__(self) -> None:
        self.raw_path: typing.Optional[bytes] = None
        self.host: typing.Optional[bytes] = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.raw_path = request.url.raw_path
        self.host = request.headers["host"].encode("ascii")
        return httpx.Response(200)


# `httpx.URL` construction.


@pytest.mark.parametrize("url, expected_raw_path, expected_host", SIGNED_URL_SAMPLES)
def test_url_preserves_signed_bytes(url, expected_raw_path, expected_host):
    parsed = httpx.URL(url)
    assert parsed.raw_path == expected_raw_path
    assert parsed.netloc == expected_host


@pytest.mark.parametrize("url, expected_raw_path, expected_host", SIGNED_URL_SAMPLES)
def test_url_copies_preserve_signed_bytes(url, expected_raw_path, expected_host):
    original = httpx.URL(url)

    # Copying via the constructor, via `str()`, and via `copy_with()`
    # must all be byte-identical on the signed components.
    assert httpx.URL(original).raw_path == expected_raw_path
    assert httpx.URL(str(original)).raw_path == expected_raw_path
    assert original.copy_with().raw_path == expected_raw_path

    # The fragment is not part of the signed target. Changing it must
    # not touch the signed bytes.
    assert original.copy_with(fragment="unrelated").raw_path == expected_raw_path


def test_user_requested_reencoding_is_explicit():
    """
    Re-encoding only happens through explicit encoding interfaces,
    and produces documented, visible rewrites.
    """
    url = httpx.URL("https://signed.example.com/a%2Fb?x=%2f")

    # Explicitly replacing the path re-encodes it as given.
    assert url.copy_with(path="/a/b").raw_path == b"/a/b?x=%2f"

    # Explicitly supplying `params=...` rebuilds the entire query
    # through `QueryParams`, replacing the signed query string.
    assert httpx.URL(url, params={"y": "a b"}).raw_path == b"/a%2Fb?y=a+b"

    # Explicitly supplying a raw `query=...` uses those exact bytes.
    assert httpx.URL(url, query=b"x=%2f&y=1").raw_path == b"/a%2Fb?x=%2f&y=1"


def test_queryparams_reencoding_is_not_byte_stable():
    """
    `QueryParams` is a decoding/re-encoding interface: round-tripping a
    signed query through it normalizes percent-encoding case. This pins
    the existing behavior of the normal encoding interface, and is exactly
    why signed URLs must never pass through it silently.
    """
    signed_query = "x=%2f&plus=a+b&empty="
    assert str(httpx.QueryParams(signed_query)) == "x=%2F&plus=a+b&empty="


# `httpx.Request` construction.


@pytest.mark.parametrize("url, expected_raw_path, expected_host", SIGNED_URL_SAMPLES)
def test_request_with_unrelated_options_preserves_signed_bytes(
    url, expected_raw_path, expected_host
):
    request = httpx.Request(
        "GET",
        url,
        headers={"X-Unrelated": "true"},
        cookies={"session": "abc"},
        extensions={"trace": "unrelated"},
    )
    assert request.url.raw_path == expected_raw_path
    # The `Host` header is typically covered by the signature.
    assert request.headers["host"].encode("ascii") == expected_host


def test_request_params_argument_replaces_signed_query():
    """
    Passing `params=...` to a request is a user-requested rewrite:
    it replaces the *entire* signed query. Pinned here so the behavior
    is explicit rather than a silent surprise.
    """
    url = "https://signed.example.com/bucket/key?X-Amz-Signature=s"
    request = httpx.Request("GET", url, params={"y": "a b"})
    assert request.url.raw_path == b"/bucket/key?y=a+b"


# End-to-end: public client API through to the transport.


@pytest.mark.parametrize("url, expected_raw_path, expected_host", SIGNED_URL_SAMPLES)
def test_client_send_preserves_signed_bytes(url, expected_raw_path, expected_host):
    """
    From the public client API to the transport: neither client-level
    configuration nor per-request unrelated options may alter the bytes
    that the signature covers.
    """
    capture = TargetCapture()
    client = httpx.Client(
        transport=httpx.MockTransport(capture),
        base_url="https://other.example.com",
        headers={"User-Agent": "test-suite"},
        event_hooks={"request": [lambda request: None]},
    )
    client.get(
        url,
        headers={"X-Unrelated": "true"},
        timeout=5.0,
        follow_redirects=True,
    )
    assert capture.raw_path == expected_raw_path
    assert capture.host == expected_host


@pytest.mark.anyio
async def test_async_client_send_preserves_signed_bytes():
    url, expected_raw_path, expected_host = SIGNED_URL_SAMPLES[0]
    capture = TargetCapture()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(capture),
        headers={"User-Agent": "test-suite"},
    ) as client:
        await client.get(url, headers={"X-Unrelated": "true"})
    assert capture.raw_path == expected_raw_path
    assert capture.host == expected_host


def test_client_level_params_replace_signed_query():
    """
    Client-level `params=...` are merged into every request and *replace*
    the signed query string. This rewrites the signed target, so it must
    be visible in tests rather than silent.
    """
    capture = TargetCapture()
    client = httpx.Client(
        transport=httpx.MockTransport(capture), params={"token": "abc"}
    )
    client.get("https://signed.example.com/bucket/key?X-Amz-Signature=s")
    assert capture.raw_path == b"/bucket/key?token=abc"


# Counterexamples: semantically similar URLs that sign different bytes.


@pytest.mark.parametrize("url_a, url_b", SEMANTICALLY_SIMILAR_PAIRS)
def test_semantically_similar_urls_sign_different_bytes(url_a, url_b):
    a, b = httpx.URL(url_a), httpx.URL(url_b)

    # The decoded, textual display is identical...
    assert a.path == b.path
    assert dict(a.params) == dict(b.params)

    # ...but the signed bytes differ, and so does any signature over them.
    assert a.raw_path != b.raw_path
    assert sign(a.raw_path, a.netloc) != sign(b.raw_path, b.netloc)


@pytest.mark.parametrize("url_a, url_b", SEMANTICALLY_SIMILAR_PAIRS)
def test_semantically_similar_urls_keep_their_difference_on_the_wire(url_a, url_b):
    """
    The byte difference between lookalike URLs survives all the way
    to the transport; httpx does not normalize one into the other.
    """
    sent: typing.List[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.url.raw_path)
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    client.get(url_a)
    client.get(url_b)
    assert sent == [httpx.URL(url_a).raw_path, httpx.URL(url_b).raw_path]
    assert sent[0] != sent[1]


# Invalid authorities are rejected, never silently repaired.


@pytest.mark.parametrize(
    "url",
    [
        "https://signed.example.com:notaport/bucket/key",
        "https://signed.example.com:443:443/bucket/key",
        "https://999.999.999.999/bucket/key",
        "https://[::1/bucket/key",
        "https://[not-an-ipv6]/bucket/key",
    ],
)
def test_invalid_authority_is_rejected_not_repaired(url):
    with pytest.raises(httpx.InvalidURL):
        httpx.URL(url)
