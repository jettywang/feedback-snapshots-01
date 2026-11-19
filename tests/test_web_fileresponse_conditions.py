"""Exhaustive conditional-request and Range matrix for FileResponse.

The matrix runs entirely in memory against short, fixed files: a custom
stream writer captures every body byte while a mocked request supplies the
conditional and range headers.  Each case asserts the exact status, the
relevant representation headers, and the precise bytes emitted, so a failed
precondition can never leak a fragment of the protected file.
"""

import gzip
import math
import os
import time
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import pytest

from aiohttp import hdrs, web_fileresponse
from aiohttp.test_utils import make_mocked_request
from aiohttp.web_fileresponse import FileResponse

FILE_CONTENT = b"0123456789abcdef"  # 16 bytes, deliberately short
FILE_SIZE = len(FILE_CONTENT)


@pytest.fixture(autouse=True)
def force_sendfile_fallback() -> None:
    """Route all transfers through the chunked, in-memory fallback writer."""
    with mock.patch.object(web_fileresponse, "NOSENDFILE", True):
        yield


@dataclass
class CapturedResponse:
    status: int
    headers: dict[str, str]
    body: bytes


class MemoryWriter:
    """An in-memory AbstractStreamWriter stand-in that records body bytes."""

    buffer_size = 0
    output_size = 0
    length = 0
    on_body_write = None
    transport = None

    def __init__(self) -> None:
        self._chunks: list[bytes] = []
        self.headers: dict[str, str] = {}
        self.chunked = False

    async def write(self, chunk: bytes) -> None:
        self._chunks.append(bytes(chunk))

    async def write_eof(self, chunk: bytes = b"") -> None:
        if chunk:
            self._chunks.append(bytes(chunk))

    async def drain(self) -> None:
        return None

    def enable_compression(self, encoding: str = "deflate", strategy=None) -> None:
        raise AssertionError("FileResponse must not compress an open file")

    def enable_chunking(self) -> None:
        self.chunked = True

    async def write_headers(self, status_line: str, headers) -> None:
        self.headers = {k: v for k, v in headers.items()}

    def send_headers(self) -> None:
        return None

    @property
    def body(self) -> bytes:
        return b"".join(self._chunks)


def http_date(epoch_seconds: float) -> str:
    return time.strftime(
        "%a, %d %b %Y %H:%M:%S GMT", time.gmtime(epoch_seconds)
    )


@pytest.fixture
def file_path(tmp_path: Path) -> Path:
    path = tmp_path / "matrix.bin"
    path.write_bytes(FILE_CONTENT)
    # Pin a sub-second mtime so HTTP-date rounding behaviour is exercised.
    stamp_ns = int((math.floor(time.time()) + 0.25) * 1_000_000_000)
    os.utime(path, ns=(stamp_ns, stamp_ns))
    return path


@dataclass(frozen=True)
class Precompressed:
    base_path: Path
    gz_path: Path
    compressed: bytes


@pytest.fixture
def precompressed(tmp_path: Path) -> Precompressed:
    # The response is built for the base path; the .gz sibling is selected
    # only when the request advertises gzip support.
    base_path = tmp_path / "matrix.bin"
    base_path.write_bytes(FILE_CONTENT)
    compressed = gzip.compress(FILE_CONTENT)
    gz_path = tmp_path / "matrix.bin.gz"
    gz_path.write_bytes(compressed)
    return Precompressed(base_path, gz_path, compressed)


def etag_for(path: Path) -> str:
    st = path.stat()
    return f'"{st.st_mtime_ns:x}-{st.st_size:x}"'


def last_modified_for(path: Path) -> str:
    return http_date(math.ceil(path.stat().st_mtime))


async def prepare_file(
    path: Path,
    method: str = hdrs.METH_GET,
    headers: dict[str, str] | None = None,
    *,
    accept_encoding: str = "",
) -> CapturedResponse:
    writer = MemoryWriter()
    request_headers = dict(headers or {})
    if accept_encoding:
        request_headers[hdrs.ACCEPT_ENCODING] = accept_encoding
    request = make_mocked_request(
        method,
        "http://example.com/matrix.bin",
        headers=request_headers,
        writer=writer,
    )
    response = FileResponse(path, chunk_size=4)
    await response.prepare(request)
    return CapturedResponse(
        status=response.status,
        headers=dict(writer.headers),
        body=writer.body,
    )


# ---------------------------------------------------------------------------
# Unconditional baseline
# ---------------------------------------------------------------------------


async def test_full_get_sends_every_byte_with_validators(file_path: Path) -> None:
    captured = await prepare_file(file_path)

    assert captured.status == 200
    assert captured.body == FILE_CONTENT
    assert captured.headers[hdrs.CONTENT_LENGTH] == str(FILE_SIZE)
    assert captured.headers[hdrs.ETAG] == etag_for(file_path)
    assert captured.headers[hdrs.LAST_MODIFIED] == last_modified_for(file_path)
    assert captured.headers[hdrs.ACCEPT_RANGES] == "bytes"
    assert hdrs.CONTENT_RANGE not in captured.headers


async def test_head_emits_headers_but_no_body(file_path: Path) -> None:
    captured = await prepare_file(file_path, method=hdrs.METH_HEAD)

    assert captured.status == 200
    assert captured.body == b""
    assert captured.headers[hdrs.CONTENT_LENGTH] == str(FILE_SIZE)
    assert hdrs.CONTENT_RANGE not in captured.headers


# ---------------------------------------------------------------------------
# If-Match (strong comparison only)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "if_match",
    [
        lambda p: etag_for(p),
        lambda p: f'"other", {etag_for(p)}',
        lambda p: "*",
    ],
    ids=["exact", "list-match", "star"],
)
async def test_if_match_success_sends_file(
    file_path: Path, if_match
) -> None:
    captured = await prepare_file(
        file_path, headers={hdrs.IF_MATCH: if_match(file_path)}
    )

    assert captured.status == 200
    assert captured.body == FILE_CONTENT


@pytest.mark.parametrize(
    "if_match",
    [
        lambda p: f"W/{etag_for(p)}",
        lambda p: '"stale-etag"',
    ],
    ids=["weak-current", "stale"],
)
async def test_if_match_failure_is_412_without_bytes(
    file_path: Path, if_match
) -> None:
    captured = await prepare_file(
        file_path, headers={hdrs.IF_MATCH: if_match(file_path)}
    )

    assert captured.status == 412
    assert captured.body == b""
    assert FILE_CONTENT not in captured.body


async def test_if_match_failure_takes_precedence_over_range(
    file_path: Path,
) -> None:
    headers = {
        hdrs.IF_MATCH: '"stale-etag"',
        hdrs.RANGE: "bytes=2-5",
    }
    captured = await prepare_file(file_path, headers=headers)

    assert captured.status == 412
    assert captured.body == b""
    assert hdrs.CONTENT_RANGE not in captured.headers


# ---------------------------------------------------------------------------
# If-Unmodified-Since
# ---------------------------------------------------------------------------


async def test_if_unmodified_since_future_allows(file_path: Path) -> None:
    future = http_date(time.time() + 10_000)
    captured = await prepare_file(
        file_path, headers={hdrs.IF_UNMODIFIED_SINCE: future}
    )

    assert captured.status == 200
    assert captured.body == FILE_CONTENT


async def test_if_unmodified_since_past_is_412(file_path: Path) -> None:
    past = "Mon, 1 Jan 1990 00:00:00 GMT"
    captured = await prepare_file(
        file_path, headers={hdrs.IF_UNMODIFIED_SINCE: past}
    )

    assert captured.status == 412
    assert captured.body == b""


async def test_if_match_outranks_if_unmodified_since(file_path: Path) -> None:
    # If-Match succeeds, so a stale If-Unmodified-Since must be ignored.
    future_past = "Mon, 1 Jan 1990 00:00:00 GMT"
    captured = await prepare_file(
        file_path,
        headers={
            hdrs.IF_MATCH: etag_for(file_path),
            hdrs.IF_UNMODIFIED_SINCE: future_past,
        },
    )

    assert captured.status == 200
    assert captured.body == FILE_CONTENT


# ---------------------------------------------------------------------------
# If-None-Match (weak allowed; method-dependent outcome)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method", [hdrs.METH_GET, hdrs.METH_HEAD], ids=["get", "head"]
)
@pytest.mark.parametrize(
    "if_none_match",
    [
        lambda p: etag_for(p),
        lambda p: f"W/{etag_for(p)}",
        lambda p: "*",
    ],
    ids=["strong-current", "weak-current", "star"],
)
async def test_if_none_match_get_head_is_304(
    file_path: Path, method, if_none_match
) -> None:
    captured = await prepare_file(
        file_path, method=method, headers={hdrs.IF_NONE_MATCH: if_none_match(file_path)}
    )

    assert captured.status == 304
    assert captured.body == b""
    assert captured.headers[hdrs.ETAG] == etag_for(file_path)
    assert captured.headers[hdrs.LAST_MODIFIED] == last_modified_for(file_path)
    # 304 responses never carry a body length or content range.
    assert hdrs.CONTENT_LENGTH not in captured.headers
    assert hdrs.CONTENT_RANGE not in captured.headers


@pytest.mark.parametrize(
    "method", [hdrs.METH_POST, hdrs.METH_PUT], ids=["post", "put"]
)
async def test_if_none_match_match_on_writer_is_412(
    file_path: Path, method
) -> None:
    captured = await prepare_file(
        file_path,
        method=method,
        headers={hdrs.IF_NONE_MATCH: etag_for(file_path)},
    )

    assert captured.status == 412
    assert captured.body == b""


async def test_if_none_match_mismatch_sends_file(file_path: Path) -> None:
    captured = await prepare_file(
        file_path, headers={hdrs.IF_NONE_MATCH: '"different-representation"'}
    )

    assert captured.status == 200
    assert captured.body == FILE_CONTENT


async def test_if_none_match_outranks_if_modified_since(
    file_path: Path,
) -> None:
    captured = await prepare_file(
        file_path,
        headers={
            hdrs.IF_NONE_MATCH: etag_for(file_path),
            # A past date would otherwise allow sending the file.
            hdrs.IF_MODIFIED_SINCE: "Mon, 1 Jan 1990 00:00:00 GMT",
        },
    )

    assert captured.status == 304
    assert captured.body == b""


# ---------------------------------------------------------------------------
# If-Modified-Since
# ---------------------------------------------------------------------------


async def test_if_modified_since_equal_is_304(file_path: Path) -> None:
    captured = await prepare_file(
        file_path,
        headers={hdrs.IF_MODIFIED_SINCE: last_modified_for(file_path)},
    )

    assert captured.status == 304
    assert captured.body == b""


async def test_if_modified_since_past_sends_file(file_path: Path) -> None:
    captured = await prepare_file(
        file_path,
        headers={hdrs.IF_MODIFIED_SINCE: "Mon, 1 Jan 1990 00:00:00 GMT"},
    )

    assert captured.status == 200
    assert captured.body == FILE_CONTENT


async def test_invalid_date_headers_are_ignored(file_path: Path) -> None:
    captured = await prepare_file(
        file_path,
        headers={
            hdrs.IF_MODIFIED_SINCE: "not-a-date",
            hdrs.IF_UNMODIFIED_SINCE: "garbage",
        },
    )

    assert captured.status == 200
    assert captured.body == FILE_CONTENT


# ---------------------------------------------------------------------------
# Range without If-Range
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "range_header,expected_status,expected_body,expected_range",
    [
        ("bytes=0-3", 206, b"0123", f"bytes 0-3/{FILE_SIZE}"),
        ("bytes=2-5", 206, b"2345", f"bytes 2-5/{FILE_SIZE}"),
        ("bytes=12-", 206, b"cdef", f"bytes 12-15/{FILE_SIZE}"),
        ("bytes=10-100", 206, b"abcdef", f"bytes 10-15/{FILE_SIZE}"),
        ("bytes=-4", 206, b"cdef", f"bytes 12-15/{FILE_SIZE}"),
        ("bytes=-1000", 206, FILE_CONTENT, f"bytes 0-15/{FILE_SIZE}"),
        ("bytes=16-", 416, b"", None),
        ("bytes=100-200", 416, b"", None),
        ("bytes=-", 416, b"", None),
        ("blocks=0-3", 416, b"", None),
    ],
    ids=[
        "prefix",
        "middle",
        "open-ended",
        "oversized-end",
        "suffix",
        "suffix-overflow-clamped",
        "start-at-size",
        "start-beyond-size",
        "empty-spec",
        "wrong-unit",
    ],
)
async def test_range_matrix(
    file_path: Path,
    range_header: str,
    expected_status: int,
    expected_body: bytes,
    expected_range: str | None,
) -> None:
    captured = await prepare_file(file_path, headers={hdrs.RANGE: range_header})

    assert captured.status == expected_status
    assert captured.body == expected_body
    if expected_status == 206:
        assert captured.headers[hdrs.CONTENT_RANGE] == expected_range
        assert captured.headers[hdrs.CONTENT_LENGTH] == str(len(expected_body))
        assert captured.headers[hdrs.ACCEPT_RANGES] == "bytes"
    else:
        assert captured.headers[hdrs.CONTENT_RANGE] == f"bytes */{FILE_SIZE}"
        assert captured.body == b""


async def test_range_on_head_keeps_headers_and_empty_body(file_path: Path) -> None:
    captured = await prepare_file(
        file_path, method=hdrs.METH_HEAD, headers={hdrs.RANGE: "bytes=2-5"}
    )

    assert captured.status == 206
    assert captured.body == b""
    assert captured.headers[hdrs.CONTENT_RANGE] == f"bytes 2-5/{FILE_SIZE}"
    assert captured.headers[hdrs.CONTENT_LENGTH] == "4"


# ---------------------------------------------------------------------------
# If-Range gating
# ---------------------------------------------------------------------------


async def test_if_range_strong_etag_match_applies_range(file_path: Path) -> None:
    captured = await prepare_file(
        file_path,
        headers={hdrs.IF_RANGE: etag_for(file_path), hdrs.RANGE: "bytes=2-5"},
    )

    assert captured.status == 206
    assert captured.body == b"2345"
    assert captured.headers[hdrs.CONTENT_RANGE] == f"bytes 2-5/{FILE_SIZE}"


async def test_if_range_weak_etag_never_authorizes_partial(file_path: Path) -> None:
    captured = await prepare_file(
        file_path,
        headers={
            hdrs.IF_RANGE: f"W/{etag_for(file_path)}",
            hdrs.RANGE: "bytes=2-5",
        },
    )

    # A weak validator is not an exact-content identity: fall back to 200.
    assert captured.status == 200
    assert captured.body == FILE_CONTENT
    assert hdrs.CONTENT_RANGE not in captured.headers
    assert captured.headers[hdrs.CONTENT_LENGTH] == str(FILE_SIZE)


async def test_if_range_stale_etag_ignores_range(file_path: Path) -> None:
    captured = await prepare_file(
        file_path,
        headers={hdrs.IF_RANGE: '"stale"', hdrs.RANGE: "bytes=2-5"},
    )

    assert captured.status == 200
    assert captured.body == FILE_CONTENT


async def test_if_range_matching_date_applies_range(file_path: Path) -> None:
    captured = await prepare_file(
        file_path,
        headers={
            hdrs.IF_RANGE: last_modified_for(file_path),
            hdrs.RANGE: "bytes=2-5",
        },
    )

    assert captured.status == 206
    assert captured.body == b"2345"


async def test_if_range_stale_date_ignores_range(file_path: Path) -> None:
    captured = await prepare_file(
        file_path,
        headers={
            hdrs.IF_RANGE: "Mon, 1 Jan 1990 00:00:00 GMT",
            hdrs.RANGE: "bytes=2-5",
        },
    )

    assert captured.status == 200
    assert captured.body == FILE_CONTENT


@pytest.mark.parametrize(
    "if_range",
    ["{etag}", '"{etag}', "not-a-date"],
    ids=["unquoted", "unterminated", "garbage"],
)
async def test_if_range_malformed_ignores_range(
    file_path: Path, if_range: str
) -> None:
    etag = etag_for(file_path).strip('"')
    captured = await prepare_file(
        file_path,
        headers={
            hdrs.IF_RANGE: if_range.format(etag=etag),
            hdrs.RANGE: "bytes=2-5",
        },
    )

    assert captured.status == 200
    assert captured.body == FILE_CONTENT


async def test_if_range_without_range_header_sends_full(file_path: Path) -> None:
    captured = await prepare_file(
        file_path, headers={hdrs.IF_RANGE: etag_for(file_path)}
    )

    assert captured.status == 200
    assert captured.body == FILE_CONTENT
    assert hdrs.CONTENT_RANGE not in captured.headers


# ---------------------------------------------------------------------------
# Combined precondition + range: failed preconditions must never emit bytes
# ---------------------------------------------------------------------------


async def test_failed_precondition_blocks_range_fragment(file_path: Path) -> None:
    captured = await prepare_file(
        file_path,
        headers={
            hdrs.IF_UNMODIFIED_SINCE: "Mon, 1 Jan 1990 00:00:00 GMT",
            hdrs.RANGE: "bytes=0-3",
        },
    )

    assert captured.status == 412
    assert captured.body == b""
    assert hdrs.CONTENT_RANGE not in captured.headers


async def test_not_modified_blocks_range_fragment(file_path: Path) -> None:
    captured = await prepare_file(
        file_path,
        headers={
            hdrs.IF_NONE_MATCH: etag_for(file_path),
            hdrs.RANGE: "bytes=0-3",
        },
    )

    assert captured.status == 304
    assert captured.body == b""
    assert hdrs.CONTENT_RANGE not in captured.headers


async def test_failed_precondition_closes_handle_without_reading(
    file_path: Path,
) -> None:
    # The representation is opened (and re-statted) but must be closed before
    # any byte can reach the writer when a precondition does not hold.
    real_open = file_path.open
    handle = None

    def tracking_open(self_path, *args, **kwargs):
        nonlocal handle
        assert self_path == file_path
        handle = real_open(*args, **kwargs)
        return handle

    with mock.patch.object(Path, "open", autospec=True, side_effect=tracking_open):
        captured = await prepare_file(
            file_path, headers={hdrs.IF_MATCH: '"stale-etag"'}
        )

    assert captured.status == 412
    assert captured.body == b""
    assert handle is not None
    assert handle.closed is True


# ---------------------------------------------------------------------------
# Compressed representation: ranges and lengths use the selected variant
# ---------------------------------------------------------------------------


async def test_precompressed_representation_measured_on_its_own(
    precompressed: Precompressed,
) -> None:
    captured = await prepare_file(
        precompressed.base_path, accept_encoding="gzip"
    )

    assert captured.status == 200
    assert captured.body == precompressed.compressed
    assert captured.headers[hdrs.CONTENT_ENCODING] == "gzip"
    assert captured.headers[hdrs.VARY] == hdrs.ACCEPT_ENCODING
    assert captured.headers[hdrs.CONTENT_LENGTH] == str(
        len(precompressed.compressed)
    )
    assert captured.headers[hdrs.ETAG] == etag_for(precompressed.gz_path)


async def test_precompressed_range_uses_compressed_bounds(
    precompressed: Precompressed,
) -> None:
    captured = await prepare_file(
        precompressed.base_path,
        headers={hdrs.RANGE: "bytes=2-5"},
        accept_encoding="gzip",
    )

    assert captured.status == 206
    assert captured.body == precompressed.compressed[2:6]
    assert captured.headers[hdrs.CONTENT_RANGE] == (
        f"bytes 2-5/{len(precompressed.compressed)}"
    )
    assert captured.headers[hdrs.CONTENT_LENGTH] == "4"


async def test_precompressed_if_range_uses_compressed_etag(
    precompressed: Precompressed,
) -> None:
    captured = await prepare_file(
        precompressed.base_path,
        headers={
            hdrs.IF_RANGE: etag_for(precompressed.gz_path),
            hdrs.RANGE: "bytes=1-3",
        },
        accept_encoding="gzip",
    )

    assert captured.status == 206
    assert captured.body == precompressed.compressed[1:4]
    assert captured.headers[hdrs.CONTENT_RANGE] == (
        f"bytes 1-3/{len(precompressed.compressed)}"
    )
