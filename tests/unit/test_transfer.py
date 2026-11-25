"""Tests for auditable download receipts and streams."""

from __future__ import annotations

import hashlib

import pytest
import requests
import responses

from gitlab import transfer, utils
from tests.unit import helpers


def _stream_response(
    content: bytes,
    *,
    headers: dict[str, str] | None = None,
    url: str = "https://example.com/path",
) -> requests.Response:
    return helpers.httmock_response(
        status_code=200,
        content=content,
        headers=headers or {},
        stream=True,
        request=requests.Request("GET", url).prepare(),
    )


def test_sanitize_url_drops_credentials():
    url = (
        "https://user:secret@gitlab.example.com/projects/1/artifacts"
        "?private_token=topsecret&job=build"
    )
    receipt = transfer.DownloadReceipt()
    receipt.bind_response(
        helpers.httmock_response(
            content=b"",
            request=requests.Request("GET", url).prepare(),
            stream=True,
        )
    )
    assert receipt.request_path == "/projects/1/artifacts?job=build"
    assert "secret" not in (receipt.request_path or "")
    assert "topsecret" not in (receipt.request_path or "")


def test_receipt_completes_full_stream():
    binary_content = b"binary content"
    response = _stream_response(
        binary_content, headers={"Content-Length": str(len(binary_content))}
    )
    receipt = transfer.DownloadReceipt(project_id=1, job_id=123)
    stream = transfer.AuditedStream(response, receipt, chunk_size=4)

    chunks = list(stream)
    assert b"".join(chunks) == binary_content
    assert receipt.complete is True
    assert receipt.error is None
    assert receipt.bytes_received == len(binary_content)
    assert receipt.expected_size == len(binary_content)
    assert receipt.sha256 == hashlib.sha256(binary_content).hexdigest()
    assert receipt.started_at is not None
    assert receipt.finished_at is not None
    assert receipt.request_path == "/path"


def test_receipt_records_early_close():
    response = _stream_response(b"binary content")
    receipt = transfer.DownloadReceipt(project_id=1, job_id=123)
    stream = transfer.AuditedStream(response, receipt, chunk_size=4)

    received = b""
    for chunk in stream:
        received += chunk
        if len(received) >= 4:
            stream.close()

    assert receipt.complete is False
    assert receipt.error == "stream_closed_early"
    assert receipt.bytes_received == len(received)
    assert receipt.sha256 == hashlib.sha256(received).hexdigest()
    assert receipt.project_id == 1
    assert receipt.job_id == 123


def test_receipt_context_manager_marks_early_close():
    response = _stream_response(b"binary content")
    receipt = transfer.DownloadReceipt()
    with transfer.AuditedStream(response, receipt, chunk_size=4) as stream:
        next(iter(stream))
    assert receipt.complete is False
    assert receipt.error == "stream_closed_early"


def test_receipt_records_stream_error():
    class FailingRaw:
        version = 11

        def stream(self, chunk_size, decode_content=False):
            yield b"abc"
            raise requests.ConnectionError("connection reset with token topsecret")

        def read(self, *args, **kwargs):
            raise requests.ConnectionError("boom")

        def release_conn(self):
            pass

    response = _stream_response(b"")
    response.raw = FailingRaw()
    receipt = transfer.DownloadReceipt()

    with pytest.raises(requests.ConnectionError):
        list(transfer.AuditedStream(response, receipt, chunk_size=4))

    assert receipt.complete is False
    assert receipt.error == "ConnectionError"
    assert receipt.bytes_received == 3
    assert "topsecret" not in (receipt.error or "")
    assert receipt.sha256 == hashlib.sha256(b"abc").hexdigest()


def test_receipt_marks_truncated_content():
    # Advertise more bytes than the server actually sends.
    response = _stream_response(
        b"binary content", headers={"Content-Length": "100"}
    )
    receipt = transfer.DownloadReceipt()
    list(transfer.AuditedStream(response, receipt, chunk_size=4))

    assert receipt.complete is False
    assert receipt.error == "incomplete_content"
    assert receipt.bytes_received == len(b"binary content")
    assert receipt.expected_size == 100


def test_receipt_without_content_length_completes_when_exhausted():
    response = _stream_response(b"binary content")
    receipt = transfer.DownloadReceipt()
    list(transfer.AuditedStream(response, receipt, chunk_size=4))
    assert receipt.complete is True
    assert receipt.error is None


def test_receipt_digest_matches_saved_copy():
    binary_content = b"binary content"
    response = _stream_response(
        binary_content, headers={"Content-Length": str(len(binary_content))}
    )
    receipt = transfer.DownloadReceipt()
    saved = b"".join(transfer.AuditedStream(response, receipt, chunk_size=4))

    assert saved == binary_content
    assert receipt.sha256 == hashlib.sha256(saved).hexdigest()


@responses.activate
def test_response_content_default_behavior_unchanged(capsys):
    responses.add(
        method="GET",
        url="https://example.com",
        status=200,
        body="test",
        content_type="application/octet-stream",
    )
    resp = requests.get("https://example.com", stream=True)
    utils.response_content(
        resp, streamed=True, action=None, chunk_size=1024, iterator=False
    )
    captured = capsys.readouterr()
    assert "test" in captured.out
