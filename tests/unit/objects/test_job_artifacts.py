"""
GitLab API: https://docs.gitlab.com/ee/api/job_artifacts.html
"""

import hashlib

import pytest
import requests
import responses

from gitlab import transfer, utils

ref_name = "main"
job = "build"


@pytest.fixture
def resp_artifacts_by_ref_name(binary_content):
    url = f"http://localhost/api/v4/projects/1/jobs/artifacts/{ref_name}/download?job={job}"

    with responses.RequestsMock() as rsps:
        rsps.add(
            method=responses.GET,
            url=url,
            body=binary_content,
            content_type="application/octet-stream",
            status=200,
        )
        yield rsps


@pytest.fixture
def resp_project_artifacts_delete():
    with responses.RequestsMock() as rsps:
        rsps.add(
            method=responses.DELETE,
            url="http://localhost/api/v4/projects/1/artifacts",
            status=204,
        )
        yield rsps


@pytest.fixture
def resp_job_artifact_bytes_range(binary_content):
    with responses.RequestsMock() as rsps:
        rsps.add(
            method=responses.GET,
            url="http://localhost/api/v4/projects/1/jobs/123/artifacts",
            body=binary_content[:10],
            content_type="application/octet-stream",
            status=206,
            match=[responses.matchers.header_matcher({"Range": "bytes=0-9"})],
        )
        yield rsps


def test_project_artifacts_delete(gl, resp_project_artifacts_delete):
    project = gl.projects.get(1, lazy=True)
    project.artifacts.delete()


def test_project_artifacts_download_by_ref_name(
    gl, binary_content, resp_artifacts_by_ref_name
):
    project = gl.projects.get(1, lazy=True)
    artifacts = project.artifacts.download(ref_name=ref_name, job=job)
    assert artifacts == binary_content


def test_job_artifact_download_bytes_range(
    gl, binary_content, resp_job_artifact_bytes_range
):
    project = gl.projects.get(1, lazy=True)
    job = project.jobs.get(123, lazy=True)

    artifacts = job.artifacts(extra_headers={"Range": "bytes=0-9"})
    assert len(artifacts) == 10


@pytest.fixture
def resp_artifacts_stream(binary_content):
    url = "http://localhost/api/v4/projects/1/jobs/123/artifacts"
    with responses.RequestsMock() as rsps:
        rsps.add(
            method=responses.GET,
            url=url,
            body=binary_content,
            content_type="application/octet-stream",
            status=200,
            headers={"Content-Length": str(len(binary_content))},
        )
        yield rsps


def test_job_artifacts_stream_receipt_matches_saved_copy(
    gl, binary_content, resp_artifacts_stream, tmp_path
):
    project = gl.projects.get(1, lazy=True)
    job = project.jobs.get(123, lazy=True)
    receipt = transfer.DownloadReceipt()

    saved = tmp_path / "artifact.zip"
    with saved.open("wb") as f:
        job.artifacts(streamed=True, action=f.write, receipt=receipt)

    assert saved.read_bytes() == binary_content
    assert receipt.complete is True
    assert receipt.error is None
    assert str(receipt.project_id) == "1"
    assert receipt.job_id == 123
    assert receipt.bytes_received == len(binary_content)
    assert receipt.expected_size == len(binary_content)
    assert receipt.request_path == "/api/v4/projects/1/jobs/123/artifacts"
    # The digest of the fully saved copy matches the receipt digest.
    assert receipt.sha256 == hashlib.sha256(saved.read_bytes()).hexdigest()


def test_job_artifacts_iterator_receipt_matches_saved_copy(
    gl, binary_content, resp_artifacts_stream
):
    project = gl.projects.get(1, lazy=True)
    job = project.jobs.get(123, lazy=True)
    receipt = transfer.DownloadReceipt()

    stream = job.artifacts(iterator=True, receipt=receipt)
    saved = b"".join(stream)

    assert saved == binary_content
    assert isinstance(stream, transfer.AuditedStream)
    assert receipt.complete is True
    assert receipt.sha256 == hashlib.sha256(binary_content).hexdigest()
    assert str(receipt.project_id) == "1"
    assert receipt.job_id == 123


def test_job_artifacts_receipt_marks_truncated_stream(
    gl, binary_content, resp_artifacts_stream, monkeypatch
):
    project = gl.projects.get(1, lazy=True)
    job = project.jobs.get(123, lazy=True)
    receipt = transfer.DownloadReceipt()

    real_init = transfer.AuditedStream.__init__

    def failing_init(self, response, receipt, chunk_size=1024):
        real_init(self, response, receipt, chunk_size=chunk_size)
        real_iterator = self._iterator

        def broken_iterator():
            # A same-named stream that breaks at the end of the transfer.
            yield from real_iterator
            raise requests.exceptions.ChunkedEncodingError(
                "connection dropped with token xyz"
            )

        self._iterator = broken_iterator()

    monkeypatch.setattr(transfer.AuditedStream, "__init__", failing_init)

    stream = job.artifacts(iterator=True, receipt=receipt)
    received = b""
    with pytest.raises(requests.exceptions.ChunkedEncodingError):
        for chunk in stream:
            received += chunk

    assert receipt.complete is False
    assert receipt.error == "ChunkedEncodingError"
    assert receipt.bytes_received == len(binary_content)
    assert receipt.expected_size == len(binary_content)
    assert str(receipt.project_id) == "1"
    assert receipt.job_id == 123
    assert received == binary_content
    # Only the exception type is retained, never its message.
    assert "xyz" not in str(receipt)


def test_job_artifacts_receipt_marks_early_close(gl, resp_artifacts_stream):
    project = gl.projects.get(1, lazy=True)
    job = project.jobs.get(123, lazy=True)
    receipt = transfer.DownloadReceipt()

    stream = job.artifacts(iterator=True, receipt=receipt)
    received = next(iter(stream))
    stream.close()

    assert receipt.complete is False
    assert receipt.error == "stream_closed_early"
    assert receipt.bytes_received == len(received)
    assert str(receipt.project_id) == "1"
    assert receipt.job_id == 123


def test_buffered_artifacts_receipt(gl, binary_content, resp_artifacts_stream):
    project = gl.projects.get(1, lazy=True)
    job = project.jobs.get(123, lazy=True)
    receipt = transfer.DownloadReceipt()

    content = job.artifacts(receipt=receipt)

    assert content == binary_content
    assert receipt.complete is True
    assert receipt.bytes_received == len(binary_content)
    assert receipt.sha256 == hashlib.sha256(binary_content).hexdigest()


def test_artifact_download_receipt_strips_credentials(gl, binary_content):
    url = (
        "http://localhost/api/v4/projects/1/jobs/artifacts/main/download"
        "?job=build&private_token=topsecret"
    )
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(
            method=responses.GET,
            url=url,
            body=binary_content,
            content_type="application/octet-stream",
            status=200,
        )
        # Issue the raw request through a receipt directly, so the sensitive
        # query string is present on response.request.url like a real redirect.
        response = gl.http_get(
            "/projects/1/jobs/artifacts/main/download",
            query_data={
                "job": "build",
                "private_token": "topsecret",
            },
            streamed=True,
            raw=True,
        )
        receipt = transfer.DownloadReceipt()
        utils.response_content(
            response,
            streamed=False,
            action=None,
            chunk_size=1024,
            iterator=False,
            receipt=receipt,
        )

    assert receipt.complete is True
    assert receipt.request_path == (
        "/api/v4/projects/1/jobs/artifacts/main/download?job=build"
    )
    assert "topsecret" not in str(receipt)
