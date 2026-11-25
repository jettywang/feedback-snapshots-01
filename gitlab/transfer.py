"""Auditable transfer receipts for streamed downloads.

This module provides an opt-in evidence record for streamed artifact
downloads. A :class:`DownloadReceipt` keeps track of the project and job a
download belongs to, the bytes that were actually received, a digest of those
bytes and whether the transfer completed successfully.

Credentials are never stored: only the URL path is retained and exception
messages are reduced to their type so that tokens cannot leak into a receipt.
"""

from __future__ import annotations

import dataclasses
import datetime as _datetime
import hashlib
import types
import urllib.parse
from collections.abc import Iterator

import requests

__all__ = ["AuditedStream", "DownloadReceipt"]

# Query parameters that may carry credentials and must never be recorded.
_SENSITIVE_QUERY_PARAMS = frozenset(
    {"private_token", "token", "job_token", "access_token", "jwt"}
)


def _sanitize_url(url: str | None) -> str | None:
    """Return a safe representation of a URL.

    Only the path component is kept. User info and the query string (which may
    contain a token) are dropped, along with the host, so no credential can end
    up in a receipt.
    """
    if not url:
        return None
    parsed = urllib.parse.urlsplit(url)
    safe_query = urllib.parse.urlencode(
        [
            (key, value)
            for key, value in urllib.parse.parse_qsl(
                parsed.query, keep_blank_values=True
            )
            if key.lower() not in _SENSITIVE_QUERY_PARAMS
        ]
    )
    path = urllib.parse.urlunsplit(("", "", parsed.path, safe_query, ""))
    return path or None


@dataclasses.dataclass
class DownloadReceipt:
    """Evidence record of a streamed download.

    The receipt is updated while chunks are received. It can be inspected at
    any time, including after an early close or a stream error, in which case
    :attr:`complete` is ``False`` and :attr:`error` describes what happened.

    Args:
        project_id: ID (or URL-encoded path) of the project.
        job_id: ID of the job, when known.
        job_name: Name of the job, when the download is addressed by name.
        ref_name: Branch or tag name, when applicable.
        artifact_path: Path of the requested artifact within the archive.
    """

    project_id: int | str | None = None
    job_id: int | str | None = None
    job_name: str | None = None
    ref_name: str | None = None
    artifact_path: str | None = None
    request_path: str | None = None
    bytes_received: int = 0
    expected_size: int | None = None
    complete: bool = False
    error: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    sha256: str | None = None

    def __post_init__(self) -> None:
        self._hasher: hashlib._Hash = hashlib.sha256()

    @staticmethod
    def _timestamp() -> str:
        return _datetime.datetime.now(_datetime.timezone.utc).isoformat()

    def bind_response(self, response: requests.Response) -> None:
        """Record request-level, credential-free information from a response."""
        self.request_path = _sanitize_url(response.request.url)
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                self.expected_size = int(content_length)
            except (TypeError, ValueError):
                self.expected_size = None
        if self.started_at is None:
            self.started_at = self._timestamp()

    def record_chunk(self, chunk: bytes) -> None:
        """Account for a chunk that was handed to the caller."""
        if chunk:
            self.bytes_received += len(chunk)
            self._hasher.update(chunk)

    def mark_error(self, error: Exception) -> None:
        """Record a failed transfer without storing the error message."""
        self.complete = False
        # Only keep the exception type. Messages and chained exceptions can
        # contain URLs or credentials, so they must not be persisted here.
        self.error = type(error).__name__
        self.finished_at = self._timestamp()
        self.sha256 = self._hasher.hexdigest()

    def mark_closed(self, reason: str = "stream_closed_early") -> None:
        """Record that the caller stopped consuming the stream early."""
        self.complete = False
        self.error = reason
        self.finished_at = self._timestamp()
        self.sha256 = self._hasher.hexdigest()

    def mark_complete(self) -> None:
        """Record a finished transfer, honoring the expected length if known."""
        if self.expected_size is not None:
            self.complete = self.bytes_received == self.expected_size
            if not self.complete:
                self.error = "incomplete_content"
        else:
            self.complete = True
        self.finished_at = self._timestamp()
        self.sha256 = self._hasher.hexdigest()


class AuditedStream(Iterator[bytes]):
    """Wrap a response iterator and update a :class:`DownloadReceipt`.

    The stream yields the exact same chunks as ``response.iter_content()`` so
    callers keep full control of the data. Closing the stream early or an error
    raised while reading leaves the receipt in an auditable, incomplete state.
    """

    def __init__(
        self,
        response: requests.Response,
        receipt: DownloadReceipt,
        chunk_size: int = 1024,
    ) -> None:
        self._response = response
        self._receipt = receipt
        self._iterator: Iterator[bytes] = response.iter_content(
            chunk_size=chunk_size
        )
        self._closed: bool = False
        receipt.bind_response(response)

    def __iter__(self) -> AuditedStream:
        return self

    def __next__(self) -> bytes:
        if self._closed:
            raise StopIteration
        try:
            chunk = next(self._iterator)
        except StopIteration:
            self._finish()
            raise
        except Exception as exc:
            self._fail(exc)
            raise
        self._receipt.record_chunk(chunk)
        return chunk

    def _finish(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._receipt.mark_complete()
        self._response.close()

    def _fail(self, exc: Exception) -> None:
        if self._closed:
            return
        self._closed = True
        self._receipt.mark_error(exc)
        self._response.close()

    def close(self) -> None:
        """Stop consuming the stream and record an incomplete transfer."""
        if self._closed:
            return
        self._closed = True
        self._receipt.mark_closed()
        self._response.close()

    def __enter__(self) -> AuditedStream:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> None:
        if exc_value is None:
            self.close()
        elif isinstance(exc_value, Exception):
            self._fail(exc_value)
        else:
            # Do not swallow interrupts such as KeyboardInterrupt.
            self.close()

    def __del__(self) -> None:
        # Defensive cleanup if a caller dropped the stream without closing it.
        try:
            self.close()
        except Exception:
            pass
