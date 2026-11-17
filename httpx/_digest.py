"""
Optional verification of a response body against a caller supplied digest.

The digest value is always supplied by the caller. HTTPX does not treat
`Content-Digest`, `Content-MD5` or any other response header as a trusted
digest, and a matching `Content-Length` is never treated as proof that the
content is authentic.
"""

from __future__ import annotations

import base64
import binascii
import enum
import hashlib
import hmac
import re
import typing

from ._decoders import ByteChunker
from ._exceptions import (
    DigestError,
    DigestIncompleteError,
    DigestMismatchError,
    RequestError,
    StreamError,
)
from ._types import AsyncByteStream, SyncByteStream

if typing.TYPE_CHECKING:  # pragma: no cover
    from hashlib import _Hash

    from ._models import Response


__all__ = ["DigestScope", "DigestStatus", "DigestVerifier"]


class DigestScope(str, enum.Enum):
    """
    The bytes covered by a response digest.

    * `RAW` is the encoded body as received on the wire, before any
      `Content-Encoding` decoding.
    * `DECODED` is the body after `Content-Encoding` decoding, which is also
      the body exposed by `response.content`.
    """

    RAW = "raw"
    DECODED = "decoded"


class DigestStatus(str, enum.Enum):
    """
    The current state of a `DigestVerifier`.

    Only `VERIFIED` means that the complete promised byte range was consumed
    and matched the expected digest. `PENDING` means verification has not been
    completed, so the content must not be treated as authenticated.
    """

    PENDING = "pending"
    VERIFIED = "verified"
    MISMATCH = "mismatch"
    INCOMPLETE = "incomplete"
    ERROR = "error"


_ALGORITHM_PREFIX = re.compile(r"^([A-Za-z][A-Za-z0-9_.-]*)\s*[:=]\s*(\S.*)$", re.S)
_SUPPORTED_ENCODINGS = {"gzip", "deflate", "br", "zstd"}


def _canonical_algorithm(algorithm: str) -> tuple[str, int]:
    try:
        hasher = hashlib.new(algorithm)
    except (TypeError, ValueError) as exc:
        raise DigestError(f"Unsupported digest algorithm {algorithm!r}") from exc
    return hasher.name, hasher.digest_size


def _decode_digest_value(
    value: str, digest_size: int, *, algorithm: str
) -> bytes:
    value = value.strip()
    if value.endswith(":"):
        # RFC 9530 style structured field byte sequence: `:base64:` or
        # `sha-256=:base64:`.
        value = value[:-1]
    if value.startswith(":"):
        value = value[1:]

    if len(value) == digest_size * 2 and re.fullmatch(r"[0-9A-Fa-f]+", value):
        return bytes.fromhex(value)

    padded = value + "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DigestError(
            f"Invalid {algorithm} digest: expected hexadecimal or base64"
        ) from exc

    if len(decoded) != digest_size:
        raise DigestError(
            f"Invalid {algorithm} digest: expected {digest_size} bytes, "
            f"got {len(decoded)}"
        )
    return decoded


def _parse_expected_digest(
    expected_digest: str | bytes, algorithm: str | None
) -> tuple[str, bytes]:
    if isinstance(expected_digest, bytes):
        if algorithm is None:
            algorithm = "sha256"
        canonical, digest_size = _canonical_algorithm(algorithm)
        if len(expected_digest) != digest_size:
            raise DigestError(
                f"Invalid {canonical} digest: expected {digest_size} bytes, "
                f"got {len(expected_digest)}"
            )
        return canonical, expected_digest

    if not isinstance(expected_digest, str):
        raise TypeError("'expected_digest' must be a str or bytes")

    value = expected_digest.strip()
    if not value:
        raise DigestError("The expected digest must not be empty")

    prefix_match = _ALGORITHM_PREFIX.match(value)
    if prefix_match is not None:
        prefix_algorithm, prefixed_value = prefix_match.groups()
        try:
            prefixed, _ = _canonical_algorithm(prefix_algorithm)
        except DigestError:
            # Not an algorithm prefix after all; treat the whole value as the
            # digest itself.
            pass
        else:
            value = prefixed_value
            if algorithm is None:
                algorithm = prefixed
            else:
                supplied, _ = _canonical_algorithm(algorithm)
                if prefixed != supplied:
                    raise DigestError(
                        f"Digest algorithm {prefix_algorithm!r} conflicts with "
                        f"the supplied algorithm {algorithm!r}"
                    )

    if algorithm is None:
        algorithm = "sha256"

    canonical, digest_size = _canonical_algorithm(algorithm)
    return canonical, _decode_digest_value(
        value, digest_size, algorithm=canonical
    )


def _has_content_decoding(response: Response) -> bool:
    values = response.headers.get_list("content-encoding", split_commas=True)
    return any(value.strip().lower() in _SUPPORTED_ENCODINGS for value in values)


def _request_for(response: Response) -> typing.Any:
    return getattr(response, "_request", None)


def _error_for(
    response: Response, error_type: type[RequestError], message: str
) -> RequestError:
    return error_type(message, request=_request_for(response))


def _is_cancellation(exc: BaseException) -> bool:
    return type(exc).__name__ in ("CancelledError", "Cancelled")


class DigestVerifier:
    """
    Verify a response body against a caller supplied digest.

    Instances are returned by `response.verify_digest(...)`. Consume the body
    through this object, using its iterators or `read()`/`aread()`. The
    `status` stays `PENDING` until the whole promised range has been consumed.
    Only then may it become `VERIFIED`, `MISMATCH`, `INCOMPLETE` or `ERROR`.

    A streaming body can be consumed exactly once. If iteration is abandoned,
    call `abort()`/`aclose()` or leave a `with`/`async with` block so the
    status becomes `INCOMPLETE` and the response is closed. Partial content is
    never copied into the response's content cache.
    """

    def __init__(
        self,
        response: Response,
        expected_digest: str | bytes,
        *,
        scope: DigestScope | str,
        algorithm: str | None = None,
        raise_on_mismatch: bool = True,
    ) -> None:
        self.response = response
        try:
            self.scope = DigestScope(scope)
        except ValueError as exc:
            raise DigestError(
                "Digest scope must be either 'raw' or 'decoded'"
            ) from exc

        self.algorithm, self._expected_digest = _parse_expected_digest(
            expected_digest, algorithm
        )
        self._hasher: _Hash = hashlib.new(self.algorithm)
        self.raise_on_mismatch = raise_on_mismatch

        self._status = DigestStatus.PENDING
        self._error: RequestError | None = None
        self._actual_digest: str | None = None
        self._declared_length = self._get_declared_length()

        if hasattr(response, "_content"):
            self._verify_cached()

    @property
    def expected_digest(self) -> str:
        """
        The expected digest as a hexadecimal string.
        """
        return self._expected_digest.hex()

    @property
    def actual_digest(self) -> str | None:
        """
        The actual digest as a hexadecimal string once the promised range has
        been fully consumed, or `None` if it was not fully covered.
        """
        if self._status in (DigestStatus.VERIFIED, DigestStatus.MISMATCH):
            return self._actual_digest
        return None

    @property
    def status(self) -> DigestStatus:
        return self._status

    @property
    def verified(self) -> bool:
        return self._status is DigestStatus.VERIFIED

    @property
    def pending(self) -> bool:
        return self._status is DigestStatus.PENDING

    @property
    def failed(self) -> bool:
        return self._status in (
            DigestStatus.MISMATCH,
            DigestStatus.INCOMPLETE,
            DigestStatus.ERROR,
        )

    @property
    def error(self) -> RequestError | None:
        return self._error

    def require_verified(self) -> None:
        """
        Return normally only if the digest was verified, otherwise raise the
        stored verification error.
        """
        if self._status is DigestStatus.VERIFIED:
            return
        if self._error is not None:
            raise self._error
        raise _error_for(
            self.response,
            DigestIncompleteError,
            "Response content has not been fully verified",
        )

    def abort(self) -> None:
        """
        Mark an incomplete verification as `INCOMPLETE` and close the
        response. Calling this after a terminal status has no effect.
        """
        if self._status is DigestStatus.PENDING:
            self._status = DigestStatus.INCOMPLETE
            self._error = _error_for(
                self.response,
                DigestIncompleteError,
                "Response digest verification was cancelled before the "
                "complete promised range was consumed",
            )
        self._close_response()

    close = abort

    async def aclose(self) -> None:
        """
        Asynchronous equivalent of `abort()`.
        """
        if self._status is DigestStatus.PENDING:
            self._status = DigestStatus.INCOMPLETE
            self._error = _error_for(
                self.response,
                DigestIncompleteError,
                "Response digest verification was cancelled before the "
                "complete promised range was consumed",
            )
        await self._aclose_response()

    def __enter__(self) -> DigestVerifier:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: typing.Any,
    ) -> None:
        if self._status is DigestStatus.PENDING:
            self.abort()

    async def __aenter__(self) -> DigestVerifier:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: typing.Any,
    ) -> None:
        if self._status is DigestStatus.PENDING:
            await self.aclose()

    def read(self) -> bytes:
        """
        Read and return the decoded response body, verifying the complete
        promised range before returning it.
        """
        if hasattr(self.response, "_content"):
            self._raise_if_failed()
            return self.response._content
        return self._consume(self.iter_bytes())

    async def aread(self) -> bytes:
        """
        Asynchronous equivalent of `read()`.
        """
        if hasattr(self.response, "_content"):
            self._raise_if_failed()
            return self.response._content
        return await self._aconsume(self.aiter_bytes())

    def read_raw(self) -> bytes:
        """
        Read and return the encoded response body, verifying the complete
        promised range before returning it.
        """
        cached = self._cached_raw_content()
        if cached is not None:
            self._raise_if_failed()
            return cached
        if hasattr(self.response, "_content"):
            self._raise_if_failed()
            raise _error_for(
                self.response,
                DigestIncompleteError,
                "The raw encoded response body is no longer available",
            )
        return self._consume(self.iter_raw())

    async def aread_raw(self) -> bytes:
        """
        Asynchronous equivalent of `read_raw()`.
        """
        cached = self._cached_raw_content()
        if cached is not None:
            self._raise_if_failed()
            return cached
        if hasattr(self.response, "_content"):
            self._raise_if_failed()
            raise _error_for(
                self.response,
                DigestIncompleteError,
                "The raw encoded response body is no longer available",
            )
        return await self._aconsume(self.aiter_raw())

    def iter_bytes(
        self, chunk_size: int | None = None
    ) -> typing.Iterator[bytes]:
        """
        Iterate over the decoded response body while verifying the configured
        scope. The final status is set only after the body is exhausted.
        """
        if hasattr(self.response, "_content"):
            self._raise_if_failed()
            for chunk in self._iter_bytes_of(self.response._content, chunk_size):
                yield chunk
            return

        decoder = self.response._get_content_decoder()
        chunker = ByteChunker(chunk_size=chunk_size)
        raw_length = 0
        body = bytearray()
        raw_body = bytearray()
        source = self.response.iter_raw()
        try:
            for raw_bytes in source:
                raw_body.extend(raw_bytes)
                raw_length += len(raw_bytes)
                if self.scope is DigestScope.RAW:
                    self._hasher.update(raw_bytes)
                decoded = decoder.decode(raw_bytes)
                if self.scope is DigestScope.DECODED:
                    self._hasher.update(decoded)
                body.extend(decoded)
                for chunk in chunker.decode(decoded):
                    yield chunk
            tail = decoder.flush()
            if self.scope is DigestScope.DECODED:
                self._hasher.update(tail)
            body.extend(tail)
            for chunk in chunker.decode(tail):
                yield chunk
            for chunk in chunker.flush():
                yield chunk
        except GeneratorExit:
            self._interrupted()
            source.close()
            raise
        except BaseException as exc:
            source.close()
            self._handle_exception(exc)
            raise

        self._finalize(raw_length, decoder.is_complete())
        self._raise_if_failed()
        if self._status is DigestStatus.VERIFIED:
            self.response._content = bytes(body)
            if self.response._raw_content is None:
                self.response._raw_content = bytes(raw_body)

    async def aiter_bytes(
        self, chunk_size: int | None = None
    ) -> typing.AsyncIterator[bytes]:
        """
        Asynchronous equivalent of `iter_bytes()`.
        """
        if hasattr(self.response, "_content"):
            self._raise_if_failed()
            for chunk in self._iter_bytes_of(self.response._content, chunk_size):
                yield chunk
            return

        decoder = self.response._get_content_decoder()
        chunker = ByteChunker(chunk_size=chunk_size)
        raw_length = 0
        body = bytearray()
        raw_body = bytearray()
        source = self.response.aiter_raw()
        try:
            async for raw_bytes in source:
                raw_body.extend(raw_bytes)
                raw_length += len(raw_bytes)
                if self.scope is DigestScope.RAW:
                    self._hasher.update(raw_bytes)
                decoded = decoder.decode(raw_bytes)
                if self.scope is DigestScope.DECODED:
                    self._hasher.update(decoded)
                body.extend(decoded)
                for chunk in chunker.decode(decoded):
                    yield chunk
            tail = decoder.flush()
            if self.scope is DigestScope.DECODED:
                self._hasher.update(tail)
            body.extend(tail)
            for chunk in chunker.decode(tail):
                yield chunk
            for chunk in chunker.flush():
                yield chunk
        except GeneratorExit:
            await source.aclose()
            self._interrupted()
            await self._aclose_response()
            raise
        except BaseException as exc:
            await source.aclose()
            self._handle_exception(exc)
            await self._aclose_response()
            raise

        self._finalize(raw_length, decoder.is_complete())
        self._raise_if_failed()
        if self._status is DigestStatus.VERIFIED:
            self.response._content = bytes(body)
            if self.response._raw_content is None:
                self.response._raw_content = bytes(raw_body)

    def iter_raw(self, chunk_size: int | None = None) -> typing.Iterator[bytes]:
        """
        Iterate over the encoded response body while verifying the configured
        scope.
        """
        cached = self._cached_raw_content()
        if cached is not None:
            self._raise_if_failed()
            for chunk in self._iter_bytes_of(cached, chunk_size):
                yield chunk
            return
        if hasattr(self.response, "_content"):
            self._raise_if_failed()
            raise _error_for(
                self.response,
                DigestIncompleteError,
                "The raw encoded response body is no longer available",
            )

        decoder = self.response._get_content_decoder()
        chunker = ByteChunker(chunk_size=chunk_size)
        raw_length = 0
        source = self.response.iter_raw()
        try:
            for raw_bytes in source:
                raw_length += len(raw_bytes)
                self._hasher.update(raw_bytes)
                decoded = decoder.decode(raw_bytes)
                if self.scope is DigestScope.DECODED:
                    self._hasher.update(decoded)
                for chunk in chunker.decode(raw_bytes):
                    yield chunk
            tail = decoder.flush()
            if self.scope is DigestScope.DECODED:
                self._hasher.update(tail)
            for chunk in chunker.flush():
                yield chunk
        except GeneratorExit:
            self._interrupted()
            source.close()
            raise
        except BaseException as exc:
            source.close()
            self._handle_exception(exc)
            raise

        self._finalize(raw_length, decoder.is_complete())
        self._raise_if_failed()

    async def aiter_raw(
        self, chunk_size: int | None = None
    ) -> typing.AsyncIterator[bytes]:
        """
        Asynchronous equivalent of `iter_raw()`.
        """
        cached = self._cached_raw_content()
        if cached is not None:
            self._raise_if_failed()
            for chunk in self._iter_bytes_of(cached, chunk_size):
                yield chunk
            return
        if hasattr(self.response, "_content"):
            self._raise_if_failed()
            raise _error_for(
                self.response,
                DigestIncompleteError,
                "The raw encoded response body is no longer available",
            )

        decoder = self.response._get_content_decoder()
        chunker = ByteChunker(chunk_size=chunk_size)
        raw_length = 0
        source = self.response.aiter_raw()
        try:
            async for raw_bytes in source:
                raw_length += len(raw_bytes)
                self._hasher.update(raw_bytes)
                decoded = decoder.decode(raw_bytes)
                if self.scope is DigestScope.DECODED:
                    self._hasher.update(decoded)
                for chunk in chunker.decode(raw_bytes):
                    yield chunk
            tail = decoder.flush()
            if self.scope is DigestScope.DECODED:
                self._hasher.update(tail)
            for chunk in chunker.flush():
                yield chunk
        except GeneratorExit:
            await source.aclose()
            self._interrupted()
            await self._aclose_response()
            raise
        except BaseException as exc:
            await source.aclose()
            self._handle_exception(exc)
            await self._aclose_response()
            raise

        self._finalize(raw_length, decoder.is_complete())
        self._raise_if_failed()

    @staticmethod
    def _iter_bytes_of(
        content: bytes, chunk_size: int | None
    ) -> typing.Iterator[bytes]:
        if chunk_size is None or chunk_size <= 0:
            if content:
                yield content
            return
        for index in range(0, len(content), chunk_size):
            yield content[index : index + chunk_size]

    def _consume(self, iterator: typing.Iterator[bytes]) -> bytes:
        try:
            return b"".join(iterator)
        finally:
            iterator.close()

    async def _aconsume(
        self, iterator: typing.AsyncIterator[bytes]
    ) -> bytes:
        chunks = []
        try:
            async for chunk in iterator:
                chunks.append(chunk)
        finally:
            aclose = getattr(iterator, "aclose", None)
            if aclose is not None:
                await aclose()
        return b"".join(chunks)

    def _cached_raw_content(self) -> bytes | None:
        raw = getattr(self.response, "_raw_content", None)
        if raw is not None:
            return raw
        content = getattr(self.response, "_content", None)
        if content is not None and not _has_content_decoding(self.response):
            # With no applied content encoding, raw and decoded bytes are
            # identical, so previously read content is still a valid source.
            return content
        return None

    def _verify_cached(self) -> None:
        content = self.response._content
        if self.scope is DigestScope.RAW:
            data = self._cached_raw_content()
            if data is None:
                self._mark_incomplete(
                    "The raw encoded response body is no longer available"
                )
                return
            self._hasher.update(data)
            decoder = getattr(self.response, "_decoder", None)
            encoded_complete = (
                decoder.is_complete() if decoder is not None else True
            )
            self._finalize(len(data), encoded_complete)
            return

        self._hasher.update(content)
        raw = self._cached_raw_content()
        if raw is not None:
            raw_length: int | None = len(raw)
        elif not _has_content_decoding(self.response):
            raw_length = len(content)
        else:
            raw_length = None

        decoder = getattr(self.response, "_decoder", None)
        encoded_complete = decoder.is_complete() if decoder is not None else True
        self._finalize(raw_length, encoded_complete)

    def _get_declared_length(self) -> int | None:
        status_code = self.response.status_code
        if 100 <= status_code < 200 or status_code in (204, 304):
            return None

        request = _request_for(self.response)
        if request is not None and request.method == "HEAD":
            return None

        values = self.response.headers.get_list("content-length")
        if len(values) != 1:
            return None
        try:
            value = int(values[0].strip())
        except ValueError:
            return None
        return value if value >= 0 else None

    def _finalize(self, raw_length: int | None, encoded_complete: bool) -> None:
        if self._status is not DigestStatus.PENDING:
            return

        self._actual_digest = self._hasher.hexdigest()

        if not encoded_complete:
            self._mark_incomplete(
                "The encoded response body ended before the content decoder "
                "reported a complete stream"
            )
            return

        if (
            raw_length is not None
            and self._declared_length is not None
            and raw_length != self._declared_length
        ):
            self._mark_incomplete(
                "The encoded response body length does not match the "
                "declared Content-Length; the promised range is incomplete"
            )
            return

        if hmac.compare_digest(self._hasher.digest(), self._expected_digest):
            self._status = DigestStatus.VERIFIED
        else:
            self._status = DigestStatus.MISMATCH
            self._error = _error_for(
                self.response,
                DigestMismatchError,
                f"{self.algorithm} digest mismatch for "
                f"{self.scope.value} response content",
            )

    def _mark_incomplete(self, message: str) -> None:
        if self._status is DigestStatus.PENDING:
            self._status = DigestStatus.INCOMPLETE
            self._error = _error_for(
                self.response, DigestIncompleteError, message
            )

    def _response_closed(self) -> None:
        """
        Called by `Response.close()`/`aclose()`. A verifier that has not
        reached a terminal state can no longer cover the promised range.
        """
        self._mark_incomplete(
            "The response was closed before the complete promised range was "
            "consumed"
        )

    def _interrupted(self) -> None:
        if self._status is DigestStatus.PENDING:
            self._status = DigestStatus.INCOMPLETE
            self._error = _error_for(
                self.response,
                DigestIncompleteError,
                "Response digest verification was cancelled before the "
                "complete promised range was consumed",
            )
        self._close_response()

    def _handle_exception(self, exc: BaseException) -> None:
        if self._status is DigestStatus.PENDING:
            if _is_cancellation(exc):
                self._status = DigestStatus.INCOMPLETE
                self._error = _error_for(
                    self.response,
                    DigestIncompleteError,
                    "Response digest verification was cancelled before the "
                    "complete promised range was consumed",
                )
            elif isinstance(exc, StreamError):
                self._status = DigestStatus.INCOMPLETE
                self._error = _error_for(
                    self.response,
                    DigestIncompleteError,
                    "Response content could not be fully consumed for "
                    "verification",
                )
            else:
                self._status = DigestStatus.ERROR
                if isinstance(exc, RequestError):
                    self._error = exc
                else:
                    self._error = _error_for(
                        self.response,
                        DigestIncompleteError,
                        f"Response content could not be verified: {exc}",
                    )
        self._close_response()

    def _raise_if_failed(self) -> None:
        if self._status is DigestStatus.VERIFIED:
            return
        if self._status is DigestStatus.PENDING:
            raise _error_for(
                self.response,
                DigestIncompleteError,
                "Response content has not been fully verified",
            )
        if self._status is DigestStatus.INCOMPLETE:
            raise self._error or _error_for(
                self.response,
                DigestIncompleteError,
                "Response content has not been fully verified",
            )
        if self._status is DigestStatus.MISMATCH and not self.raise_on_mismatch:
            return
        if self._error is not None:
            raise self._error
        raise _error_for(
            self.response,
            DigestIncompleteError,
            "Response content has not been fully verified",
        )

    def _close_response(self) -> None:
        if isinstance(self.response.stream, SyncByteStream):
            if not self.response.is_closed:
                self.response.close()

    async def _aclose_response(self) -> None:
        if self.response.is_closed:
            return
        if isinstance(self.response.stream, AsyncByteStream):
            await self.response.aclose()
        else:
            self.response.close()
