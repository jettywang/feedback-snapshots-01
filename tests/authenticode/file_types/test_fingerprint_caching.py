"""Tests for shared, per-open-input fingerprint calculation in :class:`SignedPEFile`.

These tests use counting file-like objects to prove that:

* multiple digest algorithms share a single pass over the input instead of re-reading
  the file once per algorithm;
* the result is independent of the order in which the algorithms are requested;
* short reads, read errors and content changes while hashing never produce a partial or
  cached "successful" fingerprint;
* fingerprints are never reused across separate opens, even when the file name and the
  file length are identical.
"""

from __future__ import annotations

import hashlib
import io

import pytest

from signify.authenticode.signed_file.pe import SignedPEFile
from signify.exceptions import FingerprinterError, SignedPEParseError
from tests._utils import open_test_data

DUAL_SIGNATURE_SAMPLE = "sigcheck.exe"
DIGEST_ALGORITHMS = (hashlib.sha1, hashlib.sha256)


class CountingBytesIO(io.BytesIO):
    """BytesIO that records the number of reads and the total number of bytes read."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.read_count = 0
        self.bytes_read = 0

    def read(self, size: int | None = -1) -> bytes:
        self.read_count += 1
        block = super().read(size)
        self.bytes_read += len(block)
        return block


class ShortReadOnBig(io.BytesIO):
    """Behaves normally for small (header) reads, but returns only half of the
    requested bytes for large reads, simulating a short read while hashing."""

    def read(self, size: int | None = -1) -> bytes:
        if size is not None and size > 4096:
            return super().read(size // 2)
        return super().read(size)


class FailingReadOnBig(io.BytesIO):
    """Raises an OSError the first time a large block is read."""

    def read(self, size: int | None = -1) -> bytes:
        if size is not None and size > 4096:
            raise OSError("simulated read failure")
        return super().read(size)


class TruncateOnBig(io.BytesIO):
    """Truncates itself the first time a large block is read, so the length re-check at
    the end of hashing observes a changed input."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self._truncated = False

    def read(self, size: int | None = -1) -> bytes:
        if not self._truncated and size is not None and size > 4096:
            self._truncated = True
            self.truncate(len(self.getvalue()) - 100)
        return super().read(size)


@pytest.fixture(scope="module")
def sample_bytes() -> bytes:
    with open_test_data(DUAL_SIGNATURE_SAMPLE) as f:
        return f.read()


def _separate_fingerprints(data: bytes) -> dict[str, bytes]:
    """Reproduces the pre-optimisation behaviour: one independent fingerprinter pass
    per digest algorithm."""
    pe = SignedPEFile(io.BytesIO(data))
    result = {}
    for algorithm in DIGEST_ALGORITHMS:
        fingerprinter = pe.get_fingerprinter()
        fingerprinter.add_signed_pe_hashers(algorithm)
        result[algorithm().name] = fingerprinter.hash()[algorithm().name]
    return result


def test_combined_fingerprints_match_separate_ones(sample_bytes):
    separate = _separate_fingerprints(sample_bytes)

    stream = CountingBytesIO(sample_bytes)
    combined = SignedPEFile(stream).get_fingerprints(*DIGEST_ALGORITHMS)

    assert combined == separate
    assert set(combined) == {"sha1", "sha256"}


def test_combined_pass_reads_file_once(sample_bytes):
    # One fresh fingerprinter per algorithm (the old behaviour) reads the file twice.
    separate_stream = CountingBytesIO(sample_bytes)
    pe = SignedPEFile(separate_stream)
    for algorithm in DIGEST_ALGORITHMS:
        fingerprinter = pe.get_fingerprinter()
        fingerprinter.add_signed_pe_hashers(algorithm)
        fingerprinter.hash()
    separate_reads = separate_stream.read_count
    separate_bytes = separate_stream.bytes_read

    combined_stream = CountingBytesIO(sample_bytes)
    SignedPEFile(combined_stream).get_fingerprints(*DIGEST_ALGORITHMS)

    assert combined_stream.read_count < separate_reads
    assert combined_stream.bytes_read == separate_bytes // len(DIGEST_ALGORITHMS)
    assert combined_stream.bytes_read < separate_bytes


def test_repeated_call_on_open_input_uses_cache(sample_bytes):
    stream = CountingBytesIO(sample_bytes)
    pe = SignedPEFile(stream)

    first = pe.get_fingerprints(*DIGEST_ALGORITHMS)
    reads_after_first = stream.read_count
    bytes_after_first = stream.bytes_read

    second = pe.get_fingerprints(*DIGEST_ALGORITHMS)

    assert second == first
    # The cached fingerprints add no further data reads.
    assert stream.read_count == reads_after_first
    assert stream.bytes_read == bytes_after_first


def test_fingerprint_order_does_not_change_result(sample_bytes):
    forward = SignedPEFile(CountingBytesIO(sample_bytes)).get_fingerprints(
        hashlib.sha1, hashlib.sha256
    )
    reverse_stream = CountingBytesIO(sample_bytes)
    reverse = SignedPEFile(reverse_stream).get_fingerprints(
        hashlib.sha256, hashlib.sha1
    )

    assert forward == reverse

    forward_stream = CountingBytesIO(sample_bytes)
    SignedPEFile(forward_stream).get_fingerprints(hashlib.sha1, hashlib.sha256)
    assert reverse_stream.read_count == forward_stream.read_count
    assert reverse_stream.bytes_read == forward_stream.bytes_read


def test_each_digest_keeps_independent_conclusion(sample_bytes):
    pe = SignedPEFile(io.BytesIO(sample_bytes))
    signatures = list(pe.iter_embedded_signatures())
    assert [s.digest_algorithm().name for s in signatures] == ["sha1", "sha256"]

    for signature in signatures:
        name = signature.indirect_data.digest_algorithm().name
        expected = pe.get_fingerprints(signature.indirect_data.digest_algorithm)[name]
        assert expected == signature.indirect_data.digest


def test_short_read_raises_and_caches_nothing(sample_bytes):
    pe = SignedPEFile(ShortReadOnBig(sample_bytes))
    with pytest.raises(FingerprinterError):
        pe.get_fingerprints(*DIGEST_ALGORITHMS)
    assert pe._fingerprint_cache == {}


def test_read_exception_raises_and_caches_nothing(sample_bytes):
    pe = SignedPEFile(FailingReadOnBig(bytearray(sample_bytes)))
    with pytest.raises(FingerprinterError):
        pe.get_fingerprints(*DIGEST_ALGORITHMS)
    assert pe._fingerprint_cache == {}


def test_content_change_while_hashing_raises_and_caches_nothing(sample_bytes):
    pe = SignedPEFile(TruncateOnBig(bytearray(sample_bytes)))
    with pytest.raises(FingerprinterError):
        pe.get_fingerprints(*DIGEST_ALGORITHMS)
    assert pe._fingerprint_cache == {}


def test_failed_combined_hash_never_substitutes_one_digest(sample_bytes):
    pe = SignedPEFile(FailingReadOnBig(bytearray(sample_bytes)))
    with pytest.raises(FingerprinterError):
        pe.get_fingerprints(*DIGEST_ALGORITHMS)

    # Neither digest may be served from a partial result afterwards.
    assert not pe._fingerprint_cache
    with pytest.raises(FingerprinterError):
        pe.get_fingerprint(hashlib.sha1)


def test_truncation_after_caching_invalidates_cache(sample_bytes):
    stream = CountingBytesIO(bytearray(sample_bytes))
    pe = SignedPEFile(stream)
    original = pe.get_fingerprints(*DIGEST_ALGORITHMS)
    assert pe._fingerprint_cache

    stream.truncate(len(sample_bytes) - 50)

    with pytest.raises(FingerprinterError):
        pe.get_fingerprints(*DIGEST_ALGORITHMS)
    assert pe._fingerprint_cache == {}
    # The previously returned value must not silently survive as a reusable result.
    assert original  # sanity: it really was computed before the change


def test_cache_is_not_reused_for_modified_same_named_file(sample_bytes, tmp_path):
    path = tmp_path / "same-name.exe"
    path.write_bytes(sample_bytes)

    with path.open("rb") as fh:
        first_pe = SignedPEFile(io.BytesIO(fh.read()))
        first = first_pe.get_fingerprints(*DIGEST_ALGORITHMS)

    # Same name AND same length, but the content is changed.
    modified = bytearray(sample_bytes)
    modified[2000] ^= 0xFF
    path.write_bytes(modified)
    assert len(path.read_bytes()) == len(sample_bytes)

    with path.open("rb") as fh:
        second_pe = SignedPEFile(io.BytesIO(fh.read()))
        second = second_pe.get_fingerprints(*DIGEST_ALGORITHMS)

    assert first != second
    # The second object starts with an empty cache and never sees the first object's
    # fingerprints.
    assert not (set(first_pe._fingerprint_cache.values()) & set(second.values()))


def test_unparseable_pe_raises_parse_error_instead_of_keyerror(sample_bytes):
    class AlwaysShort(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            if size is None or size < 0:
                return super().read(size)
            return super().read(max(1, size // 2))

    pe = SignedPEFile(AlwaysShort(sample_bytes))
    with pytest.raises(SignedPEParseError):
        pe.get_fingerprints(*DIGEST_ALGORITHMS)


def test_full_verify_still_succeeds(sample_bytes):
    pe = SignedPEFile(io.BytesIO(sample_bytes))
    pe.verify()
