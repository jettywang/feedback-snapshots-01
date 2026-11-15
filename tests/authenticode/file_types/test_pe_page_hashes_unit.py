"""Unit tests for page hash parsing and report construction without signed data."""

import hashlib
import struct

import pytest

from signify.authenticode.page_hashes import (
    PageHashStatus,
    PageHashTableError,
    build_page_hash_report,
    parse_page_hash_table,
)
from signify.exceptions import AuthenticodePageHashParseError


def _entry(offset: int, digest: bytes) -> bytes:
    return struct.pack("<I", offset) + digest


def _table(*entries: tuple[int, bytes]) -> bytes:
    return b"".join(_entry(offset, digest) for offset, digest in entries)


def test_duplicate_offsets_are_structural_errors():
    with pytest.raises(AuthenticodePageHashParseError, match="duplicate"):
        parse_page_hash_table(
            hashlib.sha256, _table((0, b"a" * 32), (0, b"b" * 32), (4096, b"\0" * 32))
        )


def test_decreasing_offsets_are_structural_errors():
    with pytest.raises(AuthenticodePageHashParseError, match="decreasing"):
        parse_page_hash_table(
            hashlib.sha256,
            _table((4096, b"a" * 32), (0, b"b" * 32), (8192, b"\0" * 32)),
        )


def test_terminal_offset_must_be_last_and_pages_must_be_nonzero():
    with pytest.raises(AuthenticodePageHashParseError, match="terminator"):
        parse_page_hash_table(hashlib.sha256, _table((0, b"a" * 32), (4096, b"b" * 32)))
    with pytest.raises(AuthenticodePageHashParseError, match="all-zero"):
        parse_page_hash_table(
            hashlib.sha256, _table((0, b"\0" * 32), (4096, b"\0" * 32))
        )


def test_partial_entries_are_structural_errors():
    content = _table((0, b"a" * 32), (4096, b"\0" * 32))
    with pytest.raises(AuthenticodePageHashParseError):
        parse_page_hash_table(hashlib.sha256, content + b"\x01")
    with pytest.raises(AuthenticodePageHashParseError):
        parse_page_hash_table(hashlib.sha256, b"")


def test_digest_count_mismatch_is_a_structural_error():
    # The SHA-1 table declares SHA-1-sized entries; parsing it with SHA-256 leaves
    # trailing bytes, i.e. the declared digest count does not match the ranges.
    content = _table((0, b"a" * 20), (4096, b"\0" * 20))
    with pytest.raises(AuthenticodePageHashParseError):
        parse_page_hash_table(hashlib.sha256, content)


def test_valid_table_yields_pages_without_terminal_entry():
    table = parse_page_hash_table(
        hashlib.sha256, _table((0, b"a" * 32), (4096, b"b" * 32), (8192, b"\0" * 32))
    )
    assert [page.range for page in table.ranges] == [(0, 4096), (4096, 8192)]
    assert table.terminal_offset == 8192


def test_report_padding_and_unverifiable_pages():
    table = parse_page_hash_table(
        hashlib.sha256, _table((0, b"a" * 32), (1000, b"b" * 32), (6000, b"\0" * 32))
    )

    def hash_page(algorithm, start, end):
        if start == 0:
            return b"a" * 32
        if start == 1000:
            raise ValueError("cannot hash this range")
        return b"c" * 32

    report = build_page_hash_report(
        tables=[table],
        file_size=7000,
        page_size=4096,
        hash_page=hash_page,
        structural_errors=[PageHashTableError("example structural problem")],
        excluded_sections=[("checksum", 100, 104)],
    )

    assert report.excluded_fields == {"checksum": (100, 104)}
    assert report.structural_error_messages == ("example structural problem",)
    assert not report.all_pages_match

    first, second = report.pages
    assert first.status is PageHashStatus.VALID
    assert first.padding_length == 4096 - 1000
    assert first.padded_end == 4096
    assert first.excluded_ranges == ((100, 104),)
    assert first.hashed_ranges == ((0, 100), (104, 1000))

    assert second.status is PageHashStatus.UNVERIFIABLE
    assert second.actual_digest is None
    assert "cannot hash" in second.reason
    assert second.padding_length == 8192 - 5000

    with pytest.raises(AuthenticodePageHashParseError):
        report.raise_for_error()
