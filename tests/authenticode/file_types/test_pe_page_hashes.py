"""Tests for structured Authenticode PE page hash verification."""

import hashlib
import io
import struct

import pytest

from signify.authenticode.page_hashes import (
    PageHashStatus,
    parse_page_hash_table,
)
from signify.authenticode.signed_file.pe import SignedPEFile
from signify.exceptions import (
    AuthenticodeInvalidDigestError,
    AuthenticodeInvalidPageHashError,
    AuthenticodePageHashParseError,
    AuthenticodeVerificationError,
)
from tests._utils import data_path

PAGE_HASH_SAMPLE = "DXCore.dll"
PAGE_HASH_SAMPLE_ALIGNMENT = (
    "d62d3ca4f677eb06ba81b1eba82f375c0c345f0e8f8097c92fc5e36e4d72294e.sample"
)


def _read(name: str) -> bytes:
    return data_path(name).read_bytes()


def _pefile(data: bytes) -> SignedPEFile:
    return SignedPEFile(io.BytesIO(data))


def _report(data: bytes):
    pefile = _pefile(data)
    signature = next(pefile.iter_embedded_signatures(include_nested=False))
    return pefile, pefile.get_page_hash_report(signature.indirect_data)


def _page_hash_content(data: bytes) -> bytes:
    """Returns the raw page hash blob of the first page hash table."""
    pefile = _pefile(data)
    signature = next(pefile.iter_embedded_signatures(include_nested=False))
    image_data = signature.indirect_data.content
    return next(iter(image_data.content_pairs))[1][0]


@pytest.mark.parametrize("filename", [PAGE_HASH_SAMPLE, PAGE_HASH_SAMPLE_ALIGNMENT])
def test_report_for_valid_page_hashes(filename):
    data = _read(filename)
    pefile, report = _report(data)

    assert report is not None
    assert report.all_pages_match
    assert report.ok
    assert report.mismatches == ()
    assert report.unverifiable == ()
    assert report.structural_errors == ()
    assert report.page_size == pefile.page_size
    assert report.file_size == len(data)
    assert len(report.tables) == 1

    table = report.tables[0]
    assert table.algorithm == "sha256"
    certtable = pefile.get_authenticode_omit_sections()["certtable"]
    assert table.terminal_offset == certtable.start
    assert table.terminal_digest == b"\0" * 32

    pages = report.pages
    assert len(pages) == len(table.entries)
    assert [page.start for page in pages] == sorted(page.start for page in pages)
    # Every page starts where the previous page ended; the terminal entry is not a page.
    for previous, current in zip(pages, pages[1:]):
        assert previous.end == current.start
    assert pages[-1].end == table.terminal_offset
    assert pages[-1].end + pages[-1].padding_length == table.terminal_offset
    assert all(page.status is PageHashStatus.VALID for page in pages)
    assert all(page.expected_hex == page.actual_hex for page in pages)


def test_report_explains_real_page_boundaries_and_exclusions():
    _, report = _report(_read(PAGE_HASH_SAMPLE))
    assert report is not None
    first = report.pages[0]

    # The first page covers 0-4096 and is a full page, so it is not padded.
    assert first.range == (0, 4096)
    assert first.padding_length == 0
    assert first.padded_end == first.end

    # The checksum and certificate table directory entry live in the first page and
    # are excluded from its digest, but still count towards the page boundary.
    excluded = report.excluded_fields
    assert first.excluded_ranges == (
        excluded["checksum"],
        excluded["datadir_certtable"],
    )
    assert first.hashed_length == 4096 - 4 - 8
    assert sum(end - start for start, end in first.hashed_ranges) == first.hashed_length


def test_terminal_offset_is_not_a_page():
    _, report = _report(_read(PAGE_HASH_SAMPLE))
    assert report is not None
    table = report.tables[0]
    assert table.terminal_offset not in {page.start for page in table.entries}
    assert len(table.entries) + 1 == 74 + 1


def test_mutation_of_page_covered_byte_is_reported_for_that_page():
    data = bytearray(_read(PAGE_HASH_SAMPLE))
    # Offset 0x1000 is in the second page, which is not affected by any exclusion.
    data[0x1000] ^= 0xFF

    pefile, report = _report(bytes(data))
    assert report is not None
    assert not report.all_pages_match
    assert len(report.mismatches) == 1

    mismatch = report.mismatches[0]
    assert mismatch.status is PageHashStatus.MISMATCH
    assert mismatch.range == (4096, 8192)
    assert mismatch.expected_digest != mismatch.actual_digest
    assert mismatch.reason is None

    # The existing exception API remains in place, and the raw helper agrees.
    signature = next(pefile.iter_embedded_signatures(include_nested=False))
    with pytest.raises(AuthenticodeInvalidPageHashError):
        pefile.verify_additional_hashes(signature.indirect_data)
    with pytest.raises(AuthenticodeInvalidDigestError):
        pefile.verify()


def test_mutation_of_checksum_is_excluded_from_both_page_and_file_hash():
    data = bytearray(_read(PAGE_HASH_SAMPLE))
    pefile = _pefile(bytes(data))
    checksum = pefile.get_authenticode_omit_sections()["checksum"]
    data[checksum.start] ^= 0xFF

    pefile, report = _report(bytes(data))
    assert report is not None
    assert report.all_pages_match
    assert report.mismatches == ()
    assert report.unverifiable == ()
    # The change is inside the first page's file range, but not in its digest input.
    assert report.pages[0].range == (0, 4096)
    hashed_offsets = [
        offset
        for start, end in report.pages[0].hashed_ranges
        for offset in range(start, end)
    ]
    assert checksum.start not in hashed_offsets

    pefile.verify()


def test_failed_page_report_does_not_imply_full_signature_failure_and_vice_versa():
    data = bytearray(_read(PAGE_HASH_SAMPLE))

    # Changing the page-covered byte breaks both the page hash and the file digest.
    covered = bytearray(data)
    covered[0x1000] ^= 0xFF
    covered_pefile, covered_report = _report(bytes(covered))
    assert covered_report is not None
    assert not covered_report.all_pages_match
    with pytest.raises(AuthenticodeInvalidDigestError):
        covered_pefile.verify()

    # Changing the signature bytes leaves all page hashes intact, but full
    # Authenticode verification fails: a page hash report is not a trust statement.
    signed = _pefile(bytes(data))
    signature = next(signed.iter_embedded_signatures(include_nested=False))
    signature_bytes = signature.signer_info.asn1["signature"].native
    patched = bytearray(data)
    offset = patched.index(signature_bytes)
    patched[offset + len(signature_bytes) // 2] ^= 0xFF

    signed_pefile, signed_report = _report(bytes(patched))
    assert signed_report is not None
    assert signed_report.all_pages_match
    with pytest.raises(AuthenticodeVerificationError):
        signed_pefile.verify()


def test_page_hash_table_with_duplicate_offset_is_structural_error():
    data = _read(PAGE_HASH_SAMPLE)
    content = _page_hash_content(data)

    # The second entry duplicates the first offset. The table must not be sorted
    # into shape.
    entry_length = 4 + 32
    patched_content = bytearray(content)
    patched_content[entry_length : entry_length + 4] = struct.pack("<I", 0)
    with pytest.raises(AuthenticodePageHashParseError):
        parse_page_hash_table(hashlib.sha256, bytes(patched_content))


def test_page_hash_table_with_decreasing_offset_is_structural_error():
    content = _page_hash_content(_read(PAGE_HASH_SAMPLE))
    entry_length = 4 + 32
    patched_content = bytearray(content)
    # The first offset is 0, the second 4096; make the first one larger.
    patched_content[0:4] = struct.pack("<I", 8192)
    with pytest.raises(AuthenticodePageHashParseError):
        parse_page_hash_table(hashlib.sha256, bytes(patched_content))


def test_page_hash_table_with_trailing_partial_entry_is_structural_error():
    content = _page_hash_content(_read(PAGE_HASH_SAMPLE))
    with pytest.raises(AuthenticodePageHashParseError):
        parse_page_hash_table(hashlib.sha256, content[:-1])


def test_page_hash_table_without_zero_terminator_is_structural_error():
    content = _page_hash_content(_read(PAGE_HASH_SAMPLE))
    entry_length = 4 + 32
    patched_content = bytearray(content)
    patched_content[-entry_length + 4 :] = b"\xff" * 32
    with pytest.raises(AuthenticodePageHashParseError):
        parse_page_hash_table(hashlib.sha256, bytes(patched_content))


def test_page_hash_table_with_only_terminator_is_structural_error():
    content = _page_hash_content(_read(PAGE_HASH_SAMPLE))
    entry_length = 4 + 32
    with pytest.raises(AuthenticodePageHashParseError):
        parse_page_hash_table(hashlib.sha256, content[-entry_length:])


def test_invalid_table_is_reported_and_verify_still_raises():
    """A malformed table in the signed file yields a report with a structural error,
    and the exception API still raises rather than silently skipping the table."""

    data = bytearray(_read(PAGE_HASH_SAMPLE))
    content = _page_hash_content(bytes(data))
    # Duplicate the second offset in the signed structure.
    entry_length = 4 + 32
    duplicate = content[entry_length : entry_length + 4]
    first = content[0:4]
    assert duplicate != first
    offset = bytes(data).index(content)
    data[offset + entry_length : offset + entry_length + 4] = first

    pefile = _pefile(bytes(data))
    signature = next(pefile.iter_embedded_signatures(include_nested=False))
    report = pefile.get_page_hash_report(signature.indirect_data)
    assert report is not None
    assert report.structural_errors
    assert not report.all_pages_match
    with pytest.raises(AuthenticodePageHashParseError):
        pefile.verify_additional_hashes(signature.indirect_data)
