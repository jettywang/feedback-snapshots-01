"""Byte-level tests for PE Authenticode coverage.

These tests pin the boundaries that matter to an ingestion service: which real
file offsets feed the Authenticode digest, which are excluded, and which excluded
regions are expected versus merely unexamined.
"""

from __future__ import annotations

import hashlib
import io
import pathlib

import pytest

from signify.authenticode import AuthenticodeVerificationResult
from signify.authenticode.coverage import (
    Mutation,
    PECoverageReport,
    default_mutations,
    run_mutation_matrix,
)
from signify.authenticode.signed_file.pe import SignedPEFile
from signify.x509 import Certificate, CertificateStore
from tests._utils import data_path, open_test_data

COVERAGE_FIXTURES = data_path("coverage")
SELF_SIGNED_PEM = COVERAGE_FIXTURES / "selfsigned.pem"


def _trust_store() -> CertificateStore:
    certificate = Certificate.from_pem(SELF_SIGNED_PEM.read_bytes())
    return CertificateStore([certificate], trusted=True)


def _report(filename: str, verify_chain: bool = True) -> PECoverageReport:
    with (COVERAGE_FIXTURES / filename).open("rb") as file_obj:
        signed_pe = SignedPEFile(file_obj)
        return PECoverageReport(
            signed_pe,
            verify_chain=verify_chain,
            trusted_certificate_store=_trust_store() if verify_chain else None,
        )


def _region(report: PECoverageReport, kind: str):
    return next(region for region in report.regions if region.kind == kind)


def test_hash_ranges_match_fingerprinter_input():
    """The exposed ranges are exactly what the fingerprinter consumes."""

    with open_test_data("pciide.sys") as file_obj:
        signed_pe = SignedPEFile(file_obj)
        ranges = signed_pe.get_authenticode_hash_ranges()
        assert ranges is not None
        expected = hashlib.sha256()
        for range_ in ranges:
            file_obj.seek(range_.start)
            expected.update(file_obj.read(range_.end - range_.start))
        assert signed_pe.get_fingerprint(hashlib.sha256) == expected.digest()


def test_minimal_layout_has_no_post_table_claim():
    report = _report("minimal_signed.exe")
    assert report.signature_status == "VALID"
    assert report.coverage_status == "AUTHENTICODE_RANGES_VERIFIED"
    assert report.extra_content_status == "NONE"
    assert report.full_file_hash_policy == "RECOMMENDED"

    table = report.certificate_table
    assert table is not None
    assert (table.address, table.end) == (0x400, 0xA08)
    assert table.slack_size == 0
    assert not any(region.kind == "post_certificate_table" for region in report.regions)

    # The checksum and directory entry are in real header offsets.
    checksum = _region(report, "checksum")
    assert (checksum.start, checksum.end) == (0x98, 0x9C)
    directory = _region(report, "certificate_directory")
    assert (directory.start, directory.end) == (0xE8, 0xF0)
    assert not checksum.in_digest and not directory.in_digest


def test_post_table_overlay_is_hashed():
    """Bytes after the declared table are folded into Signify's digest."""

    report = _report("minimal_signed_post_table_overlay.exe")
    assert report.signature_status == "VALID"
    tail = _region(report, "post_certificate_table")
    assert (tail.start, tail.end) == (0xA08, 0xA48)
    assert tail.in_digest
    assert report.hashed_tail_bytes == 0x40
    assert report.full_file_hash_policy == "RECOMMENDED"


def test_declared_table_slack_is_excluded_and_flagged():
    """Slack is excluded; it is not part of the signed payload."""

    report = _report("minimal_signed_slack.exe")
    assert report.signature_status == "VALID"
    assert report.coverage_status == "AUTHENTICODE_RANGES_VERIFIED"
    assert report.extra_content_status == "REVIEW_REQUIRED"
    assert report.full_file_hash_policy == "REQUIRED"
    slack = _region(report, "certificate_table_slack")
    assert (slack.start, slack.end) == (0xA08, 0xA28)
    assert not slack.in_digest
    assert report.unaccounted_excluded_bytes == 0x20
    assert report.signature_parse_error is not None


def test_table_can_be_extended_to_absorb_appended_bytes():
    """The same appended bytes are excluded once the declaration grows."""

    report = _report("minimal_signed_table_extended.exe")
    assert report.signature_status == "VALID"
    # The first 0x40 appended bytes at 0xa08..0xa48 are absorbed as table slack.
    slack = _region(report, "certificate_table_slack")
    assert (slack.start, slack.end) == (0xA08, 0xA48)
    assert not slack.in_digest
    # The remaining appended bytes at 0xa48..0xa88 are after the table and hashed.
    tail = _region(report, "post_certificate_table")
    assert (tail.start, tail.end) == (0xA48, 0xA88)
    assert tail.in_digest
    assert report.unaccounted_excluded_bytes == 0x40
    assert report.full_file_hash_policy == "REQUIRED"


@pytest.mark.parametrize(
    ("filename", "offset", "label"),
    [
        ("minimal_signed.exe", 0x98, "checksum"),
        ("minimal_signed.exe", 0x170, "header_gap"),
        ("minimal_signed.exe", 0x201, "section_padding"),
        ("minimal_signed.exe", 0x400, "certificate_table_header"),
        ("minimal_signed.exe", 0x408, "certificate_table_payload"),
        ("minimal_signed_slack.exe", 0xA08, "certificate_table_slack"),
        ("minimal_signed_post_table_overlay.exe", 0xA08, "post_certificate_table"),
    ],
)
def test_mutation_matrix_classifies_single_byte_edits(filename, offset, label):
    """A one-bit edit is either covered (digest changes) or excluded."""

    _, results = run_mutation_matrix(
        COVERAGE_FIXTURES / filename,
        mutations=[
            Mutation(name=label, description=label, operation="xor", offset=offset)
        ],
        trusted_certificate_store=_trust_store(),
        verify_chain=True,
    )
    result = results[0]
    assert result.file_size == len((COVERAGE_FIXTURES / filename).read_bytes())

    if label == "checksum":
        assert result.classification.startswith("EXCLUDED")
    if label == "certificate_table_slack":
        # Slack is excluded; the slack fixture's trailing bytes still parse as
        # malformed table data, which the report surfaces separately.
        assert result.signed_digest_matches
        assert result.signature_crypto_ok
    if label == "post_certificate_table":
        assert result.classification.startswith("COVERED")
    if label == "checksum":
        assert result.signed_digest_matches
        assert result.verify_status == "OK"

    # Every mutation changes the ordinary SHA-256, including excluded bytes.
    assert (
        result.sha256
        != hashlib.sha256((COVERAGE_FIXTURES / filename).read_bytes()).hexdigest()
    )


def test_default_mutations_cover_each_region_family():
    report = _report("minimal_signed.exe", verify_chain=False)
    names = {mutation.name for mutation in default_mutations(report)}
    assert {
        "checksum",
        "certificate_directory_address",
        "certificate_directory_size",
        "certificate_entry_length",
        "certificate_entry_payload",
        "header_gap",
        "section_padding",
        "first_section",
        "last_section_byte",
        "append_without_size",
        "append_with_size",
    } <= names


def test_default_mutations_include_non_pkcs7_entry():
    report = _report("minimal_signed_extra_entry.exe", verify_chain=False)
    names = {mutation.name for mutation in default_mutations(report)}
    assert "non_pkcs7_entry_payload" in names


def test_pciide_real_sample_boundaries():
    """A real signed driver: excluded header fields, hashed section bytes."""

    with open_test_data("pciide.sys") as file_obj:
        signed_pe = SignedPEFile(file_obj)
        report = PECoverageReport(signed_pe, verify_chain=False)

    assert report.signature_status == "VALID_DIGEST_ONLY"
    assert report.coverage_status == "AUTHENTICODE_RANGES_VERIFIED"
    assert report.file_size == 12352
    table = report.certificate_table
    assert table is not None
    assert (table.address, table.end) == (0x1400, 0x3040)
    assert table.slack_size == 0
    assert report.hashed_tail_bytes == 0
    assert report.full_file_hash_policy == "RECOMMENDED"

    by_kind = {region.kind: region for region in report.regions}
    assert by_kind["checksum"].start == 0x130
    assert by_kind["certificate_directory"].start == 0x180
    assert by_kind["header_gap"].start == 0x2D0
    assert by_kind["header_gap"].in_digest
    assert by_kind["section"].start == 0x1000

    sections = [region for region in report.regions if region.kind == "section"]
    assert sections[0].start == 0x400  # .text
    assert sections[-1].end == 0x1400  # .rsrc ends at the certificate table


def test_pciide_append_requires_table_update_to_stay_valid():
    base_path = data_path("pciide.sys")
    base = base_path.read_bytes()

    def status(data: bytes) -> tuple[bool, str]:
        signed_pe = SignedPEFile(io.BytesIO(data))
        report = PECoverageReport(signed_pe, verify_chain=False)
        return report.digest_matches, report.signature_status

    # Without updating the declared size, appended bytes are hashed.
    appended = base + b"\x41" * 64
    matches, signature_status = status(appended)
    assert not matches
    assert signature_status == "INVALID_DIGEST"

    # Extending the declared size over the same bytes excludes them.
    import struct

    extended = bytearray(appended)
    struct.pack_into("<I", extended, 0x184, 0x1C40 + 64)
    matches, signature_status = status(bytes(extended))
    assert matches
    assert signature_status == "VALID_DIGEST_ONLY"


def test_peek_into_untrusted_chain_is_separate():
    with open_test_data("pciide.sys") as file_obj:
        signed_pe = SignedPEFile(file_obj)
        report = PECoverageReport(signed_pe, verify_chain=False)
    assert report.signature_status == "VALID_DIGEST_ONLY"
    assert report.signature_valid  # digest + signer signature
    assert not report.chain_checked


def test_non_pkcs7_entry_is_flagged_as_extra_content():
    """A second certificate entry is excluded, but is not signed content."""

    report = _report("minimal_signed_extra_entry.exe")
    assert report.signature_status == "VALID"
    assert report.coverage_status == "AUTHENTICODE_RANGES_VERIFIED"
    assert report.extra_content_status == "REVIEW_REQUIRED"
    assert report.full_file_hash_policy == "REQUIRED"
    assert report.unaccounted_excluded_bytes == 0x18

    table = report.certificate_table
    assert table is not None
    assert len(table.entries) == 2
    assert table.entries[0].is_pkcs7
    assert not table.entries[1].is_pkcs7
    assert (table.entries[1].offset, table.entries[1].end) == (0xA08, 0xA20)
    assert [region.category for region in report.extra_excluded_regions] == [
        "certificate_table_header",
        "certificate_table_non_pkcs7_payload",
    ]


def test_get_coverage_report_convenience_method():
    with (COVERAGE_FIXTURES / "minimal_signed.exe").open("rb") as file_obj:
        signed_pe = SignedPEFile(file_obj)
        report = signed_pe.get_coverage_report(
            verify_chain=True, trusted_certificate_store=_trust_store()
        )
    assert report.signature_status == "VALID"


def test_report_to_dict_has_stable_status_keys():
    report = _report("minimal_signed_slack.exe")
    payload = report.to_dict()
    assert payload["signature_status"] == "VALID"
    assert payload["coverage_status"] == "AUTHENTICODE_RANGES_VERIFIED"
    assert payload["extra_content_status"] == "REVIEW_REQUIRED"
    assert payload["full_file_hash_policy"] == "REQUIRED"
    assert payload["certificate_table"]["slack_size"] == 0x20
    assert any(
        entry["category"] == "certificate_table_slack"
        for entry in payload["excluded_ranges"]
    )


def test_inter_section_gap_is_hashed_not_treated_as_overlay():
    """Padding between sections is inside the digest, unlike the cert table."""

    report = _report("minimal_signed_section_gap.exe")
    assert report.signature_status == "VALID"
    gap = _region(report, "inter_section_gap")
    assert (gap.start, gap.end) == (0x600, 0x800)
    assert gap.in_digest
    assert report.extra_content_status == "NONE"


def test_section_boundaries_are_reported_in_real_offsets():
    report = _report("minimal_signed_section_gap.exe")
    assert [
        (section.name, section.raw_address, section.raw_size)
        for section in report.sections
    ] == [
        (".text", 0x400, 0x200),
        (".data", 0x800, 0x200),
    ]
    regions = {
        region.kind: region for region in report.regions if region.kind == "section"
    }
    section_regions = [region for region in report.regions if region.kind == "section"]
    assert [(r.start, r.end) for r in section_regions] == [
        (0x400, 0x600),
        (0x800, 0xA00),
    ]
