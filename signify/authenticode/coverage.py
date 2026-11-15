"""Byte-level coverage analysis for PE Authenticode signatures.

This module answers a narrower question than :meth:`SignedPEFile.verify`: which
exact file offsets contribute to the Authenticode digest, which are excluded, and
what remains unauthenticated even when the signature validates.

The distinction matters for ingestion pipelines.  A valid Authenticode signature
proves that a signer approved the digest over the ranges in
:meth:`SignedPEFile.get_authenticode_hash_ranges`.  It does not prove that every
byte in the file was approved: the PE checksum, the certificate-directory entry,
and the declared certificate table are excluded by design, and the declaration
itself is outside the digest.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import pathlib
import struct
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, BinaryIO, Literal

from signify._typing import HashFunction
from signify.authenticode.verification_result import AuthenticodeVerificationResult
from signify.x509 import CertificateStore

if TYPE_CHECKING:
    from signify.authenticode.signed_file.pe import SignedPEFile


# ---------------------------------------------------------------------------
# data model


@dataclass(frozen=True)
class PESection:
    """A section header as stored in the PE section table."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_address: int
    raw_size: int

    @property
    def raw_end(self) -> int:
        return self.raw_address + self.raw_size

    @property
    def mapped_end(self) -> int:
        """End of the part of the raw data that belongs to the mapped image."""
        return self.raw_address + min(self.virtual_size, self.raw_size)


@dataclass(frozen=True)
class CertificateTableEntry:
    """A single ``WIN_CERTIFICATE`` record in the PE certificate table."""

    offset: int
    length: int
    revision: int
    certificate_type: int
    payload_start: int
    payload_end: int
    padding_start: int
    padding_end: int

    @property
    def end(self) -> int:
        return self.padding_end

    @property
    def header_end(self) -> int:
        return self.offset + 8

    @property
    def is_pkcs7(self) -> bool:
        return self.certificate_type == 0x0002 and self.revision == 0x0200

    @property
    def label(self) -> str:
        kind = "PKCS#7 SignedData" if self.is_pkcs7 else "non-PKCS#7 entry"
        return (
            f"WIN_CERTIFICATE {kind} "
            f"(type=0x{self.certificate_type:04x}, rev=0x{self.revision:04x})"
        )


@dataclass(frozen=True)
class CertificateTable:
    """Parsed view of the certificate table declared in the data directory."""

    address: int
    size: int
    entries: tuple[CertificateTableEntry, ...]
    parsed_end: int
    slack_start: int
    slack_end: int
    excluded: bool = True
    malformed_reason: str | None = None

    @property
    def end(self) -> int:
        return self.address + self.size

    @property
    def slack_size(self) -> int:
        return self.slack_end - self.slack_start

    @property
    def padding_size(self) -> int:
        return sum(e.padding_end - e.padding_start for e in self.entries)

    @property
    def non_pkcs7_entries(self) -> tuple[CertificateTableEntry, ...]:
        return tuple(e for e in self.entries if not e.is_pkcs7)

    @property
    def non_pkcs7_bytes(self) -> int:
        return sum(e.end - e.offset for e in self.non_pkcs7_entries)

    @property
    def signature_bytes(self) -> int:
        return sum(e.end - e.offset for e in self.entries if e.is_pkcs7)


@dataclass(frozen=True)
class Region:
    """A contiguous, non-overlapping file region with a semantic label."""

    start: int
    end: int
    kind: str
    label: str
    in_digest: bool

    @property
    def length(self) -> int:
        return self.end - self.start

    @property
    def span(self) -> str:
        return f"0x{self.start:08x}-0x{self.end:08x}"


@dataclass(frozen=True)
class SignatureCheck:
    """Result of checking one embedded Authenticode SignedData object."""

    index: int
    algorithm: str
    signed_digest: str
    computed_digest: str | None
    digest_matches: bool
    crypto_ok: bool
    crypto_error: str | None
    chain_status: str | None
    chain_error: str | None

    @property
    def valid(self) -> bool:
        return (
            self.digest_matches
            and self.crypto_ok
            and self.chain_status
            in (
                None,
                "OK",
            )
        )


@dataclass(frozen=True)
class ExcludedRange:
    """A range excluded from the Authenticode digest."""

    start: int
    end: int
    category: str
    description: str

    @property
    def length(self) -> int:
        return self.end - self.start

    @property
    def span(self) -> str:
        return f"0x{self.start:08x}-0x{self.end:08x}"


@dataclass
class PECoverageReport:
    """A byte-level report of what a PE Authenticode signature covers.

    The report is intentionally independent from certificate-chain trust.  Digest
    coverage can be established without network access or a trust store; chain
    verification is an optional separate check.
    """

    signed_pe_file: SignedPEFile
    verify_chain: bool = True
    trusted_certificate_store: CertificateStore | None = None
    countersignature_mode: Literal["strict", "permit", "ignore"] = "permit"

    file_size: int = field(init=False)
    pe_offset: int | None = field(init=False, default=None)
    optional_header_offset: int | None = field(init=False, default=None)
    checksum_offset: int | None = field(init=False, default=None)
    certificate_directory_offset: int | None = field(init=False, default=None)
    certificate_table: CertificateTable | None = field(init=False, default=None)
    declared_certificate_address: int | None = field(init=False, default=None)
    declared_certificate_size: int | None = field(init=False, default=None)
    hash_ranges: list[tuple[int, int]] = field(init=False, default_factory=list)
    regions: list[Region] = field(init=False, default_factory=list)
    excluded_ranges: list[ExcludedRange] = field(init=False, default_factory=list)
    signatures: list[SignatureCheck] = field(init=False, default_factory=list)
    signature_parse_error: str | None = field(init=False, default=None)
    parse_error: str | None = field(init=False, default=None)
    sections: list[PESection] = field(init=False, default_factory=list)
    header_end: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        self.signed_pe_file.file.seek(0)
        self.data = self.signed_pe_file.file.read()
        self.file_size = len(self.data)

        self._parse_headers()
        self._parse_hash_ranges()
        self._parse_certificate_table()
        self._build_regions()
        self._parse_signatures()

    # -- parsing ----------------------------------------------------------

    def _parse_headers(self) -> None:
        data = self.data
        try:
            if data[:2] != b"MZ":
                raise ValueError("missing MZ header")
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if data[pe_offset : pe_offset + 4] != b"PE\0\0":
                raise ValueError("missing PE signature")
            self.pe_offset = pe_offset

            number_of_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
            optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            optional_header_offset = pe_offset + 24
            self.optional_header_offset = optional_header_offset
            self.checksum_offset = optional_header_offset + 64
            if optional_header_offset + optional_header_size > len(data):
                raise ValueError("optional header extends beyond EOF")

            magic = struct.unpack_from("<H", data, optional_header_offset)[0]
            if magic == 0x10B:
                rva_count_offset = optional_header_offset + 92
                certificate_directory_offset = optional_header_offset + 128
            elif magic == 0x20B:
                rva_count_offset = optional_header_offset + 108
                certificate_directory_offset = optional_header_offset + 144
            else:
                raise ValueError(f"unknown optional header magic 0x{magic:04x}")

            self.certificate_directory_offset = certificate_directory_offset
            if optional_header_offset + optional_header_size >= rva_count_offset + 4:
                number_of_rva = struct.unpack_from("<I", data, rva_count_offset)[0]
                if number_of_rva < 5:
                    self.certificate_directory_offset = None
            else:
                self.certificate_directory_offset = None

            section_table_offset = optional_header_offset + optional_header_size
            self.header_end = min(
                section_table_offset + number_of_sections * 40, len(data)
            )
            for index in range(number_of_sections):
                offset = section_table_offset + index * 40
                if offset + 40 > len(data):
                    raise ValueError("section table extends beyond EOF")
                name = (
                    data[offset : offset + 8].rstrip(b"\0").decode("latin-1", "replace")
                )
                virtual_size, virtual_address, raw_size, raw_address = (
                    struct.unpack_from("<IIII", data, offset + 8)
                )
                self.sections.append(
                    PESection(
                        name=name,
                        virtual_address=virtual_address,
                        virtual_size=virtual_size,
                        raw_address=raw_address,
                        raw_size=raw_size,
                    )
                )
            self.sections.sort(key=lambda section: section.raw_address)
        except (ValueError, struct.error) as exc:
            self.parse_error = str(exc)

    def _parse_hash_ranges(self) -> None:
        try:
            ranges = self.signed_pe_file.get_authenticode_hash_ranges()
        except Exception as exc:  # pragma: no cover - defensive
            self.parse_error = self.parse_error or str(exc)
            ranges = None
        if ranges is None:
            return
        self.hash_ranges = [(r.start, r.end) for r in ranges if r.end > r.start]

    def _parse_certificate_table(self) -> None:
        if self.certificate_directory_offset is None:
            return
        if self.certificate_directory_offset + 8 > len(self.data):
            return
        address, size = struct.unpack_from(
            "<II", self.data, self.certificate_directory_offset
        )
        self.declared_certificate_address = address
        self.declared_certificate_size = size
        if not size:
            return
        if address + size > len(self.data):
            return
        # Mirror the range Signify actually excludes. A table pointing into the
        # headers is ignored by the fingerprinter and must not be presented here as
        # an authenticated exclusion boundary.
        try:
            omit = self.signed_pe_file.get_authenticode_omit_sections()
        except Exception:
            omit = None
        excluded = omit is not None and "certtable" in omit
        if excluded and omit is not None:
            declared = omit["certtable"]
            if declared.start != address or declared.length != size:
                excluded = False
        entries: list[CertificateTableEntry] = []
        position = address
        end = address + size
        malformed: str | None = None
        while position < end:
            if position + 8 > end:
                malformed = "truncated WIN_CERTIFICATE header"
                break
            length, revision, certificate_type = struct.unpack_from(
                "<IHH", self.data, position
            )
            if length <= 8 or position + length > end:
                malformed = (
                    f"invalid WIN_CERTIFICATE length 0x{length:x} at " f"0x{position:x}"
                )
                break
            payload_start = position + 8
            payload_end = position + length
            padding_end = min(payload_end + (-length % 8), end)
            if payload_end + (-length % 8) > end:
                malformed = "WIN_CERTIFICATE alignment padding exceeds table end"
            entries.append(
                CertificateTableEntry(
                    offset=position,
                    length=length,
                    revision=revision,
                    certificate_type=certificate_type,
                    payload_start=payload_start,
                    payload_end=payload_end,
                    padding_start=payload_end,
                    padding_end=padding_end,
                )
            )
            if payload_end + (-length % 8) > end:
                position = end
                break
            position = padding_end

        self.certificate_table = CertificateTable(
            address=address,
            size=size,
            entries=tuple(entries),
            parsed_end=position,
            slack_start=position,
            slack_end=end,
            excluded=excluded,
            malformed_reason=malformed,
        )

    # -- regions ----------------------------------------------------------

    def _build_regions(self) -> None:
        """Build a complete, non-overlapping semantic map of the file."""

        data = self.data
        boundaries: set[int] = {0, len(data)}
        candidates: list[tuple[int, int, int, str, str]] = []

        def add(
            start: int,
            end: int,
            priority: int,
            kind: str,
            label: str,
        ) -> None:
            start = max(0, start)
            end = min(len(data), end)
            if end <= start:
                return
            candidates.append((start, end, priority, kind, label))
            boundaries.add(start)
            boundaries.add(end)

        if self.parse_error is not None:
            add(0, len(data), 1, "unparsed", "unparsed PE layout")
        else:
            add(0, self.header_end, 10, "headers", "PE headers")
            if self.checksum_offset is not None:
                add(
                    self.checksum_offset,
                    self.checksum_offset + 4,
                    100,
                    "checksum",
                    "PE optional-header CheckSum field (excluded)",
                )
            if self.certificate_directory_offset is not None:
                add(
                    self.certificate_directory_offset,
                    self.certificate_directory_offset + 8,
                    100,
                    "certificate_directory",
                    "Data Directory entry 4: certificate table address/size "
                    "(excluded; controls the exclusion boundary)",
                )

            previous_end = self.header_end
            for section in self.sections:
                if section.raw_size == 0:
                    continue
                start = max(section.raw_address, 0)
                end = min(section.raw_end, len(data))
                if end <= start:
                    continue
                if start > previous_end:
                    add(
                        previous_end,
                        start,
                        (30 if previous_end == self.header_end else 31),
                        (
                            "header_gap"
                            if previous_end == self.header_end
                            else "inter_section_gap"
                        ),
                        (
                            "header padding before first section (hashed)"
                            if previous_end == self.header_end
                            else "gap between sections (hashed)"
                        ),
                    )
                add(
                    start,
                    end,
                    50,
                    "section",
                    f"section {section.name or '<unnamed>'} raw data",
                )
                if section.virtual_size < section.raw_size:
                    add(
                        start + section.virtual_size,
                        end,
                        55,
                        "section_padding",
                        f"section {section.name or '<unnamed>'} raw padding beyond "
                        "VirtualSize (hashed, not mapped)",
                    )
                previous_end = max(previous_end, end)

            table = self.certificate_table
            if table is not None:
                if previous_end < table.address:
                    add(
                        previous_end,
                        table.address,
                        30,
                        "gap_before_certificate_table",
                        "gap between last section and certificate table (hashed)",
                    )
                if table.excluded:
                    add(
                        table.address,
                        table.end,
                        60,
                        "certificate_table",
                        "declared certificate table (excluded)",
                    )
                else:
                    add(
                        table.address,
                        table.end,
                        60,
                        "declared_certificate_table_not_excluded",
                        "declared certificate table that Signify does not exclude "
                        "(invalid placement; hashed)",
                    )
                for entry in table.entries:
                    add(
                        entry.offset,
                        entry.header_end,
                        88,
                        "certificate_table_header",
                        (
                            "WIN_CERTIFICATE header "
                            f"(type=0x{entry.certificate_type:04x}, "
                            f"rev=0x{entry.revision:04x}; excluded, controls "
                            "entry parsing)"
                        ),
                    )
                    add(
                        entry.header_end,
                        entry.payload_end,
                        80,
                        (
                            "certificate_table_payload"
                            if entry.is_pkcs7
                            else "certificate_table_non_pkcs7_payload"
                        ),
                        (
                            "PKCS#7 SignedData payload (excluded)"
                            if entry.is_pkcs7
                            else "non-PKCS#7 certificate payload (excluded)"
                        ),
                    )
                    add(
                        entry.padding_start,
                        entry.padding_end,
                        85,
                        "certificate_table_padding",
                        "WIN_CERTIFICATE alignment padding (excluded)",
                    )
                add(
                    table.slack_start,
                    table.slack_end,
                    85,
                    "certificate_table_slack",
                    "declared certificate-table slack after last parsed entry "
                    "(excluded)",
                )
                if table.end < len(data):
                    add(
                        table.end,
                        len(data),
                        40,
                        "post_certificate_table",
                        "bytes after declared certificate table "
                        "(Signify includes these in the digest)",
                    )
            elif previous_end < len(data):
                add(
                    previous_end,
                    len(data),
                    30,
                    "post_section_tail",
                    "tail after last section, outside any certificate table "
                    "(hashed)",
                )

        offsets: list[int] = sorted(boundaries)
        cells: list[tuple[int, int, str, str]] = []
        for start, end in zip(offsets, offsets[1:]):
            chosen: tuple[int, int, int, str, str] | None = None
            for candidate in candidates:
                c_start, c_end, priority, kind, label = candidate
                if c_start <= start and end <= c_end:
                    if chosen is None or priority > chosen[2]:
                        chosen = candidate
            if chosen is None:
                cells.append((start, end, "unclassified", "unclassified bytes"))
            else:
                cells.append((start, end, chosen[3], chosen[4]))

        merged: list[Region] = []
        for start, end, kind, label in cells:
            in_digest = self._range_is_hashed(start, end)
            region = Region(start, end, kind, label, in_digest)
            if (
                merged
                and merged[-1].kind == region.kind
                and merged[-1].label == region.label
                and merged[-1].in_digest == region.in_digest
                and merged[-1].end == region.start
            ):
                previous = merged[-1]
                merged[-1] = Region(
                    previous.start,
                    region.end,
                    previous.kind,
                    previous.label,
                    previous.in_digest,
                )
            else:
                merged.append(region)
        self.regions = merged
        self.excluded_ranges = [
            ExcludedRange(
                region.start,
                region.end,
                region.kind,
                region.label,
            )
            for region in merged
            if not region.in_digest
        ]

    def _range_is_hashed(self, start: int, end: int) -> bool:
        return any(
            range_start <= start and end <= range_end
            for range_start, range_end in self.hash_ranges
        )

    # -- signatures -------------------------------------------------------

    def _parse_signatures(self) -> None:
        # Windows (and Signify's verify() default) keeps earlier valid entries when a
        # later certificate-table entry is malformed.  Mirror that here, but retain
        # the parse error as a warning rather than discarding usable signatures.
        try:
            signatures = list(
                self.signed_pe_file.iter_embedded_signatures(ignore_parse_errors=True)
            )
        except Exception as exc:
            # Signify normally swallows SignedPEParseError here; an ASN.1 error
            # inside the PKCS#7 blob can still escape and means no usable signature.
            self.signature_parse_error = f"{type(exc).__name__}: {exc}"
            signatures = []
        try:
            list(
                self.signed_pe_file.iter_embedded_signatures(ignore_parse_errors=False)
            )
        except Exception as exc:
            self.signature_parse_error = f"{type(exc).__name__}: {exc}"

        for index, signed_data in enumerate(signatures):
            indirect_data = signed_data.indirect_data
            algorithm = indirect_data.digest_algorithm().name
            signed_digest = indirect_data.digest.hex()
            try:
                computed = self.signed_pe_file.get_fingerprint(
                    indirect_data.digest_algorithm
                )
                computed_digest: str | None = computed.hex()
                digest_matches = computed == indirect_data.digest
            except Exception:
                computed_digest = None
                digest_matches = False

            crypto_ok = False
            crypto_error: str | None = None
            try:
                issuer = next(
                    (
                        certificate
                        for certificate in signed_data.certificates
                        if certificate.issuer == signed_data.signer_info.issuer
                        and certificate.serial_number
                        == signed_data.signer_info.serial_number
                    ),
                    None,
                )
                if issuer is None:
                    raise ValueError("issuer certificate is not embedded")
                issuer.verify_signature(
                    signed_data.signer_info.encrypted_digest,
                    signed_data.signer_info._encoded_authenticated_attributes,
                    signed_data.signer_info.digest_algorithm,
                )
                crypto_ok = True
            except Exception as exc:
                crypto_error = f"{type(exc).__name__}: {exc}"

            chain_status: str | None = None
            chain_error: str | None = None
            if self.verify_chain and self.trusted_certificate_store is not None:
                status, error = AuthenticodeVerificationResult.call(
                    signed_data.verify,
                    trusted_certificate_store=self.trusted_certificate_store,
                    countersignature_mode=self.countersignature_mode,
                    verification_context_kwargs={"allow_fetching": False},
                )
                chain_status = status.name
                chain_error = str(error) if error else None

            self.signatures.append(
                SignatureCheck(
                    index=index,
                    algorithm=algorithm,
                    signed_digest=signed_digest,
                    computed_digest=computed_digest,
                    digest_matches=digest_matches,
                    crypto_ok=crypto_ok,
                    crypto_error=crypto_error,
                    chain_status=chain_status,
                    chain_error=chain_error,
                )
            )

    # -- summary / decisions ---------------------------------------------

    @property
    def covered_bytes(self) -> int:
        return sum(region.length for region in self.regions if region.in_digest)

    @property
    def excluded_bytes(self) -> int:
        return self.file_size - self.covered_bytes

    @property
    def hashed_tail_bytes(self) -> int:
        return sum(
            region.length
            for region in self.regions
            if region.kind == "post_certificate_table" and region.in_digest
        )

    @property
    def unaccounted_excluded_bytes(self) -> int:
        """Excluded bytes outside the checksum, directory entry, and PKCS#7.

        These are bytes a valid signature explicitly does not speak about, but
        which also do not correspond to the expected signature structure: table
        padding, table slack, and non-PKCS#7 certificate entries.
        """

        if self.certificate_table is None:
            return 0
        table = self.certificate_table
        return table.padding_size + table.non_pkcs7_bytes + table.slack_size

    @property
    def extra_excluded_regions(self) -> list[ExcludedRange]:
        """Excluded regions that warrant a separate content review.

        PKCS#7 payload bytes and the 8-byte entry headers that locate them are
        expected; padding, declared table slack, and non-PKCS#7 entries are not.
        """

        result = []
        for region in self.excluded_ranges:
            if region.category in {"checksum", "certificate_directory"}:
                continue
            if region.category in {
                "certificate_table_payload",
            }:
                continue
            if region.category == "certificate_table_header":
                # A PKCS#7 header is expected; a non-PKCS#7 header is not.
                if self._header_is_pkcs7(region.start):
                    continue
                result.append(region)
                continue
            result.append(region)
        return result

    def _header_is_pkcs7(self, offset: int) -> bool:
        table = self.certificate_table
        if table is None:
            return False
        return any(entry.offset == offset and entry.is_pkcs7 for entry in table.entries)

    @property
    def digest_matches(self) -> bool:
        return any(signature.digest_matches for signature in self.signatures)

    @property
    def signature_crypto_ok(self) -> bool:
        return any(signature.crypto_ok for signature in self.signatures)

    @property
    def signature_valid(self) -> bool:
        return any(signature.valid for signature in self.signatures)

    @property
    def chain_checked(self) -> bool:
        return self.verify_chain and self.trusted_certificate_store is not None

    @property
    def signature_status(self) -> str:
        if self.signature_parse_error is not None and not self.signatures:
            return "PARSE_ERROR"
        if not self.signatures:
            return "UNSIGNED"
        if self.digest_matches and self.signature_crypto_ok:
            if not self.chain_checked:
                return "VALID_DIGEST_ONLY"
            if any(signature.chain_status == "OK" for signature in self.signatures):
                return "VALID"
            return "UNTRUSTED_CHAIN"
        if not self.signature_crypto_ok:
            return "INVALID_SIGNATURE"
        return "INVALID_DIGEST"

    @property
    def coverage_status(self) -> str:
        if self.digest_matches and self.signature_crypto_ok:
            return "AUTHENTICODE_RANGES_VERIFIED"
        if not self.signatures:
            return "NO_SIGNATURE"
        return "NOT_VERIFIED"

    @property
    def extra_content_status(self) -> str:
        if self.signature_parse_error is not None:
            return "REVIEW_REQUIRED"
        if self.unaccounted_excluded_bytes:
            return "REVIEW_REQUIRED"
        if self.extra_excluded_regions:
            return "REVIEW_REQUIRED"
        return "NONE"

    @property
    def full_file_hash_policy(self) -> str:
        if not self.signatures or self.parse_error is not None:
            return "REQUIRED"
        if not self.digest_matches:
            return "REQUIRED"
        if self.unaccounted_excluded_bytes:
            return "REQUIRED"
        return "RECOMMENDED"

    @property
    def full_file_hash_reasons(self) -> list[str]:
        reasons: list[str] = []
        if self.parse_error is not None:
            return [
                "PE layout could not be parsed; no Authenticode coverage can be "
                "established."
            ]
        if not self.signatures:
            return [
                "No usable embedded Authenticode signature; the whole file must "
                "be treated as unverified."
            ]
        if not self.digest_matches:
            reasons.append(
                "the Authenticode digest over the computed ranges does not match "
                "the signed digest, so no covered range can be relied upon."
            )
        if self.checksum_offset is not None:
            reasons.append(
                f"the 4-byte PE CheckSum at 0x{self.checksum_offset:x} is excluded "
                "from the Authenticode digest and can change without invalidating "
                "the signature."
            )
        if self.certificate_directory_offset is not None:
            reasons.append(
                f"the 8-byte certificate-directory entry at "
                f"0x{self.certificate_directory_offset:x} is excluded and also "
                "selects which certificate-table bytes are excluded; it is not "
                "authenticated by the digest it controls."
            )
        if self.certificate_table is not None:
            table = self.certificate_table
            reasons.append(
                f"the declared certificate table 0x{table.address:x}-0x{table.end:x} "
                f"({table.size} bytes) is excluded; this includes "
                f"{table.signature_bytes} bytes of PKCS#7 structure."
            )
            if table.slack_size:
                reasons.append(
                    f"{table.slack_size} bytes of declared table slack at "
                    f"0x{table.slack_start:x}-0x{table.slack_end:x} are excluded "
                    "and were not parsed as a certificate."
                )
            if table.non_pkcs7_bytes:
                reasons.append(
                    f"{table.non_pkcs7_bytes} bytes belong to non-PKCS#7 "
                    "certificate-table entries and are not covered by the "
                    "Authenticode signature."
                )
            if table.padding_size:
                reasons.append(
                    f"{table.padding_size} bytes of WIN_CERTIFICATE alignment "
                    "padding are excluded."
                )
            pkcs7_headers = sum(8 for entry in table.entries if entry.is_pkcs7)
            if pkcs7_headers:
                reasons.append(
                    f"{pkcs7_headers} bytes of WIN_CERTIFICATE headers are "
                    "excluded and control how the PKCS#7 payload is located; "
                    "they are not authenticated by the digest."
                )
        if self.hashed_tail_bytes:
            reasons.append(
                f"{self.hashed_tail_bytes} bytes after the declared certificate "
                "table are included by Signify's range construction; treat this as "
                "a layout-dependent difference from other verifiers and bind the "
                "exact bytes with a full-file hash."
            )
        return reasons

    # -- rendering --------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        table = self.certificate_table
        return {
            "file_size": self.file_size,
            "parse_error": self.parse_error,
            "signature_parse_error": self.signature_parse_error,
            "pe_offset": self.pe_offset,
            "checksum_offset": self.checksum_offset,
            "certificate_directory_offset": self.certificate_directory_offset,
            "header_end": self.header_end,
            "hash_ranges": [
                {"start": start, "end": end, "length": end - start}
                for start, end in self.hash_ranges
            ],
            "covered_bytes": self.covered_bytes,
            "excluded_bytes": self.excluded_bytes,
            "excluded_ranges": [
                {
                    "start": region.start,
                    "end": region.end,
                    "length": region.length,
                    "category": region.category,
                    "description": region.description,
                }
                for region in self.excluded_ranges
            ],
            "regions": [
                {
                    "start": region.start,
                    "end": region.end,
                    "length": region.length,
                    "kind": region.kind,
                    "label": region.label,
                    "in_digest": region.in_digest,
                }
                for region in self.regions
            ],
            "sections": [
                {
                    "name": section.name,
                    "virtual_address": section.virtual_address,
                    "virtual_size": section.virtual_size,
                    "raw_address": section.raw_address,
                    "raw_size": section.raw_size,
                }
                for section in self.sections
            ],
            "certificate_table": None
            if table is None
            else {
                "address": table.address,
                "size": table.size,
                "end": table.end,
                "parsed_end": table.parsed_end,
                "slack_start": table.slack_start,
                "slack_end": table.slack_end,
                "slack_size": table.slack_size,
                "padding_size": table.padding_size,
                "non_pkcs7_bytes": table.non_pkcs7_bytes,
                "malformed_reason": table.malformed_reason,
                "entries": [
                    {
                        "offset": entry.offset,
                        "length": entry.length,
                        "revision": entry.revision,
                        "certificate_type": entry.certificate_type,
                        "payload_start": entry.payload_start,
                        "payload_end": entry.payload_end,
                        "padding_start": entry.padding_start,
                        "padding_end": entry.padding_end,
                        "is_pkcs7": entry.is_pkcs7,
                    }
                    for entry in table.entries
                ],
            },
            "signatures": [
                {
                    "index": signature.index,
                    "algorithm": signature.algorithm,
                    "signed_digest": signature.signed_digest,
                    "computed_digest": signature.computed_digest,
                    "digest_matches": signature.digest_matches,
                    "crypto_ok": signature.crypto_ok,
                    "crypto_error": signature.crypto_error,
                    "chain_status": signature.chain_status,
                    "chain_error": signature.chain_error,
                }
                for signature in self.signatures
            ],
            "signature_status": self.signature_status,
            "coverage_status": self.coverage_status,
            "extra_content_status": self.extra_content_status,
            "unaccounted_excluded_bytes": self.unaccounted_excluded_bytes,
            "full_file_hash_policy": self.full_file_hash_policy,
            "full_file_hash_reasons": self.full_file_hash_reasons,
        }

    def to_text(self) -> str:
        lines: list[str] = []
        lines.append("PE Authenticode coverage report")
        lines.append(f"file size: 0x{self.file_size:x} ({self.file_size} bytes)")
        if self.parse_error:
            lines.append(f"layout parse error: {self.parse_error}")
        lines.append(
            f"covered bytes: {self.covered_bytes}; excluded bytes: "
            f"{self.excluded_bytes}"
        )
        lines.append("")
        lines.append("Signatures:")
        if self.signature_parse_error:
            lines.append(f"  parse error: {self.signature_parse_error}")
        if not self.signatures:
            lines.append("  (none)")
        for signature in self.signatures:
            chain = (
                "not checked"
                if signature.chain_status is None
                else signature.chain_status
            )
            lines.append(
                f"  [{signature.index}] {signature.algorithm}: "
                f"signed={signature.signed_digest} "
                f"computed={signature.computed_digest} "
                f"digest={'MATCH' if signature.digest_matches else 'MISMATCH'} "
                f"crypto={'OK' if signature.crypto_ok else 'FAIL'} "
                f"chain={chain}"
            )
            if signature.crypto_error:
                lines.append(f"      crypto error: {signature.crypto_error}")
            if signature.chain_error:
                lines.append(f"      chain error: {signature.chain_error}")
        lines.append(
            f"status: signature={self.signature_status} "
            f"coverage={self.coverage_status} "
            f"extra={self.extra_content_status}"
        )
        lines.append("")
        lines.append("Authenticated ranges (bytes fed to the Authenticode digest):")
        lines.extend(
            f"  0x{region.start:08x}-0x{region.end:08x} "
            f"{region.length:7d} B  {region.label}"
            for region in self.regions
            if region.in_digest
        )
        lines.append("")
        lines.append("Excluded ranges (not authenticated by the signature):")
        lines.extend(
            f"  0x{region.start:08x}-0x{region.end:08x} "
            f"{region.length:7d} B  {region.description} [{region.category}]"
            for region in self.excluded_ranges
        )
        lines.append("")
        table = self.certificate_table
        if table is None:
            lines.append("Certificate table: none declared")
        else:
            lines.append(
                f"Certificate table: address=0x{table.address:x} "
                f"size=0x{table.size:x} end=0x{table.end:x}"
            )
            for index, entry in enumerate(table.entries):
                lines.append(
                    f"  [{index}] 0x{entry.offset:08x} len=0x{entry.length:x} "
                    f"rev=0x{entry.revision:04x} "
                    f"type=0x{entry.certificate_type:04x} "
                    f"payload=0x{entry.payload_start:08x}-0x{entry.payload_end:08x} "
                    f"padding=0x{entry.padding_start:08x}-0x{entry.padding_end:08x}"
                )
            if table.slack_size:
                lines.append(
                    f"  slack: 0x{table.slack_start:08x}-0x{table.slack_end:08x} "
                    f"({table.slack_size} bytes, excluded)"
                )
            if table.non_pkcs7_entries:
                lines.append(
                    f"  non-PKCS#7 entries: {len(table.non_pkcs7_entries)} "
                    f"({table.non_pkcs7_bytes} bytes, excluded)"
                )
            if table.malformed_reason:
                lines.append(f"  malformed: {table.malformed_reason}")
        lines.append("")
        lines.append(f"full-file hash policy: {self.full_file_hash_policy}")
        lines.extend(f"  - {reason}" for reason in self.full_file_hash_reasons)
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.to_text()


# ---------------------------------------------------------------------------
# mutation matrix


@dataclass(frozen=True)
class Mutation:
    """A single mutation applied to a baseline file."""

    name: str
    description: str
    operation: Literal["xor", "append"]
    offset: int | None = None
    payload: bytes = b"\x41" * 16
    update_certificate_table_size: bool = False


@dataclass(frozen=True)
class MutationResult:
    """The observable effect of one mutation."""

    mutation: Mutation
    file_size: int
    sha256: str
    authentihash_sha256: str | None
    authentihash_changed: bool | None
    baseline_covered: bool | None
    signed_digest_matches: bool
    signature_crypto_ok: bool
    verify_status: str
    classification: str
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.mutation.name,
            "description": self.mutation.description,
            "operation": self.mutation.operation,
            "offset": self.mutation.offset,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "authentihash_sha256": self.authentihash_sha256,
            "authentihash_changed": self.authentihash_changed,
            "baseline_covered": self.baseline_covered,
            "signed_digest_matches": self.signed_digest_matches,
            "signature_crypto_ok": self.signature_crypto_ok,
            "verify_status": self.verify_status,
            "classification": self.classification,
            "error": self.error,
        }


def _find_region(report: PECoverageReport, kind: str) -> Region | None:
    return next((region for region in report.regions if region.kind == kind), None)


def default_mutations(report: PECoverageReport) -> list[Mutation]:
    """Return a representative single-site mutation set for a report.

    The set intentionally covers both sides of the boundary: hashed bytes that
    must invalidate the digest, excluded bytes that can change while the
    signature remains valid, and appended bytes with and without extending the
    declared certificate table.
    """

    mutations: list[Mutation] = []
    seen: set[tuple[str, int | None]] = set()

    def add(name: str, description: str, offset: int | None) -> None:
        if offset is None or (name, offset) in seen:
            return
        if not 0 <= offset < report.file_size:
            return
        seen.add((name, offset))
        mutations.append(
            Mutation(
                name=name,
                description=description,
                operation="xor",
                offset=offset,
            )
        )

    if report.checksum_offset is not None:
        add(
            "checksum",
            "flip one bit in the excluded PE CheckSum field",
            report.checksum_offset,
        )
    if report.certificate_directory_offset is not None:
        add(
            "certificate_directory_address",
            "flip one bit in the excluded certificate-table address",
            report.certificate_directory_offset,
        )
        add(
            "certificate_directory_size",
            "flip one bit in the excluded certificate-table size",
            report.certificate_directory_offset + 4,
        )
    table = report.certificate_table
    if table is not None and table.entries:
        entry = table.entries[0]
        add(
            "certificate_entry_length",
            "flip one bit in WIN_CERTIFICATE.dwLength",
            entry.offset,
        )
        add(
            "certificate_entry_revision",
            "flip one bit in WIN_CERTIFICATE.wRevision",
            entry.offset + 4,
        )
        add(
            "certificate_entry_type",
            "flip one bit in WIN_CERTIFICATE.wCertificateType",
            entry.offset + 6,
        )
        add(
            "certificate_entry_payload",
            "flip one bit in the first byte of the PKCS#7 payload",
            entry.payload_start,
        )
        if entry.padding_end > entry.padding_start:
            add(
                "certificate_entry_padding",
                "flip one bit in WIN_CERTIFICATE alignment padding",
                entry.padding_start,
            )
    if table is not None and table.slack_size:
        add(
            "certificate_table_slack",
            "flip one bit in declared certificate-table slack",
            table.slack_start,
        )
    if table is not None:
        non_pkcs7 = table.non_pkcs7_entries
        if non_pkcs7:
            add(
                "non_pkcs7_entry_payload",
                "flip one bit in a non-PKCS#7 certificate payload",
                non_pkcs7[0].payload_start,
            )

    for kind, name, description in (
        (
            "header_gap",
            "header_gap",
            "flip one bit in header padding before the first section",
        ),
        (
            "inter_section_gap",
            "inter_section_gap",
            "flip one bit in the gap between two sections",
        ),
        (
            "post_certificate_table",
            "post_certificate_table",
            "flip one bit in the bytes after the declared certificate table",
        ),
        (
            "section_padding",
            "section_padding",
            "flip one bit in section padding beyond VirtualSize",
        ),
    ):
        region = _find_region(report, kind)
        if region is not None:
            add(name, description, region.start)

    if report.sections:
        add(
            "first_section",
            "flip one bit in the first section's raw data",
            report.sections[0].raw_address,
        )
        last = report.sections[-1]
        add(
            "last_section_byte",
            "flip one bit in the last byte of the last section",
            last.raw_end - 1,
        )

    # Appending is not an xor; add it separately.
    mutations.append(
        Mutation(
            name="append_without_size",
            description=(
                "append 16 bytes without changing the declared certificate-table "
                "size (Signify hashes these bytes)"
            ),
            operation="append",
        )
    )
    if table is not None:
        mutations.append(
            Mutation(
                name="append_with_size",
                description=(
                    "append 16 bytes and extend the declared certificate-table "
                    "size over them (excluded; signature can remain valid)"
                ),
                operation="append",
                update_certificate_table_size=True,
            )
        )
    return mutations


def _evaluate_mutation(
    data: bytes,
    mutation: Mutation,
    *,
    baseline: PECoverageReport,
    baseline_authentihash: str | None,
    trusted_certificate_store: CertificateStore | None,
    verify_chain: bool,
) -> MutationResult:
    baseline_covered: bool | None = None
    if mutation.offset is not None:
        baseline_covered = any(
            range_start <= mutation.offset < range_end
            for range_start, range_end in baseline.hash_ranges
        )

    from signify.authenticode.signed_file.pe import SignedPEFile

    try:
        pe = SignedPEFile(io.BytesIO(data))
        report = PECoverageReport(
            pe,
            verify_chain=verify_chain,
            trusted_certificate_store=trusted_certificate_store,
        )
    except Exception as exc:
        return MutationResult(
            mutation=mutation,
            file_size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            authentihash_sha256=None,
            authentihash_changed=None,
            baseline_covered=baseline_covered,
            signed_digest_matches=False,
            signature_crypto_ok=False,
            verify_status="PARSE_ERROR",
            classification="LAYOUT/LOOKUP BROKEN (no usable signature)",
            error=f"{type(exc).__name__}: {exc}",
        )

    try:
        authentihash = pe.get_fingerprint(hashlib.sha256).hex()
    except Exception:
        authentihash = None
    authentihash_changed: bool | None = None
    if authentihash is not None and baseline_authentihash is not None:
        authentihash_changed = authentihash != baseline_authentihash

    digest_matches = report.digest_matches
    crypto_ok = report.signature_crypto_ok
    usable_signature = bool(report.signatures)
    if report.signature_parse_error is not None and not usable_signature:
        verify_status = "PARSE_ERROR"
    elif not usable_signature:
        verify_status = "NOT_SIGNED"
    elif report.signature_status == "VALID":
        verify_status = "OK"
    elif report.signature_status == "VALID_DIGEST_ONLY":
        verify_status = "DIGEST_ONLY"
    elif report.signature_status == "UNTRUSTED_CHAIN":
        verify_status = "UNTRUSTED_CHAIN"
    elif report.signature_status == "INVALID_DIGEST":
        verify_status = "INVALID_DIGEST"
    elif report.signature_status == "INVALID_SIGNATURE":
        verify_status = "INVALID_SIGNATURE"
    else:
        verify_status = report.signature_status

    if authentihash_changed is None:
        classification = "AUTHENTIHASH UNAVAILABLE (layout cannot be hashed)"
    elif authentihash_changed:
        if crypto_ok:
            classification = "COVERED (digest changed; signature invalid)"
        elif not usable_signature:
            classification = (
                "COVERED (digest changed; signer payload no longer parseable)"
            )
        else:
            classification = "COVERED (digest changed; signer check failed)"
    elif baseline_covered:
        classification = (
            "COVERED BYTE BUT AUTHENTIHASH UNAVAILABLE (unexpected range result)"
        )
    elif not usable_signature:
        classification = (
            "EXCLUDED BYTES, SIGNATURE LOOKUP ALTERED (digest unchanged; "
            "certificate entry/table headers changed)"
        )
    elif report.signature_parse_error is not None:
        classification = (
            "EXCLUDED BYTES (digest unchanged; usable entry still validates; "
            "trailing table data malformed)"
        )
    elif crypto_ok:
        classification = "EXCLUDED BYTES (digest unchanged; signer still valid)"
    else:
        classification = "EXCLUDED BYTES, SIGNER CHECK FAILED (digest unchanged)"

    return MutationResult(
        mutation=mutation,
        file_size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        authentihash_sha256=authentihash,
        authentihash_changed=authentihash_changed,
        baseline_covered=baseline_covered,
        signed_digest_matches=digest_matches,
        signature_crypto_ok=crypto_ok,
        verify_status=verify_status,
        classification=classification,
    )


def run_mutation_matrix(
    source: str | pathlib.Path | BinaryIO,
    *,
    mutations: Sequence[Mutation] | None = None,
    trusted_certificate_store: CertificateStore | None = None,
    verify_chain: bool = False,
) -> tuple[PECoverageReport, list[MutationResult]]:
    """Run a mutation matrix against a PE file.

    ``source`` may be a path, a binary stream, or a :class:`SignedPEFile`.
    The returned report is the baseline report; each result records whether the
    full-file hash changed, whether the Authenticode digest changed, and whether
    the signature still verifies.
    """

    from signify.authenticode.signed_file.pe import SignedPEFile

    if isinstance(source, (str, pathlib.Path)):
        with pathlib.Path(source).open("rb") as file_obj:
            data = file_obj.read()
        pe = SignedPEFile(io.BytesIO(data))
    elif hasattr(source, "get_authenticode_hash_ranges"):
        pe = source  # type: ignore[assignment]
        pe.file.seek(0)
        data = pe.file.read()
        pe = SignedPEFile(io.BytesIO(data))
    else:
        pe = SignedPEFile(source)
        pe.file.seek(0)
        data = pe.file.read()
        pe = SignedPEFile(io.BytesIO(data))

    baseline = PECoverageReport(
        pe,
        verify_chain=verify_chain,
        trusted_certificate_store=trusted_certificate_store,
    )
    try:
        baseline_authentihash: str | None = pe.get_fingerprint(hashlib.sha256).hex()
    except Exception:
        baseline_authentihash = None
    selected = list(mutations) if mutations is not None else default_mutations(baseline)
    results: list[MutationResult] = []
    for mutation in selected:
        mutated = bytearray(data)
        if mutation.operation == "xor":
            assert mutation.offset is not None
            if not 0 <= mutation.offset < len(mutated):
                continue
            mutated[mutation.offset] ^= 0x01
        elif mutation.operation == "append":
            mutated.extend(mutation.payload)
            if mutation.update_certificate_table_size:
                if baseline.certificate_directory_offset is None:
                    continue
                offset = baseline.certificate_directory_offset + 4
                original_size = struct.unpack_from("<I", mutated, offset)[0]
                struct.pack_into(
                    "<I", mutated, offset, original_size + len(mutation.payload)
                )
        else:  # pragma: no cover - exhaustive enum
            raise ValueError(f"unknown mutation operation {mutation.operation!r}")
        results.append(
            _evaluate_mutation(
                bytes(mutated),
                mutation,
                baseline=baseline,
                baseline_authentihash=baseline_authentihash,
                trusted_certificate_store=trusted_certificate_store,
                verify_chain=verify_chain,
            )
        )
    return baseline, results


# ---------------------------------------------------------------------------
# command line


def _load_trust_store(path: str | pathlib.Path | None) -> CertificateStore | None:
    if path is None:
        return None
    from signify.x509 import Certificate

    certificates = list(Certificate.from_pems(pathlib.Path(path).read_bytes()))
    return CertificateStore(certificates, trusted=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Report which PE file bytes an Authenticode signature covers, and "
            "optionally run a mutation matrix."
        )
    )
    parser.add_argument("filename", type=pathlib.Path)
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of a text report.",
    )
    parser.add_argument(
        "--mutate",
        action="store_true",
        help="Run the default single-site mutation matrix.",
    )
    parser.add_argument(
        "--trust",
        type=pathlib.Path,
        help="PEM file with trusted root certificate(s) for chain verification.",
    )
    args = parser.parse_args(argv)

    store = _load_trust_store(args.trust)
    with args.filename.open("rb") as file_obj:
        from signify.authenticode.signed_file.pe import SignedPEFile

        pe = SignedPEFile(file_obj)
        report = PECoverageReport(
            pe,
            verify_chain=store is not None,
            trusted_certificate_store=store,
        )

    if args.json:
        payload: dict[str, Any] = {"report": report.to_dict()}
        if args.mutate:
            _, results = run_mutation_matrix(
                args.filename,
                trusted_certificate_store=store,
                verify_chain=store is not None,
            )
            payload["mutations"] = [result.to_dict() for result in results]
        print(json.dumps(payload, indent=2))
        return 0

    print(report.to_text())
    if args.mutate:
        print("")
        print("Mutation matrix:")
        _, results = run_mutation_matrix(
            args.filename,
            trusted_certificate_store=store,
            verify_chain=store is not None,
        )
        print(
            f"  {'mutation':32s} {'sha256':12s} {'auth':12s} "
            f"{'digest':6s} {'crypto':6s} {'verify':16s} classification"
        )
        for result in results:
            print(
                f"  {result.mutation.name:32s} "
                f"{result.sha256[:12]:12s} "
                f"{(result.authentihash_sha256 or '-')[:12]:12s} "
                f"{'MATCH' if result.signed_digest_matches else 'DIFF':6s} "
                f"{'OK' if result.signature_crypto_ok else 'FAIL':6s} "
                f"{result.verify_status:16s} {result.classification}"
            )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
