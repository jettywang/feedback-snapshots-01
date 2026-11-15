"""Boundary regressions for the PE Certificate Table (the array of
``WIN_CERTIFICATE`` structures).

A signed PE does not stop at its first signature: the Certificate Table may hold
several back-to-back ``WIN_CERTIFICATE`` entries, each 8-byte aligned. A repository
ingestion service walks *all* of them. These tests prove that one damaged entry can
never enlarge its own DER view so it swallows a neighbouring certificate or ordinary
file content, and that the Authenticode digest excludes exactly the declared,
well-formed table rather than whatever a malformed entry tries to claim.

Every synthetic PE below is built from an explicitly documented byte layout, so the
start/end offset of each entry is asserted instead of being inferred.
"""

from __future__ import annotations

import hashlib
import importlib
import inspect
import io
import struct
import textwrap
import types

import pytest

from signify.authenticode.signed_data import AuthenticodeSignature
from signify.authenticode.signed_file.pe import SignedPEFile
from signify.exceptions import SignedPEParseError
from signify.fingerprinter import Range
from tests._utils import open_test_data

pe_module = importlib.import_module("signify.authenticode.signed_file.pe")

# ---------------------------------------------------------------------------
# Fixed geometry of the synthetic PE files.
#
#   0x000 .. 0x080  DOS header (MZ + e_lfanew at 0x3C pointing at 0x80)
#   0x080 .. 0x084  "PE\0\0"
#   0x084 .. 0x098  COFF file header (20 bytes), SizeOfOptionalHeader = 224
#   0x098 .. 0x178  PE32 optional header (224 bytes):
#                     magic 0x10B                 @ +0
#                     NumberOfRvaAndSizes = 16    @ +92
#                     cert data dir (addr,size)   @ +128
#   0x178 .. 0x200  ordinary file content ("gap"), part of the Authenticode hash
#   0x200 .......... Certificate Table (address stored in the data directory)
#   after table .... trailing ordinary file content, also part of the hash
#
# A WIN_CERTIFICATE entry is an 8-byte header
# ``dwLength (uint32) | wRevision (uint16) | wCertificateType (uint16)`` followed by
# ``dwLength - 8`` bytes of certificate data. Entries are padded so each starts on an
# 8-byte boundary; the padding is zero bytes and is part of the table, not of the DER.
# ---------------------------------------------------------------------------
PE_OFFSET = 0x80
OPTIONAL_HEADER_SIZE = 224
CERT_TABLE_OFFSET = 0x200
HEADERS_END = PE_OFFSET + 4 + 20 + OPTIONAL_HEADER_SIZE  # 0x178

WIN_CERT_REVISION = 0x200
# wCertificateType values used below: 2 = WIN_CERT_TYPE_PKCS_SIGNED_DATA, while 1 and
# 3 are non-PKCS types that the signature enumeration must skip but still bound.

GAP_FILL = b"G"
TRAILING_CONTENT = b"TAIL-SENTINEL-ORDINARY-CONTENT"


def win_certificate(
    declared_length: int, revision: int, cert_type: int, payload: bytes
) -> bytes:
    """Build a single WIN_CERTIFICATE with a caller-controlled ``dwLength``.

    The length is deliberately not derived from ``payload`` so malformed headers with
    a too-small ``dwLength`` can be constructed.
    """
    return struct.pack("<IHH", declared_length, revision, cert_type) + payload


def align8(blob: bytes, fill: bytes = b"\x00") -> bytes:
    return blob + fill * ((8 - len(blob) % 8) % 8)


def build_pe(
    cert_table: bytes,
    *,
    table_size: int | None = None,
    trailing: bytes = TRAILING_CONTENT,
) -> bytes:
    """Assemble a minimal PE32 whose Certificate Table is ``cert_table``."""
    if table_size is None:
        table_size = len(cert_table)

    dos_header = bytearray(PE_OFFSET)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, PE_OFFSET)

    # Machine, NumberOfSections, TimeDateStamp, PtrToSymbolTable,
    # NumberOfSymbols, SizeOfOptionalHeader, Characteristics
    coff_header = struct.pack("<HHIIIHH", 0x14C, 0, 0, 0, 0, OPTIONAL_HEADER_SIZE, 0)

    optional_header = bytearray(OPTIONAL_HEADER_SIZE)
    struct.pack_into("<H", optional_header, 0, 0x10B)  # PE32 magic
    struct.pack_into("<I", optional_header, 92, 16)  # NumberOfRvaAndSizes
    # Certificate Table data directory: (file offset, size)
    struct.pack_into("<II", optional_header, 128, CERT_TABLE_OFFSET, table_size)

    image = bytearray(dos_header) + b"PE\0\0" + coff_header + optional_header
    assert len(image) == HEADERS_END

    image += GAP_FILL * (CERT_TABLE_OFFSET - len(image))
    assert len(image) == CERT_TABLE_OFFSET
    image += cert_table
    image += trailing
    return bytes(image)


def parse_entries(blob: bytes) -> list[dict]:
    return list(SignedPEFile(io.BytesIO(blob))._parse_cert_table())


def real_pkcs7_der() -> bytes:
    """The genuine PKCS#7 SignedData blob embedded in pciide.sys."""
    with open_test_data("pciide.sys") as f:
        pe_file = SignedPEFile(f)
        return next(pe_file._parse_cert_table())["certificate"]


def expected_layout(entries: list[bytes]) -> list[tuple[int, int, int]]:
    """Return the independently computed (header_start, payload_start, entry_end)
    offsets for the given raw entry blobs, without consulting the parser."""
    positions = []
    position = CERT_TABLE_OFFSET
    for raw in entries:
        declared_length = struct.unpack("<I", raw[:4])[0]
        positions.append((position, position + 8, position + declared_length))
        position += len(raw)  # raw blobs already include the 8-byte padding
    return positions


# ---------------------------------------------------------------------------
# Well-formed, multi-entry tables
# ---------------------------------------------------------------------------


def test_multi_entry_layout_is_exact_and_non_overlapping():
    # Layout (all dwLength values deliberately off the 8-byte grid):
    #   entry 0  hdr 0x200  type 2  payload 0x208..0x211 (9)   padded -> next 0x218
    #   entry 1  hdr 0x218  type 3  payload 0x220..0x22b (11)  padded -> next 0x230
    #   entry 2  hdr 0x230  type 1  payload 0x238..0x248 (16)  aligned   -> end  0x248
    raw = [
        align8(win_certificate(8 + 9, WIN_CERT_REVISION, 2, b"A" * 9)),
        align8(win_certificate(8 + 11, WIN_CERT_REVISION, 3, b"B" * 11)),
        align8(win_certificate(8 + 16, WIN_CERT_REVISION, 1, b"C" * 16)),
    ]
    blob = build_pe(b"".join(raw))

    entries = parse_entries(blob)
    assert [e["type"] for e in entries] == [2, 3, 1]
    assert [len(e["certificate"]) for e in entries] == [9, 11, 16]

    expected = expected_layout(raw)
    assert expected == [
        (0x200, 0x208, 0x211),
        (0x218, 0x220, 0x22B),
        (0x230, 0x238, 0x248),
    ]

    # The DER slice handed back for every entry is exactly its own payload, read from
    # the independently computed span: no padding byte and no neighbour leaks in.
    for entry, (_header_start, payload_start, entry_end) in zip(entries, expected):
        assert entry["revision"] == WIN_CERT_REVISION
        assert blob[payload_start:entry_end] == entry["certificate"]
        assert entry["certificate"] not in (b"", b"\x00")

    # Entries are contiguous, non-overlapping and together cover the whole table.
    spans = [(s, e) for s, _, e in expected]
    assert all(spans[i][1] <= spans[i + 1][0] for i in range(len(spans) - 1))
    assert spans[0][0] == CERT_TABLE_OFFSET
    table_end = CERT_TABLE_OFFSET + sum(len(r) for r in raw)
    assert spans[-1][1] == table_end
    assert blob[table_end : table_end + len(TRAILING_CONTENT)] == TRAILING_CONTENT


def test_non_pkcs_type_is_skipped_but_still_bounded_during_enumeration():
    # Two real PKCS#7 envelopes with a non-PKCS (type 3) entry sandwiched between them.
    der = real_pkcs7_der()
    raw = [
        align8(win_certificate(8 + len(der), WIN_CERT_REVISION, 2, der)),
        align8(win_certificate(8 + 13, WIN_CERT_REVISION, 3, b"NON-PKCS-DATA")),
        align8(win_certificate(8 + len(der), WIN_CERT_REVISION, 2, der)),
    ]
    blob = build_pe(b"".join(raw))

    # The low-level table parser still enumerates all three bounded entries.
    entries = parse_entries(blob)
    assert [e["type"] for e in entries] == [2, 3, 2]
    expected = expected_layout(raw)
    for entry, (_, payload_start, entry_end) in zip(entries, expected):
        assert blob[payload_start:entry_end] == entry["certificate"]

    # The signature enumeration goes through the PE entry point and skips the non-PKCS
    # entry while returning both real, distinct signatures.
    pe_file = SignedPEFile(io.BytesIO(blob))
    signatures = list(
        pe_file.iter_embedded_signatures(
            include_nested=False, ignore_parse_errors=False
        )
    )
    assert len(signatures) == 2
    assert all(isinstance(s, AuthenticodeSignature) for s in signatures)

    # A table that contains no PKCS entry at all is reported as unsigned rather than
    # misread as a signature.
    no_pkcs = build_pe(
        align8(win_certificate(8 + 13, WIN_CERT_REVISION, 3, b"NON-PKCS-DATA"))
    )
    pe_no_pkcs = SignedPEFile(io.BytesIO(no_pkcs))
    assert list(pe_no_pkcs.iter_embedded_signatures()) == []
    with pytest.raises(SignedPEParseError):
        list(pe_no_pkcs.iter_embedded_signatures(ignore_parse_errors=False))


def test_existing_multi_signature_sample_stays_complete_and_non_overlapping():
    # sigcheck.exe carries two valid SignedData structures; walking the whole table
    # must still return both, each bounded inside the single declared entry.
    with open_test_data("sigcheck.exe") as f:
        data = f.read()
    pe_file = SignedPEFile(io.BytesIO(data))

    cert_range = pe_file.get_authenticode_omit_sections()["certtable"]
    table_start, table_end = cert_range.start, sum(cert_range)

    entries = list(pe_file._parse_cert_table())
    assert entries, "the existing signed sample must still parse"
    cursor = table_start
    for entry in entries:
        header = data[cursor : cursor + 8]
        declared_length = struct.unpack("<I", header[:4])[0]
        # The parser's DER view is exactly the payload, never crossing the boundary.
        assert len(entry["certificate"]) == declared_length - 8
        assert data[cursor + 8 : cursor + declared_length] == entry["certificate"]
        cursor += declared_length + (8 - declared_length % 8) % 8
    assert cursor == table_end

    assert len(list(pe_file.embedded_signatures)) == 2


# ---------------------------------------------------------------------------
# Malformed entries: each must raise rather than absorb neighbouring bytes.
# ---------------------------------------------------------------------------


def test_dwlength_smaller_than_header_cannot_swallow_neighbour():
    # Two good, non-PKCS entries, then a header claiming dwLength=4 (< 8), then another
    # good entry whose payload marks it as the neighbour that must stay untouched.
    # Non-PKCS types are used for the valid entries so signature enumeration skips
    # them cleanly, isolating the boundary failure from DER decoding.
    good = b"".join(
        [
            align8(win_certificate(8 + 9, WIN_CERT_REVISION, 3, b"A" * 9)),
            align8(win_certificate(8 + 11, WIN_CERT_REVISION, 3, b"B" * 11)),
        ]
    )
    bad_entry = win_certificate(4, WIN_CERT_REVISION, 3, b"X" * 8)
    neighbour = align8(win_certificate(8 + 5, WIN_CERT_REVISION, 3, b"NEIGH"))
    blob = build_pe(good + bad_entry + neighbour)

    with pytest.raises(SignedPEParseError):
        parse_entries(blob)

    # The neighbour and the trailing file content remain intact on disk; nothing was
    # allowed to reinterpret them as part of the malformed entry's DER.
    assert blob.find(b"NEIGH") != -1
    assert blob.endswith(TRAILING_CONTENT)

    # Strict enumeration through the public PE entry point propagates the failure.
    with pytest.raises(SignedPEParseError):
        list(
            SignedPEFile(io.BytesIO(blob)).iter_embedded_signatures(
                ignore_parse_errors=False
            )
        )
    # Lenient enumeration never yields a signature here, and certainly never the
    # malformed entry, because no bounded PKCS#7 entry survives the damaged table.
    assert (
        list(
            SignedPEFile(io.BytesIO(blob)).iter_embedded_signatures(
                ignore_parse_errors=True
            )
        )
        == []
    )


def test_truncated_last_entry_is_rejected():
    # Header claims 32 payload bytes but only 5 are present before the table ends.
    good = align8(win_certificate(8 + 9, WIN_CERT_REVISION, 2, b"A" * 9))
    truncated = win_certificate(8 + 32, WIN_CERT_REVISION, 2, b"Z" * 5)
    blob = build_pe(good + truncated)

    with pytest.raises(SignedPEParseError):
        parse_entries(blob)


def test_trailing_partial_header_is_rejected():
    # Fewer than 8 bytes remain where another WIN_CERTIFICATE header is expected.
    good = align8(win_certificate(8 + 9, WIN_CERT_REVISION, 2, b"A" * 9))
    partial_header = struct.pack("<I", 16)  # only 4 of the 8 header bytes
    blob = build_pe(good + partial_header)

    with pytest.raises(SignedPEParseError):
        parse_entries(blob)


def test_dwlength_running_past_table_end_is_rejected():
    # A well-aligned header whose dwLength reaches beyond the declared table end into
    # the trailing ordinary content must be rejected, not read up to end-of-file.
    entry = win_certificate(8 + 9, WIN_CERT_REVISION, 2, b"A" * 9)
    # Keep the table size tight while the single entry over-claims its length.
    oversized = win_certificate(8 + 9 + 64, WIN_CERT_REVISION, 2, b"A" * 9)
    blob = build_pe(oversized, table_size=len(align8(entry)))

    with pytest.raises(SignedPEParseError):
        parse_entries(blob)
    assert blob.endswith(TRAILING_CONTENT)


# ---------------------------------------------------------------------------
# Authenticode omission: the whole *declared, well-formed* table is excluded.
# ---------------------------------------------------------------------------


def _authentihash(blob: bytes) -> bytes:
    return SignedPEFile(io.BytesIO(blob)).get_fingerprint(hashlib.sha256)


def _hashed_ranges(blob: bytes, omit: dict[str, Range]) -> list[Range]:
    ranges = []
    range_start = 0
    for start_length in sorted(omit.values()):
        ranges.append(Range(range_start, start_length.start))
        range_start = sum(start_length)
    ranges.append(Range(range_start, len(blob)))
    return ranges


def _is_fully_hashed(hashed: list[Range], start: int, end: int) -> bool:
    """True when every byte of [start, end) is covered by one of the hashed ranges."""
    cursor = start
    for range_start, range_end in sorted(hashed):
        if range_end <= cursor:
            continue
        if range_start > cursor:
            return False
        cursor = max(cursor, range_end)
        if cursor >= end:
            return True
    return cursor >= end


def test_omit_section_covers_exact_declared_table():
    raw = [
        align8(win_certificate(8 + 9, WIN_CERT_REVISION, 2, b"A" * 9)),
        align8(win_certificate(8 + 11, WIN_CERT_REVISION, 3, b"B" * 11)),
        align8(win_certificate(8 + 16, WIN_CERT_REVISION, 1, b"C" * 16)),
    ]
    table = b"".join(raw)
    blob = build_pe(table)
    pe_file = SignedPEFile(io.BytesIO(blob))

    cert_range = pe_file.get_authenticode_omit_sections()["certtable"]
    assert (cert_range.start, cert_range.length) == (
        CERT_TABLE_OFFSET,
        len(table),
    )
    # The excluded region ends exactly where ordinary trailing content begins.
    assert cert_range.start + cert_range.length == (CERT_TABLE_OFFSET + len(table))

    # Ordinary file content (the gap between the PE headers and the table, and the
    # trailing bytes) remains fully hashed. The checksum and data-directory entries
    # legitimately split the pre-table region, so check the ordinary gap directly.
    hashed = _hashed_ranges(blob, pe_file.get_authenticode_omit_sections())
    assert _is_fully_hashed(hashed, HEADERS_END, CERT_TABLE_OFFSET)
    assert _is_fully_hashed(hashed, CERT_TABLE_OFFSET + len(table), len(blob))
    # No hashed range may touch a single byte of the declared table.
    assert all(
        range_end <= CERT_TABLE_OFFSET or range_start >= CERT_TABLE_OFFSET + len(table)
        for range_start, range_end in hashed
    )


def test_malformed_table_cannot_expand_the_exclusion_to_hide_content():
    # The over-claiming entry must not enlarge the omitted interval: the omission is
    # governed solely by the data-directory size, not by an entry's dwLength.
    good = align8(win_certificate(8 + 9, WIN_CERT_REVISION, 2, b"A" * 9))
    oversized = win_certificate(8 + 9 + 64, WIN_CERT_REVISION, 2, b"A" * 9)
    declared_size = len(good) + 8  # table ends right after the bad header start
    blob = build_pe(good + oversized, table_size=declared_size)

    pe_file = SignedPEFile(io.BytesIO(blob))
    cert_range = pe_file.get_authenticode_omit_sections()["certtable"]
    assert cert_range.start == CERT_TABLE_OFFSET
    assert cert_range.length == declared_size  # not the inflated dwLength

    # The trailing ordinary content stays inside the hashed region, so it cannot be
    # hidden from the Authenticode digest by an inflated certificate length.
    trailing_start = CERT_TABLE_OFFSET + declared_size
    hashed = _hashed_ranges(blob, pe_file.get_authenticode_omit_sections())
    assert _is_fully_hashed(hashed, trailing_start, trailing_start + 1)
    assert all(
        range_start >= trailing_start or range_end <= CERT_TABLE_OFFSET
        for range_start, range_end in hashed
    )


def test_ordinary_content_changes_are_observed_but_table_changes_are_not():
    raw = [
        align8(win_certificate(8 + 9, WIN_CERT_REVISION, 2, b"A" * 9)),
        align8(win_certificate(8 + 11, WIN_CERT_REVISION, 3, b"B" * 11)),
    ]
    table = b"".join(raw)
    baseline = build_pe(table)

    # A byte inside the declared table is excluded from the digest.
    inside = bytearray(baseline)
    inside[CERT_TABLE_OFFSET + 10] ^= 0xFF
    assert _authentihash(bytes(inside)) == _authentihash(baseline)

    # A byte of ordinary content after the table is always observed.
    outside = bytearray(baseline)
    outside[-1] ^= 0xFF
    assert _authentihash(bytes(outside)) != _authentihash(baseline)


# ---------------------------------------------------------------------------
# Mutated-parser variants: prove the tests catch a removed length/alignment guard.
# ---------------------------------------------------------------------------


def _parser_variant(replacements: list[tuple[str, str]]):
    """Recompile ``_parse_cert_table`` with the listed source substitutions applied,
    returning an unbound function that behaves like the method minus a specific guard.
    """
    source = inspect.getsource(SignedPEFile._parse_cert_table)
    for old, new in replacements:
        assert old in source, f"guard text not found: {old!r}"
        source = source.replace(old, new)
    globals_ns = dict(pe_module.__dict__)
    # Intentional in-test code mutation to emulate a removed parser guard.
    exec(  # noqa: S102
        compile(textwrap.dedent(source), "<certtable-variant>", "exec"), globals_ns
    )
    return globals_ns["_parse_cert_table"]


def test_variant_without_length_guard_is_detected():
    # Removing the dwLength/end-bound check lets the bad entry read the neighbour and
    # the trailing file content into its own certificate bytes.
    good = b"".join(
        [
            align8(win_certificate(8 + 9, WIN_CERT_REVISION, 2, b"A" * 9)),
            align8(win_certificate(8 + 11, WIN_CERT_REVISION, 3, b"B" * 11)),
        ]
    )
    bad_entry = win_certificate(4, WIN_CERT_REVISION, 2, b"X" * 8)
    neighbour = align8(win_certificate(8 + 5, WIN_CERT_REVISION, 2, b"NEIGH"))
    blob = build_pe(good + bad_entry + neighbour)

    loose = _parser_variant(
        [
            (
                "if length <= 8 or position + length > certtable_end:",
                "if False:",
            )
        ]
    )
    bound = types.MethodType(loose, SignedPEFile(io.BytesIO(blob)))
    entries = list(bound())

    # The damaged entry now over-reads: neighbour marker and ordinary content leak
    # into a certificate slot, which the strict parser never permits.
    joined = b"".join(e["certificate"] for e in entries)
    assert b"NEIGH" in joined or TRAILING_CONTENT in joined


def test_variant_without_alignment_advance_is_detected():
    # With 8-byte padding removed, iteration resumes inside the padding and loses the
    # next header; the strict parser instead lands exactly on the next entry.
    raw = [
        align8(win_certificate(8 + 9, WIN_CERT_REVISION, 2, b"A" * 9)),
        align8(win_certificate(8 + 11, WIN_CERT_REVISION, 3, b"B" * 11)),
        align8(win_certificate(8 + 16, WIN_CERT_REVISION, 1, b"C" * 16)),
    ]
    blob = build_pe(b"".join(raw))

    # Baseline: strict parsing finds all three entries on their aligned offsets.
    assert [e["type"] for e in parse_entries(blob)] == [2, 3, 1]

    no_align = _parser_variant(
        [
            (
                "position += length + (8 - length % 8) % 8",
                "position += length",
            )
        ]
    )
    bound = types.MethodType(no_align, SignedPEFile(io.BytesIO(blob)))
    with pytest.raises(SignedPEParseError):
        list(bound())
