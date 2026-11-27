# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
import copy
import hashlib
import json
from datetime import datetime
from pathlib import Path

import pytest

from spdx_tools.spdx.model import (
    Actor,
    ActorType,
    Checksum,
    ChecksumAlgorithm,
    CreationInfo,
    Document,
    Snippet,
)
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.snippet_verification import (
    RangeStatus,
    SnippetStatus,
    verify_document_snippets,
    verify_snippet,
)
from spdx_tools.spdx.snippet_verification.report import (
    overall_exit_code,
    render_json_report,
    render_text_report,
)
from spdx_tools.spdx.snippet_verification.verifier import _split_lines

DATA_DIR = Path(__file__).parent / "data"


def data_path(name: str) -> Path:
    return DATA_DIR / name


def data_dir() -> Path:
    return DATA_DIR


@pytest.fixture(scope="module")
def lf_document():
    return parse_file(str(data_path("snippet-evidence-lf.spdx.json")))


@pytest.fixture(scope="module")
def crlf_document():
    return parse_file(str(data_path("snippet-evidence-crlf.spdx.json")))


def test_manifest_matches_files_on_disk():
    manifest = json.loads(data_path("manifest.json").read_text(encoding="utf-8"))
    for name, entry in manifest.items():
        raw = data_path(name).read_bytes()

        assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
        assert len(raw) == entry["bytes"]


def test_lf_original_source_verifies(lf_document):
    report = verify_document_snippets(lf_document, base_dir=data_dir())
    snippet = report.snippets[0]

    assert snippet.status == SnippetStatus.VERIFIED
    assert snippet.holds is True
    assert snippet.byte_range.status == RangeStatus.MATCH
    assert snippet.line_range.status == RangeStatus.MATCH
    assert snippet.byte_range.declared_range == (68, 302)
    assert snippet.line_range.declared_range == (2, 6)

    source = report.source_files[0]
    assert source.newline_style == "LF"
    assert source.line_count == 10
    assert all(result.matches for result in source.checksum_results)
    assert overall_exit_code(report) == 0


def test_crlf_original_source_verifies_with_its_own_byte_range(crlf_document):
    report = verify_document_snippets(crlf_document, base_dir=data_dir())
    snippet = report.snippets[0]

    assert snippet.status == SnippetStatus.VERIFIED
    assert snippet.byte_range.declared_range == (69, 308)
    assert snippet.line_range.declared_range == (2, 6)

    source = report.source_files[0]
    assert source.newline_style == "CRLF"
    assert source.line_count == 10
    assert source.file_size_bytes == 407
    assert all(result.matches for result in source.checksum_results)


def test_byte_and_line_ranges_agree_on_extracted_content(lf_document):
    report = verify_document_snippets(lf_document, base_dir=data_dir())
    raw = data_path("suspicious_lf.py").read_bytes()
    snippet = report.snippets[0]

    byte_slice = raw[68 - 1 : 302]
    line_slice = b"".join(_split_lines(raw)[1:6])
    assert byte_slice == line_slice
    assert snippet.extracted_sha256 == hashlib.sha256(byte_slice).hexdigest()


def test_ranges_are_unit_independent_for_multibyte_text():
    line = "零一二三四五六七八九\n".encode("utf-8")
    raw = line * 3
    snippet = Snippet(
        spdx_id="SPDXRef-S",
        file_spdx_id="SPDXRef-F",
        byte_range=(32, 62),  # second logical line: ten 3-byte CJK chars + LF = 31 bytes
        line_range=(2, 2),
    )
    result = verify_snippet(snippet, raw, None)

    assert result.byte_range.status == RangeStatus.MATCH
    assert result.line_range.status == RangeStatus.MATCH
    assert result.status == SnippetStatus.VERIFIED
    assert raw[31:62] == line
    assert b"".join(_split_lines(raw)[1:2]) == line


def test_control_copy_is_flagged_even_though_ranges_still_fit(lf_document):
    report = verify_document_snippets(
        lf_document,
        base_dir=data_dir(),
        path_overrides={"SPDXRef-SuspiciousSource": data_path("control_lf.py")},
    )
    snippet = report.snippets[0]
    source = report.source_files[0]

    assert snippet.byte_range.status == RangeStatus.MATCH
    assert snippet.line_range.status == RangeStatus.MATCH
    assert snippet.status == SnippetStatus.MISMATCH
    assert snippet.holds is False
    assert any(not result.matches for result in source.checksum_results)
    assert overall_exit_code(report) == 1


def test_out_of_bounds_byte_range_is_reported_in_byte_unit():
    raw = b"a\nb\nc\n"
    snippet = Snippet(
        spdx_id="SPDXRef-S",
        file_spdx_id="SPDXRef-F",
        byte_range=(1, 99),
        line_range=(1, 2),
    )
    result = verify_snippet(snippet, raw, None)

    assert result.byte_range.status == RangeStatus.OUT_OF_BOUNDS
    assert result.line_range.status == RangeStatus.MATCH
    assert result.status == SnippetStatus.OUT_OF_BOUNDS


def test_out_of_bounds_line_range_is_reported_in_line_unit():
    raw = b"a\nb\n"
    snippet = Snippet(
        spdx_id="SPDXRef-S",
        file_spdx_id="SPDXRef-F",
        byte_range=(1, 2),
        line_range=(1, 9),
    )
    result = verify_snippet(snippet, raw, None)

    assert result.line_range.status == RangeStatus.OUT_OF_BOUNDS
    assert result.byte_range.status == RangeStatus.MATCH
    assert result.status == SnippetStatus.OUT_OF_BOUNDS


def test_missing_source_file_is_reported(lf_document):
    report = verify_document_snippets(
        lf_document,
        base_dir=data_dir(),
        path_overrides={"SPDXRef-SuspiciousSource": data_path("does_not_exist.py")},
    )
    snippet = report.snippets[0]

    assert snippet.status == SnippetStatus.SOURCE_MISSING
    assert report.source_files[0].exists is False


def test_unresolved_snippet_file_id():
    snippet = Snippet(
        spdx_id="SPDXRef-Orphan",
        file_spdx_id="SPDXRef-Missing",
        byte_range=(1, 4),
    )
    document = Document(
        CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="d",
            document_namespace="https://example.com/ns",
            creators=[Actor(ActorType.TOOL, "t")],
            created=datetime(2026, 11, 28),
        ),
        snippets=[snippet],
    )
    report = verify_document_snippets(document)

    assert report.snippets[0].status == SnippetStatus.UNRESOLVED
    assert overall_exit_code(report) == 1


def test_declared_checksum_mismatch_is_flagged(lf_document):
    document = copy.deepcopy(lf_document)
    document.files[0].checksums = [
        Checksum(ChecksumAlgorithm.SHA256, "0" * 64),
    ]
    report = verify_document_snippets(document, base_dir=data_dir())

    assert report.source_files[0].checksum_results[0].matches is False
    assert overall_exit_code(report) == 1


def test_reports_are_rendered_and_machine_readable(lf_document):
    report = verify_document_snippets(lf_document, base_dir=data_dir())
    text = render_text_report(report)
    payload = json.loads(render_json_report(report))

    assert "SPDXRef-Snippet-Evidence" in text
    assert "byte range 68:302" in text
    assert payload["verified_snippet_ids"] == ["SPDXRef-Snippet-Evidence"]
    assert payload["failed_snippet_ids"] == []
    assert payload["snippets"][0]["byte_range"]["status"] == "match"


def test_crlf_and_lf_line_splitting_agrees_on_line_count():
    lf = data_path("suspicious_lf.py").read_bytes()
    crlf = data_path("suspicious_crlf.py").read_bytes()

    assert len(_split_lines(lf)) == len(_split_lines(crlf)) == 10
    assert [line.replace(b"\r\n", b"\n") for line in _split_lines(crlf)] == _split_lines(lf)


def test_cr_only_and_mixed_newlines_are_split_into_logical_lines():
    from spdx_tools.spdx.snippet_verification.verifier import _detect_newline_style

    cr_only = b"a\rb\rc\r"
    assert _detect_newline_style(cr_only) == "CR"
    assert _split_lines(cr_only) == [b"a\r", b"b\r", b"c\r"]

    mixed = b"a\r\nb\nc\rd"
    assert _detect_newline_style(mixed) == "mixed (CRLF and CR and LF)"
    assert len(_split_lines(mixed)) == 4

    no_newline = b"single line"
    assert _detect_newline_style(no_newline) == "none"
    assert _split_lines(no_newline) == [b"single line"]


def test_line_range_works_with_cr_only_endings():
    line = "第二行\r".encode("utf-8")
    raw = "第一行\r".encode("utf-8") + line + "第三行\r".encode("utf-8")
    line_begin = len("第一行\r".encode("utf-8")) + 1
    snippet = Snippet(
        spdx_id="SPDXRef-S",
        file_spdx_id="SPDXRef-F",
        byte_range=(line_begin, line_begin + len(line) - 1),
        line_range=(2, 2),
    )
    result = verify_snippet(snippet, raw, None)

    assert result.line_range.status == RangeStatus.MATCH
    assert result.byte_range.status == RangeStatus.MATCH
    assert result.status == SnippetStatus.VERIFIED
    assert b"".join(_split_lines(raw)[1:2]) == line
