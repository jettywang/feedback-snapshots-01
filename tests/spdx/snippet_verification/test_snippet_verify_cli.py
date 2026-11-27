# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path

from click.testing import CliRunner

from spdx_tools.spdx.clitools.snippet_verify import main, _assert_bump_preserves_ranges
from spdx_tools.spdx.parser.parse_anything import parse_file

DATA_DIR = Path(__file__).parent / "data"


def data_path(name: str) -> Path:
    return DATA_DIR / name


def test_cli_verifies_original_lf_source_with_exit_code_0():
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["-i", str(data_path("snippet-evidence-lf.spdx.json"))],
    )

    assert result.exit_code == 0
    assert "snippets still holding: 1" in result.output
    assert "SPDXRef-Snippet-Evidence" in result.output


def test_cli_verifies_crlf_source():
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["-i", str(data_path("snippet-evidence-crlf.spdx.json"))],
    )

    assert result.exit_code == 0
    assert "newline style: CRLF" in result.output
    assert "byte range 69:308" in result.output


def test_cli_flags_control_copy_with_exit_code_1():
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "-i",
            str(data_path("snippet-evidence-lf.spdx.json")),
            "--file",
            f"SPDXRef-SuspiciousSource={data_path('control_lf.py')}",
        ],
    )

    assert result.exit_code == 1
    assert "status: mismatch" in result.output
    assert "checksum SHA256: MISMATCH" in result.output


def test_cli_json_output_is_reviewable():
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["-i", str(data_path("snippet-evidence-lf.spdx.json")), "--json"],
    )

    payload = json.loads(result.output)
    assert result.exit_code == 0
    assert payload["verified_snippet_ids"] == ["SPDXRef-Snippet-Evidence"]
    source = payload["source_files"][0]
    assert source["sha256"] == "cce7675086ac3dc709cd94582c806b3ef2a094827661db7632e2d2b21ade4027"
    assert source["line_count"] == 10


def test_cli_via_spdx3_still_finds_the_original_snippet():
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["-i", str(data_path("snippet-evidence-lf.spdx.json")), "--via-spdx3"],
    )

    assert result.exit_code == 0
    assert "status: verified" in result.output


def test_bump_preserves_declared_ranges():
    document = parse_file(str(data_path("snippet-evidence-lf.spdx.json")))
    # Should not raise SystemExit.
    _assert_bump_preserves_ranges(document)


def test_cli_missing_document_returns_exit_code_2():
    runner = CliRunner()
    result = runner.invoke(main, ["-i", "no-such-document.spdx.json"])

    assert result.exit_code == 2


def test_cli_rejects_malformed_override():
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["-i", str(data_path("snippet-evidence-lf.spdx.json")), "--file", "no-equals-sign"],
    )

    assert result.exit_code == 2


def test_ranges_survive_spdx2_to_spdx3_upgrade_on_disk(tmp_path):
    from spdx_tools.spdx3.bump_from_spdx2.spdx_document import bump_spdx_document
    from spdx_tools.spdx3.writer.json_ld.json_ld_writer import write_payload

    document = parse_file(str(data_path("snippet-evidence-lf.spdx.json")))
    out_file = tmp_path / "upgraded.jsonld"
    write_payload(bump_spdx_document(document), str(out_file))

    payload = json.loads((tmp_path / "upgraded.jsonld.jsonld").read_text(encoding="utf-8"))
    elements = payload if isinstance(payload, list) else payload.get("@graph", [payload])
    snippet = next(
        element
        for element in elements
        if "SPDXRef-Snippet-Evidence" in str(element.get("@id", ""))
    )

    assert snippet["byteRange"]["begin"] == 68
    assert snippet["byteRange"]["end"] == 302
    assert snippet["lineRange"]["begin"] == 2
    assert snippet["lineRange"]["end"] == 6
