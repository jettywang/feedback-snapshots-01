# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
import json
import os

import pytest

from spdx_tools.spdx.importer import (
    ErrorCategory,
    ImportServiceError,
    ProcessingStage,
    import_file,
)
from spdx_tools.spdx.model import Document
from spdx_tools.spdx.parser.error import SPDXParsingError
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.writer.write_anything import write_file

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "importer")
INTERNAL_HOST_NAME = "tool-internal-host-7.example.net"


def fixture_path(name: str) -> str:
    return os.path.join(FIXTURE_DIR, name)


@pytest.mark.parametrize(
    "fixture_name, expected_category, expected_line",
    [
        ("syntax_error.spdx.json", ErrorCategory.SYNTAX_ERROR, 11),
        ("syntax_error.spdx.yaml", ErrorCategory.SYNTAX_ERROR, 11),
        ("syntax_error.spdx.xml", ErrorCategory.SYNTAX_ERROR, 11),
        ("syntax_error.spdx", ErrorCategory.SCHEMA_VIOLATION, None),
        ("schema_violation.spdx.json", ErrorCategory.SCHEMA_VIOLATION, None),
    ],
)
def test_parse_stage_failures_are_classified_by_format(fixture_name, expected_category, expected_line):
    result = import_file(fixture_path(fixture_name))

    assert result.success is False
    assert result.document is None
    assert len(result.records) >= 1
    record = result.records[0]
    assert record.stage == ProcessingStage.PARSE
    assert record.category == expected_category
    assert record.coordinates.document_location.endswith(fixture_name)
    assert record.coordinates.line_number == expected_line


def test_syntax_failure_does_not_produce_output(tmp_path):
    output_target = str(tmp_path / "must_not_be_created.json")

    result = import_file(fixture_path("syntax_error.spdx.json"), output_target=output_target)

    assert result.success is False
    assert result.records[0].category == ErrorCategory.SYNTAX_ERROR
    assert not os.path.exists(output_target)


def test_validation_failure_is_a_separate_stage_and_blocks_writing(tmp_path):
    output_target = str(tmp_path / "must_not_be_created.json")

    result = import_file(fixture_path("validation_error.spdx.json"), output_target=output_target)

    assert result.success is False
    assert result.document is None
    record = result.records[0]
    assert record.stage == ProcessingStage.VALIDATION
    assert record.category == ErrorCategory.VALIDATION_ERROR
    assert record.coordinates.element_type == "RELATIONSHIP"
    assert not os.path.exists(output_target)


def test_successful_import_returns_document_and_writes_output(tmp_path):
    output_target = str(tmp_path / "round_trip.spdx.json")

    result = import_file(fixture_path("valid.spdx.json"), output_target=output_target)

    assert result.success is True
    assert isinstance(result.document, Document)
    assert result.records == []
    assert os.path.exists(output_target)
    summary = result.external_summary()
    assert summary["success"] is True
    assert summary["errors"] == []
    assert summary["output_target"] == output_target


def test_write_stage_failure_is_classified_as_write_error(tmp_path):
    # a directory has no SPDX file extension, so format detection in the writer fails
    result = import_file(fixture_path("valid.spdx.json"), output_target=str(tmp_path))

    assert result.success is False
    record = result.records[0]
    assert record.stage == ProcessingStage.WRITE
    assert record.category == ErrorCategory.WRITE_ERROR
    assert record.coordinates.document_location == str(tmp_path)


def test_raise_mode_attaches_the_same_result():
    with pytest.raises(ImportServiceError) as exc_info:
        import_file(fixture_path("syntax_error.spdx.json"), raise_on_error=True)

    result = exc_info.value.result
    assert result.success is False
    assert result.records[0].category == ErrorCategory.SYNTAX_ERROR


@pytest.mark.parametrize(
    "fixture_name",
    [
        "syntax_error.spdx.json",
        "syntax_error.spdx.yaml",
        "syntax_error.spdx.xml",
        "syntax_error.spdx",
        "schema_violation.spdx.json",
        "validation_error.spdx.json",
    ],
)
def test_external_summary_contains_only_coordinates_and_categories(fixture_name):
    result = import_file(fixture_path(fixture_name))
    summary = result.external_summary()
    serialized = json.dumps(summary)

    assert INTERNAL_HOST_NAME not in serialized
    assert "diagnostic_message" not in serialized
    for error in summary["errors"]:
        assert set(error.keys()) == {"category", "stage", "coordinates"}
        assert set(error["coordinates"].keys()) == {
            "document_location",
            "spdx_id",
            "element_type",
            "line_number",
        }


@pytest.mark.parametrize(
    "fixture_name",
    [
        "syntax_error.spdx.json",
        "schema_violation.spdx.json",
        "validation_error.spdx.json",
    ],
)
def test_diagnostic_channel_keeps_raw_notes_and_source(fixture_name):
    result = import_file(fixture_path(fixture_name))
    diagnostics = result.diagnostic_records()

    assert diagnostics
    for record in diagnostics:
        assert record["source"].endswith(fixture_name)
        assert record["diagnostic_message"]
        assert record["category"]
        assert record["stage"]


def test_diagnostic_channel_can_point_to_the_originating_note():
    result = import_file(fixture_path("schema_violation.spdx.json"))
    diagnostics = result.diagnostic_records()

    assert any("not-a-valid-timestamp" in record["diagnostic_message"] for record in diagnostics)
    # the same detail must never reach the external channel
    assert "not-a-valid-timestamp" not in json.dumps(result.external_summary())


def test_missing_source_is_classified_as_unknown_error(tmp_path):
    missing_source = str(tmp_path / "does_not_exist.spdx.json")

    result = import_file(missing_source)

    assert result.success is False
    record = result.records[0]
    assert record.stage == ProcessingStage.PARSE
    assert record.category == ErrorCategory.UNKNOWN_ERROR
    assert record.coordinates.document_location == missing_source
    assert "diagnostic_message" not in result.external_summary()["errors"][0]


def test_legacy_parse_interface_keeps_exception_behavior():
    with pytest.raises(SPDXParsingError):
        parse_file(fixture_path("schema_violation.spdx.json"))


def test_legacy_write_interface_keeps_exception_behavior(tmp_path):
    document = parse_file(fixture_path("valid.spdx.json"))
    with pytest.raises(Exception):
        write_file(document, str(tmp_path), validate=False)
