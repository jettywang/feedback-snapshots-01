# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
import json
from datetime import datetime
from importlib import resources

import pytest
from click.testing import CliRunner

from spdx_tools.spdx.annotation_export import extract_stable_id, load_annotation_audit_file
from spdx_tools.spdx.clitools.pyspdxtools import main
from spdx_tools.spdx.model import (
    Actor,
    ActorType,
    Annotation,
    AnnotationType,
    Document,
    Package,
    Relationship,
    RelationshipType,
)
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.writer.write_anything import write_file
from tests.spdx.fixtures import creation_info_fixture


@pytest.mark.parametrize(
    "options",
    [
        ("--infile", str(resources.files("tests.spdx.data").joinpath("SPDXJSONExample-v2.3.spdx.json"))),
        ("-i", str(resources.files("tests.spdx.data").joinpath("SPDXJSONExample-v2.3.spdx.json")), "--novalidation"),
        (
            "-i",
            str(resources.files("tests.spdx.data").joinpath("SPDXJSONExample-v2.3.spdx.json")),
            "--novalidation",
            "--version",
            "SPDX-2.3",
        ),
        ("-i", str(resources.files("tests.spdx.data").joinpath("SPDXJSONExample-v2.3.spdx.json")), "-o", "-"),
    ],
)
def test_cli_with_system_exit_code_0(options):
    runner = CliRunner()

    result = runner.invoke(main, options)

    assert result.exit_code == 0


@pytest.mark.parametrize(
    "options",
    [
        (
            "-i",
            str(
                resources.files("tests.spdx.data.invalid").joinpath(
                    "spdx-trivy-vmware_log-intelligence-fluentd-"
                    "sha256_086af034f561f343f633be9d9f9e95f65ae6c61b8ddb2c6755ef5bb25b40f53a.json"
                )
            ),
        ),
        ("-i", "non_existent_file.spdx"),
    ],
)
def test_cli_with_system_exit_code_1(options):
    runner = CliRunner()

    result = runner.invoke(main, options)

    assert result.exit_code == 1


@pytest.mark.parametrize(
    "options",
    [
        (),
        ("-i", str(resources.files("tests.spdx.data").joinpath("SPDXJSONExample-v2.3.spdx.json")), "--version"),
        ("-i", str(resources.files("tests.spdx.data").joinpath("SPDXJSONExample-v2.3.spdx.json")), "-o"),
    ],
)
def test_cli_with_system_exit_code_2(options):
    runner = CliRunner()

    result = runner.invoke(main, options)

    assert result.exit_code == 2


def _write_export_fixture(file_name: str) -> None:
    package = Package("SPDXRef-Package", "affected-package", "https://example.com/package.tar.gz")
    document = Document(
        creation_info_fixture(),
        packages=[package],
        relationships=[Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-Package")],
        annotations=[
            Annotation(
                "SPDXRef-Package",
                AnnotationType.OTHER,
                Actor(ActorType.PERSON, "Public Reviewer", "public@example.com"),
                datetime(2024, 1, 1),
                "Public review note.",
            ),
            Annotation(
                "SPDXRef-Package",
                AnnotationType.REVIEW,
                Actor(ActorType.PERSON, "Incident Team", "incident@internal.example"),
                datetime(2024, 2, 3),
                "Internal investigation: db-17 leaked credentials",
            ),
        ],
    )
    write_file(document, file_name, validate=True)


@pytest.mark.parametrize("file_ending", ["json", "spdx"])
def test_cli_annotation_export_round_trip(tmp_path, file_ending: str):
    input_file = tmp_path / "input.spdx.json"
    _write_export_fixture(str(input_file))
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "restricted": {"annotator_names": ["Incident Team"]},
                "allowed_fields": ["annotation_type", "annotator", "annotation_date"],
            }
        )
    )
    shared_file = tmp_path / f"shared.{file_ending}"
    audit_file = tmp_path / "annotations.audit.json"

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "-i",
            str(input_file),
            "-o",
            str(shared_file),
            "--annotation-policy",
            str(policy_file),
            "--annotation-audit-out",
            str(audit_file),
        ],
    )

    assert result.exit_code == 0, result.output
    reparsed = parse_file(str(shared_file))
    assert validate_full_spdx_document(reparsed) == []
    assert reparsed.annotations[0].annotation_comment == "Public review note."
    stable_id = extract_stable_id(reparsed.annotations[1].annotation_comment)
    assert stable_id is not None
    assert "Internal investigation" not in reparsed.annotations[1].annotation_comment
    assert [entry.stable_id for entry in load_annotation_audit_file(str(audit_file))] == [stable_id]
    audit_text = audit_file.read_text()
    assert "Internal investigation" not in audit_text
    assert "db-17" not in audit_text


@pytest.mark.parametrize(
    "extra_options",
    [
        ("--annotation-audit-out", "audit.json"),
        ("--annotation-policy", "policy.json", "--graph"),
        ("--annotation-redact-all", "-o", "-"),
    ],
)
def test_cli_annotation_export_option_errors(tmp_path, extra_options):
    input_file = tmp_path / "input.spdx.json"
    _write_export_fixture(str(input_file))

    runner = CliRunner()
    result = runner.invoke(main, ["-i", str(input_file), *extra_options])

    assert result.exit_code == 1


def test_cli_redact_all_with_field_only_policy(tmp_path):
    input_file = tmp_path / "input.spdx.json"
    _write_export_fixture(str(input_file))
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({"allowed_fields": ["annotation_type"]}))
    shared_file = tmp_path / "shared.spdx.json"

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "-i",
            str(input_file),
            "-o",
            str(shared_file),
            "--annotation-policy",
            str(policy_file),
            "--annotation-redact-all",
        ],
    )

    assert result.exit_code == 0, result.output
    reparsed = parse_file(str(shared_file))
    assert all(extract_stable_id(annotation.annotation_comment) is not None for annotation in reparsed.annotations)
