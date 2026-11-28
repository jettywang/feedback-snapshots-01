# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
import json

from click.testing import CliRunner

from spdx_tools.spdx.clitools.exception_gate import main
from spdx_tools.spdx.governance.gate import register_approval
from spdx_tools.spdx.governance.ledger import approvals_to_json
from spdx_tools.spdx.governance.model import PolicyVersion
from spdx_tools.spdx.model import Relationship, RelationshipType
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.writer.write_anything import write_file
from tests.spdx.fixtures import creation_info_fixture, document_fixture, file_fixture, package_fixture


def _manifest(namespace="https://suppliers.example/acme"):
    return document_fixture(
        creation_info=creation_info_fixture(document_namespace=namespace),
        packages=[package_fixture(spdx_id="SPDXRef-AcmePackage")],
        files=[file_fixture(spdx_id="SPDXRef-File")],
        snippets=[],
        annotations=[],
        relationships=[Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, "SPDXRef-ghost")],
    )


def _write_inputs(tmp_path, with_approval: bool):
    document = _manifest()
    infile = tmp_path / "manifest.spdx.json"
    # write without validation so the deliberately dangling reference stays a finding
    write_file(document, str(infile), validate=False)
    ledger = tmp_path / "ledger.json"
    approvals = []
    if with_approval:
        approvals = [
            register_approval(
                "EXC-ACME-1",
                validate_full_spdx_document(document)[0],
                document,
                PolicyVersion("supplier-review", "7"),
            )
        ]
    ledger.write_text(approvals_to_json(approvals), encoding="utf-8")
    return infile, ledger


def test_cli_blocks_without_approval_and_still_prints_specification_message(tmp_path):
    infile, ledger = _write_inputs(tmp_path, with_approval=False)
    status_file = tmp_path / "status.json"

    result = CliRunner().invoke(
        main,
        ["-i", str(infile), "-l", str(ledger), "--policy", "supplier-review@7", "--status-file", str(status_file)],
    )

    assert result.exit_code == 1
    assert 'did not find the referenced spdx_id "SPDXRef-ghost"' in result.output
    status = json.loads(status_file.read_text(encoding="utf-8"))
    assert status["releasable"] is False
    expected = 'did not find the referenced spdx_id "SPDXRef-ghost" in the SPDX document'
    assert status["findings"][0]["specification_message"] == expected


def test_cli_allows_with_matching_approval(tmp_path):
    infile, ledger = _write_inputs(tmp_path, with_approval=True)

    result = CliRunner().invoke(
        main, ["-i", str(infile), "-l", str(ledger), "--policy", "supplier-review@7"]
    )

    assert result.exit_code == 0, result.output
    assert "Release allowed" in result.output
    # the underlying specification information stays visible
    assert 'did not find the referenced spdx_id "SPDXRef-ghost"' in result.output


def test_cli_blocks_for_other_policy_version(tmp_path):
    infile, ledger = _write_inputs(tmp_path, with_approval=True)

    result = CliRunner().invoke(
        main, ["-i", str(infile), "-l", str(ledger), "--policy", "supplier-review@8"]
    )

    assert result.exit_code == 1
    assert "Release blocked" in result.output
