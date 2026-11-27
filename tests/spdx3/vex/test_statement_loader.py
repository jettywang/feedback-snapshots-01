# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from datetime import datetime

from spdx_tools.spdx3.payload import Payload
from spdx_tools.spdx3.vex import (
    PendingReason,
    VerificationStatus,
    build_migration_manifest,
    load_statements_from_serialized,
    parse_statement_records,
    verify_payload,
)
from tests.spdx3.vex.conftest import VULN_ID, make_package, package_id

SERIALIZED_STATEMENTS = """
- spdx_id: https://internal-archive.example/spdx#SPDXRef-VEX-1
  vulnerability_id: https://internal-archive.example/spdx#SPDXRef-Vulnerability-CVE-2026-0001
  assessed_element_id: https://internal-archive.example/spdx#SPDXRef-Package-legacy
  kind: fixed
  published_time: '2026-11-01T09:00:00'
  supplied_by: https://internal-archive.example/spdx#SPDXRef-Agent-security-team
  hash_algorithm: SHA256
  hash_value: patch-evidence-v1
- spdx_id: https://internal-archive.example/spdx#SPDXRef-VEX-2
  vulnerability_id: https://internal-archive.example/spdx#SPDXRef-Vulnerability-CVE-2026-0001
  assessed_element_id: https://internal-archive.example/spdx#SPDXRef-Package-legacy
  kind: affected
  published_time: '2026-11-20T09:00:00'
  supplied_by: https://internal-archive.example/spdx#SPDXRef-Agent-security-team
  hash_algorithm: SHA256
  hash_value: recheck-evidence
- spdx_id: https://internal-archive.example/spdx#SPDXRef-VEX-3
  vulnerability_id: https://internal-archive.example/spdx#SPDXRef-Vulnerability-CVE-2026-0001
  assessed_element_id: https://internal-archive.example/spdx#SPDXRef-Package-upgraded
  kind: fixed
  published_time: '2026-11-21T09:00:00'
  supplied_by: https://internal-archive.example/spdx#SPDXRef-Agent-security-team
  hash_algorithm: SHA256
  hash_value: upgraded-patch-evidence
"""


def _payload_with_two_branches() -> Payload:
    payload = Payload()
    payload.add_element(make_package("SPDXRef-Package-legacy", "legacy-logger", "1.2.0"))
    payload.add_element(make_package("SPDXRef-Package-upgraded", "legacy-logger", "1.3.0"))
    return payload


def test_records_are_parsed_chronologically_and_ingested_in_reverse():
    records = parse_statement_records(SERIALIZED_STATEMENTS)

    assert [record.spdx_id for record in records] == [
        package_id("SPDXRef-VEX-1"),
        package_id("SPDXRef-VEX-2"),
        package_id("SPDXRef-VEX-3"),
    ]
    assert records[0].published_time == datetime(2026, 11, 1, 9, 0)

    payload = _payload_with_two_branches()
    load_statements_from_serialized(SERIALIZED_STATEMENTS, payload)
    elements = list(payload.get_full_map().values())
    # Reverse ingestion means the newest record is the first assessment added to the payload.
    assessment_ids = [
        element.spdx_id
        for element in elements
        if element.spdx_id
        in {package_id("SPDXRef-VEX-1"), package_id("SPDXRef-VEX-2"), package_id("SPDXRef-VEX-3")}
    ]
    assert assessment_ids == [
        package_id("SPDXRef-VEX-3"),
        package_id("SPDXRef-VEX-2"),
        package_id("SPDXRef-VEX-1"),
    ]


def test_reverse_ingestion_keeps_verification_results_consistent():
    payload = _payload_with_two_branches()
    load_statements_from_serialized(SERIALIZED_STATEMENTS, payload)
    manifest = build_migration_manifest(
        payload,
        [package_id("SPDXRef-Package-legacy")],
    )

    verdicts = {
        verdict.component_spdx_id: verdict
        for verdict in verify_payload(payload, VULN_ID, manifest.origin_map())
    }

    legacy = verdicts[package_id("SPDXRef-Package-legacy")]
    upgraded = verdicts[package_id("SPDXRef-Package-upgraded")]

    # Newer affected statement supersedes the older fixed claim on the legacy branch only;
    # the conflicting evidence keeps the branch pending while both statements stay traceable.
    assert legacy.status == VerificationStatus.UNDER_INVESTIGATION
    assert legacy.pending_reason == PendingReason.CONFLICTING_STATEMENTS
    assert legacy.governing_statement.spdx_id == package_id("SPDXRef-VEX-2")
    assert legacy.conflicts[0].losing_statement_id == package_id("SPDXRef-VEX-1")

    # The statement targeting the upgraded branch is unaffected by the legacy conflict.
    assert upgraded.status == VerificationStatus.FIXED
    assert upgraded.governing_statement.spdx_id == package_id("SPDXRef-VEX-3")
