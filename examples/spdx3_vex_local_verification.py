# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Local VEX verification after an upgrade package.

Scenario:
* two component branches were converted from an old SPDX 2.x document,
* one additional component was authored directly in SPDX 3 and lacks evidence,
* VEX statements arrive as a chronological record list and are read newest-first,
* the migration manifest keeps entries without a version or evidence as pending.

Run with: .venv/bin/python examples/spdx3_vex_local_verification.py
"""
from datetime import datetime

from spdx_tools.spdx3.model.hash import Hash, HashAlgorithm
from spdx_tools.spdx3.model.software import Package
from spdx_tools.spdx3.payload import Payload
from spdx_tools.spdx3.vex import (
    StatementRecord,
    VerificationStatus,
    build_migration_manifest,
    load_statements,
    verify_payload,
)

NAMESPACE = "https://internal-archive.example/spdx"
VULN_ID = f"{NAMESPACE}#SPDXRef-Vulnerability-CVE-2026-0001"


def pkg(local_id, name, version, with_hash=True):
    return Package(
        spdx_id=f"{NAMESPACE}#{local_id}",
        name=name,
        package_version=version,
        verified_using=[Hash(HashAlgorithm.SHA256, f"hash-{local_id}")] if with_hash else [],
    )


def main():
    payload = Payload()
    legacy = pkg("SPDXRef-Package-legacy", "legacy-logger", "1.2.0")
    upgraded = pkg("SPDXRef-Package-upgraded", "legacy-logger", "1.3.0")
    no_version = Package(spdx_id=f"{NAMESPACE}#SPDXRef-Package-no-version", name="mystery-lib", package_version=None)
    unrelated = pkg("SPDXRef-Package-unrelated", "unrelated-lib", "9.0.0")
    for package in (legacy, upgraded, no_version, unrelated):
        payload.add_element(package)

    # 1. Migration manifest: the two legacy-logger branches came from the old SPDX 2.x document.
    manifest = build_migration_manifest(
        payload,
        migrated_component_ids=[legacy.spdx_id, no_version.spdx_id],
    )
    print("=== Migration manifest ===")
    print(manifest.to_yaml())

    # 2. Two valid fixed relationships plus an unrelated not-affected statement, oldest first.
    records = [
        StatementRecord(
            spdx_id=f"{NAMESPACE}#SPDXRef-VEX-legacy-fixed",
            vulnerability_id=VULN_ID,
            assessed_element_id=legacy.spdx_id,
            kind="fixed",
            published_time=datetime(2026, 11, 10, 9, 0),
            supplied_by=f"{NAMESPACE}#SPDXRef-Agent-security-team",
            hash_algorithm="SHA256",
            hash_value="legacy-patch-evidence",
        ),
        StatementRecord(
            spdx_id=f"{NAMESPACE}#SPDXRef-VEX-upgraded-fixed",
            vulnerability_id=VULN_ID,
            assessed_element_id=upgraded.spdx_id,
            kind="fixed",
            published_time=datetime(2026, 11, 11, 9, 0),
            supplied_by=f"{NAMESPACE}#SPDXRef-Agent-security-team",
            hash_algorithm="SHA256",
            hash_value="upgraded-patch-evidence",
        ),
        StatementRecord(
            spdx_id=f"{NAMESPACE}#SPDXRef-VEX-unrelated",
            vulnerability_id=VULN_ID,
            assessed_element_id=unrelated.spdx_id,
            kind="not_affected",
            published_time=datetime(2026, 11, 9, 9, 0),
            supplied_by=f"{NAMESPACE}#SPDXRef-Agent-security-team",
        ),
        # A newer conflicting claim targets only the legacy branch.
        StatementRecord(
            spdx_id=f"{NAMESPACE}#SPDXRef-VEX-legacy-recheck",
            vulnerability_id=VULN_ID,
            assessed_element_id=legacy.spdx_id,
            kind="affected",
            published_time=datetime(2026, 11, 20, 9, 0),
            supplied_by=f"{NAMESPACE}#SPDXRef-Agent-security-team",
            hash_algorithm="SHA256",
            hash_value="recheck-evidence",
        ),
    ]

    # 3. Reverse ingestion: newest statement materialized first, scoped to its own branch.
    load_statements(records, payload)

    verdicts = verify_payload(payload, VULN_ID, manifest.origin_map())
    print("=== Verification results ===")
    for verdict in verdicts:
        label = {
            VerificationStatus.FIXED: "已修复 fixed",
            VerificationStatus.UNDER_INVESTIGATION: "待查 under-investigation",
            VerificationStatus.NOT_AFFECTED: "无关 not-affected",
        }[verdict.status]
        print(f"{verdict.branch_key} [{verdict.origin}] -> {label}")
        if verdict.pending_reason:
            print(f"    pending reason: {verdict.pending_reason.name}")
        if verdict.governing_statement:
            print(f"    governing statement: {verdict.governing_statement.spdx_id}")
        for conflict in verdict.conflicts:
            print(
                "    conflict: "
                f"{conflict.losing_statement_id} ({conflict.losing_kind.name}) superseded by "
                f"{conflict.winning_statement_id} ({conflict.winning_kind.name})"
            )
        for evidence in verdict.supporting_evidence:
            print(f"    evidence: {evidence.kind} on {evidence.element_spdx_id} ({evidence.detail})")


if __name__ == "__main__":
    main()
