# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from datetime import datetime

from spdx_tools.spdx3.vex import (
    PendingReason,
    VerificationStatus,
    build_migration_manifest,
    verify_payload,
)
from tests.spdx3.vex.conftest import VULN_ID, make_vex, package_id


def _build_full_scenario(payload):
    # Two valid fixed relationships: one for the legacy branch, one for the upgraded branch.
    payload.add_element(
        make_vex(
            "SPDXRef-VEX-legacy-fixed",
            "fixed",
            "SPDXRef-Package-legacy",
            published=datetime(2026, 11, 10, 9, 0),
        )
    )
    payload.add_element(
        make_vex(
            "SPDXRef-VEX-upgraded-fixed",
            "fixed",
            "SPDXRef-Package-upgraded",
            published=datetime(2026, 11, 11, 9, 0),
        )
    )
    # The unrelated component is explicitly not affected.
    payload.add_element(
        make_vex(
            "SPDXRef-VEX-unrelated-not-affected",
            "not_affected",
            "SPDXRef-Package-unrelated",
            published=datetime(2026, 11, 9, 9, 0),
        )
    )
    # A fixed claim without integrity evidence or supplier cannot be verified.
    payload.add_element(
        make_vex(
            "SPDXRef-VEX-no-evidence",
            "fixed",
            "SPDXRef-Package-no-evidence",
            published=datetime(2026, 11, 12, 9, 0),
            supplied_by=None,
            with_hash=False,
        )
    )
    return payload


def _verdicts_by_id(payload, manifest):
    verdicts = verify_payload(payload, VULN_ID, manifest.origin_map())
    return {verdict.component_spdx_id: verdict for verdict in verdicts}


def test_verdict_outputs_fixed_pending_and_not_affected(payload_with_branches, migrated_ids):
    manifest = build_migration_manifest(payload_with_branches, migrated_ids)
    verdicts = _verdicts_by_id(_build_full_scenario(payload_with_branches), manifest)

    assert verdicts[package_id("SPDXRef-Package-legacy")].status == VerificationStatus.FIXED
    assert verdicts[package_id("SPDXRef-Package-upgraded")].status == VerificationStatus.FIXED
    assert verdicts[package_id("SPDXRef-Package-unrelated")].status == VerificationStatus.NOT_AFFECTED

    no_version = verdicts[package_id("SPDXRef-Package-no-version")]
    assert no_version.status == VerificationStatus.UNDER_INVESTIGATION
    assert no_version.pending_reason == PendingReason.NO_STATEMENT

    no_evidence = verdicts[package_id("SPDXRef-Package-no-evidence")]
    assert no_evidence.status == VerificationStatus.UNDER_INVESTIGATION
    assert no_evidence.pending_reason == PendingReason.MISSING_EVIDENCE


def test_migrated_legacy_component_can_be_associated(payload_with_branches, migrated_ids):
    manifest = build_migration_manifest(payload_with_branches, migrated_ids)
    verdicts = _verdicts_by_id(_build_full_scenario(payload_with_branches), manifest)

    legacy = verdicts[package_id("SPDXRef-Package-legacy")]
    assert legacy.origin == "migrated-spdx2"
    assert legacy.status == VerificationStatus.FIXED
    assert legacy.governing_statement.spdx_id == package_id("SPDXRef-VEX-legacy-fixed")
    # Requisites: the statement's own patch hash plus the package hash.
    assert {evidence.kind for evidence in legacy.supporting_evidence} == {"Hash"}
    assert len(legacy.supporting_evidence) == 2


def test_missing_version_stays_pending_even_with_fixed_statement(payload_with_branches, migrated_ids):
    payload_with_branches.add_element(
        make_vex(
            "SPDXRef-VEX-missing-version-fixed",
            "fixed",
            "SPDXRef-Package-no-version",
            published=datetime(2026, 11, 13, 9, 0),
        )
    )
    manifest = build_migration_manifest(payload_with_branches, migrated_ids)
    verdicts = _verdicts_by_id(payload_with_branches, manifest)

    verdict = verdicts[package_id("SPDXRef-Package-no-version")]
    assert verdict.status == VerificationStatus.UNDER_INVESTIGATION
    assert verdict.pending_reason == PendingReason.MISSING_VERSION
    assert verdict.governing_statement is not None


def test_newer_statement_only_changes_its_own_branch(payload_with_branches, migrated_ids):
    payload_with_branches.add_element(
        make_vex(
            "SPDXRef-VEX-legacy-affected",
            "affected",
            "SPDXRef-Package-legacy",
            published=datetime(2026, 11, 20, 9, 0),
        )
    )
    payload_with_branches.add_element(
        make_vex(
            "SPDXRef-VEX-upgraded-fixed",
            "fixed",
            "SPDXRef-Package-upgraded",
            published=datetime(2026, 11, 11, 9, 0),
        )
    )
    manifest = build_migration_manifest(payload_with_branches, migrated_ids)
    verdicts = _verdicts_by_id(payload_with_branches, manifest)

    legacy = verdicts[package_id("SPDXRef-Package-legacy")]
    upgraded = verdicts[package_id("SPDXRef-Package-upgraded")]
    assert legacy.status == VerificationStatus.UNDER_INVESTIGATION
    assert legacy.pending_reason == PendingReason.AFFECTED
    assert upgraded.status == VerificationStatus.FIXED


def test_conflicting_evidence_is_traced_to_both_statements(payload_with_branches, migrated_ids):
    payload_with_branches.add_element(
        make_vex(
            "SPDXRef-VEX-legacy-fixed-early",
            "fixed",
            "SPDXRef-Package-legacy",
            published=datetime(2026, 11, 1, 9, 0),
        )
    )
    payload_with_branches.add_element(
        make_vex(
            "SPDXRef-VEX-legacy-affected-late",
            "affected",
            "SPDXRef-Package-legacy",
            published=datetime(2026, 11, 20, 9, 0),
        )
    )
    manifest = build_migration_manifest(payload_with_branches, migrated_ids)
    verdicts = _verdicts_by_id(payload_with_branches, manifest)

    legacy = verdicts[package_id("SPDXRef-Package-legacy")]
    assert legacy.governing_statement.spdx_id == package_id("SPDXRef-VEX-legacy-affected-late")
    assert len(legacy.considered_statements) == 2
    assert len(legacy.conflicts) == 1
    conflict = legacy.conflicts[0]
    assert conflict.winning_statement_id == package_id("SPDXRef-VEX-legacy-affected-late")
    assert conflict.losing_statement_id == package_id("SPDXRef-VEX-legacy-fixed-early")


def test_withdrawn_statement_does_not_verify_fix(payload_with_branches, migrated_ids):
    payload_with_branches.add_element(
        make_vex(
            "SPDXRef-VEX-legacy-withdrawn",
            "fixed",
            "SPDXRef-Package-legacy",
            published=datetime(2026, 11, 1, 9, 0),
            withdrawn=datetime(2026, 11, 5, 9, 0),
        )
    )
    manifest = build_migration_manifest(payload_with_branches, migrated_ids)
    verdicts = _verdicts_by_id(payload_with_branches, manifest)

    legacy = verdicts[package_id("SPDXRef-Package-legacy")]
    assert legacy.status == VerificationStatus.UNDER_INVESTIGATION
    assert legacy.pending_reason == PendingReason.SUPERSEDED_BY_WITHDRAWAL
    assert legacy.considered_statements[0].spdx_id == package_id("SPDXRef-VEX-legacy-withdrawn")


def test_verification_is_scoped_per_vulnerability(payload_with_branches, migrated_ids):
    payload_with_branches.add_element(
        make_vex(
            "SPDXRef-VEX-legacy-fixed",
            "fixed",
            "SPDXRef-Package-legacy",
            published=datetime(2026, 11, 10, 9, 0),
        )
    )
    manifest = build_migration_manifest(payload_with_branches, migrated_ids)

    scoped = verify_payload(payload_with_branches, VULN_ID, manifest.origin_map())
    other_vuln_id = "https://ns#SPDXRef-Vulnerability-CVE-other"
    other_vuln = verify_payload(payload_with_branches, other_vuln_id, manifest.origin_map())

    legacy_scoped = next(v for v in scoped if v.component_spdx_id == package_id("SPDXRef-Package-legacy"))
    assert legacy_scoped.status == VerificationStatus.FIXED
    assert all(verdict.pending_reason == PendingReason.NO_STATEMENT for verdict in other_vuln)


def test_verification_without_vulnerability_id_aggregates_all_statements(payload_with_branches, migrated_ids):
    from spdx_tools.spdx3.model import RelationshipType
    from spdx_tools.spdx3.model.security import VexFixedVulnAssessmentRelationship

    legacy_id = package_id("SPDXRef-Package-legacy")
    for vulnerability_local_id in ("CVE-2026-A", "CVE-2026-B"):
        payload_with_branches.add_element(
            VexFixedVulnAssessmentRelationship(
                spdx_id=package_id(f"SPDXRef-VEX-{vulnerability_local_id}"),
                from_element=package_id(f"SPDXRef-Vulnerability-{vulnerability_local_id}"),
                relationship_type=RelationshipType.HAS_ASSESSMENT_FOR,
                to=[legacy_id],
                assessed_element=legacy_id,
                published_time=datetime(2026, 11, 10, 9, 0),
                supplied_by=package_id("SPDXRef-Agent-security-team"),
            )
        )
    manifest = build_migration_manifest(payload_with_branches, migrated_ids)

    verdicts = {
        verdict.component_spdx_id: verdict
        for verdict in verify_payload(
            payload_with_branches, component_origins=manifest.origin_map()
        )
    }

    legacy = verdicts[legacy_id]
    assert len(legacy.considered_statements) == 2
    assert legacy.status == VerificationStatus.FIXED
