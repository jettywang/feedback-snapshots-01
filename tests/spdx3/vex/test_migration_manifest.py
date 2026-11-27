# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from spdx_tools.spdx3.vex import (
    MIGRATED_SPDX2,
    NATIVE_SPDX3,
    MigrationManifest,
    MigrationStatus,
    build_migration_manifest,
)
from tests.spdx3.vex.conftest import package_id


def test_manifest_marks_migrated_and_native_origins(payload_with_branches, migrated_ids):
    manifest = build_migration_manifest(payload_with_branches, migrated_ids)

    origins = {entry.component_spdx_id: entry.origin for entry in manifest.entries}
    assert origins[package_id("SPDXRef-Package-legacy")] == MIGRATED_SPDX2
    assert origins[package_id("SPDXRef-Package-no-version")] == MIGRATED_SPDX2
    assert origins[package_id("SPDXRef-Package-upgraded")] == NATIVE_SPDX3


def test_manifest_keeps_entries_without_version_or_evidence_pending(payload_with_branches, migrated_ids):
    manifest = build_migration_manifest(payload_with_branches, migrated_ids)
    statuses = {entry.component_spdx_id: entry.status for entry in manifest.entries}

    assert statuses[package_id("SPDXRef-Package-legacy")] == MigrationStatus.ASSOCIABLE
    assert statuses[package_id("SPDXRef-Package-no-version")] == MigrationStatus.PENDING_VERSION
    assert statuses[package_id("SPDXRef-Package-no-evidence")] == MigrationStatus.PENDING_EVIDENCE
    assert package_id("SPDXRef-Package-no-version") in manifest.pending_ids()
    assert package_id("SPDXRef-Package-legacy") in manifest.associable_ids()


def test_manifest_round_trips_through_yaml(payload_with_branches, migrated_ids):
    manifest = build_migration_manifest(payload_with_branches, migrated_ids)

    restored = MigrationManifest.from_yaml(manifest.to_yaml())

    assert [entry.to_dict() for entry in restored.entries] == [entry.to_dict() for entry in manifest.entries]
    assert restored.origin_map() == manifest.origin_map()


def test_manifest_without_explicit_ids_treats_all_packages_as_migrated(payload_with_branches):
    manifest = build_migration_manifest(payload_with_branches)

    assert all(entry.origin == MIGRATED_SPDX2 for entry in manifest.entries)


def test_manifest_built_from_bumped_spdx2_document():
    from spdx_tools.spdx3.bump_from_spdx2.spdx_document import bump_spdx_document
    from spdx_tools.spdx3.vex import build_migration_manifest_from_spdx2_document
    from tests.spdx.fixtures import document_fixture, package_fixture

    spdx2_document = document_fixture(
        packages=[package_fixture(spdx_id="SPDXRef-Legacy", name="legacy-lib", version="1.2.0")],
        files=[],
        snippets=[],
        annotations=[],
        relationships=[],
        extracted_licensing_info=[],
    )
    payload = bump_spdx_document(spdx2_document)
    manifest = build_migration_manifest_from_spdx2_document(spdx2_document, payload)

    legacy_entry = next(
        entry for entry in manifest.entries if entry.component_spdx_id.endswith("#SPDXRef-Legacy")
    )
    assert legacy_entry.origin == MIGRATED_SPDX2
    assert legacy_entry.status == MigrationStatus.ASSOCIABLE
