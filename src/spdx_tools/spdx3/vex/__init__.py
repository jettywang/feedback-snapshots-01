# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from spdx_tools.spdx3.vex.migration import (
    MIGRATED_SPDX2,
    NATIVE_SPDX3,
    MigrationEntry,
    MigrationManifest,
    MigrationStatus,
    build_migration_manifest,
    build_migration_manifest_from_spdx2_document,
)
from spdx_tools.spdx3.vex.statement_loader import (
    StatementRecord,
    load_statements,
    load_statements_from_serialized,
    parse_statement_records,
)
from spdx_tools.spdx3.vex.verification import (
    ComponentVerdict,
    ConflictRecord,
    Evidence,
    PendingReason,
    StatementKind,
    VexStatement,
    VexVerificationEngine,
    VerificationStatus,
    branch_key_for_package,
    extract_vex_statements,
    verify_payload,
)
