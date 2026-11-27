# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from spdx_tools.spdx.ingest.normalization import NormalizationError, UnifiedRelationshipLedger
from spdx_tools.spdx.ingest.relationship_identity import (
    EndpointKey,
    RelationshipKey,
    RelationshipRecord,
    extract_relationship_records,
)
from spdx_tools.spdx.ingest.verification import (
    EvidenceKind,
    IngestionDecision,
    IngestionVerificationReport,
    RelationshipEvidence,
    ingest_document,
    ingest_file,
    verify_candidate,
)

__all__ = [
    "EndpointKey",
    "EvidenceKind",
    "IngestionDecision",
    "IngestionVerificationReport",
    "NormalizationError",
    "RelationshipEvidence",
    "RelationshipKey",
    "RelationshipRecord",
    "UnifiedRelationshipLedger",
    "extract_relationship_records",
    "ingest_document",
    "ingest_file",
    "verify_candidate",
]
