# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional, Union

from spdx_tools.spdx.ingest.normalization import NormalizationError, UnifiedRelationshipLedger
from spdx_tools.spdx.ingest.relationship_identity import RelationshipKey, extract_relationship_records
from spdx_tools.spdx.model import Document
from spdx_tools.spdx.parser.parse_anything import parse_file


class IngestionDecision(Enum):
    INGEST = auto()
    BLOCK = auto()


class EvidenceKind:
    MISSING_IN_CANDIDATE = "missing_in_candidate"
    ADDED_IN_CANDIDATE = "added_in_candidate"
    UNUSABLE_IN_CANDIDATE = "unusable_in_candidate"
    INEXPRESSIBLE_IN_TARGET_FORMAT = "inexpressible_in_target_format"


@dataclass(frozen=True)
class RelationshipEvidence:
    kind: str
    detail: str
    relationship_type: Optional[str] = None
    source: Optional[str] = None
    target: Optional[str] = None


@dataclass
class IngestionVerificationReport:
    decision: IngestionDecision
    evidence: List[RelationshipEvidence] = field(default_factory=list)
    retained_content: List[dict] = field(default_factory=list)
    ledger: Optional[UnifiedRelationshipLedger] = None

    @property
    def is_ingestible(self) -> bool:
        return self.decision == IngestionDecision.INGEST


def _key_evidence(kind: str, key: RelationshipKey, detail: str) -> RelationshipEvidence:
    return RelationshipEvidence(
        kind=kind,
        detail=detail,
        relationship_type=key.relationship_type,
        source=key.source.render(),
        target=key.target.render(),
    )


def verify_candidate(
    candidate: Document,
    baseline: Optional[UnifiedRelationshipLedger] = None,
    allow_multiple_types_per_pair: bool = True,
) -> IngestionVerificationReport:
    """Offline verification at the ingestion boundary. Compares the candidate's
    policy-relevant relationships - identified by relationship type, endpoint owning
    document and post-validation usability - against the retained baseline ledger and
    against what the unified target format is able to express."""
    evidence: List[RelationshipEvidence] = []

    for record in extract_relationship_records(candidate):
        if not record.usable:
            evidence.append(
                _key_evidence(
                    EvidenceKind.UNUSABLE_IN_CANDIDATE,
                    record.key,
                    "relationship is not usable after validation: " + "; ".join(record.usability_issues),
                )
            )

    ledger: Optional[UnifiedRelationshipLedger] = None
    try:
        ledger = UnifiedRelationshipLedger.from_document(
            candidate, allow_multiple_types_per_pair=allow_multiple_types_per_pair
        )
    except NormalizationError as error:
        for pair, types in error.inexpressible:
            evidence.append(
                RelationshipEvidence(
                    kind=EvidenceKind.INEXPRESSIBLE_IN_TARGET_FORMAT,
                    detail=(
                        f"endpoint pair {pair[0].render()} -> {pair[1].render()} carries named relationships "
                        f"{list(types)}, which the unified target format cannot express"
                    ),
                    relationship_type=", ".join(types),
                    source=pair[0].render(),
                    target=pair[1].render(),
                )
            )

    if baseline is not None and ledger is not None:
        missing = Counter(baseline.records) - Counter(ledger.records)
        added = Counter(ledger.records) - Counter(baseline.records)
        for key in sorted(missing, key=str):
            evidence.append(
                _key_evidence(
                    EvidenceKind.MISSING_IN_CANDIDATE,
                    key,
                    f"relationship retained in the repository is gone from the candidate: {key.render()}",
                )
            )
        for key in sorted(added, key=str):
            evidence.append(
                _key_evidence(
                    EvidenceKind.ADDED_IN_CANDIDATE,
                    key,
                    f"candidate introduces a relationship that is not retained in the repository: {key.render()}",
                )
            )

    decision = IngestionDecision.BLOCK if evidence else IngestionDecision.INGEST
    return IngestionVerificationReport(
        decision=decision,
        evidence=evidence,
        retained_content=ledger.retained_content() if ledger else [],
        ledger=ledger,
    )


def ingest_document(
    document: Document,
    baseline: Optional[UnifiedRelationshipLedger] = None,
    allow_multiple_types_per_pair: bool = True,
) -> IngestionVerificationReport:
    return verify_candidate(
        document, baseline=baseline, allow_multiple_types_per_pair=allow_multiple_types_per_pair
    )


def ingest_file(
    file_name: str,
    baseline: Optional[UnifiedRelationshipLedger] = None,
    allow_multiple_types_per_pair: bool = True,
) -> IngestionVerificationReport:
    document: Document = parse_file(file_name)
    return verify_candidate(
        document, baseline=baseline, allow_multiple_types_per_pair=allow_multiple_types_per_pair
    )
