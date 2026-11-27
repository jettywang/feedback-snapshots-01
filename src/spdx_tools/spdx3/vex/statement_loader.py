# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
"""Ingest serialized VEX statements into a payload.

Statements are exchanged as plain records (for example YAML or JSON). Archives append new
statements to the end of such a record list, so on reload the list is read in reverse order: the
newest statement is materialized first. A statement only ever touches the component branch it
targets, hence statements for other branches cannot overwrite each other. The VEX verification
later orders by publication time again and keeps every superseded statement as conflict evidence.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

import yaml

from spdx_tools.spdx3.model import RelationshipType
from spdx_tools.spdx3.model.hash import Hash, HashAlgorithm
from spdx_tools.spdx3.model.security.vex_affected_vuln_assessment_relationship import (
    VexAffectedVulnAssessmentRelationship,
)
from spdx_tools.spdx3.model.security.vex_fixed_vuln_assessment_relationship import (
    VexFixedVulnAssessmentRelationship,
)
from spdx_tools.spdx3.model.security.vex_not_affected_vuln_assessment_relationship import (
    VexNotAffectedVulnAssessmentRelationship,
)
from spdx_tools.spdx3.model.security.vex_under_investigation_vuln_assessment_relationship import (
    VexUnderInvestigationVulnAssessmentRelationship,
)
from spdx_tools.spdx3.model.security.vex_vuln_assessment_relationship import VexVulnAssessmentRelationship
from spdx_tools.spdx3.payload import Payload

STATEMENT_CLASS_BY_KIND: Dict[str, type] = {
    "fixed": VexFixedVulnAssessmentRelationship,
    "affected": VexAffectedVulnAssessmentRelationship,
    "not_affected": VexNotAffectedVulnAssessmentRelationship,
    "under_investigation": VexUnderInvestigationVulnAssessmentRelationship,
}


@dataclass
class StatementRecord:
    spdx_id: str
    vulnerability_id: str
    assessed_element_id: str
    kind: str
    published_time: Optional[datetime] = None
    modified_time: Optional[datetime] = None
    withdrawn_time: Optional[datetime] = None
    supplied_by: Optional[str] = None
    vex_version: Optional[str] = None
    status_notes: Optional[str] = None
    hash_algorithm: Optional[str] = None
    hash_value: Optional[str] = None
    extra: Dict = field(default_factory=dict)


def parse_statement_records(serialized: str) -> List[StatementRecord]:
    """Parse a YAML/JSON list of statement records, oldest first as exported by the archive."""
    loaded = yaml.safe_load(serialized) or []
    records = []
    for item in loaded:
        records.append(
            StatementRecord(
                spdx_id=item["spdx_id"],
                vulnerability_id=item["vulnerability_id"],
                assessed_element_id=item["assessed_element_id"],
                kind=item["kind"],
                published_time=_parse_time(item.get("published_time")),
                modified_time=_parse_time(item.get("modified_time")),
                withdrawn_time=_parse_time(item.get("withdrawn_time")),
                supplied_by=item.get("supplied_by"),
                vex_version=item.get("vex_version"),
                status_notes=item.get("status_notes"),
                hash_algorithm=item.get("hash_algorithm"),
                hash_value=item.get("hash_value"),
                extra={
                    key: value
                    for key, value in item.items()
                    if key
                    not in {
                        "spdx_id",
                        "vulnerability_id",
                        "assessed_element_id",
                        "kind",
                        "published_time",
                        "modified_time",
                        "withdrawn_time",
                        "supplied_by",
                        "vex_version",
                        "status_notes",
                        "hash_algorithm",
                        "hash_value",
                    }
                },
            )
        )
    return records


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if value in (None, ""):
        return None
    return datetime.fromisoformat(value)


def _build_relationship(record: StatementRecord) -> VexVulnAssessmentRelationship:
    relationship_class = STATEMENT_CLASS_BY_KIND[record.kind]
    verified_using = []
    if record.hash_algorithm and record.hash_value:
        verified_using.append(Hash(HashAlgorithm[record.hash_algorithm], record.hash_value))
    return relationship_class(
        spdx_id=record.spdx_id,
        from_element=record.vulnerability_id,
        relationship_type=RelationshipType.OTHER,
        to=[record.assessed_element_id],
        assessed_element=record.assessed_element_id,
        published_time=record.published_time,
        modified_time=record.modified_time,
        withdrawn_time=record.withdrawn_time,
        supplied_by=record.supplied_by,
        vex_version=record.vex_version,
        status_notes=record.status_notes,
        verified_using=verified_using,
    )


def load_statements(records: List[StatementRecord], payload: Payload) -> Payload:
    """Materialize records into the payload, reading them newest-first (reverse order).

    Each record is independent: it only adds its own assessment relationship and only references
    the single component branch it targets, so reverse ingestion never changes another branch.
    """
    for record in reversed(records):
        payload.add_element(_build_relationship(record))
    return payload


def load_statements_from_serialized(serialized: str, payload: Payload) -> Payload:
    return load_statements(parse_statement_records(serialized), payload)
