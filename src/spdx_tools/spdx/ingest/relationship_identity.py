# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from dataclasses import dataclass
from typing import List, Optional, Tuple

from spdx_tools.spdx.model import Document, Relationship, SpdxNoAssertion, SpdxNone
from spdx_tools.spdx.validation.spdx_id_validators import validate_spdx_id

THIS_DOCUMENT = "this document"


@dataclass(frozen=True)
class EndpointKey:
    """Identity of a relationship endpoint. ``owner`` is ``None`` for elements of the
    ingested document itself and the ``DocumentRef-...`` id for external elements."""

    owner: Optional[str]
    local_id: str

    def render(self) -> str:
        owner = self.owner if self.owner is not None else THIS_DOCUMENT
        return f"{self.local_id} ({owner})"


@dataclass(frozen=True)
class RelationshipKey:
    """Policy-relevant identity of a named relationship: its type plus the owning
    document and local id of both endpoints. Two relationships between the same
    endpoint pair are distinct as long as their types differ."""

    relationship_type: str
    source: EndpointKey
    target: EndpointKey

    def render(self) -> str:
        return f"{self.relationship_type}: {self.source.render()} -> {self.target.render()}"


@dataclass(frozen=True)
class RelationshipRecord:
    key: RelationshipKey
    usable: bool
    usability_issues: Tuple[str, ...]


def endpoint_key_for(spdx_id: object) -> EndpointKey:
    if isinstance(spdx_id, (SpdxNone, SpdxNoAssertion)):
        return EndpointKey(None, str(spdx_id))
    split_id = str(spdx_id).split(":")
    if len(split_id) == 2:
        return EndpointKey(split_id[0], split_id[1])
    return EndpointKey(None, str(spdx_id))


def _endpoint_usability_issues(spdx_id: object, document: Document) -> List[str]:
    if isinstance(spdx_id, (SpdxNone, SpdxNoAssertion)):
        return []
    return validate_spdx_id(str(spdx_id), document, check_document=True)


def record_for_relationship(relationship: Relationship, document: Document) -> RelationshipRecord:
    key = RelationshipKey(
        relationship_type=relationship.relationship_type.name,
        source=endpoint_key_for(relationship.spdx_element_id),
        target=endpoint_key_for(relationship.related_spdx_element_id),
    )
    issues = _endpoint_usability_issues(relationship.spdx_element_id, document)
    issues += _endpoint_usability_issues(relationship.related_spdx_element_id, document)
    return RelationshipRecord(key=key, usable=not issues, usability_issues=tuple(issues))


def extract_relationship_records(document: Document) -> List[RelationshipRecord]:
    """Extract all relationships of the document together with their post-validation
    usability. A relationship is usable if both endpoints resolve: internal ids must
    be present in the document, external ids must reference a declared DocumentRef."""
    return [record_for_relationship(relationship, document) for relationship in document.relationships]
