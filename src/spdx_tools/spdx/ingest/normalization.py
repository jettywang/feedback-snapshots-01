# SPDX-FileCopyrightText: 2026 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Tuple

from spdx_tools.spdx.ingest.relationship_identity import RelationshipKey, extract_relationship_records
from spdx_tools.spdx.model import Document


class NormalizationError(Exception):
    """Raised when the unified target format cannot express the relationships of a
    document without loss. ``inexpressible`` holds one entry per affected endpoint
    pair: (pair, sorted relationship types that collide on the pair)."""

    def __init__(self, inexpressible: List[Tuple[Tuple, Tuple[str, ...]]]):
        self.inexpressible = inexpressible
        details = "; ".join(
            f"{pair[0].render()} -> {pair[1].render()} carries named relationships {list(types)}"
            for pair, types in inexpressible
        )
        super().__init__(f"unified format cannot express multiple named relationships per endpoint pair: {details}")


def _sort_key(key: RelationshipKey) -> Tuple:
    return (
        key.relationship_type,
        key.source.owner or "",
        key.source.local_id,
        key.target.owner or "",
        key.target.local_id,
    )


@dataclass(frozen=True)
class UnifiedRelationshipLedger:
    """The normalized, order-insensitive unified format retained by the repository.
    Only relationships that are usable after validation are retained."""

    document_name: str
    records: Tuple[RelationshipKey, ...]

    @classmethod
    def from_document(
        cls, document: Document, allow_multiple_types_per_pair: bool = True
    ) -> "UnifiedRelationshipLedger":
        records = extract_relationship_records(document)
        usable_keys = [record.key for record in records if record.usable]
        if not allow_multiple_types_per_pair:
            types_per_pair: Dict[Tuple, set] = defaultdict(set)
            for key in usable_keys:
                types_per_pair[(key.source, key.target)].add(key.relationship_type)
            inexpressible = [
                (pair, tuple(sorted(types)))
                for pair, types in sorted(types_per_pair.items(), key=lambda item: str(item[0]))
                if len(types) > 1
            ]
            if inexpressible:
                raise NormalizationError(inexpressible)
        return cls(
            document_name=document.creation_info.name,
            records=tuple(sorted(usable_keys, key=_sort_key)),
        )

    def retained_content(self) -> List[dict]:
        return [
            {
                "relationshipType": key.relationship_type,
                "source": {"owner": key.source.owner, "id": key.source.local_id},
                "target": {"owner": key.target.owner, "id": key.target.local_id},
            }
            for key in self.records
        ]
