"""Evidence-chain data model.

The graph is made of *documents* (nodes) and *external-document references*
(directed edges).  Every edge carries its own claimed checksum and its own
verdict, so two aliases pointing at identical bytes converge on one content
node, while a single tampered or missing target is judged independently.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import List, Optional


class EdgeStatus(enum.Enum):
    # Referenced path exists and its bytes match the claimed checksum.
    VERIFIED = "verified"
    # No authoritative path, but the claimed digest was found in the inventory.
    VERIFIED_DIGEST = "verified-digest"
    # File(s) exist but none reproduce the claimed digest (tamper / wrong bytes).
    DIGEST_MISMATCH = "digest-mismatch"
    # No candidate bytes are present in the offline directory.
    MISSING = "missing"
    # SPDX uses an algorithm we cannot compute locally.
    UNSUPPORTED_ALGORITHM = "unsupported-algorithm"
    # URI scheme cannot be resolved against the offline directory at all.
    NON_LOCAL_URI = "non-local-uri"

    @property
    def confirmed(self) -> bool:
        return self in (EdgeStatus.VERIFIED, EdgeStatus.VERIFIED_DIGEST)


class RootStatus(enum.Enum):
    SIDECAR_MATCH = "sidecar-match"
    SIDECAR_MISSING = "sidecar-missing"
    SIDECAR_MISMATCH = "sidecar-mismatch"
    UNAVAILABLE = "unavailable"


@dataclass
class CandidateEvidence:
    rel_path: str
    algorithm: str
    expected_digest: str
    actual_digest: str
    matches: bool
    size: int


@dataclass
class EdgeEvidence:
    edge_id: str
    source_document: str
    document_ref_id: str
    document_uri: str
    depth: int
    algorithm: str
    claimed_digest: str
    status: EdgeStatus
    confirmed: bool
    resolution: str  # how the URI was mapped to local bytes
    referenced_path: Optional[str]
    candidates: List[CandidateEvidence] = field(default_factory=list)
    matching_content_path: Optional[str] = None
    content_id: Optional[str] = None
    note: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "edge_id": self.edge_id,
            "source_document": self.source_document,
            "document_ref_id": self.document_ref_id,
            "document_uri": self.document_uri,
            "depth": self.depth,
            "algorithm": self.algorithm,
            "claimed_digest": self.claimed_digest,
            "status": self.status.value,
            "confirmed": self.confirmed,
            "resolution": self.resolution,
            "referenced_path": self.referenced_path,
            "candidates": [vars(candidate) for candidate in self.candidates],
            "matching_content_path": self.matching_content_path,
            "content_id": self.content_id,
            "note": self.note,
        }


@dataclass
class ContentNode:
    content_id: str
    sha256: str
    aliases: List[str]
    paths: List[str]
    edge_ids: List[str]
    document_namespace: Optional[str] = None

    def to_dict(self) -> dict:
        return vars(self)


@dataclass
class RootEvidence:
    path: str
    rel_path: str
    format: str
    document_namespace: Optional[str]
    actual_sha256: Optional[str]
    sidecar_path: Optional[str]
    sidecar_status: RootStatus
    external_ref_count: int

    def to_dict(self) -> dict:
        data = vars(self).copy()
        data["sidecar_status"] = self.sidecar_status.value
        return data


@dataclass
class EvidenceReport:
    root: RootEvidence
    edges: List[EdgeEvidence]
    nodes: List[ContentNode]
    parse_errors: List[str] = field(default_factory=list)

    @property
    def confirmed_edges(self) -> List[EdgeEvidence]:
        return [edge for edge in self.edges if edge.confirmed]

    @property
    def unconfirmed_edges(self) -> List[EdgeEvidence]:
        return [edge for edge in self.edges if not edge.confirmed]

    def to_dict(self) -> dict:
        return {
            "root": self.root.to_dict(),
            "summary": {
                "total_edges": len(self.edges),
                "confirmed_edges": len(self.confirmed_edges),
                "unconfirmed_edges": len(self.unconfirmed_edges),
                "content_nodes": len(self.nodes),
                "parse_errors": len(self.parse_errors),
            },
            "edges": [edge.to_dict() for edge in self.edges],
            "content_nodes": [node.to_dict() for node in self.nodes],
            "parse_errors": self.parse_errors,
        }
