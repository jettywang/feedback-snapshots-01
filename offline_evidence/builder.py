"""Build an offline evidence chain for SPDX external-document references."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

from spdx_tools.spdx.model import ChecksumAlgorithm, Document
from spdx_tools.spdx.parser.parse_anything import parse_file

from .digest import algorithm_available, digests_equal
from .inventory import Inventory, InventoryFile, read_sidecar_digest, sidecar_for
from .model import (
    CandidateEvidence,
    ContentNode,
    EdgeEvidence,
    EdgeStatus,
    EvidenceReport,
    RootEvidence,
    RootStatus,
)
from .uri_resolver import resolve_uri

_ALGO_BY_NAME = {member.name: member for member in ChecksumAlgorithm}


def _rel(path: Path, inventory: Inventory) -> str:
    for root in inventory.roots:
        try:
            return str(path.resolve().relative_to(root))
        except ValueError:
            continue
    return str(path)


def _spdx_format(path: Path) -> str:
    suffix = path.suffix.lower()
    names = {
        ".json": "SPDX-JSON",
        ".spdx": "SPDX-TagValue",
        ".tag": "SPDX-TagValue",
        ".xml": "SPDX-XML",
        ".rdf": "SPDX-RDF",
        ".yaml": "SPDX-YAML",
        ".yml": "SPDX-YAML",
    }
    return names.get(suffix, "unknown")


def _evaluate_edge(
    edge_index: int,
    source_rel: str,
    ref,
    depth: int,
    inventory: Inventory,
) -> Tuple[EdgeEvidence, Optional[InventoryFile]]:
    algorithm = ref.checksum.algorithm
    claimed = ref.checksum.value.strip().lower()
    resolution = resolve_uri(ref.document_uri, inventory)
    edge = EdgeEvidence(
        edge_id=f"E{edge_index:03d}",
        source_document=source_rel,
        document_ref_id=ref.document_ref_id,
        document_uri=ref.document_uri,
        depth=depth,
        algorithm=algorithm.name,
        claimed_digest=claimed,
        status=EdgeStatus.MISSING,
        confirmed=False,
        resolution=resolution.kind,
        referenced_path=str(resolution.referenced_path) if resolution.referenced_path else None,
        note=resolution.note,
    )

    if resolution.kind == "non-local":
        edge.status = EdgeStatus.NON_LOCAL_URI
        return edge, None

    if not algorithm_available(algorithm):
        edge.status = EdgeStatus.UNSUPPORTED_ALGORITHM
        edge.note = (edge.note + "; " if edge.note else "") + (
            f"algorithm {algorithm.name} cannot be computed in this environment"
        )
        return edge, None

    for item in resolution.candidates:
        actual = item.digest(algorithm)
        edge.candidates.append(
            CandidateEvidence(
                rel_path=item.rel_path,
                algorithm=algorithm.name,
                expected_digest=claimed,
                actual_digest=actual,
                matches=digests_equal(claimed, actual),
                size=item.size,
            )
        )

    matching = [item for item in resolution.candidates if digests_equal(claimed, item.digest(algorithm))]

    if resolution.kind == "local-path" and matching:
        edge.status = EdgeStatus.VERIFIED
        edge.confirmed = True
        return edge, matching[0]

    if matching:
        edge.status = EdgeStatus.VERIFIED
        edge.confirmed = True
        return edge, matching[0]

    # The referenced name resolves to bytes that do not reproduce the digest.
    if resolution.candidates:
        edge.status = EdgeStatus.DIGEST_MISMATCH
        recovered = inventory.find_by_digest(algorithm, claimed)
        if recovered:
            target = recovered[0]
            edge.matching_content_path = target.rel_path
            edge.note = (edge.note + "; " if edge.note else "") + (
                "claimed digest exists elsewhere in the inventory (possible rename)"
            )
        return edge, None

    # Nothing at the referenced name: search the whole inventory by digest.
    recovered = inventory.find_by_digest(algorithm, claimed)
    if recovered:
        target = recovered[0]
        edge.status = EdgeStatus.VERIFIED_DIGEST
        edge.confirmed = True
        edge.matching_content_path = target.rel_path
        edge.referenced_path = str(target.path)
        for item in recovered:
            edge.candidates.append(
                CandidateEvidence(
                    rel_path=item.rel_path,
                    algorithm=algorithm.name,
                    expected_digest=claimed,
                    actual_digest=item.digest(algorithm),
                    matches=True,
                    size=item.size,
                )
            )
        return edge, target

    edge.status = EdgeStatus.MISSING
    return edge, None


def _build_root_evidence(root_path: Path, document: Document, inventory: Inventory, ref_count: int) -> RootEvidence:
    item = inventory.get(root_path)
    actual_sha = item.digest(ChecksumAlgorithm.SHA256) if item else None
    sidecar = sidecar_for(root_path, "sha256")
    sidecar_digest = read_sidecar_digest(sidecar)
    if not sidecar.is_file():
        sidecar_status = RootStatus.SIDECAR_MISSING
    elif sidecar_digest is None:
        sidecar_status = RootStatus.SIDECAR_MISSING
    elif actual_sha is not None and digests_equal(sidecar_digest, actual_sha):
        sidecar_status = RootStatus.SIDECAR_MATCH
    else:
        sidecar_status = RootStatus.SIDECAR_MISMATCH
    return RootEvidence(
        path=str(root_path),
        rel_path=_rel(root_path, inventory),
        format=_spdx_format(root_path),
        document_namespace=document.creation_info.document_namespace,
        actual_sha256=actual_sha,
        sidecar_path=str(sidecar) if sidecar.is_file() else None,
        sidecar_status=sidecar_status,
        external_ref_count=ref_count,
    )


def build_evidence(root: str | Path, search_roots: List[str | Path]) -> EvidenceReport:
    root_path = Path(root).resolve()
    inventory = Inventory.build(search_roots)

    parse_errors: List[str] = []
    parse_cache: Dict[Path, Optional[Document]] = {}
    root_document = parse_file(str(root_path))
    parse_cache[root_path] = root_document
    root_evidence = _build_root_evidence(
        root_path, root_document, inventory, len(root_document.creation_info.external_document_refs)
    )

    edges: List[EdgeEvidence] = []
    nodes_by_id: Dict[str, ContentNode] = {}
    edge_counter = 0

    # Queue: (document to inspect, its inventory file, depth, set of visited paths).
    queue: List[Tuple[Document, Optional[InventoryFile], int, set]] = [
        (root_document, inventory.get(root_path), 0, {root_path})
    ]

    while queue:
        document, source_item, depth, visited = queue.pop(0)
        source_rel = _rel(source_item.path, inventory) if source_item else root_evidence.rel_path
        for ref in document.creation_info.external_document_refs:
            edge_counter += 1
            edge, matched_item = _evaluate_edge(edge_counter, source_rel, ref, depth, inventory)
            edges.append(edge)

            if matched_item is None:
                continue

            # Converge aliases onto one content node keyed by the actual bytes.
            content_sha = matched_item.digest(ChecksumAlgorithm.SHA256)
            content_id = f"sha256:{content_sha}"
            edge.content_id = content_id
            node = nodes_by_id.get(content_id)
            if node is None:
                node = ContentNode(
                    content_id=content_id,
                    sha256=content_sha,
                    aliases=[ref.document_ref_id],
                    paths=[matched_item.rel_path],
                    edge_ids=[edge.edge_id],
                    document_namespace=_namespace_of(matched_item, parse_cache, parse_errors),
                )
                nodes_by_id[content_id] = node
            else:
                if ref.document_ref_id not in node.aliases:
                    node.aliases.append(ref.document_ref_id)
                if matched_item.rel_path not in node.paths:
                    node.paths.append(matched_item.rel_path)
                node.edge_ids.append(edge.edge_id)

            if matched_item.path in visited:
                continue
            child_doc = _cached_parse(matched_item.path, parse_cache, parse_errors)
            if child_doc is not None:
                queue.append((child_doc, matched_item, depth + 1, visited | {matched_item.path}))

    return EvidenceReport(
        root=root_evidence,
        edges=edges,
        nodes=list(nodes_by_id.values()),
        parse_errors=parse_errors,
    )


def _cached_parse(
    path: Path, parse_cache: Dict[Path, Optional[Document]], parse_errors: List[str]
) -> Optional[Document]:
    if path not in parse_cache:
        try:
            parse_cache[path] = parse_file(str(path))
        except Exception as exc:  # noqa: BLE001 - record any parser failure as evidence
            parse_errors.append(f"{path}: {exc}")
            parse_cache[path] = None
    return parse_cache[path]


def _namespace_of(
    item: InventoryFile, parse_cache: Dict[Path, Optional[Document]], parse_errors: List[str]
) -> Optional[str]:
    document = _cached_parse(item.path, parse_cache, parse_errors)
    return document.creation_info.document_namespace if document else None
