"""Render an EvidenceReport in machine- and human-readable formats."""
from __future__ import annotations

import csv
import io
import json
from typing import List

from .model import EdgeStatus, EvidenceReport

_STATUS_BADGE = {
    EdgeStatus.VERIFIED: "[OK]  ",
    EdgeStatus.VERIFIED_DIGEST: "[DIG] ",
    EdgeStatus.DIGEST_MISMATCH: "[FAIL]",
    EdgeStatus.MISSING: "[MISS]",
    EdgeStatus.UNSUPPORTED_ALGORITHM: "[UNSP]",
    EdgeStatus.NON_LOCAL_URI: "[NET] ",
}


def to_json(report: EvidenceReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False, sort_keys=False)


def to_csv(report: EvidenceReport) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "edge_id",
            "depth",
            "source_document",
            "document_ref_id",
            "document_uri",
            "algorithm",
            "claimed_digest",
            "status",
            "confirmed",
            "resolution",
            "referenced_path",
            "candidate_path",
            "actual_digest",
            "matches",
            "content_id",
        ]
    )
    for edge in report.edges:
        if not edge.candidates:
            writer.writerow(
                [
                    edge.edge_id,
                    edge.depth,
                    edge.source_document,
                    edge.document_ref_id,
                    edge.document_uri,
                    edge.algorithm,
                    edge.claimed_digest,
                    edge.status.value,
                    edge.confirmed,
                    edge.resolution,
                    edge.referenced_path or "",
                    edge.matching_content_path or "",
                    "",
                    "",
                    edge.content_id or "",
                ]
            )
            continue
        for candidate in edge.candidates:
            writer.writerow(
                [
                    edge.edge_id,
                    edge.depth,
                    edge.source_document,
                    edge.document_ref_id,
                    edge.document_uri,
                    edge.algorithm,
                    edge.claimed_digest,
                    edge.status.value,
                    edge.confirmed,
                    edge.resolution,
                    edge.referenced_path or "",
                    candidate.rel_path,
                    candidate.actual_digest,
                    candidate.matches,
                    edge.content_id or "",
                ]
            )
    return buffer.getvalue()


def to_text(report: EvidenceReport) -> str:
    lines: List[str] = []
    root = report.root
    lines.append("SPDX OFFLINE EXTERNAL-REFERENCE EVIDENCE REPORT")
    lines.append("=" * 60)
    lines.append(f"Root document : {root.rel_path} ({root.format})")
    lines.append(f"Namespace     : {root.document_namespace}")
    lines.append(f"Root SHA-256  : {root.actual_sha256}")
    lines.append(f"Root sidecar  : {root.sidecar_status.value}")
    if root.sidecar_path:
        lines.append(f"Sidecar file  : {root.sidecar_path}")
    lines.append(f"External refs : {root.external_ref_count}")
    lines.append("")

    summary = report.to_dict()["summary"]
    lines.append("SUMMARY")
    lines.append("-" * 60)
    lines.append(f"edges total={summary['total_edges']} confirmed={summary['confirmed_edges']} "
                 f"unconfirmed={summary['unconfirmed_edges']} content_nodes={summary['content_nodes']}")
    lines.append("")

    lines.append("ALIAS CONVERGENCE (one original byte-identity, several aliases)")
    lines.append("-" * 60)
    converged = [node for node in report.nodes if len(node.aliases) > 1]
    if not converged:
        lines.append("(no content node is referenced by more than one alias)")
    for node in converged:
        lines.append(f"{node.content_id}")
        lines.append(f"  aliases : {', '.join(node.aliases)}")
        lines.append(f"  paths   : {', '.join(node.paths)}")
        lines.append(f"  edges   : {', '.join(node.edge_ids)}")
    lines.append("")

    lines.append("EDGES")
    lines.append("-" * 60)
    for edge in report.edges:
        badge = _STATUS_BADGE[edge.status]
        lines.append(
            f"{badge} {edge.edge_id} depth={edge.depth} {edge.document_ref_id} "
            f"-> {edge.status.value}"
        )
        lines.append(f"      uri       : {edge.document_uri}")
        lines.append(f"      claimed   : {edge.algorithm}:{edge.claimed_digest}")
        lines.append(f"      resolve   : {edge.resolution}"
                     + (f" ({edge.referenced_path})" if edge.referenced_path else ""))
        for candidate in edge.candidates:
            mark = "MATCH" if candidate.matches else "DIFFER"
            lines.append(
                f"      candidate : {candidate.rel_path} {candidate.algorithm}="
                f"{candidate.actual_digest} [{mark}]"
            )
        if edge.matching_content_path and edge.status.name == "VERIFIED_DIGEST":
            lines.append(f"      recovered : {edge.matching_content_path} (digest-only match)")
        if edge.matching_content_path and edge.status.name == "DIGEST_MISMATCH":
            lines.append(f"      recovered : {edge.matching_content_path} (claimed digest found elsewhere)")
        if edge.content_id:
            lines.append(f"      content   : {edge.content_id}")
        if edge.note:
            lines.append(f"      note      : {edge.note}")
    lines.append("")

    lines.append("CONTENT NODES")
    lines.append("-" * 60)
    for node in report.nodes:
        lines.append(f"{node.content_id}")
        lines.append(f"  aliases={node.aliases} paths={node.paths} edges={node.edge_ids}")

    if report.parse_errors:
        lines.append("")
        lines.append("PARSE ERRORS")
        lines.append("-" * 60)
        lines.extend(f"  {error}" for error in report.parse_errors)

    return "\n".join(lines) + "\n"
