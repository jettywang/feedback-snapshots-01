"""Behavioural tests for the offline external-reference evidence chain."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from offline_evidence.builder import build_evidence
from offline_evidence.model import EdgeStatus, RootStatus
from offline_evidence.reporters import to_csv, to_json, to_text

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIX = PROJECT_ROOT / "fixtures"
OFFLINE = FIX / "offline"
MANIFESTS = FIX / "manifests"


@pytest.fixture(scope="module")
def json_report():
    return build_evidence(MANIFESTS / "root-manifest.spdx.json", [OFFLINE, MANIFESTS])


@pytest.fixture(scope="module")
def tag_report():
    return build_evidence(MANIFESTS / "root-manifest.spdx", [OFFLINE, MANIFESTS])


def _edge(report, ref_id):
    matches = [edge for edge in report.edges if edge.document_ref_id == ref_id]
    assert matches, f"edge {ref_id} not found"
    return matches[0]


def test_root_is_independently_verifiable(json_report):
    root = json_report.root
    assert root.sidecar_status == RootStatus.SIDECAR_MATCH
    assert root.actual_sha256 and len(root.actual_sha256) == 64
    sidecar = Path(root.sidecar_path).read_text(encoding="utf-8").split()[0]
    assert sidecar == root.actual_sha256


def test_two_aliases_converge_on_one_content_node(json_report):
    alpha = _edge(json_report, "DocumentRef-alpha")
    alias = _edge(json_report, "DocumentRef-alpha-alias")
    assert alpha.status == EdgeStatus.VERIFIED
    assert alias.status == EdgeStatus.VERIFIED
    assert alpha.content_id == alias.content_id
    node = next(node for node in json_report.nodes if node.content_id == alpha.content_id)
    assert set(node.aliases) == {"DocumentRef-alpha", "DocumentRef-alpha-alias"}
    assert set(node.paths) == {"component-a.spdx.json", "mirror/component-a.spdx.json"}


def test_colliding_basename_is_decided_by_per_edge_digest(json_report):
    collision = _edge(json_report, "DocumentRef-collision")
    assert collision.status == EdgeStatus.VERIFIED
    candidate = next(c for c in collision.candidates if c.matches)
    assert candidate.rel_path == "other-vendor/component-a.spdx.json"
    # The other same-named file must remain a distinct content node.
    alpha = _edge(json_report, "DocumentRef-alpha")
    assert collision.content_id != alpha.content_id


def test_tampered_target_is_digest_mismatch(json_report):
    gamma = _edge(json_report, "DocumentRef-gamma")
    assert gamma.status == EdgeStatus.DIGEST_MISMATCH
    assert gamma.confirmed is False
    assert len(gamma.candidates) == 1
    assert gamma.candidates[0].matches is False
    assert gamma.claimed_digest != gamma.candidates[0].actual_digest


def test_missing_file_is_reported_missing(json_report):
    delta = _edge(json_report, "DocumentRef-delta")
    assert delta.status == EdgeStatus.MISSING
    assert delta.confirmed is False
    assert delta.candidates == []


def test_renamed_original_recovered_by_digest(json_report):
    epsilon = _edge(json_report, "DocumentRef-epsilon")
    assert epsilon.status == EdgeStatus.VERIFIED_DIGEST
    assert epsilon.matching_content_path == "renamed/lib-moved.spdx.json"
    assert epsilon.confirmed is True


def test_non_local_uri_is_flagged(json_report):
    zeta = _edge(json_report, "DocumentRef-zeta")
    assert zeta.status == EdgeStatus.NON_LOCAL_URI
    assert zeta.confirmed is False


def test_unsupported_algorithm_is_unprovable(json_report):
    eta = _edge(json_report, "DocumentRef-eta")
    assert eta.status == EdgeStatus.UNSUPPORTED_ALGORITHM
    assert eta.confirmed is False


def test_transitive_reference_is_followed(json_report):
    libbeta = _edge(json_report, "DocumentRef-libbeta")
    assert libbeta.depth == 1
    assert libbeta.status == EdgeStatus.VERIFIED
    assert libbeta.source_document.endswith("dep-chain.spdx.json")


def test_tag_value_manifest_matches_json_on_shared_edges(tag_report, json_report):
    json_status = {e.document_ref_id: e.status for e in json_report.edges}
    tag_status = {e.document_ref_id: e.status for e in tag_report.edges}
    # Tag-Value cannot carry the MD4 edge; every shared edge must agree.
    assert "DocumentRef-eta" not in tag_status
    for ref_id, status in tag_status.items():
        assert json_status[ref_id] == status
    tag_aliases = next(
        node for node in tag_report.nodes if len(node.aliases) > 1
    )
    assert set(tag_aliases.aliases) == {"DocumentRef-alpha", "DocumentRef-alpha-alias"}


def test_reports_render_in_three_formats(json_report):
    payload = json.loads(to_json(json_report))
    assert payload["summary"]["total_edges"] == len(json_report.edges)
    text = to_text(json_report)
    assert "ALIAS CONVERGENCE" in text and "DocumentRef-alpha-alias" in text
    csv_text = to_csv(json_report)
    assert csv_text.splitlines()[0].startswith("edge_id,")
    # One CSV row per candidate (plus a single row for edges without candidates).
    assert csv_text.count("DocumentRef-gamma") == 1
