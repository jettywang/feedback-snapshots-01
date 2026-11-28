"""Local-only regression tests for the archive evidence triage.

These use the curated `archive-recovery/` fixture set and the Sigstore
production/staging trust roots in offline mode. They require no network but
do need a writable HOME for the TUF target cache; the conftest `trust_home`
fixture provides one.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "archive-recovery"))

import recover  # noqa: E402

MANIFEST = ROOT / "archive-recovery" / "archive" / "manifest.json"


@pytest.fixture(scope="module")
def report(trust_home) -> dict:
    manifest = json.loads(MANIFEST.read_text())
    return {
        "blobs": [recover.judge_blob(e) for e in manifest["blobs"]],
        "orphans": [recover.judge_orphan(r) for r in manifest["orphan_evidence"]],
    }


def _by_blob(report: dict, blob: str) -> dict:
    return next(r for r in report["blobs"] if r["blob"] == blob)


def test_origin_proof_reattaches_to_record(report: dict) -> None:
    row = _by_blob(report, "blob-001.bin")
    assert row["signature"] == "PASS"
    assert row["digest_match"] is True
    assert row["reconnectable_to"].startswith("pypi_attestations-0.0.19.tar.gz @ sha256:")
    assert "GitHubPublisher" in row["origin"]


def test_signed_but_local_only_origin(report: dict) -> None:
    row = _by_blob(report, "blob-004.bin")
    assert row["signature"] == "PASS"
    assert row["digest_match"] is True
    assert row["origin"] == "no publishing record; signer identity known only locally"


def test_missing_proof_is_not_reconnected(report: dict) -> None:
    row = _by_blob(report, "blob-007.bin")
    assert row["signature"] == "NO_PROOF"
    assert row["reconnectable_to"] is None


def test_same_content_renamed_mirror_uses_subject_name(report: dict) -> None:
    row = _by_blob(report, "blob-005.bin")
    # Assigned name is normalized differently, but bytes + subject agree.
    assert row["name_exact_vs_assigned"] is False
    assert row["name_parsed_equal_vs_assigned"] is True
    assert row["digest_match"] is True
    assert row["reconnectable_to"].startswith("pypi_attestation_models-0.0.4a2.tar.gz @ sha256:")


def test_same_version_different_platform_is_distinct(report: dict) -> None:
    row = _by_blob(report, "blob-006.bin")
    # The blob is byte-identical to the any-wheel, but the assigned platform
    # tag differs; the signed subject (py3-none-any) is authoritative.
    assert row["name_parsed_equal_vs_assigned"] is False
    assert row["digest_match"] is True
    assert row["signed_subject_name"] == "rfc8785-0.1.2-py3-none-any.whl"


def test_orphan_evidence_waits_for_artifact(report: dict) -> None:
    row = report["orphans"][0]
    assert row["status"].startswith("ORPHAN")
    assert row["need"].startswith("the artifact bytes with sha256 ")
