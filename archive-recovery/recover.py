"""Local-only evidence triage for a migrated artifact archive.

Design rules:
  * The bytes and the signed material are the only authorities.
  * The migration-assigned filename is a hint, never a fact.
  * Signature validity, signed-subject filename, content digest, and
    publishing origin are reported as four INDEPENDENT conclusions.

Run: python archive-recovery/recover.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography import x509
from pypi_attestations import Attestation, Distribution, Provenance
from sigstore.models import Bundle
from sigstore.verify import policy

ROOT = Path(__file__).resolve().parent
ARCHIVE = ROOT / "archive"

_CLAIM_ISSUER = "1.3.6.1.4.1.57264.1.8"
_CLAIM_BUILD_CONFIG = "1.3.6.1.4.1.57264.1.18"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_attestation(path: Path) -> Attestation:
    if path.name.endswith(".sigstore"):
        return Attestation.from_bundle(Bundle.from_json(path.read_bytes()))
    return Attestation.model_validate_json(path.read_bytes())


def parsed_name(name: str) -> tuple[str, ...]:
    from packaging.utils import parse_sdist_filename, parse_wheel_filename

    if name.endswith(".whl"):
        n, v, b, tags = parse_wheel_filename(name)
        return ("wheel", str(n), str(v), str(b), tuple(sorted(str(t) for t in tags)))
    n, v = parse_sdist_filename(name)
    return ("sdist", str(n), str(v))


def signer_identity(att: Attestation) -> tuple[str, str]:
    cert = x509.load_der_x509_certificate(att.verification_material.certificate)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    identity = next(
        n.value for n in san
        if isinstance(n, (x509.DNSName, x509.RFC822Name, x509.UniformResourceIdentifier))
    )
    issuer = att.certificate_claims.get(_CLAIM_ISSUER)
    if issuer is None:
        raise ValueError("certificate has no OIDC issuer claim")
    return identity, issuer


def attestations_from_provenance(path: Path) -> list[Attestation]:
    prov = Provenance.model_validate_json(path.read_bytes())
    return [a for b in prov.attestation_bundles for a in b.attestations]


def evidence_attestations(evidence: list[str]) -> list[tuple[str, Attestation]]:
    out: list[tuple[str, Attestation]] = []
    for rel in evidence:
        p = ROOT / rel
        if p.name.endswith(".provenance"):
            for i, a in enumerate(attestations_from_provenance(p)):
                out.append((f"{rel}#{i}", a))
        else:
            out.append((rel, load_attestation(p)))
    return out


def judge_blob(entry: dict[str, Any]) -> dict[str, Any]:
    blob = ARCHIVE / entry["blob"]
    digest = sha256(blob)
    assigned = entry["assigned_name"]
    staging = entry.get("staging", False)
    result: dict[str, Any] = {
        "blob": entry["blob"],
        "assigned_name": assigned,
        "sha256": digest,
        "signature": "NO_PROOF",
        "signed_subject_name": None,
        "subject_digest": None,
        "name_exact_vs_assigned": None,
        "name_parsed_equal_vs_assigned": None,
        "digest_match": None,
        "origin": "no proof",
        "matched_evidence": None,
        "reconnectable_to": None,
    }
    if not entry["evidence"]:
        result["need"] = "no attestation/sigstore/provenance migrated; obtain the publisher's signed material"
        return result

    cands = evidence_attestations(entry["evidence"])
    # Match by CONTENT DIGEST only; the assigned name is not used to select.
    matches = [(rid, a) for rid, a in cands if a.statement["subject"][0]["digest"].get("sha256") == digest]
    if not matches:
        result["signature"] = "DIGEST_MISMATCH"
        result["need"] = "none of the kept proofs cover these bytes; do not attach"
        return result

    rid, att = matches[0]
    subject = att.statement["subject"][0]
    result["matched_evidence"] = rid
    result["signed_subject_name"] = subject["name"]
    result["subject_digest"] = subject["digest"].get("sha256")
    result["digest_match"] = subject["digest"].get("sha256") == digest
    result["name_exact_vs_assigned"] = subject["name"] == assigned
    try:
        result["name_parsed_equal_vs_assigned"] = parsed_name(subject["name"]) == parsed_name(assigned)
    except Exception:
        result["name_parsed_equal_vs_assigned"] = "unparseable assigned name"

    # Independent: does the signature verify under the recorded signer identity?
    identity, issuer = signer_identity(att)
    result["signer_identity"] = identity
    result["signer_issuer"] = issuer
    try:
        # The blob's stored name is opaque; the only trustworthy pairing is
        # (signed subject name, bytes measured here). Build the Distribution
        # from the subject, not from the migration-assigned name.
        probe = Distribution(name=subject["name"], digest=digest)
        att.verify(
            policy.Identity(identity=identity, issuer=issuer),
            probe,
            staging=staging,
            offline=True,
        )
        result["signature"] = "PASS"
    except Exception as exc:  # noqa: BLE001 - report, never raise
        result["signature"] = f"FAIL: {type(exc).__name__}: {exc}"

    # Independent: publishing origin record, if any.
    prov_paths = [ROOT / e for e in entry["evidence"] if e.endswith(".provenance")]
    if prov_paths:
        publisher = Provenance.model_validate_json(prov_paths[0].read_bytes()).attestation_bundles[0].publisher
        result["origin"] = f"provenance record: {publisher!r}"
    else:
        result["origin"] = "no publishing record; signer identity known only locally"

    # Verdict.
    if result["signature"] != "PASS":
        result["reconnectable_to"] = None
        result["need"] = "signature does not verify; escalate to publisher/archivist"
    elif not result["digest_match"]:
        result["reconnectable_to"] = None
        result["need"] = "digest mismatch; do not attach"
    else:
        note = "subject name matches assigned name" if result["name_exact_vs_assigned"] else "subject name DIFFERS from assigned name (attach by subject, not assigned)"
        result["reconnectable_to"] = f"{subject['name']} @ sha256:{subject['digest']['sha256']}"
        result["need"] = "none" if prov_paths else "optional: obtain publisher provenance to confirm origin"
        result["name_note"] = note
    return result


def judge_orphan(rel: str) -> dict[str, Any]:
    att = load_attestation(ROOT / rel)
    subject = att.statement["subject"][0]
    identity, issuer = signer_identity(att)
    return {
        "evidence": rel,
        "signed_subject_name": subject["name"],
        "subject_digest": subject["digest"].get("sha256"),
        "signer_identity": identity,
        "signer_issuer": issuer,
        "origin": "no publishing record; signer identity known only locally",
        "status": "ORPHAN: no archived blob matches this digest",
        "need": "the artifact bytes with sha256 " + subject["digest"].get("sha256", "?"),
    }


def main() -> None:
    manifest = json.loads((ARCHIVE / "manifest.json").read_text())
    report = {
        "blobs": [judge_blob(e) for e in manifest["blobs"]],
        "orphans": [judge_orphan(rel) for rel in manifest.get("orphan_evidence", [])],
    }
    out = ROOT / "recovery-report.json"
    out.write_text(json.dumps(report, indent=2))
    for row in report["blobs"]:
        print(
            f"{row['blob']:<11} sig={row['signature']:<70.70} "
            f"reconnect={row.get('reconnectable_to')}"
        )
        if row.get("name_note"):
            print(f"            note: {row['name_note']}")
    for row in report["orphans"]:
        print(f"ORPHAN      {row['signed_subject_name']} -> {row['status']}")
    print(f"\nfull report: {out}")


if __name__ == "__main__":
    main()
