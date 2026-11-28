#!/usr/bin/env python3
"""Validate publisher-registry/publishers.json and re-run its offline samples.

Exit code is 0 when every entry is internally consistent (approved entries
have no blocking findings, pending entries carry explicit reasons) and every
offline sample verifies. Offline samples are read from ../test/assets.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography import x509
from pydantic import TypeAdapter, ValidationError
from sigstore.models import Bundle

import pypi_attestations._impl as impl

HERE = Path(__file__).resolve().parent
ASSETS = HERE.parent / "test" / "assets"
REGISTRY_PATH = HERE / "publishers.json"

# Fields each provider's `_as_policy()` actually enforces. Anything registered
# outside these sets cannot participate in admission decisions.
ADMISSION_FIELDS = {
    "GitHub": {"repository", "workflow"},
    "GitLab": {"repository", "workflow_filepath"},
    "Google": {"email"},
    "CircleCI": {"project_id", "pipeline_definition_id", "vcs_origin", "vcs_ref"},
}

REQUIRED_FIELDS = {
    "GitHub": {"repository", "workflow"},
    "GitLab": {"repository", "workflow_filepath"},
    "Google": {"email"},
    "CircleCI": {"project_id", "pipeline_definition_id"},
}

# Declared on the publisher model but never consumed by `_as_policy()`.
DECLARED_UNENFORCED = {
    "GitHub": {"environment"},
    "GitLab": {"environment"},
}

# Optional boundary claims: enforced when present, silently absent otherwise.
OPTIONAL_CLAIMS = {"CircleCI": {"vcs_origin", "vcs_ref"}}

REASON_TEXT = {
    "unsupported-provider": "库未实现该提供方策略",
    "unenforced-declared-field": "字段已声明但不参与验签",
    "unknown-boundary-field": "边界字段不在该提供方的准入字段集内",
    "missing-required-field": "缺少必需准入字段",
    "optional-claim-absent": "可选边界声明未固定",
    "identity-only-boundary": "边界仅为身份级,无工作流级证明",
    "extension-shadows-admission": "供应商拓展字段与准入字段重名",
    "missing-offline-sample": "缺少可复核的离线样本",
}


def derive_findings(entry: dict) -> list[dict]:
    """Re-derive blocking/warning findings from the entry itself."""
    findings = []
    kind = entry.get("provider", {}).get("kind")
    boundary = entry.get("workflow_boundary", {})
    extensions = entry.get("vendor_extensions", {})

    if kind not in ADMISSION_FIELDS:
        findings.append({"level": "block", "code": "unsupported-provider", "field": "provider.kind"})
        return findings

    for field in REQUIRED_FIELDS[kind] - boundary.keys():
        findings.append({"level": "block", "code": "missing-required-field", "field": field})

    for field in boundary:
        if field in DECLARED_UNENFORCED.get(kind, set()):
            findings.append(
                {"level": "block", "code": "unenforced-declared-field", "field": field}
            )
        elif field not in ADMISSION_FIELDS[kind]:
            findings.append({"level": "block", "code": "unknown-boundary-field", "field": field})

    for field in OPTIONAL_CLAIMS.get(kind, set()):
        if boundary.get(field) is None:
            findings.append({"level": "warn", "code": "optional-claim-absent", "field": field})

    if kind == "Google":
        findings.append({"level": "warn", "code": "identity-only-boundary", "field": "email"})

    for field in extensions:
        if field in ADMISSION_FIELDS[kind] or field in DECLARED_UNENFORCED.get(kind, set()):
            findings.append(
                {"level": "block", "code": "extension-shadows-admission", "field": field}
            )

    if entry.get("status") == "approved" and "offline_sample" not in entry:
        findings.append({"level": "warn", "code": "missing-offline-sample", "field": None})

    return findings


def build_publisher(entry: dict) -> impl.Publisher:
    raw = {"kind": entry["provider"]["kind"], **entry["workflow_boundary"]}
    return TypeAdapter(impl.Publisher).validate_python(raw)


def run_offline_sample(entry: dict) -> str:
    sample = entry["offline_sample"]
    publisher = build_publisher(entry)
    fmt = sample["format"]

    if fmt == "x509-certificate":
        cert = x509.load_pem_x509_certificate((ASSETS / sample["certificate"]).read_bytes())
        publisher._as_policy().verify(cert)
        return "PASS"

    dist = impl.Distribution.from_file(ASSETS / sample["distribution"])
    if fmt == "sigstore-bundle":
        attestation = impl.Attestation.from_bundle(
            Bundle.from_json((ASSETS / sample["attestation"]).read_bytes())
        )
    elif fmt == "pep740-attestation":
        attestation = impl.Attestation.model_validate_json(
            (ASSETS / sample["attestation"]).read_bytes()
        )
    elif fmt == "pep740-provenance":
        provenance = impl.Provenance.model_validate_json(
            (ASSETS / sample["attestation"]).read_bytes()
        )
        attestation = provenance.attestation_bundles[0].attestations[0]
    else:
        return f"ERROR(unknown format {fmt})"

    attestation.verify(publisher, dist, offline=True)
    return "PASS"


def main() -> int:
    registry = json.loads(REGISTRY_PATH.read_text())
    rows = []
    ok = True

    for entry in registry["entries"]:
        entry_ok = True
        findings = derive_findings(entry)
        declared = {r["code"] for r in entry.get("pending_reasons", [])}
        derived_block = {f["code"] for f in findings if f["level"] == "block"}
        derived_warn = {f["code"] for f in findings if f["level"] == "warn"}

        if entry["status"] == "approved" and derived_block:
            entry_ok = False
        if entry["status"] == "pending" and not (declared | derived_block):
            entry_ok = False
        # Every derived blocker must be explained by a declared pending reason.
        unexplained = derived_block - declared
        if unexplained:
            entry_ok = False

        sample_result = "-"
        if "offline_sample" in entry:
            try:
                sample_result = run_offline_sample(entry)
            except (ValidationError, impl.VerificationError, Exception) as exc:  # noqa: BLE001
                sample_result = f"FAIL({type(exc).__name__})"
                entry_ok = False

        notes = []
        for code in sorted(derived_block | derived_warn):
            fields = sorted({f["field"] for f in findings if f["code"] == code and f["field"]})
            label = code + (f"({', '.join(fields)})" if fields else "")
            notes.append(("⛔ " if code in derived_block else "⚠️ ") + label)
        if entry["status"] == "pending" and unexplained:
            notes.append("⛔ 待查原因未登记: " + ", ".join(sorted(unexplained)))

        rows.append(
            (
                entry["id"],
                entry["provider"]["kind"],
                entry["status"],
                sample_result,
                "<br>".join(notes) if notes else "—",
            )
        )
        ok = ok and entry_ok

    print("| 登记条目 | 提供方 | 状态 | 离线样本复核 | 检查发现 |")
    print("| --- | --- | --- | --- | --- |")
    for row in rows:
        print("| " + " | ".join(row) + " |")

    print()
    print("待查原因码:")
    for code, text in REASON_TEXT.items():
        print(f"- `{code}`: {text}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
