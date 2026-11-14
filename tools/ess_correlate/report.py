"""Render the correlation report as human-readable Markdown."""

from __future__ import annotations

from typing import Dict, Iterable, List, Sequence


def _yes(value) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "?"


def _cell(value) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = str(value)
    return text.replace("|", "\\|")


def _table(headers: Sequence[str], rows: Iterable[Sequence]) -> List[str]:
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("|" + "|".join("---" for _ in headers) + "|")
    for row in rows:
        lines.append("| " + " | ".join(_cell(item) for item in row) + " |")
    return lines


def render_markdown(report: Dict) -> str:
    lines: List[str] = ["# S/MIME ESS signed-receipt correlation report", ""]
    lines.append(
        "All signature and certificate-status outcomes come from explicit attestation input. "
        "This report never performs cryptographic verification and never upgrades an unknown "
        "status."
    )
    lines.append("")

    lines.append("## Identical body digests")
    groups = report.get("identicalBodyGroups", [])
    if groups:
        lines.extend(
            _table(
                ["body SHA-256", "messages"],
                [(group["bodySha256"], ", ".join(group["messages"])) for group in groups],
            )
        )
    else:
        lines.append("No two archived messages share an identical body digest.")
    lines.append("")

    lines.append("## Receipts: three cumulative levels")
    rows = []
    for item in report.get("receipts", []):
        levels = item.get("levels", {})
        matched = item.get("matched") or {}
        rows.append(
            [
                item["receipt"],
                matched.get("message") or "—",
                matched.get("signer") or "—",
                "yes" if levels.get("signatureLocated") else "no",
                "yes" if levels.get("receiptTrusted") else "no",
                "yes" if levels.get("expectedRecipientConfirmed") else "no",
            ]
        )
    lines.extend(
        _table(
            ["receipt", "matched message", "matched signer", "L1 signature located", "L2 receipt trusted", "L3 recipient confirmed"],
            rows,
        )
    )
    lines.append("")

    lines.append("## Field-by-field linkage")
    rows = []
    for item in report.get("receipts", []):
        link = (item.get("matched") or {}).get("link", {}).get("matched", {})
        msg = item.get("receiptSigner", {})
        details = item.get("levelDetails", {})
        msg_check = {
            check["name"]: check
            for check in details.get("receiptTrusted", {}).get("checks", [])
        }.get("msgSigDigest over matched SignerInfo SignedAttributes", {})
        rows.append(
            [
                item["receipt"],
                _yes(link.get("contentType")),
                _yes(link.get("signedContentIdentifier")),
                _yes(link.get("originatorSignatureValue")),
                _cell(msg.get("msgSigDigest")),
                _cell(msg_check.get("computed")),
                _yes(msg_check.get("ok")),
            ]
        )
    lines.extend(
        _table(
            [
                "receipt",
                "Receipt.contentType = signer contentType",
                "signedContentIdentifier = request/identifier",
                "originatorSignatureValue = SignerInfo.signature",
                "receipt msgSigDigest",
                "recomputed SignedAttributes digest",
                "match",
            ],
            rows,
        )
    )
    lines.append("")

    lines.append("## Field evidence ledger")
    for item in report.get("receipts", []):
        lines.append("### %s" % item["receipt"])
        lines.append("")
        fields = item.get("receiptFields", {})
        lines.append(
            "- `Receipt.version` = %s; `Receipt.contentType` = %s; "
            "`Receipt.signedContentIdentifier` = %s; "
            "`Receipt.originatorSignatureValue` = %s"
            % (
                fields.get("version"),
                fields.get("contentType"),
                fields.get("signedContentIdentifier"),
                fields.get("originatorSignatureValue"),
            )
        )
        signer = item.get("receiptSigner", {})
        lines.append(
            "- receipt SignerInfo: `messageDigest` = %s; `msgSigDigest` = %s; "
            "`digestAlgorithm` = %s; `signatureAlgorithm` = %s; cert emails = %s"
            % (
                signer.get("messageDigest"),
                signer.get("msgSigDigest"),
                signer.get("digestAlgorithm"),
                signer.get("signatureAlgorithm"),
                ", ".join(signer.get("certificateEmails") or []) or "—",
            )
        )
        link = (item.get("matched") or {}).get("link", {}).get("checks", {})
        for key, check in link.items():
            lines.append(
                "- `%s` %s: observed `%s` vs expected `%s` → %s"
                % (
                    check.get("path"),
                    check.get("field"),
                    check.get("observed"),
                    check.get("expected"),
                    _yes(check.get("match")),
                )
            )
        for check in item.get("closest", [])[:1]:
            lines.append(
                "- closest candidate %s %s: %s checked fields match"
                % (check["message"], check["signer"], check["score"])
            )
            for key, field in check["checks"].items():
                if field.get("match") is False:
                    lines.append(
                        "- mismatch `%s` %s: observed `%s` vs expected `%s`"
                        % (
                            field.get("path"),
                            field.get("field"),
                            field.get("observed"),
                            field.get("expected"),
                        )
                    )
        l2 = item.get("levelDetails", {}).get("receiptTrusted", {})
        for check in l2.get("checks", []):
            if check.get("computed") is None and check.get("observed") is None:
                continue
            lines.append(
                "- L2 `%s`%s: observed `%s`; computed `%s`; algorithm `%s`; ok=%s%s"
                % (
                    check.get("name"),
                    (" at `%s`" % check["path"]) if check.get("path") else "",
                    check.get("observed"),
                    check.get("computed"),
                    check.get("algorithm"),
                    _yes(check.get("ok")),
                    ("; " + check["detail"]) if check.get("detail") else "",
                )
            )
        l3 = item.get("levelDetails", {}).get("expectedRecipientConfirmed", {})
        evaluation = l3.get("recipientEvaluation", {})
        lines.append(
            "- L3 recipient evaluation: status=%s; identityBasis=%s; matched=%s; reasons=%s"
            % (
                evaluation.get("status"),
                evaluation.get("identityBasis"),
                ", ".join(evaluation.get("matchedNames") or []) or "—",
                "; ".join(evaluation.get("reasons") or []) or "—",
            )
        )
        for scope in l3.get("scope", []):
            lines.append("- L3 scope evidence: `%s`" % (scope,))
        lines.append("")

    lines.append("## Per-receipt conclusions")
    for item in report.get("receipts", []):
        lines.append("### %s" % item["receipt"])
        lines.append("")
        lines.append(item.get("conclusion", ""))
        lines.append("")
        for level, label in (
            ("signatureLocated", "1. signature located"),
            ("receiptTrusted", "2. receipt trusted"),
            ("expectedRecipientConfirmed", "3. expected recipient confirmed"),
        ):
            detail = item.get("levelDetails", {}).get(level, {})
            lines.append("- **%s**: %s" % (label, detail.get("status", "blocked")))
            notes = detail.get("note")
            if notes:
                lines.append("  - %s" % notes)
        if item.get("parseIssues"):
            lines.append("- parse issues: %s" % "; ".join(item["parseIssues"]))
        lines.append("")

    lines.append("## Controls")
    for control in report.get("controls", []):
        lines.append("### %s" % control["control"])
        lines.append("")
        lines.append(control.get("finding", ""))
        lines.append("")
        for observation in control.get("observations", []) or []:
            levels = observation.get("levels") or {}
            lines.append(
                "- %s → %s; L1=%s L2=%s L3=%s"
                % (
                    observation.get("receipt"),
                    observation.get("matched") or "no match",
                    levels.get("signatureLocated"),
                    levels.get("receiptTrusted"),
                    levels.get("expectedRecipientConfirmed"),
                )
            )
        for case in control.get("cases", []) or []:
            if "receiptOutcomes" in case:
                for outcome in case["receiptOutcomes"]:
                    levels = outcome.get("levels") or {}
                    lines.append(
                        "- %s via %s: recipient=%s; L1=%s L2=%s L3=%s"
                        % (
                            outcome["receipt"],
                            ", ".join(outcome.get("receiptSigner") or []) or "unknown",
                            outcome.get("recipientStatus"),
                            levels.get("signatureLocated"),
                            levels.get("receiptTrusted"),
                            levels.get("expectedRecipientConfirmed"),
                        )
                    )
            elif "receipt" in case:
                levels = case.get("levels") or {}
                lines.append(
                    "- %s missing %s: L1=%s L2=%s L3=%s"
                    % (
                        case["receipt"],
                        case.get("missingField"),
                        levels.get("signatureLocated"),
                        levels.get("receiptTrusted"),
                        levels.get("expectedRecipientConfirmed"),
                    )
                )
        for message in control.get("messages", []) or []:
            if "signers" in message:
                for signer in message["signers"]:
                    lines.append(
                        "- %s %s receiptRequest=%s verification=%s receipts=%s"
                        % (
                            message["message"],
                            signer["signer"],
                            signer["receiptRequest"],
                            signer["verification"],
                            ", ".join(signer.get("receiptsLocatingIt") or []) or "none",
                        )
                    )
            elif "layers" in message:
                lines.append(
                    "- %s layers=%s outer=%s inner=%s"
                    % (
                        message["message"],
                        message["layers"],
                        [entry["status"] for entry in message["outerSignerStatus"]],
                        [entry["status"] for entry in message["innerSignerStatus"]],
                    )
                )
        lines.append("")

    lines.append("## Method")
    method = report.get("method", {})
    for key, value in method.items():
        lines.append("- `%s`: %s" % (key, value))
    lines.append("")
    return "\n".join(lines)
