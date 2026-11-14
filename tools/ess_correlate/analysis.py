"""Three-level correlation of ESS signed receipts to archived signatures.

Level 1 — signature located
    Receipt.contentType, Receipt.signedContentIdentifier and
    Receipt.originatorSignatureValue reproduce, byte for byte, the fields of
    exactly one SignerInfo that carried an id-aa-receiptRequest.  This is a
    structural link only; no verification is implied.

Level 2 — receipt trusted
    Level 1 plus the receipt's own signature status (supplied input) is
    valid, its certificate chain is trusted (supplied input), the Receipt
    content digest matches the receipt's messageDigest attribute, and the
    receipt's msgSigDigest equals a fresh digest of that exact SignerInfo's
    SignedAttributes.  This authenticates the receipt and binds it to the
    signer's signed attributes, but says nothing about whether the original
    signature verified or whether the right recipient replied.

Level 3 — expected recipient confirmed
    Level 2 plus the original signer's signature status (supplied input) is
    valid and the receipt signer is an expected responder under the
    ReceiptRequest scope and any mailing-list receipt policy.  Only this
    level supports "the expected recipient received this signed message".

An unknown input can never satisfy a level.  No level is inferred from body
equality or from the mere presence of a document.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from pyasn1_modules import rfc2634, rfc5652

from .model import (
    Attestations,
    DecodeError,
    MessageRecord,
    ReceiptRecord,
    STATUS_VALID,
    TRUST_TRUSTED,
    canonical_name,
    decode_message,
    decode_receipt,
    digest_for_oid,
    effective_history,
    general_names_texts,
    layer_history,
    ml_data_summary,
    receipt_request_names,
    receipts_to_names,
)

DOMAIN = "S/MIME ESS signed receipt correlation"

LEVEL_NAMES = ("signatureLocated", "receiptTrusted", "expectedRecipientConfirmed")

_EMAIL_HEADER = re.compile(r"^(to|cc):\s*(.*)$", re.IGNORECASE | re.MULTILINE)
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+")


@dataclass(frozen=True)
class CaseInputs:
    """Archive contents plus explicit verification attestations."""

    messages: Mapping[str, bytes]
    receipts: Mapping[str, bytes]
    attestations: Attestations


def _citation(path: str, field: str, observed, expected=None, matched: Optional[bool] = None) -> Dict:
    citation = {"path": path, "field": field, "observed": observed}
    if expected is not None:
        citation["expected"] = expected
    if matched is not None:
        citation["match"] = matched
    return citation


def _value_text(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if hasattr(value, "asOctets") and hasattr(value, "isValue"):
        try:
            return str(value)
        except Exception:
            return repr(value)
    return str(value)


def body_recipients(body: Optional[bytes]) -> Tuple[str, ...]:
    """Extract To/Cc addresses from the archived body headers.

    This is artifact inspection, not verification.  It is used only to
    identify the claimed recipient for level 3, and is reported with its
    provenance.
    """

    if body is None:
        return ()
    try:
        text = body.decode("utf-8", "replace")
    except Exception:  # pragma: no cover - decode never raises with replace
        return ()
    found: List[str] = []
    for header, value in _EMAIL_HEADER.findall(text):
        for email in _EMAIL.findall(value):
            lowered = email.lower()
            if lowered not in found:
                found.append(lowered)
    return tuple(found)


def _digest_name(signer) -> Tuple[Optional[bytes], Optional[str]]:
    """Digest of the signer's SignedAttributes using the signer's algorithm."""

    if signer.signed_attributes_der is None:
        return None, "SignedAttributes are absent, so msgSigDigest cannot be recomputed"
    return digest_for_oid(signer.digest_algorithm, signer.signed_attributes_der)


def _receipt_content_digest(receipt: ReceiptRecord) -> Tuple[Optional[bytes], Optional[str]]:
    return digest_for_oid(receipt.signer.digest_algorithm, receipt.receipt_content_der)


def _field_link(receipt: ReceiptRecord, signer) -> Dict:
    """Byte-level three-field comparison; no verification attached."""

    request = signer.receipt_request
    content_type_attr = signer.content_type
    receipt_content_type = receipt.content_type
    expected_identifier = (
        bytes(request["signedContentIdentifier"])
        if request is not None
        else signer.content_identifier
    )

    signed_attrs_present = signer.signed_attributes_der is not None
    checks = {
        "signedAttrsPresent": _citation(
            signer.path + ".signedAttrs",
            "SignedAttributes presence",
            "present" if signed_attrs_present else "absent",
            "present",
            signed_attrs_present,
        ),
        "contentType": _citation(
            signer.path + ".signedAttrs " + str(rfc5652.id_contentType),
            "contentType attribute",
            _value_text(content_type_attr),
            receipt_content_type,
            None if content_type_attr is None else content_type_attr == receipt_content_type,
        ),
        "signedContentIdentifier": _citation(
            signer.path + ".signedAttrs " + str(rfc2634.id_aa_receiptRequest),
            "receiptRequest.signedContentIdentifier (or contentIdentifier when absent)",
            _value_text(expected_identifier),
            _value_text(receipt.signed_content_identifier),
            None if expected_identifier is None else expected_identifier == receipt.signed_content_identifier,
        ),
        "originatorSignatureValue": _citation(
            signer.path + ".signature",
            "SignerInfo.signature",
            _value_text(signer.signature),
            _value_text(receipt.originator_signature_value),
            signer.signature == receipt.originator_signature_value,
        ),
    }
    matched = {
        "signedAttrsPresent": signed_attrs_present,
        "contentType": None if content_type_attr is None else content_type_attr == receipt_content_type,
        "signedContentIdentifier": None
        if expected_identifier is None
        else expected_identifier == receipt.signed_content_identifier,
        "originatorSignatureValue": signer.signature == receipt.originator_signature_value,
    }
    return {"checks": checks, "matched": matched}


def _envelope_checks(receipt: ReceiptRecord) -> List[Dict]:
    checks = []
    outer = receipt.envelope
    signed_data = outer.econtent_type
    checks.append(
        _citation(
            receipt.name + ": SignedData.encapContentInfo.eContentType",
            "eContentType",
            signed_data,
            str(rfc2634.id_ct_receipt),
            signed_data == str(rfc2634.id_ct_receipt),
        )
    )
    checks.append(
        _citation(
            receipt.name + ": Receipt.version",
            "version",
            str(receipt.version),
            "v1 (1)",
            receipt.version == 1,
        )
    )
    rt = receipt.signer.content_type
    checks.append(
        _citation(
            receipt.name + ": signerInfos[0].signedAttrs contentType",
            "contentType",
            _value_text(rt),
            str(rfc2634.id_ct_receipt),
            rt == str(rfc2634.id_ct_receipt),
        )
    )
    has_rr = receipt.signer.receipt_request is not None
    checks.append(
        _citation(
            receipt.name + ": signerInfos[0].signedAttrs receiptRequest",
            "id-aa-receiptRequest presence",
            "present" if has_rr else "absent",
            "absent (RFC 2634 section 2.2)",
            not has_rr,
        )
    )
    checks.append(
        _citation(
            receipt.name + ": Receipt.contentType",
            "contentType",
            receipt.content_type,
            "originator contentType attribute",
        )
    )
    return checks


def _write_receipt_checks(receipt: ReceiptRecord) -> List[Dict]:
    checks = []
    signer = receipt.signer
    content_digest, content_error = _receipt_content_digest(receipt)
    checks.append(
        {
            "name": "receipt content digest",
            "path": receipt.name + ": signerInfos[0].signedAttrs messageDigest",
            "algorithm": signer.digest_algorithm,
            "status": "ok" if content_digest is not None else "unsupported",
            "detail": content_error,
            "observed": _value_text(signer.message_digest),
            "computed": _value_text(content_digest),
            "matched": None if content_digest is None else content_digest == signer.message_digest,
        }
    )
    return checks


def _recipient_scope(receipt: ReceiptRecord, message: MessageRecord, signer) -> Tuple[Dict, ...]:
    request = signer.receipt_request
    if request is None:
        return (
            {
                "scope": "none",
                "status": "not_requested",
                "detail": "匹配的 SignerInfo 没有 ReceiptRequest",
            },
        )
    scope = request["receiptsFrom"].getName()
    entries: List[Dict] = []
    if scope == "receiptList":
        entries.append(
            {
                "scope": "receiptList",
                "names": [
                    {"kind": kind, "value": value}
                    for kind, value in receipt_request_names(request)
                ],
            }
        )
    else:
        entries.append(
            {
                "scope": "allOrFirstTier",
                "value": str(request["receiptsFrom"]["allOrFirstTier"]),
            }
        )

    layer, history, history_der, conflict = effective_history(message)
    if layer is None:
        entries.append(
            {
                "scope": "mlExpansionHistory",
                "status": "absent",
                "detail": "最外层 SignedData 没有任何签名者携带 mlExpansionHistory",
            }
        )
    else:
        last = history[-1]
        policy = last["mlReceiptPolicy"]
        kind = policy.getName() if policy.isValue else None
        summary = ml_data_summary(history)
        entries.append(
            {
                "scope": "mlExpansionHistory",
                "layer": layer.path,
                "history": summary,
                "policyKind": kind,
                "policyNames": [
                    {"kind": name_kind, "value": value}
                    for entry in (policy[kind] if kind in ("insteadOf", "inAdditionTo") else ())
                    for name_kind, value in general_names_texts(entry)
                ],
                "conflictAcrossSigners": conflict,
            }
        )
    return tuple(entries)


def _expected_recipient(
    receipt: ReceiptRecord,
    message: MessageRecord,
    signer,
    attestation_names: Tuple[str, ...],
    identity_basis: str,
) -> Dict:
    """Evaluate RFC 2634 section 2.3 responder scope plus identity evidence."""

    result: Dict = {
        "status": "unconfirmed",
        "identity": list(attestation_names),
        "identityBasis": identity_basis,
        "attestationSuppliedIdentity": bool(attestation_names),
        "reasons": [],
        "scope": [],
    }
    request = signer.receipt_request
    if request is None:
        result["status"] = "not_requested"
        result["reasons"].append(
            "匹配的 SignerInfo 上没有 ReceiptRequest 属性（RFC 2634 第 2.3 节：未请求则不得生成回执）；"
            "回执仍可与该签名者的字节关联，但不能解释为被请求的投递确认"
        )
        return result

    layer, history, _, conflict = effective_history(message)
    if layer is not None and history is not None:
        last = history[-1]
        policy = last["mlReceiptPolicy"]
        policy_kind = policy.getName() if policy.isValue else None
        result["scope"].append(
            {
                "path": layer.path + ".signerInfos[*].signedAttrs mlExpansionHistory[-1].mlReceiptPolicy",
                "kind": policy_kind,
            }
        )
        if policy_kind == "none":
            result["status"] = "blocked"
            result["reasons"].append(
                "mlReceiptPolicy 为 none：RFC 2634 第 2.3 节步骤 1.2.1 规定必须不生成回执"
            )
            return result
        if conflict:
            result["status"] = "blocked"
            result["reasons"].append(
                "同一层已验证签名者对 mlExpansionHistory 的取值不一致：RFC 2634 第 2.3 节禁止返回回执"
            )
            return result

    if not identity_basis.startswith("attestation"):
        result["status"] = "identity_unverified"
        result["reasons"].append(
            "回执签名者身份仅来自其自带的证书，未由验签输入确认；不能升级为预期收件人"
        )
        return result

    scope = request["receiptsFrom"].getName()
    if scope == "receiptList":
        listed = [canonical_name(kind, value) for kind, value in receipt_request_names(request)]
        supplied = [canonical_name("rfc822Name", value) for value in attestation_names]
        result["scope"].append(
            {
                "path": signer.path + ".signedAttrs receiptRequest.receiptsFrom.receiptList",
                "names": listed,
            }
        )
        if not attestation_names:
            result["reasons"].append(
                "回执签名者身份未知，无法判断是否在 receiptList 中"
            )
            return result
        if any(name in listed for name in supplied):
            matched = [name for name in supplied if name in listed]
            result["status"] = "confirmed"
            result["matchedNames"] = matched
            result["reasons"].append("回执签名者出现在 receiptRequest.receiptsFrom.receiptList 中")
            return result
        result["status"] = "unexpected_recipient"
        result["reasons"].append(
            "回执签名者不在 receiptList 中：RFC 2634 第 2.3 节步骤 3.2 规定必须不生成回执"
        )
        return result

    if scope == "allOrFirstTier":
        value = request["receiptsFrom"]["allOrFirstTier"]
        if int(value) == 1:
            value = "firstTierRecipients"
        else:
            value = "allReceipts"
        result["scope"].append(
            {
                "path": signer.path + ".signedAttrs receiptRequest.receiptsFrom.allOrFirstTier",
                "value": value,
            }
        )
        if value == "firstTierRecipients" and layer is not None:
            result["status"] = "blocked"
            result["reasons"].append(
                "receiptsFrom 为 firstTierRecipients 且存在 mlExpansionHistory：RFC 2634 第 2.3 节步骤 2.2.1 规定必须不生成回执"
            )
            return result
        if not attestation_names:
            result["reasons"].append(
                "receipt signer identity is unknown; recipient set cannot be tested"
            )
            return result

        claimed_recipients = [canonical_name("rfc822Name", value) for value in body_recipients(message.body)]
        originator_names = []
        if signer.certificate is not None:
            originator_names = [canonical_name("rfc822Name", email) for email in signer.certificate.emails]
        supplied = [canonical_name("rfc822Name", value) for value in attestation_names]
        result["claimedRecipients"] = [
            {"source": "archived body To/Cc", "names": claimed_recipients}
        ]
        if claimed_recipients and any(name in claimed_recipients for name in supplied):
            if originator_names and any(name in originator_names for name in supplied):
                result["status"] = "self_receipt"
                result["reasons"].append(
                    "回执签名者与发起人证书身份相同；自我回执不能证明外部投递"
                )
                return result
            result["status"] = "confirmed"
            result["matchedNames"] = [name for name in supplied if name in claimed_recipients]
            result["reasons"].append(
                "receipt signer matches an archived To/Cc recipient and allReceipts permits that recipient to respond"
            )
            return result
        result["reasons"].append(
            "回执签名者不在归档正文的 To/Cc 收件人中，无法导出预期收件人确认"
        )
        return result

    result["reasons"].append("不支持的 receiptsFrom 形式 %s" % (scope,))
    return result


_LEVEL2_REASON_TEXT = {
    "receipt_signature_not_valid": "回执签名状态不是 valid",
    "receipt_certificate_not_trusted": "回执证书链不是 trusted",
    "receipt_content_digest_mismatch": "Receipt 内容与回执 messageDigest 不符",
    "receipt_content_digest_unavailable": "无法计算 Receipt 内容摘要",
    "msgSigDigest_absent": "缺少 msgSigDigest 关联属性",
    "msgSigDigest_mismatch": "msgSigDigest 与匹配签名者的 SignedAttributes 摘要不符",
    "msgSigDigest_unavailable": "无法计算匹配签名者的 SignedAttributes 摘要",
    "originator_signed_attrs_absent": "原签名者没有 signedAttrs",
}


def _level_reason_text(codes: Sequence[str]) -> str:
    text = []
    for code in codes:
        key, _, value = code.partition(":")
        base = _LEVEL2_REASON_TEXT.get(key, key)
        text.append("%s(%s)" % (base, value) if value else base)
    return "、".join(text)


class CorrelationAnalyzer:
    def __init__(self, inputs: CaseInputs):
        self.inputs = inputs
        self._last_level2_reasons: Dict[str, Sequence[str]] = {}
        self.messages: Dict[str, MessageRecord] = {}
        self.receipts: Dict[str, ReceiptRecord] = {}
        self.decode_issues: List[Dict] = []
        for name, der in inputs.messages.items():
            try:
                self.messages[name] = decode_message(name, der)
            except DecodeError as exc:
                self.decode_issues.append({"object": name, "kind": "message", "issue": str(exc)})
        for name, der in inputs.receipts.items():
            try:
                self.receipts[name] = decode_receipt(name, der)
            except DecodeError as exc:
                self.decode_issues.append({"object": name, "kind": "receipt", "issue": str(exc)})

    # -- input attestations -------------------------------------------------

    def _message_signer_attestation(self, message: MessageRecord, signer):
        return self.inputs.attestations.message_signer(
            message.name, signer.layer_index, signer.index, signer.signature
        )

    def _receipt_attestation(self, receipt: ReceiptRecord):
        return self.inputs.attestations.receipt(receipt.name)

    # -- receipt evaluation -------------------------------------------------

    def _candidates(self, receipt: ReceiptRecord) -> List[Dict]:
        candidates = []
        for message in self.messages.values():
            for signer in message.signers:
                link = _field_link(receipt, signer)
                matched = link["matched"]
                if (
                    matched["signedAttrsPresent"]
                    and matched["contentType"]
                    and matched["originatorSignatureValue"]
                    and matched["signedContentIdentifier"] is True
                ):
                    candidates.append({"message": message, "signer": signer, "link": link})
        return candidates

    def _digest_cross_reference(self, receipt: ReceiptRecord) -> List[Dict]:
        """Where does the receipt's msgSigDigest actually point?"""

        digest = receipt.signer.msg_sig_digest
        if digest is None:
            return []
        hits = []
        for message in self.messages.values():
            for signer in message.signers:
                computed, error = _digest_name(signer)
                if computed is None:
                    continue
                if computed == digest:
                    hits.append(
                        {
                            "message": message.name,
                            "signer": signer.path,
                            "algorithm": signer.digest_algorithm,
                            "digest": "0x" + computed.hex(),
                            "nestedLayer": signer.layer_index > 0,
                        }
                    )
        return hits

    def evaluate_receipt(self, receipt: ReceiptRecord) -> Dict:
        attestation = self._receipt_attestation(receipt)
        candidates = self._candidates(receipt)
        structural = _envelope_checks(receipt)
        write_checks = _write_receipt_checks(receipt)
        cross = self._digest_cross_reference(receipt)

        result: Dict = {
            "receipt": receipt.name,
            "derSha256": receipt.der_sha256,
            "receiptFields": {
                "contentType": receipt.content_type,
                "signedContentIdentifier": "0x" + receipt.signed_content_identifier.hex(),
                "originatorSignatureValue": "0x" + receipt.originator_signature_value.hex(),
                "version": receipt.version,
                "receiptContentSha256": hashlib.sha256(receipt.receipt_content_der).hexdigest(),
            },
            "receiptSigner": {
                "signerInfosIndex": receipt.signer.index,
                "signatureAlgorithm": receipt.signer.signature_algorithm,
                "digestAlgorithm": receipt.signer.digest_algorithm,
                "messageDigest": _value_text(receipt.signer.message_digest),
                "msgSigDigest": _value_text(receipt.signer.msg_sig_digest),
                "certificateEmails": list(receipt.signer.emails),
            },
            "attestation": {
                "signatureStatus": attestation.signature_status,
                "certificateTrust": attestation.certificate_trust,
                "reason": attestation.reason,
                "signerNames": list(attestation.signer_names),
            },
            "structuralChecks": structural,
            "writeChecks": write_checks,
            "parseIssues": list(receipt.parse_issues) + list(receipt.envelope.parse_issues),
            "candidates": [
                {"message": candidate["message"].name, "signer": candidate["signer"].path}
                for candidate in candidates
            ],
            "digestCrossReference": cross,
            "levels": {name: False for name in LEVEL_NAMES},
            "levelDetails": {},
            "conclusion": "",
        }

        if not candidates:
            result["candidates"] = []
            result["levels"] = {name: False for name in LEVEL_NAMES}
            if not any(
                signer.receipt_request is not None
                for message in self.messages.values()
                for signer in message.signers
            ):
                result["conclusion"] = "没有任何消息声明 ReceiptRequest，回执无法与签名建立三层证据。"
            else:
                closest = self._closest_candidates(receipt)
                if closest:
                    best = closest[0]
                    compared = [
                        (key, citation)
                        for key, citation in best["checks"].items()
                        if citation.get("match") is not None
                    ]
                    missing = [
                        key for key, citation in compared if citation["match"] is False
                    ]
                    result["conclusion"] = (
                        "未找到字段完全吻合的签名者；最接近的是 %s %s（%d/%d 项可比字段吻合），"
                        "不吻合字段：%s。"
                        % (
                            best["message"],
                            best["signer"],
                            sum(1 for _, citation in compared if citation["match"]),
                            len(compared),
                            ", ".join(missing) or "无",
                        )
                    )
                else:
                    result["conclusion"] = (
                        "未找到字段吻合的签名者：contentType、signedContentIdentifier 与 "
                        "originatorSignatureValue 无法指向任何带 ReceiptRequest 的 SignerInfo。"
                    )
            # Still report partial candidate diagnostics for the closest signer.
            result["closest"] = self._closest_candidates(receipt)
            result["structuralViolations"] = [
                check for check in structural if check.get("match") is False
            ]
            return result

        if len(candidates) > 1:
            result["conclusion"] = (
                "多个归档对象中的签名者字段完全相同（%d 个候选），回执无法唯一绑定到某一 "
                "SignerInfo；只能视为歧义关联，不进入第二层。"
                % (len(candidates),)
            )
            result["ambiguousCandidates"] = [
                {"message": c["message"].name, "signer": c["signer"].path} for c in candidates
            ]
            result["closest"] = self._closest_candidates(receipt)
            return result

        message = candidates[0]["message"]
        signer = candidates[0]["signer"]
        link = candidates[0]["link"]

        structural_ok = all(check.get("match") is not False for check in structural)
        result["matched"] = {
            "message": message.name,
            "signer": signer.path,
            "link": link,
            "messageBodySha256": message.body_sha256,
        }
        failed_structural = [
            check for check in structural if check.get("match") is False
        ]
        result["structuralViolations"] = failed_structural
        result["levelDetails"]["signatureLocated"] = {
            "status": "satisfied" if structural_ok else "structural_violation",
            "citations": [
                link["checks"][key]
                for key in (
                    "contentType",
                    "signedContentIdentifier",
                    "originatorSignatureValue",
                )
            ],
            "structural": structural,
            "failedStructural": failed_structural,
            "note": (
                "三字段逐字节吻合仅证明回执自称指向该 SignerInfo；"
                "不证明任何签名通过验签。"
            ),
        }
        result["levels"]["signatureLocated"] = bool(structural_ok)

        signer_verification = self._message_signer_attestation(message, signer)

        # Level 2 material.
        content_digest, content_error = _receipt_content_digest(receipt)
        content_ok = content_digest is not None and receipt.signer.message_digest is not None and content_digest == receipt.signer.message_digest
        msg_digest, msg_error = _digest_name(signer)
        msg_ok = (
            receipt.signer.msg_sig_digest is not None
            and msg_digest is not None
            and msg_digest == receipt.signer.msg_sig_digest
        )
        own_signature_ok = attestation.signature_status == STATUS_VALID
        trust_ok = attestation.certificate_trust == TRUST_TRUSTED
        signed_attrs_present = signer.signed_attributes_der is not None
        reason_codes: List[str] = []
        if not own_signature_ok:
            reason_codes.append("receipt_signature_not_valid:%s" % attestation.signature_status)
        if not trust_ok:
            reason_codes.append("receipt_certificate_not_trusted:%s" % attestation.certificate_trust)
        if not content_ok:
            reason_codes.append("receipt_content_digest_mismatch" if content_digest is not None else "receipt_content_digest_unavailable")
        if receipt.signer.msg_sig_digest is None:
            reason_codes.append("msgSigDigest_absent")
        elif not msg_ok:
            reason_codes.append("msgSigDigest_mismatch" if msg_digest is not None else "msgSigDigest_unavailable")
        if not signed_attrs_present:
            reason_codes.append("originator_signed_attrs_absent")

        level2 = bool(result["levels"]["signatureLocated"]) and own_signature_ok and trust_ok and content_ok and msg_ok and signed_attrs_present
        result["levelDetails"]["receiptTrusted"] = {
            "status": "satisfied" if level2 else "blocked",
            "checks": [
                {
                    "name": "receipt signature status (explicit input)",
                    "value": attestation.signature_status,
                    "required": STATUS_VALID,
                    "ok": own_signature_ok,
                    "source": "attestation",
                },
                {
                    "name": "receipt certificate trust (explicit input)",
                    "value": attestation.certificate_trust,
                    "required": TRUST_TRUSTED,
                    "ok": trust_ok,
                    "source": "attestation",
                },
                {
                    "name": "Receipt content messageDigest",
                    "path": receipt.signer.path + ".signedAttrs " + str(rfc5652.id_messageDigest),
                    "observed": _value_text(receipt.signer.message_digest),
                    "computed": _value_text(content_digest),
                    "algorithm": receipt.signer.digest_algorithm,
                    "ok": content_ok,
                    "detail": content_error,
                },
                {
                    "name": "msgSigDigest over matched SignerInfo SignedAttributes",
                    "path": receipt.signer.path + ".signedAttrs " + str(rfc2634.id_aa_msgSigDigest),
                    "observed": _value_text(receipt.signer.msg_sig_digest),
                    "computed": _value_text(msg_digest),
                    "algorithm": signer.digest_algorithm,
                    "setOfDerSha256": hashlib.sha256(signer.signed_attributes_der).hexdigest()
                    if signer.signed_attributes_der is not None
                    else None,
                    "ok": msg_ok,
                    "detail": msg_error,
                },
                {
                    "name": "matched SignerInfo signedAttrs present",
                    "path": signer.path + ".signedAttrs",
                    "ok": signed_attrs_present,
                },
            ],
            "reasonCodes": reason_codes,
            "note": (
                "本层只证明回执自身可信且绑定到该签名者的 SignedAttributes；"
                "尚未要求原签名验签通过，也不判断回执是否来自预期收件人。"
            ),
        }
        result["levels"]["receiptTrusted"] = bool(level2)
        self._last_level2_reasons[receipt.name] = tuple(reason_codes)

        # Level 3 material.
        identity_names = attestation.signer_names
        identity_basis = "attestation signerNames" if identity_names else "embedded certificate (unattested identity)"
        if not identity_names and receipt.signer.certificate is not None:
            identity_names = receipt.signer.certificate.emails
        recipient = _expected_recipient(receipt, message, signer, tuple(identity_names), identity_basis)
        original_valid = signer_verification.status == STATUS_VALID
        if not original_valid:
            reason_codes_l3 = ["original_signature_not_valid:%s" % signer_verification.status]
        else:
            reason_codes_l3 = []
        if recipient["status"] != "confirmed":
            reason_codes_l3.append("recipient_scope:%s" % recipient["status"])
        level3 = bool(level2) and original_valid and recipient["status"] == "confirmed"
        result["levelDetails"]["expectedRecipientConfirmed"] = {
            "status": "satisfied" if level3 else "blocked",
            "originalSignerAttestation": {
                "message": message.name,
                "signer": signer.path,
                "status": signer_verification.status,
                "reason": signer_verification.reason,
                "required": STATUS_VALID,
                "ok": original_valid,
            },
            "recipientEvaluation": recipient,
            "scope": list(_recipient_scope(receipt, message, signer)),
            "reasonCodes": reason_codes_l3,
            "note": (
                "仅当原签名验签结果明确为 valid 且回执签名者属于 ReceiptRequest 允许的收件人范围时，"
                "才可将回执解释为预期收件人的投递确认。未知验签状态一律不满足。"
            ),
        }
        result["levels"]["expectedRecipientConfirmed"] = bool(level3)
        result["conclusion"] = self._conclusion(receipt, message, signer, result["levels"], attestation, signer_verification, recipient)
        return result

    def _closest_candidates(self, receipt: ReceiptRecord) -> List[Dict]:
        closest = []
        for message in self.messages.values():
            for signer in message.signers:
                if signer.receipt_request is None:
                    continue
                link = _field_link(receipt, signer)
                score = sum(1 for key, value in link["matched"].items() if value is True)
                if score >= 2:
                    closest.append(
                        {
                            "message": message.name,
                            "signer": signer.path,
                            "score": score,
                            "checks": link["checks"],
                        }
                    )
        closest.sort(key=lambda item: item["score"], reverse=True)
        return closest

    def _conclusion(self, receipt, message, signer, levels, attestation, verification, recipient) -> str:
        parts = []
        if levels["signatureLocated"]:
            parts.append(
                "找到对应签名：%s %s 的 contentType、signedContentIdentifier、originatorSignatureValue "
                "与回执逐字吻合。" % (message.name, signer.path)
            )
        else:
            parts.append("未找到对应签名。")
        if levels["receiptTrusted"]:
            parts.append(
                "回执可信：回执签名=%s，证书=%s，msgSigDigest 与签名者的 SignedAttributes 摘要一致。"
                % (attestation.signature_status, attestation.certificate_trust)
            )
        else:
            reasons = _level_reason_text(
                self._last_level2_reasons.get(receipt.name, ())
            )
            parts.append("回执未达可信层%s。" % (("：" + reasons) if reasons else ""))
        if levels["expectedRecipientConfirmed"]:
            parts.append("预期收件人确认：回执签名者可被认定为该 ReceiptRequest 范围内的收件人。")
        elif levels["receiptTrusted"]:
            blockers = []
            if verification.status != STATUS_VALID:
                blockers.append("原签名验签状态为 %s，不是 valid" % (verification.status,))
            if recipient["status"] != "confirmed":
                blockers.extend(recipient["reasons"] or ["收件人范围条件不足"])
            parts.append("预期收件人确认不成立：%s。" % "；".join(blockers))
        else:
            parts.append("预期收件人确认未评估（第二层未成立）。")
        return " ".join(parts)

    # -- message evaluation -------------------------------------------------

    def evaluate_messages(self) -> List[Dict]:
        rows = []
        for message in self.messages.values():
            signers = []
            for signer in message.signers:
                attestation = self._message_signer_attestation(message, signer)
                request = signer.receipt_request
                signers.append(
                    {
                        "path": signer.path,
                        "signature": "0x" + signer.signature.hex(),
                        "signatureSha256": hashlib.sha256(signer.signature).hexdigest(),
                        "contentType": signer.content_type,
                        "contentIdentifier": _value_text(signer.content_identifier),
                        "receiptRequest": None
                        if request is None
                        else {
                            "signedContentIdentifier": "0x" + bytes(request["signedContentIdentifier"]).hex(),
                            "receiptsFrom": request["receiptsFrom"].getName(),
                            "receiptsTo": [
                                [{"kind": kind, "value": value} for kind, value in entry]
                                for entry in receipts_to_names(request)
                            ],
                            "der": "0x" + (signer.receipt_request_der or b"").hex(),
                        },
                        "verification": {
                            "status": attestation.status,
                            "reason": attestation.reason,
                            "source": "attestation",
                        },
                        "certificateEmails": list(signer.emails),
                    }
                )
            layer_rows = []
            for layer in message.layers:
                history, history_der, conflict = layer_history(layer)
                layer_rows.append(
                    {
                        "path": layer.path,
                        "eContentType": layer.econtent_type,
                        "signers": len(layer.signers),
                        "mlExpansionHistory": None
                        if history is None
                        else {
                            "entries": list(ml_data_summary(history)),
                            "conflictAcrossSigners": conflict,
                            "derSha256": hashlib.sha256(history_der).hexdigest(),
                        },
                    }
                )
            rows.append(
                {
                    "message": message.name,
                    "derSha256": message.der_sha256,
                    "bodySha256": message.body_sha256,
                    "layers": layer_rows,
                    "signers": signers,
                    "parseIssues": list(message.parse_issues)
                    + [issue for layer in message.layers for issue in layer.parse_issues],
                }
            )
        return rows

    def body_groups(self) -> List[Dict]:
        groups: Dict[str, List[str]] = {}
        for message in self.messages.values():
            if message.body_sha256 is None:
                continue
            groups.setdefault(message.body_sha256, []).append(message.name)
        return [
            {"bodySha256": digest, "messages": names}
            for digest, names in sorted(groups.items())
            if len(names) > 1
        ]

    def coverage_matrix(self, analyses: Sequence[Dict]) -> List[Dict]:
        rows = []
        for item in analyses:
            details = item.get("levelDetails", {})
            l2_checks = {
                check["name"]: check
                for check in details.get("receiptTrusted", {}).get("checks", [])
            }
            l3 = details.get("expectedRecipientConfirmed", {})
            rows.append(
                {
                    "receipt": item["receipt"],
                    "fieldLink": item.get("matched", {}).get("link", {}).get("matched"),
                    "msgSigDigest": {
                        "observed": item.get("receiptSigner", {}).get("msgSigDigest"),
                        "computed": l2_checks.get(
                            "msgSigDigest over matched SignerInfo SignedAttributes", {}
                        ).get("computed"),
                        "match": l2_checks.get(
                            "msgSigDigest over matched SignerInfo SignedAttributes", {}
                        ).get("ok"),
                    },
                    "receiptSignatureStatus": item.get("attestation", {}).get("signatureStatus"),
                    "certificateTrust": item.get("attestation", {}).get("certificateTrust"),
                    "originalSignatureStatus": l3.get("originalSignerAttestation", {}).get("status"),
                    "recipientStatus": l3.get("recipientEvaluation", {}).get("status"),
                    "levels": item.get("levels"),
                }
            )
        return rows

    def summarize(self) -> Dict:
        return {
            "domain": DOMAIN,
            "levels": {
                "signatureLocated": "字段逐字节关联，不依赖验签",
                "receiptTrusted": "回执自身可信 + msgSigDigest 绑定到原签名者的 SignedAttributes",
                "expectedRecipientConfirmed": "原签名验签 valid + 回执签名者属于请求范围",
            },
            "attestationOnlyInputs": [
                "receipt signature status",
                "receipt certificate trust",
                "original message signer status (per layer and signer)",
            ],
            "neverUpgraded": "absent/unknown attestations remain unknown and cannot satisfy any level",
        }

    def run(self) -> Dict:
        analyses = [self.evaluate_receipt(receipt) for receipt in self.receipts.values()]
        report = {
            "summary": self.summarize(),
            "decodeIssues": self.decode_issues,
            "messages": self.evaluate_messages(),
            "identicalBodyGroups": self.body_groups(),
            "receipts": analyses,
            "coverageMatrix": self.coverage_matrix(analyses),
            "controls": self._controls(analyses),
            "method": {
                "receiptStruct": str(rfc2634.id_ct_receipt),
                "msgSigDigestOid": str(rfc2634.id_aa_msgSigDigest),
                "receiptRequestOid": str(rfc2634.id_aa_receiptRequest),
                "signedAttributesDigestRule": (
                    "RFC 5652 section 5.4: digest the DER SET OF encoding, replacing "
                    "the IMPLICIT [0] tag with the EXPLICIT SET OF tag"
                ),
                "normalization": "rfc822Name values compared case-insensitively; other GeneralName forms are case-sensitive",
            },
        }
        return report

    # -- controls -----------------------------------------------------------

    def _controls(self, analyses: Sequence[Dict]) -> List[Dict]:
        by_name = {item["receipt"]: item for item in analyses}
        controls = []

        # 1. Same body, re-signed.
        bodies = self.body_groups()
        controls.append(
            {
                "control": "same_body_resignature",
                "question": "正文摘要相同能否把回执扩展到另一封邮件？",
                "bodyGroups": bodies,
                "observations": [
                    {
                        "receipt": name,
                        "matched": by_name.get(name, {}).get("matched", {}).get("message"),
                        "levels": by_name.get(name, {}).get("levels"),
                        "otherMessagesWithSameBody": [
                            group["messages"] for group in bodies
                            if by_name.get(name, {}).get("matched", {}).get("message") in group["messages"]
                        ],
                    }
                    for name in by_name
                ],
                "finding": (
                    "回执只绑定 originatorSignatureValue 与 msgSigDigest；同正文的其他签名者"
                    "即使正文摘要一致也不匹配，正文摘要不得作为签收证据。"
                ),
            }
        )

        # 2. Forwarding encapsulation.
        forwarded = [
            message for message in self.messages.values()
            if message.layers[0].econtent_type == str(rfc5652.id_signedData)
        ]
        controls.append(
            {
                "control": "forwarded_encapsulation",
                "messages": [
                    {
                        "message": message.name,
                        "layers": [layer.econtent_type for layer in message.layers],
                        "outerSignerStatus": self._layer_statuses(message, 0),
                        "innerSignerStatus": self._layer_statuses(message, 1),
                    }
                    for message in forwarded
                ],
                "finding": (
                    "外层转发签名不携带 ReceiptRequest，内层 SignedData 逐字节保留；"
                    "回执只能匹配内层签名者，外层签名状态不能替代内层，未知外层状态也不影响"
                    "已由 msgSigDigest 绑定的内层结论；反之，外层签名通过也不能把回执归给转发者。"
                ),
            }
        )

        # 3. One required linkage attribute deleted.
        deleted = []
        for name, item in by_name.items():
            if item.get("receiptFields", {}).get("version") != 1:
                continue
            missing = [
                check for check in item.get("levelDetails", {}).get("receiptTrusted", {}).get("checks", [])
                if check.get("name") == "msgSigDigest over matched SignerInfo SignedAttributes"
                and check.get("observed") is None
            ]
            if missing:
                deleted.append(
                    {
                        "receipt": name,
                        "missingField": str(rfc2634.id_aa_msgSigDigest),
                        "levels": item["levels"],
                        "reasonCodes": item.get("levelDetails", {}).get("receiptTrusted", {}).get("reasonCodes"),
                    }
                )
        controls.append(
            {
                "control": "missing_required_linkage_attribute",
                "cases": deleted,
                "finding": (
                    "msgSigDigest 是收据与原始 SignedAttributes 的必要关联证据；删除后"
                    "仍可通过签名者身份与 contentIdentifier 找到候选，但无法证明收件人收到的是"
                    "原签名者签署的字节，因此停在第一层。"
                ),
            }
        )
        # 4. Multiple signers on the original.
        multi = [
            message
            for message in self.messages.values()
            if len(message.layers[-1].signers) > 1
        ]
        controls.append(
            {
                "control": "multiple_originator_signers",
                "messages": [
                    {
                        "message": message.name,
                        "signers": [
                            {
                                "signer": signer.path,
                                "signature": "0x" + signer.signature.hex(),
                                "contentType": signer.content_type,
                                "contentIdentifier": _value_text(signer.content_identifier),
                                "receiptRequest": signer.receipt_request is not None,
                                "verification": self._message_signer_attestation(message, signer).status,
                                "receiptsLocatingIt": [
                                    item["receipt"]
                                    for item in analyses
                                    if item.get("matched", {}).get("message") == message.name
                                    and item.get("matched", {}).get("signer") == signer.path
                                ],
                            }
                            for signer in message.layers[-1].signers
                        ],
                        "requestConsistency": self._request_consistency(message),
                    }
                    for message in multi
                ],
                "finding": (
                    "每个 SignerInfo 独立承载自己的 receiptRequest；只有一个签名者带 ReceiptRequest 时，"
                    "回执即使指向另一签名者也不构成该签名者的签收请求。RFC 2634 section 2.2.1 要求"
                    "带请求的多个 SignerInfo 的 receiptRequest 必须完全相同；不一致时必须不生成回执。"
                ),
            }
        )

        # 5. Mailing-list expansion.
        list_cases = []
        for message in self.messages.values():
            layer, history, _, conflict = effective_history(message)
            if history is None:
                continue
            inner = message.layers[-1]
            list_cases.append(
                {
                    "message": message.name,
                    "outerLayer": layer.path,
                    "policy": ml_data_summary(history)[-1]["mlReceiptPolicy"],
                    "receiptsTo": [
                        [
                            {"kind": kind, "value": value}
                            for kind, value in entry
                        ]
                        for signer in inner.signers
                        if signer.receipt_request is not None
                        for entry in receipts_to_names(signer.receipt_request)
                    ],
                    "innerReceiptsFrom": [
                        {
                            "signer": signer.path,
                            "form": signer.receipt_request["receiptsFrom"].getName(),
                            "names": [
                                {"kind": kind, "value": value}
                                for kind, value in receipt_request_names(signer.receipt_request)
                            ],
                        }
                        for signer in inner.signers
                        if signer.receipt_request is not None
                    ],
                    "receiptOutcomes": [
                        {
                            "receipt": item["receipt"],
                            "receiptSigner": item.get("attestation", {}).get("signerNames"),
                            "levels": item["levels"],
                            "recipientStatus": item.get("levelDetails", {})
                            .get("expectedRecipientConfirmed", {})
                            .get("recipientEvaluation", {})
                            .get("status"),
                        }
                        for item in analyses
                        if item.get("matched", {}).get("message") == message.name
                    ],
                }
            )
        controls.append(
            {
                "control": "mailing_list_expansion",
                "cases": list_cases,
                "finding": (
                    "mlExpansionHistory 只在最外层签名者上生效：mlReceiptPolicy none 抑制回执；"
                    "firstTierRecipients 在发生列表扩展后不得回执；insteadOf/inAdditionTo 改变回执的"
                    "发送对象（receiptsTo 路由），不扩大有权回执的收件人集合——后者仍由 receiptsFrom "
                    "的 receiptList 或 allOrFirstTier 决定。上述规则不改变回执与内层签名者的字段绑定。"
                ),
            }
        )

        return controls

    def _request_consistency(self, message: MessageRecord) -> Dict:
        requests = [
            (signer.path, signer.receipt_request_der)
            for signer in message.layers[-1].signers
            if signer.receipt_request is not None
        ]
        if len(requests) < 2:
            return {"requestingSigners": len(requests), "identical": True}
        first = requests[0][1]
        return {
            "requestingSigners": len(requests),
            "identical": all(der == first for _, der in requests[1:]),
            "differing": [path for path, der in requests if der != first],
        }

    def _layer_statuses(self, message: MessageRecord, layer_index: int) -> List[Dict]:
        return [
            {
                "signer": signer.path,
                "status": self._message_signer_attestation(message, signer).status,
                "receiptRequest": signer.receipt_request is not None,
            }
            for signer in message.signers
            if signer.layer_index == layer_index
        ]


def analyze_archive(inputs: CaseInputs) -> Dict:
    return CorrelationAnalyzer(inputs).run()
