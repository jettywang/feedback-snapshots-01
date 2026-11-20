"""证书领用回执：审批核对、结论判定与防篡改签名。

结论（verdict）取值刻意做成可区分、可机读：
  PASS                     证据齐全、链可信、身份一致、期限合规
  REJECT_INCOMPLETE_EVIDENCE 证据不全（缺证书/链/CA，无法复核）
  REJECT_UNTRUSTED_CHAIN   签发链无法通过指定根 CA 校验或签发方指纹不匹配
  REJECT_IDENTITY_MISMATCH CN/SAN 与审批单不一致
  REJECT_TTL_VIOLATION     实际有效期超出审批可用期限

回执只保存证书识别信息（序列号、指纹、DN、SAN、起止时间、公钥指纹），
不保存任何 PEM 证书与私钥；私钥字段在落证据前即被剥离。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import pki_crypto

SENSITIVE_MARKERS = (
    "PRIVATE KEY",  # 覆盖 EC/RSA/ENCRYPTED 各类 PEM 私钥块
)

VERDICTS = (
    "PASS",
    "REJECT_INCOMPLETE_EVIDENCE",
    "REJECT_UNTRUSTED_CHAIN",
    "REJECT_IDENTITY_MISMATCH",
    "REJECT_TTL_VIOLATION",
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact_sensitive(response_data: dict) -> dict:
    """剥离 Vault 响应中的私钥材料，只保留可流转的公开字段。"""
    return {
        key: value
        for key, value in response_data.items()
        if key not in ("private_key", "private_key_type")
    }


def assert_no_private_material(text: str, source: str) -> None:
    """防御性断言：任何要落盘/流转的文本都不得含私钥块。"""
    if "BEGIN" in text and "PRIVATE KEY" in text:
        raise ValueError(f"{source} 中检测到私钥材料，已阻断落盘")


@dataclass
class CheckResult:
    verdict: str
    reasons: list[str] = field(default_factory=list)


def _incomplete_checks(evidence: dict, approval: dict) -> CheckResult:
    missing: list[str] = []
    data = evidence.get("vault_response", {}).get("data", {})
    for field_name in ("certificate", "issuing_ca"):
        if not data.get(field_name):
            missing.append(field_name)
    if not data.get("ca_chain"):
        missing.append("ca_chain")
    if not approval.get("trusted_root_pem"):
        missing.append("approval.trusted_root_pem")
    if missing:
        return CheckResult(
            "REJECT_INCOMPLETE_EVIDENCE",
            [f"证据缺失或为空: {', '.join(missing)}"],
        )
    return CheckResult("PASS")


def evaluate(approval: dict, evidence: dict) -> CheckResult:
    """按固定优先级执行五项核对，返回可区分结论与原因。"""
    incomplete = _incomplete_checks(evidence, approval)
    if incomplete.verdict != "PASS":
        return incomplete

    data = evidence["vault_response"]["data"]
    leaf_pem = data["certificate"]
    chain_pem = data["issuing_ca"]
    root_pem = approval["trusted_root_pem"]
    leaf = pki_crypto.parse_cert(leaf_pem)
    chain = pki_crypto.parse_cert(chain_pem)

    # 1) 签发链：openssl verify + 审批单钉扎的签发方（中间 CA）指纹
    chain_result = pki_crypto.verify_chain(leaf_pem, chain_pem, root_pem)
    chain_fpr = chain["sha256_fingerprint"]
    pinned = approval["issuer_sha256"].lower()
    chain_reasons: list[str] = []
    if not chain_result["ok"]:
        chain_reasons.append(f"链校验失败: {chain_result['detail']}")
    if chain_fpr != pinned:
        chain_reasons.append(
            "签发方指纹不匹配: "
            f"实际={chain_fpr} 审批钉扎={pinned}"
        )
    if chain_reasons:
        return CheckResult("REJECT_UNTRUSTED_CHAIN", chain_reasons)

    # 2) 身份：CN 必须相等，审批 SAN 必须全部覆盖实际 SAN
    identity_reasons: list[str] = []
    if leaf["common_name"] != approval["common_name"]:
        identity_reasons.append(
            "CN 不符: "
            f"实际={leaf['common_name']} 审批={approval['common_name']}"
        )
    approved_sans = set(approval["alt_names"])
    actual_sans = set(leaf["sans"])
    if not actual_sans.issubset(approved_sans):
        identity_reasons.append(
            "SAN 超出审批范围: "
            f"越权={sorted(actual_sans - approved_sans)}"
        )
    if identity_reasons:
        return CheckResult("REJECT_IDENTITY_MISMATCH", identity_reasons)

    # 3) 期限：实际有效期不得超过审批 TTL，且起止窗口不得早于审批时间
    ttl_reasons: list[str] = []
    if leaf["lifetime_seconds"] > approval["max_ttl_seconds"]:
        ttl_reasons.append(
            "有效期超限: "
            f"实际={leaf['lifetime_seconds']}s "
            f"上限={approval['max_ttl_seconds']}s"
        )
    approved_at = datetime.strptime(
        approval["approved_at"], "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc)
    leaf_not_before = datetime.strptime(
        leaf["not_before"], "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc)
    if leaf_not_before < approved_at:
        ttl_reasons.append(
            f"证书起期 {leaf['not_before']} 早于审批时间 "
            f"{approval['approved_at']}"
        )
    if ttl_reasons:
        return CheckResult("REJECT_TTL_VIOLATION", ttl_reasons)

    return CheckResult("PASS", ["全部核对通过"])


def build_receipt(approval: dict, evidence: dict,
                  check: CheckResult) -> dict:
    """组装只含识别信息的回执对象（无 PEM、无私钥）。"""
    data = evidence["vault_response"].get("data", {})
    leaf_info = None
    chain_info = None
    if data.get("certificate"):
        leaf_pem = data["certificate"]
        leaf_info = pki_crypto.parse_cert(leaf_pem)
        leaf_info["public_key_sha256"] = pki_crypto.public_key_sha256(leaf_pem)
        leaf_info.pop("is_ca", None)
    if data.get("issuing_ca"):
        chain_info = {
            "subject_dn": pki_crypto.parse_cert(data["issuing_ca"])["subject_dn"],
            "sha256_fingerprint": pki_crypto.sha256_fingerprint(
                data["issuing_ca"]
            ),
        }

    return {
        "receipt_version": "1.0",
        "receipt_id": evidence["evidence_id"],
        "ticket_id": approval["ticket_id"],
        "approval_id": approval["approval_id"],
        "generated_at": utc_now_iso(),
        "vault": {
            "address": approval["vault_address"],
            "mount_point": approval["mount_point"],
            "role": approval["role"],
        },
        "approval_expectation": {
            "common_name": approval["common_name"],
            "alt_names": sorted(approval["alt_names"]),
            "max_ttl_seconds": approval["max_ttl_seconds"],
            "issuer_sha256": approval["issuer_sha256"],
        },
        "received_certificate": leaf_info,
        "observed_issuer": chain_info,
        "verdict": check.verdict,
        "reasons": check.reasons,
        "evidence_locator": {
            "evidence_file": evidence["evidence_path"],
            "vault_request_id": evidence["vault_response"].get("request_id"),
        },
    }


def canonical_bytes(payload: dict) -> bytes:
    """规范化 JSON 字节：排序键、无空白、LF 换行，用于稳定签名/验签。"""
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True,
                   separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def sign_receipt(receipt: dict, signing_key: Path) -> dict:
    """对 receipt（除签名字段外）签名，返回带签名信封的可流转回执。"""
    payload = {k: v for k, v in receipt.items() if k != "signature"}
    signature = pki_crypto.sign_bytes(signing_key, canonical_bytes(payload))
    return {
        "payload": payload,
        "signature": {
            "alg": "ECDSA-P256-SHA256",
            "value": signature,
        },
    }


def verify_receipt_envelope(signed_receipt: dict,
                            verification_pubkey_pem: str) -> bool:
    payload = signed_receipt["payload"]
    signature = signed_receipt["signature"]["value"]
    return pki_crypto.verify_bytes(
        verification_pubkey_pem, canonical_bytes(payload), signature
    )
