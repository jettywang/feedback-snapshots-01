"""证书领用入口：模拟运维通过 hvac 向 Vault PKI 申领并生成回执。

用法：
  python -m vault_cert_receipt.issue_cert case-a-valid
  python -m vault_cert_receipt.issue_cert case-b-wrong-identity
  python -m vault_cert_receipt.issue_cert case-c-incomplete

真实环境切换：设置 VAULT_ADDR 与 VAULT_TOKEN 后，将 build_client 替换为
hvac.Client(...)，其余申请/核对/回执流程不变（响应结构一致）。
"""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

from . import pki_crypto, receipt
from .mock_hvac import MockHvacClient, parse_ttl

LAB_ROOT = Path(__file__).resolve().parent


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def build_client(approval: dict):
    """本地模拟客户端；生产替换为 hvac.Client(url, token)。"""
    return MockHvacClient(
        ca_dir=LAB_ROOT / "ca",
        key_dir=LAB_ROOT / "keys",
    )


def request_certificate(approval: dict) -> dict:
    client = build_client(approval)
    # 用例 B：申请的 CN/SAN 与审批单不符，模拟身份越权
    if approval["approval_id"] == "APR-case-b-wrong-identity":
        common_name = "billing-evil.internal.example.com"
        alt_names = "billing-evil.internal.example.com,other.internal.example.com"
    else:
        common_name = approval["common_name"]
        alt_names = ",".join(approval["alt_names"])

    response = client.secrets.pki.generate_certificate(
        name=approval["role"],
        common_name=common_name,
        extra_params={
            "alt_names": alt_names,
            "ttl": approval["requested_ttl"],
            "exclude_cn_from_sans": False,
        },
        mount_point=approval["mount_point"],
    )
    return response


def tamper_for_case_c(evidence: dict) -> dict:
    """用例 C：模拟证据不全——发行结果缺少签发链与 ca_chain，无法复核。"""
    data = evidence["vault_response"]["data"]
    data["issuing_ca"] = ""
    data["ca_chain"] = []
    return evidence


def save_evidence(case_id: str, approval: dict, response: dict,
                  drop_chain: bool) -> Path:
    safe_response = {
        "request_id": response.get("request_id"),
        "data": receipt.redact_sensitive(response["data"]),
    }
    evidence = {
        "evidence_id": f"EV-{uuid.uuid4().hex[:12]}",
        "case_id": case_id,
        "approval_id": approval["approval_id"],
        "ticket_id": approval["ticket_id"],
        "collected_at": receipt.utc_now_iso(),
        "vault_response": safe_response,
    }
    if drop_chain:
        evidence = tamper_for_case_c(evidence)

    serialized = json.dumps(evidence, ensure_ascii=False, indent=2) + "\n"
    receipt.assert_no_private_material(serialized, "证据文件")
    path = LAB_ROOT / "evidence" / f"{case_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized, encoding="utf-8")
    evidence["evidence_path"] = str(path.relative_to(LAB_ROOT))
    return path


def run(case_id: str) -> dict:
    approval_path = LAB_ROOT / "approvals" / f"{case_id}.json"
    approval = load_json(approval_path)

    response = request_certificate(approval)
    drop_chain = case_id == "case-c-incomplete"
    evidence_path = save_evidence(case_id, approval, response, drop_chain)
    evidence = load_json(evidence_path)
    evidence["evidence_path"] = str(evidence_path.relative_to(LAB_ROOT))

    check = receipt.evaluate(approval, evidence)
    receipt_obj = receipt.build_receipt(approval, evidence, check)
    signing_key = LAB_ROOT / "keys" / "receipt-signing.key"
    signed = receipt.sign_receipt(receipt_obj, signing_key)

    serialized = json.dumps(signed, ensure_ascii=False, indent=2) + "\n"
    receipt.assert_no_private_material(serialized, "回执文件")
    out_path = LAB_ROOT / "receipts" / f"{case_id}.receipt.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(serialized, encoding="utf-8")

    print(f"[{case_id}] 结论={check.verdict}")
    for reason in check.reasons:
        print(f"    - {reason}")
    print(f"    回执: {out_path.relative_to(LAB_ROOT)}")
    return signed


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    run(argv[1])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
