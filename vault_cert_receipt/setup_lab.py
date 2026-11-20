"""搭建本地测试 PKI 与审批单。

目录结构（私钥集中在 ca/private 与 keys，权限 600，不进入回执/证据）：
  ca/certs/root.crt            自签名根 CA（审批信任锚）
  ca/certs/intermediate.crt    中间 CA（模拟 Vault 的实际签发方）
  ca/private/*.key             根/中间私钥
  keys/receipt-signing.key     回执签名私钥
  keys/receipt-signing.pub.pem 回执验签公钥（可随工单分发）
  approvals/*.json             审批单（含签发方指纹钉扎与 TTL 上限）
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from . import pki_crypto

LAB_ROOT = Path(__file__).resolve().parent


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_ca() -> dict:
    ca_dir = LAB_ROOT / "ca"
    key_dir = LAB_ROOT / "keys"
    key_dir.mkdir(parents=True, exist_ok=True)
    (ca_dir / "private").mkdir(parents=True, exist_ok=True)
    (ca_dir / "certs").mkdir(parents=True, exist_ok=True)
    (LAB_ROOT / "approvals").mkdir(parents=True, exist_ok=True)

    root_key = ca_dir / "private" / "root.key"
    root_crt = ca_dir / "certs" / "root.crt"
    int_key = ca_dir / "private" / "intermediate.key"
    int_crt = ca_dir / "certs" / "intermediate.crt"

    pki_crypto.gen_ec_key(root_key)
    pki_crypto.self_signed_root(root_key, root_crt, "Lab Root CA G1")
    pki_crypto.gen_ec_key(int_key)
    pki_crypto.sign_intermediate(
        root_key, root_crt, int_key, int_crt,
        "Lab Vault Issuing Intermediate G1",
    )

    sign_key = key_dir / "receipt-signing.key"
    sign_pub = key_dir / "receipt-signing.pub.pem"
    pki_crypto.gen_ec_key(sign_key)
    pki_crypto._run(["ec", "-in", str(sign_key), "-pubout", "-out", str(sign_pub)])

    root_pem = root_crt.read_text(encoding="utf-8")
    int_pem = int_crt.read_text(encoding="utf-8")
    return {
        "root_pem": root_pem,
        "intermediate_pem": int_pem,
        "issuer_sha256": pki_crypto.sha256_fingerprint(int_pem),
        "root_sha256": pki_crypto.sha256_fingerprint(root_pem),
        "signing_key": sign_key,
        "verification_pubkey_pem": sign_pub.read_text(encoding="utf-8"),
    }


def write_approval(ca_info: dict, *, case_id: str, ticket: str,
                   common_name: str, alt_names: list[str],
                   ttl: str, max_ttl: str) -> Path:
    from .mock_hvac import parse_ttl

    approval = {
        "approval_id": f"APR-{case_id}",
        "ticket_id": ticket,
        "approved_at": utc_now_iso(),
        "vault_address": "https://vault-lab.internal:8200",
        "mount_point": "pki-internal",
        "role": f"role-{case_id}",
        "common_name": common_name,
        "alt_names": sorted(set(alt_names)),
        "requested_ttl": ttl,
        "max_ttl_seconds": parse_ttl(max_ttl),
        "issuer_sha256": ca_info["issuer_sha256"],
        "trusted_root_pem": ca_info["root_pem"],
    }
    path = LAB_ROOT / "approvals" / f"{case_id}.json"
    path.write_text(
        json.dumps(approval, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def main() -> None:
    ca_info = build_ca()
    common = dict(
        common_name="billing.internal.example.com",
        alt_names=[
            "billing.internal.example.com",
            "billing-vip.internal.example.com",
        ],
        ttl="48h",
        max_ttl="72h",
    )
    cases = [
        ("case-a-valid", "TICKET-1001", common),
        ("case-b-wrong-identity", "TICKET-1002", common),
        ("case-c-incomplete", "TICKET-1003", common),
    ]
    for case_id, ticket, kwargs in cases:
        path = write_approval(ca_info, case_id=case_id, ticket=ticket, **kwargs)
        print(f"审批单已生成: {path.relative_to(LAB_ROOT)}")
    print(f"签发方(中间CA)指纹: {ca_info['issuer_sha256']}")
    print(f"信任锚(根CA)指纹:   {ca_info['root_sha256']}")


if __name__ == "__main__":
    main()
