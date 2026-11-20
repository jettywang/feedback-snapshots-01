"""一键演示：搭建 PKI -> 三个领用用例 -> 独立核验 -> 私钥泄漏扫描。"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from . import setup_lab, issue_cert, verify_receipt

LAB_ROOT = Path(__file__).resolve().parent
CASES = ("case-a-valid", "case-b-wrong-identity", "case-c-incomplete")


def scan_leaks() -> int:
    """在所有可流转产物中搜索 PEM 私钥块，预期 0 命中。"""
    hits = 0
    for sub in ("receipts", "evidence", "approvals"):
        for path in (LAB_ROOT / sub).rglob("*"):
            if path.is_file() and "PRIVATE KEY" in path.read_text(
                encoding="utf-8"
            ):
                hits += 1
                print(f"  ! 私钥泄漏: {path}")
    return hits


def main() -> int:
    print("== 1. 搭建本地 CA 与审批单 ==")
    setup_lab.main()

    print("\n== 2. 模拟 hvac 领用并生成回执 ==")
    for case_id in CASES:
        issue_cert.run(case_id)

    print("\n== 3. 独立核验每份回执 ==")
    rc_max = 0
    for case_id in CASES:
        receipt_path = LAB_ROOT / "receipts" / f"{case_id}.receipt.json"
        rc = verify_receipt.run(receipt_path)
        rc_max = max(rc_max, rc)
        print()

    print("== 4. 私钥材料泄漏扫描（receipts/evidence/approvals）==")
    hits = scan_leaks()
    print(f"  命中私钥块数量: {hits}")
    if hits:
        return 1

    print("== 5. 正确签发链的 openssl 独立验证 ==")
    chain = subprocess.run(
        [
            "openssl", "verify",
            "-CAfile", str(LAB_ROOT / "ca" / "certs" / "root.crt"),
            "-untrusted", str(LAB_ROOT / "ca" / "certs" / "intermediate.crt"),
            str(LAB_ROOT / "keys" / "billing.internal.example.com.crt"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    print(f"  {chain.stdout.strip()}")
    print("\n演示完成。")
    return 0 if rc_max in (0, 1) else rc_max


if __name__ == "__main__":
    raise SystemExit(main())
