"""独立回执核验器（工单流转后由第三方/审计运行）。

用法：
  python -m vault_cert_receipt.verify_receipt receipts/case-a-valid.receipt.json

核验内容：
  1. 回执 ECDSA 信封签名是否有效（防篡改）
  2. 回执结论是否可由审批单 + 证据独立复算得到
  3. 证据/回执是否含任何私钥材料
退出码：0 全部一致；1 核验失败；2 用法错误。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from . import receipt

LAB_ROOT = Path(__file__).resolve().parent
EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def scan_private_material(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    return [
        marker
        for marker in receipt.SENSITIVE_MARKERS
        if "BEGIN" in text and marker in text
    ]


def run(receipt_path: Path) -> int:
    receipt_path = receipt_path.resolve()
    pubkey_pem = (LAB_ROOT / "keys" / "receipt-signing.pub.pem").read_text(
        encoding="utf-8"
    )
    signed = load(receipt_path)
    failures: list[str] = []

    if not receipt.verify_receipt_envelope(signed, pubkey_pem):
        failures.append("回执签名无效，内容可能被篡改")

    payload = signed["payload"]
    approval = load(LAB_ROOT / "approvals" / f"{_case_id(payload)}.json")
    evidence = load(LAB_ROOT / payload["evidence_locator"]["evidence_file"])
    evidence["evidence_path"] = payload["evidence_locator"]["evidence_file"]

    rechecked = receipt.evaluate(approval, evidence)
    if rechecked.verdict != payload["verdict"]:
        failures.append(
            f"结论复算不一致: 回执={payload['verdict']} "
            f"复算={rechecked.verdict}"
        )
    if rechecked.reasons != payload["reasons"]:
        failures.append("核对原因与回执记载不一致")

    for related in (
        receipt_path,
        LAB_ROOT / payload["evidence_locator"]["evidence_file"],
    ):
        markers = scan_private_material(related)
        if markers:
            failures.append(f"{related} 含私钥标记: {markers}")

    display_path = _display_path(receipt_path)
    print(f"回执: {display_path}")
    print(f"  结论: {payload['verdict']}")
    print(f"  序列号: {_leaf_field(payload, 'serial_number')}")
    print(f"  指纹: {_leaf_field(payload, 'sha256_fingerprint')}")
    print(f"  有效期: {_leaf_field(payload, 'not_before')} -> "
          f"{_leaf_field(payload, 'not_after')}")
    if failures:
        print("  核验结果: 不通过")
        for item in failures:
            print(f"    ! {item}")
        return EXIT_FAIL
    print("  核验结果: 通过（签名有效、结论可复算、无私钥泄漏）")
    return EXIT_OK


def _case_id(payload: dict) -> str:
    return payload["receipt_id"] and payload["evidence_locator"][
        "evidence_file"
    ].split("/")[-1].replace(".json", "")


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(LAB_ROOT))
    except ValueError:
        return str(path)


def _leaf_field(payload: dict, field: str):
    leaf = payload.get("received_certificate") or {}
    return leaf.get(field, "N/A")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return EXIT_USAGE
    return run(Path(argv[1]))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
