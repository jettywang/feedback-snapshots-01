"""报告渲染：人类可读文本与机器可读 JSON。

默认不输出恢复出的私钥 d 与 nonce k；只有显式 --reveal-secrets 才包含，
且 JSON 中会额外标注 redacted=false 提醒调用方妥善处置。
"""

from __future__ import annotations

from .analyzer import AuditReport, GroupReport

REASON_TEXT = {
    "duplicate_record": "重复记录（同摘要且 low-S 规范化后 s 相同），无新增信息",
    "same_message_repeat": "同一消息重复签名（z 相同），差分子方程消不掉 z，无法推导",
    "denominator_noninvertible": "存在配对的差分分母不可逆（s1≡s2 mod n），无法求逆",
    "no_candidate_matches_pubkey": "推导候选均无法重现声明公钥，线索不成立",
    "single_record": "同 r 只有一条记录，没有可配对的第二条签名",
    "cross_key_r_collision": "相同 r 来自不同公钥，属碰撞线索，不能跨钥匙合并推导",
    "invalid_signature_in_group": "组内含验证失败的签名，证据链不完整",
}


def _group_to_dict(group: GroupReport, reveal_secrets: bool) -> dict:
    data = {
        "status": (
            "confirmed_nonce_reuse"
            if group.confirmed
            else "unconfirmed_clue"
        ),
        "curve": group.curve,
        "r": group.r_hex,
        "record_ids": group.record_ids,
        "public_key_fingerprints": group.key_fingerprints,
        "cross_key": group.cross_key,
        "reason_codes": group.reason_codes,
        "reasons": [
            REASON_TEXT.get(code, code) for code in group.reason_codes
        ],
        "invalid_record_ids": group.invalid_record_ids,
        "pair_details": [
            {
                "pair": [pair.record_a, pair.record_b],
                "same_message": pair.same_message,
                "exact_duplicate": pair.exact_duplicate,
                "natural_denominator_invertible": (
                    pair.natural_denominator_invertible
                ),
                "candidate_count": len(pair.candidates),
            }
            for pair in group.pair_analyses
        ],
    }
    if group.confirmed:
        data["evidence_record_ids"] = group.evidence_record_ids
        data["derivation"] = group.derivation
        data["secrets"] = {
            "redacted": not reveal_secrets,
            "private_key_d": (
                format(group.confirmed_d, "x") if reveal_secrets else None
            ),
            "canonical_nonce_k": (
                format(group.confirmed_k, "x") if reveal_secrets else None
            ),
        }
    return data


def report_to_dict(report: AuditReport, reveal_secrets: bool = False) -> dict:
    return {
        "schema": "ecdsa-nonce-audit-report/v1",
        "summary": {
            "total_records": report.total_records,
            "curves": report.curve_counts,
            "r_groups": len(report.groups),
            "confirmed_nonce_reuse_groups": len(report.confirmed_groups),
            "unconfirmed_clue_groups": len(report.unconfirmed_clues),
            "invalid_signature_records": len(report.invalid_records),
        },
        "invalid_records": report.invalid_records,
        "confirmed": [
            _group_to_dict(group, reveal_secrets)
            for group in report.confirmed_groups
        ],
        "unconfirmed_clues": [
            _group_to_dict(group, reveal_secrets)
            for group in report.unconfirmed_clues
        ],
    }


def render_text(report: AuditReport, reveal_secrets: bool = False) -> str:
    lines = []
    lines.append("ECDSA nonce 重用离线审计报告")
    lines.append("=" * 48)
    lines.append(f"记录总数: {report.total_records}")
    lines.append(
        "曲线分布: "
        + ", ".join(f"{k}={v}" for k, v in report.curve_counts.items())
    )
    lines.append(f"同 r 分组数: {len(report.groups)}")
    lines.append(f"已确认 nonce 重用: {len(report.confirmed_groups)} 组")
    lines.append(f"未能确认的线索: {len(report.unconfirmed_clues)} 组")
    lines.append(f"验证失败签名: {len(report.invalid_records)} 条")

    if report.invalid_records:
        lines.append("")
        lines.append("[验证失败记录]")
        for item in report.invalid_records:
            lines.append(
                f"  - {item['id']} ({item['curve']}): {item['reason']}"
            )

    if report.confirmed_groups:
        lines.append("")
        lines.append("[已确认 nonce 重用]")
        for index, group in enumerate(report.confirmed_groups, 1):
            lines.append(
                f"  {index}. 曲线 {group.curve} r=0x{group.r_hex[:16]}…"
            )
            lines.append(f"     证据记录: {', '.join(group.evidence_record_ids)}")
            lines.append(
                "     推导条件: 候选 d*G 等于公钥；组内全部签名验证通过；"
                "所有不同消息配对收敛到同一 d"
            )
            orient = group.derivation.get("s_orientations", {})
            if orient:
                rendered = ", ".join(
                    f"{pair}→{'/'.join('|'.join(d) for d in dirs)}"
                    for pair, dirs in orient.items()
                )
                lines.append(f"     s 方向枚举: {rendered}")
            secrets = "已隐藏（--reveal-secrets 可显示）"
            if reveal_secrets:
                secrets = (
                    f"d=0x{group.confirmed_d:x} "
                    f"canonical_k=0x{group.confirmed_k:x}"
                )
            lines.append(f"     恢复秘密: {secrets}")

    if report.unconfirmed_clues:
        lines.append("")
        lines.append("[未能确认的同 r 线索]")
        for index, group in enumerate(report.unconfirmed_clues, 1):
            lines.append(
                f"  {index}. 曲线 {group.curve} r=0x{group.r_hex[:16]}…"
            )
            lines.append(f"     涉及记录: {', '.join(group.record_ids)}")
            for code in group.reason_codes:
                lines.append(f"     - {code}: {REASON_TEXT.get(code, code)}")
            if group.invalid_record_ids:
                lines.append(
                    "     验证失败记录: " + ", ".join(group.invalid_record_ids)
                )

    if not report.groups:
        lines.append("")
        lines.append("没有任何同 r 分组（所有 r 两两不同）。")
    lines.append("")
    return "\n".join(lines)
