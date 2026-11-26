"""Human-readable reporting and snapshot diffing for the offline analyzer."""

from __future__ import annotations

import json
from typing import Any

VERDICT_ORDER = [
    "DENY_EXPLICIT",
    "ALLOW_EFFECTIVE",
    "PENDING_CONDITION",
    "PENDING_MISSING_DATA",
    "IMPLICIT_DENY",
]

VERDICT_LABEL = {
    "DENY_EXPLICIT": "显式拒绝 (确定)",
    "ALLOW_EFFECTIVE": "有效允许 (确定)",
    "PENDING_CONDITION": "待确认-条件不可离线评价",
    "PENDING_MISSING_DATA": "待确认-缺少输入",
    "IMPLICIT_DENY": "隐式拒绝 (确定)",
}


def _fmt_hits(hits: list[dict[str, Any]]) -> str:
    if not hits:
        return "无"
    parts = []
    for hit in hits:
        parts.append(f"{hit['source']}::{hit['sid']} ({hit['effect']})")
    return "; ".join(parts)


def _fmt_evidence(records: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for record in records:
        for ev in record.get("evidence", []):
            lines.append(
                f"    - 条件 {ev['condition_key']} {ev['operator']} "
                f"期望[{ev['expected']}] 实际[{ev['actual']}] "
                f"=> {ev['status']}（{ev['reason']}；来源 {ev['origin']}）"
            )
    return lines


def render_text(report: dict[str, Any]) -> str:
    out: list[str] = []
    out.append(f"角色: {report['role']}   快照: {report['snapshot']}")
    out.append(
        f"权限边界: {'已提供' if report['boundary_present'] else '缺失'}"
        f"（完整性={report['boundary_completeness']}）"
    )
    if report["missing_inputs"]:
        out.append("缺失输入:")
        for item in report["missing_inputs"]:
            out.append(f"  - [{item['kind']}] {item['input']}: {item['note']}")
    else:
        out.append("缺失输入: 无（快照完整）")

    counts = {name: 0 for name in VERDICT_ORDER}
    for result in report["results"]:
        counts[result["verdict"]] += 1
    out.append("")
    out.append("汇总: " + "  ".join(
        f"{VERDICT_LABEL[name]}={counts[name]}" for name in VERDICT_ORDER))
    out.append("=" * 78)

    for result in report["results"]:
        out.append("")
        out.append(
            f"[{result['target_id']}] {result['action']}  资源={result['resource']}")
        out.append(f"  结论: {VERDICT_LABEL[result['verdict']]} "
                   f"({'确定' if result['determined'] else '待补件'})")
        out.append(f"  显式拒绝命中: {_fmt_hits(result['explicit_deny'])}")
        out.append(f"  身份侧允许: {_fmt_hits(result['identity_allows'])}")
        out.append(f"  边界侧允许: {_fmt_hits(result['boundary_allows'])}")
        if result["indeterminate_conditions"]:
            out.append("  无法评价的条件:")
            out.extend(_fmt_evidence(result["indeterminate_conditions"]))
            affected = sorted({
                rec["source"] for rec in result["indeterminate_conditions"]})
            out.append(f"  受影响输入/范围: {', '.join(affected)}")
        if result["relevant_gaps"]:
            out.append("  待补输入/范围:")
            for item in result["relevant_gaps"]:
                out.append(
                    f"    - 输入[{item['input']}] 范围[{item['scope']}]: "
                    f"{item['reason']}")
        if result["gap"]:
            out.append(f"  判定说明: {result['gap']}")
    return "\n".join(out)


def diff_reports(incomplete: dict[str, Any], complete: dict[str, Any]) -> str:
    before = {r["target_id"]: r for r in incomplete["results"]}
    after = {r["target_id"]: r for r in complete["results"]}
    lines: list[str] = []
    lines.append("缺件 -> 补齐 差异（仅列出结论发生变化的目标）")
    lines.append("=" * 78)
    changed = 0
    for target_id in sorted(before):
        old = before[target_id]
        new = after.get(target_id)
        if new is None:
            continue
        if old["verdict"] != new["verdict"]:
            changed += 1
            lines.append(
                f"[{target_id}] {new['action']} {new['resource']}\n"
                f"  {VERDICT_LABEL[old['verdict']]}  ->  "
                f"{VERDICT_LABEL[new['verdict']]}"
            )
    if changed == 0:
        lines.append("无目标结论发生变化。")
    lines.append("")
    lines.append("未变化目标保持原结论；两份授权策略与边界仍可各自单独分析。")
    return "\n".join(lines)


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)
