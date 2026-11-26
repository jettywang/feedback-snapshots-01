"""Human-readable Chinese rendering of the evidence inventory."""

from __future__ import annotations

import json
from typing import Any

KIND_LABEL = {
    "console_entry": "控制台入口",
    "gui_entry": "GUI 入口",
    "plugin_entry": "插件声明",
    "archived_script": "实际归档脚本",
}

VERDICT_LABEL = {
    "verified": "已核实：成员存在且摘要/大小与 RECORD 一致",
    "digest_mismatch": "冲突：归档摘要与 RECORD 不一致",
    "missing_from_archive": "冲突：RECORD 有记录但归档缺该成员",
    "unverified": "未能核实：成员在归档中，但没有可用摘要证据",
    "source_required": "需源码确认：清册只能证明声明/模块字节，可调用对象语义需源码",
    "not_packaged": "本 wheel 未打包该目标模块（可能由依赖提供）",
}


def dumps_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False)


def _line(char: str = "─", width: int = 72) -> str:
    return char * width


def render_inventory(report: dict[str, Any]) -> str:
    out: list[str] = []
    wheel = report["wheel"]
    dist = report.get("distribution") or {}
    out.append(_line("="))
    out.append(f"Wheel 证据清册  {wheel['filename']}")
    out.append(_line("="))
    out.append(f"wheel-sha256 : {wheel['sha256']}")
    if dist.get("name"):
        out.append(f"发行包        : {dist['name']} {dist.get('version') or ''}".rstrip())
    out.append(f"dist-info    : {report.get('dist_info') or '(未找到)'}")
    out.append(f"归档成员数    : {wheel.get('member_count', 0)}")
    trust = report["trust"]
    out.append(f"总体可信度    : {trust['level']} ({trust['code']}) — {trust['summary']}")

    out.append("")
    out.append("【RECORD 审计】")
    audit = report["record_audit"]
    out.append(
        f"  已核实 {audit['verified']}；摘要冲突 {len(audit['digest_mismatch'])}；"
        f"无可用证据 {len(audit['unverified'])}；RECORD 有/归档无 "
        f"{len(audit['missing_from_archive'])}；未登记成员 {len(audit['unlisted_members'])}"
    )
    record = report.get("record")
    if record:
        out.append(
            f"  RECORD 自身  : {record['member']} → {record['verdict']}"
            f"（{record.get('reason_code')}，RECORD 第 {record.get('record_line')} 行）"
        )
    for ev in audit["digest_mismatch"]:
        out.append(f"  [冲突] {ev['member']}")
        out.append(f"         RECORD: {ev.get('digest_record')} size={ev.get('size_record')}")
        out.append(f"         实际  : {ev.get('digest_actual')} size={ev.get('size_actual')}")
        if ev.get("record_line"):
            out.append(f"         来源  : RECORD:L{ev['record_line']}")
    for item in audit["unverified"]:
        if item["reason_code"] == "record_self_hash_absent":
            continue
        out.append(f"  [待证] {item['member']} ({item['reason_code']})")
    for item in audit["missing_from_archive"]:
        out.append(f"  [冲突] RECORD:L{item['record_line']} 登记的 {item['member']} 不在归档中")

    out.append("")
    out.append("【入口点区段】")
    sections = report["entry_point_sections"]
    if not sections:
        out.append("  （无 entry_points.txt 或无区段）")
    for section in sections:
        verdict = section["declaration_verdict"]
        out.append(
            f"  [{section['section']}]  来源 {section['source_member']}"
            f":L{section['header_line']}  声明文件={verdict}"
            f"  RECORD:L{section.get('record_line')}"
        )
        for entry in section["entries"]:
            out.append(f"    - {entry['name']}  (规范化 {entry['normalized_name']})")
            out.append(f"        目标: {entry['target']}")
            target = entry.get("target_module") or {}
            if target.get("member"):
                out.append(
                    f"        目标模块: {target['member']} → {target['verdict']}"
                    f"  RECORD:L{target.get('record_line')}"
                )
            else:
                out.append(f"        目标模块: {target.get('verdict')} ({target.get('reason_code')})")
            callable_ = entry.get("callable") or {}
            out.append(f"        可调用对象: {callable_.get('verdict')} ({callable_.get('reason_code')})")

    out.append("")
    out.append("【归档脚本路径】")
    if not report["scripts"]:
        out.append("  （未发现 .data/scripts 成员或带 shebang 的脚本）")
    for script in report["scripts"]:
        out.append(
            f"  - {script['member']}  [{script['script_kind']}]"
            f"  规范化={script['normalized_name']}"
        )
        out.append(
            f"      摘要={script['verdict']}  RECORD:L{script.get('record_line')}"
            f"  权限={script['executable_mode']} 可执行位={script['executable_bit']}"
        )
        if script.get("shebang"):
            out.append(f"      shebang: {script['shebang']}")

    if report["findings"]:
        out.append("")
        out.append("【发现项与来源】")
        for finding in report["findings"]:
            out.append(f"  ({finding['severity']}) {finding['code']}: {finding['message']}")
            for source in finding.get("sources", []):
                out.append(f"      来源: {source}")

    out.append(_line("="))
    return "\n".join(out)


def render_entry_points(report: dict[str, Any], section_filter: str | None = None) -> str:
    out = [f"入口点区段 — {report['wheel']['filename']}"]
    found = False
    for section in report["entry_point_sections"]:
        if section_filter and section["section"] != section_filter:
            continue
        found = True
        out.append("")
        out.append(
            f"[{section['section']}]  {section['source_member']}:L{section['header_line']}"
            f"  声明摘要={section['declaration_verdict']}"
            f"  RECORD:L{section.get('record_line')}"
        )
        for entry in section["entries"]:
            out.append(
                f"  {entry['name']} | 规范化={entry['normalized_name']} | "
                f"{entry['target']} | 定义于 L{entry['line']}"
            )
    if not found:
        out.append(f"（没有匹配的区段: {section_filter or '全部'}）")
    return "\n".join(out)


def render_scripts(report: dict[str, Any]) -> str:
    out = [f"归档脚本路径 — {report['wheel']['filename']}", ""]
    if not report["scripts"]:
        out.append("（未发现脚本成员）")
    for script in report["scripts"]:
        out.append(
            f"{script['normalized_name']}\t{script['member']}\t{script['verdict']}\t"
            f"RECORD:L{script.get('record_line')}\tmode={script['executable_mode']}\t"
            f"kind={script['script_kind']}"
        )
    return "\n".join(out)


def render_verify(report: dict[str, Any]) -> str:
    audit = report["record_audit"]
    out = [
        f"RECORD 校验 — {report['wheel']['filename']}",
        f"wheel-sha256: {report['wheel']['sha256']}",
        (
            f"member_count={audit['member_count']} verified={audit['verified']} "
            f"mismatch={len(audit['digest_mismatch'])} "
            f"unverified={len(audit['unverified'])} "
            f"missing={len(audit['missing_from_archive'])}"
        ),
        f"trust={report['trust']['level']} ({report['trust']['code']})",
        "",
    ]
    for ev in audit["digest_mismatch"]:
        out.append(f"[DIGEST-MISMATCH] {ev['member']} RECORD:L{ev.get('record_line')}")
        out.append(f"    expected {ev.get('digest_record')} ({ev.get('size_record')} bytes)")
        out.append(f"    actual   {ev.get('digest_actual')} ({ev.get('size_actual')} bytes)")
    for item in audit["missing_from_archive"]:
        out.append(f"[MISSING] {item['member']} RECORD:L{item['record_line']}")
    for item in audit["unverified"]:
        out.append(f"[UNVERIFIED] {item['member']} ({item['reason_code']})")
    if not audit["digest_mismatch"] and not audit["missing_from_archive"]:
        out.append("没有摘要冲突。")
    return "\n".join(out)


def render_command(report: dict[str, Any], result: dict[str, Any]) -> str:
    out = [
        f"命令核查 — 查询 {result['query']!r} → 规范化 {result['normalized_query']!r}",
        f"wheel: {report['wheel']['filename']} ({report['wheel']['sha256'][:16]}…)",
        f"命中: {result['found']}；同名类别共存: {result['coexisting_kinds']}；"
        f"总体可信程度: {result['overall_confidence']}",
        "",
    ]
    if not result["claims"]:
        out.append("该 wheel 中没有任何入口点、插件声明或归档脚本匹配此规范化命令名。")
        return "\n".join(out)

    for idx, claim in enumerate(result["claims"], start=1):
        label = KIND_LABEL.get(claim["kind"], claim["kind"])
        out.append(f"{idx}. {label}  原名={claim['name']} 规范化={claim['normalized_name']}")
        if claim["kind"] == "archived_script":
            record_anchor = f"L{claim['record_line']}" if claim.get("record_line") else "无登记行（未列入 RECORD）"
            out.append(
                f"   成员: {claim['member']} ({claim['script_kind']}, 匹配={claim['match_basis']})"
            )
            out.append(f"   完整性: {claim['verdict']} / 可信度 {claim['confidence']}")
            out.append(f"   RECORD 行: {record_anchor}")
            out.append(f"   权限: {claim['executable_mode']} 可执行位={claim['executable_bit']}")
            if claim.get("shebang"):
                out.append(f"   shebang: {claim['shebang']}")
        else:
            record_anchor = f"L{claim['record_line']}" if claim.get("record_line") else "无登记行"
            out.append(f"   区段: [{claim['section']}]  目标: {claim['target']}")
            out.append(
                f"   声明完整性: {claim['declaration_verdict']}  "
                f"来源 {claim['source_member']}:L{claim['source_line']}  "
                f"RECORD:{record_anchor}"
            )
            if claim.get("target_module_member"):
                out.append(
                    f"   目标模块: {claim['target_module_member']} → "
                    f"{claim['target_module_verdict']} RECORD:L{claim.get('target_module_record_line')}"
                )
            else:
                out.append(f"   目标模块: {claim.get('target_module_verdict')}")
            out.append(
                f"   可调用对象: {claim['callable_verdict']} "
                f"（RECORD 只证明字节；需源码才能确认属性/可调用性）"
            )
        out.append("   证据链:")
        for ref in claim["evidence_refs"]:
            out.append(f"     - {ref}")
        out.append("")
    return "\n".join(out)
