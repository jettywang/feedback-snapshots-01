"""Item-by-item acceptance check for the generated evidence reports.

It only reads the JSON/text reports produced from the finished wheels and
checks that every expected conclusion carries sources, a verdict and a
trust level. Exit code 0 means every check passed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "evidence_lab" / "reports"

checks: list[tuple[bool, str, str]] = []


def check(condition: bool, label: str, detail: str = "") -> None:
    checks.append((bool(condition), label, detail))


def load(name: str):
    return json.loads((REPORTS / name).read_text(encoding="utf-8"))


a_cmd = load("A_command.json")
a_var = load("A_command_normalized_variant.json")
a_inv = load("A_inventory.json")
a_ver = load("A_verify.json")
b_ver = load("B_verify.json")
b_inv = load("B_inventory.json")
t_ver = load("T_pristine_verify.json")
c_cmd = load("C_edge_command.json")
c_ver = load("C_edge_verify.json")

check(a_cmd["found"] is True, "A 命令被命中", a_cmd["normalized_query"])
check(a_cmd["same_name_coexists"] is True, "A 同名声明同时共存")
check(
    set(a_cmd["coexisting_kinds"])
    == {"console_entry", "plugin_entry", "archived_script"},
    "A 三类身份齐全（控制台/插件/归档脚本）",
    ",".join(a_cmd["coexisting_kinds"]),
)

claims = {c["kind"]: c for c in a_cmd["claims"]}
console = claims.get("console_entry", {})
check(console.get("section") == "console_scripts", "A 控制台入口区段正确")
check(console.get("declaration_verdict") == "verified", "A 入口声明文件摘要已核实")
check(
    console.get("source_member", "").endswith(".dist-info/entry_points.txt"),
    "A 控制台来源落到 entry_points.txt 成员",
    console.get("source_member", ""),
)
check(console.get("source_line") == 2, "A 控制台来源落到具体行 L2", f"L{console.get('source_line')}")
check(console.get("record_line") == 7, "A entry_points.txt 对应 RECORD:L7", f"L{console.get('record_line')}")
check(console.get("target_module_member") == "evidence_samename/cli.py", "A 目标模块成员可定位")
check(console.get("target_module_verdict") == "verified", "A 目标模块字节摘要已核实")
check(console.get("callable_verdict") == "source_required", "A 可调用对象判定为需源码确认")
check(
    any(ref.startswith("RECORD:L") for ref in console.get("evidence_refs", [])),
    "A 控制台证据链含 RECORD 行锚点",
)

plugin = claims.get("plugin_entry", {})
check(plugin.get("section") == "evidence.probes", "A 插件声明位于自定义组 evidence.probes")
check(plugin.get("declaration_verdict") == "verified", "A 插件声明摘要已核实")
check(plugin.get("callable_verdict") == "source_required", "A 插件可调用对象需源码确认")

script = claims.get("archived_script", {})
check(
    script.get("member") == "evidence_samename-1.0.0.data/scripts/evidence-probe",
    "A 脚本路径为 *.data/scripts/evidence-probe",
    script.get("member", ""),
)
check(script.get("verdict") == "verified", "A 归档脚本存在且摘要对得上")
check(script.get("record_line") == 4, "A 脚本对应 RECORD:L4", f"L{script.get('record_line')}")
check(script.get("executable_bit") is True and script.get("executable_mode") == "0755", "A 脚本带可执行位 0755")

check(a_var["found"] is True and len(a_var["claims"]) == 3, "A 规范化变体 EVIDENCE_PROBE 同样关联三类身份")

check(a_ver["trust"]["code"] == "record_consistent", "A 总体可信度 record_consistent")
check(len(a_ver["record_audit"]["digest_mismatch"]) == 0, "A 无摘要冲突")
record_a = a_inv.get("record") or {}
check(
    record_a.get("verdict") == "unverified"
    and record_a.get("reason_code") == "record_self_hash_absent",
    "A RECORD 自身归入“归档有但无可用证据”（规范允许的空摘要）",
)

mismatches = b_ver["record_audit"]["digest_mismatch"]
check(b_ver["trust"]["code"] == "record_conflict", "B 总体可信度为 record_conflict")
check(len(mismatches) == 1, "B 恰好一条摘要不一致", f"count={len(mismatches)}")
if mismatches:
    bad = mismatches[0]
    check(
        bad["member"] == "evidence_tampered/__init__.py",
        "B 冲突成员是普通代码成员 __init__.py",
        bad["member"],
    )
    check(bad["digest_record"] != bad["digest_actual"], "B RECORD 摘要与实测摘要不同")
    check(
        bad.get("size_record") == bad.get("size_actual") == 106,
        "B 等长篡改：大小一致，仅摘要冲突",
        f"record={bad.get('size_record')} actual={bad.get('size_actual')}",
    )
    check(bad.get("record_line") == 1, "B 冲突可落到 RECORD:L1", f"L{bad.get('record_line')}")
check(len(b_ver["record_audit"]["missing_from_archive"]) == 0, "B 无缺失成员冲突")
check(
    any(i["member"].endswith(".dist-info/RECORD") for i in b_ver["record_audit"]["unverified"]),
    "B RECORD 自身同样是无摘要证据状态",
)
check(
    t_ver["trust"]["code"] == "record_consistent"
    and len(t_ver["record_audit"]["digest_mismatch"]) == 0,
    "T 未篡改原件作为对照：record_consistent",
)

c_claims = c_cmd.get("claims", [])
check(c_cmd.get("found") is True and len(c_claims) == 1, "C 边缘轮命中唯一 ghost-cmd 脚本")
if c_claims:
    edge = c_claims[0]
    check(edge.get("kind") == "archived_script", "C ghost-cmd 身份是实际归档脚本")
    check(
        edge.get("member") == "evidence_edge-0.1.0.data/scripts/ghost-cmd",
        "C 脚本路径落在 .data/scripts",
        edge.get("member", ""),
    )
    check(edge.get("verdict") == "unverified", "C 未登记 RECORD 的脚本判定为 unverified")
    check(edge.get("confidence") == "indeterminate", "C 可信度为 indeterminate（无可用摘要证据）")
    check(edge.get("record_line") is None, "C 没有 RECORD 行锚点")
check(
    any("ghost-cmd" in m for m in c_ver["record_audit"]["unlisted_members"])
    and c_ver["trust"]["code"] == "unlisted_members",
    "C verify 列出未登记成员且信任级为 unlisted_members",
)

leak_markers = [str(ROOT), "/Users/", "/private/var", "/var/folders"]
leaks: list[str] = []
for path in sorted(REPORTS.iterdir()):
    if path.suffix not in {".json", ".txt"}:
        continue
    text = path.read_text(encoding="utf-8")
    for marker in leak_markers:
        if marker and marker in text:
            leaks.append(f"{path.name} contains {marker!r}")
check(not leaks, "所有报告不含生成机器全路径/临时目录", "; ".join(leaks))

width = max(len(label) for _, label, _ in checks)
failed = 0
for ok, label, detail in checks:
    mark = "PASS" if ok else "FAIL"
    if not ok:
        failed += 1
    suffix = f" — {detail}" if detail and not ok else (f" ({detail})" if detail and ok and len(detail) < 60 else "")
    print(f"[{mark}] {label.ljust(width)}{suffix}")

print(f"\n{len(checks) - failed}/{len(checks)} checks passed")
if failed:
    raise SystemExit(1)
