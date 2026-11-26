"""
离线排查编排：固定一份审计读取模板，逐变量构造对照运行，逐层比对，
产出“首处分歧层”证据与定位建议。

从仓库根目录运行（全程离线，不访问网络）：

    .venv/bin/python offline-triage/run_experiments.py

运行矩阵（资源值全部为虚构项目 fict-proj-audit）：
    A-baseline                  基准模板 + 基准快照（bundled 的字节级拷贝）
    B-partition-only            仅把模板里 arn:aws: 换成 arn:aws-cn:
    C-snapshot-only             基准模板 + 快照 S1（kms:KeySpec 仅从资源/动作条目摘除）
    D-control-condition-absent  基准模板 + 快照 S2（kms:KeySpec 从目录中彻底移除，对照）
    E-template-resource-typo    模板中 KMS ARN 资源段写成 keystore/（演示资源匹配失败）

输出：
    offline-triage/runs/<运行名>.json   每次运行的分层记录
    offline-triage/runs/report.md       逐层 diff 与首处分歧结论
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TRIAGE_DIR = REPO_ROOT / "offline-triage"
RUNS_DIR = TRIAGE_DIR / "runs"
BASELINE_TEMPLATE = TRIAGE_DIR / "templates" / "audit-read.yml"
BUNDLED_DATA = REPO_ROOT / "policy_sentry" / "shared" / "data" / "iam-definition.json"
WATCH_CONDITION = "kms:KeySpec"

MISSING = "__MISSING__"


def build_snapshots() -> dict[str, Path]:
    """构造三份目录快照，每份放进独立的伪 HOME，靠 HOME 切换 DATASTORE_FILE_PATH。"""
    homes: dict[str, Path] = {}

    def make_home(name: str, data: bytes) -> Path:
        home = RUNS_DIR / f"home-{name}"
        data_dir = home / ".policy_sentry"
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "iam-definition.json").write_bytes(data)
        return home

    baseline_bytes = BUNDLED_DATA.read_bytes()
    homes["baseline"] = make_home("baseline", baseline_bytes)

    s1 = json.loads(baseline_bytes)
    kms = s1["kms"]
    # S1：模拟“另一环境的目录快照”——资源/动作条目里没了 kms:KeySpec，
    # 服务级 conditions 表里还在（文档表不同步的典型形态）。
    kms["resources"]["key"]["condition_keys"] = [
        k for k in kms["resources"]["key"]["condition_keys"] if k != WATCH_CONDITION
    ]
    for priv in kms["privileges"].values():
        for rtype in priv["resource_types"].values():
            rtype["condition_keys"] = [
                k for k in rtype["condition_keys"] if k != WATCH_CONDITION
            ]
    homes["snap-no-resource-cond"] = make_home(
        "snap-no-resource-cond", json.dumps(s1).encode()
    )

    # S2：对照目录——kms:KeySpec 彻底不存在（服务级 conditions 也移除）。
    s2 = json.loads(json.dumps(s1))
    s2["kms"]["conditions"] = {
        k: v for k, v in s2["kms"]["conditions"].items() if k != WATCH_CONDITION
    }
    homes["snap-no-condition"] = make_home(
        "snap-no-condition", json.dumps(s2).encode()
    )
    return homes


def build_templates() -> dict[str, Path]:
    """从基准模板派生变体，字符串级替换保证‘只换一个变量’。"""
    templates: dict[str, Path] = {"baseline": BASELINE_TEMPLATE}
    base_text = BASELINE_TEMPLATE.read_text(encoding="utf-8")

    partition_swap = base_text.replace("arn:aws:", "arn:aws-cn:")
    assert partition_swap != base_text
    t1 = RUNS_DIR / "template-partition-only.yml"
    t1.write_text(partition_swap, encoding="utf-8")
    templates["partition-only"] = t1

    typo = base_text.replace(":key/11111111-", ":keystore/11111111-")
    assert typo != base_text
    t2 = RUNS_DIR / "template-resource-typo.yml"
    t2.write_text(typo, encoding="utf-8")
    templates["resource-typo"] = t2
    return templates


def run_trace(run_name: str, template: Path, home: Path) -> Path:
    output = RUNS_DIR / f"{run_name}.json"
    env = dict(os.environ)
    env["HOME"] = str(home)
    proc = subprocess.run(
        [sys.executable, str(TRIAGE_DIR / "trace_run.py"), str(template), str(output), run_name],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"{run_name} failed:\n{proc.stdout}\n{proc.stderr}")
    return output


def deep_diff(left, right, path: str = "$", out: list | None = None) -> list[dict]:
    if out is None:
        out = []
    if type(left) is not type(right):
        out.append({"path": path, "baseline": left, "variant": right})
        return out
    if isinstance(left, dict):
        for key in sorted(set(left) | set(right)):
            deep_diff(
                left.get(key, MISSING), right.get(key, MISSING), f"{path}.{key}", out
            )
    elif isinstance(left, list):
        if left != right:
            out.append({"path": path, "baseline": left, "variant": right})
    elif left != right:
        out.append({"path": path, "baseline": left, "variant": right})
    return out


def short(value, limit: int = 160) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def main() -> int:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    homes = build_snapshots()
    templates = build_templates()

    matrix = {
        "A-baseline": (templates["baseline"], homes["baseline"]),
        "B-partition-only": (templates["partition-only"], homes["baseline"]),
        "C-snapshot-only": (templates["baseline"], homes["snap-no-resource-cond"]),
        "D-control-condition-absent": (templates["baseline"], homes["snap-no-condition"]),
        "E-template-resource-typo": (templates["resource-typo"], homes["baseline"]),
    }

    records: dict[str, dict] = {}
    for run_name, (template, home) in matrix.items():
        output = run_trace(run_name, template, home)
        records[run_name] = json.loads(output.read_text(encoding="utf-8"))

    baseline = records["A-baseline"]
    layer_names = list(baseline["layers"].keys())

    lines: list[str] = []
    lines.append("# 离线排查报告：审计读取策略跨分区条件不一致\n")
    lines.append("所有资源值均为虚构项目 fict-proj-audit；全程离线，仅使用本仓库 Policy Sentry 的真实匹配与渲染入口。\n")

    lines.append("## 运行矩阵与数据锚点\n")
    lines.append("| 运行 | 变动 | datastore sha256 | 模板 sha256 |")
    lines.append("| --- | --- | --- | --- |")
    change_desc = {
        "A-baseline": "无（基准）",
        "B-partition-only": "仅分区 arn:aws:→arn:aws-cn:",
        "C-snapshot-only": "仅目录快照：资源/动作条目摘除 kms:KeySpec",
        "D-control-condition-absent": "仅目录快照：kms:KeySpec 彻底移除（对照）",
        "E-template-resource-typo": "仅模板：KMS 资源段 key/→keystore/",
    }
    for run_name, record in records.items():
        env = record["layers"]["layer0_environment"]
        lines.append(
            f"| {run_name} | {change_desc[run_name]} | `{env['datastore_sha256'][:16]}…` | `{env['template_sha256'][:16]}…` |"
        )
    lines.append("")

    lines.append("## 首处分歧层（各运行 vs A-baseline）\n")
    lines.append("| 运行 | 首处分歧层 | 最终渲染策略是否与基准一致 | 说明 |")
    lines.append("| --- | --- | --- | --- |")
    # layer0 是受控变量本身（换了哪份快照/哪个模板的证据锚点），
    # 首处分歧只在 layer1-layer4 的业务链路上判定。
    divergence_layers = [l for l in layer_names if l != "layer0_environment"]
    first_divergence: dict[str, str] = {}
    for run_name, record in records.items():
        if run_name == "A-baseline":
            continue
        first = "（无分歧）"
        for layer in divergence_layers:
            diffs = deep_diff(baseline["layers"][layer], record["layers"][layer])
            if diffs:
                first = layer
                break
        first_divergence[run_name] = first
        rendered_same = (
            baseline["layers"]["layer4_final_sid"]["rendered_policy"]
            == record["layers"]["layer4_final_sid"]["rendered_policy"]
        )
        notes = {
            "B-partition-only": "分歧只来自模板输入本身；匹配与条件能力层完全一致",
            "C-snapshot-only": "条件能力在资源/动作条目层缺失，服务级 conditions 表仍有该键",
            "D-control-condition-absent": "条件键在目录中彻底不存在（对照）",
            "E-template-resource-typo": "候选资源类型为空，KMS 的 Sid 整体消失",
        }
        lines.append(f"| {run_name} | {first} | {'是' if rendered_same else '否'} | {notes[run_name]} |")
    lines.append("")

    def match_signature(record):
        # 按请求顺序排列的候选资源类型（剥离回显的输入 ARN，只留匹配结果）
        return [
            (m["service_prefix"], sorted(c["resource_type_name"] for c in m["candidates"]))
            for m in record["layers"]["layer2_resource_match"]
        ]

    def capability_map(record):
        return {
            (c["resource_type_name"], c["access_level"]): (
                tuple(c["actions"]),
                tuple(c["condition_keys_available_to_raw_arn"]),
            )
            for c in record["layers"]["layer3_action_condition_capability"]
        }

    def rendered_normalized(record):
        # 把分区段归一化后再比，隔离“回显输入 ARN”带来的差异
        return json.dumps(record["layers"]["layer4_final_sid"]["rendered_policy"], sort_keys=True).replace(
            "arn:aws-cn:", "arn:aws:"
        )

    def sids(record):
        return [s["Sid"] for s in record["layers"]["layer4_final_sid"]["rendered_policy"]["Statement"]]

    lines.append("## 关键判定（剥离输入回显后的结构性比较）\n")
    lines.append("| 运行 | 候选资源类型一致 | 动作+条件能力一致 | 渲染策略一致 | 渲染策略一致（归一化分区后） | 缺失的 Sid |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    base_sids = sids(baseline)
    for run_name, record in records.items():
        if run_name == "A-baseline":
            continue
        match_same = match_signature(baseline) == match_signature(record)
        cap_same = capability_map(baseline) == capability_map(record)
        rendered_same = (
            baseline["layers"]["layer4_final_sid"]["rendered_policy"]
            == record["layers"]["layer4_final_sid"]["rendered_policy"]
        )
        rendered_norm_same = rendered_normalized(baseline) == rendered_normalized(record)
        missing_sids = [s for s in base_sids if s not in sids(record)]
        yn = lambda b: "是" if b else "否"
        lines.append(
            f"| {run_name} | {yn(match_same)} | {yn(cap_same)} | {yn(rendered_same)} | {yn(rendered_norm_same)} | {', '.join(missing_sids) or '无'} |"
        )
    lines.append("")
    lines.append("注：B 运行在 layer2/layer3 的 diff 明细里出现的差异，全部来自记录中回显的输入 ARN 字符串；"
                 "上表剥离回显后可见匹配结果与条件能力逐项一致。C/D 的渲染策略与基准逐字节一致，"
                 "说明条件缺失在 Policy Sentry 渲染层不可见，只能由 layer3 的能力记录暴露。\n")

    kms_watch = []
    for run_name in ("C-snapshot-only", "D-control-condition-absent"):
        record = records[run_name]
        for cap in record["layers"]["layer3_action_condition_capability"]:
            if cap["resource_type_name"] == "key":
                kms_watch.append(
                    f"- {run_name}：资源级条件键含 kms:KeySpec = "
                    f"{'kms:KeySpec' in cap['condition_keys_available_to_raw_arn']}；"
                    f"服务级 conditions 表含 kms:KeySpec = "
                    f"{'kms:KeySpec' in cap['service_level_condition_keys']}"
                )
    lines.append("## 对照：kms:KeySpec 在两份问题快照中的落点\n")
    lines.extend(kms_watch)
    lines.append("")

    lines.append("## 逐层 diff 明细\n")
    for run_name, record in records.items():
        if run_name == "A-baseline":
            continue
        lines.append(f"### {run_name} vs A-baseline\n")
        any_diff = False
        for layer in layer_names:
            diffs = deep_diff(baseline["layers"][layer], record["layers"][layer])
            if not diffs:
                continue
            any_diff = True
            lines.append(f"- `{layer}`：{len(diffs)} 处差异")
            for d in diffs[:8]:
                lines.append(f"  - `{d['path']}`")
                lines.append(f"    - 基准: {short(d['baseline'])}")
                lines.append(f"    - 变体: {short(d['variant'])}")
            if len(diffs) > 8:
                lines.append(f"  - … 其余 {len(diffs) - 8} 处见 runs/{run_name}.json")
        if not any_diff:
            lines.append("- 与基准完全一致")
        lines.append("")

    lines.append("## 定位建议（给运营）\n")
    lines.append("- 首处分歧在 `layer1_template_input` 且 layer2 候选非空、layer3 一致：模板输入差异。"
                 "Policy Sentry 的匹配器不比较 ARN 分区段（`ARN.same_resource_type` 只比服务与资源段），"
                 "单换分区不会改变匹配与条件能力；若审批工具此时已显示条件缺失，"
                 "应复核其实际提交的模板与其自身的分区处理，补的资料是审批工具实际收到的模板原文。")
    lines.append("- 首处分歧在 `layer1_template_input` 且 layer2 候选为空（或首处分歧直接在 layer2）：资源匹配失败。"
                 "候选资源类型为空时该 ARN 会被静默跳过、最终策略少一整条 Sid。"
                 "补齐方向：核对 ARN 资源段写法；若写法无误，则确认目录快照是否包含该服务/资源类型。")
    lines.append("- 首处分歧在 `layer3_action_condition_capability`：资料缺失。动作与 Sid 不变、仅条件能力缩水；"
                 "对照 `service_level_condition_keys` 可进一步区分——服务级仍有该键说明快照的资源/动作表陈旧"
                 "（补该服务的资源/动作段数据），服务级也没有说明目录本身不含该条件（换更新的 iam-definition.json 整包复核）。")
    lines.append("- 注意 `layer4_final_sid`：Policy Sentry 渲染的策略不含 Condition 块（内部 conditions 恒为空），"
                 "所以条件类分歧在最终文件层面不可见，必须靠 layer3 的中间记录定位。")
    lines.append("")

    report = RUNS_DIR / "report.md"
    report.write_text("\n".join(lines), encoding="utf-8")
    print(f"[run_experiments] report written to {report}")
    for run_name, layer in first_divergence.items():
        print(f"  {run_name}: first divergence = {layer}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
