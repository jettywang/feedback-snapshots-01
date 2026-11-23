# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Human-readable rendering of a :class:`ReviewReport`."""

from .data import (
    ReviewReport,
    RuleReview,
    VERDICT_BLOCKED,
    VERDICT_NOT_VERIFIABLE,
    VERDICT_REMOVABLE,
)

_VERDICT_TEXT = {
    VERDICT_REMOVABLE: "可核实可删（证据充分）",
    VERDICT_BLOCKED: "禁止删除（归档决策会改变）",
    VERDICT_NOT_VERIFIABLE: "无法核实（存在无覆盖区域，保守不建议删除）",
}


def _render_rvals(rvals, optional_tokens=()):
    rendered = list(rvals)
    for index, token in enumerate(optional_tokens):
        position = len(rvals) - len(optional_tokens) + index
        if 0 <= position < len(rendered) and rendered[position] == "":
            rendered[position] = "<空:可选参数 %s>" % token
    return "(" + ", ".join(rendered) + ")"


def _render_rule_review(review: RuleReview) -> str:
    candidate = review.candidate
    lines = []
    lines.append(f"候选规则 {candidate.rule_id}: {candidate.csv_line}")
    lines.append(f"  规则类型: {'禁令 (deny)' if review.is_deny_rule else '允许 (allow)'}")
    lines.append(f"  快照中匹配条数: {review.matching_rule_count}")
    lines.append(f"  结论: {_VERDICT_TEXT[review.verdict]} ({review.verdict})")
    lines.append("  判定依据:")
    for reason in review.reasons:
        lines.append(f"    - {reason}")

    if review.role_chains:
        lines.append("  角色链（域继承已纳入对照）:")
        for subject, paths in review.role_chains.items():
            for path in paths:
                lines.append(f"    - {subject}: " + " -> ".join(path))
    else:
        lines.append("  角色链: 规则主体未出现在任何角色继承关系中（按字面主体生效）")

    if review.observed_requests:
        lines.append(f"  归档中由该规则直接决定的请求: {', '.join(review.observed_requests)}")
    else:
        lines.append("  归档中由该规则直接决定的请求: 无")

    if review.decision_changes:
        lines.append("  试删后受影响的归档请求:")
        for change in review.decision_changes:
            lines.append(
                f"    - {change.request_id} {_render_rvals(change.rvals, change.optional_tokens)}: "
                f"{change.change_label}"
            )
            baseline_rule = list(change.baseline_explain) or "无匹配（默认拒绝）"
            trial_rule = list(change.trial_explain) or "无匹配（默认拒绝）"
            lines.append(f"        基线解释规则: {baseline_rule}")
            lines.append(f"        试删解释规则: {trial_rule}")
    else:
        lines.append("  试删后受影响的归档请求: 无（所有归档请求决策保持不变）")

    if review.unobserved_probes:
        lines.append("  无覆盖区域（规则有效覆盖内、但归档没有对应请求，无法核实）:")
        for probe in review.unobserved_probes:
            if probe.baseline_allow:
                status = "基线判定 allow"
            else:
                status = "基线判定 deny（被更高优先级禁令遮蔽，匹配关系仍无法核实）"
            lines.append(
                f"    - 主体 {probe.subject} 经角色链 {' -> '.join(probe.role_chain)}: "
                f"{_render_rvals(probe.rvals, probe.optional_tokens)} {status}"
            )
    else:
        lines.append("  无覆盖区域: 未发现（有效覆盖均有归档请求佐证）")

    if review.orphan_probes:
        lines.append("  可核实的死覆盖（无任何角色授予可达该规则主体）:")
        for probe in review.orphan_probes:
            lines.append(
                f"    - 主体 {probe.subject}: {_render_rvals(probe.rvals, probe.optional_tokens)} "
                "仅在以规则自身为请求主体时成立，现实中无此主体"
            )

    if review.baseline_mismatches:
        lines.append("  基线校验失败的归档请求:")
        for archived in review.baseline_mismatches:
            lines.append(
                f"    - {archived.request_id} {_render_rvals(archived.rvals, archived.optional_tokens)}: "
                f"归档记录 {archived.expected_label}，但快照判定不一致"
            )
    return "\n".join(lines)


def render_text_report(report: ReviewReport) -> str:
    lines = [
        "Casbin 策略收敛复查报告（只读试删，不修改实际策略）",
        "=" * 60,
        f"模型文件: {report.model_path}",
        f"策略快照: {report.policy_path}",
        f"策略快照 SHA-256（回滚证据）: {report.policy_sha256}",
        f"请求字段顺序: {', '.join(report.request_tokens)}",
        f"归档请求数: {report.archived_count}",
        "",
    ]
    for index, review in enumerate(report.reviews):
        if index:
            lines.append("")
        lines.append(_render_rule_review(review))

    lines.append("")
    lines.append("可核实的收敛建议（仅列证据充分项）:")
    removable = [review for review in report.reviews if review.verdict == VERDICT_REMOVABLE]
    if removable:
        for review in removable:
            lines.append(f"  - 可删除 {review.candidate.rule_id}: {review.candidate.csv_line}")
    else:
        lines.append("  - 无：本批证据下没有可核实的删除项，实际策略保持不变")
    lines.append("")
    lines.append("说明: 原策略文件未被改动；上面的 SHA-256 与策略原文可作为回滚证据。")
    return "\n".join(lines)
