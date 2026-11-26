"""Render evidence JSON as a self-contained, offline HTML report.

No JavaScript, fonts, images, or network resources are used. The generated
report can be opened from a laptop on an air-gapped incident bridge.
"""

from __future__ import annotations

import html
import json
from typing import Any

CATEGORY_LABELS = {
    "parent": ("parent", "parent 改变"),
    "tracestate": ("state", "tracestate 不再适用"),
    "baggage": ("baggage", "baggage 被改写"),
    "sampling": ("sampling", "采样结论改变"),
}

CSS = """
:root {
  --ink: #17212b;
  --muted: #5d6b7a;
  --line: #d7dee7;
  --panel: #ffffff;
  --bg: #f3f6fa;
  --blue: #1d5fbf;
  --blue-soft: #e8f0fc;
  --purple: #6b3fa0;
  --purple-soft: #f1eafb;
  --orange: #a85a00;
  --orange-soft: #fff0dd;
  --red: #b3261e;
  --red-soft: #fdecea;
  --green: #1f6b45;
  --green-soft: #e7f5ed;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC",
        "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
}
main { max-width: 1240px; margin: 0 auto; padding: 28px 22px 64px; }
header.hero {
  background: linear-gradient(135deg, #10233c 0%, #1d5fbf 62%, #3b82c4 100%);
  color: #fff; border-radius: 14px; padding: 26px 28px 22px;
  box-shadow: 0 8px 24px rgba(16, 35, 60, .18);
}
header.hero h1 { margin: 0 0 6px; font-size: 25px; line-height: 1.25; }
header.hero p { margin: 0; color: #dbe8f7; }
.hero-meta { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }
.hero-meta span {
  border: 1px solid rgba(255,255,255,.35); background: rgba(255,255,255,.12);
  border-radius: 999px; padding: 4px 11px; font-size: 12px;
}
.mono { font-family: var(--mono); }
h2 { font-size: 19px; margin: 32px 0 10px; padding-bottom: 6px; border-bottom: 2px solid var(--line); }
h3 { font-size: 15px; margin: 20px 0 8px; }
p.note { color: var(--muted); margin: 6px 0 14px; }
.cards { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-top: 18px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px 15px; }
.card .k { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
.card .v { font-size: 17px; font-weight: 650; margin-top: 4px; overflow-wrap: anywhere; }
.card .s { color: var(--muted); font-size: 12px; margin-top: 4px; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 16px; overflow-x: auto; }
.card.hot { border-color: #e0b06a; box-shadow: inset 0 0 0 1px #f2d3a7; }
.legend { display: flex; flex-wrap: wrap; gap: 10px; margin: 8px 0 0; }
.badge, .tag {
  display: inline-block; border-radius: 999px; padding: 2px 9px; font-size: 12px;
  font-weight: 600; white-space: nowrap; border: 1px solid transparent;
}
.badge.parent, .tag.parent { color: var(--blue); background: var(--blue-soft); border-color: #c8daf7; }
.badge.state, .tag.state { color: var(--purple); background: var(--purple-soft); border-color: #ddcdf5; }
.badge.baggage, .tag.baggage { color: var(--orange); background: var(--orange-soft); border-color: #f2d3a7; }
.badge.sampling, .tag.sampling { color: var(--red); background: var(--red-soft); border-color: #f3c3c0; }
.badge.ok { color: var(--green); background: var(--green-soft); border-color: #bfe3cf; }
.badge.neutral { color: var(--muted); background: #eef2f6; border-color: #dbe3ec; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { border: 1px solid var(--line); padding: 8px 9px; text-align: left; vertical-align: top; }
th { background: #eef3f8; font-weight: 650; white-space: nowrap; }
tr.divergent td { background: #fffaf0; }
tr.divergent td:first-child { border-left: 4px solid var(--orange); }
td code, p code, li code { font-family: var(--mono); font-size: 12px; background: #eef2f6; border-radius: 4px; padding: 1px 5px; }
pre {
  background: #0f1c2b; color: #e7eef7; border-radius: 8px; padding: 14px 16px;
  overflow-x: auto; font: 12px/1.5 var(--mono);
}
.flow { width: 100%; height: auto; display: block; }
.flow text { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", sans-serif; }
.flow .box { fill: #fff; stroke: #cbd5e1; stroke-width: 1.4; }
.flow .box.hot { stroke: #a85a00; stroke-width: 2.2; }
.flow .stage { fill: #f4f7fb; stroke: #cbd5e1; stroke-width: 1.2; }
.flow .arrow { stroke: #7b8b9d; stroke-width: 1.6; fill: none; marker-end: url(#arrow); }
.flow .title { font-size: 13px; font-weight: 650; fill: #17212b; }
.flow .small { font-size: 11px; fill: #5d6b7a; }
.flow .val { font-size: 11px; fill: #17212b; font-family: var(--mono); }
.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.stack { display: grid; gap: 8px; }
.finding { border-left: 4px solid var(--line); padding: 10px 14px; margin: 10px 0; background: #fbfcfe; border-radius: 0 8px 8px 0; }
.finding strong { display: block; margin-bottom: 3px; }
.finding.parent { border-left-color: var(--blue); }
.finding.state { border-left-color: var(--purple); }
.finding.baggage { border-left-color: var(--orange); }
.finding.sampling { border-left-color: var(--red); }
.finding.neutral { border-left-color: var(--muted); }
ul.clean { margin: 6px 0 0 18px; padding: 0; }
ul.clean li { margin: 4px 0; }
details { margin-top: 10px; }
summary { cursor: pointer; color: var(--blue); }
footer { color: var(--muted); font-size: 12px; margin-top: 36px; }
@media (max-width: 900px) {
  .cards { grid-template-columns: 1fr 1fr; }
  .two-col { grid-template-columns: 1fr; }
}
@media print {
  body { background: #fff; }
  main { max-width: none; padding: 0; }
  header.hero { box-shadow: none; }
  .panel, .card { break-inside: avoid; }
}
"""


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def code(value: Any) -> str:
    return f"<code>{esc(value)}</code>"


def bool_text(value: bool) -> str:
    return "是" if value else "否"


def short_span(value: str | None) -> str:
    return value or "—"


def tags(categories: list[str]) -> str:
    if not categories:
        return '<span class="badge neutral">无变化</span>'
    return " ".join(
        f'<span class="tag {esc(CATEGORY_LABELS.get(c, (c, c))[0])}">'
        f'{esc(CATEGORY_LABELS.get(c, (c, c))[1])}</span>'
        for c in categories
    )


def baggage_text(entries: dict[str, Any]) -> str:
    if not entries:
        return "（空）"
    return ", ".join(f"{key}={value}" for key, value in entries.items())


def context_summary(snapshot: dict[str, Any]) -> str:
    span = snapshot["span"]
    state = span["tracestate"] or "—"
    return (
        f'parent={code(short_span(span["span_id"]))} '
        f'sampled={code(str(span["sampled"]).lower())} '
        f'tracestate={code(state)}'
    )


def stage_table(comparison: dict[str, Any], runs: dict[tuple[str, str], dict[str, Any]]) -> str:
    rows = []
    for pair in comparison["stage_pairs"]:
        index = pair["index"]
        run_a = runs[(comparison["fixture_id"], "A")]["stages"][index - 1]
        run_b = runs[(comparison["fixture_id"], "B")]["stages"][index - 1]
        divergent = " class=\"divergent\"" if pair["material"] else ""
        rows.append(
            f"<tr{divergent}>"
            f"<td><strong>{index}</strong><br><span class=\"small\">{esc(pair['propagator_A'])}"
            f"<br>vs<br>{esc(pair['propagator_B'])}</span></td>"
            f"<td>{context_summary(run_a['returned_context'])}"
            f"<br><span class=\"small\">child recording={esc(str(run_a['child_span']['recording']).lower())}"
            f", exported={run_a['child_span']['exported_count']}</span></td>"
            f"<td>{context_summary(run_b['returned_context'])}"
            f"<br><span class=\"small\">child recording={esc(str(run_b['child_span']['recording']).lower())}"
            f", exported={run_b['child_span']['exported_count']}</span></td>"
            f"<td>{tags(pair['categories'])}</td>"
            "</tr>"
        )
    return (
        '<div class="panel"><table><thead><tr>'
        "<th>阶段 / 传播器</th><th>A：tracecontext,baggage,b3</th>"
        "<th>B：tracecontext,baggage,jaeger</th><th>该阶段 A/B 差异</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )


def injection_table(comparison: dict[str, Any]) -> str:
    final = comparison["final"]
    headers = sorted(set(final["injected_A"]) | set(final["injected_B"]))
    rows = []
    for header in headers:
        a = final["injected_A"].get(header, "—")
        b = final["injected_B"].get(header, "—")
        cls = " class=\"divergent\"" if a != b else ""
        rows.append(
            f"<tr{cls}><td>{code(header)}</td><td>{code(a)}</td><td>{code(b)}</td></tr>"
        )
    return (
        '<div class="panel"><table><thead><tr><th>注入 header</th>'
        "<th>A 最终注入</th><th>B 最终注入</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def flow_svg(comparison: dict[str, Any]) -> str:
    final = comparison["final"]
    full = comparison["fixture_id"] == "full"
    a_parent = final["parent_A"][:8] + "…"
    b_parent = final["parent_B"][:8] + "…"
    a_bag = "tenant=blue" if full else "（无 baggage）"
    b_bag = "tenant=green" if full else "（无 baggage）"
    a_sample = "sampled" if final["sampled_A"] else "NOT sampled"
    b_sample = "sampled" if final["sampled_B"] else "NOT sampled"
    trace = final["trace_id_A"]
    return f"""
<svg class="flow" viewBox="0 0 1180 430" role="img" aria-label="传播器阶段与首次分歧流程图">
  <defs>
    <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="#7b8b9d"></path>
    </marker>
  </defs>
  <text x="20" y="26" class="title">入站载体</text>
  <rect class="box" x="20" y="38" width="205" height="112" rx="9"></rect>
  <text x="34" y="60" class="small">traceparent</text>
  <text x="34" y="78" class="val">…{esc(trace[-12:])}-00f067…-01</text>
  <text x="34" y="100" class="small">tracestate / baggage</text>
  <text x="34" y="118" class="val">{'vendor=alpha…' if full else '（缺失）'}</text>
  <text x="34" y="136" class="small">B3 / Jaeger 字段</text>

  <path class="arrow" d="M225 94 L270 94"></path>
  <rect class="stage" x="270" y="38" width="165" height="112" rx="9"></rect>
  <text x="284" y="60" class="title">阶段 1</text>
  <text x="284" y="80" class="small">TraceContext</text>
  <text x="284" y="100" class="val">parent 00f067…</text>
  <text x="284" y="120" class="val">state {'present' if full else 'absent'}</text>

  <path class="arrow" d="M435 94 L480 94"></path>
  <rect class="stage" x="480" y="38" width="165" height="112" rx="9"></rect>
  <text x="494" y="60" class="title">阶段 2</text>
  <text x="494" y="80" class="small">W3C Baggage</text>
  <text x="494" y="100" class="val">baggage {'tenant=blue' if full else '（空）'}</text>
  <text x="494" y="120" class="val">span 不变</text>

  <path class="arrow" d="M645 94 L700 70"></path>
  <path class="arrow" d="M645 112 L700 286"></path>

  <rect class="stage hot" x="700" y="34" width="196" height="96" rx="9"></rect>
  <text x="714" y="56" class="title">阶段 3A：B3MultiFormat</text>
  <text x="714" y="76" class="small">x-b3-*</text>
  <text x="714" y="96" class="val">parent b3b3…</text>
  <text x="714" y="116" class="val">tracestate → 空</text>

  <rect class="stage hot" x="700" y="274" width="196" height="96" rx="9"></rect>
  <text x="714" y="296" class="title">阶段 3B：Jaeger</text>
  <text x="714" y="316" class="small">uber-trace-id / uberctx-*</text>
  <text x="714" y="336" class="val">parent 0a0a…</text>
  <text x="714" y="356" class="val">tracestate → 空</text>

  <path class="arrow" d="M896 82 L950 82"></path>
  <path class="arrow" d="M896 322 L950 322"></path>

  <rect class="box" x="950" y="26" width="210" height="142" rx="9"></rect>
  <text x="964" y="48" class="title">A 下游</text>
  <text x="964" y="68" class="small">trace ID 相同</text>
  <text x="964" y="88" class="val">{esc(final['trace_id_A'][:16])}…</text>
  <text x="964" y="108" class="val">parent {esc(a_parent)}</text>
  <text x="964" y="128" class="val">{esc(a_sample)}</text>
  <text x="964" y="148" class="val">{esc(a_bag)}</text>

  <rect class="box" x="950" y="266" width="210" height="142" rx="9"></rect>
  <text x="964" y="288" class="title">B 下游</text>
  <text x="964" y="308" class="small">trace ID 相同</text>
  <text x="964" y="328" class="val">{esc(final['trace_id_B'][:16])}…</text>
  <text x="964" y="348" class="val">parent {esc(b_parent)}</text>
  <text x="964" y="368" class="val">{esc(b_sample)}</text>
  <text x="964" y="388" class="val">{esc(b_bag)}</text>

  <text x="700" y="404" class="small">首次差异：阶段 3（第三传播器）</text>
  <text x="20" y="404" class="small">阶段 1、2 在两个 profile 中逐字节一致 → 分歧不可能来自入站 W3C 解析或 baggage 读取。</text>
</svg>"""


def finding_block(key: str, title: str, body: str, category: str = "neutral") -> str:
    return (
        f'<div class="finding {esc(category)}"><strong>{esc(title)}</strong>'
        f"<div>{body}</div></div>"
    )


def render_findings(report: dict[str, Any]) -> str:
    blocks = []
    for comparison in report["comparisons"]:
        name = comparison["fixture_id"]
        finding = report["findings"][name]
        first = comparison["first_divergence"]
        stage = (
            f"阶段 {first['index']} · {first['propagator_A']} vs {first['propagator_B']}"
            if first
            else "无"
        )
        ordered = [c for c in ("parent", "tracestate", "baggage", "sampling") if c in finding["first_divergence_categories"]]
        badges = tags(ordered)
        rows = "".join(
            f"<li>{esc(item)}</li>" for item in finding["conclusions"]
        )
        blocks.append(
            f'<section class="panel"><h3>{esc(finding["fixture_label"])} '
            f'<span class="badge neutral">{esc(name)}</span></h3>'
            f"<p>首个发生差异的传播器与阶段：{code(stage)} {badges}</p>"
            f'<div class="stack">'
            + finding_block(
                "same-trace",
                "trace ID 相同并不等于链路可互换",
                f"两侧最终 trace ID 都是 {code(comparison['final']['trace_id_A'])}，"
                f"但 parent、tracestate、baggage 或采样结论不同；"
                f"值班时必须以 parent + baggage + sampled 三者联合判断。",
                "neutral",
            )
            + "</div>"
            f"<ul class=\"clean\">{rows}</ul></section>"
        )
    return "".join(blocks)


def render_stage_cards(comparison: dict[str, Any], run: dict[str, Any]) -> str:
    cards = []
    for stage in run["stages"]:
        categories = stage["context_diff"]["categories"]
        hot = " hot" if categories else ""
        child = stage["child_span"]
        inj = stage["final_injected"]
        cards.append(
            f'<div class="card{hot}">'
            f'<div class="k">阶段 {stage["index"]} · {esc(stage["propagator"])}</div>'
            f'<div class="v">{esc(short_span(stage["returned_context"]["span"]["span_id"]))}</div>'
            f'<div class="s">sampled={esc(str(stage["returned_context"]["span"]["sampled"]).lower())} · '
            f'tracestate={esc(stage["returned_context"]["span"]["tracestate"] or "—")}</div>'
            f'<div class="s">child recording={esc(str(child["recording"]).lower())}, '
            f'exported={child["exported_count"]}</div>'
            f'<div class="s">注入 {code(", ".join(inj) if inj else "（无）")}</div>'
            f"<div style=\"margin-top:6px\">{tags(categories)}</div>"
            "</div>"
        )
    return "".join(cards)


def render_html(report: dict[str, Any]) -> str:
    full = next(c for c in report["comparisons"] if c["fixture_id"] == "full")
    partial = next(c for c in report["comparisons"] if c["fixture_id"] == "partial")
    runs = {(run["fixture_id"], run["order_id"]): run for run in report["runs"]}
    order_a = next(o for o in report["orderings"] if o["id"] == "A")
    order_b = next(o for o in report["orderings"] if o["id"] == "B")
    all_first = [c["first_divergence"]["index"] for c in report["comparisons"] if c["first_divergence"]]
    first_stage = min(all_first) if all_first else None
    findings = report["findings"]

    four = "".join(
        f"<tr><td><strong>{esc(name)}</strong></td><td>{esc(desc)}</td><td>{code(path)}</td></tr>"
        for name, desc, path in (
            (
                "入站载体",
                "请求级入站 header，按 key 排序；三个 stage 都从同一份载体重新读取，因此前两阶段一致可以排除入站差异。",
                "runs[].stages[].inbound_carrier",
            ),
            (
                "传播器返回的上下文",
                "span_id / is_remote / sampled / trace_flags / tracestate / baggage。",
                "runs[].stages[].returned_context",
            ),
            (
                "子 span",
                "用该阶段上下文真实启动的 SDK SERVER span：是否 recording、是否导出、parent。",
                "runs[].stages[].child_span",
            ),
            (
                "最后注入值",
                "该 profile 从该阶段上下文注入到下游的全部 header。",
                "runs[].stages[].final_injected",
            ),
        )
    )

    fixture_rows = "".join(
        f"<tr><td>{code(f['id'])}</td><td>{esc(f['label'])}</td>"
        f"<td>{esc(', '.join(f['missing']) if f['missing'] else '无')}</td>"
        f"<td>{esc(f['note'])}</td></tr>"
        for f in report["fixtures"]
    )

    ordering_rows = "".join(
        f"<tr><td>{code(o['id'])}</td><td>{code(o['label'])}</td>"
        f"<td>{esc(' → '.join(o['propagators']))}</td><td>{esc(o['description'])}</td></tr>"
        for o in report["orderings"]
    )

    full_finding = findings["full"]
    partial_finding = findings["partial"]

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>跨服务 trace 传播取证 · {esc(report['e2e_id'])}</title>
<style>{CSS}</style>
</head>
<body>
<main>
<header class="hero">
  <h1>跨服务 trace 传播取证：同 trace ID，不同采样来源与业务关联</h1>
  <p>离线复跑 OpenTelemetry Python 复合传播器；用真实 extract / inject 与真实 SDK 子 span 定位首个差异阶段。</p>
  <div class="hero-meta">
    <span>端到端关联号 <b class="mono">{esc(report['e2e_id'])}</b></span>
    <span>schema <b class="mono">{esc(report['schema'])}</b></span>
    <span>首个差异：阶段 <b>{esc(first_stage)}</b></span>
    <span>两种 profile 共享 tracecontext,baggage 前缀</span>
  </div>
</header>

<div class="cards">
  <div class="card"><div class="k">相同 trace ID</div><div class="v mono">{esc(full['final']['trace_id_A'])}</div><div class="s">full 与 partial 两侧均相同</div></div>
  <div class="card"><div class="k">首个差异传播器</div><div class="v">阶段 {esc(first_stage)} · B3 vs Jaeger</div><div class="s">阶段 1/2 逐字段一致</div></div>
  <div class="card"><div class="k">完整请求 · parent</div><div class="v mono">{esc(full['final']['parent_A'][:10])} / {esc(full['final']['parent_B'][:10])}</div><div class="s">A/B3 与 B/Jaeger 不同</div></div>
  <div class="card"><div class="k">缺字段请求 · 采样</div><div class="v">{esc(str(partial['final']['sampled_A']).lower())} / {esc(str(partial['final']['sampled_B']).lower())}</div><div class="s">A 丢子 span；B 正常导出</div></div>
</div>

<h2>结论先行</h2>
<div class="panel">
  <p class="note">以下为<strong>完整请求</strong>；两个 profile 的入站载体完全相同，差异只可能从第三个传播器开始。实测首次差异确实落在阶段 3。缺字段请求的差异见下一节。</p>
  <div class="two-col">
    <div>
      <h3>A：tracecontext,baggage,b3</h3>
      <div class="stack">
        {finding_block("parent", "parent 改变", f"最终 parent={code(full['final']['parent_A'])}；下游以 B3 span 作为远端父。", "parent")}
        {finding_block("state", "tracestate 不再适用", "阶段 2 仍有 vendor=alpha,region=cn-north；阶段 3 B3 重建 SpanContext 后清空。", "state")}
        {finding_block("baggage", "baggage 保持 W3C 值", f"tenant=blue；request.id={esc(report['e2e_id'])}。", "neutral")}
      </div>
    </div>
    <div>
      <h3>B：tracecontext,baggage,jaeger</h3>
      <div class="stack">
        {finding_block("parent", "parent 改变", f"最终 parent={code(full['final']['parent_B'])}；下游以 Jaeger span 作为远端父。", "parent")}
        {finding_block("state", "tracestate 不再适用", "同样在阶段 3 重建 SpanContext 后清空。", "state")}
        {finding_block("baggage", "baggage 被另一个传播器改写", "Jaeger 的 uberctx-tenant=green 覆盖 W3C baggage 的 tenant=blue。", "baggage")}
      </div>
    </div>
  </div>
  <p><strong>为何 trace ID 相同仍可能需要两种排查结论：</strong>A 侧看到的是 B3 parent + blue baggage；B 侧看到的是 Jaeger parent + green baggage。按 trace ID 搜索会返回同一条 trace，但按 parent 还原服务跳转、按 baggage 找业务租户时会得到两条不同结论。缺字段请求下，A 还额外出现 B3 采样丢失，子 span 不导出；B 仍导出。两者不能共用同一条“全链路已齐”的判断。</p>
</div>

<h2>图 1 · 首次分歧发生在阶段 3</h2>
<div class="panel">
  {flow_svg(full)}
  <div class="legend">
    <span class="tag parent">parent 改变</span>
    <span class="tag state">tracestate 不再适用</span>
    <span class="tag baggage">baggage 被改写</span>
    <span class="tag sampling">采样结论改变</span>
    <span class="small">橙色边框 = 该阶段 A/B 返回上下文出现差异。</span>
  </div>
</div>

<h2>四类观察（每个阶段都记录）</h2>
<div class="panel">
  <table><thead><tr><th>观察</th><th>内容</th><th>证据路径</th></tr></thead>
  <tbody>{four}</tbody></table>
  <p class="note">每个 stage 的 <code>final_injected</code> 都是“从该阶段返回的上下文继续注入”的快照，因此可区分“传播器返回的上下文”与“最终真正写出的 header”。</p>
</div>

<h2>实验矩阵</h2>
<div class="panel">
  <h3>两种传播器排列</h3>
  <table><thead><tr><th>ID</th><th>OTEL_PROPAGATORS 等价值</th><th>阶段顺序</th><th>说明</th></tr></thead>
  <tbody>{ordering_rows}</tbody></table>
  <h3>两个合成请求</h3>
  <table><thead><tr><th>ID</th><th>类型</th><th>缺失字段</th><th>说明</th></tr></thead>
  <tbody>{fixture_rows}</tbody></table>
</div>

<h2>图 2 · 逐阶段 A/B 对照</h2>
<h3>完整请求</h3>
{stage_table(full, runs)}
<h3>缺少部分追踪字段的合成请求</h3>
{stage_table(partial, runs)}

<h3>完整请求 · 阶段明细</h3>
<div class="cards">{render_stage_cards(full, runs[("full", "A")])}</div>
<p class="note">以上为 A 侧；B 侧同名阶段仅第三阶段不同：parent=0a0a0a0a0a0a0a0a，baggage tenant=green。</p>

<h3>缺字段请求 · 阶段明细</h3>
<div class="cards">{render_stage_cards(partial, runs[("partial", "A")])}</div>
<p class="note">A 的第三阶段因缺少 x-b3-sampled，B3 将父上下文降为未采样，子 span 不导出；B 的 Jaeger 使用 uber-trace-id 的 flags=1，仍导出。</p>

<h2>最终注入值对照</h2>
<p class="note">完整请求 · A 与 B 的最终下游 header；橙色行表示不同。</p>
{injection_table(full)}
<h3>缺字段请求</h3>
{injection_table(partial)}

<h2>值班判断表</h2>
<div class="panel">
  <table>
    <thead><tr><th>观察点</th><th>A：tracecontext,baggage,b3</th><th>B：tracecontext,baggage,jaeger</th><th>为何不能只看 trace ID</th></tr></thead>
    <tbody>
      <tr><td>远端 parent</td><td>{code(full['final']['parent_A'])}</td><td>{code(full['final']['parent_B'])}</td><td>同一 trace ID 下 parent 不同，服务跳转的因果关系不同。</td></tr>
      <tr><td>tracestate</td><td>阶段 2 有，阶段 3 清空</td><td>阶段 2 有，阶段 3 清空</td><td>vendor 状态在第三阶段已不可用，不能拿最终 span 的 tracestate 做路由判断。</td></tr>
      <tr><td>baggage.tenant</td><td>{code(full['final']['baggage_A'].get('tenant'))}</td><td>{code(full['final']['baggage_B'].get('tenant'))}</td><td>业务租户在两条 profile 中不同，按 trace ID 聚合会把 blue 与 green 混在一起。</td></tr>
      <tr><td>缺字段请求的 sampled</td><td>{code(str(partial['final']['sampled_A']).lower())}（子 span 不导出）</td><td>{code(str(partial['final']['sampled_B']).lower())}（子 span 导出）</td><td>一条 trace 有缺口 vs 完整，采样来源不同，排查入口不同。</td></tr>
      <tr><td>建议先查</td><td>B3 的 x-b3-sampled 是否缺失；B3 是否覆盖了 W3C parent</td><td>Jaeger 的 uberctx-* 是否覆盖 W3C baggage；Jaeger parent 来源</td><td>同一 trace ID 不能同时回答“丢 span”和“业务关联错”两个问题。</td></tr>
    </tbody>
  </table>
</div>

<h2>Finding 明细</h2>
{render_findings(report)}

<h2>复跑步骤（值班可直接执行）</h2>
<div class="panel">
  <ol>
    <li>在仓库根目录确认解释器：<code>.venv/bin/python -V</code>，应为 Python 3.12。</li>
    <li>执行采集：<code>.venv/bin/python -m forensics.collect --out forensics/out</code></li>
    <li>执行断言：<code>.venv/bin/python -m pytest -q forensics/tests/test_collect.py</code></li>
    <li>复跑并比对字节：<code>forensics/reproduce.sh</code>；脚本会输出 <code>evidence.sha256</code> 与 diff 结果。</li>
    <li>离线打开 <code>forensics/out/report.html</code>；无需网络、无需 collector。</li>
  </ol>
  <pre>.venv/bin/python -m forensics.collect --out forensics/out
.venv/bin/python -m pytest -q forensics/tests/test_collect.py
forensics/reproduce.sh</pre>
  <p class="note">预期：full 与 partial 均输出 <code>first divergence=阶段 3 B3MultiFormat vs JaegerPropagator</code>；两侧 trace ID 都是 <code>{esc(report['synthetic_fields']['trace_id'])}</code>。若你的值不同，先看 <code>evidence.json</code> 的 <code>comparisons[].stage_pairs</code> 与 <code>runs[].stages[].returned_context</code>。</p>
</div>

<h2>原始证据</h2>
<details>
  <summary>展开 evidence.json（完整）</summary>
  <pre>{esc(json.dumps(report, indent=2, ensure_ascii=False))}</pre>
</details>

<footer>
  生成器：<code>{esc(report['generated_by'])}</code> · schema <code>{esc(report['schema'])}</code> ·
  合成字段：trace={code(report['synthetic_fields']['trace_id'])}, child span={code(report['synthetic_fields']['child_span_id'])} ·
  端到端关联号 <code>{esc(report['e2e_id'])}</code>。
  本报告完全离线生成，不含真实用户数据。
</footer>
</main>
</body>
</html>
"""
