#!/usr/bin/env python3
"""Offline forensic replay of OpenTelemetry Python composite extraction.

This drives the propagators shipped in this repository, not a simulation:

    TraceContextTextMapPropagator  (W3C traceparent / tracestate)
    W3CBaggagePropagator           (W3C baggage)
    B3MultiFormat                  (x-b3-traceid / x-b3-spanid / x-b3-sampled)
    JaegerPropagator               (uber-trace-id / uberctx-*)

Two service profiles are replayed against two synthetic inbound requests. The
profiles share the `tracecontext,baggage` prefix and differ only in the third
propagator, so the first divergence is attributable to one propagator and one
stage.

For every (profile, request, stage) it records the four observations requested
by the runbook:

    1. inbound carrier
    2. context returned by that propagator
    3. a real SDK child span started from that context
    4. the headers injected by the full profile from that context

Everything is local and deterministic. No collector, exporter, clock, or random
ID is used. Running the command twice produces byte-identical evidence JSON.

    .venv/bin/python -m forensics.collect --out forensics/out
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
for package in (
    "opentelemetry-api/src",
    "opentelemetry-sdk/src",
    "propagator/opentelemetry-propagator-b3/src",
    "propagator/opentelemetry-propagator-jaeger/src",
):
    path = str(REPO / package)
    if path not in sys.path:
        sys.path.insert(0, path)

from opentelemetry import baggage, trace  # noqa: E402
from opentelemetry.baggage.propagation import W3CBaggagePropagator  # noqa: E402
from opentelemetry.propagators.b3 import B3MultiFormat  # noqa: E402
from opentelemetry.propagators.composite import CompositePropagator  # noqa: E402
from opentelemetry.propagators.jaeger import JaegerPropagator  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (  # noqa: E402
    InMemorySpanExporter,
)
from opentelemetry.sdk.trace.id_generator import IdGenerator  # noqa: E402
from opentelemetry.sdk.trace.sampling import DEFAULT_ON  # noqa: E402
from opentelemetry.trace import SpanKind, format_span_id, format_trace_id  # noqa: E402
from opentelemetry.trace.propagation.tracecontext import (  # noqa: E402
    TraceContextTextMapPropagator,
)

from forensics.report import render_html  # noqa: E402

SCHEMA = "otel-propagator-forensics/v1"

# Synthetic but well-formed values. Every ID is fixed so two runs can be
# compared byte-for-byte and a reviewer can follow one trace through the report.
TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
INBOUND_SPAN_ID = "00f067aa0ba902b7"
B3_SPAN_ID = "b3b3b3b3b3b3b3b3"
JAEGER_SPAN_ID = "0a0a0a0a0a0a0a0a"
JAEGER_PARENT_ID = "cacacacacacacaca"
CHILD_SPAN_ID = 0x00C0FFEE00C0FFEE
E2E_ID = "e2e-jw175-0001"

# What each propagator actually reads on extract. Used only for the report.
READS = {
    "TraceContextTextMapPropagator": ["traceparent", "tracestate"],
    "W3CBaggagePropagator": ["baggage"],
    "B3MultiFormat": ["b3", "x-b3-traceid", "x-b3-spanid", "x-b3-sampled", "x-b3-flags"],
    "JaegerPropagator": ["uber-trace-id", "uberctx-*"],
}

EXPLANATIONS = {
    "TraceContextTextMapPropagator": (
        "Parses traceparent and tracestate, then installs a remote NonRecordingSpan "
        "with is_remote=True."
    ),
    "W3CBaggagePropagator": (
        "Reads the W3C baggage header into the baggage context key. It does not "
        "touch the span or tracestate."
    ),
    "B3MultiFormat": (
        "Rebuilds the remote parent from x-b3-* with trace_state=TraceState() (empty). "
        "A missing x-b3-sampled defaults to \"0\", so an unsampled B3 parent replaces "
        "an already-sampled W3C parent."
    ),
    "JaegerPropagator": (
        "Rebuilds the remote parent from uber-trace-id with trace_state=TraceState() "
        "(empty), then reads every uberctx-* key into baggage. Those entries overwrite "
        "same-named W3C baggage entries because this propagator runs later."
    ),
}


class FixedIdGenerator(IdGenerator):
    """Deterministic child span ID; the trace ID is never generated for children."""

    def generate_span_id(self) -> int:
        return CHILD_SPAN_ID

    def generate_trace_id(self) -> int:
        return int(TRACE_ID, 16)


_EXPORTER = InMemorySpanExporter()
_PROVIDER = TracerProvider(id_generator=FixedIdGenerator(), sampler=DEFAULT_ON)
_PROVIDER.add_span_processor(SimpleSpanProcessor(_EXPORTER))


def build_orderings() -> list[dict[str, Any]]:
    """Two service profiles with a shared prefix and one differing stage.

    The shared prefix is deliberate: it proves that tracecontext and baggage
    agree before the third stage, so the first divergence cannot be blamed on
    the inbound W3C parse or on a different carrier shape.
    """
    return [
        {
            "id": "A",
            "label": "tracecontext,baggage,b3",
            "description": "Service A terminates W3C then B3.",
            "propagators": [
                TraceContextTextMapPropagator(),
                W3CBaggagePropagator(),
                B3MultiFormat(),
            ],
        },
        {
            "id": "B",
            "label": "tracecontext,baggage,jaeger",
            "description": "Service B terminates W3C then Jaeger.",
            "propagators": [
                TraceContextTextMapPropagator(),
                W3CBaggagePropagator(),
                JaegerPropagator(),
            ],
        },
    ]


def build_fixtures() -> list[dict[str, Any]]:
    full = {
        "traceparent": f"00-{TRACE_ID}-{INBOUND_SPAN_ID}-01",
        "tracestate": "vendor=alpha,region=cn-north",
        "baggage": f"tenant=blue,request.id={E2E_ID}",
        "x-b3-traceid": TRACE_ID,
        "x-b3-spanid": B3_SPAN_ID,
        "x-b3-sampled": "1",
        "uber-trace-id": f"{TRACE_ID}:{JAEGER_SPAN_ID}:{JAEGER_PARENT_ID}:1",
        "uberctx-tenant": "green",
    }
    partial = dict(full)
    for key in ("tracestate", "baggage", "x-b3-sampled", "uberctx-tenant"):
        del partial[key]
    return [
        {
            "id": "full",
            "label": "完整请求",
            "e2e_id": E2E_ID,
            "carrier": full,
            "missing": [],
            "note": "所有传播器都能找到自己的字段。",
        },
        {
            "id": "partial",
            "label": "缺少部分追踪字段的合成请求",
            "e2e_id": E2E_ID,
            "carrier": partial,
            "missing": ["tracestate", "baggage", "x-b3-sampled", "uberctx-tenant"],
            "note": (
                "W3C traceparent 仍完整且带 sampled=01；B3 缺 x-b3-sampled；"
                "Jaeger 的 uber-trace-id 仍带 flags=1；没有 W3C baggage，也没有 uberctx-*。"
            ),
        },
    ]


def manifest(carrier: dict[str, Any]) -> dict[str, Any]:
    return {key: carrier[key] for key in sorted(carrier)}


def snapshot(context) -> dict[str, Any]:
    span = trace.get_current_span(context).get_span_context()
    state = span.trace_state
    entries = dict(baggage.get_all(context=context))
    return {
        "span": {
            "valid": bool(span.is_valid),
            "trace_id": format_trace_id(span.trace_id) if span.is_valid else None,
            "span_id": format_span_id(span.span_id) if span.is_valid else None,
            "is_remote": bool(span.is_remote),
            "sampled": bool(span.trace_flags.sampled),
            "trace_flags": f"{int(span.trace_flags):02x}",
            "tracestate": state.to_header() if state else None,
        },
        "baggage": entries,
        "baggage_header": ",".join(f"{key}={value}" for key, value in entries.items()),
    }


def diff_context(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key in ("valid", "trace_id", "span_id", "is_remote", "sampled", "trace_flags", "tracestate"):
        if before["span"][key] != after["span"][key]:
            fields[f"span.{key}"] = {"before": before["span"][key], "after": after["span"][key]}
    for key in ("baggage", "baggage_header"):
        if before[key] != after[key]:
            fields[key] = {"before": before[key], "after": after[key]}
    categories: set[str] = set()
    if any(key.startswith("span.") for key in fields):
        categories.add("parent")
    if "span.tracestate" in fields:
        categories.add("tracestate")
    if any(key.startswith("baggage") for key in fields):
        categories.add("baggage")
    if "span.sampled" in fields or "span.trace_flags" in fields:
        categories.add("sampling")
    return {"changed": fields, "categories": sorted(categories), "material": bool(fields)}


def child_span(
    context,
    name: str,
    *,
    e2e_id: str,
    order_id: str,
    stage_index: int,
    propagator_name: str,
) -> dict[str, Any]:
    _EXPORTER.clear()
    tracer = _PROVIDER.get_tracer("forensics.collect", "1.0")
    with tracer.start_as_current_span(
        name,
        context=context,
        kind=SpanKind.SERVER,
        attributes={
            "e2e.id": e2e_id,
            "synthetic.order": order_id,
            "synthetic.stage": stage_index,
            "synthetic.propagator": propagator_name,
        },
    ) as span:
        child_context = snapshot(trace.set_span_in_context(span))
        recording = bool(span.is_recording())
    exported = []
    for finished in _EXPORTER.get_finished_spans():
        parent = finished.parent
        exported.append(
            {
                "name": finished.name,
                "trace_id": format_trace_id(finished.context.trace_id),
                "span_id": format_span_id(finished.context.span_id),
                "parent_span_id": format_span_id(parent.span_id) if parent else None,
                "sampled": bool(finished.context.trace_flags.sampled),
                "tracestate": finished.context.trace_state.to_header()
                if finished.context.trace_state
                else None,
                "attributes": dict(finished.attributes or {}),
            }
        )
    return {
        "recording": recording,
        "span_context": child_context["span"],
        "exported_count": len(exported),
        "exported": exported,
    }


def inject(composite: CompositePropagator, context) -> dict[str, Any]:
    carrier: dict[str, Any] = {}
    composite.inject(carrier, context=context)
    return manifest(carrier)


def run_order(order: dict[str, Any], fixture: dict[str, Any]) -> dict[str, Any]:
    composite = CompositePropagator(order["propagators"])
    context = None
    inbound = dict(fixture["carrier"])
    before = snapshot(context)
    stages = []
    for index, propagator in enumerate(order["propagators"], start=1):
        # Each stage sees exactly the context returned by the previous stage,
        # matching CompositePropagator.extract's loop.
        stage_context = propagator.extract(inbound, context)
        after = snapshot(stage_context)
        name = type(propagator).__name__
        stages.append(
            {
                "index": index,
                "propagator": name,
                "reads": READS.get(name, []),
                "explanation": EXPLANATIONS.get(name, ""),
                "inbound_carrier": manifest(inbound),
                "returned_context": after,
                "context_diff": diff_context(before, after),
                "child_span": child_span(
                    stage_context,
                    f"{fixture['id']}-{order['id']}-s{index}",
                    e2e_id=fixture["e2e_id"],
                    order_id=order["id"],
                    stage_index=index,
                    propagator_name=name,
                ),
                "final_injected": inject(composite, stage_context),
            }
        )
        context = stage_context
        before = after
    extracted = snapshot(context)
    # The report claims the manual replay equals the real composite. Verify it
    # rather than merely asserting it in prose.
    composite_context = composite.extract(dict(fixture["carrier"]))
    composite_snapshot = snapshot(composite_context)
    return {
        "order_id": order["id"],
        "order_label": order["label"],
        "fixture_id": fixture["id"],
        "e2e_id": fixture["e2e_id"],
        "stages": stages,
        "composite_extract": composite_snapshot,
        "composite_matches_replay": composite_snapshot == extracted,
        "final_injected": inject(composite, composite_context),
    }


def _stage_pair(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key in ("trace_id", "span_id", "is_remote", "sampled", "trace_flags", "tracestate"):
        if a["returned_context"]["span"][key] != b["returned_context"]["span"][key]:
            fields[f"span.{key}"] = {
                "A": a["returned_context"]["span"][key],
                "B": b["returned_context"]["span"][key],
            }
    for key in ("baggage", "baggage_header"):
        if a["returned_context"][key] != b["returned_context"][key]:
            fields[key] = {"A": a["returned_context"][key], "B": b["returned_context"][key]}
    categories: set[str] = set()
    if any(key.startswith("span.") for key in fields):
        categories.add("parent")
    if "span.tracestate" in fields:
        categories.add("tracestate")
    if any(key.startswith("baggage") for key in fields):
        categories.add("baggage")
    if "span.sampled" in fields or "span.trace_flags" in fields:
        categories.add("sampling")
    return {
        "index": a["index"],
        "propagator_A": a["propagator"],
        "propagator_B": b["propagator"],
        "categories_A": a["context_diff"]["categories"],
        "categories_B": b["context_diff"]["categories"],
        "differing_fields": fields,
        "categories": sorted(categories),
        "material": bool(fields),
    }


def compare_orders(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key = {(item["fixture_id"], item["order_id"]): item for item in results}
    comparisons = []
    for fixture in build_fixtures():
        a = by_key[(fixture["id"], "A")]
        b = by_key[(fixture["id"], "B")]
        pairs = [_stage_pair(left, right) for left, right in zip(a["stages"], b["stages"])]
        first = next((pair for pair in pairs if pair["material"]), None)
        final_a = a["composite_extract"]
        final_b = b["composite_extract"]
        stage2_a = a["stages"][1]["returned_context"]["span"]
        stage2_b = b["stages"][1]["returned_context"]["span"]
        stage3_a = a["stages"][-1]["returned_context"]["span"]
        stage3_b = b["stages"][-1]["returned_context"]["span"]
        comparisons.append(
            {
                "fixture_id": fixture["id"],
                "fixture_label": fixture["label"],
                "e2e_id": fixture["e2e_id"],
                "stage_pairs": pairs,
                "first_divergence": first,
                "final": {
                    "trace_id_A": final_a["span"]["trace_id"],
                    "trace_id_B": final_b["span"]["trace_id"],
                    "same_trace_id": final_a["span"]["trace_id"] == final_b["span"]["trace_id"],
                    "parent_A": final_a["span"]["span_id"],
                    "parent_B": final_b["span"]["span_id"],
                    "sampled_A": final_a["span"]["sampled"],
                    "sampled_B": final_b["span"]["sampled"],
                    "tracestate_A": final_a["span"]["tracestate"],
                    "tracestate_B": final_b["span"]["tracestate"],
                    "tracestate_stage2_A": stage2_a["tracestate"],
                    "tracestate_stage2_B": stage2_b["tracestate"],
                    "tracestate_lost_in_stage3_A": bool(stage2_a["tracestate"])
                    and stage3_a["tracestate"] is None,
                    "tracestate_lost_in_stage3_B": bool(stage2_b["tracestate"])
                    and stage3_b["tracestate"] is None,
                    "baggage_A": final_a["baggage"],
                    "baggage_B": final_b["baggage"],
                    "injected_A": a["final_injected"],
                    "injected_B": b["final_injected"],
                },
            }
        )
    return comparisons


def build_findings(comparisons: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for comparison in comparisons:
        final = comparison["final"]
        first = comparison["first_divergence"]
        parent_changed = final["parent_A"] != final["parent_B"]
        tracestate_lost = bool(
            final["tracestate_lost_in_stage3_A"] or final["tracestate_lost_in_stage3_B"]
        )
        tracestate_absent_inbound = (
            final["tracestate_stage2_A"] is None and final["tracestate_stage2_B"] is None
        )
        baggage_rewritten = final["baggage_A"] != final["baggage_B"]
        sampling_changed = final["sampled_A"] != final["sampled_B"]
        stage_text = (
            f"阶段 {first['index']}：{first['propagator_A']} vs {first['propagator_B']}"
            if first
            else "无阶段差异"
        )
        conclusions = []
        if parent_changed:
            conclusions.append(
                "parent 改变：两条 trace 的 trace ID 相同，但下游 span.parent 分别指向 "
                f"{final['parent_A']}（A/B3）和 {final['parent_B']}（B/Jaeger）。按 trace ID "
                "能搜到同一条 trace，但按 parent 还原服务跳转时会得到不同的因果关系。"
            )
        if tracestate_lost:
            conclusions.append(
                "tracestate 不再适用：第 2 阶段仍有 vendor=alpha,region=cn-north，第 3 阶段 "
                "B3/Jaeger 重建远端 SpanContext 时被清空。依赖 tracestate 做租户路由或"
                "采样权重的一方会看到“同 trace ID 但无 vendor 状态”。"
            )
        elif tracestate_absent_inbound:
            conclusions.append(
                "tracestate 自入站就缺失：第 2 阶段没有可传播的 tracestate，第 3 阶段并未"
                "额外清空。这与完整请求的“阶段 2 有、阶段 3 被清空”是两种不同故障，"
                "不能都归因为传播器丢状态。"
            )
        if baggage_rewritten:
            conclusions.append(
                "baggage 被另一个传播器改写：A 保留 W3C baggage 的 tenant=blue；B 的 "
                "JaegerPropagator 读取 uberctx-tenant=green 并覆盖同名 baggage。"
            )
        if sampling_changed:
            conclusions.append(
                "采样结论改变：A 的 B3 缺少 x-b3-sampled，按默认 \"0\" 把父上下文降为未采样，"
                "子 span 不导出；B 的 Jaeger uber-trace-id flags=1，子 span 正常导出。"
            )
        if comparison["fixture_id"] == "full":
            conclusions.append(
                "两种排查结论：A 侧应按“parent 指向 B3 span、baggage 仍是 blue”排查；"
                "B 侧应按“parent 指向 Jaeger span、baggage 已变成 green”排查。只看 trace ID "
                "会把两者误判为同一条链路。"
            )
        else:
            conclusions.append(
                "两种排查结论：A 侧先查 B3 采样字段缺失导致的丢 span；B 侧先查为何 parent "
                "换成 Jaeger span、但 trace 仍完整。缺少 x-b3-sampled 与缺少 W3C baggage "
                "是两类不同的告警，不能用同一条“按 trace ID 查全链路”结论覆盖。"
            )
        out[comparison["fixture_id"]] = {
            "fixture_label": comparison["fixture_label"],
            "first_divergence_stage": stage_text,
            "first_divergence_categories": first["categories"] if first else [],
            "parent_changed": parent_changed,
            "tracestate_no_longer_applies": tracestate_lost,
            "tracestate_absent_inbound": tracestate_absent_inbound,
            "baggage_rewritten": baggage_rewritten,
            "sampling_changed": sampling_changed,
            "same_trace_id": final["same_trace_id"],
            "conclusions": conclusions,
        }
    return out


def run() -> dict[str, Any]:
    orderings = build_orderings()
    fixtures = build_fixtures()
    results = [
        run_order(order, fixture) for order in orderings for fixture in fixtures
    ]
    comparisons = compare_orders(results)
    return {
        "schema": SCHEMA,
        "generated_by": "forensics/collect.py",
        "e2e_id": E2E_ID,
        "synthetic_fields": {
            "trace_id": TRACE_ID,
            "inbound_span_id": INBOUND_SPAN_ID,
            "b3_span_id": B3_SPAN_ID,
            "jaeger_span_id": JAEGER_SPAN_ID,
            "jaeger_parent_id": JAEGER_PARENT_ID,
            "child_span_id": format_span_id(CHILD_SPAN_ID),
            "baggage_keys": ["tenant", "request.id"],
        },
        "orderings": [
            {
                "id": order["id"],
                "label": order["label"],
                "description": order["description"],
                "propagators": [type(propagator).__name__ for propagator in order["propagators"]],
            }
            for order in orderings
        ],
        "fixtures": [
            {
                "id": fixture["id"],
                "label": fixture["label"],
                "e2e_id": fixture["e2e_id"],
                "missing": fixture["missing"],
                "note": fixture["note"],
                "carrier": manifest(fixture["carrier"]),
            }
            for fixture in fixtures
        ],
        "runs": results,
        "comparisons": comparisons,
        "findings": build_findings(comparisons),
        "runbook": {
            "command": ".venv/bin/python -m forensics.collect --out forensics/out",
            "repeat_command": "forensics/reproduce.sh",
            "test_command": ".venv/bin/python -m pytest -q forensics/tests/test_collect.py",
            "assertion": (
                "两次运行的 evidence.json 必须逐字节相同；full 与 partial 的 first_divergence "
                "都必须是阶段 3（B3MultiFormat vs JaegerPropagator），且 trace ID 相同。"
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("forensics/out"))
    args = parser.parse_args()
    report = run()
    args.out.mkdir(parents=True, exist_ok=True)
    json_path = args.out / "evidence.json"
    json_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    html_path = args.out / "report.html"
    html_path.write_text(render_html(report), encoding="utf-8")
    print(f"wrote {json_path}")
    print(f"wrote {html_path}")
    for comparison in report["comparisons"]:
        first = comparison["first_divergence"]
        stage = (
            f"阶段 {first['index']} {first['propagator_A']} vs {first['propagator_B']}"
            if first
            else "无差异"
        )
        final = comparison["final"]
        print(
            f"{comparison['fixture_id']}: trace={final['trace_id_A']} "
            f"parent A/B={final['parent_A']}/{final['parent_B']} "
            f"baggage A/B={final['baggage_A']}/{final['baggage_B']} "
            f"first divergence={stage}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
