# SPDX-License-Identifier: Apache-2.0

"""Human-readable rendering of scenarios, verdicts and leftover-set diffs."""

from typing import Dict, List, Optional

from tests.rule_fuzz.model import Outcome, Rule, Step

# Only show a short prefix of each 64-char digest in reports.
DIGEST_PREVIEW = 8


def _short_digest(digest: str) -> str:
    return digest[:DIGEST_PREVIEW] + ".."


def _render_artifacts(artifacts: Dict[str, str]) -> str:
    if not artifacts:
        return "{}"
    body = ", ".join(
        f"{path}={_short_digest(digest)}"
        for path, digest in sorted(artifacts.items())
    )
    return "{" + body + "}"


def render_rules(rules: List[Rule], indent: str = "      ") -> str:
    if not rules:
        return indent + "(none)"
    return "\n".join(f"{indent}{index + 1}. {rule.render()}"
                     for index, rule in enumerate(rules))


def render_scenario(steps: List[Step]) -> str:
    lines = ["SCENARIO"]
    for step in steps:
        lines.append(f"  step {step.name}")
        lines.append(f"    materials: {_render_artifacts(step.materials)}")
        lines.append(f"    products:  {_render_artifacts(step.products)}")
        lines.append("    material rules:")
        lines.append(render_rules(step.material_rules))
        lines.append("    product rules:")
        lines.append(render_rules(step.product_rules))
    return "\n".join(lines)


def _verdict(accepted: bool) -> str:
    return "ACCEPT" if accepted else "REJECT"


def render_outcome(outcome: Outcome, title: str) -> str:
    lines = [f"{title}: {_verdict(outcome.accepted)}"]
    for step_name, side, result in outcome.step_results:
        lines.append(
            f"  {step_name}/{side}: {_verdict(result.accepted)} "
            f"remaining={list(result.remaining)}"
        )
        if result.failed_rule:
            lines.append(f"    failed rule: {result.failed_rule}")
        for entry in result.trace:
            lines.append(f"    trace: {entry}")
    return "\n".join(lines)


def render_remaining_diff(model_outcome: Outcome,
                          engine_outcome: Outcome) -> str:
    """Show per-queue set differences between model and engine leftovers."""
    model_remaining = model_outcome.remaining_by_queue
    engine_remaining = engine_outcome.remaining_by_queue
    keys = sorted(set(model_remaining) | set(engine_remaining))
    lines = ["REMAINING SET DIFFERENCE (model vs engine)"]
    for key in keys:
        model_set = set(model_remaining.get(key, ()))
        engine_set = set(engine_remaining.get(key, ()))
        if model_set == engine_set:
            continue
        only_model = sorted(model_set - engine_set)
        only_engine = sorted(engine_set - model_set)
        lines.append(f"  {key[0]}/{key[1]}:")
        lines.append(f"    model remaining:  {sorted(model_set)}")
        lines.append(f"    engine remaining: {sorted(engine_set)}")
        if only_model:
            lines.append(f"    only model kept:  {only_model}")
        if only_engine:
            lines.append(f"    only engine kept: {only_engine}")
    if len(lines) == 1:
        lines.append("  (leftover sets identical; verdicts still differ)")
    return "\n".join(lines)


def render_counterexample(steps: List[Step], model_outcome: Outcome,
                          engine_outcome: Outcome,
                          iterations: Optional[int] = None) -> str:
    blocks = [
        render_scenario(steps),
        render_outcome(model_outcome, "MODEL"),
        render_outcome(engine_outcome, "ENGINE"),
        render_remaining_diff(model_outcome, engine_outcome),
    ]
    if iterations is not None:
        blocks.append(f"shrink iterations: {iterations}")
    return "\n".join(blocks)
