# SPDX-License-Identifier: Apache-2.0

"""Queue-based artifact rule engine used as the system under test.

This engine mirrors the production firewall/queue algorithm independently
(no imports from ``in_toto.verifylib``). Two defect injections are supported
so the fuzzer can demonstrate readable counterexamples:

* ``modify_same_content``: MODIFY wrongly consumes artifacts whose material
  and product digests are *equal* (it should only consume changed digests).
* ``match_ignore_target_step``: MATCH ignores the destination step named in
  the rule and instead searches every step for a digest match.
"""

from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Dict, List, Optional, Tuple

from tests.rule_fuzz.model import (
    Outcome,
    QueueResult,
    Rule,
    Step,
    _glob,
    _join,
    _strip_prefix,
)


@dataclass(frozen=True)
class EngineConfig:
    modify_same_content: bool = False
    match_ignore_target_step: bool = False


class EngineReject(Exception):
    def __init__(self, rule: str, reason: str):
        super().__init__(f"{rule} -> REJECT ({reason})")
        self.rule = rule
        self.reason = reason


def _modify_consumes(rule: Rule, queue: set, step: Step,
                     config: EngineConfig) -> set:
    matched = _glob(rule.pattern, queue)
    both = matched & set(step.materials) & set(step.products)
    consumed = set()
    for path in both:
        equal = step.materials[path] == step.products[path]
        if not equal:
            # Correct behavior: genuinely modified content is consumed.
            consumed.add(path)
        elif config.modify_same_content:
            # Injected defect: unchanged content is wrongly consumed too,
            # letting an unmodified artifact escape later constraints.
            consumed.add(path)
    return consumed


def _match_consumes(rule: Rule, queue: set, source_artifacts: Dict[str, str],
                    steps_by_name: Dict[str, Step],
                    config: EngineConfig) -> set:
    if rule.source_prefix:
        candidates = _strip_prefix(rule.source_prefix, sorted(queue))
    else:
        candidates = sorted(queue)
    candidates = sorted(_glob(rule.pattern, candidates))

    if config.match_ignore_target_step:
        # Bug: ignore the declared target step and scan all steps.
        search_steps = [
            item for name, item in steps_by_name.items()
        ]
    else:
        target = steps_by_name.get(rule.dest_name)
        search_steps = [target] if target is not None else []

    consumed = set()
    for suffix in candidates:
        source_path = _join(rule.source_prefix, suffix)
        if source_path not in source_artifacts:
            continue
        dest_path = _join(rule.dest_prefix, suffix)
        source_digest = source_artifacts[source_path]
        for candidate_step in search_steps:
            dest_artifacts = getattr(candidate_step, rule.dest_type)
            if dest_path in dest_artifacts and \
                    dest_artifacts[dest_path] == source_digest:
                consumed.add(source_path)
                break
    return consumed


def evaluate_queue(side: str, rules: List[Rule], step: Step,
                   steps_by_name: Dict[str, Step],
                   config: EngineConfig) -> QueueResult:
    source_artifacts = step.materials if side == "materials" else step.products
    queue = set(source_artifacts)
    trace: List[str] = []

    for rule in rules:
        if rule.type == "require":
            if rule.pattern not in queue:
                trace.append(f"{rule.render()} -> REJECT (missing)")
                return QueueResult(
                    False, tuple(sorted(queue)), rule.render(), tuple(trace)
                )
            trace.append(f"{rule.render()} -> ok")
            continue

        if rule.type == "disallow":
            if _glob(rule.pattern, queue):
                trace.append(f"{rule.render()} -> REJECT (residual match)")
                return QueueResult(
                    False, tuple(sorted(queue)), rule.render(), tuple(trace)
                )
            trace.append(f"{rule.render()} -> ok")
            continue

        if rule.type == "match":
            consumed = _match_consumes(
                rule, queue, source_artifacts, steps_by_name, config
            )
        elif rule.type == "modify":
            consumed = _modify_consumes(rule, queue, step, config)
        elif rule.type == "create":
            matched = _glob(rule.pattern, queue)
            consumed = matched & (set(step.products) - set(step.materials))
        elif rule.type == "delete":
            matched = _glob(rule.pattern, queue)
            consumed = matched & (set(step.materials) - set(step.products))
        elif rule.type == "allow":
            consumed = set(_glob(rule.pattern, queue))
        else:  # pragma: no cover - defensive, unknown types never generated
            raise ValueError(f"unknown rule type {rule.type!r}")

        queue -= consumed
        trace.append(
            f"{rule.render()} -> consumed {sorted(consumed) or '[]'}"
        )

    return QueueResult(True, tuple(sorted(queue)), None, tuple(trace))


def evaluate_scenario(steps: List[Step],
                      config: Optional[EngineConfig] = None) -> Outcome:
    config = config or EngineConfig()
    steps_by_name = {step.name: step for step in steps}
    results: List[Tuple[str, str, QueueResult]] = []
    for step in steps:
        for side, rules in (
            ("materials", step.material_rules),
            ("products", step.product_rules),
        ):
            if not rules:
                continue
            result = evaluate_queue(side, rules, step, steps_by_name, config)
            results.append((step.name, side, result))
            if not result.accepted:
                return Outcome(False, tuple(results), result.failed_rule)
    return Outcome(True, tuple(results), None)
