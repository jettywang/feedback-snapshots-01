# SPDX-License-Identifier: Apache-2.0

"""Automatic reduction of failing scenarios (greedy delta debugging).

Given a scenario where the engine under test disagrees with the independent
model, the shrinker repeatedly applies the smallest deterministic reduction
that still triggers the disagreement:

1. remove a whole step,
2. remove an artifact from a material/product set,
3. remove a rule from a rule list (never the only rule),
4. narrow a rule pattern toward an exact path or ``*``.

Reduction stops when no single change preserves the failure, yielding a
short, human-readable counterexample.
"""

import copy
from dataclasses import replace
from typing import Callable, List, Tuple

from tests.rule_fuzz.model import Outcome, Rule, Step

# A predicate returns True while the reduced scenario still fails.
FailurePredicate = Callable[[List[Step]], bool]


def outcomes_differ(model_outcome: Outcome,
                    engine_outcome: Outcome) -> bool:
    """A divergence is a verdict flip or a different leftover set."""
    if model_outcome.accepted != engine_outcome.accepted:
        return True
    return (
        model_outcome.remaining_by_queue
        != engine_outcome.remaining_by_queue
    )


def _rule_lists(step: Step):
    return [step.material_rules, step.product_rules]


def _narrow_patterns(rule: Rule, step: Step) -> List[Rule]:
    """Only produce *more specific* patterns present in the step's artifacts.

    Widening an exact path (e.g. to ``*``) changes rule semantics and can
    erase the failure, so narrowing is restricted to concrete existing paths.
    """
    existing = sorted(set(step.materials) | set(step.products))
    candidates = []
    for path in existing:
        if rule.pattern != path:
            candidates.append(replace(rule, pattern=path))
    return candidates


def _candidates(steps: List[Step]) -> List[List[Step]]:
    """Yield every one-step reduction of the scenario."""
    variants: List[List[Step]] = []

    # 1. Drop a whole step.
    if len(steps) > 1:
        for index in range(len(steps)):
            variant = copy.deepcopy(steps)
            del variant[index]
            variants.append(variant)

    for step_index, step in enumerate(steps):
        # 2. Drop a single artifact from either digest map.
        for attr in ("materials", "products"):
            artifacts = getattr(step, attr)
            for path in list(artifacts):
                variant = copy.deepcopy(steps)
                del getattr(variant[step_index], attr)[path]
                variants.append(variant)

        # 3. Drop a single rule (keep at least one rule per list and never
        #    remove the terminal DISALLOW, otherwise the safety net that makes
        #    the oracle reject would disappear and the failure could flip).
        for list_index, rules in enumerate(_rule_lists(step)):
            for rule_index in range(len(rules)):
                if rule_index == len(rules) - 1 and \
                        rules[rule_index].type == "disallow":
                    continue
                if len(rules) <= 1:
                    continue
                variant = copy.deepcopy(steps)
                target_rules = (
                    variant[step_index].material_rules
                    if list_index == 0
                    else variant[step_index].product_rules
                )
                del target_rules[rule_index]
                variants.append(variant)

        # 4. Narrow a rule pattern toward a concrete existing path.
        for list_index, rules in enumerate(_rule_lists(step)):
            for rule_index, rule in enumerate(rules):
                for narrowed in _narrow_patterns(rule, step):
                    variant = copy.deepcopy(steps)
                    target_list = (
                        variant[step_index].material_rules
                        if list_index == 0
                        else variant[step_index].product_rules
                    )
                    target_list[rule_index] = narrowed
                    variants.append(variant)

    return variants


def shrink(steps: List[Step], is_failure: FailurePredicate,
           max_iterations: int = 200) -> Tuple[List[Step], int]:
    """Return a reduced scenario that still satisfies ``is_failure``."""
    current = copy.deepcopy(steps)
    if not is_failure(current):
        raise ValueError("scenario passed to shrinker does not fail")

    iterations = 0
    changed = True
    while changed and iterations < max_iterations:
        changed = False
        for candidate in _candidates(current):
            iterations += 1
            if iterations >= max_iterations:
                break
            try:
                if is_failure(candidate):
                    current = candidate
                    changed = True
                    break
            except Exception:  # pragma: no cover - malformed reduction guard
                continue
    return current, iterations


def scenario_size(steps: List[Step]) -> int:
    """Rough size metric used to confirm the shrinker made progress."""
    size = 0
    for step in steps:
        size += len(step.materials) + len(step.products)
        size += len(step.material_rules) + len(step.product_rules)
    size += len(steps)
    return size
