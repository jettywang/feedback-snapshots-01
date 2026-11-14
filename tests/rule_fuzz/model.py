# SPDX-License-Identifier: Apache-2.0

"""Independent, set-based state model for in-toto artifact rules.

This module deliberately re-expresses the in-toto artifact rule semantics
using plain Python sets and digest (hash) relations. It does not import or
call any production rule code; it is the standalone oracle that the fuzzing
harness compares other engines against.

The model follows the firewall-style semantics documented by in-toto:

* Every step carries a finite set of materials and products, each mapping a
  path to a digest.
* A separate verification queue is built from the step's materials (for
  material rules) or products (for product rules).
* Rules are applied in order. A rule consumes zero or more queued paths by
  removing them from the working set.
* ``REQUIRE`` fails if its literal filename is missing from the queue and
  ``DISALLOW`` fails if its pattern still matches anything in the queue.
* A well-formed policy ends with ``DISALLOW *`` so that anything left
  unconsumed rejects the whole step.
"""

from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Dict, List, Optional, Tuple

# A digest map is path -> digest (a single, content-addressed hash string).
DigestMap = Dict[str, str]

# Canonical rule types exercised by the harness.
GENERIC_TYPES = frozenset(
    {"create", "delete", "modify", "allow", "disallow", "require"}
)
MATCH_TYPE = "match"


@dataclass(frozen=True)
class Rule:
    """An artifact rule expressed as structured data rather than token lists."""

    type: str
    pattern: str = "*"
    source_prefix: str = ""
    dest_type: str = ""  # "materials" or "products" for MATCH
    dest_prefix: str = ""
    dest_name: str = ""

    def render(self) -> str:
        """Return a compact, human-readable single-line rendering."""
        if self.type == MATCH_TYPE:
            parts = ["MATCH", self.pattern]
            if self.source_prefix:
                parts += ["IN", self.source_prefix]
            parts += ["WITH", self.dest_type.upper()]
            if self.dest_prefix:
                parts += ["IN", self.dest_prefix]
            parts += ["FROM", self.dest_name]
            return " ".join(parts)
        return f"{self.type.upper()} {self.pattern}"


@dataclass
class Step:
    """A supply chain step with finite materials, products and rule lists."""

    name: str
    materials: DigestMap
    products: DigestMap
    material_rules: List[Rule] = field(default_factory=list)
    product_rules: List[Rule] = field(default_factory=list)


@dataclass(frozen=True)
class QueueResult:
    """Outcome of evaluating one rule list against one queue."""

    accepted: bool
    remaining: Tuple[str, ...]
    failed_rule: Optional[str]
    trace: Tuple[str, ...]


@dataclass(frozen=True)
class Outcome:
    """Per-step and whole-scenario verification result."""

    accepted: bool
    step_results: Tuple[Tuple[str, str, QueueResult], ...]
    failed_rule: Optional[str]

    @property
    def remaining_by_queue(self) -> Dict[Tuple[str, str], Tuple[str, ...]]:
        return {
            (step_name, side): result.remaining
            for step_name, side, result in self.step_results
        }


def _join(prefix: str, path: str) -> str:
    """Join a path prefix and a relative path using forward slashes."""
    if not prefix:
        return path
    return prefix.rstrip("/") + "/" + path


def _strip_prefix(prefix: str, paths: List[str]) -> List[str]:
    """Return the suffixes of ``paths`` that live under ``prefix``."""
    normalized = prefix.rstrip("/") + "/"
    return [
        path[len(normalized):]
        for path in paths
        if path.startswith(normalized)
    ]


def _glob(pattern: str, paths) -> set:
    """Apply an fnmatch glob, mirroring the production pattern semantics."""
    return {path for path in paths if fnmatch(path, pattern)}


def _consume_generic(rule: Rule, queue: set, step: Step) -> set:
    """Return the set of queued paths a generic rule would consume."""
    matched = _glob(rule.pattern, queue)
    material_paths = set(step.materials)
    product_paths = set(step.products)

    if rule.type == "create":
        return matched & (product_paths - material_paths)
    if rule.type == "delete":
        return matched & (material_paths - product_paths)
    if rule.type == "modify":
        both = matched & material_paths & product_paths
        return {
            path
            for path in both
            if step.materials[path] != step.products[path]
        }
    if rule.type == "allow":
        return set(matched)
    return set()


def evaluate_queue(
    side: str,
    rules: List[Rule],
    step: Step,
    steps_by_name: Dict[str, Step],
) -> QueueResult:
    """Apply one rule list to one step queue using set operations only."""
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

        if rule.type == MATCH_TYPE:
            consumed = _match_consumed(rule, queue, source_artifacts,
                                       steps_by_name)
        else:
            consumed = _consume_generic(rule, queue, step)

        queue -= consumed
        trace.append(
            f"{rule.render()} -> consumed {sorted(consumed) or '[]'}"
        )

    return QueueResult(True, tuple(sorted(queue)), None, tuple(trace))


def _match_consumed(rule, queue, source_artifacts, steps_by_name) -> set:
    """MATCH consumption with the source digest map passed explicitly."""
    dest_step = steps_by_name.get(rule.dest_name)
    if dest_step is None:
        return set()
    dest_artifacts = getattr(dest_step, rule.dest_type)

    if rule.source_prefix:
        candidates = _strip_prefix(rule.source_prefix, sorted(queue))
    else:
        candidates = sorted(queue)
    candidates = sorted(_glob(rule.pattern, candidates))

    consumed = set()
    for suffix in candidates:
        source_path = _join(rule.source_prefix, suffix)
        dest_path = _join(rule.dest_prefix, suffix)
        if source_path not in source_artifacts:
            continue
        if dest_path not in dest_artifacts:
            continue
        if source_artifacts[source_path] == dest_artifacts[dest_path]:
            consumed.add(source_path)
    return consumed


def evaluate_scenario(steps: List[Step]) -> Outcome:
    """Evaluate every queue of every step and aggregate the verdict."""
    steps_by_name = {step.name: step for step in steps}
    results = []
    for step in steps:
        for side, rules in (
            ("materials", step.material_rules),
            ("products", step.product_rules),
        ):
            if not rules:
                continue
            result = evaluate_queue(side, rules, step, steps_by_name)
            results.append((step.name, side, result))
            if not result.accepted:
                return Outcome(False, tuple(results), result.failed_rule)
    return Outcome(True, tuple(results), None)
