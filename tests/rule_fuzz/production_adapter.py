# SPDX-License-Identifier: Apache-2.0

"""Optional cross-check against the real ``in_toto.verifylib`` engine.

This adapter translates the harness's independent data structures into the
dictionaries and rule token lists consumed by the production entry point
:func:`in_toto.verifylib.verify_item_rules`. It is the only module allowed to
import production code, keeping the oracle itself fully independent.

The production engine does not return its working queue, so the leftover set
is read from its rule trace (the last recorded queue). Rejecting rules
(DISALLOW/REQUIRE) never consume artifacts, so the queue recorded just before
the raised error equals the remaining set at rejection.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional

from in_toto import verifylib
from in_toto.exceptions import RuleVerificationError

from tests.rule_fuzz.model import Rule, Step


@dataclass
class ProductionResult:
    accepted: bool
    remaining: tuple
    error: Optional[str]


def _hash_dict(artifacts: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    return {path: {"sha256": digest} for path, digest in artifacts.items()}


def _pack_rule(rule: Rule) -> List[str]:
    """Translate a structured rule into production rule token list."""
    if rule.type == "match":
        tokens = ["MATCH", rule.pattern]
        if rule.source_prefix:
            tokens += ["IN", rule.source_prefix]
        tokens += ["WITH", rule.dest_type.upper()]
        if rule.dest_prefix:
            tokens += ["IN", rule.dest_prefix]
        tokens += ["FROM", rule.dest_name]
        return tokens
    return [rule.type.upper(), rule.pattern]


def build_links(steps: List[Step]) -> Dict[str, object]:
    from in_toto.models.link import Link

    links = {}
    for step in steps:
        links[step.name] = Link(
            name=step.name,
            materials=_hash_dict(step.materials),
            products=_hash_dict(step.products),
        )
    return links


def evaluate_queue(side: str, rules: List[Rule], step: Step,
                   links: Dict[str, object]) -> ProductionResult:
    packed = [_pack_rule(rule) for rule in rules]
    initial = set(
        step.materials if side == "materials" else step.products
    )
    try:
        verifylib.verify_item_rules(step.name, side, packed, links)
    except RuleVerificationError as error:
        trace = verifylib.RULE_TRACE.get("trace", [])
        remaining = trace[-1]["queue"] if trace else sorted(initial)
        return ProductionResult(False, tuple(sorted(remaining)), str(error))

    trace = verifylib.RULE_TRACE.get("trace", [])
    remaining = trace[-1]["queue"] if trace else sorted(initial)
    return ProductionResult(True, tuple(sorted(remaining)), None)
