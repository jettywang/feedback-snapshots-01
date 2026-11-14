# SPDX-License-Identifier: Apache-2.0

"""Deterministic scenario generator for the artifact rule state model.

The generator keeps the world deliberately small so that failures stay
human-readable and the same seed always reproduces the same scenario:

* a handful of relative paths (plus directory-prefixed variants),
* a small pool of real hex digests, so identical content naturally collides,
* two or three steps, each with finite materials and products,
* rule lists that mix CREATE, DELETE, MODIFY, MATCH, REQUIRE, DISALLOW and
  ALLOW in different orders.

Two flavours are produced:

* :func:`generate_legal_scenario` builds a policy that consumes every queued
  artifact before the terminal ``DISALLOW *`` and is accepted by the
  independent model.
* :func:`generate_fuzz_scenario` builds an arbitrary world and rule sequence;
  the model decides whether the leftover set is caught by the constraints.
"""

import random
import string
from typing import Dict, List, Optional, Sequence, Tuple

from tests.rule_fuzz.model import MATCH_TYPE, Rule, Step

# Small, fixed universes keep counterexamples short and readable.
BASE_PATHS = ["alpha", "beta", "gamma", "delta"]
PREFIXES = ["out", "build"]
DIGEST_POOL_SIZE = 4
RULE_TYPES = [
    "create",
    "delete",
    "modify",
    "allow",
    "disallow",
    "require",
    MATCH_TYPE,
]
GENERIC_FOR_FUZZ = ["create", "delete", "modify", "allow", "require"]


def make_rng(seed: int) -> random.Random:
    return random.Random(seed)


def _digest(rng: random.Random) -> str:
    # Valid 64-char lowercase hex, as expected by real link hash dicts.
    return "".join(rng.choice("0123456789abcdef") for _ in range(64))


def digest_pool(rng: random.Random,
                size: int = DIGEST_POOL_SIZE) -> Tuple[str, ...]:
    return tuple(_digest(rng) for _ in range(size))


def _path_universe(rng: random.Random) -> List[str]:
    paths = list(BASE_PATHS)
    if rng.random() < 0.6:
        paths.append(f"{rng.choice(PREFIXES)}/{rng.choice(BASE_PATHS)}")
    return paths


def _pick_artifacts(rng: random.Random, paths: Sequence[str],
                    pool: Sequence[str]) -> Dict[str, str]:
    chosen = rng.sample(paths, rng.randint(1, len(paths)))
    return {path: rng.choice(pool) for path in chosen}


def _disallow_terminal(rng: random.Random) -> Rule:
    # Occasionally target a glob narrower than "*" to exercise patterns too.
    pattern = "*" if rng.random() < 0.8 else rng.choice(["*", "build/*"])
    return Rule("disallow", pattern)


def _fuzz_rule(rng: random.Random, step: Step,
               steps: Sequence[Step], side: str) -> Rule:
    rule_type = rng.choice(GENERIC_FOR_FUZZ + [MATCH_TYPE])
    queue = step.materials if side == "materials" else step.products
    paths = list(queue) or BASE_PATHS
    pattern = rng.choice(paths + ["*", "build/*"])

    if rule_type == "require":
        # REQUIRE uses a literal filename, sometimes one that is absent.
        return Rule("require", rng.choice(BASE_PATHS + paths))

    if rule_type == MATCH_TYPE:
        target = rng.choice([s.name for s in steps])
        dest_type = rng.choice(["materials", "products"])
        use_prefix = rng.random() < 0.4
        prefix = rng.choice(PREFIXES) if use_prefix else ""
        return Rule(
            MATCH_TYPE,
            pattern=rng.choice(["*", "build/*", rng.choice(BASE_PATHS)]),
            source_prefix=prefix,
            dest_type=dest_type,
            dest_prefix=prefix if rng.random() < 0.5 else "",
            dest_name=target,
        )

    return Rule(rule_type, pattern)


def _fuzz_rule_list(rng: random.Random, step: Step, steps: Sequence[Step],
                    side: str) -> List[Rule]:
    count = rng.randint(2, 4)
    rules = [_fuzz_rule(rng, step, steps, side) for _ in range(count)]
    rules.append(_disallow_terminal(rng))
    return rules


def generate_fuzz_scenario(seed: int,
                           step_count: Optional[int] = None) -> Tuple[
                               List[Step], random.Random]:
    """Build an arbitrary finite world and randomized rule sequences."""
    rng = make_rng(seed)
    count = step_count or rng.randint(2, 3)
    pool = digest_pool(rng)
    names = [f"step-{index}" for index in range(count)]
    steps: List[Step] = []

    for name in names:
        paths = _path_universe(rng)
        materials = _pick_artifacts(rng, paths, pool)
        products = _pick_artifacts(rng, paths, pool)
        steps.append(Step(name, materials, products))

    for step in steps:
        step.material_rules = _fuzz_rule_list(rng, step, steps, "materials")
        step.product_rules = _fuzz_rule_list(rng, step, steps, "products")

    return steps, rng


def _exact_generic(rule_type: str, path: str) -> Rule:
    return Rule(rule_type, path)


def _legal_product_rules(rng: random.Random, step: Step,
                         steps: Sequence[Step]) -> List[Rule]:
    """Consume the whole product queue with semantically correct rules."""
    rules: List[Rule] = []
    material_paths = set(step.materials)
    for path in sorted(step.products):
        if path not in material_paths:
            rules.append(_exact_generic("create", path))
        elif step.materials[path] != step.products[path]:
            # Same name, changed content -> MODIFY.
            rules.append(_exact_generic("modify", path))
        else:
            # Unchanged content -> ALLOW (CREATE/MODIFY would not consume it).
            rules.append(Rule("allow", path))
    rng.shuffle(rules)
    rules.append(Rule("disallow", "*"))
    return rules


def _legal_material_rules(rng: random.Random, step: Step,
                          steps: Sequence[Step]) -> List[Rule]:
    """Consume the whole material queue with semantically correct rules."""
    rules: List[Rule] = []
    product_paths = set(step.products)
    for path in sorted(step.materials):
        if path not in product_paths:
            rules.append(_exact_generic("delete", path))
        elif step.materials[path] != step.products[path]:
            rules.append(_exact_generic("modify", path))
        else:
            rules.append(Rule("allow", path))
    rng.shuffle(rules)
    rules.append(Rule("disallow", "*"))
    return rules


def generate_legal_scenario(seed: int,
                            step_count: Optional[int] = None
                            ) -> List[Step]:
    """Build a policy the independent model accepts (empty leftover sets)."""
    rng = make_rng(seed)
    count = step_count or rng.randint(2, 3)
    pool = digest_pool(rng)
    names = [f"step-{index}" for index in range(count)]
    steps: List[Step] = []

    for name in names:
        paths = _path_universe(rng)
        materials = _pick_artifacts(rng, paths, pool)
        # Products reuse some material names so MODIFY/DELETE become possible.
        products = {}
        for path in rng.sample(paths, rng.randint(1, len(paths))):
            if path in materials and rng.random() < 0.5:
                # Same name, sometimes changed content, sometimes identical.
                products[path] = (
                    rng.choice(pool) if rng.random() < 0.7
                    else materials[path]
                )
            else:
                products[path] = rng.choice(pool)
        steps.append(Step(name, materials, products))

    for step in steps:
        step.product_rules = _legal_product_rules(rng, step, steps)
        step.material_rules = _legal_material_rules(rng, step, steps)

    return steps


def add_prefix_transformation(step: Step, prefix: str = "build") -> Step:
    """Re-key every artifact under a prefix, keeping digests stable."""
    step.materials = {
        f"{prefix}/{path}": digest for path, digest in step.materials.items()
    }
    step.products = {
        f"{prefix}/{path}": digest for path, digest in step.products.items()
    }
    return step


def add_match_rule(steps: List[Step], source_index: int, target_index: int,
                   pattern: str = "*", dest_type: str = "products",
                   source_prefix: str = "", dest_prefix: str = "",
                   side: str = "products") -> None:
    """Insert a MATCH rule before the terminal DISALLOW."""
    rule = Rule(
        MATCH_TYPE,
        pattern=pattern,
        source_prefix=source_prefix,
        dest_type=dest_type,
        dest_prefix=dest_prefix,
        dest_name=steps[target_index].name,
    )
    target = steps[source_index]
    rule_list = target.product_rules if side == "products" \
        else target.material_rules
    rule_list.insert(len(rule_list) - 1, rule)


def permute_rule_order(steps: List[Step], rng: random.Random) -> List[Step]:
    """Shuffle the non-terminal rules while keeping DISALLOW last."""
    for step in steps:
        for rules in (step.material_rules, step.product_rules):
            if len(rules) > 2:
                head, tail = rules[:-1], rules[-1:]
                rng.shuffle(head)
                rules[:] = head + tail
    return steps


def random_label() -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(6))
