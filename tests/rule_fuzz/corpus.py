# SPDX-License-Identifier: Apache-2.0

"""Handcrafted, human-readable scenarios for the artifact rule fuzzer.

Each entry is small enough to inspect by hand and pins down one of the
behaviors the generator must cover. The two ``*_bug_*`` scenarios are the
targets of the defect injections in :mod:`tests.rule_fuzz.engine`.
"""

from typing import List

from tests.rule_fuzz.model import MATCH_TYPE, Rule, Step

# Reusable hex digests (64 lowercase hex chars), distinct per content label.
def _h(token: str) -> str:
    return (token * 64)[:64]


A = _h("a")
B = _h("b")
C = _h("c")


def same_name_modified() -> List[Step]:
    """Same path in materials and products with a changed digest."""
    step = Step(
        name="build",
        materials={"src": A},
        products={"src": B},
        product_rules=[Rule("modify", "src"), Rule("disallow", "*")],
        material_rules=[Rule("modify", "src"), Rule("disallow", "*")],
    )
    return [step]


def same_name_unchanged() -> List[Step]:
    """Unchanged content must NOT be consumed by MODIFY.

    The model rejects because MODIFY leaves ``src`` in the queue for the
    terminal DISALLOW. The ``modify_same_content`` bug wrongly accepts it.
    """
    step = Step(
        name="build",
        materials={"src": A},
        products={"src": A},
        product_rules=[Rule("modify", "src"), Rule("disallow", "*")],
    )
    return [step]


def create_then_disallow() -> List[Step]:
    """A newly created product is consumed by CREATE, then DISALLOW passes."""
    step = Step(
        name="build",
        materials={},
        products={"out.bin": A},
        product_rules=[Rule("create", "out.bin"), Rule("disallow", "*")],
    )
    return [step]


def delete_scenario() -> List[Step]:
    """A material removed from products is consumed by DELETE."""
    step = Step(
        name="build",
        materials={"old": A},
        products={},
        material_rules=[Rule("delete", "old"), Rule("disallow", "*")],
    )
    return [step]


def early_consumption_leftover() -> List[Step]:
    """ALLOW consumes the path first; the later REQUIRE finds nothing."""
    step = Step(
        name="build",
        materials={},
        products={"keep": A},
        product_rules=[
            Rule("allow", "keep"),
            Rule("require", "keep"),
            Rule("disallow", "*"),
        ],
    )
    return [step]


def require_missing() -> List[Step]:
    """REQUIRE rejects when the literal filename is absent from the queue."""
    step = Step(
        name="build",
        materials={},
        products={"present": A},
        product_rules=[Rule("require", "missing"), Rule("disallow", "*")],
    )
    return [step]


def disallow_catches_illegal() -> List[Step]:
    """An unconsumed illegal product must be caught by terminal DISALLOW."""
    step = Step(
        name="build",
        materials={},
        products={"evil": A, "good": B},
        product_rules=[Rule("create", "good"), Rule("disallow", "*")],
    )
    return [step]


def prefix_transformation() -> List[Step]:
    """Same content moved under a prefix and matched via MATCH prefixes."""
    producer = Step(
        name="producer",
        materials={},
        products={"artifact": A},
        product_rules=[Rule("create", "artifact"), Rule("disallow", "*")],
    )
    consumer = Step(
        name="consumer",
        materials={},
        products={"build/artifact": A},
        product_rules=[
            Rule(
                MATCH_TYPE,
                pattern="artifact",
                source_prefix="build",
                dest_type="products",
                dest_prefix="",
                dest_name="producer",
            ),
            Rule("disallow", "*"),
        ],
    )
    return [producer, consumer]


def match_target_step() -> List[Step]:
    """MATCH must only accept the digest from the declared target step."""
    target = Step(
        name="target",
        materials={},
        products={"shared": A},
        product_rules=[Rule("create", "shared"), Rule("disallow", "*")],
    )
    other = Step(
        name="other",
        materials={},
        products={"shared": A},
        product_rules=[Rule("create", "shared"), Rule("disallow", "*")],
    )
    source = Step(
        name="source",
        materials={},
        products={"shared": A},
        product_rules=[
            Rule(
                MATCH_TYPE,
                pattern="shared",
                dest_type="products",
                dest_name="target",
            ),
            Rule("disallow", "*"),
        ],
    )
    return [target, other, source]


def match_ignored_target_counterexample() -> List[Step]:
    """Target step lacks the artifact, but an unrelated step has it.

    The model rejects (MATCH against ``target`` consumes nothing, so the
    terminal DISALLOW sees the leftover). The ``match_ignore_target_step``
    bug scans ``other`` and wrongly accepts.
    """
    target = Step(
        name="target",
        materials={},
        products={"different": C},
        product_rules=[Rule("create", "different"), Rule("disallow", "*")],
    )
    other = Step(
        name="other",
        materials={},
        products={"shared": A},
        product_rules=[Rule("create", "shared"), Rule("disallow", "*")],
    )
    source = Step(
        name="source",
        materials={},
        products={"shared": A},
        product_rules=[
            Rule(
                MATCH_TYPE,
                pattern="shared",
                dest_type="products",
                dest_name="target",
            ),
            Rule("disallow", "*"),
        ],
    )
    return [target, other, source]


def digest_mismatch_rejected() -> List[Step]:
    """MATCH must not consume when the destination digest differs."""
    target = Step(
        name="target",
        materials={},
        products={"shared": B},
        product_rules=[Rule("create", "shared"), Rule("disallow", "*")],
    )
    source = Step(
        name="source",
        materials={},
        products={"shared": A},
        product_rules=[
            Rule(
                MATCH_TYPE,
                pattern="shared",
                dest_type="products",
                dest_name="target",
            ),
            Rule("disallow", "*"),
        ],
    )
    return [target, source]


def all_scenarios() -> List[tuple]:
    return [
        ("same_name_modified", same_name_modified, True),
        ("same_name_unchanged", same_name_unchanged, False),
        ("create_then_disallow", create_then_disallow, True),
        ("delete_scenario", delete_scenario, True),
        ("early_consumption_leftover", early_consumption_leftover, False),
        ("require_missing", require_missing, False),
        ("disallow_catches_illegal", disallow_catches_illegal, False),
        ("prefix_transformation", prefix_transformation, True),
        ("match_target_step", match_target_step, True),
        ("match_ignored_target", match_ignored_target_counterexample, False),
        ("digest_mismatch_rejected", digest_mismatch_rejected, False),
    ]
