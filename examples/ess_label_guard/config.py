"""Load a closed policy document from local JSON.

The loader exists so deployment uses one explicit file rather than code edits.
It validates the same invariants as ``mapping.validate_configuration`` and
refuses to load anything incomplete, ambiguous or contradictory.
"""

import json
from pathlib import Path
from typing import Mapping, Tuple

from .mapping import (
    CategorySpec,
    Clearance,
    ClearanceError,
    Policy,
    Translation,
    validate_configuration,
)


def load_policy_document(path) -> Tuple[Mapping[str, Policy], Tuple[Translation, ...],
                                        frozenset]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    return build_from_document(document)


def build_from_document(document: Mapping):
    try:
        raw_policies = document["policies"]
        raw_translations = document["translations"]
        trusted_assertors = frozenset(document["trusted_assertors"])
    except (KeyError, TypeError) as exc:
        raise ClearanceError(f"policy document is missing {exc}") from exc

    policies = {}
    for policy_oid, raw in raw_policies.items():
        categories = {}
        for cat_oid, raw_cat in raw["categories"].items():
            values = raw_cat.get("values")
            categories[cat_oid] = CategorySpec(
                oid=cat_oid,
                name=raw_cat["name"],
                syntax=raw_cat["syntax"],
                values=None if values is None else frozenset(values),
            )
        policies[policy_oid] = Policy(
            oid=policy_oid,
            name=raw["name"],
            levels=tuple((int(number), name) for number, name in raw["levels"]),
            categories=categories,
            required_categories=frozenset(raw.get("required_categories", ())),
            absent_classification=raw.get("absent_classification"),
        )

    translations = tuple(
        Translation(
            source_policy=raw["source_policy"],
            source_classification=int(raw["source_classification"]),
            source_categories=_pairs(raw["source_categories"]),
            target_policy=raw["target_policy"],
            target_classification=int(raw["target_classification"]),
            target_categories=_pairs(raw["target_categories"]),
            assertor=raw["assertor"],
        )
        for raw in raw_translations
    )

    validate_configuration(policies, translations, trusted_assertors)

    return policies, translations, trusted_assertors


def _pairs(raw) -> Tuple[Tuple[str, str], ...]:
    return tuple(sorted((str(oid), str(value)) for oid, value in raw))


def parse_clearance(document: Mapping) -> Clearance:
    """Build a clearance from an attested out-of-band record, never a message."""

    return Clearance(
        policy_oid=document["policy_oid"],
        classification=int(document["classification"]),
        categories=_pairs(document.get("categories", ())),
    )
