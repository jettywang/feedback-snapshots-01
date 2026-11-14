"""Explicit, local security-policy mappings for ESS / S-MIME security labels.

There is no network, directory lookup or auto-discovery here.  A receiving
gateway loads one of the two finite policies below (or a JSON document in the
same shape) and can only reason inside that closed set.  Anything outside it
yields REVIEW, never a guessed level.

ASN.1 shape (RFC 2634, section 3.2, as modelled by pyasn1_modules.rfc2634):

    ESSSecurityLabel ::= SET {
        security-policy-identifier SecurityPolicyIdentifier,
        security-classification  SecurityClassification OPTIONAL,
        privacy-mark             ESSPrivacyMark OPTIONAL,
        security-categories      SecurityCategories OPTIONAL }

A classification integer is meaningful only under its policy OID.  The
ordered ``levels`` list below is the single source of truth for ordering;
integers are opaque identifiers, not a magnitude.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple


# --- Two finite policy domains ------------------------------------------------

POLICY_A = "1.3.6.1.4.1.32473.100.1"
POLICY_B = "1.3.6.1.4.1.32473.200.1"

# Category types are meaningful only together with a policy OID.  A and B use
# different OIDs.  A category's syntax is part of its local definition; a
# category type that is absent from this table cannot be decoded at all.
CAT_A_COMPARTMENT = "1.3.6.1.4.1.32473.100.2.1"
CAT_A_CAVEAT = "1.3.6.1.4.1.32473.100.2.2"
CAT_A_RELEASABILITY = "1.3.6.1.4.1.32473.100.2.3"

CAT_B_DEPARTMENT = "1.3.6.1.4.1.32473.200.2.1"
CAT_B_HANDLING = "1.3.6.1.4.1.32473.200.2.2"


@dataclass(frozen=True)
class CategorySpec:
    """One category type in one policy domain.

    ``values`` is the closed set of accepted decoded values; ``None`` means a
    free-form value is accepted, but only because the local policy explicitly
    says so.  ``syntax`` is one of ``utf8``, ``ia5`` or ``integer``.
    """

    oid: str
    name: str
    syntax: str
    values: Optional[frozenset] = None


@dataclass(frozen=True)
class Policy:
    oid: str
    name: str
    # Ordered ascending: index = rank.  Integers need not ascend numerically.
    levels: Tuple[Tuple[int, str], ...]
    categories: Dict[str, CategorySpec]
    # Categories that must appear on every complete label of this policy.
    required_categories: frozenset = field(default_factory=frozenset)
    # What an absent security-classification means in this policy.  ``None``
    # means "no local rule"; the guard then returns REVIEW instead of inventing
    # a level (RFC 2634 allows a policy to define absence as unmarked, but this
    # must be an explicit local decision).
    absent_classification: Optional[int] = None

    def rank(self, classification: int) -> Optional[int]:
        for index, (number, _name) in enumerate(self.levels):
            if number == classification:
                return index
        return None

    def level_name(self, classification: int) -> Optional[str]:
        rank = self.rank(classification)
        return None if rank is None else self.levels[rank][1]


POLICIES = {
    POLICY_A: Policy(
        oid=POLICY_A,
        name="Agency-A",
        # Ascending rank, deliberately not ascending numeric order.  This is
        # the RFC 2634 section 3.3.2 example: 11 (Sensitive-But-Unclassified)
        # ranks below 2 (restricted), even though 11 > 2 numerically.
        levels=((0, "unmarked"), (1, "unclassified"),
                (11, "sensitive-but-unclassified"), (2, "restricted"),
                (4, "secret"), (5, "top-secret")),
        categories={
            CAT_A_COMPARTMENT: CategorySpec(
                oid=CAT_A_COMPARTMENT, name="compartment", syntax="utf8",
                values=frozenset({"ALPHA", "BRAVO"})),
            CAT_A_CAVEAT: CategorySpec(
                oid=CAT_A_CAVEAT, name="caveat", syntax="utf8",
                values=frozenset({"NOFORN", "EYES-ONLY"})),
            CAT_A_RELEASABILITY: CategorySpec(
                oid=CAT_A_RELEASABILITY, name="releasability", syntax="utf8",
                values=frozenset({"A", "A+B"})),
        },
        required_categories=frozenset({CAT_A_COMPARTMENT}),
        absent_classification=None,
    ),
    POLICY_B: Policy(
        oid=POLICY_B,
        name="Agency-B",
        # A different hierarchy.  B's integer 2 is "internal"; A's integer 2
        # is "restricted".  The same number does not denote the same level.
        levels=((0, "public"), (2, "internal"), (7, "confidential"),
                (9, "restricted")),
        categories={
            CAT_B_DEPARTMENT: CategorySpec(
                oid=CAT_B_DEPARTMENT, name="department", syntax="utf8",
                values=frozenset({"FIN", "HR", "ENG"})),
            CAT_B_HANDLING: CategorySpec(
                oid=CAT_B_HANDLING, name="handling", syntax="utf8",
                values=frozenset({"NEED-TO-KNOW", "PUBLIC-SECTOR"})),
        },
        required_categories=frozenset({CAT_B_DEPARTMENT}),
        absent_classification=None,
    ),
}


# Global syntax table.  It is deliberately local data: an unseen category type
# is never decoded by guesswork.
CATEGORY_SYNTAX = {
    spec.oid: spec.syntax
    for policy in POLICIES.values()
    for spec in policy.categories.values()
}


# --- Bilateral translation tables --------------------------------------------
#
# A translation entry says: "under source policy S, classification N with
# exactly these category values is equivalent to target policy T classification
# M with these category values".  Every source label must match one entry in
# full; there is no "closest", "minimum" or "most permissive" fallback.

@dataclass(frozen=True)
class Translation:
    source_policy: str
    source_classification: int
    # source category OID -> decoded value
    source_categories: Tuple[Tuple[str, str], ...]
    target_policy: str
    target_classification: int
    target_categories: Tuple[Tuple[str, str], ...]
    # The accountable role authorised to assert this mapping.  This is an OID,
    # not a person and not a key.  The CMS layer decides whether the signature
    # on EquivalentLabels is valid; local policy decides whether this role is
    # trusted to translate.
    assertor: str


def _cats(mapping):
    return tuple(sorted(mapping.items()))


TRUSTED_ASSERTORS = frozenset({
    "1.3.6.1.4.1.32473.100.9.1",
    "1.3.6.1.4.1.32473.200.9.1",
})

_A_TO_B = "1.3.6.1.4.1.32473.100.9.1"
_B_TO_A = "1.3.6.1.4.1.32473.200.9.1"



TRANSLATIONS = (
    # --- A -> B: both classification and category meaning change -------------
    Translation(POLICY_A, 1, _cats({CAT_A_COMPARTMENT: "ALPHA"}),
                POLICY_B, 0, _cats({CAT_B_DEPARTMENT: "FIN"}), _A_TO_B),
    Translation(POLICY_A, 1, _cats({CAT_A_COMPARTMENT: "BRAVO"}),
                POLICY_B, 0, _cats({CAT_B_DEPARTMENT: "HR"}), _A_TO_B),
    Translation(POLICY_A, 11, _cats({CAT_A_COMPARTMENT: "ALPHA"}),
                POLICY_B, 2, _cats({CAT_B_DEPARTMENT: "FIN"}), _A_TO_B),
    Translation(POLICY_A, 11, _cats({CAT_A_COMPARTMENT: "BRAVO"}),
                POLICY_B, 2, _cats({CAT_B_DEPARTMENT: "ENG"}), _A_TO_B),
    Translation(POLICY_A, 2, _cats({CAT_A_COMPARTMENT: "ALPHA"}),
                POLICY_B, 7, _cats({CAT_B_DEPARTMENT: "FIN"}), _A_TO_B),
    Translation(POLICY_A, 2, _cats({CAT_A_COMPARTMENT: "BRAVO"}),
                POLICY_B, 7, _cats({CAT_B_DEPARTMENT: "ENG"}), _A_TO_B),
    Translation(POLICY_A, 4, _cats({CAT_A_COMPARTMENT: "ALPHA"}),
                POLICY_B, 9, _cats({CAT_B_DEPARTMENT: "FIN"}), _A_TO_B),
    Translation(POLICY_A, 4, _cats({CAT_A_COMPARTMENT: "BRAVO"}),
                POLICY_B, 9, _cats({CAT_B_DEPARTMENT: "ENG"}), _A_TO_B),
    Translation(
        POLICY_A, 5, _cats({CAT_A_COMPARTMENT: "ALPHA"}),
        POLICY_B, 9,
        _cats({CAT_B_DEPARTMENT: "FIN", CAT_B_HANDLING: "NEED-TO-KNOW"}),
        _A_TO_B),

    # --- B -> A: the reverse direction needs its own local table -------------
    Translation(POLICY_B, 0, _cats({CAT_B_DEPARTMENT: "FIN"}),
                POLICY_A, 1, _cats({CAT_A_COMPARTMENT: "ALPHA"}), _B_TO_A),
    Translation(POLICY_B, 0, _cats({CAT_B_DEPARTMENT: "HR"}),
                POLICY_A, 1, _cats({CAT_A_COMPARTMENT: "BRAVO"}), _B_TO_A),
    Translation(POLICY_B, 2, _cats({CAT_B_DEPARTMENT: "FIN"}),
                POLICY_A, 11, _cats({CAT_A_COMPARTMENT: "ALPHA"}), _B_TO_A),
    Translation(POLICY_B, 7, _cats({CAT_B_DEPARTMENT: "FIN"}),
                POLICY_A, 2, _cats({CAT_A_COMPARTMENT: "ALPHA"}), _B_TO_A),
    Translation(POLICY_B, 7, _cats({CAT_B_DEPARTMENT: "ENG"}),
                POLICY_A, 2, _cats({CAT_A_COMPARTMENT: "BRAVO"}), _B_TO_A),
    Translation(POLICY_B, 9, _cats({CAT_B_DEPARTMENT: "FIN"}),
                POLICY_A, 4, _cats({CAT_A_COMPARTMENT: "ALPHA"}), _B_TO_A),
    Translation(POLICY_B, 9, _cats({CAT_B_DEPARTMENT: "ENG"}),
                POLICY_A, 4, _cats({CAT_A_COMPARTMENT: "BRAVO"}), _B_TO_A),
)


class ClearanceError(ValueError):
    """The local policy/translation configuration is not safe to use."""


def lookup(policy_oid: str) -> Optional[Policy]:
    return POLICIES.get(policy_oid)


def translations_from(policy_oid: str):
    return tuple(t for t in TRANSLATIONS if t.source_policy == policy_oid)


def category_syntax_table(policies=POLICIES):
    """Local {category OID: syntax} table for a given closed policy set."""

    return {
        spec.oid: spec.syntax
        for policy in policies.values()
        for spec in policy.categories.values()
    }


def validate_configuration(policies=POLICIES, translations=TRANSLATIONS,
                           trusted_assertors=TRUSTED_ASSERTORS):
    """Refuse to start with incomplete, ambiguous or contradictory mappings."""

    errors = []

    for policy_oid, policy in policies.items():
        if policy.oid != policy_oid:
            errors.append(f"{policy_oid}: policy.oid mismatch {policy.oid}")
        numbers = [number for number, _name in policy.levels]
        if len(numbers) != len(set(numbers)):
            errors.append(f"{policy_oid}: duplicate classification integer")
        names = [name for _number, name in policy.levels]
        if len(names) != len(set(names)):
            errors.append(f"{policy_oid}: duplicate classification name")
        if policy.absent_classification is not None:
            if policy.rank(policy.absent_classification) is None:
                errors.append(
                    f"{policy_oid}: absent classification "
                    f"{policy.absent_classification} is not in the hierarchy")
        for cat_oid, spec in policy.categories.items():
            if spec.oid != cat_oid:
                errors.append(f"{policy_oid}: category key/oid mismatch {cat_oid}")
            if spec.syntax not in {"utf8", "ia5", "integer"}:
                errors.append(f"{policy_oid}: bad syntax for {cat_oid}")
            if spec.values is not None and not spec.values:
                errors.append(f"{policy_oid}: empty value set for {cat_oid}")
        for cat_oid in policy.required_categories:
            if cat_oid not in policy.categories:
                errors.append(
                    f"{policy_oid}: required category {cat_oid} is undefined")

    category_owner = {}
    for policy_oid, policy in policies.items():
        for cat_oid, spec in policy.categories.items():
            previous = category_owner.get(cat_oid)
            if previous is not None:
                other_policy, other_spec = previous
                if (other_spec.syntax != spec.syntax
                        or other_spec.values != spec.values
                        or other_spec.name != spec.name):
                    errors.append(
                        f"category {cat_oid} is defined inconsistently in "
                        f"{other_policy} and {policy_oid}")
            else:
                category_owner[cat_oid] = (policy_oid, spec)

    source_keys = {}
    direction_assertors = {}
    for index, trans in enumerate(translations):
        label = f"translation[{index}]"
        source = policies.get(trans.source_policy)
        target = policies.get(trans.target_policy)
        if source is None:
            errors.append(f"{label}: unknown source policy {trans.source_policy}")
        if target is None:
            errors.append(f"{label}: unknown target policy {trans.target_policy}")
        if source is None or target is None:
            continue
        if trans.source_policy == trans.target_policy:
            errors.append(f"{label}: source and target policy are identical")
        if source.rank(trans.source_classification) is None:
            errors.append(f"{label}: unknown source classification")
        if target.rank(trans.target_classification) is None:
            errors.append(f"{label}: unknown target classification")
        if trans.assertor not in trusted_assertors:
            errors.append(
                f"{label}: assertor {trans.assertor} is not in the local "
                "trust allowlist")

        direction_assertors.setdefault(
            (trans.source_policy, trans.target_policy), set()).add(
                trans.assertor)

        _check_category_set(
            errors, label, "source", source, trans.source_categories)
        _check_category_set(
            errors, label, "target", target, trans.target_categories)

        for role, policy, category_set in (
                ("source", source, trans.source_categories),
                ("target", target, trans.target_categories)):
            missing_required = {
                oid for oid in policy.required_categories
                if oid not in dict(category_set)
            }
            if missing_required:
                errors.append(
                    f"{label}: {role} misses required categories "
                    f"{sorted(missing_required)}")

        source_key = (trans.source_policy, trans.source_classification,
                      trans.source_categories)
        if source_key in source_keys:
            errors.append(
                f"{label}: ambiguous source key also used by "
                f"{source_keys[source_key]}")
        source_keys[source_key] = label

    # Trust is per direction, not global.  A single direction must name exactly
    # one accountable role; otherwise "who may translate" is ambiguous.
    for direction, assertors in direction_assertors.items():
        if len(assertors) > 1:
            errors.append(
                f"direction {direction[0]} -> {direction[1]} names multiple "
                f"assertors {sorted(assertors)}; ownership is ambiguous")

    if errors:
        raise ClearanceError("; ".join(errors))
    return True


def _check_category_set(errors, label, side, policy, category_set):
    seen = set()
    for cat_oid, value in category_set:
        if cat_oid in seen:
            errors.append(f"{label}: duplicate {side} category {cat_oid}")
        seen.add(cat_oid)
        spec = policy.categories.get(cat_oid)
        if spec is None:
            errors.append(f"{label}: unknown {side} category {cat_oid}")
            continue
        if spec.values is not None and value not in spec.values:
            errors.append(
                f"{label}: {side} value {value!r} not allowed for {cat_oid}")


validate_configuration()


@dataclass(frozen=True)
class Clearance:
    """An authoritative recipient clearance, already in the local policy.

    The caller obtains this from a trusted source (for example a signed
    clearance attribute or the recipient's directory entry).  The guard checks
    it; the guard is not the authority that grants it.
    """

    policy_oid: str
    classification: Optional[int]
    categories: Tuple[Tuple[str, str], ...] = ()

    def category_values(self, oid: str):
        return {value for cat_oid, value in self.categories if cat_oid == oid}
