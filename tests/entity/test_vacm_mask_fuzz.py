"""
Structured fuzz tests for VACM wildcard masks (RFC 3415 section 3.2.5).

The reference oracle compares OBJECT IDENTIFIER components directly as
specified by RFC 3415 (vacmViewTreeFamilyTable DESCRIPTION): a family
matches when the target OID has at least as many sub-identifiers as
vacmViewTreeFamilySubtree and every significant (mask bit = 1) component
is equal; masks shorter than the subtree are extended with 1-bits.  Among
the matching families of a view the one with the most sub-identifiers
wins; ties are broken by the lexicographically greatest family subtree.
The oracle deliberately avoids the normalization and sorting helpers used
by pysnmp/proto/acmod/rfc3415.py.

Inputs are kept small (sub-identifiers in 0..3, up to 3 view families,
masks up to 2 octets) and reproducible (fixed seeds).  A counterexample
is greedily shrunk and persisted to vacm_fuzz_counterexamples.json next
to this file; the replay test re-checks the shrunk cases.

Covered combinations: included/excluded subtrees, mask length vs subtree
length (default 1-bits), ignored components, OIDs shorter than the
subtree, same-length include/exclude conflicts, and view deletion
followed by re-creation (VACM cache rebuild).
"""

import copy
import json
import random
from pathlib import Path

import pytest

from pysnmp.entity import config, engine
from pysnmp.proto import error as proto_error
from pysnmp.proto.rfc1902 import OctetString

SECURITY_MODEL = 2
SECURITY_LEVEL = 1
SECURITY_NAME = OctetString("fuzzuser")
CONTEXT_NAME = OctetString("")
GROUP_NAME = "fuzzgroup"
VIEW_NAME = "fuzzview"

COUNTEREXAMPLES_PATH = Path(__file__).with_name("vacm_fuzz_counterexamples.json")

FUZZ_SEED = 20261114
FUZZ_CASES = 300
MUTANT_SEED = 3415
MUTANT_CASES = 500
MAX_SHRINK_ROUNDS = 100

# config.add_vacm_view() treats masks containing a "." byte as OID-like
# strings; that config-layer heuristic is not the fuzz target
MASK_BYTE_ALPHABET = [b for b in range(256) if b != 0x2E]


# ---------------------------------------------------------------------------
# RFC 3415 reference oracle (plain tuples, no production helpers)
# ---------------------------------------------------------------------------


def _mask_significance(position, mask):
    """RFC 3415: masks shorter than the subtree are extended with 1-bits."""
    byte_index, bit_index = divmod(position, 8)
    if byte_index < len(mask):
        return (mask[byte_index] >> (7 - bit_index)) & 1
    return 1


def _rfc3415_view_decision(families, oid, significance, tiebreak_key):
    """Pick the applicable view family and return its included flag."""
    best = None
    for subtree, mask, included in families:
        # RFC 3415: X must have at least as many sub-identifiers as the subtree
        if len(oid) < len(subtree):
            continue
        if all(
            not significance(position, mask) or oid[position] == component
            for position, component in enumerate(subtree)
        ):
            key = (len(subtree), tiebreak_key(subtree))
            if best is None or key > best[0]:
                best = key, included
    return best is not None and best[1]


def oracle_decision(families, oid):
    """RFC 3415 decision: longest match, then greatest subtree wins."""
    return _rfc3415_view_decision(families, oid, _mask_significance, tuple)


def mutant_compares_masked_components(families, oid):
    """Buggy decider: mask ignored, masked-away components compared exactly."""
    return _rfc3415_view_decision(families, oid, lambda position, mask: True, tuple)


def mutant_reversed_exclusion_precedence(families, oid):
    """Buggy decider: equal-length ties won by the smallest subtree."""
    return _rfc3415_view_decision(
        families, oid, _mask_significance, lambda subtree: tuple(-x for x in subtree)
    )


# ---------------------------------------------------------------------------
# Case structure and structured generator
# ---------------------------------------------------------------------------


def _gen_oid(rng, max_length):
    length = rng.randint(1, max_length)
    oid = [rng.choice((0, 1, 2))]
    oid.extend(rng.choice((0, 1, 2, 3)) for _ in range(length - 1))
    return oid


def _gen_mask(rng):
    return [rng.choice(MASK_BYTE_ALPHABET) for _ in range(rng.randint(0, 2))]


def generate_case(rng):
    # occasionally longer subtrees so that short masks exercise the
    # default 1-bit extension beyond whole octets
    max_subtree_length = 10 if rng.random() < 0.15 else 4
    families = [
        {
            "subtree": _gen_oid(rng, max_subtree_length),
            "mask": _gen_mask(rng),
            "included": rng.random() < 0.5,
        }
        for _ in range(rng.randint(1, 3))
    ]
    case = {"families": families, "oid": _gen_oid(rng, 5), "rebuild": None}
    if rng.random() < 0.3:
        case["rebuild"] = {
            "index": rng.randrange(len(families)),
            "mask": _gen_mask(rng),
            "included": rng.random() < 0.5,
        }
    return case


def effective_families(case):
    """Collapse duplicate subtrees (same table row, last write wins)."""
    rows = {}
    for family in case["families"]:
        rows[tuple(family["subtree"])] = (tuple(family["mask"]), family["included"])
    if case["rebuild"]:
        rebuild = case["rebuild"]
        subtree = tuple(case["families"][rebuild["index"]]["subtree"])
        rows[subtree] = (tuple(rebuild["mask"]), rebuild["included"])
    return [(subtree, mask, included) for subtree, (mask, included) in rows.items()]


# ---------------------------------------------------------------------------
# Harness driving the production VACM through a real SnmpEngine
# ---------------------------------------------------------------------------


class EngineHarness:
    """Apply fuzz cases as live VACM config and query the production Vacm."""

    def __init__(self):
        self.snmp_engine = engine.SnmpEngine()
        config.add_context(self.snmp_engine, b"")
        config.add_vacm_group(
            self.snmp_engine, GROUP_NAME, SECURITY_MODEL, SECURITY_NAME
        )
        config.add_vacm_access(
            self.snmp_engine,
            GROUP_NAME,
            b"",
            SECURITY_MODEL,
            SECURITY_LEVEL,
            "exact",
            VIEW_NAME,
            "",
            "",
        )
        self.vacm = self.snmp_engine.access_control_model[3]
        self._added_subtrees = set()

    def _add_view(self, subtree, mask, included):
        config.add_vacm_view(
            self.snmp_engine,
            VIEW_NAME,
            "included" if included else "excluded",
            tuple(subtree),
            bytes(mask),
        )
        self._added_subtrees.add(tuple(subtree))

    def apply(self, case):
        for subtree in self._added_subtrees:
            config.delete_vacm_view(self.snmp_engine, VIEW_NAME, subtree)
        self._added_subtrees = set()
        for family in case["families"]:
            self._add_view(family["subtree"], family["mask"], family["included"])
        if case["rebuild"]:
            rebuild = case["rebuild"]
            subtree = tuple(case["families"][rebuild["index"]]["subtree"])
            config.delete_vacm_view(self.snmp_engine, VIEW_NAME, subtree)
            self._add_view(subtree, rebuild["mask"], rebuild["included"])
        return self.decide(case["oid"])

    def decide(self, oid):
        try:
            self.vacm.is_access_allowed(
                self.snmp_engine,
                SECURITY_MODEL,
                SECURITY_NAME,
                SECURITY_LEVEL,
                "read",
                CONTEXT_NAME,
                tuple(oid),
            )
        except proto_error.StatusInformation as exc:
            return ("denied", str(exc["errorIndication"]))
        except Exception as exc:
            # IndexError (or anything else) is never a legitimate denial
            return ("error", "%s: %s" % (type(exc).__name__, exc))
        return ("allowed", None)


def check_case(apply, case):
    """Return (failed, outcome, expected) for one case."""
    outcome = apply(case)
    expected = oracle_decision(effective_families(case), tuple(case["oid"]))
    if outcome[0] == "error":
        return True, outcome, expected
    return (outcome[0] == "allowed") != expected, outcome, expected


# ---------------------------------------------------------------------------
# Greedy shrinker
# ---------------------------------------------------------------------------


def _simplifications(case):
    if case["rebuild"] is not None:
        candidate = copy.deepcopy(case)
        candidate["rebuild"] = None
        yield candidate
    for index in range(len(case["families"])):
        if len(case["families"]) > 1:
            candidate = copy.deepcopy(case)
            del candidate["families"][index]
            if candidate["rebuild"]:
                candidate["rebuild"] = None
            yield candidate
    if len(case["oid"]) > 1:
        candidate = copy.deepcopy(case)
        candidate["oid"] = candidate["oid"][:-1]
        yield candidate
    for position, value in enumerate(case["oid"]):
        if value:
            candidate = copy.deepcopy(case)
            candidate["oid"][position] = 0
            yield candidate
    for index, family in enumerate(case["families"]):
        if len(family["subtree"]) > 1:
            candidate = copy.deepcopy(case)
            candidate["families"][index]["subtree"] = family["subtree"][:-1]
            if candidate["rebuild"]:
                candidate["rebuild"] = None
            yield candidate
        if family["mask"]:
            candidate = copy.deepcopy(case)
            candidate["families"][index]["mask"] = family["mask"][:-1]
            yield candidate
        for position, value in enumerate(family["subtree"]):
            if value:
                candidate = copy.deepcopy(case)
                candidate["families"][index]["subtree"][position] = 0
                yield candidate
        for position, value in enumerate(family["mask"]):
            if value:
                candidate = copy.deepcopy(case)
                candidate["families"][index]["mask"][position] = 0
                yield candidate


def shrink(case, still_fails):
    case = copy.deepcopy(case)
    for _ in range(MAX_SHRINK_ROUNDS):
        for candidate in _simplifications(case):
            if still_fails(candidate):
                case = candidate
                break
        else:
            return case
    return case


# ---------------------------------------------------------------------------
# Fuzz driver and counterexample persistence
# ---------------------------------------------------------------------------


def run_fuzz(apply, seed, case_count):
    rng = random.Random(seed)
    for _ in range(case_count):
        case = generate_case(rng)
        failed, _, _ = check_case(apply, case)
        if failed:
            shrunk = shrink(case, lambda c: check_case(apply, c)[0])
            failed, outcome, expected = check_case(apply, shrunk)
            return shrunk, outcome, expected
    return None


def _load_counterexamples():
    if not COUNTEREXAMPLES_PATH.exists():
        return []
    return json.loads(COUNTEREXAMPLES_PATH.read_text())


def _record_counterexample(case, outcome, expected):
    entries = _load_counterexamples()
    entry = {
        "case": case,
        "expected": "allowed" if expected else "denied",
        "actual": [outcome[0], outcome[1]],
    }
    if entry not in entries:
        entries.append(entry)
        COUNTEREXAMPLES_PATH.write_text(
            json.dumps(entries, indent=2, sort_keys=True) + "\n"
        )


def _format_case(case, outcome, expected):
    return "counterexample: %s\nexpected %s but got %s %s" % (
        json.dumps(case, sort_keys=True),
        "allowed" if expected else "denied",
        outcome[0],
        outcome[1],
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def harness():
    return EngineHarness()


def test_fuzz_vacm_mask_against_rfc3415_oracle(harness):
    result = run_fuzz(harness.apply, FUZZ_SEED, FUZZ_CASES)
    if result is not None:
        case, outcome, expected = result
        _record_counterexample(case, outcome, expected)
        pytest.fail(_format_case(case, outcome, expected))


def test_replay_shrunk_counterexamples(harness):
    for entry in _load_counterexamples():
        failed, outcome, expected = check_case(harness.apply, entry["case"])
        assert not failed, _format_case(entry["case"], outcome, expected)


def test_oid_shorter_than_masked_subtree_is_denied_cleanly(harness):
    """An OID shorter than the subtree never matches (RFC 3415); the mask
    normalization must not turn that into an IndexError."""
    case = {
        "families": [{"subtree": [1, 3, 6], "mask": [0], "included": True}],
        "oid": [1],
        "rebuild": None,
    }
    outcome = harness.apply(case)
    assert outcome[0] == "denied", outcome


def test_mask_shorter_than_subtree_defaults_to_exact_bits(harness):
    """Missing mask bits default to 1 (exact match), not to wildcards."""
    # empty mask: every bit defaults to 1 -> exact subtree match
    case = {
        "families": [{"subtree": [1, 3, 6], "mask": [], "included": True}],
        "oid": [1, 3, 7],
        "rebuild": None,
    }
    assert harness.apply(case)[0] == "denied"
    case["oid"] = [1, 3, 6, 9]
    assert harness.apply(case)[0] == "allowed"
    # one-octet mask over a 9-sub-identifier subtree: bit 9 defaults to 1
    case["families"] = [
        {"subtree": [1, 3, 6, 1, 2, 1, 1, 1, 1], "mask": [0xFF], "included": True}
    ]
    case["oid"] = [1, 3, 6, 1, 2, 1, 1, 1, 2]
    assert harness.apply(case)[0] == "denied"
    case["oid"] = [1, 3, 6, 1, 2, 1, 1, 1, 1, 0]
    assert harness.apply(case)[0] == "allowed"


def test_same_length_conflict_greatest_subtree_wins(harness):
    """Equal-length matches: lexicographically greatest subtree decides."""
    families = [
        {"subtree": [1, 3], "mask": [0x80], "included": False},
        {"subtree": [2, 0], "mask": [0x00], "included": True},
    ]
    case = {"families": families, "oid": [1, 1], "rebuild": None}
    # (2,0) is lexicographically greater and included -> allowed
    assert harness.apply(case)[0] == "allowed"
    case["families"] = [dict(f, included=not f["included"]) for f in families]
    # now the greatest subtree is excluded -> denied
    assert harness.apply(case)[0] == "denied"


def test_view_delete_and_rebuild_updates_decision(harness):
    """Deleting and re-creating a view family must rebuild the VACM cache."""
    case = {
        "families": [{"subtree": [1, 3, 6], "mask": [], "included": True}],
        "oid": [1, 3, 6, 1],
        "rebuild": None,
    }
    assert harness.apply(case)[0] == "allowed"
    case["families"][0]["included"] = False
    assert harness.apply(case)[0] == "denied"
    case["rebuild"] = {"index": 0, "mask": [], "included": True}
    assert harness.apply(case)[0] == "allowed"


def _collect_mismatches(apply, seed, case_count):
    rng = random.Random(seed)
    mismatches = []
    for _ in range(case_count):
        case = generate_case(rng)
        failed, outcome, expected = check_case(apply, case)
        if failed:
            mismatches.append((case, outcome, expected))
    return mismatches


def _mutant_apply(mutant):
    def apply(case):
        allowed = mutant(effective_families(case), tuple(case["oid"]))
        return ("allowed", None) if allowed else ("denied", "notInView")

    return apply


def test_mutant_comparing_masked_components_is_caught():
    """A decider that compares mask-ignored components breaks legit traffic."""
    mismatches = _collect_mismatches(
        _mutant_apply(mutant_compares_masked_components), MUTANT_SEED, MUTANT_CASES
    )
    assert mismatches, "fuzzer failed to catch the masked-component mutant"
    assert any(
        expected and outcome[0] == "denied" for _, outcome, expected in mismatches
    ), "no legit-vs-mutant contrast found"


def test_mutant_reversed_exclusion_precedence_is_caught():
    """A decider that reverses exclusion precedence allows protected OIDs."""
    mismatches = _collect_mismatches(
        _mutant_apply(mutant_reversed_exclusion_precedence), MUTANT_SEED, MUTANT_CASES
    )
    assert mismatches, "fuzzer failed to catch the precedence mutant"
    assert any(
        not expected and outcome[0] == "allowed" for _, outcome, expected in mismatches
    ), "no unauthorized-access contrast found"
