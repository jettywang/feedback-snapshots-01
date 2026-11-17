"""
Tests for a single, spec-aware equality contract shared by the ordinary
comparison operators (=, !=) and the set membership operators (IN, NOT IN).

The motivation is that Python's native equality conflates the JSON boolean
and number types (True == 1, hash(True) == hash(1)).  STIX treats them as
distinct, non-interoperable types, so that relationship must never change a
matching result.  These tests pin down the distinction between:

  - a property that is absent (the path selects nothing),
  - a property that is explicitly null,
  - values whose types are not interoperable (type mismatch -> not equal),
  - values that are genuinely unequal,

while preserving the interoperability the spec does allow (int/float and
binary/string).  They also ensure an IN set is exactly equivalent to the
OR-ed chain of "=" comparisons, across several SCOs reached via wildcard
paths.
"""
import pytest

from stix2matcher.matcher import match

_stix_version = '2.1'

# One observed-data SDO referencing several SCOs.  Each SCO exposes a single
# "flag" value of a different JSON type, plus a "vals" list reached through a
# wildcard ([*]) path so that observation expressions are evaluated against a
# heterogeneous collection of values.
_observations = [
    {
        "type": "bundle",
        "id": "bundle--7d2c0d63-type-contract",
        "objects": [
            {
                "id": "observed-data--type-contract",
                "type": "observed-data",
                "spec_version": "2.1",
                "number_observed": 1,
                "first_observed": "2020-01-01T00:00:00Z",
                "last_observed": "2020-01-01T00:00:00Z",
                "object_refs": [
                    "tcbool--1",
                    "tcint--1",
                    "tcfloat--1",
                    "tcstr--1",
                    "tcbin--1",
                ],
            },
            # boolean true: must never be treated as the number 1.
            {
                "id": "tcbool--1",
                "type": "tcbool",
                "flag": True,
                "vals": [True, False],
            },
            # integer 1: must never be treated as the boolean true.
            {
                "id": "tcint--1",
                "type": "tcint",
                "flag": 1,
                "vals": [1, 2],
            },
            # floating point 1.0: interoperable with integers.
            {
                "id": "tcfloat--1",
                "type": "tcfloat",
                "flag": 1.0,
                "vals": [1.0, 2.5],
            },
            # string "1": a distinct type from both bool and number; "note"
            # is explicitly null and "missing" is simply absent.
            {
                "id": "tcstr--1",
                "type": "tcstr",
                "flag": "1",
                "vals": ["1", "two"],
                "note": None,
            },
            # binary value and an all-codepoints<256 string: the spec allows
            # binary/string comparison, which must keep working under IN too.
            {
                "id": "tcbin--1",
                "type": "tcbin",
                "blob": b"abc",
            },
        ],
    }
]


# (pattern, expected_match).  Each row is one cell of the comparison matrix.
_MATRIX = [
    # --- the True vs 1 hazard: bool and number are never interoperable ---
    ("[tcbool:flag = 1]", False),
    ("[tcbool:flag != 1]", True),
    ("[tcbool:flag = true]", True),
    ("[tcbool:flag IN (1)]", False),
    ("[tcbool:flag IN (true)]", True),
    ("[tcbool:flag NOT IN (1)]", True),
    ("[tcbool:flag NOT IN (true)]", False),

    # integer 1 is not boolean true, in either direction
    ("[tcint:flag = true]", False),
    ("[tcint:flag IN (true)]", False),
    ("[tcint:flag NOT IN (true)]", True),
    ("[tcint:vals[*] IN (true)]", False),

    # --- numeric interop is preserved: int/float may compare equal ---
    ("[tcint:flag = 1.0]", True),
    ("[tcfloat:flag = 1]", True),
    ("[tcint:vals[*] = 1.0]", True),
    ("[tcint:vals[*] IN (1)]", True),
    ("[tcint:vals[*] IN (1.0)]", True),
    ("[tcint:vals[*] IN (0, 1.0, 2)]", True),
    ("[tcint:vals[*] NOT IN (9, 9.5)]", True),

    # --- genuine inequality among interoperable numeric types ---
    ("[tcint:flag = 7]", False),
    ("[tcint:vals[*] IN (7, 8)]", False),
    # vals are 1 and 2; 2 is genuinely not in (1, 7), so the wildcard finds a
    # passing element even though 1 is a member.
    ("[tcint:vals[*] NOT IN (1, 7)]", True),

    # --- string/number and string/bool are non-interoperable ---
    ("[tcstr:flag = 1]", False),
    ("[tcstr:flag != 1]", True),
    ("[tcstr:flag IN (1, 2)]", False),
    ("[tcstr:flag NOT IN (1, 2)]", True),
    ("[tcstr:vals[*] IN ('one', 'two')]", True),
    ("[tcstr:vals[*] IN (1, 2)]", False),

    # --- binary/string interop is preserved (all codepoints < 256) ---
    ("[tcbin:blob = b'YWJj']", True),
    ("[tcbin:blob = 'abc']", True),
    ("[tcbin:blob IN (b'YWJj', b'emQ=')]", True),
    ("[tcbin:blob IN ('abc', 'zd')]", True),
    ("[tcbin:blob NOT IN ('abc', 'zd')]", False),
    # binary versus a number is not interoperable: not equal, and NOT IN holds
    ("[tcbin:blob IN (1, 2)]", False),
    ("[tcbin:blob NOT IN (1, 2)]", True),

    # --- explicit null: never equal, always not-equal; membership fails but
    # NOT IN holds because the value is unequal to every set member ---
    ("[tcstr:note = 'x']", False),
    ("[tcstr:note IN ('x', 'y')]", False),
    ("[tcstr:note NOT IN ('x', 'y')]", True),

    # --- missing property: the path selects nothing, so neither the
    # positive test nor the membership test can match; NOT IN cannot match
    # either because there is no value to test ---
    ("[tcstr:missing = 'x']", False),
    ("[tcstr:missing != 'x']", False),
    ("[tcstr:missing IN ('x', 'y')]", False),
    ("[tcstr:missing NOT IN ('x', 'y')]", False),
]


@pytest.mark.parametrize("pattern, expected", _MATRIX)
def test_type_contract_matrix(pattern, expected):
    assert bool(match(pattern, _observations, stix_version=_stix_version)) \
        is expected


# Every IN / NOT IN condition must give the same answer as its expansion into
# OR-ed / AND-ed "=" / "!=" comparisons over the same wildcard-selected values.
_EQUIVALENCE = [
    ("[tcint:vals[*] IN (1, 2, 3)]",
     "[tcint:vals[*] = 1 OR tcint:vals[*] = 2 OR tcint:vals[*] = 3]"),
    ("[tcbool:vals[*] IN (true, false)]",
     "[tcbool:vals[*] = true OR tcbool:vals[*] = false]"),
    ("[tcstr:vals[*] IN ('1', 'two')]",
     "[tcstr:vals[*] = '1' OR tcstr:vals[*] = 'two']"),
    ("[tcint:vals[*] NOT IN (7, 8)]",
     "[tcint:vals[*] != 7 AND tcint:vals[*] != 8]"),
]


@pytest.mark.parametrize("set_pattern, expanded_pattern", _EQUIVALENCE)
def test_in_equivalent_to_or_chain(set_pattern, expanded_pattern):
    set_result = bool(match(set_pattern, _observations,
                            stix_version=_stix_version))
    expanded_result = bool(match(expanded_pattern, _observations,
                                 stix_version=_stix_version))
    assert set_result == expanded_result
