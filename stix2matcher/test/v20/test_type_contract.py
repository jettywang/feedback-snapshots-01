"""
v2.0 counterpart of test_type_contract.py: a single spec-aware equality
contract shared by (=, !=) and (IN, NOT IN), so Python's True == 1 can never
change a matching result.  See the v2.1 module for the full rationale.
"""
import pytest

from stix2matcher.matcher import match

_stix_version = '2.0'

# A single observed-data SDO holding several Cyber Observable objects of
# distinct types.  "vals" lists are reached through a wildcard ([*]) step.
_observations = [
    {
        "type": "observed-data",
        "number_observed": 1,
        "first_observed": "2020-01-01T00:00:00Z",
        "last_observed": "2020-01-01T00:00:00Z",
        "objects": {
            "0": {
                "type": "tcbool",
                "flag": True,
                "vals": [True, False],
            },
            "1": {
                "type": "tcint",
                "flag": 1,
                "vals": [1, 2],
            },
            "2": {
                "type": "tcfloat",
                "flag": 1.0,
                "vals": [1.0, 2.5],
            },
            "3": {
                "type": "tcstr",
                "flag": "1",
                "vals": ["1", "two"],
                "note": None,
            },
            "4": {
                "type": "tcbin",
                "blob": b"abc",
            },
        },
    }
]


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
    ("[tcint:vals[*] NOT IN (1, 7)]", True),

    # --- string/number and string/bool are non-interoperable ---
    ("[tcstr:flag = 1]", False),
    ("[tcstr:flag != 1]", True),
    ("[tcstr:flag IN (1, 2)]", False),
    ("[tcstr:flag NOT IN (1, 2)]", True),
    ("[tcstr:vals[*] IN ('one', 'two')]", True),
    ("[tcstr:vals[*] IN (1, 2)]", False),

    # --- explicit null ---
    ("[tcstr:note = 'x']", False),
    ("[tcstr:note IN ('x', 'y')]", False),
    ("[tcstr:note NOT IN ('x', 'y')]", True),

    # --- missing property: path selects nothing ---
    ("[tcstr:missing = 'x']", False),
    ("[tcstr:missing != 'x']", False),
    ("[tcstr:missing IN ('x', 'y')]", False),
    ("[tcstr:missing NOT IN ('x', 'y')]", False),

    # --- binary/string interop preserved (all codepoints < 256) ---
    ("[tcbin:blob = b'YWJj']", True),
    ("[tcbin:blob = 'abc']", True),
    ("[tcbin:blob IN (b'YWJj', b'emQ=')]", True),
    ("[tcbin:blob IN ('abc', 'zd')]", True),
    ("[tcbin:blob NOT IN ('abc', 'zd')]", False),
    ("[tcbin:blob IN (1, 2)]", False),
    ("[tcbin:blob NOT IN (1, 2)]", True),
]


@pytest.mark.parametrize("pattern, expected", _MATRIX)
def test_type_contract_matrix(pattern, expected):
    assert bool(match(pattern, _observations, stix_version=_stix_version)) \
        is expected


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
