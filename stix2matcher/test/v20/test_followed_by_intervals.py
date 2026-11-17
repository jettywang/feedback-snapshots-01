import itertools

import pytest
from stix2patterns.v20.pattern import Pattern as Pattern20

from stix2matcher.matcher import MatchListener, match

_stix_version = '2.0'


def _timestamp(second):
    return "2020-01-01T00:00:{:02d}Z".format(second)


def _observed_data(name, first, last, number_observed=1):
    return {
        "type": "observed-data",
        "first_observed": _timestamp(first),
        "last_observed": _timestamp(last),
        "number_observed": number_observed,
        "objects": {
            "0": {
                "type": "person",
                "name": name,
            }
        },
    }


def _observations(*rows, **kwargs):
    return [_observed_data(*row, **kwargs) for row in rows]


def _binding_names(observations, pattern):
    matcher = MatchListener(observations, stix_version=_stix_version)
    Pattern20(pattern).walk(matcher)
    names = []
    for binding in matcher.matched():
        binding_names = []
        for sdo in matcher.get_sdos_from_binding(binding):
            binding_names.extend(
                obj["name"]
                for obj in sdo["objects"].values()
                if obj["type"] == "person"
            )
        names.append(tuple(sorted(binding_names)))
    return sorted(names)


def test_interval_boundaries():
    observations = _observations(
        ("left", 0, 10),
        ("touching", 10, 20),
        ("right", 21, 30),
    )

    assert match(
        "[person:name='left'] FOLLOWEDBY [person:name='touching']",
        observations,
        stix_version=_stix_version,
    )
    assert match(
        "[person:name='touching'] FOLLOWEDBY [person:name='left']",
        observations,
        stix_version=_stix_version,
    )
    assert match(
        "[person:name='left'] FOLLOWEDBY [person:name='right']",
        observations,
        stix_version=_stix_version,
    )
    assert not match(
        "[person:name='right'] FOLLOWEDBY [person:name='left']",
        observations,
        stix_version=_stix_version,
    )


@pytest.mark.parametrize("pattern,expected", [
    ("([person:name='a'] AND [person:name='b']) FOLLOWEDBY [person:name='c']",
     [("a", "b", "c")]),
    ("[person:name='a'] FOLLOWEDBY ([person:name='c'] AND [person:name='d'])",
     [("a", "c", "d")]),
    ("([person:name='a'] AND [person:name='b']) "
     "FOLLOWEDBY ([person:name='c'] OR [person:name='d'])",
     [("a", "b", "c"), ("a", "b", "d")]),
    ("([person:name='a'] OR [person:name='b']) "
     "FOLLOWEDBY ([person:name='c'] AND [person:name='d'])",
     [("a", "c", "d"), ("b", "c", "d")]),
])
def test_compound_and_or_bindings(pattern, expected):
    observations = _observations(
        ("a", 0, 2),
        ("b", 1, 3),
        ("c", 4, 5),
        ("d", 5, 6),
    )
    assert _binding_names(observations, pattern) == expected


def test_observation_instance_cannot_be_reused_across_both_sides():
    single_observation = _observations(("a", 0, 10), number_observed=1)

    assert not match(
        "[person:name='a'] FOLLOWEDBY [person:name='a']",
        single_observation,
        stix_version=_stix_version,
    )

    two_instances = _observations(("a", 0, 10), number_observed=2)

    assert match(
        "[person:name='a'] FOLLOWEDBY [person:name='a']",
        two_instances,
        stix_version=_stix_version,
    )


def test_input_permutations_preserve_binding_set():
    observations = _observations(
        ("left", 0, 2),
        ("other_left", 1, 3),
        ("right", 4, 5),
        ("other_right", 5, 6),
    )
    pattern = ("([person:name='left'] OR [person:name='other_left']) "
               "FOLLOWEDBY "
               "([person:name='right'] OR [person:name='other_right'])")
    expected = _binding_names(observations, pattern)

    assert expected == [
        ("left", "other_right"),
        ("left", "right"),
        ("other_left", "other_right"),
        ("other_left", "right"),
    ]
    for permutation in itertools.permutations(observations):
        assert _binding_names(list(permutation), pattern) == expected


def test_reversing_temporal_order_changes_result():
    observations = _observations(("early", 0, 10), ("late", 20, 30))

    assert match(
        "[person:name='early'] FOLLOWEDBY [person:name='late']",
        observations,
        stix_version=_stix_version,
    )
    assert not match(
        "[person:name='late'] FOLLOWEDBY [person:name='early']",
        observations,
        stix_version=_stix_version,
    )
