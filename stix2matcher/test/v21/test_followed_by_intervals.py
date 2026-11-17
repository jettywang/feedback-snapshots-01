import itertools

import pytest
from stix2patterns.v21.pattern import Pattern as Pattern21

from stix2matcher.matcher import MatchListener, _intervals_follow, match

_stix_version = '2.1'


def _timestamp(second):
    return "2020-01-01T00:00:{:02d}Z".format(second)


def _observed_data(name, first, last, number_observed=1):
    key = "obs-" + name
    return {
        "type": "bundle",
        "id": "bundle--" + name + "-bundle",
        "objects": [
            {
                "id": "observed-data--" + key,
                "type": "observed-data",
                "spec_version": "2.1",
                "number_observed": number_observed,
                "first_observed": _timestamp(first),
                "last_observed": _timestamp(last),
                "object_refs": ["person--" + key],
            },
            {
                "id": "person--" + key,
                "type": "person",
                "name": name,
            },
        ],
    }


def _observations(*rows, **kwargs):
    return [_observed_data(*row, **kwargs) for row in rows]


def _binding_names(observations, pattern):
    matcher = MatchListener(observations, stix_version=_stix_version)
    Pattern21(pattern).walk(matcher)
    names = []
    for binding in matcher.matched():
        binding_names = []
        for sdo in matcher.get_sdos_from_binding(binding):
            binding_names.extend(
                obj["name"]
                for obj in sdo["objects"]
                if obj["type"] == "person"
            )
        names.append(tuple(sorted(binding_names)))
    return sorted(names)


def _satisfiable(lhs_intervals, rhs_intervals):
    """
    Independent exhaustive model of the STIX interval rule.

    Each observed-data interval [first_observed, last_observed] denotes all
    timestamps at which its observations may have occurred.  FOLLOWEDBY is
    satisfiable exactly when some choice of a timestamp from every LHS
    interval and every RHS interval makes every LHS timestamp <= every RHS
    timestamp.  Endpoints are inclusive, so touching intervals are valid in
    both directions.  An empty binding has no observation and cannot satisfy
    the relation.
    """
    if not lhs_intervals or not rhs_intervals:
        return False

    for lhs_choice in itertools.product(
            *(range(first, last + 1) for first, last in lhs_intervals)):
        for rhs_choice in itertools.product(
                *(range(first, last + 1) for first, last in rhs_intervals)):
            if all(lhs <= rhs for lhs in lhs_choice for rhs in rhs_choice):
                return True
    return False


_INTERVALS = [
    (first, last)
    for first in range(5)
    for last in range(first, 5)
]


@pytest.mark.parametrize("lhs_intervals", [
    (),
    [(0, 0)],
    [(0, 4), (1, 2)],
])
@pytest.mark.parametrize("rhs_intervals", [
    (),
    [(0, 0)],
    [(1, 3), (2, 4)],
])
def test_intervals_follow_matches_exhaustive_model(lhs_intervals, rhs_intervals):
    assert _intervals_follow(lhs_intervals, rhs_intervals) == \
        _satisfiable(lhs_intervals, rhs_intervals)


def test_intervals_follow_exhaustive_small_sets():
    for lhs_size in (1, 2):
        for rhs_size in (1, 2):
            for lhs in itertools.combinations_with_replacement(_INTERVALS, lhs_size):
                for rhs in itertools.combinations_with_replacement(_INTERVALS, rhs_size):
                    assert _intervals_follow(lhs, rhs) == _satisfiable(lhs, rhs)


@pytest.mark.parametrize("lhs_interval,rhs_interval,expected", [
    # Overlapping: a timestamp can be chosen in the intersection.
    ((0, 10), (5, 15), True),
    ((5, 15), (0, 10), True),
    ((0, 10), (0, 10), True),
    # Touching at one endpoint: the shared instant is legal for both sides.
    ((0, 10), (10, 20), True),
    ((10, 20), (0, 10), True),
    ((10, 10), (10, 10), True),
    # Zero-length interval inside a longer one.
    ((0, 20), (10, 10), True),
    ((10, 10), (0, 20), True),
    # Fully separated with a genuine gap.
    ((0, 5), (6, 10), True),
    ((6, 10), (0, 5), False),
    ((0, 0), (1, 1), True),
    ((1, 1), (0, 0), False),
])
def test_interval_boundaries(lhs_interval, rhs_interval, expected):
    assert _intervals_follow([lhs_interval], [rhs_interval]) is expected


@pytest.mark.parametrize("lhs_intervals,rhs_intervals,expected", [
    # The latest LHS first_observed must not exceed the earliest RHS
    # last_observed; only maxima and minima matter.
    ([(0, 2), (1, 3)], [(2, 4)], True),
    ([(0, 2), (1, 3)], [(1, 1)], True),
    ([(0, 2), (1, 3)], [(0, 0)], False),
    ([(0, 2), (1, 3)], [(3, 3)], True),
    ([(0, 1)], [(1, 2), (2, 3)], True),
    ([(1, 1)], [(0, 0), (2, 3)], False),
])
def test_compound_interval_bindings(lhs_intervals, rhs_intervals, expected):
    assert _intervals_follow(lhs_intervals, rhs_intervals) is expected


def test_overlap_allows_either_temporal_order():
    observations = _observations(("left", 0, 10), ("right", 5, 15))

    assert match(
        "[person:name='left'] FOLLOWEDBY [person:name='right']",
        observations,
        stix_version=_stix_version,
    )
    assert match(
        "[person:name='right'] FOLLOWEDBY [person:name='left']",
        observations,
        stix_version=_stix_version,
    )


def test_touching_intervals_are_ordered_at_the_shared_instant():
    observations = _observations(("left", 0, 10), ("right", 10, 20))

    assert match(
        "[person:name='left'] FOLLOWEDBY [person:name='right']",
        observations,
        stix_version=_stix_version,
    )
    assert match(
        "[person:name='right'] FOLLOWEDBY [person:name='left']",
        observations,
        stix_version=_stix_version,
    )


def test_separated_intervals_are_order_sensitive():
    observations = _observations(("left", 0, 10), ("right", 20, 30))

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


def test_compound_binding_uses_its_latest_first_observed():
    observations = _observations(
        ("early", 0, 2),
        ("expanding", 10, 11),
        ("rhs", 5, 5),
    )

    # The LHS binding contains both "early" and "expanding".  A comparison
    # using only the first list element (0) would accept this, but the compound
    # binding requires all LHS intervals to be at or before the RHS instant.
    # "expanding" starts at 10, after the RHS interval ends at 5.
    assert not match(
        "([person:name='early'] AND [person:name='expanding']) "
        "FOLLOWEDBY [person:name='rhs']",
        observations,
        stix_version=_stix_version,
    )


def test_compound_binding_uses_its_earliest_last_observed():
    observations = _observations(
        ("lhs", 3, 6),
        ("closing", 1, 2),
        ("shrinking", 7, 8),
    )

    # The RHS binding contains "closing" and "shrinking".  The earliest
    # last_observed is 2, so the LHS must start by 2.  Using only the last list
    # element (8) would wrongly accept the binding.
    assert not match(
        "[person:name='lhs'] FOLLOWEDBY "
        "([person:name='closing'] AND [person:name='shrinking'])",
        observations,
        stix_version=_stix_version,
    )


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
    early_then_late = _observations(("early", 0, 10), ("late", 20, 30))
    late_then_early = _observations(("late", 20, 30), ("early", 0, 10))
    pattern = "[person:name='early'] FOLLOWEDBY [person:name='late']"

    assert match(pattern, early_then_late, stix_version=_stix_version)
    assert match(pattern, late_then_early, stix_version=_stix_version)

    reversed_pattern = "[person:name='late'] FOLLOWEDBY [person:name='early']"

    assert not match(reversed_pattern, early_then_late, stix_version=_stix_version)
    assert not match(reversed_pattern, late_then_early, stix_version=_stix_version)


def test_list_order_alone_does_not_decide_match():
    # "later" appears first in the input list, but FOLLOWEDBY must use the
    # intervals.  A matcher which consumed list order would reject this.
    observations = _observations(("later", 20, 30), ("earlier", 0, 10))
    pattern = "[person:name='earlier'] FOLLOWEDBY [person:name='later']"

    names_by_index = {observation["objects"][1]["name"]: index
                      for index, observation in enumerate(observations)}
    list_order_matcher = (
        names_by_index["earlier"] < names_by_index["later"]
    )

    assert not list_order_matcher
    assert match(pattern, observations, stix_version=_stix_version)


def test_first_observed_alone_is_insufficient():
    # "span" starts before "point", so a first_observed-only comparison would
    # accept "span FOLLOWEDBY point" and reject "point FOLLOWEDBY span".
    # Since "span" lasts until 30, both orders are valid: "span" can choose a
    # timestamp at or after the point, and "point" can choose one at or before
    # the span's end.
    observations = _observations(("span", 0, 30), ("point", 10, 10))

    span = observations[0]["objects"][0]
    point = observations[1]["objects"][0]
    first_observed_matcher = span["first_observed"] <= point["first_observed"]

    assert first_observed_matcher
    assert match(
        "[person:name='point'] FOLLOWEDBY [person:name='span']",
        observations,
        stix_version=_stix_version,
    )
    assert match(
        "[person:name='span'] FOLLOWEDBY [person:name='point']",
        observations,
        stix_version=_stix_version,
    )


def test_last_observed_alone_is_insufficient():
    # Symmetrically, comparing only last_observed would reject
    # "span FOLLOWEDBY point": "span" ends after the point's instant, but it
    # can choose an earlier timestamp within [0, 30] which is <= 10.
    observations = _observations(("span", 0, 30), ("point", 10, 10))

    span = observations[0]["objects"][0]
    point = observations[1]["objects"][0]
    last_observed_matcher = span["last_observed"] <= point["last_observed"]

    assert not last_observed_matcher
    assert match(
        "[person:name='span'] FOLLOWEDBY [person:name='point']",
        observations,
        stix_version=_stix_version,
    )
