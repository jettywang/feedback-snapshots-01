"""
Tests for lazy handling of ``number_observed`` instance expansion.

An observed-data SDO with ``number_observed == N`` represents N distinct,
non-reusable observation instances.  The matcher must not enumerate all N
instances (or all combinations of them) merely to decide a REPEATS match, but
it must still enforce that repeated branches consume distinct instances.
"""
import itertools
import tracemalloc

import pytest

from stix2matcher.matcher import (
    MatcherException,
    Pattern,
    _Binding,
    match,
)

_stix_version = '2.0'
_TIME = "2004-10-11T21:44:58Z"


def _obs(number_observed, age=10, name=u"alice", first=_TIME, last=_TIME):
    return {
        "type": "observed-data",
        "first_observed": first,
        "last_observed": last,
        "number_observed": number_observed,
        "objects": {"a0": {"type": u"person", "name": name, "age": age}},
    }


def _bindings(pattern, observations):
    """Return the distinct consumed-count vectors for all matcher bindings."""
    compiled = Pattern(pattern)
    listener = compiled._Pattern__pattern
    from stix2matcher.matcher import MatchListener
    match_listener = MatchListener(observations)
    listener.walk(match_listener)
    return {
        tuple(sorted(dict(binding.counts).items()))
        for binding in match_listener.matched_bindings()
    }


def _brute_instances(observations):
    return [
        (obs_idx, inst_idx)
        for obs_idx, obs in enumerate(observations)
        for inst_idx in range(obs["number_observed"])
    ]


def _brute_counts(bindings):
    counts = {}
    for instance in bindings:
        counts[instance[0]] = counts.get(instance[0], 0) + 1
    return tuple(sorted(counts.items()))


def _brute_repeat(observations, predicate, rep_count):
    """Exhaustively enumerate REPEATS by expanding every virtual instance."""
    matching = [
        inst for inst in _brute_instances(observations)
        if predicate(observations[inst[0]]["objects"]["a0"])
    ]
    result = set()
    for combo in itertools.combinations(matching, rep_count):
        result.add(_brute_counts(combo))
    return result


def _brute_and(observations, left, right):
    left_insts = [
        inst for inst in _brute_instances(observations)
        if left(observations[inst[0]]["objects"]["a0"])
    ]
    right_insts = [
        inst for inst in _brute_instances(observations)
        if right(observations[inst[0]]["objects"]["a0"])
    ]
    result = set()
    for lhs in left_insts:
        for rhs in right_insts:
            if lhs != rhs:
                result.add(_brute_counts([lhs, rhs]))
    return result


def _age_below(limit):
    return lambda obj: obj["age"] < limit


@pytest.mark.parametrize("rep_count", [1, 2, 3, 4])
@pytest.mark.parametrize("counts", [
    (1,),
    (2,),
    (5,),
    (1, 1),
    (1, 2),
    (2, 3),
    (3, 3),
    (4, 1, 2),
])
def test_repeats_matches_brute_force(rep_count, counts):
    """Small counts are compared item-by-item against an exhaustive oracle."""
    observations = [
        _obs(n, age=10 if idx % 2 == 0 else 22)
        for idx, n in enumerate(counts)
    ]
    pattern = u"[person:age < 20] REPEATS {} TIMES".format(rep_count)

    expected = _brute_repeat(observations, _age_below(20), rep_count)
    assert _bindings(pattern, observations) == expected


@pytest.mark.parametrize("counts", [(1, 1), (1, 2), (2, 3), (3, 3), (2, 1, 2)])
def test_and_matches_brute_force(counts):
    """Concurrent AND branches must not share virtual instances."""
    observations = [
        _obs(n, age=10 + 5 * idx) for idx, n in enumerate(counts)
    ]
    pattern = u"[person:age < 20] AND [person:age < 25]"

    expected = _brute_and(observations, _age_below(20), _age_below(25))
    assert _bindings(pattern, observations) == expected


def test_repeats_never_reuses_one_instance():
    """A single virtual instance cannot satisfy REPEATS 2."""
    observations = [_obs(1)]
    assert not match(u"[person:age < 20] REPEATS 2 TIMES", observations)
    assert match(u"[person:age < 20] REPEATS 1 TIMES", observations)


def test_branch_contention_same_observation():
    """
    Regression: left and right AND branches compete for one SDO's instances.

    With number_observed == 1 there is exactly one virtual instance.  Both
    branches match its object, but they must not both consume it.  A naive
    "count := multiplication" optimization would report a false match here.
    """
    observations = [_obs(1, age=10)]
    pattern = u"[person:age < 20] AND [person:age < 30]"
    assert not match(pattern, observations)

    # With a second virtual instance, the same pattern genuinely matches.
    assert match(pattern, [_obs(2, age=10)])


def test_branch_contention_with_repeats():
    """Both sides of an OR-of-REPEATS draw from the same instance pool."""
    observations = [_obs(2, age=10)]
    # Each side alone needs 2 instances: satisfies the OR.
    assert match(
        u"[person:age < 20] REPEATS 2 TIMES OR [person:age < 30] REPEATS 2 TIMES",
        observations,
    )
    # 3 instances per side cannot fit in a pool of 2.
    assert not match(
        u"[person:age < 20] REPEATS 3 TIMES OR [person:age < 30] REPEATS 3 TIMES",
        observations,
    )


def test_repeat_beyond_capacity_is_not_fabricated():
    observations = [_obs(3, age=10), _obs(2, age=10)]
    assert match(u"[person:age < 20] REPEATS 5 TIMES", observations)
    assert not match(u"[person:age < 20] REPEATS 6 TIMES", observations)


def test_shared_pool_multiplication_counterexample():
    """
    Regression: a naive "count x repeat" optimization reports a false match.

    Two observations offer 3 and 2 instances respectively (5 total).  REPEATS 5
    is satisfiable, but REPEATS 6 is not: the pool cannot be multiplied, and the
    two observations' pools cannot be treated as one reusable supply.  A naive
    optimization which multiplies a count by the repeat factor, or which merges
    both observations into an unbounded pool, accepts REPEATS 6 here.
    """
    observations = [_obs(3, age=10), _obs(2, age=10)]
    assert match(u"[person:age < 20] REPEATS 5 TIMES", observations)
    assert not match(u"[person:age < 20] REPEATS 6 TIMES", observations)


def test_branch_contention_counterexample_documented():
    """
    Regression: left and right branches contending for one shared instance.

    One observation has number_observed == 1, so exactly one virtual instance
    exists.  The left branch ``[person:age < 20]`` and the right branch
    ``[person:age < 30]`` both match it.  Because instances are non-reusable,
    AND cannot consume that single instance twice: the correct answer is no
    match.  An optimization which simply adds the two branch counts (or treats
    the count as shared without a capacity check) fabricates a match.
    """
    assert not match(
        u"[person:age < 20] AND [person:age < 30]", [_obs(1, age=10)])

    # The mirrored OR case may use the single instance on either side.
    assert match(
        u"[person:age < 20] OR [person:age < 30]", [_obs(1, age=10)])


def test_repeated_temporal_qualifier():
    observations = [
        _obs(4, age=10, first="2004-10-11T21:44:58Z",
             last="2004-10-11T21:44:58Z"),
    ]
    assert match(
        u"[person:age < 20] REPEATS 4 TIMES WITHIN 1 SECONDS", observations)
    assert not match(
        u"[person:age < 20] REPEATS 5 TIMES WITHIN 1 SECONDS", observations)


@pytest.mark.parametrize("number_observed", [0, -1, -100])
def test_invalid_small_number_observed_rejected(number_observed):
    with pytest.raises(MatcherException):
        match(u"[person:age < 20]", [_obs(number_observed)])


@pytest.mark.parametrize("number_observed", [1.5, 2.0, True, "3", None])
def test_invalid_typed_number_observed_rejected(number_observed):
    with pytest.raises(MatcherException):
        match(u"[person:age < 20] REPEATS 2 TIMES", [_obs(number_observed)])


def test_error_detected_before_expansion():
    """
    Invalid input must be rejected without enumerating instances.

    A huge number_observed on a later SDO would blow up an eager expansion; the
    invalid value on an earlier SDO must be reported first.
    """
    observations = [_obs(-1), _obs(10 ** 12)]
    with pytest.raises(MatcherException):
        match(u"[person:age < 20] REPEATS 2 TIMES", observations)


HUGE = 10 ** 15


@pytest.mark.parametrize("rep_count", [1, 2, 3, 10, 1000, 10 ** 9])
def test_large_count_work_is_independent_of_number_observed(rep_count):
    """
    Large counts: peak memory and time must not scale with number_observed.

    The same pattern is run against a small and a huge virtual instance count;
    neither the peak allocation nor the work may grow proportionally to the
    huge count.
    """
    pattern = u"[person:age < 20] REPEATS {} TIMES".format(rep_count)

    def measure(count):
        observations = [_obs(count)]
        tracemalloc.start()
        try:
            result = bool(match(pattern, observations))
        finally:
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        return result, peak

    small_result, small_peak = measure(rep_count)
    huge_result, huge_peak = measure(HUGE)

    assert small_result is True
    assert huge_result is True

    # Peak memory should be essentially the same; allow a small constant
    # overhead but certainly not growth proportional to 10**15.
    assert huge_peak < small_peak + 5 * 1024 * 1024


def test_large_count_repeat_never_reuses_instances():
    """Capacity is still respected, even at large values."""
    huge = 10 ** 12
    assert match(u"[person:age < 20] REPEATS {} TIMES".format(huge), [_obs(huge)])
    assert not match(
        u"[person:age < 20] REPEATS {} TIMES".format(huge + 1), [_obs(huge)])


def test_consumed_counts_are_recoverable():
    """The result can restore which observations and how many were consumed."""
    observations = [_obs(4, age=10), _obs(3, age=17), _obs(1, age=30)]
    compiled = Pattern(u"[person:age < 20] REPEATS 5 TIMES")
    from stix2matcher.matcher import MatchListener
    listener = MatchListener(observations)
    compiled._Pattern__pattern.walk(listener)

    bindings = list(listener.matched_bindings())
    assert bindings
    binding = bindings[0]
    assert isinstance(binding, _Binding)
    # Consumed instances are exactly the 4 + 1 needed from the two under-20
    # observations; the third observation is not consumed.
    assert dict(binding.counts) == {0: 4, 1: 1}

    sdos = listener.get_sdos_from_binding(binding)
    assert len(sdos) == 2


def test_matched_public_bindings_preserve_historical_format():
    """matched() still yields observation indices and None placeholders."""
    observations = [_obs(3, age=10)]
    compiled = Pattern(u"[person:age < 20] REPEATS 3 TIMES")
    from stix2matcher.matcher import MatchListener
    listener = MatchListener(observations)
    compiled._Pattern__pattern.walk(listener)

    bindings = list(listener.matched())
    assert bindings == [(0, None, None)]
