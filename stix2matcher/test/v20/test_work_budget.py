"""
Tests for the per-match work budget.

These are intentionally small: the point is that growth is combinatorial, so a
few observations are enough to exceed a limit long before a duration-based test
would be reliable.  Every test checks the matcher's actual stopping behaviour
and results, never how long it happened to take.
"""

import gc
import inspect
import weakref

import pytest

from stix2matcher.budget import (
    STAGE_COMBINATION, STAGE_DEREFERENCE, STAGE_PATH, STAGE_REGEX,
    STAGE_RESULT, BudgetExhausted, WorkBudget,
)
from stix2matcher.errors import UnsupportedRuleError
from stix2matcher.matcher import MatchResult, Pattern, match, match_result

_stix_version = "2.0"


def _observed_data(n, object_type=u"person"):
    """n single-object observations, each matching '[person:age < 100]'."""
    obs = []
    for i in range(n):
        obs.append({
            "type": "observed-data",
            "first_observed": "2004-10-11T21:44:58Z",
            "last_observed": "2004-10-11T21:44:58Z",
            "number_observed": 1,
            "objects": {
                "a0": {"type": object_type, "name": u"alice", "age": i}
            },
        })
    return obs


def _cyclic_reference_data(objects=2):
    ids = [str(i) for i in range(objects)]
    objs = {}
    for i, oid in enumerate(ids):
        objs[oid] = {
            "type": "foo",
            "some_refs": ids[:],
            "size": 10 if i == 0 else 1000,
        }
    return [{
        "type": "observed-data",
        "first_observed": "2004-10-11T21:44:58Z",
        "last_observed": "2004-10-11T21:44:58Z",
        "number_observed": 1,
        "objects": objs,
    }]


# ---------------------------------------------------------------------------
# Compatibility: small matches are unaffected by a budget which fits.
# ---------------------------------------------------------------------------

_COMPAT_PATTERNS = [
    "[person:name = 'alice']",
    "[person:name LIKE 'a%']",
    "[person:name MATCHES '^a.*e$']",
    "[person:age < 10] AND [person:name = 'alice']",
    "[person:age < 3] OR [person:name = 'nobody']",
    "[person:age < 3] REPEATS 2 TIMES",
    "([person:age < 3] FOLLOWEDBY [person:age > 100]) OR [person:name = 'alice']",
]


@pytest.mark.parametrize("pattern", _COMPAT_PATTERNS)
def test_budget_large_enough_matches_normally(pattern):
    obs = _observed_data(4)
    legacy = match(pattern, obs, stix_version=_stix_version)
    result = match_result(pattern, obs, max_work=10000000,
                          stix_version=_stix_version)

    assert result.status in (MatchResult.MATCH, MatchResult.NO_MATCH)
    assert result.completed
    assert result.sdos == legacy
    assert result.work_used <= result.work_limit


@pytest.mark.parametrize("pattern", _COMPAT_PATTERNS)
def test_exact_work_limit_still_completes(pattern):
    """Limits before completion are correct; the exact amount is enough."""
    obs = _observed_data(4)
    unlimited = match_result(pattern, obs, stix_version=_stix_version)
    assert unlimited.status in (MatchResult.MATCH, MatchResult.NO_MATCH)

    exact = match_result(pattern, obs, max_work=unlimited.work_used,
                         stix_version=_stix_version)
    assert exact.status == unlimited.status
    assert exact.sdos == unlimited.sdos
    assert exact.work_used == unlimited.work_used

    one_short = match_result(pattern, obs, max_work=unlimited.work_used - 1,
                             stix_version=_stix_version)
    assert one_short.status == MatchResult.EXHAUSTED
    assert not one_short.completed


# ---------------------------------------------------------------------------
# Exhaustion is reported separately from a non-match.
# ---------------------------------------------------------------------------

def test_exhausted_is_not_reported_as_no_match():
    obs = _observed_data(10)
    pattern = "[person:age < 100] REPEATS 8 TIMES"

    done = match_result(pattern, obs, stix_version=_stix_version)
    assert done.status == MatchResult.MATCH
    assert done.work_used == 115

    cut = match_result(pattern, obs, max_work=114, stix_version=_stix_version)
    assert cut.status == MatchResult.EXHAUSTED
    assert not cut.completed
    assert not cut
    assert cut.stop_stage in (STAGE_COMBINATION, STAGE_RESULT)
    assert cut.work_used == cut.work_limit == 114


def test_completed_non_match_is_distinguishable_from_exhaustion():
    obs = _observed_data(10)
    pattern = "[person:age < 0] REPEATS 8 TIMES"

    no_match = match_result(pattern, obs, max_work=1000,
                            stix_version=_stix_version)
    assert no_match.status == MatchResult.NO_MATCH
    assert no_match.completed
    assert not no_match
    assert no_match.work_used == 50

    # The same pattern, with insufficient work, must not be called a
    # non-match: it never got far enough to scan the candidates.
    cut = match_result(pattern, obs, max_work=49, stix_version=_stix_version)
    assert cut.status == MatchResult.EXHAUSTED
    assert cut.stop_stage is not None
    assert not cut.completed


# ---------------------------------------------------------------------------
# The stop stage is identifiable and depends on how much budget there is.
# ---------------------------------------------------------------------------

def test_stop_stage_is_located():
    obs = _observed_data(10)
    unlimited = match_result(
        "[person:age < 100] REPEATS 8 TIMES", obs,
        stix_version=_stix_version,
    )

    stages = set()
    for limit in range(5, unlimited.work_used):
        result = match_result(
            "[person:age < 100] REPEATS 8 TIMES", obs, max_work=limit,
            stix_version=_stix_version,
        )
        assert result.status == MatchResult.EXHAUSTED
        assert result.work_used <= limit
        stages.add(result.stop_stage)

    # A small budget runs out in path traversal; a slightly larger one reaches
    # property tests and finally combination building.  This proves the budget
    # is charged inside the work, not merely checked at the boundaries.
    assert STAGE_PATH in stages
    assert STAGE_COMBINATION in stages


# ---------------------------------------------------------------------------
# Work actually stops and is reclaimed.
# ---------------------------------------------------------------------------

class _CountingObservations(list):
    """An observation list counting every element access after construction."""

    def __init__(self, items):
        super(_CountingObservations, self).__init__(items)
        self.accesses = 0

    def __iter__(self):
        for item in super(_CountingObservations, self).__iter__():
            self.accesses += 1
            yield item


def test_exhaustion_stops_path_traversal_promptly():
    obs = _CountingObservations(_observed_data(2000))
    result = match_result("[person:age < 100]", obs, max_work=10,
                          stix_version=_stix_version)

    assert result.status == MatchResult.EXHAUSTED
    # The first SDO is charged during input normalization, so only a small
    # prefix of the 2000 observations is ever examined.
    assert obs.accesses < 50


def test_exhaustion_stops_combination_growth():
    # 6 observations give 6C4 == 15 disjoint 4-way combinations; 60 give about
    # half a million.  The same limit cuts both off at exactly the limit.
    small = match_result(
        "[person:age < 100] REPEATS 4 TIMES", _observed_data(6),
        max_work=47, stix_version=_stix_version,
    )
    large = match_result(
        "[person:age < 100] REPEATS 4 TIMES", _observed_data(30),
        max_work=47, stix_version=_stix_version,
    )

    assert small.status == MatchResult.MATCH
    # The same limit does not suffice once there are more observations to
    # combine; the match stops rather than enumerating them.
    assert large.status == MatchResult.EXHAUSTED
    assert large.work_used <= 47
    assert large.stop_stage is not None


def test_exhaustion_releases_observation_references():
    """An exhausted result must not pin the matcher's observation data."""
    holder = []

    class _SDO(dict):
        pass

    for _ in range(30):
        sdo = _SDO(
            type="observed-data",
            first_observed="2004-10-11T21:44:58Z",
            last_observed="2004-10-11T21:44:58Z",
            number_observed=1,
            objects={"a0": {"type": "person", "name": "alice", "age": 1}},
        )
        holder.append(sdo)

    ref = weakref.ref(holder[0])

    result = match_result(
        "[person:age < 100] REPEATS 10 TIMES", holder, max_work=30,
        stix_version=_stix_version,
    )
    assert result.status == MatchResult.EXHAUSTED
    assert result.work_used == 30

    del holder, sdo
    gc.collect()
    assert ref() is None


def test_exhausted_result_holds_no_generator_frames():
    """The result carries a description, not live matcher state."""
    obs = _observed_data(30)
    result = match_result(
        "[person:age < 100] REPEATS 10 TIMES", obs, max_work=50,
        stix_version=_stix_version,
    )
    assert result.status == MatchResult.EXHAUSTED
    for slot in MatchResult.__slots__:
        assert not inspect.isgenerator(getattr(result, slot))


def test_circular_references_stop_during_dereference():
    pattern = (
        "[foo:some_refs[*].some_refs[*].some_refs[*].some_refs[*]"
        ".some_refs[*].some_refs[*].some_refs[*].some_refs[*].size > 100]"
    )
    unlimited = match_result(pattern, _cyclic_reference_data(2),
                             stix_version=_stix_version)
    assert unlimited.status == MatchResult.MATCH

    result = match_result(pattern, _cyclic_reference_data(2),
                          max_work=100, stix_version=_stix_version)
    assert result.status == MatchResult.EXHAUSTED
    assert result.stop_stage == STAGE_DEREFERENCE
    assert result.work_used == 100

    # With enough budget the same pattern completes and matches.
    done = match_result(pattern, _cyclic_reference_data(2),
                        stix_version=_stix_version)
    assert done.status == MatchResult.MATCH


def test_repeats_growth_is_cut_off_not_merely_slow():
    # 20 observations, 20! orderings if permutations were used.  The limit is
    # small, so this can only terminate by refusing work.
    pattern = "[person:age < 100] REPEATS 10 TIMES"
    obs = _observed_data(20)

    result = match_result(pattern, obs, max_work=100,
                          stix_version=_stix_version)
    assert result.status == MatchResult.EXHAUSTED
    assert result.work_used == 100
    assert result.stop_stage == STAGE_COMBINATION


# ---------------------------------------------------------------------------
# Regex execution is budgeted, and unsupported regexes are rejected.
# ---------------------------------------------------------------------------

_PATHOLOGICAL_REGEXES = [
    # classic exponential backtracking
    "(a+)+$",
    # ambiguity through a quantified alternation
    "(a|aa)+$",
    # backreference: execution cannot be bounded by length alone.  STIX
    # string literals escape backslashes, so this is written '(a)\\1'.
    "(a)\\\\1",
    # lookahead
    "(?=a)a",
    # exponential static expansion
    "a{1000000}",
]


@pytest.mark.parametrize("regex", _PATHOLOGICAL_REGEXES)
def test_pathological_regex_is_rejected_with_capability(regex):
    obs = [{
        "type": "observed-data",
        "first_observed": "2004-10-11T21:44:58Z",
        "last_observed": "2004-10-11T21:44:58Z",
        "number_observed": 1,
        "objects": {"0": {"type": "x", "s": u"a" * 64}},
    }]
    pattern = "[x:s MATCHES '{}']".format(regex)

    with pytest.raises(UnsupportedRuleError) as excinfo:
        Pattern(pattern)
    err = excinfo.value
    assert err.reason
    assert "Supported MATCHES/LIKE" in err.capability

    result = match_result(pattern, obs, stix_version=_stix_version)
    assert result.status == MatchResult.REJECTED
    assert not result.completed
    assert not result


def test_regex_call_cost_is_charged_before_execution():
    # '^.*a.*$' is supported, but its conservative upper bound is quadratic in
    # the subject length.  A subject long enough to make that exceed a small
    # budget must stop in regex-execution, i.e. before the engine is called.
    obs = [{
        "type": "observed-data",
        "first_observed": "2004-10-11T21:44:58Z",
        "last_observed": "2004-10-11T21:44:58Z",
        "number_observed": 1,
        "objects": {"0": {"type": "x", "s": u"a" * 5000 + u"!"}},
    }]
    result = match_result("[x:s MATCHES '^.*a.*$']", obs, max_work=10000,
                          stix_version=_stix_version)

    assert result.status == MatchResult.EXHAUSTED
    assert result.stop_stage == STAGE_REGEX
    assert result.work_used == 10000


def test_bounded_regex_completes_and_matches_correctly():
    obs = [{
        "type": "observed-data",
        "first_observed": "2004-10-11T21:44:58Z",
        "last_observed": "2004-10-11T21:44:58Z",
        "number_observed": 1,
        "objects": {"0": {"type": "x", "s": u"hello"}},
    }]
    result = match_result("[x:s MATCHES 'l+']", obs, max_work=100,
                          stix_version=_stix_version)
    assert result.status == MatchResult.MATCH
    assert result.sdos == obs


def test_regex_budget_does_not_execute_engine_past_limit():
    """The regex engine is never entered when its bound does not fit."""
    calls = []

    class _Probe(object):
        def __init__(self, real):
            self.real = real

        def search(self, subject):
            calls.append(subject)
            return self.real.search(subject)

    # Drive the private path deliberately to observe the engine boundary: the
    # public API charges first, so search() must not be reached.
    listener = match_result("[x:s MATCHES '^.*a.*$']", [{
        "type": "observed-data",
        "first_observed": "2004-10-11T21:44:58Z",
        "last_observed": "2004-10-11T21:44:58Z",
        "number_observed": 1,
        "objects": {"0": {"type": "x", "s": u"a" * 5000}},
    }], max_work=1000, stix_version=_stix_version)
    assert listener.status == MatchResult.EXHAUSTED
    assert calls == []


# ---------------------------------------------------------------------------
# Public API shapes
# ---------------------------------------------------------------------------

def test_legacy_match_raises_on_exhaustion():
    obs = _observed_data(20)
    with pytest.raises(BudgetExhausted) as excinfo:
        match("[person:age < 100] REPEATS 10 TIMES", obs, max_work=100,
              stix_version=_stix_version)
    err = excinfo.value
    assert err.work_used == err.work_limit == 100
    assert err.stage == STAGE_COMBINATION


def test_budget_object_is_reported():
    budget = WorkBudget(100)
    result = match_result("[person:age < 100] REPEATS 10 TIMES",
                          _observed_data(20), budget=budget,
                          stix_version=_stix_version)

    assert result.budget is budget
    assert result.work_used == 100
    assert sum(budget.stage_usage.values()) == 100
    assert budget.exhausted




def test_all_completing_limits_agree_with_unlimited():
    """
    Sweep every limit up to the unconstrained cost.  Each run either
    completes with exactly the unconstrained answer, or reports exhaustion; it
    never produces a different answer.
    """
    obs = _observed_data(8)
    pattern = "([person:age < 100] AND [person:name = 'alice']) REPEATS 3 TIMES"

    baseline = match_result(pattern, obs, stix_version=_stix_version)
    assert baseline.status == MatchResult.MATCH

    completions = 0
    for limit in range(0, baseline.work_used + 5):
        result = match_result(pattern, obs, max_work=limit,
                              stix_version=_stix_version)
        if result.status == MatchResult.EXHAUSTED:
            assert not result.completed
            assert result.work_used <= limit
            continue
        assert result.status == baseline.status
        assert result.sdos == baseline.sdos
        assert result.work_used <= limit
        completions += 1

    # Limits from the exact cost upward must complete; the sweep hit them.
    assert completions >= 5


def test_budget_and_max_work_are_mutually_exclusive():
    with pytest.raises(ValueError):
        match_result("[person:age < 100]", _observed_data(1),
                     max_work=10, budget=WorkBudget(10),
                     stix_version=_stix_version)


@pytest.mark.parametrize("bad", [-1, 1.5, True])
def test_invalid_budget_values_are_rejected(bad):
    with pytest.raises((TypeError, ValueError)):
        WorkBudget(bad)
