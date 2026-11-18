# Regression tests for the scope and time-boundary behavior of nested
# WITHIN and START/STOP qualifiers.
#
# The tests compare the matcher against an independent semantic model.  The
# model gives every bound observation its own timestamp, chosen from that
# observation's first_observed/last_observed interval, and then requires a
# single assignment to satisfy every qualifier in the pattern tree as the
# grammar scopes it.  The model's feasibility check is a difference-constraint
# solver written here, not the matcher's helpers.
#
# This distinguishes the two failure modes the regression must report:
#
#   scope failure     the qualifier is attached to a different subexpression
#                     than the grammar specifies (e.g. the whole AND instead
#                     of one operand, or vice versa);
#   boundary failure  the scope is right but a window endpoint, duration, or
#                     timestamp representation is compared incorrectly.

import datetime
import itertools
import random
import re

import dateutil.tz
import pytest

from stix2matcher.matcher import match

_stix_version = '2.1'

_US = datetime.timedelta(microseconds=1)
_EPOCH = datetime.datetime(2020, 1, 1, tzinfo=dateutil.tz.tzutc())

_SECOND = 1000000
_DAY = 24 * 3600 * _SECOND


# ---------------------------------------------------------------------------
# Pattern construction
# ---------------------------------------------------------------------------

class _Leaf:
    def __init__(self, name):
        self.name = name

    def pattern(self):
        return "[person:name='{}']".format(self.name)


class _And:
    def __init__(self, *children):
        self.children = children

    def pattern(self):
        return "(" + " AND ".join(c.pattern() for c in self.children) + ")"


class _Or:
    def __init__(self, *children):
        self.children = children

    def pattern(self):
        return "(" + " OR ".join(c.pattern() for c in self.children) + ")"


class _Within:
    def __init__(self, child, duration_us):
        self.child = child
        self.duration_us = duration_us

    def pattern(self):
        return "({}) WITHIN {} SECONDS".format(
            self.child.pattern(), _seconds(self.duration_us))


class _StartStop:
    def __init__(self, child, start_us, stop_us):
        self.child = child
        self.start_us = start_us
        self.stop_us = stop_us

    def pattern(self):
        return "({}) START t'{}' STOP t'{}'".format(
            self.child.pattern(), _iso(self.start_us), _iso(self.stop_us))


class _FollowedBy:
    def __init__(self, earlier, later):
        self.earlier = earlier
        self.later = later

    def pattern(self):
        # FOLLOWEDBY binds looser than OR/AND, so both operands must be
        # explicitly parenthesized or the printed pattern would mean a
        # different tree than this node represents.
        return "(({}) FOLLOWEDBY ({}))".format(
            self.earlier.pattern(), self.later.pattern())


def _seconds(duration_us):
    return "{:.6f}".format(duration_us / 1000000.0).rstrip('0').rstrip('.')


def _iso(offset_us):
    return (_EPOCH + offset_us * _US).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


# ---------------------------------------------------------------------------
# Observation construction
# ---------------------------------------------------------------------------

def _bundle(index, name, first_us, last_us):
    suffix = '{:012d}'.format(index)
    return {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-" + suffix,
        "objects": [
            {
                "id": "observed-data--00000000-0000-4000-8000-" + suffix,
                "type": "observed-data",
                "spec_version": "2.1",
                "number_observed": 1,
                "first_observed": _iso(first_us),
                "last_observed": _iso(last_us),
                "object_refs": [
                    "person--00000000-0000-4000-8000-" + suffix,
                ],
            },
            {
                "type": "person",
                "id": "person--00000000-0000-4000-8000-" + suffix,
                "name": name,
            },
        ],
    }


def _observations(intervals):
    items = intervals.items() if isinstance(intervals, dict) else intervals
    return [
        _bundle(i + 1, name, first_us, last_us)
        for i, (name, (first_us, last_us)) in enumerate(items)
    ]


# ---------------------------------------------------------------------------
# Independent model
# ---------------------------------------------------------------------------

class _Constraints:
    """A set of timestamp requirements over named observations.

    `bounds` maps a name to its allowed inclusive [low, high] microsecond
    range.  `groups` holds (names, duration) pairs meaning all those
    timestamps must fit in a window of that duration.  `orderings` holds
    (earlier_names, later_names) pairs meaning every earlier timestamp must
    be <= every later timestamp.
    """

    def __init__(self, bounds, groups, orderings):
        self.bounds = bounds
        self.groups = groups
        self.orderings = orderings

    def with_bounds(self, names, low, high):
        bounds = dict(self.bounds)
        for name in names:
            current_low, current_high = bounds[name]
            bounds[name] = (max(current_low, low), min(current_high, high))
        return _Constraints(bounds, self.groups, self.orderings)

    def with_group(self, names, duration_us):
        return _Constraints(
            self.bounds,
            self.groups + [(frozenset(names), duration_us)],
            self.orderings,
        )

    def with_ordering(self, earlier, later):
        return _Constraints(
            self.bounds,
            self.groups,
            self.orderings + [(frozenset(earlier), frozenset(later))],
        )

    def combine(self, other):
        bounds = dict(self.bounds)
        bounds.update(other.bounds)
        return _Constraints(
            bounds, self.groups + other.groups,
            self.orderings + other.orderings,
        )

    def feasible(self):
        """Exact satisfiability check for difference constraints.

        Variables are the observations plus a source node.  Bounds become
        unary constraints, groups become pairwise t_j - t_i <= duration, and
        orderings become t_early <= t_late.  Bellman-Ford reports a negative
        cycle exactly when no assignment exists.  All weights are integers,
        so a real solution implies an integer solution.
        """

        names = sorted(self.bounds)
        index = {name: i + 1 for i, name in enumerate(names)}
        size = len(names) + 1
        edges = []

        for name, (low, high) in self.bounds.items():
            if high < low:
                return False
            edges.append((0, index[name], high))
            edges.append((index[name], 0, -low))

        for group, duration_us in self.groups:
            members = [index[name] for name in group]
            for u in members:
                for v in members:
                    if u != v:
                        edges.append((u, v, duration_us))

        for earlier, later in self.orderings:
            for left in earlier:
                for right in later:
                    edges.append((index[right], index[left], 0))

        distance = [0] * size
        for _ in range(size):
            changed = False
            for u, v, weight in edges:
                candidate = distance[u] + weight
                if candidate < distance[v]:
                    distance[v] = candidate
                    changed = True
            if not changed:
                return True
        return False


def _alternatives(node, intervals):
    """Enumerate the ways `node` can bind observations, each as a
    (names, constraints) pair.  Infeasible alternatives are dropped.

    This mirrors the semantics, not the matcher: a qualifier governs exactly
    the observations bound beneath the node it is attached to, and OR
    produces bindings from one branch only (matching the matcher's documented
    one-sided pruning, which cannot introduce false negatives).
    """

    if isinstance(node, _Leaf):
        bounds = {node.name: intervals[node.name]}
        return [({node.name}, _Constraints(bounds, [], []))]

    if isinstance(node, _Or):
        result = []
        for child in node.children:
            result.extend(_alternatives(child, intervals))
        return result

    if isinstance(node, _And):
        combinations = [(set(), _Constraints({}, [], []))]
        for child in node.children:
            child_alts = _alternatives(child, intervals)
            next_combinations = []
            for names, constraints in combinations:
                for child_names, child_constraints in child_alts:
                    if names & child_names:
                        continue
                    next_combinations.append(
                        (names | child_names,
                         constraints.combine(child_constraints)))
            combinations = next_combinations
        return [(n, c) for n, c in combinations if c.feasible()]

    if isinstance(node, _Within):
        result = []
        for names, constraints in _alternatives(node.child, intervals):
            constrained = constraints.with_group(names, node.duration_us)
            if constrained.feasible():
                result.append((names, constrained))
        return result

    if isinstance(node, _StartStop):
        result = []
        for names, constraints in _alternatives(node.child, intervals):
            if node.start_us >= node.stop_us:
                continue
            constrained = constraints.with_bounds(
                names, node.start_us, node.stop_us - 1)
            if constrained.feasible():
                result.append((names, constrained))
        return result

    if isinstance(node, _FollowedBy):
        result = []
        left_alts = _alternatives(node.earlier, intervals)
        right_alts = _alternatives(node.later, intervals)
        for left_names, left in left_alts:
            for right_names, right in right_alts:
                if left_names & right_names:
                    continue
                combined = left.combine(right).with_ordering(
                    left_names, right_names)
                if combined.feasible():
                    result.append((left_names | right_names, combined))
        return result

    raise TypeError("unsupported node: {!r}".format(node))


def _model_matches(pattern_node, intervals):
    return bool(_alternatives(pattern_node, intervals))


def _check(pattern_node, intervals):
    """Assert the matcher agrees with the model and is order-independent.

    Returns the model's verdict so tests can also pin specific expectations.
    """

    expected = _model_matches(pattern_node, intervals)
    pattern = pattern_node.pattern()

    forward = bool(match(pattern, _observations(intervals),
                         stix_version=_stix_version))
    reversed_input = list(intervals.items())[::-1]
    backward = bool(match(pattern, _observations(reversed_input),
                          stix_version=_stix_version))

    assert forward == expected, (
        "{}: matcher={}, model={} (intervals={!r})".format(
            pattern, forward, expected, intervals))
    assert backward == expected, (
        "{}: verdict changed when bundles were reordered".format(pattern))
    return expected


# ---------------------------------------------------------------------------
# Scope: qualifiers bind where the grammar places them
# ---------------------------------------------------------------------------

def test_postfix_within_binds_only_its_own_operand():
    """`A AND B WITHIN n` is A AND (B WITHIN n); `(A AND B) WITHIN n` is not.

    The same observations are used for both spellings, so only the
    bracketing differs.  This is the canonical scope discrimination: the
    postfix qualifier must not leak onto the whole AND, and the parenthesized
    qualifier must not degrade into a per-leaf check.
    """

    intervals = {'a': (100 * _SECOND, 100 * _SECOND), 'b': (0, 0)}

    # Postfix WITHIN governs only 'b'; 'a' is unconstrained.
    postfix = _And(_Leaf('a'), _Within(_Leaf('b'), _SECOND))
    assert _check(postfix, intervals) is True

    # The same tokens with different parentheses govern both observations.
    grouped = _Within(_And(_Leaf('a'), _Leaf('b')), _SECOND)
    assert _check(grouped, intervals) is False


def test_postfix_within_on_left_operand_only():
    """`A WITHIN n AND B` is (A WITHIN n) AND B."""

    intervals = {'a': (0, 0), 'b': (100 * _SECOND, 100 * _SECOND)}

    postfix = _And(_Within(_Leaf('a'), _SECOND), _Leaf('b'))
    assert _check(postfix, intervals) is True

    grouped = _Within(_And(_Leaf('a'), _Leaf('b')), _SECOND)
    assert _check(grouped, intervals) is False


def test_start_stop_over_compound_constrains_every_member():
    """`(A AND B) START ... STOP ...` constrains both observations.

    'a' is inside the window while 'b' is far outside, so the compound must
    not match; a leaf-only implementation would accept.
    """

    intervals = {'a': (5 * _SECOND, 5 * _SECOND),
                 'b': (500 * _SECOND, 500 * _SECOND)}

    grouped = _StartStop(_And(_Leaf('a'), _Leaf('b')), 0, 10 * _SECOND)
    assert _check(grouped, intervals) is False

    # Postfix form moves the window onto 'b' only, and 'b' is outside it.
    postfix = _And(_Leaf('a'), _StartStop(_Leaf('b'), 0, 10 * _SECOND))
    assert _check(postfix, intervals) is False

    # Move 'b' inside, leave 'a' outside: only the postfix form matches.
    intervals = {'a': (500 * _SECOND, 500 * _SECOND),
                 'b': (5 * _SECOND, 5 * _SECOND)}
    assert _check(postfix, intervals) is True
    assert _check(grouped, intervals) is False


def test_start_stop_on_or_branch_binds_only_that_branch():
    """`A OR B START ... STOP ...` scopes the window to B only."""

    intervals = {'a': (500 * _SECOND, 500 * _SECOND),
                 'b': (500 * _SECOND, 500 * _SECOND)}

    postfix = _Or(_Leaf('a'), _StartStop(_Leaf('b'), 0, 10 * _SECOND))
    assert _check(postfix, intervals) is True

    grouped = _StartStop(_Or(_Leaf('a'), _Leaf('b')), 0, 10 * _SECOND)
    assert _check(grouped, intervals) is False


def test_nested_start_stop_windows_must_share_a_timestamp():
    """Two windows over one observation must intersect.

    'a' spans 0..100s; the inner window is 90..91s and the outer is 0..20s.
    Each overlaps the raw interval, but no single timestamp satisfies both.
    """

    intervals = {'a': (0, 100 * _SECOND)}
    node = _StartStop(
        _StartStop(_Leaf('a'), 90 * _SECOND, 91 * _SECOND),
        0, 20 * _SECOND)

    assert _check(node, intervals) is False

    # A compatible outer window keeps the same observation matching.
    compatible = _StartStop(
        _StartStop(_Leaf('a'), 90 * _SECOND, 91 * _SECOND),
        90 * _SECOND, 95 * _SECOND)
    assert _check(compatible, intervals) is True


def test_outer_within_respects_stop_exclusivity_of_inner_window():
    """An outer WITHIN must treat the inner STOP value as unusable.

    'b' spans 0..2s and the inner window is [0, 2s), so the latest usable
    timestamp for 'b' is 2s - 1us.  'a' sits exactly at 2s, so the closest
    the pair can be is exactly one microsecond.

    A sub-microsecond outer duration truncates to a zero-length window and
    must therefore fail.  An implementation which treated the inner last
    value as usable (or which rounded the duration up to one microsecond)
    would accept it.
    """

    intervals = {'a': (2 * _SECOND, 2 * _SECOND), 'b': (0, 2 * _SECOND)}
    inner = _StartStop(_Leaf('b'), 0, 2 * _SECOND)
    one_us = _Within(_And(inner, _Leaf('a')), 1)

    # Exactly one microsecond apart: within a one-microsecond window.
    assert _check(one_us, intervals) is True

    # Shrinking the window below one microsecond makes it impossible.
    pattern = one_us.pattern().replace(
        '0.000001 SECONDS', '0.0000001 SECONDS')
    assert not match(pattern, _observations(intervals),
                     stix_version=_stix_version)


def test_outer_within_respects_inner_start_stop_window():
    """An outer WITHIN must see the inner window, not raw first/last.

    'a' spans 0..100s and 'b' 0..5s.  The inner window pins 'a' to 90..91s,
    so the pair cannot be within 5s even though the raw interval for 'a'
    overlaps 'b' at time zero.
    """

    intervals = {'a': (0, 100 * _SECOND), 'b': (0, 5 * _SECOND)}

    node = _Within(
        _And(_StartStop(_Leaf('a'), 90 * _SECOND, 91 * _SECOND), _Leaf('b')),
        5 * _SECOND)
    assert _check(node, intervals) is False


def test_outer_start_stop_respects_inner_within():
    """An outer window must be checked against an inner WITHIN's group.

    'b' is pinned by the inner window to 0..2s while 'a' can only be in the
    outer window at 90..92s, so the inner WITHIN 1s cannot hold even though
    each qualifier alone is satisfiable.
    """

    intervals = {'a': (0, 100 * _SECOND), 'b': (0, 100 * _SECOND)}

    node = _StartStop(
        _Within(_And(_StartStop(_Leaf('b'), 0, 2 * _SECOND), _Leaf('a')),
                _SECOND),
        90 * _SECOND, 92 * _SECOND)
    assert _check(node, intervals) is False

    # The same nesting is satisfiable when the windows overlap.
    compatible = _StartStop(
        _Within(_And(_StartStop(_Leaf('b'), 0, 2 * _SECOND), _Leaf('a')),
                _SECOND),
        0, 2 * _SECOND)
    assert _check(compatible, intervals) is True


def test_nested_within_groups_are_conjunctive():
    """An inner WITHIN group and an outer WITHIN group over a superset must
    both hold for one assignment.

    'a' and 'b' each span 0..10s, so the inner WITHIN 5s is satisfiable and
    also allows both to sit at a chosen instant.  With 'c' fixed at 20s the
    outer WITHIN 1s over a, b, c would require a and b near 20s, which their
    own intervals forbid.
    """

    intervals = {'a': (0, 10 * _SECOND), 'b': (0, 10 * _SECOND),
                 'c': (20 * _SECOND, 20 * _SECOND)}

    inner = _Within(_And(_Leaf('a'), _Leaf('b')), 5 * _SECOND)

    impossible = _Within(_And(inner, _Leaf('c')), _SECOND)
    assert _check(impossible, intervals) is False

    # With 'c' inside the reachable range the same nesting is satisfiable.
    intervals_with_near_c = dict(intervals)
    intervals_with_near_c['c'] = (8 * _SECOND, 8 * _SECOND)
    possible = _Within(_And(inner, _Leaf('c')), _SECOND)
    assert _check(possible, intervals_with_near_c) is True


# ---------------------------------------------------------------------------
# Boundaries: equality, sub-second precision, day rollover, UTC offsets
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("duration_us,expected", [
    (999999, False),
    (1000000, True),
    (1000001, True),
])
def test_within_equality_at_window_boundary(duration_us, expected):
    """Two observations exactly one second apart are within one second, and
    not within any shorter duration."""

    intervals = {'a': (0, 0), 'b': (_SECOND, _SECOND)}
    node = _Within(_And(_Leaf('a'), _Leaf('b')), duration_us)
    assert _check(node, intervals) is expected


def test_start_inclusive_and_stop_exclusive():
    """START includes its value; STOP excludes its value."""

    pattern = _StartStop(_Leaf('a'), _SECOND, 2 * _SECOND).pattern()

    assert match(pattern, _observations({'a': (_SECOND, _SECOND)}),
                 stix_version=_stix_version)
    assert match(pattern,
                 _observations({'a': (2 * _SECOND - 1, 2 * _SECOND - 1)}),
                 stix_version=_stix_version)
    assert not match(pattern,
                     _observations({'a': (2 * _SECOND, 2 * _SECOND)}),
                     stix_version=_stix_version)
    assert not match(pattern,
                     _observations({'a': (2 * _SECOND, 5 * _SECOND)}),
                     stix_version=_stix_version)


def test_interval_overlapping_the_window_still_matches():
    """The qualifier only needs some legal timestamp inside the window."""

    pattern = _StartStop(_Leaf('a'), 0, _SECOND).pattern()
    assert match(pattern, _observations({'a': (0, 5 * _SECOND)}),
                 stix_version=_stix_version)
    assert match(pattern, _observations({'a': (-5 * _SECOND, 0)}),
                 stix_version=_stix_version)


def test_within_uses_each_observations_full_interval():
    """WITHIN must consider first and last of every observation.

    With a wide interval and a narrower one, an interior timestamp makes the
    group feasible; this fails if an observation is compressed to an
    arbitrary single point such as its first or last value.
    """

    intervals = {'a': (0, 100 * _SECOND), 'b': (50 * _SECOND, 60 * _SECOND)}
    assert _check(_Within(_And(_Leaf('a'), _Leaf('b')), 10 * _SECOND),
                  intervals) is True
    assert _check(_Within(_And(_Leaf('a'), _Leaf('b')), _SECOND),
                  intervals) is True

    # Disjoint intervals have no common instant.
    disjoint = {'a': (0, _SECOND), 'b': (3 * _SECOND, 5 * _SECOND)}
    assert _check(_Within(_And(_Leaf('a'), _Leaf('b')), _SECOND),
                  disjoint) is False


def test_subsecond_window_is_not_truncated_to_whole_seconds():
    """A 0.4s window is long enough for points 0.3s apart, but a 0.299999s
    window is not."""

    intervals = {'a': (100000, 100000), 'b': (400000, 400000)}
    assert _check(_Within(_And(_Leaf('a'), _Leaf('b')), 400000),
                  intervals) is True
    assert _check(_Within(_And(_Leaf('a'), _Leaf('b')), 299999),
                  intervals) is False


def test_cross_day_boundaries_use_elapsed_time():
    """A window spanning midnight is compared as elapsed time, not text."""

    intervals = {'a': (_DAY - 500000, _DAY - 500000),
                 'b': (_DAY + 500000, _DAY + 500000)}

    assert _check(_Within(_And(_Leaf('a'), _Leaf('b')), _SECOND),
                  intervals) is True
    assert _check(_Within(_And(_Leaf('a'), _Leaf('b')), 999999),
                  intervals) is False
    assert _check(_StartStop(_And(_Leaf('a'), _Leaf('b')),
                             _DAY - _SECOND, _DAY + _SECOND),
                  intervals) is True


def test_utc_offsets_in_observed_data_are_normalized():
    """Observed-data timestamps carrying different numeric offsets denote the
    same instants and must compare correctly against Z pattern literals.

    (Numeric offsets are not accepted inside STIX pattern TimestampLiteral
    tokens by the grammar, so the windows themselves use 'Z'.)
    """

    normalized = _bundle(2, 'b', 0, 0)
    normalized["objects"][0]["first_observed"] = \
        '2020-01-01T01:00:00+01:00'
    normalized["objects"][0]["last_observed"] = \
        '2020-01-01T01:00:00+01:00'

    observations = [_bundle(1, 'a', 0, 0), normalized]

    # Same instant under different offsets: the pair is within any positive
    # duration and also within exactly 0 seconds (they coincide).
    assert match(_Within(_And(_Leaf('a'), _Leaf('b')), _SECOND).pattern(),
                 observations, stix_version=_stix_version)

    # Add a point exactly one microsecond later, also written with +01:00.
    # Equality at the window boundary must be inclusive.
    offset_by_one_us = _bundle(3, 'c', 0, 0)
    offset_by_one_us["objects"][0]["first_observed"] = \
        '2020-01-01T01:00:00.000001+01:00'
    offset_by_one_us["objects"][0]["last_observed"] = \
        '2020-01-01T01:00:00.000001+01:00'
    three = observations + [offset_by_one_us]

    assert match(
        "({} AND {}) WITHIN 0.000001 SECONDS".format(
            _Leaf('a').pattern(), _Leaf('c').pattern()),
        three, stix_version=_stix_version)
    # A window strictly shorter than one microsecond cannot contain them.
    assert not match(
        "({} AND {}) WITHIN 0.0000005 SECONDS".format(
            _Leaf('a').pattern(), _Leaf('c').pattern()),
        three, stix_version=_stix_version)

    # An offset which moves an instant outside the window is not normalized
    # away into a match.
    shifted = _bundle(4, 'd', 0, 0)
    shifted["objects"][0]["first_observed"] = \
        '2020-01-01T01:00:02+01:00'
    shifted["objects"][0]["last_observed"] = \
        '2020-01-01T01:00:02+01:00'
    shifted_observations = [_bundle(1, 'a', 0, 0), shifted]
    assert not match(
        "({} AND {}) WITHIN 1 SECONDS".format(
            _Leaf('a').pattern(), _Leaf('d').pattern()),
        shifted_observations, stix_version=_stix_version)


def test_offset_value_exactly_at_stop_is_excluded():
    """A +01:00 timestamp equal to STOP is excluded exactly like the Z form."""

    observation = _bundle(1, 'a', 0, 0)
    observation["objects"][0]["first_observed"] = \
        '2020-01-01T01:00:01+01:00'
    observation["objects"][0]["last_observed"] = \
        '2020-01-01T01:00:01+01:00'

    pattern = _StartStop(_Leaf('a'), 0, _SECOND).pattern()
    assert not match(pattern, [observation], stix_version=_stix_version)

    observation["objects"][0]["first_observed"] = \
        '2020-01-01T01:00:00.999999+01:00'
    observation["objects"][0]["last_observed"] = \
        '2020-01-01T01:00:00.999999+01:00'
    assert match(pattern, [observation], stix_version=_stix_version)


def test_more_than_six_fractional_digits_truncate_without_rounding():
    """0.9999999s truncates to 0.999999s and stays inside a 1s window; if it
    were rounded it would become 1.0s and be wrongly excluded."""

    observation = _bundle(1, 'a', 0, 0)
    observation["objects"][0]["first_observed"] = \
        '2020-01-01T00:00:00.9999999Z'
    observation["objects"][0]["last_observed"] = \
        '2020-01-01T00:00:00.9999999Z'

    pattern = _StartStop(_Leaf('a'), 0, _SECOND).pattern()
    assert match(pattern, [observation], stix_version=_stix_version)


# ---------------------------------------------------------------------------
# FOLLOWEDBY ordering must be checked with the surrounding window
# ---------------------------------------------------------------------------

def test_followedby_ordering_is_checked_jointly_with_window():
    """'a' is pinned after 'b' by the inner windows while FOLLOWEDBY demands
    the reverse; both fit inside the outer WITHIN, so only a joint check
    rejects this."""

    intervals = {'a': (0, 100 * _SECOND), 'b': (0, 100 * _SECOND)}

    impossible = _Within(
        _FollowedBy(
            _StartStop(_Leaf('a'), 90 * _SECOND, 95 * _SECOND),
            _StartStop(_Leaf('b'), 0, 5 * _SECOND),
        ),
        100 * _SECOND)
    assert _check(impossible, intervals) is False

    possible = _Within(
        _FollowedBy(
            _StartStop(_Leaf('a'), 0, 5 * _SECOND),
            _StartStop(_Leaf('b'), 0, 5 * _SECOND),
        ),
        10 * _SECOND)
    assert _check(possible, intervals) is True


# ---------------------------------------------------------------------------
# Input ordering must not change the verdict
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("node_factory", [
    lambda: _And(_Leaf('a'), _Within(_Leaf('b'), _SECOND)),
    lambda: _Within(_And(_Leaf('a'), _Leaf('b')), _SECOND),
    lambda: _StartStop(_And(_Leaf('a'), _Leaf('b')), 0, 5 * _SECOND),
    lambda: _Within(
        _And(_StartStop(_Leaf('a'), 0, 2 * _SECOND), _Leaf('b')),
        5 * _SECOND),
    lambda: _Within(
        _FollowedBy(_Leaf('a'), _Leaf('b')), 5 * _SECOND),
])
def test_input_reordering_does_not_change_verdict(node_factory):
    """Bundle order is not pattern input; the verdict must be invariant."""

    intervals = {'a': (0, 100 * _SECOND), 'b': (0, 5 * _SECOND)}
    pattern = node_factory().pattern()

    verdicts = set()
    for ordering in itertools.permutations(list(intervals.items())):
        verdicts.add(bool(match(pattern, _observations(ordering),
                                stix_version=_stix_version)))

    assert len(verdicts) == 1, (
        "verdict depends on input order: {} for {}".format(
            verdicts, pattern))


# ---------------------------------------------------------------------------
# Reporting: distinguish scope from boundary failures
# ---------------------------------------------------------------------------

def _classify(first, second):
    """Classify two disagreeing patterns as 'scope' or 'boundary'.

    Time values are replaced by a placeholder.  If the resulting texts match,
    only a time value changed, so the failure is a boundary failure.  If the
    texts with all parentheses removed match but the texts themselves do not,
    only bracketing changed, so it is a scope failure.
    """

    def without_times(text):
        return re.sub(r"\d+(?:\.\d+)?", "#", text)

    def without_times_or_parens(text):
        return without_times(text).replace("(", "").replace(")", "")

    if without_times(first) == without_times(second):
        return 'boundary'
    if without_times_or_parens(first) == without_times_or_parens(second):
        return 'scope'
    return 'both'


def test_report_distinguishes_scope_from_boundary_failures():
    """A bracketing change and a window change must be classified
    differently, and a single time comparison must not replace the group
    check."""

    observations = _observations(
        {'a': (0, 0), 'b': (5 * _SECOND, 5 * _SECOND)})

    scope_change = (
        "{} AND {} WITHIN 1 SECONDS".format(_Leaf('a').pattern(),
                                            _Leaf('b').pattern()),
        "({} AND {}) WITHIN 1 SECONDS".format(_Leaf('a').pattern(),
                                              _Leaf('b').pattern()),
    )
    assert _classify(*scope_change) == 'scope'

    boundary_change = (
        "({} AND {}) WITHIN 4 SECONDS".format(_Leaf('a').pattern(),
                                              _Leaf('b').pattern()),
        "({} AND {}) WITHIN 6 SECONDS".format(_Leaf('a').pattern(),
                                              _Leaf('b').pattern()),
    )
    assert _classify(*boundary_change) == 'boundary'

    # A per-observation comparison is not a substitute for the group check:
    # 'a' alone satisfies any duration, but (a AND b) with 1s does not.
    assert match("{} WITHIN 1 SECONDS".format(_Leaf('a').pattern()),
                 observations, stix_version=_stix_version)
    assert not match(
        "({} AND {}) WITHIN 1 SECONDS".format(_Leaf('a').pattern(),
                                              _Leaf('b').pattern()),
        observations, stix_version=_stix_version)


# ---------------------------------------------------------------------------
# Randomized model agreement
# ---------------------------------------------------------------------------

def _random_node(rng, depth, names):
    """Generate a random pattern tree.  Leaf names may repeat; the model and
    the matcher both require a binding to be disjoint, so repeated names
    exercise that rule too."""

    if depth <= 0 or rng.random() < 0.40:
        return _Leaf(rng.choice(names))

    choice = rng.choice(
        ['and', 'or', 'within', 'within', 'start_stop', 'start_stop',
         'followedby'])
    if choice == 'and':
        return _And(_random_node(rng, depth - 1, names),
                    _random_node(rng, depth - 1, names))
    if choice == 'or':
        return _Or(_random_node(rng, depth - 1, names),
                   _random_node(rng, depth - 1, names))
    if choice == 'within':
        return _Within(_random_node(rng, depth - 1, names),
                       rng.choice([1, 2, 3, 5]) * _SECOND)
    if choice == 'start_stop':
        start = rng.choice([0, 1, 2, 3]) * _SECOND
        return _StartStop(_random_node(rng, depth - 1, names),
                          start, start + rng.choice([1, 2, 3, 4]) * _SECOND)
    return _FollowedBy(_random_node(rng, depth - 1, names),
                       _random_node(rng, depth - 1, names))


@pytest.mark.parametrize("seed", range(40))
def test_randomized_nested_shapes_agree_with_model(seed):
    """Random nested combinations must agree with the independent model.

    This is the broad safety net: scope mistakes and boundary mistakes both
    surface as a disagreement, across mixed AND/OR/WITHIN/START-STOP/
    FOLLOWEDBY trees.  Bases include a day-scale offset so cross-day and
    wide-interval behavior is exercised alongside sub-second values.
    """

    rng = random.Random(seed)

    intervals = {}
    for name in 'abcdefgh':
        base = rng.choice([0, _SECOND, 2 * _SECOND, 3 * _SECOND, _DAY])
        intervals[name] = (
            base, base + rng.choice([0, 1, _SECOND // 10, _SECOND, 2 * _SECOND]))

    node = _random_node(rng, 3, 'abcdefgh')
    _check(node, intervals)
