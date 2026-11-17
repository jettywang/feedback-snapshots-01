"""
Deterministic tests for the reuse boundary of compiled patterns.

The design under test separates:

* shareable compiled syntax -- the ANTLR parse tree plus its STIX version,
  cached and reused across invocations;
* per-invocation state -- a fresh MatchListener, its compute stack, its lazy
  binding generators, and any exception state, which must never bleed between
  matches.

These tests avoid random stress testing.  Instead they use a fixed,
deterministic interleaving of two observation sets and one call that fails
mid-way, then assert that:

1. parsing happens only once per (pattern text, STIX version);
2. interleaved matches keep independent bindings, SDOs, and input objects;
3. a failed invocation does not corrupt the compiled pattern, which remains
   reusable afterwards;
4. identical pattern text compiled for STIX 2.0 and 2.1 never shares a parse
   tree, because their semantics can differ;
5. matching is genuinely re-executed -- a hit on one input can never be
   replayed as the result for a different, non-matching input.
"""
import copy

import pytest

from stix2patterns.exceptions import ParseException

from stix2matcher.matcher import (
    COMPILED_PATTERN_CACHE,
    CompiledPatternCache,
    MatcherException,
    Pattern,
    match,
)


# Two distinct observation sets.  Set A has two matching observations, set B
# a single different one.  They are deliberately interleaved in the tests
# below.
_OBSERVATIONS_A = [
    {
        "type": "observed-data",
        "first_observed": "2004-10-11T21:44:58Z",
        "last_observed": "2004-10-11T21:44:58Z",
        "number_observed": 1,
        "objects": {
            "a0": {"type": "person", "name": "alice", "age": 10},
        },
    },
    {
        "type": "observed-data",
        "first_observed": "2008-05-09T01:21:58.6Z",
        "last_observed": "2008-05-09T01:21:58.6Z",
        "number_observed": 1,
        "objects": {
            "b0": {"type": "person", "name": "bob", "age": 17},
        },
    },
]

_OBSERVATIONS_B = [
    {
        "type": "observed-data",
        "first_observed": "2010-01-01T00:00:00Z",
        "last_observed": "2010-01-01T00:00:00Z",
        "number_observed": 1,
        "objects": {
            "c0": {"type": "person", "name": "carol", "age": 22},
        },
    },
]

# An input that is structurally invalid for matching (missing required SDO
# keys), used to force a failure after a successful compilation.
_BAD_OBSERVATIONS = [{"type": "observed-data"}]


def _v21_bundle(bundle_id, observed_data_id, sco_id, value):
    return [
        {
            "type": "bundle",
            "id": bundle_id,
            "objects": [
                {
                    "id": observed_data_id,
                    "type": "observed-data",
                    "number_observed": 1,
                    "first_observed": "2014-04-19T06:51:26Z",
                    "last_observed": "2014-04-19T06:51:26Z",
                    "object_refs": [sco_id],
                    "spec_version": "2.1",
                },
                {"id": sco_id, "type": "test", "int": value},
            ],
        }
    ]


_OBSERVATIONS_21_A = _v21_bundle(
    "bundle--00000000-0000-0000-0000-000000000010",
    "observed-data--00000000-0000-0000-0000-000000000011",
    "test--00000000-0000-0000-0000-000000000012",
    5,
)
_OBSERVATIONS_21_B = _v21_bundle(
    "bundle--00000000-0000-0000-0000-000000000020",
    "observed-data--00000000-0000-0000-0000-000000000021",
    "test--00000000-0000-0000-0000-000000000022",
    9,
)


@pytest.fixture
def cache():
    compiled_cache = CompiledPatternCache()
    yield compiled_cache
    compiled_cache.clear()


def test_parse_tree_compiled_once_and_reused(cache):
    pattern_text = "[person:age > 5]"

    first = Pattern(pattern_text, "2.0", compiled_pattern_cache=cache)
    second = Pattern(pattern_text, "2.0", compiled_pattern_cache=cache)

    assert len(cache) == 1
    assert first.compiled_pattern is second.compiled_pattern
    # The parse tree itself is the shared, read-only artifact.
    assert first.compiled_pattern.parse_tree is second.compiled_pattern.parse_tree


def test_interleaved_matches_keep_independent_bindings(cache):
    pattern_text = "[person:age > 5]"
    compiled = Pattern(pattern_text, "2.0", compiled_pattern_cache=cache)

    # Start both matches, then consume their lazy generators in a fixed
    # interleaving: A, B, A, B.  Each generator must remember its own
    # position and must never see the other invocation's bindings.
    bindings_a = compiled.matched_bindings(_OBSERVATIONS_A)
    bindings_b = compiled.matched_bindings(_OBSERVATIONS_B)

    assert next(bindings_a) == (0,)
    assert next(bindings_b) == (0,)
    assert next(bindings_a) == (1,)
    with pytest.raises(StopIteration):
        next(bindings_b)
    with pytest.raises(StopIteration):
        next(bindings_a)


def test_interleaved_matches_keep_independent_results_and_inputs(cache):
    pattern_text = "[person:age > 5]"
    compiled = Pattern(pattern_text, "2.0", compiled_pattern_cache=cache)

    snapshot_a = copy.deepcopy(_OBSERVATIONS_A)
    snapshot_b = copy.deepcopy(_OBSERVATIONS_B)

    sdos_a = compiled.match(_OBSERVATIONS_A)
    sdos_b = compiled.match(_OBSERVATIONS_B)

    # Results resolve against each invocation's own observations only.
    assert sdos_a == [_OBSERVATIONS_A[0]]
    assert sdos_b == [_OBSERVATIONS_B[0]]
    assert sdos_a[0] is _OBSERVATIONS_A[0]
    assert sdos_b[0] is _OBSERVATIONS_B[0]
    assert sdos_a[0] is not sdos_b[0]

    # Input objects must not be mutated or aliased across invocations.
    assert _OBSERVATIONS_A == snapshot_a
    assert _OBSERVATIONS_B == snapshot_b


def test_failed_match_leaves_compiled_pattern_reusable(cache):
    pattern_text = "[person:age > 5]"
    compiled = Pattern(pattern_text, "2.0", compiled_pattern_cache=cache)

    # A successful match first, then a failing one, then reuse.
    assert compiled.match(_OBSERVATIONS_A)
    with pytest.raises(MatcherException):
        compiled.match(_BAD_OBSERVATIONS)

    # The failure's exception state is gone; the shared syntax is untouched.
    assert len(cache) == 1
    reused = Pattern(pattern_text, "2.0", compiled_pattern_cache=cache)
    assert reused.compiled_pattern is compiled.compiled_pattern
    assert reused.match(_OBSERVATIONS_A) == [_OBSERVATIONS_A[0]]


def test_failure_amid_interleaving_does_not_corrupt_other_match(cache):
    pattern_text = "[person:age > 5]"
    compiled = Pattern(pattern_text, "2.0", compiled_pattern_cache=cache)

    good_bindings = compiled.matched_bindings(_OBSERVATIONS_A)
    assert next(good_bindings) == (0,)

    with pytest.raises(MatcherException):
        compiled.match(_BAD_OBSERVATIONS)

    # The in-flight generator from before the failure still works and still
    # only yields set A's bindings.
    assert list(good_bindings) == [(1,)]
    assert compiled.match(_OBSERVATIONS_B) == [_OBSERVATIONS_B[0]]


def test_same_text_different_versions_use_distinct_compiled_entries(cache):
    pattern_text = "[identity:name = 'foo']"

    p20 = Pattern(pattern_text, "2.0", compiled_pattern_cache=cache)
    p21 = Pattern(pattern_text, "2.1", compiled_pattern_cache=cache)

    # The version is part of the cache identity: no cross-version reuse.
    assert ("2.0", pattern_text) in cache
    assert ("2.1", pattern_text) in cache
    assert len(cache) == 2
    assert p20.compiled_pattern is not p21.compiled_pattern
    assert p20.compiled_pattern.parse_tree is not p21.compiled_pattern.parse_tree
    assert p20.stix_version == "2.0"
    assert p21.stix_version == "2.1"


def test_same_text_versions_do_not_share_wrong_semantics(cache):
    # This exact text is legal under both grammars, but "identity" is an
    # excluded non-SCO type under 2.1 while matching normally under 2.0.
    pattern_text = "[identity:name = 'foo']"

    obs20 = [
        {
            "type": "observed-data",
            "number_observed": 1,
            "first_observed": "2014-04-19T06:51:26Z",
            "last_observed": "2014-04-19T06:51:26Z",
            "objects": {"0": {"type": "identity", "name": "foo"}},
        }
    ]
    obs21 = [
        {
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000000",
            "objects": [
                {
                    "id": "observed-data--00000000-0000-0000-0000-000000000001",
                    "type": "observed-data",
                    "number_observed": 1,
                    "first_observed": "2014-04-19T06:51:26Z",
                    "last_observed": "2014-04-19T06:51:26Z",
                    "object_refs": [
                        "identity--00000000-0000-0000-0000-000000000002"
                    ],
                    "spec_version": "2.1",
                },
                {
                    "id": "identity--00000000-0000-0000-0000-000000000002",
                    "type": "identity",
                    "name": "foo",
                },
            ],
        }
    ]

    compiled20 = Pattern(pattern_text, "2.0", compiled_pattern_cache=cache)
    compiled21 = Pattern(pattern_text, "2.1", compiled_pattern_cache=cache)

    assert compiled20.match(obs20)
    assert not compiled21.match(obs21)


def test_match_is_reexecuted_not_served_from_a_result_cache(cache):
    # The same compiled pattern must give different answers for different
    # inputs; a cached hit must never substitute for a real execution.
    pattern_text = "[person:age > 50]"
    compiled = Pattern(pattern_text, "2.0", compiled_pattern_cache=cache)

    assert not compiled.match(_OBSERVATIONS_A)
    assert not compiled.match(_OBSERVATIONS_B)

    older = {
        "type": "observed-data",
        "first_observed": "2012-06-01T00:00:00Z",
        "last_observed": "2012-06-01T00:00:00Z",
        "number_observed": 1,
        "objects": {"d0": {"type": "person", "name": "dave", "age": 71}},
    }
    assert compiled.match([older]) == [older]
    # And the earlier inputs still report their real (non-matching) result.
    assert not compiled.match(_OBSERVATIONS_A)


def test_parse_failure_is_not_cached(cache):
    with pytest.raises(ParseException):
        Pattern("[not a valid pattern", "2.0", compiled_pattern_cache=cache)

    assert len(cache) == 0
    # A later valid compilation of different text works normally.
    Pattern("[person:age > 5]", "2.0", compiled_pattern_cache=cache)
    assert len(cache) == 1


def test_interleaved_matches_work_under_v21(cache):
    compiled = Pattern("[test:int > 1]", "2.1", compiled_pattern_cache=cache)

    bindings_a = compiled.matched_bindings(_OBSERVATIONS_21_A)
    bindings_b = compiled.matched_bindings(_OBSERVATIONS_21_B)

    assert next(bindings_a) == (0,)
    assert next(bindings_b) == (0,)
    assert list(bindings_a) == []
    assert list(bindings_b) == []
    assert len(cache) == 1


def test_verbose_output_is_isolated_per_invocation(cache, capsys):
    compiled = Pattern("[person:age > 5]", "2.0", compiled_pattern_cache=cache)

    compiled.match(_OBSERVATIONS_A, verbose=True)
    assert capsys.readouterr().out.strip()

    # A later quiet invocation must not inherit any verbose tracing state.
    compiled.match(_OBSERVATIONS_B, verbose=False)
    assert capsys.readouterr().out == ""


def test_module_level_cache_reuses_parse_across_match_calls():
    COMPILED_PATTERN_CACHE.clear()
    pattern_text = "[person:age > 5]"
    try:
        assert match(pattern_text, _OBSERVATIONS_A, stix_version="2.0")
        assert match(pattern_text, _OBSERVATIONS_B, stix_version="2.0")
        assert ("2.0", pattern_text) in COMPILED_PATTERN_CACHE

        # A single compiled entry serves both module-level match() calls.
        compiled = COMPILED_PATTERN_CACHE.get_or_compile(pattern_text, "2.0")
        assert compiled.parse_tree is not None
    finally:
        COMPILED_PATTERN_CACHE.clear()
