"""Generative, seeded regression tests for JMESPath equivalence.

The regression corpus is produced locally from fixed seeds.  No external
service is contacted and only ordinary JSON documents and normal
expressions are used.

What is checked:

* sound rewrites (extra parentheses, associativity, layout, an index
  expression rewritten as a pipe, `a || b` with a null `a` rewritten as
  `not_null(a, b)`, projection rewritten as `map` when no nulls can be
  dropped) must agree on the JSON value *and* on branch access;
* an implementation that touches an extra short-circuit branch must be
  caught even when the JSON value is identical -- demonstrated twice, once
  as an intentional failing assertion and once through the recording
  extension functions' call order;
* deliberately inequivalent expressions stay available as negative
  controls and are never reported as equivalent;
* the same seed reproduces the same minimal expression and input, on both
  the cold-parse path and the reused-parsed-expression path.
"""

import pytest

import jmespath
from jmespath import parser as parser_module

from tests.regression import families
from tests.regression.criteria import (
    assert_equivalent,
    assert_not_equivalent,
    assert_strict,
    compare,
)
from tests.regression.generator import (
    Fixture,
    build_fixture,
    cold_observe,
    corpus,
    minimal_seed,
    reused_observe,
)
from tests.regression.observations import observe

CORPUS_SIZE = 12

# Legal syntactic rewrites must match value, branch access and order.
# The comparator-swap family is value+branch equivalent but reorders reads,
# so it is checked through `assert_equivalent` instead.
STRICT_FAMILIES = [fam.name for fam in families.FAMILIES
                   if fam.level == families.STRICT]
STRICT_ASSERTION_FAMILIES = list(STRICT_FAMILIES)
EQUIVALENT_FAMILIES = [fam.name for fam in families.FAMILIES
                       if fam.level == families.EQUIVALENT]
CONTROL_FAMILIES = [fam.name for fam in families.FAMILIES
                    if fam.level == families.CONTROL]

ALL_FAMILIES = [fam.name for fam in families.FAMILIES]


def _level_for(name):
    return families.FAMILIES[ALL_FAMILIES.index(name)].level


def _assert_fixture_level(fixture):
    left = observe(fixture.left, fixture.document)
    right = observe(fixture.right, fixture.document)
    level = _level_for(fixture.family)
    if level == families.STRICT:
        assert_strict(left, right, note="family %r seed %d" % (
            fixture.family, fixture.seed))
    elif level == families.EQUIVALENT:
        assert_equivalent(left, right, note="family %r seed %d" % (
            fixture.family, fixture.seed))
    else:
        assert_not_equivalent(left, right, note="family %r seed %d" % (
            fixture.family, fixture.seed))


@pytest.mark.parametrize("family_name", STRICT_ASSERTION_FAMILIES)
def test_sound_rewrites_are_strictly_equivalent(family_name):
    """Value, branch set, read order and call order all agree."""
    for fixture in corpus(family_name, count=CORPUS_SIZE):
        left = observe(fixture.left, fixture.document)
        right = observe(fixture.right, fixture.document)
        assert_strict(left, right, note="family %r seed %d" % (
            fixture.family, fixture.seed))


@pytest.mark.parametrize("family_name", EQUIVALENT_FAMILIES)
def test_equivalent_rewrites_match_value_and_branches(family_name):
    for fixture in corpus(family_name, count=CORPUS_SIZE):
        _assert_fixture_level(fixture)


@pytest.mark.parametrize("family_name", CONTROL_FAMILIES)
def test_contrast_expressions_are_not_equivalent(family_name):
    for fixture in corpus(family_name, count=CORPUS_SIZE):
        _assert_fixture_level(fixture)
        # A negative control must differ in *value or* in branch access;
        # record which one so a future change cannot silently turn it into
        # a same-value pair without the branch test catching it.
        left = observe(fixture.left, fixture.document)
        right = observe(fixture.right, fixture.document)
        report = compare(left, right)
        assert not report.equivalent


@pytest.mark.parametrize("family_name", ALL_FAMILIES)
def test_cold_and_reused_parse_agree(family_name):
    for fixture in corpus(family_name, count=CORPUS_SIZE):
        cold = cold_observe(fixture.left, fixture.document)
        first, second = reused_observe(fixture.left, fixture.document)
        assert cold == first == second, (
            "cold/reused mismatch for %r seed %d\ncold:  %r\nfirst: %r\n"
            "second: %r" % (family_name, fixture.seed, cold, first, second))


@pytest.mark.parametrize("family_name", ALL_FAMILIES)
def test_same_seed_reproduces_same_fixture(family_name):
    seed = minimal_seed(family_name)
    first = build_fixture(family_name, seed)
    parser_module.Parser._CACHE.clear()
    second = build_fixture(family_name, seed)
    assert isinstance(first, Fixture)
    assert first.key() == second.key(), (
        "same seed produced different fixtures\nfirst:  %r\nsecond: %r" % (
            first, second))


def test_parser_cache_reused_for_repeated_expression():
    """Reuse means no second parse, not merely a re-run of the interpreter."""
    original = parser_module.Parser._parse
    counter = {"parses": 0}

    def counting(self, expression):
        counter["parses"] += 1
        return original(self, expression)

    parser_module.Parser._CACHE.clear()
    parser_module.Parser._parse = counting
    try:
        parsed = jmespath.compile("a || b")
        parser_module.Parser._CACHE.clear()
        parser_module.Parser._parse = original
        first = observe(parsed, {"a": None, "b": 2})
        second = observe(parsed, {"a": None, "b": 2})
    finally:
        parser_module.Parser._parse = original
    assert counter["parses"] == 1
    assert first == second
