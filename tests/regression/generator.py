"""Seeded generator for (expression, document) fixtures.

Properties this module guarantees:

* one seed -> one fixture, reproducibly; the fixture records both the
  minimal working seed for the family and the seed that produced it;
* cold parsing (`compile()` on a cleared parser cache) and reuse of a
  parsed expression (`ParsedResult.search` twice) are separate paths,
  and both are expected to observe exactly the same thing;
* the same seed feeds the document selector, so documents are stable.
"""

import jmespath

from jmespath import parser as parser_module
from tests.regression import families
from tests.regression.documents import build_document
from tests.regression.observations import observe
from tests.regression.prng import SeededRandom

PROFILE_FOR = {
    "redundant-parentheses": "short_circuit_chain",
    "associativity": "short_circuit_chain",
    "grouped-subexpression": "items_clean",
    "quoted-argument-layout": "short_circuit_chain",
    "whitespace": "items_clean",
    "index-expression-pipe": "items_clean",
    "or-to-not-null": "short_circuit_null",
    "projection-to-map": "items_clean",
    "projection-to-pipe": "items_clean",
    "comparator-swap": "short_circuit_chain",
    "extra-branch-not-null": "short_circuit_truthy",
    "contrast-grouped-projection": "items_clean",
    "contrast-or-and": "short_circuit_truthy",
    "contrast-projection-map-nulls": "items_with_nulls",
}

# Fixed, small document pools per profile.  The seed selects both which
# document is drawn (via `rng.choice`-stable indexing) and which variant
# template is used, so both halves stay reproducible.
DOCUMENT_POOL_SIZE = 6
MAX_SEED_SEARCH = 10000


class Fixture(object):
    def __init__(self, family, seed, minimal_seed, left, right, document):
        self.family = family
        self.seed = seed
        self.minimal_seed = minimal_seed
        self.left = left
        self.right = right
        self.document = document

    def __repr__(self):
        return "Fixture(family=%r, seed=%r, left=%r, right=%r, document=%r)" \
            % (self.family, self.seed, self.left, self.right, self.document)

    def key(self):
        # Identity of the *minimal expression and input* for this seed.
        return (self.family, self.seed, self.left, self.right,
                _freeze_document(self.document))


def _freeze_document(document):
    if isinstance(document, dict):
        return tuple(sorted((k, _freeze_document(v))
                            for k, v in document.items()))
    if isinstance(document, list):
        return tuple(_freeze_document(v) for v in document)
    return document


def _profile_pool(profile):
    seed = 0xD0C5 + sum(ord(c) for c in profile)
    rng = SeededRandom(seed)
    return [build_document(rng, profile) for _ in range(DOCUMENT_POOL_SIZE)]


_POOLS = {}


def profile_pool(profile):
    if profile not in _POOLS:
        _POOLS[profile] = _profile_pool(profile)
    return _POOLS[profile]


def family(name):
    for candidate in families.FAMILIES:
        if candidate.name == name:
            return candidate
    raise KeyError(name)


def build_fixture(family_name, seed):
    """Return a Fixture for this seed.

    Raises `ValueError` when the seed cannot satisfy the family's checked
    precondition; callers search seeds rather than weaken the condition.
    """
    fam = family(family_name)
    pool = profile_pool(PROFILE_FOR[family_name])
    rng = SeededRandom(seed)
    doc_index = rng.below(len(pool))
    document = pool[doc_index]
    if not fam.applicable(document):
        raise ValueError("seed %d cannot satisfy %r" % (seed, family_name))
    left, right = fam.build(document, SeededRandom(seed * 2 + 1))
    return Fixture(family_name, seed, None, left, right, document)


def minimal_seed(family_name, start_seed=0):
    seed = start_seed
    while seed <= start_seed + MAX_SEED_SEARCH:
        try:
            build_fixture(family_name, seed)
            return seed
        except ValueError:
            seed += 1
    raise AssertionError("no valid seed for %r" % family_name)


def corpus(family_name, count=20, start_seed=0):
    """`count` fixtures with their minimal_seed recorded."""
    minimal = minimal_seed(family_name, start_seed)
    fixtures = []
    seed = start_seed
    while len(fixtures) < count:
        try:
            fixture = build_fixture(family_name, seed)
        except ValueError:
            seed += 1
            continue
        fixture.minimal_seed = minimal
        fixtures.append(fixture)
        seed += 1
    return fixtures


def clear_parser_cache():
    """Force the next compile() through the cold parse path."""
    parser_module.Parser._CACHE.clear()


def cold_observe(expression, document):
    """Cold path: parse from scratch, then evaluate once."""
    clear_parser_cache()
    parsed = jmespath.compile(expression)
    return observe(parsed, document)


def reused_observe(expression, document):
    """Reuse path: compile once, evaluate the same ParsedResult twice."""
    parsed = jmespath.compile(expression)
    first = observe(parsed, document)
    second = observe(parsed, document)
    return first, second


def assert_reproducible(family_name, seed):
    """Same seed must give the same minimal expression and same document."""
    first = build_fixture(family_name, seed)
    clear_parser_cache()
    second = build_fixture(family_name, seed)
    assert first.key() == second.key(), (first, second)
    return first
