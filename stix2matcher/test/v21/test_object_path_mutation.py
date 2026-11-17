# -*- coding: utf-8 -*-
"""Syntax-aware mutation tests for STIX object paths.

Strategy
--------
1. Build object paths as *syntax trees* (a first key component plus a list
   of key/index steps), never as raw strings.  A serializer turns the tree
   into pattern text, quoting and escaping keys exactly where the grammar
   requires it.
2. An independent tree-walking interpreter computes the values a path
   selects, directly from the object graph (no string re-parsing, no dot
   splitting).  It mirrors the documented matcher semantics: ``_ref`` /
   ``_refs`` suffixes trigger dereferencing, dangling references are
   dropped, ``[*]`` expands list elements, and every selected value stays
   attached to the root object it was reached from.
3. Both levels are compared against the real matcher:
   - path value selection: ``[t:path = <literal>]`` probes for every
     expected value and for sentinel values that must be absent;
   - final rule hits: ``[EXISTS t:path]`` and two-path conjunctions
     ``[t:p1 = v1 AND t:p2 = v2]`` (the latter pins root-object identity:
     both comparisons must hold on the *same* root object).
4. Syntax-aware mutations edit the tree (rename keys, move indices, toggle
   ``_ref`` suffixes, drop/append steps) and re-serialize; every mutant is
   checked against the oracle again.
5. Illegal paths (unquoted keys containing hyphens/dots/keywords) must
   stop at a syntax error or select nothing -- they must never be
   silently "repaired" by splitting on dots.

All generators are driven by seeded RNGs, so failures are deterministic.
On failure, a greedy shrinker reduces objects/keys/path steps while the
failure keeps reproducing, and the minimal counterexample is reported.
"""

import collections
import json
import random
import re

import pytest
from stix2patterns.pattern import ParseException

from stix2matcher.matcher import match

_STIX_VERSION = u"2.1"

# A string/int pair guaranteed to never appear in generated data.  Used to
# probe that paths do not select values they shouldn't.
_SENTINEL_STR = u"__sentinel__"
_SENTINEL_INT = 987654321


# ---------------------------------------------------------------------------
# Path syntax tree + serializer
# ---------------------------------------------------------------------------

Key = collections.namedtuple("Key", ["name"])
Index = collections.namedtuple("Index", ["index"])  # int or u"*"

Case = collections.namedtuple("Case", ["objects", "type_", "first", "steps"])

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")

# Pattern-language keywords: usable as keys only when quoted.
_RESERVED = {
    u"AND", u"OR", u"NOT", u"FOLLOWEDBY", u"LIKE", u"MATCHES",
    u"ISSUPERSET", u"ISSUBSET", u"EXISTS", u"LAST", u"IN", u"START",
    u"STOP", u"SECONDS", u"TRUE", u"FALSE", u"WITHIN", u"REPEATS",
    u"TIMES",
}


def quote_string(raw):
    """Serialize a python string as a STIX string literal."""
    return u"'" + raw.replace(u"\\", u"\\\\").replace(u"'", u"\\'") + u"'"


def serialize_key(key):
    """Serialize an object-path key component, quoting only if needed."""
    if _IDENT_RE.match(key) and key.upper() not in _RESERVED:
        return key
    return quote_string(key)


def serialize_path(type_, first, steps):
    """Serialize a path syntax tree to pattern text."""
    parts = [type_, u":", serialize_key(first)]
    for step in steps:
        if isinstance(step, Key):
            parts.append(u".")
            parts.append(serialize_key(step.name))
        else:
            parts.append(u"[")
            parts.append(u"*" if step.index == u"*" else str(step.index))
            parts.append(u"]")
    return u"".join(parts)


def serialize_literal(value):
    """Serialize a scalar as a pattern comparison literal."""
    if isinstance(value, str):
        return quote_string(value)
    return str(value)


# ---------------------------------------------------------------------------
# Independent tree-walking interpreter (the oracle)
# ---------------------------------------------------------------------------

def select_values(objects, type_, first, steps):
    """Walk a path syntax tree over the object graph.

    :param objects: all objects of the observation (any type)
    :return: {root_object_id: [selected values]}; roots with empty
        selections are omitted.
    """
    by_id = {obj["id"]: obj for obj in objects}

    current = {}
    for obj in objects:
        if obj.get("type") == type_:
            current[obj["id"]] = [obj]

    def key_step(state, name):
        out = {}
        for root_id, values in state.items():
            stepped = []
            for value in values:
                if not isinstance(value, dict) or name not in value:
                    continue
                val = value[name]
                if name.endswith(u"_ref"):
                    # Reference property: substitute the referenced object.
                    # Dangling references are dropped, not an error.
                    if isinstance(val, str) and val in by_id:
                        stepped.append(by_id[val])
                elif name.endswith(u"_refs"):
                    # Reference list: the resolved objects become a single
                    # (nested) list value; empty resolutions vanish.
                    resolved = [
                        by_id[ref] for ref in val
                        if isinstance(ref, str) and ref in by_id
                    ] if isinstance(val, list) else []
                    if resolved:
                        stepped.append(resolved)
                else:
                    stepped.append(val)
            if stepped:
                out[root_id] = stepped
        return out

    def index_step(state, index):
        out = {}
        for root_id, values in state.items():
            stepped = []
            for value in values:
                if not isinstance(value, list):
                    continue
                if index == u"*":
                    stepped.extend(value)
                elif 0 <= index < len(value):
                    stepped.append(value[index])
            if stepped:
                out[root_id] = stepped
        return out

    current = key_step(current, first)
    for step in steps:
        if isinstance(step, Key):
            current = key_step(current, step.name)
        else:
            current = index_step(current, step.index)
    return current


def _is_scalar(value):
    return isinstance(value, (str, int)) and not isinstance(value, bool)


def _selected_scalars(selection):
    """Distinct scalar values in a selection, in deterministic order."""
    scalars = set()
    for values in selection.values():
        for value in values:
            if _is_scalar(value):
                scalars.add(value)
    return sorted(scalars, key=repr)


# ---------------------------------------------------------------------------
# Observation assembly
# ---------------------------------------------------------------------------

def make_bundle(objects):
    return [{
        "type": u"bundle",
        "id": u"bundle--00000000-0000-4000-8000-0000000000aa",
        "objects": [
            {
                "type": u"observed-data",
                "id": u"observed-data--00000000-0000-4000-8000-0000000000bb",
                "number_observed": 1,
                "first_observed": u"2004-10-11T21:44:58Z",
                "last_observed": u"2004-10-11T21:44:58Z",
                "spec_version": u"2.1",
                "object_refs": [obj["id"] for obj in objects],
            },
        ] + list(objects),
    }]


def _matches(pattern, objects):
    return bool(match(pattern, make_bundle(objects),
                      stix_version=_STIX_VERSION))


# ---------------------------------------------------------------------------
# Oracle comparison
# ---------------------------------------------------------------------------

class CaseFailure(AssertionError):
    pass


def check_case(case):
    """Compare matcher behaviour against the oracle for one path case.

    Raises CaseFailure on any disagreement.
    """
    path = serialize_path(case.type_, case.first, case.steps)
    selection = select_values(case.objects, case.type_, case.first,
                              case.steps)

    # Final rule hit: EXISTS must agree with selection emptiness.
    expected_exists = any(selection.values())
    got_exists = _matches(u"[EXISTS {}]".format(path), case.objects)
    if got_exists != expected_exists:
        raise CaseFailure(
            u"EXISTS mismatch for path {}: matcher={}, oracle={}".format(
                path, got_exists, expected_exists))

    # Path value selection: every expected scalar must be selectable...
    for value in _selected_scalars(selection):
        pattern = u"[{} = {}]".format(path, serialize_literal(value))
        if not _matches(pattern, case.objects):
            raise CaseFailure(
                u"value {} selected by oracle but not by matcher: "
                u"{}".format(repr(value), pattern))

    # ...and sentinels must never be selected.
    for sentinel in (_SENTINEL_STR, _SENTINEL_INT):
        pattern = u"[{} = {}]".format(path, serialize_literal(sentinel))
        if _matches(pattern, case.objects):
            raise CaseFailure(
                u"sentinel {} unexpectedly matched: {}".format(
                    repr(sentinel), pattern))


def check_conjunction(objects, type_, path1, path2, val1, val2):
    """Two comparisons in one observation expression must bind to the
    same root object.  Losing root identity (pooling values across
    roots) makes this check fail deterministically."""
    sel1 = select_values(objects, type_, path1[0], path1[1])
    sel2 = select_values(objects, type_, path2[0], path2[1])
    root_ids = {obj["id"] for obj in objects if obj.get("type") == type_}
    expected = any(
        val1 in sel1.get(root, ()) and val2 in sel2.get(root, ())
        for root in root_ids)

    text1 = serialize_path(type_, path1[0], path1[1])
    text2 = serialize_path(type_, path2[0], path2[1])
    pattern = u"[{} = {} AND {} = {}]".format(
        text1, serialize_literal(val1), text2, serialize_literal(val2))
    got = _matches(pattern, objects)
    if got != expected:
        raise CaseFailure(
            u"conjunction mismatch: matcher={}, oracle={} for {}".format(
                got, expected, pattern))


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

# Keys exercising quoting: dots, hyphens, quotes, backslashes, spaces,
# reserved words, and reference-*lookalikes* that are not references.
_SCALAR_KEYS = [
    u"alpha", u"num", u"has.dot", u"has-hyphen", u"hy.phe-n",
    u"quote'key", u"back\\slash", u"with space", u"AND",
    u"ref_count", u"reference", u"x_ref_y",
]
_REF_KEYS = [u"link_ref", u"next_ref"]
_REFS_KEY = u"many_refs"
_LIST_KEYS = [u"items", u"empty_list"]
_NESTED_KEY = u"nested"
# A plain key and a real reference holding the same id string: mixing them
# up is a deterministic failure.
_BUDDY_KEY = u"buddy"
_BUDDY_REF_KEY = u"buddy_ref"

_STR_POOL = [u"red", u"blue", u"has.dot", u"it's", u"back\\slash", u""]
_INT_POOL = [0, 1, 2, 3, 7, 42]


def _make_scalar(rng):
    if rng.random() < 0.5:
        return rng.choice(_INT_POOL)
    return rng.choice(_STR_POOL)


def make_objects(rng):
    """Generate 2-3 same-type root objects plus a decoy of another type."""
    n_roots = rng.randint(2, 3)
    ids = [u"thing--{:04d}".format(i) for i in range(n_roots)]
    objects = []
    for i, obj_id in enumerate(ids):
        obj = {u"type": u"thing", u"id": obj_id}
        for key in rng.sample(_SCALAR_KEYS, rng.randint(3, 6)):
            obj[key] = _make_scalar(rng)
        for key in _REF_KEYS:
            roll = rng.random()
            if roll < 0.4:
                obj[key] = rng.choice(ids)          # resolvable
            elif roll < 0.6:
                obj[key] = u"thing--dangling"       # missing reference
        if rng.random() < 0.5:
            obj[_REFS_KEY] = [
                rng.choice(ids + [u"thing--dangling"])
                for _ in range(rng.randint(0, 2))
            ]
        if rng.random() < 0.6:
            obj[_LIST_KEYS[0]] = [
                _make_scalar(rng) for _ in range(rng.randint(0, 3))
            ]
        if rng.random() < 0.5:
            obj[_LIST_KEYS[1]] = []                 # empty array
        if rng.random() < 0.4:
            obj[_NESTED_KEY] = {
                u"inner": _make_scalar(rng),
                u"deep_ref": rng.choice(ids),       # reference chain link
            }
        if rng.random() < 0.7:
            target = rng.choice(ids)
            obj[_BUDDY_KEY] = target                # plain string, not a ref
            obj[_BUDDY_REF_KEY] = target            # real reference
        objects.append(obj)

    # Decoy: same property names, different type; must never be selected.
    decoy = {u"type": u"decoy", u"id": u"decoy--0000"}
    for key in rng.sample(_SCALAR_KEYS, 3):
        decoy[key] = _make_scalar(rng)
    objects.append(decoy)
    return objects


def _random_present_key(rng, dicts):
    keys = set()
    for d in dicts:
        keys.update(k for k in d if k not in (u"type", u"id"))
    return rng.choice(sorted(keys)) if keys else None


def make_path(rng, objects, type_=u"thing"):
    """Generate a path syntax tree by walking the object graph.

    Steps are chosen to be mostly applicable, sometimes deliberately not
    (absent keys, out-of-range indices) so empty selections are covered.
    """
    roots = [obj for obj in objects if obj.get("type") == type_]
    first = _random_present_key(rng, roots)
    if first is None or rng.random() < 0.1:
        first = u"absent_key"
    steps = []
    for _ in range(rng.randint(0, 3)):
        selection = select_values(objects, type_, first, steps)
        values = [v for vs in selection.values() for v in vs]
        dicts = [v for v in values if isinstance(v, dict)]
        lists = [v for v in values if isinstance(v, list)]
        roll = rng.random()
        if dicts and (roll < 0.5 or not lists):
            key = _random_present_key(rng, dicts)
            if key is None or rng.random() < 0.15:
                key = u"absent_key"
            steps.append(Key(key))
        elif lists:
            if rng.random() < 0.3:
                steps.append(Index(u"*"))
            else:
                longest = max(len(v) for v in lists)
                index = rng.randint(0, longest)  # may be out of range
                if rng.random() < 0.1:
                    index = -1                     # legal syntax, no value
                steps.append(Index(index))
        else:
            break
    return first, tuple(steps)


def make_case(rng):
    objects = make_objects(rng)
    first, steps = make_path(rng, objects)
    return Case(objects, u"thing", first, steps)


# ---------------------------------------------------------------------------
# Syntax-aware mutations (operate on the tree, then re-serialize)
# ---------------------------------------------------------------------------

def mutate_case(rng, case):
    """Return a mutated copy of the case; the oracle re-derives expectations."""
    first, steps = case.first, list(case.steps)
    op = rng.choice([u"rename", u"index", u"drop", u"append", u"refswap"])

    if op == u"rename":
        key_steps = [i for i, s in enumerate(steps) if isinstance(s, Key)]
        target = rng.choice([-1] + key_steps)  # -1 == first component
        new_key = rng.choice(_SCALAR_KEYS + [u"absent_key"])
        if target == -1:
            first = new_key
        else:
            steps[target] = Key(new_key)
    elif op == u"index":
        idx_steps = [i for i, s in enumerate(steps) if isinstance(s, Index)]
        if idx_steps:
            i = rng.choice(idx_steps)
            current = steps[i].index
            steps[i] = Index(u"*" if current != u"*" else 0
                             if rng.random() < 0.5 else
                             rng.randint(0, 3))
        else:
            steps.append(Index(rng.choice([0, 1, u"*"])))
    elif op == u"drop":
        if steps:
            del steps[rng.randrange(len(steps))]
    elif op == u"append":
        extra_first, extra_steps = make_path(rng, case.objects, case.type_)
        if extra_steps:
            steps.append(extra_steps[0])
        else:
            steps.append(Key(extra_first))
    elif op == u"refswap":
        # Toggle between a plain key and a real reference holding the same
        # id string; confusing the two flips the expected selection.
        if any(_BUDDY_KEY in obj for obj in case.objects):
            first = rng.choice([_BUDDY_KEY, _BUDDY_REF_KEY])
            steps = []

    return Case(case.objects, case.type_, first, tuple(steps))


# ---------------------------------------------------------------------------
# Shrinking: reduce a failing case while it keeps failing
# ---------------------------------------------------------------------------

def _path_keys(case):
    keys = {case.first}
    for step in case.steps:
        if isinstance(step, Key):
            keys.add(step.name)
    return keys


def _simplifications(case):
    """Deterministic sequence of simpler candidate cases."""
    if case.steps:
        yield case._replace(steps=case.steps[:-1])
    for i in range(len(case.objects)):
        if len(case.objects) > 1:
            yield case._replace(
                objects=case.objects[:i] + case.objects[i + 1:])
    keep = _path_keys(case) | {u"type", u"id"}
    for i, obj in enumerate(case.objects):
        droppable = [k for k in sorted(obj) if k not in keep]
        for key in droppable:
            trimmed = dict(obj)
            del trimmed[key]
            objects = (case.objects[:i] + [trimmed] +
                       case.objects[i + 1:])
            yield case._replace(objects=objects)


def shrink(case, check):
    """Greedily simplify `case` while `check` still raises CaseFailure."""
    improved = True
    while improved:
        improved = False
        for candidate in _simplifications(case):
            try:
                check(candidate)
            except CaseFailure:
                case = candidate
                improved = True
                break
    return case


def _report_and_fail(seed, case, failure):
    shrunk = shrink(case, check_case)
    try:
        check_case(shrunk)
    except CaseFailure as shrunk_failure:
        failure = shrunk_failure
    path = serialize_path(shrunk.type_, shrunk.first, shrunk.steps)
    pytest.fail(
        u"seed={} path={}\n{}\nobjects={}".format(
            seed, path, failure,
            json.dumps(shrunk.objects, sort_keys=True)))


# ---------------------------------------------------------------------------
# Deterministic tests: quoting, escaping, references, root identity
# ---------------------------------------------------------------------------

_TRICKY_OBJECTS = [{
    u"type": u"thing",
    u"id": u"thing--tricky",
    u"has.dot": 2,
    u"has-hyphen": 1,
    u"hy.phe-n": 3,
    u"quote'key": 4,
    u"back\\slash": 5,
    u"with space": 6,
    u"AND": 7,
    u"ref_count": u"thing--tricky",   # plain key holding an id string
    u"reference": 8,
    u"x_ref_y": 9,
    u"it's": u"back\\slash",          # tricky value, not just tricky key
}]


@pytest.mark.parametrize("key,value", [
    (u"has-hyphen", 1),
    (u"has.dot", 2),
    (u"hy.phe-n", 3),
    (u"quote'key", 4),
    (u"back\\slash", 5),
    (u"with space", 6),
    (u"AND", 7),
    (u"reference", 8),
    (u"x_ref_y", 9),
])
def test_quoted_keys_select_their_values(key, value):
    """Quoted/escaped keys round-trip to exactly one dict key."""
    path = serialize_path(u"thing", key, ())
    assert _matches(u"[{} = {}]".format(path, serialize_literal(value)),
                    _TRICKY_OBJECTS)
    # The value is not reachable through any *other* interpretation.
    assert not _matches(u"[{} = {}]".format(path, _SENTINEL_INT),
                        _TRICKY_OBJECTS)


def test_escaped_string_value_roundtrip():
    path = serialize_path(u"thing", u"it's", ())
    assert _matches(u"[{} = {}]".format(path, serialize_literal(u"back\\slash")),
                    _TRICKY_OBJECTS)


@pytest.mark.parametrize("key", [u"has-hyphen", u"hy.phe-n", u"AND"])
def test_unquotable_keys_raise_syntax_error(key):
    """Illegal paths stop at a syntax error; no auto-repair happens."""
    with pytest.raises(ParseException):
        match(u"[thing:{} = 1]".format(key), make_bundle(_TRICKY_OBJECTS),
              stix_version=_STIX_VERSION)


def test_dotted_key_is_not_auto_split():
    """'has.dot' unquoted parses as two steps and must select nothing --
    splitting on dots must not accidentally reach the quoted key's value."""
    assert _matches(u"[thing:'has.dot' = 2]", _TRICKY_OBJECTS)
    assert not _matches(u"[thing:has.dot = 2]", _TRICKY_OBJECTS)
    assert not _matches(u"[EXISTS thing:has.dot]", _TRICKY_OBJECTS)


@pytest.mark.parametrize("key", [
    key for key in _SCALAR_KEYS if serialize_key(key) != key
])
def test_unquoted_tricky_keys_never_reach_the_value(key):
    """For every key that requires quoting, the unquoted form must either
    stop at a syntax error or select nothing -- never silently reach the
    quoted key's value via dot-splitting or keyword tolerance."""
    value = _TRICKY_OBJECTS[0][key]
    pattern = u"[thing:{} = {}]".format(key, serialize_literal(value))
    try:
        matched = _matches(pattern, _TRICKY_OBJECTS)
    except ParseException:
        return  # syntax error is the required behavior
    assert not matched, u"illegal path was auto-repaired: " + pattern


def test_plain_key_holding_id_string_is_not_dereferenced():
    """ref_count does not end in _ref: its string value must be compared
    as-is, not resolved to the object with that id."""
    assert _matches(u"[thing:ref_count = 'thing--tricky']", _TRICKY_OBJECTS)
    selection = select_values(_TRICKY_OBJECTS, u"thing", u"ref_count", ())
    assert selection == {u"thing--tricky": [u"thing--tricky"]}


def test_reference_chain_selects_through_objects():
    objects = [
        {u"type": u"thing", u"id": u"thing--a",
         u"link_ref": u"thing--b"},
        {u"type": u"thing", u"id": u"thing--b",
         u"link_ref": u"thing--c"},
        {u"type": u"thing", u"id": u"thing--c",
         u"name": u"deep"},
    ]
    assert _matches(u"[thing:link_ref.link_ref.name = 'deep']", objects)
    assert not _matches(u"[thing:link_ref.link_ref.name = 'shallow']", objects)
    selection = select_values(objects, u"thing", u"link_ref",
                              (Key(u"link_ref"), Key(u"name")))
    # Root identity is preserved: only root a's two-hop chain reaches a
    # name; root b's chain dies at thing--c, which has no link_ref.
    assert selection == {u"thing--a": [u"deep"]}


def test_dangling_and_empty_references_select_nothing():
    objects = [
        {u"type": u"thing", u"id": u"thing--a",
         u"link_ref": u"thing--gone", u"many_refs": []},
        {u"type": u"thing", u"id": u"thing--b",
         u"many_refs": [u"thing--gone"]},
    ]
    assert not _matches(u"[EXISTS thing:link_ref.name]", objects)
    assert not _matches(u"[EXISTS thing:many_refs[*].name]", objects)
    assert select_values(objects, u"thing", u"link_ref", ()) == {}
    assert select_values(objects, u"thing", u"many_refs", ()) == {}


def test_empty_array_selects_nothing():
    objects = [{u"type": u"thing", u"id": u"thing--a", u"items": []}]
    assert not _matches(u"[EXISTS thing:items[0]]", objects)
    assert not _matches(u"[EXISTS thing:items[*]]", objects)


def test_conjunction_requires_same_root_object():
    """Values pooled across roots would match; correct root identity must
    not.  This fails deterministically if root identity is lost."""
    objects = [
        {u"type": u"thing", u"id": u"thing--a", u"alpha": 1, u"num": 9},
        {u"type": u"thing", u"id": u"thing--b", u"alpha": 8, u"num": 2},
    ]
    # No single root has both alpha=1 and num=2.
    assert not _matches(u"[thing:alpha = 1 AND thing:num = 2]", objects)
    # Each disjunct holds on some root.
    assert _matches(u"[thing:alpha = 1]", objects)
    assert _matches(u"[thing:num = 2]", objects)
    # Same-root conjunction does hold.
    objects[0][u"num"] = 2
    assert _matches(u"[thing:alpha = 1 AND thing:num = 2]", objects)


# ---------------------------------------------------------------------------
# Property tests: generated + mutated paths vs. the oracle
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("seed", range(20))
def test_generated_paths_agree_with_oracle(seed):
    case = make_case(random.Random(seed))
    try:
        check_case(case)
    except CaseFailure as failure:
        _report_and_fail(seed, case, failure)


@pytest.mark.parametrize("seed", range(20))
def test_mutated_paths_agree_with_oracle(seed):
    rng = random.Random(1000 + seed)
    case = make_case(rng)
    for _ in range(4):
        case = mutate_case(rng, case)
        try:
            check_case(case)
        except CaseFailure as failure:
            _report_and_fail(seed, case, failure)


@pytest.mark.parametrize("seed", range(20))
def test_conjunctions_agree_with_oracle(seed):
    rng = random.Random(2000 + seed)
    objects = make_objects(rng)
    path1 = make_path(rng, objects)
    path2 = make_path(rng, objects)
    sel1 = _selected_scalars(select_values(objects, u"thing", *path1))
    sel2 = _selected_scalars(select_values(objects, u"thing", *path2))
    # Probe both present values (when any) and absent sentinels.
    probes = []
    if sel1 and sel2:
        probes.append((sel1[0], sel2[0]))
    probes.append((_SENTINEL_STR, sel2[0] if sel2 else _SENTINEL_INT))
    for val1, val2 in probes:
        try:
            check_conjunction(objects, u"thing", path1, path2, val1, val2)
        except CaseFailure as failure:
            case = Case(objects, u"thing", path1[0], path1[1])

            def conj_check(candidate):
                check_conjunction(candidate.objects, u"thing",
                                  path1, path2, val1, val2)

            shrunk = shrink(case, conj_check)
            pytest.fail(
                u"seed={} {}\nobjects={}".format(
                    seed, failure,
                    json.dumps(shrunk.objects, sort_keys=True)))
