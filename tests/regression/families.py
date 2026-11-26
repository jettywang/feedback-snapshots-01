"""Rewriting families with explicit, checked preconditions.

Each family answers:

1. ``applicable(doc)`` -- when the rewrite is sound for *this* document.
   The generator does not generate a shape it cannot prove safe, so the
   list-projection/null interaction is encoded here rather than assumed.
2. ``build(doc, rng)`` -- the (canonical, rewritten) pair.
3. ``level`` -- which criterion must hold (strict / equivalent / control).
"""

STRICT = "strict"          # value + access order + call order
EQUIVALENT = "equivalent"  # value + same branches + same call order
CONTROL = "control"        # must diverge (value or branch)


def _all_items_are_objects_with_a(doc):
    items = doc.get("items")
    if not isinstance(items, list):
        return False
    return all(isinstance(item, dict) and item.get("a") is not None
               for item in items)


def _all_items_are_objects(doc):
    # `items[*] | [*].a` differs from `items[*].a` only when the first
    # projection drops null elements before the second projection runs.
    items = doc.get("items")
    if not isinstance(items, list):
        return False
    return all(item is not None for item in items)


def _has_null_a_item(doc):
    items = doc.get("items")
    return isinstance(items, list) and any(
        not isinstance(item, dict) or item.get("a") is None
        for item in items)


class Family(object):
    def __init__(self, name, template, why, level, applicable):
        self.name = name
        self.template = template
        self.why = why
        self.level = level
        self.applicable = applicable

    def build(self, doc, rng):
        left, right = self.template(doc, rng)
        return left, right


def _redundant_parens(doc, rng):
    body = rng.choice(["a || b", "a && b", "items[*].a", "items[0].a",
                       "not_null(a, b)", "a == b"])
    return body, "(" + body + ")"


def _associativity(doc, rng):
    op = rng.choice(["||", "&&"])
    terms = "a %s b %s c" % (op, op)
    return terms, "(a %s b) %s c" % (op, op)


def _whitespace(doc, rng):
    # Layout only: spaces around dots, commas and binary operators.  We
    # deliberately do not touch `[?` because spaces there are a syntax
    # error, not a layout variant.
    body = rng.choice(["items[*].a", "a == b", "a || b",
                       "not_null(a, b)", "items[0].a", "items[?flag].a"])
    spaced = body.replace(".", " . ").replace(",", " , ")
    for operator in ("||", "&&", "==", "!="):
        spaced = spaced.replace(operator, " %s " % operator)
    rule = rng.choice(["  ", "\n  ", "\t"])
    spaced = spaced.replace(" ", rule)
    # A fresh logical line around the projection separator is also layout.
    if rng.chance(1, 2):
        spaced = spaced.replace(rule + ".", "\n" + rule + ".", 1)
    return body, spaced


def _grouped_subexpression(doc, rng):
    # Grouping the *base field* keeps the projection attached to it:
    # `(items)[*].a` parses exactly like `items[*].a`.  Grouping the whole
    # projection, `(items[*]).a`, is a subexpression and is deliberately
    # left to the contrast family below.
    base, tail = rng.choice([
        ("items", "[*].a"),
        ("items", "[0].a"),
        ("items", "[?flag].a"),
    ])
    return base + tail, "(" + base + ")" + tail


def _quoted_function_argument(doc, rng):
    # Single-quoted raw string literals may be laid out with spaces inside
    # the call; `probe('x', a)` and `probe( 'x' , a )` parse identically.
    body = "probe('%s', a)" % rng.choice(["x", "L", "p"])
    inner = body[len("probe("):-1]
    return body, "probe( " + inner.replace(",", " ,") + " )"


def _index_expression_to_pipe(doc, rng):
    # A standalone index expression does not start a projection, so the
    # chain and the pipe evaluate identically.
    return "items[0].a", "items[0] | a"


def _or_to_not_null(doc, rng):
    # Applicability guarantees `a` is absent or null: `a || b` falls
    # through to b, and `not_null(a, b)` does too, in the same order.
    return "a || b", "not_null(a, b)"


def _projection_to_map(doc, rng):
    # Applicability guarantees every element is an object with a present,
    # non-null `a`: the projection never drops a result, so it equals map.
    return "items[*].a", "map(&a, items)"


def _projection_to_pipe(doc, rng):
    # Applicability guarantees no null element is dropped by the first
    # projection, so the second `[*]` sees the same elements.
    return "items[*].a", "items[*] | [*].a"


def _comparator_swap(doc, rng):
    op = rng.choice(["==", "!="])
    return "a %s b" % op, "b %s a" % op


def _extra_branch_not_null(doc, rng):
    # `a` is truthy (non-null), so `a || probe(...)` short-circuits before
    # the second probe, while not_null() always evaluates both arguments.
    # Same JSON value, extra branch executed.
    return ("probe('L', a) || probe('R', b)",
            "not_null(probe('L', a), probe('R', b))")


def _contrast_or_and(doc, rng):
    # a truthy, b falsey: or returns a, and returns b.
    return "a || b", "a && b"


def _contrast_grouped_projection(doc, rng):
    # `(items[*]).a` is a subexpression: a field lookup on the *array*
    # just outside the projection, which produces a different value.
    return "items[*].a", "(items[*]).a"


def _contrast_projection_map_nulls(doc, rng):
    # At least one item has null/missing `a`: projection drops it, map keeps it.
    return "items[*].a", "map(&a, items)"


FAMILIES = [
    Family("grouped-subexpression", _grouped_subexpression,
           "grouping a field/index does not change the parsed node tree",
           STRICT,
           lambda doc: isinstance(doc.get("items"), list)),
    Family("quoted-argument-layout", _quoted_function_argument,
           "spaces inside a function call do not change the literal",
           STRICT,
           lambda doc: True),
    Family("redundant-parentheses", _redundant_parens,
           "extra grouping parses to the same AST", STRICT,
           lambda doc: True),
    Family("associativity", _associativity,
           "left associativity is the default parse", STRICT,
           lambda doc: True),
    Family("whitespace", _whitespace,
           "layout-only tokens do not change the AST", STRICT,
           lambda doc: True),
    Family("index-expression-pipe", _index_expression_to_pipe,
           "a standalone index expression chains like a pipe", STRICT,
           lambda doc: isinstance(doc.get("items"), list)),
    Family("or-to-not-null", _or_to_not_null,
           "a is null, so both forms fall through to b in the same order",
           STRICT,
           lambda doc: doc.get("a") is None and "b" in doc),
    Family("projection-to-map", _projection_to_map,
           "every item has a non-null `a`, so the projection never drops a "
           "result and equals map", STRICT,
           _all_items_are_objects_with_a),
    Family("projection-to-pipe", _projection_to_pipe,
           "no null item is dropped before the second projection",
           STRICT,
           _all_items_are_objects),
    Family("comparator-swap", _comparator_swap,
           "== / != are symmetric in value; the same two fields are read",
           EQUIVALENT,
           lambda doc: "a" in doc and "b" in doc),
    Family("extra-branch-not-null", _extra_branch_not_null,
           "a is truthy, so `||` skips the right probe while not_null runs it",
           CONTROL,
           lambda doc: doc.get("a") is not None and "b" in doc),
    Family("contrast-or-and", _contrast_or_and,
           "a truthy and b falsey: or yields a, and yields b",
           CONTROL,
           lambda doc: doc.get("a") is not None and
           doc.get("b") in (None, False, "", [], {})),
    Family("contrast-grouped-projection", _contrast_grouped_projection,
           "parenthesising the whole projection creates a subexpression",
           CONTROL,
           lambda doc: isinstance(doc.get("items"), list)),
    Family("contrast-projection-map-nulls", _contrast_projection_map_nulls,
           "a null item survives map but is dropped by the projection",
           CONTROL,
           _has_null_a_item),
]
