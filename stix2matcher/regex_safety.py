"""
Conservative capability analysis for MATCHES/LIKE regular expressions.

CPython's :mod:`re` engine cannot be interrupted in the middle of a call.  A
wall-clock timer around the match therefore either cannot stop the regex, or
stops the caller while the engine keeps consuming CPU (if the regex runs in
another thread).  To keep a match's work budget honest, this module refuses
regexes whose worst-case execution is not tractable, *before* they are run.

The accepted subset is deliberately conservative and explainable:

* no backreferences, lookaround assertions, or conditional groups;
* no variable-length quantifier nested inside another quantifier;
* no quantified alternation whose branches can match the same leading text;
* no quantified subexpression which can match the empty string;
* bounded expansion and a bounded number of sequential unbounded quantifiers.

Accepted regexes are still potentially expensive (for example ``a*a*a*``), so
the matcher charges an upper-bound cost, based on the subject length and this
analysis, before calling :mod:`re`.  If that cost does not fit in the remaining
work budget, the regex is never executed.

Unsupported regexes raise :class:`stix2matcher.errors.UnsupportedRuleError`,
which names the offending construct and states the capability boundary.
"""

import warnings

from stix2matcher.errors import UnsupportedRuleError

with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    try:  # Python 3.11+
        from re import _constants as _C
        from re import _parser as _p
    except ImportError:  # pragma: no cover - older Pythons
        import sre_constants as _C
        import sre_parse as _p


# Constructs only present on newer Python versions (3.11+).  Keep the module
# importable on older Pythons, where these simply cannot occur in a parse tree.
_POSSESSIVE_REPEAT = getattr(_C, "POSSESSIVE_REPEAT", None)
_ATOMIC_GROUP = getattr(_C, "ATOMIC_GROUP", None)
_ANY_ALL = getattr(_C, "ANY_ALL", None)

#: Maximum static expansion of a regex (atoms times bounded repeat counts).
MAX_STATIC_COST = 1000000

#: Maximum number of sequential unbounded quantifiers (e.g. ``.*a.*a.*``).
#: Each one can multiply the engine's work by the subject length in the worst
#: case, so this caps the polynomial degree of accepted regexes.  Ten allows
#: realistic LIKE patterns (``'%a%b%c%'`` is four unbounded quantifiers) while
#: refusing patterns whose worst case grows too fast to bound usefully.  The
#: per-call charge below reflects the degree, so an expensive but accepted
#: regex still exhausts a bounded match before it is executed.
MAX_BACKTRACK_DEGREE = 10

_CAPABILITY = (
    u"Supported MATCHES/LIKE regular expressions use literals, character "
    u"classes, anchors, bounded groups, and non-nested quantifiers; "
    u"backreferences, lookaround, conditional groups, nested variable-length "
    u"quantifiers, and ambiguous quantified alternation are not supported."
)

class _AnyFirst(object):
    """Sentinel: the subexpression could start with any character."""

    __slots__ = ()

    def __repr__(self):
        return "<any>"


_ANY = _AnyFirst()


class RegexAnalysis(object):
    """Static facts about an accepted regex."""

    __slots__ = (
        "pattern", "static_cost", "backtrack_degree", "bounded_factor",
        "text_byte_safe",
    )

    def __init__(self, pattern, static_cost, backtrack_degree, bounded_factor,
                 text_byte_safe):
        self.pattern = pattern
        self.static_cost = static_cost
        self.backtrack_degree = backtrack_degree
        self.bounded_factor = bounded_factor
        # True if the pattern text can be encoded as a byte regex, preserving
        # the matcher's established binary-matching behaviour.
        self.text_byte_safe = text_byte_safe

    def estimated_call_cost(self, subject_length):
        """
        A conservative upper bound, in budget units, for one match attempt
        against a subject of the given length.
        """
        length = max(1, int(subject_length))
        cost = self.static_cost * self.bounded_factor
        # Each sequential unbounded quantifier contributes at most one factor
        # of the subject length to the worst case (see MAX_BACKTRACK_DEGREE).
        # This is charged before execution, so the regex engine is never
        # entered unless its upper bound fits in the remaining budget.
        for _ in range(max(1, self.backtrack_degree)):
            cost *= length
        return max(1, cost)


class _Prop(object):
    """Nullable-ness and possible first characters of a subexpression."""

    __slots__ = ("nullable", "firsts")

    def __init__(self, nullable, firsts):
        self.nullable = nullable
        self.firsts = firsts  # None means "any", else frozenset of ints


def analyze(pattern):
    """
    Parse and analyze a regex.

    :raises UnsupportedRuleError: if the regex is outside the supported,
        bounded-execution subset.
    :raises re.error: if the regex is syntactically invalid (preserved from
        the normal matcher behaviour).
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        tree = _p.parse(pattern)

    ctx = _Context(pattern)
    try:
        _analyze_seq(tree, ctx, depth=0, in_repeat=False, ignorecase=False)
    except RecursionError:
        raise UnsupportedRuleError(
            pattern,
            u"the pattern is nested too deeply to analyze",
            _CAPABILITY,
        )
    cost = _static_cost_seq(tree)
    if cost > MAX_STATIC_COST:
        raise UnsupportedRuleError(
            pattern,
            u"the pattern expands to at least {} tokens, above the limit of {}"
            .format(cost, MAX_STATIC_COST),
            _CAPABILITY,
        )
    if ctx.degree > MAX_BACKTRACK_DEGREE:
        raise UnsupportedRuleError(
            pattern,
            u"the pattern contains {} sequential unbounded quantifiers, above "
            u"the limit of {}".format(ctx.degree, MAX_BACKTRACK_DEGREE),
            _CAPABILITY,
        )
    return RegexAnalysis(
        pattern, cost, ctx.degree, ctx.bounded_factor,
        all(ord(c) < 256 for c in pattern),
    )


class _Context(object):
    __slots__ = ("pattern", "degree", "bounded_factor")

    def __init__(self, pattern):
        self.pattern = pattern
        self.degree = 0
        self.bounded_factor = 1


def _reject(ctx, reason, construct, position=None):
    reason = u"{} ({})".format(reason, construct) if construct else reason
    if position is not None:
        reason += u" at regex position {}".format(position)
    raise UnsupportedRuleError(ctx.pattern, reason, _CAPABILITY)


_REPEAT_OPS = tuple(
    op for op in (_C.MAX_REPEAT, _C.MIN_REPEAT, _POSSESSIVE_REPEAT)
    if op is not None
)


def _is_unbounded(hi):
    return hi == _C.MAXREPEAT or hi is None


def _is_variable_repeat(lo, hi):
    return _is_unbounded(hi) or hi != lo


def _is_repeating(lo, hi):
    return _is_unbounded(hi) or hi > 1


def _firsts_union(a, b):
    if a is _ANY or b is _ANY:
        return _ANY
    return a | b


def _firsts_overlap(a, b):
    if a is _ANY or b is _ANY:
        return True
    return bool(a & b)


def _char_class_firsts(items, ignorecase):
    if ignorecase:
        return _ANY
    result = set()
    for op, av in items:
        if op == _C.LITERAL:
            result.add(av)
        elif op == _C.RANGE:
            lo, hi = av
            if hi - lo <= 64:
                result.update(range(lo, hi + 1))
            else:
                return _ANY
        elif op == _C.NEGATE:
            return _ANY
        elif op == _C.CATEGORY:
            return _ANY
        else:
            # Unknown/future character class item: be conservative.
            return _ANY
    return frozenset(result)


def _analyze_seq(seq, ctx, depth, in_repeat, ignorecase):
    nullable = True
    firsts = frozenset()
    saw_consuming = False

    for op, av in seq:
        prop = _analyze_node(op, av, ctx, depth, in_repeat, ignorecase)

        if nullable:
            firsts = _firsts_union(firsts, prop.firsts)
        if prop.firsts is not None and not prop.nullable:
            saw_consuming = True
        nullable = nullable and prop.nullable

    if not saw_consuming and nullable:
        # Only anchors/empty constructs: no possible first characters.
        firsts = frozenset()
    return _Prop(nullable, firsts)


def _analyze_node(op, av, ctx, depth, in_repeat, ignorecase):
    if op == _C.LITERAL:
        if ignorecase:
            return _Prop(False, _ANY)
        return _Prop(False, frozenset((av,)))

    if op == _C.NOT_LITERAL:
        return _Prop(False, _ANY)

    if op == _C.ANY or (_ANY_ALL is not None and op == _ANY_ALL):
        return _Prop(False, _ANY)

    if op == _C.IN:
        return _Prop(False, _char_class_firsts(av, ignorecase))

    if op == _C.CATEGORY:
        return _Prop(False, _ANY)

    if op == _C.AT:
        return _Prop(True, frozenset())

    if op == _C.SUBPATTERN:
        _group, add_flags, _del_flags, body = av
        child_ignorecase = ignorecase or bool(add_flags & _C.SRE_FLAG_IGNORECASE)
        return _analyze_seq(
            body, ctx, depth, in_repeat, child_ignorecase
        )

    if _ATOMIC_GROUP is not None and op == _ATOMIC_GROUP:
        return _analyze_seq(av, ctx, depth, in_repeat, ignorecase)

    if op in _REPEAT_OPS:
        lo, hi, body = av
        label = _op_name(op)

        if op in (_C.MAX_REPEAT, _C.MIN_REPEAT) and _is_variable_repeat(lo, hi):
            if depth > 0:
                _reject(
                    ctx,
                    u"variable-length quantifier is nested inside another "
                    u"quantifier, which can cause exponential backtracking",
                    label,
                )
        if _is_unbounded(hi):
            ctx.degree += 1

        # A repeat with a one-occurrence bound is just grouping; it cannot
        # amplify backtracking.
        if _is_repeating(lo, hi):
            body_prop = _analyze_seq(
                body, ctx, depth + 1, True, ignorecase
            )
            if body_prop.nullable:
                _reject(
                    ctx,
                    u"quantified subexpression can match the empty string",
                    label,
                )
            if not _is_unbounded(hi) and hi > 1:
                ctx.bounded_factor = _bound_mul(ctx.bounded_factor, hi)
        else:
            body_prop = _analyze_seq(
                body, ctx, depth, in_repeat, ignorecase
            )

        # Repeat is nullable if it can match zero times, or its body is
        # nullable (already rejected for repeating bodies).
        nullable = (lo == 0) or body_prop.nullable
        firsts = body_prop.firsts if hi != 0 else frozenset()
        return _Prop(nullable, firsts)

    if op == _C.BRANCH:
        _unused, alternatives = av
        props = [
            _analyze_seq(alt, ctx, depth, in_repeat, ignorecase)
            for alt in alternatives
        ]
        nullable = any(p.nullable for p in props)

        if in_repeat:
            # A quantified alternation is only safe when the branches are
            # unambiguously distinguishable.  An empty branch (as produced by
            # the parser when alternatives share a prefix, e.g. (a|aa)) or
            # overlapping leading characters means the engine may retry the
            # same input split, which is the classic exponential case.
            ambiguous = any(prop.nullable for prop in props)
            for i in range(len(props)):
                for j in range(i + 1, len(props)):
                    if _firsts_overlap(props[i].firsts, props[j].firsts):
                        ambiguous = True
            if ambiguous:
                _reject(
                    ctx,
                    u"quantified alternation is ambiguous: its branches can "
                    u"match the same text",
                    u"alternation",
                )

        firsts = frozenset()
        for prop in props:
            firsts = _firsts_union(firsts, prop.firsts)
        return _Prop(nullable, firsts)

    if op == _C.GROUPREF:
        _reject(
            ctx,
            u"backreferences are not supported because their execution cannot "
            u"be bounded",
            u"backreference",
        )

    if op == _C.GROUPREF_EXISTS:
        _reject(
            ctx,
            u"conditional groups are not supported",
            u"conditional group",
        )

    if op in (_C.ASSERT, _C.ASSERT_NOT):
        _reject(
            ctx,
            u"lookaround assertions are not supported because their execution "
            u"cannot be bounded",
            u"lookaround",
        )

    if op == _C.SUCCESS:
        return _Prop(True, frozenset())

    if op == _C.FAILURE:
        return _Prop(False, frozenset())

    # Unknown node type: refuse rather than guess about its cost.
    _reject(
        ctx,
        u"unsupported regular expression construct",
        _op_name(op),
    )


def _bound_mul(a, b):
    product = a * b
    if product > MAX_STATIC_COST:
        return MAX_STATIC_COST + 1
    return product


def _bound_add(a, b):
    total = a + b
    if total > MAX_STATIC_COST:
        return MAX_STATIC_COST + 1
    return total


def _static_cost_seq(seq, ignorecase=False):
    total = 0
    for op, av in seq:
        total = _bound_add(total, _static_cost_node(op, av, ignorecase))
        if total > MAX_STATIC_COST:
            return total
    return max(1, total)


def _static_cost_node(op, av, ignorecase=False):
    if op in _REPEAT_OPS:
        lo, hi, body = av
        body_cost = _static_cost_seq(body, ignorecase)
        if _is_unbounded(hi):
            factor = 1
        else:
            factor = max(1, hi)
        return _bound_add(1, _bound_mul(body_cost, factor))

    if op == _C.BRANCH:
        _unused, alternatives = av
        total = 1
        for alt in alternatives:
            total = _bound_add(
                total, _static_cost_seq(alt, ignorecase)
            )
        return total

    if op == _C.SUBPATTERN:
        _group, add_flags, _del_flags, body = av
        child_ignorecase = ignorecase or \
            bool(add_flags & _C.SRE_FLAG_IGNORECASE)
        return _bound_add(
            1, _static_cost_seq(body, child_ignorecase)
        )

    if _ATOMIC_GROUP is not None and op == _ATOMIC_GROUP:
        return _bound_add(1, _static_cost_seq(av, ignorecase))

    if op == _C.IN:
        return _bound_add(1, len(av))

    return 1


def _op_name(op):
    return getattr(op, "name", None) or u"{}".format(op)
