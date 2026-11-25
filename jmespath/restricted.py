"""Restricted JMESPath queries driven by source-field visibility.

This module is an intentionally small, independent entry point for the
reporting backend use case: business users author their own JMESPath views,
but what they are allowed to see is decided by the *data source fields*, not
by the names the expression happens to project.

The guarantee is provided by substitution rather than by output filtering.
Before an expression is evaluated, every source field that the
:class:`VisibilityPolicy` marks as restricted is replaced with JSON ``null``
on a deep copy of the data.  The expression then runs through the ordinary,
unmodified JMESPath interpreter.  Because the substituted value is always the
same constant regardless of the real value, two documents that differ only in
their restricted fields produce byte-identical external results.  A restricted
field may therefore still participate in a filter or in a sort key without its
value being inferable from which rows come back or from their order.

The regular :func:`jmespath.search` / :func:`jmespath.compile` entry points
are not changed; an expression that only touches public fields keeps exactly
its existing behavior.
"""
import jmespath


# Trie terminal marker.  A trie node is either a nested ``dict`` (more path
# segments may follow) or maps a field name to this sentinel (the field and
# everything below it are restricted).  The marker is not a string, so it can
# never collide with a real JSON field name.
_DENIED = object()


class VisibilityPolicy(object):
    """Field-level visibility policy for a data source.

    Visibility is expressed as a collection of dotted source-field paths that
    are restricted, for example ``"employees.salary"`` or ``"dept.budget"``.
    List indices are implicit: a path segment that lands on a list applies to
    every element of that list.  Restricting a field restricts the whole
    subtree below it, so denying ``"dept"`` hides ``dept`` entirely even if a
    more specific path such as ``"dept.budget"`` is also listed.
    """

    def __init__(self, restricted_fields=()):
        if isinstance(restricted_fields, str):
            restricted_fields = (restricted_fields,)
        self._restricted_paths = []
        # A nested dict trie of the restricted paths.
        self._trie = {}
        for spec in restricted_fields:
            path = self._normalize_path(spec)
            self._restricted_paths.append(path)
            self._add_path(self._trie, path)

    @staticmethod
    def _normalize_path(spec):
        if not isinstance(spec, str) or not spec.strip():
            raise ValueError(
                "restricted field paths must be non-empty strings, "
                "got: %r" % (spec,))
        parts = tuple(spec.split('.'))
        if any(part == '' for part in parts):
            raise ValueError(
                "restricted field path %r contains an empty segment" % spec)
        return parts

    def _add_path(self, trie, path):
        node = trie
        for segment in path[:-1]:
            existing = node.get(segment)
            if existing is _DENIED:
                # A parent field is already fully restricted; this more
                # specific path adds nothing.
                return
            if not isinstance(existing, dict):
                existing = {}
                node[segment] = existing
            node = existing
        last = path[-1]
        # Restricting the field hides the entire subtree below it.
        node[last] = _DENIED

    def restricted_paths(self):
        """Return the normalized restricted paths as tuples of field names."""
        return list(self._restricted_paths)


def redact(data, policy):
    """Return a deep copy of ``data`` with restricted fields set to ``null``.

    Only the values of restricted fields change; their keys, the surrounding
    structure and the order of arrays and objects are preserved.  The original
    ``data`` object is never mutated.
    """
    if not isinstance(policy, VisibilityPolicy):
        raise TypeError(
            "policy must be a VisibilityPolicy, got: %r" % type(policy))
    return _redact(data, policy._trie)


def _redact(node, trie):
    if isinstance(node, dict):
        result = type(node)()
        for key, value in node.items():
            next_trie = trie.get(key)
            if next_trie is _DENIED:
                result[key] = None
            elif isinstance(next_trie, dict):
                result[key] = _redact(value, next_trie)
            else:
                # Not restricted: recurse with an empty trie so the value is
                # still deep-copied and shares nothing with the input.
                result[key] = _redact(value, {})
        return result
    if isinstance(node, list):
        # List positions are implicit; the same policy applies to each item.
        return [_redact(item, trie) for item in node]
    # Scalars (str, int, float, bool, None) are immutable JSON values and can
    # be shared safely.
    return node


def restricted_search(expression, data, policy, options=None):
    """Evaluate ``expression`` against visibility-filtered ``data``.

    This is the restricted counterpart of :func:`jmespath.search`.  The data
    is redacted according to ``policy`` before the expression runs, so the
    result can never expose a restricted value regardless of how the
    expression renames, projects, merges, filters or sorts the data.
    """
    sanitized = redact(data, policy)
    return jmespath.search(expression, sanitized, options=options)


class RestrictedExpression(object):
    """A compiled JMESPath expression bound to a :class:`VisibilityPolicy`."""

    def __init__(self, parsed, policy):
        self._parsed = parsed
        self._policy = policy

    def search(self, data, options=None):
        sanitized = redact(data, self._policy)
        return self._parsed.search(sanitized, options=options)


def compile_restricted(expression, policy):
    """Compile ``expression`` and bind it to ``policy`` for repeated use."""
    if not isinstance(policy, VisibilityPolicy):
        raise TypeError(
            "policy must be a VisibilityPolicy, got: %r" % type(policy))
    return RestrictedExpression(jmespath.compile(expression), policy)
