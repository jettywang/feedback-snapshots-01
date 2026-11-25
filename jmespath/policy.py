"""Per-caller capabilities for JMESPath extension functions.

Built-in JMESPath functions are part of the language and are never affected
by a policy.  Only functions registered by a ``Functions`` subclass can be
allowed or denied.  The gate is consulted before an argument expression is
evaluated, so a denied outer call cannot cause another (possibly allowed)
extension to run as a side effect of resolving its arguments.  Deferred
``&expr`` references run under the same caller policy as the search that
created them.
"""

import threading

from jmespath import exceptions


class FunctionPermissionError(exceptions.JMESPathError):
    """Raised when a caller may not use an extension function.

    ``path`` is the chain of function names from the outermost function
    expression to the denied function, for example ``('outer', 'inner')``.
    ``checkpoint`` is ``'function_entry'`` when the call has not started or
    ``'expression_reference'`` when a deferred ``&expr`` was about to call it.
    """

    def __init__(self, function_name, path, checkpoint='function_entry'):
        self.function_name = function_name
        self.path = tuple(path)
        self.checkpoint = checkpoint
        self.outer_function = (
            self.path[-2] if len(self.path) > 1 else None)
        super(FunctionPermissionError, self).__init__(
            self.function_name, self.path, self.checkpoint)

    def __str__(self):
        if self.outer_function is None:
            location = ''
        else:
            location = ' (reached from %s())' % self.outer_function
        return (
            'Function %s() is not permitted for this caller at the %s '
            'checkpoint%s' % (
                self.function_name, self.checkpoint, location))


class _FunctionPolicySnapshot(object):
    """Immutable capability view captured at the start of one search."""

    __slots__ = ('revision', 'default_allowed', '_decisions')

    def __init__(self, revision, decisions, default_allowed):
        self.revision = revision
        self.default_allowed = default_allowed
        self._decisions = dict(decisions)

    def is_allowed(self, function_name):
        return self._decisions.get(function_name, self.default_allowed)


class FunctionPolicy(object):
    """An allow/deny list for extension functions.

    A service can keep one policy per caller and pass it through
    ``jmespath.Options(function_policy=...)``.  Because the options are
    supplied at search time, two callers can reuse one compiled expression
    while having different capabilities.

    Every search takes a fresh snapshot.  A policy may therefore be changed
    between searches without affecting a search that is already running.
    """

    def __init__(self, allowed=(), default_allowed=False):
        self._lock = threading.RLock()
        self._decisions = dict((name, True) for name in allowed)
        self._revision = 0
        self.default_allowed = default_allowed

    @property
    def revision(self):
        with self._lock:
            return self._revision

    def allow(self, function_name):
        with self._lock:
            if not self._decisions.get(function_name, False):
                self._decisions[function_name] = True
                self._revision += 1
            return self

    def deny(self, function_name):
        with self._lock:
            if self._decisions.get(function_name, True):
                self._decisions[function_name] = False
                self._revision += 1
            return self

    def is_allowed(self, function_name):
        with self._lock:
            return self._decisions.get(
                function_name, self.default_allowed)

    def snapshot(self):
        with self._lock:
            return _FunctionPolicySnapshot(
                self._revision, self._decisions, self.default_allowed)


def coerce_policy(policy):
    """Normalize an allow-list iterable into a :class:`FunctionPolicy`."""
    if policy is None or hasattr(policy, 'snapshot'):
        return policy
    if isinstance(policy, str):
        raise TypeError(
            'function_policy must be a FunctionPolicy or an iterable of '
            'function names, not a string')
    return FunctionPolicy(allowed=policy)
