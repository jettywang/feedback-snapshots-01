"""Runtime permission policy for JMESPath extension functions.

This module lets a service revoke the permission to use a custom extension
function while searches may already be running.  The rules are deliberately
split by *when* the revocation becomes observable:

* A search captures an immutable :class:`PolicySnapshot` when it starts.
  Every function that the search enters directly is authorized against that
  snapshot, so a function which has already been entered is allowed to run to
  completion even if the permission is revoked afterwards.
* A deferred expression reference (the ``&foo`` arguments of higher order
  functions such as ``map`` or ``sort_by``) is evaluated later, potentially
  after the permission changed.  Each deferred evaluation is therefore
  authorized against the *live* policy instead of the entry snapshot.
* New searches always take a fresh snapshot, so the next request observes the
  current revision of the rules.

Every decision is appended to an :class:`AuditLog`.  The handoff for an
in-flight query is meant to be reconstructed from those records rather than
from in-memory state.
"""
import threading
import time

from jmespath.exceptions import JMESPathError


class ExtensionRevokedError(JMESPathError):
    """Raised when an extension function is no longer permitted.

    ``checkpoint`` is either ``"function_entry"`` (the search had not entered
    the function yet) or ``"deferred_expression"`` (a deferred expression
    reference was about to evaluate the function).
    """

    def __init__(self, function_name, checkpoint, revision):
        self.function_name = function_name
        self.checkpoint = checkpoint
        self.revision = revision
        message = (
            "Extension function %s() is not permitted at the %s checkpoint "
            "(policy revision %s)" % (function_name, checkpoint, revision)
        )
        super(ExtensionRevokedError, self).__init__(message)


class PolicySnapshot(object):
    """Immutable authorization state captured when a search starts."""

    __slots__ = ('revision', 'default_allowed', '_decisions')

    def __init__(self, revision, decisions, default_allowed):
        self.revision = revision
        self.default_allowed = default_allowed
        self._decisions = dict(decisions)

    def is_allowed(self, function_name):
        return self._decisions.get(function_name, self.default_allowed)


class Policy(object):
    """Thread-safe allow/revoke registry for extension functions.

    Each material change bumps a monotonic ``revision``.  ``default_allowed``
    controls the decision for extension names the policy does not manage;
    managed names carry an explicit decision.
    """

    def __init__(self, allowed=(), default_allowed=True):
        self._lock = threading.RLock()
        self._revision = 0
        self._decisions = dict((name, True) for name in allowed)
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
            return self._revision

    def revoke(self, function_name):
        with self._lock:
            if self._decisions.get(function_name, False):
                self._decisions[function_name] = False
                self._revision += 1
            return self._revision

    def is_allowed(self, function_name):
        with self._lock:
            return self._decisions.get(function_name, self.default_allowed)

    def snapshot(self):
        with self._lock:
            return PolicySnapshot(
                self._revision, self._decisions, self.default_allowed)


class AuditLog(object):
    """Append-only, thread-safe record of policy decisions and query status."""

    def __init__(self):
        self._lock = threading.Lock()
        self._seq = 0
        self._records = []

    def record(self, **event):
        with self._lock:
            self._seq += 1
            event = dict(event)
            event['seq'] = self._seq
            event.setdefault('thread', threading.current_thread().name)
            event.setdefault('ts', time.monotonic())
            self._records.append(event)
            return event

    @property
    def records(self):
        with self._lock:
            return list(self._records)

    def for_query(self, query_id):
        with self._lock:
            return [dict(r) for r in self._records
                    if r.get('query_id') == query_id]
