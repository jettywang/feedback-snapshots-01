Extension function revocation and in-flight query handoff
=========================================================

The revocation support lives in :mod:`jmespath.policy` and is wired through
:class:`jmespath.visitor.TreeInterpreter`.  It only governs *custom extension*
functions supplied through ``Options(custom_functions=...)``; the built-in
JMESPath functions bypass the policy and are never gated or audited.

Public surface
--------------

* ``jmespath.Policy(allowed=[...], default_allowed=True)`` - thread-safe
  allow/revoke registry.  ``allow``/``revoke`` return a monotonic
  ``revision`` that only increases when a decision actually changes.
* ``jmespath.AuditLog`` - append-only record of ``search_start``,
  ``function_check``, ``search_completed`` and ``search_cancelled`` events.
* ``jmespath.ExtensionRevokedError`` - carries ``function_name``,
  ``checkpoint`` (``function_entry`` or ``deferred_expression``) and
  ``revision``.
* ``jmespath.search(..., policy=, audit=, query_id=)`` and
  ``ParsedResult.search(..., policy=, audit=, query_id=)``.

Handoff rules
-------------

Each search captures an immutable snapshot of the policy when it starts and
records its revision on the ``search_start`` event.  Where a revocation lands
decides what happens:

1. **Before the search enters the function.** The entry check consults the
   entry snapshot, sees the function is no longer allowed, raises
   ``ExtensionRevokedError(checkpoint="function_entry")`` and emits
   ``search_cancelled``.  The function body never runs and no partial result
   is published.
2. **After the function has started.** A body already executing keeps running
   under the entry snapshot; the search reaches ``search_completed`` and
   returns its normal result.  The revocation only affects later calls.
3. **When a deferred expression reference is about to run.** The ``&expr``
   arguments of higher order functions (``map``, ``sort_by``, ...) are
   evaluated later.  Every function reached from such a reference is
   re-authorized against the *live* policy, so a revocation that lands in
   this window raises ``checkpoint="deferred_expression"`` and cancels the
   search before that nested function body is entered.

The next request always takes a fresh snapshot and therefore observes the
current revision.  Whether an in-flight query kept running, what result it
produced and which revision it used must be read from the AuditLog rather than
from in-memory state.

Shared compilation
------------------

The parser caches compiled expressions independently of the policy. Revoking a
function never purges the cache: a cached extension expression is simply
denied on its next search, while cached expressions that do not use the
extension continue to evaluate normally. The per-interpreter authorization
gate is installed on a copy of the custom ``Functions`` object, so a shared
``Functions`` instance is never mutated and can be reused across searches.

Demo and tests
--------------

* ``python policy_handoff/demo.py`` runs the threaded acceptance scenario and
  exits non-zero if any check fails.
* ``python -m pytest tests/test_policy_handoff.py`` covers the three
  checkpoints, revision handoff and compiled-result reuse.
