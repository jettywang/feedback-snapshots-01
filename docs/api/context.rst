opentelemetry.context package
=============================

OpenTelemetry context values are immutable snapshots. Functions such as
``set_value`` return a new ``Context`` object rather than mutating the
current one.

There are two common ways to use a context:

* Pass it explicitly to APIs that accept a ``context=...`` parameter.
* Attach it with ``context.attach`` so it becomes current for the
  current execution unit, then restore the previous context with
  ``context.detach``.

For example:

.. code-block:: python

   from opentelemetry import context

   ctx = context.set_value("key", "value")

   print(context.get_current().get("key"))
   # None

   token = context.attach(ctx)
   try:
       print(context.get_current().get("key"))
       # value
   finally:
       context.detach(token)

Optional runtime guard
----------------------

``opentelemetry.context.guard`` provides an opt-in wrapper around the context
runtime. It is meant for diagnosing asynchronous jobs that copy contexts: it
records who attached and detached a context token, and distinguishes invalid
tokens, duplicate releases and releases made while a task is being cancelled.
It never changes propagation, so synchronous, nested and parallel use keeps
working as before.

Enable it programmatically, or by setting :envvar:`OTEL_PYTHON_CONTEXT_GUARD`
to ``true`` before importing ``opentelemetry.context``:

.. code-block:: python

   from opentelemetry import context
   from opentelemetry.context import guard

   guard.enable()  # reads OTEL_PYTHON_CONTEXT_GUARD_LOG for log output

   with guard.diagnostics(correlation_id="req-42", phase="dispatch"):
       token = context.attach(ctx)
       context.detach(token)

   guard.disable()  # restores the wrapped runtime

Records are kept in memory on the guard (``guard.get_guard().records``). When
log output is enabled, log lines contain only the request correlation id and
the phase. Context values and baggage are never inspected or logged. Use
``GuardOutcome`` to tell normal releases (``DETACHED``) from releases made
during cancellation (``DETACHED_AFTER_CANCEL``), from tokens that were already
released (``DUPLICATE_DETACH``), from tokens owned by another task or context
(``FOREIGN_OWNER``, ``CROSS_CONTEXT``), and from attachments that were never
released (``RELEASED_BY_CANCEL``, ``ABANDONED``).

Module contents
---------------

.. automodule:: opentelemetry.context
   :members:
   :undoc-members:
   :show-inheritance:

.. automodule:: opentelemetry.context.guard
   :members: ContextGuardRecord, ContextRuntimeGuard, GuardOutcome, clear_diagnostics, current_diagnostics, current_owner, diagnostics, disable, enable, get_guard
   :show-inheritance:
