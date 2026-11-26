Fair per-source queue quotas
============================

The batch processor buffers telemetry from every service running in a process
in a single queue. A service that emits a burst of telemetry can fill that queue
and crowd out important signals from other services, such as security alerts.

This example configures the ``BatchSpanProcessor`` with per-source fair quotas
keyed by the telemetry ``service.name`` resource attribute:

- ``max_queue_size`` remains the hard memory limit and is always enforced;
- a source may borrow the unused quota reservations of idle sources;
- when an idle source resumes, its reservation is visibly reclaimed and
  over-quota items from other sources are rejected with the
  ``fair_quota_exceeded`` drop reason;
- ``force_flush`` and shutdown preserve the global receive order and every
  rejection is recorded per source with a reason.

The script pauses a custom in-memory exporter twice. During the first pause only
a noisy service produces and borrows the idle capacity. During the second pause
the noisy service and a slower security service produce at different speeds,
showing how the security alerts keep their reserved capacity.

Configuration
-------------

Quotas are passed through the ``fair_quotas`` keyword argument or the
``OTEL_BSP_FAIR_QUOTAS`` / ``OTEL_BLRP_FAIR_QUOTAS`` environment variables as a
JSON object, for example::

    OTEL_BSP_FAIR_QUOTAS='{"noisy-service": 6, "security-service": 4}'

The source key can be customized with the ``source_key_extractor`` argument.

Run the Example
---------------

.. code-block:: sh

    python docs/examples/fair-quotas/fair_quota_example.py
