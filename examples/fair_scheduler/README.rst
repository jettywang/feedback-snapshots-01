=========================================
Bounded Fair HTTP/2 Send Scheduling
=========================================

This example layers a *bounded, fair response scheduler* on top of the public
``h2`` API without modifying the protocol stack.  It answers one question:
when one authenticated user keeps raising HTTP/2 priority, how does a server
stop that user from consuming everyone else's response bandwidth?

The short answer: client priority never grants bandwidth.  All scheduling quota
comes from the server's authenticated context; the client's weight is only a
hint used *within* that user's own group of streams.

Files
-----

``auth.py``
    Server-side :class:`~auth.Principal` objects and the :class:`~auth.AuthDirectory`
    that maps a request's bearer token to a fixed, operator-provisioned budget.
    This is the *only* source of scheduling quota.

``scheduler.py``
    :class:`~scheduler.BoundedSendScheduler`, a two-level Deficit Round Robin
    queue with bounded buffering, cycle detection and rate-limited priority.

``transport.py``
    An in-memory loopback (:class:`~transport.H2Link`) wiring two **real**
    ``H2Connection`` objects together, plus the server harness that feeds
    requests, resets and priority frames to the scheduler.

``demo.py``
    Three scenarios driven over real h2 frames, plus the metrics they record.

``test_fair_scheduler.py``
    Guarantee tests (pytest) asserting the properties rather than printing them.

What is enforced
----------------

1. **Authenticated quota is the hard cap.** Each principal gets a fixed byte
   quantum per DRR turn.  Opening more streams, raising weights or forging
   dependencies cannot increase it.  Two principals with equal quota receive
   equal long-run bytes regardless of stream count.

2. **Priority is group-local and advisory.** A stream's client weight only
   distributes its owning principal's existing quantum among that principal's
   own streams.  Weights are clamped to ``1..256``, updates are rate limited
   per stream, dependencies cannot cross a principal's group, and dependency
   cycles are detected and reparented to the root.

3. **Flow control is always honoured.** A chunk is emitted only when both the
   real h2 connection window and the stream window admit it.  A zero window, a
   reset stream, or a producer with no data simply skips that stream for the
   round; it never blocks the other subjects.

4. **Buffering is bounded.** Each principal has a per-principal pending cap and
   there is a global cap; producers are never pulled past the free space.  The
   number of live streams per principal is also capped.

Demonstration
-------------

Run the scenarios::

    python -m examples.fair_scheduler.demo

Run the guarantee tests::

    python -m pytest examples/fair_scheduler/test_fair_scheduler.py

The scenarios use two real authenticated principals (``alice`` and ``bob``):

* **Proportional share** -- alice fans out across eight streams (four weighted
  200, four weighted 25) while bob uses one weight-1 stream.  Both principals
  still get exactly 50% of the bytes; inside alice's group the weighted streams
  receive roughly 8x the low-weight ones, showing the hint still works locally.

* **Attack lower bound** -- alice opens 32 streams, arranges them in a ring of
  dependency cycles, and flaps their weights far past the update cap, against
  bob's single victim stream.  The cycles are broken, the flapping is capped,
  and the victim retains ~50% of all bytes -- the lower-bound guarantee.

* **Liveness** -- one stream's flow-control window is deliberately exhausted and
  never replenished, one stream is reset mid-flight, and one producer stalls.
  Each affects only its own stream; the healthy streams keep receiving service,
  and the metrics record the exact waiting rounds and their causes
  (``window`` / ``quota`` / ``starved``).

Why this is not "ignore flow control"
-------------------------------------

A naive "fair" demo can look perfectly balanced only by sending bytes without
consulting h2 windows.  Here every byte passes through
``H2Connection.send_data`` after a real ``local_flow_control_window`` check, so
the connection and stream windows are genuine hard limits.  The scheduler
records *waiting rounds* precisely because correctly respecting a zero window
means a ready stream sometimes cannot send -- fairness is measured across those
waits, not by pretending the limits do not exist.
