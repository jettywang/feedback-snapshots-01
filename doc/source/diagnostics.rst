=====================
Request diagnostics
=====================

When an OpenStack call fails, the material handed to another team usually
has to answer three questions in order: *which catalog entry was selected*,
*did the session re-authenticate*, and *what was the final error*.  It must
also not disclose credentials or internal addresses that were not approved
for sharing.

keystoneauth1 records this as a single :class:`~keystoneauth1.diagnostics.
RequestDiagnostic`.  One record spans the whole logical request, including
redirects, retries and the re-authentication exchange, and it can render two
views of the same data.

Approved switches
-----------------

What the shareable view may contain is decided by independent switches on a
:class:`~keystoneauth1.diagnostics.DiagnosticPolicy`:

.. code-block:: python

   from keystoneauth1 import diagnostics
   from keystoneauth1 import session

   policy = diagnostics.DiagnosticPolicy(
       service_name=True,     # catalog service names
       endpoint=True,         # catalog and request addresses
       user_token=False,      # Authorization / X-Auth-Token / X-Subject-Token
       service_token=False,   # X-Service-Token
       private_markers=('a-fictional-value',),
   )
   sess = session.Session(auth=auth, diagnostic_policy=policy)

``service_name``, ``endpoint``, ``user_token`` and ``service_token`` are
approved separately, so a dual-token request can reveal one identity side
without the other.  Anything not approved is replaced by a stable
``{SHA256}...`` digest rather than being dropped, which keeps correlation
without revealing the value.  ``private_markers`` are scrubbed from every
public string and their digests are reported in the export.

The same policy applies everywhere a formatted record is produced: debug
logging, the diagnostic attached to exceptions, and the intermediate
responses captured during retries and redirects.

Public and internal views
-------------------------

Pass a record to :meth:`~keystoneauth1.session.Session.request` to populate
it explicitly, or let the session create one and attach it to a raised
exception:

.. code-block:: python

   from keystoneauth1 import diagnostics

   record = diagnostics.RequestDiagnostic(policy=sess.diagnostic_policy)
   try:
       sess.get('servers', endpoint_filter={'service_type': 'compute'},
                diagnostic=record)
   except Exception as exc:
       shareable = exc.diagnostic.public_view()
       internal = exc.diagnostic.internal_view()

``public_view()`` is the export that can leave the team.  It keeps the
``request_id``, the stage order and the approval switches, and withholds
everything else.  ``internal_view()`` is the unredacted counterpart for
controlled debugging: it carries the same ``request_id`` so a digest in the
public export can be matched back to the real value.

Both views set ``request_kind`` to ``standard`` or ``dual-token``, so a
normal request is distinguishable from one that also carries a service
identity.

Configuration
-------------

The session loader exposes the switches as CLI and ``oslo.config`` options:
``--diagnostic-show-service-name``, ``--diagnostic-show-endpoint``,
``--diagnostic-show-user-token``, ``--diagnostic-show-service-token`` and
``--diagnostic-private-marker`` (repeatable).
