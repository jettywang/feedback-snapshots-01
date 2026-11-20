Revocation Plans
================

.. contents::
   :local:
   :depth: 1

Vault's lease endpoints are blunt. ``sys/leases/revoke-prefix`` removes every
lease under a prefix, and ``sys/leases/revoke-force`` does the same while
ignoring backend errors. For incident response, ``client.sys.revocation``
provides a small approval gate:

1. create a plan and inspect the namespace and scope;
2. obtain an explicit, named approval bound to that plan;
3. execute the approved plan, or fail closed before sending a revoke request.

Create a Plan
-------------

``create_plan`` performs only lookups. It records the client's actual
``X-Vault-Namespace``, the requested lease IDs and prefixes, and the leases
currently visible below each prefix.

.. code:: python

    plan = client.sys.revocation.create_plan(
        lease_ids=['database/creds/app/AbCdEf'],
        prefixes=['database/creds/app'],
        ttl='10m',
    )
    print(plan.describe())

The output is the evidence attached to the approval request::

    Revocation plan 1f0d...
      namespace: team-a
      mode: prefix+lease
      prefixes: database/creds/app
      lease IDs: database/creds/app/AbCdEf
      observed scope (2):
        - database/creds/app/AbCdEf
        - database/creds/app/GhIjKl
      created_at: 2026-11-21T10:00:00+00:00
      expires_at: 2026-11-21T10:10:00+00:00
      approved: False
      fingerprint: 5e2c...

``plan.summary()`` returns the same facts as a dict, including
``namespace_header``, ``scope_count``, ``expires_in_seconds`` and the
``dangerous`` flag. Plans never call a revoke endpoint.

Force Revocation Is Explicit
----------------------------

``force`` defaults to ``False`` and only applies to prefixes. Selecting it
changes the execution endpoint and is called out in the plan:

.. code:: python

    plan = client.sys.revocation.create_plan(
        prefixes=['database/creds/app'],
        force=True,
    )
    assert plan.summary()['dangerous'] is True
    assert plan.summary()['mode'] == 'force'

Do not infer force from the incident type or from a retry; it must be chosen
when the plan is created and is included in the approval fingerprint.

Approve One Exact Plan
----------------------

Approval is bound to the plan fingerprint (namespace, targets, force flag and
observed scope). An approved copy is returned; the original is unchanged.
Re-approving is rejected so the audit trail has one named sign-off per plan.

.. code:: python

    approved = client.sys.revocation.approve_plan(
        plan,
        approver='oncall-alice',
        note='INC-4242',
    )

Execute
-------

``execute_plan`` checks, before the first revoke request, that:

- the plan is approved and the approval fingerprint matches;
- the plan contents still hash to the same fingerprint;
- the plan has not expired;
- the client's current namespace matches the approved namespace;
- the prefix scope still matches the approved snapshot.

Any failure raises a distinct exception and sends zero revocation requests.
On success the returned ``RevocationReceipt`` lists every target and outcome.

.. code:: python

    receipt = client.sys.revocation.execute_plan(approved)
    print(receipt.state)  # 'succeeded'
    print(receipt.to_dict())

Expiry
------

A plan expires after ``ttl`` (default 15 minutes). Expired plans cannot be
approved or executed:

.. code:: python

    plan = client.sys.revocation.create_plan(prefixes=['database/creds/app'], ttl='1m')
    # after the minute passes
    client.sys.revocation.execute_plan(plan)
    # hvac.exceptions.RevocationPlanExpired: ...; no revocation request was sent

Create a new plan and a new approval if the work is still needed.

Scope or Namespace Changed
--------------------------

The observed scope is part of the approval. If a lease appears or disappears
under the approved prefix after sign-off, execution refuses with
``RevocationPlanScopeChanged``. If the client is pointed at another namespace,
execution refuses with ``RevocationPlanNamespaceChanged``. Both failures send
zero revoke requests.

.. code:: python

    evidence = client.sys.revocation.readback(approved)
    print(evidence['namespace'], evidence['changed'])
    print(evidence['added'], evidence['removed'])

``readback`` is read-only and also returns ``lease_states`` with
``present``/``missing``/``unknown`` for each exact lease ID.

Transport Failure: Unknown Outcome
----------------------------------

If a revoke request fails in transport, or Vault returns a 5xx response, hvac
raises ``RevocationOutcomeUnknown``. The request is **not retried**: Vault may
already have applied it. The exception carries a partial receipt and the
on-call checks:

.. code:: python

    try:
        client.sys.revocation.execute_plan(approved)
    except exceptions.RevocationOutcomeUnknown as exc:
        print(exc.receipt.to_dict())
        for step in exc.verification_steps:
            print(step)

The check sequence is:

1. do not retry automatically;
2. run ``readback`` and compare the current scope with the approved scope;
3. check the Vault audit device for ``sys/leases/revoke*`` entries at the
   request time;
4. check the target secrets engine or credential store for the credential;
5. only if the scope is unchanged and no audit entry exists, create a new plan
   and obtain new approval before retrying.

A 4xx response is different: it is reported as ``rejected`` and produces a
``RevocationFailed`` receipt with ``partial`` or ``failed`` state, because
Vault explicitly refused that target.

API Reference
-------------

.. automethod:: hvac.api.system_backend.Revocation.create_plan
   :noindex:

.. automethod:: hvac.api.system_backend.Revocation.approve_plan
   :noindex:

.. automethod:: hvac.api.system_backend.Revocation.execute_plan
   :noindex:

.. automethod:: hvac.api.system_backend.Revocation.readback
   :noindex:

.. automethod:: hvac.api.system_backend.Revocation.verification_steps
   :noindex:
