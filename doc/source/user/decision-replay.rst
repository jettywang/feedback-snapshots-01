=============================
Decision recording and replay
=============================

.. note::

   The ``oslo_policy.replay`` module is optional and opt-in. Importing
   it or constructing a recorder never changes how :meth:`Enforcer.enforce`
   behaves and writes nothing to disk; the calling service owns
   persistence of the returned evidence.

Why a minimal evidence record?
==============================

When an access complaint is reviewed days later, the service usually no
longer holds the original request. Storing the full target and
credentials for every decision is both a privacy liability and
unnecessary: to *explain* a rule result inside a trusted environment
only a small, anchored set of evidence is needed.

The recorder therefore persists:

* the evaluated rule text and a digest of the whole rule set in effect,
* SHA-256 digests of the target and credentials (never the raw values),
* one trace node per evaluated leaf check with its observed result,
* for ``http:``/``https:`` checks, digests of the wire request and
  response plus the observed boolean,
* an optional HMAC-SHA256 seal using a key held by the trusted
  environment.

Raw business values are absent by default. A scalar allow list
(``input_allowlist``) may expose specific non-sensitive keys, for
example a case identifier, when a human-readable preview is useful.

Recording a decision
====================

::

    from oslo_policy import replay

    decision, record = replay.record_decision(
        enforcer,
        'complaint:view',
        target,
        creds,
        decision_id='FB-149',
        recorded_at='2026-11-20T08:30:00Z',
        input_allowlist=['case_id'],
        secret=trusted_environment_hmac_key,
    )

    persist(record.to_json())  # the service chooses the audit store

The recorded decision is produced by the same check tree as
:meth:`Enforcer.enforce`, including fail-closed handling for unknown
rules and scope enforcement, so the evidence describes the decision the
engine actually took.

Replaying and classifying the evidence
======================================

Replay needs the same target and credentials. In practice these come
from the protected ticket archive attached to the complaint; they are
matched against the stored digests before any rule is re-evaluated.

Two modes are supported:

``offline`` (default)
    No network access. Deterministic leaves (roles, attribute
    comparisons, nested ``rule:`` references) are recomputed. Remote
    leaves are not invoked; their recorded outcome is reused as
    attested input and the leaf is reported as ``external``.

``live``
    Remote checks are invoked again. A ``remote_provider`` callable can
    stand in for the remote service inside an enclave, or the real
    ``http:``/``https:`` call is made when no provider is supplied.

::

    record = replay.DecisionRecord.from_json(persisted_evidence)
    report = replay.DecisionReplayer(
        record, secret=trusted_environment_hmac_key, mode='offline',
    ).replay(enforcer, target, creds)

The report makes the three evidence classes explicit:

* ``seen_then`` - the decision and per-leaf results observed at record
  time, including the remote call digests;
* ``recomputable_now`` - node ids of leaves whose result was
  recomputed and matched the record;
* ``not_verifiable_offline`` - node ids of remote leaves whose original
  outcome is only attested by digests.

The overall ``verdict`` is one of:

``reproduced``
    Every recomputable leaf matches and the combined decision matches.
``external``
    All deterministic leaves reproduce; only remote-attested leaves
    remain unverifiable offline.
``mismatch``
    A leaf or the combined decision no longer reproduces.
``input_drift`` / ``rule_drift``
    The target/credentials digests or the rule set digest differ.
``tampered``
    The optional HMAC seal does not verify.

Remote checks and custom kinds
==============================

The shipped :class:`oslo_policy._external.HttpCheck` and
``HttpsCheck`` are treated as remote automatically. A service that
registers its own live check registers the kind as well so the recorder
classifies it correctly::

    replay.mark_remote_kind('fraud-service')

Remote failures (timeouts, connection errors) are captured as evidence
with an ``error`` field and then propagated, preserving the failure
behaviour of a normal enforcement call.
