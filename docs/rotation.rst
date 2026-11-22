Rotating signing configuration
==============================

This guide replaces ``SECRET_KEY`` without downtime while links signed with
the old key are still in flight. It also covers retiring the legacy v1 token
format. The procedure relies only on public behavior of django-sesame 3.2 and
Django's :setting:`SECRET_KEY_FALLBACKS` setting.

How signing works
-----------------

Both token formats are signed with a key derived from the Django
:setting:`SECRET_KEY` setting, but only v2 consults
:setting:`SECRET_KEY_FALLBACKS` through django-sesame's own derivation.

v1 tokens are signed by Django's :class:`~django.core.signing.Signer` or
:class:`~django.core.signing.TimestampSigner`, created with
``salt=SESAME_SALT``. Those classes accept ``fallback_keys`` and default it to
:setting:`SECRET_KEY_FALLBACKS`, so v1 verification also survives a secret key
rotation — **provided** the signer is rebuilt in the new process.

v2 tokens use a Blake2 keyed hash. The key is derived from ``SECRET_KEY``,
``SESAME_KEY``, ``SESAME_MAX_AGE``, ``SESAME_PACKER``, and
``SESAME_PRIMARY_KEY_FIELD``. Verification tries the current key first, then
one key per entry in :setting:`SECRET_KEY_FALLBACKS`. A fallback key is
re-derived with the *current* values of the other settings, so those settings
must stay frozen for the whole transition.

Issuance always uses the first entry of :data:`SESAME_TOKENS`; verification
accepts any entry in that list. The default
``["sesame.tokens_v2", "sesame.tokens_v1"]`` means "issue v2, accept v2 and
v1". New v1 tokens are never issued under that default.

Rotation plan
-------------

Use four states. ``MAX_AGE`` below is the effective ``SESAME_MAX_AGE``; let
``T`` be its value. If ``SESAME_MAX_AGE`` is ``None``, see
:ref:`non-expiring links <Non-expiring links>` instead.

.. list-table::
    :header-rows: 1

    * - State
      - ``SECRET_KEY``
      - ``SECRET_KEY_FALLBACKS``
      - Issues with
      - Accepts
    * - A. Baseline
      - old
      - ``[]``
      - old key
      - old key
    * - B. Prepare
      - old
      - ``[new]``
      - old key
      - old key, new key
    * - C. Switch
      - new
      - ``[old]``
      - new key
      - new key, old key
    * - D. Contract
      - new
      - ``[]``
      - new key
      - new key only

1. **State A — baseline.** Record ``T`` and confirm the deployed
   ``SESAME_MAX_AGE``. Capture the current ``SESAME_KEY``, ``SESAME_PACKER``,
   ``SESAME_PRIMARY_KEY_FIELD``, and ``SESAME_SALT``; none of them may change
   during the transition.
2. **State B — prepare.** Add the new key to :setting:`SECRET_KEY_FALLBACKS`
   and deploy everywhere. Nothing changes for issuers; verifiers now accept
   the new key too. This step only buys rollback safety for state C.
3. **State C — switch.** Set ``SECRET_KEY`` to the new key and move the old key
   into :setting:`SECRET_KEY_FALLBACKS`. Deploy in a rolling fashion. **From
   the first state C process onward, new links are issued under the new key,
   but old-key links remain valid on every node.**
4. **State D — contract.** Wait until every link issued in states A and B has
   expired, then clear :setting:`SECRET_KEY_FALLBACKS` and deploy. **From this
   step onward, old-key links are no longer accepted.**

Wait at least ``T`` after the *last* state C process has been serving traffic,
then add a safety margin for clock skew and in-flight deploy overlap. The
boundary matters: v1 rejects a link only when ``age > T``, while v2 rejects it
when ``age >= T``. Waiting strictly longer than ``T`` satisfies both.

Mixed deployment behavior
-------------------------

During a rolling deploy, states B, C, and D coexist. Measured with frozen time
and two throwaway keys, for both v1 and v2 links:

- old-key links verified in B and C succeed; in D they fail;
- new-key links issued in C verify in B, C, and D;
- new-key links issued in D fail in A and B;
- a direct A → D deploy fails both directions for in-flight links.

So the safe rollback target at any point during C is **B**, not A. Rolling
back from C to A immediately breaks every link issued under the new key.

Rolling back
------------

- **From C to B:** safe. B accepts both keys, and B re-issues new links signed
  with the old key, which C still accepts. No link is lost.
- **From D to C:** safe for correctness, but it re-accepts old-key links that
  were already rejected. Treat this as a security regression window, not a
  neutral rollback. Only do it if old links genuinely must be restored, and
  shorten it as much as possible.
- **Never roll back by deleting :setting:`SECRET_KEY_FALLBACKS` while old
  links are still expected:** that is state D and is irreversible for those
  links.

Non-expiring links
------------------

.. _Non-expiring links:

If ``SESAME_MAX_AGE`` is ``None``, links have no timestamp, so states A and B
links never expire on their own. **There is no natural end to the transition.**
You must pick an explicit acceptance condition, for example:

- every old-key link has been consumed or superseded;
- a fixed deadline has passed and reusable old links are no longer expected;
- affected users have received new links.

Moving to state D then becomes a deliberate cut-over. Before you do it, count
or sample the links still being presented: re-authenticate a sample of recent
old-key links with a large ``max_age`` override while still in state C. Once
that check returns zero old-key hits for a full business cycle, state D is
safe.

Enabling ``SESAME_MAX_AGE`` at the same time as rotating the key invalidates
**both** formats, because v1 switches from ``Signer`` to ``TimestampSigner``
and v2 folds ``MAX_AGE`` into the derived key. Do these as two separate
changes.

Retiring v1 verification
------------------------

v1 is not issued by default; "retiring v1" only removes it from
:data:`SESAME_TOKENS`. Set ``SESAME_TOKENS = ["sesame.tokens_v2"]`` after every
v1 link has expired or been consumed. In state D this is the natural next
step; in state C it is independent of key rotation and loses only v1 links.

Acceptance conditions and residual risks
----------------------------------------

- **v1 and scoped or per-call lifetimes.** Authenticating a v1 link with a
  ``scope`` argument or a ``max_age`` override raises
  :exc:`NotImplementedError`; it does not return ``None``. Any caller that
  passes either must not see v1 links during the transition. Verify this
  before starting, or migrate those callers first.
- **``SESAME_KEY`` has no fallback.** Changing it invalidates all v2 links
  immediately, even with :setting:`SECRET_KEY_FALLBACKS` set. It is not part
  of this rotation; rotate it separately if required.
- **``SESAME_SALT`` has no fallback.** Changing it invalidates all v1 links
  immediately.
- **``SESAME_SIGNATURE_SIZE`` has no fallback.** Changing it rejects existing
  v2 links.
- **``SESAME_MAX_AGE`` must stay fixed.** Removing expiry (``None``) or
  changing the packer rejects existing v2 links. Increasing the value is safe
  for v2 only; it does not extend v1 links already issued.
- **Password and email changes still invalidate links.** This rotation does
  not change that; the delivery plan must account for links lost for unrelated
  reasons.
- **v1 verification disappears in one step.** There is no per-format
  fallback switch; removing ``sesame.tokens_v1`` from :data:`SESAME_TOKENS`
  is the cut-over. The corresponding test below is the gate.

Verifying the plan
------------------

``tests/test_rotation.py`` reproduces the table above with two fake keys and a
frozen clock. It covers mixed deployment, natural expiry, both rollback paths,
non-expiring links, the v1 cut-over, and the "no fallback" settings. Run:

.. code-block:: console

    $ python -m django test tests.test_rotation --settings=tests.settings
