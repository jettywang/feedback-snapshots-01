Publisher constraints
=====================

.. module:: signify.authenticode.publisher

An update channel typically only accepts code from a small, explicit set of trusted
publishers. Certificates are renewed over time, and a renewal may keep the same key or
rotate to a new one. Matching a certificate's subject display name (for example its
``CN``) is therefore not a sound basis for a publisher allow-list: a different key can
carry the same name, and a renewal can carry a different name while keeping the same
key.

Signify therefore expresses a publisher allow-list as a set of **leaf certificate
SubjectPublicKeyInfo (SPKI) SHA-256 fingerprints**, each paired with a validity
interval. The subject display name is never used for matching.

.. note::

    The publisher constraint is applied *after* a signature has already fully
    verified. It is only ever evaluated against the end-entity (signer) leaf
    certificate that actually completed the file-digest, code-signature and
    trust-chain checks. It cannot be satisfied by:

    * a CA or root elsewhere in the verified chain (only the leaf, ``chain[-1]``, is
      considered);
    * a nested signature, which is verified and constrained independently on its own
      signer leaf;
    * a signature that failed verification, since a failing signature never reaches the
      publisher check and cannot inherit identity from another valid signature in the
      same file.

Defining a policy
-----------------

A :class:`TrustedPublisher` pins one SPKI SHA-256 and the inclusive interval during
which that key is accepted. A :class:`PublisherPolicy` is an ordered collection of such
entries.

.. code-block:: python

    import datetime
    from signify.authenticode import (
        SignedPEFile,
        PublisherPolicy,
        TrustedPublisher,
    )

    UTC = datetime.timezone.utc
    policy = PublisherPolicy(
        [
            # current generation key
            TrustedPublisher(
                "62eaab7c1110...",  # 64 hex chars: SHA-256 of the leaf SPKI
                valid_from=datetime.datetime(2026, 1, 1, tzinfo=UTC),
                valid_to=datetime.datetime(2030, 1, 1, tzinfo=UTC),
                label="generation-2",
            ),
        ]
    )

    with open("app.exe", "rb") as f:
        pe = SignedPEFile(f)
        decisions = pe.verify_publishers(
            policy,
            at=datetime.datetime(2026, 6, 1, tzinfo=UTC),
        )

``label`` is purely informational for reporting and never participates in matching.
``valid_from`` / ``valid_to`` are both inclusive; either may be :const:`None` to leave
that side of the interval open.

Renewal versus key rotation
---------------------------

* **Renewal keeping the same key** produces a new certificate (new serial, possibly new
  subject name and validity window) but the same public key, hence the same SPKI
  fingerprint. Add a second :class:`TrustedPublisher` entry with that same SPKI and the
  new validity window; signatures made with the renewed certificate keep verifying.
* **Genuine key rotation** introduces a new key, hence a different SPKI fingerprint.
  Pin the new SPKI in its own entry. Overlapping validity windows let both keys be
  accepted during a transition; once the old window closes, only the new key remains
  valid.

Per-signature reporting
-----------------------

:meth:`~signify.authenticode.signed_file.AuthenticodeFile.verify_publishers` never
short-circuits. It verifies every signature and returns one
:class:`PublisherVerification` per fully verified signature, each reporting the exact
policy entry (or entries) on which its leaf is accepted. When a file carries signatures
from multiple publishers, each is reported on its own basis rather than only the last
signature being considered.

The same constraint can be enforced through the regular
:meth:`~signify.authenticode.signed_file.AuthenticodeFile.verify` call by passing
``publisher_policy`` (and optionally ``publisher_at``); a rejected leaf then raises
:class:`~signify.exceptions.AuthenticodePublisherVerificationError`, which
:meth:`~signify.authenticode.signed_file.AuthenticodeFile.explain_verify` reports as
:class:`~signify.authenticode.verification_result.AuthenticodeVerificationResult.PUBLISHER_ERROR`.

Reference
---------

.. autoclass:: TrustedPublisher
   :members:

.. autoclass:: PublisherPolicy
   :members:

.. autoclass:: PublisherVerification
   :members:
