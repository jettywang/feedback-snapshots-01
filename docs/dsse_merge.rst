DSSE Envelope Merge
===================

.. currentmodule:: securesystemslib.dsse_merge

A publishing system may send one DSSE payload to several independent offline
signing stations and receive one :class:`~securesystemslib.dsse.Envelope` per
station. The ``dsse_merge`` module provides the single auditable entry point
that combines those envelopes into one co-signed envelope.

.. automodule:: securesystemslib.dsse_merge
   :no-members:

Merge rules
-----------

* Envelopes are combined only when their ``payload`` *bytes* and
  ``payloadType`` strings are exactly equal. Payloads are never parsed or
  re-serialized, so re-formatting a JSON payload makes the envelopes
  incompatible even when they are semantically identical.
* Every signature is verified against a trusted key selected by its
  ``keyid``. Signatures from unknown signers, or signatures that fail
  verification, are never carried into the merged envelope.
* Signatures sharing a ``keyid`` are classified as:

  * ``duplicate`` -- identical signature bytes, deduplicated;
  * ``randomized`` -- distinct valid signatures of a randomized scheme such
    as RSA-PSS, the first valid one is retained;
  * ``conflict`` -- distinct valid signatures of a deterministic scheme such
    as Ed25519, which is contradictory and aborts the merge.

* The merge is all-or-nothing. Verification runs entirely in memory and an
  envelope is returned only when every input signature is accounted for;
  input envelopes and keys are never modified. :func:`publish_merged_envelope`
  writes the result atomically, so a rejected merge cannot overwrite or leave
  a partially published artifact.

Audit trail
-----------

Every input signature produces a :class:`SignatureRecord` describing its
source envelope, ``keyid``, scheme, verification status and whether it was
retained. The records are returned inside a :class:`MergeReport` for
successful merges and attached to the raised
:class:`~securesystemslib.exceptions.EnvelopeMergeError` as ``report`` for
rejected ones, so no material enters a completed merge without an auditable
verification result.

Usage
-----

.. code-block:: python

   from securesystemslib.dsse_merge import merge_envelopes
   from securesystemslib.exceptions import EnvelopeMergeError

   try:
       merged, report = merge_envelopes(
           envelopes, trusted_keys, source_labels=["station-a", "station-b"]
       )
   except EnvelopeMergeError as error:
       for record in error.report.records:
           print(record.source_label, record.status)
       raise

API
---

.. autofunction:: merge_envelopes
.. autofunction:: publish_merged_envelope
.. autoclass:: MergeReport
   :members:
.. autoclass:: SignatureRecord
   :members:
