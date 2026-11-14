"""Auditable merge of DSSE envelopes from independent offline signers.

The publishing system sends one DSSE payload to several offline signing
stations and receives one envelope per station. This module provides the
single entry point through which those envelopes are co-signed into one
envelope.

The merge is conservative and auditable:

* Envelopes can only be combined when their ``payload`` *bytes* and
  ``payloadType`` strings are exactly equal. Payloads are never parsed or
  re-serialized, so re-formatting a JSON payload (e.g. compact vs. pretty
  printed) makes the envelopes incompatible, even if they are semantically
  identical.
* Every signature is verified against a trusted key selected by its
  ``keyid``. Unverified material is never carried into the merged envelope.
* Signatures sharing a ``keyid`` are classified as exact duplicates
  (deduplicated), distinct valid signatures of a randomized scheme (e.g.
  RSA-PSS), or genuine conflicts for a deterministic scheme (e.g. Ed25519).
* The merge is all-or-nothing: all verification happens in memory and a
  merged envelope is only returned when every input signature is accounted
  for. Input envelopes and keys are never modified.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import dataclass
from typing import Any

from securesystemslib._internal.utils import b64enc
from securesystemslib.dsse import Envelope
from securesystemslib.exceptions import EnvelopeMergeError, UnverifiedSignatureError
from securesystemslib.signer import (
    ECDSA_SHA2_NISTP256,
    ECDSA_SHA2_NISTP384,
    ECDSA_SHA2_NISTP521,
    RSASSA_PSS_SHA224,
    RSASSA_PSS_SHA256,
    RSASSA_PSS_SHA384,
    RSASSA_PSS_SHA512,
    Key,
    Signature,
)

#: Signature verified against the trusted key and retained in the merge.
SIGNATURE_VERIFIED = "verified"
#: Exact duplicate (same keyid and identical signature bytes) of a retained
#: signature; deduplicated, only the first occurrence is retained.
SIGNATURE_DUPLICATE = "duplicate"
#: Distinct, valid signature for a keyid whose scheme is randomized
#: (e.g. RSA-PSS); the first valid signature is retained, this one is recorded
#: as an equivalent randomized signature.
SIGNATURE_RANDOMIZED = "randomized"
#: Distinct, valid signature for a keyid whose scheme is deterministic
#: (e.g. Ed25519); a contradiction that aborts the merge.
SIGNATURE_CONFLICT = "conflict"
#: Signature that failed cryptographic verification against the trusted key.
SIGNATURE_INVALID = "invalid"
#: Signature whose keyid is not present in the trusted key store.
SIGNATURE_UNKNOWN_SIGNER = "unknown_signer"

#: Schemes for which two distinct valid signatures over the same message are
#: expected, because the signing operation draws random per-signature values.
_RANDOMIZED_SCHEMES = frozenset(
    [
        RSASSA_PSS_SHA224,
        RSASSA_PSS_SHA256,
        RSASSA_PSS_SHA384,
        RSASSA_PSS_SHA512,
        ECDSA_SHA2_NISTP256,
        ECDSA_SHA2_NISTP384,
        ECDSA_SHA2_NISTP521,
    ]
)


@dataclass(frozen=True)
class SignatureRecord:
    """Audit trail entry for one input signature.

    Args:
        source_index: Index of the source envelope in the merge input.
        source_label: Human readable label of the source signing station.
        keyid: Key identifier claimed by the signature.
        signature: HEX encoded signature bytes.
        scheme: Key scheme used for verification, or ``None`` if the signer
            is unknown.
        status: One of the ``SIGNATURE_*`` constants.
        retained: Whether the signature is carried into the merged envelope.
        detail: Optional human readable explanation.
    """

    source_index: int
    source_label: str
    keyid: str
    signature: str
    scheme: str | None
    status: str
    retained: bool
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the record."""
        return {
            "sourceIndex": self.source_index,
            "sourceLabel": self.source_label,
            "keyid": self.keyid,
            "sig": self.signature,
            "scheme": self.scheme,
            "status": self.status,
            "retained": self.retained,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class MergeReport:
    """Auditable result of a merge attempt.

    The report is produced for successful merges *and* for failed ones (it is
    attached to the raised :class:`EnvelopeMergeError`), so every input
    signature and the reason for every rejection can be reviewed.

    Args:
        payload: The exact payload bytes the merge operated on.
        payload_type: The payload type the merge operated on.
        records: One :class:`SignatureRecord` per input signature, in input
            order.
        accepted_keyids: Keyids of the verified signatures retained in the
            merged envelope, in first-seen order.
        errors: Human readable reasons that caused the merge to be rejected.
    """

    payload: bytes
    payload_type: str
    records: tuple[SignatureRecord, ...] = ()
    accepted_keyids: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """Whether the merge produced a merged envelope."""
        return not self.errors

    def records_for_source(self, source_index: int) -> tuple[SignatureRecord, ...]:
        """Return all audit records originating from one input envelope."""
        return tuple(
            record for record in self.records if record.source_index == source_index
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation of the report."""
        return {
            "ok": self.ok,
            "payload": b64enc(self.payload),
            "payloadType": self.payload_type,
            "acceptedKeyids": list(self.accepted_keyids),
            "errors": list(self.errors),
            "signatures": [record.to_dict() for record in self.records],
        }


def _is_randomized(scheme: str) -> bool:
    return scheme in _RANDOMIZED_SCHEMES


def merge_envelopes(
    envelopes: list[Envelope],
    keys: list[Key],
    source_labels: list[str] | None = None,
) -> tuple[Envelope, MergeReport]:
    """Merge DSSE envelopes from independent signing stations.

    The merge only succeeds when every envelope carries the exact same
    ``payload`` bytes and ``payloadType`` string, and every signature can be
    verified against a trusted key from ``keys``. Input objects are never
    modified; the returned envelope contains freshly constructed signature
    objects.

    Args:
        envelopes: Envelopes returned by the offline signing stations. Their
            order is irrelevant.
        keys: Trusted public keys; a signature is only considered when its
            ``keyid`` matches one of these keys.
        source_labels: Optional labels (e.g. station names) used in the audit
            trail. Defaults to ``"envelope-<index>"``.

    Raises:
        ValueError: If arguments are empty or malformed.
        EnvelopeMergeError: If the payloads/payload types do not match, a
            signer is unknown, a signature does not verify, or a genuine
            signature conflict is detected. The full :class:`MergeReport` is
            attached as ``report``.

    Returns:
        Tuple of the merged :class:`Envelope` and the :class:`MergeReport`.
    """
    if not envelopes:
        raise ValueError("At least one envelope is required")
    if source_labels is not None and len(source_labels) != len(envelopes):
        raise ValueError("source_labels must match the number of envelopes")

    labels = (
        [f"envelope-{index}" for index in range(len(envelopes))]
        if source_labels is None
        else list(source_labels)
    )

    key_store: dict[str, Key] = {}
    for key in keys:
        if key.keyid in key_store:
            raise ValueError(f"Duplicate trusted key for keyid {key.keyid}")
        key_store[key.keyid] = key

    reference = envelopes[0]
    errors: list[str] = []

    # Byte-exact agreement is mandatory. The payload is never decoded or
    # re-serialized: re-formatted but semantically equal payloads mismatch.
    for index, envelope in enumerate(envelopes[1:], start=1):
        if envelope.payload_type != reference.payload_type:
            errors.append(
                f"payloadType mismatch: {labels[index]!r} has "
                f"{envelope.payload_type!r}, expected {reference.payload_type!r}"
            )
        if envelope.payload != reference.payload:
            errors.append(
                f"payload bytes mismatch: {labels[index]!r} payload "
                f"({len(envelope.payload)} bytes) differs from "
                f"{labels[0]!r} payload ({len(reference.payload)} bytes)"
            )

    if errors:
        report = MergeReport(
            payload=reference.payload,
            payload_type=reference.payload_type,
            errors=tuple(errors),
        )
        raise EnvelopeMergeError("Envelope payloads are not identical", report)

    pae = reference.pae()
    records: list[SignatureRecord] = []
    retained: dict[str, Signature] = {}

    for index, envelope in enumerate(envelopes):
        for signature in envelope.signatures.values():
            record = _verify_and_classify(
                signature, key_store, pae, index, labels[index], retained
            )
            records.append(record)
            if record.status not in (
                SIGNATURE_VERIFIED,
                SIGNATURE_DUPLICATE,
                SIGNATURE_RANDOMIZED,
            ):
                errors.append(
                    f"{record.status} signature from {labels[index]!r} "
                    f"for keyid {signature.keyid}"
                    + (f": {record.detail}" if record.detail else "")
                )

    accepted_keyids = tuple(retained.keys())

    if errors:
        report = MergeReport(
            payload=reference.payload,
            payload_type=reference.payload_type,
            records=tuple(records),
            accepted_keyids=accepted_keyids,
            errors=tuple(errors),
        )
        raise EnvelopeMergeError("Envelope merge failed verification", report)

    merged = Envelope(
        payload=reference.payload,
        payload_type=reference.payload_type,
        signatures=dict(retained),
    )
    report = MergeReport(
        payload=reference.payload,
        payload_type=reference.payload_type,
        records=tuple(records),
        accepted_keyids=accepted_keyids,
    )
    return merged, report


def _verify_and_classify(  # noqa: PLR0913
    signature: Signature,
    key_store: dict[str, Key],
    pae: bytes,
    source_index: int,
    source_label: str,
    retained: dict[str, Signature],
) -> SignatureRecord:
    """Verify one signature and classify it relative to retained signatures."""
    key = key_store.get(signature.keyid)
    if key is None:
        return SignatureRecord(
            source_index,
            source_label,
            signature.keyid,
            signature.signature,
            None,
            SIGNATURE_UNKNOWN_SIGNER,
            False,
            "keyid is not present in the trusted key store",
        )

    try:
        key.verify_signature(signature, pae)
    except UnverifiedSignatureError as error:
        return SignatureRecord(
            source_index,
            source_label,
            signature.keyid,
            signature.signature,
            key.scheme,
            SIGNATURE_INVALID,
            False,
            str(error),
        )

    previous = retained.get(signature.keyid)
    if previous is None:
        # Fresh copy: the merged envelope must not share mutable signature
        # objects with the caller's inputs.
        retained[signature.keyid] = Signature(
            signature.keyid,
            signature.signature,
            dict(signature.unrecognized_fields),
        )
        return SignatureRecord(
            source_index,
            source_label,
            signature.keyid,
            signature.signature,
            key.scheme,
            SIGNATURE_VERIFIED,
            True,
        )

    if previous.signature == signature.signature:
        return SignatureRecord(
            source_index,
            source_label,
            signature.keyid,
            signature.signature,
            key.scheme,
            SIGNATURE_DUPLICATE,
            False,
            "identical signature already retained for this keyid",
        )

    if _is_randomized(key.scheme):
        return SignatureRecord(
            source_index,
            source_label,
            signature.keyid,
            signature.signature,
            key.scheme,
            SIGNATURE_RANDOMIZED,
            False,
            f"distinct valid signature from randomized scheme {key.scheme!r}",
        )

    return SignatureRecord(
        source_index,
        source_label,
        signature.keyid,
        signature.signature,
        key.scheme,
        SIGNATURE_CONFLICT,
        False,
        f"distinct valid signatures for deterministic scheme {key.scheme!r}",
    )


def publish_merged_envelope(path: str | os.PathLike[str], envelope: Envelope) -> None:
    """Atomically write a merged envelope to ``path``.

    The envelope is serialized to a temporary file in the destination
    directory and moved into place with :func:`os.replace`, so readers never
    observe a partially written file. Call this only after
    :func:`merge_envelopes` has succeeded: a failed merge raises before any
    publication happens and therefore cannot leave a half-published artifact
    or overwrite an existing publication.

    Args:
        path: Destination file path.
        envelope: The merged envelope to publish.
    """
    destination = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(destination))
    payload = json.dumps(
        envelope.to_dict(), separators=(",", ":"), sort_keys=True
    ).encode("utf-8")

    fd, tmp_path = tempfile.mkstemp(prefix=".dsse-merge-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, destination)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
