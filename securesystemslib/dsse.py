"""Dead Simple Signing Envelope"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from securesystemslib import exceptions
from securesystemslib._internal.utils import b64dec, b64enc, make_hashable
from securesystemslib.exceptions import (
    SigningContextError,
    UntrustedPayloadTypeError,
    UntrustedSigningKeyError,
)
from securesystemslib.signer import Key, Signature, Signer

logger = logging.getLogger(__name__)


def _pae(payload: bytes, payload_type: str) -> bytes:
    """Return the DSSE Pre-Auth-Encoding for the given payload and type.

    The payload type length is measured in UTF-8 bytes, as required by the
    DSSE specification. This helper is intentionally module-private: signing
    contexts must use it instead of any method a caller-supplied envelope
    class could override.
    """

    payload_type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 %d %b %d %b" % (
        len(payload_type_bytes),
        payload_type_bytes,
        len(payload),
        payload,
    )


def _key_fingerprint(key: Key) -> tuple[str, Any]:
    """Return an immutable snapshot of a key for trust comparisons.

    The snapshot contains the keyid and the serialized public key data. It is
    compared by value, so later changes to a mutable ``Key`` instance (or to
    a nested ``keyval`` dict) cannot silently satisfy a previously recorded
    trust decision.
    """

    return (key.keyid, make_hashable(key.to_dict()))


def _plain_str(value: Any, name: str) -> str:
    """Return the exact string content as a plain ``str``.

    ``str.__str__`` is used deliberately: a ``str`` subclass may override
    ``__str__``/``encode``, and the signing context must base its policy
    decision and its signed bytes on the same immutable value.
    """

    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string, got {type(value).__name__}")
    return str.__str__(value)


class DSSESigningContext:
    """Restricted signing context for DSSE envelopes.

    A context binds a ``Signer`` to a trusted configuration: only the given
    DSSE ``payloadType`` values may be signed, and the signer's public key must
    be one of the given trusted keys. The context is intended for applications
    that use one signing backend for several separate purposes (for example
    build provenance and release approval) and want to hand each caller a
    handle that can only sign its own purpose.

    The context deliberately does **not** implement the ``Signer`` interface
    and does not expose the underlying signer. ``sign_envelope()`` is the only
    signing entry point, it accepts only an :class:`Envelope`, and it derives
    the signed bytes from the envelope's own payload and payload type. There is
    no way to submit raw ``bytes`` through this handle without the payload type
    policy being applied first.

    The payload type is authenticated because it is part of the canonical DSSE
    Pre-Auth-Encoding: a signature made for one payload type cannot be moved to
    an envelope with the same payload but another payload type. Signatures
    produced by this context are ordinary DSSE signatures and remain verifiable
    with :meth:`Envelope.verify` and the matching ``Key``.

    Trusted keys and allowed payload types are snapshotted at construction. A
    later mutation of the passed iterables, of a ``Key`` instance, or of a
    nested ``keyval`` dictionary does not change the context.

    Args:
        signer: Signer used to produce the signature. It is never called before
            all policy checks have passed.
        payload_types: DSSE payload types this context may sign.
        trusted_keys: Public keys that the signer is allowed to use. The
            signer's public key must match one of them.

    Raises:
        TypeError: If arguments have invalid types, or ``payload_types`` is a
            plain string (which would be iterated character by character).
        ValueError: If ``payload_types`` or ``trusted_keys`` is empty.
        UntrustedSigningKeyError: If the signer's public key is not in
            ``trusted_keys`` at construction time.

    Usage example::

        from securesystemslib.dsse import DSSESigningContext, Envelope
        from securesystemslib.signer import CryptoSigner, Key

        signer = CryptoSigner.from_priv_key_uri(
            "file2:build-key.pem", build_key
        )

        # One restricted handle per purpose, both backed by the same key:
        build_context = DSSESigningContext(
            signer,
            payload_types=["https://example.com/build-provenance"],
            trusted_keys=[build_key],
        )

        envelope = Envelope(payload, "https://example.com/build-provenance", {})
        build_context.sign_envelope(envelope)
    """

    __slots__ = ("_signer", "_payload_types", "_trusted_key_fingerprints")

    _signer: Signer
    _payload_types: frozenset[str]
    _trusted_key_fingerprints: frozenset[tuple[str, Any]]

    def __init__(
        self,
        signer: Signer,
        payload_types: Iterable[str],
        trusted_keys: Iterable[Key],
    ):
        if not isinstance(signer, Signer):
            raise TypeError("signer must be a Signer instance")

        if isinstance(payload_types, str):
            raise TypeError(
                "payload_types must be an iterable of strings, not a string"
            )

        types = frozenset(_plain_str(pt, "payload type") for pt in payload_types)
        if not types:
            raise ValueError("payload_types must not be empty")

        keys = tuple(trusted_keys)
        if not keys:
            raise ValueError("trusted_keys must not be empty")

        fingerprints = frozenset(_key_fingerprint(key) for key in keys)

        public_key = signer.public_key
        if _key_fingerprint(public_key) not in fingerprints:
            raise UntrustedSigningKeyError(
                f"signer key {public_key.keyid!r} is not in trusted_keys"
            )

        # Bypass __setattr__ once, while populating the frozen state.
        object.__setattr__(self, "_signer", signer)
        object.__setattr__(self, "_payload_types", types)
        object.__setattr__(self, "_trusted_key_fingerprints", fingerprints)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError(
            "DSSESigningContext is immutable; create a new context to change "
            "the policy"
        )

    def __delattr__(self, name: str) -> None:
        raise AttributeError("DSSESigningContext is immutable")

    @property
    def payload_types(self) -> frozenset[str]:
        """Allowed DSSE payload types, as an immutable snapshot."""

        return self._payload_types

    @property
    def public_key(self) -> Key:
        """Public key of the underlying signer."""

        return self._signer.public_key

    def sign_envelope(self, envelope: Envelope) -> Signature:
        """Sign an envelope if its payload type and key are authorized.

        The context checks, in order: argument type, payload type, and signer
        key. Only after all checks pass is the underlying signer called. The
        signed bytes are the canonical DSSE PAE computed from the envelope's
        snapshot payload and payload type, and the resulting signature is added
        to ``envelope.signatures`` just like :meth:`Envelope.sign` does.

        Arguments:
            envelope: An :class:`Envelope` to sign. Its payload type must be one
                of the context's allowed types, and the signer's public key
                must be one of the context's trusted keys.

        Raises:
            TypeError: If ``envelope`` is not an :class:`Envelope` (a raw
                ``bytes`` payload or an unrelated wrapper is rejected).
            UntrustedPayloadTypeError: If the envelope payload type is not
                allowed.
            UntrustedSigningKeyError: If the signer's current public key is no
                longer trusted.
            SigningContextError: If the signer returns a signature for another
                keyid.

        Returns:
            The created ``Signature``.
        """

        if not isinstance(envelope, Envelope):
            raise TypeError(
                "sign_envelope() only accepts an Envelope; raw bytes or "
                f"wrappers are not allowed (got {type(envelope).__name__})"
            )

        # Snapshot both policy-relevant values exactly once: a subclass with
        # dynamic properties must not be able to present one value to the
        # policy check and another one to the signer.
        payload_type = _plain_str(envelope.payload_type, "payload type")
        payload = envelope.payload
        if not isinstance(payload, bytes):
            raise TypeError("envelope payload must be bytes")
        payload = memoryview(payload).tobytes()

        if payload_type not in self._payload_types:
            raise UntrustedPayloadTypeError(
                f"payload type {payload_type!r} is not allowed by this context"
            )

        public_key = self._signer.public_key
        if _key_fingerprint(public_key) not in self._trusted_key_fingerprints:
            raise UntrustedSigningKeyError(
                f"signer key {public_key.keyid!r} is not in trusted_keys"
            )

        # Use the module-level helper, not envelope.pae(): an overridden
        # method on an Envelope subclass must not decide what bytes get signed.
        pae = _pae(payload, payload_type)
        signature = self._signer.sign(pae)

        if signature.keyid != public_key.keyid:
            raise SigningContextError(
                "signer returned a signature for keyid "
                f"{signature.keyid!r}, expected {public_key.keyid!r}"
            )

        envelope.signatures[signature.keyid] = signature
        return signature


class Envelope:
    """DSSE Envelope to provide interface for signing arbitrary data.

    Attributes:
        payload: Arbitrary byte sequence of serialized body.
        payload_type: string that identifies how to interpret payload.
        signatures: dict of Signature key id and Signatures.

    """

    def __init__(
        self,
        payload: bytes,
        payload_type: str,
        signatures: dict[str, Signature],
    ):
        self.payload = payload
        self.payload_type = payload_type
        self.signatures = signatures

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Envelope):
            return False

        return (
            self.payload == other.payload
            and self.payload_type == other.payload_type
            and self.signatures == other.signatures
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.payload,
                self.payload_type,
                make_hashable(self.signatures),
            )
        )

    @classmethod
    def from_dict(cls, data: dict) -> Envelope:
        """Creates a DSSE Envelope from its JSON/dict representation.

        Arguments:
            data: A dict containing a valid payload, payloadType and signatures

        Raises:
            KeyError: If any of the "payload", "payloadType" and "signatures"
                fields are missing from the "data".

            FormatError: If signature in "signatures" is incorrect.

        Returns:
            A "Envelope" instance.
        """

        payload = b64dec(data["payload"])
        payload_type = data["payloadType"]

        signatures = {}
        for signature in data["signatures"]:
            signature["sig"] = b64dec(signature["sig"]).hex()
            sig = Signature.from_dict(signature)
            if sig.keyid in signatures:
                raise ValueError(f"Multiple signatures found for keyid {sig.keyid}")
            signatures[sig.keyid] = sig
        return cls(payload, payload_type, signatures)

    def to_dict(self) -> dict:
        """Returns the JSON-serializable dictionary representation of self."""

        signatures = []
        for signature in self.signatures.values():
            sig_dict = signature.to_dict()
            sig_dict["sig"] = b64enc(bytes.fromhex(sig_dict["sig"]))
            signatures.append(sig_dict)

        return {
            "payload": b64enc(self.payload),
            "payloadType": self.payload_type,
            "signatures": signatures,
        }

    def pae(self) -> bytes:
        """Pre-Auth-Encoding byte sequence of self."""

        return _pae(self.payload, self.payload_type)

    def sign(self, signer: Signer) -> Signature:
        """Sign the payload and create the signature.

        Arguments:
            signer: A "Signer" class instance.

        Returns:
            A "Signature" instance.
        """

        signature = signer.sign(self.pae())
        self.signatures[signature.keyid] = signature

        return signature

    def verify(self, keys: list[Key], threshold: int) -> dict[str, Key]:
        """Verify the payload with the provided Keys.

        Arguments:
            keys: A list of public keys to verify the signatures.
            threshold: Number of signatures needed to pass the verification.

        Raises:
            ValueError: If "threshold" is not valid.
            VerificationError: If the enclosed signatures do not pass the
                verification.

        Note:
            Mandating keyid in signatures and matching them with keyid of Key
            in order to consider them for verification, is not DSSE spec
            compliant (Issue #416).

        Returns:
            A dict of the threshold of unique public keys that verified a
            signature.
        """

        accepted_keys = {}
        pae = self.pae()

        # checks for threshold value.
        if threshold <= 0:
            raise ValueError("Threshold must be greater than 0")

        if len(keys) < threshold:
            raise ValueError("Number of keys can't be less than threshold")

        for signature in self.signatures.values():
            for key in keys:
                # If Signature keyid doesn't match with Key, skip.
                if not key.keyid == signature.keyid:
                    continue

                # If a key verifies the signature, we exit and use the result.
                try:
                    key.verify_signature(signature, pae)
                    accepted_keys[key.keyid] = key
                    break
                except exceptions.UnverifiedSignatureError:
                    continue

            # Break, if amount of accepted_keys are more than threshold.
            if len(accepted_keys) >= threshold:
                break

        if threshold > len(accepted_keys):
            raise exceptions.VerificationError(
                "Accepted signatures do not match threshold,"
                f" Found: {len(accepted_keys)}, Expected {threshold}"
            )

        return accepted_keys
