"""Test cases for "metadata.py"."""

import copy
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from securesystemslib.dsse import DSSESigningContext, Envelope
from securesystemslib.exceptions import (
    SigningContextError,
    UntrustedPayloadTypeError,
    UntrustedSigningKeyError,
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.signer import CryptoSigner, Key, Signature, Signer

PEMS_DIR = Path(__file__).parent / "data" / "pems"


class TestEnvelope(unittest.TestCase):
    """Test metadata interface provided by DSSE envelope."""

    @classmethod
    def setUpClass(cls):
        cls.signers: list[CryptoSigner] = []
        for keytype in ["rsa", "ecdsa", "ed25519"]:
            path = PEMS_DIR / f"{keytype}_private.pem"

            with open(path, "rb") as f:
                data = f.read()

            private_key = load_pem_private_key(data, None)
            signer = CryptoSigner(private_key)

            cls.signers.append(signer)

        cls.signature_dict = {
            "keyid": "11fa391a0ed7a447",
            "sig": "MEYCIQCTQuRWZSj87PanpQ==",
        }
        cls.envelope_dict = {
            "payload": "aGVsbG8gd29ybGQ=",
            "payloadType": "http://example.com/HelloWorld",
            "signatures": [cls.signature_dict],
        }
        cls.pae = b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"

    def test_envelope_from_dict_with_duplicate_signatures(self):
        """Test envelope from_dict generates error with duplicate signature keyids"""
        envelope_dict = copy.deepcopy(self.envelope_dict)

        # add duplicate keyid.
        envelope_dict["signatures"].append(copy.deepcopy(self.signature_dict))

        # assert that calling from_dict will raise an error.
        expected_error_message = (
            f"Multiple signatures found for keyid {self.signature_dict['keyid']}"
        )
        with self.assertRaises(ValueError) as context:
            Envelope.from_dict(envelope_dict)

        self.assertEqual(str(context.exception), expected_error_message)

    def test_envelope_from_to_dict(self):
        """Test envelope to_dict and from_dict methods."""

        envelope_dict = copy.deepcopy(self.envelope_dict)

        # create envelope object from its dict.
        envelope_obj = Envelope.from_dict(envelope_dict)
        for signature in envelope_obj.signatures.values():
            self.assertIsInstance(signature, Signature)

        # Assert envelope dict created by to_dict will be equal.
        self.assertDictEqual(self.envelope_dict, envelope_obj.to_dict())

    def test_envelope_eq_(self):
        """Test envelope equality."""

        envelope_obj = Envelope.from_dict(copy.deepcopy(self.envelope_dict))

        # Assert that object and None will not be equal.
        self.assertNotEqual(None, envelope_obj)

        # Assert a copy of envelope_obj will be equal to envelope_obj.
        envelope_obj_2 = copy.deepcopy(envelope_obj)
        self.assertEqual(envelope_obj, envelope_obj_2)

        # Assert that changing the "payload" will make the objects not equal.
        envelope_obj_2.payload = b"wrong_payload"
        self.assertNotEqual(envelope_obj, envelope_obj_2)
        envelope_obj_2.payload = envelope_obj.payload

        # Assert that changing the "payload_type" will make the objects not equal.
        envelope_obj_2.payload_type = "wrong_payload_type"
        self.assertNotEqual(envelope_obj, envelope_obj_2)
        envelope_obj_2.payload = envelope_obj.payload

        # Assert that changing the "signatures" will make the objects not equal.
        sig_obg = Signature("", self.signature_dict["sig"])
        envelope_obj_2.signatures = [sig_obg]
        self.assertNotEqual(envelope_obj, envelope_obj_2)

    def test_envelope_hash(self):
        """Envelopes should be hashable despite the signatures dict."""
        envelope_obj = Envelope.from_dict(copy.deepcopy(self.envelope_dict))
        envelope_obj_2 = copy.deepcopy(envelope_obj)

        # Equal envelopes hash equally and collapse in a set.
        self.assertEqual(hash(envelope_obj), hash(envelope_obj_2))
        self.assertEqual(len({envelope_obj, envelope_obj_2}), 1)

    def test_preauthencoding(self):
        """Test envelope Pre-Auth-Encoding."""

        envelope_obj = Envelope.from_dict(copy.deepcopy(self.envelope_dict))

        # Checking for Pre-Auth-Encoding generated is correct.
        self.assertEqual(self.pae, envelope_obj.pae())

    def test_preauthencoding_non_ascii_payload_type(self):
        """Test that Pre-Auth-Encoding counts payload type length in bytes."""

        envelope_obj = Envelope(b"hello world", "application/vnd.caf\u00e9+json", {})

        # 25 characters, 26 bytes in UTF-8.
        self.assertEqual(
            b"DSSEv1 26 application/vnd.caf\xc3\xa9+json 11 hello world",
            envelope_obj.pae(),
        )

    def test_sign_and_verify(self):
        """Test for creating and verifying DSSE signatures."""

        # Create an Envelope with no signatures.
        envelope_dict = copy.deepcopy(self.envelope_dict)
        envelope_dict["signatures"] = []
        envelope_obj = Envelope.from_dict(envelope_dict)

        key_list = []
        for signer in self.signers:
            envelope_obj.sign(signer)

            # Create a List of "Key" from key_dict.
            key_list.append(signer.public_key)

        # Check for signatures of Envelope.
        self.assertEqual(len(self.signers), len(envelope_obj.signatures))
        for signature in envelope_obj.signatures.values():
            self.assertIsInstance(signature, Signature)

        # Test for invalid threshold value for keys_list.
        # threshold is 0.
        with self.assertRaises(ValueError):
            envelope_obj.verify(key_list, 0)

        # threshold is greater than no of keys.
        with self.assertRaises(ValueError):
            envelope_obj.verify(key_list, 4)

        # Test with valid keylist and threshold.
        verified_keys = envelope_obj.verify(key_list, len(key_list))
        self.assertEqual(len(verified_keys), len(key_list))

        # Test for unknown keys and threshold of 1.
        new_key_list = []
        for key in key_list:
            new_key = copy.deepcopy(key)
            # if it has a different keyid, it is a different key in sslib
            new_key.keyid = reversed(key.keyid)
            new_key_list.append(new_key)

        with self.assertRaises(VerificationError):
            envelope_obj.verify(new_key_list, 1)

        all_keys = key_list + new_key_list
        envelope_obj.verify(all_keys, 3)

        # Test with duplicate keys.
        duplicate_keys = key_list + key_list
        with self.assertRaises(VerificationError):
            envelope_obj.verify(duplicate_keys, 4)  # 3 unique keys, threshold 4.


class _CountingSigner(Signer):
    """Test signer wrapper that counts calls to the underlying signer."""

    def __init__(self, inner: Signer, keyid_override: str | None = None):
        self.inner = inner
        self.calls = 0
        self.keyid_override = keyid_override

    @property
    def public_key(self) -> Key:
        return self.inner.public_key

    def sign(self, payload: bytes) -> Signature:
        self.calls += 1
        signature = self.inner.sign(payload)
        if self.keyid_override is not None:
            signature.keyid = self.keyid_override
        return signature

    @classmethod
    def from_priv_key_uri(cls, priv_key_uri, public_key, secrets_handler=None):
        raise NotImplementedError


class _PaeOverrideEnvelope(Envelope):
    """Envelope subclass that tries to lie about the bytes being signed."""

    def pae(self) -> bytes:
        return b"not the canonical DSSE PAE"


class TestDSSESigningContext(unittest.TestCase):
    """Restricted DSSE signing context tests."""

    @classmethod
    def setUpClass(cls):
        cls.signer = CryptoSigner.generate_ed25519(keyid="purpose-key")
        cls.key = cls.signer.public_key

    def test_sign_allowed_type_and_verify(self):
        """A context signs its allowed type and the result verifies."""
        context = DSSESigningContext(
            self.signer, ["https://example.com/build"], [self.key]
        )
        envelope = Envelope(b"same content", "https://example.com/build", {})

        signature = context.sign_envelope(envelope)

        self.assertEqual(signature.keyid, self.key.keyid)
        self.assertIs(envelope.signatures[signature.keyid], signature)
        self.assertIsNone(self.key.verify_signature(signature, envelope.pae()))
        self.assertEqual(envelope.verify([self.key], 1), {self.key.keyid: self.key})

    def test_rejected_type_does_not_call_signer(self):
        """A disallowed payload type is rejected before any signing happens."""
        counting = _CountingSigner(self.signer)
        context = DSSESigningContext(
            counting, ["https://example.com/build"], [self.key]
        )
        envelope = Envelope(b"same content", "https://example.com/release", {})

        with self.assertRaises(UntrustedPayloadTypeError):
            context.sign_envelope(envelope)

        self.assertEqual(counting.calls, 0)
        self.assertEqual(envelope.signatures, {})

    def test_raw_bytes_cannot_bypass_type_check(self):
        """The restricted handle has no raw sign(bytes) entry point."""
        context = DSSESigningContext(
            _CountingSigner(self.signer), ["https://example.com/build"], [self.key]
        )

        self.assertFalse(isinstance(context, Signer))
        self.assertFalse(hasattr(context, "sign"))

        with self.assertRaises(TypeError):
            context.sign_envelope(b"raw bytes")  # type: ignore[arg-type]

        # A caller cannot smuggle the context into the unrestricted API either.
        with self.assertRaises(AttributeError):
            Envelope(b"raw bytes", "https://example.com/build", {}).sign(context)  # type: ignore[arg-type]

    def test_same_payload_different_type_signature_not_interchangeable(self):
        """Identical payload bytes in another purpose cannot reuse the signature."""
        build_context = DSSESigningContext(
            self.signer, ["https://example.com/build"], [self.key]
        )
        release_context = DSSESigningContext(
            self.signer, ["https://example.com/release"], [self.key]
        )

        payload = b"identical payload"
        build_env = Envelope(payload, "https://example.com/build", {})
        release_env = Envelope(payload, "https://example.com/release", {})

        signature = build_context.sign_envelope(build_env)

        # Rejection for the other purpose happens before the signer runs.
        counting = _CountingSigner(self.signer)
        rejecting_context = DSSESigningContext(
            counting, ["https://example.com/release"], [self.key]
        )
        with self.assertRaises(UntrustedPayloadTypeError):
            rejecting_context.sign_envelope(build_env)
        self.assertEqual(counting.calls, 0)

        # Moving the signature to the other envelope must fail verification.
        release_env.signatures[signature.keyid] = signature
        with self.assertRaises(VerificationError):
            release_env.verify([self.key], 1)

        # Even the correctly-purposed context cannot re-bless the signature:
        # signing the release envelope creates a different signed byte string.
        release_signature = release_context.sign_envelope(release_env)
        self.assertNotEqual(release_signature.signature, signature.signature)

    def test_payload_type_is_in_signed_bytes_not_unsigned_fields(self):
        """The purpose is authenticated, not stored in unsigned metadata."""
        context = DSSESigningContext(
            self.signer, ["https://example.com/build"], [self.key]
        )
        envelope = Envelope(b"content", "https://example.com/build", {})
        signature = context.sign_envelope(envelope)

        self.assertEqual(signature.unrecognized_fields, {})
        self.assertIn(b"https://example.com/build", envelope.pae())

        # Changing the envelope type after signing invalidates the signature.
        envelope.payload_type = "https://example.com/release"
        with self.assertRaises(VerificationError):
            envelope.verify([self.key], 1)

    def test_mutating_allowed_types_does_not_expand_permissions(self):
        """Allowed types are frozen at construction."""
        allowed = ["https://example.com/build"]
        context = DSSESigningContext(_CountingSigner(self.signer), allowed, [self.key])

        allowed.append("https://example.com/release")
        self.assertEqual(
            context.payload_types, frozenset({"https://example.com/build"})
        )
        with self.assertRaises(AttributeError):
            context.payload_types.add("https://example.com/other")  # type: ignore[attr-defined]
        with self.assertRaises(AttributeError):
            context._payload_types.add("https://example.com/other")  # type: ignore[union-attr]
        with self.assertRaises(AttributeError):
            context._payload_types = frozenset({"https://example.com/other"})  # type: ignore[misc]

        envelope = Envelope(b"content", "https://example.com/release", {})
        with self.assertRaises(UntrustedPayloadTypeError):
            context.sign_envelope(envelope)

    def test_mutating_trusted_keys_does_not_expand_permissions(self):
        """Trusted key material is snapshotted at construction."""
        genuine = copy.deepcopy(self.key)
        trusted = [genuine]
        context = DSSESigningContext(
            self.signer, ["https://example.com/build"], trusted
        )

        # Appending another key after construction does not trust it.
        rogue = CryptoSigner.generate_ed25519(keyid="rogue").public_key
        trusted.append(rogue)
        self.assertNotEqual(rogue.keyid, self.key.keyid)

        # Mutating the trusted Key object after construction cannot make the
        # context trust a different signer: the fingerprint snapshot is fixed.
        genuine.keyid = rogue.keyid
        genuine.keytype = rogue.keytype
        genuine.scheme = rogue.scheme
        genuine.keyval = copy.deepcopy(rogue.keyval)

        counting = _CountingSigner(CryptoSigner.generate_ed25519(keyid="rogue-signer"))
        with self.assertRaises(UntrustedSigningKeyError):
            DSSESigningContext(counting, ["https://example.com/build"], trusted)
        self.assertEqual(counting.calls, 0)

        # The genuine signer still has a working context because its snapshot
        # was taken before the mutation.
        context.sign_envelope(Envelope(b"content", "https://example.com/build", {}))

    def test_untrusted_signer_rejected_at_construction(self):
        """A signer whose public key is not trusted gets no context."""
        other = CryptoSigner.generate_ed25519(keyid="other").public_key
        with self.assertRaises(UntrustedSigningKeyError):
            DSSESigningContext(self.signer, ["https://example.com/build"], [other])

    def test_envelope_subclass_pae_override_is_ignored(self):
        """The context computes canonical PAE, not Envelope.pae()."""
        context = DSSESigningContext(
            self.signer, ["https://example.com/build"], [self.key]
        )
        envelope = _PaeOverrideEnvelope(b"content", "https://example.com/build", {})
        signature = context.sign_envelope(envelope)

        canonical = Envelope(b"content", "https://example.com/build", {}).pae()
        self.assertIsNone(self.key.verify_signature(signature, canonical))
        with self.assertRaises(UnverifiedSignatureError):
            self.key.verify_signature(signature, envelope.pae())

    def test_nested_envelope_does_not_inherit_permission(self):
        """A nested disallowed envelope remains unsigned."""
        context = DSSESigningContext(
            self.signer, ["https://example.com/build"], [self.key]
        )
        inner = Envelope(b"inner content", "https://example.com/release", {})
        outer = Envelope(
            json.dumps(inner.to_dict(), sort_keys=True).encode(),
            "https://example.com/build",
            {},
        )

        signature = context.sign_envelope(outer)
        self.assertIn(signature.keyid, outer.signatures)
        self.assertEqual(inner.signatures, {})

        with self.assertRaises(UntrustedPayloadTypeError):
            context.sign_envelope(inner)

        with self.assertRaises(VerificationError):
            inner.verify([self.key], 1)

    def test_invalid_arguments(self):
        """Construction rejects empty and ambiguous configuration."""
        with self.assertRaises(TypeError):
            DSSESigningContext(self.signer, "https://example.com/build", [self.key])
        with self.assertRaises(ValueError):
            DSSESigningContext(self.signer, [], [self.key])
        with self.assertRaises(ValueError):
            DSSESigningContext(self.signer, ["https://example.com/build"], [])
        with self.assertRaises(TypeError):
            DSSESigningContext(object(), ["https://example.com/build"], [self.key])  # type: ignore[arg-type]

        context = DSSESigningContext(
            self.signer, ["https://example.com/build"], [self.key]
        )
        with self.assertRaises(TypeError):
            context.sign_envelope(Envelope(b"payload", b"type", {}))  # type: ignore[arg-type]

    def test_swapped_signer_key_after_construction_is_rejected(self):
        """Replacing the signer key after construction does not extend trust."""
        counting = _CountingSigner(self.signer)
        context = DSSESigningContext(
            counting, ["https://example.com/build"], [self.key]
        )
        # A signer whose public key changes after the context was built must
        # not inherit the old trust decision.
        counting.inner = CryptoSigner.generate_ed25519(keyid="swapped")
        envelope = Envelope(b"content", "https://example.com/build", {})

        with self.assertRaises(UntrustedSigningKeyError):
            context.sign_envelope(envelope)

        self.assertEqual(counting.calls, 0)
        self.assertEqual(envelope.signatures, {})

    def test_signer_returning_other_keyid_is_rejected(self):
        """A context does not accept a signature for another keyid."""
        counting = _CountingSigner(self.signer, keyid_override="someone-else")
        context = DSSESigningContext(
            counting, ["https://example.com/build"], [self.key]
        )
        envelope = Envelope(b"content", "https://example.com/build", {})

        with self.assertRaises(SigningContextError):
            context.sign_envelope(envelope)

        self.assertEqual(counting.calls, 1)
        self.assertEqual(envelope.signatures, {})

    def test_unrestricted_signer_api_still_works(self):
        """The ordinary Signer entry point remains available and unchanged."""
        envelope = Envelope(b"content", "https://example.com/build", {})
        envelope.sign(self.signer)
        self.assertEqual(envelope.verify([self.key], 1), {self.key.keyid: self.key})


# Run the unit tests.
if __name__ == "__main__":
    unittest.main()
