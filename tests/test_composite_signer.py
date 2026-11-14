"""Tests for the EXPERIMENTAL Ed25519 + ML-DSA-65 composite signer.

The composite format is custom to securesystemslib and explicitly not an
interoperability standard; see docs/EXPERIMENTAL_COMPOSITE_SIGNER.md.
"""

import copy
import json
import os
import tempfile
import unittest
import warnings

from securesystemslib.dsse import Envelope
from securesystemslib.exceptions import (
    KeyMismatchError,
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.signer import (
    KEY_FOR_TYPE_AND_SCHEME,
    SIGNER_FOR_URI_SCHEME,
    CompositeKey,
    CompositeSigner,
    CryptoSigner,
    Key,
    Signature,
    Signer,
    register_composite_signer,
)
from securesystemslib.signer._composite_signer import (
    COMPOSITE_ED25519_MLDSA65,
    ED25519_LABEL,
    KEY_TYPE_COMPOSITE,
    MLDSA65_LABEL,
)
from securesystemslib.signer._key import MLDSA_IMPORT_ERROR


@unittest.skipIf(
    MLDSA_IMPORT_ERROR is not None, "ML-DSA support requires cryptography>=48"
)
class TestCompositeSigner(unittest.TestCase):
    """End-to-end behavior of the experimental composite signer/key."""

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", FutureWarning)
        register_composite_signer()

        # Two independent local composite key sets.
        cls.signer_a = CompositeSigner.generate()
        cls.key_a = cls.signer_a.public_key
        cls.signer_b = CompositeSigner.generate()
        cls.key_b = cls.signer_b.public_key

        cls.message = b"the quick brown fox"
        cls.signature_a = cls.signer_a.sign(cls.message)
        cls.components_a = cls.key_a.unpack_signature(
            bytes.fromhex(cls.signature_a.signature)
        )
        cls.signature_b = cls.signer_b.sign(cls.message)
        cls.components_b = cls.key_b.unpack_signature(
            bytes.fromhex(cls.signature_b.signature)
        )

    def assert_rejected(self, key: CompositeKey, signature: Signature) -> None:
        with self.assertRaises(UnverifiedSignatureError):
            key.verify_signature(signature, self.message)

    def test_registration_is_opt_in_and_idempotent(self):
        # re-registering must not raise and must keep the dispatch targets
        register_composite_signer()
        self.assertIs(
            KEY_FOR_TYPE_AND_SCHEME[
                (KEY_TYPE_COMPOSITE, COMPOSITE_ED25519_MLDSA65)
            ],
            CompositeKey,
        )
        self.assertIs(SIGNER_FOR_URI_SCHEME[CompositeSigner.SCHEME], CompositeSigner)

    def test_experimental_warning(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            CompositeSigner.generate()
        self.assertTrue(
            any(issubclass(w.category, FutureWarning) for w in caught),
            "constructing a composite signer must warn that the format is "
            "experimental and non-standard",
        )

    def test_sign_verify_roundtrip(self):
        self.key_a.verify_signature(self.signature_a, self.message)
        self.assertEqual(self.signature_a.keyid, self.key_a.keyid)

    def test_wrong_message_fails(self):
        with self.assertRaises(UnverifiedSignatureError):
            self.key_a.verify_signature(self.signature_a, b"different message")

    def test_key_dict_roundtrip_and_dispatch(self):
        key_dict = self.key_a.to_dict()
        # self-describing, explicitly experimental labels
        self.assertEqual(key_dict["keytype"], KEY_TYPE_COMPOSITE)
        self.assertEqual(key_dict["scheme"], COMPOSITE_ED25519_MLDSA65)
        self.assertEqual(
            set(key_dict["keyval"]), {ED25519_LABEL, MLDSA65_LABEL}
        )

        reloaded = Key.from_dict(
            self.key_a.keyid, json.loads(json.dumps(key_dict))
        )
        self.assertIsInstance(reloaded, CompositeKey)
        self.assertEqual(reloaded, self.key_a)
        reloaded.verify_signature(self.signature_a, self.message)

    def test_unrecognized_fields_roundtrip(self):
        key_dict = self.key_a.to_dict()
        key_dict["custom-field"] = 1234
        reloaded = Key.from_dict(self.key_a.keyid, key_dict)
        self.assertEqual(reloaded.unrecognized_fields, {"custom-field": 1234})
        self.assertEqual(reloaded.to_dict()["custom-field"], 1234)

    def test_dsse_roundtrip_with_two_local_key_sets(self):
        envelope = Envelope(
            b"dsse body", "http://example.com/CompositeTest", {}
        )
        envelope.sign(self.signer_a)
        envelope.sign(self.signer_b)

        serialized = envelope.to_dict()
        # DSSE base64-wraps the hex composite container transparently.
        reloaded = Envelope.from_dict(json.loads(json.dumps(serialized)))
        accepted = reloaded.verify(
            [self.key_a, self.key_b], threshold=2
        )
        self.assertEqual(len(accepted), 2)

        # one composite key entry cannot satisfy a threshold of two
        with self.assertRaises(ValueError):
            reloaded.verify([self.key_a], threshold=2)

    def test_dsse_payload_tampering_fails(self):
        envelope = Envelope(
            b"dsse body", "http://example.com/CompositeTest", {}
        )
        envelope.sign(self.signer_a)
        envelope.payload = b"tampered body"
        with self.assertRaises(UnverifiedSignatureError):
            envelope.verify([self.key_a], threshold=1)

    def test_uri_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            ed_path = os.path.join(tmp, "ed25519.pem")
            ml_path = os.path.join(tmp, "mldsa65.pem")
            with open(ed_path, "wb") as f:
                f.write(self.signer_a._ed25519_signer.private_bytes)
            with open(ml_path, "wb") as f:
                f.write(self.signer_a._mldsa65_signer.private_bytes)

            uri = (
                f"{CompositeSigner.SCHEME}:?{ED25519_LABEL}={ed_path}"
                f"&{MLDSA65_LABEL}={ml_path}"
            )
            loaded = Signer.from_priv_key_uri(uri, self.key_a)
            signature = loaded.sign(self.message)
            self.key_a.verify_signature(signature, self.message)

    def test_uri_rejects_wrong_key_type(self):
        with self.assertRaises(ValueError):
            Signer.from_priv_key_uri(
                "composite2:?ed25519=a&ml-dsa-65=b",
                CryptoSigner.generate_ed25519().public_key,
            )

    def test_uri_rejects_bad_query(self):
        with self.assertRaises(ValueError):
            Signer.from_priv_key_uri(
                "composite2:?ed25519=a", self.key_a
            )

    def test_constructor_rejects_order_swap_and_wrong_algorithms(self):
        ed = self.signer_a._ed25519_signer
        ml = self.signer_a._mldsa65_signer
        with self.assertRaises(ValueError):
            CompositeSigner(ml, ed)
        with self.assertRaises(ValueError):
            CompositeSigner(CryptoSigner.generate_ecdsa(), ml)
        with self.assertRaises(ValueError):
            CompositeKey(
                "x", ml.public_key, ed.public_key  # reversed component order
            )

    def test_constructor_rejects_key_mismatch(self):
        with self.assertRaises(KeyMismatchError):
            CompositeSigner(
                self.signer_a._ed25519_signer,
                self.signer_a._mldsa65_signer,
                self.key_b,
            )

    # ------------------------------------------------------------------
    # Failure matrix: every tampering attempt must fail verification.
    # ------------------------------------------------------------------

    def test_failure_matrix(self):
        ed_sig, ml_sig = self.components_a
        foreign_ed, foreign_ml = self.components_b
        keyid = self.key_a.keyid

        def container(ed: bytes, ml: bytes) -> Signature:
            return Signature(keyid, self.key_a.pack_signature(ed, ml).hex())

        cases = {
            "component order swapped": container(ml_sig, ed_sig),
            "ed25519 key replaced": container(foreign_ed, ml_sig),
            "mldsa65 key replaced": container(ed_sig, foreign_ml),
            "both keys replaced": container(foreign_ed, foreign_ml),
            "cross composite key splice": Signature(
                keyid, self.signature_b.signature
            ),
        }
        for label, signature in cases.items():
            with self.subTest(case=label):
                self.assert_rejected(self.key_a, signature)

    def test_missing_component_is_rejected(self):
        ed_sig, _ = self.components_a
        keyid = self.key_a.keyid
        # bare single-algorithm signatures must never verify (no downgrade)
        for bare in (ed_sig, self.components_a[1]):
            with self.subTest():
                with self.assertRaises(UnverifiedSignatureError):
                    self.key_a.verify_signature(
                        Signature(keyid, bare.hex()), self.message
                    )

    def test_malformed_container_is_rejected(self):
        raw = bytearray(bytes.fromhex(self.signature_a.signature))
        keyid = self.key_a.keyid
        malformed = {
            "truncated": bytes(raw[:50]),
            "trailing bytes": bytes(raw) + b"extra",
            "tampered magic": bytes(bytearray(raw[:4] + b"XXXX" + raw[8:])),
            "empty": b"",
        }
        for label, blob in malformed.items():
            with self.subTest(case=label):
                with self.assertRaises(UnverifiedSignatureError):
                    self.key_a.verify_signature(
                        Signature(keyid, blob.hex()), self.message
                    )

    def test_keyid_mismatch_is_rejected(self):
        with self.assertRaises(UnverifiedSignatureError):
            self.key_a.verify_signature(
                Signature("0" * 64, self.signature_a.signature), self.message
            )

    def test_non_hex_signature_is_rejected(self):
        with self.assertRaises(UnverifiedSignatureError):
            self.key_a.verify_signature(
                Signature(self.key_a.keyid, "not-hex"), self.message
            )


@unittest.skipIf(
    MLDSA_IMPORT_ERROR is not None, "ML-DSA support requires cryptography>=48"
)
class TestCompositeKeyImport(unittest.TestCase):
    """Strict import-time algorithm/size checks, never a silent downgrade."""

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", FutureWarning)
        register_composite_signer()
        cls.good_dict = CompositeSigner.generate().public_key.to_dict()

    def _load(self, key_dict: dict) -> None:
        Key.from_dict("some-keyid", copy.deepcopy(key_dict))

    def test_rejects_wrong_keytype_and_scheme(self):
        for field, value in (
            ("keytype", "ed25519"),
            ("scheme", "ed25519"),
        ):
            bad = copy.deepcopy(self.good_dict)
            bad[field] = value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self._load(bad)

    def test_rejects_missing_or_extra_component(self):
        missing = copy.deepcopy(self.good_dict)
        del missing["keyval"][MLDSA65_LABEL]
        with self.assertRaises(ValueError):
            self._load(missing)

        extra = copy.deepcopy(self.good_dict)
        extra["keyval"]["rsa"] = {}
        with self.assertRaises(ValueError):
            self._load(extra)

    def test_rejects_wrong_component_algorithm(self):
        bad = copy.deepcopy(self.good_dict)
        bad["keyval"][ED25519_LABEL]["scheme"] = "ecdsa-sha2-nistp256"
        with self.assertRaises(ValueError):
            self._load(bad)

        bad = copy.deepcopy(self.good_dict)
        bad["keyval"][MLDSA65_LABEL]["scheme"] = "ml-dsa-44/1"
        with self.assertRaises(ValueError):
            self._load(bad)

    def test_rejects_wrong_component_size(self):
        bad = copy.deepcopy(self.good_dict)
        public = bad["keyval"][ED25519_LABEL]["keyval"]["public"]
        bad["keyval"][ED25519_LABEL]["keyval"]["public"] = public[:-2]
        with self.assertRaises((ValueError, VerificationError)):
            self._load(bad)

    def test_rejects_malformed_component(self):
        bad = copy.deepcopy(self.good_dict)
        bad["keyval"][ED25519_LABEL] = "not-a-dict"
        with self.assertRaises(ValueError):
            self._load(bad)

        bad = copy.deepcopy(self.good_dict)
        del bad["keyval"][MLDSA65_LABEL]["keyval"]
        with self.assertRaises(ValueError):
            self._load(bad)

    def test_rejects_unregistered_type_without_downgrade(self):
        # Without registration, Key.from_dict must not fall back to SSlibKey.
        saved = KEY_FOR_TYPE_AND_SCHEME.pop(
            (KEY_TYPE_COMPOSITE, COMPOSITE_ED25519_MLDSA65), None
        )
        try:
            with self.assertRaisesRegex(
                ValueError, "Unsupported public key"
            ):
                self._load(self.good_dict)
        finally:
            register_composite_signer()
            self.assertIsNotNone(saved)


if __name__ == "__main__":
    unittest.main()
