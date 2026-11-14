"""Tests for SubprocessSigner and its test-only helper subprocess."""

import os
import sys
import unittest

from securesystemslib import exceptions
from securesystemslib.dsse import Envelope
from securesystemslib.signer import (
    CryptoSigner,
    Signer,
    SubprocessSigner,
    SubprocessSignerError,
)

HELPER = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "scripts",
    "subprocess_signer_helper.py",
)


class TestSubprocessSigner(unittest.TestCase):
    """Test the subprocess signer protocol and its safeguards."""

    @classmethod
    def setUpClass(cls):
        cls.key_signer = CryptoSigner.generate_ed25519()
        cls.public_key = cls.key_signer.public_key
        cls.private_pem = cls.key_signer.private_bytes.decode()
        cls.wrong_pem = CryptoSigner.generate_ed25519().private_bytes.decode()

    def setUp(self):
        self.signers = []

    def tearDown(self):
        for signer in self.signers:
            signer.close()

    def new_signer(self, mode="normal", **kwargs):
        env = dict(os.environ)
        env["SSL_TEST_SIGNER_KEY"] = self.private_pem
        env["SSL_TEST_WRONG_KEY"] = self.wrong_pem
        kwargs.setdefault("env", env)
        signer = SubprocessSigner(
            self.public_key,
            sys.executable,
            [HELPER, mode],
            **kwargs,
        )
        self.signers.append(signer)
        return signer

    def assert_process_reaped(self, signer):
        self.assertIsNotNone(signer._process.poll(), "subprocess was left running")

    def test_sign_and_verify(self):
        signer = self.new_signer()
        sig = signer.sign(b"data")
        self.assertEqual(sig.keyid, self.public_key.keyid)
        self.public_key.verify_signature(sig, b"data")

    def test_dsse_envelope(self):
        signer = self.new_signer()
        envelope = Envelope(b"payload", "application/vnd.test", {})
        envelope.sign(signer)
        self.assertEqual(
            envelope.verify([self.public_key], 1),
            {self.public_key.keyid: self.public_key},
        )

    def test_fragmented_response(self):
        signer = self.new_signer("fragmented")
        sig = signer.sign(b"fragmented data")
        self.public_key.verify_signature(sig, b"fragmented data")

    def test_stderr_pollution_ignored(self):
        signer = self.new_signer("noisy")
        sig = signer.sign(b"noisy data")
        self.public_key.verify_signature(sig, b"noisy data")

    def test_late_response_times_out_and_kills_session(self):
        signer = self.new_signer("slow", timeout=0.5)
        with self.assertRaises(SubprocessSignerError):
            signer.sign(b"data")
        self.assert_process_reaped(signer)
        # A desynchronized session must not be reusable.
        with self.assertRaises(SubprocessSignerError):
            signer.sign(b"data")

    def test_wrong_key_signature_rejected(self):
        signer = self.new_signer("wrong-key")
        with self.assertRaises(exceptions.UnverifiedSignatureError):
            signer.sign(b"data")
        self.assert_process_reaped(signer)
        with self.assertRaises(SubprocessSignerError):
            signer.sign(b"data")

    def test_response_id_mismatch_kills_session(self):
        signer = self.new_signer("desync")
        with self.assertRaises(SubprocessSignerError):
            signer.sign(b"data")
        self.assert_process_reaped(signer)
        with self.assertRaises(SubprocessSignerError):
            signer.sign(b"data")

    def test_premature_exit_kills_session(self):
        signer = self.new_signer("die")
        with self.assertRaises(SubprocessSignerError):
            signer.sign(b"data")
        self.assert_process_reaped(signer)

    def test_from_priv_key_uri_rejected(self):
        with self.assertRaises(ValueError):
            SubprocessSigner.from_priv_key_uri(
                "subprocess:/bin/sh -c evil", self.public_key
            )
        with self.assertRaises(ValueError):
            Signer.from_priv_key_uri("subprocess:foo", self.public_key)

    def test_invalid_configuration(self):
        with self.assertRaises(ValueError):
            SubprocessSigner(self.public_key, "/nonexistent/helper")
        # A shell string is not an acceptable argument vector.
        with self.assertRaises(ValueError):
            SubprocessSigner(self.public_key, sys.executable, "-c 'evil'")
        with self.assertRaises(ValueError):
            SubprocessSigner(self.public_key, sys.executable, [HELPER], timeout=0)

    def test_payload_size_limit(self):
        signer = self.new_signer(max_payload_size=8)
        with self.assertRaises(ValueError):
            signer.sign(b"way too large payload")
        signer.close()

    def test_close_terminates_process(self):
        signer = self.new_signer()
        signer.close()
        self.assert_process_reaped(signer)
        with self.assertRaises(SubprocessSignerError):
            signer.sign(b"data")


if __name__ == "__main__":
    unittest.main()
