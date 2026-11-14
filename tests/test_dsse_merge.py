"""Test cases for auditable DSSE envelope merging."""

import copy
import json
import os
import unittest
from pathlib import Path
from typing import Any

from securesystemslib.dsse import Envelope
from securesystemslib.dsse_merge import (
    SIGNATURE_CONFLICT,
    SIGNATURE_DUPLICATE,
    SIGNATURE_INVALID,
    SIGNATURE_RANDOMIZED,
    SIGNATURE_UNKNOWN_SIGNER,
    SIGNATURE_VERIFIED,
    SignatureRecord,
    merge_envelopes,
    publish_merged_envelope,
)
from securesystemslib.exceptions import EnvelopeMergeError
from securesystemslib.signer import (
    CryptoSigner,
    Key,
    Signature,
)


def make_envelope(payload: bytes, payload_type: str, signers: list[CryptoSigner]) -> Envelope:
    """Return an envelope signed once by each signer."""
    envelope = Envelope(payload, payload_type, {})
    for signer in signers:
        envelope.sign(signer)
    return envelope


class PermissiveEd25519Key(Key):
    """Deterministic key that also accepts one forged alternative signature.

    A real deterministic scheme can never emit two distinct valid signatures
    for one message, so the conflict branch cannot be reached with genuine
    keys. This stub stands in for that cryptographically impossible situation
    by accepting one additional signature value in addition to the real one.
    """

    def __init__(self, delegate: Key, forged_sig: str):
        super().__init__(delegate.keyid, delegate.keytype, delegate.scheme,
                         delegate.keyval)
        self._delegate = delegate
        self._forged_sig = forged_sig

    def to_dict(self) -> dict[str, Any]:
        return self._delegate.to_dict()

    @classmethod
    def from_dict(cls, keyid: str, key_dict: dict[str, Any]) -> "PermissiveEd25519Key":
        raise NotImplementedError

    def verify_signature(self, signature: Signature, data: bytes) -> None:
        if signature.signature == self._forged_sig:
            return
        self._delegate.verify_signature(signature, data)


class TestMergeEnvelopes(unittest.TestCase):
    """Test the auditable envelope merge entry point."""

    def setUp(self):
        self.payload_type = "application/vnd.in-toto+json"
        self.payload = json.dumps(
            {"_type": "https://in-toto.io/Statement/v1", "predicateType": "demo"},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

        self.ed_signer = CryptoSigner.generate_ed25519(keyid="ed-station")
        self.rsa_signer = CryptoSigner.generate_rsa(
            keyid="rsa-station", size=2048
        )
        self.signers = [self.ed_signer, self.rsa_signer]
        self.keys = [signer.public_key for signer in self.signers]

    def test_merge_unordered_and_duplicate_stations(self):
        """Out-of-order input and repeated stations merge to one envelope."""
        ed_env = make_envelope(self.payload, self.payload_type, [self.ed_signer])
        rsa_env = make_envelope(self.payload, self.payload_type, [self.rsa_signer])

        # Re-signing a deterministic Ed25519 envelope yields identical bytes.
        ed_env_duplicate = make_envelope(
            self.payload, self.payload_type, [self.ed_signer]
        )

        envelopes = [rsa_env, ed_env, ed_env_duplicate]
        labels = ["station-rsa", "station-ed", "station-ed-resend"]
        snapshots = copy.deepcopy(envelopes)

        merged, report = merge_envelopes(envelopes, self.keys, labels)

        # Two distinct trusted keys, one retained signature each.
        self.assertEqual(len(merged.signatures), 2)
        self.assertEqual(set(merged.signatures), {"ed-station", "rsa-station"})
        self.assertTrue(report.ok)
        self.assertEqual(
            report.accepted_keyids, ("rsa-station", "ed-station")
        )

        statuses = [(record.source_label, record.status, record.retained)
                    for record in report.records]
        self.assertEqual(
            statuses,
            [
                ("station-rsa", SIGNATURE_VERIFIED, True),
                ("station-ed", SIGNATURE_VERIFIED, True),
                ("station-ed-resend", SIGNATURE_DUPLICATE, False),
            ],
        )

        # Inputs are not modified and contain only their original signatures.
        self.assertEqual(envelopes, snapshots)
        self.assertEqual(len(ed_env_duplicate.signatures), 1)

        # The merged envelope independently verifies against the trusted keys.
        merged.verify(self.keys, 2)

    def test_rsa_pss_randomized_signatures_are_distinguished(self):
        """Two distinct valid PSS signatures are randomized, not conflicts."""
        first = make_envelope(self.payload, self.payload_type, [self.rsa_signer])
        second = make_envelope(self.payload, self.payload_type, [self.rsa_signer])

        sig_first = first.signatures["rsa-station"].signature
        sig_second = second.signatures["rsa-station"].signature
        self.assertNotEqual(sig_first, sig_second)

        merged, report = merge_envelopes(
            [first, second], self.keys, ["pss-a", "pss-b"]
        )

        self.assertEqual(len(merged.signatures), 1)
        statuses = [record.status for record in report.records]
        self.assertEqual(statuses, [SIGNATURE_VERIFIED, SIGNATURE_RANDOMIZED])
        self.assertEqual(
            [record.retained for record in report.records], [True, False]
        )
        merged.verify(self.keys, 1)

    def test_deterministic_conflict_is_rejected(self):
        """Two distinct valid deterministic signatures are a real conflict."""
        good = make_envelope(self.payload, self.payload_type, [self.ed_signer])
        forged = Signature("ed-station", "aa" * 64)
        conflicting = Envelope(
            self.payload, self.payload_type, {"ed-station": forged}
        )

        permissive_key = PermissiveEd25519Key(
            self.ed_signer.public_key, forged.signature
        )
        keys = [permissive_key, self.rsa_signer.public_key]

        with self.assertRaises(EnvelopeMergeError) as context:
            merge_envelopes([good, conflicting], keys, ["good", "forged"])

        report = context.exception.report
        self.assertFalse(report.ok)
        statuses = {record.source_label: record.status for record in report.records}
        self.assertEqual(statuses["good"], SIGNATURE_VERIFIED)
        self.assertEqual(statuses["forged"], SIGNATURE_CONFLICT)
        self.assertFalse(any(record.retained for record in report.records
                             if record.source_label == "forged"))

    def test_tampered_payload_byte_rejected_before_verification(self):
        """A one-byte payload change blocks the merge on byte comparison."""
        good = make_envelope(self.payload, self.payload_type, [self.ed_signer])
        tampered_payload = self.payload[:-1] + (
            b"X" if self.payload[-1:] != b"X" else b"Y"
        )
        self.assertNotEqual(tampered_payload, self.payload)
        tampered = make_envelope(tampered_payload, self.payload_type,
                                 [self.ed_signer])

        with self.assertRaises(EnvelopeMergeError) as context:
            merge_envelopes([good, tampered], self.keys, ["good", "tampered"])

        report = context.exception.report
        self.assertFalse(report.ok)
        self.assertTrue(any("payload bytes mismatch" in error
                            for error in report.errors))
        # No signature was evaluated once the payloads disagreed.
        self.assertEqual(report.records, ())

    def test_reformatted_payload_is_not_considered_equal(self):
        """Semantically equal but re-serialized JSON payloads mismatch."""
        compact = make_envelope(self.payload, self.payload_type, [self.ed_signer])
        pretty_payload = json.dumps(
            json.loads(self.payload.decode("utf-8")), indent=2
        ).encode("utf-8")
        self.assertNotEqual(pretty_payload, self.payload)
        pretty = make_envelope(pretty_payload, self.payload_type,
                               [self.ed_signer])

        with self.assertRaises(EnvelopeMergeError) as context:
            merge_envelopes([compact, pretty], self.keys, ["compact", "pretty"])

        self.assertTrue(any("payload bytes mismatch" in error
                            for error in context.exception.report.errors))

    def test_payload_type_mismatch_is_rejected(self):
        """payloadType must match exactly as a string."""
        first = make_envelope(self.payload, self.payload_type, [self.ed_signer])
        second = make_envelope(self.payload, "application/vnd.other+json",
                               [self.ed_signer])

        with self.assertRaises(EnvelopeMergeError) as context:
            merge_envelopes([first, second], self.keys, ["a", "b"])

        self.assertTrue(any("payloadType mismatch" in error
                            for error in context.exception.report.errors))

    def test_unknown_signer_is_rejected_and_not_published(self):
        """A signature with an untrusted keyid never enters the merged set."""
        trusted = make_envelope(self.payload, self.payload_type, [self.ed_signer])
        outsider = CryptoSigner.generate_ed25519(keyid="outsider")
        unknown_env = make_envelope(self.payload, self.payload_type, [outsider])

        with self.assertRaises(EnvelopeMergeError) as context:
            merge_envelopes([trusted, unknown_env], self.keys,
                            ["trusted", "unknown"])

        report = context.exception.report
        unknown_records = [
            record for record in report.records
            if record.status == SIGNATURE_UNKNOWN_SIGNER
        ]
        self.assertEqual(len(unknown_records), 1)
        self.assertFalse(unknown_records[0].retained)
        self.assertIsNone(unknown_records[0].scheme)

    def test_invalid_signature_is_rejected(self):
        """A corrupted signature fails verification and aborts the merge."""
        good = make_envelope(self.payload, self.payload_type, [self.ed_signer])
        original = good.signatures["ed-station"]
        corrupted_hex = original.signature[:-2] + (
            "00" if original.signature[-2:] != "00" else "11"
        )
        corrupted = Envelope(
            self.payload,
            self.payload_type,
            {"ed-station": Signature("ed-station", corrupted_hex)},
        )

        with self.assertRaises(EnvelopeMergeError) as context:
            merge_envelopes([good, corrupted], self.keys, ["good", "corrupt"])

        statuses = [record.status for record in context.exception.report.records]
        self.assertIn(SIGNATURE_INVALID, statuses)

    def test_failed_merge_leaves_no_partial_result(self):
        """A failure after some valid signatures still returns no envelope."""
        good_ed = make_envelope(self.payload, self.payload_type, [self.ed_signer])
        good_rsa = make_envelope(self.payload, self.payload_type, [self.rsa_signer])
        outsider = CryptoSigner.generate_ed25519(keyid="outsider")
        bad = make_envelope(self.payload, self.payload_type, [outsider])

        with self.assertRaises(EnvelopeMergeError):
            merge_envelopes([good_ed, good_rsa, bad], self.keys,
                            ["ed", "rsa", "outsider"])

    def test_default_source_labels_and_empty_input(self):
        """Default labels are generated and empty input is a usage error."""
        envelope = make_envelope(self.payload, self.payload_type, [self.ed_signer])
        _, report = merge_envelopes([envelope], self.keys)
        self.assertEqual(report.records[0].source_label, "envelope-0")

        with self.assertRaises(ValueError):
            merge_envelopes([], self.keys)

        with self.assertRaises(ValueError):
            merge_envelopes([envelope, envelope], self.keys, ["only-one"])

    def test_merged_signatures_are_independent_copies(self):
        """Mutating an input after merging does not touch the merged envelope."""
        envelope = make_envelope(self.payload, self.payload_type, [self.ed_signer])
        merged, _ = merge_envelopes([envelope], self.keys)

        envelope.signatures["ed-station"].signature = "bb" * 64
        envelope.payload = b"mutated"

        self.assertEqual(merged.payload, self.payload)
        self.assertNotEqual(
            merged.signatures["ed-station"].signature,
            envelope.signatures["ed-station"].signature,
        )

    def test_report_serialization(self):
        """The audit report is JSON-serializable with all status details."""
        envelope = make_envelope(self.payload, self.payload_type, [self.ed_signer])
        _, report = merge_envelopes([envelope], self.keys, ["station-1"])

        data = report.to_dict()
        self.assertTrue(data["ok"])
        self.assertEqual(data["signatures"][0]["sourceLabel"], "station-1")
        self.assertEqual(data["signatures"][0]["status"], SIGNATURE_VERIFIED)
        json.dumps(data)
        self.assertIsInstance(report.records[0], SignatureRecord)


class TestPublishMergedEnvelope(unittest.TestCase):
    """Test atomic publication of merged envelopes."""

    def test_publish_writes_complete_file_and_preserves_existing(self):
        payload_type = "application/vnd.in-toto+json"
        payload = b'{"_type":"demo"}'
        signer = CryptoSigner.generate_ed25519(keyid="k1")
        envelope = make_envelope(payload, payload_type, [signer])

        publish_dir = Path(os.environ["TMPDIR"]) / "dsse-merge-publish"
        publish_dir.mkdir(parents=True, exist_ok=True)
        path = publish_dir / "envelope.json"

        existing_content = b'{"previous":"publication"}'
        path.write_bytes(existing_content)

        publish_merged_envelope(path, envelope)

        published = json.loads(path.read_bytes())
        self.assertEqual(published, envelope.to_dict())

        # A subsequent failed merge must not overwrite the published artifact.
        tampered = Envelope(b"different bytes", payload_type, dict(envelope.signatures))
        with self.assertRaises(EnvelopeMergeError):
            merge_envelopes([envelope, tampered], [signer.public_key])

        self.assertEqual(
            path.read_bytes(),
            json.dumps(
                envelope.to_dict(), separators=(",", ":"), sort_keys=True
            ).encode("utf-8"),
        )

        # No temporary files are left behind.
        self.assertEqual(
            [name for name in os.listdir(publish_dir) if name.startswith(".dsse-")],
            [],
        )


if __name__ == "__main__":
    unittest.main()
