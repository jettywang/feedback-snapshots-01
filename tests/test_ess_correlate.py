#
# This file is part of pyasn1-modules software.
#
# License: http://snmplabs.com/pyasn1/license.html
#
"""Tests for the offline ESS signed-receipt correlation prototype."""

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from pyasn1_modules import rfc2634, rfc5652

from tools.ess_correlate import fixtures
from tools.ess_correlate.analysis import CaseInputs, analyze_archive
from tools.ess_correlate.model import (
    DecodeError,
    attestations_from_mapping,
    decode_message,
    decode_receipt,
    set_of_der,
)

WORKSPACE = Path(__file__).resolve().parents[1]


def _inputs(attestation_document=None):
    corpus = fixtures.build_corpus()
    document = fixtures.attestations() if attestation_document is None else attestation_document
    return corpus, CaseInputs(
        messages={message.name: message.der for message in corpus.messages},
        receipts={receipt.name: receipt.der for receipt in corpus.receipts},
        attestations=attestations_from_mapping(document),
    )


def _report(attestation_document=None):
    corpus, inputs = _inputs(attestation_document)
    return corpus, analyze_archive(inputs)


def _receipt(report, name):
    for item in report["receipts"]:
        if item["receipt"] == name:
            return item
    raise KeyError(name)


class SignedAttributesDigestTestCase(unittest.TestCase):
    def test_implicit_tag_is_replaced_with_set_of(self):
        # [0] IMPLICIT, long-form length 0x81 0x10, then 16 content octets.
        substrate = b"\xa0\x81\x10" + b"\x00" * 0x10
        expected = b"\x31\x81\x10" + b"\x00" * 0x10
        self.assertEqual(expected, set_of_der(substrate))

    def test_content_octets_are_preserved(self):
        substrate = b"\xa0\x03\x30\x01\x00"
        result = set_of_der(substrate)
        self.assertEqual(b"\x31\x03\x30\x01\x00", result)

    def test_length_mismatch_is_rejected(self):
        with self.assertRaises(DecodeError):
            set_of_der(b"\xa0\x05\x00\x00")

    def test_fixture_digest_uses_set_of_encoding(self):
        corpus = fixtures.build_corpus()
        message = corpus.message("MSG-B")
        signer = message.signers[0]
        expected = hashlib.sha256(signer.signed_attributes_der).digest()
        decoded = decode_message("MSG-B", message.der)
        receipt = decode_receipt("RECEIPT-B", corpus.receipt("RECEIPT-B").der)
        self.assertEqual(expected, receipt.signer.msg_sig_digest)
        self.assertEqual(
            expected,
            hashlib.sha256(decoded.signers[0].signed_attributes_der).digest(),
        )


class AttestationParsingTestCase(unittest.TestCase):
    def test_unknown_words_are_rejected(self):
        with self.assertRaises(ValueError):
            attestations_from_mapping(
                {"messages": {}, "receipts": {"R": {"signatureStatus": "probably"}}}
            )

    def test_unknown_trust_words_are_rejected(self):
        with self.assertRaises(ValueError):
            attestations_from_mapping(
                {"messages": {}, "receipts": {"R": {"certificateTrust": "eventually"}}}
            )

    def test_hash_addressed_entries_do_not_fall_back_to_positions(self):
        document = {
            "messages": {
                "MSG": {
                    "layers": [
                        {
                            "signers": [
                                {
                                    "signatureSha256": "ab" * 32,
                                    "status": "valid",
                                }
                            ]
                        }
                    ]
                }
            },
            "receipts": {},
        }
        attestations = attestations_from_mapping(document)
        status = attestations.message_signer("MSG", 0, 0, b"other-signature").status
        self.assertEqual("unknown", status)
        hashed = hashlib.sha256(b"other-signature").hexdigest()
        self.assertNotEqual("ab" * 32, hashed)

    def test_signature_hash_is_matched_exactly(self):
        signature = b"THE-SIGNATURE"
        document = {
            "messages": {
                "MSG": {
                    "layers": [
                        {
                            "signers": [
                                {
                                    "signatureSha256": hashlib.sha256(signature).hexdigest(),
                                    "status": "invalid",
                                    "reason": "bad",
                                }
                            ]
                        }
                    ]
                }
            },
            "receipts": {},
        }
        attestations = attestations_from_mapping(document)
        self.assertEqual("invalid", attestations.message_signer("MSG", 0, 0, signature).status)


class FixtureShapeTestCase(unittest.TestCase):
    def setUp(self):
        self.corpus = fixtures.build_corpus()

    def test_identical_body_different_signatures(self):
        first = decode_message("MSG-A", self.corpus.message("MSG-A").der)
        second = decode_message("MSG-B", self.corpus.message("MSG-B").der)
        self.assertEqual(first.body, second.body)
        self.assertEqual(first.body_sha256, second.body_sha256)
        self.assertNotEqual(first.signers[0].signature, second.signers[0].signature)
        self.assertNotEqual(
            first.signers[0].content_identifier, second.signers[0].content_identifier
        )
        self.assertNotEqual(
            first.signers[0].signed_attributes_der,
            second.signers[0].signed_attributes_der,
        )

    def test_receipt_fields_reference_one_signature(self):
        message = decode_message("MSG-B", self.corpus.message("MSG-B").der)
        receipt = decode_receipt("RECEIPT-B", self.corpus.receipt("RECEIPT-B").der)
        signer = message.signers[0]
        self.assertEqual(str(rfc2634.id_ct_receipt), receipt.envelope.econtent_type)
        self.assertEqual(signer.content_type, receipt.content_type)
        self.assertEqual(signer.content_identifier, receipt.signed_content_identifier)
        self.assertEqual(signer.signature, receipt.originator_signature_value)

    def test_forwarded_message_keeps_inner_bytes(self):
        inner = self.corpus.message("MSG-A")
        forwarded = decode_message("MSG-FWD", self.corpus.message("MSG-FWD").der)
        self.assertEqual(2, len(forwarded.layers))
        self.assertEqual(str(rfc5652.id_signedData), forwarded.layers[0].econtent_type)
        self.assertEqual(inner.signed_data_der, forwarded.layers[0].econtent)
        self.assertEqual(
            inner.signers[0].signed_attributes_der,
            forwarded.signers[-1].signed_attributes_der,
        )

    def test_multi_signer_receipt_requests(self):
        message = decode_message("MSG-MULTI", self.corpus.message("MSG-MULTI").der)
        self.assertEqual(2, len(message.signers))
        requesting = [signer for signer in message.signers if signer.receipt_request]
        self.assertEqual(1, len(requesting))
        self.assertEqual(b"SCI-MULTI-PRIMARY", requesting[0].content_identifier)

    def test_receipt_list_and_policy_round_trip(self):
        message = decode_message("MSG-LIST-ADD", self.corpus.message("MSG-LIST-ADD").der)
        signer = message.layers[-1].signers[0]
        names = signer.receipt_request["receiptsFrom"]["receiptList"]
        self.assertEqual(1, len(names))
        self.assertEqual(
            b"dave@example.com", bytes(names[0][0]["rfc822Name"])
        )
        history = message.layers[0].signers[0].ml_expansion_history
        self.assertIsNotNone(history)
        policy = history[0]["mlReceiptPolicy"]
        self.assertEqual("inAdditionTo", policy.getName())
        self.assertEqual(b"dave@example.com", bytes(policy["inAdditionTo"][0][0]["rfc822Name"]))


class CorrelationLevelTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus, cls.report = _report()

    def test_genuine_receipt_reaches_all_levels(self):
        item = _receipt(self.report, "RECEIPT-B")
        self.assertEqual(
            {"signatureLocated": True, "receiptTrusted": True, "expectedRecipientConfirmed": True},
            item["levels"],
        )
        self.assertEqual("MSG-B", item["matched"]["message"])
        self.assertEqual("layers[0].signerInfos[0]", item["matched"]["signer"])

    def test_level_one_citations_reference_raw_fields(self):
        item = _receipt(self.report, "RECEIPT-B")
        citations = item["matched"]["link"]["checks"]
        self.assertEqual(
            "layers[0].signerInfos[0].signedAttrs 1.2.840.113549.1.9.3",
            citations["contentType"]["path"],
        )
        self.assertEqual(
            item["receiptFields"]["contentType"], citations["contentType"]["observed"]
        )
        self.assertEqual(
            item["receiptFields"]["signedContentIdentifier"],
            citations["signedContentIdentifier"]["expected"],
        )
        self.assertEqual(
            item["receiptFields"]["originatorSignatureValue"],
            citations["originatorSignatureValue"]["expected"],
        )
        self.assertTrue(citations["contentType"]["match"])
        self.assertTrue(citations["signedContentIdentifier"]["match"])
        self.assertTrue(citations["originatorSignatureValue"]["match"])

    def test_candidates_are_reported_without_upgrading(self):
        item = _receipt(self.report, "RECEIPT-B")
        self.assertEqual(
            [{"message": "MSG-B", "signer": "layers[0].signerInfos[0]"}],
            item["candidates"],
        )

    def test_comparison_does_not_expand_to_identical_body(self):
        item = _receipt(self.report, "RECEIPT-B")
        groups = self.report["identicalBodyGroups"]
        self.assertTrue(groups)
        same_body = groups[0]["messages"]
        self.assertIn("MSG-A", same_body)
        self.assertIn("MSG-B", same_body)
        self.assertIn("MSG-RESIGN", same_body)
        # The receipt names exactly one signer, not every message with the body.
        self.assertEqual([], item.get("ambiguousCandidates", []))

    def test_spliced_receipt_stops_before_trust(self):
        item = _receipt(self.report, "RECEIPT-SPLICED")
        self.assertTrue(item["levels"]["signatureLocated"])
        self.assertFalse(item["levels"]["receiptTrusted"])
        self.assertIn("msgSigDigest_mismatch", item["levelDetails"]["receiptTrusted"]["reasonCodes"])
        self.assertEqual("MSG-B", item["matched"]["message"])
        # The digest it carries actually belongs to MSG-A.
        hits = item["digestCrossReference"]
        direct = [hit for hit in hits if not hit["nestedLayer"]]
        self.assertEqual(
            [{"message": "MSG-A", "signer": "layers[0].signerInfos[0]",
              "algorithm": "2.16.840.1.101.3.4.2.1",
              "digest": item["receiptSigner"]["msgSigDigest"],
              "nestedLayer": False}],
            direct,
        )
        # MSG-FWD embeds MSG-A verbatim, so the same digest appears again
        # at its nested layer; that is a copy, not a second delivery.
        self.assertTrue(any(hit["nestedLayer"] for hit in hits))

    def test_deleted_linkage_attribute_stops_before_trust(self):
        item = _receipt(self.report, "RECEIPT-NO-MSGDIGEST")
        self.assertTrue(item["levels"]["signatureLocated"])
        self.assertFalse(item["levels"]["receiptTrusted"])
        self.assertIn("msgSigDigest_absent", item["levelDetails"]["receiptTrusted"]["reasonCodes"])
        self.assertIsNone(item["receiptSigner"]["msgSigDigest"])

    def test_originator_signature_mismatch_breaks_level_one(self):
        item = _receipt(self.report, "RECEIPT-SIG-MISMATCH")
        self.assertFalse(item["levels"]["signatureLocated"])
        self.assertFalse(item["levels"]["receiptTrusted"])
        self.assertFalse(item["levels"]["expectedRecipientConfirmed"])
        closest = item["closest"][0]
        self.assertEqual("MSG-B", closest["message"])
        self.assertFalse(closest["checks"]["originatorSignatureValue"]["match"])

    def test_receipt_with_wrong_content_type_fails_field_link(self):
        corpus, inputs = _inputs()
        wrong = fixtures.build_receipt(
            "RECEIPT-WRONG-CT",
            corpus.message("MSG-B").signers[0],
            "MSG-B",
            fixtures._certificate("Bob", "bob@example.com", 2002),
            b"WRONG-CT-SIGNATURE",
            "Receipt names id-signedData instead of the originator's id-data.",
            wrong_content_type=rfc5652.id_signedData,
        )
        report = analyze_archive(
            CaseInputs(
                messages={message.name: message.der for message in corpus.messages},
                receipts={
                    **{receipt.name: receipt.der for receipt in corpus.receipts},
                    wrong.name: wrong.der,
                },
                attestations=inputs.attestations,
            )
        )
        item = _receipt(report, "RECEIPT-WRONG-CT")
        self.assertFalse(item["levels"]["signatureLocated"])
        closest = item["closest"][0]
        self.assertFalse(closest["checks"]["contentType"]["match"])
        self.assertEqual("1.2.840.113549.1.7.2", closest["checks"]["contentType"]["expected"])

    def test_structural_receipt_rules_are_checked(self):
        item = _receipt(self.report, "RECEIPT-B")
        checks = {check["path"]: check for check in item["structuralChecks"]}
        self.assertTrue(
            checks["RECEIPT-B: SignedData.encapContentInfo.eContentType"]["match"]
        )
        self.assertTrue(checks["RECEIPT-B: Receipt.version"]["match"])
        self.assertTrue(
            checks["RECEIPT-B: signerInfos[0].signedAttrs receiptRequest"]["match"]
        )

    def test_unknown_attestation_does_not_become_delivery(self):
        item = _receipt(self.report, "RECEIPT-B-UNATTESTED")
        self.assertTrue(item["levels"]["signatureLocated"])
        self.assertFalse(item["levels"]["receiptTrusted"])
        self.assertFalse(item["levels"]["expectedRecipientConfirmed"])
        self.assertIn(
            "receipt_signature_not_valid:unknown",
            item["levelDetails"]["receiptTrusted"]["reasonCodes"],
        )

    def test_unknown_original_signature_blocks_level_three(self):
        item = _receipt(self.report, "RECEIPT-RESIGN")
        self.assertTrue(item["levels"]["receiptTrusted"])
        self.assertFalse(item["levels"]["expectedRecipientConfirmed"])
        self.assertIn(
            "original_signature_not_valid:unknown",
            item["levelDetails"]["expectedRecipientConfirmed"]["reasonCodes"],
        )

    def test_identity_without_attestation_blocks_level_three(self):
        document = fixtures.attestations()
        del document["receipts"]["RECEIPT-B"]["signerNames"]
        _, report = _report(document)
        item = _receipt(report, "RECEIPT-B")
        self.assertTrue(item["levels"]["receiptTrusted"])
        self.assertFalse(item["levels"]["expectedRecipientConfirmed"])
        evaluation = item["levelDetails"]["expectedRecipientConfirmed"]["recipientEvaluation"]
        self.assertEqual("identity_unverified", evaluation["status"])

    def test_embedded_certificate_identity_is_reported_separately(self):
        document = fixtures.attestations()
        del document["receipts"]["RECEIPT-B"]["signerNames"]
        _, report = _report(document)
        item = _receipt(report, "RECEIPT-B")
        self.assertEqual(["bob@example.com"], item["receiptSigner"]["certificateEmails"])
        evaluation = item["levelDetails"]["expectedRecipientConfirmed"]["recipientEvaluation"]
        self.assertEqual("embedded certificate (unattested identity)", evaluation["identityBasis"])


class DuplicateSignerTestCase(unittest.TestCase):
    def test_two_archived_copies_with_same_signature_are_ambiguous(self):
        corpus, inputs = _inputs()
        messages = {message.name: message.der for message in corpus.messages}
        # A byte-identical second copy of MSG-B: two distinct archive objects
        # carry the same signature, so the receipt cannot pick one.
        messages["MSG-B-COPY"] = corpus.message("MSG-B").der
        report = analyze_archive(
            CaseInputs(
                messages=messages,
                receipts={receipt.name: receipt.der for receipt in corpus.receipts},
                attestations=inputs.attestations,
            )
        )
        item = _receipt(report, "RECEIPT-B")
        self.assertFalse(item["levels"]["signatureLocated"])
        self.assertFalse(item["levels"]["receiptTrusted"])
        self.assertEqual(
            {"MSG-B", "MSG-B-COPY"},
            {candidate["message"] for candidate in item["ambiguousCandidates"]},
        )


class MultiSignerAndListTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus, cls.report = _report()

    def test_receipt_for_non_requesting_signer(self):
        item = _receipt(self.report, "RECEIPT-MULTI-CAROL")
        self.assertTrue(item["levels"]["receiptTrusted"])
        self.assertFalse(item["levels"]["expectedRecipientConfirmed"])
        self.assertEqual("not_requested", item["levelDetails"]["expectedRecipientConfirmed"]
                         ["recipientEvaluation"]["status"])
        control = next(
            control for control in self.report["controls"]
            if control["control"] == "multiple_originator_signers"
        )
        signers = control["messages"][0]["signers"]
        by_signature = {signer["contentType"]: signer for signer in signers}
        requesting = [signer for signer in signers if signer["receiptRequest"]]
        self.assertEqual(1, len(requesting))
        self.assertEqual([], requesting[0]["receiptsLocatingIt"])

    def test_missing_receipt_request_blocks_level_three(self):
        item = _receipt(self.report, "RECEIPT-NO-RR")
        self.assertTrue(item["levels"]["receiptTrusted"])
        self.assertFalse(item["levels"]["expectedRecipientConfirmed"])
        self.assertEqual("not_requested", item["levelDetails"]["expectedRecipientConfirmed"]
                         ["recipientEvaluation"]["status"])

    def test_list_policy_none_blocks(self):
        item = _receipt(self.report, "RECEIPT-LIST-NONE")
        self.assertTrue(item["levels"]["receiptTrusted"])
        self.assertFalse(item["levels"]["expectedRecipientConfirmed"])
        self.assertEqual("blocked", item["levelDetails"]["expectedRecipientConfirmed"]
                         ["recipientEvaluation"]["status"])

    def test_list_policy_in_addition_to_confirms_dave_only(self):
        confirmed = _receipt(self.report, "RECEIPT-LIST-ADD")
        unexpected = _receipt(self.report, "RECEIPT-LIST-UNEXPECTED")
        self.assertTrue(confirmed["levels"]["expectedRecipientConfirmed"])
        self.assertFalse(unexpected["levels"]["expectedRecipientConfirmed"])
        self.assertEqual(
            "unexpected_recipient",
            unexpected["levelDetails"]["expectedRecipientConfirmed"]
            ["recipientEvaluation"]["status"],
        )

    def test_first_tier_request_after_expansion_is_blocked(self):
        item = _receipt(self.report, "RECEIPT-LIST-FIRST")
        self.assertTrue(item["levels"]["receiptTrusted"])
        self.assertFalse(item["levels"]["expectedRecipientConfirmed"])
        self.assertEqual("blocked", item["levelDetails"]["expectedRecipientConfirmed"]
                         ["recipientEvaluation"]["status"])

    def test_forwarded_outer_status_stays_unknown(self):
        control = next(
            control for control in self.report["controls"]
            if control["control"] == "forwarded_encapsulation"
        )
        forwarded = next(
            message for message in control["messages"] if message["message"] == "MSG-FWD"
        )
        self.assertEqual(["unknown"], [entry["status"] for entry in forwarded["outerSignerStatus"]])
        self.assertEqual(["valid"], [entry["status"] for entry in forwarded["innerSignerStatus"]])

    def test_coverage_matrix_records_each_layer(self):
        rows = {row["receipt"]: row for row in self.report["coverageMatrix"]}
        self.assertEqual(
            {"signatureLocated": True, "receiptTrusted": False, "expectedRecipientConfirmed": False},
            rows["RECEIPT-NO-MSGDIGEST"]["levels"],
        )
        self.assertEqual(
            {"signatureLocated": True, "receiptTrusted": True, "expectedRecipientConfirmed": True},
            rows["RECEIPT-B"]["levels"],
        )


class CommandLineTestCase(unittest.TestCase):
    def test_fixture_cli_writes_report(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            markdown = Path(directory) / "report.md"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tools.ess_correlate.cli",
                    "--fixtures",
                    "--json",
                    str(output),
                    "--markdown",
                    str(markdown),
                ],
                cwd=WORKSPACE,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(12, len(document["receipts"]))
            text = markdown.read_text(encoding="utf-8")
            self.assertIn("RECEIPT-SPLICED", text)
            self.assertIn("找到对应签名", text)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
