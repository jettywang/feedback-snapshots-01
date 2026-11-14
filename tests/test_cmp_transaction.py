"""Unit tests for the offline CMP transaction validator."""

import hashlib
import sys
import unittest
from datetime import datetime, timedelta, timezone

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import tag

from pyasn1_modules import rfc4210

from cmp_transaction import (
    CMPTransactionValidator,
    CertReqState,
    RejectReason,
    TransactionPhase,
)
from cmp_transaction import builders


class FakeClock:
    def __init__(self, start):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)


def sha256_der(certificate):
    return hashlib.sha256(der_encoder.encode(certificate)).digest()


class ValidatorTestCase(unittest.TestCase):
    def setUp(self):
        self.t0 = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
        self.clock = FakeClock(self.t0)
        self.validator = CMPTransactionValidator(clock=self.clock)
        self.ca = builders.rfc822_name("ca@example.test")
        self.ee = builders.rfc822_name("ee@example.test")
        self.other = builders.rfc822_name("mallory@example.test")
        self.txn_id = b"txn-0001"
        self.cert0 = builders.minimal_certificate(100)
        self.cert1 = builders.minimal_certificate(101)

    def validate(self, der):
        # Every message must survive a raw DER round trip before validation.
        decoded, rest = der_decoder.decode(der, asn1Spec=rfc4210.PKIMessage())
        self.assertFalse(rest)
        self.assertEqual(der_encoder.encode(decoded), der)
        return self.validator.validate(der)

    def open_transaction(self, cert_req_ids=(0, 1)):
        result = self.validate(builders.ir(
            list(cert_req_ids), self.ee, self.ca, self.txn_id,
            b"n1", self.t0))
        self.assertTrue(result.accepted, result.detail)
        return result

    def record(self):
        return self.validator.get_transaction(
            der_encoder.encode(self.ee), self.txn_id)

    def assert_reject(self, result, reason):
        self.assertFalse(result.accepted)
        self.assertIs(result.reason, reason)

    def test_happy_path_two_cert_req_ids_with_polling(self):
        self.open_transaction()
        # First ip: id 0 granted, id 1 still waiting.
        result = self.validate(builders.ip(
            [(0, 0, self.cert0), (1, 3, None)],
            self.ca, self.ee, self.txn_id,
            b"n2", b"n1", self.t0))
        self.assertTrue(result.accepted, result.detail)
        record = self.record()
        self.assertEqual(record.certs[0].state, CertReqState.ISSUED)
        self.assertEqual(record.certs[1].state, CertReqState.WAITING)
        self.assertEqual(record.certs[0].cert_hash, sha256_der(self.cert0))
        self.assertEqual(record.installed_certs, {})

        # Polling round trip for the waiting id.
        result = self.validate(builders.poll_req(
            [1], self.ee, self.ca, self.txn_id,
            b"n3", b"n2", self.t0))
        self.assertTrue(result.accepted, result.detail)
        self.clock.advance(5)
        result = self.validate(builders.poll_rep(
            [(1, 120)], self.ca, self.ee, self.txn_id,
            b"n4", b"n3", self.clock.now))
        self.assertTrue(result.accepted, result.detail)

        # Polling again before checkAfter must be rejected deterministically.
        early = builders.poll_req(
            [1], self.ee, self.ca, self.txn_id,
            b"n5", b"n4", self.clock.now)
        self.assert_reject(self.validate(early), RejectReason.POLL_TOO_EARLY)

        # The rejected message consumed no state: retry after the deadline.
        self.clock.advance(120)
        result = self.validate(builders.poll_req(
            [1], self.ee, self.ca, self.txn_id,
            b"n5", b"n4", self.clock.now))
        self.assertTrue(result.accepted, result.detail)
        result = self.validate(builders.ip(
            [(1, 0, self.cert1)], self.ca, self.ee, self.txn_id,
            b"n6", b"n5", self.clock.now))
        self.assertTrue(result.accepted, result.detail)
        record = self.record()
        self.assertEqual(record.certs[1].state, CertReqState.ISSUED)

        # certConf must cover every issued id, not only the first one.
        incomplete = builders.cert_conf(
            [(0, sha256_der(self.cert0))],
            self.ee, self.ca, self.txn_id,
            b"n7", b"n6", self.clock.now)
        self.assert_reject(self.validate(incomplete),
                           RejectReason.MISSING_CERT_RESPONSE)

        result = self.validate(builders.cert_conf(
            [(0, sha256_der(self.cert0)), (1, sha256_der(self.cert1))],
            self.ee, self.ca, self.txn_id,
            b"n7", b"n6", self.clock.now))
        self.assertTrue(result.accepted, result.detail)
        record = result.transaction
        self.assertEqual(set(record.installed_certs), {0, 1})
        self.assertEqual(
            record.installed_certs[0], der_encoder.encode(self.cert0))

        result = self.validate(builders.pki_conf(
            self.ca, self.ee, self.txn_id,
            b"n8", b"n7", self.clock.now))
        self.assertTrue(result.accepted, result.detail)
        self.assertIs(result.transaction.phase, TransactionPhase.COMPLETED)

    def test_duplicate_der_message_is_replayed_and_idempotent(self):
        ir_der = builders.ir(
            [0], self.ee, self.ca, self.txn_id,
            b"n1", self.t0)
        self.assertTrue(self.validator.validate(ir_der).accepted)
        replay = self.validator.validate(ir_der)
        self.assert_reject(replay, RejectReason.DUPLICATE_MESSAGE)
        # Only one transaction exists and remains open.
        self.assertEqual(len(self.validator.records), 1)
        self.assertIs(self.record().phase, TransactionPhase.OPEN)

    def test_bad_recipient_nonce_and_reused_sender_nonce(self):
        self.open_transaction(cert_req_ids=(0,))
        good_ip = builders.ip(
            [(0, 3, None)], self.ca, self.ee, self.txn_id,
            b"n2", b"n1", self.t0)
        tampered = builders.ip(
            [(0, 3, None)], self.ca, self.ee, self.txn_id,
            b"n2", b"wrong-recip-nonce", self.t0)
        self.assert_reject(
            self.validate(tampered), RejectReason.BAD_RECIPIENT_NONCE)
        # Rejection does not advance the nonce chain.
        self.assertTrue(self.validate(good_ip).accepted)

        # A reused sender nonce is a replay even with fresh DER bytes.
        reused = builders.poll_req(
            [0], self.ee, self.ca, self.txn_id,
            b"n2", b"n2", self.t0)
        self.assert_reject(self.validate(reused),
                           RejectReason.BAD_SENDER_NONCE)

    def test_late_poll_rep_after_certificate_is_ready(self):
        self.open_transaction(cert_req_ids=(0,))
        self.assertTrue(self.validate(builders.ip(
            [(0, 0, self.cert0)], self.ca, self.ee, self.txn_id,
            b"n2", b"n1", self.t0)).accepted)
        # No pollReq is outstanding, so a pollRep is stale/unsolicited.
        late = builders.poll_rep(
            [(0, 60)], self.ca, self.ee, self.txn_id,
            b"n3", b"n2", self.t0)
        self.assert_reject(self.validate(late), RejectReason.LATE_POLL_REP)
        # The issued certificate is untouched and can still be confirmed.
        self.assertEqual(
            self.record().certs[0].state, CertReqState.ISSUED)
        ok = builders.cert_conf(
            [(0, sha256_der(self.cert0))],
            self.ee, self.ca, self.txn_id,
            b"n4", b"n2", self.t0)
        self.assertTrue(self.validate(ok).accepted)

    def test_unknown_cert_req_id_is_rejected_everywhere(self):
        self.open_transaction(cert_req_ids=(0,))
        bad_ip = builders.ip(
            [(9, 0, self.cert0)], self.ca, self.ee, self.txn_id,
            b"n2", b"n1", self.t0)
        self.assert_reject(self.validate(bad_ip), RejectReason.BAD_CERT_ID)
        bad_poll = builders.poll_req(
            [9], self.ee, self.ca, self.txn_id,
            b"n3", b"n1", self.t0)
        self.assert_reject(self.validate(bad_poll), RejectReason.BAD_CERT_ID)

    def test_terminal_transaction_rejects_further_messages(self):
        self.open_transaction(cert_req_ids=(0,))
        self.assertTrue(self.validate(builders.ip(
            [(0, 0, self.cert0)], self.ca, self.ee, self.txn_id,
            b"n2", b"n1", self.t0)).accepted)
        self.assertTrue(self.validate(builders.cert_conf(
            [(0, sha256_der(self.cert0))],
            self.ee, self.ca, self.txn_id,
            b"n3", b"n2", self.t0)).accepted)
        self.assertTrue(self.validate(builders.pki_conf(
            self.ca, self.ee, self.txn_id,
            b"n4", b"n3", self.t0)).accepted)

        after = builders.poll_req(
            [0], self.ee, self.ca, self.txn_id,
            b"n5", b"n4", self.t0)
        self.assert_reject(self.validate(after), RejectReason.TRANSACTION_TERMINATED)
        # Same txnID cannot be re-used by the same client either.
        re_open = builders.ir(
            [0], self.ee, self.ca, self.txn_id,
            b"n6", self.t0)
        self.assert_reject(self.validate(re_open), RejectReason.TRANSACTION_TERMINATED)

    def test_transaction_id_in_use_for_same_client(self):
        self.open_transaction(cert_req_ids=(0,))
        duplicate = builders.ir(
            [0], self.ee, self.ca, self.txn_id,
            b"n2", self.t0)
        self.assert_reject(self.validate(duplicate), RejectReason.TRANSACTION_ID_IN_USE)

    def test_wrong_parties_and_unknown_transaction(self):
        self.open_transaction(cert_req_ids=(0,))
        # Another client tries to ride the known transactionID.
        foreign = builders.ip(
            [(0, 0, self.cert0)], self.ca, self.other, self.txn_id,
            b"n2", b"n1", self.t0)
        self.assert_reject(self.validate(foreign), RejectReason.WRONG_PARTIES)
        # A transactionID nobody ever used.
        unknown = builders.ip(
            [(0, 0, self.cert0)], self.ca, self.ee, b"never-seen",
            b"n2", b"n1", self.t0)
        self.assert_reject(self.validate(unknown), RejectReason.UNKNOWN_TRANSACTION_ID)

    def test_interleaved_transactions_are_independent(self):
        id_a, id_b = b"txn-A", b"txn-B"
        cert_a = builders.minimal_certificate(201)
        cert_b = builders.minimal_certificate(202)
        ee_b = builders.rfc822_name("ee-b@example.test")

        self.assertTrue(self.validate(builders.ir(
            [0], self.ee, self.ca, id_a, b"a1", self.t0)).accepted)
        self.assertTrue(self.validate(builders.ir(
            [0, 1], ee_b, self.ca, id_b, b"b1", self.t0)).accepted)

        # Interleave: an ip for B lands between A's ir and A's ip.
        self.assertTrue(self.validate(builders.ip(
            [(0, 0, cert_b), (1, 3, None)],
            self.ca, ee_b, id_b, b"b2", b"b1", self.t0)).accepted)
        self.assertTrue(self.validate(builders.ip(
            [(0, 0, cert_a)], self.ca, self.ee, id_a,
            b"a2", b"a1", self.t0)).accepted)

        rec_a = self.validator.get_transaction(
            der_encoder.encode(self.ee), id_a)
        rec_b = self.validator.get_transaction(
            der_encoder.encode(ee_b), id_b)
        self.assertEqual(rec_a.certs[0].state, CertReqState.ISSUED)
        self.assertEqual(rec_b.certs[0].state, CertReqState.ISSUED)
        self.assertEqual(rec_b.certs[1].state, CertReqState.WAITING)
        # B's certificate never lands in A's installed set.
        self.assertNotIn(der_encoder.encode(cert_b),
                         rec_a.installed_certs.values())

    def test_cert_bound_to_request_template_rejects_foreign_cert(self):
        requested = builders.minimal_certificate(300)
        foreign = builders.minimal_certificate(301)
        specs = [(0, builders.cert_subject(requested),
                  builders.cert_spki(requested))]
        self.assertTrue(self.validate(builders.ir(
            specs, self.ee, self.ca, self.txn_id, b"n1", self.t0)).accepted)

        # A cryptographically well-formed cert for a different subject/key
        # must not be installed into this transaction.
        attack = builders.ip(
            [(0, 0, foreign)], self.ca, self.ee, self.txn_id,
            b"n2", b"n1", self.t0)
        self.assert_reject(
            self.validate(attack),
            RejectReason.CERT_DOES_NOT_MATCH_REQUEST)
        self.assertEqual(self.record().installed_certs, {})
        # The correct certificate is still accepted afterwards.
        good = builders.ip(
            [(0, 0, requested)], self.ca, self.ee, self.txn_id,
            b"n2", b"n1", self.t0)
        self.assertTrue(self.validate(good).accepted)

    def test_bad_cert_hash_does_not_install(self):
        self.open_transaction(cert_req_ids=(0,))
        self.assertTrue(self.validate(builders.ip(
            [(0, 0, self.cert0)], self.ca, self.ee, self.txn_id,
            b"n2", b"n1", self.t0)).accepted)
        bad_hash = builders.cert_conf(
            [(0, b"\x11" * 32)], self.ee, self.ca, self.txn_id,
            b"n3", b"n2", self.t0)
        self.assert_reject(self.validate(bad_hash), RejectReason.BAD_CERT_HASH)
        self.assertEqual(self.record().installed_certs, {})
        self.assertEqual(
            self.record().certs[0].state, CertReqState.ISSUED)
        # Correct confirmation still accepted afterwards.
        good = builders.cert_conf(
            [(0, sha256_der(self.cert0))],
            self.ee, self.ca, self.txn_id,
            b"n4", b"n2", self.t0)
        self.assertTrue(self.validate(good).accepted)

    def test_message_time_skew_and_backwards_time(self):
        self.open_transaction(cert_req_ids=(0,))
        future = self.t0 + timedelta(minutes=30)
        skewed = builders.ip(
            [(0, 3, None)], self.ca, self.ee, self.txn_id,
            b"n2", b"n1", future)
        self.assert_reject(self.validate(skewed), RejectReason.BAD_MESSAGE_TIME)
        past = self.t0 - timedelta(seconds=10)
        backwards = builders.ip(
            [(0, 3, None)], self.ca, self.ee, self.txn_id,
            b"n2", b"n1", past)
        self.assert_reject(self.validate(backwards), RejectReason.BAD_MESSAGE_TIME)
        ok = builders.ip(
            [(0, 3, None)], self.ca, self.ee, self.txn_id,
            b"n2", b"n1", self.t0)
        self.assertTrue(self.validate(ok).accepted)

    def test_rejected_message_never_poisons_state_or_seen_set(self):
        self.open_transaction(cert_req_ids=(0,))
        # Malformed input is rejected the same way on every attempt and never
        # becomes a "duplicate" or opens a transaction.
        for _ in range(2):
            self.assert_reject(
                self.validator.validate(b"\x00\x01garbage"),
                RejectReason.MALFORMED_DER)
        self.assertEqual(len(self.validator.records), 1)

        bad_nonce = builders.ip(
            [(0, 3, None)], self.ca, self.ee, self.txn_id,
            b"n2", b"nope", self.t0)
        self.assert_reject(
            self.validate(bad_nonce), RejectReason.BAD_RECIPIENT_NONCE)
        # Re-sending the rejected DER keeps yielding the same deterministic
        # reason because it was never admitted to the seen set.
        self.assert_reject(
            self.validate(bad_nonce), RejectReason.BAD_RECIPIENT_NONCE)
        good = builders.ip(
            [(0, 3, None)], self.ca, self.ee, self.txn_id,
            b"n2", b"n1", self.t0)
        self.assertTrue(self.validate(good).accepted)
        self.assertEqual(
            self.record().certs[0].state, CertReqState.WAITING)

    def test_unsupported_and_malformed_inputs(self):
        self.assert_reject(
            self.validator.validate(b"not-der"),
            RejectReason.MALFORMED_DER)
        # error body (PKIBody tag [23]) is outside the supported scope.
        body = rfc4210.PKIBody()
        body.setComponentByName(
            "error", rfc4210.ErrorMsgContent().subtype(explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 23)))
        error_content = body.getComponentByName("error")
        status_info = rfc4210.PKIStatusInfo()
        status_info.setComponentByName("status", rfc4210.PKIStatus(2))
        error_content.setComponentByName("pKIStatusInfo", status_info)
        message = rfc4210.PKIMessage()
        message.setComponentByName(
            "header",
            builders._header(
                self.ca, self.ee, self.txn_id, b"n1", None, self.t0))
        message.setComponentByName("body", body)
        self.assert_reject(
            self.validator.validate(der_encoder.encode(message)),
            RejectReason.UNSUPPORTED_BODY)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == "__main__":
    unittest.main()
