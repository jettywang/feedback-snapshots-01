#
# This file is part of pyasn1-modules software.
#
# License: http://snmplabs.com/pyasn1/license.html
#

import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import char, tag, univ

from pyasn1_modules import pem
from pyasn1_modules import rfc5280
from pyasn1_modules import rfc5652
from pyasn1_modules import rfc7191
from pyasn1_modules import rfc7191_receipts as receipts


def make_name(common_name, string_type=char.UTF8String, extra_rdn=None):
    attribute = rfc5280.AttributeTypeAndValue()
    attribute['type'] = rfc5280.id_at_commonName
    attribute['value'] = string_type(common_name)
    rdn = rfc5280.RelativeDistinguishedName()
    rdn.append(attribute)
    name = rfc5280.Name()
    name['rdnSequence'].append(rdn)
    if extra_rdn is not None:
        name['rdnSequence'].append(extra_rdn)
    return der_encoder(name)


def make_entity(common_name, string_type=char.UTF8String, extra_rdn=None):
    value = rfc7191.siren_dn()
    value['sirenValue'] = make_name(common_name, string_type, extra_rdn)
    return receipts.entity_from_siren(value)


def make_receipt(package_id, received_by):
    value = rfc7191.KeyPackageReceipt()
    value['receiptOf'] = package_id
    value['receivedBy'] = _siren(received_by)
    return value


def make_error(package_id, error_by, code=10, error_of=True):
    value = rfc7191.KeyPackageError()
    if error_of and package_id is not None:
        tagged = rfc7191.KeyPkgIdentifier().subtype(
            implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 0))
        if package_id.getName() == 'pkgID':
            tagged['pkgID'] = bytes(package_id['pkgID'])
        else:
            tagged['attribute'] = package_id['attribute']
        value['errorOf'] = tagged
    value['errorBy'] = _siren(error_by)
    choice = rfc7191.ErrorCodeChoice()
    choice['enum'] = rfc7191.EnumeratedErrorCode(code)
    value['errorCode'] = choice
    return value


def _siren(entity):
    value = rfc7191.siren_dn()
    value['sirenValue'] = entity.value_der
    return value


class CorrelationTestCase(unittest.TestCase):
    def setUp(self):
        self.alice = make_entity('Alice')
        self.bob = make_entity('Bob')
        self.kta = make_entity('kta.example.com')
        self.pkg = receipts.PackageIdentifier.for_pkg_id(b'package-0001')
        self.request = receipts.ReceiptRequest(
            receipts_to=(self.kta,),
            receipts_from=(self.alice, self.bob),
        )
        self.send = receipts.SendRecord(
            package_id=self.pkg,
            recipients=(self.alice, self.bob),
            receipt_request=self.request,
            receipt_recipient=self.kta,
        )

    def receipt(self, entity, package_id=None):
        return receipts.VerifiedReceipt.create(
            make_receipt(package_id or self._asn1_pkg_id(), entity),
            entity,
        )

    def error(self, entity, code=10, package_id=None, error_of=True):
        return receipts.VerifiedReceipt.create(
            make_error(
                package_id or self._asn1_pkg_id(), entity,
                code=code, error_of=error_of),
            entity,
        )

    def _asn1_pkg_id(self):
        value = rfc7191.KeyPkgIdentifier()
        value['pkgID'] = self.pkg.pkg_id
        return value

    def status_of(self, result, entity):
        for package in result.packages:
            state = package.recipient(entity)
            if state is not None:
                return state.status
        raise AssertionError('entity not found in result')


class TimelineTestCase(CorrelationTestCase):
    def test_out_of_order_both_confirm(self):
        timeline = receipts.ReceiptCorrelator(self.send)
        timeline.add(self.receipt(self.bob))

        partial = timeline.result
        self.assertFalse(partial.complete)
        self.assertFalse(partial.resolved)
        self.assertEqual(
            (self.alice.evidence()['sirenValue'],),
            tuple(item['entity']['sirenValue']
                  for item in partial.pending()))

        timeline.add(self.receipt(self.alice))
        final = timeline.result
        self.assertTrue(final.complete)
        self.assertTrue(final.resolved)
        self.assertEqual((), final.pending())
        self.assertEqual(
            receipts.DeliveryStatus.CONFIRMED,
            self.status_of(final, self.alice))
        self.assertEqual(
            receipts.DeliveryStatus.CONFIRMED,
            self.status_of(final, self.bob))

    def test_duplicate_forged_evidence_is_idempotent(self):
        forged = receipts.VerifiedReceipt.create(
            make_receipt(self._asn1_pkg_id(), self.bob), self.alice)
        timeline = receipts.ReceiptCorrelator(self.send)
        timeline.add(forged)
        timeline.add(forged)
        result = timeline.result
        self.assertFalse(result.complete)
        self.assertEqual(1, len(result.rejected()))
        self.assertEqual(
            1, result.packages[0].recipients[0].duplicate_count)

    def test_duplicate_receipt_is_idempotent(self):
        timeline = receipts.ReceiptCorrelator(self.send)
        first = timeline.add(self.receipt(self.alice))
        second = timeline.add(self.receipt(self.alice))
        self.assertEqual(first.receipt_der, second.receipt_der)
        state = timeline.result.packages[0].recipient(self.alice)
        self.assertEqual(receipts.DeliveryStatus.CONFIRMED, state.status)
        self.assertEqual(1, state.duplicate_count)
        self.assertEqual(1, len(state.confirmations))
        self.assertEqual([], list(timeline.result.rejected()))

    def test_forged_received_by_does_not_advance(self):
        forged = receipts.VerifiedReceipt.create(
            make_receipt(self._asn1_pkg_id(), self.bob),
            self.alice,
        )
        result = receipts.correlate_receipts(self.send, [forged])
        self.assertFalse(result.complete)
        self.assertEqual(
            receipts.DeliveryStatus.PENDING,
            self.status_of(result, self.alice))
        self.assertEqual(
            receipts.DeliveryStatus.PENDING,
            self.status_of(result, self.bob))
        rejected = result.rejected()
        self.assertEqual(1, len(rejected))
        self.assertIn('receivedBy', rejected[0]['reason'])
        self.assertEqual(forged.evidence['contentDer'],
                         rejected[0]['evidence']['contentDer'])

    def test_legal_failure_receipt(self):
        result = receipts.correlate_receipts(
            self.send, [self.error(self.bob, code=10)])
        self.assertEqual(
            receipts.DeliveryStatus.FAILED,
            self.status_of(result, self.bob))
        self.assertEqual(
            receipts.DeliveryStatus.PENDING,
            self.status_of(result, self.alice))
        self.assertFalse(result.complete)
        self.assertFalse(result.resolved)
        failures = result.failures()
        self.assertEqual(1, len(failures))
        self.assertEqual('noTrustAnchor',
                         failures[0]['errors'][0]['errorCode']['name'])
        self.assertIn('missing confirmation', result.status())
        self.assertIn('noTrustAnchor', result.status())

    def test_conflicting_evidence_does_not_confirm(self):
        result = receipts.correlate_receipts(
            self.send,
            [self.receipt(self.alice), self.error(self.alice, code=10)])
        self.assertFalse(result.complete)
        self.assertEqual(
            receipts.DeliveryStatus.CONFLICTED,
            self.status_of(result, self.alice))
        self.assertFalse(result.complete)
        self.assertEqual(1, len(result.conflicts()))
        self.assertIn('both confirmation and failure',
                      result.conflicts()[0]['reason'])

    def test_conflicting_error_codes_do_not_resolve(self):
        result = receipts.correlate_receipts(
            self.send,
            [self.error(self.alice, code=10),
             self.error(self.alice, code=16)])
        self.assertEqual(
            receipts.DeliveryStatus.CONFLICTED,
            self.status_of(result, self.alice))
        self.assertIn('conflicting error codes',
                      result.conflicts()[0]['reason'])
        self.assertFalse(result.complete)

    def test_error_without_package_does_not_advance(self):
        orphan = receipts.VerifiedReceipt.create(
            make_error(None, self.bob, code=10, error_of=False),
            self.bob,
        )
        result = receipts.correlate_receipts(self.send, [orphan])
        self.assertEqual(
            receipts.DeliveryStatus.PENDING,
            self.status_of(result, self.alice))
        self.assertEqual(
            receipts.DeliveryStatus.PENDING,
            self.status_of(result, self.bob))
        self.assertFalse(result.complete)
        self.assertEqual(1, len(result.unrouted))
        self.assertIn('does not identify', result.unrouted[0].reason)

    def test_forged_error_by_does_not_advance(self):
        forged = receipts.VerifiedReceipt.create(
            make_error(self._asn1_pkg_id(), self.bob, code=10),
            self.alice,
        )
        result = receipts.correlate_receipts(self.send, [forged])
        self.assertEqual(
            receipts.DeliveryStatus.PENDING,
            self.status_of(result, self.alice))
        self.assertIn('errorBy', result.rejected()[0]['reason'])

    def test_unknown_package_is_rejected(self):
        other = receipts.PackageIdentifier.for_pkg_id(b'other-package')
        other_asn1 = rfc7191.KeyPkgIdentifier()
        other_asn1['pkgID'] = other.pkg_id
        unknown = receipts.VerifiedReceipt.create(
            make_receipt(other_asn1, self.alice),
            self.alice,
        )
        result = receipts.correlate_receipts(self.send, [unknown])
        self.assertFalse(result.complete)
        self.assertEqual(1, len(result.unrouted))
        self.assertIn('no send record', result.unrouted[0].reason)


class IdentityTestCase(CorrelationTestCase):
    def test_display_name_is_not_identity(self):
        # Same CN text, but a different DER string type.  A display-name
        # comparison would merge these entities; exact evidence must not.
        lookalike = make_entity('Alice', char.PrintableString)
        self.assertNotEqual(self.alice, lookalike)

        forged = receipts.VerifiedReceipt.create(
            make_receipt(self._asn1_pkg_id(), lookalike),
            self.alice,
        )
        result = receipts.correlate_receipts(self.send, [forged])
        self.assertFalse(result.complete)
        self.assertEqual(
            receipts.DeliveryStatus.PENDING,
            self.status_of(result, self.alice))
        self.assertEqual(1, len(result.rejected()))

    def test_same_dn_bytes_confirm(self):
        same = make_entity('Alice')
        self.assertEqual(self.alice, same)
        result = receipts.correlate_receipts(
            self.send, [self.receipt(same)])
        self.assertEqual(
            receipts.DeliveryStatus.CONFIRMED,
            self.status_of(result, self.alice))

    def test_entity_outside_recipients_is_rejected(self):
        outsider = receipts.VerifiedReceipt.create(
            make_receipt(self._asn1_pkg_id(), self.kta), self.kta)
        result = receipts.correlate_receipts(self.send, [outsider])
        self.assertFalse(result.complete)
        rejected = result.rejected()
        self.assertEqual(1, len(rejected))
        self.assertIn('not a protected recipient', rejected[0]['reason'])

    def test_receipts_from_request_is_enforced(self):
        request = receipts.ReceiptRequest(
            receipts_to=(self.kta,), receipts_from=(self.alice,))
        send = receipts.SendRecord(
            package_id=self.pkg,
            recipients=(self.alice, self.bob),
            receipt_request=request,
            receipt_recipient=self.kta,
        )
        result = receipts.correlate_receipts(
            send, [self.receipt(self.bob)])
        self.assertEqual(
            receipts.DeliveryStatus.PENDING,
            self.status_of(result, self.bob))
        self.assertIn('receiptsFrom', result.rejected()[0]['reason'])

    def test_receipts_to_is_enforced(self):
        # The originator addressed receiptsTo to Alice, not to this service
        # (the KTA).  The evidence is therefore misdelivered and cannot
        # confirm delivery.
        request = receipts.ReceiptRequest(
            receipts_to=(self.alice,),
            receipts_from=(self.alice, self.bob),
        )
        send = receipts.SendRecord(
            package_id=self.pkg,
            recipients=(self.alice, self.bob),
            receipt_request=request,
            receipt_recipient=self.kta,
        )
        result = receipts.correlate_receipts(
            send, [self.receipt(self.alice)])
        self.assertEqual(
            receipts.DeliveryStatus.PENDING,
            self.status_of(result, self.alice))
        self.assertIn('receiptsTo', result.rejected()[0]['reason'])


class PackageIdentifierTestCase(CorrelationTestCase):
    def test_pkg_id_and_attribute_are_distinct_representations(self):
        attr_type = rfc5280.id_at_commonName
        attribute = receipts.PackageIdentifier.for_attribute(
            attr_type, der_encoder(char.UTF8String('package-0001')))
        self.assertEqual('attribute', attribute.kind)
        self.assertNotEqual(self.pkg, attribute)

        result = receipts.correlate_receipts(
            self.send,
            [receipts.VerifiedReceipt.create(
                make_receipt(self._asn1_pkg_id(attribute), self.alice),
                self.alice)])
        self.assertFalse(result.complete)
        self.assertEqual(
            receipts.DeliveryStatus.PENDING,
            self.status_of(result, self.alice))
        self.assertEqual(1, len(result.unrouted))

    def test_attribute_identifier_matches_same_representation(self):
        attribute = receipts.PackageIdentifier.for_attribute(
            rfc5280.id_at_commonName,
            der_encoder(char.UTF8String('package-0001')))
        send = receipts.SendRecord(
            package_id=attribute,
            recipients=(self.alice,),
            receipt_request=self.request,
            receipt_recipient=self.kta,
        )
        asn1_id = rfc7191.KeyPkgIdentifier()
        single = rfc7191.SingleAttribute()
        single['attrType'] = rfc5280.id_at_commonName
        single['attrValues'][0] = der_encoder(char.UTF8String('package-0001'))
        asn1_id['attribute'] = single
        evidence = receipts.VerifiedReceipt.create(
            make_receipt(asn1_id, self.alice), self.alice)
        self.assertEqual(attribute, evidence.package_id)
        result = receipts.correlate_receipts(send, [evidence])
        self.assertTrue(result.complete)

    def test_original_identifier_evidence_is_retained(self):
        content = der_encoder(
            make_receipt(self._asn1_pkg_id(), self.alice))
        evidence = receipts.VerifiedReceipt.create(content, self.alice)
        identifier = evidence.evidence['receiptOf']
        self.assertEqual(self.pkg.der.hex(), identifier['der'].lower())
        self.assertEqual(self.pkg.der.hex(), identifier['fieldDer'].lower())
        self.assertEqual(content.hex(), evidence.evidence['contentDer'])
        self.assertTrue(evidence.receipt_der)

    def test_error_identifier_field_evidence_retains_explicit_tag(self):
        content = der_encoder(make_error(
            self._asn1_pkg_id(), self.alice, code=10))
        evidence = receipts.VerifiedReceipt.create(content, self.alice)
        field_der = evidence.evidence['errorOf']['fieldDer']
        self.assertTrue(field_der.startswith('a0'))
        self.assertIn(self.pkg.pkg_id.hex(), field_der)
        self.assertEqual(content.hex(), evidence.evidence['contentDer'])

    def _asn1_pkg_id(self, package_id=None):
        package_id = package_id or self.pkg
        if package_id.kind == 'pkgID':
            value = rfc7191.KeyPkgIdentifier()
            value['pkgID'] = package_id.pkg_id
            return value
        value = rfc7191.KeyPkgIdentifier()
        single = rfc7191.SingleAttribute()
        single['attrType'] = univ.ObjectIdentifier(
            package_id.attribute_type)
        for index, item in enumerate(package_id.attribute_values):
            single['attrValues'][index] = item
        value['attribute'] = single
        return value


class SendRecordConstructionTestCase(CorrelationTestCase):
    def test_build_from_key_package_attribute(self):
        attribute = rfc7191.KeyPkgIdentifierAndReceiptReq()
        attribute['pkgID'] = self.pkg.pkg_id
        request = rfc7191.KeyPkgReceiptReq()
        request['receiptsFrom'].append(_siren(self.bob))
        request['receiptsTo'].append(_siren(self.kta))
        attribute['receiptReq'] = request

        record = receipts.SendRecord.from_key_package_attribute(
            der_encoder(attribute),
            recipients=(self.alice, self.bob),
            receipt_recipient=self.kta,
        )
        self.assertEqual(self.pkg, record.package_id)
        self.assertFalse(record.requires_receipt_from(self.alice))
        self.assertTrue(record.requires_receipt_from(self.bob))

        result = receipts.correlate_receipts(
            record, [self.receipt(self.alice)])
        self.assertEqual(
            receipts.DeliveryStatus.PENDING,
            self.status_of(result, self.alice))
        self.assertIn('receiptsFrom', result.rejected()[0]['reason'])

    def test_absent_receipts_from_asks_all_recipients(self):
        request = receipts.ReceiptRequest(receipts_to=(self.kta,))
        send = receipts.SendRecord(
            package_id=self.pkg,
            recipients=(self.alice, self.bob),
            receipt_request=request,
            receipt_recipient=self.kta,
        )
        self.assertTrue(send.requires_receipt_from(self.alice))
        self.assertTrue(send.requires_receipt_from(self.bob))
        result = receipts.correlate_receipts(
            send, [self.receipt(self.bob)])
        self.assertEqual(
            receipts.DeliveryStatus.CONFIRMED,
            self.status_of(result, self.bob))


class DeliveryStatusTestCase(CorrelationTestCase):
    def test_receipt_request_requires_local_receipt_recipient(self):
        with self.assertRaises(receipts.CorrelationError):
            receipts.SendRecord(
                package_id=self.pkg,
                recipients=(self.alice, self.bob),
                receipt_request=receipts.ReceiptRequest(
                    receipts_to=(self.kta,)),
            )

    def test_no_receipt_request_keeps_signed_error_valid(self):
        send = receipts.SendRecord(
            package_id=self.pkg,
            recipients=(self.alice, self.bob),
        )
        result = receipts.correlate_receipts(
            send, [self.receipt(self.alice), self.error(self.bob, code=10)])
        self.assertEqual(
            receipts.DeliveryStatus.PENDING,
            self.status_of(result, self.alice))
        self.assertEqual(
            receipts.DeliveryStatus.FAILED,
            self.status_of(result, self.bob))
        self.assertIn('did not request a receipt',
                      result.rejected()[0]['reason'])


class MultiplePackageTestCase(CorrelationTestCase):
    def test_same_receipt_cannot_confirm_two_packages(self):
        other = receipts.PackageIdentifier.for_pkg_id(b'package-0002')
        other_asn1 = rfc7191.KeyPkgIdentifier()
        other_asn1['pkgID'] = other.pkg_id
        second = receipts.SendRecord(
            package_id=other,
            recipients=(self.alice, self.bob),
            receipt_request=self.request,
            receipt_recipient=self.kta,
        )
        result = receipts.correlate_receipts(
            [self.send, second],
            [self.receipt(self.alice)])
        self.assertEqual(
            receipts.DeliveryStatus.CONFIRMED,
            self.status_of(result, self.alice))
        second_state = result.packages[1].recipient(self.alice)
        self.assertEqual(receipts.DeliveryStatus.PENDING,
                         second_state.status)
        self.assertFalse(result.complete)

    def test_duplicate_send_identifiers_are_rejected(self):
        with self.assertRaises(receipts.CorrelationError):
            receipts.correlate_receipts(
                [self.send, self.send], [self.receipt(self.alice)])


class CmsInputTestCase(CorrelationTestCase):
    def _content_info(self, content):
        signed = rfc5652.SignedData()
        signed['version'] = 3
        digest_alg = rfc5652.DigestAlgorithmIdentifier()
        digest_alg['algorithm'] = univ.ObjectIdentifier('2.16.840.1.101.3.4.2.1')
        signed['digestAlgorithms'].append(digest_alg)
        encap = rfc5652.EncapsulatedContentInfo()
        encap['eContentType'] = rfc7191.id_ct_KP_keyPackageReceipt
        encap['eContent'] = der_encoder(content)
        signed['encapContentInfo'] = encap
        signer = rfc5652.SignerInfo()
        signer['version'] = 3
        signer['sid']['subjectKeyIdentifier'] = b'\x01' * 20
        signer['digestAlgorithm'] = digest_alg
        signature_alg = rfc5652.SignatureAlgorithmIdentifier()
        signature_alg['algorithm'] = digest_alg['algorithm']
        signer['signatureAlgorithm'] = signature_alg
        signer['signature'] = b'\x00'
        signed['signerInfos'].append(signer)
        info = rfc5652.ContentInfo()
        info['contentType'] = rfc5652.id_signedData
        info['content'] = der_encoder(signed)
        return info

    def test_signed_content_info_is_parsed(self):
        content = make_receipt(self._asn1_pkg_id(), self.alice)
        info = self._content_info(content)
        evidence = receipts.VerifiedReceipt.from_cms(info, self.alice)
        self.assertEqual('receipt', evidence.kind)
        self.assertEqual(self.pkg, evidence.package_id)
        self.assertEqual(evidence.evidence['receiptDer'],
                         der_encoder(info).hex())
        result = receipts.correlate_receipts(self.send, [evidence])
        self.assertEqual(
            receipts.DeliveryStatus.CONFIRMED,
            self.status_of(result, self.alice))

    def test_outer_verification_failure_is_not_accepted(self):
        info = self._content_info(
            make_receipt(self._asn1_pkg_id(), self.alice))
        with self.assertRaises(receipts.CorrelationError):
            receipts.VerifiedReceipt.from_cms(
                info, self.alice, verify_outer=lambda signer, content: False)

    def _asn1_pkg_id(self):
        value = rfc7191.KeyPkgIdentifier()
        value['pkgID'] = self.pkg.pkg_id
        return value


class PublishedVectorTestCase(unittest.TestCase):
    """Use the RFC 7191 receipt vector already exercised by test_rfc7191."""

    receipt_pem = """\
MIIEdAYJKoZIhvcNAQcCoIIEZTCCBGECAQMxDTALBglghkgBZQMEAgIwgawGCmCGSAFlAgEC
TgOggZ0EgZowgZcEFCe4nFY7FiJRnReHHHm/rIht3/g9MH8GCWCGSAFlAgEQAARyMHAxCzAJ
BgNVBAYTAlVTMQswCQYDVQQIEwJWQTEQMA4GA1UEBxMHSGVybmRvbjEQMA4GA1UEChMHRXhh
bXBsZTEOMAwGA1UEAxMFQWxpY2UxIDAeBgkqhkiG9w0BCQEWEWFsaWNlQGV4YW1wbGUuY29t
oIICfDCCAngwggH+oAMCAQICCQCls1QoG7BuOzAKBggqhkjOPQQDAzA/MQswCQYDVQQGEwJV
UzELMAkGA1UECAwCVkExEDAOBgNVBAcMB0hlcm5kb24xETAPBgNVBAoMCEJvZ3VzIENBMB4X
DTE5MDUyOTE0NDU0MVoXDTIwMDUyODE0NDU0MVowcDELMAkGA1UEBhMCVVMxCzAJBgNVBAgT
AlZBMRAwDgYDVQQHEwdIZXJuZG9uMRAwDgYDVQQKEwdFeGFtcGxlMQ4wDAYDVQQDEwVBbGlj
ZTEgMB4GCSqGSIb3DQEJARYRYWxpY2VAZXhhbXBsZS5jb20wdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAAT4zZ8HL+xEDpXWkoWp5xFMTz4u4Ae1nF6zXCYlmsEGD5vPu5hl9hDEjd1UHRgJIPoy
3fJcWWeZ8FHCirICtuMgFisNscG/aTwKyDYOFDuqz/C2jyEwqgWCRyxyohuJXtmjgZQwgZEw
CwYDVR0PBAQDAgeAMEIGCWCGSAGG+EIBDQQ1FjNUaGlzIGNlcnRpZmljYXRlIGNhbm5vdCBi
ZSB0cnVzdGVkIGZvciBhbnkgcHVycG9zZS4wHQYDVR0OBBYEFMS6Wg4+euM8gbD0Aqpouxbg
lg41MB8GA1UdIwQYMBaAFPI12zQE2qVV8r1pA5mwYuziFQjBMAoGCCqGSM49BAMDA2gAMGUC
MGO5H9E1uAveRGGaf48lN4pov2yH+hCAc5hOAuZKe/f40MKSF8q4w2ij+0euSaKFiAIxAL3g
xp6sMitCmLQgOH6/RBIC/2syJ97y0KVp9da0PDAvwxLugCHTKZPjjpSLPHHc9TGCARwwggEY
AgEDgBTEuloOPnrjPIGw9AKqaLsW4JYONTALBglghkgBZQMEAgKgejAZBgkqhkiG9w0BCQMx
DAYKYIZIAWUCAQJOAzAcBgkqhkiG9w0BCQUxDxcNMTkwNjEzMTYxNjA4WjA/BgkqhkiG9w0B
CQQxMgQwQSWYpq4jwhMkmS0as0JL3gjYxKLgDfzP2ndTNsAY0m9p8Igp8ZcK4+5n9fXJ43vU
MAoGCCqGSM49BAMDBGgwZgIxAMfq2EJ5pSl9tGOEVJEgZitc266ljrOg5GDjkd2d089qw1A3
bUcOYuCdivgxVuhlAgIxAPR9JavxziwCbVyBUWOAiKKYfglTgG3AwNmrKDj0NtXUQ9qDmGAc
6L+EAY2P5OVB8Q==
"""

    def test_real_receipt_matches_only_the_authenticated_subject(self):
        content_info = self._content_info()
        signed, rest = der_decoder(
            content_info['content'], asn1Spec=rfc5652.SignedData())
        self.assertFalse(rest)
        receipt, rest = der_decoder(
            signed['encapContentInfo']['eContent'],
            asn1Spec=rfc7191.KeyPackageReceipt())
        self.assertFalse(rest)
        claimed = receipts.entity_from_siren(receipt['receivedBy'])

        evidence = receipts.VerifiedReceipt.from_cms(content_info, claimed)
        send = receipts.SendRecord(
            package_id=evidence.package_id,
            recipients=(claimed,),
            receipt_request=receipts.ReceiptRequest(
                receipts_to=(claimed,)),
            receipt_recipient=claimed,
        )
        result = receipts.correlate_receipts(send, [evidence])
        self.assertTrue(result.complete)
        self.assertEqual(
            receipts.DeliveryStatus.CONFIRMED,
            result.packages[0].recipients[0].status)

        # The receipt is signed, but attribution still comes from the
        # authenticated subject.  A different subject cannot borrow it.
        forged = receipts.VerifiedReceipt.from_cms(
            content_info, receipts.entity_from_siren(
                self._other_entity()))
        forged_result = receipts.correlate_receipts(send, [forged])
        self.assertFalse(forged_result.complete)
        self.assertEqual(1, len(forged_result.rejected()))

    def _other_entity(self):
        value = rfc7191.siren_dn()
        value['sirenValue'] = make_name('Alice', char.PrintableString)
        return value

    def _content_info(self):
        content_info, rest = der_decoder(
            pem.readBase64fromText(self.receipt_pem),
            asn1Spec=rfc5652.ContentInfo())
        self.assertFalse(rest)
        return content_info


if __name__ == '__main__':
    unittest.main()
