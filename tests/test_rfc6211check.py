#
# This file is part of pyasn1-modules software.
#
# License: http://snmplabs.com/pyasn1/license.html
#
import sys
import unittest

from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_modules import pem
from pyasn1_modules import rfc4055
from pyasn1_modules import rfc5280
from pyasn1_modules import rfc5652
from pyasn1_modules import rfc6211
from pyasn1_modules import rfc6211check
from pyasn1_modules import rfc8018


_ID_SHA1 = rfc4055.id_sha1
_ID_SHA256 = rfc4055.id_sha256
_ID_SHA384 = rfc4055.id_sha384
_ID_SHA512 = rfc4055.id_sha512
_ID_PSS = rfc4055.id_RSASSA_PSS
_ID_HMAC_SHA1 = rfc8018.id_hmacWithSHA1
_ID_HMAC_SHA256 = rfc8018.id_hmacWithSHA256

_EXPLICIT_0 = tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
_EXPLICIT_1 = tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
_IMPLICIT_1 = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
_IMPLICIT_2 = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)


def _alg_id(oid, params=None):
    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id['algorithm'] = oid
    if params is not None:
        alg_id['parameters'] = params
    return alg_id


def _pss_params(hash_oid=None, mgf_hash_oid=None, salt_length=None,
                trailer_field=None):
    params = rfc4055.RSASSA_PSS_params()
    if hash_oid is not None:
        hash_alg = _alg_id(hash_oid, univ.Null(''))
        params['hashAlgorithm'] = hash_alg.subtype(
            explicitTag=_EXPLICIT_0, cloneValueFlag=True)
    if mgf_hash_oid is not None:
        mgf = _alg_id(rfc4055.id_mgf1, _alg_id(mgf_hash_oid, univ.Null('')))
        params['maskGenAlgorithm'] = mgf.subtype(
            explicitTag=_EXPLICIT_1, cloneValueFlag=True)
    if salt_length is not None:
        params['saltLength'] = salt_length
    if trailer_field is not None:
        params['trailerField'] = trailer_field
    return params


def _protection_der(digest_oid, digest_params=None, sig_alg=None,
                    mac_alg=None):
    protection = rfc6211.CMSAlgorithmProtection()
    protection['digestAlgorithm']['algorithm'] = digest_oid
    if digest_params is not None:
        protection['digestAlgorithm']['parameters'] = digest_params
    if sig_alg is not None:
        protection['signatureAlgorithm'] = sig_alg.subtype(
            implicitTag=_IMPLICIT_1, cloneValueFlag=True)
    if mac_alg is not None:
        protection['macAlgorithm'] = mac_alg.subtype(
            implicitTag=_IMPLICIT_2, cloneValueFlag=True)
    return der_encoder(protection)


def _both_present_protection_der(digest_oid, sig_alg, mac_alg):
    # signatureAlgorithm and macAlgorithm at once violate the RFC 6211
    # XOR constraint, so the encoder refuses a CMSAlgorithmProtection
    # value; build the raw SEQUENCE by hand instead
    both = univ.Sequence()
    both[0] = _alg_id(digest_oid)
    both[1] = sig_alg.subtype(implicitTag=_IMPLICIT_1, cloneValueFlag=True)
    both[2] = mac_alg.subtype(implicitTag=_IMPLICIT_2, cloneValueFlag=True)
    return der_encoder(both)


def _protection_attribute(protection_der, value_count=1):
    attribute = rfc5652.Attribute()
    attribute['attrType'] = rfc6211.id_aa_cmsAlgorithmProtect
    for idx in range(value_count):
        attribute['attrValues'][idx] = univ.Any(protection_der)
    return attribute


def _content_type_attribute():
    attribute = rfc5652.Attribute()
    attribute['attrType'] = rfc5652.id_contentType
    attribute['attrValues'][0] = univ.Any(der_encoder(
        univ.ObjectIdentifier(rfc5652.id_data)))
    return attribute


def _signer_info(digest_alg, sig_alg):
    signer_info = rfc5652.SignerInfo()
    signer_info['version'] = 3
    signer_info['sid']['subjectKeyIdentifier'] = b'\x01' * 20
    signer_info['digestAlgorithm'] = digest_alg
    signer_info['signatureAlgorithm'] = sig_alg
    signer_info['signature'] = b'\xaa' * 64
    return signer_info


def _authenticated_data(digest_alg, mac_alg):
    auth_data = rfc5652.AuthenticatedData()
    auth_data['version'] = 0
    if digest_alg is not None:
        # digestAlgorithm carries an implicit [1] tag; assign component-wise
        auth_data['digestAlgorithm']['algorithm'] = digest_alg['algorithm']
        if digest_alg['parameters'].isValue:
            auth_data['digestAlgorithm']['parameters'] = \
                digest_alg['parameters']
    auth_data['macAlgorithm'] = mac_alg
    auth_data['mac'] = b'\xbb' * 32
    return auth_data


class SignerInfoCheckTestCase(unittest.TestCase):

    def test_pss_equivalent_representations_match(self):
        # Outer identifier relies on RFC 4055 defaults (absent parameters);
        # the attribute spells the same defaults out in full
        outer_sig = _alg_id(_ID_PSS)
        declared_sig = _alg_id(_ID_PSS, univ.Any(der_encoder(_pss_params(
            hash_oid=_ID_SHA1, mgf_hash_oid=_ID_SHA1,
            salt_length=20, trailer_field=1))))

        signer_info = _signer_info(
            _alg_id(_ID_SHA256, univ.Null('')), outer_sig)
        signer_info['signedAttrs'][0] = _protection_attribute(
            _protection_der(_ID_SHA256, sig_alg=declared_sig))

        protection = rfc6211check.check_signer_info(signer_info)
        self.assertEqual(
            tuple(_ID_SHA256),
            tuple(protection['digestAlgorithm']['algorithm']))

        # Empty PSS SEQUENCE outside, absent parameters in the attribute
        signer_info = _signer_info(
            _alg_id(_ID_SHA256),
            _alg_id(_ID_PSS, univ.Any(der_encoder(_pss_params()))))
        signer_info['signedAttrs'][0] = _protection_attribute(
            _protection_der(_ID_SHA256, sig_alg=_alg_id(_ID_PSS)))

        protection = rfc6211check.check_signer_info(signer_info)
        self.assertTrue(protection['signatureAlgorithm'].isValue)

    def test_pss_parameter_substitution_rejected(self):
        outer_sig = _alg_id(_ID_PSS)  # all RFC 4055 defaults

        # Only the salt length is replaced (20 -> 32)
        declared_sig = _alg_id(_ID_PSS, univ.Any(der_encoder(
            _pss_params(salt_length=32))))

        signer_info = _signer_info(_alg_id(_ID_SHA256), outer_sig)
        signer_info['signedAttrs'][0] = _protection_attribute(
            _protection_der(_ID_SHA256, sig_alg=declared_sig))

        with self.assertRaises(rfc6211check.CMSAlgorithmProtectionError):
            rfc6211check.check_signer_info(signer_info)

        # Only the PSS hash algorithm is replaced (sha1 -> sha256)
        declared_sig = _alg_id(_ID_PSS, univ.Any(der_encoder(
            _pss_params(hash_oid=_ID_SHA256, mgf_hash_oid=_ID_SHA1))))

        signer_info = _signer_info(_alg_id(_ID_SHA256), outer_sig)
        signer_info['signedAttrs'][0] = _protection_attribute(
            _protection_der(_ID_SHA256, sig_alg=declared_sig))

        with self.assertRaises(rfc6211check.CMSAlgorithmProtectionError):
            rfc6211check.check_signer_info(signer_info)

    def test_digest_null_and_absent_parameters_equivalent(self):
        # NULL outside, absent inside the attribute
        signer_info = _signer_info(
            _alg_id(_ID_SHA512, univ.Null('')), _alg_id(_ID_PSS))
        signer_info['signedAttrs'][0] = _protection_attribute(
            _protection_der(_ID_SHA512, sig_alg=_alg_id(_ID_PSS)))

        protection = rfc6211check.check_signer_info(signer_info)
        self.assertEqual(
            tuple(_ID_SHA512),
            tuple(protection['digestAlgorithm']['algorithm']))

        # A genuinely different digest must still be caught
        signer_info = _signer_info(
            _alg_id(_ID_SHA512), _alg_id(_ID_PSS))
        signer_info['signedAttrs'][0] = _protection_attribute(
            _protection_der(_ID_SHA384, sig_alg=_alg_id(_ID_PSS)))

        with self.assertRaises(rfc6211check.CMSAlgorithmProtectionError):
            rfc6211check.check_signer_info(signer_info)

    def test_attribute_position(self):
        protection_der = _protection_der(
            _ID_SHA256, sig_alg=_alg_id(_ID_PSS))

        # Order within signedAttrs is irrelevant
        signer_info = _signer_info(
            _alg_id(_ID_SHA256), _alg_id(_ID_PSS))
        signer_info['signedAttrs'][0] = _content_type_attribute()
        signer_info['signedAttrs'][1] = _protection_attribute(protection_der)
        self.assertTrue(rfc6211check.check_signer_info(signer_info))

        signer_info = _signer_info(
            _alg_id(_ID_SHA256), _alg_id(_ID_PSS))
        signer_info['signedAttrs'][0] = _protection_attribute(protection_der)
        signer_info['signedAttrs'][1] = _content_type_attribute()
        self.assertTrue(rfc6211check.check_signer_info(signer_info))

        # Moved to unsignedAttrs the attribute is unauthenticated: it is
        # ignored (returns None) even though its content is inconsistent
        wrong_der = _protection_der(
            _ID_SHA384, sig_alg=_alg_id(_ID_PSS,
                                        univ.Any(der_encoder(
                                            _pss_params(salt_length=32)))))
        signer_info = _signer_info(
            _alg_id(_ID_SHA256), _alg_id(_ID_PSS))
        signer_info['signedAttrs'][0] = _content_type_attribute()
        signer_info['unsignedAttrs'][0] = _protection_attribute(wrong_der)

        self.assertIsNone(rfc6211check.check_signer_info(signer_info))

    def test_duplicate_attribute_rejected(self):
        protection_der = _protection_der(
            _ID_SHA256, sig_alg=_alg_id(_ID_PSS))

        signer_info = _signer_info(
            _alg_id(_ID_SHA256), _alg_id(_ID_PSS))
        signer_info['signedAttrs'][0] = _protection_attribute(protection_der)
        signer_info['signedAttrs'][1] = _protection_attribute(protection_der)

        with self.assertRaises(rfc6211check.CMSAlgorithmProtectionError):
            rfc6211check.check_signer_info(signer_info)

    def test_multiple_attribute_values_rejected(self):
        protection_der = _protection_der(
            _ID_SHA256, sig_alg=_alg_id(_ID_PSS))

        signer_info = _signer_info(
            _alg_id(_ID_SHA256), _alg_id(_ID_PSS))
        signer_info['signedAttrs'][0] = _protection_attribute(
            protection_der, value_count=2)

        with self.assertRaises(rfc6211check.CMSAlgorithmProtectionError):
            rfc6211check.check_signer_info(signer_info)

    def test_both_signature_and_mac_rejected(self):
        both_der = _both_present_protection_der(
            _ID_SHA256, _alg_id(_ID_PSS), _alg_id(_ID_HMAC_SHA256))

        signer_info = _signer_info(
            _alg_id(_ID_SHA256), _alg_id(_ID_PSS))
        signer_info['signedAttrs'][0] = _protection_attribute(both_der)

        with self.assertRaises(rfc6211check.CMSAlgorithmProtectionError):
            rfc6211check.check_signer_info(signer_info)

    def test_mac_algorithm_in_signer_context_rejected(self):
        mac_only_der = _protection_der(
            _ID_SHA256, mac_alg=_alg_id(_ID_HMAC_SHA256))

        signer_info = _signer_info(
            _alg_id(_ID_SHA256), _alg_id(_ID_PSS))
        signer_info['signedAttrs'][0] = _protection_attribute(mac_only_der)

        with self.assertRaises(rfc6211check.CMSAlgorithmProtectionError):
            rfc6211check.check_signer_info(signer_info)

    def test_unknown_parameters_never_silently_match(self):
        # NULL is not a valid RSASSA-PSS parameter form; it must not be
        # treated as equivalent to the (defaulted) declared parameters
        signer_info = _signer_info(
            _alg_id(_ID_SHA256), _alg_id(_ID_PSS, univ.Null('')))
        signer_info['signedAttrs'][0] = _protection_attribute(
            _protection_der(_ID_SHA256, sig_alg=_alg_id(_ID_PSS)))

        with self.assertRaises(rfc6211check.CMSAlgorithmProtectionError):
            rfc6211check.check_signer_info(signer_info)

        # Byte-identical unrecognized parameters still match each other
        signer_info = _signer_info(
            _alg_id(_ID_SHA256), _alg_id(_ID_PSS, univ.Null('')))
        signer_info['signedAttrs'][0] = _protection_attribute(
            _protection_der(_ID_SHA256,
                            sig_alg=_alg_id(_ID_PSS, univ.Null(''))))

        self.assertTrue(rfc6211check.check_signer_info(signer_info))

    def test_absent_attribute_returns_none(self):
        signer_info = _signer_info(
            _alg_id(_ID_SHA256), _alg_id(_ID_PSS))
        self.assertIsNone(rfc6211check.check_signer_info(signer_info))

        signer_info['signedAttrs'][0] = _content_type_attribute()
        self.assertIsNone(rfc6211check.check_signer_info(signer_info))


class AuthenticatedDataCheckTestCase(unittest.TestCase):

    def test_mac_match(self):
        auth_data = _authenticated_data(
            _alg_id(_ID_SHA256, univ.Null('')), _alg_id(_ID_HMAC_SHA256))
        auth_data['authAttrs'][0] = _protection_attribute(
            _protection_der(_ID_SHA256, mac_alg=_alg_id(_ID_HMAC_SHA256)))

        protection = rfc6211check.check_authenticated_data(auth_data)
        self.assertEqual(
            tuple(_ID_HMAC_SHA256),
            tuple(protection['macAlgorithm']['algorithm']))

    def test_mac_mismatch_rejected(self):
        auth_data = _authenticated_data(
            _alg_id(_ID_SHA256), _alg_id(_ID_HMAC_SHA256))
        auth_data['authAttrs'][0] = _protection_attribute(
            _protection_der(_ID_SHA256, mac_alg=_alg_id(_ID_HMAC_SHA1)))

        with self.assertRaises(rfc6211check.CMSAlgorithmProtectionError):
            rfc6211check.check_authenticated_data(auth_data)

    def test_digest_mismatch_rejected(self):
        auth_data = _authenticated_data(
            _alg_id(_ID_SHA256), _alg_id(_ID_HMAC_SHA256))
        auth_data['authAttrs'][0] = _protection_attribute(
            _protection_der(_ID_SHA384, mac_alg=_alg_id(_ID_HMAC_SHA256)))

        with self.assertRaises(rfc6211check.CMSAlgorithmProtectionError):
            rfc6211check.check_authenticated_data(auth_data)

    def test_signature_algorithm_in_mac_context_rejected(self):
        sig_only_der = _protection_der(
            _ID_SHA256, sig_alg=_alg_id(_ID_PSS))

        auth_data = _authenticated_data(
            _alg_id(_ID_SHA256), _alg_id(_ID_HMAC_SHA256))
        auth_data['authAttrs'][0] = _protection_attribute(sig_only_der)

        with self.assertRaises(rfc6211check.CMSAlgorithmProtectionError):
            rfc6211check.check_authenticated_data(auth_data)

    def test_missing_outer_digest_rejected(self):
        auth_data = _authenticated_data(None, _alg_id(_ID_HMAC_SHA256))
        auth_data['authAttrs'][0] = _protection_attribute(
            _protection_der(_ID_SHA256, mac_alg=_alg_id(_ID_HMAC_SHA256)))

        with self.assertRaises(rfc6211check.CMSAlgorithmProtectionError):
            rfc6211check.check_authenticated_data(auth_data)

    def test_attribute_in_unauth_attrs_ignored(self):
        auth_data = _authenticated_data(
            _alg_id(_ID_SHA256), _alg_id(_ID_HMAC_SHA256))
        auth_data['unauthAttrs'][0] = _protection_attribute(
            _protection_der(_ID_SHA384, mac_alg=_alg_id(_ID_HMAC_SHA1)))

        self.assertIsNone(rfc6211check.check_authenticated_data(auth_data))

    def test_absent_attribute_returns_none(self):
        auth_data = _authenticated_data(
            _alg_id(_ID_SHA256), _alg_id(_ID_HMAC_SHA256))
        self.assertIsNone(rfc6211check.check_authenticated_data(auth_data))


class RealSignedMessageTestCase(unittest.TestCase):
    # RFC 6211 appendix A signed message; the protection attribute declares
    # sha384 + ecdsa-with-SHA384, matching the outer SignerInfo
    signed_message_pem_text = """\
MIIEyAYJKoZIhvcNAQcCoIIEuTCCBLUCAQExDTALBglghkgBZQMEAgIwUQYJKoZI
hvcNAQcBoEQEQkNvbnRlbnQtVHlwZTogdGV4dC9wbGFpbg0KDQpXYXRzb24sIGNv
bWUgaGVyZSAtIEkgd2FudCB0byBzZWUgeW91LqCCAnwwggJ4MIIB/qADAgECAgkA
pbNUKBuwbjswCgYIKoZIzj0EAwMwPzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAlZB
MRAwDgYDVQQHDAdIZXJuZG9uMREwDwYDVQQKDAhCb2d1cyBDQTAeFw0xOTA1Mjkx
NDQ1NDFaFw0yMDA1MjgxNDQ1NDFaMHAxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJW
QTEQMA4GA1UEBxMHSGVybmRvbjEQMA4GA1UEChMHRXhhbXBsZTEOMAwGA1UEAxMF
QWxpY2UxIDAeBgkqhkiG9w0BCQEWEWFsaWNlQGV4YW1wbGUuY29tMHYwEAYHKoZI
zj0CAQYFK4EEACIDYgAE+M2fBy/sRA6V1pKFqecRTE8+LuAHtZxes1wmJZrBBg+b
z7uYZfYQxI3dVB0YCSD6Mt3yXFlnmfBRwoqyArbjIBYrDbHBv2k8Csg2DhQ7qs/w
to8hMKoFgkcscqIbiV7Zo4GUMIGRMAsGA1UdDwQEAwIHgDBCBglghkgBhvhCAQ0E
NRYzVGhpcyBjZXJ0aWZpY2F0ZSBjYW5ub3QgYmUgdHJ1c3RlZCBmb3IgYW55IHB1
cnBvc2UuMB0GA1UdDgQWBBTEuloOPnrjPIGw9AKqaLsW4JYONTAfBgNVHSMEGDAW
gBTyNds0BNqlVfK9aQOZsGLs4hUIwTAKBggqhkjOPQQDAwNoADBlAjBjuR/RNbgL
3kRhmn+PJTeKaL9sh/oQgHOYTgLmSnv3+NDCkhfKuMNoo/tHrkmihYgCMQC94Mae
rDIrQpi0IDh+v0QSAv9rMife8tClafXWtDwwL8MS7oAh0ymT446Uizxx3PUxggHM
MIIByAIBATBMMD8xCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJWQTEQMA4GA1UEBwwH
SGVybmRvbjERMA8GA1UECgwIQm9ndXMgQ0ECCQCls1QoG7BuOzALBglghkgBZQME
AgKggfIwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcN
MTkwNTI5MTgyMzE5WjAoBgkqhkiG9w0BCTQxGzAZMAsGCWCGSAFlAwQCAqEKBggq
hkjOPQQDAzA/BgkqhkiG9w0BCQQxMgQwtuQipP2CZx7U96rGbUT06LC5jVFYccZW
5/CaNvpcrOPiChDm2vI3m4k300z5mSZsME0GCyqGSIb3DQEJEAIBMT4wPAQgx08h
D2QnVwj1DoeRELNtdZ0PffW4BQIvcwwVc/goU6OAAQEwFTATgRFhbGljZUBleGFt
cGxlLmNvbTAKBggqhkjOPQQDAwRnMGUCMQChIMyN1nTN+LLQcYJuhWT297vSKMDK
fIUedSwWYrcSnSa1pq2s3Wue+pNBfecEjYECMGrUNu1UpWdafEJulP9Vz76qOPMa
5V/AnTEV5zkmzRle8sffN+nQ+SGkoos5zpI1kA==
"""

    def _signer_info(self, decode_open_types):
        substrate = pem.readBase64fromText(self.signed_message_pem_text)
        content_info, rest = der_decoder(
            substrate, asn1Spec=rfc5652.ContentInfo(),
            decodeOpenTypes=decode_open_types)
        self.assertFalse(rest)
        content = content_info['content']
        if isinstance(content, rfc5652.SignedData):
            return content['signerInfos'][0]
        signed_data, rest = der_decoder(
            content, asn1Spec=rfc5652.SignedData(),
            decodeOpenTypes=decode_open_types)
        self.assertFalse(rest)
        return signed_data['signerInfos'][0]

    def test_real_message_open_types(self):
        protection = rfc6211check.check_signer_info(
            self._signer_info(decode_open_types=True))
        self.assertEqual(
            tuple(_ID_SHA384),
            tuple(protection['digestAlgorithm']['algorithm']))

    def test_real_message_plain_decode(self):
        protection = rfc6211check.check_signer_info(
            self._signer_info(decode_open_types=False))
        self.assertEqual(
            tuple(_ID_SHA384),
            tuple(protection['digestAlgorithm']['algorithm']))


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
