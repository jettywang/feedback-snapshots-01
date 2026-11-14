#
# This file is part of pyasn1-modules software.
#
# Tests for the RFC 5914 trust anchor import adapter.
#
import sys
import unittest

from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_modules import rfc5280
from pyasn1_modules import rfc5914
from pyasn1_modules import rfc5914_import
from pyasn1_modules import rfc5914_pathcheck


def _dns_general_name(domain):
    # GeneralName.dNSName is an implicit [2] context-tagged IA5String.
    tagged = rfc5280.char.IA5String(domain).subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
    general_name = rfc5280.GeneralName()
    general_name.setComponentByName('dNSName', tagged)
    return general_name


# --------------------------------------------------------------------------
# Fixture builders (pure pyasn1, no external crypto library)
# --------------------------------------------------------------------------

def _spki_der(oid_s, bitstring_hex):
    alg = rfc5280.AlgorithmIdentifier()
    alg.setComponentByName('algorithm', univ.ObjectIdentifier(oid_s))
    spki = rfc5280.SubjectPublicKeyInfo()
    spki.setComponentByName('algorithm', alg)
    spki.setComponentByName(
        'subjectPublicKey', univ.BitString().fromHexString(bitstring_hex))
    return der_encoder(spki)


TEST_KEY_DER_A = _spki_der('1.2.840.10045.2.1', '00aabb')
TEST_KEY_DER_B = _spki_der('1.2.840.10045.2.1', '00ccdd')
KEY_ID_A = b'\x01\x02\x03\x04'
KEY_ID_B = b'\x05\x06\x07\x08'

OID_POLICY_1 = univ.ObjectIdentifier('1.3.6.1.4.1.99.1')
OID_POLICY_2 = univ.ObjectIdentifier('1.3.6.1.4.1.99.2')
OID_UNKNOWN_CRITICAL = univ.ObjectIdentifier('1.3.6.1.4.1.99.99')


def _spki(key_der):
    spki, rest = der_decoder(key_der, rfc5280.SubjectPublicKeyInfo())
    assert not rest
    return spki


def _name(cn):
    # AttributeValue is an open Any, so the chosen DirectoryString is wrapped
    # as its raw DER encoding.
    directory_string_der = der_encoder(rfc5280.char.UTF8String(cn))
    atv = rfc5280.AttributeTypeAndValue()
    atv.setComponentByName('type', rfc5280.id_at_commonName)
    atv.setComponentByName('value', univ.Any(directory_string_der))
    rdn = rfc5280.RelativeDistinguishedName()
    rdn.setComponentByPosition(0, atv)
    sequence = rfc5280.RDNSequence()
    sequence.setComponentByPosition(0, rdn)
    name = rfc5280.Name()
    name.setComponentByName('rdnSequence', sequence)
    return name


def _fill_name_constraints(target, permitted=(), excluded=()):
    """Populate an existing (possibly context-tagged) NameConstraints."""
    def fill(tagged_field, domains):
        container = target[tagged_field]
        for pos, domain in enumerate(domains):
            subtree = rfc5280.GeneralSubtree()
            subtree.setComponentByName('base', _dns_general_name(domain))
            container.setComponentByPosition(pos, subtree)

    if permitted:
        fill('permittedSubtrees', permitted)
    if excluded:
        fill('excludedSubtrees', excluded)
    return target


def _dns_constraints(permitted=(), excluded=()):
    return _fill_name_constraints(
        rfc5280.NameConstraints(), permitted, excluded)


def _policies(oids):
    cps = rfc5280.CertificatePolicies()
    for pos, oid in enumerate(oids):
        info = rfc5280.PolicyInformation()
        info.setComponentByName('policyIdentifier', rfc5280.CertPolicyId(oid))
        cps.setComponentByPosition(pos, info)
    return cps


def _extension(oid, critical, inner_value):
    ext = rfc5280.Extension()
    ext.setComponentByName('extnID', oid)
    ext.setComponentByName('critical', univ.Boolean(critical))
    if isinstance(inner_value, (bytes, bytearray)):
        # Raw inner content octets: place them directly in the extnValue
        # OctetString without an extra wrapper.
        ext.setComponentByName('extnValue', univ.OctetString(bytes(inner_value)))
    else:
        ext.setComponentByName(
            'extnValue', univ.OctetString(der_encoder(inner_value)))
    return ext


def _extensions(*exts):
    container = rfc5280.Extensions()
    for pos, ext in enumerate(exts):
        container.setComponentByPosition(pos, ext)
    return container


def _populate_tbs(tbs, key_der, subject_cn, extensions):
    tbs.setComponentByName('serialNumber', rfc5280.CertificateSerialNumber(1))
    tbs.setComponentByName('signature', rfc5280.AlgorithmIdentifier())
    tbs['signature'].setComponentByName(
        'algorithm', univ.ObjectIdentifier('1.2.840.113549.1.1.11'))
    tbs.setComponentByName('issuer', _name('issuer'))
    validity = rfc5280.Validity()
    validity.setComponentByName('notBefore', rfc5280.Time())
    validity['notBefore'].setComponentByName(
        'utcTime', rfc5280.useful.UTCTime('250101000000Z'))
    validity.setComponentByName('notAfter', rfc5280.Time())
    validity['notAfter'].setComponentByName(
        'utcTime', rfc5280.useful.UTCTime('300101000000Z'))
    tbs.setComponentByName('validity', validity)
    tbs.setComponentByName('subject', _name(subject_cn or 'anchor'))
    tbs.setComponentByName('subjectPublicKeyInfo', _spki(key_der))
    if extensions is not None:
        # TBSCertificate.extensions is an explicit [3] tagged field.
        tagged_extensions = tbs['extensions']
        for pos, extension in enumerate(extensions):
            tagged_extensions.setComponentByPosition(pos, extension)
    return tbs


def _tbs(key_der, subject_cn=None, extensions=None):
    return _populate_tbs(
        rfc5280.TBSCertificate(), key_der, subject_cn, extensions)


def _standalone_certificate(key_der, extensions=None, subject_cn='anchor'):
    """A fully populated, untagged Certificate value object."""
    cert = rfc5280.Certificate()
    cert.setComponentByName(
        'tbsCertificate', _tbs(key_der, subject_cn=subject_cn,
                               extensions=extensions))
    alg = rfc5280.AlgorithmIdentifier()
    alg.setComponentByName(
        'algorithm', univ.ObjectIdentifier('1.2.840.113549.1.1.11'))
    cert.setComponentByName('signatureAlgorithm', alg)
    cert.setComponentByName(
        'signature', univ.BitString().fromHexString('00'))
    return cert


def _certificate_choice(key_der, extensions=None, subject_cn=None):
    choice = rfc5914.TrustAnchorChoice()
    cert = choice['certificate']
    tbs = _tbs(key_der, subject_cn=subject_cn, extensions=extensions)
    cert.setComponentByName('tbsCertificate', tbs)
    cert.setComponentByName('signatureAlgorithm', rfc5280.AlgorithmIdentifier())
    cert['signatureAlgorithm'].setComponentByName(
        'algorithm', univ.ObjectIdentifier('1.2.840.113549.1.1.11'))
    cert.setComponentByName('signature', univ.BitString().fromHexString('00'))
    return choice


def _tbs_choice(key_der, extensions=None, subject_cn=None):
    choice = rfc5914.TrustAnchorChoice()
    # tbsCert is an explicit [1] TBSCertificate; the placeholder already
    # carries the tag and the TBS component layout.
    tagged_tbs = choice['tbsCert']
    _populate_tbs(tagged_tbs, key_der, subject_cn, extensions)
    return choice


def _ta_info(key_der, key_id, cert_path=None, exts=None):
    choice = rfc5914.TrustAnchorChoice()
    ta = choice['taInfo']
    ta.setComponentByName('pubKey', _spki(key_der))
    ta.setComponentByName('keyId', rfc5280.KeyIdentifier(key_id))
    if cert_path is not None:
        ta.setComponentByName('certPath', cert_path)
    if exts is not None:
        # TrustAnchorInfo.exts is an explicit [1] tagged Extensions field.
        tagged_exts = ta['exts']
        for pos, extension in enumerate(exts):
            tagged_exts.setComponentByPosition(pos, extension)
    return choice


def _dns_names_from_constraints(name_constraints, field_name):
    if not name_constraints[field_name].hasValue():
        return ()
    return tuple(
        str(subtree['base'].getComponent())
        for subtree in name_constraints[field_name]
        if subtree['base'].getName() == 'dNSName'
    )


def _cert_path(ta_name, name_constr=None, policy_set=None,
               path_len=None, flags=None, embedded=None):
    cp = rfc5914.CertPathControls()
    cp.setComponentByName('taName', ta_name)
    if name_constr is not None:
        # nameConstr is implicit [3]; rebuild fresh subtrees on that
        # placeholder using the dNSName values (never re-insert tagged objects).
        _fill_name_constraints(
            cp['nameConstr'],
            _dns_names_from_constraints(name_constr, 'permittedSubtrees'),
            _dns_names_from_constraints(name_constr, 'excludedSubtrees'))
    if policy_set is not None:
        # policySet is implicit [1]; rebuild fresh PolicyInformation entries.
        target = cp['policySet']
        for pos, info in enumerate(policy_set):
            rebuilt = rfc5280.PolicyInformation()
            rebuilt.setComponentByName(
                'policyIdentifier',
                rfc5280.CertPolicyId(info['policyIdentifier']))
            target.setComponentByPosition(pos, rebuilt)
    if path_len is not None:
        # pathLenConstraint is implicit [4]; reuse the placeholder's tag.
        cp.setComponentByName(
            'pathLenConstraint', cp['pathLenConstraint'].clone(path_len))
    if flags is not None:
        # policyFlags is implicit [2] CertPolicyFlags; clone the placeholder
        # tag with the desired bit value.
        cp.setComponentByName(
            'policyFlags',
            cp['policyFlags'].clone(flags.asInteger()))
    if embedded is not None:
        # certificate is implicit [0] Certificate; copy each field onto the
        # tagged placeholder so the wrapper tag is preserved.
        tagged_cert = cp['certificate']
        tagged_cert.setComponentByName('tbsCertificate',
                                       embedded['tbsCertificate'])
        tagged_cert.setComponentByName(
            'signatureAlgorithm', embedded['signatureAlgorithm'])
        tagged_cert.setComponentByName('signature', embedded['signature'])
    return cp


def _list(*choices):
    tal = rfc5914.TrustAnchorList()
    for pos, choice in enumerate(choices):
        tal.setComponentByPosition(pos, choice)
    return tal


def _leaf_san(domains):
    sans = rfc5280.GeneralNames()
    for pos, domain in enumerate(domains):
        sans.setComponentByPosition(pos, _dns_general_name(domain))
    return der_encoder(sans)


def _leaf_policies(oids):
    return der_encoder(_policies(oids))


class ImportContractTestCase(unittest.TestCase):

    def test_requires_explicit_trust(self):
        tal = _list(_certificate_choice(TEST_KEY_DER_A))
        with self.assertRaises(rfc5914_import.UntrustedSourceError):
            rfc5914_import.import_trust_anchor_list(tal, source_trusted=False)
        # decoding a self-signed-looking cert must not flip trust on
        der = der_encoder(tal)
        with self.assertRaises(rfc5914_import.UntrustedSourceError):
            rfc5914_import.import_trust_anchor_list_der(
                der, source_trusted=False)

    def test_import_succeeds_only_when_trust_confirmed(self):
        tal = _list(_certificate_choice(TEST_KEY_DER_A))
        anchors = rfc5914_import.import_trust_anchor_list(
            tal, source_trusted=True)
        self.assertEqual(1, len(anchors))
        self.assertEqual('certificate', anchors[0].anchor_form)

    def test_immutable_constraints(self):
        tal = _list(_certificate_choice(TEST_KEY_DER_A))
        anchor = rfc5914_import.import_trust_anchor_list(
            tal, source_trusted=True)[0]
        with self.assertRaises((AttributeError, Exception)):
            anchor.path_len_constraint = 9
        self.assertIsInstance(anchor, object)

    def test_three_forms_retain_controls(self):
        nc = _dns_constraints(permitted=('example.com',))
        policies = _policies((OID_POLICY_1,))
        exts = _extensions(
            _extension(rfc5280.id_ce_nameConstraints, True, nc),
            _extension(rfc5280.id_ce_certificatePolicies, False, policies),
        )
        tal = _list(
            _certificate_choice(TEST_KEY_DER_A, extensions=exts),
            _tbs_choice(TEST_KEY_DER_A, extensions=exts),
        )
        cp = _cert_path(_name('anchor'), name_constr=nc,
                        policy_set=policies, path_len=2,
                        flags=rfc5914.CertPolicyFlags().fromBinaryString(
                            '10100000'))
        tal.setComponentByPosition(2, _ta_info(
            TEST_KEY_DER_A, KEY_ID_A, cert_path=cp))
        anchors = rfc5914_import.import_trust_anchor_list(
            tal, source_trusted=True)

        forms = [a.anchor_form for a in anchors]
        self.assertEqual(['certificate', 'tbsCert', 'taInfo'], forms)
        for anchor in anchors:
            self.assertIsNotNone(anchor.name_constraints_der)
            self.assertEqual(der_encoder(nc), anchor.name_constraints_der)
            self.assertEqual(der_encoder(policies),
                             anchor.certificate_policies_der)
        ta_anchor = anchors[2]
        self.assertEqual(2, ta_anchor.path_len_constraint)
        self.assertEqual(
            frozenset(('inhibitPolicyMapping', 'inhibitAnyPolicy')),
            ta_anchor.policy_flags)
        self.assertEqual(KEY_ID_A, ta_anchor.key_id)


class NoSilentMergeTestCase(unittest.TestCase):

    def _two_same_key_anchors(self):
        nc1 = _dns_constraints(permitted=('example.com',))
        nc2 = _dns_constraints(permitted=('other.example.net',))
        first = _ta_info(
            TEST_KEY_DER_A, KEY_ID_A,
            cert_path=_cert_path(_name('a'), name_constr=nc1))
        second = _ta_info(
            TEST_KEY_DER_A, KEY_ID_A,
            cert_path=_cert_path(_name('b'), name_constr=nc2))
        tal = _list(first, second)
        return rfc5914_import.import_trust_anchor_list(
            tal, source_trusted=True)

    def test_same_key_kept_distinct(self):
        anchors = self._two_same_key_anchors()
        self.assertEqual(2, len(anchors))
        self.assertTrue(anchors[0].has_same_key(anchors[1]))
        self.assertNotEqual(anchors[0].fingerprint, anchors[1].fingerprint)
        self.assertNotEqual(anchors[0].name_constraints_der,
                            anchors[1].name_constraints_der)
        grouped = rfc5914_import.group_by_public_key(anchors)
        self.assertEqual(1, len(grouped))
        self.assertEqual(2, len(grouped[TEST_KEY_DER_A]))

    def test_same_key_different_policy_distinct(self):
        first = _ta_info(
            TEST_KEY_DER_A, KEY_ID_A,
            cert_path=_cert_path(_name('a'),
                                 policy_set=_policies((OID_POLICY_1,))))
        second = _ta_info(
            TEST_KEY_DER_A, KEY_ID_A,
            cert_path=_cert_path(_name('a'),
                                 policy_set=_policies((OID_POLICY_2,))))
        anchors = rfc5914_import.import_trust_anchor_list(
            _list(first, second), source_trusted=True)
        self.assertEqual(2, len(anchors))
        self.assertNotEqual(anchors[0].fingerprint, anchors[1].fingerprint)

    def test_consumer_gives_different_verdicts(self):
        anchors = self._two_same_key_anchors()
        leaf = _leaf_san(('host.example.com',))
        first = rfc5914_pathcheck.evaluate_leaf(anchors[0], leaf, None)
        second = rfc5914_pathcheck.evaluate_leaf(anchors[1], leaf, None)
        self.assertTrue(first.accepted, first.reason)
        self.assertFalse(second.accepted)
        self.assertIn('permittedSubtrees', second.reason)

    def test_excluded_subtree_rejects(self):
        nc = _dns_constraints(excluded=('bad.example.com',))
        anchor = rfc5914_import.import_trust_anchor_list(
            _list(_ta_info(TEST_KEY_DER_A, KEY_ID_A,
                           cert_path=_cert_path(_name('a'),
                                                name_constr=nc))),
            source_trusted=True)[0]
        ok = rfc5914_pathcheck.evaluate_leaf(
            anchor, _leaf_san(('good.example.com',)), None)
        bad = rfc5914_pathcheck.evaluate_leaf(
            anchor, _leaf_san(('bad.example.com',)), None)
        self.assertTrue(ok.accepted)
        self.assertFalse(bad.accepted)

    def test_policy_control_changes_verdict(self):
        anchor = rfc5914_import.import_trust_anchor_list(
            _list(_ta_info(
                TEST_KEY_DER_A, KEY_ID_A,
                cert_path=_cert_path(
                    _name('a'), policy_set=_policies((OID_POLICY_1,))))),
            source_trusted=True)[0]
        sans = _leaf_san(('host.example.com',))
        missing = rfc5914_pathcheck.evaluate_leaf(
            anchor, sans, _leaf_policies((OID_POLICY_2,)))
        satisfied = rfc5914_pathcheck.evaluate_leaf(
            anchor, sans, _leaf_policies((OID_POLICY_1, OID_POLICY_2)))
        self.assertFalse(missing.accepted)
        self.assertTrue(satisfied.accepted)


class ConflictDiagnosticsTestCase(unittest.TestCase):

    def test_embedded_cert_key_mismatch_detected(self):
        embedded = _standalone_certificate(TEST_KEY_DER_B)
        cp = _cert_path(_name('anchor'), embedded=embedded)
        tal = _list(_ta_info(TEST_KEY_DER_A, KEY_ID_A, cert_path=cp))
        with self.assertRaises(rfc5914_import.TrustAnchorConflictError) as cm:
            rfc5914_import.import_trust_anchor_list(
                tal, source_trusted=True)
        self.assertIn('public key', str(cm.exception))

    def test_embedded_cert_skid_mismatch_detected(self):
        exts = _extensions(_extension(
            rfc5280.id_ce_subjectKeyIdentifier, False,
            rfc5280.KeyIdentifier(KEY_ID_B)))
        embedded = _standalone_certificate(TEST_KEY_DER_A, extensions=exts)
        cp = _cert_path(_name('anchor'), embedded=embedded)
        tal = _list(_ta_info(TEST_KEY_DER_A, KEY_ID_A, cert_path=cp))
        with self.assertRaises(rfc5914_import.TrustAnchorConflictError):
            rfc5914_import.import_trust_anchor_list(
                tal, source_trusted=True)

    def test_embedded_name_constraint_conflict_detected(self):
        path_nc = _dns_constraints(permitted=('a.example.com',))
        cert_nc = _dns_constraints(permitted=('b.example.com',))
        exts = _extensions(_extension(
            rfc5280.id_ce_nameConstraints, True, cert_nc))
        embedded = _standalone_certificate(TEST_KEY_DER_A, extensions=exts)
        cp = _cert_path(_name('anchor'), name_constr=path_nc,
                        embedded=embedded)
        tal = _list(_ta_info(TEST_KEY_DER_A, KEY_ID_A, cert_path=cp))
        with self.assertRaises(rfc5914_import.TrustAnchorConflictError):
            rfc5914_import.import_trust_anchor_list(
                tal, source_trusted=True)

    def test_consistent_embedded_cert_accepted(self):
        exts = _extensions(_extension(
            rfc5280.id_ce_subjectKeyIdentifier, False,
            rfc5280.KeyIdentifier(KEY_ID_A)))
        embedded = _standalone_certificate(TEST_KEY_DER_A, extensions=exts)
        cp = _cert_path(_name('anchor'), embedded=embedded)
        anchors = rfc5914_import.import_trust_anchor_list(
            _list(_ta_info(TEST_KEY_DER_A, KEY_ID_A, cert_path=cp)),
            source_trusted=True)
        self.assertEqual(1, len(anchors))


class CriticalControlTestCase(unittest.TestCase):

    def test_unsupported_critical_extension_rejected(self):
        exts = _extensions(_extension(
            OID_UNKNOWN_CRITICAL, True, b'\x01\x02'))
        tal = _list(_certificate_choice(TEST_KEY_DER_A, extensions=exts))
        with self.assertRaises(
                rfc5914_import.UnsupportedCriticalControlError) as cm:
            rfc5914_import.import_trust_anchor_list(
                tal, source_trusted=True)
        self.assertIn(str(OID_UNKNOWN_CRITICAL), str(cm.exception))

    def test_unsupported_non_critical_extension_retained(self):
        exts = _extensions(_extension(
            OID_UNKNOWN_CRITICAL, False, b'\x01\x02'))
        anchors = rfc5914_import.import_trust_anchor_list(
            _list(_certificate_choice(TEST_KEY_DER_A, extensions=exts)),
            source_trusted=True)
        self.assertEqual(
            str(OID_UNKNOWN_CRITICAL), anchors[0].extensions[0].extn_id)
        self.assertEqual(b'\x01\x02', anchors[0].extensions[0].value_der)

    def test_supported_critical_extension_accepted(self):
        nc = _dns_constraints(permitted=('example.com',))
        exts = _extensions(_extension(
            rfc5280.id_ce_nameConstraints, True, nc))
        anchors = rfc5914_import.import_trust_anchor_list(
            _list(_certificate_choice(TEST_KEY_DER_A, extensions=exts)),
            source_trusted=True)
        self.assertEqual(der_encoder(nc), anchors[0].name_constraints_der)


class RoundTripTestCase(unittest.TestCase):

    def test_export_reimport_does_not_widen(self):
        nc = _dns_constraints(permitted=('example.com',))
        original_list = _list(
            _ta_info(TEST_KEY_DER_A, KEY_ID_A,
                     cert_path=_cert_path(
                         _name('a'), name_constr=nc,
                         policy_set=_policies((OID_POLICY_1,)),
                         path_len=3)),
            _certificate_choice(
                TEST_KEY_DER_B,
                extensions=_extensions(_extension(
                    rfc5280.id_ce_nameConstraints, True,
                    _dns_constraints(excluded=('deny.example.org',))))),
        )
        original_der = der_encoder(original_list)
        anchors = rfc5914_import.import_trust_anchor_list_der(
            original_der, source_trusted=True)

        exported_der = rfc5914_import.export_trust_anchor_list_der(anchors)

        # byte-identical: the export cannot add any control
        self.assertEqual(original_der, exported_der)
        self.assertTrue(rfc5914_import.authorisation_is_within(
            exported_der, original_der))

        reimported = rfc5914_import.import_trust_anchor_list_der(
            exported_der, source_trusted=True)
        self.assertEqual(
            [a.fingerprint for a in anchors],
            [a.fingerprint for a in reimported])

    def test_roundtrip_preserves_all_three_forms(self):
        tal = _list(
            _certificate_choice(TEST_KEY_DER_A),
            _tbs_choice(TEST_KEY_DER_B),
            _ta_info(TEST_KEY_DER_A, KEY_ID_A),
        )
        original_der = der_encoder(tal)
        anchors = rfc5914_import.import_trust_anchor_list_der(
            original_der, source_trusted=True)
        exported = rfc5914_import.export_trust_anchor_list_der(anchors)
        self.assertEqual(original_der, exported)


class RealWorldListTestCase(unittest.TestCase):
    """The adapter must also accept the real DER list used by the codec test."""

    def test_import_decoded_sample_list(self):
        from tests.test_rfc5914 import TrustAnchorListTestCase
        from pyasn1_modules import pem, rfc5652

        substrate = pem.readBase64fromText(
            TrustAnchorListTestCase.trust_anchor_list_pem_text)
        ci, _ = der_decoder(substrate, rfc5652.ContentInfo())
        tal, _ = der_decoder(ci['content'], rfc5914.TrustAnchorList())
        anchors = rfc5914_import.import_trust_anchor_list(
            tal, source_trusted=True)
        self.assertEqual(3, len(anchors))
        # every anchor exposes a public key and a stable fingerprint
        self.assertEqual(3, len({a.fingerprint for a in anchors}))
        for anchor in anchors:
            self.assertTrue(anchor.public_key_der)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
