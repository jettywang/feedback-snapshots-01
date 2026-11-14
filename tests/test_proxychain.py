#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import inspect
import os
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import univ

from pyasn1_modules import rfc5280
from pyasn1_modules import rfc3820
from pyasn1_modules import pem
from pyasn1_modules import proxychain
from pyasn1_modules.proxychain import Decision
from pyasn1_modules.proxychain import Reason
from pyasn1_modules.proxychain import Rights
from pyasn1_modules.proxychain import PolicyError
from pyasn1_modules.proxychain import PolicyInterpreter


from tests.proxy_fixtures import (  # noqa: E402
    CN, LOCAL_POLICY, NOW, O, READ, READ_B, US, WRITE,
    basic_constraints, certificate, ext_key_usage, extension, key_usage,
    make_eec, make_proxy, name, proxy_info,
)



FIXTURE_DIR = os.path.join(os.path.dirname(__file__), '..', 'docs',
                           'fixtures')


class ReadingInterpreter(PolicyInterpreter):
    """Grants a subset of ``rights`` named in a tiny comma-separated format."""

    language = LOCAL_POLICY

    def __init__(self):
        self.calls = []

    def interpret(self, policy_octets, delegated_rights):
        self.calls.append((policy_octets, delegated_rights))
        if policy_octets is None:
            raise PolicyError('policy expression is required')
        granted = set()
        for token in policy_octets.decode('ascii').split(','):
            token = token.strip()
            if token == 'read':
                granted.add(READ)
            elif token == 'write':
                granted.add(WRITE)
            elif token == 'read-b':
                granted.add(READ_B)
            else:
                raise PolicyError('unknown right %r' % token)
        return Rights(granted)


class WrittenPolicyTestCase(unittest.TestCase):
    def test_legal_two_level_inherit_all_chain(self):
        eec = make_eec()
        first = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                           path_len=1, serial=2)
        second = make_proxy(first, 'alice-2', rfc3820.id_ppl_inheritAll,
                            path_len=0, serial=3)

        result = proxychain.check_chain(eec, [first, second], now=NOW)

        self.assertEqual(Decision.ACCEPT, result.code)
        self.assertTrue(result.accepted)
        self.assertTrue(result.rights.unrestricted)
        self.assertEqual(['alice-1', 'alice-2'],
                         [d['subject_cn'] for d in result.delegations])
        self.assertEqual([1, 0],
                         [d['path_length'] for d in result.delegations])

    def test_single_proxy_chain_is_legal(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                           path_len=0)
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.ACCEPT, result.code)

    def test_chain_without_proxy_is_rejected(self):
        result = proxychain.check_chain(make_eec(), [], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.EMPTY_CHAIN, result.reason)


class PathLengthTestCase(unittest.TestCase):
    def test_zero_path_length_cannot_sign_another_proxy(self):
        eec = make_eec()
        first = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                           path_len=0, serial=2)
        second = make_proxy(first, 'alice-2', rfc3820.id_ppl_inheritAll,
                            path_len=0, serial=3)

        result = proxychain.check_chain(eec, [first, second], now=NOW)

        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.PATH_LENGTH_EXCEEDED, result.reason)

    def test_later_smaller_path_length_applies_to_its_own_tail(self):
        eec = make_eec()
        first = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                           path_len=5, serial=2)
        second = make_proxy(first, 'alice-2', rfc3820.id_ppl_inheritAll,
                            path_len=0, serial=3)
        third = make_proxy(second, 'alice-3', rfc3820.id_ppl_inheritAll,
                           serial=4)

        result = proxychain.check_chain(eec, [first, second, third], now=NOW)

        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.PATH_LENGTH_EXCEEDED, result.reason)
        # Only certificates whose delegation was accepted are recorded.
        self.assertEqual(1, len(result.delegations))

    def test_missing_path_length_is_unlimited(self):
        eec = make_eec()
        first = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                           path_len=None, serial=2)
        second = make_proxy(first, 'alice-2', rfc3820.id_ppl_inheritAll,
                            path_len=None, serial=3)
        third = make_proxy(second, 'alice-3', rfc3820.id_ppl_inheritAll,
                           path_len=None, serial=4)
        self.assertEqual(
            Decision.ACCEPT,
            proxychain.check_chain(eec, [first, second, third], now=NOW).code,
        )

    def test_negative_path_length_is_rejected(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                           path_len=-1)
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.PROXY_INFO_NEGATIVE_PATH_LENGTH,
                         result.reason)


class SubjectDerivationTestCase(unittest.TestCase):
    def test_appended_organization_is_rejected(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll)
        proxy['tbsCertificate']['subject'] = name(
            (US, 'US'), (O, 'Example'), (CN, 'Alice'), (O, 'Mallory')
        )
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.SUBJECT_NOT_DERIVED, result.reason)

    def test_two_appended_cns_are_rejected(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll)
        proxy['tbsCertificate']['subject'] = name(
            (US, 'US'), (O, 'Example'), (CN, 'Alice'),
            (CN, 'alice-1'), (CN, 'alice-2')
        )
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.SUBJECT_NOT_DERIVED, result.reason)

    def test_replaced_eec_name_is_rejected(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll)
        proxy['tbsCertificate']['subject'] = name(
            (US, 'US'), (O, 'Attacker'), (CN, 'alice-1')
        )
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.SUBJECT_NOT_DERIVED, result.reason)

    def test_issuer_field_must_match_previous_subject(self):
        eec = make_eec()
        first = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                           path_len=1, serial=2)
        second = make_proxy(first, 'alice-2', rfc3820.id_ppl_inheritAll,
                            path_len=0, serial=3)
        second['tbsCertificate']['issuer'] = name((US, 'US'), (O, 'Example'))
        result = proxychain.check_chain(eec, [first, second], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.ISSUER_MISMATCH, result.reason)

    def test_append_cn_subject_helper_produces_derived_name(self):
        issuer = make_eec()['tbsCertificate']['subject']
        subject = proxychain.append_cn_subject(issuer, 'proxy-1')
        issuer_sig = proxychain._name_signature(issuer)[0]
        subject_sig, cns = proxychain._name_signature(subject)
        self.assertEqual(issuer_sig, subject_sig[:-1])
        self.assertEqual(('Alice', 'proxy-1'), cns)


class ProxyCertInfoCriticalityTestCase(unittest.TestCase):
    def test_non_critical_proxy_cert_info_is_rejected(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                           critical=False)
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.PROXY_INFO_NOT_CRITICAL, result.reason)

    def test_missing_proxy_cert_info_is_rejected(self):
        eec = make_eec()
        impostor = certificate(
            2, eec['tbsCertificate']['subject'],
            proxychain.append_cn_subject(
                eec['tbsCertificate']['subject'], 'alice-1'
            ),
            [key_usage('digitalSignature')],
        )
        result = proxychain.check_chain(eec, [impostor], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.PROXY_INFO_MISSING, result.reason)

    def test_eec_must_not_carry_proxy_cert_info(self):
        eec = make_eec()
        eec['tbsCertificate']['extensions'].append(
            proxy_info(rfc3820.id_ppl_inheritAll)
        )
        result = proxychain.check_chain(eec, [make_proxy(eec, 'a',
                                                         rfc3820.id_ppl_inheritAll)],
                                        now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.EEC_HAS_PROXY_INFO, result.reason)


class ProfileTestCase(unittest.TestCase):
    def test_basic_constraints_ca_is_rejected_on_proxy(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                           extra_extensions=[basic_constraints(ca=True)])
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.BASIC_CONSTRAINTS_CA, result.reason)

    def test_subject_alt_name_is_rejected(self):
        eec = make_eec()
        san = rfc5280.SubjectAltName()
        general_name = rfc5280.GeneralName()
        general_name['dNSName'] = 'proxy.example'
        san.append(general_name)
        proxy = make_proxy(
            eec, 'alice-1', rfc3820.id_ppl_inheritAll,
            extra_extensions=[extension(rfc5280.id_ce_subjectAltName,
                                        der_encoder(san))],
        )
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.SUBJECT_ALT_NAME_PRESENT, result.reason)

    def test_issuer_alt_name_is_rejected(self):
        eec = make_eec()
        ian = rfc5280.IssuerAltName()
        general_name = rfc5280.GeneralName()
        general_name['dNSName'] = 'issuer.example'
        ian.append(general_name)
        proxy = make_proxy(
            eec, 'alice-1', rfc3820.id_ppl_inheritAll,
            extra_extensions=[extension(rfc5280.id_ce_issuerAltName,
                                        der_encoder(ian))],
        )
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.ISSUER_ALT_NAME_PRESENT, result.reason)

    def test_signing_proxy_needs_digital_signature_key_usage(self):
        eec = make_eec()
        first = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                           path_len=1, serial=2,
                           key_usage_names=('keyEncipherment',))
        second = make_proxy(first, 'alice-2', rfc3820.id_ppl_inheritAll,
                            serial=3)
        result = proxychain.check_chain(eec, [first, second], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.KEY_USAGE_NO_DIGITAL_SIGNATURE, result.reason)

    def test_issuing_proxy_may_omit_key_usage_entirely(self):
        eec = make_eec()
        first = certificate(
            2, eec['tbsCertificate']['subject'],
            proxychain.append_cn_subject(
                eec['tbsCertificate']['subject'], 'alice-1'
            ),
            [proxy_info(rfc3820.id_ppl_inheritAll, path_len=1)],
        )
        second = make_proxy(first, 'alice-2', rfc3820.id_ppl_inheritAll,
                            path_len=0, serial=3)
        result = proxychain.check_chain(eec, [first, second], now=NOW)
        self.assertEqual(Decision.ACCEPT, result.code)

    def test_leaf_key_usage_may_omit_digital_signature(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                           key_usage_names=('keyAgreement',))
        self.assertEqual(Decision.ACCEPT,
                         proxychain.check_chain(eec, [proxy], now=NOW).code)

    def test_v1_proxy_is_rejected(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll)
        proxy['tbsCertificate']['version'] = 'v1'
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.UNSUPPORTED_VERSION, result.reason)

    def test_expired_proxy_is_rejected(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                           not_before='250101000000Z',
                           not_after='250201000000Z')
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.CERTIFICATE_EXPIRED, result.reason)

    def test_proxy_not_yet_valid_is_rejected(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                           not_before='261201000000Z',
                           not_after='270101000000Z')
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.CERTIFICATE_NOT_YET_VALID, result.reason)

    def test_unknown_critical_extension_is_rejected(self):
        eec = make_eec()
        proxy = make_proxy(
            eec, 'alice-1', rfc3820.id_ppl_inheritAll,
            extra_extensions=[extension(univ.ObjectIdentifier('1.2.3.4'),
                                        b'\x05\x00')],
        )
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.UNKNOWN_CRITICAL_EXTENSION, result.reason)

    def test_unknown_critical_extension_on_eec_is_rejected(self):
        eec = make_eec(extensions=[
            key_usage('digitalSignature'),
            basic_constraints(),
            extension(univ.ObjectIdentifier('1.2.3.4'), b'\x05\x00'),
        ])
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll)
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.UNKNOWN_CRITICAL_EXTENSION, result.reason)

    def test_unknown_non_critical_extension_warns(self):
        eec = make_eec()
        proxy = make_proxy(
            eec, 'alice-1', rfc3820.id_ppl_inheritAll,
            extra_extensions=[extension(univ.ObjectIdentifier('1.2.3.4'),
                                        b'\x05\x00', critical=False)],
        )
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.ACCEPT, result.code)
        self.assertTrue(any('1.2.3.4' in w for w in result.warnings))

    def test_malformed_proxy_cert_info_is_rejected_not_raised(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll)
        for junk in (b'', b'\x30', b'\x30\x80', b'\x30\x00',
                     b'\xff\xff'):
            candidate, rest = der_decoder(der_encoder(proxy),
                                          asn1Spec=rfc5280.Certificate())
            self.assertFalse(rest)
            for ext in candidate['tbsCertificate']['extensions']:
                if ext['extnID'] == rfc3820.id_pe_proxyCertInfo:
                    ext['extnValue'] = univ.OctetString(junk)
            result = proxychain.check_chain(eec, [candidate], now=NOW)
            self.assertEqual(Decision.REJECT, result.code, junk)
            self.assertEqual(Reason.PROXY_INFO_MALFORMED, result.reason,
                             junk)

    def test_duplicate_proxy_cert_info_is_rejected(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll)
        proxy['tbsCertificate']['extensions'].append(
            proxy_info(rfc3820.id_ppl_inheritAll)
        )
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.PROXY_INFO_DUPLICATE, result.reason)


class PolicyTestCase(unittest.TestCase):
    def test_inherit_all_must_not_have_policy_field(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                           policy=b'unexpected')
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.POLICY_FORBIDDEN_FIELD, result.reason)

    def test_independent_must_not_have_policy_field(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_independent,
                           policy=b'unexpected')
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.POLICY_FORBIDDEN_FIELD, result.reason)

    def test_independent_proxy_does_not_inherit_eec_rights(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_independent)
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.ACCEPT, result.code)
        self.assertFalse(result.rights.unrestricted)
        self.assertEqual(frozenset(), result.rights.items)

    def test_inherit_all_after_independent_stays_empty(self):
        eec = make_eec()
        first = make_proxy(eec, 'alice-1', rfc3820.id_ppl_independent,
                           path_len=1, serial=2)
        second = make_proxy(first, 'alice-2', rfc3820.id_ppl_inheritAll,
                            serial=3)
        result = proxychain.check_chain(eec, [first, second], now=NOW)
        self.assertEqual(Decision.ACCEPT, result.code)
        self.assertFalse(result.rights.unrestricted)
        self.assertEqual(frozenset(), result.rights.items)

    def test_unknown_language_is_indeterminate(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', LOCAL_POLICY,
                           policy=b'read')
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.INDETERMINATE, result.code)
        self.assertEqual(Reason.POLICY_UNKNOWN_LANGUAGE, result.reason)
        self.assertFalse(result.accepted)

    def test_unknown_language_never_inherits_all(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', LOCAL_POLICY, policy=b'read')
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertIsNone(result.rights)

    def test_any_language_is_not_a_certificate_policy(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_anyLanguage)
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.POLICY_ANY_LANGUAGE_IN_CERT, result.reason)

    def test_acceptable_set_can_exclude_inherit_all(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll)
        result = proxychain.check_chain(
            eec, [proxy], now=NOW,
            acceptable_policy_languages=[LOCAL_POLICY],
        )
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.POLICY_UNSUPPORTED_BY_APP, result.reason)

    def test_acceptable_language_set_is_enforced(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll)
        result = proxychain.check_chain(
            eec, [proxy], now=NOW,
            acceptable_policy_languages=[LOCAL_POLICY],
        )
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.POLICY_UNSUPPORTED_BY_APP, result.reason)

    def test_whitelist_rejection_takes_precedence_over_missing_interpreter(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', LOCAL_POLICY, policy=b'read')
        result = proxychain.check_chain(
            eec, [proxy], now=NOW,
            acceptable_policy_languages=[rfc3820.id_ppl_inheritAll],
        )
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.POLICY_UNSUPPORTED_BY_APP, result.reason)

    def test_any_language_sentinel_defers_language_check(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll)
        result = proxychain.check_chain(
            eec, [proxy], now=NOW,
            acceptable_policy_languages=[rfc3820.id_ppl_anyLanguage],
        )
        self.assertEqual(Decision.ACCEPT, result.code)


class UnrestrictedInterpreter(PolicyInterpreter):
    language = LOCAL_POLICY

    def interpret(self, policy_octets, delegated_rights):
        return Rights()


class InterpreterTestCase(unittest.TestCase):
    def test_custom_interpreter_cannot_return_unrestricted_rights(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', LOCAL_POLICY, policy=b'read')
        result = proxychain.check_chain(
            eec, [proxy], now=NOW,
            policy_interpreters=[UnrestrictedInterpreter()],
        )
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.POLICY_INTERPRETER_UNRESTRICTED, result.reason)
        self.assertIsNone(result.rights)

    def test_interpreter_narrows_rights(self):
        eec = make_eec()
        interpreter = ReadingInterpreter()
        proxy = make_proxy(eec, 'alice-1', LOCAL_POLICY, policy=b'read')
        result = proxychain.check_chain(
            eec, [proxy], now=NOW, policy_interpreters=[interpreter]
        )
        self.assertEqual(Decision.ACCEPT, result.code)
        self.assertEqual(Rights({READ}), result.rights)
        self.assertEqual(b'read', interpreter.calls[0][0])
        self.assertTrue(interpreter.calls[0][1].unrestricted)

    def test_two_level_intersection(self):
        eec = make_eec()
        interpreter = ReadingInterpreter()
        first = make_proxy(eec, 'alice-1', LOCAL_POLICY,
                           policy=b'read,write', path_len=1, serial=2)
        second = make_proxy(first, 'alice-2', LOCAL_POLICY,
                            policy=b'read', path_len=0, serial=3)
        result = proxychain.check_chain(
            eec, [first, second], now=NOW,
            policy_interpreters=[interpreter],
        )
        self.assertEqual(Decision.ACCEPT, result.code)
        self.assertEqual(Rights({READ}), result.rights)

    def test_interpreter_cannot_widen_rights(self):
        eec = make_eec()
        first = make_proxy(eec, 'alice-1', LOCAL_POLICY,
                           policy=b'read', path_len=1, serial=2)
        second = make_proxy(first, 'alice-2', LOCAL_POLICY,
                            policy=b'write', path_len=0, serial=3)
        result = proxychain.check_chain(
            eec, [first, second], now=NOW,
            policy_interpreters=[ReadingInterpreter()],
        )
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.POLICY_INTERPRETER_NOT_MONOTONE, result.reason)

    def test_interpreter_returning_extra_rights_is_rejected(self):
        eec = make_eec()
        # The first delegation narrows the unrestricted EEC rights to
        # ``read``.  The same interpreter then tries to add ``write`` on the
        # second level; that is outside the delegated set and must be rejected
        # rather than silently intersected.
        first = make_proxy(eec, 'alice-1', LOCAL_POLICY,
                           policy=b'read', path_len=1, serial=2)
        second = make_proxy(first, 'alice-2', LOCAL_POLICY,
                            policy=b'read', path_len=0, serial=3)

        class EscalatesWhenNarrowed(ReadingInterpreter):
            def interpret(self, policy_octets, delegated_rights):
                if delegated_rights.unrestricted:
                    return super().interpret(policy_octets, delegated_rights)
                return Rights(set(delegated_rights.items) | {WRITE})

        result = proxychain.check_chain(
            eec, [first, second], now=NOW,
            policy_interpreters=[EscalatesWhenNarrowed()],
        )
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.POLICY_INTERPRETER_NOT_MONOTONE, result.reason)

    def test_interpreter_error_is_indeterminate(self):
        eec = make_eec()
        proxy = make_proxy(eec, 'alice-1', LOCAL_POLICY, policy=b'bogus')
        result = proxychain.check_chain(
            eec, [proxy], now=NOW,
            policy_interpreters=[ReadingInterpreter()],
        )
        self.assertEqual(Decision.INDETERMINATE, result.code)
        self.assertEqual(Reason.POLICY_INTERPRETER_ERROR, result.reason)

    def test_missing_policy_octets_reach_interpreter(self):
        eec = make_eec()
        interpreter = ReadingInterpreter()
        proxy = make_proxy(eec, 'alice-1', LOCAL_POLICY)
        result = proxychain.check_chain(
            eec, [proxy], now=NOW, policy_interpreters=[interpreter]
        )
        self.assertEqual(Decision.INDETERMINATE, result.code)
        self.assertIsNone(interpreter.calls[0][0])

    def test_duplicate_interpreter_language_is_a_programming_error(self):
        with self.assertRaises(ValueError):
            proxychain.check_chain(
                make_eec(), [], now=NOW,
                policy_interpreters=[ReadingInterpreter(),
                                     ReadingInterpreter()],
            )


class PemFixtureTestCase(unittest.TestCase):
    """Re-parse the emitted PEM fixtures, as a service would receive them."""

    def _load(self, name):
        path = os.path.join(FIXTURE_DIR, name)
        with open(path, 'r') as stream:
            certificates = []
            while True:
                idx, substrate = pem.readPemBlocksFromFile(
                    stream,
                    ('-----BEGIN CERTIFICATE-----',
                     '-----END CERTIFICATE-----'),
                )
                if not substrate:
                    break
                cert, rest = der_decoder(substrate,
                                         asn1Spec=rfc5280.Certificate())
                self.assertFalse(rest)
                certificates.append(cert)
        return certificates

    def test_leaf_first_order_is_rejected(self):
        certificates = self._load('legal-two-level-inheritall.pem')
        result = proxychain.check_chain(
            certificates[0], list(reversed(certificates[1:])), now=NOW
        )
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.ISSUER_MISMATCH, result.reason)

    def test_legal_fixture_is_accepted_after_parsing(self):
        certificates = self._load('legal-two-level-inheritall.pem')
        self.assertEqual(3, len(certificates))
        result = proxychain.check_chain(certificates[0], certificates[1:],
                                        now=NOW)
        self.assertEqual(Decision.ACCEPT, result.code)
        self.assertTrue(result.rights.unrestricted)

    def test_failure_fixtures_keep_their_reasons_after_parsing(self):
        expectations = {
            'path-length-0-still-signs-a-proxy.pem':
                Reason.PATH_LENGTH_EXCEEDED,
            'subject-adds-an-o-instead-of-one-cn.pem':
                Reason.SUBJECT_NOT_DERIVED,
            'proxycertinfo-not-critical.pem':
                Reason.PROXY_INFO_NOT_CRITICAL,
            'restricted-language-no-interpreter.pem':
                Reason.POLICY_UNKNOWN_LANGUAGE,
            'inheritall-below-independent-stays-empty.pem': None,
        }
        for name, reason in expectations.items():
            certificates = self._load(name)
            result = proxychain.check_chain(certificates[0],
                                            certificates[1:], now=NOW)
            if reason is None:
                self.assertEqual(Decision.ACCEPT, result.code, name)
                self.assertEqual(frozenset(), result.rights.items, name)
            else:
                self.assertEqual(reason, result.reason, name)


class SignatureBindingTestCase(unittest.TestCase):
    def test_signature_callback_vetoes(self):
        eec = make_eec()
        first = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                           path_len=1, serial=2)
        second = make_proxy(first, 'alice-2', rfc3820.id_ppl_inheritAll,
                            serial=3)

        def verify(cert, issuer):
            if cert['tbsCertificate']['serialNumber'] == 3:
                raise ValueError('bad signature')

        result = proxychain.check_chain(eec, [first, second], now=NOW,
                                        verify_signatures=verify)
        self.assertEqual(Decision.REJECT, result.code)
        self.assertEqual(Reason.SIGNATURE_NOT_VERIFIED, result.reason)

    def test_signature_check_is_explicit_opt_in(self):
        # Omitting the callback models an offline structural review, not a
        # production verifier.  The API must not offer a "verification off"
        # boolean that can be flipped accidentally.
        parameters = inspect.signature(
            proxychain.check_chain
        ).parameters
        self.assertIn('verify_signatures', parameters)
        self.assertNotIn('verify', parameters)
        self.assertIsNone(parameters['verify_signatures'].default)


class EffectiveKeyUsageTestCase(unittest.TestCase):
    def test_result_reports_effective_key_usage(self):
        eec = make_eec(extensions=[
            key_usage('digitalSignature', 'keyAgreement'),
        ])
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                           key_usage_names=('digitalSignature',
                                            'keyEncipherment'))
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.ACCEPT, result.code)
        self.assertEqual({'digitalSignature'}, result.key_usage)

    def test_eku_intersection(self):
        eec = make_eec(extensions=[
            key_usage('digitalSignature'),
            ext_key_usage(rfc5280.id_kp_serverAuth, rfc5280.id_kp_clientAuth),
        ])
        proxy = make_proxy(
            eec, 'alice-1', rfc3820.id_ppl_inheritAll,
            extra_extensions=[ext_key_usage(rfc5280.id_kp_serverAuth)],
        )
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.ACCEPT, result.code)
        self.assertEqual(frozenset([proxychain._oid_str(rfc5280.id_kp_serverAuth)]),
                         result.extended_key_usage)

    def test_any_eku_does_not_narrow(self):
        eec = make_eec(extensions=[
            key_usage('digitalSignature'),
            ext_key_usage(rfc5280.anyExtendedKeyUsage),
        ])
        proxy = make_proxy(
            eec, 'alice-1', rfc3820.id_ppl_inheritAll,
            extra_extensions=[ext_key_usage(rfc5280.id_kp_serverAuth)],
        )
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(frozenset([proxychain._oid_str(rfc5280.id_kp_serverAuth)]),
                         result.extended_key_usage)

    def test_independent_resets_eku(self):
        eec = make_eec(extensions=[
            key_usage('digitalSignature'),
            ext_key_usage(rfc5280.id_kp_serverAuth),
        ])
        proxy = make_proxy(
            eec, 'alice-1', rfc3820.id_ppl_independent,
            extra_extensions=[ext_key_usage(rfc5280.id_kp_clientAuth)],
        )
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(frozenset([proxychain._oid_str(rfc5280.id_kp_clientAuth)]),
                         result.extended_key_usage)

    def test_key_usage_intersection(self):
        eec = make_eec(extensions=[
            key_usage('digitalSignature', 'keyAgreement'),
        ])
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_inheritAll,
                           key_usage_names=('digitalSignature',
                                            'keyEncipherment'))
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.ACCEPT, result.code)
        self.assertEqual({'digitalSignature'}, result.key_usage)

    def test_independent_starts_its_own_key_usage(self):
        eec = make_eec(extensions=[key_usage('digitalSignature')])
        proxy = make_proxy(eec, 'alice-1', rfc3820.id_ppl_independent,
                           key_usage_names=('keyAgreement',))
        result = proxychain.check_chain(eec, [proxy], now=NOW)
        self.assertEqual(Decision.ACCEPT, result.code)
        self.assertEqual({'keyAgreement'}, result.key_usage)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
