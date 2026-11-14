#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""Regression tests for CRMF proof-of-possession binding (RFC 4211 4.1).

The property under test is not signature validity.  Every attack copy here
carries a cryptographically valid POP over the octets it names; what makes
it an attack is that those octets are not the request being submitted.
A validator that only calls a signature routine -- and never recomputes
the octets from the request or compares the public-key copies -- accepts
them.  A test named ``VerifySignatureOnlyDefectTest`` encodes exactly that
defect and asserts the attacks slip through it, which demonstrates the
regression has teeth.
"""

import copy
import sys
import unittest

from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import univ

from pyasn1_modules import rfc4211
from pyasn1_modules import rfc3280

from examples.crmf_pop import der
from examples.crmf_pop import fixtures
from examples.crmf_pop import verifier


def check_signature(public_key_der, signed_bytes, signature,
                    algorithm_der):
    """Fixed test signature: HMAC keyed by the principal owning the key."""
    del algorithm_der
    for principal in (fixtures.LEGITIMATE, fixtures.ATTACKER):
        if public_key_der == der.subject_public_key_info(
                der.public_key(principal)):
            return signature == der.sign(principal, signed_bytes)
    return False


def check_public_key_mac(pbm, public_key_der, mac_value):
    expected = der.pbm_mac(
        der.password(fixtures.LEGITIMATE), bytes(pbm['salt']),
        int(pbm['iterationCount']), public_key_der)
    return mac_value == expected


def issuer_context():
    return verifier.IssuerContext(**fixtures.issuer_context())


def verify(example, **kwargs):
    kwargs.setdefault('issuer', issuer_context())
    kwargs.setdefault('verify_public_key_mac', check_public_key_mac)
    return verifier.verify_cert_request(
        example.message, check_signature, **kwargs)


class SignedInputOracleTest(unittest.TestCase):
    """The verifier must reproduce the independently built signed octets."""

    def test_no_input_signs_cert_request(self):
        example = fixtures.build_no_input()
        accepted = verify(example)
        self.assertEqual(example.cert_request_der, accepted.signed_bytes)
        self.assertEqual(example.cert_request_der, example.signed_bytes)

    def test_sender_signs_poposk_input(self):
        example = fixtures.build_sender()
        accepted = verify(example)
        self.assertEqual(example.signed_bytes, accepted.signed_bytes)

    def test_public_key_mac_signs_poposk_input(self):
        example = fixtures.build_public_key_mac()
        accepted = verify(example)
        self.assertEqual(example.signed_bytes, accepted.signed_bytes)

    def test_signed_bytes_exclude_the_context_tags(self):
        """The signed value is the untagged structure, per RFC 4211 4.1."""
        example = fixtures.build_sender()
        # The [0] tag on poposkInput is not part of POPOSigningKeyInput.
        self.assertEqual(0x30, example.signed_bytes[0])
        self.assertNotEqual(0xa0, example.signed_bytes[0])
        accepted = verify(example)
        self.assertNotEqual(0xa0, accepted.signed_bytes[0])

    def test_public_key_bytes_are_independent_of_pyasn1(self):
        """Fix the expected key bytes so an encoder drift cannot hide."""
        expected = der.subject_public_key_info(der.public_key('alice'))
        example = fixtures.build_no_input()
        accepted = verify(example)
        self.assertEqual(expected, accepted.public_key_der)
        self.assertEqual(expected, example.public_key_der)


class LegitimateRequestTest(unittest.TestCase):
    """Every RFC 4211 case with a well-formed, bound POP is accepted."""

    def test_all_legitimate_cases_are_accepted(self):
        for name, example in fixtures.legitimate_cases().items():
            policy = verifier.VerificationPolicy(
                allow_ra_verified=(name == 'ra_verified'))
            ra_context = verifier.TrustedRA(
                'test-ra', example.cert_request_der) \
                if name == 'ra_verified' else None
            with self.subTest(case=name):
                accepted = verify(example, policy=policy,
                                  ra_context=ra_context)
                self.assertIsNotNone(accepted)
                self.assertTrue(accepted.subject_bound)

    def test_case_3_binds_subject_and_key(self):
        accepted = verify(fixtures.build_no_input())
        self.assertEqual('signature', accepted.kind)
        self.assertIsNone(accepted.auth_method)
        self.assertIsNone(accepted.poposk_input_public_key_der)
        self.assertTrue(accepted.subject_authenticated)

    def test_case_2_binds_subject_through_sender(self):
        accepted = verify(fixtures.build_sender())
        self.assertEqual('sender', accepted.auth_method)
        self.assertTrue(accepted.sender_authenticated)
        self.assertEqual(der.directory_name('alice'),
                         accepted.claimed_sender_der)

    def test_incomplete_template_public_key_only(self):
        """The template has the key only; the subject comes from sender."""
        example = fixtures.build_sender_public_key_only()
        self.assertEqual(fixtures.PUBKEY_ONLY, example.template_fields)
        accepted = verify(example)
        self.assertIsNone(accepted.template_subject_der)
        self.assertEqual(der.common_name('alice'), accepted.subject_der)
        self.assertTrue(accepted.subject_bound)
        self.assertTrue(accepted.subject_authenticated)

    def test_incomplete_template_neither_field(self):
        accepted = verify(fixtures.build_sender_no_template_fields())
        self.assertIsNone(accepted.template_subject_der)
        self.assertIsNone(accepted.template_public_key_der)
        self.assertEqual(der.common_name('alice'), accepted.subject_der)
        self.assertEqual(der.subject_public_key_info(der.public_key('alice')),
                         accepted.public_key_der)


class AbsentAndMalformedPopTest(unittest.TestCase):
    """Structural rules from RFC 4211 section 4.1 and its ASN.1 comments."""

    def _message_without_popo(self):
        example = fixtures.build_no_input()
        message = example.message.subtype()
        message['certReq'] = example.message['certReq']
        return message

    def test_popo_is_required_by_default(self):
        message = self._message_without_popo()
        with self.assertRaises(verifier.PopError):
            verifier.verify_cert_request(message, check_signature,
                                         issuer=issuer_context())

    def test_popo_omission_allowed_only_by_policy(self):
        message = self._message_without_popo()
        accepted = verifier.verify_cert_request(
            message, check_signature,
            policy=verifier.VerificationPolicy(require_popo=False))
        self.assertIsNone(accepted)

    def test_poposk_input_forbidden_when_template_is_complete(self):
        """The structural rule fires before the signature is even checked."""
        with self.assertRaises(verifier.PopError) as caught:
            verify(fixtures.attack_no_input_poposk_input_added())
        self.assertIn('poposkInput', str(caught.exception))

    def test_poposk_input_required_when_template_is_incomplete(self):
        with self.assertRaises(verifier.PopError) as caught:
            verify(fixtures.attack_sender_without_poposk_input())
        self.assertIn('poposkInput', str(caught.exception))

    def test_input_public_key_must_equal_template_public_key(self):
        with self.assertRaises(verifier.PopError) as caught:
            verify(fixtures.attack_sender_input_key_mismatch())
        self.assertIn('does not match CertTemplate', str(caught.exception))

    def test_unsupported_popo_choice_is_rejected(self):
        """A POPOPrivKey branch is not signature POP and is out of scope."""
        from pyasn1.type import tag

        example = fixtures.build_no_input()
        message = rfc4211.CertReqMsg()
        message['certReq'] = example.message['certReq']
        popo = rfc4211.ProofOfPossession()
        priv = rfc4211.POPOPrivKey().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, 1, 2))
        priv['subsequentMessage'] = rfc4211.SubsequentMessage(
            'encrCert').subtype(
            implicitTag=tag.Tag(tag.tagClassContext, 0, 1))
        popo['keyEncipherment'] = priv
        message['popo'] = popo
        with self.assertRaises(verifier.PopError):
            verifier.verify_cert_request(message, check_signature,
                                         issuer=issuer_context())


class AttackCopiesRejectedTest(unittest.TestCase):
    """Each attack changes one field; binding, not crypto, must reject it."""

    def test_every_attack_copy_is_rejected(self):
        legitimate_ra = fixtures.build_ra_verified()
        ra_context = verifier.TrustedRA(
            'test-ra', legitimate_ra.cert_request_der)
        for name, example in fixtures.attack_cases().items():
            with self.subTest(attack=name):
                with self.assertRaises(verifier.PopError):
                    verify(example,
                           policy=verifier.VerificationPolicy(
                               allow_ra_verified=True),
                           ra_context=ra_context)

    def test_subject_swap_breaks_case_3_signature(self):
        """In case 3 the subject really is covered, so the signature fails."""
        example = fixtures.attack_no_input_subject()
        self.assertEqual(fixtures.SUBJECT_AND_KEY, example.template_fields)
        self.assertNotEqual(
            example.signed_bytes,
            der_encoder(example.message['certReq']))
        with self.assertRaises(verifier.PopError):
            verify(example)

    def test_public_key_swap_breaks_case_3_signature(self):
        example = fixtures.attack_no_input_public_key()
        self.assertNotEqual(example.signed_bytes,
                            der_encoder(example.message['certReq']))
        with self.assertRaises(verifier.PopError):
            verify(example)

    def test_sender_template_subject_mismatch_is_rejected(self):
        example = fixtures.attack_sender_template_subject()
        # Signature and sender are internally consistent; only the
        # template subject differs from the signed identity.
        self.assertEqual(example.signed_bytes,
                         verifier.encode_poposk_input(
                             example.message['popo']['signature']
                             ['poposkInput']))
        with self.assertRaises(verifier.PopError):
            verify(example)

    def test_sender_key_substitution_is_rejected(self):
        """The name says alice but the key and signature are mallory's."""
        example = fixtures.attack_sender_key_substitution()
        self.assertEqual(der.directory_name('alice'),
                         example.claimed_sender_der)
        self.assertNotEqual(
            der.subject_public_key_info(der.public_key('alice')),
            example.public_key_der)
        with self.assertRaises(verifier.PopError):
            verify(example)

    def test_input_key_mismatch_is_rejected_before_signature(self):
        with self.assertRaises(verifier.PopError):
            verify(fixtures.attack_sender_input_key_mismatch())

    def test_sender_subject_mismatch_survives_a_relaxed_sender_policy(self):
        """Isolate the equality rule from the sender-authentication rule.

        With ``require_authenticated_sender=False``, the only thing left
        that can reject a valid mallory POP whose template names alice is
        the rule that the template subject must equal the signed identity.
        """
        example = fixtures.attack_sender_template_subject()
        relaxed = verifier.VerificationPolicy(
            require_authenticated_sender=False)
        with self.assertRaises(verifier.PopError):
            verify(example, policy=relaxed)

    def test_input_key_mismatch_survives_a_relaxed_sender_policy(self):
        """The two-key equality rule is independent of identity checks."""
        example = fixtures.attack_sender_input_key_mismatch()
        relaxed = verifier.VerificationPolicy(
            require_authenticated_sender=False)
        with self.assertRaises(verifier.PopError):
            verify(example, policy=relaxed)


class PublicKeyMacTest(unittest.TestCase):
    """``publicKeyMAC`` covers the DER public key and nothing else."""

    def test_mac_case_has_no_template_subject(self):
        accepted = verify(fixtures.build_public_key_mac())
        self.assertEqual('publicKeyMAC', accepted.auth_method)
        self.assertIsNone(accepted.subject_der)
        self.assertFalse(accepted.subject_authenticated)

    def test_template_subject_beside_public_key_mac_is_unbound(self):
        """A subject next to publicKeyMAC is an applicant claim, not POP."""
        example = fixtures.attack_public_key_mac_subject()
        with self.assertRaises(verifier.PopError):
            verify(example)
        # Opting out of the binding rule exposes exactly that: not bound.
        accepted = verify(example, policy=verifier.VerificationPolicy(
            require_bound_subject=False))
        self.assertFalse(accepted.subject_bound)
        self.assertEqual(der.common_name('mallory'), accepted.subject_der)

    def test_mac_over_different_key_fails(self):
        with self.assertRaises(verifier.PopError):
            verify(fixtures.attack_public_key_mac_key())

    def test_wrong_shared_secret_fails(self):
        with self.assertRaises(verifier.PopError):
            verify(fixtures.attack_public_key_mac_wrong_password())

    def test_mac_callback_is_required(self):
        example = fixtures.build_public_key_mac()
        with self.assertRaises(verifier.PopError):
            verifier.verify_cert_request(
                example.message, check_signature, issuer=issuer_context())

    def test_mac_profile_requires_password_based_mac(self):
        """An ``algId`` other than id-PasswordBasedMac must be rejected."""
        spki = der.subject_public_key_info(der.public_key('alice'))
        # Same MAC shape, but labelled with a non-PBM algorithm.
        auth_info = der.sequence(
            der.algorithm_identifier('1.2.840.113549.1.1.1'),
            der.bit_string(b'\x00' * 20))
        signed_bytes = der.poposk_input_der(auth_info, spki)
        template = der.cert_template(spki_der=spki)
        cert_request = der.cert_request_der(3, template)
        signature = der.sign('alice', signed_bytes)
        wire = der.cert_req_msg_der(
            cert_request,
            der.popo_signature_der(signed_bytes, der.TEST_SIGNATURE_ALGORITHM,
                                   signature))
        # This message is structurally well formed; only the algorithm
        # label is wrong, so it must decode and then fail the profile.
        with self.assertRaises(verifier.PopError):
            verify_message(verifier.decode_cert_req_msg(wire))


def verify_message(message):
    return verifier.verify_cert_request(
        message, check_signature, issuer=issuer_context(),
        verify_public_key_mac=check_public_key_mac)


class PkmacProfileTest(unittest.TestCase):
    """The mandatory section 4.4 profile checks are enforced, not assumed."""

    def _example_with_pbm(self, salt=b'salt-0123456789', iterations=1000,
                          owf=der.ID_SHA1, mac=der.ID_HMAC_SHA1,
                          truncate_params=False):
        spki = der.subject_public_key_info(der.public_key('alice'))
        auth_info = der.auth_info_public_key_mac(
            b'\x00' * 20, salt, iterations, owf, mac)
        if truncate_params:
            # Keep the PKMACValue shape but make PBMParameter undecodable.
            auth_info = der.sequence(
                der.sequence(der.oid(der.ID_PASSWORD_BASED_MAC),
                             der.octet_string(b'not-a-parameter')),
                der.bit_string(b'\x00' * 20))
        signed_bytes = der.poposk_input_der(auth_info, spki)
        template = der.cert_template(spki_der=spki)
        cert_request = der.cert_request_der(3, template)
        wire = der.cert_req_msg_der(
            cert_request,
            der.popo_signature_der(signed_bytes, der.TEST_SIGNATURE_ALGORITHM,
                                   der.sign('alice', signed_bytes)))
        return verifier.decode_cert_req_msg(wire)

    def test_low_iteration_count_is_rejected(self):
        with self.assertRaises(verifier.PopError) as caught:
            verify_message(self._example_with_pbm(iterations=99))
        self.assertIn('iterationCount', str(caught.exception))

    def test_wrong_owf_is_rejected(self):
        with self.assertRaises(verifier.PopError) as caught:
            verify_message(self._example_with_pbm(
                owf='1.3.14.3.2.28'))
        self.assertIn('owf', str(caught.exception))

    def test_wrong_mac_algorithm_is_rejected(self):
        with self.assertRaises(verifier.PopError) as caught:
            verify_message(self._example_with_pbm(
                mac='1.2.840.113549.2.8'))
        self.assertIn('mac', str(caught.exception))

    def test_undecodable_pbm_parameters_are_rejected(self):
        with self.assertRaises(verifier.PopError) as caught:
            verify_message(self._example_with_pbm(truncate_params=True))
        self.assertIn('PBMParameter', str(caught.exception))

    def test_pbm_parameters_with_trailing_data_are_rejected(self):
        """``PBMParameter`` must consume its whole parameter blob."""
        from pyasn1.codec.der.decoder import decode as der_decoder
        from pyasn1_modules import rfc3280

        pbm = der.sequence(
            der.octet_string(b'salt-0123456789'),
            der.algorithm_identifier(der.ID_SHA1),
            der.integer(1000),
            der.algorithm_identifier(der.ID_HMAC_SHA1))
        alg_id = rfc3280.AlgorithmIdentifier()
        alg_id['algorithm'] = der.ID_PASSWORD_BASED_MAC
        alg_id['parameters'] = univ.Any(pbm + b'\x00')
        pkmac = rfc4211.PKMACValue()
        pkmac['algId'] = alg_id
        pkmac['value'] = univ.BitString.fromOctetString(b'\x00' * 20)
        with self.assertRaises(verifier.PopError) as caught:
            verifier.decode_public_key_mac(pkmac)
        self.assertIn('trailing data', str(caught.exception))

    def test_trailing_data_after_cert_req_msg_is_rejected(self):
        example = fixtures.build_no_input()
        with self.assertRaises(verifier.PopError) as caught:
            verifier.decode_cert_req_msg(example.wire + b'\x00')
        self.assertIn('trailing data', str(caught.exception))


class PolicyOptInTest(unittest.TestCase):
    """Checks that exist only when the caller opts into them."""

    def test_authenticated_subject_policy_is_enforced(self):
        policy = verifier.VerificationPolicy(
            require_authenticated_subject=True)
        with self.assertRaises(verifier.PopError) as caught:
            verify(fixtures.build_public_key_mac(), policy=policy)
        self.assertIn('authenticated subject', str(caught.exception))

    def test_authenticated_subject_policy_applies_to_ra_verified(self):
        example = fixtures.build_ra_verified()
        context = verifier.TrustedRA('test-ra', example.cert_request_der)
        with self.assertRaises(verifier.PopError) as caught:
            verify(example, policy=verifier.VerificationPolicy(
                allow_ra_verified=True, require_authenticated_subject=True),
                ra_context=context, issuer=verifier.IssuerContext())
        self.assertIn('authenticated subject', str(caught.exception))

    def test_authenticated_subject_policy_accepts_known_identity(self):
        accepted = verify(fixtures.build_no_input(),
                          policy=verifier.VerificationPolicy(
                              require_authenticated_subject=True))
        self.assertTrue(accepted.subject_authenticated)

    def test_ra_context_without_request_is_rejected(self):
        example = fixtures.build_ra_verified()
        context = verifier.TrustedRA('test-ra', None)
        with self.assertRaises(verifier.PopError) as caught:
            verify(example, policy=verifier.VerificationPolicy(
                allow_ra_verified=True), ra_context=context)
        self.assertIn('does not cover', str(caught.exception))

    def test_ra_verified_requires_a_template_public_key(self):
        spki = der.subject_public_key_info(der.public_key('alice'))
        del spki
        template = der.cert_template(subject_der=der.common_name('alice'))
        cert_request = der.cert_request_der(4, template)
        wire = der.cert_req_msg_der(cert_request, der.popo_ra_verified_der())
        message = verifier.decode_cert_req_msg(wire)
        context = verifier.TrustedRA('test-ra', cert_request)
        with self.assertRaises(verifier.PopError) as caught:
            verifier.verify_cert_request(
                message, check_signature,
                policy=verifier.VerificationPolicy(allow_ra_verified=True),
                issuer=issuer_context(), ra_context=context)
        self.assertIn('public key', str(caught.exception))


class RaVerifiedTest(unittest.TestCase):
    """``raVerified`` is an RA statement, not a requestor one."""

    policy = verifier.VerificationPolicy(allow_ra_verified=True)

    def test_requires_explicit_trusted_ra_context(self):
        example = fixtures.build_ra_verified()
        with self.assertRaises(verifier.PopError):
            verify(example, policy=self.policy, ra_context=None)

    def test_untrusted_context_is_rejected(self):
        example = fixtures.build_ra_verified()
        context = verifier.TrustedRA(
            'self-declared', example.cert_request_der, trusted=False)
        with self.assertRaises(verifier.PopError):
            verify(example, policy=self.policy, ra_context=context)

    def test_context_must_name_this_cert_request(self):
        example = fixtures.build_ra_verified()
        other = fixtures.attack_ra_verified_replay()
        context = verifier.TrustedRA(
            'test-ra', other.cert_request_der)
        with self.assertRaises(verifier.PopError):
            verify(example, policy=self.policy, ra_context=context)

    def test_replay_is_rejected_by_binding(self):
        """The legitimate RA approval must not cover the replayed request."""
        legitimate = fixtures.build_ra_verified()
        context = verifier.TrustedRA('test-ra', legitimate.cert_request_der)
        with self.assertRaises(verifier.PopError):
            verify(fixtures.attack_ra_verified_replay(),
                   policy=self.policy, ra_context=context)

    def test_replay_differs_only_in_cert_request(self):
        legitimate = fixtures.build_ra_verified()
        replay = fixtures.attack_ra_verified_replay()
        self.assertEqual(legitimate.wire[-3:], replay.wire[-3:])
        self.assertNotEqual(legitimate.cert_request_der,
                            replay.cert_request_der)

    def test_ra_verified_is_rejected_without_policy_opt_in(self):
        example = fixtures.build_ra_verified()
        with self.assertRaises(verifier.PopError):
            verify(example, ra_context=verifier.TrustedRA(
                'test-ra', example.cert_request_der))


class SingleFieldAttackTest(unittest.TestCase):
    """Each attack copy differs from a legitimate request in one place."""

    def test_subject_swap_changes_only_the_subject(self):
        legitimate = fixtures.build_no_input()
        attacked = fixtures.attack_no_input_subject()
        before = fixtures.template_fields_of(legitimate)
        after = fixtures.template_fields_of(attacked)
        differing = [key for key in set(before) | set(after)
                     if before.get(key) != after.get(key)]
        self.assertEqual(['subject'], differing)
        self.assertIsNone(fixtures.poposk_input_of(attacked))

    def test_key_swap_changes_only_the_public_key(self):
        legitimate = fixtures.build_no_input()
        attacked = fixtures.attack_no_input_public_key()
        before = fixtures.template_fields_of(legitimate)
        after = fixtures.template_fields_of(attacked)
        differing = [key for key in set(before) | set(after)
                     if before.get(key) != after.get(key)]
        self.assertEqual(['publicKey'], differing)

    def test_mac_subject_swap_keeps_the_signed_input_intact(self):
        """Only the asserted subject differs; the signed input is identical.

        The legitimate case-1 request carries no subject, because RFC 4211
        forbids ``poposkInput`` alongside a template subject.  The attack
        copies the byte-identical ``poposkInput`` and adds a subject to the
        template -- exactly the claim the MAC does not cover.
        """
        legitimate = fixtures.build_public_key_mac()
        attacked = fixtures.attack_public_key_mac_subject()
        self.assertEqual(fixtures.poposk_input_of(legitimate),
                         fixtures.poposk_input_of(attacked))
        self.assertEqual(attacked.message['popo']['signature']['signature'],
                         legitimate.message['popo']['signature']['signature'])
        before = fixtures.template_fields_of(legitimate)
        after = fixtures.template_fields_of(attacked)
        self.assertNotIn('subject', before)
        self.assertEqual(der.common_name('mallory'), after['subject'])

    def test_ra_replay_keeps_ra_verified_and_moves_the_request(self):
        legitimate = fixtures.build_ra_verified()
        replay = fixtures.attack_ra_verified_replay()
        self.assertEqual(legitimate.message['popo']['raVerified'],
                         replay.message['popo']['raVerified'])
        before = fixtures.template_fields_of(legitimate)
        after = fixtures.template_fields_of(replay)
        differing = [key for key in set(before) | set(after)
                     if before.get(key) != after.get(key)]
        self.assertEqual(['subject'], differing)


class VerifySignatureOnlyDefectTest(unittest.TestCase):
    """The deliberate defect the regression has to catch.

    ``verify_signature_only`` does what a careless integration does: it
    finds the key in the message, calls the signature routine, and stops.
    It never recomputes the octets from the submitted request and never
    compares the two public-key copies.  The attacks below are genuinely
    valid signatures, so they pass -- and that is the failure the real
    verifier must prevent.
    """

    @staticmethod
    def verify_signature_only(message):
        popo = message['popo']
        signing_key = popo['signature']
        if verifier.has_component(signing_key, 'poposkInput'):
            input_ = signing_key['poposkInput']
            public_key = verifier.encode_spki(input_['publicKey'])
            signed_bytes = verifier.encode_poposk_input(input_)
        else:
            public_key = verifier.encode_spki(
                message['certReq']['certTemplate']['publicKey'])
            signed_bytes = der_encoder(message['certReq'])
        return check_signature(
            public_key, signed_bytes, signing_key['signature'].asOctets(),
            der_encoder(signing_key['algorithmIdentifier']))

    def test_defect_accepts_transplanted_sender_proof(self):
        example = fixtures.attack_sender_template_subject()
        self.assertTrue(self.verify_signature_only(example.message))
        with self.assertRaises(verifier.PopError):
            verify(example)

    def test_defect_accepts_public_key_mac_subject_swap(self):
        example = fixtures.attack_public_key_mac_subject()
        self.assertTrue(self.verify_signature_only(example.message))
        with self.assertRaises(verifier.PopError):
            verify(example)

    def test_defect_ignores_public_key_mac(self):
        """Signature-only never even looks at the MAC branch."""
        example = fixtures.attack_public_key_mac_wrong_password()
        self.assertTrue(self.verify_signature_only(example.message))
        with self.assertRaises(verifier.PopError):
            verify(example)

    def test_defect_accepts_input_key_mismatch(self):
        """The signature covers only the input, so the template key is free."""
        example = fixtures.attack_sender_input_key_mismatch()
        self.assertTrue(self.verify_signature_only(example.message))
        with self.assertRaises(verifier.PopError):
            verify(example)


class IdentityClaimTest(unittest.TestCase):
    """Tests that document which fields are claims rather than evidence."""

    def test_sender_name_alone_is_a_claim(self):
        """A valid signature over a sender name proves key custody only."""
        example = fixtures.attack_sender_key_substitution()
        self.assertTrue(check_signature(
            example.public_key_der, example.signed_bytes,
            example.message['popo']['signature']['signature'].asOctets(),
            b''))
        # With no out-of-band knowledge, nothing ties alice's name to the key.
        result = verify(example, policy=verifier.VerificationPolicy(
            require_authenticated_sender=False))
        self.assertTrue(result.subject_bound)
        self.assertFalse(result.sender_authenticated)

    def test_template_subject_is_a_claim_in_mac_case(self):
        example = fixtures.attack_public_key_mac_subject()
        result = verify(example, policy=verifier.VerificationPolicy(
            require_bound_subject=False))
        self.assertFalse(result.subject_bound)
        self.assertFalse(result.subject_authenticated)

    def test_authentication_requires_out_of_band_key_binding(self):
        """Same name, attacker key: out-of-band pairs do not match."""
        example = fixtures.attack_sender_key_substitution()
        result = verify(example, policy=verifier.VerificationPolicy(
            require_bound_subject=False, require_authenticated_sender=False))
        self.assertFalse(result.sender_authenticated)
        self.assertFalse(result.subject_authenticated)
        # The same signature over alice's key *does* authenticate.
        legitimate = fixtures.build_sender()
        authenticated = verify(legitimate)
        self.assertTrue(authenticated.subject_authenticated)

    def test_authenticated_sender_supplies_subject_authentication(self):
        accepted = verify(fixtures.build_sender_public_key_only())
        self.assertTrue(accepted.sender_authenticated)
        self.assertTrue(accepted.subject_authenticated)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
