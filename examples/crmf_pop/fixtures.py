#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""Signed CRMF fixtures for the RFC 4211 section 4.1 POP cases.

Every certificate request here is built as a DER byte string.  The octets
that RFC 4211 says are signed are produced by :mod:`examples.crmf_pop.der`,
independently of pyasn1, so the expected signature input does not inherit
any bug in the module under test.  The envelope (sequence nesting, choice
tags, and the ``[1]`` POP wrapper) is also built by hand in that module.

Principals
-----------

``alice``
    The legitimate applicant.  Owns the key in the legitimate templates.

``mallory``
    The attacker.  Owns a key of her own and signs with it.

A legitimate fixture and its attack copy therefore differ in exactly one
place, and the attack copy is still a *cryptographically valid* POP over
the octets it names.  That is the point: signature validity is not the
property under test; binding is.

Cases
-----

``no_input``
    Template has both subject and publicKey, so ``poposkInput`` is absent
    and the signature covers the DER ``CertRequest`` (RFC 4211 case 3).

``sender``
    Template has the subject only, so ``poposkInput`` is present and the
    signature covers the DER ``POPOSigningKeyInput``.  ``authInfo`` uses
    ``sender`` (RFC 4211 case 2).

``public_key_mac``
    Template has the public key only, so ``poposkInput`` is present and
    uses ``publicKeyMAC`` (RFC 4211 case 1).  The MAC covers the DER public
    key; a subject, if present, is not covered.

``ra_verified``
    ``popo`` is ``raVerified``.  Valid only for an RA, and only for the
    exact ``CertRequest`` the RA approved.

Each builder returns an :class:`Example` containing the wire bytes, the
parsed message, the signed octets the verifier must reproduce, and helper
data for the attack cases.
"""

from dataclasses import dataclass
from typing import Optional

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import univ

from pyasn1_modules import rfc4211
from pyasn1_modules import rfc3280

from examples.crmf_pop import der

# Fields that are not covered by the POP in each case.  Tests assert that
# changing them leaves the signature valid, which is exactly why the
# verifier must not treat the signature as covering them.
SUBJECT_ONLY = 'subject only'
PUBKEY_ONLY = 'public key only'
SUBJECT_AND_KEY = 'subject and public key'

PBKDF_ITERATIONS = 1000
MAC_SALT = b'crmf-pop-salt-01'

# Principals.
LEGITIMATE = 'alice'
ATTACKER = 'mallory'


@dataclass
class Example:
    """One CRMF message plus the facts a verifier has to reproduce.

    ``signed_bytes`` is what RFC 4211 requires the signature to cover for
    this case.  ``template_fields`` records which template fields exist,
    because that decides whether ``poposkInput`` is allowed or required.
    """

    name: str
    wire: bytes
    message: 'rfc4211.CertReqMsg'
    cert_request_der: bytes
    signed_bytes: bytes
    template_fields: str
    public_key_der: bytes
    subject_der: Optional[bytes]
    cert_req_id: int
    auth_method: Optional[str]  # 'sender', 'publicKeyMAC' or None
    claimed_sender_der: Optional[bytes] = None
    sender_key_der: Optional[bytes] = None

    @property
    def cert_request(self):
        return self.message['certReq']


def _decode(substrate):
    msg, rest = der_decoder(substrate, asn1Spec=rfc4211.CertReqMsg())
    if rest:
        raise ValueError('fixture has trailing data')
    return msg


def _spki(label):
    return der.subject_public_key_info(der.public_key(label))


def build_no_input(cert_req_id=1, applicant=LEGITIMATE, subject=LEGITIMATE,
                   serial_number=0x1234):
    """Case 3: template carries subject and key; no ``poposkInput``."""
    spki = _spki(applicant)
    subject_der = der.common_name(subject)
    template = der.cert_template(
        subject_der=subject_der, spki_der=spki,
        serial_number=serial_number, version=2)
    cert_request = der.cert_request_der(cert_req_id, template)
    signature = der.sign(applicant, cert_request)
    wire = der.cert_req_msg_der(
        cert_request,
        der.popo_signature_der(None, der.TEST_SIGNATURE_ALGORITHM, signature))
    return Example(
        name='no_input',
        wire=wire,
        message=_decode(wire),
        cert_request_der=cert_request,
        signed_bytes=cert_request,
        template_fields=SUBJECT_AND_KEY,
        public_key_der=spki,
        subject_der=subject_der,
        cert_req_id=cert_req_id,
        auth_method=None)


def build_sender(cert_req_id=2, applicant=LEGITIMATE, sender_name=LEGITIMATE,
                 template_subject=LEGITIMATE, with_template_subject=True):
    """Case 2: ``poposkInput`` with ``sender``; template lacks the key."""
    spki = _spki(applicant)
    signed_bytes = der.poposk_input_der(
        der.auth_info_sender(sender_name), spki)
    template = der.cert_template(
        subject_der=der.common_name(template_subject) if with_template_subject
        else None)
    cert_request = der.cert_request_der(cert_req_id, template)
    signature = der.sign(applicant, signed_bytes)
    wire = der.cert_req_msg_der(
        cert_request,
        der.popo_signature_der(signed_bytes, der.TEST_SIGNATURE_ALGORITHM,
                               signature))
    return Example(
        name='sender',
        wire=wire,
        message=_decode(wire),
        cert_request_der=cert_request,
        signed_bytes=signed_bytes,
        template_fields=SUBJECT_ONLY if with_template_subject else 'neither',
        public_key_der=spki,
        subject_der=der.common_name(template_subject)
        if with_template_subject else None,
        cert_req_id=cert_req_id,
        auth_method='sender',
        claimed_sender_der=der.directory_name(sender_name),
        sender_key_der=spki)


def build_sender_public_key_only(cert_req_id=5, applicant=LEGITIMATE,
                                 sender_name=LEGITIMATE):
    """Template carries the key but no subject; ``sender`` supplies it.

    RFC 4211 requires ``poposkInput`` here because the template lacks one
    of the two values.  The subject the certificate would get is the signed
    sender identity, so it is bound even though it is absent from the
    template.
    """
    spki = _spki(applicant)
    signed_bytes = der.poposk_input_der(
        der.auth_info_sender(sender_name), spki)
    template = der.cert_template(spki_der=spki)
    cert_request = der.cert_request_der(cert_req_id, template)
    signature = der.sign(applicant, signed_bytes)
    wire = der.cert_req_msg_der(
        cert_request,
        der.popo_signature_der(signed_bytes, der.TEST_SIGNATURE_ALGORITHM,
                               signature))
    return Example(
        name='sender_public_key_only',
        wire=wire,
        message=_decode(wire),
        cert_request_der=cert_request,
        signed_bytes=signed_bytes,
        template_fields=PUBKEY_ONLY,
        public_key_der=spki,
        subject_der=der.common_name(sender_name),
        cert_req_id=cert_req_id,
        auth_method='sender',
        claimed_sender_der=der.directory_name(sender_name),
        sender_key_der=spki)


def build_sender_no_template_fields(cert_req_id=6, applicant=LEGITIMATE,
                                    sender_name=LEGITIMATE):
    """Template is empty; both the subject and the key come from the input.

    ``poposkInput`` is mandatory because the template carries neither value.
    Both must then be taken from the signed structure, never from anywhere
    else in the message.
    """
    spki = _spki(applicant)
    signed_bytes = der.poposk_input_der(
        der.auth_info_sender(sender_name), spki)
    template = der.cert_template()
    cert_request = der.cert_request_der(cert_req_id, template)
    signature = der.sign(applicant, signed_bytes)
    wire = der.cert_req_msg_der(
        cert_request,
        der.popo_signature_der(signed_bytes, der.TEST_SIGNATURE_ALGORITHM,
                               signature))
    return Example(
        name='sender_no_template_fields',
        wire=wire,
        message=_decode(wire),
        cert_request_der=cert_request,
        signed_bytes=signed_bytes,
        template_fields='neither',
        public_key_der=spki,
        subject_der=der.common_name(sender_name),
        cert_req_id=cert_req_id,
        auth_method='sender',
        claimed_sender_der=der.directory_name(sender_name),
        sender_key_der=spki)


def build_public_key_mac(cert_req_id=3, applicant=LEGITIMATE,
                         password_owner=LEGITIMATE):
    """Case 1: ``poposkInput`` with ``publicKeyMAC``; MAC covers the key.

    The template deliberately carries no subject: adding one alongside
    ``publicKeyMAC`` would make it an unbound applicant claim, which is the
    situation :func:`attack_public_key_mac_subject` models.
    """
    spki = _spki(applicant)
    mac = der.pbm_mac(
        der.password(password_owner), MAC_SALT, PBKDF_ITERATIONS, spki)
    auth_info = der.auth_info_public_key_mac(
        mac, MAC_SALT, PBKDF_ITERATIONS)
    signed_bytes = der.poposk_input_der(auth_info, spki)
    template = der.cert_template(spki_der=spki)
    cert_request = der.cert_request_der(cert_req_id, template)
    signature = der.sign(applicant, signed_bytes)
    wire = der.cert_req_msg_der(
        cert_request,
        der.popo_signature_der(signed_bytes, der.TEST_SIGNATURE_ALGORITHM,
                               signature))
    return Example(
        name='public_key_mac',
        wire=wire,
        message=_decode(wire),
        cert_request_der=cert_request,
        signed_bytes=signed_bytes,
        template_fields=PUBKEY_ONLY,
        public_key_der=spki,
        subject_der=None,
        cert_req_id=cert_req_id,
        auth_method='publicKeyMAC')


def build_ra_verified(cert_req_id=4, applicant=LEGITIMATE,
                      subject=LEGITIMATE, serial_number=0x1234):
    """``popo`` is ``raVerified``; the RA context must name this request."""
    spki = _spki(applicant)
    template = der.cert_template(
        subject_der=der.common_name(subject), spki_der=spki,
        serial_number=serial_number, version=2)
    cert_request = der.cert_request_der(cert_req_id, template)
    wire = der.cert_req_msg_der(cert_request, der.popo_ra_verified_der())
    return Example(
        name='ra_verified',
        wire=wire,
        message=_decode(wire),
        cert_request_der=cert_request,
        signed_bytes=None,  # nothing is signed in this branch
        template_fields=SUBJECT_AND_KEY,
        public_key_der=spki,
        subject_der=der.common_name(subject),
        cert_req_id=cert_req_id,
        auth_method=None)


def legitimate_cases():
    """The four legitimate requests, keyed by case name."""
    return {
        'no_input': build_no_input(),
        'sender': build_sender(),
        'sender_public_key_only': build_sender_public_key_only(),
        'sender_no_template_fields': build_sender_no_template_fields(),
        'public_key_mac': build_public_key_mac(),
        'ra_verified': build_ra_verified(),
    }


# ---------------------------------------------------------------------------
# Attack copies.  Each changes exactly one field and is still a valid POP
# over the octets it names, so only request binding can reject it.
# ---------------------------------------------------------------------------


def attack_no_input_subject():
    """Same signed ``CertRequest`` signature, different template subject.

    The signature is over the original ``CertRequest``.  Replacing the
    subject invalidates the signature, which is the expected outcome: in
    case 3 the subject *is* covered.  This attack documents that a verifier
    seeing a new subject must not reuse the old signature.
    """
    spki = _spki(LEGITIMATE)
    original_template = der.cert_template(
        subject_der=der.common_name(LEGITIMATE), spki_der=spki,
        serial_number=0x1234, version=2)
    original = der.cert_request_der(1, original_template)
    signature = der.sign(LEGITIMATE, original)

    attacked_template = der.cert_template(
        subject_der=der.common_name(ATTACKER), spki_der=spki,
        serial_number=0x1234, version=2)
    attacked_request = der.cert_request_der(1, attacked_template)
    wire = der.cert_req_msg_der(
        attacked_request,
        der.popo_signature_der(None, der.TEST_SIGNATURE_ALGORITHM, signature))
    message = _decode(wire)
    return Example(
        name='attack_no_input_subject',
        wire=wire,
        message=message,
        cert_request_der=attacked_request,
        signed_bytes=original,
        template_fields=SUBJECT_AND_KEY,
        public_key_der=spki,
        subject_der=der.common_name(ATTACKER),
        cert_req_id=1,
        auth_method=None)


def attack_no_input_public_key():
    """Same as case 3 but the template key is replaced after signing."""
    original_spki = _spki(LEGITIMATE)
    original_template = der.cert_template(
        subject_der=der.common_name(LEGITIMATE), spki_der=original_spki,
        serial_number=0x1234, version=2)
    original = der.cert_request_der(1, original_template)
    signature = der.sign(LEGITIMATE, original)

    attacker_spki = _spki(ATTACKER)
    attacked_template = der.cert_template(
        subject_der=der.common_name(LEGITIMATE), spki_der=attacker_spki,
        serial_number=0x1234, version=2)
    attacked_request = der.cert_request_der(1, attacked_template)
    wire = der.cert_req_msg_der(
        attacked_request,
        der.popo_signature_der(None, der.TEST_SIGNATURE_ALGORITHM, signature))
    message = _decode(wire)
    return Example(
        name='attack_no_input_public_key',
        wire=wire,
        message=message,
        cert_request_der=attacked_request,
        signed_bytes=original,
        template_fields=SUBJECT_AND_KEY,
        public_key_der=attacker_spki,
        subject_der=der.common_name(LEGITIMATE),
        cert_req_id=1,
        auth_method=None)


def attack_sender_template_subject():
    """Valid ``sender = mallory`` POP, but template claims ``alice``.

    The template carries the subject only, so ``poposkInput`` is allowed.
    The signature verifies and the sender really is mallory; the subject
    is simply a different name that the attacker wrote into the template.
    Only the rule that the template subject must equal the signed sender
    identity catches this.
    """
    attacked_key = _spki(ATTACKER)
    signed_bytes = der.poposk_input_der(
        der.auth_info_sender(ATTACKER), attacked_key)
    template = der.cert_template(
        subject_der=der.common_name(LEGITIMATE))
    cert_request = der.cert_request_der(2, template)
    signature = der.sign(ATTACKER, signed_bytes)
    wire = der.cert_req_msg_der(
        cert_request,
        der.popo_signature_der(signed_bytes, der.TEST_SIGNATURE_ALGORITHM,
                               signature))
    return Example(
        name='attack_sender_template_subject',
        wire=wire,
        message=_decode(wire),
        cert_request_der=cert_request,
        signed_bytes=signed_bytes,
        template_fields=SUBJECT_ONLY,
        public_key_der=attacked_key,
        subject_der=der.common_name(LEGITIMATE),
        cert_req_id=2,
        auth_method='sender',
        claimed_sender_der=der.directory_name(ATTACKER),
        sender_key_der=attacked_key)


def attack_sender_key_substitution():
    """Legitimate ``sender = alice`` label, attacker's key and signature.

    ``authInfo`` still says alice and the template repeats that name, so
    every in-band consistency check passes.  The key that signed the input
    is mallory's, however, and nothing inside the message reveals it: only
    out-of-band knowledge of which key alice controls does.  This is the
    case that separates "the sender name is a claim" from "the sender was
    authenticated".
    """
    attacked_key = _spki(ATTACKER)
    signed_bytes = der.poposk_input_der(
        der.auth_info_sender(LEGITIMATE), attacked_key)
    template = der.cert_template(
        subject_der=der.common_name(LEGITIMATE))
    cert_request = der.cert_request_der(2, template)
    signature = der.sign(ATTACKER, signed_bytes)
    wire = der.cert_req_msg_der(
        cert_request,
        der.popo_signature_der(signed_bytes, der.TEST_SIGNATURE_ALGORITHM,
                               signature))
    return Example(
        name='attack_sender_key_substitution',
        wire=wire,
        message=_decode(wire),
        cert_request_der=cert_request,
        signed_bytes=signed_bytes,
        template_fields=SUBJECT_ONLY,
        public_key_der=attacked_key,
        subject_der=der.common_name(LEGITIMATE),
        cert_req_id=2,
        auth_method='sender',
        claimed_sender_der=der.directory_name(LEGITIMATE),
        sender_key_der=attacked_key)


def attack_sender_input_key_mismatch():
    """``poposkInput.publicKey`` is mallory's, template ``publicKey`` alice's.

    Clause 4.1 requires the two copies to be identical.  The attacker signs
    the input over her own key and leaves the template pointing at alice's.
    The template carries the key only, so ``poposkInput`` is the right
    structure and no other rule fires first.
    """
    attacker_key = _spki(ATTACKER)
    signed_bytes = der.poposk_input_der(
        der.auth_info_sender(ATTACKER), attacker_key)
    template = der.cert_template(spki_der=_spki(LEGITIMATE))
    cert_request = der.cert_request_der(2, template)
    signature = der.sign(ATTACKER, signed_bytes)
    wire = der.cert_req_msg_der(
        cert_request,
        der.popo_signature_der(signed_bytes, der.TEST_SIGNATURE_ALGORITHM,
                               signature))
    return Example(
        name='attack_sender_input_key_mismatch',
        wire=wire,
        message=_decode(wire),
        cert_request_der=cert_request,
        signed_bytes=signed_bytes,
        template_fields=PUBKEY_ONLY,
        public_key_der=attacker_key,
        subject_der=None,
        cert_req_id=2,
        auth_method='sender',
        claimed_sender_der=der.directory_name(ATTACKER),
        sender_key_der=attacker_key)


def attack_public_key_mac_subject():
    """Valid ``publicKeyMAC`` over the key, template subject swapped.

    The MAC provably covers only the public key.  Replacing the subject
    leaves the MAC and the signature valid, which is why a template subject
    next to ``publicKeyMAC`` must be treated as an applicant claim.

    RFC 4211 forbids ``poposkInput`` when the template has *both* subject
    and public key, so the template here carries the subject only and the
    key lives in ``poposkInput``.
    """
    spki = _spki(LEGITIMATE)
    mac = der.pbm_mac(
        der.password(LEGITIMATE), MAC_SALT, PBKDF_ITERATIONS, spki)
    auth_info = der.auth_info_public_key_mac(
        mac, MAC_SALT, PBKDF_ITERATIONS)
    signed_bytes = der.poposk_input_der(auth_info, spki)
    template = der.cert_template(
        subject_der=der.common_name(ATTACKER))
    cert_request = der.cert_request_der(3, template)
    signature = der.sign(LEGITIMATE, signed_bytes)
    wire = der.cert_req_msg_der(
        cert_request,
        der.popo_signature_der(signed_bytes, der.TEST_SIGNATURE_ALGORITHM,
                               signature))
    return Example(
        name='attack_public_key_mac_subject',
        wire=wire,
        message=_decode(wire),
        cert_request_der=cert_request,
        signed_bytes=signed_bytes,
        template_fields=SUBJECT_ONLY,
        public_key_der=spki,
        subject_der=der.common_name(ATTACKER),
        cert_req_id=3,
        auth_method='publicKeyMAC')


def attack_public_key_mac_key():
    """MAC computed over alice's key, template and input carry mallory's.

    Both copies agree with each other, so the equality rule passes; the
    MAC value is the one that no longer matches the public key.
    """
    alice_key = _spki(LEGITIMATE)
    attacker_key = _spki(ATTACKER)
    mac_over_alice = der.pbm_mac(
        der.password(LEGITIMATE), MAC_SALT, PBKDF_ITERATIONS, alice_key)
    auth_info = der.auth_info_public_key_mac(
        mac_over_alice, MAC_SALT, PBKDF_ITERATIONS)
    signed_bytes = der.poposk_input_der(auth_info, attacker_key)
    template = der.cert_template(spki_der=attacker_key)
    cert_request = der.cert_request_der(3, template)
    signature = der.sign(ATTACKER, signed_bytes)
    wire = der.cert_req_msg_der(
        cert_request,
        der.popo_signature_der(signed_bytes, der.TEST_SIGNATURE_ALGORITHM,
                               signature))
    return Example(
        name='attack_public_key_mac_key',
        wire=wire,
        message=_decode(wire),
        cert_request_der=cert_request,
        signed_bytes=signed_bytes,
        template_fields=PUBKEY_ONLY,
        public_key_der=attacker_key,
        subject_der=None,
        cert_req_id=3,
        auth_method='publicKeyMAC')


def attack_public_key_mac_wrong_password():
    """MAC over the right key, computed with the wrong shared secret.

    Identical to ``build_public_key_mac`` except for the secret used to
    derive the MAC key.
    """
    spki = _spki(LEGITIMATE)
    mac = der.pbm_mac(
        der.password(ATTACKER), MAC_SALT, PBKDF_ITERATIONS, spki)
    auth_info = der.auth_info_public_key_mac(
        mac, MAC_SALT, PBKDF_ITERATIONS)
    signed_bytes = der.poposk_input_der(auth_info, spki)
    template = der.cert_template(spki_der=spki)
    cert_request = der.cert_request_der(3, template)
    signature = der.sign(LEGITIMATE, signed_bytes)
    wire = der.cert_req_msg_der(
        cert_request,
        der.popo_signature_der(signed_bytes, der.TEST_SIGNATURE_ALGORITHM,
                               signature))
    return Example(
        name='attack_public_key_mac_wrong_password',
        wire=wire,
        message=_decode(wire),
        cert_request_der=cert_request,
        signed_bytes=signed_bytes,
        template_fields=PUBKEY_ONLY,
        public_key_der=spki,
        subject_der=None,
        cert_req_id=3,
        auth_method='publicKeyMAC')


def attack_ra_verified_replay(subject=ATTACKER, serial_number=0x1234,
                             cert_req_id=4):
    """``raVerified`` moved onto a different request.

    ``raVerified`` is a NULL, so it can be copied byte for byte.  With a
    trusted-RA context that approved the original request, the only thing
    standing between this copy and acceptance is a comparison of the
    ``CertRequest`` bytes.
    """
    spki = _spki(LEGITIMATE)
    template = der.cert_template(
        subject_der=der.common_name(subject), spki_der=spki,
        serial_number=serial_number, version=2)
    cert_request = der.cert_request_der(cert_req_id, template)
    wire = der.cert_req_msg_der(cert_request, der.popo_ra_verified_der())
    return Example(
        name='attack_ra_verified_replay',
        wire=wire,
        message=_decode(wire),
        cert_request_der=cert_request,
        signed_bytes=None,
        template_fields=SUBJECT_AND_KEY,
        public_key_der=spki,
        subject_der=der.common_name(subject),
        cert_req_id=4,
        auth_method=None)


def attack_no_input_poposk_input_added():
    """Case 3 gains a ``poposkInput``; RFC 4211 forbids that.

    The extra structure shifts the input the signature must cover, so this
    also fails signature checking.  The dedicated rule fires first.
    """
    spki = _spki(LEGITIMATE)
    signed_bytes = der.poposk_input_der(
        der.auth_info_sender(LEGITIMATE), spki)
    template = der.cert_template(
        subject_der=der.common_name(LEGITIMATE), spki_der=spki,
        serial_number=0x1234, version=2)
    cert_request = der.cert_request_der(1, template)
    signature = der.sign(LEGITIMATE, cert_request)
    wire = der.cert_req_msg_der(
        cert_request,
        der.popo_signature_der(signed_bytes, der.TEST_SIGNATURE_ALGORITHM,
                               signature))
    return Example(
        name='attack_no_input_poposk_input_added',
        wire=wire,
        message=_decode(wire),
        cert_request_der=cert_request,
        signed_bytes=signed_bytes,
        template_fields=SUBJECT_AND_KEY,
        public_key_der=spki,
        subject_der=der.common_name(LEGITIMATE),
        cert_req_id=1,
        auth_method='sender',
        claimed_sender_der=der.directory_name(LEGITIMATE),
        sender_key_der=spki)


def attack_sender_without_poposk_input():
    """``poposkInput`` removed although the template has no public key.

    The attacker downgrades to case 3 even though the template lacks the
    key, so there is no key in the signed ``CertRequest``.
    """
    spki = _spki(ATTACKER)
    template = der.cert_template(subject_der=der.common_name(LEGITIMATE))
    cert_request = der.cert_request_der(2, template)
    signed_bytes = der.poposk_input_der(
        der.auth_info_sender(LEGITIMATE), spki)
    signature = der.sign(ATTACKER, signed_bytes)
    wire = der.cert_req_msg_der(
        cert_request,
        der.popo_signature_der(None, der.TEST_SIGNATURE_ALGORITHM, signature))
    return Example(
        name='attack_sender_without_poposk_input',
        wire=wire,
        message=_decode(wire),
        cert_request_der=cert_request,
        signed_bytes=signed_bytes,
        template_fields=SUBJECT_ONLY,
        public_key_der=spki,
        subject_der=der.common_name(LEGITIMATE),
        cert_req_id=2,
        auth_method=None)


def attack_cases():
    """All attack copies, keyed by case name."""
    return {
        'attack_no_input_subject': attack_no_input_subject(),
        'attack_no_input_public_key': attack_no_input_public_key(),
        'attack_sender_template_subject': attack_sender_template_subject(),
        'attack_sender_key_substitution': attack_sender_key_substitution(),
        'attack_sender_input_key_mismatch': attack_sender_input_key_mismatch(),
        'attack_public_key_mac_subject': attack_public_key_mac_subject(),
        'attack_public_key_mac_key': attack_public_key_mac_key(),
        'attack_public_key_mac_wrong_password':
            attack_public_key_mac_wrong_password(),
        'attack_ra_verified_replay': attack_ra_verified_replay(),
        'attack_no_input_poposk_input_added':
            attack_no_input_poposk_input_added(),
        'attack_sender_without_poposk_input':
            attack_sender_without_poposk_input(),
    }


def template_fields_of(example):
    """Return a dict of the present template fields as normalised DER.

    Used to show that an attack copy differs from a legitimate request in
    exactly one place.
    """
    template = example.message['certReq']['certTemplate']
    from examples.crmf_pop import verifier

    fields = {}
    if verifier.has_component(template, 'version'):
        fields['version'] = int(template['version'])
    if verifier.has_component(template, 'serialNumber'):
        fields['serialNumber'] = int(template['serialNumber'])
    if verifier.has_component(template, 'subject'):
        fields['subject'] = verifier.encode_name(template['subject'])
    if verifier.has_component(template, 'publicKey'):
        fields['publicKey'] = verifier.encode_spki(template['publicKey'])
    return fields


def poposk_input_of(example):
    """Return normalised DER of ``POPOSigningKeyInput`` or ``None``."""
    from examples.crmf_pop import verifier
    signing_key = example.message['popo']['signature']
    if not verifier.has_component(signing_key, 'poposkInput'):
        return None
    return verifier.encode_poposk_input(signing_key['poposkInput'])


def issuer_context():
    """The CA/RA view of alice: her subject and sender names, her key."""
    alice_key = _spki(LEGITIMATE)
    return {
        'authenticated_subjects': frozenset({
            (der.common_name(LEGITIMATE), alice_key)}),
        'authenticated_senders': frozenset({
            (der.directory_name(LEGITIMATE), alice_key)},
        ),
    }
