#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""Reference CRMF proof-of-possession validation for RFC 4211 section 4.1.

This is integration scaffolding, not a production verifier.  Real deployments
replace the signature and MAC callbacks with crypto libraries.  The rules
enforced here are the ones that decide whether a valid ``POPOSigningKey`` is
evidence about *this* request or merely about some key:

* The octets handed to the signature callback are recomputed from the request
  being validated, never copied from the message.
* When ``poposkInput`` is present, its ``publicKey`` must equal the template
  ``publicKey``; RFC 4211 requires both copies to be identical.
* ``poposkInput`` must be omitted exactly when the template carries both
  ``subject`` and ``publicKey``, and must be present otherwise.
* ``authInfo.sender`` is a claim.  It is only trusted when the
  ``(sender, publicKey)`` pair was established out of band.
* ``publicKeyMAC`` covers the public key only.  It never binds a template
  subject, so a subject alongside it is an unverified applicant claim.
* ``raVerified`` is accepted only with an explicit trusted-RA context that
  names this exact ``CertRequest``.
"""

from dataclasses import dataclass
from typing import FrozenSet, Optional, Tuple

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_modules import rfc4211
from pyasn1_modules import rfc3280

from examples.crmf_pop import der as crmf_der

__all__ = [
    'IssuerContext',
    'PopError',
    'TrustedRA',
    'ValidatedPop',
    'VerificationPolicy',
    'decode_cert_req_msg',
    'encode_general_name',
    'encode_name',
    'encode_poposk_input',
    'encode_spki',
    'has_component',
    'verify_cert_request',
]


class PopError(Exception):
    """Raised when a CRMF request fails proof-of-possession validation."""


@dataclass(frozen=True)
class VerificationPolicy:
    """Policy knobs for :func:`verify_cert_request`.

    ``require_popo``
        Reject a request with no ``popo``.  RFC 4211 allows omission when the
        CA/RA performs POP out of band; a service requiring in-band POP keeps
        this enabled.

    ``require_bound_subject``
        Reject a template subject that the POP does not cover.  Safe default.
        Disable only when the subject will be authenticated by another
        mechanism; the result then reports ``subject_bound is False``.

    ``require_authenticated_subject``
        Reject unless the effective subject/public-key pair matches one from
        :class:`IssuerContext`.  An issuance policy, not a POP rule.

    ``require_authenticated_sender``
        Reject unless ``authInfo.sender`` matches a sender/public-key pair
        established out of band.  Without this, sender is only a claim.

    ``allow_ra_verified``
        Allow the ``raVerified`` alternative.  An explicit :class:`TrustedRA`
        is still required.
    """

    require_popo: bool = True
    require_bound_subject: bool = True
    require_authenticated_subject: bool = False
    require_authenticated_sender: bool = True
    allow_ra_verified: bool = False


@dataclass(frozen=True)
class IssuerContext:
    """Identity/key pairs established out of band by the CA or RA.

    Each entry is ``(DER(identity), DER(SubjectPublicKeyInfo))``.  Pairs, not
    bare names, are essential: possession of a key says nothing about the name
    the holder is entitled to use.  A prior certificate or an account lookup
    supplies both halves.  These values never come from the CRMF message; if
    they did, an attacker could assert them.
    """

    authenticated_subjects: FrozenSet[Tuple[bytes, bytes]] = frozenset()
    authenticated_senders: FrozenSet[Tuple[bytes, bytes]] = frozenset()


@dataclass(frozen=True)
class TrustedRA:
    """Evidence that an authenticated RA approved one specific request.

    ``approved_cert_request_der`` is the DER of the ``CertRequest`` the RA
    validated out of band.  ``raVerified`` has no cryptographic binding of its
    own, so without this exact value it could be transplanted between
    requests.
    """

    name: str
    approved_cert_request_der: Optional[bytes]
    trusted: bool = True


@dataclass(frozen=True)
class ValidatedPop:
    """Outcome of a successful POP validation.

    The ``*_der`` fields are normalised DER: no implicit context tags.  They
    are suitable for equality checks and for logging.

    ``subject_bound`` means "the POP covers every subject this request
    asserts", not "a subject was established".  It is ``True`` when the
    request asserts no subject at all; callers that need a subject must also
    check ``subject_der is not None`` (or ``subject_authenticated``).
    """

    kind: str  # 'signature' or 'raVerified'
    signed_bytes: Optional[bytes]
    public_key_der: bytes
    template_public_key_der: Optional[bytes]
    poposk_input_public_key_der: Optional[bytes]
    subject_der: Optional[bytes]
    template_subject_der: Optional[bytes]
    subject_bound: bool
    subject_authenticated: bool
    claimed_sender_der: Optional[bytes]
    sender_authenticated: bool
    auth_method: Optional[str]  # 'sender', 'publicKeyMAC' or None
    ra_verified: bool
    cert_req_id: int


def has_component(asn1_object, name):
    """Return whether an optional component is present in a value object."""
    return not isinstance(
        asn1_object.getComponentByName(name, instantiate=False), univ.NoValue)


def encode_name(name):
    """DER-encode a ``Name`` without any implicit context tag."""
    plain = rfc3280.Name()
    plain['rdnSequence'] = name['rdnSequence']
    return der_encoder(plain)


def encode_general_name(general_name):
    """DER-encode a ``GeneralName`` without its ``sender [0]`` tag.

    GeneralName is a CHOICE.  The chosen alternative keeps its own context
    tag (``directoryName`` is ``[4]``), and only the ``sender [0]`` wrapper
    is removed.
    """
    plain = rfc3280.GeneralName()
    chosen = general_name.getName()
    if chosen == 'directoryName':
        name = rfc3280.Name().subtype(
            implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 4))
        name['rdnSequence'] = general_name[chosen]['rdnSequence']
        plain[chosen] = name
    else:
        plain[chosen] = general_name[chosen]
    return der_encoder(plain)


def encode_spki(spki):
    """DER-encode a ``SubjectPublicKeyInfo`` without any context tag."""
    plain = rfc3280.SubjectPublicKeyInfo()
    plain['algorithm'] = spki['algorithm']
    plain['subjectPublicKey'] = spki['subjectPublicKey']
    return der_encoder(plain)


def encode_poposk_input(poposk_input):
    """DER-encode ``POPOSigningKeyInput`` without its ``[0]`` tag.

    RFC 4211 signs the DER encoding of the structure, not the tagged field.
    pyasn1 keeps the implicit tag on a decoded field, so a fresh untagged
    value is populated from the components.  The nested ``publicKey`` has no
    context tag of its own and can be assigned unchanged.
    """
    plain = rfc4211.POPOSigningKeyInput()
    plain['authInfo'] = poposk_input['authInfo']
    plain['publicKey'] = poposk_input['publicKey']
    return der_encoder(plain)


def decode_cert_req_msg(substrate):
    """Decode one DER ``CertReqMsg`` and reject trailing data."""
    msg, rest = der_decoder(substrate, asn1Spec=rfc4211.CertReqMsg())
    if rest:
        raise PopError('trailing data after CertReqMsg')
    return msg


def _choice_name(choice):
    try:
        return choice.getName()
    except PyAsn1Error:
        return None


def _require_component(asn1_object, name, what):
    if not has_component(asn1_object, name):
        raise PopError('%s is missing %s' % (what, name))
    return asn1_object[name]


def decode_public_key_mac(pkmac):
    """Decode ``PKMACValue`` and enforce the section 4.4 algorithm profile."""
    alg_id = _require_component(pkmac, 'algId', 'publicKeyMAC')
    if str(_require_component(alg_id, 'algorithm', 'publicKeyMAC algId')) != \
            crmf_der.ID_PASSWORD_BASED_MAC:
        raise PopError('publicKeyMAC does not use id-PasswordBasedMac')

    params = _require_component(alg_id, 'parameters', 'publicKeyMAC algId')
    try:
        pbm, rest = der_decoder(params.asOctets(),
                                asn1Spec=rfc4211.PBMParameter())
    except PyAsn1Error as exc:
        raise PopError(
            'publicKeyMAC parameters are not PBMParameter: %s' % exc)

    if rest:
        raise PopError('publicKeyMAC parameters have trailing data')
    if int(pbm['iterationCount']) < 100:
        raise PopError('publicKeyMAC iterationCount is below 100')
    if str(pbm['owf']['algorithm']) != crmf_der.ID_SHA1:
        raise PopError('publicKeyMAC owf is not SHA-1')
    if str(pbm['mac']['algorithm']) != crmf_der.ID_HMAC_SHA1:
        raise PopError('publicKeyMAC mac is not HMAC-SHA1')

    value = _require_component(pkmac, 'value', 'publicKeyMAC').asOctets()
    return pbm, value


def _identity_authenticated(identity_der, public_key_der, identities):
    return identity_der is not None and \
        (identity_der, public_key_der) in identities


def verify_cert_request(msg, verify_signature, policy=None, issuer=None,
                        ra_context=None, verify_public_key_mac=None):
    """Validate the POP on one ``CertReqMsg``.

    :param msg: decoded ``rfc4211.CertReqMsg``.
    :param verify_signature: ``(public_key_der, signed_bytes, signature,
        algorithm_identifier_der) -> bool``.  It must compare the key and the
        bytes; a constant ``True`` would defeat the regression.
    :param policy: :class:`VerificationPolicy`.
    :param issuer: :class:`IssuerContext` with out-of-band identities.
    :param ra_context: :class:`TrustedRA` for the ``raVerified`` branch.
    :param verify_public_key_mac: ``(pbm_parameters, public_key_der,
        mac_value) -> bool`` for the ``publicKeyMAC`` branch.
    :return: :class:`ValidatedPop`, or ``None`` when POP is omitted and
        allowed by policy.
    :raises PopError: when the request cannot be accepted.
    """
    if policy is None:
        policy = VerificationPolicy()
    if issuer is None:
        issuer = IssuerContext()

    cert_req = _require_component(msg, 'certReq', 'CertReqMsg')
    template = _require_component(cert_req, 'certTemplate', 'CertRequest')
    cert_req_id = int(_require_component(cert_req, 'certReqId', 'CertRequest'))

    has_subject = has_component(template, 'subject')
    has_public_key = has_component(template, 'publicKey')
    template_subject_der = \
        encode_name(template['subject']) if has_subject else None
    template_pk_der = \
        encode_spki(template['publicKey']) if has_public_key else None

    if not has_component(msg, 'popo'):
        if policy.require_popo:
            raise PopError('CertReqMsg has no proof of possession')
        return None

    popo = msg['popo']
    popo_choice = _choice_name(popo)

    if popo_choice == 'raVerified':
        return _verify_ra_verified(
            cert_req, template_subject_der, template_pk_der,
            cert_req_id, policy, issuer, ra_context)

    if popo_choice != 'signature':
        raise PopError(
            'unsupported proof of possession choice: %s' % popo_choice)

    signing_key = popo['signature']
    input_present = has_component(signing_key, 'poposkInput')

    if input_present:
        if has_subject and has_public_key:
            raise PopError(
                'poposkInput must be omitted when certTemplate has both '
                'subject and publicKey')

        poposk_input = signing_key['poposkInput']
        input_pk_der = encode_spki(
            _require_component(poposk_input, 'publicKey',
                               'POPOSigningKeyInput'))
        if template_pk_der is not None and template_pk_der != input_pk_der:
            raise PopError(
                'POPOSigningKeyInput publicKey does not match CertTemplate')
        public_key_der = input_pk_der
        signed_bytes = encode_poposk_input(poposk_input)
        auth_info = _require_component(poposk_input, 'authInfo',
                                       'POPOSigningKeyInput')
        auth_method = _choice_name(auth_info)
        claimed_sender_der = None
        sender_authenticated = False
        sender_subject_der = None

        if auth_method == 'sender':
            sender = _require_component(auth_info, 'sender', 'authInfo')
            claimed_sender_der = encode_general_name(sender)
            sender_authenticated = _identity_authenticated(
                claimed_sender_der, public_key_der,
                issuer.authenticated_senders)

            if _choice_name(sender) == 'directoryName':
                sender_subject_der = encode_name(sender['directoryName'])

            if template_subject_der is not None:
                if sender_subject_der is None or \
                        template_subject_der != sender_subject_der:
                    raise PopError(
                        'CertTemplate subject does not match the signed '
                        'sender identity')
                subject_der = template_subject_der
            else:
                subject_der = sender_subject_der
            subject_bound = True

        elif auth_method == 'publicKeyMAC':
            if verify_public_key_mac is None:
                raise PopError(
                    'publicKeyMAC cannot be checked without a MAC callback')
            pkmac = _require_component(auth_info, 'publicKeyMAC', 'authInfo')
            pbm, mac_value = decode_public_key_mac(pkmac)
            if not verify_public_key_mac(pbm, public_key_der, mac_value):
                raise PopError('publicKeyMAC verification failed')

            # The MAC covers the DER public key only.  A template subject
            # alongside it is not covered by anything the MAC proves.
            subject_der = template_subject_der
            subject_bound = template_subject_der is None
            if not subject_bound and policy.require_bound_subject:
                raise PopError(
                    'CertTemplate subject is not bound by publicKeyMAC '
                    'proof of possession')

        else:
            raise PopError(
                'unsupported authInfo choice: %s' % auth_method)

    else:
        if not (has_subject and has_public_key):
            raise PopError(
                'poposkInput must be present when certTemplate lacks subject '
                'or publicKey')
        public_key_der = template_pk_der
        signed_bytes = der_encoder(cert_req)
        auth_method = None
        claimed_sender_der = None
        sender_authenticated = False
        sender_subject_der = None
        subject_der = template_subject_der
        subject_bound = True

    signature = _require_component(signing_key, 'signature',
                                   'POPOSigningKey').asOctets()
    algorithm_der = der_encoder(
        _require_component(signing_key, 'algorithmIdentifier',
                           'POPOSigningKey'))

    if not verify_signature(public_key_der, signed_bytes, signature,
                            algorithm_der):
        raise PopError('POP signature verification failed')

    if auth_method == 'sender' and policy.require_authenticated_sender \
            and not sender_authenticated:
        raise PopError(
            'authInfo.sender is only an applicant claim; it was not '
            'established out of band for this public key')

    subject_authenticated = _identity_authenticated(
        subject_der, public_key_der, issuer.authenticated_subjects)
    if auth_method == 'sender' and sender_authenticated and \
            sender_subject_der is not None and \
            subject_der == sender_subject_der:
        subject_authenticated = True
    if policy.require_authenticated_subject and not subject_authenticated:
        raise PopError('request has no authenticated subject')

    return ValidatedPop(
        kind='signature',
        signed_bytes=signed_bytes,
        public_key_der=public_key_der,
        template_public_key_der=template_pk_der,
        poposk_input_public_key_der=public_key_der if input_present else None,
        subject_der=subject_der,
        template_subject_der=template_subject_der,
        subject_bound=subject_bound,
        subject_authenticated=subject_authenticated,
        claimed_sender_der=claimed_sender_der,
        sender_authenticated=sender_authenticated,
        auth_method=auth_method,
        ra_verified=False,
        cert_req_id=cert_req_id)


def _verify_ra_verified(cert_req, template_subject_der, template_pk_der,
                        cert_req_id, policy, issuer, ra_context):
    if not policy.allow_ra_verified:
        raise PopError('raVerified is not accepted by policy')

    if not isinstance(ra_context, TrustedRA) or not ra_context.trusted:
        raise PopError('raVerified requires an explicit trusted RA context')

    if ra_context.approved_cert_request_der is None:
        raise PopError('trusted RA context does not cover a CertRequest')

    if der_encoder(cert_req) != ra_context.approved_cert_request_der:
        raise PopError('raVerified does not cover this CertRequest')

    if template_pk_der is None:
        raise PopError('raVerified request has no public key in CertTemplate')

    subject_authenticated = _identity_authenticated(
        template_subject_der, template_pk_der, issuer.authenticated_subjects)
    if policy.require_authenticated_subject and not subject_authenticated:
        raise PopError('request has no authenticated subject')

    return ValidatedPop(
        kind='raVerified',
        signed_bytes=None,
        public_key_der=template_pk_der,
        template_public_key_der=template_pk_der,
        poposk_input_public_key_der=None,
        subject_der=template_subject_der,
        template_subject_der=template_subject_der,
        subject_bound=True,
        subject_authenticated=subject_authenticated,
        claimed_sender_der=None,
        sender_authenticated=False,
        auth_method=None,
        ra_verified=True,
        cert_req_id=cert_req_id)
