# coding: utf-8
#
# This file is part of pyasn1-modules software.
#
# License: http://snmplabs.com/pyasn1/license.html
#
"""Offline RFC 3820 proxy-chain admission for CA-only services.

The :func:`check_chain` entry point answers one question: may the leaf proxy
certificate be treated as a short-lived stand-in for the end-entity
certificate (EEC) at the root of the chain, given the service's local policy?

The checks are split in two layers:

* Structural admission (automatically decidable): ProxyCertInfo presence and
  criticality, EEC/PC subject derivation, issuer chaining, BasicConstraints,
  forbidden extensions, pCPathLenConstraint, key-usage prerequisites and
  duplicate/unknown critical extensions.
* Authorization semantics (requires an application interpreter): proxyPolicy
  languages.  Only ``id-ppl-inheritAll`` and ``id-ppl-independent`` have
  behaviour defined by RFC 3820.  Every other language is routed through an
  explicit :class:`PolicyInterpreter`.  An interpreter must return a
  :class:`Rights` object that is a subset of the rights it was given; otherwise
  the chain is rejected.  No interpreter means no decision: the result is
  ``INDETERMINATE``, never success.

The returned ``Rights`` set is the intersection of every delegation step, so a
later proxy can never widen a constraint imposed by an earlier one.  In
particular, ``id-ppl-independent`` yields an empty inherited set, and a
subsequent ``id-ppl-inheritAll`` keeps that empty set instead of resurrecting
the EEC's rights.

Signature verification and ordinary RFC 5280 path validation of the EEC are
outside this module: callers pass already-verified certificates.  The optional
``verify_signatures`` callback lets a caller bind each proxy to its issuer
without pulling a crypto dependency into ``pyasn1-modules``.
"""

import datetime

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import char

from pyasn1_modules import rfc5280
from pyasn1_modules import rfc3820

__all__ = [
    'Decision',
    'Reason',
    'Rights',
    'PolicyInterpreter',
    'PolicyError',
    'ChainResult',
    'check_chain',
    'parse_proxy_cert_info',
    'effective_key_usage',
    'effective_extended_key_usage',
    'is_proxy_certificate',
    'append_cn_subject',
]


class Decision(object):
    ACCEPT = 'ACCEPT'
    REJECT = 'REJECT'
    INDETERMINATE = 'INDETERMINATE'


class Reason(object):
    # Structural / automatic decisions
    EMPTY_CHAIN = 'empty_chain'
    EEC_HAS_PROXY_INFO = 'eec_has_proxy_cert_info'
    EEC_EMPTY_SUBJECT = 'eec_empty_subject'
    EEC_BASIC_CONSTRAINTS_CA = 'eec_basic_constraints_ca'
    EEC_KEY_USAGE_NO_DIGITAL_SIGNATURE = 'eec_key_usage_no_digital_signature'
    PROXY_INFO_MISSING = 'proxy_cert_info_missing'
    PROXY_INFO_DUPLICATE = 'proxy_cert_info_duplicate'
    PROXY_INFO_NOT_CRITICAL = 'proxy_cert_info_not_critical'
    PROXY_INFO_MALFORMED = 'proxy_cert_info_malformed'
    PROXY_INFO_NEGATIVE_PATH_LENGTH = 'proxy_cert_info_negative_path_length'
    SUBJECT_NOT_DERIVED = 'subject_not_derived_from_issuer'
    ISSUER_MISMATCH = 'issuer_mismatch'
    BASIC_CONSTRAINTS_CA = 'basic_constraints_ca'
    SUBJECT_ALT_NAME_PRESENT = 'subject_alt_name_present'
    ISSUER_ALT_NAME_PRESENT = 'issuer_alt_name_present'
    KEY_USAGE_NO_DIGITAL_SIGNATURE = 'key_usage_no_digital_signature'
    PATH_LENGTH_EXCEEDED = 'path_length_exceeded'
    DUPLICATE_EXTENSION = 'duplicate_extension'
    UNKNOWN_CRITICAL_EXTENSION = 'unknown_critical_extension'
    UNSUPPORTED_VERSION = 'unsupported_version'
    CERTIFICATE_EXPIRED = 'certificate_expired'
    CERTIFICATE_NOT_YET_VALID = 'certificate_not_yet_valid'
    CERTIFICATE_TIME_INVALID = 'certificate_time_invalid'
    SIGNATURE_NOT_VERIFIED = 'signature_not_verified'
    # Policy / interpreter decisions
    POLICY_UNKNOWN_LANGUAGE = 'policy_unknown_language'
    POLICY_INTERPRETER_ERROR = 'policy_interpreter_error'
    POLICY_INTERPRETER_NOT_MONOTONE = 'policy_interpreter_not_monotone'
    POLICY_FORBIDDEN_FIELD = 'policy_forbidden_field'
    POLICY_UNSUPPORTED_BY_APP = 'policy_unsupported_by_application'
    POLICY_ANY_LANGUAGE_IN_CERT = 'policy_any_language_in_certificate'
    POLICY_INTERPRETER_UNRESTRICTED = 'policy_interpreter_unrestricted'

    ALL = (
        EMPTY_CHAIN, EEC_HAS_PROXY_INFO, EEC_EMPTY_SUBJECT,
        EEC_BASIC_CONSTRAINTS_CA, EEC_KEY_USAGE_NO_DIGITAL_SIGNATURE,
        PROXY_INFO_MISSING, PROXY_INFO_DUPLICATE, PROXY_INFO_NOT_CRITICAL,
        PROXY_INFO_MALFORMED, PROXY_INFO_NEGATIVE_PATH_LENGTH,
        SUBJECT_NOT_DERIVED, ISSUER_MISMATCH, BASIC_CONSTRAINTS_CA,
        SUBJECT_ALT_NAME_PRESENT, ISSUER_ALT_NAME_PRESENT,
        KEY_USAGE_NO_DIGITAL_SIGNATURE, PATH_LENGTH_EXCEEDED,
        DUPLICATE_EXTENSION, UNKNOWN_CRITICAL_EXTENSION, UNSUPPORTED_VERSION,
        CERTIFICATE_EXPIRED, CERTIFICATE_NOT_YET_VALID,
        CERTIFICATE_TIME_INVALID, SIGNATURE_NOT_VERIFIED,
        POLICY_UNKNOWN_LANGUAGE, POLICY_INTERPRETER_ERROR,
        POLICY_INTERPRETER_NOT_MONOTONE, POLICY_INTERPRETER_UNRESTRICTED,
        POLICY_FORBIDDEN_FIELD, POLICY_UNSUPPORTED_BY_APP,
        POLICY_ANY_LANGUAGE_IN_CERT,
    )

    #: These outcomes mean "cannot decide", not "decided deny".  Callers must
    #: fail closed, but can distinguish them for logging and retry.  A policy
    #: language the application explicitly excludes (or an invalid use of
    #: anyLanguage) is a decided rejection, not an indeterminate one.
    INDETERMINATE = frozenset([
        POLICY_UNKNOWN_LANGUAGE,
        POLICY_INTERPRETER_ERROR,
    ])


class PolicyError(Exception):
    """Raised by a PolicyInterpreter when it cannot decide a policy."""


#: Sentinel meaning "the complete set of rights a certificate can confer".
#: It intentionally is not a mutable set; the first concrete interpreter
#: result narrows it to a finite set of operation/resource strings.
UNRESTRICTED = None


class Rights(object):
    """Immutable set of ``(operation, resource)`` authorizations.

    ``Rights(None)`` (or ``Rights()``) means *unrestricted*, which is only
    sound for ``id-ppl-inheritAll``.  Any restricted policy -- including
    ``id-ppl-independent`` -- must return an explicit, finite set, so that the
    admission engine can enforce monotonic narrowing with ``<=``.

    Elements are opaque to this module: applications choose their own string
    vocabulary.  The only required property is that ``intersection`` and the
    subset test are meaningful for that vocabulary.
    """

    __slots__ = ('_items',)

    def __init__(self, items=None):
        if items is None:
            self._items = UNRESTRICTED
        else:
            self._items = frozenset(items)

    @property
    def unrestricted(self):
        return self._items is UNRESTRICTED

    @property
    def items(self):
        return self._items

    def __le__(self, other):
        if not isinstance(other, Rights):
            return NotImplemented
        if other.unrestricted:
            return True
        if self.unrestricted:
            return False
        return self._items <= other._items

    def __eq__(self, other):
        if not isinstance(other, Rights):
            return NotImplemented
        if self.unrestricted or other.unrestricted:
            return self.unrestricted == other.unrestricted
        return self._items == other._items

    def __ge__(self, other):
        if not isinstance(other, Rights):
            return NotImplemented
        return other.__le__(self)

    def __lt__(self, other):
        return self <= other and self != other

    def __hash__(self):
        if self.unrestricted:
            return hash((Rights, None))
        return hash((Rights, self._items))

    def __repr__(self):
        if self.unrestricted:
            return 'Rights(<unrestricted>)'
        return 'Rights(%r)' % (sorted(self._items),)

    def intersection(self, other):
        if not isinstance(other, Rights):
            raise TypeError('Rights.intersection expects Rights')
        if self.unrestricted:
            return other
        if other.unrestricted:
            return self
        return Rights(self._items & other._items)


class PolicyInterpreter(object):
    """Contract for application-supplied proxy policy languages.

    ``language`` is the policyLanguage OID as a dotted string.  ``interpret``
    receives the policy OCTET STRING value (``None`` when the field is
    absent) and the rights delegated by the issuing certificate, and returns
    the rights granted to this certificate.

    Implementations MUST raise :class:`PolicyError` when they cannot decide.
    Returning a permissive set on error is a policy bypass.  The returned set
    must not contain rights outside ``delegated_rights``; the engine rejects
    non-monotone results rather than silently narrowing or widening them.
    """

    language = None

    def interpret(self, policy_octets, delegated_rights):
        raise NotImplementedError

    def __repr__(self):
        return '<%s language=%s>' % (type(self).__name__, self.language)


def _oid_str(oid):
    if isinstance(oid, str):
        return oid
    return '.'.join(str(x) for x in oid)


def _decode_cn_value(atv):
    """Return the text value of a CommonName AttributeTypeAndValue.

    The value may be an undecoded ``AttributeValue`` from the wire or a concrete
    string type from a hand-built certificate; re-encoding normalises both to
    a single TLV before decoding as ``X520CommonName``.
    """
    spec = rfc5280.certificateAttributesMap.get(
        rfc5280.id_at_commonName, rfc5280.X520CommonName()
    )
    try:
        value, rest = der_decoder(der_encoder(atv['value']), asn1Spec=spec)
    except Exception:
        return None
    if rest:
        return None
    try:
        return str(value.getComponent())
    except Exception:
        return None


def _canonical_rdn(rdn):
    """Encode one RDN canonically, independent of how it was constructed.

    ``pyasn1`` keeps ``AttributeValue`` as an undecoded ``Any`` after DER
    parsing, while a hand-built certificate may hold the concrete string
    type.  Re-encoding each attribute value normalises both forms to DER.
    """
    parts = []
    for atv in rdn:
        try:
            value_der = der_encoder(atv['value'])
        except Exception:
            value_der = bytes(atv['value'].asOctets())
        parts.append((_oid_str(atv['type']), value_der))
    return tuple(sorted(parts))


def _name_signature(name):
    """Return ``(rdn_signatures, cn_values)`` for a Name.

    RDN order is significant for subject derivation; the order of attributes
    inside a single RDN is not.  The CN list is returned in RDN order so the
    caller can enforce "exactly one appended CN" and reject extra CNs.
    """
    signatures = []
    cn_values = []
    for rdn in name['rdnSequence']:
        signatures.append(_canonical_rdn(rdn))
        for atv in rdn:
            if atv['type'] == rfc5280.id_at_commonName:
                cn_values.append(_decode_cn_value(atv))
    return tuple(signatures), tuple(cn_values)


def _same_name(left, right):
    return _name_signature(left)[0] == _name_signature(right)[0]


def append_cn_subject(issuer_name, new_cn):
    """Build the only legal proxy subject: issuer subject plus exactly one CN.

    The issuer name is round-tripped through DER first: ``Name.clone()`` does
    not copy the ``rdnSequence`` components in pyasn1, and a DER round trip
    also guarantees the appended name uses the same ``AttributeValue`` form
    (raw ``Any``) as a certificate parsed from the wire.
    """
    encoded, rest = der_decoder(der_encoder(issuer_name),
                                asn1Spec=rfc5280.Name())
    if rest:
        raise ValueError('issuer name has trailing bytes')
    subject = encoded
    rdn = rfc5280.RelativeDistinguishedName()
    atv = rfc5280.AttributeTypeAndValue()
    atv['type'] = rfc5280.id_at_commonName
    atv['value'] = char.UTF8String(new_cn)
    rdn.append(atv)
    subject['rdnSequence'].append(rdn)
    return subject


def _has_empty_subject(name):
    return len(name['rdnSequence']) == 0


def _extension_list(cert):
    """Return extensions, tolerating a v1/v2 certificate without any."""
    if not cert['tbsCertificate']['extensions'].isValue:
        return []
    return list(cert['tbsCertificate']['extensions'])


def _find_extensions(cert, oid):
    return [ext for ext in _extension_list(cert) if ext['extnID'] == oid]


def parse_proxy_cert_info(ext):
    """Decode a ProxyCertInfo extension value.

    Returns ``(info, error_text)``; ``info`` is ``None`` when malformed.
    """
    try:
        info, rest = der_decoder(
            ext['extnValue'], asn1Spec=rfc3820.ProxyCertInfoExtension()
        )
    except Exception as exc:
        return None, str(exc)
    if rest:
        return None, 'trailing bytes after ProxyCertInfo'
    try:
        # Force access so lazily-raised schema errors surface here.
        info['proxyPolicy']['policyLanguage']
        info['pCPathLenConstraint']
    except Exception as exc:
        return None, str(exc)
    return info, None


def is_proxy_certificate(cert):
    return bool(_find_extensions(cert, rfc3820.id_pe_proxyCertInfo))


def effective_key_usage(cert):
    """Return KeyUsage as a set of asserted bit names.

    ``None`` means the extension is absent (no constraint from X.509).
    """
    exts = _find_extensions(cert, rfc5280.id_ce_keyUsage)
    if not exts:
        return None
    if len(exts) != 1:
        raise ValueError('duplicate keyUsage extension')
    usage, rest = der_decoder(exts[0]['extnValue'], asn1Spec=rfc5280.KeyUsage())
    if rest:
        raise ValueError('trailing bytes in keyUsage')
    # pyasn1's KeyUsage is a BIT STRING; bit 0 is the leftmost character of
    # ``asBinary()``.  Map positions back to names without relying on the
    # named-value constructor's tuple semantics.
    binary = usage.asBinary()
    names = set()
    for name, index in rfc5280.KeyUsage.namedValues.items():
        if index < len(binary) and binary[index] == '1':
            names.add(name)
    return names


def effective_extended_key_usage(cert):
    """Return ExtKeyUsage as a set of dotted OIDs, or ``None`` if absent."""
    exts = _find_extensions(cert, rfc5280.id_ce_extKeyUsage)
    if not exts:
        return None
    if len(exts) != 1:
        raise ValueError('duplicate extKeyUsage extension')
    usage, rest = der_decoder(exts[0]['extnValue'],
                              asn1Spec=rfc5280.ExtKeyUsageSyntax())
    if rest:
        raise ValueError('trailing bytes in extKeyUsage')
    return frozenset(_oid_str(purpose) for purpose in usage)


def _intersect_optional(issuer_set, own_set):
    if own_set is None:
        return issuer_set
    if issuer_set is None:
        return own_set
    return issuer_set & own_set


def _intersect_eku(issuer_set, own_set):
    """Intersect EKU sets, honouring the anyExtendedKeyUsage wildcard."""
    if own_set is None:
        return issuer_set
    if issuer_set is None:
        return own_set
    any_eku = _oid_str(rfc5280.anyExtendedKeyUsage)
    if any_eku in issuer_set:
        return own_set
    if any_eku in own_set:
        return issuer_set
    return issuer_set & own_set


def _check_key_usage(cert, required_name, missing_reason):
    try:
        usage = effective_key_usage(cert)
    except ValueError as exc:
        return missing_reason, str(exc)
    if usage is not None and required_name not in usage:
        return missing_reason, 'keyUsage lacks %s' % required_name
    return None, None


class ChainResult(object):
    """Outcome of :func:`check_chain`.

    ``code`` is one of :class:`Decision`.  ``reason`` is a stable string from
    :class:`Reason`, ``detail`` is human-readable, ``warnings`` carries
    non-fatal observations, and ``rights`` is the inherited rights set on
    success.
    """

    def __init__(self, code, reason=None, detail='', warnings=None,
                 rights=None, delegations=None, key_usage=None,
                 extended_key_usage=None):
        self.code = code
        self.reason = reason
        self.detail = detail
        self.warnings = list(warnings or ())
        self.rights = rights
        self.delegations = list(delegations or ())
        self.key_usage = key_usage
        self.extended_key_usage = extended_key_usage

    @property
    def accepted(self):
        return self.code == Decision.ACCEPT

    def __bool__(self):
        return self.accepted

    def __repr__(self):
        return 'ChainResult(code=%r, reason=%r, detail=%r)' % (
            self.code, self.reason, self.detail
        )


def _ok(rights, warnings, delegations, key_usage=None,
        extended_key_usage=None):
    return ChainResult(Decision.ACCEPT, None, '', warnings, rights,
                       delegations, key_usage, extended_key_usage)


def _reject(reason, detail, warnings=None, delegations=None):
    return ChainResult(Decision.REJECT, reason, detail, warnings, None,
                       delegations)


def _indeterminate(reason, detail, warnings=None, delegations=None):
    return ChainResult(Decision.INDETERMINATE, reason, detail, warnings, None,
                       delegations)


def _failure(reason, detail, warnings, delegations):
    # Reason.INDETERMINATE lists the only two outcomes that mean "this service
    # cannot decide".  Everything else is a decided rejection, including an
    # application whitelist that excludes a language.
    if reason in Reason.INDETERMINATE:
        return _indeterminate(reason, detail, warnings, delegations)
    return _reject(reason, detail, warnings, delegations)


#: Critical extensions understood by the structural validator.  KeyUsage,
#: BasicConstraints and the alt-name extensions are validated explicitly;
#: EKU affects authorization but does not block structural admission.
_KNOWN_CRITICAL = frozenset([
    rfc3820.id_pe_proxyCertInfo,
    rfc5280.id_ce_keyUsage,
    rfc5280.id_ce_basicConstraints,
    rfc5280.id_ce_extKeyUsage,
    rfc5280.id_ce_subjectAltName,
    rfc5280.id_ce_issuerAltName,
    rfc5280.id_ce_subjectKeyIdentifier,
    rfc5280.id_ce_authorityKeyIdentifier,
])


def _check_common_extensions(cert, warnings):
    """Reject duplicate extensions and unknown critical extensions.

    Returns ``(reason, detail)`` or ``(None, None)``.  Unknown non-critical
    extensions are ignored with a warning, as RFC 5280 permits.
    """
    seen = set()
    for ext in _extension_list(cert):
        oid = ext['extnID']
        if oid in seen:
            return (Reason.DUPLICATE_EXTENSION,
                    'extension %s appears more than once' % _oid_str(oid))
        seen.add(oid)
        if ext['critical']:
            if oid not in _KNOWN_CRITICAL:
                return (Reason.UNKNOWN_CRITICAL_EXTENSION,
                        'unrecognised critical extension %s' % _oid_str(oid))
        elif oid not in _KNOWN_CRITICAL:
            warnings.append('ignoring unrecognised non-critical extension %s'
                            % _oid_str(oid))
    return None, None


def _check_proxy_identity(issuer_name, cert):
    """Enforce RFC 3820 section 3.4 subject derivation."""
    expected_sig, issuer_cns = _name_signature(issuer_name)
    actual_sig, proxy_cns = _name_signature(cert['tbsCertificate']['subject'])
    if len(actual_sig) != len(expected_sig) + 1:
        return (Reason.SUBJECT_NOT_DERIVED,
                'proxy subject must be issuer subject plus exactly one RDN')
    if actual_sig[:-1] != expected_sig:
        return (Reason.SUBJECT_NOT_DERIVED,
                'proxy subject does not start with the issuer subject')
    appended = actual_sig[-1]
    if len(appended) != 1 or appended[0][0] != _oid_str(rfc5280.id_at_commonName):
        return (Reason.SUBJECT_NOT_DERIVED,
                'appended RDN must contain exactly one CommonName')
    if len(proxy_cns) != len(issuer_cns) + 1 or not proxy_cns[-1]:
        return (Reason.SUBJECT_NOT_DERIVED,
                'proxy subject must add exactly one non-empty CN')
    if any(cn is None for cn in proxy_cns):
        return (Reason.SUBJECT_NOT_DERIVED,
                'proxy subject contains an undecodable CommonName')
    return None, None


def _check_eec(eec, warnings):
    """Validate the EEC side of the boundary.

    The EEC is assumed to have passed ordinary RFC 5280 path validation; here
    we only reject things that would make proxy delegation unsound.
    """
    if is_proxy_certificate(eec):
        return _reject(Reason.EEC_HAS_PROXY_INFO,
                       'chain root already carries ProxyCertInfo')
    if _has_empty_subject(eec['tbsCertificate']['subject']):
        return _reject(Reason.EEC_EMPTY_SUBJECT, 'EEC subject is empty')
    reason, detail = _check_common_extensions(eec, warnings)
    if reason:
        return _reject(reason, detail)

    bcs = _find_extensions(eec, rfc5280.id_ce_basicConstraints)
    if len(bcs) > 1:
        return _reject(Reason.DUPLICATE_EXTENSION,
                       'duplicate basicConstraints on EEC')
    if bcs:
        bc, rest = der_decoder(bcs[0]['extnValue'],
                               asn1Spec=rfc5280.BasicConstraints())
        if rest:
            return _reject(Reason.BASIC_CONSTRAINTS_CA,
                           'trailing bytes in EEC basicConstraints')
        if bool(bc['cA']):
            return _reject(Reason.EEC_BASIC_CONSTRAINTS_CA,
                           'EEC basicConstraints cA is TRUE')

    reason, detail = _check_key_usage(
        eec, 'digitalSignature', Reason.EEC_KEY_USAGE_NO_DIGITAL_SIGNATURE
    )
    if reason:
        return _reject(reason, detail)
    return None


def _check_proxy_structure(cert, issuer_name, is_issuer, warnings):
    """Structural checks for one proxy certificate.

    ``is_issuer`` is true when another proxy certificate follows, which is
    when RFC 3820 requires the digitalSignature KeyUsage bit on this
    certificate.  Returns ``(reason, detail, info)``.
    """
    try:
        version = int(cert['tbsCertificate']['version'])
    except Exception:
        return Reason.UNSUPPORTED_VERSION, 'unreadable certificate version', None
    if version != 2:
        return Reason.UNSUPPORTED_VERSION, 'proxy certificate must be v3', None

    infos = _find_extensions(cert, rfc3820.id_pe_proxyCertInfo)
    if not infos:
        return Reason.PROXY_INFO_MISSING, 'ProxyCertInfo extension absent', None
    if len(infos) > 1:
        return Reason.PROXY_INFO_DUPLICATE, 'ProxyCertInfo appears twice', None
    ext = infos[0]
    if not ext['critical']:
        return (Reason.PROXY_INFO_NOT_CRITICAL,
                'ProxyCertInfo must be marked critical', None)

    info, error = parse_proxy_cert_info(ext)
    if info is None:
        return Reason.PROXY_INFO_MALFORMED, error, None

    path_len = info['pCPathLenConstraint']
    if path_len.isValue:
        try:
            value = int(path_len)
        except Exception:
            return Reason.PROXY_INFO_MALFORMED, 'invalid pCPathLenConstraint', None
        if value < 0:
            return (Reason.PROXY_INFO_NEGATIVE_PATH_LENGTH,
                    'pCPathLenConstraint is negative', None)

    if not _same_name(cert['tbsCertificate']['issuer'], issuer_name):
        return (Reason.ISSUER_MISMATCH,
                'proxy issuer does not match the preceding subject', None)

    reason, detail = _check_proxy_identity(issuer_name, cert)
    if reason:
        return reason, detail, None

    bcs = _find_extensions(cert, rfc5280.id_ce_basicConstraints)
    if len(bcs) > 1:
        return Reason.DUPLICATE_EXTENSION, 'duplicate basicConstraints', None
    if bcs:
        bc, rest = der_decoder(bcs[0]['extnValue'],
                               asn1Spec=rfc5280.BasicConstraints())
        if rest:
            return Reason.BASIC_CONSTRAINTS_CA, 'trailing bytes', None
        if bool(bc['cA']):
            return (Reason.BASIC_CONSTRAINTS_CA,
                    'proxy basicConstraints cA is TRUE', None)

    if _find_extensions(cert, rfc5280.id_ce_subjectAltName):
        return (Reason.SUBJECT_ALT_NAME_PRESENT,
                'subjectAltName is forbidden in a proxy certificate', None)
    if _find_extensions(cert, rfc5280.id_ce_issuerAltName):
        return (Reason.ISSUER_ALT_NAME_PRESENT,
                'issuerAltName is forbidden in a proxy certificate', None)

    reason, detail = _check_common_extensions(cert, warnings)
    if reason:
        return reason, detail, None

    if is_issuer:
        # RFC 3820 section 4.1.4(f): before a proxy certificate may sign
        # another proxy, its KeyUsage, if present, must assert digitalSignature.
        # An absent KeyUsage is no constraint in RFC 5280 terms, so only an
        # explicitly incompatible KeyUsage is rejected here.
        try:
            usage = effective_key_usage(cert)
        except ValueError as exc:
            return Reason.KEY_USAGE_NO_DIGITAL_SIGNATURE, str(exc), None
        if usage is not None and 'digitalSignature' not in usage:
            return (Reason.KEY_USAGE_NO_DIGITAL_SIGNATURE,
                    'issuing proxy keyUsage lacks digitalSignature', None)
    return None, None, info


def _check_time(cert, now):
    try:
        validity = cert['tbsCertificate']['validity']
        not_before = validity['notBefore'].getComponent().asDateTime
        not_after = validity['notAfter'].getComponent().asDateTime
    except Exception:
        return Reason.CERTIFICATE_TIME_INVALID, 'invalid validity encoding'
    if now < not_before:
        return Reason.CERTIFICATE_NOT_YET_VALID, 'proxy is not yet valid'
    if now > not_after:
        return Reason.CERTIFICATE_EXPIRED, 'proxy has expired'
    return None, None


def _normalise_interpreters(policy_interpreters):
    if not policy_interpreters:
        return {}
    if hasattr(policy_interpreters, 'items'):
        items = policy_interpreters.items()
    else:
        items = ((interpreter.language, interpreter)
                 for interpreter in policy_interpreters)
    interpreters = {}
    for language, interpreter in items:
        key = _oid_str(language)
        if key in interpreters:
            raise ValueError('duplicate policy interpreter for %s' % key)
        interpreters[key] = interpreter
    return interpreters


def _check_acceptable(language, acceptable):
    """Return True when the application refuses to evaluate this language.

    ``acceptable=None`` means no whitelist was supplied.  The RFC 3820
    ``id-ppl-anyLanguage`` entry defers language checking, as the specification
    defines it; it does not whitelist any concrete language by itself.
    """
    if acceptable is None:
        return False
    if _oid_str(rfc3820.id_ppl_anyLanguage) in acceptable:
        return False
    return language not in acceptable


def _apply_policy(info, state, interpreters, acceptable):
    """Resolve one certificate's policy language to concrete rights.

    Returns ``(rights, reason, detail)``.  ``rights`` is only meaningful when
    ``reason`` is ``None``.
    """
    policy = info['proxyPolicy']
    language = _oid_str(policy['policyLanguage'])
    has_policy = policy['policy'].isValue
    policy_octets = bytes(policy['policy'].asOctets()) if has_policy else None

    if _check_acceptable(language, acceptable):
        return (None, Reason.POLICY_UNSUPPORTED_BY_APP,
                'policy language %s is not in the acceptable set' % language)

    if language == _oid_str(rfc3820.id_ppl_anyLanguage):
        # anyLanguage is a path-validation input sentinel, never a policy
        # carried inside a certificate.
        return (None, Reason.POLICY_ANY_LANGUAGE_IN_CERT,
                'id-ppl-anyLanguage is not a certificate policy language')

    if language == _oid_str(rfc3820.id_ppl_inheritAll):
        if has_policy:
            return (None, Reason.POLICY_FORBIDDEN_FIELD,
                    'inheritAll must not carry a policy field')
        # If the issuer was independent, state.rights is already the explicit
        # empty set, so this returns an empty set rather than resurrecting
        # rights from above the independent certificate.
        return (state.rights, None, '')

    if language == _oid_str(rfc3820.id_ppl_independent):
        if has_policy:
            return (None, Reason.POLICY_FORBIDDEN_FIELD,
                    'independent must not carry a policy field')
        return (Rights(frozenset()), None, '')

    interpreter = interpreters.get(language)
    if interpreter is None:
        return (None, Reason.POLICY_UNKNOWN_LANGUAGE,
                'no interpreter registered for policy language %s' % language)

    try:
        granted = interpreter.interpret(policy_octets, state.rights)
    except PolicyError as exc:
        return (None, Reason.POLICY_INTERPRETER_ERROR, str(exc))
    except Exception as exc:
        return (None, Reason.POLICY_INTERPRETER_ERROR,
                '%s: %s' % (type(exc).__name__, exc))

    if not isinstance(granted, Rights):
        return (None, Reason.POLICY_INTERPRETER_ERROR,
                'interpreter must return Rights, got %r' % (type(granted),))
    if granted.unrestricted:
        # Only RFC 3820 id-ppl-inheritAll may mean "all rights".  A custom
        # language that returns the unrestricted sentinel is either broken or
        # attempting to impersonate inheritAll; both must fail closed.
        return (None, Reason.POLICY_INTERPRETER_UNRESTRICTED,
                'custom policy interpreter may not return unrestricted rights')
    if not granted <= state.rights:
        # Do not silently intersect: that would hide a broken policy engine
        # and could mask an attempted privilege escalation.
        return (None, Reason.POLICY_INTERPRETER_NOT_MONOTONE,
                'interpreter returned rights outside the delegated set')
    return (granted, None, '')


def check_chain(eec, proxies, *, policy_interpreters=None,
                acceptable_policy_languages=None,
                verify_signatures=None, now=None):
    """Admit a proxy chain rooted at an already-validated EEC.

    Args:
        eec: ``rfc5280.Certificate`` for the end entity.  Its CA signature
            chain and validity period are assumed to have been checked by the
            caller.
        proxies: ordered list of proxy certificates, root-most first.  Each
            certificate's signature must be verified by the caller; when
            ``verify_signatures`` is supplied it is called as
            ``verify_signatures(cert, issuer_cert)`` and may raise to veto.
        policy_interpreters: iterable (or mapping) of
            :class:`PolicyInterpreter`.  A language not covered here yields
            ``INDETERMINATE``; it never silently inherits.
        acceptable_policy_languages: optional iterable of dotted OID strings
            the relying party is willing to evaluate.  A language outside this
            set is a decided rejection (``policy_unsupported_by_application``).
            The RFC 3820 ``id-ppl-anyLanguage`` sentinel may be included to defer
            language checking; unknown languages still require an interpreter.
        verify_signatures: optional callback, see above.
        now: timezone-aware ``datetime`` used for proxy validity checks;
            defaults to ``datetime.datetime.now(datetime.timezone.utc)``.
            A naive value is interpreted as UTC.

    Returns:
        :class:`ChainResult`.
    """
    warnings = []
    delegations = []
    interpreters = _normalise_interpreters(policy_interpreters)

    if not proxies:
        return _reject(Reason.EMPTY_CHAIN, 'at least one proxy is required')

    acceptable = None
    if acceptable_policy_languages is not None:
        acceptable = frozenset(
            _oid_str(language) for language in acceptable_policy_languages
        )

    eec_result = _check_eec(eec, warnings)
    if eec_result is not None:
        return eec_result

    if verify_signatures is not None:
        issuer = eec
        for cert in proxies:
            try:
                verify_signatures(cert, issuer)
            except Exception as exc:
                return _reject(Reason.SIGNATURE_NOT_VERIFIED, str(exc))
            issuer = cert

    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)

    state = _State()
    issuer = eec
    state.key_usage = effective_key_usage(eec)
    state.extended_key_usage = effective_extended_key_usage(eec)

    for index, cert in enumerate(proxies, start=1):
        issuer_name = issuer['tbsCertificate']['subject']
        is_issuer = index < len(proxies)

        try:
            reason, detail, info = _check_proxy_structure(
                cert, issuer_name, is_issuer, warnings
            )
        except Exception as exc:  # malformed ASN.1 must not escape
            return _reject(Reason.PROXY_INFO_MALFORMED, str(exc), warnings)
        if reason:
            return _failure(reason, detail, warnings, delegations)

        reason, detail = _check_time(cert, now)
        if reason:
            return _reject(reason, detail, warnings, delegations)

        inherited, reason, detail = _apply_policy(
            info, state, interpreters, acceptable
        )
        if reason:
            return _failure(reason, detail, warnings, delegations)

        # pCPathLenConstraint limits the number of proxy certificates that
        # may follow *this* certificate.  index is 1-based.
        remaining = len(proxies) - index
        path_len = info['pCPathLenConstraint']
        if path_len.isValue and int(path_len) < remaining:
            return _reject(
                Reason.PATH_LENGTH_EXCEEDED,
                'pCPathLenConstraint=%d but %d proxy certificate(s) follow'
                % (int(path_len), remaining),
                warnings, delegations
            )

        language = _oid_str(info['proxyPolicy']['policyLanguage'])
        own_ku = effective_key_usage(cert)
        own_eku = effective_extended_key_usage(cert)
        if language == _oid_str(rfc3820.id_ppl_independent):
            state.key_usage = own_ku
            state.extended_key_usage = own_eku
        else:
            state.key_usage = _intersect_optional(state.key_usage, own_ku)
            state.extended_key_usage = _intersect_eku(
                state.extended_key_usage, own_eku
            )

        state.rights = inherited
        delegations.append({
            'index': index,
            'policy_language': language,
            'path_length': int(path_len) if path_len.isValue else None,
            'subject_cn': _name_signature(
                cert['tbsCertificate']['subject'])[1][-1],
        })
        issuer = cert

    return _ok(state.rights, warnings, delegations, state.key_usage,
               state.extended_key_usage)


class _State(object):
    __slots__ = ('rights', 'key_usage', 'extended_key_usage')

    def __init__(self):
        self.rights = Rights()
        self.key_usage = None
        self.extended_key_usage = None
