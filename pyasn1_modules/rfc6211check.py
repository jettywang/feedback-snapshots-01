#
# This file is part of pyasn1-modules software.
#
# License: http://snmplabs.com/pyasn1/license.html
#
"""Pre-verification checks for the RFC 6211 CMSAlgorithmProtection attribute.

Before a CMS signature (``SignerInfo``) or MAC (``AuthenticatedData``) is
verified cryptographically, the CMSAlgorithmProtection attribute (RFC 6211)
-- when present in the *authenticated* attributes -- must be checked for
consistency with the algorithm identifiers carried by the outer structure.
This module implements that pre-check for both entry points:

* :func:`check_signer_info` -- for ``SignerInfo`` (e.g. inside SignedData)
* :func:`check_authenticated_data` -- for ``AuthenticatedData``

What is checked
---------------
* the attribute appears at most once in signedAttrs/authAttrs;
* the attribute value SET contains exactly one CMSAlgorithmProtection value;
* ``signatureAlgorithm`` and ``macAlgorithm`` never appear together, and
  each appears only in its proper context (``signatureAlgorithm`` in a
  SignerInfo, ``macAlgorithm`` in an AuthenticatedData);
* the declared ``digestAlgorithm`` matches the outer ``digestAlgorithm``;
* the declared ``signatureAlgorithm``/``macAlgorithm`` matches the outer
  algorithm identifier.

Algorithm identifier comparison
-------------------------------
Comparison covers parameter semantics, not just the algorithm OID:

* RSASSA-PSS (RFC 4055): the hash algorithm, the mask generation function
  (including the MGF's own digest algorithm) and the salt length are
  compared after applying the RFC 4055 defaults (SHA-1, MGF1-with-SHA-1,
  salt length 20, trailer field 1).  Absent parameters, an empty SEQUENCE
  and fully explicit default parameters are therefore equivalent;
* common digest algorithms (MD2/MD5, SHA-1, SHA-2 and SHA-3 families):
  NULL and absent parameters are treated as equivalent;
* any other parameter form -- including parameters this module does not
  understand -- only matches when the DER encodings are byte-identical.
  An unknown parameter form is never considered equal to a different
  (e.g. defaulted or reordered) encoding.

Unauthenticated attributes
--------------------------
Only signedAttrs (SignerInfo) and authAttrs (AuthenticatedData) are
consulted.  A CMSAlgorithmProtection attribute found in unsignedAttrs or
unauthAttrs is unauthenticated: it is ignored by these checks and MUST NOT
be used to grant any downgrade permission.

Responsibility boundary
-----------------------
These functions are a *pre-check* only.  A passing result means the
protection attribute is well-formed and consistent with the outer
algorithm identifiers; it says nothing about the validity of the
signature or MAC itself.  The caller MUST still:

* cryptographically verify the signature/MAC (that verification also
  covers signedAttrs/authAttrs, and therefore this attribute),
* validate certificates, trust anchors and key ownership,
* enforce algorithm policy (which algorithms are acceptable at all).

Conversely, when :class:`CMSAlgorithmProtectionError` is raised, the
message MUST be rejected without attempting cryptographic verification.
"""

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import constraint
from pyasn1.type import univ

from pyasn1_modules import rfc4055
from pyasn1_modules import rfc5280
from pyasn1_modules import rfc6211


class CMSAlgorithmProtectionError(ValueError):
    """The CMSAlgorithmProtection attribute failed pre-verification."""


class _CMSAlgorithmProtectionNoXOR(rfc6211.CMSAlgorithmProtection):
    # RFC 6211 defines signatureAlgorithm and macAlgorithm as mutually
    # exclusive.  Decoding attribute values without that constraint lets
    # the checks below report a precise error instead of a generic
    # constraint failure.
    subtypeSpec = constraint.ConstraintsIntersection()


_NULL_DER = der_encoder(univ.Null(''))

# Digest algorithm OIDs for which NULL and absent parameters are treated
# as equivalent (MD2/MD5 per RFC 2313, SHA-1 per RFC 3370, SHA-2 per
# RFC 5754, SHA-3 per RFC 8692).
_DIGEST_ALGORITHM_OIDS = frozenset([
    (1, 2, 840, 113549, 2, 2),          # md2
    (1, 2, 840, 113549, 2, 5),          # md5
    (1, 3, 14, 3, 2, 26),               # sha1
    (2, 16, 840, 1, 101, 3, 4, 2, 1),   # sha256
    (2, 16, 840, 1, 101, 3, 4, 2, 2),   # sha384
    (2, 16, 840, 1, 101, 3, 4, 2, 3),   # sha512
    (2, 16, 840, 1, 101, 3, 4, 2, 4),   # sha224
    (2, 16, 840, 1, 101, 3, 4, 2, 5),   # sha512-224
    (2, 16, 840, 1, 101, 3, 4, 2, 6),   # sha512-256
    (2, 16, 840, 1, 101, 3, 4, 2, 7),   # sha3-224
    (2, 16, 840, 1, 101, 3, 4, 2, 8),   # sha3-256
    (2, 16, 840, 1, 101, 3, 4, 2, 9),   # sha3-384
    (2, 16, 840, 1, 101, 3, 4, 2, 10),  # sha3-512
])

_ID_RSASSA_PSS = tuple(rfc4055.id_RSASSA_PSS)
_ID_MGF1 = tuple(rfc4055.id_mgf1)

_SIGNATURE_CONTEXT = 'signature'
_MAC_CONTEXT = 'mac'


def _parameters_der(alg_id):
    params = alg_id['parameters']
    if not params.isValue:
        return None
    return der_encoder(params)


def _canonical_pss_params_key(params_der):
    if params_der is None:
        # RFC 4055: absent parameters mean all defaults
        params_der = der_encoder(rfc4055.RSASSA_PSS_params())

    try:
        params, rest = der_decoder(
            params_der, asn1Spec=rfc4055.RSASSA_PSS_params(),
            decodeOpenTypes=True)
    except PyAsn1Error:
        return ('der', params_der)

    if rest:
        return ('der', params_der)

    hash_alg = params['hashAlgorithm']
    if hash_alg.isValue:
        hash_key = _canonical_algorithm_key(hash_alg)
    else:
        hash_key = _canonical_algorithm_key(rfc4055.sha1Identifier)

    mgf = params['maskGenAlgorithm']
    if mgf.isValue:
        mgf_key = _canonical_algorithm_key(mgf)
    else:
        mgf_key = _canonical_algorithm_key(rfc4055.mgf1SHA1Identifier)

    # saltLength and trailerField are DEFAULT components; the decoder
    # supplies the RFC 4055 defaults (20 and 1) when they are absent
    salt_length = int(params['saltLength'])
    trailer_field = int(params['trailerField'])

    return ('pss', hash_key, mgf_key, salt_length, trailer_field)


def _canonical_mgf1_params_key(params_der):
    if params_der is None:
        return ('der', None)

    try:
        alg_id, rest = der_decoder(
            params_der, asn1Spec=rfc5280.AlgorithmIdentifier(),
            decodeOpenTypes=True)
    except PyAsn1Error:
        return ('der', params_der)

    if rest:
        return ('der', params_der)

    return _canonical_algorithm_key(alg_id)


def _canonical_algorithm_key(alg_id):
    oid = tuple(alg_id['algorithm'])
    params_der = _parameters_der(alg_id)

    if oid == _ID_RSASSA_PSS:
        return oid, _canonical_pss_params_key(params_der)

    if oid == _ID_MGF1:
        return oid, _canonical_mgf1_params_key(params_der)

    if oid in _DIGEST_ALGORITHM_OIDS and params_der in (None, _NULL_DER):
        return oid, None

    # Unknown algorithm or unrecognized parameter form: only byte-identical
    # DER encodings are considered equal
    return oid, ('der', params_der)


def algorithm_identifiers_match(first, second):
    """Tell whether two AlgorithmIdentifier values are semantically equal.

    The comparison covers parameter semantics as described in the module
    docstring: RSASSA-PSS defaults are applied, NULL and absent digest
    parameters are equivalent, and unrecognized parameter forms only
    match on byte-identical DER.
    """
    return _canonical_algorithm_key(first) == _canonical_algorithm_key(second)


def _decode_protection_value(value):
    if isinstance(value, rfc6211.CMSAlgorithmProtection):
        return value

    try:
        substrate = bytes(value)
    except (TypeError, ValueError) as exc:
        raise CMSAlgorithmProtectionError(
            'CMSAlgorithmProtection attribute value has an unexpected '
            'type: %r' % type(value)) from exc

    # Parameters are kept as raw Any values: unrecognized parameter forms
    # must reach the comparison (where they only match byte-identical DER)
    # instead of breaking the decode here
    try:
        protection, rest = der_decoder(
            substrate, asn1Spec=_CMSAlgorithmProtectionNoXOR())
    except PyAsn1Error as exc:
        raise CMSAlgorithmProtectionError(
            'CMSAlgorithmProtection attribute value cannot be decoded: '
            '%s' % exc) from exc

    if rest:
        raise CMSAlgorithmProtectionError(
            'CMSAlgorithmProtection attribute value has trailing data')

    return protection


def _extract_protection_attribute(attributes):
    found = [attr for attr in attributes
             if attr['attrType'] == rfc6211.id_aa_cmsAlgorithmProtect]

    if not found:
        return None

    if len(found) > 1:
        raise CMSAlgorithmProtectionError(
            'CMSAlgorithmProtection attribute appears more than once')

    attribute = found[0]

    if len(attribute['attrValues']) != 1:
        raise CMSAlgorithmProtectionError(
            'CMSAlgorithmProtection attribute must carry exactly one '
            'value, found %d' % len(attribute['attrValues']))

    return _decode_protection_value(attribute['attrValues'][0])


def _check_consistency(protection, digest_algorithm, outer_algorithm,
                       context):
    has_signature = protection['signatureAlgorithm'].isValue
    has_mac = protection['macAlgorithm'].isValue

    if has_signature and has_mac:
        raise CMSAlgorithmProtectionError(
            'CMSAlgorithmProtection carries both signatureAlgorithm and '
            'macAlgorithm')

    if context == _SIGNATURE_CONTEXT:
        if has_mac:
            raise CMSAlgorithmProtectionError(
                'CMSAlgorithmProtection macAlgorithm is not allowed in a '
                'SignerInfo')
        if not has_signature:
            raise CMSAlgorithmProtectionError(
                'CMSAlgorithmProtection in a SignerInfo must carry '
                'signatureAlgorithm')
        claimed_name = 'signatureAlgorithm'
    else:
        if has_signature:
            raise CMSAlgorithmProtectionError(
                'CMSAlgorithmProtection signatureAlgorithm is not allowed '
                'in an AuthenticatedData')
        if not has_mac:
            raise CMSAlgorithmProtectionError(
                'CMSAlgorithmProtection in an AuthenticatedData must '
                'carry macAlgorithm')
        claimed_name = 'macAlgorithm'

    if digest_algorithm is None:
        raise CMSAlgorithmProtectionError(
            'CMSAlgorithmProtection declares a digestAlgorithm but the '
            'outer structure carries none')

    if not algorithm_identifiers_match(
            protection['digestAlgorithm'], digest_algorithm):
        raise CMSAlgorithmProtectionError(
            'CMSAlgorithmProtection digestAlgorithm does not match the '
            'outer digestAlgorithm')

    if not algorithm_identifiers_match(
            protection[claimed_name], outer_algorithm):
        raise CMSAlgorithmProtectionError(
            'CMSAlgorithmProtection %s does not match the outer %s' % (
                claimed_name, claimed_name))


def check_signer_info(signer_info):
    """Pre-check the CMSAlgorithmProtection attribute of a SignerInfo.

    Only the authenticated signedAttrs are consulted; an attribute placed
    in unsignedAttrs is ignored and grants nothing.

    Returns the validated CMSAlgorithmProtection value, or None when the
    attribute is not present in signedAttrs.  Raises
    :class:`CMSAlgorithmProtectionError` when the attribute is malformed
    or inconsistent with the outer algorithm identifiers.
    """
    signed_attrs = signer_info['signedAttrs']
    if not signed_attrs.isValue:
        return None

    protection = _extract_protection_attribute(signed_attrs)
    if protection is None:
        return None

    _check_consistency(
        protection, signer_info['digestAlgorithm'],
        signer_info['signatureAlgorithm'], _SIGNATURE_CONTEXT)

    return protection


def check_authenticated_data(authenticated_data):
    """Pre-check the CMSAlgorithmProtection attribute of AuthenticatedData.

    Only the authenticated authAttrs are consulted; an attribute placed
    in unauthAttrs is ignored and grants nothing.

    Returns the validated CMSAlgorithmProtection value, or None when the
    attribute is not present in authAttrs.  Raises
    :class:`CMSAlgorithmProtectionError` when the attribute is malformed
    or inconsistent with the outer algorithm identifiers.
    """
    auth_attrs = authenticated_data['authAttrs']
    if not auth_attrs.isValue:
        return None

    protection = _extract_protection_attribute(auth_attrs)
    if protection is None:
        return None

    digest_algorithm = authenticated_data['digestAlgorithm']

    _check_consistency(
        protection,
        digest_algorithm if digest_algorithm.isValue else None,
        authenticated_data['macAlgorithm'], _MAC_CONTEXT)

    return protection
