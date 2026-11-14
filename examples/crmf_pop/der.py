#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
"""Independent DER construction for RFC 4211 section 4.1 signed octets.

The fixtures must not derive their expected signature input from the same
pyasn1 encoding path that the code under test uses, or an encoding bug
would cancel itself out.  This module therefore builds the relevant DER by
hand, directly from the ASN.1 in RFC 4211.  Only the handful of types the
proof-of-possession structures need are implemented.

The module also holds the fixed test signature construction.  It is not a
real public-key signature: it is an HMAC over the signed octets keyed by a
per-principal secret.  That keeps the tests fast and deterministic while
still forcing the verifier to compare the exact key and the exact bytes --
a callback that ignores its arguments, or returns constant success, cannot
pass the attack cases.
"""

import hashlib
import hmac

UNIVERSAL = 0
CONTEXT = 2

INTEGER = 2
BIT_STRING = 3
OCTET_STRING = 4
NULL = 5
OBJECT_IDENTIFIER = 6
UTF8_STRING = 12
SEQUENCE = 16
SET = 17
IA5_STRING = 22

# Test-only algorithm identifiers.  They are deliberately not standard
# signature OIDs: the signature primitive here is HMAC, not RSA or ECDSA.
TEST_KEY_ALGORITHM = '1.3.6.1.4.1.99999.1.2'
TEST_SIGNATURE_ALGORITHM = '1.3.6.1.4.1.99999.1.1'

# RFC 4211 section 4.4 identifiers.  SHA-1 and HMAC-SHA1 are the algorithms
# every implementation must support.
ID_SHA1 = '1.3.14.3.2.26'
ID_HMAC_SHA1 = '1.2.840.113549.2.7'
ID_PASSWORD_BASED_MAC = '1.2.840.113533.7.66.13'

# RDN attribute type used by the fixtures.
ID_AT_COMMON_NAME = '2.5.4.3'


def _length(size):
    if size < 0x80:
        return bytes([size])
    encoded = size.to_bytes((size.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(encoded)]) + encoded


def tlv(tag_class, constructed, number, content):
    if not 0 <= number < 31:
        raise ValueError('high tag numbers are not needed by CRMF POP')
    first = (tag_class << 6) | (0x20 if constructed else 0) | number
    return bytes([first]) + _length(len(content)) + content


def sequence(*parts):
    return tlv(UNIVERSAL, True, SEQUENCE, b''.join(parts))


def set_of(*parts):
    return tlv(UNIVERSAL, True, SET, b''.join(parts))


def integer(value):
    if value == 0:
        payload = b'\x00'
    else:
        payload = value.to_bytes((value.bit_length() + 8) // 8, 'big',
                                 signed=True)
    return tlv(UNIVERSAL, False, INTEGER, payload)


def bit_string(octets, unused_bits=0):
    return tlv(UNIVERSAL, False, BIT_STRING, bytes([unused_bits]) + octets)


def octet_string(octets):
    return tlv(UNIVERSAL, False, OCTET_STRING, octets)


def null():
    return tlv(UNIVERSAL, False, NULL, b'')


def utf8_string(text):
    return tlv(UNIVERSAL, False, UTF8_STRING, text.encode('utf-8'))


def ia5_string(text):
    return tlv(UNIVERSAL, False, IA5_STRING, text.encode('ascii'))


def oid(dotted):
    arcs = [int(arc) for arc in dotted.split('.')]
    if len(arcs) < 2:
        raise ValueError('object identifier needs at least two arcs')
    payload = bytearray([arcs[0] * 40 + arcs[1]])
    for arc in arcs[2:]:
        if arc < 0x80:
            payload.append(arc)
            continue
        chunk = [arc & 0x7f]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7f))
            arc >>= 7
        payload.extend(reversed(chunk))
    return tlv(UNIVERSAL, False, OBJECT_IDENTIFIER, bytes(payload))


def context(number, content, constructed=True):
    return tlv(CONTEXT, constructed, number, content)


def algorithm_identifier(algorithm_oid):
    return sequence(oid(algorithm_oid), null())


def subject_public_key_info(public_key, algorithm_oid=TEST_KEY_ALGORITHM):
    return sequence(
        algorithm_identifier(algorithm_oid),
        bit_string(public_key),
    )


def common_name(value):
    """A ``Name`` with exactly one commonName RDN encoded as UTF8String."""
    atv = sequence(oid(ID_AT_COMMON_NAME), utf8_string(value))
    return sequence(set_of(atv))


def directory_name(value):
    """``directoryName [4] Name``.  Name is a CHOICE, so [4] is explicit."""
    return context(4, common_name(value))


def auth_info_sender(value):
    """``sender [0] GeneralName`` for a directoryName sender.

    GeneralName is a CHOICE, so the ``[0]`` wrapper from
    ``POPOSigningKeyInput`` is explicit around the ``[4]`` alternative.
    """
    return context(0, directory_name(value))


def pkmac_value(mac_value, salt, iteration_count,
                owf_oid=ID_SHA1, mac_oid=ID_HMAC_SHA1):
    """``PKMACValue`` with the id-PasswordBasedMac profile of section 4.4."""
    pbm = sequence(
        octet_string(salt),
        algorithm_identifier(owf_oid),
        integer(iteration_count),
        algorithm_identifier(mac_oid),
    )
    return sequence(
        sequence(oid(ID_PASSWORD_BASED_MAC), pbm),
        bit_string(mac_value),
    )


def auth_info_public_key_mac(mac_value, salt, iteration_count,
                             owf_oid=ID_SHA1, mac_oid=ID_HMAC_SHA1):
    return pkmac_value(mac_value, salt, iteration_count, owf_oid, mac_oid)


def poposk_input_der(auth_info, spki):
    """``POPOSigningKeyInput``: the structure signed when poposkInput exists.

    RFC 4211 section 4.1 says the signature is computed over the DER-encoded
    ``POPOSigningKeyInput``.  The ``[0]`` on the field is not part of the
    signed value.
    """
    return sequence(auth_info, spki)


def cert_template(subject_der=None, spki_der=None, serial_number=None,
                  version=None):
    """``CertTemplate`` with the requested fields in DER tag order."""
    fields = []
    if version is not None:
        fields.append(context(0, integer(version), constructed=False))
    if serial_number is not None:
        fields.append(context(1, integer(serial_number), constructed=False))
    if subject_der is not None:
        # subject [5] Name: Name is a CHOICE, so the [5] is explicit.
        fields.append(context(5, subject_der))
    if spki_der is not None:
        # publicKey [6] SubjectPublicKeyInfo: implicit replaces the SEQUENCE.
        fields.append(context(6, split_tlv(spki_der)[1]))
    return sequence(*fields)


def cert_request_der(cert_req_id, template_der):
    """``CertRequest``: the structure signed when poposkInput is absent."""
    return sequence(integer(cert_req_id), template_der)


def split_tlv(blob):
    """Split one DER TLV into ``(tag_byte, content)``."""
    if not blob:
        raise ValueError('empty DER value')
    tag_byte = blob[0]
    if tag_byte & 0x1f == 0x1f:
        raise ValueError('high tag numbers are not needed by CRMF POP')
    first = blob[1]
    if first < 0x80:
        offset, length = 2, first
    else:
        count = first & 0x7f
        offset = 2 + count
        length = int.from_bytes(blob[2:offset], 'big')
    content = blob[offset:offset + length]
    if len(content) != length or offset + length != len(blob):
        raise ValueError('malformed DER value')
    return tag_byte, content


def popo_signature_der(poposk_input_der_value, algorithm_oid, signature):
    """``signature [1] POPOSigningKey``.

    ``[1]`` is an implicit tag on a SEQUENCE, so it replaces the SEQUENCE tag
    and the content is the SEQUENCE content: optional ``poposkInput [0]``,
    ``algorithmIdentifier``, ``signature``.  No inner SEQUENCE is emitted.
    """
    body = []
    if poposk_input_der_value is not None:
        body.append(context(0, split_tlv(poposk_input_der_value)[1]))
    body.append(algorithm_identifier(algorithm_oid))
    body.append(bit_string(signature))
    return context(1, b''.join(body))


def popo_ra_verified_der():
    return context(0, b'', constructed=False)


def cert_req_msg_der(cert_request, popo=None):
    parts = [cert_request]
    if popo is not None:
        parts.append(popo)
    return sequence(*parts)


def cert_req_messages_der(*messages):
    return sequence(*messages)


def public_key(label):
    """Deterministic public-key octets for a named test principal."""
    return hashlib.sha256(b'crmf-pop-public:' + label.encode()).digest()


def private_key(label):
    """Deterministic test signing secret for a named test principal."""
    return hashlib.sha256(b'crmf-pop-secret:' + label.encode()).digest()


def password(label):
    """Deterministic test password for the publicKeyMAC branch."""
    return b'crmf-pop-password:' + label.encode()


def sign(label, signed_bytes):
    """Fixed test signature: HMAC-SHA256 keyed by the principal's secret."""
    return hmac.new(private_key(label), signed_bytes, hashlib.sha256).digest()


def pbm_derive_key(shared_secret, salt, iteration_count):
    """RFC 4211 section 4.4 key derivation, using the mandatory SHA-1."""
    derived = hashlib.sha1(shared_secret + salt).digest()
    for _ in range(iteration_count):
        derived = hashlib.sha1(derived).digest()
    return derived


def pbm_mac(shared_secret, salt, iteration_count, data):
    """HMAC-SHA1, keyed per section 4.4, over the DER-encoded public key."""
    key = pbm_derive_key(shared_secret, salt, iteration_count)
    return hmac.new(key, data, hashlib.sha1).digest()
