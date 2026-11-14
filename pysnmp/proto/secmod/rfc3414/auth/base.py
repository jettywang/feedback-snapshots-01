#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# License: https://www.pysnmp.com/pysnmp/license.html
#
from pysnmp.proto import errind, error

# BER tags used while walking the SNMPv3 message substrate (RFC 3412)
BER_TAG_INTEGER = 0x02
BER_TAG_OCTET_STRING = 0x04
BER_TAG_SEQUENCE = 0x30

# Position of msgAuthenticationParameters inside UsmSecurityParameters (RFC 3414)
MSG_AUTHENTICATION_PARAMETERS_INDEX = 4


def _read_tlv_header(substrate, offset, expected_tag):
    """Read a BER TLV header at *offset*, validating tag and length octets.

    Returns a tuple of (value_offset, value_length, end_offset). Definite
    length encoding is mandatory; indefinite length, truncated length octets
    and values extending past the end of *substrate* are rejected so that a
    malformed message can never drive a slice past the buffer.
    """
    if offset >= len(substrate) or substrate[offset] != expected_tag:
        raise error.ProtocolError("Unexpected BER tag while locating auth parameters")

    length_offset = offset + 1
    if length_offset >= len(substrate):
        raise error.ProtocolError("Truncated BER length octets")

    first_length_octet = substrate[length_offset]
    if first_length_octet == 0x80:
        raise error.ProtocolError("Indefinite BER length is not allowed")

    if first_length_octet < 0x80:
        value_length = first_length_octet
        value_offset = length_offset + 1
    else:
        length_byte_count = first_length_octet & 0x7F
        if length_byte_count == 0 or length_byte_count > 4:
            raise error.ProtocolError("Invalid BER long-form length")
        value_offset = length_offset + 1 + length_byte_count
        if value_offset > len(substrate):
            raise error.ProtocolError("Truncated BER long-form length")
        value_length = 0
        for length_byte in substrate[length_offset + 1 : value_offset]:
            value_length = (value_length << 8) | length_byte

    end_offset = value_offset + value_length
    if end_offset > len(substrate):
        raise error.ProtocolError("BER TLV value extends past message end")

    return value_offset, value_length, end_offset


def locate_authentication_parameters(whole_msg):
    """Locate msgAuthenticationParameters value octets in a raw SNMPv3 message.

    The walk follows the fixed BER structure of the message instead of
    searching the substrate for a placeholder or a digest byte pattern, so a
    run of zero bytes (or bytes equal to the digest) appearing in
    msgAuthoritativeEngineID, msgUserName, the PDU or anywhere else can never
    decide where the MAC is read or written.

    Returns a tuple of (offset, length) delimiting the
    msgAuthenticationParameters value octets within *whole_msg*.
    """
    # SNMPv3 message ::= SEQUENCE { version INTEGER, headerData SEQUENCE,
    # msgSecurityParameters OCTET STRING, scopedPduData ... }
    message_offset, _, message_end = _read_tlv_header(
        whole_msg, 0, BER_TAG_SEQUENCE
    )
    if message_end != len(whole_msg):
        raise error.ProtocolError("Trailing octets after SNMP message")

    _, _, version_end = _read_tlv_header(
        whole_msg, message_offset, BER_TAG_INTEGER
    )
    _, _, header_end = _read_tlv_header(whole_msg, version_end, BER_TAG_SEQUENCE)

    security_params_offset, _, security_params_end = _read_tlv_header(
        whole_msg, header_end, BER_TAG_OCTET_STRING
    )
    if security_params_end > message_end:
        raise error.ProtocolError("Security parameters extend past message")

    # UsmSecurityParameters ::= SEQUENCE of six components (RFC 3414)
    sec_params_offset, _, sec_params_end = _read_tlv_header(
        whole_msg, security_params_offset, BER_TAG_SEQUENCE
    )
    if sec_params_end != security_params_end:
        raise error.ProtocolError("Trailing octets in security parameters")

    # Skip the four components preceding msgAuthenticationParameters:
    # engineID (OCTET STRING), engineBoots (INTEGER),
    # engineTime (INTEGER), userName (OCTET STRING)
    component_offset = sec_params_offset
    for component_index in range(MSG_AUTHENTICATION_PARAMETERS_INDEX):
        expected_tag = (
            BER_TAG_OCTET_STRING if component_index in (0, 3) else BER_TAG_INTEGER
        )
        _, _, component_end = _read_tlv_header(
            whole_msg, component_offset, expected_tag
        )
        component_offset = component_end

    auth_value_offset, auth_value_length, auth_end = _read_tlv_header(
        whole_msg, component_offset, BER_TAG_OCTET_STRING
    )

    # msgPrivacyParameters still has to be fully parseable behind the MAC
    _, _, privacy_end = _read_tlv_header(
        whole_msg, auth_end, BER_TAG_OCTET_STRING
    )
    if privacy_end != sec_params_end:
        raise error.ProtocolError("Malformed USM security parameters structure")

    return auth_value_offset, auth_value_length


class AbstractAuthenticationService:
    """Abstract base class for SNMPv3 authentication services."""

    SERVICE_ID = None

    def hash_passphrase(self, authKey):
        """Hash authentication key."""
        raise error.ProtocolError(errind.noAuthentication)

    def localize_key(self, authKey, snmpEngineID):
        """Localize authentication key."""
        raise error.ProtocolError(errind.noAuthentication)

    @property
    def digest_length(self):
        """Return length of the digest produced by this service."""
        raise error.ProtocolError(errind.noAuthentication)

    # 7.2.4.1
    def authenticate_outgoing_message(
        self, authKey, wholeMsg, authParametersLocation=None
    ):
        """Authenticate outgoing message.

        *authParametersLocation* is an optional (offset, length) tuple that
        delimits the digest placeholder in the raw message. When omitted, the
        location is recovered from the message BER structure, which keeps
        legacy callers working without falling back to substring searching.
        """
        raise error.ProtocolError(errind.noAuthentication)

    # 7.2.4.2
    def authenticate_incoming_message(
        self, authKey, authParameters, wholeMsg, authParametersLocation=None
    ):
        """Authenticate incoming message.

        *authParametersLocation* is an optional (offset, length) tuple that
        delimits the received digest in the raw message. When omitted, the
        location is recovered from the message BER structure, which keeps
        legacy callers working without falling back to substring searching.
        """
        raise error.ProtocolError(errind.noAuthentication)
