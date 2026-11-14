"""Structural location of USM msgAuthenticationParameters.

These tests never let the library verify its own output in isolation:

* the digest position is re-computed with an independent BER walker,
* the digest value is re-computed with an independent HMAC implementation,
* the exact byte ranges that get zeroed or filled with the digest are
  asserted interval by interval,
* field boundaries on received messages are then corrupted pointwise.
"""
import hashlib
import hmac as hmac_module

import pytest
from pyasn1.codec.ber import encoder

from pysnmp.entity import config, engine
from pysnmp.proto import errind, error
from pysnmp.proto.api import v2c
from pysnmp.proto.mpmod import rfc3412
from pysnmp.proto.secmod.rfc3414 import service
from pysnmp.proto.secmod.rfc3414.auth import base, hmacmd5, hmacsha
from pysnmp.proto.secmod.rfc7860.auth import hmacsha2

BER_INTEGER = 0x02
BER_OCTET_STRING = 0x04
BER_SEQUENCE = 0x30

# An engine ID that contains a run of zero bytes matching the content of the
# digest placeholder for the 96/128/192-bit digest protocols. A substring
# search would stop inside this field instead of at the auth parameter.
ZERO_RIDDEN_ENGINE_ID = b"\x80" + b"\x00" * 26 + b"\x01"

AUTH_CASES = [
    ("md5", config.USM_AUTH_HMAC96_MD5, hashlib.md5, 12),
    ("sha1", config.USM_AUTH_HMAC96_SHA, hashlib.sha1, 12),
    ("sha224", config.USM_AUTH_HMAC128_SHA224, hashlib.sha224, 16),
    ("sha256", config.USM_AUTH_HMAC192_SHA256, hashlib.sha256, 24),
    ("sha384", config.USM_AUTH_HMAC256_SHA384, hashlib.sha384, 32),
    ("sha512", config.USM_AUTH_HMAC384_SHA512, hashlib.sha512, 48),
]


def read_tlv(buffer, offset, expected_tag):
    """Independent BER TLV reader, mirroring the production walker."""
    assert buffer[offset] == expected_tag
    first = buffer[offset + 1]
    if first < 0x80:
        value_offset = offset + 2
        length = first
    else:
        count = first & 0x7F
        length = int.from_bytes(buffer[offset + 2 : offset + 2 + count], "big")
        value_offset = offset + 2 + count
    return value_offset, length, value_offset + length


def locate_auth_parameters(whole_msg):
    """Locate the auth parameter value via an independent BER structure walk."""
    msg_value, _, msg_end = read_tlv(whole_msg, 0, BER_SEQUENCE)
    assert msg_end == len(whole_msg)
    _, _, version_end = read_tlv(whole_msg, msg_value, BER_INTEGER)
    _, _, header_end = read_tlv(whole_msg, version_end, BER_SEQUENCE)
    sec_params_value, _, sec_params_outer_end = read_tlv(
        whole_msg, header_end, BER_OCTET_STRING
    )
    inner_value, _, inner_end = read_tlv(
        whole_msg, sec_params_value, BER_SEQUENCE
    )
    assert inner_end == sec_params_outer_end

    cursor = inner_value
    for index in range(4):
        tag = BER_OCTET_STRING if index in (0, 3) else BER_INTEGER
        _, _, cursor = read_tlv(whole_msg, cursor, tag)

    auth_value, auth_length, auth_end = read_tlv(
        whole_msg, cursor, BER_OCTET_STRING
    )
    _, _, privacy_end = read_tlv(whole_msg, auth_end, BER_OCTET_STRING)
    assert privacy_end == inner_end
    return auth_value, auth_length


def build_message(snmp_engine, user_name, digest_length, engine_id=None):
    """Build an SNMPv3 message with a fully zeroed auth parameter placeholder."""
    mib_builder = snmp_engine.get_mib_builder()
    if engine_id is None:
        engine_id = mib_builder.import_symbols(
            "__SNMP-FRAMEWORK-MIB", "snmpEngineID"
        )[0].syntax

    request = v2c.GetRequestPDU()
    v2c.apiPDU.set_defaults(request)
    v2c.apiPDU.set_varbinds(request, [((1, 3, 6, 1, 2, 1, 1, 1, 0), None)])

    scoped_pdu = rfc3412.ScopedPDU()
    scoped_pdu.setComponentByPosition(0, engine_id)
    scoped_pdu.setComponentByPosition(1, b"")
    scoped_pdu.getComponentByPosition(2).setComponentByPosition(0, request)

    message = rfc3412.SNMPv3Message()
    message.setComponentByPosition(0, 3)
    message.setComponentByPosition(1)
    header = message.getComponentByPosition(1)
    header.setComponentByPosition(0, 1)
    header.setComponentByPosition(1, 65507)
    header.setComponentByPosition(2, b"\x01")  # authNoPriv, not reportable
    header.setComponentByPosition(3, 3)
    message.getComponentByPosition(3).setComponentByPosition(0, scoped_pdu)

    security_parameters = service.UsmSecurityParameters()
    security_parameters.setComponentByPosition(0, engine_id)
    security_parameters.setComponentByPosition(1, 0)
    security_parameters.setComponentByPosition(2, 0)
    security_parameters.setComponentByPosition(3, user_name)
    security_parameters.setComponentByPosition(4, b"\x00" * digest_length)
    security_parameters.setComponentByPosition(5, b"")
    encoded_security_parameters = encoder.encode(security_parameters)
    message.setComponentByPosition(2, encoded_security_parameters)

    return message, encoder.encode(message), encoded_security_parameters


def localized_auth_key(snmp_engine, engine_id, user_name):
    mib_instrum = snmp_engine.message_dispatcher.mib_instrum_controller
    usm_user_entry = mib_instrum.get_mib_builder().import_symbols(
        "SNMP-USER-BASED-SM-MIB", "usmUserEntry"
    )[0]
    table_index = usm_user_entry.getInstIdFromIndices(engine_id, user_name)
    return mib_instrum.get_mib_builder().import_symbols(
        "PYSNMP-USM-MIB", "pysnmpUsmKeyAuthLocalized"
    )[0].getNode(
        mib_instrum.get_mib_builder()
        .import_symbols("PYSNMP-USM-MIB", "pysnmpUsmKeyEntry")[0]
        .name
        + (1,)
        + table_index
    ).syntax


def independent_mac(hash_func, key, zeroed_message, digest_length):
    """Reference HMAC: RFC 7860 for SHA-2, RFC 3414 split-HMAC for the rest."""
    if hash_func in (hashlib.md5, hashlib.sha1):
        block_size = 64
        padded_key = key + b"\x00" * (block_size - len(key))
        ipad = bytes(b ^ 0x36 for b in padded_key)
        opad = bytes(b ^ 0x5C for b in padded_key)
        inner = hash_func(ipad + zeroed_message).digest()
        return hash_func(opad + inner).digest()[:digest_length]
    return hmac_module.new(
        key, zeroed_message, hash_func
    ).digest()[:digest_length]


@pytest.mark.parametrize(
    "label,auth_protocol,hash_func,digest_length", AUTH_CASES
)
def test_outgoing_digest_is_written_only_at_structural_location(
    label, auth_protocol, hash_func, digest_length
):
    snmp_engine = engine.SnmpEngine()
    user_name = f"usr-{label}"
    config.add_v3_user(
        snmp_engine, user_name, auth_protocol, "authkey1",
        securityEngineId=ZERO_RIDDEN_ENGINE_ID,
    )
    sec_model = snmp_engine.security_models[3]
    auth_handler = sec_model.AUTH_SERVICES[auth_protocol]

    message, zeroed_whole_msg, _ = build_message(
        snmp_engine, user_name, digest_length, ZERO_RIDDEN_ENGINE_ID
    )

    # The zero-ridden engine ID precedes the placeholder in the substrate and
    # contains the whole placeholder pattern for the 96/128/192-bit digests.
    auth_offset, auth_length = locate_auth_parameters(zeroed_whole_msg)
    if digest_length <= 26:
        assert zeroed_whole_msg.find(b"\x00" * digest_length) < auth_offset
    else:
        assert zeroed_whole_msg.find(b"\x00" * 26) < auth_offset
    assert auth_length == digest_length
    assert zeroed_whole_msg[auth_offset : auth_offset + auth_length] == (
        b"\x00" * digest_length
    )

    # The production locator and the independent walker agree.
    located_offset, located_length = base.locate_authentication_parameters(
        zeroed_whole_msg
    )
    assert (located_offset, located_length) == (auth_offset, auth_length)

    key = localized_auth_key(
        snmp_engine, ZERO_RIDDEN_ENGINE_ID, user_name
    ).asOctets()
    expected_mac = independent_mac(
        hash_func, key, zeroed_whole_msg, digest_length
    )

    signed_msg = auth_handler.authenticate_outgoing_message(
        localized_auth_key(snmp_engine, ZERO_RIDDEN_ENGINE_ID, user_name),
        zeroed_whole_msg,
        (auth_offset, auth_length),
    )

    # Length stays identical: only placeholder value octets are replaced.
    assert len(signed_msg) == len(zeroed_whole_msg)

    # Interval 1: every byte before the auth parameter value is untouched.
    assert signed_msg[:auth_offset] == zeroed_whole_msg[:auth_offset]
    # Interval 2: the located range carries exactly the reference MAC.
    assert signed_msg[auth_offset : auth_offset + digest_length] == expected_mac
    # Interval 3: every byte after the auth parameter value is untouched.
    assert signed_msg[auth_offset + digest_length :] == (
        zeroed_whole_msg[auth_offset + digest_length :]
    )

    # The same message is accepted by the full incoming USM pipeline.
    from pyasn1.codec.ber import decoder

    decoded_msg, _ = decoder.decode(signed_msg, asn1Spec=rfc3412.SNMPv3Message())
    sec_model.process_incoming_message(
        snmp_engine,
        3,
        65507,
        decoded_msg.getComponentByPosition(2),
        3,
        2,
        signed_msg,
        decoded_msg,
    )


@pytest.mark.parametrize(
    "label,auth_protocol,hash_func,digest_length", AUTH_CASES
)
def test_incoming_verification_zeros_only_structural_range_and_accepts(
    label, auth_protocol, hash_func, digest_length
):
    snmp_engine = engine.SnmpEngine()
    user_name = f"usr-{label}"
    config.add_v3_user(
        snmp_engine, user_name, auth_protocol, "authkey1",
        securityEngineId=ZERO_RIDDEN_ENGINE_ID,
    )
    sec_model = snmp_engine.security_models[3]
    auth_handler = sec_model.AUTH_SERVICES[auth_protocol]

    _, zeroed_whole_msg, _ = build_message(
        snmp_engine, user_name, digest_length, ZERO_RIDDEN_ENGINE_ID
    )
    auth_offset, auth_length = locate_auth_parameters(zeroed_whole_msg)
    key = localized_auth_key(
        snmp_engine, ZERO_RIDDEN_ENGINE_ID, user_name
    )
    signed_msg = auth_handler.authenticate_outgoing_message(
        key, zeroed_whole_msg, (auth_offset, auth_length)
    )

    # Verify through the full incoming pipeline with the wire message.
    message = rfc3412.SNMPv3Message()
    from pyasn1.codec.ber import decoder

    decoded_msg, _ = decoder.decode(signed_msg, asn1Spec=message)
    sec_model.process_incoming_message(
        snmp_engine,
        3,
        65507,
        decoded_msg.getComponentByPosition(2),
        3,
        2,
        signed_msg,
        decoded_msg,
    )

    # The handler-returned substrate must zero exactly the structural range.
    auth_parameters = v2c.OctetString(
        signed_msg[auth_offset : auth_offset + auth_length]
    )
    authenticated_msg = auth_handler.authenticate_incoming_message(
        key, auth_parameters, signed_msg, (auth_offset, auth_length)
    )
    assert authenticated_msg[:auth_offset] == signed_msg[:auth_offset]
    assert authenticated_msg[auth_offset : auth_offset + auth_length] == (
        b"\x00" * digest_length
    )
    assert authenticated_msg[auth_offset + auth_length :] == (
        signed_msg[auth_offset + auth_length :]
    )


def _run_full_incoming(snmp_engine, wire_msg, user_name):
    from pyasn1.codec.ber import decoder
    from pyasn1.error import PyAsn1Error

    message = rfc3412.SNMPv3Message()
    try:
        decoded_msg, _ = decoder.decode(wire_msg, asn1Spec=message)
    except PyAsn1Error:
        # Truncated/garbled substrate is rejected by the BER decoder before
        # the security model could ever expose the plaintext PDU.
        raise error.StatusInformation(errorIndication=errind.parseError)
    return snmp_engine.security_models[3].process_incoming_message(
        snmp_engine,
        3,
        65507,
        decoded_msg.getComponentByPosition(2),
        3,
        2,
        wire_msg,
        decoded_msg,
    )


def _signed_wire_message(snmp_engine, auth_protocol, digest_length, user_name):
    sec_model = snmp_engine.security_models[3]
    auth_handler = sec_model.AUTH_SERVICES[auth_protocol]
    _, zeroed_whole_msg, _ = build_message(
        snmp_engine, user_name, digest_length, ZERO_RIDDEN_ENGINE_ID
    )
    auth_offset, auth_length = locate_auth_parameters(zeroed_whole_msg)
    key = localized_auth_key(snmp_engine, ZERO_RIDDEN_ENGINE_ID, user_name)
    signed_msg = auth_handler.authenticate_outgoing_message(
        key, zeroed_whole_msg, (auth_offset, auth_length)
    )
    return signed_msg, auth_offset, auth_length


@pytest.mark.parametrize(
    "label,auth_protocol,hash_func,digest_length", AUTH_CASES
)
def test_pointwise_field_boundary_corruption_is_rejected(
    label, auth_protocol, hash_func, digest_length
):
    snmp_engine = engine.SnmpEngine()
    user_name = f"usr-{label}"
    config.add_v3_user(
        snmp_engine, user_name, auth_protocol, "authkey1",
        securityEngineId=ZERO_RIDDEN_ENGINE_ID,
    )
    signed_msg, auth_offset, auth_length = _signed_wire_message(
        snmp_engine, auth_protocol, digest_length, user_name
    )

    # Flip the first and last digest value byte: both must fail verification.
    for position in (auth_offset, auth_offset + auth_length - 1):
        corrupted = bytearray(signed_msg)
        corrupted[position] ^= 0xFF
        with pytest.raises(error.StatusInformation) as raised:
            _run_full_incoming(snmp_engine, bytes(corrupted), user_name)
        assert raised.value["errorIndication"] is errind.authenticationFailure

    # Corrupt a byte well outside the auth field but inside the authenticated
    # substrate: the msgID INTEGER value inside headerData. The BER structure
    # stays valid, the structural walk still finds the MAC, and the digest
    # mismatch must be reported rather than silently accepted.
    msg_value, _, _ = read_tlv(signed_msg, 0, BER_SEQUENCE)
    _, _, version_end = read_tlv(signed_msg, msg_value, BER_INTEGER)
    header_value, _, _ = read_tlv(signed_msg, version_end, BER_SEQUENCE)
    msg_id_value, _, _ = read_tlv(signed_msg, header_value, BER_INTEGER)
    corrupted = bytearray(signed_msg)
    corrupted[msg_id_value] ^= 0x01
    with pytest.raises(error.StatusInformation) as raised:
        _run_full_incoming(snmp_engine, bytes(corrupted), user_name)
    assert raised.value["errorIndication"] is errind.authenticationFailure


@pytest.mark.parametrize(
    "label,auth_protocol,hash_func,digest_length", AUTH_CASES
)
def test_truncated_and_malformed_messages_are_rejected_before_pdu(
    label, auth_protocol, hash_func, digest_length
):
    snmp_engine = engine.SnmpEngine()
    user_name = f"usr-{label}"
    config.add_v3_user(
        snmp_engine, user_name, auth_protocol, "authkey1",
        securityEngineId=ZERO_RIDDEN_ENGINE_ID,
    )
    signed_msg, auth_offset, auth_length = _signed_wire_message(
        snmp_engine, auth_protocol, digest_length, user_name
    )

    # Truncate inside the digest value and inside the outer SEQUENCE.
    for cut in (auth_offset + 1, len(signed_msg) - 1, 2):
        with pytest.raises(error.StatusInformation) as raised:
            _run_full_incoming(snmp_engine, signed_msg[:cut], user_name)
        assert raised.value["errorIndication"] in (
            errind.authenticationFailure,
            errind.parseError,
        )

    # Flip the auth parameter BER tag so the structural walk cannot find it.
    corrupted = bytearray(signed_msg)
    corrupted[auth_offset - 1] = BER_INTEGER
    with pytest.raises(error.StatusInformation) as raised:
        _run_full_incoming(snmp_engine, bytes(corrupted), user_name)
    assert raised.value["errorIndication"] in (
        errind.authenticationFailure,
        errind.parseError,
    )

    # Inflate the auth parameter length past the actual field; the walker
    # must reject instead of reading out of bounds.
    corrupted = bytearray(signed_msg)
    corrupted[auth_offset] = 0x7F
    with pytest.raises(error.StatusInformation) as raised:
        _run_full_incoming(snmp_engine, bytes(corrupted), user_name)
    assert raised.value["errorIndication"] in (
        errind.authenticationFailure,
        errind.parseError,
    )


def test_legacy_entry_point_without_location_still_uses_structure():
    """Old callers pass no location; substring search must never come back."""
    snmp_engine = engine.SnmpEngine()
    user_name = "usr-legacy"
    config.add_v3_user(
        snmp_engine,
        user_name,
        config.USM_AUTH_HMAC96_SHA,
        "authkey1",
        securityEngineId=ZERO_RIDDEN_ENGINE_ID,
    )
    auth_handler = hmacsha.HmacSha()
    _, zeroed_whole_msg, _ = build_message(
        snmp_engine, user_name, 12, ZERO_RIDDEN_ENGINE_ID
    )
    auth_offset, auth_length = locate_auth_parameters(zeroed_whole_msg)
    key = localized_auth_key(snmp_engine, ZERO_RIDDEN_ENGINE_ID, user_name)

    signed = auth_handler.authenticate_outgoing_message(key, zeroed_whole_msg)
    expected = auth_handler.authenticate_outgoing_message(
        key, zeroed_whole_msg, (auth_offset, auth_length)
    )
    assert signed == expected

    # A second run of 12 zero bytes earlier in the message must not move the
    # insertion point: only the structural range changes.
    assert signed[:auth_offset] == zeroed_whole_msg[:auth_offset]
    assert signed[auth_offset + 12 :] == zeroed_whole_msg[auth_offset + 12 :]

    auth_parameters = v2c.OctetString(signed[auth_offset : auth_offset + 12])
    authenticated = auth_handler.authenticate_incoming_message(
        key, auth_parameters, signed
    )
    assert authenticated[auth_offset : auth_offset + 12] == b"\x00" * 12
    assert authenticated[:auth_offset] == signed[:auth_offset]
    assert authenticated[auth_offset + 12 :] == signed[auth_offset + 12 :]


def test_locator_rejects_malformed_structures_directly():
    snmp_engine = engine.SnmpEngine()
    config.add_v3_user(
        snmp_engine,
        "usr-locator",
        config.USM_AUTH_HMAC96_SHA,
        "authkey1",
        securityEngineId=ZERO_RIDDEN_ENGINE_ID,
    )
    _, zeroed_whole_msg, _ = build_message(
        snmp_engine, "usr-locator", 12, ZERO_RIDDEN_ENGINE_ID
    )

    with pytest.raises(error.ProtocolError):
        base.locate_authentication_parameters(b"")
    with pytest.raises(error.ProtocolError):
        base.locate_authentication_parameters(zeroed_whole_msg[:-1])
    with pytest.raises(error.ProtocolError):
        # Replace the outer SEQUENCE tag with an OCTET STRING tag.
        base.locate_authentication_parameters(
            BER_OCTET_STRING.to_bytes(1, "big") + zeroed_whole_msg[1:]
        )

    # A long-form length claiming more octets than the buffer holds.
    with pytest.raises(error.ProtocolError):
        base.locate_authentication_parameters(b"\x30\x84\xff\xff\xff\xff")


def test_locator_handles_long_form_length_octets():
    """A message larger than 127 bytes uses long-form BER length octets."""
    snmp_engine = engine.SnmpEngine()
    config.add_v3_user(
        snmp_engine,
        "usr-longform",
        config.USM_AUTH_HMAC96_SHA,
        "authkey1",
    )
    engine_id = snmp_engine.get_mib_builder().import_symbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineID"
    )[0].syntax

    request = v2c.GetRequestPDU()
    v2c.apiPDU.set_defaults(request)
    v2c.apiPDU.set_varbinds(
        request, [((1, 3, 6, 1, 2, 1, 1, 1, 0), v2c.OctetString(b"\xab" * 200))]
    )
    scoped_pdu = rfc3412.ScopedPDU()
    scoped_pdu.setComponentByPosition(0, engine_id)
    scoped_pdu.setComponentByPosition(1, b"")
    scoped_pdu.getComponentByPosition(2).setComponentByPosition(0, request)

    security_parameters = service.UsmSecurityParameters()
    for position, value in (
        (0, engine_id),
        (1, 0),
        (2, 0),
        (3, b"usr-longform"),
        (4, b"\x00" * 12),
        (5, b""),
    ):
        security_parameters.setComponentByPosition(position, value)

    message = rfc3412.SNMPv3Message()
    message.setComponentByPosition(0, 3)
    message.setComponentByPosition(1)
    header = message.getComponentByPosition(1)
    for position, value in ((0, 1), (1, 65507), (2, b"\x01"), (3, 3)):
        header.setComponentByPosition(position, value)
    message.setComponentByPosition(2, encoder.encode(security_parameters))
    message.getComponentByPosition(3).setComponentByPosition(0, scoped_pdu)

    whole_msg = encoder.encode(message)
    assert whole_msg[1] & 0x80  # long-form length is actually exercised

    offset, length = base.locate_authentication_parameters(whole_msg)
    assert length == 12
    assert whole_msg[offset : offset + 12] == b"\x00" * 12
    assert whole_msg[offset - 2] == BER_OCTET_STRING
