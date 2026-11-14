"""Build and dissect SNMPv3 messages for the offline Report investigation.

These helpers produce real BER-encoded SNMPv3 messages (Reports and
Responses) using pysnmp's own ASN.1 schema objects, so the manager parses
them through exactly the production code path.
"""

from pyasn1.codec.ber import decoder, encoder
from pyasn1.type import univ

from pysnmp.proto import rfc1905
from pysnmp.proto.api import v2c

OctetString = v2c.OctetString
from pysnmp.proto.mpmod import rfc3412
from pysnmp.proto.secmod.rfc3414.service import UsmSecurityParameters

# Report counter OIDs (SNMP-USER-BASED-SM-MIB / SNMP-MPD-MIB).
OID_NOT_IN_TIME_WINDOW = (1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0)
OID_UNKNOWN_ENGINE_ID = (1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0)
OID_WRONG_DIGEST = (1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0)
OID_UNKNOWN_USER = (1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0)

# msgFlags bits: 0x01 auth, 0x02 priv, 0x04 reportable.
FLAG_NOAUTH = 0x04
FLAG_AUTH = 0x05
FLAG_AUTHPRIV = 0x07


def dissect(wire):
    """Return a dict of the fields relevant to the investigation."""
    msg, _ = decoder.decode(wire, asn1Spec=rfc3412.SNMPv3Message())
    header = msg.getComponentByPosition(1)
    msg_id = int(header.getComponentByPosition(0))
    max_size = int(header.getComponentByPosition(1))
    flags = header.getComponentByPosition(2).asNumbers()[0]
    sec_model = int(header.getComponentByPosition(3))

    sec_params, _ = decoder.decode(
        msg.getComponentByPosition(2), asn1Spec=UsmSecurityParameters()
    )
    engine_id = bytes(sec_params.getComponentByPosition(0))
    boots = int(sec_params.getComponentByPosition(1))
    engine_time = int(sec_params.getComponentByPosition(2))
    user_name = bytes(sec_params.getComponentByPosition(3))

    scoped = msg.getComponentByPosition(3).getComponentByName("plaintext")
    context_engine_id = bytes(scoped.getComponentByPosition(0))
    pdu = scoped.getComponentByPosition(2).getComponent()
    pdu_tag = pdu.tagSet
    request_id = int(v2c.apiPDU.get_request_id(pdu))
    varbinds = v2c.apiPDU.get_varbinds(pdu)
    return {
        "msgID": msg_id,
        "maxSize": max_size,
        "flags": flags,
        "securityModel": sec_model,
        "engineID": engine_id,
        "boots": boots,
        "engineTime": engine_time,
        "userName": user_name,
        "contextEngineID": context_engine_id,
        "pduTag": pdu_tag,
        "requestID": request_id,
        "varbinds": varbinds,
        "raw": msg,
    }


def _security_parameters(engine_id, boots, engine_time, user_name):
    sp = UsmSecurityParameters()
    sp.setComponentByPosition(0, OctetString(engine_id), verifyConstraints=False, matchTags=False, matchConstraints=False)
    sp.setComponentByPosition(1, boots, verifyConstraints=False, matchTags=False, matchConstraints=False)
    sp.setComponentByPosition(2, engine_time, verifyConstraints=False, matchTags=False, matchConstraints=False)
    sp.setComponentByPosition(3, OctetString(user_name), verifyConstraints=False, matchTags=False, matchConstraints=False)
    sp.setComponentByPosition(4, OctetString(b""), verifyConstraints=False, matchTags=False, matchConstraints=False)
    sp.setComponentByPosition(5, OctetString(b""), verifyConstraints=False, matchTags=False, matchConstraints=False)
    return sp


def _wrap(flags, sec_params, scoped_pdu):
    message = rfc3412.SNMPv3Message()
    message.setComponentByPosition(0, 3, verifyConstraints=False, matchTags=False, matchConstraints=False)
    global_data = message.setComponentByPosition(1).getComponentByPosition(1)
    global_data.setComponentByPosition(0, 0, verifyConstraints=False, matchTags=False, matchConstraints=False)  # msgID overwritten by caller
    global_data.setComponentByPosition(1, 65507)
    global_data.setComponentByPosition(2, OctetString(bytes([flags])), verifyConstraints=False, matchTags=False, matchConstraints=False)
    global_data.setComponentByPosition(3, 3)  # USM
    message.setComponentByPosition(2, encoder.encode(sec_params))
    data = rfc3412.ScopedPduData()
    data.setComponentByName("plaintext", scoped_pdu)
    message.setComponentByPosition(3, data)
    return message


def _scoped(context_engine_id, pdu):
    scoped = rfc3412.ScopedPDU()
    scoped.setComponentByPosition(0, OctetString(context_engine_id), verifyConstraints=False, matchTags=False, matchConstraints=False)
    scoped.setComponentByPosition(1, OctetString(b""), verifyConstraints=False, matchTags=False, matchConstraints=False)
    scoped.getComponentByPosition(2).setComponentByName(
        pdu.__class__.__name__.replace("PDU", "").lower(), pdu
    )
    return scoped


def build_report(
    msg_id,
    engine_id,
    boots,
    engine_time,
    error_oid,
    context_engine_id=b"",
    user_name=b"",
    flags=FLAG_NOAUTH,
    auth_handler=None,
    auth_key=None,
):
    """Construct a Report-PDU message, optionally authenticating it."""
    report = rfc1905.ReportPDU()
    v2c.apiPDU.set_defaults(report)
    v2c.apiPDU.set_request_id(report, 0)
    v2c.apiPDU.set_error_status(report, 0)
    v2c.apiPDU.set_error_index(report, 0)
    v2c.apiPDU.set_varbinds(
        report, [(v2c.ObjectIdentifier(error_oid), v2c.Counter32(1))]
    )

    sp = _security_parameters(engine_id, boots, engine_time, user_name)
    scoped = _scoped(context_engine_id or engine_id, report)
    message = _wrap(flags, sp, scoped)
    message.getComponentByPosition(1).setComponentByPosition(0, msg_id, verifyConstraints=False, matchTags=False, matchConstraints=False)

    if auth_handler is not None:
        # Reserve digest space, encode, then compute and splice the MAC.
        sp.setComponentByPosition(4, OctetString(b"\x00" * auth_handler.digest_length), verifyConstraints=False, matchTags=False, matchConstraints=False)
        message.setComponentByPosition(2, encoder.encode(sp))
        whole = encoder.encode(message)
        whole = auth_handler.authenticate_outgoing_message(auth_key, whole)
        return bytes(whole)
    return bytes(encoder.encode(message))


def build_response(
    msg_id,
    request_id,
    engine_id,
    boots,
    engine_time,
    user_name,
    flags,
    auth_handler=None,
    auth_key=None,
    varbinds=None,
):
    """Construct a GetResponse-PDU message, optionally authenticating it."""
    response = rfc1905.ResponsePDU()
    v2c.apiPDU.set_defaults(response)
    v2c.apiPDU.set_request_id(response, request_id)
    v2c.apiPDU.set_error_status(response, 0)
    v2c.apiPDU.set_error_index(response, 0)
    if varbinds is None:
        varbinds = [(v2c.ObjectIdentifier((1, 3, 6, 1, 2, 1, 1, 1, 0)),
                     v2c.OctetString("offline-ok"))]
    v2c.apiPDU.set_varbinds(response, varbinds)

    sp = _security_parameters(engine_id, boots, engine_time, user_name)
    scoped = _scoped(engine_id, response)
    message = _wrap(flags, sp, scoped)
    message.getComponentByPosition(1).setComponentByPosition(0, msg_id, verifyConstraints=False, matchTags=False, matchConstraints=False)

    if auth_handler is not None:
        sp.setComponentByPosition(4, OctetString(b"\x00" * auth_handler.digest_length), verifyConstraints=False, matchTags=False, matchConstraints=False)
        message.setComponentByPosition(2, encoder.encode(sp))
        whole = encoder.encode(message)
        whole = auth_handler.authenticate_outgoing_message(auth_key, whole)
        return bytes(whole)
    return bytes(encoder.encode(message))


def flip_msg_id(wire, new_msg_id):
    """Return a copy of an encoded message with only msgID changed."""
    msg, _ = decoder.decode(wire, asn1Spec=rfc3412.SNMPv3Message())
    msg.getComponentByPosition(1).setComponentByPosition(0, new_msg_id, verifyConstraints=False, matchTags=False, matchConstraints=False)
    return bytes(encoder.encode(msg))


def flip_engine_id(wire, new_engine_id):
    """Return a copy with a different authoritative engine ID (no re-auth)."""
    msg, _ = decoder.decode(wire, asn1Spec=rfc3412.SNMPv3Message())
    sp, _ = decoder.decode(
        msg.getComponentByPosition(2), asn1Spec=UsmSecurityParameters()
    )
    sp.setComponentByPosition(0, OctetString(new_engine_id), verifyConstraints=False, matchTags=False, matchConstraints=False)
    msg.setComponentByPosition(2, encoder.encode(sp))
    return bytes(encoder.encode(msg))
