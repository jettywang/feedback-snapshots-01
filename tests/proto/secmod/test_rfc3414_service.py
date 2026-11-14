from pyasn1.codec.ber import encoder
import pytest

from pysnmp.entity import config, engine
from pysnmp.proto import errind, error
from pysnmp.proto.api import v2c
from pysnmp.proto.mpmod import rfc3412
from pysnmp.proto.secmod.rfc3414 import service


def test_authenticated_message_with_empty_authentication_parameters_is_rejected():
    snmp_engine = engine.SnmpEngine()
    config.add_v3_user(
        snmp_engine, "usr-sha-none", config.USM_AUTH_HMAC96_SHA, "authkey1"
    )

    mib_builder = snmp_engine.get_mib_builder()
    (snmp_engine_id,) = mib_builder.import_symbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineID"
    )
    snmp_engine_boots, snmp_engine_time = mib_builder.import_symbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineBoots", "snmpEngineTime"
    )

    request = v2c.GetRequestPDU()
    v2c.apiPDU.set_defaults(request)
    v2c.apiPDU.set_varbinds(request, [((1, 3, 6, 1, 2, 1, 1, 1, 0), None)])

    scoped_pdu = rfc3412.ScopedPDU()
    scoped_pdu.setComponentByPosition(0, snmp_engine_id.syntax)
    scoped_pdu.setComponentByPosition(1, b"")
    scoped_pdu.getComponentByPosition(2).setComponentByPosition(0, request)

    message = rfc3412.SNMPv3Message()
    message.setComponentByPosition(0, 3)
    message.setComponentByPosition(1)
    header = message.getComponentByPosition(1)
    header.setComponentByPosition(0, 1)
    header.setComponentByPosition(1, 65507)
    header.setComponentByPosition(2, b"\x05")
    header.setComponentByPosition(3, 3)
    message.getComponentByPosition(3).setComponentByPosition(0, scoped_pdu)

    security_parameters = service.UsmSecurityParameters()
    security_parameters.setComponentByPosition(0, snmp_engine_id.syntax)
    security_parameters.setComponentByPosition(1, int(snmp_engine_boots.syntax))
    security_parameters.setComponentByPosition(2, int(snmp_engine_time.syntax))
    security_parameters.setComponentByPosition(3, b"usr-sha-none")
    security_parameters.setComponentByPosition(4, b"")
    security_parameters.setComponentByPosition(5, b"")
    encoded_security_parameters = encoder.encode(security_parameters)
    message.setComponentByPosition(2, encoded_security_parameters)

    with pytest.raises(error.StatusInformation) as raised:
        snmp_engine.security_models[3].process_incoming_message(
            snmp_engine,
            3,
            65507,
            encoded_security_parameters,
            3,
            2,
            encoder.encode(message),
            message,
        )

    assert raised.value["errorIndication"] is errind.authenticationFailure


def _build_noauth_discovery_security_params(snmp_engine, peer_engine_id):
    from pyasn1.codec.ber import encoder as _encoder

    from pysnmp.proto.secmod.rfc3414.service import UsmSecurityParameters

    security_parameters = UsmSecurityParameters()
    # Empty user name + noAuth flags is the discovery Report shape.
    security_parameters.setComponentByPosition(0, peer_engine_id)
    security_parameters.setComponentByPosition(1, 1)
    security_parameters.setComponentByPosition(2, 10)
    security_parameters.setComponentByPosition(3, b"")
    security_parameters.setComponentByPosition(4, b"")
    security_parameters.setComponentByPosition(5, b"")
    return _encoder.encode(security_parameters)


def _timeline(svc):
    return getattr(svc, "_SnmpUSMSecurityModel__timeline")


def test_unauthenticated_report_bootstraps_timeline_only_for_in_flight_probe():
    snmp_engine = engine.SnmpEngine()
    config.add_v3_user(
        snmp_engine, "usr-md5-none", config.USM_AUTH_HMAC96_MD5, "authkey1"
    )
    svc = snmp_engine.security_models[3]
    peer_engine_id = v2c.OctetString(hexValue="8000000001bbbbbbbb")
    sec_params = _build_noauth_discovery_security_params(
        snmp_engine, peer_engine_id
    )

    # A minimal noAuth message wrapper; the USM layer only reads the security
    # parameters and the plaintext scoped PDU presence for this path.
    message = rfc3412.SNMPv3Message()
    message.setComponentByPosition(0, 3)
    message.setComponentByPosition(1)
    header = message.getComponentByPosition(1)
    header.setComponentByPosition(0, 1)
    header.setComponentByPosition(1, 65507)
    header.setComponentByPosition(2, b"\x04")  # noAuthNoPriv, reportable
    header.setComponentByPosition(3, 3)
    message.setComponentByPosition(2, sec_params)
    scoped = rfc3412.ScopedPDU()
    scoped.setComponentByPosition(0, peer_engine_id)
    scoped.setComponentByPosition(1, b"")
    report = v2c.ReportPDU()
    v2c.apiPDU.set_defaults(report)
    scoped.getComponentByPosition(2).setComponentByName("report", report)
    message.getComponentByPosition(3).setComponentByPosition(0, scoped)
    whole = encoder.encode(message)

    # Default call (no in-flight flag): the unauthenticated Report must not be
    # allowed to create a timeline entry.
    svc.process_incoming_message(
        snmp_engine, 3, 65507, sec_params, 3, 1, whole, message
    )
    assert peer_engine_id not in _timeline(svc)

    # Explicitly marked as the answer to a real in-flight probe: bootstrap is
    # permitted exactly once.
    svc.process_incoming_message(
        snmp_engine,
        3,
        65507,
        sec_params,
        3,
        1,
        whole,
        message,
        discovery_response_requested=True,
    )
    assert peer_engine_id in _timeline(svc)
