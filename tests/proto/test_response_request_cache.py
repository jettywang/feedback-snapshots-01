"""
Regression tests for request/response association on the manager side.

A response carrying a ``msgID`` (SNMPv3) or unique request-id (SNMPv1/v2c)
that collides with an in-flight request must only complete that request when
every association matches: message processing model, security model,
security name, security level, context engine id, context name and request
id.  A cryptographically valid but context-mismatching response has to be
silently dropped while leaving the original request pending so the later,
correct response can still complete it.

The tests drive the full stack -- message dispatcher, message processing
models, USM/community security models and the command generator -- through an
in-memory transport that records outgoing requests and lets the test inject
arbitrary response datagrams.
"""

from pyasn1.codec.ber import decoder, encoder
from pyasn1.type import univ

from pysnmp.carrier.asyncio.dgram.udp import UdpTransportAddress
from pysnmp.carrier.base import AbstractTransport, AbstractTransportDispatcher
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdgen
from pysnmp.proto import api, rfc1905
from pysnmp.proto.mpmod import rfc3412 as mp_rfc3412
from pysnmp.proto.secmod.rfc3414.service import UsmSecurityParameters

V2C_PMOD = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]
TRANSPORT_DOMAIN = (1, 3, 6, 1, 6, 1, 1)
TRANSPORT_ADDRESS = ("127.0.0.1", 161)
OID = (1, 3, 6, 1, 2, 1, 1, 1, 0)


class ManualDispatcher(AbstractTransportDispatcher):
    """Transport dispatcher whose clock and input are driven by the test."""

    def __init__(self):
        super().__init__()
        self.set_timer_resolution(0.1)
        self._now = 1.0

    def run_dispatcher(self, timeout=0.0):
        pass

    def close_dispatcher(self):
        super().close_dispatcher()

    def tick(self, ticks=1):
        """Advance the virtual clock by the given number of ticks."""
        for _ in range(ticks):
            self._now += self.get_timer_resolution()
            self.handle_timer_tick(self._now)


class FakeTransport(AbstractTransport):
    """Records outgoing datagrams and remembers how to deliver inputs."""

    ADDRESS_TYPE = UdpTransportAddress

    def __init__(self, dispatcher):
        self._dispatcher = dispatcher
        self.sent = []

    def send_message(self, outgoingMessage, transportAddress):
        self.sent.append(bytes(outgoingMessage))

    def deliver(self, wholeMsg):
        """Inject a datagram as if it had arrived from the network."""
        self._dispatcher._callback_function(
            self, TRANSPORT_ADDRESS, bytes(wholeMsg)
        )


def _new_engine():
    snmp_engine = engine.SnmpEngine()
    dispatcher = ManualDispatcher()
    transport = FakeTransport(dispatcher)
    snmp_engine.register_transport_dispatcher(dispatcher)
    dispatcher.register_transport(TRANSPORT_DOMAIN, transport)
    return snmp_engine, dispatcher, transport


def _response_callback(results):
    def cbFun(
        snmpEngine,
        sendRequestHandle,
        errorIndication,
        errorStatus,
        errorIndex,
        varBinds,
        cbCtx,
    ):
        results.append(
            {
                "handle": sendRequestHandle,
                "errorIndication": errorIndication,
                "errorStatus": errorStatus,
                "varBinds": varBinds,
            }
        )

    return cbFun


def _build_v3_response(snmp_engine, request_wire, expected_request_id, context_name, value):
    """Rebuild a noAuthNoPriv SNMPv3 response from the captured request."""
    request, _ = decoder.decode(request_wire, asn1Spec=mp_rfc3412.SNMPv3Message())
    header = request.getComponentByPosition(1)
    msg_id = header.getComponentByPosition(0)
    max_size = header.getComponentByPosition(1)
    security_model = header.getComponentByPosition(3)

    (local_engine_id,) = snmp_engine.get_mib_builder().import_symbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineID"
    )

    # The agent answers using the authoritative (manager-local) engine id the
    # manager already knows, so no engine discovery is required.
    security_parameters = UsmSecurityParameters()
    security_parameters.setComponentByPosition(0, local_engine_id.syntax.clone())
    security_parameters.setComponentByPosition(1, 0)
    security_parameters.setComponentByPosition(2, 0)
    security_parameters.setComponentByPosition(3, "usr-none-none")
    security_parameters.setComponentByPosition(4, b"")
    security_parameters.setComponentByPosition(5, b"")

    response_pdu = rfc1905.ResponsePDU()
    V2C_PMOD.apiPDU.set_defaults(response_pdu)
    V2C_PMOD.apiPDU.set_request_id(response_pdu, expected_request_id)
    V2C_PMOD.apiPDU.set_error_status(response_pdu, 0)
    V2C_PMOD.apiPDU.set_error_index(response_pdu, 0)
    V2C_PMOD.apiPDU.set_varbinds(
        response_pdu, [(univ.ObjectIdentifier(OID), univ.Integer(value))]
    )

    response_scoped = mp_rfc3412.ScopedPDU()
    response_scoped.setComponentByPosition(0, local_engine_id.syntax.clone())
    response_scoped.setComponentByPosition(1, univ.OctetString(context_name))
    response_scoped.getComponentByPosition(2).setComponentByName(
        "response", response_pdu
    )

    message = mp_rfc3412.SNMPv3Message()
    message.setComponentByPosition(0, 3)
    message.setComponentByPosition(1)
    global_data = message.getComponentByPosition(1)
    global_data.setComponentByPosition(0, msg_id)
    global_data.setComponentByPosition(1, max_size)
    # noAuthNoPriv, not reportable (this is a response)
    global_data.setComponentByPosition(2, b"\x00")
    global_data.setComponentByPosition(3, security_model)
    message.setComponentByPosition(2, encoder.encode(security_parameters))
    scoped_data = mp_rfc3412.ScopedPduData()
    scoped_data.setComponentByName("plaintext", response_scoped)
    message.setComponentByPosition(3, scoped_data)
    return encoder.encode(message)


def _expected_request_id(generator):
    """The request-id the command generator stored with the pending request."""
    pending = next(iter(generator._CommandGenerator__pendingReqs.values()))  # noqa: SLF001
    orig_pdu = pending[9]
    return V2C_PMOD.apiPDU.get_request_id(orig_pdu)


def _v2c_wire_request_id(request_wire):
    """The unique per-message request-id carried on the wire (v1/v2c)."""
    request, _ = decoder.decode(request_wire, asn1Spec=V2C_PMOD.Message())
    request_pdu = request.getComponentByPosition(2).getComponent()
    return V2C_PMOD.apiPDU.get_request_id(request_pdu)


def _build_v2c_response(request_wire, wire_request_id, community, value):
    """Rebuild an SNMPv2c response from the captured request."""
    response_pdu = rfc1905.ResponsePDU()
    V2C_PMOD.apiPDU.set_defaults(response_pdu)
    V2C_PMOD.apiPDU.set_request_id(response_pdu, wire_request_id)
    V2C_PMOD.apiPDU.set_error_status(response_pdu, 0)
    V2C_PMOD.apiPDU.set_error_index(response_pdu, 0)
    V2C_PMOD.apiPDU.set_varbinds(
        response_pdu, [(univ.ObjectIdentifier(OID), univ.Integer(value))]
    )

    message = V2C_PMOD.Message()
    message.setComponentByPosition(0, 1)
    message.setComponentByPosition(1, univ.OctetString(community))
    message.getComponentByPosition(2).setComponentByName("response", response_pdu)
    return encoder.encode(message)


def _v3_engine():
    snmp_engine, dispatcher, transport = _new_engine()
    config.add_v3_user(snmp_engine, "usr-none-none")
    config.add_target_parameters(
        snmp_engine, "creds", "usr-none-none", "noAuthNoPriv"
    )
    config.add_target_address(
        snmp_engine,
        "target",
        TRANSPORT_DOMAIN,
        TRANSPORT_ADDRESS,
        "creds",
        timeout=1.0,
        retryCount=0,
    )
    return snmp_engine, dispatcher, transport


def _v2c_engine():
    snmp_engine, dispatcher, transport = _new_engine()
    config.add_v1_system(snmp_engine, "public", "public", contextName=b"")
    # A second, fully valid community that resolves to a different security
    # name and context, used to build a cryptographically fine but
    # association-mismatching response.
    config.add_v1_system(
        snmp_engine, "privctx", "privctx", contextName=b"other-context"
    )
    config.add_target_parameters(
        snmp_engine, "creds", "public", "noAuthNoPriv", mpModel=1
    )
    config.add_target_address(
        snmp_engine,
        "target",
        TRANSPORT_DOMAIN,
        TRANSPORT_ADDRESS,
        "creds",
        timeout=1.0,
        retryCount=0,
    )
    return snmp_engine, dispatcher, transport


def _send_get(snmp_engine, results):
    generator = cmdgen.GetCommandGenerator()
    generator.send_varbinds(
        snmp_engine,
        "target",
        None,
        "",
        [(OID, None)],
        _response_callback(results),
    )
    return generator


def _v3_caches(snmp_engine):
    mp_cache = snmp_engine.message_processing_subsystems[3]._cache  # noqa: SLF001
    dsp_cache = snmp_engine.message_dispatcher._MsgAndPduDispatcher__cache  # noqa: SLF001
    usm_cache = snmp_engine.security_models[3]._cache  # noqa: SLF001
    return mp_cache, dsp_cache, usm_cache


def test_v3_rejected_response_keeps_request_which_then_completes():
    snmp_engine, dispatcher, transport = _v3_engine()
    results = []
    generator = _send_get(snmp_engine, results)

    assert len(transport.sent) == 1
    mp_cache, dsp_cache, usm_cache = _v3_caches(snmp_engine)
    assert len(mp_cache._Cache__msgIdIndex) == 1  # noqa: SLF001
    assert len(dsp_cache._Cache__cacheRepository) == 1  # noqa: SLF001

    wrong = _build_v3_response(
        snmp_engine,
        transport.sent[0],
        _expected_request_id(generator),
        b"unexpected-context",
        1,
    )
    right = _build_v3_response(
        snmp_engine,
        transport.sent[0],
        _expected_request_id(generator),
        b"",
        42,
    )

    # Wrong context first: valid wire encoding and USM, rejected association.
    transport.deliver(wrong)
    assert results == []  # no business result for the rejected response
    assert len(mp_cache._Cache__msgIdIndex) == 1  # noqa: SLF001
    assert len(dsp_cache._Cache__cacheRepository) == 1  # noqa: SLF001
    assert generator._CommandGenerator__pendingReqs  # noqa: SLF001

    # The correct response still completes the request exactly once.
    transport.deliver(right)
    assert len(results) == 1
    assert results[0]["errorIndication"] is None
    assert int(results[0]["varBinds"][0][1]) == 42

    # Every cache and the job bookkeeping are drained.
    assert not mp_cache._Cache__msgIdIndex  # noqa: SLF001
    assert not dsp_cache._Cache__cacheRepository  # noqa: SLF001
    assert not generator._CommandGenerator__pendingReqs  # noqa: SLF001
    assert not dispatcher.jobs_are_pending()

    # A late duplicate of the correct response must not fire the callback again.
    transport.deliver(right)
    assert len(results) == 1


def test_v3_duplicate_correct_response_completes_only_once():
    snmp_engine, dispatcher, transport = _v3_engine()
    results = []
    generator = _send_get(snmp_engine, results)

    right = _build_v3_response(
        snmp_engine,
        transport.sent[0],
        _expected_request_id(generator),
        b"",
        7,
    )
    transport.deliver(right)
    transport.deliver(right)
    transport.deliver(right)

    assert len(results) == 1
    assert int(results[0]["varBinds"][0][1]) == 7
    mp_cache, dsp_cache, _ = _v3_caches(snmp_engine)
    assert not mp_cache._Cache__msgIdIndex  # noqa: SLF001
    assert not dsp_cache._Cache__cacheRepository  # noqa: SLF001


def test_v3_unanswered_request_times_out_and_drains_all_caches():
    snmp_engine, dispatcher, transport = _v3_engine()
    results = []
    generator = _send_get(snmp_engine, results)

    mp_cache, dsp_cache, usm_cache = _v3_caches(snmp_engine)
    assert len(mp_cache._Cache__msgIdIndex) == 1  # noqa: SLF001
    assert len(dsp_cache._Cache__cacheRepository) == 1  # noqa: SLF001

    # 1 second timeout at 0.1s resolution = 10 ticks; retryCount is 0.
    dispatcher.tick(11)

    assert len(results) == 1
    assert results[0]["errorIndication"] is not None
    assert not mp_cache._Cache__msgIdIndex  # noqa: SLF001
    assert not dsp_cache._Cache__cacheRepository  # noqa: SLF001
    assert not generator._CommandGenerator__pendingReqs  # noqa: SLF001
    assert not dispatcher.jobs_are_pending()
    # The USM state cache only ever holds per-message references, which the
    # rejected/accepted releases; nothing is left over.
    assert usm_cache.is_empty()


def test_v2c_rejected_response_keeps_request_which_then_completes():
    snmp_engine, dispatcher, transport = _v2c_engine()
    results = []
    generator = _send_get(snmp_engine, results)

    assert len(transport.sent) == 1
    mp_cache = snmp_engine.message_processing_subsystems[1]._cache  # noqa: SLF001
    dsp_cache = snmp_engine.message_dispatcher._MsgAndPduDispatcher__cache  # noqa: SLF001
    assert len(mp_cache._Cache__msgIdIndex) == 1  # noqa: SLF001

    # Both communities are valid, but "privctx" resolves to a different
    # security name and context, so the association must be rejected while the
    # original request stays pending.
    wire_id = _v2c_wire_request_id(transport.sent[0])
    wrong = _build_v2c_response(transport.sent[0], wire_id, b"privctx", 1)
    right = _build_v2c_response(transport.sent[0], wire_id, b"public", 42)

    transport.deliver(wrong)
    assert results == []
    assert len(mp_cache._Cache__msgIdIndex) == 1  # noqa: SLF001
    assert len(dsp_cache._Cache__cacheRepository) == 1  # noqa: SLF001
    assert generator._CommandGenerator__pendingReqs  # noqa: SLF001

    transport.deliver(right)
    assert len(results) == 1
    assert results[0]["errorIndication"] is None
    assert int(results[0]["varBinds"][0][1]) == 42
    assert not mp_cache._Cache__msgIdIndex  # noqa: SLF001
    assert not dsp_cache._Cache__cacheRepository  # noqa: SLF001
    assert not dispatcher.jobs_are_pending()
