"""Tests for SNMP response wire-size budgeting over in-memory transport.

The SNMP engine must cap the *actual* wire length of a response message
-- security encapsulation (BER length fields, USM parameters, digest
sizes, engineID/contextName, DES/AES padding) included -- by both the
local snmpEngineMaxMessageSize and the peer-declared msgMaxSize. When a
response does not fit, a tooBig error response that does fit must be
sent instead; when even that does not fit, the message must be silently
dropped and counted (snmpSilentDrops), without ever lowering the
security level to squeeze a message into the budget.

All sizes are measured byte-by-byte on the final serialized messages
captured through an in-memory transport, never estimated.
"""

import pytest
from pyasn1.codec.ber import decoder

from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.proto.api import v1, v2c
from pysnmp.proto.mpmod import cache as mpmod_cache
from pysnmp.proto.mpmod import rfc3412 as mpmod_rfc3412

DOMAIN = ("in-memory",)
ADDRESS = ("agent",)

TEST_OID = (1, 3, 6, 1, 4, 1, 99999, 1, 1)
TEST_OID_0 = TEST_OID + (0,)

NO_AUTH_NO_PRIV = 1
AUTH_NO_PRIV = 2
AUTH_PRIV = 3

HUGE_BUDGET = 262144

PROFILES = {
    "none-none": dict(
        authProtocol=config.USM_AUTH_NONE,
        authKey=None,
        privProtocol=config.USM_PRIV_NONE,
        privKey=None,
        securityLevel=NO_AUTH_NO_PRIV,
        vacmLevel="noAuthNoPriv",
        msgFlags=0x00,
    ),
    "sha-none": dict(
        authProtocol=config.USM_AUTH_HMAC96_SHA,
        authKey="authkey1",
        privProtocol=config.USM_PRIV_NONE,
        privKey=None,
        securityLevel=AUTH_NO_PRIV,
        vacmLevel="authNoPriv",
        msgFlags=0x01,
    ),
    "sha256-none": dict(
        authProtocol=config.USM_AUTH_HMAC192_SHA256,
        authKey="authkey1",
        privProtocol=config.USM_PRIV_NONE,
        privKey=None,
        securityLevel=AUTH_NO_PRIV,
        vacmLevel="authNoPriv",
        msgFlags=0x01,
    ),
    "sha512-none": dict(
        authProtocol=config.USM_AUTH_HMAC384_SHA512,
        authKey="authkey1",
        privProtocol=config.USM_PRIV_NONE,
        privKey=None,
        securityLevel=AUTH_NO_PRIV,
        vacmLevel="authNoPriv",
        msgFlags=0x01,
    ),
    "sha-des": dict(
        authProtocol=config.USM_AUTH_HMAC96_SHA,
        authKey="authkey1",
        privProtocol=config.USM_PRIV_CBC56_DES,
        privKey="privkey1",
        securityLevel=AUTH_PRIV,
        vacmLevel="authPriv",
        msgFlags=0x03,
    ),
    "sha-aes": dict(
        authProtocol=config.USM_AUTH_HMAC96_SHA,
        authKey="authkey1",
        privProtocol=config.USM_PRIV_CFB128_AES,
        privKey="privkey1",
        securityLevel=AUTH_PRIV,
        vacmLevel="authPriv",
        msgFlags=0x03,
    ),
}


class _SequentialIds:
    """Deterministic replacement for nextid.Integer."""

    def __init__(self, start=0x10000):
        self._value = start

    def __call__(self):
        value = self._value
        self._value += 1
        return value


@pytest.fixture(autouse=True)
def _stable_message_ids(monkeypatch):
    # Keep msgID and request-id at a fixed BER length so that wire sizes
    # measured across different messages stay directly comparable.
    monkeypatch.setattr(v1, "getNextRequestID", _SequentialIds())
    monkeypatch.setattr(mpmod_cache.Cache, "_Cache__message_id", _SequentialIds())


class InMemoryTransportDispatcher:
    """In-memory transport dispatcher recording every sent message."""

    def __init__(self):
        self.sent = []

    def send_message(self, outgoingMessage, transportDomain, transportAddress):
        self.sent.append(bytes(outgoingMessage))

    def get_timer_ticks(self):
        return 0

    def get_timer_resolution(self):
        return 1


def _set_max_message_size(snmp_engine, size):
    (max_size,) = snmp_engine.get_mib_builder().import_symbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineMaxMessageSize"
    )
    # Assign the raw value to also allow sizes outside the 484..2**31-1
    # range that the MIB object would otherwise enforce on clone()
    max_size.syntax = v2c.Integer(size)


def _get_silent_drops(snmp_engine):
    (snmpSilentDrops,) = snmp_engine.get_mib_builder().import_symbols(
        "__SNMPv2-MIB", "snmpSilentDrops"
    )
    return int(snmpSilentDrops.syntax)


class Agent:
    """In-memory SNMP agent under test."""

    def __init__(self, profile, max_message_size=HUGE_BUDGET, engine_id=None):
        if engine_id is None:
            self.engine = engine.SnmpEngine()
        else:
            self.engine = engine.SnmpEngine(
                snmpEngineID=v2c.OctetString(engine_id)
            )
        self.engine.transport_dispatcher = InMemoryTransportDispatcher()
        _set_max_message_size(self.engine, max_message_size)
        config.add_v3_user(
            self.engine,
            "usr",
            profile["authProtocol"],
            profile["authKey"],
            profile["privProtocol"],
            profile["privKey"],
        )
        config.add_vacm_user(self.engine, 3, "usr", profile["vacmLevel"], (1, 3, 6))

        self.context = context.SnmpContext(self.engine)
        mib_builder = self.context.get_mib_instrum().get_mib_builder()
        (MibScalar, MibScalarInstance) = mib_builder.import_symbols(
            "SNMPv2-SMI", "MibScalar", "MibScalarInstance"
        )

        holder = self.holder = {"value": b""}

        class SizedMibScalarInstance(MibScalarInstance):
            def getValue(self, name, **context):
                return self.getSyntax().clone(holder["value"])

        mib_builder.export_symbols(
            "__TEST-MIB",
            MibScalar(TEST_OID, v2c.OctetString()),
            SizedMibScalarInstance(TEST_OID, (0,), v2c.OctetString("")),
        )
        self.responder = cmdrsp.GetCommandResponder(self.engine, self.context)

    @property
    def engine_id(self):
        return self.engine.snmpEngineID

    @property
    def sent(self):
        return self.engine.transport_dispatcher.sent

    @property
    def silent_drops(self):
        return _get_silent_drops(self.engine)

    def receive(self, message):
        self.engine.message_dispatcher.receive_message(
            self.engine, DOMAIN, ADDRESS, message
        )


class Manager:
    """In-memory SNMP manager producing requests."""

    def __init__(self, profile, agent_engine_id, max_message_size=HUGE_BUDGET):
        self.engine = engine.SnmpEngine()
        self.engine.transport_dispatcher = InMemoryTransportDispatcher()
        _set_max_message_size(self.engine, max_message_size)
        config.add_v3_user(
            self.engine,
            "usr",
            profile["authProtocol"],
            profile["authKey"],
            profile["privProtocol"],
            profile["privKey"],
            securityEngineId=agent_engine_id,
        )
        self.profile = profile
        self.responses = []
        self.last_request_id = None

    @property
    def sent(self):
        return self.engine.transport_dispatcher.sent

    def send_get(self, context_name=b""):
        pdu = v2c.GetRequestPDU()
        v2c.apiPDU.set_defaults(pdu)
        v2c.apiPDU.set_varbinds(pdu, [(TEST_OID_0, None)])
        self.last_request_id = int(v2c.apiPDU.get_request_id(pdu))
        self.engine.message_dispatcher.send_pdu(
            self.engine,
            DOMAIN,
            ADDRESS,
            3,
            3,
            v2c.OctetString("usr"),
            self.profile["securityLevel"],
            None,
            context_name,
            1,
            pdu,
            True,
            cbFun=self._on_response,
        )
        assert len(self.sent) == 1
        return self.sent.pop()

    def _on_response(
        self,
        snmpEngine,
        messageProcessingModel,
        securityModel,
        securityName,
        securityLevel,
        contextEngineId,
        contextName,
        pduVersion,
        PDU,
        statusInformation,
        sendPduHandle,
        cbCtx,
    ):
        self.responses.append(
            dict(pdu=PDU, statusInformation=statusInformation)
        )

    def receive(self, message):
        self.engine.message_dispatcher.receive_message(
            self.engine, DOMAIN, ADDRESS, message
        )


def prime_engine_id_and_timeline(manager, agent):
    """Run USM engineID discovery over the in-memory wire."""
    agent.receive(manager.send_get())
    assert len(agent.sent) == 1, "expected a discovery Report"
    manager.receive(agent.sent.pop())
    manager.responses.clear()


def round_trip(manager, agent, context_name=b""):
    """Send a GET request; return the response message or None if dropped."""
    agent.receive(manager.send_get(context_name))
    if not agent.sent:
        return None
    response = agent.sent.pop()
    manager.receive(response)
    return response


def make_pair(profile_name, agent_max_message_size=HUGE_BUDGET, engine_id=None):
    profile = PROFILES[profile_name]
    agent = Agent(profile, max_message_size=agent_max_message_size, engine_id=engine_id)
    manager = Manager(profile, agent.engine_id)
    prime_engine_id_and_timeline(manager, agent)
    return manager, agent, profile


def measure_wire_size(manager, agent, value_size, context_name=b""):
    agent.holder["value"] = b"x" * value_size
    response = round_trip(manager, agent, context_name)
    assert response is not None
    return len(response)



def find_exact_fit_budget(manager, agent, value_size, context_name=b""):
    """Find, by measurement, the budget at which the response fits exactly.

    The response carries the engine's own snmpEngineMaxMessageSize in its
    header, so changing the budget changes the response wire size (BER
    length fields included): the exact-fit point is the fixpoint where
    the measured wire size equals the configured budget.
    """
    _set_max_message_size(agent.engine, HUGE_BUDGET)
    budget = measure_wire_size(manager, agent, value_size, context_name)
    for _ in range(5):
        _set_max_message_size(agent.engine, budget)
        agent.holder["value"] = b"x" * value_size
        response = round_trip(manager, agent, context_name)
        assert response is not None
        if len(response) == budget:
            return budget
        budget = len(response)
    raise AssertionError("no exact-fit budget found")

def decode_v3_message(message):
    msg, rest = decoder.decode(message, asn1Spec=mpmod_rfc3412.SNMPv3Message())
    assert rest == b""
    return msg


ALL_PROFILES = sorted(PROFILES)


@pytest.mark.parametrize("profile_name", ALL_PROFILES)
def test_response_fitting_budget_exactly_is_delivered(profile_name):
    """A response whose wire size equals the budget must be delivered."""
    manager, agent, profile = make_pair(profile_name)
    for value_size in (0, 1, 17, 100, 1000):
        budget = find_exact_fit_budget(manager, agent, value_size)
        agent.holder["value"] = b"x" * value_size
        response = round_trip(manager, agent)
        assert response is not None
        assert len(response) == budget  # exact fit, byte for byte
        assert agent.silent_drops == 0


@pytest.mark.parametrize("profile_name", ALL_PROFILES)
def test_response_never_exceeds_budget(profile_name):
    """No matter the budget, nothing longer than the budget may be sent."""
    manager, agent, profile = make_pair(profile_name)
    for value_size in (0, 1, 100, 1000):
        budget = find_exact_fit_budget(manager, agent, value_size)
        for delta in (1, 2, 3):
            _set_max_message_size(agent.engine, budget - delta)
            agent.holder["value"] = b"x" * value_size
            response = round_trip(manager, agent)
            assert response is not None, "a tooBig response must still fit"
            assert len(response) <= budget - delta
        assert agent.silent_drops == 0


@pytest.mark.parametrize("profile_name", ALL_PROFILES)
def test_one_byte_over_budget_yields_too_big_response(profile_name):
    """One byte over the budget must produce a fitting tooBig response."""
    manager, agent, profile = make_pair(profile_name)
    value_size = 600  # keep the peer-declared budget above the 484 minimum
    wire_size = measure_wire_size(manager, agent, value_size)
    assert wire_size > 484

    # Drive the budget through the peer-declared msgMaxSize: the response
    # header keeps carrying the (larger) local limit, so the response
    # wire size does not depend on the peer-declared budget
    _set_max_message_size(manager.engine, wire_size - 1)
    agent.holder["value"] = b"x" * value_size
    response = round_trip(manager, agent)

    assert response is not None, "tooBig response must still be sent"
    assert len(response) <= wire_size - 1

    # security level must not be lowered to make the message fit
    msg = decode_v3_message(response)
    (msg_flags,) = msg.getComponentByPosition(1).getComponentByPosition(
        2
    ).asNumbers()
    assert msg_flags == profile["msgFlags"]
    if profile["securityLevel"] == AUTH_PRIV:
        assert msg.getComponentByPosition(3).getName() == "encryptedPDU"

    # RFC 1905 4.2.1.3: tooBig, error-index 0, empty var-bind list,
    # original request-id
    rsp_pdu = manager.responses[-1]["pdu"]
    assert int(v2c.apiPDU.get_error_status(rsp_pdu)) == 1  # tooBig
    assert int(v2c.apiPDU.get_error_index(rsp_pdu)) == 0
    assert v2c.apiPDU.get_varbinds(rsp_pdu) == []
    assert int(v2c.apiPDU.get_request_id(rsp_pdu)) == manager.last_request_id

    assert agent.silent_drops == 0


@pytest.mark.parametrize("profile_name", ALL_PROFILES)
def test_even_too_big_over_budget_is_silently_dropped(profile_name):
    """When even the tooBig response does not fit: silent drop + count."""
    manager, agent, profile = make_pair(profile_name)

    # measure the tooBig response size through the peer-declared budget
    # so the stamped local limit does not interfere with the measurement
    wire_size = measure_wire_size(manager, agent, 600)
    _set_max_message_size(manager.engine, wire_size - 1)
    agent.holder["value"] = b"x" * 600
    too_big_response = round_trip(manager, agent)
    assert too_big_response is not None
    too_big_size = len(too_big_response)
    assert too_big_size < wire_size

    # now make even the tooBig response not fit; the margin exceeds any
    # shrinkage the stamped msgMaxSize field itself may cause
    _set_max_message_size(manager.engine, HUGE_BUDGET)
    _set_max_message_size(agent.engine, too_big_size - 10)
    agent.holder["value"] = b"x" * 600
    drops_before = agent.silent_drops
    response = round_trip(manager, agent)

    assert response is None, "nothing may be sent"
    assert agent.sent == []
    assert agent.silent_drops == drops_before + 1  # counted exactly once

    # no state may be left behind: USM security cache, MP response cache
    # and responder pending requests must all be clean
    assert agent.engine.security_models[3]._cache.is_empty()
    mp_cache = agent.engine.message_processing_subsystems[3]._cache
    assert getattr(mp_cache, "_Cache__stateReferenceIndex") == {}
    assert getattr(agent.responder, "_CommandResponderBase__pendingReqs") == {}
    dispatcher = agent.engine.message_dispatcher
    assert getattr(dispatcher, "_MsgAndPduDispatcher__transportInfo") == {}
    agent.engine._close()  # raises if any security state leaked


@pytest.mark.parametrize("profile_name", ALL_PROFILES)
def test_failed_response_does_not_recurse(profile_name):
    """A dropped tooBig response must not trigger further error messages."""
    manager, agent, profile = make_pair(profile_name)
    _set_max_message_size(agent.engine, 60)  # nothing fits, not even tooBig
    agent.holder["value"] = b"x" * 100
    drops_before = agent.silent_drops

    agent.receive(manager.send_get())

    assert agent.sent == [], "no recursive error generation"
    assert agent.silent_drops == drops_before + 1
    agent.engine._close()


@pytest.mark.parametrize("profile_name", ALL_PROFILES)
def test_oversized_discovery_report_is_dropped_without_recursion(profile_name):
    """An error Report that does not fit must be dropped, not re-reported."""
    profile = PROFILES[profile_name]
    agent = Agent(profile)
    manager = Manager(profile, agent.engine_id)
    # no engineID discovery priming: the first message triggers a Report
    _set_max_message_size(agent.engine, 60)  # even the Report won't fit
    drops_before = agent.silent_drops

    agent.receive(manager.send_get())  # must return, not raise or loop

    assert agent.sent == []
    assert agent.silent_drops == drops_before + 1
    agent.engine._close()


@pytest.mark.parametrize("profile_name", ["none-none", "sha-aes"])
@pytest.mark.parametrize("boundary", [128, 256, 65536])
def test_ber_length_encoding_boundaries(profile_name, boundary):
    """Budget checks must hold across BER long-form length transitions."""
    manager, agent, profile = make_pair(profile_name)

    # find value sizes whose response wire sizes straddle the boundary
    base_size = measure_wire_size(manager, agent, 0)
    if base_size > boundary:
        pytest.skip(
            "empty response of %d octets already exceeds the boundary"
            % base_size
        )
    wire_sizes = {}
    for value_size in range(
        max(0, boundary - base_size - 32), boundary - base_size + 10
    ):
        wire_sizes[value_size] = measure_wire_size(manager, agent, value_size)

    assert min(wire_sizes.values()) <= boundary < max(wire_sizes.values())

    for target in (boundary - 1, boundary, boundary + 1):
        hits = [vs for vs, ws in wire_sizes.items() if ws == target]
        if not hits:
            # size skipped by a BER length-field jump: a response of
            # exactly this size is not representable
            continue
        value_size = hits[0]

        budget = find_exact_fit_budget(manager, agent, value_size)
        agent.holder["value"] = b"x" * value_size
        response = round_trip(manager, agent)
        assert response is not None
        assert len(response) == budget

        _set_max_message_size(agent.engine, budget - 1)
        agent.holder["value"] = b"x" * value_size
        response = round_trip(manager, agent)
        assert response is not None
        assert len(response) <= budget - 1


def test_des_block_padding_boundaries():
    """DES pads the scoped PDU to 8-byte blocks; the budget must see that."""
    manager, agent, profile = make_pair("sha-des")

    previous_encrypted_size = None
    for value_size in range(0, 24):
        _set_max_message_size(agent.engine, HUGE_BUDGET)
        agent.holder["value"] = b"x" * value_size
        response = round_trip(manager, agent)
        assert response is not None

        msg = decode_v3_message(response)
        encrypted_pdu = msg.getComponentByPosition(3).getComponent()
        encrypted_size = len(bytes(encrypted_pdu))
        assert encrypted_size % 8 == 0, "DES output must be block-aligned"
        if previous_encrypted_size is not None:
            # padding absorbs growth, then jumps by a whole block
            assert encrypted_size - previous_encrypted_size in (0, 8)
        previous_encrypted_size = encrypted_size

        # the budget applies to the padded, encapsulated size
        budget = find_exact_fit_budget(manager, agent, value_size)
        _set_max_message_size(agent.engine, budget - 1)
        agent.holder["value"] = b"x" * value_size
        too_big = round_trip(manager, agent)
        assert too_big is not None and len(too_big) <= budget - 1


def test_aes_cfb_stream_boundaries():
    """AES-CFB does not pad; ciphertext tracks the plaintext byte-by-byte."""
    manager, agent, profile = make_pair("sha-aes")

    previous_encrypted_size = None
    for value_size in range(0, 24):
        _set_max_message_size(agent.engine, HUGE_BUDGET)
        agent.holder["value"] = b"x" * value_size
        response = round_trip(manager, agent)
        assert response is not None

        msg = decode_v3_message(response)
        encrypted_pdu = msg.getComponentByPosition(3).getComponent()
        encrypted_size = len(bytes(encrypted_pdu))
        if previous_encrypted_size is not None:
            # stream mode: grows with the plaintext (plus the occasional
            # BER length byte), never by whole cipher blocks
            assert 1 <= encrypted_size - previous_encrypted_size <= 3
        previous_encrypted_size = encrypted_size


def test_digest_size_differences_are_accounted():
    """Larger USM digests must produce correspondingly larger budgets."""
    wire_sizes = {}
    for profile_name in ("none-none", "sha-none", "sha256-none", "sha512-none"):
        manager, agent, profile = make_pair(profile_name)
        wire_sizes[profile_name] = measure_wire_size(manager, agent, 100)

        # exact fit and one-byte-less behavior holds for every digest
        budget = find_exact_fit_budget(manager, agent, 100)
        _set_max_message_size(agent.engine, budget - 1)
        agent.holder["value"] = b"x" * 100
        too_big = round_trip(manager, agent)
        assert too_big is not None
        assert len(too_big) <= budget - 1

    # HMAC96-SHA: 12 octets, HMAC192-SHA256: 24, HMAC384-SHA512: 48
    assert wire_sizes["none-none"] < wire_sizes["sha-none"]
    assert wire_sizes["sha-none"] < wire_sizes["sha256-none"]
    assert wire_sizes["sha256-none"] < wire_sizes["sha512-none"]


def test_engine_id_length_is_accounted():
    """A longer authoritative engineID must eat into the response budget."""
    short_id = b"\x80\x00\x00\x00\x01"
    long_id = b"\x80" + b"\x00" * 30 + b"\x01"  # 32 octets, the maximum

    sizes = {}
    for engine_id in (short_id, long_id):
        manager, agent, profile = make_pair("none-none", engine_id=engine_id)
        sizes[engine_id] = find_exact_fit_budget(manager, agent, 100)

    assert sizes[long_id] - sizes[short_id] == 2 * (
        len(long_id) - len(short_id)
    )  # engineID appears in securityParameters and scopedPDU


def test_context_name_length_is_accounted():
    """A longer contextName must eat into the response budget."""
    manager, agent, profile = make_pair("none-none")
    long_context = b"c" * 24
    agent.context.register_context_name(long_context)
    config.add_vacm_user(
        agent.engine, 3, "usr", profile["vacmLevel"], (1, 3, 6),
        contextName=long_context,
    )

    short_size = measure_wire_size(manager, agent, 100)
    long_size = measure_wire_size(manager, agent, 100, context_name=long_context)
    assert long_size - short_size == len(long_context)

    budget = find_exact_fit_budget(manager, agent, 100, context_name=long_context)
    _set_max_message_size(agent.engine, budget - 1)
    agent.holder["value"] = b"x" * 100
    too_big = round_trip(manager, agent, context_name=long_context)
    assert too_big is not None and len(too_big) <= budget - 1


def test_local_and_peer_budgets_are_both_enforced():
    """The effective budget is min(local engine max, peer msgMaxSize)."""
    manager, agent, profile = make_pair("none-none")
    value_size = 600  # keep all budgets above the 484 minimum
    wire_size = measure_wire_size(manager, agent, value_size)

    # peer allows more than the local engine: local limit binds; the
    # margin exceeds any shrinkage of the stamped msgMaxSize field so
    # the normal response definitely stays over the budget
    _set_max_message_size(agent.engine, wire_size - 10)
    agent.holder["value"] = b"x" * value_size
    response = round_trip(manager, agent)
    assert response is not None
    assert len(response) <= wire_size - 10
    rsp_pdu = manager.responses[-1]["pdu"]
    assert int(v2c.apiPDU.get_error_status(rsp_pdu)) == 1  # tooBig

    # local engine allows more than the peer: peer limit binds
    manager2, agent2, _ = make_pair("none-none")
    wire_size2 = measure_wire_size(manager2, agent2, value_size)
    _set_max_message_size(manager2.engine, wire_size2 - 1)
    agent2.holder["value"] = b"x" * value_size
    response = round_trip(manager2, agent2)
    assert response is not None
    assert len(response) <= wire_size2 - 1
    rsp_pdu = manager2.responses[-1]["pdu"]
    assert int(v2c.apiPDU.get_error_status(rsp_pdu)) == 1  # tooBig


def test_v2c_oversized_response_is_counted_once():
    """The v1/v2c path must silently drop and count oversize exactly once."""
    agent_engine = engine.SnmpEngine()
    agent_engine.transport_dispatcher = InMemoryTransportDispatcher()
    config.add_v1_system(agent_engine, "public", "public")
    config.add_vacm_user(agent_engine, 2, "public", "noAuthNoPriv", (1, 3, 6))

    snmp_context = context.SnmpContext(agent_engine)
    mib_builder = snmp_context.get_mib_instrum().get_mib_builder()
    (MibScalar, MibScalarInstance) = mib_builder.import_symbols(
        "SNMPv2-SMI", "MibScalar", "MibScalarInstance"
    )
    mib_builder.export_symbols(
        "__TEST-MIB",
        MibScalar(TEST_OID, v2c.OctetString()),
        MibScalarInstance(TEST_OID, (0,), v2c.OctetString("x" * 100)),
    )
    responder = cmdrsp.GetCommandResponder(agent_engine, snmp_context)

    manager_engine = engine.SnmpEngine()
    manager_engine.transport_dispatcher = InMemoryTransportDispatcher()
    config.add_v1_system(manager_engine, "public", "public")

    responses = []

    def send_v2c_get():
        pdu = v2c.GetRequestPDU()
        v2c.apiPDU.set_defaults(pdu)
        v2c.apiPDU.set_varbinds(pdu, [(TEST_OID_0, None)])
        manager_engine.message_dispatcher.send_pdu(
            manager_engine,
            DOMAIN,
            ADDRESS,
            1,
            2,
            v2c.OctetString("public"),
            1,
            None,
            b"",
            1,
            pdu,
            True,
            cbFun=lambda *args: responses.append(args),
        )
        assert len(manager_engine.transport_dispatcher.sent) == 1
        request = manager_engine.transport_dispatcher.sent.pop()
        agent_engine.message_dispatcher.receive_message(
            agent_engine, DOMAIN, ADDRESS, request
        )

    # baseline: the response fits the default local limit
    send_v2c_get()
    assert len(agent_engine.transport_dispatcher.sent) == 1
    wire_size = len(agent_engine.transport_dispatcher.sent.pop())
    assert _get_silent_drops(agent_engine) == 0

    # one byte less: the v1/v2c MP model has no tooBig fallback of its
    # own, so the dispatcher drops the oversized response and counts it
    _set_max_message_size(agent_engine, wire_size - 1)
    send_v2c_get()
    assert agent_engine.transport_dispatcher.sent == []
    assert _get_silent_drops(agent_engine) == 1  # not two

    # no state left behind
    assert agent_engine.security_models[2]._cache.is_empty()
    assert getattr(responder, "_CommandResponderBase__pendingReqs") == {}
    agent_engine._close()
