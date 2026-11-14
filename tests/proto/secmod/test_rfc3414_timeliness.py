"""RFC 3414 USM timeliness and limited replay protection.

The non-authoritative SNMP engine's cached notion of a peer's
``snmpEngineBoots`` / ``snmpEngineTime`` must only ever move forward, and only
as the result of an *authenticated* message (RFC 3414 section 3.2 steps 6 and
7b). In particular:

* an unauthenticated discovery message must not create or overwrite a
  timeline entry;
* an authenticated but stale message must be rejected with
  ``notInTimeWindow`` and leave both the time estimate and the replay
  baseline (``latestReceivedEngineTime``) untouched, so replaying it again
  keeps failing;
* a rejected message must not extend the 300s lifetime of the cached entry;
* a legitimate higher ``snmpEngineBoots`` (peer re-boot) and the first
  authenticated time synchronization after discovery must still work.

The authoritative side is covered too: it judges timeliness against its own
LCD and never caches anything in the USM timeline for its own engine ID.

Every message travels through the real
``SnmpUSMSecurityModel.process_incoming_message`` receive path, the clock is
frozen and advanced explicitly, and all MACs are computed from a localized
authentication key rather than stubbed out.
"""

import time as stdlib_time

import pytest
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type import univ

from pysnmp.entity import config, engine
from pysnmp.proto import errind, error
from pysnmp.proto.api import v2c
from pysnmp.proto.mpmod import rfc3412
from pysnmp.proto.secmod.rfc3414 import service
from pysnmp.proto.secmod.rfc3414.auth import hmacsha

USER = b"usr-sha"
AUTHORITATIVE_ENGINE_ID = univ.OctetString(hexValue="8000000001aaaaaaaaaaaaaaaa")
MANAGER_ENGINE_ID = univ.OctetString(hexValue="8000000002bbbbbbbbbbbbbbbb")
MASTER_KEY = b"0" * 20
SHA = hmacsha.HmacSha()
TIMELINE_ATTR = "_SnmpUSMSecurityModel__timeline"
EXPIRY_ATTR = "_SnmpUSMSecurityModel__timelineExpiry"


class FrozenClock:
    """Monkeypatch target for the stdlib clock shared by USM and the MIB."""

    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def frozen_clock(monkeypatch):
    clock = FrozenClock()
    monkeypatch.setattr(stdlib_time, "time", clock)
    # USM imported ``time`` directly, patch the same attribute there too.
    monkeypatch.setattr(service.time, "time", clock)
    return clock


def _localized_key(snmp_engine, engine_id):
    mib_builder = snmp_engine.get_mib_builder()
    (usm_user_entry,) = mib_builder.import_symbols(
        "SNMP-USER-BASED-SM-MIB", "usmUserEntry"
    )
    (key_entry,) = mib_builder.import_symbols("PYSNMP-USM-MIB", "pysnmpUsmKeyEntry")
    index = usm_user_entry.getInstIdFromIndices(engine_id, USER)
    return key_entry.getNode(key_entry.name + (1,) + index).syntax


def _make_engine(engine_id, peer_engine_id=None):
    snmp_engine = engine.SnmpEngine(snmpEngineID=engine_id)
    config.add_v3_user(
        snmp_engine,
        USER,
        config.USM_AUTH_HMAC96_SHA,
        MASTER_KEY,
        authKeyType=config.USM_KEY_TYPE_MASTER,
    )
    if peer_engine_id is not None:
        peer_key = SHA.localize_key(MASTER_KEY, peer_engine_id)
        config.add_v3_user(
            snmp_engine,
            USER,
            config.USM_AUTH_HMAC96_SHA,
            peer_key,
            securityEngineId=peer_engine_id,
            authKeyType=config.USM_KEY_TYPE_LOCALIZED,
        )
    return snmp_engine


def _build_message(engine_id, boots, engine_time, user, flags, auth_key=None):
    request = v2c.GetRequestPDU()
    v2c.apiPDU.set_defaults(request)

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
    header.setComponentByPosition(2, flags)
    header.setComponentByPosition(3, 3)
    message.getComponentByPosition(3).setComponentByPosition(0, scoped_pdu)

    security_parameters = service.UsmSecurityParameters()
    security_parameters.setComponentByPosition(0, engine_id)
    security_parameters.setComponentByPosition(1, boots)
    security_parameters.setComponentByPosition(2, engine_time)
    security_parameters.setComponentByPosition(3, user)
    security_parameters.setComponentByPosition(
        4, b"\x00" * (SHA.digest_length if auth_key else 0)
    )
    security_parameters.setComponentByPosition(5, b"")
    encoded_parameters = encoder.encode(security_parameters)
    message.setComponentByPosition(2, encoded_parameters)

    whole_message = encoder.encode(message)
    if auth_key:
        whole_message = SHA.authenticate_outgoing_message(auth_key, whole_message)
        outer, _ = decoder.decode(
            whole_message, asn1Spec=rfc3412.SNMPv3Message()
        )
        encoded_parameters = outer.getComponentByPosition(2).asOctets()
    return encoded_parameters, whole_message


def _process(snmp_engine, encoded_parameters, whole_message, security_level):
    message, _ = decoder.decode(
        whole_message, asn1Spec=rfc3412.SNMPv3Message()
    )
    try:
        snmp_engine.security_models[3].process_incoming_message(
            snmp_engine,
            3,
            65507,
            encoded_parameters,
            3,
            security_level,
            whole_message,
            message,
        )
    except error.StatusInformation as exc:
        return exc["errorIndication"]
    return None


def _timeline(snmp_engine, engine_id):
    entry = getattr(snmp_engine.security_models[3], TIMELINE_ATTR).get(engine_id)
    if entry is None:
        return None
    boots, engine_time, latest_received, updated_at = entry
    return int(boots), int(engine_time), int(latest_received), updated_at


def _set_authoritative_time(snmp_engine, value, clock):
    # The live snmpEngineTime is (wall clock - captured base); anchor the
    # base at a non-negative instant so that the derived time equals *value*.
    (engine_time_object,) = snmp_engine.get_mib_builder().import_symbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineTime"
    )
    base = max(0, int(clock()) - value)
    engine_time_object.syntax = engine_time_object.syntax.clone(base)


def test_manager_timeline_never_moves_backward_and_replay_stays_rejected(
    frozen_clock,
):
    """Stale MAC-valid and unauthenticated messages cannot roll time back."""
    manager = _make_engine(MANAGER_ENGINE_ID, AUTHORITATIVE_ENGINE_ID)
    peer_key = SHA.localize_key(MASTER_KEY, AUTHORITATIVE_ENGINE_ID)

    def send(boots, engine_time, user, flags, key, level):
        encoded_parameters, whole_message = _build_message(
            AUTHORITATIVE_ENGINE_ID, boots, engine_time, user, flags, key
        )
        return _process(manager, encoded_parameters, whole_message, level)

    # 1. normal authenticated report establishes the trusted estimate
    assert send(5, 1000, USER, b"\x05", peer_key, 2) is None
    trusted = _timeline(manager, AUTHORITATIVE_ENGINE_ID)
    assert trusted == (5, 1000, 1000, 1000)

    # 2. authenticated but stale message: rejected, state completely unchanged
    frozen_clock.advance(10)
    assert (
        send(5, 200, USER, b"\x05", peer_key, 2) is errind.notInTimeWindow
    )
    assert _timeline(manager, AUTHORITATIVE_ENGINE_ID) == trusted

    # 3. unauthenticated discovery message with forged boots/time: accepted at
    #    noAuthNoPriv but the timeline estimate is not touched at all
    frozen_clock.advance(10)
    assert send(1, 50, b"", b"\x04", None, 1) is None
    assert _timeline(manager, AUTHORITATIVE_ENGINE_ID) == trusted

    # 4. the rejected message replayed later is still rejected
    frozen_clock.advance(10)
    assert (
        send(5, 200, USER, b"\x05", peer_key, 2) is errind.notInTimeWindow
    )
    assert _timeline(manager, AUTHORITATIVE_ENGINE_ID) == trusted


def test_manager_accepts_legitimate_reboot_and_recovers(frozen_clock):
    """A higher boots value (authoritative engine re-boot) still synchronizes."""
    manager = _make_engine(MANAGER_ENGINE_ID, AUTHORITATIVE_ENGINE_ID)
    peer_key = SHA.localize_key(MASTER_KEY, AUTHORITATIVE_ENGINE_ID)

    def send(boots, engine_time):
        encoded_parameters, whole_message = _build_message(
            AUTHORITATIVE_ENGINE_ID,
            boots,
            engine_time,
            USER,
            b"\x05",
            peer_key,
        )
        return _process(manager, encoded_parameters, whole_message, 2)

    assert send(5, 1000) is None
    frozen_clock.advance(10)

    # peer rebooted: boots jumps forward, engine time restarts near zero
    assert send(6, 1) is None
    assert _timeline(manager, AUTHORITATIVE_ENGINE_ID) == (6, 1, 1, 1010)

    # ordinary forward progress keeps advancing
    frozen_clock.advance(10)
    assert send(6, 50) is None
    assert _timeline(manager, AUTHORITATIVE_ENGINE_ID) == (6, 50, 50, 1020)

    # going back to the previous boots is no longer possible
    frozen_clock.advance(10)
    assert send(5, 1000) is errind.notInTimeWindow
    assert _timeline(manager, AUTHORITATIVE_ENGINE_ID) == (6, 50, 50, 1020)


def test_first_time_synchronization_after_discovery_creates_timeline(frozen_clock):
    """RFC 3414 section 4: first authed message syncs an unknown engine."""
    manager = _make_engine(MANAGER_ENGINE_ID, AUTHORITATIVE_ENGINE_ID)
    peer_key = SHA.localize_key(MASTER_KEY, AUTHORITATIVE_ENGINE_ID)

    assert _timeline(manager, AUTHORITATIVE_ENGINE_ID) is None

    encoded_parameters, whole_message = _build_message(
        AUTHORITATIVE_ENGINE_ID, 7, 42, USER, b"\x05", peer_key
    )
    assert (
        _process(manager, encoded_parameters, whole_message, 2) is None
    )
    assert _timeline(manager, AUTHORITATIVE_ENGINE_ID) == (7, 42, 42, 1000)


def test_rejected_message_does_not_refresh_timeline_lifetime(frozen_clock):
    """Only a state-changing update may reschedule the 300s expiry."""
    manager = _make_engine(MANAGER_ENGINE_ID, AUTHORITATIVE_ENGINE_ID)
    peer_key = SHA.localize_key(MASTER_KEY, AUTHORITATIVE_ENGINE_ID)
    usm = manager.security_models[3]

    def send(boots, engine_time, level=2, user=USER, flags=b"\x05", key=None):
        encoded_parameters, whole_message = _build_message(
            AUTHORITATIVE_ENGINE_ID,
            boots,
            engine_time,
            user,
            flags,
            peer_key if key is None else key,
        )
        return _process(manager, encoded_parameters, whole_message, level)

    assert send(5, 1000) is None
    expiry_at_creation = getattr(usm, EXPIRY_ATTR)[AUTHORITATIVE_ENGINE_ID]

    # let the internal timer advance; rejected messages must not reschedule
    # the expiry relative to these ticks
    for _ in range(5):
        frozen_clock.advance(1)
        usm.receive_timer_tick(manager, frozen_clock())
    assert send(5, 200) is errind.notInTimeWindow
    assert send(1, 50, level=1, user=b"", flags=b"\x04", key=False) is None
    assert getattr(usm, EXPIRY_ATTR)[AUTHORITATIVE_ENGINE_ID] == expiry_at_creation

    # a genuine forward update reschedules the expiry 300 ticks from now
    assert send(5, 1010) is None
    assert getattr(usm, EXPIRY_ATTR)[AUTHORITATIVE_ENGINE_ID] > expiry_at_creation


def test_authoritative_engine_enforces_150_second_window_and_keeps_no_timeline(
    frozen_clock,
):
    """The authoritative side judges against its LCD and caches no timeline."""
    agent = _make_engine(AUTHORITATIVE_ENGINE_ID)
    agent_key = _localized_key(agent, AUTHORITATIVE_ENGINE_ID)
    mib_builder = agent.get_mib_builder()
    (boots_object,) = mib_builder.import_symbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineBoots"
    )
    boots_object.syntax = boots_object.syntax.clone(5)

    def send(boots, engine_time, user=USER, flags=b"\x05", key=agent_key, level=2):
        encoded_parameters, whole_message = _build_message(
            AUTHORITATIVE_ENGINE_ID, boots, engine_time, user, flags, key
        )
        return _process(agent, encoded_parameters, whole_message, level)

    # within +/- 150s of the local clock
    _set_authoritative_time(agent, 1000, frozen_clock)
    assert send(5, 1000) is None

    # 151s behind the local clock is outside the window
    frozen_clock.advance(200)
    _set_authoritative_time(agent, 1200, frozen_clock)
    assert send(5, 1000) is errind.notInTimeWindow

    # mismatched boots is outside the window
    assert send(4, 1200) is errind.notInTimeWindow

    # unauthenticated traffic must not create a self-timeline entry
    assert send(1, 1, user=b"", flags=b"\x04", key=None, level=1) is None
    assert _timeline(agent, AUTHORITATIVE_ENGINE_ID) is None

    # back inside the window: accepted again, still nothing cached
    _set_authoritative_time(agent, 1250, frozen_clock)
    assert send(5, 1200) is None
    assert _timeline(agent, AUTHORITATIVE_ENGINE_ID) is None


def test_authoritative_window_boundary_is_exactly_150_seconds(frozen_clock):
    """Lock in the inclusive 150s boundary of the RFC 3414 time window."""
    agent = _make_engine(AUTHORITATIVE_ENGINE_ID)
    agent_key = _localized_key(agent, AUTHORITATIVE_ENGINE_ID)
    (boots_object,) = agent.get_mib_builder().import_symbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineBoots"
    )
    boots_object.syntax = boots_object.syntax.clone(5)

    def send(engine_time):
        encoded_parameters, whole_message = _build_message(
            AUTHORITATIVE_ENGINE_ID, 5, engine_time, USER, b"\x05", agent_key
        )
        return _process(agent, encoded_parameters, whole_message, 2)

    _set_authoritative_time(agent, 1000, frozen_clock)
    assert send(850) is None  # exactly 150s behind: still inside
    assert send(849) is errind.notInTimeWindow  # 151s behind: outside
    assert send(1150) is None  # exactly 150s ahead: still inside
    assert send(1151) is errind.notInTimeWindow  # 151s ahead: outside


def test_bad_mac_message_leaves_trusted_timeline_untouched(frozen_clock):
    """A message that fails authentication must not reach the timeline logic."""
    manager = _make_engine(MANAGER_ENGINE_ID, AUTHORITATIVE_ENGINE_ID)
    peer_key = SHA.localize_key(MASTER_KEY, AUTHORITATIVE_ENGINE_ID)

    encoded_parameters, whole_message = _build_message(
        AUTHORITATIVE_ENGINE_ID, 5, 1000, USER, b"\x05", peer_key
    )
    assert _process(manager, encoded_parameters, whole_message, 2) is None
    trusted = _timeline(manager, AUTHORITATIVE_ENGINE_ID)

    # fresh-looking boots/time but MAC computed with the wrong key: the
    # message is internally consistent yet fails authentication
    frozen_clock.advance(10)
    wrong_key = SHA.localize_key(b"1" * 20, AUTHORITATIVE_ENGINE_ID)
    tampered_parameters, tampered_message = _build_message(
        AUTHORITATIVE_ENGINE_ID, 5, 2000, USER, b"\x05", wrong_key
    )
    assert (
        _process(manager, tampered_parameters, tampered_message, 2)
        is errind.authenticationFailure
    )
    assert _timeline(manager, AUTHORITATIVE_ENGINE_ID) == trusted


def test_window_duplicate_is_limited_replay_but_never_moves_estimate(frozen_clock):
    """RFC 3414 offers limited replay: in-window duplicates are tolerated."""
    manager = _make_engine(MANAGER_ENGINE_ID, AUTHORITATIVE_ENGINE_ID)
    peer_key = SHA.localize_key(MASTER_KEY, AUTHORITATIVE_ENGINE_ID)

    def send(boots, engine_time):
        encoded_parameters, whole_message = _build_message(
            AUTHORITATIVE_ENGINE_ID,
            boots,
            engine_time,
            USER,
            b"\x05",
            peer_key,
        )
        return _process(manager, encoded_parameters, whole_message, 2)

    assert send(5, 1000) is None
    trusted = _timeline(manager, AUTHORITATIVE_ENGINE_ID)

    # exact duplicate 30s later stays inside the 150s window: tolerated, but
    # latestReceivedEngineTime must not be rewritten
    frozen_clock.advance(30)
    assert send(5, 1000) is None
    assert _timeline(manager, AUTHORITATIVE_ENGINE_ID) == trusted

    # the same duplicate beyond the window is finally rejected, state intact
    frozen_clock.advance(130)
    assert send(5, 1000) is errind.notInTimeWindow
    assert _timeline(manager, AUTHORITATIVE_ENGINE_ID) == trusted
