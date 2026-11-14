"""Regression tests: unauthenticated Reports must not poison manager state.

These drive the full asyncio command-generator stack through an in-memory
transport (no sockets, no real device). They pin the security properties
established by the offline forged-Report investigation:

  * the USM timeline (RFC 3414 3.2.6) is only updated from an authenticated
    message, or the single noAuth discovery Report that answers an in-flight
    probe;
  * the MP engine-ID cache applies the same rule;
  * an unsolicited/wrong-msgID/late Report never creates trusted state;
  * a legitimate discovery + authenticated GET still completes.
"""
import pytest

from pysnmp.proto.secmod.rfc3414.auth.hmacmd5 import HmacMd5

from tests.security_investigation import harness, v3msg
from tests.security_investigation.harness import (
    FORGED_ADDR,
    FORGED_ENGINE,
    PEER_ADDR,
    REAL_ENGINE,
    USER,
    Manager,
    localized_auth_key,
    run_scenario,
)

pytestmark = pytest.mark.asyncio

AUTH = HmacMd5()
REAL_KEY = localized_auth_key(REAL_ENGINE)


def _discovery_report(msg_id, engine_id, source=PEER_ADDR):
    return source, v3msg.build_report(
        msg_id, engine_id, 1, 10,
        v3msg.OID_UNKNOWN_ENGINE_ID,
        context_engine_id=engine_id, flags=v3msg.FLAG_NOAUTH,
    )


def _genuine_response(info):
    return PEER_ADDR, v3msg.build_response(
        info["msgID"], info["requestID"], REAL_ENGINE, 1, 11,
        USER.encode(), v3msg.FLAG_AUTH, auth_handler=AUTH, auth_key=REAL_KEY,
    )


def _genuine_peer():
    def peer(manager, info, wire, seq):
        if info["engineID"] == b"" and info["userName"] == b"":
            return [_discovery_report(info["msgID"], REAL_ENGINE)]
        return [_genuine_response(info)]
    return peer


async def test_legitimate_discovery_and_get_still_succeed():
    manager = Manager()
    try:
        error_indication, error_status, _, _ = await run_scenario(
            manager, _genuine_peer()
        )
        assert error_indication is None
        assert error_status == 0
        # Trusted state for the real peer is established normally.
        assert REAL_ENGINE.hex() in manager.timeline_summary()
        cached = manager.engine_id_cache_summary()
        assert cached[PEER_ADDR] == REAL_ENGINE.hex()
    finally:
        await manager.close()


async def test_unsolicited_report_with_unknown_msgid_creates_no_state():
    def peer(manager, info, wire, seq):
        if seq == 1:
            forged = v3msg.build_report(
                info["msgID"] + 99999, FORGED_ENGINE, 1, 10,
                v3msg.OID_UNKNOWN_ENGINE_ID,
                context_engine_id=FORGED_ENGINE, flags=v3msg.FLAG_NOAUTH,
            )
            genuine = _discovery_report(info["msgID"], REAL_ENGINE)[1]
            return [(FORGED_ADDR, forged), (PEER_ADDR, genuine)]
        return [_genuine_response(info)]

    manager = Manager()
    try:
        error_indication, _, _, _ = await run_scenario(manager, peer)
        assert error_indication is None
        # The forged engine must appear nowhere in trusted state.
        assert FORGED_ENGINE.hex() not in manager.timeline_summary()
        assert FORGED_ADDR not in manager.engine_id_cache_summary()
        assert PEER_ADDR in manager.engine_id_cache_summary()
    finally:
        await manager.close()


async def test_late_report_after_completion_leaves_no_residue():
    state = {}

    def peer(manager, info, wire, seq):
        if info["engineID"] == b"" and info["userName"] == b"":
            return [_discovery_report(info["msgID"], REAL_ENGINE)]
        late = v3msg.build_report(
            info["msgID"], FORGED_ENGINE, 1, 10,
            v3msg.OID_UNKNOWN_ENGINE_ID,
            context_engine_id=FORGED_ENGINE, flags=v3msg.FLAG_NOAUTH,
        )
        state["late"] = (late, FORGED_ADDR)
        import asyncio
        loop = asyncio.get_running_loop()
        loop.call_soon(manager.transport.deliver, loop, late, FORGED_ADDR)
        return [_genuine_response(info)]

    manager = Manager()
    try:
        error_indication, _, _, _ = await run_scenario(manager, peer)
        assert error_indication is None
        assert FORGED_ENGINE.hex() not in manager.timeline_summary()
        assert FORGED_ADDR not in manager.engine_id_cache_summary()
    finally:
        await manager.close()


async def test_noauth_resync_report_cannot_overwrite_trusted_timeline():
    manager = Manager()
    try:
        await run_scenario(manager, _genuine_peer())
        manager.transport.sent.clear()
        trusted_before = dict(manager.timeline_summary())

        def attacker(manager, info, wire, seq):
            report = v3msg.build_report(
                info["msgID"], REAL_ENGINE, boots=99, engine_time=999999,
                error_oid=v3msg.OID_NOT_IN_TIME_WINDOW,
                context_engine_id=REAL_ENGINE, user_name=USER.encode(),
                flags=v3msg.FLAG_NOAUTH,  # attacker cannot produce a valid MAC
            )
            return [(FORGED_ADDR, report)]

        error_indication, _, _, _ = await run_scenario(manager, attacker)
        assert error_indication is not None
        # Trusted boots/time for the real engine are untouched.
        assert manager.timeline_summary() == trusted_before
        assert FORGED_ADDR not in manager.engine_id_cache_summary()
    finally:
        await manager.close()


async def test_wrong_digest_report_does_not_mutate_state():
    forged_key = localized_auth_key(FORGED_ENGINE)
    manager = Manager()
    try:
        await run_scenario(manager, _genuine_peer())
        manager.transport.sent.clear()
        before = dict(manager.timeline_summary())

        def attacker(manager, info, wire, seq):
            report = v3msg.build_report(
                info["msgID"], REAL_ENGINE, 1, 11,
                v3msg.OID_WRONG_DIGEST,
                context_engine_id=REAL_ENGINE, user_name=USER.encode(),
                flags=v3msg.FLAG_AUTH, auth_handler=AUTH, auth_key=forged_key,
            )
            return [(PEER_ADDR, report)]

        await run_scenario(manager, attacker)
        assert manager.timeline_summary() == before
        assert manager.engine_id_cache_summary() == {PEER_ADDR: REAL_ENGINE.hex()}
    finally:
        await manager.close()


async def test_forged_discovery_answer_is_isolated_per_transport_address():
    """A forged Report answering a real probe may bootstrap state, but only
    keyed to the attacker's own address; the real peer stays independently
    discoverable and reachable."""
    def attacker(manager, info, wire, seq):
        return [_discovery_report(info["msgID"], FORGED_ENGINE, source=FORGED_ADDR)]

    manager = Manager()
    try:
        # The forged peer never offers a usable authenticated response, so the
        # operation ends with an engine-ID error after discovery retries.
        attack_error, _, _, _ = await run_scenario(manager, attacker)
        assert attack_error is not None
        manager.transport.sent.clear()

        error_indication, _, _, _ = await run_scenario(
            manager, _genuine_peer()
        )
        assert error_indication is None
        # Both engines exist, but each is bound to its own source address.
        cache = manager.engine_id_cache_summary()
        assert cache[FORGED_ADDR] == FORGED_ENGINE.hex()
        assert cache[PEER_ADDR] == REAL_ENGINE.hex()
        # Requests to the real peer carry the real engine, never the forged one.
        for wire, _ in manager.outgoing():
            info = v3msg.dissect(wire)
            if info["engineID"]:
                assert info["engineID"] == REAL_ENGINE
    finally:
        await manager.close()
