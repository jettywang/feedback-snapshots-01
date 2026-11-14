"""Forged-Report scenario matrix (fully offline, in-memory transport).

Each scenario records:
  * the minimal wire sequence (outgoing probes, injected Reports),
  * the three manager state stores before/after,
  * the security level and target engine of every retry actually sent.

Phase A = first discovery (no trusted state).
Phase B = re-synchronisation with an already trusted engine timeline.
"""
import asyncio

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config

_UDP_DOMAIN = udp.DOMAIN_NAME
from pysnmp.proto.secmod.rfc3414.auth.hmacmd5 import HmacMd5

from tests.security_investigation import harness, v3msg
from tests.security_investigation.harness import (
    FORGED_ADDR,
    FORGED_ENGINE,
    Manager,
    PEER_ADDR,
    REAL_ENGINE,
    USER,
    localized_auth_key,
    run_scenario,
)

AUTH = HmacMd5()
REAL_KEY = localized_auth_key(REAL_ENGINE)
FORGED_KEY = localized_auth_key(FORGED_ENGINE)


def discovery_report(msg_id, engine_id, source=PEER_ADDR, boots=1, etime=10):
    rpt = v3msg.build_report(
        msg_id, engine_id, boots, etime,
        v3msg.OID_UNKNOWN_ENGINE_ID,
        context_engine_id=engine_id, flags=v3msg.FLAG_NOAUTH,
    )
    return source, rpt


def legit_response(info):
    return PEER_ADDR, v3msg.build_response(
        info["msgID"], info["requestID"], REAL_ENGINE, 1, 11,
        USER.encode(), v3msg.FLAG_AUTH, auth_handler=AUTH, auth_key=REAL_KEY,
    )


def summarize_outgoing(manager):
    rows = []
    for wire, _addr in manager.outgoing():
        d = v3msg.dissect(wire)
        rows.append({
            "flags": d["flags"],
            "level": {0: "noAuth", 1: "auth", 3: "authPriv"}[d["flags"] & 0x03],
            "engineID": d["engineID"].hex() or "(empty/discovery)",
            "user": d["userName"].decode() or "-",
            "msgID": d["msgID"],
            "boots": d["boots"], "time": d["engineTime"],
        })
    return rows


def stat_counters(manager):
    mb = manager.engine.get_mib_builder()
    names = [
        "usmStatsUnknownEngineIDs", "usmStatsNotInTimeWindows",
        "usmStatsWrongDigests", "usmStatsUnknownUserNames",
        "usmStatsUnsupportedSecLevels",
    ]
    out = {}
    for name in names:
        try:
            (sym,) = mb.import_symbols("__SNMP-USER-BASED-SM-MIB", name)
            out[name] = int(sym.syntax)
        except Exception:
            out[name] = "n/a"
    return out


async def execute(name, peer_logic, preload_trusted=False, expect_error=False):
    m = Manager()
    record = {"name": name}
    if preload_trusted:
        # Establish trusted state with the genuine engine first. The same
        # transport is reused; its capture buffer is cleared afterwards so the
        # recorded outgoing sequence reflects only the scenario under test.
        m.register()
        await asyncio.wait_for(run_scenario(m, _legit_peer_only()), timeout=6)
        m.transport.sent.clear()
        record["pre_timeline"] = m.timeline_summary()
        record["pre_engine_cache"] = m.engine_id_cache_summary()
    else:
        record["pre_timeline"] = {}
        record["pre_engine_cache"] = {}

    before_timeline = m.timeline_summary()
    before_counters = stat_counters(m)
    try:
        result = await asyncio.wait_for(run_scenario(m, peer_logic), timeout=6)
        record["result"] = (str(result[0]), result[1])
    except asyncio.TimeoutError:
        record["result"] = ("TIMEOUT", None)
    record["post_timeline"] = m.timeline_summary()
    record["post_engine_cache"] = m.engine_id_cache_summary()
    record["msgid_cache_remaining"] = list(m.msgid_cache().keys())
    record["outgoing"] = summarize_outgoing(m)
    record["outgoing_count"] = len(m.outgoing())
    after = stat_counters(m)
    record["counter_deltas"] = {
        k: (after[k] - before_counters[k]) if isinstance(after[k], int) else "n/a"
        for k in after
    }
    await m.close()
    return record


def _legit_peer_only():
    def peer(manager, info, wire, seq):
        if info["engineID"] == b"" and info["userName"] == b"":
            return [discovery_report(info["msgID"], REAL_ENGINE)]
        return [legit_response(info)]
    return peer


def print_record(rec):
    print("=" * 78)
    print("SCENARIO:", rec["name"])
    print("  pre  timeline:", rec["pre_timeline"])
    print("  pre  engineIdCache:", rec["pre_engine_cache"])
    print("  result:", rec["result"])
    print("  post timeline:", rec["post_timeline"])
    print("  post engineIdCache:", rec["post_engine_cache"])
    print("  msgID cache left (should be empty):", rec["msgid_cache_remaining"])
    print("  counter deltas:", rec["counter_deltas"])
    print("  outgoing count:", rec.get("outgoing_count", len(rec["outgoing"])))
    print("  outgoing sequence (first 12):")
    for i, row in enumerate(rec["outgoing"][:12], 1):
        print(f"    {i}. level={row['level']:<7} flags={row['flags']} "
              f"engine={row['engineID']:<20} user={row['user']:<12} "
              f"boots={row['boots']} time={row['time']} msgID={row['msgID']}")
    if rec.get("outgoing_count", 0) > 12:
        print(f"    ... {rec['outgoing_count'] - 12} more (retry storm)")


# ---------------------------------------------------------------------------
# Phase A: first discovery, no trusted state
# ---------------------------------------------------------------------------

async def phase_a():
    records = []

    # A1: forged source address, forged engine ID in an unauthenticated Report.
    # The attacker only ever answers with its own noAuth Report; there is no
    # genuine agent. This isolates the effect of the forged Report itself.
    async def a1():
        def peer(manager, info, wire, seq):
            return [discovery_report(info["msgID"], FORGED_ENGINE, source=FORGED_ADDR)]
        return await execute("A1 first-discovery: Report from FORGED source/engine (noAuth)", peer)
    records.append(await a1())

    # A2: no matching probe (unsolicited) Report, then genuine discovery
    async def a2():
        def peer(manager, info, wire, seq):
            if seq == 1:
                # Inject an extra unsolicited Report with an unrelated msgID
                # alongside the genuine discovery Report.
                forged = v3msg.build_report(
                    info["msgID"] + 99999, FORGED_ENGINE, 1, 10,
                    v3msg.OID_UNKNOWN_ENGINE_ID,
                    context_engine_id=FORGED_ENGINE, flags=v3msg.FLAG_NOAUTH,
                )
                genuine = discovery_report(info["msgID"], REAL_ENGINE)[1]
                return [(FORGED_ADDR, forged), (PEER_ADDR, genuine)]
            return [legit_response(info)]
        return await execute("A2 first-discovery: unsolicited Report (no matching probe/msgID)", peer)
    records.append(await a2())

    # A3: Report with wrong msgID (probe in flight, but msgID does not match)
    # A3: a Report whose msgID matches no in-flight probe must be dropped
    # (dataMismatch) without touching trusted state; the genuine discovery
    # Report then completes discovery normally.
    async def a3():
        def peer(manager, info, wire, seq):
            if seq == 1:
                bad = v3msg.build_report(
                    info["msgID"] + 777, FORGED_ENGINE, 1, 10,
                    v3msg.OID_UNKNOWN_ENGINE_ID,
                    context_engine_id=FORGED_ENGINE, flags=v3msg.FLAG_NOAUTH,
                )
                genuine = discovery_report(info["msgID"], REAL_ENGINE)[1]
                loop = asyncio.get_running_loop()
                # Wrong-msgID Report first (no cache entry -> dataMismatch),
                # genuine Report on the following tick.
                loop.call_soon(manager.transport.deliver, loop, bad, PEER_ADDR)
                return [(PEER_ADDR, genuine)]
            return [legit_response(info)]
        return await execute("A3 first-discovery: Report with WRONG msgID then genuine", peer)
    records.append(await a3())

    # A4: duplicate genuine discovery Report (replay)
    async def a4():
        def peer(manager, info, wire, seq):
            if seq == 1:
                rpt = discovery_report(info["msgID"], REAL_ENGINE)[1]
                return [(PEER_ADDR, rpt), (PEER_ADDR, rpt)]
            return [legit_response(info)]
        return await execute("A4 first-discovery: DUPLICATE discovery Report", peer)
    records.append(await a4())

    # A5: late (stale) discovery Report arriving after the request already completed
    async def a5():
        state = {"late": None}

        def peer(manager, info, wire, seq):
            if seq == 1:
                state["late"] = discovery_report(info["msgID"], FORGED_ENGINE)[1]
                return [discovery_report(info["msgID"], REAL_ENGINE)]
            response = legit_response(info)
            # Schedule a late forged Report after the GET response, on next tick.
            loop = asyncio.get_running_loop()
            loop.call_soon(manager.transport.deliver, loop, state["late"], FORGED_ADDR)
            return [response]
        return await execute("A5 first-discovery: LATE forged Report after completion", peer)
    records.append(await a5())

    return records


# ---------------------------------------------------------------------------
# Phase B: trusted engine already known, re-synchronisation
# ---------------------------------------------------------------------------

async def phase_b():
    records = []

    # B1: noAuth notInTimeWindow Report from forged source claiming REAL engine
    async def b1():
        def peer(manager, info, wire, seq):
            if seq == 1:  # this seq counts the preload; first real call seq==2
                pass
            # preload consumes seq 1..2; the scenario run starts at seq 3
            if info["engineID"] == REAL_ENGINE and (info["flags"] & 0x03):
                rpt = v3msg.build_report(
                    info["msgID"], REAL_ENGINE, boots=99, engine_time=999999,
                    error_oid=v3msg.OID_NOT_IN_TIME_WINDOW,
                    context_engine_id=REAL_ENGINE, user_name=USER.encode(),
                    flags=v3msg.FLAG_NOAUTH,  # attacker cannot authenticate
                )
                return [(FORGED_ADDR, rpt)]
            return [legit_response(info)]
        return await execute(
            "B1 resync: noAuth notInTimeWindow from FORGED source (claims real engine)",
            peer, preload_trusted=True)
    records.append(await b1())

    # B2: authenticated wrong-digest Report (attacker key unknown to manager)
    async def b2():
        def peer(manager, info, wire, seq):
            if info["engineID"] == REAL_ENGINE and (info["flags"] & 0x03):
                rpt = v3msg.build_report(
                    info["msgID"], REAL_ENGINE, boots=1, engine_time=11,
                    error_oid=v3msg.OID_WRONG_DIGEST,
                    context_engine_id=REAL_ENGINE, user_name=USER.encode(),
                    flags=v3msg.FLAG_AUTH, auth_handler=AUTH, auth_key=FORGED_KEY,
                )
                return [(PEER_ADDR, rpt)]
            return [legit_response(info)]
        return await execute(
            "B2 resync: AUTH Report with WRONG digest (forged MAC)",
            peer, preload_trusted=True)
    records.append(await b2())

    # B3: noAuth Report with WRONG msgID during trusted phase
    async def b3():
        def peer(manager, info, wire, seq):
            if info["engineID"] == REAL_ENGINE and (info["flags"] & 0x03):
                rpt = v3msg.build_report(
                    info["msgID"] + 555, REAL_ENGINE, boots=1, engine_time=11,
                    error_oid=v3msg.OID_NOT_IN_TIME_WINDOW,
                    context_engine_id=REAL_ENGINE, user_name=USER.encode(),
                    flags=v3msg.FLAG_NOAUTH,
                )
                return [(PEER_ADDR, rpt)]
            return [legit_response(info)]
        return await execute(
            "B3 resync: noAuth Report with WRONG msgID",
            peer, preload_trusted=True)
    records.append(await b3())

    # B4: duplicate authenticated Report (replay of a valid-looking error)
    async def b4():
        def peer(manager, info, wire, seq):
            if info["engineID"] == REAL_ENGINE and (info["flags"] & 0x03):
                rpt = v3msg.build_report(
                    info["msgID"], REAL_ENGINE, boots=1, engine_time=11,
                    error_oid=v3msg.OID_NOT_IN_TIME_WINDOW,
                    context_engine_id=REAL_ENGINE, user_name=USER.encode(),
                    flags=v3msg.FLAG_AUTH, auth_handler=AUTH, auth_key=REAL_KEY,
                )
                return [(PEER_ADDR, rpt), (PEER_ADDR, rpt)]
            return [legit_response(info)]
        return await execute(
            "B4 resync: DUPLICATE authenticated notInTimeWindow Report",
            peer, preload_trusted=True)
    records.append(await b4())

    # B5: late noAuth Report arriving after the trusted GET already succeeded
    async def b5():
        state = {"late": None}

        def peer(manager, info, wire, seq):
            if info["engineID"] == REAL_ENGINE and (info["flags"] & 0x03):
                state["late"] = v3msg.build_report(
                    info["msgID"], FORGED_ENGINE, boots=7, engine_time=700,
                    error_oid=v3msg.OID_NOT_IN_TIME_WINDOW,
                    context_engine_id=FORGED_ENGINE, user_name=USER.encode(),
                    flags=v3msg.FLAG_NOAUTH,
                )
                loop = asyncio.get_running_loop()
                loop.call_soon(manager.transport.deliver, loop, state["late"], FORGED_ADDR)
            return [legit_response(info)]
        return await execute(
            "B5 resync: LATE noAuth Report after successful GET",
            peer, preload_trusted=True)
    records.append(await b5())

    return records


async def main():
    print("#" * 78)
    print("# PHASE A - FIRST DISCOVERY (no trusted state)")
    print("#" * 78)
    for rec in await phase_a():
        print_record(rec)
    print()
    print("#" * 78)
    print("# PHASE B - RE-SYNCHRONISATION (trusted engine timeline present)")
    print("#" * 78)
    for rec in await phase_b():
        print_record(rec)


if __name__ == "__main__":
    asyncio.run(main())
