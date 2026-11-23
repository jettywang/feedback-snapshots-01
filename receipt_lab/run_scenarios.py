"""Runnable evidence for the auditable-receipt design.

Scenario A: one write whose persistence succeeds but whose watcher notification
fails, repeated on the plain, synced and async enforcers.
Scenario B: one redelivered (duplicate) event while the receiver has not yet
finished reloading, once over a generic watcher (full reload) and once over a
typed WatcherEx (incremental apply).
"""

import json
import os

import casbin

from receipt_lab.async_memory_adapter import AsyncInstrumentedMemoryAdapter
from receipt_lab.controlled_watcher import Event
from receipt_lab.lab import MODEL_PATH, SEED, build_cluster
from receipt_lab.memory_adapter import InstrumentedMemoryAdapter
from receipt_lab.receipt import ChangeReceipt, probe

RULE = ["carol", "data3", "read"]
REQ = ("carol", "data3", "read")


def _header(title):
    line = "=" * 78
    print(f"\n{line}\n{title}\n{line}")


def _show_nodes(a, b):
    print(f"  enforce{REQ}  node-a={a.can(*REQ)!s:<5}  node-b={b.can(*REQ)!s:<5}")
    print(f"  node-a model has rule: {a.enforcer.has_policy(*RULE)}")
    print(f"  node-b model has rule: {b.enforcer.has_policy(*RULE)}")


def scenario_a_plain():
    _header("A1  PLAIN Enforcer  |  store OK, broker publish FAILS")
    store, bus, clock, nodes = build_cluster(watcher_mode="generic")
    a, b = nodes["node-a"], nodes["node-b"]
    a.wire_generic_reload()
    b.wire_generic_reload()
    bus.publish_fail_on.add("generic")

    call, raised = None, None
    try:
        call = a.enforcer.add_policy(*RULE)
    except Exception as exc:  # noqa: BLE001 - we want the propagated failure on record
        raised = f"{type(exc).__name__}: {exc}"

    receipt = ChangeReceipt(change_id="A1", rule=RULE, action="add",
                            call_returned=raised or call)
    receipt.local_probe = probe(a, *REQ)
    receipt.remote_probe = probe(b, *REQ)
    receipt.local_applied = receipt.local_probe["allowed"]
    receipt.remote_applied = receipt.remote_probe["allowed"]
    receipt.persistence_seq = store.journal[-1]["seq"] if store.journal else None
    receipt.persisted = store.has_rule("p", RULE)
    receipt.notified = bool(bus.delivered)
    receipt.remote_callback_ran = any(p["phase"] == "callback_entered" for p in b.gate.timeline)
    if raised:
        receipt.gaps.append(
            "call raised BEFORE model.add_policy: durable + no local effect + no notification"
        )
    print(f"  add_policy() result : raised -> {raised}")
    print(f"  store journal      : {store.journal}")
    print(f"  broker deliveries  : {bus.delivered}")
    _show_nodes(a, b)
    print(f"  node-b timeline    : {b.gate.timeline}")
    print(f"  RECEIPT verdict    : {receipt.verdict()}")
    return receipt


def scenario_a_synced():
    _header("A2  SYNCED Enforcer  |  store OK, broker publish FAILS (notify deferred)")
    store, bus, clock, nodes = build_cluster(
        watcher_mode="generic", enforcer_cls=casbin.SyncedEnforcer
    )
    a, b = nodes["node-a"], nodes["node-b"]
    a.wire_generic_reload()
    b.wire_generic_reload()
    bus.publish_fail_on.add("generic")

    call, raised = None, None
    try:
        call = a.enforcer.add_policy(*RULE)
    except Exception as exc:  # noqa: BLE001
        raised = f"{type(exc).__name__}: {exc}"

    receipt = ChangeReceipt(change_id="A2", rule=RULE, action="add",
                            call_returned=raised or call)
    receipt.local_probe = probe(a, *REQ)
    receipt.remote_probe = probe(b, *REQ)
    receipt.local_applied = receipt.local_probe["allowed"]
    receipt.remote_applied = receipt.remote_probe["allowed"]
    receipt.persistence_seq = store.journal[-1]["seq"] if store.journal else None
    receipt.persisted = store.has_rule("p", RULE)
    receipt.notified = bool(bus.delivered)
    receipt.remote_callback_ran = any(p["phase"] == "callback_entered" for p in b.gate.timeline)
    if raised:
        receipt.gaps.append(
            "return value True means local+durable; the raise arrives AFTER unlock, "
            "so callers that only catch exceptions wrongly assume the write failed"
        )
    print(f"  add_policy() result : returned={call}, then raised -> {raised}")
    print(f"  store journal      : {store.journal}")
    print(f"  broker deliveries  : {bus.delivered}")
    _show_nodes(a, b)
    print(f"  node-b timeline    : {b.gate.timeline}")
    print(f"  RECEIPT verdict    : {receipt.verdict()}")
    return receipt


def scenario_a_async():
    _header("A3  ASYNC Enforcer  |  store OK, broker publish FAILS")
    store = InstrumentedMemoryAdapter()
    for ptype, rule in SEED:
        store.add_policy(ptype, ptype, rule)
    store.journal.clear()
    store.sequence = 0
    e = casbin.AsyncEnforcer(MODEL_PATH, AsyncInstrumentedMemoryAdapter(store))
    import inspect

    if inspect.iscoroutinefunction(e.load_policy):
        import asyncio

        asyncio.run(e.load_policy())
    else:
        e.load_policy()

    from receipt_lab.controlled_watcher import ControlledWatcher, SignalBus
    from receipt_lab.reload_gate import Clock

    bus = SignalBus()
    clock = Clock()
    watcher = ControlledWatcher("async-a", bus, mode="generic")
    e.set_watcher(watcher)
    bus.publish_fail_on.add("generic")

    import asyncio

    async def drive():
        call, raised = None, None
        try:
            call = await e.add_policy(*RULE)
        except Exception as exc:  # noqa: BLE001
            raised = f"{type(exc).__name__}: {exc}"
        return call, raised

    call, raised = asyncio.run(drive())
    local_allowed = bool(e.enforce(*REQ))
    receipt = ChangeReceipt(change_id="A3", rule=RULE, action="add",
                            call_returned=raised or call)
    receipt.local_applied = local_allowed
    receipt.local_probe = {"request": list(REQ), "allowed": local_allowed}
    receipt.persisted = store.has_rule("p", RULE)
    receipt.persistence_seq = store.journal[-1]["seq"] if store.journal else None
    receipt.notified = bool(bus.delivered)
    receipt.gaps.append("same ordering as plain enforcer, awaited: durable, not local, not notified")
    print(f"  await add_policy() : raised -> {raised}")
    print(f"  store journal      : {store.journal}")
    print(f"  local model has rule: {e.has_policy(*RULE)}  (diverged from its own store)")
    print(f"  RECEIPT verdict    : {receipt.verdict()}")
    return receipt


def scenario_b_generic():
    _header("B1  GENERIC watcher  |  duplicate signal while receiver reload is blocked")
    store, bus, clock, nodes = build_cluster(watcher_mode="generic", block_reloads=True)
    a, b = nodes["node-a"], nodes["node-b"]
    a.wire_generic_reload()
    b.wire_generic_reload()

    returned = a.enforcer.add_policy(*RULE)
    first_event = bus.delivered[0]["event"]
    print(f"  add_policy() -> {returned}; broker published event #{first_event.seq}")
    print(f"  -- window: node-b callback ran but reload is blocked --")
    _show_nodes(a, b)
    print(f"  node-b timeline (1): {b.gate.timeline}")

    bus.replay(first_event, "node-b")  # broker redelivery -> duplicate
    print(f"  -- after redelivery of event #{first_event.seq}, still blocked --")
    _show_nodes(a, b)
    print(f"  node-b timeline (2): {b.gate.timeline}")

    b.gate.unblock()
    b.gate.manual_full_reload(b.enforcer)  # receiver eventually completes a full reload itself
    print(f"  -- receiver unblocked and finished a full LoadPolicy() --")
    _show_nodes(a, b)
    print(f"  node-b timeline (3): {b.gate.timeline}")

    receipt = ChangeReceipt(change_id="B1", rule=RULE, action="add", call_returned=returned)
    receipt.local_applied = a.can(*REQ)
    receipt.local_probe = probe(a, *REQ)
    receipt.remote_probe = probe(b, *REQ)
    receipt.remote_applied = receipt.remote_probe["allowed"]
    receipt.persisted = store.has_rule("p", RULE)
    receipt.notified = len(bus.delivered) >= 1
    receipt.publish_seq = first_event.seq
    receipt.remote_callback_ran = sum(
        1 for p in b.gate.timeline if p["phase"] == "callback_entered"
    )
    receipt.gaps.append(
        "two callback_entered records prove delivery/redelivery only; until reload_finished "
        "the duplicate cannot be told apart from the original and remote enforce() stays False"
    )
    print(f"  RECEIPT verdict    : {receipt.verdict()}")
    return receipt


def scenario_b_typed():
    _header("B2  TYPED WatcherEx  |  duplicate typed event while receiver apply is blocked")
    store, bus, clock, nodes = build_cluster(watcher_mode="typed", block_reloads=True)
    a, b = nodes["node-a"], nodes["node-b"]
    a.wire_typed_apply()
    b.wire_typed_apply()

    returned = a.enforcer.add_policy(*RULE)
    first_event = bus.delivered[0]["event"]
    print(f"  add_policy() -> {returned}; typed event {first_event}")
    print(f"  -- window: apply blocked on node-b --")
    _show_nodes(a, b)
    print(f"  node-b timeline (1): {b.gate.timeline}")

    bus.replay(first_event, "node-b")
    print(f"  -- redelivery of identical typed event, still blocked --")
    print(f"  node-b timeline (2): {b.gate.timeline}")

    b.gate.unblock()
    bus.replay(first_event, "node-b")  # now unblocked: first real application
    print(f"  -- unblocked and one redelivery is applied --")
    _show_nodes(a, b)
    print(f"  node-b timeline (3): {b.gate.timeline}")

    receipt = ChangeReceipt(change_id="B2", rule=RULE, action="add", call_returned=returned)
    receipt.local_applied = a.can(*REQ)
    receipt.local_probe = probe(a, *REQ)
    receipt.remote_probe = probe(b, *REQ)
    receipt.remote_applied = receipt.remote_probe["allowed"]
    receipt.persisted = store.has_rule("p", RULE)
    receipt.notified = True
    receipt.publish_seq = first_event.seq
    receipt.remote_callback_ran = sum(
        1 for p in b.gate.timeline if p["phase"] == "callback_entered"
    )
    receipt.gaps.append(
        "duplicate_ignored exists only because this receiver keeps an idempotency set; "
        "a broker redelivery without such a set (or an out-of-order remove/add) is not "
        "provably safe from the receipt alone"
    )
    print(f"  RECEIPT verdict    : {receipt.verdict()}")
    return receipt


def scenario_b_reorder():
    _header("B3  TYPED watcher  |  out-of-order add then remove (remove delivered first)")
    store, bus, clock, nodes = build_cluster(watcher_mode="typed")
    a, b = nodes["node-a"], nodes["node-b"]
    a.wire_typed_apply()
    b.wire_typed_apply()

    # node-a commits add then remove directly against itself and the shared store,
    # with the broker detached so setup traffic cannot reach node-b
    bus._subscribers.clear()
    assert a.enforcer.add_policy(*RULE) is True
    assert a.enforcer.remove_policy(*RULE) is True
    bus.subscribe("node-b", b.watcher.receive)

    # broker now redelivers the two already-published events in reverse order
    add_ev = Event("add", "p", RULE, seq=1, origin="node-a")
    rem_ev = Event("remove", "p", RULE, seq=2, origin="node-a")
    bus.replay(rem_ev, "node-b")
    bus.replay(add_ev, "node-b")
    print(f"  node-a final enforce{REQ}: {a.can(*REQ)} (rule removed, matches store)")
    print(f"  node-b final enforce{REQ}: {b.can(*REQ)}  <- True means stale add won")
    print(f"  node-b timeline: {b.gate.timeline}")
    print("  DIAGNOSIS: events carry no version/vector clock; the receiver cannot know")
    print("             the add is stale. Missing evidence = a monotonic store version per rule.")
    return {"node_a": a.can(*REQ), "node_b": b.can(*REQ), "timeline": b.gate.timeline}


def main():
    receipts = [
        scenario_a_plain(),
        scenario_a_synced(),
        scenario_a_async(),
        scenario_b_generic(),
        scenario_b_typed(),
    ]
    scenario_b_reorder()
    os.makedirs("receipt_lab/output", exist_ok=True)
    with open("receipt_lab/output/receipts.json", "w") as fh:
        json.dump([r.to_dict() for r in receipts], fh, indent=2, ensure_ascii=False)
    print("\nreceipts written to receipt_lab/output/receipts.json")


if __name__ == "__main__":
    main()
