"""Regression tests pinning the exact commit/notify/apply semantics the receipt
design must report on. They document what pycasbin 2.6.1 actually guarantees,
including two behaviours that are easy to assume away incorrectly."""

import asyncio
import inspect

import casbin
import pytest

from receipt_lab.async_memory_adapter import AsyncInstrumentedMemoryAdapter
from receipt_lab.controlled_watcher import Event
from receipt_lab.lab import MODEL_PATH, SEED, build_cluster
from receipt_lab.memory_adapter import InstrumentedMemoryAdapter

RULE = ["carol", "data3", "read"]
REQ = ("carol", "data3", "read")


def test_plain_enforcer_notify_failure_leaves_durable_but_not_local():
    store, bus, _, nodes = build_cluster(watcher_mode="generic")
    a, b = nodes["node-a"], nodes["node-b"]
    a.wire_generic_reload()
    b.wire_generic_reload()
    bus.publish_fail_on.add("generic")

    with pytest.raises(RuntimeError):
        a.enforcer.add_policy(*RULE)

    # counterintuitive: persistence happened before the failing notification
    assert store.has_rule("p", RULE)
    assert store.journal[-1]["ok"] is True
    # and the local in-memory commit never ran
    assert a.enforcer.has_policy(*RULE) is False
    assert a.can(*REQ) is False
    # nothing reached the broker or the peer
    assert bus.delivered == []
    assert b.gate.timeline == []


def test_synced_enforcer_defers_notify_until_after_local_commit():
    store, bus, _, nodes = build_cluster(
        watcher_mode="generic", enforcer_cls=casbin.SyncedEnforcer
    )
    a, b = nodes["node-a"], nodes["node-b"]
    a.wire_generic_reload()
    b.wire_generic_reload()
    bus.publish_fail_on.add("generic")

    with pytest.raises(RuntimeError):
        a.enforcer.add_policy(*RULE)

    # unlike the plain enforcer: local + durable already hold when the raise arrives
    assert a.enforcer.has_policy(*RULE) is True
    assert a.can(*REQ) is True
    assert store.has_rule("p", RULE)
    assert bus.delivered == []
    assert b.can(*REQ) is False


def test_async_enforcer_shares_plain_ordering():
    store = InstrumentedMemoryAdapter()
    for ptype, rule in SEED:
        store.add_policy(ptype, ptype, rule)
    e = casbin.AsyncEnforcer(MODEL_PATH, AsyncInstrumentedMemoryAdapter(store))
    coro = e.load_policy()
    asyncio.run(coro) if inspect.iscoroutine(coro) else coro

    from receipt_lab.controlled_watcher import ControlledWatcher, SignalBus

    bus = SignalBus()
    bus.publish_fail_on.add("generic")
    e.set_watcher(ControlledWatcher("async-a", bus, mode="generic"))

    with pytest.raises(RuntimeError):
        asyncio.run(e.add_policy(*RULE))

    assert store.has_rule("p", RULE)
    assert e.has_policy(*RULE) is False


def test_generic_redelivery_during_blocked_reload_is_not_remote_application():
    store, bus, _, nodes = build_cluster(watcher_mode="generic", block_reloads=True)
    a, b = nodes["node-a"], nodes["node-b"]
    a.wire_generic_reload()
    b.wire_generic_reload()

    assert a.enforcer.add_policy(*RULE) is True
    first = bus.delivered[0]["event"]
    bus.replay(first, "node-b")

    # two deliveries, zero applications
    assert sum(p["phase"] == "callback_entered" for p in b.gate.timeline) == 2
    assert b.can(*REQ) is False

    b.gate.unblock()
    b.gate.manual_full_reload(b.enforcer)
    assert b.can(*REQ) is True
    assert any(p["phase"] == "reload_finished:manual" for p in b.gate.timeline)


def test_typed_redelivery_is_idempotent_after_application():
    store, bus, _, nodes = build_cluster(watcher_mode="typed", block_reloads=True)
    a, b = nodes["node-a"], nodes["node-b"]
    a.wire_typed_apply()
    b.wire_typed_apply()

    assert a.enforcer.add_policy(*RULE) is True
    first = bus.delivered[0]["event"]
    bus.replay(first, "node-b")  # blocked, so not deduped yet
    assert b.can(*REQ) is False

    b.gate.unblock()
    bus.replay(first, "node-b")  # first real application
    assert b.can(*REQ) is True
    bus.replay(first, "node-b")  # genuine duplicate after application
    assert b.can(*REQ) is True
    assert sum(p["phase"] == "duplicate_ignored" for p in b.gate.timeline) == 1


def test_out_of_order_typed_events_cause_unprovable_divergence():
    store, bus, _, nodes = build_cluster(watcher_mode="typed")
    a, b = nodes["node-a"], nodes["node-b"]
    a.wire_typed_apply()
    b.wire_typed_apply()

    bus._subscribers.clear()
    a.enforcer.add_policy(*RULE)
    a.enforcer.remove_policy(*RULE)
    bus.subscribe("node-b", b.watcher.receive)

    bus.replay(Event("remove", "p", RULE, seq=2, origin="node-a"), "node-b")
    bus.replay(Event("add", "p", RULE, seq=1, origin="node-a"), "node-b")

    assert a.can(*REQ) is False      # authoritative: rule was removed
    assert b.can(*REQ) is True       # stale add applied last -> split brain
    assert store.has_rule("p", RULE) is False


def test_distributed_enforcer_persist_branch_is_broken_in_this_version():
    """Documents a real pycasbin 2.6.1 defect: DistributedEnforcer.add_policy_self
    references self.adapter, but SyncedEnforcer stores the adapter on self._e."""
    store, _, _, nodes = build_cluster(watcher_mode="typed")
    a = nodes["node-a"]
    with pytest.raises(TypeError):  # AttributeError inside, then botched str concat
        a.enforcer.add_policy_self(True, "p", "p", [["erin", "data5", "read"]])
    assert store.has_rule("p", ("erin", "data5", "read")) is False


def test_distributed_enforcer_local_only_branch_still_works():
    _, _, _, nodes = build_cluster(watcher_mode="typed")
    a = nodes["node-a"]
    affected = a.enforcer.add_policy_self(False, "p", "p", [["frank", "data6", "read"]])
    assert affected == [["frank", "data6", "read"]]
    assert a.enforcer.has_policy("frank", "data6", "read") is True


def test_audited_enforcer_keeps_old_api_and_records_failure_receipt():
    from receipt_lab.integration import AuditedEnforcer, InMemoryReceiptStore

    store, bus, _, nodes = build_cluster(watcher_mode="generic")
    a, b = nodes["node-a"], nodes["node-b"]
    a.wire_generic_reload()
    b.wire_generic_reload()
    receipt_store = InMemoryReceiptStore()
    audited = AuditedEnforcer(a.enforcer, receipt_store, peer_probe=lambda req: b.can(*req))

    # identical signature and boolean return as the raw enforcer
    assert audited.add_policy(*RULE) is True
    assert audited.enforce("alice", "data1", "read") is True
    healthy = list(receipt_store.receipts.values())[-1]
    assert healthy.verdict().startswith("PROVEN")

    bus.publish_fail_on.add("generic")
    with pytest.raises(RuntimeError):
        audited.add_policy("gina", "data10", "read")
    failed = list(receipt_store.receipts.values())[-1]
    assert failed.persisted is True
    assert failed.local_applied is False
    assert "DURABLE but not local" in failed.gaps[-1]
