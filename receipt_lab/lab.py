"""Two-node lab wiring: shared store, independent enforcers, controllable bus."""

import os

import casbin

from receipt_lab.controlled_watcher import ControlledWatcher, SignalBus
from receipt_lab.memory_adapter import InstrumentedMemoryAdapter
from receipt_lab.reload_gate import Clock, ReloadGate

MODEL_PATH = os.path.join("examples", "rbac_model.conf")
SEED = [
    ("p", ["alice", "data1", "read"]),
    ("p", ["bob", "data2", "write"]),
    ("p", ["data2_admin", "data2", "read"]),
    ("p", ["data2_admin", "data2", "write"]),
    ("g", ["alice", "data2_admin"]),
]


class PolicyNode:
    def __init__(self, node_id, store, bus, clock, enforcer_cls=casbin.Enforcer,
                 watcher_mode="generic", block_reloads=False, reload_delay=0.0):
        self.node_id = node_id
        self.enforcer = enforcer_cls(MODEL_PATH, store)
        self.watcher = ControlledWatcher(node_id, bus, mode=watcher_mode)
        self.enforcer.set_watcher(self.watcher)
        self.gate = ReloadGate(node_id, clock, block_reloads=block_reloads,
                               reload_delay=reload_delay)
        bus.subscribe(node_id, self.watcher.receive)

    def wire_generic_reload(self):
        """Classic deployment: any signal => full LoadPolicy()."""
        self.watcher.set_update_callback(
            lambda event: self.gate.generic_callback(self.enforcer, event)
        )

    def wire_typed_apply(self):
        """WatcherEx deployment: typed event => incremental add/remove rule."""
        self.watcher.set_update_callback(
            lambda event: self.gate.generic_callback(self.enforcer, event)
        )
        self.watcher.set_update_for_add_policy_callback(
            lambda event: self.gate.typed_callback(self.enforcer, event)
        )

    def can(self, sub, obj, act):
        return bool(self.enforcer.enforce(sub, obj, act))

    def rules(self):
        return sorted([list(r) for r in self.enforcer.get_policy()])


def build_cluster(seed=True, watcher_mode="generic", enforcer_cls=None,
                  block_reloads=False, reload_delay=0.0):
    # Typed receivers apply rules incrementally through add_policy_self, which
    # only DistributedEnforcer exposes; generic-reload clusters default to Enforcer.
    if enforcer_cls is None:
        enforcer_cls = casbin.DistributedEnforcer if watcher_mode == "typed" else casbin.Enforcer
    store = InstrumentedMemoryAdapter()
    if seed:
        for ptype, rule in SEED:
            store.add_policy(ptype, ptype, rule)
        store.journal.clear()
        store.sequence = 0
    bus = SignalBus()
    clock = Clock()
    nodes = {}
    for node_id in ("node-a", "node-b"):
        node = PolicyNode(node_id, store, bus, clock, enforcer_cls=enforcer_cls,
                          watcher_mode=watcher_mode, block_reloads=block_reloads,
                          reload_delay=reload_delay)
        nodes[node_id] = node
    return store, bus, clock, nodes
