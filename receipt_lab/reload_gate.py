"""Separates the three moments an auditor must not conflate.

For every inbound event a receiver records:
  1. callback_entered: the watcher callback started (message received)
  2. reload_started:   the enforcer began reloading / applying the rule
  3. reload_finished:  the enforcer's in-memory model actually changed

A gate can block reloads, so a lab can observe a window where the event was
delivered and the callback even ran, but enforcement still returns the old
answer. That window is exactly where "notified" must not be claimed as "applied".
"""

import threading
import time


class Clock:
    def __init__(self):
        self.t0 = time.monotonic()

    def now(self):
        return round(time.monotonic() - self.t0, 6)


class ReloadGate:
    def __init__(self, node_id, clock, block_reloads=False, reload_delay=0.0):
        self.node_id = node_id
        self.clock = clock
        self.block_reloads = block_reloads
        self.reload_delay = reload_delay
        self.events = []
        self.timeline = []
        self._seen = set()           # dedupe key for typed events (idempotency check)
        self._lock = threading.RLock()

    def unblock(self):
        """Release a previously blocked receiver; queued/redelivered events now apply."""
        with self._lock:
            self.block_reloads = False
            self.timeline.append({
                "t": self.clock.now(), "node": self.node_id, "phase": "gate_unblocked",
                "event": "-", "seq": None, "rule": None,
            })

    def manual_full_reload(self, enforcer, reason="manual"):
        """A receiver-initiated full reload, recorded on the same timeline as callbacks."""
        with self._lock:
            self.timeline.append({
                "t": self.clock.now(), "node": self.node_id,
                "phase": f"reload_started:{reason}", "event": "full", "seq": None, "rule": None,
            })
        enforcer.load_policy()
        with self._lock:
            self.timeline.append({
                "t": self.clock.now(), "node": self.node_id,
                "phase": "reload_finished:manual", "event": "full", "seq": None, "rule": None,
            })

    def _record(self, phase, event):
        self.timeline.append({
            "t": self.clock.now(),
            "node": self.node_id,
            "phase": phase,
            "event": event.kind,
            "seq": event.seq,
            "rule": event.rule,
        })

    def generic_callback(self, enforcer, event):
        """Receiver wired the classic way: every signal triggers a full reload."""
        with self._lock:
            self._record("callback_entered", event)
            self.events.append(event)
            if self.block_reloads:
                self._record("reload_blocked", event)
                return
            self._record("reload_started", event)
        if self.reload_delay:
            time.sleep(self.reload_delay)
        enforcer.load_policy()
        with self._lock:
            self._record("reload_finished", event)

    def typed_callback(self, enforcer, event):
        """Receiver wired the WatcherEx way: apply the exact rule incrementally.

        The idempotency check deliberately runs *after* the block check, so a
        redelivery that arrived during the blocked window can still be applied
        once the gate opens; only genuinely applied rules join the dedupe set.
        """
        with self._lock:
            self._record("callback_entered", event)
            self.events.append(event)
            if self.block_reloads:
                self._record("apply_blocked", event)
                return
            key = (event.kind, event.ptype, tuple(event.rule or []))
            if key in self._seen:
                self._record("duplicate_ignored", event)
                return
            self._seen.add(key)
            self._record("apply_started", event)
        if self.reload_delay:
            time.sleep(self.reload_delay)
        if event.kind == "add":
            enforcer.add_policy_self(False, "p", event.ptype, [event.rule])
        elif event.kind == "remove":
            enforcer.remove_policy_self(False, "p", event.ptype, [event.rule])
        with self._lock:
            self._record("apply_finished", event)
