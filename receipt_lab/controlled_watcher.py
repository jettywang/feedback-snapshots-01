"""Controllable watcher double and its in-process message bus.

The bus stands in for Redis/NATS/Kafka. A publish is "the sender handed the
message to the broker"; a delivered callback is "the receiver's watcher got
the message". Neither one is evidence that the receiver *applied* anything:
application is a separate, independently recorded step (see reload_gate.py).
"""

import itertools
import threading
import time


class Event:
    def __init__(self, kind, ptype=None, rule=None, seq=None, origin=None):
        self.kind = kind          # "generic" | "add" | "remove" | "save"
        self.ptype = ptype
        self.rule = list(rule) if rule is not None else None
        self.seq = seq
        self.origin = origin      # node id that published

    def __repr__(self):
        body = self.rule if self.rule is not None else ""
        return f"Event(#{self.seq} {self.kind} {self.ptype} {body} from={self.origin})"


class SignalBus:
    def __init__(self):
        self._counter = itertools.count(1)
        self._subscribers = {}          # node_id -> callback
        self._lock = threading.RLock()
        self.delivered = []             # broker-side delivery log (delivered, not applied)
        self.publish_fail_on = set()    # event kinds whose next publish must raise
        self.delivery_fail_on = set()   # event kinds whose broker delivery must raise
        self.held = []                  # messages held back instead of delivered (outage window)

    def subscribe(self, node_id, callback):
        with self._lock:
            self._subscribers[node_id] = callback

    def publish(self, event, sender_id):
        event.seq = next(self._counter)
        event.origin = sender_id
        if event.kind in self.publish_fail_on:
            raise RuntimeError(f"broker rejected publish of {event.kind} (event #{event.seq})")
        with self._lock:
            targets = [(nid, cb) for nid, cb in self._subscribers.items() if nid != sender_id]
        for node_id, callback in targets:
            if event.kind in self.delivery_fail_on:
                self.delivered.append({"event": event, "node": node_id, "ok": False})
                raise RuntimeError(f"broker could not deliver {event} to {node_id}")
            self.delivered.append({"event": event, "node": node_id, "ok": True})
            callback(event)
        return event.seq

    def replay(self, event, node_id):
        """Redeliver an already-published event to one node (broker retry / duplicate)."""
        callback = self._subscribers[node_id]
        self.delivered.append({"event": event, "node": node_id, "ok": True, "replay": True})
        callback(event)

    def hold_next(self, flag=True):
        """When holding, subscribers receive nothing; messages queue in self.held."""
        self._holding = flag


class ControlledWatcher:
    """Implements both Watcher (generic update) and WatcherEx (typed events).

    mode="generic": enforcer typed calls collapse onto update(), like a basic
    Redis watcher that only knows "something changed, reload please".
    mode="typed":   update_for_add_policy / update_for_remove_policy carry the
    exact rule, like a WatcherEx deployment.
    """

    def __init__(self, node_id, bus, mode="generic"):
        self.node_id = node_id
        self.bus = bus
        self.mode = mode
        self.callback = None
        self.typed_callback = None
        self.publish_log = []
        self.held = False

    def close(self):
        pass

    def set_update_callback(self, callback):
        self.callback = callback

    def set_update_for_add_policy_callback(self, callback):
        self.typed_callback = callback

    def _publish(self, event):
        self.publish_log.append(event)
        return self.bus.publish(event, self.node_id)

    def update(self):
        return self._publish(Event("generic"))

    def update_for_add_policy(self, sec, ptype, *params):
        if self.mode == "generic" or self.typed_callback is None:
            return self.update()
        return self._publish(Event("add", ptype, params[0] if params else None))

    def update_for_add_policies(self, sec, ptype, *rules):
        if self.mode == "generic" or self.typed_callback is None:
            return self.update()
        return self._publish(Event("add", ptype, list(rules)))

    def update_for_remove_policy(self, sec, ptype, *params):
        if self.mode == "generic" or self.typed_callback is None:
            return self.update()
        if self.mode == "typed":
            return self._publish(Event("remove", ptype, params[0] if params else None))
        return self.update()

    def update_for_remove_policies(self, sec, ptype, *rules):
        if self.mode == "generic" or self.typed_callback is None:
            return self.update()
        return self._publish(Event("remove", ptype, list(rules)))

    def update_for_remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        return self.update()

    def receive(self, event):
        """Broker ingress: the watcher got a message and dispatches to its callback.

        This is the receive-side counterpart of publish(); it only proves the
        watcher accepted the message, not that the enforcer applied it.
        """
        if event.kind in ("add", "remove") and self.mode == "typed" and self.typed_callback:
            self.typed_callback(event)
        elif self.callback is not None:
            self.callback(event)

    def update_for_save_policy(self, model):
        return self._publish(Event("save"))
