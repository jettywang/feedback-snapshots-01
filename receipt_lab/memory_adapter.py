"""In-memory persistence layer for the receipt lab.

One instance is shared by both local enforcers, so it plays the role of the
central policy store (the thing a real SQL/Redis adapter would point at). Every
mutation is appended to an append-only journal, which is the only durable
evidence available to an auditor. Failures can be injected to model a store
outage; they happen *before* any state change so a failed call leaves no trace
beyond its own journal entry.
"""

import threading

from casbin.persist.adapter import Adapter, load_policy_line
from casbin.persist.batch_adapter import BatchAdapter
from casbin.persist.update_adapter import UpdateAdapter


class InjectedStoreError(RuntimeError):
    """Raised by test configuration to simulate a persistence failure."""


class InstrumentedMemoryAdapter(BatchAdapter, UpdateAdapter):
    def __init__(self):
        self._rules = set()
        self._lock = threading.RLock()
        self.journal = []
        self.fail_next = 0
        self.sequence = 0

    def _tick(self, op, sec, ptype, rules, ok, detail=""):
        self.sequence += 1
        entry = {
            "seq": self.sequence,
            "op": op,
            "sec": sec,
            "ptype": ptype,
            "rules": [list(r) for r in rules],
            "ok": ok,
            "detail": detail,
        }
        self.journal.append(entry)
        return entry

    def _maybe_fail(self, op):
        if self.fail_next > 0:
            self.fail_next -= 1
            raise InjectedStoreError(f"injected failure during {op}")

    @staticmethod
    def _key(ptype, rule):
        return (ptype, tuple(rule))

    def load_policy(self, model):
        with self._lock:
            snapshot = sorted(self._rules)
        for ptype, rule in snapshot:
            load_policy_line(", ".join([ptype, *rule]), model)

    def save_policy(self, model):
        with self._lock:
            self._maybe_fail("save_policy")
            new_rules = set()
            for sec in ("p", "g"):
                for ptype, ast in model.model.get(sec, {}).items():
                    for rule in ast.policy:
                        new_rules.add(self._key(ptype, rule))
            self._rules = new_rules
            self._tick("save_policy", "-", "-", [list(r) for _, r in sorted(new_rules)], True)

    def add_policy(self, sec, ptype, rule):
        with self._lock:
            try:
                self._maybe_fail("add_policy")
            except InjectedStoreError as exc:
                self._tick("add_policy", sec, ptype, [rule], False, str(exc))
                raise
            existed = self._key(ptype, rule) in self._rules
            self._rules.add(self._key(ptype, rule))
            self._tick("add_policy", sec, ptype, [rule], True,
                       "noop-already-present" if existed else "stored")
            return not existed

    def add_policies(self, sec, ptype, rules):
        with self._lock:
            try:
                self._maybe_fail("add_policies")
            except InjectedStoreError as exc:
                self._tick("add_policies", sec, ptype, rules, False, str(exc))
                raise
            added = []
            for rule in rules:
                if self._key(ptype, rule) not in self._rules:
                    self._rules.add(self._key(ptype, rule))
                    added.append(rule)
            self._tick("add_policies", sec, ptype, rules, True,
                       f"{len(added)} new of {len(rules)} requested")
            return True

    def remove_policy(self, sec, ptype, rule):
        with self._lock:
            try:
                self._maybe_fail("remove_policy")
            except InjectedStoreError as exc:
                self._tick("remove_policy", sec, ptype, [rule], False, str(exc))
                raise
            existed = self._rules.discard(self._key(ptype, rule)) is not None
            self._tick("remove_policy", sec, ptype, [rule], True,
                       "deleted" if existed else "noop-absent")
            return True

    def remove_policies(self, sec, ptype, rules):
        with self._lock:
            try:
                self._maybe_fail("remove_policies")
            except InjectedStoreError as exc:
                self._tick("remove_policies", sec, ptype, rules, False, str(exc))
                raise
            for rule in rules:
                self._rules.discard(self._key(ptype, rule))
            self._tick("remove_policies", sec, ptype, rules, True)
            return True

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        with self._lock:
            values = field_values[0] if field_values and isinstance(field_values[0], (list, tuple)) else field_values
            victims = []
            for stored_ptype, rule in list(self._rules):
                if stored_ptype != ptype:
                    continue
                matched = True
                for offset, value in enumerate(values):
                    if value not in ("", None) and rule[field_index + offset] != value:
                        matched = False
                        break
                if matched:
                    victims.append(rule)
                    self._rules.discard(self._key(stored_ptype, rule))
            self._tick("remove_filtered_policy", sec, ptype, victims, True,
                       f"{len(victims)} deleted")
            return True

    def update_policy(self, sec, ptype, old_rule, new_rule):
        with self._lock:
            try:
                self._maybe_fail("update_policy")
            except InjectedStoreError as exc:
                self._tick("update_policy", sec, ptype, [old_rule], False, str(exc))
                raise
            self._rules.discard(self._key(ptype, old_rule))
            self._rules.add(self._key(ptype, new_rule))
            self._tick("update_policy", sec, ptype, [old_rule, new_rule], True)
            return True

    def update_policies(self, sec, ptype, old_rules, new_rules):
        with self._lock:
            for old_rule, new_rule in zip(old_rules, new_rules):
                self._rules.discard(self._key(ptype, old_rule))
                self._rules.add(self._key(ptype, new_rule))
            self._tick("update_policies", sec, ptype,
                       [list(r) for r in old_rules] + [list(r) for r in new_rules], True)
            return True

    def update_filtered_policies(self, sec, ptype, new_rules, field_index, *field_values):
        with self._lock:
            old_rules = [list(rule) for _, rule in sorted(self._rules)]
            self._tick("update_filtered_policies", sec, ptype, old_rules, True)
            return old_rules

    def snapshot_rules(self):
        with self._lock:
            return sorted([list(rule) for _, rule in self._rules])

    def has_rule(self, ptype, rule):
        with self._lock:
            return self._key(ptype, tuple(rule)) in self._rules
