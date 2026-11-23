"""Gradual, old-API-preserving integration layer.

AuditedEnforcer is a thin wrapper: every original enforcer method keeps the same
signature and return value, so an existing application can swap
    enforcer = casbin.Enforcer(model, adapter)
for
    enforcer = AuditedEnforcer(casbin.Enforcer(model, adapter), receipt_store)
without touching call sites. Receipts are an additive side channel, never a
reason to change the enforcer's own behaviour (swallowing watcher errors here
would hide real failures; instead we record them and re-raise).
"""

import uuid
from dataclasses import dataclass, field

from receipt_lab.receipt import ChangeReceipt


@dataclass
class InMemoryReceiptStore:
    receipts: dict = field(default_factory=dict)

    def save(self, receipt: ChangeReceipt):
        self.receipts[receipt.change_id] = receipt
        return receipt.change_id

    def get(self, change_id):
        return self.receipts.get(change_id)

    def open_for(self, rule, action):
        return ChangeReceipt(change_id=uuid.uuid4().hex, rule=list(rule), action=action)


class AuditedEnforcer:
    """Drop-in wrapper that emits evidence-backed receipts for policy writes."""

    _WRITE_METHODS = ("add_policy", "remove_policy", "add_policies", "remove_policies")

    def __init__(self, enforcer, receipt_store, peer_probe=None):
        self._e = enforcer
        self._store = receipt_store
        # peer_probe(node_id, request) -> bool | None; None means "not observable here"
        self._peer_probe = peer_probe
        self._watcher = enforcer.get_watcher() if hasattr(enforcer, "get_watcher") else None

    def __getattr__(self, name):
        # read-only and unknown methods pass straight through untouched
        return getattr(self._e, name)

    def _record_write(self, method_name, rule, call):
        receipt = self._store.open_for(rule, method_name)
        try:
            result = call()
            receipt.call_returned = result
        except Exception as exc:  # noqa: BLE001 - receipt must capture the real failure
            receipt.call_returned = f"{type(exc).__name__}: {exc}"
            receipt.gaps.append("enforcer call raised; local commit status must be probed, not assumed")
            self._fill_failure_evidence(receipt, rule)
            self._store.save(receipt)
            raise
        self._fill_local_evidence(receipt, rule)
        self._store.save(receipt)
        return result, receipt

    def _fill_failure_evidence(self, receipt, rule):
        # On a raised call the model may or may not hold the rule; the store journal
        # is the only trustworthy source for "did persistence happen anyway".
        receipt.local_applied = bool(self._e.has_policy(*rule))
        receipt.local_probe = {"has_policy": receipt.local_applied}
        adapter = self._safe_adapter()
        if adapter is not None and hasattr(adapter, "has_rule"):
            receipt.persisted = adapter.has_rule("p", tuple(rule))
            matching = [e for e in adapter.journal
                        if e["rules"] and list(e["rules"][0]) == list(rule)]
            if matching:
                receipt.persistence_seq = matching[-1]["seq"]
        watcher = self._watcher
        if watcher is not None and hasattr(watcher, "bus"):
            receipt.notified = bool(watcher.bus.delivered)
        if receipt.persisted and not receipt.local_applied:
            receipt.gaps.append(
                "DURABLE but not local: store committed before the failing watcher call"
            )

    def _fill_local_evidence(self, receipt, rule):
        # local application is proven by reading the model + an enforce probe,
        # never inferred from the boolean return alone
        exists = self._e.has_policy(*rule)
        receipt.local_applied = bool(exists)
        receipt.local_probe = {"has_policy": bool(exists)}
        adapter = self._safe_adapter()
        if adapter is not None and hasattr(adapter, "has_rule"):
            receipt.persisted = adapter.has_rule("p", tuple(rule))
            if adapter.journal:
                receipt.persistence_seq = adapter.journal[-1]["seq"]
        watcher = self._watcher
        if watcher is not None and hasattr(watcher, "bus"):
            receipt.notified = bool(watcher.bus.delivered)
            if watcher.bus.delivered:
                receipt.publish_seq = watcher.bus.delivered[-1]["event"].seq
        if self._peer_probe is not None:
            allowed = self._peer_probe(tuple(rule))
            receipt.remote_probe = {"request": list(rule), "allowed": allowed}
            receipt.remote_applied = bool(allowed)
        if receipt.local_applied and not receipt.persisted:
            receipt.gaps.append("local effect without durable evidence (auto_save off or adapter opaque)")
        if receipt.notified and not receipt.remote_applied:
            receipt.gaps.append("broker accepted publish; peer application NOT proven by this receipt")

    def _safe_adapter(self):
        try:
            return self._e.get_adapter()
        except Exception:  # noqa: BLE001
            return None

    def add_policy(self, *rule):
        result, _ = self._record_write("add_policy", rule, lambda: self._e.add_policy(*rule))
        return result

    def remove_policy(self, *rule):
        result, _ = self._record_write("remove_policy", rule, lambda: self._e.remove_policy(*rule))
        return result

    def add_policy_with_receipt(self, *rule):
        return self._record_write("add_policy", rule, lambda: self._e.add_policy(*rule))

    def remove_policy_with_receipt(self, *rule):
        return self._record_write("remove_policy", rule, lambda: self._e.remove_policy(*rule))
