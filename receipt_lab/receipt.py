"""Receipt model: every claim is backed by a specific piece of evidence."""

from dataclasses import dataclass, field, asdict


@dataclass
class ChangeReceipt:
    change_id: str
    rule: list
    action: str                      # add | remove
    call_returned: object = None    # what the enforcer method returned / raised
    local_applied: bool = False     # proven by a local enforce() probe afterwards
    local_probe: dict = field(default_factory=dict)
    persisted: bool = False         # proven by store journal + post-read
    persistence_seq: int = None
    notified: bool = False          # broker accepted the publish (nothing more)
    publish_seq: int = None
    remote_callback_ran: bool = False     # receiver's watcher callback entered
    remote_applied: bool = False         # receiver's enforce() actually changed
    remote_probe: dict = field(default_factory=dict)
    gaps: list = field(default_factory=list)

    def verdict(self):
        """Human-readable, deliberately narrow wording."""
        if self.local_applied and self.persisted and self.remote_applied:
            return "PROVEN end-to-end on the observed nodes"
        if self.local_applied and self.persisted and self.remote_callback_ran:
            return "LOCAL + DURABLE + DELIVERED; remote application NOT proven"
        if self.local_applied and self.persisted:
            return "LOCAL + DURABLE only; no remote evidence"
        if self.persisted and not self.local_applied:
            return "DURABLE but local commit not proven (call failed before/within model update)"
        return "INCOMPLETE evidence"

    def to_dict(self):
        data = asdict(self)
        data["verdict"] = self.verdict()
        return data


def probe(node, sub, obj, act):
    return {"request": [sub, obj, act], "allowed": node.can(sub, obj, act)}
