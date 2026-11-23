"""Async facade over the same shared in-memory store.

Both the sync enforcer on node-a and the async enforcer can point at one
InstrumentedMemoryAdapter; this class just awaits the identical synchronous
operations so AsyncEnforcer's type checks accept it.
"""

from casbin.persist.adapters.asyncio.adapter import AsyncAdapter
from casbin.persist.adapters.asyncio.batch_adapter import AsyncBatchAdapter
from casbin.persist.adapters.asyncio.update_adapter import AsyncUpdateAdapter


class AsyncInstrumentedMemoryAdapter(AsyncBatchAdapter, AsyncUpdateAdapter, AsyncAdapter):
    def __init__(self, inner):
        self.inner = inner

    async def load_policy(self, model):
        return self.inner.load_policy(model)

    async def save_policy(self, model):
        return self.inner.save_policy(model)

    async def add_policy(self, sec, ptype, rule):
        return self.inner.add_policy(sec, ptype, rule)

    async def add_policies(self, sec, ptype, rules):
        return self.inner.add_policies(sec, ptype, rules)

    async def remove_policy(self, sec, ptype, rule):
        return self.inner.remove_policy(sec, ptype, rule)

    async def remove_policies(self, sec, ptype, rules):
        return self.inner.remove_policies(sec, ptype, rules)

    async def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        return self.inner.remove_filtered_policy(sec, ptype, field_index, *field_values)

    async def update_policy(self, sec, ptype, old_rule, new_rule):
        return self.inner.update_policy(sec, ptype, old_rule, new_rule)

    async def update_policies(self, sec, ptype, old_rules, new_rules):
        return self.inner.update_policies(sec, ptype, old_rules, new_rules)

    async def update_filtered_policies(self, sec, ptype, new_rules, field_index, *field_values):
        return self.inner.update_filtered_policies(
            sec, ptype, new_rules, field_index, *field_values
        )
