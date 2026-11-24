from __future__ import annotations

import threading
import time

from dynaconf import Dynaconf, Validator, ValidationError
from dynaconf.transaction import TransactionManager

# Approved baseline that readers must keep seeing until a full record passes.
settings = Dynaconf(
    environments=False,
    ITEM_ONE="v1",
    ITEM_TWO="v1",
    validators=[
        Validator(
            "ITEM_TWO", must_exist=True, condition=lambda v: v != "bad"
        )
    ],
)
manager = TransactionManager(settings)

observations = []
stop = threading.Event()


def reader(name):
    """Readers may only observe a complete, validated generation."""
    while not stop.is_set():
        with manager.consistent_read() as view:
            observations.append((name, view("ITEM_ONE"), view("ITEM_TWO")))
        time.sleep(0.002)


threads = [threading.Thread(target=reader, args=(f"r{i}",)) for i in range(4)]
for t in threads:
    t.start()

# In-memory "loader": write the first item, pause so readers run, then hand a
# value that the validator rejects for the second item.
tx = manager.begin()
tx.set("ITEM_ONE", "v2")
time.sleep(0.05)  # readers must still see the approved (v1, v1) record
tx.set("ITEM_TWO", "bad")
try:
    tx.commit(validate="all")
except ValidationError as exc:
    print("candidate rejected:", str(exc).split(" in env")[0])

time.sleep(0.03)

# A valid full record should now become visible atomically.
with manager.transaction() as ok:
    ok.set("ITEM_ONE", "v3")
    ok.set("ITEM_TWO", "v3")
time.sleep(0.03)
stop.set()
for t in threads:
    t.join()

distinct = sorted({(one, two) for _, one, two in observations})
print("distinct (ITEM_ONE, ITEM_TWO) pairs readers observed:")
for pair in distinct:
    print("  ", pair)

leaked = [
    o for o in observations if (o[1], o[2]) not in {("v1", "v1"), ("v3", "v3")}
]
print("torn/invalid reads:", len(leaked))
print("final live values:", settings.ITEM_ONE, settings.ITEM_TWO)
print("diagnostic history:")
for rec in manager.history():
    print("  gen", rec["generation"], rec["status"], rec["changes"], rec["error"])
