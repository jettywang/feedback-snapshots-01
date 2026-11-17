"""
Finite, runnable probes into stix2-matcher binding semantics.

Three levels of question a caller might ask of a pattern + observations:
  (E) existence         : does ANY satisfying binding exist?            -> bool
  (W) one witness       : give me ONE set of SDOs that proves it        -> list
  (N) full enumeration  : give me EVERY observation that hits           -> ???

This script prints what the library actually returns for each level so the
conclusions in the report are backed by real output, not assumptions.
"""
import json
from stix2matcher.matcher import Pattern, MatchListener, match

V = "2.0"


def obs(oid, first, last, n, obj_id, obj):
    return {
        "type": "observed-data",
        "id": oid,
        "first_observed": first,
        "last_observed": last,
        "number_observed": n,
        "objects": {obj_id: obj},
    }


def all_bindings(pattern, observations):
    """Reach into the listener to enumerate EVERY binding tuple the engine yields."""
    p = Pattern(pattern, V)
    ml = MatchListener(observations, stix_version=V)
    p.walk(ml)
    return list(ml.matched())


def witness_sdos(pattern, observations):
    """The supported public API: SDOs from the FIRST binding only."""
    return match(pattern, observations, stix_version=V)


def names(sdos):
    return [o.get("id") for o in sdos]


def show(title, pattern, observations):
    print("=" * 78)
    print(title)
    print("pattern :", pattern)
    print("obs ids :", [o["id"] for o in observations])
    bindings = all_bindings(pattern, observations)
    print("ALL binding tuples (obs indices; None = that branch not bound):")
    for b in bindings:
        print("   ", b)
    print("count of bindings           :", len(bings := bindings))
    flat = sorted({idx for t in bindings for idx in t if idx is not None})
    print("distinct obs indices covered:", flat)
    print("public match() witness SDOs :", names(witness_sdos(pattern, observations)))
    print("existence truthy?           :", bool(match(pattern, observations, stix_version=V)))
    print()
    return bindings
