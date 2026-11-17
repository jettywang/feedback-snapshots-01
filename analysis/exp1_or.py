from analysis.probe import obs, show, all_bindings, witness_sdos, names
from stix2matcher.matcher import match

# Three people across three SDOs.
OBS = [
    obs("observed-data--A", "2004-01-01T00:00:00Z", "2004-01-01T00:00:00Z", 1,
        "a0", {"type": "person", "name": "alice", "age": 10}),
    obs("observed-data--B", "2004-01-02T00:00:00Z", "2004-01-02T00:00:00Z", 1,
        "b0", {"type": "person", "name": "bob", "age": 17}),
    obs("observed-data--C", "2004-01-03T00:00:00Z", "2004-01-03T00:00:00Z", 1,
        "c0", {"type": "person", "name": "carol", "age": 22}),
]

# Pattern-level OR.  alice hits the LEFT branch only;
# carol hits the RIGHT branch only; nobody hits both branches.
show("EXP1-A: pattern OR, disjoint hits per branch",
     "[person:name='alice'] OR [person:name='carol']", OBS)

# Now an observation (alice) satisfies BOTH branches of an OR.
# This is the case where the engine deliberately drops two-sided bindings.
show("EXP1-B: pattern OR, one obs satisfies BOTH branches",
     "[person:name='alice'] OR [person:age<20]", OBS)

# Three-way OR, alice satisfies all three branches.
show("EXP1-C: three-way OR, alice satisfies every branch",
     "[person:name='alice'] OR [person:age<20] OR [person:name>'aaa']", OBS)
