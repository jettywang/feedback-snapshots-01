from analysis.probe import obs, all_bindings

# One SDO satisfies BOTH branches of an OR.
OBS = [
    obs("observed-data--A", "2004-01-01T00:00:00Z", "2004-01-01T00:00:00Z", 1,
        "a", {"type": "person", "name": "alice", "age": 10}),
    obs("observed-data--B", "2004-01-02T00:00:00Z", "2004-01-02T00:00:00Z", 1,
        "b", {"type": "person", "name": "bob", "age": 17}),
]
PAT = "[person:name='alice'] OR [person:age<20]"

bindings = all_bindings(PAT, OBS)
print("Pattern:", PAT)
print("Obs A (alice,age10) satisfies LEFT and RIGHT; Obs B (bob,age17) satisfies RIGHT only.")
print("Engine bindings (note: A appears once per branch, NEVER as (0,0) two-sided):")
for t in bindings:
    print("   ", t)
print()
# What naive "full enumeration" semantics would demand:
# For an OR, the mathematically complete set of satisfying branch-assignments
# for observation A includes the two-sided assignment {left:A, right:A}.
two_sided = [t for t in bindings if all(x is not None for x in t)]
print("Two-sided bindings present:", two_sided, "(empty by design)")
print()
# Even enumerating every tuple cannot reconstruct a two-sided assignment,
# because OR is implemented as an outer join with None placeholders only.
print("Distinct obs covered by unioning all tuples:",
      sorted({i for t in bindings for i in t if i is not None}))
print("=> Union gives the set of obs that satisfy AT LEAST ONE branch,")
print("   but loses WHICH branch(es) each satisfied. Turning off the")
print("   one-sided optimization would change binding cardinality, not just")
print("   expose hidden existing tuples.")
