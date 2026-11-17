from stix2matcher.matcher import Pattern, MatchListener, match
from analysis.probe import obs, show

V = "2.0"

def raw_instance_bindings(pattern, observations):
    """Walk with a listener but read the stack BEFORE matched() collapses
    inst_idx>0 to None, to show the underlying (obs_idx, inst_idx) pairs."""
    p = Pattern(pattern, V)
    ml = MatchListener(observations, stix_version=V)
    p.walk(ml)
    # top of stack is the generator of (obs_idx, inst_idx) tuples
    gen = ml._MatchListener__compute_stack[0]
    return list(gen)

# One SDO with number_observed=3 and three separate SDOs with number_observed=1.
OBS = [
    obs("observed-data--MULTI", "2004-01-01T00:00:00Z", "2004-01-01T00:00:10Z", 3,
        "x0", {"type": "person", "age": 5}),
    obs("observed-data--S1", "2004-01-02T00:00:00Z", "2004-01-02T00:00:00Z", 1,
        "s1", {"type": "person", "age": 6}),
    obs("observed-data--S2", "2004-01-03T00:00:00Z", "2004-01-03T00:00:00Z", 1,
        "s2", {"type": "person", "age": 7}),
    obs("observed-data--S3", "2004-01-04T00:00:00Z", "2004-01-04T00:00:00Z", 1,
        "s3", {"type": "person", "age": 8}),
]

PAT = "[person:age < 20] REPEATS 3 TIMES"

print("### Raw (obs_idx, inst_idx) instance bindings BEFORE matched() filtering")
raw = raw_instance_bindings(PAT, OBS)
for t in raw:
    print("   ", t)
print("raw binding count:", len(raw))
print()
b = show("EXP2: REPEATS 3 over one number_observed=3 SDO + three single SDOs", PAT, OBS)

# Distinct SDOs if the caller unions all bindings vs. just the first.
union_idx = sorted({i for tup in b for i in tup if i is not None})
print("union of distinct obs indices over ALL bindings:", union_idx)
print("public match() returns only first binding's SDOs:",
      [o['id'] for o in match(PAT, OBS, stix_version=V)])
