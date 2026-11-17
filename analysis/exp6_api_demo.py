from analysis.probe import obs
from analysis.contract_api import matches, witness, matched_sdo_index_set

def sdo_ids(observations, idxs):
    return [observations[i]["id"] for i in sorted(idxs)]

OR_OBS = [
    obs("observed-data--A", "2004-01-01T00:00:00Z", "2004-01-01T00:00:00Z", 1,
        "a", {"type": "person", "name": "alice", "age": 10}),
    obs("observed-data--B", "2004-01-02T00:00:00Z", "2004-01-02T00:00:00Z", 1,
        "b", {"type": "person", "name": "bob", "age": 17}),
    obs("observed-data--C", "2004-01-03T00:00:00Z", "2004-01-03T00:00:00Z", 1,
        "c", {"type": "person", "name": "carol", "age": 22}),
]

cases = [
    ("OR, alice hits both branches",
     "[person:name='alice'] OR [person:age<20]", OR_OBS),
    ("OR, disjoint branch hits",
     "[person:name='alice'] OR [person:name='carol']", OR_OBS),
    ("AND, disjoint SDOs required",
     "[person:name='alice'] AND [person:age>20]", OR_OBS),
]

for title, pat, data in cases:
    print("###", title)
    print("  pattern           :", pat)
    print("  (E) matches()     :", matches(pat, data))
    print("  (W) witness() SDO :", [o["id"] for o in witness(pat, data)])
    print("  (N) SDO index set :", sdo_ids(data, matched_sdo_index_set(pat, data)))
    print()

# REPEATS dedup granularity check
REP_OBS = [
    obs("observed-data--MULTI", "2004-01-01T00:00:00Z", "2004-01-01T00:00:10Z", 3,
        "x", {"type": "person", "age": 5}),
    obs("observed-data--S1", "2004-01-02T00:00:00Z", "2004-01-02T00:00:00Z", 1,
        "s", {"type": "person", "age": 6}),
]
PAT = "[person:age<20] REPEATS 3 TIMES"
print("### REPEATS 3, MULTI has number_observed=3 (3 instances)")
print("  pattern           :", PAT)
print("  (E) matches()     :", matches(PAT, REP_OBS))
print("  (W) witness() SDO :", [o["id"] for o in witness(PAT, REP_OBS)])
print("  (N) SDO index set :", sdo_ids(REP_OBS, matched_sdo_index_set(PAT, REP_OBS)))
print("  -> MULTI's 3 instances dedup to ONE sdo index:",
      sdo_ids(REP_OBS, matched_sdo_index_set(PAT, REP_OBS)))
