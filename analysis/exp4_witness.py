from stix2matcher.matcher import match
from analysis.probe import obs, all_bindings

def mk(order):
    base = {
        "alpha": obs("observed-data--alpha", "2004-01-01T00:00:00Z",
                     "2004-01-01T00:00:00Z", 1, "a",
                     {"type": "indicator", "name": "hit", "confidence": 10}),
        "gamma": obs("observed-data--gamma", "2004-01-03T00:00:00Z",
                     "2004-01-03T00:00:00Z", 1, "g",
                     {"type": "indicator", "name": "hit", "confidence": 90}),
    }
    return [base[k] for k in order]

PAT = "[indicator:name='hit']"   # single comparison; BOTH SDOs match

for order in (["alpha", "gamma"], ["gamma", "alpha"]):
    observations = mk(order)
    bindings = all_bindings(PAT, observations)
    witness = match(PAT, observations, stix_version="2.0")
    print("input order :", order)
    print("  bindings  :", bindings)
    print("  witness   :", [(o["id"], next(iter(o["objects"].values()))["confidence"])
                            for o in witness])
    print()

print("Same two equally-true SDOs; the witness SDO flips with input order,")
print("so a returned SDO is 'a sufficient witness', never 'the unique hit'.")
