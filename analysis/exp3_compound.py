from analysis.probe import obs, show

# Two SDOs, each containing BOTH a network traffic marker and an email marker
# in different cyber-observable objects.  Both observations can satisfy both
# sides of an AND (on different inner objects).
OBS = [
    {
        "type": "observed-data", "id": "observed-data--X",
        "first_observed": "2004-01-01T00:00:00Z",
        "last_observed": "2004-01-01T00:00:10Z", "number_observed": 1,
        "objects": {
            "x0": {"type": "network-traffic", "dst_port": 443},
            "x1": {"type": "email-addr", "value": "a@example.com"},
        },
    },
    {
        "type": "observed-data", "id": "observed-data--Y",
        "first_observed": "2004-02-01T00:00:00Z",
        "last_observed": "2004-02-01T00:00:10Z", "number_observed": 1,
        "objects": {
            "y0": {"type": "network-traffic", "dst_port": 443},
            "y1": {"type": "email-addr", "value": "b@example.com"},
        },
    },
]

# AND requires DISJOINT observations for the two branches.
# Even though each SDO alone contains both objects, _disjoint forbids binding
# the same SDO to both branches, so the only bindings are cross-SDO.
show("EXP3-A: AND across two SDOs that each contain both object types",
     "[network-traffic:dst_port=443] AND [email-addr:value LIKE '%@example.com']",
     OBS)

# FOLLOWEDBY: same disjoint rule, plus temporal ordering.
show("EXP3-B: FOLLOWEDBY (X in Jan precedes Y in Feb)",
     "[network-traffic:dst_port=443] FOLLOWEDBY [email-addr:value LIKE '%@example.com']",
     OBS)
