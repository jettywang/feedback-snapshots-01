"""Print a stable fingerprint of selected fixtures (subprocess helper).

Used by the reproducibility test to prove that a fresh interpreter with a
different PYTHONHASHSEED builds the same minimal expressions and inputs.
"""

import json

from tests.regression.generator import corpus

DEFAULT_FAMILIES = [
    "or-to-not-null",
    "projection-to-pipe",
    "projection-to-map",
    "extra-branch-not-null",
    "contrast-or-and",
]


def fingerprint(family_names, count=4):
    rows = []
    for name in family_names:
        for fixture in corpus(name, count=count):
            rows.append({
                "family": fixture.family,
                "seed": fixture.seed,
                "left": fixture.left,
                "right": fixture.right,
                "document": json.dumps(fixture.document, sort_keys=True),
            })
    return json.dumps(rows, sort_keys=True)


if __name__ == "__main__":
    import sys
    names = sys.argv[1:] or ["or-to-not-null", "projection-to-pipe",
                             "extra-branch-not-null",
                             "contrast-projection-map-nulls"]
    print(fingerprint(names))
