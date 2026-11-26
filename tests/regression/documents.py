"""Plain-JSON document builders for the regression generator.

Each profile targets one combination of the hazards the generator must
respect: nulls inside list projections, missing object fields, and
values that drive boolean short-circuits.
"""

FALSE_VALUES = [None, False, "", [], {}]
TRUTHY_VALUES = [0, 1, -1, 2, "x", "y", [0], [1, 2], {"z": 1}, {"z": None}]
ANY_VALUES = FALSE_VALUES + TRUTHY_VALUES


def _item(rng, fields=("a", "b", "flag")):
    item = {}
    for name in fields:
        if rng.chance(4, 5):
            if name == "flag":
                item[name] = rng.choice([True, False])
            else:
                item[name] = rng.choice(ANY_VALUES)
    return item


def _majority_truthy(rng):
    return rng.choice([0, 1, 2, "x", [1], {"z": 1}])


def build_document(rng, profile):
    """Return a document tailored to `profile` (all values JSON-safe)."""
    doc = {}

    if profile == "short_circuit_null":
        # A must be absent or explicitly null so `a || b` and
        # not_null(a, b) take the same branch.
        if rng.chance(1, 2):
            doc["a"] = None
        doc["b"] = rng.choice(ANY_VALUES)
        if rng.chance(1, 2):
            doc["c"] = rng.choice(ANY_VALUES)
        return doc

    if profile == "short_circuit_truthy":
        doc["a"] = _majority_truthy(rng)
        doc["b"] = rng.choice(ANY_VALUES)
        return doc

    if profile == "short_circuit_chain":
        doc["a"] = rng.choice(ANY_VALUES)
        doc["b"] = rng.choice(ANY_VALUES)
        doc["c"] = rng.choice(ANY_VALUES)
        if rng.chance(1, 2):
            doc["d"] = rng.choice(ANY_VALUES)
        return doc

    if profile == "items_clean":
        # Every element is an object whose `a` is present and non-null,
        # the precondition for projection <-> map.
        items = []
        for _ in range(rng.between(0, 4)):
            item = {"a": rng.choice([True, False, 0, 1, "", "x", [1], {}])}
            if rng.chance(1, 2):
                item["b"] = rng.choice(ANY_VALUES)
            items.append(item)
        doc["items"] = items
        return doc

    if profile == "items_with_nulls":
        items = []
        for _ in range(rng.between(1, 4)):
            item = _item(rng, fields=("a", "b"))
            if rng.chance(1, 3):
                item["a"] = None
            if rng.chance(1, 4):
                item.pop("a", None)
            items.append(item)
        doc["items"] = items
        if rng.chance(1, 4):
            items.append(None)
        return doc

    if profile == "filter_bool":
        items = []
        for _ in range(rng.between(0, 4)):
            item = {"a": rng.choice(ANY_VALUES)}
            if rng.chance(3, 4):
                item["flag"] = rng.choice([True, False])
            items.append(item)
        doc["items"] = items
        return doc

    if profile == "filter_number":
        doc["items"] = [
            {"flag": 1, "a": "x"},
            {"flag": True, "a": "y"},
            {"flag": 0, "a": "z"},
        ]
        return doc

    if profile == "multiselect":
        doc["a"] = rng.choice(ANY_VALUES)
        doc["b"] = rng.choice(ANY_VALUES)
        return doc

    # Generic profile.
    doc["items"] = [_item(rng) for _ in range(rng.between(0, 4))]
    for name in ("a", "b", "c", "d"):
        if rng.chance(1, 2):
            doc[name] = rng.choice(ANY_VALUES)
    return doc
