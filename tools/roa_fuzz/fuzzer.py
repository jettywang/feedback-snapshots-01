"""Deterministic, seed-driven semantic fuzzing of ROA authorization.

The fuzzer starts from legal ROAs whose prefixes are all contained in the
authenticated EE resources, then mutates the five fields the task names:
address family, prefix bit length, maxLength, AS number and resource
range.  Each generated case is judged twice:

* by :class:`~tools.roa_fuzz.adapter.LocalRoaAdapter` (the code under test),
* by :class:`~tools.roa_fuzz.oracle.ReferenceOracle`, which recomputes the
  expected result independently with the standard library.

Every mismatch is reduced to a minimal failing artifact holding the DER,
the EE resources and the route triple.
"""

import random

from .adapter import LocalRoaAdapter
from .asn1_codec import StructuralError, encode_roa
from .model import (
    AFI_BITS,
    AFI_IPV4,
    AFI_IPV6,
    EEResources,
    Prefix,
    RoaObject,
    RoaPrefix,
    Route,
)
from .oracle import ReferenceOracle


def _seeded_rng(seed):
    rng = random.Random()
    rng.seed(seed, version=2)
    return rng


def build_legal_case(rng):
    """A ROA that is structurally valid and fully inside the EE resources."""
    afi = rng.choice((AFI_IPV4, AFI_IPV6))
    width = AFI_BITS[afi]
    base_len = rng.randint(8, width - 4)
    base = rng.getrandbits(base_len) << (width - base_len)

    ee = EEResources()
    ee_block = 1 << (width - base_len)
    ee.add_range(afi, base, base + ee_block - 1)

    entries = []
    for _ in range(rng.randint(1, 3)):
        length = rng.randint(base_len, width - 2)
        address = base | (rng.getrandbits(length - base_len) << (width - length))
        prefix = Prefix(afi, address, length)
        max_length = rng.choice([None, length, rng.randint(length, width)])
        entries.append(RoaPrefix(prefix, max_length))

    roa = RoaObject(rng.randint(1, (1 << 32) - 2), {afi: entries})
    route_length = rng.randint(entries[0].prefix.length, width)
    route_address = entries[0].prefix.network_address() | (
        rng.getrandbits(route_length - entries[0].prefix.length)
        << (width - route_length)
    )
    route = Route(roa.as_id, Prefix(afi, route_address, route_length))
    return roa, ee, route


def _mutate(rng, roa, ee, route):
    """Apply one field mutation; returns (field, roa, ee, route)."""
    roa = RoaObject(roa.as_id, {afi: list(entries) for afi, entries in roa.blocks.items()}, roa.version)
    ee = EEResources({afi: (None if value is None else list(value)) for afi, value in ee.ranges.items()})
    route = Route(route.origin_as, Prefix(route.prefix.afi, route.prefix.address, route.prefix.length))

    # The five fields the exercise names, plus version for an extra
    # structural-only rejection path.
    field = rng.choice(
        ("address_family", "prefix_bits", "max_length", "as_number", "resource_range", "version")
    )
    afi = next(iter(roa.blocks))
    width = AFI_BITS[afi]

    if field == "address_family":
        other = AFI_IPV6 if afi == AFI_IPV4 else AFI_IPV4
        entry = roa.blocks[afi][0]
        roa.blocks.setdefault(other, []).append(
            RoaPrefix(Prefix(other, entry.prefix.address, entry.prefix.length), entry.max_length)
        )
        if rng.random() < 0.5:
            del roa.blocks[afi]
    elif field == "prefix_bits":
        entry = roa.blocks[afi][rng.randrange(len(roa.blocks[afi]))]
        new_length = rng.choice([0, width, rng.randint(0, width), width + rng.randint(1, 8)])
        entry.prefix.length = min(new_length, width + 8)
    elif field == "max_length":
        entry = roa.blocks[afi][rng.randrange(len(roa.blocks[afi]))]
        entry.max_length = rng.choice(
            [None, entry.prefix.length - 1, width, width + rng.randint(1, 8), rng.randint(0, width)]
        )
    elif field == "as_number":
        roa.as_id = rng.choice([0, roa.as_id, rng.randint(0, (1 << 32) - 1)])
        if rng.random() < 0.5:
            route.origin_as = roa.as_id
    elif field == "resource_range":
        entry = roa.blocks[afi][0]
        if rng.random() < 0.5:
            ee.ranges[afi] = None  # inherit or missing AFI
        else:
            width_block = 1 << (width - entry.prefix.length)
            start = entry.prefix.network_address() + width_block
            ee.ranges[afi] = [(start, start + width_block - 1)]  # disjoint range
    elif field == "version":
        roa.version = rng.choice([1, 2, -1])
    return field, roa, ee, route


class FuzzCase:
    __slots__ = ("index", "field", "roa", "ee", "route", "der")

    def __init__(self, index, field, roa, ee, route, der):
        self.index = index
        self.field = field
        self.roa = roa
        self.ee = ee
        self.route = route
        self.der = der


class FuzzFinding:
    """A minimal artifact describing one checker/oracle disagreement."""

    __slots__ = ("case", "expected", "actual", "reason")

    def __init__(self, case, expected, actual, reason):
        self.case = case
        self.expected = expected
        self.actual = actual
        self.reason = reason

    def to_dict(self):
        return {
            "index": self.case.index,
            "field": self.case.field,
            "expected_authorized": self.expected,
            "actual_authorized": self.actual,
            "adapter_reason": self.reason,
            "der_hex": self.case.der.hex() if self.case.der else None,
            "ee_resources": self.case.ee.to_dict(),
            "route": self.case.route.to_dict(),
            "roa": self.case.roa.to_dict(),
        }


class RoaSemanticFuzzer:
    def __init__(self, seed=20261114, sample_size=200):
        self.seed = seed
        self.sample_size = sample_size
        self.adapter = LocalRoaAdapter()
        self.oracle = ReferenceOracle()

    def generate(self):
        rng = _seeded_rng(self.seed)
        cases = []
        for index in range(self.sample_size):
            roa, ee, route = build_legal_case(rng)
            if index % 4 != 0:
                field, roa, ee, route = _mutate(rng, roa, ee, route)
            else:
                field = "baseline"
            try:
                der = encode_roa(roa)
            except StructuralError:
                der = None
            cases.append(FuzzCase(index, field, roa, ee, route, der))
        return cases

    def run(self):
        """Return (cases, findings); findings are checker/oracle mismatches."""
        cases = self.generate()
        findings = []
        for case in cases:
            expected = self._expected(case)
            if case.der is None:
                actual, reason = False, "un-encodable ROA"
            else:
                verdict = self.adapter.authorize(case.der, case.ee, case.route)
                actual, reason = verdict.authorized, verdict.reason
            if expected != actual:
                findings.append(FuzzFinding(case, expected, actual, reason))
        return cases, findings

    def _expected(self, case):
        # Expectations come only from the independent oracle; the adapter is
        # never consulted while computing what the answer should be.
        if case.der is None or not self.oracle.is_structurally_valid_roa(case.roa):
            return False
        return self.oracle.is_route_authorized(case.roa, case.ee, case.route)
