#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Evidence script for the bounded multi-scalar interface.

Runs three demonstrations and prints the raw numbers:

1. Malicious / malformed inputs are rejected before any precomputation table
   is allocated (a sentinel fails the run if ``_build_table`` is touched).
2. Real operation counts (point additions, doublings) and the maximum table
   size for the allowed term counts.
3. Where the small-input crossover lies, i.e. when requests should keep
   using the existing ``mul_add`` instead of the windowed MSM.

Run with: .venv/bin/python speed_msm.py
"""

from __future__ import print_function

from ecdsa import curves
from ecdsa.ellipticcurve import INFINITY, PointJacobi
from ecdsa import multi_mul
from ecdsa.multi_mul import (
    MAX_TABLE_ENTRIES,
    MAX_TERMS,
    MAX_WINDOW,
    MUL_ADD_TERMS_THRESHOLD,
    MultiScalarError,
    multi_scalar_mul,
    public_point_combination,
)


class TableBuildAsserted(MultiScalarError):
    pass


def install_table_guard():
    original = multi_mul._build_table

    def guarded(*args, **kwargs):
        raise TableBuildAsserted(
            "policy failure: table allocation was attempted"
        )

    multi_mul._build_table = guarded
    return original


def section(title):
    print("\n=== {0} ===".format(title))


def rejection_evidence():
    section("1. Early rejection (no precomputation table allocated)")
    original = install_table_guard()
    generator = curves.NIST256p.generator
    cases = [
        (
            "100000 terms (DoS-sized input)",
            [generator] * 100000,
            [1] * 100000,
        ),
        (
            "MAX_TERMS + 1 = {0} terms".format(MAX_TERMS + 1),
            [generator * (i + 1) for i in range(MAX_TERMS + 1)],
            [1] * (MAX_TERMS + 1),
        ),
        (
            "point not on curve",
            [PointJacobi(
                curves.NIST256p.curve,
                generator.x(),
                generator.y() + 1,
                1,
            )],
            [1],
        ),
        (
            "mixed curves (P-256 + P-384)",
            [curves.NIST256p.generator, curves.NIST384p.generator],
            [1, 1],
        ),
        (
            "non-allowlisted curve (BrainpoolP256r1)",
            [curves.BRAINPOOLP256r1.generator],
            [1],
        ),
        (
            "point at infinity",
            [INFINITY],
            [1],
        ),
        (
            "length mismatch (2 points, 1 scalar)",
            [generator, generator * 2],
            [1],
        ),
        (
            "non-integer scalar",
            [generator],
            [1.5],
        ),
    ]
    for label, points, scalars in cases:
        try:
            multi_scalar_mul(points, scalars)
        except TableBuildAsserted:
            print("  FAIL (table built): {0}".format(label))
            continue
        except MultiScalarError as exc:
            print("  rejected before allocation: {0:38s} {1}".format(
                label, exc))
            continue
        print("  FAIL (accepted): {0}".format(label))
    multi_mul._build_table = original


def operation_and_table_evidence():
    section("2. Operation counts and table sizes (NIST P-256)")
    generator = curves.NIST256p.generator
    order = curves.NIST256p.order
    print(
        "  fixed caps: MAX_TERMS={0}, MAX_WINDOW={1}, "
        "MAX_TABLE_ENTRIES={2}".format(
            MAX_TERMS, MAX_WINDOW, MAX_TABLE_ENTRIES
        )
    )
    header = "  {0:>5} {1:>7} {2:>13} {3:>11} {4:>10}".format(
        "terms", "window", "table entries", "doublings", "additions"
    )
    print(header)
    observed_max_table = 0
    for num_terms in (1, 2, 3, 4, 8, 12, 16):
        points = [generator * (i + 1) for i in range(num_terms)]
        scalars = [
            (0x9E3779B97F4A7C15 * (i + 1)) % order
            for i in range(num_terms)
        ]
        result, stats = multi_scalar_mul(
            points, scalars, return_stats=True
        )
        observed_max_table = max(
            observed_max_table, stats["table_entries"]
        )
        print(
            "  {0:>5} {1:>7} {2:>13} {3:>11} {4:>10}".format(
                num_terms,
                stats["window"],
                stats["table_entries"],
                stats["doublings"],
                stats["additions"],
            )
        )
        # correctness cross-check against straightforward multiplication
        expected = INFINITY
        for point, scalar in zip(points, scalars):
            expected = expected + point * scalar
        assert result == expected
    print(
        "  observed maximum table over all allowed sizes: {0} entries "
        "(cap {1})".format(observed_max_table, MAX_TABLE_ENTRIES)
    )


def routing_evidence():
    section("3. Routing: when small inputs stay on mul_add")
    generator = curves.NIST256p.generator
    for num_terms in (1, 2, 3, 4):
        points = [generator * (i + 1) for i in range(num_terms)]
        scalars = [i + 3 for i in range(num_terms)]
        result, stats = public_point_combination(
            points, scalars, return_stats=True
        )
        print(
            "  terms={0:2d} -> path={1:16s} table_entries={2}".format(
                num_terms, stats["path"], stats["table_entries"]
            )
        )
    print(
        "  rule: fewer than {0} terms use mul_add (no table); "
        "{0}+ terms use the windowed multi-scalar path.".format(
            MUL_ADD_TERMS_THRESHOLD
        )
    )


if __name__ == "__main__":
    rejection_evidence()
    operation_and_table_evidence()
    routing_evidence()
