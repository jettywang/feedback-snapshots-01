#! /usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the bounded, public-material multi-scalar interface."""

from __future__ import division

import pytest

try:
    import unittest2 as unittest  # noqa: F401
except ImportError:
    import unittest  # noqa: F401
from hypothesis import given, settings
import hypothesis.strategies as st

from . import curves
from .ellipticcurve import (
    CurveFp,
    INFINITY,
    Point,
    PointJacobi,
)
from .multi_mul import (
    ALLOWED_CURVES,
    MAX_TABLE_ENTRIES,
    MAX_TERMS,
    MAX_WINDOW,
    MUL_ADD_TERMS_THRESHOLD,
    MultiScalarError,
    _select_window,
    multi_scalar_mul,
    public_point_combination,
)


# ---------------------------------------------------------------------------
# Fully independent affine reference implementation.
#
# It deliberately uses none of the Jacobi machinery of the module under test:
# points are plain (x, y) tuples and every operation follows the X9.62 affine
# formulas directly, including a field inversion per addition/doubling.
# ---------------------------------------------------------------------------

class AffineReference(object):
    def __init__(self, curve_fp):
        self.p = curve_fp.p()
        self.a = curve_fp.a()

    def add(self, p1, p2):
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        x1, y1 = p1
        x2, y2 = p2
        p = self.p
        if (x1 - x2) % p == 0:
            if (y1 + y2) % p == 0:
                return None
            inv = pow(2 * y1, -1, p)
            lam = ((3 * x1 * x1 + self.a) * inv) % p
        else:
            lam = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
        x3 = (lam * lam - x1 - x2) % p
        y3 = (lam * (x1 - x3) - y1) % p
        return x3, y3

    def mul(self, scalar, point):
        result = None
        addend = point
        while scalar:
            if scalar & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            scalar >>= 1
        return result

    def msm(self, points, scalars, order):
        result = None
        for point, scalar in zip(points, scalars):
            term = self.mul(scalar % order, point)
            result = self.add(result, term)
        return result


# Two tiny curves from the existing test suite. They are *not* in the
# allow-list, so they are used only to validate the independent reference
# arithmetic and as rejected inputs below.
TINY_CURVE = CurveFp(23, 1, 1)
TINY_G = Point(TINY_CURVE, 13, 7, 7)
TINY_ORDER = 7

TINY_CURVE_2 = CurveFp(31, 2, 3)
TINY_G_2 = Point(TINY_CURVE_2, 6, 18)


def _affine(point):
    if point == INFINITY:
        return None
    return point.x() % point.curve().p(), point.y() % point.curve().p()


# ---------------------------------------------------------------------------
# Independent affine arithmetic on a small curve
# ---------------------------------------------------------------------------

class TestAffineCrossCheck(object):
    def test_reference_matches_affine_point_ops(self):
        ref = AffineReference(TINY_CURVE)
        for scalar in range(TINY_ORDER * 2 + 3):
            got = ref.mul(scalar, (13, 7))
            expected = _affine(TINY_G * scalar)
            assert got == expected

    @pytest.mark.parametrize("num_terms", [1, 2, 3, 4, 5, 8])
    def test_msm_matches_independent_affine_reference(self, num_terms):
        # Exercise the windowed Jacobi implementation against the affine
        # reference on an allow-listed curve (NIST P-256) but with small,
        # fully enumerated scalars so every window digit is covered.
        named = curves.NIST256p
        generator = named.generator
        order = named.order
        points = [generator * (3 + 2 * i) for i in range(num_terms)]
        scalars = [(i * 7 + 1) % 127 - 40 for i in range(num_terms)]

        result, stats = multi_scalar_mul(
            points, scalars, return_stats=True
        )

        reference = AffineReference(named.curve)
        expected = reference.msm(
            [_affine(pt) for pt in points], scalars, order
        )
        assert _affine(result) == expected
        assert stats["num_terms"] == num_terms
        assert stats["table_entries"] <= MAX_TABLE_ENTRIES

    def test_tiny_curve_affine_cancellation(self):
        # The reference itself must handle cancellation to infinity.
        ref = AffineReference(TINY_CURVE)
        got = ref.msm(
            [(13, 7), (13, 7)], [3, -3], TINY_ORDER
        )
        assert got is None


# ---------------------------------------------------------------------------
# Correctness edge cases on allow-listed curves
# ---------------------------------------------------------------------------

ALLOWED = list(ALLOWED_CURVES)


@pytest.mark.parametrize("named", ALLOWED, ids=[c.name for c in ALLOWED])
class TestAllowedCurves(object):
    def test_basic_combination(self, named):
        generator = named.generator
        order = named.order
        points = [generator * k for k in (2, 3, 5)]
        scalars = [7, 11, 13]
        result = multi_scalar_mul(points, scalars)
        assert result == generator * (2 * 7 + 3 * 11 + 5 * 13)

    def test_zero_scalars(self, named):
        generator = named.generator
        points = [generator * 2, generator * 3]
        assert multi_scalar_mul(points, [0, 0]) == INFINITY
        assert multi_scalar_mul(points, [0, 4]) == generator * 12

    def test_negative_scalars(self, named):
        generator = named.generator
        point = generator * 6
        assert multi_scalar_mul([point], [-9]) == point * (-9)
        assert multi_scalar_mul(
            [point, point], [9, -9]
        ) == INFINITY
        assert multi_scalar_mul(
            [point, -point], [9, 9]
        ) == INFINITY

    def test_order_boundary_scalars(self, named):
        generator = named.generator
        order = named.order
        point = generator * 6
        assert multi_scalar_mul([point], [0]) == INFINITY
        assert multi_scalar_mul([point], [order]) == INFINITY
        assert multi_scalar_mul([point], [2 * order]) == INFINITY
        assert multi_scalar_mul([point], [order + 4]) == point * 4
        assert multi_scalar_mul([point], [order - 1]) == point * (order - 1)

    def test_duplicate_points(self, named):
        generator = named.generator
        point = generator * 5
        result = multi_scalar_mul(
            [point, point, point], [1, 2, 3]
        )
        assert result == point * 6

    def test_partial_cancellation_then_more_terms(self, named):
        # The first two terms cancel to infinity while a third remains; this
        # exercises the accumulator resetting to zero mid-walk and growing
        # again on later table lookups.
        generator = named.generator
        point = generator * 5
        result = multi_scalar_mul(
            [point, -point, generator * 7], [9, 9, 11]
        )
        assert result == generator * 77
        assert result != INFINITY

    def test_full_cancellation_of_nonzero_scalars(self, named):
        generator = named.generator
        point = generator * 5
        result = multi_scalar_mul(
            [point, point, -point], [3, 4, 7]
        )
        assert result == INFINITY

    def test_affine_and_jacobi_inputs_agree(self, named):
        generator = named.generator
        point_j = generator * 4
        point_a = Point(
            named.curve, point_j.x(), point_j.y(), named.order
        )
        scalars = [17, -5]
        r1 = multi_scalar_mul([point_j, generator * 7], scalars)
        r2 = multi_scalar_mul([point_a, generator * 7], scalars)
        assert r1 == r2

    def test_caller_point_objects_are_not_mutated(self, named):
        generator = named.generator
        point = PointJacobi.from_affine(generator * 9)
        coords_before = point._PointJacobi__coords
        precompute_before = list(point._PointJacobi__precompute)
        multi_scalar_mul([point, generator * 2], [123, 456])
        assert point._PointJacobi__coords == coords_before
        assert point._PointJacobi__precompute == precompute_before

    def test_affine_caller_not_mutated(self, named):
        generator = named.generator
        point = Point(named.curve, (generator * 9).x(), (generator * 9).y())
        x_before, y_before = point.x(), point.y()
        multi_scalar_mul([point, generator * 2], [123, 456])
        assert point.x() == x_before
        assert point.y() == y_before


# ---------------------------------------------------------------------------
# Policy rejection: every check must fire before any table is allocated
# ---------------------------------------------------------------------------

class _TableBuildSentinel(RuntimeError):
    pass


def _fail_if_table_built(monkeypatch):
    from . import multi_mul

    def boom(*args, **kwargs):
        raise _TableBuildSentinel("precomputation table was allocated")

    monkeypatch.setattr(multi_mul, "_build_table", boom)


class TestRejection(object):
    def test_too_many_terms_rejected_before_allocation(self, monkeypatch):
        _fail_if_table_built(monkeypatch)
        generator = curves.NIST256p.generator
        points = [generator * (i + 1) for i in range(MAX_TERMS + 1)]
        scalars = [1] * len(points)
        with pytest.raises(MultiScalarError):
            multi_scalar_mul(points, scalars)

    def test_malicious_size_fails_without_any_table_work(
        self, monkeypatch
    ):
        # A request claiming thousands of terms must be rejected on the term
        # count alone, and the rejection must happen before table setup.
        _fail_if_table_built(monkeypatch)
        generator = curves.NIST256p.generator
        points = [generator] * 100000
        scalars = [1] * 100000
        with pytest.raises(MultiScalarError):
            multi_scalar_mul(points, scalars)

    def test_empty_request_rejected(self):
        generator = curves.NIST256p.generator
        with pytest.raises(MultiScalarError):
            multi_scalar_mul([], [])

    def test_length_mismatch_rejected(self):
        generator = curves.NIST256p.generator
        with pytest.raises(MultiScalarError):
            multi_scalar_mul([generator, generator * 2], [1])

    def test_non_integer_scalar_rejected(self):
        generator = curves.NIST256p.generator
        for bad in (1.5, "1", None, True):
            with pytest.raises(MultiScalarError):
                multi_scalar_mul([generator], [bad])

    def test_wrong_container_types_rejected(self):
        generator = curves.NIST256p.generator
        with pytest.raises(MultiScalarError):
            multi_scalar_mul(generator, [1])
        with pytest.raises(MultiScalarError):
            multi_scalar_mul([generator], 1)

    def test_point_not_on_curve_rejected(self, monkeypatch):
        _fail_if_table_built(monkeypatch)
        named = curves.NIST256p
        generator = named.generator
        bad = PointJacobi(named.curve, generator.x(), generator.y() + 1, 1)
        with pytest.raises(MultiScalarError):
            multi_scalar_mul([bad], [1])

    def test_mixed_curves_rejected(self, monkeypatch):
        _fail_if_table_built(monkeypatch)
        with pytest.raises(MultiScalarError):
            multi_scalar_mul(
                [curves.NIST256p.generator, curves.NIST384p.generator],
                [1, 1],
            )

    def test_non_allowlisted_curve_rejected(self, monkeypatch):
        _fail_if_table_built(monkeypatch)
        with pytest.raises(MultiScalarError):
            multi_scalar_mul([TINY_G], [1])
        # Brainpool curves are defined in the library but not allow-listed.
        with pytest.raises(MultiScalarError):
            multi_scalar_mul(
                [curves.BRAINPOOLP256r1.generator], [1]
            )

    def test_infinity_rejected(self):
        with pytest.raises(MultiScalarError):
            multi_scalar_mul([INFINITY], [1])

    def test_edwards_curve_rejected(self):
        with pytest.raises(MultiScalarError):
            multi_scalar_mul([curves.Ed25519.generator], [1])

    def test_foreign_object_rejected(self):
        with pytest.raises(MultiScalarError):
            multi_scalar_mul([(1, 2)], [1])

    def test_ad_hoc_curve_that_compares_equal_is_rejected(self):
        named = curves.NIST256p
        curve_fp = named.curve
        clone = CurveFp(curve_fp.p(), curve_fp.a(), curve_fp.b())
        assert clone == curve_fp
        point = Point(clone, named.generator.x(), named.generator.y())
        with pytest.raises(MultiScalarError):
            multi_scalar_mul([point], [1])

    def test_window_and_table_budget_caps(self):
        order = curves.NIST256p.order
        # The window never exceeds MAX_WINDOW and the table never exceeds
        # the fixed entry budget for any allowed term count.
        for num_terms in range(1, MAX_TERMS + 1):
            window = _select_window(num_terms, order)
            assert 1 <= window <= MAX_WINDOW
            assert num_terms * (1 << window) <= MAX_TABLE_ENTRIES

    def test_max_terms_succeeds_at_the_boundary(self):
        named = curves.NIST256p
        generator = named.generator
        points = [generator * (i + 1) for i in range(MAX_TERMS)]
        scalars = [i + 1 for i in range(MAX_TERMS)]
        result, stats = multi_scalar_mul(
            points, scalars, return_stats=True
        )
        expected = generator * sum(
            (i + 1) * (i + 1) for i in range(MAX_TERMS)
        )
        assert result == expected
        assert stats["table_entries"] <= MAX_TABLE_ENTRIES


# ---------------------------------------------------------------------------
# Operation accounting and routing
# ---------------------------------------------------------------------------

class TestStatsAndRouting(object):
    def test_stats_reflect_real_work(self):
        named = curves.NIST256p
        generator = named.generator
        points = [generator * 2, generator * 3, generator * 5]
        scalars = [7, 11, 13]
        result, stats = multi_scalar_mul(
            points, scalars, return_stats=True
        )
        assert result == generator * (14 + 33 + 65)
        window = stats["window"]
        assert stats["table_entries"] == 3 * (1 << window)
        # table build: per term (2**window - 2) adds, then the windowed
        # accumulation adds one addition per non-zero digit.
        assert stats["additions"] > 0
        assert stats["doublings"] > 0
        assert stats["path"] == "multi_scalar_mul"

    def test_small_jobs_use_mul_add_path(self):
        generator = curves.NIST256p.generator
        points = [generator * 2, generator * 3]
        result, stats = public_point_combination(
            points, [7, 11], return_stats=True
        )
        assert result == generator * (14 + 33)
        assert stats["path"] == "mul_add"
        assert stats["table_entries"] == 0

    def test_single_term_routed_to_mul_add(self):
        generator = curves.NIST256p.generator
        result, stats = public_point_combination(
            [generator * 2], [9], return_stats=True
        )
        assert result == generator * 18
        assert stats["path"] == "mul_add"

    def test_threshold_constant(self):
        assert MUL_ADD_TERMS_THRESHOLD == 3

    def test_large_job_uses_msm_path(self):
        generator = curves.NIST256p.generator
        points = [generator * (i + 1) for i in range(4)]
        scalars = [3, 5, 7, 11]
        result, stats = public_point_combination(
            points, scalars, return_stats=True
        )
        assert result == generator * sum(
            (i + 1) * s for i, s in enumerate(scalars)
        )
        assert stats["path"] == "multi_scalar_mul"
        assert stats["table_entries"] > 0

    def test_router_enforces_the_same_policy(self):
        with pytest.raises(MultiScalarError):
            public_point_combination(
                [curves.NIST256p.generator, curves.NIST384p.generator],
                [1, 1],
            )


# ---------------------------------------------------------------------------
# Randomised cross-checking against the independent reference
# ---------------------------------------------------------------------------

@settings(max_examples=50, deadline=None)
@given(
    num_terms=st.integers(min_value=1, max_value=8),
    seed=st.integers(min_value=1, max_value=2 ** 32),
)
def test_random_combinations_match_affine_reference(num_terms, seed):
    named = curves.NIST256p
    generator = named.generator
    order = named.order
    points = [
        generator * (1 + (seed * (i + 1)) % (order - 1))
        for i in range(num_terms)
    ]
    # Range deliberately spans negatives, zero and the order boundary.
    scalars = [
        (seed * (i + 3)) % (3 * order) - order
        for i in range(num_terms)
    ]

    result = multi_scalar_mul(points, scalars)

    reference = AffineReference(named.curve)
    expected = reference.msm(
        [_affine(pt) for pt in points], scalars, order
    )
    assert _affine(result) == expected

    # And against the straightforward, already-tested point operators.
    naive = INFINITY
    for point, scalar in zip(points, scalars):
        naive = naive + point * scalar
    assert result == naive
