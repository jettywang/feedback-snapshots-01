#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Bounded multi-scalar multiplication over public elliptic curve points.
#
# This module is intended for *public* verification material only (e.g. the
# point combination performed during ECDSA verification). It is a fixed-size,
# input-validating front end on top of the existing PointJacobi operations;
# it is NOT a constant-time / side-channel resistant implementation and must
# not be used to handle private keys.

from __future__ import division

from . import curves
from .ellipticcurve import (
    CurveFp,
    INFINITY,
    Point,
    PointJacobi,
)


# Fixed policy: do not accept arbitrarily large jobs.
#
# Only the five NIST prime curves and secp256k1 are supported. Curves are
# matched by object identity against the named curves in ecdsa.curves, so a
# caller cannot smuggle in an ad-hoc CurveFp that merely compares equal.
ALLOWED_CURVES = (
    curves.NIST192p,
    curves.NIST224p,
    curves.NIST256p,
    curves.NIST384p,
    curves.NIST521p,
    curves.SECP256k1,
)

# Hard cap on the number of (point, scalar) terms in a single request.
MAX_TERMS = 16

# Hard cap on the window width and on the total number of precomputed point
# entries the request is allowed to allocate. The tables are sized
# ``len(terms) * 2**window``, so MAX_TABLE_ENTRIES bounds the memory a single
# request can reserve no matter how wide the scalars are.
MAX_WINDOW = 8
MAX_TABLE_ENTRIES = 512

# Below this number of terms the existing two-point ``mul_add`` is at least as
# fast and needs no precomputation table, so callers keep using it.
MUL_ADD_TERMS_THRESHOLD = 3


class MultiScalarError(ValueError):
    """Raised when a multi-scalar request violates the fixed policy.

    The error is always raised *before* any precomputation table is
    allocated, so a malformed or oversized request cannot exhaust worker
    memory.
    """

    pass


def _select_window(num_terms, order):
    """Pick the window width for a validated request.

    The window grows with the number of terms (amortising the table over
    more scalars) but is bounded by both ``MAX_WINDOW`` and the precomputation
    budget ``MAX_TABLE_ENTRIES``. The result depends only on the term count
    and the curve order, never on the caller's point objects.
    """
    if num_terms <= 4:
        window = 4
    elif num_terms <= 8:
        window = 5
    else:
        window = 6
    order_bits = order.bit_length()
    if window > order_bits:
        window = order_bits
    while window > 1 and num_terms * (1 << window) > MAX_TABLE_ENTRIES:
        window -= 1
    if window > MAX_WINDOW:
        window = MAX_WINDOW
    return window


def _validate(terms, scalars):
    """Run every policy check before a single table entry is allocated.

    Returns fresh, private PointJacobi copies of the accepted points so that
    later scaling and precomputation never mutate the caller's objects.
    """
    if not isinstance(terms, (list, tuple)):
        raise MultiScalarError(
            "terms must be provided as a list or tuple of points"
        )
    if not isinstance(scalars, (list, tuple)):
        raise MultiScalarError(
            "scalars must be provided as a list or tuple of integers"
        )
    if len(terms) != len(scalars):
        raise MultiScalarError(
            "there must be exactly one scalar per point "
            "(got {0} points and {1} scalars)".format(
                len(terms), len(scalars)
            )
        )
    if not terms:
        raise MultiScalarError("at least one term is required")
    if len(terms) > MAX_TERMS:
        raise MultiScalarError(
            "too many terms: {0} is above the limit of {1}".format(
                len(terms), MAX_TERMS
            )
        )

    for scalar in scalars:
        # bool is a subclass of int; reject it to keep types unambiguous.
        if isinstance(scalar, bool) or not isinstance(scalar, int):
            raise MultiScalarError("every scalar must be an integer")

    reference_curve = None
    order = None
    private_terms = []
    for point in terms:
        if point is INFINITY or point == INFINITY:
            raise MultiScalarError("the point at infinity is not accepted")
        if isinstance(point, PointJacobi):
            source = point
        elif isinstance(point, Point):
            source = PointJacobi.from_affine(point)
        else:
            raise MultiScalarError(
                "every term must be a Point or PointJacobi instance"
            )

        curve_fp = source.curve()
        if not isinstance(curve_fp, CurveFp):
            raise MultiScalarError(
                "only short Weierstrass (CurveFp) curves are supported"
            )

        matched = None
        for named_curve in ALLOWED_CURVES:
            if named_curve.curve is curve_fp:
                matched = named_curve
                break
        if matched is None:
            raise MultiScalarError(
                "curve is not in the fixed allow-list of supported curves"
            )

        if reference_curve is None:
            reference_curve = matched
        elif matched is not reference_curve:
            raise MultiScalarError(
                "all points must be on the same curve "
                "(mixed {0} and {1} points)".format(
                    reference_curve.name, matched.name
                )
            )

        # PointJacobi does not assert on-curve membership in its constructor,
        # so verify the curve equation explicitly for every input point.
        # Negated points may carry an un-reduced negative y, normalise the
        # coordinates modulo p before the range and membership checks.
        prime = curve_fp.p()
        x_coord = source.x() % prime
        y_coord = source.y() % prime
        if not (0 <= x_coord < prime and 0 <= y_coord < prime):
            raise MultiScalarError(
                "point coordinates are outside the field of the curve"
            )
        if not curve_fp.contains_point(x_coord, y_coord):
            raise MultiScalarError("point is not on the curve")

        # Private copy: scaling and precomputation only touch this object.
        # No point order is stored so no scalar reduction ever happens inside
        # the point arithmetic.
        order = matched.order
        private_terms.append(PointJacobi(curve_fp, x_coord, y_coord, 1))

    window = _select_window(len(private_terms), order)
    # Defence in depth: the table size is re-checked after the window was
    # selected, still before any allocation happens.
    if len(private_terms) * (1 << window) > MAX_TABLE_ENTRIES:
        raise MultiScalarError(
            "precomputation budget exhausted; request rejected"
        )
    return private_terms, reference_curve, order, window


def _build_table(point, window, curve_fp):
    """Build [P, 2P, 3P, ..., (2**window - 1)P] from a private point.

    The low level ``_add``/``_double`` formulas are used directly instead of
    the ``+``/``double()`` operators: the latter reduce scalars by the point's
    stored order (Minerva protection), which corrupts multiples once the
    table is built from a point that carries the curve order. Orderless
    helper points keep the arithmetic purely geometric.

    Consecutive entries are computed as ``kP = (k-1)P + P`` rather than
    ``(k-1)P + 2P``: the low level addition routine switches to its doubling
    branch when both operands are the same point, which would silently turn
    an intended 3P into 4P. P and (k-1)P are distinct for every k >= 2.
    """
    p = curve_fp.p()
    a = curve_fp.a()
    helper = PointJacobi(curve_fp, 0, 0, 1)
    base = point.scale()
    x_base, y_base, z_base = base._PointJacobi__coords
    table = [base]
    if window == 1:
        return table, 0
    dx, dy, dz = helper._double(x_base, y_base, z_base, p, a)
    table.append(PointJacobi(curve_fp, dx, dy, dz))
    additions = 0
    for _ in range(2, 1 << window):
        px, py, pz = table[-1]._PointJacobi__coords
        nx, ny, nz = helper._add(
            px, py, pz, x_base, y_base, z_base, p
        )
        table.append(PointJacobi(curve_fp, nx, ny, nz))
        additions += 1
    return table, additions


def multi_scalar_mul(terms, scalars, return_stats=False):
    """Compute a bounded multi-scalar multiplication of public points.

    Calculates::

        scalars[0] * terms[0] + ... + scalars[-1] * terms[-1]

    over a single, fixed, allow-listed curve.

    All policy checks (number of terms, scalar types, curve allow-list,
    on-curve membership, mixed-curve rejection, precomputation budget) run
    before any precomputation table is allocated.

    :param terms: public points to multiply, at most :py:data:`MAX_TERMS`
    :type terms: list or tuple of
        :py:class:`~ecdsa.ellipticcurve.Point` or
        :py:class:`~ecdsa.ellipticcurve.PointJacobi`
    :param scalars: integer scalars, one per point; zero and negative values
        are accepted (scalars are reduced modulo the curve order)
    :type scalars: list or tuple of int
    :param bool return_stats: when True, return a ``(result, stats)`` tuple
        where ``stats`` records the window width, table size and the number
        of point additions and doublings actually performed

    :raises MultiScalarError: when the request violates the fixed policy

    :return: the resulting point (possibly the point at infinity), or a
        ``(result, stats)`` tuple when ``return_stats`` is True
    """
    private_terms, named_curve, order, window = _validate(terms, scalars)

    # Reduce scalars modulo the order. This makes zero scalars, multiples of
    # the order (order-boundary values) and negative scalars all well defined
    # and makes mutually cancelling terms evaluate to the point at infinity.
    reduced = [scalar % order for scalar in scalars]

    stats = {
        "window": window,
        "num_terms": len(private_terms),
        "table_entries": len(private_terms) * (1 << window),
        "doublings": 0,
        "additions": 0,
        "path": "multi_scalar_mul",
    }

    if not any(reduced):
        if return_stats:
            return INFINITY, stats
        return INFINITY

    curve_fp = named_curve.curve
    p = curve_fp.p()
    a = curve_fp.a()
    helper = PointJacobi(curve_fp, 0, 0, 1)
    tables = []
    for point in private_terms:
        table, table_additions = _build_table(point, window, curve_fp)
        tables.append(table)
        stats["additions"] += table_additions

    accum = (0, 0, 0)
    # Cover the full bit length of every reduced scalar. Using the order bit
    # length would silently drop high bits of scalars larger than the order.
    max_bits = max(scalar.bit_length() for scalar in reduced)
    num_windows = (max_bits + window - 1) // window

    # Windows from the most significant to the least significant, doubling
    # the accumulator "window" times between table lookups.
    for window_index in range(num_windows - 1, -1, -1):
        shift = window_index * window
        for _ in range(window):
            accum = helper._double(accum[0], accum[1], accum[2], p, a)
            stats["doublings"] += 1
        for index, scalar in enumerate(reduced):
            digit = (scalar >> shift) & ((1 << window) - 1)
            if digit:
                # table[0] is 1P, so digit d selects table[d - 1] = dP
                tx, ty, tz = tables[index][digit - 1]._PointJacobi__coords
                if not accum[2]:
                    # First addition: the low level routine returns the
                    # second operand un-reduced when the accumulator is zero.
                    accum = (tx % p, ty % p, tz % p)
                else:
                    accum = helper._add(
                        accum[0], accum[1], accum[2], tx, ty, tz, p
                    )
                stats["additions"] += 1

    if not accum[2]:
        result = INFINITY
    else:
        result = PointJacobi(curve_fp, accum[0], accum[1], accum[2], order)

    if return_stats:
        return result, stats
    return result


def public_point_combination(terms, scalars, return_stats=False):
    """Route a public point combination to the cheapest available path.

    Requests with fewer than :py:data:`MUL_ADD_TERMS_THRESHOLD` terms are sent
    to the existing :py:meth:`~ecdsa.ellipticcurve.PointJacobi.mul_add`
    implementation, which needs no precomputation table; larger requests use
    the bounded :py:func:`multi_scalar_mul`. The same policy validation runs
    in both cases, so the limits apply regardless of the chosen path.
    """
    private_terms, named_curve, order, _window = _validate(terms, scalars)

    if len(private_terms) < MUL_ADD_TERMS_THRESHOLD:
        stats = {
            "window": 0,
            "num_terms": len(private_terms),
            "table_entries": 0,
            "doublings": 0,
            "additions": 0,
            "path": "mul_add",
        }
        if len(private_terms) == 1:
            result = private_terms[0] * (scalars[0] % order)
        else:
            result = private_terms[0].mul_add(
                scalars[0] % order,
                private_terms[1],
                scalars[1] % order,
            )
        if return_stats:
            return result, stats
        return result

    return multi_scalar_mul(private_terms, scalars, return_stats)
