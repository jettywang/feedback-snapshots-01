"""
Directed fuzz tests for the point arithmetic behind ECDSA verification.

The verification equation (see ``ecdsa.ecdsa.Public_key.verifies``) computes
``u1 * G + u2 * Q`` in Jacobian coordinates (``PointJacobi.mul_add``) and
compares the affine x coordinate of the result with the ``r`` component of
the signature.  Any divergence between the group element that the optimised
Jacobian branches compute and the actual group element can therefore turn
into a wrong accept/reject decision at the public verification entry point.

Design rules of this file:

* expected values always come from an independent, affine-only reference
  implementation (``RefCurve``) that shares no code with the library - in
  particular the Jacobian<->affine coordinate conversions under test are
  never used to compute expectations;
* inputs are valid curve points in various Jacobian representations
  (different z coordinates, including unreduced ones), so no exception is
  ever a legitimate outcome - unexpected exceptions fail the tests instead
  of being counted as valid rejections;
* when a divergence is found it is first minimised (z coordinates forced
  to 1, scalars reduced towards zero, point inputs dropped to the point at
  infinity) and the report names the curve, the points and the scalars of
  the minimised case, together with the impact the divergence has on the
  public ``VerifyingKey.verify_digest`` entry point;
* a controlled, degenerate branch bug is injected to prove that the checks
  distinguish a group-element-changing bug (which causes wrong acceptance
  at the verify level) from a change that only alters the Jacobian
  encoding of the results.
"""

import random
import sys

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from hashlib import sha256

from . import curves
from ._compat import int_to_bytes
from .ellipticcurve import CurveFp, INFINITY, Point, PointJacobi
from .keys import BadSignatureError, SigningKey, VerifyingKey
from .util import sigdecode_string, sigencode_string


FAST = "--fast" in sys.argv

# fixed seed base for all randomised checks in this file: the fuzzing is
# directed and deterministic, every run exercises exactly the same cases
SEED_BASE = 0x5EED


def _is_prime(num):
    if num < 2:
        return False
    if num % 2 == 0:
        return num == 2
    div = 3
    while div * div <= num:
        if num % div == 0:
            return False
        div += 2
    return True


def _ref_inverse(value, modulus):
    """Modular inverse via the extended Euclidean algorithm.

    Implemented locally so that the reference oracle does not depend on
    the library's numbertheory module either.
    """
    value %= modulus
    if not value:
        raise ZeroDivisionError("inverse of zero does not exist")
    old_r, rem = value, modulus
    old_s, coeff = 1, 0
    while rem:
        quot = old_r // rem
        old_r, rem = rem, old_r - quot * rem
        old_s, coeff = coeff, old_s - quot * coeff
    if old_r != 1:
        raise ZeroDivisionError("inverse does not exist")
    return old_s % modulus


class RefCurve(object):
    """Independent affine-only reference model of a short Weierstrass curve.

    Points are plain ``(x, y)`` tuples, the point at infinity is ``None``.
    Only text-book affine formulas are used, so that no expected value in
    this file is produced by the coordinate conversions under test.
    """

    def __init__(self, p, a, b):
        if p < 5:
            raise ValueError("prime too small")
        self.p = p
        self.a = a % p
        self.b = b % p
        if (4 * self.a**3 + 27 * self.b**2) % p == 0:
            raise ValueError("singular curve")

    def is_on_curve(self, pt):
        if pt is None:
            return True
        x, y = pt
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def negate(self, pt):
        if pt is None:
            return None
        return (pt[0] % self.p, -pt[1] % self.p)

    def add(self, pt1, pt2):
        if pt1 is None:
            return pt2
        if pt2 is None:
            return pt1
        p = self.p
        x1, y1 = pt1[0] % p, pt1[1] % p
        x2, y2 = pt2[0] % p, pt2[1] % p
        if x1 == x2:
            if (y1 + y2) % p == 0:
                return None
            slope = ((3 * x1 * x1 + self.a) % p) * _ref_inverse(2 * y1, p) % p
        else:
            slope = ((y2 - y1) % p) * _ref_inverse((x2 - x1) % p, p) % p
        x3 = (slope * slope - x1 - x2) % p
        y3 = (slope * (x1 - x3) - y1) % p
        return (x3, y3)

    def mul(self, pt, k):
        if k < 0:
            return self.mul(self.negate(pt), -k)
        result = None
        addend = pt
        while k:
            if k & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            k >>= 1
        return result

    def mul_add(self, k1, pt1, k2, pt2):
        return self.add(self.mul(pt1, k1), self.mul(pt2, k2))

    def points(self):
        pts = []
        p = self.p
        for x in range(p):
            rhs = (x * x * x + self.a * x + self.b) % p
            for y in range(p):
                if y * y % p == rhs:
                    pts.append((x, y))
        pts.append(None)
        return pts

    def order_of(self, pt):
        acc = None
        k = 0
        # by Hasse the order is below 4*(p+2) for p >= 5
        while True:
            acc = self.add(acc, pt)
            k += 1
            if acc is None:
                return k
            if k > 4 * (self.p + 2):  # pragma: no cover
                raise AssertionError("point order search did not terminate")


class FuzzCurve(object):
    """Bundles the library curve object with the independent reference."""

    def __init__(
        self, p, a, b, order=None, gen_affine=None, gen_order=None, name=None
    ):
        self.curve_fp = CurveFp(p, a, b)
        self.ref = RefCurve(p, a, b)
        self.order = order if order is not None else len(self.ref.points())
        self._gen_affine = gen_affine
        self._gen_order = gen_order
        self.name = name or "y^2 = x^3 + {0}x + {1} over F_{2}".format(a, b, p)

    @classmethod
    def from_standard(cls, curve):
        cfp = curve.curve
        gen = curve.generator
        # the standard generators are stored with z == 1, so these are the
        # published curve constants, not results of the conversions under
        # test
        return cls(
            cfp.p(),
            cfp.a(),
            cfp.b(),
            order=curve.order,
            gen_affine=(gen.x(), gen.y()),
            gen_order=curve.order,
            name=curve.name,
        )

    @property
    def gen_affine(self):
        if self._gen_affine is None:
            best, best_order = None, 0
            for pt in self.ref.points():
                if pt is None:
                    continue
                pt_order = self.ref.order_of(pt)
                if pt_order > best_order:
                    best, best_order = pt, pt_order
            self._gen_affine = best
        return self._gen_affine

    @property
    def gen_order(self):
        if self._gen_order is None:
            self._gen_order = self.ref.order_of(self.gen_affine)
        return self._gen_order

    def jacobi(self, affine, z=1, generator=False):
        """Jacobian representation of an affine point with the given z."""
        if affine is None:
            return PointJacobi(self.curve_fp, 0, 0, 0, self.order)
        x, y = affine
        return PointJacobi(
            self.curve_fp,
            x * z * z,
            y * z * z * z,
            z,
            self.order,
            generator=generator,
        )


def _evaluate(fcurve, op, affines, zs, scalars):
    """Run the library code under test."""
    pts = [fcurve.jacobi(aff, z) for aff, z in zip(affines, zs)]
    if op == "add":
        return pts[0] + pts[1]
    if op == "double":
        return pts[0].double()
    if op == "neg":
        return -pts[0]
    if op == "mul":
        return pts[0] * scalars[0]
    if op == "mul_add":
        return pts[0].mul_add(scalars[0], pts[1], scalars[1])
    raise ValueError("unknown op: {0}".format(op))  # pragma: no cover


def _reference(fcurve, op, affines, scalars):
    """Compute the expected value with the independent affine reference."""
    ref = fcurve.ref
    if op == "add":
        return ref.add(affines[0], affines[1])
    if op == "double":
        return ref.add(affines[0], affines[0])
    if op == "neg":
        return ref.negate(affines[0])
    if op == "mul":
        return ref.mul(affines[0], scalars[0])
    if op == "mul_add":
        return ref.mul_add(scalars[0], affines[0], scalars[1], affines[1])
    raise ValueError("unknown op: {0}".format(op))  # pragma: no cover


def _same_group_element(fcurve, actual, expected_affine):
    """Compare a library result with the reference affine point.

    Uses only the group law equality of the library (cross-multiplication
    of the Jacobian coordinates), never a conversion of the expected
    value.
    """
    if expected_affine is None:
        return actual == INFINITY
    expected_point = Point(
        fcurve.curve_fp, expected_affine[0], expected_affine[1]
    )
    return actual == expected_point


def _find_divergence(fcurve, op, affines, zs, scalars):
    """Return a description dict if the library disagrees with the
    reference, None otherwise."""
    expected = _reference(fcurve, op, affines, scalars)
    try:
        actual = _evaluate(fcurve, op, affines, zs, scalars)
    except Exception as exc:
        # an exception on valid inputs is not a legitimate rejection, it
        # is a divergence like any other and fails the test
        return {
            "op": op,
            "affines": affines,
            "zs": zs,
            "scalars": scalars,
            "expected": expected,
            "actual": "raised {0!r}".format(exc),
        }
    if not _same_group_element(fcurve, actual, expected):
        return {
            "op": op,
            "affines": affines,
            "zs": zs,
            "scalars": scalars,
            "expected": expected,
            "actual": "different group element",
        }
    return None


def _minimise(fcurve, op, affines, zs, scalars):
    """Shrink a diverging case to a minimal curve/point/scalar shape.

    Greedily forces z coordinates to 1, reduces scalars towards zero and
    drops point inputs to the point at infinity, as long as the divergence
    keeps reproducing.
    """
    affines, zs, scalars = list(affines), list(zs), list(scalars)

    def diverges(aff, z, sc):
        return _find_divergence(fcurve, op, aff, z, sc) is not None

    changed = True
    while changed:
        changed = False
        for i in range(len(affines)):
            if affines[i] is None:
                continue
            # first try the canonical, reduced representative of z
            reduced = zs[i] % fcurve.curve_fp.p()
            if reduced != zs[i]:
                cand = list(zs)
                cand[i] = reduced
                if diverges(affines, cand, scalars):
                    zs = cand
                    changed = True
            if zs[i] != 1:
                cand = list(zs)
                cand[i] = 1
                if diverges(affines, cand, scalars):
                    zs = cand
                    changed = True
        for i in range(len(scalars)):
            for cand_s in (0, 1, -1, 2, scalars[i] // 2):
                if abs(cand_s) < abs(scalars[i]):
                    cand = list(scalars)
                    cand[i] = cand_s
                    if diverges(affines, zs, cand):
                        scalars = cand
                        changed = True
                        break
        if op in ("add", "mul_add"):
            for i in range(len(affines)):
                if affines[i] is not None:
                    cand = list(affines)
                    cand[i] = None
                    if diverges(cand, zs, scalars):
                        affines = cand
                        changed = True
    return affines, zs, scalars


def _format_affine(affine):
    if affine is None:
        return "INFINITY"
    return "(x={0}, y={1})".format(*affine)


def _build_verify_corpus(fcurve, sample, seed):
    """Build a verifying key and a corpus of signatures with ground truth.

    The expected validity of every corpus entry is computed with the
    independent affine reference, never with library code.
    """
    ref = fcurve.ref
    n = fcurve.gen_order
    gen = fcurve.gen_affine
    secret = 2
    pub = ref.mul(gen, secret)
    generator = PointJacobi(fcurve.curve_fp, gen[0], gen[1], 1, n)
    curve_obj = curves.Curve("fuzz-target", fcurve.curve_fp, generator, None)
    vk = VerifyingKey.from_public_point(
        Point(fcurve.curve_fp, pub[0], pub[1], n), curve_obj
    )
    rng = random.Random(seed)
    corpus = []

    def expected_valid(h, r, s):
        if not (1 <= r < n and 1 <= s < n):
            return None  # outside of what the corpus exercises
        try:
            w = _ref_inverse(s, n)
        except ZeroDivisionError:
            return None
        u1 = h * w % n
        u2 = r * w % n
        point = ref.mul_add(u1, gen, u2, pub)
        if point is None:
            # the library raises a TypeError when the verification point
            # is the point at infinity instead of cleanly rejecting the
            # signature; such inputs are outside the scope of this oracle
            return None
        return point[0] % n == r

    def add_case(h, r, s):
        expected = expected_valid(h, r, s)
        if expected is not None:
            corpus.append((h, r, s, expected))

    # reference-computed valid signatures first
    made = 0
    k = 0
    while made < max(2, sample // 4) and k < 4 * n:
        k += 1
        h = 1 + rng.randrange(n - 1)
        try:
            k_inv = _ref_inverse(k, n)
        except ZeroDivisionError:
            continue
        point = ref.mul(gen, k)
        r = point[0] % n
        if not r:
            continue
        s = k_inv * (h + secret * r) % n
        if not s:
            continue
        add_case(h, r, s)
        made += 1
    # random, mostly invalid triples
    attempts = 0
    while len(corpus) < sample and attempts < 20 * sample:
        attempts += 1
        add_case(
            1 + rng.randrange(n - 1),
            1 + rng.randrange(n - 1),
            1 + rng.randrange(n - 1),
        )
    return vk, corpus


def _verify_decision(vk, h, r, s):
    """Query the public verification entry point.

    Only BadSignatureError is a legitimate rejection; any other exception
    propagates and fails the calling test.
    """
    sig = sigencode_string(r, s, vk.curve.order)
    digest = int_to_bytes(h)
    try:
        vk.verify_digest(sig, digest)
        return True
    except BadSignatureError:
        return False


def _verify_decision_lenient(vk, h, r, s):
    try:
        return _verify_decision(vk, h, r, s)
    except Exception:
        return "error"


def _ecdsa_impact_note(fcurve):
    """Check how the current arithmetic affects the public verify entry.

    Returns a human readable note appended to divergence reports.
    """
    try:
        vk, corpus = _build_verify_corpus(fcurve, 24, SEED_BASE + 7)
    except Exception as exc:
        return (
            "ECDSA impact: could not build a verification corpus under "
            "the current arithmetic ({0!r})".format(exc)
        )
    flips = wrong_accepts = errors = 0
    for h, r, s, expected in corpus:
        got = _verify_decision_lenient(vk, h, r, s)
        if got == "error":
            errors += 1
        if got != expected:
            flips += 1
            if got is True:
                wrong_accepts += 1
    return (
        "ECDSA impact: {0} of {1} verify_digest decisions changed "
        "(wrong accepts: {2}, exceptions: {3})".format(
            flips, len(corpus), wrong_accepts, errors
        )
    )


def _report(fcurve, op, affines, zs, scalars):
    """Minimise a diverging case and format the failure report."""
    affines, zs, scalars = _minimise(fcurve, op, affines, zs, scalars)
    div = _find_divergence(fcurve, op, affines, zs, scalars)
    expected = div["expected"]
    if div["actual"].startswith("raised"):
        # the evaluation itself raised on valid inputs
        actual_desc = div["actual"]
    else:
        actual = _evaluate(fcurve, op, affines, zs, scalars)
        if actual == INFINITY:
            actual_desc = "INFINITY"
        else:
            try:
                affine = actual.to_affine()
                actual_desc = "affine (x={0}, y={1})".format(
                    affine.x(), affine.y()
                )
            except Exception as exc:
                actual_desc = (
                    "result not representable on the curve "
                    "(to_affine raised {0!r})".format(exc)
                )
    lines = [
        "point arithmetic divergence (minimised)",
        "curve: {0} (p={1}, a={2}, b={3}, order={4})".format(
            fcurve.name,
            fcurve.curve_fp.p(),
            fcurve.curve_fp.a(),
            fcurve.curve_fp.b(),
            fcurve.order,
        ),
        "operation: {0}".format(op),
    ]
    for i, (aff, z) in enumerate(zip(affines, zs)):
        lines.append(
            "point {0}: {1} with z={2}".format(i, _format_affine(aff), z)
        )
    if scalars:
        lines.append("scalars: {0}".format(scalars))
    lines.append(
        "expected (independent affine reference): {0}".format(
            _format_affine(expected)
        )
    )
    lines.append("library result: {0}".format(actual_desc))
    lines.append(_ecdsa_impact_note(fcurve))
    return "\n".join(lines)


def assert_consistent(testcase, fcurve, op, affines, zs, scalars):
    """Check one case, fail with a minimised report on divergence."""
    div = _find_divergence(fcurve, op, affines, zs, scalars)
    if div is not None:
        testcase.fail(_report(fcurve, op, affines, zs, scalars))


def run_directed_round(fcurve, rng, add_cases, mul_cases, mul_add_cases):
    """Run one directed fuzz round over a curve.

    Returns None when the library agrees with the independent reference on
    every case, otherwise a minimised report of the first divergence.
    """
    ref = fcurve.ref
    pts = ref.points()
    p = fcurve.curve_fp.p()
    n = fcurve.order

    def rand_z():
        z = 1 + rng.randrange(p - 1)
        # sometimes use an unreduced representative of the same z
        return z + rng.choice((0, 0, 0, 1, 2)) * p

    def check(op, affines, zs, scalars):
        if _find_divergence(fcurve, op, affines, zs, scalars) is not None:
            return _report(fcurve, op, affines, zs, scalars)
        return None

    for _ in range(add_cases):
        pt1 = rng.choice(pts)
        pt2 = rng.choice(pts)
        report = check("add", [pt1, pt2], [rand_z(), rand_z()], [])
        if report:
            return report
        report = check("double", [pt1], [rand_z()], [])
        if report:
            return report
        report = check("neg", [pt1], [rand_z()], [])
        if report:
            return report
        # a point and its opposite must cancel out through every branch
        report = check("add", [pt1, ref.negate(pt1)], [rand_z(), rand_z()], [])
        if report:
            return report
        # the point at infinity is the identity on both sides
        report = check("add", [None, pt1], [1, rand_z()], [])
        if report:
            return report
    for _ in range(mul_cases):
        pt1 = rng.choice(pts)
        k = rng.choice(
            (
                0,
                1,
                2,
                n - 1,
                n,
                n + 1,
                2 * n,
                rng.randrange(-2 * n, 2 * n + 1),
                rng.getrandbits(48),
            )
        )
        report = check("mul", [pt1], [rand_z()], [k])
        if report:
            return report
    for _ in range(mul_add_cases):
        # mul_add is what the verification equation uses; the public entry
        # point never calls it with the point at infinity, so keep both
        # inputs finite here
        pt1 = rng.choice(pts[:-1])
        pt2 = rng.choice(pts[:-1])
        k1 = rng.randrange(0, 2 * n + 1)
        k2 = rng.randrange(0, 2 * n + 1)
        report = check("mul_add", [pt1, pt2], [rand_z(), rand_z()], [k1, k2])
        if report:
            return report
    return None


def _valid_params(p):
    for a in range(p):
        for b in range(p):
            if (4 * a * a * a + 27 * b * b) % p:
                yield a, b


class SmallCurveExhaustiveTest(unittest.TestCase):
    """Exhaustively check finite combinations on small valid curves."""

    def test_all_point_pairs_tiny_curves(self):
        for p in (5, 7):
            for a, b in _valid_params(p):
                fcurve = FuzzCurve(p, a, b)
                pts = fcurve.ref.points()
                rng = random.Random(SEED_BASE + p * 10000 + a * 100 + b)
                for pt1 in pts:
                    assert_consistent(self, fcurve, "double", [pt1], [1], [])
                    assert_consistent(self, fcurve, "neg", [pt1], [1], [])
                    assert_consistent(
                        self, fcurve, "add", [pt1, None], [1, 1], []
                    )
                    assert_consistent(
                        self, fcurve, "add", [None, pt1], [1, 1], []
                    )
                    assert_consistent(
                        self,
                        fcurve,
                        "add",
                        [pt1, fcurve.ref.negate(pt1)],
                        [1, 1],
                        [],
                    )
                    for pt2 in pts:
                        assert_consistent(
                            self, fcurve, "add", [pt1, pt2], [1, 1], []
                        )
                        # the same pair in random non-trivial Jacobian
                        # representations must denote the same sum
                        z1 = 1 + rng.randrange(p - 1)
                        z2 = 1 + rng.randrange(p - 1)
                        assert_consistent(
                            self, fcurve, "add", [pt1, pt2], [z1, z2], []
                        )

    def test_all_scalar_multiples_tiny_curves(self):
        for p in (5, 7):
            for a, b in _valid_params(p):
                fcurve = FuzzCurve(p, a, b)
                n = fcurve.order
                for pt in fcurve.ref.points():
                    for k in range(-1, 2 * n + 2):
                        assert_consistent(self, fcurve, "mul", [pt], [1], [k])

    def test_mul_add_exhaustive_smallest_curves(self):
        for a, b in _valid_params(5):
            fcurve = FuzzCurve(5, a, b)
            n = fcurve.order
            pts = fcurve.ref.points()[:-1]
            scalars = (0, 1, 2, 3, n - 1, n, n + 1)
            for pt1 in pts:
                for pt2 in pts:
                    for k1 in scalars:
                        for k2 in scalars:
                            assert_consistent(
                                self,
                                fcurve,
                                "mul_add",
                                [pt1, pt2],
                                [1, 1],
                                [k1, k2],
                            )

    def test_directed_rounds_all_small_curves(self):
        primes = (11, 13) if FAST else (11, 13, 17, 19, 23)
        for p in primes:
            for a, b in _valid_params(p):
                fcurve = FuzzCurve(p, a, b)
                rng = random.Random(SEED_BASE + p * 10000 + a * 100 + b)
                report = run_directed_round(
                    fcurve, rng, add_cases=3, mul_cases=2, mul_add_cases=2
                )
                if report is not None:
                    self.fail(report)


class StandardCurveSeededTest(unittest.TestCase):
    """Fixed-seed checks of mul_add and the precompute path on standard
    curves."""

    def _check_curve(self, curve, rounds):
        fcurve = FuzzCurve.from_standard(curve)
        ref = fcurve.ref
        n = fcurve.order
        gen = fcurve.gen_affine
        p = fcurve.curve_fp.p()
        rng = random.Random(SEED_BASE + len(curve.name) * 7919 + p % 7919)
        k1 = k2 = 1
        for _ in range(rounds):
            k1 = rng.randrange(0, n)
            k2 = rng.randrange(0, n)
            kq = rng.randrange(1, n)
            pub = ref.mul(gen, kq)
            # generator multiplication uses the precomputed table
            expected = ref.mul(gen, k1)
            actual = curve.generator * k1
            self.assertTrue(
                _same_group_element(fcurve, actual, expected),
                "precomputed generator multiplication diverges on {0} "
                "for scalar {1}".format(curve.name, k1),
            )
            # plain NAF multiplication of a fresh point
            assert_consistent(self, fcurve, "mul", [pub], [1], [k2])
            # mul_add exactly as the verification equation uses it
            assert_consistent(
                self, fcurve, "mul_add", [gen, pub], [1, 1], [k1, k2]
            )
            # the public point may arrive in any Jacobian representation
            z = 1 + rng.randrange(p - 1)
            assert_consistent(
                self, fcurve, "mul_add", [gen, pub], [1, z], [k1, k2]
            )
            # mixed affine/Jacobian addition
            mixed = fcurve.jacobi(gen, 1) + Point(
                fcurve.curve_fp, pub[0], pub[1]
            )
            self.assertTrue(
                _same_group_element(fcurve, mixed, ref.add(gen, pub)),
                "mixed addition diverges on {0}".format(curve.name),
            )
        # multiplication with a precomputed table of a non-generator point
        # (this is what VerifyingKey.precompute() enables)
        pub = ref.mul(gen, rng.randrange(1, n))
        precomputed = fcurve.jacobi(pub, 1, generator=True)
        k = rng.randrange(0, n)
        self.assertTrue(
            _same_group_element(fcurve, precomputed * k, ref.mul(pub, k)),
            "precomputed multiplication diverges on {0}".format(curve.name),
        )
        # mul_add when both points have precomputed tables
        both = curve.generator.mul_add(k1, precomputed, k2)
        self.assertTrue(
            _same_group_element(fcurve, both, ref.mul_add(k1, gen, k2, pub)),
            "mul_add with two precomputed points diverges on {0}".format(
                curve.name
            ),
        )

    def test_secp112r1(self):
        self._check_curve(curves.SECP112r1, 4 if FAST else 10)

    def test_secp112r2(self):
        self._check_curve(curves.SECP112r2, 4 if FAST else 10)

    def test_nist192p(self):
        self._check_curve(curves.NIST192p, 4 if FAST else 10)

    def test_brainpoolp160r1(self):
        self._check_curve(curves.BRAINPOOLP160r1, 4 if FAST else 10)

    def test_secp256k1(self):
        self._check_curve(curves.SECP256k1, 4 if FAST else 10)


def _prime_order_tiny_curves(count, require_nonzero_a=False):
    found = []
    for p in (13, 17, 19, 23):
        for a, b in _valid_params(p):
            if require_nonzero_a and not a:
                continue
            fcurve = FuzzCurve(p, a, b)
            if _is_prime(fcurve.order):
                found.append(fcurve)
                if len(found) == count:
                    return found
    return found


class PublicVerifyEntryTest(unittest.TestCase):
    """Feed the fuzzed arithmetic back through the public verify entry."""

    def test_verify_matches_reference_on_tiny_curves(self):
        for fcurve in _prime_order_tiny_curves(2 if FAST else 3):
            n = fcurve.gen_order
            if n <= 20:
                corpus_size = None  # enumerate everything below
            else:
                corpus_size = 400
            vk, corpus = _build_verify_corpus(
                fcurve, corpus_size or 8, SEED_BASE + fcurve.order
            )
            if corpus_size is None:
                # recompute ground truth for the full enumeration
                ref = fcurve.ref
                gen = fcurve.gen_affine
                pub = ref.mul(gen, 2)
                corpus = []
                for h in range(1, n):
                    for r in range(1, n):
                        for s in range(1, n):
                            w = _ref_inverse(s, n)
                            point = ref.mul_add(h * w % n, gen, r * w % n, pub)
                            if point is None:
                                # the library raises TypeError instead of
                                # cleanly rejecting here; outside the scope
                                # of this oracle
                                continue
                            corpus.append((h, r, s, point[0] % n == r))
            for precompute in (False, True):
                if precompute:
                    vk.precompute()
                for h, r, s, expected in corpus:
                    got = _verify_decision(vk, h, r, s)
                    self.assertEqual(
                        got,
                        expected,
                        "verify_digest decision diverges on {0} for "
                        "(h={1}, r={2}, s={3}), precompute={4}".format(
                            fcurve.name, h, r, s, precompute
                        ),
                    )

    def test_valid_and_tampered_signature_on_standard_curve(self):
        secret = 0x1FA55E5EED
        sk = SigningKey.from_secret_exponent(secret, curve=curves.NIST192p)
        vk = sk.get_verifying_key()
        vk.precompute()
        sig = sk.sign_deterministic(b"directed fuzz", hashfunc=sha256)
        self.assertTrue(vk.verify(sig, b"directed fuzz", hashfunc=sha256))
        with self.assertRaises(BadSignatureError):
            vk.verify(sig, b"directed fuzz!", hashfunc=sha256)
        # a signature with r and s swapped must not verify
        order = curves.NIST192p.order
        r, s = sigdecode_string(sig, order)
        swapped = sigencode_string(s, r, order)
        with self.assertRaises(BadSignatureError):
            vk.verify(swapped, b"directed fuzz", hashfunc=sha256)


class ControlledMutationTest(unittest.TestCase):
    """Prove the fuzzer distinguishes a group-element-changing bug from a
    mere encoding change in the same optimised branch."""

    def setUp(self):
        # the degenerate bug injected below lives in a term multiplied by
        # the curve's a coefficient, so pick a curve with a != 0
        self.fcurve = _prime_order_tiny_curves(1, require_nonzero_a=True)[0]
        self.vk, self.corpus = _build_verify_corpus(
            self.fcurve, 48, SEED_BASE + 0xBAD
        )

    def _directed(self, cases):
        rng = random.Random(SEED_BASE + 0xD16)
        return run_directed_round(
            self.fcurve,
            rng,
            add_cases=cases,
            mul_cases=cases,
            mul_add_cases=cases,
        )

    def _decisions(self, lenient=False):
        decide = _verify_decision_lenient if lenient else _verify_decision
        return [decide(self.vk, h, r, s) for h, r, s, _ in self.corpus]

    def _expected(self):
        return [expected for _, _, _, expected in self.corpus]

    @staticmethod
    def _patched_double(variant):
        """Return a context manager patching PointJacobi._double.

        ``degenerate`` drops one ZZ factor from the M computation of the
        general-z doubling branch - the result is a different group
        element.  ``encoding`` scales the result by lambda=2 - the exact
        same group element, only a different Jacobian encoding.
        """
        import contextlib

        original = PointJacobi._double

        if variant == "degenerate":

            def mutated(self, X1, Y1, Z1, p, a):
                if Z1 == 1:
                    return self._double_with_z_1(X1, Y1, p, a)
                if not Z1:
                    return 0, 0, 0
                XX, YY = X1 * X1 % p, Y1 * Y1 % p
                if not YY:
                    return 0, 0, 0
                YYYY = YY * YY % p
                ZZ = Z1 * Z1 % p
                S = 2 * ((X1 + YY) ** 2 - XX - YYYY) % p
                # degenerate: one ZZ factor missing
                M = (3 * XX + a * ZZ) % p
                T = (M * M - 2 * S) % p
                Y3 = (M * (S - T) - 8 * YYYY) % p
                Z3 = ((Y1 + Z1) ** 2 - YY - ZZ) % p
                return T, Y3, Z3

        elif variant == "encoding":

            def mutated(self, X1, Y1, Z1, p, a):
                X3, Y3, Z3 = original(self, X1, Y1, Z1, p, a)
                return (X3 * 4 % p, Y3 * 8 % p, Z3 * 2 % p)

        else:  # pragma: no cover
            raise ValueError("unknown variant")

        @contextlib.contextmanager
        def manager():
            PointJacobi._double = mutated
            try:
                yield
            finally:
                PointJacobi._double = original

        return manager()

    def test_unmutated_baseline(self):
        self.assertIsNone(self._directed(8))
        self.assertEqual(self._decisions(), self._expected())

    def test_degenerate_branch_bug_is_caught(self):
        with self._patched_double("degenerate"):
            report = self._directed(8)
            self.assertIsNotNone(
                report,
                "fuzzer failed to flag a group-element-changing bug",
            )
            outcomes = self._decisions(lenient=True)
            expected = self._expected()
            wrong_accepts = sum(
                1
                for got, want in zip(outcomes, expected)
                if got is True and want is False
            )
            flips = sum(
                1 for got, want in zip(outcomes, expected) if got != want
            )
            self.assertTrue(
                flips > 0,
                "group-element-changing bug did not affect any verify "
                "decision at the public entry point",
            )
            self.assertTrue(
                wrong_accepts > 0,
                "group-element-changing bug did not turn into a wrong "
                "accept at the public entry point",
            )
            # the report must connect the divergence to the public
            # verification entry point
            self.assertIn("ECDSA impact", report)

    def test_encoding_only_change_is_not_flagged(self):
        with self._patched_double("encoding"):
            self.assertIsNone(
                self._directed(8),
                "fuzzer flagged a mere encoding change as a divergence",
            )
            self.assertEqual(
                self._decisions(),
                self._expected(),
                "encoding-only change altered verify decisions",
            )
