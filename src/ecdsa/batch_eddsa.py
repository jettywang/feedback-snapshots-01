"""Randomised batch verification for Pure EdDSA signatures (Ed25519/Ed448).

This module adds a *capped* batch verification API on top of the existing
single-signature :py:meth:`ecdsa.eddsa.PublicKey.verify` method.  The single
signature API is not modified or replaced; batch verification is an opt-in
abstraction built from the same curve primitives.

Security contract
-----------------
1. A batch is accepted if and only if the cofactored verification equation
   holds for the *randomly blinded* sum of all per-item equations::

       h * sum(z_i * S_i * G) == h * sum(z_i * (R_i + k_i * A_i))

   where ``h`` is the curve cofactor, ``z_i`` is a fresh, strictly positive,
   128 bit random coefficient drawn independently for every item of every
   call, and ``k_i`` is the usual EdDSA hash scalar.  Simply adding the
   unblinded equations (all ``z_i == 1``) is *not* secure: an attacker can
   pick two signatures whose individual errors are negations of each other,
   so the summed equation holds while neither signature verifies.

2. For any attacker chosen public keys, messages and signatures, if at least
   one item is individually invalid, a batch is accepted with probability at
   most ``2**-128`` per call, because after fixing every coefficient but one
   at most a single value of the remaining coefficient can satisfy the
   equation.  The cofactor multiplication clears small-subgroup residuals,
   so the bound also applies to malicious, non-canonical public points.

3. Randomness contract: the production default is :func:`os.urandom`.  The
   entropy source is injectable (any callable ``entropy(num_bytes) -> bytes``
   behaving like :func:`os.urandom`) so that tests can pin the coefficients.
   There is deliberately no fixed/default coefficient table and passing
   ``entropy=None`` is rejected.  Coefficients are drawn fresh on every call
   and are never reused or cached.

4. Nothing is skipped for the sake of batching: every signature length,
every scalar range check (``S < order``) and every point encoding/on-curve
check performed by single verification is performed for every item, via the
same :py:meth:`PointEdwards.from_bytes` decoder.

5. When the aggregate equation fails, each item is re-checked independently
   with the regular single-signature verifier to locate the bad indices.
   Batch results depend on fresh randomness, so this module keeps no state
   and caches nothing: an accidental one-off acceptance is never remembered
   as a permanent verdict.
"""

import os

from . import ellipticcurve
from .eddsa import curve_ed448
from ._compat import bytes_to_int, compat26_str

#: Maximum number of signatures accepted in a single :func:`verify_batch`
#: call.  Callers may tighten the cap per call, never rely on a larger one.
MAX_BATCH_SIZE = 1024

#: Width, in bytes, of each random blinding coefficient (128 bits).
BATCH_RANDOM_BYTES = 16

#: Upper bound (exclusive) of the coefficient range, ``2**128``.
COEFFICIENT_MODULUS = 2 ** (8 * BATCH_RANDOM_BYTES)

#: How many times a zero coefficient may be re-rolled before the entropy
#: source is considered broken.
_MAX_ZERO_REROLLS = 8


class BatchError(ValueError):
    """Raised when a batch request itself is malformed or over the cap."""


class BatchResult(object):
    """Outcome of a batch verification call.

    :ivar bool valid: ``True`` exactly when every item in the batch passed.
    :ivar results: per-item verdicts, in input order; ``True`` means the
        signature verified individually.
    :vartype results: list(bool)
    :ivar invalid_indices: indices of the failed items, in input order.
    :vartype invalid_indices: tuple(int)
    """

    def __init__(self, results):
        self.results = list(results)
        self.invalid_indices = tuple(
            idx for idx, ok in enumerate(self.results) if not ok
        )
        self.valid = not self.invalid_indices

    def __len__(self):
        return len(self.results)

    def __iter__(self):
        return iter(self.results)

    def __getitem__(self, index):
        return self.results[index]

    def __repr__(self):
        return "BatchResult(valid={0}, invalid_indices={1})".format(
            self.valid, self.invalid_indices
        )

    def __eq__(self, other):
        if isinstance(other, BatchResult):
            return self.results == other.results
        return NotImplemented

    def __ne__(self, other):
        return not self == other


def _random_coefficients(count, entropy):
    """Draw ``count`` independent coefficients in ``[1, 2**128)``.

    Zero is rejected (re-rolled) so every coefficient is strictly positive.
    """
    coefficients = []
    for _ in range(count):
        value = 0
        attempts = 0
        while not value:
            raw = entropy(BATCH_RANDOM_BYTES)
            if not isinstance(raw, (bytes, bytearray)) or len(raw) != (
                BATCH_RANDOM_BYTES
            ):
                raise BatchError(
                    "entropy source must return {0} bytes, got: {1!r}".format(
                        BATCH_RANDOM_BYTES, raw
                    )
                )
            value = bytes_to_int(bytearray(raw), "little")
            attempts += 1
            if not value and attempts > _MAX_ZERO_REROLLS:
                raise BatchError(
                    "entropy source keeps producing zero coefficients"
                )
        if value >= COEFFICIENT_MODULUS:
            # Unreachable for a correctly sized byte string, kept as a
            # defensive range check of the documented contract.
            raise BatchError("coefficient outside the documented range")
        coefficients.append(value)
    return coefficients


def _multi_scalar_mul(scalars, points, order):
    """Compute ``sum(scalar_i * point_i)`` with interleaved NAF.

    All points must live on the same curve of prime order ``order``.
    Combining the scalar multiplications into one double-and-add loop
    replaces one full doubling chain per scalar with a single shared chain,
    which is where the group operation savings of batch verification come
    from.
    """
    nafs = [
        ellipticcurve.PointEdwards._naf(scalar % order) for scalar in scalars
    ]
    width = max(len(naf) for naf in nafs)
    # NAF digits are least-significant first, so pad the high end on the
    # right and walk the shared bit-width from the most significant digit.
    nafs = [naf + [0] * (width - len(naf)) for naf in nafs]

    result = None
    for level in range(width - 1, -1, -1):
        if result is not None:
            result = result.double()
        for index, naf in enumerate(nafs):
            digit = naf[level]
            if not digit:
                continue
            term = points[index] if digit > 0 else -points[index]
            result = term if result is None else result + term

    if result is None:
        # Every scalar reduced to zero, the sum is the identity.
        return points[0] * 0
    return result


def _parse_item(public_key, data, signature):
    """Validate and decode one batch item, exactly like single verification.

    Returns ``(R, S, k, public_point, cofactor)``.  Raises the same
    exceptions as :py:meth:`ecdsa.eddsa.PublicKey.verify` on malformed input.
    """
    data = compat26_str(data)
    baselen = public_key.baselen
    if len(signature) != 2 * baselen:
        raise ValueError(
            "Invalid signature length, expected: {0} bytes".format(2 * baselen)
        )

    curve = public_key.curve
    R = ellipticcurve.PointEdwards.from_bytes(curve, signature[:baselen])
    S = bytes_to_int(signature[baselen:], "little")
    order = public_key.generator.order()
    if S >= order:
        raise ValueError("Invalid signature")

    dom = bytearray()
    if curve == curve_ed448:
        dom = bytearray(b"SigEd448" + b"\x00\x00")

    k = bytes_to_int(
        curve.hash_func(dom + R.to_bytes() + public_key.public_key() + data),
        "little",
    )
    return R, S, k, public_key.point, curve.cofactor()


def _verify_single(public_key, data, signature):
    """Independent single-signature verdict used for failure localisation."""
    try:
        return public_key.verify(data, signature)
    except (ValueError, AssertionError):
        # ValueError covers range/length failures; AssertionError covers the
        # MalformedPointError raised by the point decoder.
        return False


def verify_batch(items, entropy=os.urandom, max_batch_size=MAX_BATCH_SIZE):
    """Verify a capped batch of Pure EdDSA signatures.

    :param items: iterable of ``(public_key, data, signature)`` tuples, where
        ``public_key`` is an :class:`ecdsa.eddsa.PublicKey` instance.  Every
        item must use the same Edwards curve.
    :param callable entropy: source of the blinding coefficients, a callable
        taking a byte count and returning that many bytes like
        :func:`os.urandom`.  Defaults to :func:`os.urandom`; ``None`` is
        rejected and there is no fixed-coefficient default.  Inject a
        deterministic source only in tests.
    :param int max_batch_size: per-call cap on the number of items; defaults
        to :data:`MAX_BATCH_SIZE`.
    :return: per-item verdicts and the indices of the failures.
    :rtype: BatchResult
    :raises BatchError: if the batch is empty, exceeds the cap, mixes curves
        or the entropy source violates its contract.
    :raises ValueError: if an item has a malformed signature or point, with
        the same exceptions single verification would raise.
    """
    if entropy is None:
        raise BatchError(
            "an entropy callable is required; fixed coefficients are not "
            "supported by the production interface"
        )
    if not callable(entropy):
        raise BatchError("entropy must be a callable returning bytes")
    if max_batch_size > MAX_BATCH_SIZE:
        raise BatchError(
            "max_batch_size {0} exceeds the hard cap {1}".format(
                max_batch_size, MAX_BATCH_SIZE
            )
        )

    items = list(items)
    if not items:
        raise BatchError("refusing to verify an empty batch")
    if len(items) > max_batch_size:
        raise BatchError(
            "batch of {0} signatures exceeds the limit of {1}".format(
                len(items), max_batch_size
            )
        )

    parsed = []
    reference_curve = None
    for public_key, data, signature in items:
        if reference_curve is None:
            reference_curve = public_key.curve
        elif public_key.curve != reference_curve:
            raise BatchError("all items in a batch must use the same curve")
        parsed.append(_parse_item(public_key, data, signature))

    coefficients = _random_coefficients(len(parsed), entropy)
    cofactor = parsed[0][4]

    # h * sum(z_i * S_i * G) versus h * sum(z_i * (R_i + k_i * A_i)).
    generator = items[0][0].generator
    order = generator.order()
    left_scalars = []
    left_points = []
    right_scalars = []
    right_points = []
    for coefficient, (R, S, k, public_point, _) in zip(coefficients, parsed):
        left_scalars.append(cofactor * coefficient * S)
        left_points.append(generator)

        right_scalars.append(cofactor * coefficient)
        right_points.append(R)
        right_scalars.append(cofactor * coefficient * k)
        right_points.append(public_point)

    lhs = _multi_scalar_mul(left_scalars, left_points, order)
    rhs = _multi_scalar_mul(right_scalars, right_points, order)

    if lhs == rhs:
        return BatchResult([True] * len(parsed))

    # The randomised aggregate failed: localise the bad items with the
    # independent single-signature verifier.  No result is cached; a later
    # call draws fresh coefficients and starts from scratch.
    results = [
        _verify_single(public_key, data, signature)
        for public_key, data, signature in items
    ]
    return BatchResult(results)
