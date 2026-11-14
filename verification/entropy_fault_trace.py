#!/usr/bin/env python
"""Runnable, bounded entropy fault-injection trace for python-ecdsa.

Run with the project virtualenv:

    .venv/bin/python verification/entropy_fault_trace.py

Every scenario is bounded (no waiting on wall-clock time, no unbounded
loops) so a regression is reported rather than hanging.  The script prints
the entropy request trace for each layer and the exception that layer owns.
Exit status is non-zero if any expectation is not met.
"""

from __future__ import print_function

import hashlib
import os
import sys

# Make ``src`` importable when run from a checkout without installation.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ecdsa.curves import Curve, Ed25519, NIST256p  # noqa: E402
from ecdsa.ecdsa import RSZeroError  # noqa: E402
from ecdsa.ellipticcurve import CurveFp, PointJacobi  # noqa: E402
from ecdsa.errors import (  # noqa: E402
    EntropyError,
    EntropyExhaustedError,
    EntropySourceError,
)
from ecdsa.keys import SigningKey  # noqa: E402
from ecdsa.util import bit_length, entropy_bytes, randrange  # noqa: E402

FAILURES = []


def check(name, condition, detail=""):
    status = "ok" if condition else "FAIL"
    print("  [{0}] {1}{2}".format(status, name, (": " + detail) if detail else ""))
    if not condition:
        FAILURES.append(name)


class Trace(object):
    def __init__(self, plan):
        self.plan = list(plan)
        self.calls = []

    def __call__(self, numbytes):
        self.calls.append(numbytes)
        if len(self.calls) > len(self.plan):
            return b"\xff" * numbytes  # forces bounded termination
        item = self.plan[len(self.calls) - 1]
        if callable(item):
            return item(numbytes)
        return item


def toy_key():
    curve = CurveFp(163, 84, 58)
    gen = PointJacobi(curve, 2, 87, 1, 167, generator=True)
    toy = Curve("toy_p8", curve, gen, (1, 2, 0))
    return SigningKey.from_secret_exponent(140, toy, hashfunc=hashlib.sha1)


def scenario(title):
    print("\n" + title)
    print("-" * len(title))


def main():
    order = NIST256p.order
    sample = bit_length(order - 2) // 8 + 1

    scenario("L1 entropy callback: exact-length contract")
    for label, value in (
        ("empty read", b""),
        ("short read", b"\x00"),
        ("long read", b"\x00" * (sample + 1)),
        ("non-bytes", 1234),
    ):
        try:
            entropy_bytes(lambda n, v=value: v, sample)
            check(label, False, "no exception (BAD)")
        except EntropySourceError as exc:
            check(label, True, "EntropySourceError: {0}".format(exc))

    class Down(Exception):
        pass

    def down(numbytes):
        raise Down("device gone")

    try:
        entropy_bytes(down, sample)
        check("callback exception", False)
    except Down as exc:
        check("callback exception propagates", True, repr(exc))

    scenario("L2 randrange: bounded rejection, no modulo reduction")
    trace = Trace([b"\xff\xff", b"\x10\x00"])
    value = randrange(167, entropy=trace)
    check(
        "one legitimate rejection then accept",
        value == 17 and trace.calls == [2, 2],
        "k={0}, requests={1}".format(value, trace.calls),
    )

    stuck = Trace([b"\xff\xff"] * 128)
    try:
        randrange(167, entropy=stuck)
        check("persistent out-of-range", False, "returned a value (BAD)")
    except EntropyExhaustedError as exc:
        check(
            "persistent out-of-range is bounded",
            len(stuck.calls) == 128,
            "requests={0}, {1}".format(len(stuck.calls), exc),
        )

    all_ones = Trace([b"\xff" * sample] * 128)
    try:
        randrange(order, entropy=all_ones)
        check("all-ones sample", False, "folded into range (modulo bias!)")
    except EntropyExhaustedError:
        check(
            "all-ones sample rejected (no modulo)",
            len(all_ones.calls) == 128,
            "requests={0}".format(len(all_ones.calls)),
        )

    scenario("L3 random key generation")
    for curve in (NIST256p, Ed25519):
        try:
            SigningKey.generate(curve, entropy=lambda n: b"\x00")
            check("{0} short read".format(curve.name), False, "key made (BAD)")
        except EntropySourceError as exc:
            check("{0} short read fails closed".format(curve.name), True, str(exc))

    scenario("L4 probabilistic signing: nonce re-selection")
    sk = toy_key()
    trace = Trace([b"\x0e\x00", b"\x2a\x00"])
    from ecdsa.util import sigdecode_string

    sig = sk.sign(b"message", entropy=trace, hashfunc=hashlib.sha1)
    check(
        "r==0 nonce re-drawn from same source",
        len(trace.calls) == 2 and sk.verifying_key.verify(
            sig, b"message", hashfunc=hashlib.sha1
        ),
        "requests={0}".format(trace.calls),
    )

    stuck_nonce = Trace([b"\x0e\x00"] * 128)
    try:
        sk.sign_number(54, entropy=stuck_nonce)
        check("stuck r==0 nonce", False, "returned (BAD)")
    except RSZeroError as exc:
        check(
            "stuck r==0 nonce is bounded",
            len(stuck_nonce.calls) == 128,
            "draws={0}, {1}".format(len(stuck_nonce.calls), exc),
        )

    scenario("Deterministic path: independent RFC6979 contract")
    sig1 = sk.sign_deterministic(b"\x00\x4f")
    sig2 = sk.sign_deterministic(b"\x00\x4f")
    check(
        "deterministic signature stable through RSZero retry",
        sig1 == sig2 == b"\x36\x9e",
        repr(sig1),
    )

    scenario("Taxonomy")
    check(
        "EntropyError is RuntimeError, not ValueError",
        issubclass(EntropyError, RuntimeError)
        and not issubclass(EntropyError, ValueError),
    )

    print("\n{0} failure(s)".format(len(FAILURES)))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
