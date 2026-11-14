"""Fault-injection regression tests for the entropy call chain.

The tests exercise the two entropy-dependent flows in this package:

* random key generation (``SigningKey.generate`` for Weierstrass curves via
  :func:`ecdsa.util.randrange`, and for Edwards curves via
  :func:`ecdsa.util.entropy_bytes`), and
* probabilistic ECDSA signing (``SigningKey.sign`` -> ``sign_digest`` ->
  ``sign_number`` -> :func:`ecdsa.util.randrange`).

Every layer is given its own explicit contract, and the tests state which
failure each layer owns:

* the *entropy callback* must return exactly the requested number of bytes;
* :func:`ecdsa.util.randrange` owns the rejection-sampling budget and must
  never reduce modulo the order;
* :meth:`ecdsa.keys.SigningKey.sign_number` owns the nonce re-selection
  budget, but only for entropy-derived nonces;
* the *deterministic* RFC6979 path keeps its own independent retry contract
  (``retry_gen``) and never consults an entropy callback.

A broken entropy source must fail closed.  In particular it must never be
replaced by a time-derived value, a constant, or an implicit pseudo-random
fallback.  To make the "no infinite loop" property testable without waiting,
all loops are bounded: a stuck source raises a typed error instead of
spinning.
"""

import hashlib

import pytest

try:
    memoryview
except NameError:  # pragma: no cover - Python 2.6
    memoryview = buffer

from .curves import Curve, Ed25519, NIST192p, NIST256p
from .ecdsa import RSZeroError
from .ellipticcurve import CurveFp, PointJacobi
from .errors import EntropyError, EntropyExhaustedError, EntropySourceError
from .keys import SigningKey
from .util import bit_length, entropy_bytes, randrange


# --- layers under test -----------------------------------------------------

NIST_ORDER = NIST256p.order
NIST_SAMPLE = bit_length(NIST_ORDER - 2) // 8 + 1  # bytes randrange requests


def _toy_key():
    """A tiny curve whose complete point set can be enumerated.

    It is used to construct nonces that deterministically produce r == 0 or
    s == 0, so the nonce re-selection path can be tested without waiting for
    an astronomically unlikely event.
    """
    curve = CurveFp(163, 84, 58)
    gen = PointJacobi(curve, 2, 87, 1, 167, generator=True)
    toy = Curve("toy_p8", curve, gen, (1, 2, 0))
    return SigningKey.from_secret_exponent(140, toy, hashfunc=hashlib.sha1)


class RecordingEntropy(object):
    """Entropy source that records every request and delegates a plan.

    ``plan`` maps a 1-based call number to a return value or a callable that
    receives the requested length.  Calls past the end of the plan raise
    AssertionError so a test that accidentally loops is reported, not hung.
    """

    def __init__(self, plan):
        self.plan = plan
        self.calls = []

    def __call__(self, numbytes):
        self.calls.append(numbytes)
        index = len(self.calls)
        if index > len(self.plan):
            raise AssertionError(
                "entropy callback called {0} times, plan only covers "
                "{1}: {2!r}".format(index, len(self.plan), self.calls)
            )
        item = self.plan[index - 1]
        if callable(item):
            return item(numbytes)
        return item


# --- layer 1: entropy callback contract ------------------------------------


@pytest.mark.parametrize(
    "returned,expected",
    [
        (b"", 0),  # empty read
        (b"\x00", 1),  # one byte short of the requested 33
        (b"\x00" * 32, 32),  # short read
        (b"\x00" * 34, 34),  # one byte too many
    ],
)
def test_entropy_bytes_rejects_wrong_length(returned, expected):
    with pytest.raises(EntropySourceError) as exc:
        entropy_bytes(lambda n: returned, NIST_SAMPLE)
    message = str(exc.value)
    assert str(expected) in message
    assert str(NIST_SAMPLE) in message
    # The contract violation is unrecoverable and must not masquerade as a
    # ValueError that a broad except clause could swallow.
    assert not isinstance(exc.value, ValueError)


@pytest.mark.parametrize("bad", [None, 1234, "0123456789abcdef"])
def test_entropy_bytes_rejects_non_bytes(bad):
    with pytest.raises(EntropySourceError):
        entropy_bytes(lambda n: bad, 8)


def test_entropy_bytes_accepts_exact_bytes_like():
    values = (
        b"\x01" * 8,
        bytearray(b"\x02" * 8),
        memoryview(b"\x03" * 8),
    )
    for value in values:
        assert len(entropy_bytes(lambda n: value, 8)) == 8


def test_entropy_bytes_default_is_os_urandom():
    # Only ``None`` selects the default; the call is not a fallback.
    value = entropy_bytes(None, 16)
    assert len(value) == 16


def test_entropy_bytes_does_not_wrap_callback_exception():
    class SourceDown(Exception):
        pass

    def down(numbytes):
        raise SourceDown("device gone")

    with pytest.raises(SourceDown):
        entropy_bytes(down, 8)


# --- layer 2: randrange rejection sampling ---------------------------------


def test_randrange_short_read_is_not_silently_used():
    # Regression: a single zero byte used to be zero-padded/truncated and
    # produced k == 1.  It must now fail closed.
    with pytest.raises(EntropySourceError):
        randrange(NIST_ORDER, entropy=lambda n: b"\x00")


def test_randrange_empty_read_is_not_silently_used():
    with pytest.raises(EntropySourceError):
        randrange(NIST_ORDER, entropy=lambda n: b"")


def test_randrange_constant_short_read_never_returns():
    # A stuck short source must raise, not return a constant nonce.
    with pytest.raises(EntropySourceError):
        randrange(NIST_ORDER, entropy=lambda n: b"\xff")


def test_randrange_callback_exception_propagates_unchanged():
    class SourceDown(Exception):
        pass

    def down(numbytes):
        raise SourceDown("hwrng offline")

    with pytest.raises(SourceDown):
        randrange(NIST_ORDER, entropy=down)


def test_randrange_legitimate_rejection_then_accept():
    # For the toy order 167 the mask is the top 8 bits of a 2-byte sample.
    # 0xff.. masks to 256 (out of range, rejected), while 0x10.. masks to 16
    # and yields the valid candidate 17.  One rejection is normal and must be
    # retried, not reported as an error.
    fake = RecordingEntropy([b"\xff\xff", b"\x10\x00"])
    value = randrange(167, entropy=fake)
    assert value == 17
    assert len(fake.calls) == 2
    assert fake.calls == [2, 2]


def test_randrange_persistent_out_of_range_is_bounded():
    calls = {"n": 0}

    def always_invalid(numbytes):
        calls["n"] += 1
        return b"\xff\xff"  # masks to 256; always >= 167

    with pytest.raises(EntropyExhaustedError) as exc:
        randrange(167, entropy=always_invalid)
    # The loop terminated on its own (bounded), it did not hang.
    assert calls["n"] == 128
    assert "167" in str(exc.value)


def test_randrange_does_not_use_modulo_reduction():
    # The raw sample is masked to the order's bit length and rejected when
    # out of range.  All-ones bytes mask to exactly 2**256, which is outside
    # NIST256p's order.  A ``% order`` implementation would fold that back
    # into range (returning a biased value); the correct implementation
    # rejects it every time and exhausts the bounded budget instead.
    calls = {"n": 0}

    def all_ones(numbytes):
        calls["n"] += 1
        return b"\xff" * numbytes

    with pytest.raises(EntropyExhaustedError):
        randrange(NIST_ORDER, entropy=all_ones)
    # No sample was ever accepted (and no biased value was produced).
    assert calls["n"] == 128


@pytest.mark.parametrize(
    "order", [2 ** 8 - 2, 2 ** 8 - 1, 2 ** 8, 2 ** 16 - 1]
)
def test_randrange_result_is_in_range(order):
    calls = {"n": 0}

    def counter(numbytes):
        calls["n"] += 1
        # Deterministic but varied bytes; length honours the contract.
        seed = hashlib.sha256(str(calls["n"]).encode()).digest()
        return (seed * 8)[:numbytes]

    for _ in range(50):
        value = randrange(order, entropy=counter)
        assert 1 <= value < order


def test_randrange_default_source_is_usable():
    value = randrange(NIST_ORDER)
    assert 1 <= value < NIST_ORDER


# --- layer 3: random key generation ---------------------------------------


@pytest.mark.parametrize("curve", [NIST192p, NIST256p])
def test_weierstrass_keygen_short_read_fails_closed(curve):
    with pytest.raises(EntropySourceError):
        SigningKey.generate(curve, entropy=lambda n: b"\x00")


def test_weierstrass_keygen_exception_propagates():
    class SourceDown(Exception):
        pass

    def down(numbytes):
        raise SourceDown("no entropy")

    with pytest.raises(SourceDown):
        SigningKey.generate(NIST256p, entropy=down)


def test_weierstrass_keygen_does_not_fall_back_to_default():
    # If the supplied source fails, generate() must not quietly use
    # os.urandom.  Prove it by making the failing source the only path that
    # could set a known key, then assert the failure surfaces.
    def broken(numbytes):
        raise EntropySourceError("for test")

    with pytest.raises(EntropySourceError):
        SigningKey.generate(NIST256p, entropy=broken)


def test_edwards_keygen_empty_read_fails_closed():
    with pytest.raises(EntropySourceError):
        SigningKey.generate(Ed25519, entropy=lambda n: b"")


def test_edwards_keygen_short_read_fails_closed():
    with pytest.raises(EntropySourceError):
        SigningKey.generate(Ed25519, entropy=lambda n: b"\x00" * 31)


def test_edwards_keygen_wrong_length_is_entropy_error_not_valueerror():
    # Regression: a short Ed25519 read previously surfaced as the unrelated
    # eddsa.PrivateKey "Incorrect size of private key" ValueError.
    with pytest.raises(EntropySourceError):
        SigningKey.generate(Ed25519, entropy=lambda n: b"\x00" * 31)


def test_edwards_keygen_falsy_callable_is_not_replaced():
    # A callable whose __bool__ is False is still a valid entropy source and
    # must not be swapped for os.urandom.
    class FalsySource(object):
        def __init__(self):
            self.used = False

        def __bool__(self):
            return False

        __nonzero__ = __bool__

        def __call__(self, numbytes):
            self.used = True
            return b"\x2a" * numbytes

    source = FalsySource()
    key = SigningKey.generate(Ed25519, entropy=source)
    assert source.used is True
    assert key.to_string() == b"\x2a" * Ed25519.baselen


def test_keygen_short_read_does_not_return_predictable_key():
    # A short read must not be zero-padded into a fixed key.  If it were, two
    # generations from the same broken source would agree.
    keys = []
    for _ in range(3):
        try:
            keys.append(
                SigningKey.generate(NIST256p, entropy=lambda n: b"\x00")
            )
        except EntropySourceError:
            keys.append(None)
    assert keys == [None, None, None]


# --- layer 4: probabilistic signing (nonce selection) ---------------------


def test_sign_entropy_short_read_fails_closed():
    sk = SigningKey.generate(NIST256p)
    with pytest.raises(EntropySourceError):
        sk.sign(b"message", entropy=lambda n: b"\x00")


def test_sign_entropy_exception_propagates():
    sk = SigningKey.generate(NIST256p)

    class SourceDown(Exception):
        pass

    def down(numbytes):
        raise SourceDown("hwrng offline")

    with pytest.raises(SourceDown):
        sk.sign(b"message", entropy=down)


def test_sign_number_reselects_nonce_on_r_zero():
    # k=15 gives r == 0 on the toy curve; k=20 is fine.  The nonce layer must
    # draw again from the same source, not fail and not substitute a value.
    sk = _toy_key()
    fake = RecordingEntropy([b"\x0e\x00", b"\x13\x00"])
    r, s = sk.sign_number(54, entropy=fake)
    assert (r, s) == (54, 30)
    assert fake.calls == [2, 2]  # exactly two entropy draws, same source


def test_sign_number_bounded_when_nonce_always_zero():
    # A source that keeps yielding the r == 0 nonce must exhaust the nonce
    # budget and raise RSZeroError; it must not loop forever.
    sk = _toy_key()
    fake = RecordingEntropy([b"\x0e\x00"] * 128)

    with pytest.raises(RSZeroError) as exc:
        sk.sign_number(54, entropy=fake)
    assert len(fake.calls) == 128
    assert "128" in str(exc.value)


def test_sign_number_explicit_k_is_never_reselected():
    # An explicit k is an exact contract: RSZeroError is raised immediately
    # and the entropy source is not consulted at all.
    sk = _toy_key()
    calls = []

    def source(numbytes):
        calls.append(numbytes)
        return b"\x00\x00"

    with pytest.raises(RSZeroError):
        sk.sign_number(54, k=15, entropy=source)
    assert calls == []


def test_sign_reselects_then_succeeds():
    # End-to-end: sign() with a source whose first draw yields r == 0 and
    # whose second draw is a valid nonce.
    sk = _toy_key()
    fake = RecordingEntropy([b"\x0e\x00", b"\x2a\x00"])
    signature = sk.sign(b"message", entropy=fake, hashfunc=hashlib.sha1)
    assert signature is not None
    assert fake.calls == [2, 2]  # both draws came from the supplied source


def test_sign_reselection_result_verifies():
    sk = _toy_key()
    fake = RecordingEntropy([b"\x0e\x00", b"\x2a\x00"])
    signature = sk.sign(b"message", entropy=fake, hashfunc=hashlib.sha1)
    assert sk.verifying_key.verify(
        signature, b"message", hashfunc=hashlib.sha1
    )


# --- deterministic path keeps its independent contract --------------------


def test_deterministic_signing_is_independent_of_entropy():
    # The deterministic methods take no entropy argument.  Signing a message
    # that forces an r == 0 retry must still succeed purely from RFC6979,
    # proving the deterministic path never consults an entropy source.
    sk = _toy_key()
    signature = sk.sign_deterministic(b"\x00\x4f")
    assert signature == b"\x36\x9e"


def test_deterministic_retry_contract_is_unchanged():
    # RFC6979 retries with retry_gen, determined by the message alone.  The
    # result must be stable and independent of any entropy source.
    sk = _toy_key()
    first = sk.sign_deterministic(b"\x01\x6d")
    second = sk.sign_deterministic(b"\x01\x6d")
    assert first == second == b"\x49\x6c"

    from .rfc6979 import generate_k

    secexp = sk.privkey.secret_multiplier
    digest = hashlib.sha1(b"\x01\x6d").digest()
    k0 = generate_k(sk.curve.order, secexp, hashlib.sha1, digest, retry_gen=0)
    k1 = generate_k(sk.curve.order, secexp, hashlib.sha1, digest, retry_gen=1)
    assert k0 != k1  # retry_gen selects a different nonce, as before


def test_deterministic_sign_is_reproducible_across_keys():
    # Independent of the entropy hardening: the deterministic signature for a
    # fixed key and message is byte-for-byte stable.
    sk1 = _toy_key()
    sk2 = _toy_key()
    msg = b"reproducible"
    assert sk1.sign_deterministic(msg) == sk2.sign_deterministic(msg)


# --- error taxonomy --------------------------------------------------------


def test_entropy_errors_are_not_valueerror():
    assert not issubclass(EntropyError, ValueError)
    assert issubclass(EntropyError, RuntimeError)
    assert issubclass(EntropySourceError, EntropyError)
    assert issubclass(EntropyExhaustedError, EntropyError)


def test_no_implicit_time_or_constant_fallback_symbols():
    # Guard against a future change that quietly introduces a clock- or
    # constant-based fallback in the entropy helpers.  Inspect the *code*
    # rather than prose.
    import dis

    from . import util

    if not hasattr(dis, "get_instructions"):  # pragma: no cover
        pytest.skip("dis.get_instructions requires Python 3.4+")

    names = set()
    for func in (util.randrange, util.entropy_bytes):
        for instruction in dis.get_instructions(func):
            if instruction.opname in ("LOAD_GLOBAL", "LOAD_ATTR", "LOAD_NAME"):
                names.add(instruction.argval)
    for forbidden in ("time", "SystemRandom", "random", "getrandbits"):
        assert forbidden not in names
    # os.urandom is the documented default selected once, only when the
    # entropy argument is None; it must not appear as a fallback branch.
    assert "urandom" in names  # still the single, explicit default
