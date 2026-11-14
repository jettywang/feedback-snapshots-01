"""Tests for the capped, randomised EdDSA batch verification API."""

import os

import pytest

from .eddsa import (
    PrivateKey,
    generator_ed25519,
    generator_ed448,
)
from .ellipticcurve import PointEdwards
from .errors import MalformedPointError
from .batch_eddsa import (
    verify_batch,
    BatchResult,
    BatchError,
    MAX_BATCH_SIZE,
    BATCH_RANDOM_BYTES,
    COEFFICIENT_MODULUS,
)
from ._compat import bytes_to_int, int_to_bytes


def _scripted_entropy(script):
    """Return an entropy callable replaying the given byte chunks."""
    state = {"index": 0}

    def entropy(size):
        chunk = script[state["index"] : state["index"] + size]
        state["index"] += size
        if len(chunk) != size:
            raise AssertionError("scripted entropy exhausted")
        return chunk

    return entropy


def _fixed_coefficient(value, count):
    """Entropy source that hands out ``count`` copies of one coefficient."""
    raw = int_to_bytes(value, BATCH_RANDOM_BYTES, "little")
    return _scripted_entropy(raw * count)


def _single_verdict(public_key, message, signature):
    try:
        return public_key.verify(message, signature)
    except (ValueError, AssertionError):
        return False


@pytest.fixture
def ed25519_batch():
    keys = [PrivateKey(generator_ed25519, os.urandom(32)) for _ in range(6)]
    return [
        (
            key.public_key(),
            b"message " + int_to_bytes(i, 1, "little"),
            key.sign(b"message " + int_to_bytes(i, 1, "little")),
        )
        for i, key in enumerate(keys)
    ]


class TestBatchHappyPath:
    def test_all_valid_accepted(self, ed25519_batch):
        result = verify_batch(ed25519_batch)
        assert result.valid
        assert result.invalid_indices == ()
        assert result.results == [True] * len(ed25519_batch)

    def test_single_item_batch(self, ed25519_batch):
        assert verify_batch(ed25519_batch[:1]).valid

    def test_ed448_batch_accepted(self):
        key = PrivateKey(generator_ed448, os.urandom(57))
        items = [
            (key.public_key(), b"ed448 payload", key.sign(b"ed448 payload")),
            (
                key.public_key(),
                b"second ed448 payload",
                key.sign(b"second ed448 payload"),
            ),
        ]
        assert verify_batch(items).valid

    def test_fixed_entropy_is_deterministic(self, ed25519_batch):
        count = len(ed25519_batch)
        first = verify_batch(
            ed25519_batch, entropy=_fixed_coefficient(12345, count)
        )
        second = verify_batch(
            ed25519_batch, entropy=_fixed_coefficient(12345, count)
        )
        assert first == second
        assert first.valid


class TestBatchFailureLocalisation:
    def test_one_bad_signature_is_located(self, ed25519_batch):
        public_key, message, signature = ed25519_batch[3]
        tampered = bytearray(signature)
        tampered[-1] ^= 0x01
        ed25519_batch[3] = (public_key, message, bytes(tampered))

        result = verify_batch(ed25519_batch)

        assert not result.valid
        assert result.invalid_indices == (3,)
        assert result[3] is False
        assert all(result[i] for i in range(6) if i != 3)

    def test_multiple_bad_signatures_are_located(self, ed25519_batch):
        # tamper with a scalar byte so R still decodes but the equation fails
        for index in (0, 2, 5):
            public_key, message, signature = ed25519_batch[index]
            tampered = bytearray(signature)
            tampered[40] ^= 0x01
            ed25519_batch[index] = (public_key, message, bytes(tampered))

        result = verify_batch(ed25519_batch)

        assert result.invalid_indices == (0, 2, 5)
        assert result.results == [False, True, False, True, True, False]

    def test_fallback_matches_independent_single_verifier(self, ed25519_batch):
        public_key, message, signature = ed25519_batch[1]
        tampered = bytearray(signature)
        tampered[35] = (tampered[35] + 7) % 256
        ed25519_batch[1] = (public_key, message, bytes(tampered))

        result = verify_batch(ed25519_batch)

        for index, (pk, data, sig) in enumerate(ed25519_batch):
            assert result[index] == _single_verdict(pk, data, sig)

    def test_repeated_calls_do_not_cache_verdicts(self, ed25519_batch):
        public_key, message, signature = ed25519_batch[4]
        tampered = bytearray(signature)
        tampered[-1] ^= 0x01
        ed25519_batch[4] = (public_key, message, bytes(tampered))

        first = verify_batch(ed25519_batch)
        second = verify_batch(ed25519_batch)

        assert not first.valid and not second.valid
        assert first.invalid_indices == second.invalid_indices == (4,)

        # repair the item: the next call must evaluate it afresh, never
        # remembering an earlier accidental acceptance
        ed25519_batch[4] = (public_key, message, signature)
        assert verify_batch(ed25519_batch).valid


class TestCancellingErrors:
    """Two individually invalid signatures whose errors negate each other."""

    def _cancelling_pair(self):
        key = PrivateKey(generator_ed25519, os.urandom(32))
        public_key = key.public_key()
        message = b"archive record"
        signature = key.sign(message)
        scalar = bytes_to_int(signature[32:], "little")
        order = generator_ed25519.order()
        if not (0 < scalar < order - 1):
            pytest.skip("unlucky scalar, rerun the test")

        sig_plus = signature[:32] + int_to_bytes(scalar + 1, 32, "little")
        sig_minus = signature[:32] + int_to_bytes(scalar - 1, 32, "little")
        return public_key, message, sig_plus, sig_minus

    def test_each_artificial_sample_fails_alone(self):
        pk, message, sig_plus, sig_minus = self._cancelling_pair()
        with pytest.raises(ValueError):
            pk.verify(message, sig_plus)
        with pytest.raises(ValueError):
            pk.verify(message, sig_minus)

    def test_naive_summation_is_fooled_but_items_remain_invalid(self):
        # With every coefficient fixed to 1 the randomised equation degrades
        # into plain summation and the two errors cancel, reproducing the
        # exact attack that naive batch verification is vulnerable to.
        pk, message, sig_plus, sig_minus = self._cancelling_pair()
        items = [(pk, message, sig_plus), (pk, message, sig_minus)]

        fooled = verify_batch(items, entropy=_fixed_coefficient(1, 2))
        assert fooled.valid

        # failure localisation still reports both items as individually bad
        fallback = BatchResult(
            [
                _single_verdict(pk, message, sig_plus),
                _single_verdict(pk, message, sig_minus),
            ]
        )
        assert fallback.invalid_indices == (0, 1)

    def test_production_randomness_rejects_the_pair(self):
        pk, message, sig_plus, sig_minus = self._cancelling_pair()
        items = [(pk, message, sig_plus), (pk, message, sig_minus)]
        # for each fresh coefficient vector at most one value satisfies the
        # equation, so 20 independent tries must all reject
        for _ in range(20):
            result = verify_batch(items)
            assert not result.valid
            assert result.invalid_indices == (0, 1)


class TestRandomnessContract:
    def test_default_entropy_is_os_urandom(self):
        import inspect
        from . import batch_eddsa

        assert "entropy=os.urandom" in inspect.getsource(
            batch_eddsa.verify_batch
        )

    def test_none_entropy_rejected(self, ed25519_batch):
        with pytest.raises(BatchError):
            verify_batch(ed25519_batch, entropy=None)

    def test_non_callable_entropy_rejected(self, ed25519_batch):
        with pytest.raises(BatchError):
            verify_batch(ed25519_batch, entropy=b"\x01" * 16)

    def test_entropy_wrong_output_size_rejected(self, ed25519_batch):
        with pytest.raises(BatchError):
            verify_batch(
                ed25519_batch, entropy=lambda size: b"\x00" * (size - 1)
            )

    def test_zero_coefficient_is_rerolled(self, ed25519_batch):
        count = len(ed25519_batch)
        zero = b"\x00" * BATCH_RANDOM_BYTES
        one = int_to_bytes(1, BATCH_RANDOM_BYTES, "little")
        # the first draw for item 0 is zero and must be replaced
        entropy = _scripted_entropy(zero + one * count)
        assert verify_batch(ed25519_batch, entropy=entropy).valid

    def test_coefficient_range_constant(self):
        assert BATCH_RANDOM_BYTES == 16
        assert COEFFICIENT_MODULUS == 2**128

    def test_fresh_coefficients_per_call(self, ed25519_batch):
        seen = []

        def recording_entropy(size):
            chunk = os.urandom(size)
            seen.append(chunk)
            return chunk

        verify_batch(ed25519_batch, entropy=recording_entropy)
        verify_batch(ed25519_batch, entropy=recording_entropy)
        assert seen[:6] != seen[6:]


class TestBatchCapAndValidation:
    def test_empty_batch_rejected(self):
        with pytest.raises(BatchError):
            verify_batch([])

    def test_batch_over_cap_rejected(self, ed25519_batch):
        with pytest.raises(BatchError):
            verify_batch(ed25519_batch, max_batch_size=3)

    def test_cap_above_hard_limit_rejected(self, ed25519_batch):
        with pytest.raises(BatchError):
            verify_batch(ed25519_batch, max_batch_size=MAX_BATCH_SIZE + 1)

    def test_batch_at_cap_accepted(self, ed25519_batch):
        result = verify_batch(ed25519_batch, max_batch_size=len(ed25519_batch))
        assert result.valid

    def test_mixed_curves_rejected(self):
        ed25519_key = PrivateKey(generator_ed25519, os.urandom(32))
        ed448_key = PrivateKey(generator_ed448, os.urandom(57))
        items = [
            (ed25519_key.public_key(), b"a", ed25519_key.sign(b"a")),
            (ed448_key.public_key(), b"b", ed448_key.sign(b"b")),
        ]
        with pytest.raises(BatchError):
            verify_batch(items)

    def test_bad_signature_length_raises(self, ed25519_batch):
        public_key, message, _ = ed25519_batch[0]
        ed25519_batch[0] = (public_key, message, b"\x00" * 31)
        with pytest.raises(ValueError):
            verify_batch(ed25519_batch)

    def test_malformed_R_point_raises(self, ed25519_batch):
        # encoding guaranteed not to map onto the curve, same vector used by
        # the single-signature malformed-point tests
        off_curve = b"\x78" + b"\x66" * 31
        public_key, message, signature = ed25519_batch[0]
        ed25519_batch[0] = (
            public_key,
            message,
            off_curve + signature[32:],
        )
        with pytest.raises(MalformedPointError):
            verify_batch(ed25519_batch)

    def test_scalar_out_of_range_raises(self, ed25519_batch):
        public_key, message, signature = ed25519_batch[0]
        order = generator_ed25519.order()
        oversized = signature[:32] + int_to_bytes(order, 32, "little")
        ed25519_batch[0] = (public_key, message, oversized)
        with pytest.raises(ValueError):
            verify_batch(ed25519_batch)


class TestGroupOperationSavings:
    @staticmethod
    def _count_group_operations(workload):
        counter = {"adds": 0, "doubles": 0}
        original_add = PointEdwards._add
        original_double = PointEdwards._double

        def counting_add(self, *args):
            counter["adds"] += 1
            return original_add(self, *args)

        def counting_double(self, *args):
            counter["doubles"] += 1
            return original_double(self, *args)

        PointEdwards._add = counting_add
        PointEdwards._double = counting_double
        try:
            workload()
        finally:
            PointEdwards._add = original_add
            PointEdwards._double = original_double
        return counter["adds"], counter["doubles"]

    def test_batch_uses_fewer_group_operations(self, ed25519_batch):
        count = len(ed25519_batch)
        # populate generator pre-computation before measuring either path
        ed25519_batch[0][0].verify(ed25519_batch[0][1], ed25519_batch[0][2])

        def single_workload():
            for public_key, message, signature in ed25519_batch:
                public_key.verify(message, signature)

        entropy = _fixed_coefficient(1, count)

        def batch_workload():
            verify_batch(ed25519_batch, entropy=entropy)

        single_adds, single_doubles = self._count_group_operations(
            single_workload
        )
        batch_adds, batch_doubles = self._count_group_operations(
            batch_workload
        )
        single_total = single_adds + single_doubles
        batch_total = batch_adds + batch_doubles

        print(
            "\nn={0} single: {1} adds + {2} doubles = {3} ops\n"
            "n={0} batch:  {4} adds + {5} doubles = {6} ops\n"
            "savings: {7} operations ({8:.1f}%)".format(
                count,
                single_adds,
                single_doubles,
                single_total,
                batch_adds,
                batch_doubles,
                batch_total,
                single_total - batch_total,
                100.0 * (single_total - batch_total) / single_total,
            )
        )

        assert batch_total < single_total
        assert batch_doubles < single_doubles


class TestBatchResult:
    def test_container_semantics(self):
        result = BatchResult([True, False, True])
        assert not result.valid
        assert result.invalid_indices == (1,)
        assert len(result) == 3
        assert list(result) == [True, False, True]
        assert result[1] is False
        assert result == BatchResult([True, False, True])
        assert result != BatchResult([True, True, True])
        assert "invalid_indices=(1,)" in repr(result)

    def test_all_valid_result(self):
        result = BatchResult([True, True])
        assert result.valid
        assert result.invalid_indices == ()


class TestAgreesWithSingleVerifier:
    """Batch verdicts must match independent single verification."""

    @pytest.mark.parametrize("seed", range(10))
    def test_random_batches_match_single_verifier(self, seed):
        import random

        rng = random.Random(seed)
        keys = [
            PrivateKey(generator_ed25519, os.urandom(32))
            for _ in range(rng.randint(1, 8))
        ]
        items = []
        expected = []
        any_malformed = False
        for index, key in enumerate(keys):
            message = b"payload " + int_to_bytes(index, 1, "little")
            signature = bytearray(key.sign(message))
            if rng.random() < 0.4:
                # attacker-style mutation of a random byte
                signature[rng.randrange(len(signature))] ^= 1 << rng.randrange(
                    8
                )
            signature = bytes(signature)
            items.append((key.public_key(), message, signature))
            try:
                key.public_key().verify(message, signature)
            except AssertionError:
                # MalformedPointError: decoding must abort the batch with the
                # same exception single verification raises
                any_malformed = True
                expected.append(False)
            except ValueError:
                expected.append(False)
            else:
                expected.append(True)

        if any_malformed:
            with pytest.raises((ValueError, AssertionError)):
                verify_batch(items)
            return

        result = verify_batch(items)
        assert result.results == expected
        assert result.valid == all(expected)
