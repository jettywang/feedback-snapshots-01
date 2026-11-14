"""Tests for bounded parallel DSSE envelope verification.

The parallel entry point is exercised with a mix of barrier-controlled fake
keys and real local signatures. The fake keys record how many plugin calls are
launched and the maximum number running concurrently, and allow tests to drive
out-of-order completion, early threshold success, cancellation and failures.
"""

import threading
import unittest
from concurrent.futures import CancelledError
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from securesystemslib import exceptions
from securesystemslib.dsse import Envelope
from securesystemslib.signer import CryptoSigner, Key, Signature

PEMS_DIR = Path(__file__).parent / "data" / "pems"
PAYLOAD = b"hello world"
PAYLOAD_TYPE = "http://example.com/HelloWorld"


class Gate:
    """A one-shot barrier that blocks a fake verification until released.

    ``wait_until_running`` lets a test wait until a worker has entered the
    plugin, providing a deterministic synchronization point without sleeping.
    """

    def __init__(self):
        self._cond = threading.Condition()
        self._running = 0
        self._open = False

    def enter(self):
        with self._cond:
            self._running += 1
            self._cond.notify_all()
            while not self._open:
                self._cond.wait()

    def wait_until_running(self, count, timeout=2.0):
        with self._cond:
            reached = self._cond.wait_for(lambda: self._running >= count, timeout)
            if not reached:
                raise AssertionError(
                    f"only {self._running} of {count} gated workers are running"
                )

    def open(self):
        with self._cond:
            self._open = True
            self._cond.notify_all()


class ConcurrencyTracker:
    """Thread-safe record of plugin launch count and peak concurrency."""

    def __init__(self):
        self._lock = threading.Lock()
        self.launches = 0
        self.active = 0
        self.max_active = 0

    def __enter__(self):
        with self._lock:
            self.launches += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        return self

    def __exit__(self, *exc):
        with self._lock:
            self.active -= 1
        return False


class FakeKey(Key):
    """A controllable verification plugin.

    Behavior is one of:

    * ``"good"`` -- verifies successfully (optionally behind a ``Gate``),
    * ``"bad"`` -- raises ``UnverifiedSignatureError`` (a bad signature),
    * ``"fault"`` -- raises ``RuntimeError`` (a plugin/process failure).

    Every call is recorded on an optional shared ``ConcurrencyTracker``.
    """

    def __init__(self, keyid, behavior="good", gate=None, tracker=None):
        super().__init__(keyid, "fake", "fake", {"public": keyid})
        self.behavior = behavior
        self.gate = gate
        self.tracker = tracker
        self.calls = 0

    def verify_signature(self, signature, data):
        self.calls += 1
        if self.tracker is not None:
            with self.tracker:
                return self._verify(signature, data)
        return self._verify(signature, data)

    def _verify(self, signature, data):
        if self.gate is not None:
            self.gate.enter()
        if self.behavior == "bad":
            raise exceptions.UnverifiedSignatureError(f"bad sig by {self.keyid}")
        if self.behavior == "fault":
            raise RuntimeError(f"plugin exploded for {self.keyid}")

    @classmethod
    def from_dict(cls, keyid, key_dict):  # pragma: no cover - unused in tests
        return cls(keyid)

    def to_dict(self):
        return self._to_dict()


class TestEnvelopeVerifyParallel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signers = []
        for keytype in ["rsa", "ecdsa", "ed25519"]:
            with open(PEMS_DIR / f"{keytype}_private.pem", "rb") as f:
                private_key = load_pem_private_key(f.read(), None)
            cls.signers.append(CryptoSigner(private_key))

    def _real_envelope(self):
        """Envelope signed by all real signers, returns (envelope, keys)."""
        envelope = Envelope(PAYLOAD, PAYLOAD_TYPE, {})
        keys = []
        for signer in self.signers:
            envelope.sign(signer)
            keys.append(signer.public_key)
        return envelope, keys

    def _fake_envelope(self, key_specs):
        """Build an envelope and trusted keys from fake key specifications.

        Each spec is ``(FakeKey, gate)``; the envelope holds a placeholder
        signature whose keyid matches the fake key.
        """
        envelope = Envelope(PAYLOAD, PAYLOAD_TYPE, {})
        keys = []
        for key, gate in key_specs:
            envelope.signatures[key.keyid] = Signature(key.keyid, "cafebabe")
            keys.append(key)
        return envelope, keys

    def test_matches_serial_verification(self):
        envelope, keys = self._real_envelope()

        serial = envelope.verify(keys, len(keys))
        for workers in (1, 2, 5):
            parallel = envelope.verify_parallel(keys, len(keys), max_workers=workers)
            self.assertEqual(serial, parallel)

    def test_threshold_returns_exactly_threshold_signers(self):
        envelope, keys = self._real_envelope()
        accepted = envelope.verify_parallel(keys, 2, max_workers=2)
        self.assertEqual(len(accepted), 2)
        trusted = {key.keyid: key for key in keys}
        for keyid, key in accepted.items():
            self.assertIs(key, trusted[keyid])

    def test_invalid_arguments(self):
        envelope, keys = self._real_envelope()
        with self.assertRaises(ValueError):
            envelope.verify_parallel(keys, 0, max_workers=2)
        with self.assertRaises(ValueError):
            envelope.verify_parallel(keys, 4, max_workers=2)
        for bad_workers in (0, -1, 1.5, "2"):
            with self.assertRaises(ValueError):
                envelope.verify_parallel(keys, 1, max_workers=bad_workers)
        with self.assertRaises(ValueError):
            envelope.verify_parallel(keys, 1, max_workers=2, timeout=-1)

    def test_out_of_order_completion(self):
        """Late and early plugins converge on the same accepted set."""

        def run_with_release_order(order):
            gates = [Gate() for _ in range(3)]
            keys_fake = [FakeKey(f"fake-{i}", gate=gates[i]) for i in range(3)]
            envelope, keys = self._fake_envelope(list(zip(keys_fake, gates)))
            for gate in gates:
                self.addCleanup(gate.open)

            result = {}
            error = []

            def worker():
                try:
                    result.update(envelope.verify_parallel(keys, 3, max_workers=3))
                except BaseException as exc:
                    error.append(exc)

            thread = threading.Thread(target=worker)
            thread.start()
            for index in order:
                gates[index].wait_until_running(1)
                gates[index].open()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive(), "verification hung")
            self.assertEqual(error, [])
            return set(result)

        first = run_with_release_order([0, 1, 2])
        second = run_with_release_order([2, 0, 1])
        self.assertEqual(first, second)
        self.assertEqual(first, {f"fake-{i}" for i in range(3)})

    def test_early_threshold_stops_launching_work(self):
        tracker = ConcurrencyTracker()
        # One shared barrier blocks every gated plugin at the same point, so
        # all worker threads are provably occupied before release.
        barrier = Gate()
        gated = [FakeKey(f"gated-{i}", gate=barrier, tracker=tracker) for i in range(4)]
        # Fast keys are queued behind the gated ones and must never run once
        # the threshold is reached early.
        fast = [
            FakeKey("fast-0", tracker=tracker),
            FakeKey("fast-1", tracker=tracker),
        ]
        specs = [(key, barrier) for key in gated] + [(key, None) for key in fast]

        envelope, keys = self._fake_envelope(specs)
        self.addCleanup(barrier.open)

        result = {}

        def worker():
            result.update(envelope.verify_parallel(keys, 2, max_workers=3))

        thread = threading.Thread(target=worker)
        thread.start()
        # All three workers are occupied behind the barrier; the remaining
        # gated item and both fast keys are still queued.
        barrier.wait_until_running(3)
        self.assertEqual(tracker.launches, 3)
        barrier.open()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive(), "verification hung")

        self.assertEqual(len(result), 2)
        # The queued fast plugins are never launched after early success.
        self.assertEqual([key.calls for key in fast], [0, 0])
        # Total plugin work stays bounded by the submitted plan.
        self.assertLessEqual(tracker.launches, len(specs))
        # In-flight gated calls were drained to completion, not force-killed.
        self.assertEqual(tracker.active, 0)

    def test_caller_cancellation_stops_and_does_not_mutate_result(self):
        tracker = ConcurrencyTracker()
        gate = Gate()
        # Two distinct signers behind one barrier: input validation passes,
        # but neither can complete while the gate is closed, so cancellation is
        # always observed before the threshold of 2 is reached.
        specs = [
            (FakeKey("cancelled-a", gate=gate, tracker=tracker), gate),
            (FakeKey("cancelled-b", gate=gate, tracker=tracker), gate),
        ]
        envelope, keys = self._fake_envelope(specs)
        self.addCleanup(gate.open)
        cancel = threading.Event()

        def cancel_when_running():
            gate.wait_until_running(1)
            cancel.set()
            # Let verify_parallel observe cancellation and reach the drain,
            # then release the in-flight calls it is waiting on.
            threading.Event().wait(0.3)
            gate.open()

        watcher = threading.Thread(target=cancel_when_running)
        watcher.start()
        with self.assertRaises(CancelledError):
            envelope.verify_parallel(keys, 2, max_workers=2, cancel_event=cancel)
        watcher.join(timeout=3)
        # Launched work was drained, not force-killed; nothing new was started
        # after the cancel event was observed.
        self.assertLessEqual(tracker.launches, 2)
        self.assertEqual(tracker.active, 0)

    def test_pre_set_cancel_event(self):
        envelope, keys = self._real_envelope()
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(CancelledError):
            envelope.verify_parallel(keys, 1, max_workers=2, cancel_event=cancel)

    def test_timeout_drains_inflight_and_raises_timeout(self):
        tracker = ConcurrencyTracker()
        gate = Gate()
        key = FakeKey("slow-key", gate=gate, tracker=tracker)
        envelope, keys = self._fake_envelope([(key, gate)])
        self.addCleanup(gate.open)

        def open_after_timeout():
            gate.wait_until_running(1)
            # Stay blocked past the timeout, then release so the draining wait
            # can complete: this proves in-flight work is not force-killed.
            threading.Event().wait(0.6)
            gate.open()

        opener = threading.Thread(target=open_after_timeout)
        opener.start()
        with self.assertRaises(TimeoutError):
            envelope.verify_parallel(keys, 1, max_workers=1, timeout=0.2)
        opener.join(timeout=3)
        # The blocked plugin was allowed to finish (drained), exactly once.
        self.assertEqual(tracker.launches, 1)
        self.assertEqual(tracker.active, 0)

    def test_bad_signature_is_verification_error(self):
        key = FakeKey("bad-key", behavior="bad")
        envelope, keys = self._fake_envelope([(key, None)])
        with self.assertRaises(exceptions.VerificationError) as ctx:
            envelope.verify_parallel(keys, 1, max_workers=2)
        # A plain bad signature carries no plugin fault cause.
        self.assertIsNone(ctx.exception.__cause__)

    def test_plugin_failure_is_distinguished_and_chained(self):
        key = FakeKey("fault-key", behavior="fault")
        envelope, keys = self._fake_envelope([(key, None)])
        with self.assertRaises(exceptions.VerificationError) as ctx:
            envelope.verify_parallel(keys, 1, max_workers=2)
        self.assertIsInstance(ctx.exception.__cause__, RuntimeError)

    def test_threshold_impossible_stops_submitting(self):
        # One good signer, a plugin fault and a bad signature: threshold 3 can
        # never be reached, so the bounded plan simply runs out of work.
        tracker = ConcurrencyTracker()
        good = FakeKey("good", tracker=tracker)
        faulty = FakeKey("faulty", behavior="fault", tracker=tracker)
        bad = FakeKey("bad", behavior="bad", tracker=tracker)
        envelope, keys = self._fake_envelope(
            [(good, None), (faulty, None), (bad, None)]
        )
        with self.assertRaises(exceptions.VerificationError):
            envelope.verify_parallel(keys, 3, max_workers=2)
        # Exactly the three bounded candidates were launched, nothing more.
        self.assertEqual(tracker.launches, 3)

    def test_concurrency_never_exceeds_bound(self):
        tracker = ConcurrencyTracker()
        # One shared barrier for four distinct signers so all three worker
        # threads are provably occupied at the same instant.
        barrier = Gate()
        specs = [
            (FakeKey(f"gated-{i}", gate=barrier, tracker=tracker), barrier)
            for i in range(4)
        ]
        envelope, keys = self._fake_envelope(specs)
        self.addCleanup(barrier.open)

        result = {}

        def worker():
            result.update(envelope.verify_parallel(keys, 4, max_workers=3))

        thread = threading.Thread(target=worker)
        thread.start()
        barrier.wait_until_running(3)
        self.assertLessEqual(tracker.active, 3)
        self.assertEqual(tracker.max_active, 3)
        barrier.open()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive(), "verification hung")
        self.assertEqual(len(result), 4)
        self.assertLessEqual(tracker.max_active, 3)

    def test_one_launch_per_signer_even_with_duplicate_work(self):
        """A malicious envelope cannot make one signer run many plugins.

        The envelope allows one signature per keyid, so duplicate counting is
        probed through repeated trusted entries for the same keyid instead.
        """
        tracker = ConcurrencyTracker()
        key = FakeKey("only-key", tracker=tracker)
        envelope, _ = self._fake_envelope([(key, None)])
        duplicate_keys = [key, key, key]
        accepted = envelope.verify_parallel(duplicate_keys, 1, max_workers=3)
        self.assertEqual(set(accepted), {"only-key"})
        self.assertEqual(tracker.launches, 1)

    def test_success_set_independent_of_failure_order(self):
        """Two good keys succeed regardless of which bad one returns first."""
        good_a = FakeKey("good-a")
        good_b = FakeKey("good-b")
        bad_x = FakeKey("bad-x", behavior="bad")
        bad_y = FakeKey("bad-y", behavior="bad")
        envelope, keys = self._fake_envelope(
            [(good_a, None), (good_b, None), (bad_x, None), (bad_y, None)]
        )
        accepted = envelope.verify_parallel(keys, 2, max_workers=4)
        self.assertEqual(set(accepted), {"good-a", "good-b"})

        # Re-run many times: completion order varies but the set must not.
        for _ in range(25):
            again = envelope.verify_parallel(keys, 2, max_workers=4)
            self.assertEqual(set(again), {"good-a", "good-b"})


if __name__ == "__main__":
    unittest.main()
