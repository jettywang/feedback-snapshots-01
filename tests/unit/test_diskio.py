# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
import threading

from s3transfer.diskio import DiskReservation, DiskReservationManager
from s3transfer.exceptions import (
    CancelledError,
    DiskReservationLimitExceededError,
)
from tests import unittest


class TestDiskReservationManager(unittest.TestCase):
    def setUp(self):
        self.manager = DiskReservationManager(100)

    def test_invalid_limit_rejected(self):
        with self.assertRaises(ValueError):
            DiskReservationManager(0)
        with self.assertRaises(ValueError):
            DiskReservationManager(-1)
        with self.assertRaises(ValueError):
            DiskReservationManager(None)

    def test_reserve_tracks_available_bytes(self):
        self.assertEqual(self.manager.reserved_bytes, 0)
        self.assertEqual(self.manager.available_bytes, 100)

        reservation = self.manager.reserve(40)
        self.assertIsInstance(reservation, DiskReservation)
        self.assertEqual(reservation.amount, 40)
        self.assertEqual(self.manager.reserved_bytes, 40)
        self.assertEqual(self.manager.available_bytes, 60)

        reservation.release()
        self.assertEqual(self.manager.reserved_bytes, 0)
        self.assertEqual(self.manager.available_bytes, 100)

    def test_reserve_exactly_at_limit_is_allowed(self):
        reservation = self.manager.reserve(100)
        self.assertEqual(self.manager.reserved_bytes, 100)
        self.assertEqual(self.manager.available_bytes, 0)
        reservation.release()

    def test_zero_byte_reservation_consumes_nothing(self):
        reservation = self.manager.reserve(0)
        self.assertEqual(reservation.amount, 0)
        self.assertEqual(self.manager.reserved_bytes, 0)
        # Releasing it must not drive the counter negative.
        reservation.release()
        self.assertEqual(self.manager.reserved_bytes, 0)

    def test_negative_reservation_rejected(self):
        with self.assertRaises(ValueError):
            self.manager.reserve(-1)

    def test_nonblocking_reserve_raises_when_budget_exhausted(self):
        self.manager.reserve(70)
        with self.assertRaises(DiskReservationLimitExceededError):
            self.manager.reserve(40, blocking=False)
        # The rejected request must not have mutated the counters.
        self.assertEqual(self.manager.reserved_bytes, 70)

    def test_request_larger_than_limit_always_rejected(self):
        with self.assertRaises(DiskReservationLimitExceededError):
            self.manager.reserve(101, blocking=True)
        self.assertEqual(self.manager.reserved_bytes, 0)

    def test_release_is_idempotent(self):
        reservation = self.manager.reserve(50)
        reservation.release()
        reservation.release()
        self.assertTrue(reservation.released)
        self.assertEqual(self.manager.reserved_bytes, 0)

    def test_context_manager_releases_on_exit(self):
        with self.manager.reservation(60):
            self.assertEqual(self.manager.reserved_bytes, 60)
        self.assertEqual(self.manager.reserved_bytes, 0)

    def test_context_manager_releases_on_exception(self):
        with self.assertRaises(RuntimeError):
            with self.manager.reservation(60):
                raise RuntimeError('boom')
        self.assertEqual(self.manager.reserved_bytes, 0)

    def test_blocking_reserve_waits_then_proceeds_on_release(self):
        holder = self.manager.reserve(80)
        waiter_errors = []

        def wait_for_budget():
            try:
                # Needs 50 but only 20 are free; it has to wait.
                with self.manager.reservation(50):
                    pass
            except BaseException as e:
                waiter_errors.append(e)

        thread = threading.Thread(target=wait_for_budget)
        thread.start()
        self._wait_for_num_waiters(1)
        self.assertEqual(self.manager.reserved_bytes, 80)

        holder.release()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(waiter_errors, [])
        # The waiter's reservation was released when its block exited.
        self.assertEqual(self.manager.reserved_bytes, 0)

    def test_blocking_reserve_aborts_when_cancelled(self):
        holder = self.manager.reserve(80)
        cancelled = threading.Event()
        waiter_errors = []

        def wait_for_budget():
            try:
                self.manager.reserve(50, is_cancelled=cancelled.is_set)
            except BaseException as e:
                waiter_errors.append(e)

        thread = threading.Thread(target=wait_for_budget)
        thread.start()
        self._wait_for_num_waiters(1)

        cancelled.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(waiter_errors), 1)
        self.assertIsInstance(waiter_errors[0], CancelledError)
        # The aborted wait must leave the held reservation untouched.
        self.assertEqual(self.manager.reserved_bytes, 80)
        holder.release()

    def test_concurrent_reservations_never_exceed_the_limit(self):
        limit = 500
        manager = DiskReservationManager(limit)
        amounts = [37, 64, 128, 200, 53, 91, 77] * 8
        violations = []
        start = threading.Event()

        def worker(amount):
            start.wait()
            with manager.reservation(amount):
                if manager.reserved_bytes > limit:
                    violations.append(manager.reserved_bytes)

        threads = [threading.Thread(target=worker, args=(a,)) for a in amounts]
        for thread in threads:
            thread.start()
        start.set()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())

        self.assertEqual(violations, [])
        self.assertEqual(manager.reserved_bytes, 0)

    def _wait_for_num_waiters(self, count, timeout=5):
        deadline_remaining = timeout
        while self.manager.num_waiters != count and deadline_remaining > 0:
            threading.Event().wait(0.01)
            deadline_remaining -= 0.01
        self.assertEqual(self.manager.num_waiters, count)
