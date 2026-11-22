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
"""Functional tests for the transfer-manager level disk reservation budget.

These tests drive the real ``TransferManager.download`` machinery against an
in-process fake S3 client (no network). Two downloads of different sizes are
used to exercise rejection, waiting/relay, cancellation, physical allocation
failure and successful rename. Budget correctness is asserted both through the
reservation manager counters and through the actual temporary files on the
shared disk.
"""

import glob
import os
import shutil
import tempfile
import threading
import time
from io import BytesIO

from botocore.session import Session

from s3transfer.diskio import DiskReservationManager
from s3transfer.exceptions import (
    CancelledError,
    DiskReservationLimitExceededError,
)
from s3transfer.manager import TransferConfig, TransferManager
from s3transfer.utils import OSUtils
from tests import skip_if_using_serial_implementation, unittest

# Every test here relies on the submission, request and io work running on
# real worker threads (blocking socket reads, reservation waiters and relay
# between transfers). The serial executor runs everything inline on the test
# thread, so these scenarios are skipped in that mode.
MODULE_SKIP = skip_if_using_serial_implementation(
    'Disk reservation concurrency tests require worker threads.'
)


class FakeBody(BytesIO):
    """A Body whose read() can block until a release event is set."""

    def __init__(self, data, gate=None):
        super().__init__(data)
        self._gate = gate

    def read(self, amount=-1):
        if self._gate is not None and self.tell() == 0:
            # Block the first read until the test releases the transfer.
            self._gate.wait()
        return super().read(amount)


class FakeS3Client:
    """Minimal, thread-safe S3 client backed by an in-memory object store."""

    def __init__(self, objects):
        # objects maps (bucket, key) -> bytes
        self._objects = objects
        self.meta = (
            Session()
            .create_client(
                's3',
                region_name='us-west-2',
                aws_access_key_id='foo',
                aws_secret_access_key='bar',
            )
            .meta
        )
        self._lock = threading.Lock()
        self._gates = {}
        self.head_calls = 0
        self.get_calls = 0

    def head_object(self, Bucket=None, Key=None, **kwargs):
        with self._lock:
            self.head_calls += 1
        size = len(self._objects[(Bucket, Key)])
        return {'ContentLength': size, 'ETag': f'"etag-{size}"'}

    def get_object(self, Bucket=None, Key=None, **kwargs):
        with self._lock:
            self.get_calls += 1
            data = self._objects[(Bucket, Key)]
            # Peek rather than pop: a key can be GET-ed more than once
            # (e.g. a relayed or retried download) and every blocked stream
            # must share the same gate until the test releases it.
            gate = self._gates.get((Bucket, Key))
        return {'Body': FakeBody(data, gate), 'ETag': f'"etag-{len(data)}"'}

    def install_gate(self, bucket, key, event):
        self._gates[(bucket, key)] = event

    def clear_gate(self, bucket, key):
        self._gates.pop((bucket, key), None)


class TrackingOSUtils(OSUtils):
    """OSUtils that records temp files and can force allocation failure."""

    def __init__(self, fail_allocate_for=None):
        super().__init__()
        self._lock = threading.Lock()
        self.temp_filenames = []
        self.allocate_calls = []
        self.rename_calls = []
        # Final filenames whose temporary file allocation should fail.
        self.fail_allocate_for = fail_allocate_for or []
        self._temp_to_final = {}

    def get_temp_filename(self, filename):
        temp_filename = super().get_temp_filename(filename)
        with self._lock:
            self.temp_filenames.append(temp_filename)
            self._temp_to_final[temp_filename] = filename
        return temp_filename

    def allocate(self, filename, size):
        with self._lock:
            self.allocate_calls.append((filename, size))
            should_fail = (
                self._temp_to_final.get(filename) in self.fail_allocate_for
            )
        if should_fail:
            raise OSError('Simulated disk allocation failure')
        return super().allocate(filename, size)

    def rename_file(self, current_filename, new_filename):
        with self._lock:
            self.rename_calls.append((current_filename, new_filename))
        return super().rename_file(current_filename, new_filename)

    def existing_temp_files(self):
        return [path for path in self.temp_filenames if os.path.exists(path)]


class BudgetInvariantChecker:
    """Samples reservation counters and temp files until stopped."""

    def __init__(self, reservation_manager, osutil, limit_bytes):
        self._reservation_manager = reservation_manager
        self._osutil = osutil
        self._limit_bytes = limit_bytes
        self._stop = threading.Event()
        self.counter_violations = []
        self.temp_file_violations = []
        self.samples = 0
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=5)
        self.assert_clean()

    def _run(self):
        while not self._stop.is_set():
            reserved = self._reservation_manager.reserved_bytes
            if reserved > self._limit_bytes or reserved < 0:
                self.counter_violations.append(reserved)
            on_disk = 0
            for path in self._osutil.existing_temp_files():
                # A temp file can be renamed or removed between the listing
                # and this stat; treat a file that disappeared as zero bytes.
                try:
                    on_disk += os.path.getsize(path)
                except OSError:
                    continue
            if on_disk > self._limit_bytes:
                self.temp_file_violations.append(on_disk)
            self.samples += 1
            time.sleep(0.002)

    def assert_clean(self):
        assert self.samples > 0, 'invariant checker never sampled'
        assert self.counter_violations == [], self.counter_violations
        assert self.temp_file_violations == [], self.temp_file_violations


class BaseDiskReservationTest(unittest.TestCase):
    BUCKET = 'bucket'

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        self.small_size = 20
        self.large_size = 80
        self.limit_bytes = self.small_size + self.large_size
        self.small_content = b's' * self.small_size
        self.large_content = b'l' * self.large_size
        self.small_key = 'small-object'
        self.large_key = 'large-object'
        self.extra_key = 'extra-object'
        self.extra_content = b'e' * self.large_size
        self.objects = {
            (self.BUCKET, self.small_key): self.small_content,
            (self.BUCKET, self.large_key): self.large_content,
            (self.BUCKET, self.extra_key): self.extra_content,
        }
        self.client = FakeS3Client(self.objects)
        self.osutil = TrackingOSUtils()
        self.reservation_manager = DiskReservationManager(self.limit_bytes)
        self.config = TransferConfig(
            max_request_concurrency=4,
            max_submission_concurrency=4,
        )
        self.manager = TransferManager(
            self.client,
            self.config,
            osutil=self.osutil,
            disk_reservation_manager=self.reservation_manager,
        )

    def tearDown(self):
        self.manager.shutdown()
        shutil.rmtree(self.tempdir, ignore_errors=True)

    def path_for(self, name):
        return os.path.join(self.tempdir, name)

    def assert_no_temp_files_left(self):
        leftovers = [
            path
            for path in glob.glob(os.path.join(self.tempdir, '*'))
            if os.path.basename(path)
            not in ('small.bin', 'large.bin', 'extra.bin', 'waiting.bin')
        ]
        self.assertEqual(leftovers, [])


@MODULE_SKIP
class TestRejectMode(BaseDiskReservationTest):
    def setUp(self):
        super().setUp()
        self.config.disk_reservation_blocking = False

    def test_rejects_when_budget_exhausted_and_releases_after_failure(self):
        # Hold the entire budget outside of a transfer.
        holder = self.reservation_manager.reserve(self.limit_bytes)

        future = self.manager.download(
            self.BUCKET, self.small_key, self.path_for('small.bin')
        )
        with self.assertRaises(DiskReservationLimitExceededError):
            future.result()

        # The rejected download must not have reserved anything and must not
        # leave a temporary file behind.
        self.assertEqual(
            self.reservation_manager.reserved_bytes, self.limit_bytes
        )
        self.assertEqual(self.osutil.existing_temp_files(), [])

        holder.release()
        self.assertEqual(self.reservation_manager.reserved_bytes, 0)

    def test_reject_mode_still_allows_fitting_download(self):
        future = self.manager.download(
            self.BUCKET, self.small_key, self.path_for('small.bin')
        )
        future.result()
        self.assertEqual(self.reservation_manager.reserved_bytes, 0)
        with open(self.path_for('small.bin'), 'rb') as f:
            self.assertEqual(f.read(), self.small_content)


@MODULE_SKIP
class TestWaitAndRelay(BaseDiskReservationTest):
    def test_large_download_waits_and_small_relays_then_succeeds(self):
        checker = BudgetInvariantChecker(
            self.reservation_manager, self.osutil, self.limit_bytes
        )
        checker.start()
        try:
            large_gate = threading.Event()
            self.client.install_gate(self.BUCKET, self.large_key, large_gate)
            large_path = self.path_for('large.bin')
            small_path = self.path_for('small.bin')

            large_future = self.manager.download(
                self.BUCKET, self.large_key, large_path
            )

            def large_file_fully_allocated():
                # Budget reservation and physical allocation happen in quick
                # succession; wait for both so the assertion cannot race the
                # allocate() call.
                temp_files = self.osutil.existing_temp_files()
                if len(temp_files) != 1:
                    return False
                try:
                    return (
                        os.path.getsize(temp_files[0]) == self.large_size
                        and self.reservation_manager.reserved_bytes
                        == self.large_size
                    )
                except OSError:
                    return False

            self._wait_until(large_file_fully_allocated)
            self.assertEqual(
                self.reservation_manager.available_bytes, self.small_size
            )

            # The small download fits in the remaining budget and completes
            # (rename included) while the large one is still in flight.
            small_future = self.manager.download(
                self.BUCKET, self.small_key, small_path
            )
            small_future.result()
            self.assertTrue(os.path.exists(small_path))
            self.assertEqual(
                self.reservation_manager.reserved_bytes, self.large_size
            )

            # A third download that does not fit must queue up and wait
            # rather than overshooting the budget. It targets its own object
            # key so its stream lifecycle is independent of the large one.
            extra_path = self.path_for('extra.bin')
            extra_future = self.manager.download(
                self.BUCKET, self.extra_key, extra_path
            )
            self._wait_until(lambda: self.reservation_manager.num_waiters == 1)
            self.assertEqual(
                self.reservation_manager.reserved_bytes, self.large_size
            )

            # Release the large GET; the large download finishes its rename
            # and frees the budget, unblocking the waiting extra download.
            large_gate.set()
            large_future.result()
            self.assertTrue(os.path.exists(large_path))
            extra_future.result()
            self.assertTrue(os.path.exists(extra_path))
        finally:
            # Make sure no parked socket gate can survive a failed assertion
            # and wedge the manager shutdown in tearDown.
            large_gate.set()
            checker.stop()

        self.assertEqual(self.reservation_manager.reserved_bytes, 0)
        self.assert_no_temp_files_left()
        with open(large_path, 'rb') as f:
            self.assertEqual(f.read(), self.large_content)
        with open(extra_path, 'rb') as f:
            self.assertEqual(f.read(), self.extra_content)

    def test_cancelled_waiter_is_unblocked_and_releases_nothing(self):
        large_gate = threading.Event()
        self.client.install_gate(self.BUCKET, self.large_key, large_gate)
        large_future = self.manager.download(
            self.BUCKET, self.large_key, self.path_for('large.bin')
        )
        self._wait_until(
            lambda: self.reservation_manager.reserved_bytes == self.large_size
        )

        # Two small-sized reservations would exceed the remaining 20 bytes,
        # so this download blocks waiting for budget.
        waiting_future = self.manager.download(
            self.BUCKET, self.large_key, self.path_for('waiting.bin')
        )
        self._wait_until(lambda: self.reservation_manager.num_waiters == 1)

        waiting_future.cancel()
        with self.assertRaises(CancelledError):
            waiting_future.result()
        self.assertEqual(self.reservation_manager.num_waiters, 0)
        # Cancellation of the waiter must not disturb the large reservation.
        self.assertEqual(
            self.reservation_manager.reserved_bytes, self.large_size
        )

        large_gate.set()
        large_future.result()
        self.assertEqual(self.reservation_manager.reserved_bytes, 0)
        self.assert_no_temp_files_left()

    def test_cancelled_inflight_download_releases_its_budget(self):
        large_gate = threading.Event()
        self.client.install_gate(self.BUCKET, self.large_key, large_gate)
        large_future = self.manager.download(
            self.BUCKET, self.large_key, self.path_for('large.bin')
        )
        self._wait_until(
            lambda: self.reservation_manager.reserved_bytes == self.large_size
        )

        large_future.cancel()
        # The GET worker is parked inside the (simulated) socket read and can
        # only observe the cancellation once the read returns, so release the
        # gate before waiting on the future.
        large_gate.set()
        with self.assertRaises(CancelledError):
            large_future.result()

        self._wait_until(lambda: self.reservation_manager.reserved_bytes == 0)
        self.assertEqual(
            self.reservation_manager.available_bytes, self.limit_bytes
        )
        self.assertEqual(self.osutil.existing_temp_files(), [])
        self.assert_no_temp_files_left()

    def test_allocation_failure_releases_budget_and_removes_temp_file(self):
        final_path = self.path_for('small.bin')
        failing_osutil = TrackingOSUtils(fail_allocate_for=[final_path])
        manager = TransferManager(
            self.client,
            self.config,
            osutil=failing_osutil,
            disk_reservation_manager=self.reservation_manager,
        )
        try:
            future = manager.download(self.BUCKET, self.small_key, final_path)
            with self.assertRaises(OSError):
                future.result()
        finally:
            manager.shutdown()

        # Budget was reserved then returned immediately on allocation failure.
        self.assertEqual(self.reservation_manager.reserved_bytes, 0)
        self.assertEqual(failing_osutil.existing_temp_files(), [])
        self.assertFalse(os.path.exists(self.path_for('small.bin')))

    def test_in_memory_download_ignores_disk_budget(self):
        # Exhaust the entire disk budget first.
        holder = self.reservation_manager.reserve(self.limit_bytes)
        self.assertEqual(self.reservation_manager.available_bytes, 0)

        stream = BytesIO()
        future = self.manager.download(self.BUCKET, self.small_key, stream)
        future.result()

        stream.seek(0)
        self.assertEqual(stream.read(), self.small_content)
        # The in-memory destination neither consumed nor released disk budget.
        self.assertEqual(
            self.reservation_manager.reserved_bytes, self.limit_bytes
        )
        self.assertEqual(self.osutil.existing_temp_files(), [])
        holder.release()

    def _wait_until(self, predicate, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        self.fail(f'condition not met within {timeout}s')
