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
"""Disk space accounting shared across all transfers of a manager.

A host running the transfer manager often has a single shared disk while
several large downloads run at the same time. The components in this module
let the manager keep an in-process reservation budget so that the aggregate
amount of disk space promised to in-flight downloads never exceeds a
configured limit, even before any byte is physically written to disk.
"""

import logging
import threading
from contextlib import contextmanager

from s3transfer.exceptions import (
    CancelledError,
    DiskReservationLimitExceededError,
)

logger = logging.getLogger(__name__)

# How long a blocking waiter sleeps between re-checks. Keeping this short
# makes cancellations and released space observable promptly while still
# avoiding a busy wait.
_WAIT_TIMEOUT = 0.05


class DiskReservation:
    """A handle representing a single granted disk reservation.

    The handle is returned by :meth:`DiskReservationManager.reserve` and can
    be released exactly once via :meth:`release` or by using it as a context
    manager.
    """

    def __init__(self, amount, manager):
        self._amount = amount
        self._manager = manager
        self._released = False
        self._lock = threading.Lock()

    @property
    def amount(self):
        """The number of bytes reserved by this handle."""
        return self._amount

    @property
    def released(self):
        with self._lock:
            return self._released

    def release(self):
        """Return the reserved bytes back to the manager.

        Releasing a handle more than once is a no-op so that cleanup paths
        for a transfer cannot accidentally corrupt the shared budget.
        """
        with self._lock:
            if self._released:
                return
            self._released = True
        self._manager._release(self._amount)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.release()


class DiskReservationManager:
    """Tracks an aggregate disk reservation budget for a transfer manager.

    The manager is a process-wide accounting primitive; it does not touch the
    filesystem. Downloads reserve the number of bytes they expect to write
    before allocating their temporary file and release the reservation as soon
    as the transfer reaches a terminal state (success, failure or cancel).

    :param limit_bytes: The maximum number of bytes that may be reserved at
        any given point in time. Must be a positive integer.
    """

    def __init__(self, limit_bytes):
        if limit_bytes is None or limit_bytes <= 0:
            raise ValueError(
                'The disk reservation limit must be greater than 0, got '
                f'{limit_bytes}.'
            )
        self._limit_bytes = limit_bytes
        self._reserved_bytes = 0
        self._num_waiters = 0
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)

    @property
    def limit_bytes(self):
        """The configured reservation cap in bytes."""
        return self._limit_bytes

    @property
    def reserved_bytes(self):
        """The number of bytes currently reserved across all transfers."""
        with self._lock:
            return self._reserved_bytes

    @property
    def available_bytes(self):
        """The number of bytes that can still be reserved right now."""
        with self._lock:
            return self._limit_bytes - self._reserved_bytes

    @property
    def num_waiters(self):
        """The number of threads currently blocked waiting for budget."""
        with self._lock:
            return self._num_waiters

    def reserve(self, amount, blocking=True, is_cancelled=None):
        """Reserve ``amount`` bytes against the shared budget.

        :param amount: The number of bytes to reserve. A reservation of zero
            bytes is granted immediately and reserves nothing.
        :param blocking: When True (the default), the call waits until enough
            budget is available. When False, it raises
            :class:`DiskReservationLimitExceededError` instead of waiting.
        :param is_cancelled: Optional zero-argument callable polled while
            blocking. When it returns True the wait aborts with a
            :class:`CancelledError`, ensuring a cancelled transfer never
            holds budget hostage while it waits.

        :rtype: DiskReservation
        :returns: A reservation handle that must be released once the
            reserved space is no longer needed.
        """
        if amount < 0:
            raise ValueError(
                f'Cannot reserve a negative amount of bytes: {amount}.'
            )
        reservation = DiskReservation(amount, self)
        if amount == 0:
            return reservation
        self._condition.acquire()
        try:
            # A request larger than the entire limit can never be satisfied,
            # even if every other reservation is released.
            if amount > self._limit_bytes:
                raise DiskReservationLimitExceededError(
                    f'Requested reservation of {amount} bytes exceeds the '
                    f'disk reservation limit of {self._limit_bytes} bytes.'
                )
            while self._reserved_bytes + amount > self._limit_bytes:
                if not blocking:
                    raise DiskReservationLimitExceededError(
                        f'Cannot reserve {amount} bytes; {self._reserved_bytes} '
                        f'of {self._limit_bytes} disk reservation bytes are '
                        'currently in use.'
                    )
                self._num_waiters += 1
                try:
                    self._condition.wait(_WAIT_TIMEOUT)
                finally:
                    self._num_waiters -= 1
                if is_cancelled is not None and is_cancelled():
                    raise CancelledError(
                        'Disk reservation wait was cancelled before budget '
                        'became available.'
                    )
            self._reserved_bytes += amount
            logger.debug(
                'Reserved %s bytes; %s of %s disk reservation bytes in use.',
                amount,
                self._reserved_bytes,
                self._limit_bytes,
            )
            return reservation
        finally:
            self._condition.release()

    @contextmanager
    def reservation(self, amount, blocking=True, is_cancelled=None):
        """Context manager granting a reservation and releasing it on exit."""
        reservation = self.reserve(
            amount, blocking=blocking, is_cancelled=is_cancelled
        )
        try:
            yield reservation
        finally:
            reservation.release()

    def _release(self, amount):
        if amount <= 0:
            return
        with self._condition:
            self._reserved_bytes -= amount
            if self._reserved_bytes < 0:
                # Defensive guard; accounting should never go negative.
                self._reserved_bytes = 0
            logger.debug(
                'Released %s bytes; %s of %s disk reservation bytes in use.',
                amount,
                self._reserved_bytes,
                self._limit_bytes,
            )
            self._condition.notify_all()
