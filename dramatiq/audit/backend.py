# This file is a part of Dramatiq.
#
# Copyright (C) 2017,2018 CLEARTYPE SRL <bogdan@cleartype.io>
#
# Dramatiq is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at
# your option) any later version.
#
# Dramatiq is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import annotations

import threading
from typing import Optional

from ..common import current_millis
from .receipt import AuditReceipt, DeliveryReceipt


class AuditBackend:
    """Base class for audit backends.

    An audit backend records :class:`AuditReceipt` instances as
    messages move through a worker.  Backends must be thread-safe as
    the callbacks may be invoked from any number of worker threads.
    The default implementations are no-ops so subclasses only need to
    implement the storage they care about.
    """

    def open_receipt(self, receipt: AuditReceipt, delivery: DeliveryReceipt) -> None:
        """Record a new delivery attempt for a message.

        Parameters:
          receipt(AuditReceipt): The receipt the delivery belongs to.
          delivery(DeliveryReceipt): The newly opened delivery.
        """
        raise NotImplementedError

    def update_delivery(
        self,
        message_id: str,
        attempt: int,
        *,
        processed_at: Optional[int] = None,
        exception_type: Optional[str] = None,
        result_stored_at: Optional[int] = None,
        stored_exception_type: Optional[str] = None,
        acked_at: Optional[int] = None,
        nacked_at: Optional[int] = None,
    ) -> None:
        """Update a previously recorded delivery.

        Only the fields that are passed in are updated.

        Parameters:
          message_id(str): The id of the audited message.
          attempt(int): The 1-based delivery attempt to update.
        """
        raise NotImplementedError

    def get_receipt(self, message_id: str) -> Optional[AuditReceipt]:
        """Return the receipt for a message, or ``None`` if it was
        never recorded.
        """
        raise NotImplementedError

    def get_all_receipts(self) -> list[AuditReceipt]:
        """Return every receipt recorded so far."""
        raise NotImplementedError


class InMemoryAuditBackend(AuditBackend):
    """An audit backend that keeps receipts in process memory.

    This backend is intended for tests and short-lived investigations.
    Access is guarded by a lock so it is safe to share between worker
    threads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._receipts: dict[str, AuditReceipt] = {}

    def open_receipt(self, receipt: AuditReceipt, delivery: DeliveryReceipt) -> None:
        with self._lock:
            existing = self._receipts.get(receipt.message_id)
            if existing is None:
                receipt.deliveries.append(delivery)
                self._receipts[receipt.message_id] = receipt
            else:
                existing.deliveries.append(delivery)

    def update_delivery(
        self,
        message_id: str,
        attempt: int,
        *,
        processed_at: Optional[int] = None,
        exception_type: Optional[str] = None,
        result_stored_at: Optional[int] = None,
        stored_exception_type: Optional[str] = None,
        acked_at: Optional[int] = None,
        nacked_at: Optional[int] = None,
    ) -> None:
        with self._lock:
            receipt = self._receipts.get(message_id)
            if receipt is None:
                return

            try:
                delivery = receipt.deliveries[attempt - 1]
            except IndexError:
                return

            if processed_at is not None:
                delivery.processed_at = processed_at
            if exception_type is not None:
                delivery.exception_type = exception_type
            if result_stored_at is not None:
                delivery.result_stored_at = result_stored_at
            if stored_exception_type is not None:
                delivery.stored_exception_type = stored_exception_type
            if acked_at is not None:
                delivery.acked_at = acked_at
            if nacked_at is not None:
                delivery.nacked_at = nacked_at

    def get_receipt(self, message_id: str) -> Optional[AuditReceipt]:
        with self._lock:
            return self._receipts.get(message_id)

    def get_all_receipts(self) -> list[AuditReceipt]:
        with self._lock:
            return list(self._receipts.values())

    def flush(self) -> None:
        """Drop every recorded receipt."""
        with self._lock:
            self._receipts.clear()


def timestamp_ms() -> int:
    """The current time in milliseconds.  Exposed for test patching."""
    return current_millis()
