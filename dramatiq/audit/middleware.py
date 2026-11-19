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

from typing import TYPE_CHECKING, Any, Optional

from ..logging import get_logger
from ..middleware import Middleware
from .backend import AuditBackend, InMemoryAuditBackend, timestamp_ms
from .receipt import AuditReceipt, DeliveryReceipt

if TYPE_CHECKING:
    from ..broker import Broker, MessageProxy

#: The attribute used to attach the active delivery receipt to a
#: MessageProxy for the duration of its processing.
DELIVERY_ATTR = "_audit_delivery"


class AuditReceipts(Middleware):
    """Optional middleware that records an audit receipt for every
    processed message.

    Each receipt tracks the three stages of consumption that can fail
    independently of each other:

    1. The actor call (work returning).
    2. Result storage (when the Results middleware is enabled).
    3. Broker acknowledgement.

    Because a receipt is only marked as confirmed from the
    ``after_ack`` hook -- which the worker emits once the broker has
    actually acknowledged the message -- a message whose work finished
    but whose acknowledgement was lost is never recorded as confirmed.
    The same ``message_id`` showing up in more than one delivery is the
    correlation evidence of a redelivery and a possible duplicate.

    Example:

      >>> from dramatiq.audit import AuditReceipts, InMemoryAuditBackend
      >>> audit_backend = InMemoryAuditBackend()
      >>> broker.add_middleware(AuditReceipts(backend=audit_backend))

      >>> # After processing, inspect what actually happened:
      >>> receipt = audit_backend.get_receipt(message.message_id)
      >>> receipt.confirmed
      True
      >>> receipt.redelivered
      False

    Parameters:
      backend(AuditBackend): The backend that persists the receipts.
        Defaults to a process-local :class:`InMemoryAuditBackend`.
    """

    def __init__(self, *, backend: Optional[AuditBackend] = None) -> None:
        self.logger = get_logger(__name__, type(self))
        self.backend = backend or InMemoryAuditBackend()

    def before_process_message(self, broker: Broker, message: MessageProxy) -> None:
        existing = self.backend.get_receipt(message.message_id)
        attempt = existing.delivery_count + 1 if existing is not None else 1

        receipt = existing or AuditReceipt(
            message_id=message.message_id,
            queue_name=message.queue_name,
            actor_name=message.actor_name,
        )
        delivery = DeliveryReceipt(
            attempt=attempt,
            queue_name=message.queue_name,
            actor_name=message.actor_name,
            started_at=timestamp_ms(),
        )
        self.backend.open_receipt(receipt, delivery)
        setattr(message, DELIVERY_ATTR, delivery)

    def after_process_message(
        self,
        broker: Broker,
        message: MessageProxy,
        *,
        result: Optional[Any] = None,
        exception: Optional[BaseException] = None,
    ) -> None:
        self.backend.update_delivery(
            message.message_id,
            self._attempt(message),
            processed_at=timestamp_ms(),
            exception_type=type(exception).__name__ if exception is not None else None,
        )

    def after_skip_message(self, broker: Broker, message: MessageProxy) -> None:
        self.backend.update_delivery(
            message.message_id,
            self._attempt(message),
            processed_at=timestamp_ms(),
        )

    def after_result_stored(
        self,
        broker: Broker,
        message: MessageProxy,
        *,
        exception: Optional[BaseException] = None,
    ) -> None:
        self.backend.update_delivery(
            message.message_id,
            self._attempt(message),
            result_stored_at=timestamp_ms(),
            stored_exception_type=type(exception).__name__ if exception is not None else None,
        )

    def after_ack(self, broker: Broker, message: MessageProxy) -> None:
        self.backend.update_delivery(
            message.message_id,
            self._attempt(message),
            acked_at=timestamp_ms(),
        )

    def after_nack(self, broker: Broker, message: MessageProxy) -> None:
        self.backend.update_delivery(
            message.message_id,
            self._attempt(message),
            nacked_at=timestamp_ms(),
        )

    def _attempt(self, message: MessageProxy) -> int:
        """Return the attempt number of the delivery attached to the
        message, falling back to the most recent recorded delivery when
        the proxy does not carry one (e.g. delayed messages).
        """
        delivery = getattr(message, DELIVERY_ATTR, None)
        if delivery is not None:
            return delivery.attempt

        receipt = self.backend.get_receipt(message.message_id)
        if receipt is not None and receipt.deliveries:
            return receipt.last_delivery.attempt

        return 1
