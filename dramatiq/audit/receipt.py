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

import dataclasses
from typing import Optional


@dataclasses.dataclass(slots=True)
class DeliveryReceipt:
    """An audit record of a single delivery attempt of a message.

    The timestamps let investigators distinguish the three stages of
    consumption that may fail independently of each other: the actor
    call (``started_at``/``processed_at``), result storage
    (``result_stored_at``) and broker acknowledgement
    (``acked_at``/``nacked_at``).

    Attributes:
      attempt(int): The 1-based index of this delivery within the
        receipt.  A value greater than one means the broker redelivered
        a message that had already been processed at least once.
      queue_name(str): The queue the message was consumed from.
      actor_name(str): The actor that handled the message.
      started_at(int): The time, in milliseconds, at which the actor
        call started.
      processed_at(Optional[int]): The time, in milliseconds, at which
        the actor call returned.  ``None`` until the actor has run.
      exception_type(Optional[str]): The name of the exception type the
        actor raised, if any.
      result_stored_at(Optional[int]): The time, in milliseconds, at
        which the actor's result was stored by the Results middleware.
        ``None`` when results are not stored or storage failed.
      stored_exception_type(Optional[str]): The name of the exception
        type stored as the message's result, if any.
      acked_at(Optional[int]): The time, in milliseconds, at which the
        broker acknowledged the message.  ``None`` means the broker has
        not confirmed this delivery, so it may be redelivered.
      nacked_at(Optional[int]): The time, in milliseconds, at which the
        message was rejected (moved to the dead-letter queue).
    """

    attempt: int
    queue_name: str
    actor_name: str
    started_at: int
    processed_at: Optional[int] = None
    exception_type: Optional[str] = None
    result_stored_at: Optional[int] = None
    stored_exception_type: Optional[str] = None
    acked_at: Optional[int] = None
    nacked_at: Optional[int] = None

    @property
    def confirmed(self) -> bool:
        """Whether the broker has acknowledged this delivery."""
        return self.acked_at is not None


@dataclasses.dataclass(slots=True)
class AuditReceipt:
    """The complete audit trail of a message, across all of its
    deliveries.

    Attributes:
      message_id(str): The id of the audited message.  Every redelivery
        of the same message shares this id, which is what ties the
        individual :class:`DeliveryReceipt` instances together.
      queue_name(str): The queue the message was consumed from.
      actor_name(str): The actor that handled the message.
      deliveries(list[DeliveryReceipt]): One receipt per delivery
        attempt, in delivery order.
    """

    message_id: str
    queue_name: str
    actor_name: str
    deliveries: list[DeliveryReceipt] = dataclasses.field(default_factory=list)

    @property
    def delivery_count(self) -> int:
        """The number of times the message has been delivered."""
        return len(self.deliveries)

    @property
    def redelivered(self) -> bool:
        """Whether the message was delivered more than once."""
        return len(self.deliveries) > 1

    @property
    def last_delivery(self) -> DeliveryReceipt:
        """The receipt of the most recent delivery attempt."""
        return self.deliveries[-1]

    @property
    def confirmed(self) -> bool:
        """Whether the broker has acknowledged at least one delivery.

        A message whose work is done but whose receipt is not confirmed
        is a candidate for duplicate processing and should be verified
        before any side effects are trusted.
        """
        return any(delivery.confirmed for delivery in self.deliveries)
