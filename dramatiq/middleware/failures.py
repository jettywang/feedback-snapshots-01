# This file is a part of Dramatiq.
#
# Copyright (C) 2017,2018,2019 CLEARTYPE SRL <bogdan@cleartype.io>
#
# Dramatiq is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at
# your option) any later version.
#
# Dramatiq is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import annotations

import dataclasses
from collections import deque
from typing import TYPE_CHECKING, Any, Callable, Optional

from ..common import current_millis
from ..errors import BrokerConnectionError, RateLimitExceeded, Retry
from ..logging import get_logger
from ..threading import Interrupt
from .middleware import Middleware

if TYPE_CHECKING:
    from ..broker import Broker, MessageProxy

#: A retry has been scheduled for the failed message.
STAGE_RETRY_SCHEDULED = "retry_scheduled"

#: The message's retry budget has been used up.
STAGE_RETRIES_EXHAUSTED = "retries_exhausted"

#: The message was deliberately not retried (eg. by ``throws`` or
#: ``retry_when``).
STAGE_REJECTED = "rejected"

#: The categories that may be assigned to errors in a failure envelope.
ERROR_CATEGORIES = frozenset(
    {
        "actor",
        "broker",
        "interrupt",
        "rate_limit",
        "retry",
        "system",
    }
)


def classify_error(exception: BaseException) -> str:
    """Return a coarse, non-sensitive category for an exception.

    The category never includes the exception's message or traceback,
    so it is safe to expose to operators.
    """
    if isinstance(exception, RateLimitExceeded):
        return "rate_limit"
    if isinstance(exception, BrokerConnectionError):
        return "broker"
    if isinstance(exception, Interrupt):
        return "interrupt"
    if isinstance(exception, Retry):
        return "retry"
    if isinstance(exception, Exception):
        return "actor"
    return "system"


@dataclasses.dataclass(frozen=True, slots=True)
class FailureEnvelope:
    """An operator-facing description of a failed message.

    Envelopes intentionally contain only routing metadata, the retry
    stage and a non-sensitive error classification.  They never
    contain the message's ``args``, ``kwargs``, ``options``,
    exception message or traceback, so they can be shown to on-call
    operators even when the payload carries customer credentials.

    Attributes:
      queue_name(str): The queue the message was consumed from.
      actor_name(str): The actor the message was addressed to.
      message_id(str): The id of the failed message.
      message_timestamp(int): When the message was first enqueued, in
        UNIX milliseconds.
      failed_at(int): When this failure was recorded, in UNIX
        milliseconds.
      stage(str): What happened after the failure.  One of
        ``"retry_scheduled"``, ``"retries_exhausted"`` or
        ``"rejected"``.
      attempts(int): The number of processing attempts made so far,
        including the attempt that failed.
      reason(str): Why the message was retried or not retried, eg.
        ``"exception"``, ``"retry_requested"``, ``"max_retries"``,
        ``"retry_when"`` or ``"throws"``.
      error_type(str): The exception class name.
      error_category(str): A coarse category, one of
        :data:`ERROR_CATEGORIES`.
      max_retries(Optional[int]): The retry budget that applied to the
        message, if any.
      retry_delay(Optional[int]): The delay before the next attempt,
        in milliseconds.  Only set when ``stage`` is
        ``"retry_scheduled"``.
    """

    queue_name: str
    actor_name: str
    message_id: str
    message_timestamp: int
    failed_at: int
    stage: str
    attempts: int
    reason: str
    error_type: str
    error_category: str
    max_retries: Optional[int] = None
    retry_delay: Optional[int] = None

    def asdict(self) -> dict[str, Any]:
        """Convert the envelope to a dictionary that is safe to send
        to an operations tooling pipeline.
        """
        return dataclasses.asdict(self)


class FailureEnvelopes(Middleware):
    """Middleware that builds an operator-readable envelope for every
    message failure and records it for an operations view.

    This relies on the |Retries| middleware, which emits the failure
    information after it has decided whether to retry, reject or give
    up on a message.  It does not expose the payload, exception message
    or traceback.

    Parameters:
      on_failure(callable): An optional callback that is called with
        each :class:`FailureEnvelope`.  Use this to forward envelopes
        to your alerting or ticketing system.
      max_envelopes(int): The maximum number of recent envelopes to
        keep in memory.  Set to ``None`` to keep all of them.
        Defaults to 1000.
    """

    def __init__(
        self,
        *,
        on_failure: Optional[Callable[[FailureEnvelope], None]] = None,
        max_envelopes: Optional[int] = 1000,
    ) -> None:
        self.logger = get_logger(__name__, type(self))
        self.on_failure = on_failure
        self.envelopes: deque[FailureEnvelope] = deque(maxlen=max_envelopes)

    def get_envelopes(self) -> tuple[FailureEnvelope, ...]:
        """Return the recorded envelopes, oldest first."""
        return tuple(self.envelopes)

    def after_message_failure(
        self,
        broker: Broker,
        message: MessageProxy,
        *,
        exception: BaseException,
        stage: str,
        reason: str,
        attempts: int,
        max_retries: Optional[int],
        retry_delay: Optional[int] = None,
    ) -> None:
        envelope = FailureEnvelope(
            queue_name=message.queue_name,
            actor_name=message.actor_name,
            message_id=message.message_id,
            message_timestamp=message.message_timestamp,
            failed_at=current_millis(),
            stage=stage,
            attempts=attempts,
            reason=reason,
            error_type=type(exception).__name__,
            error_category=classify_error(exception),
            max_retries=max_retries,
            retry_delay=retry_delay,
        )
        self.envelopes.append(envelope)

        log = self.logger.info if stage == STAGE_RETRY_SCHEDULED else self.logger.warning
        log(
            "Failure envelope: queue=%s actor=%s message_id=%s stage=%s attempts=%d max_retries=%r "
            "reason=%s error_type=%s error_category=%s retry_delay=%r",
            envelope.queue_name,
            envelope.actor_name,
            envelope.message_id,
            envelope.stage,
            envelope.attempts,
            envelope.max_retries,
            envelope.reason,
            envelope.error_type,
            envelope.error_category,
            envelope.retry_delay,
        )

        if self.on_failure is not None:
            self.on_failure(envelope)
