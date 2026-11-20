"""Per-connection evidence for publisher confirms.

A transport exception alone cannot tell the caller whether a publish reached
the broker: the socket may have failed before the bytes were written or after
the broker handled them. This module records each publish under the broker's
delivery tag and only turns that record into a terminal outcome when the broker
answers with ``Basic.Ack``/``Basic.Nack`` or the caller reports that the frame
never left the client. Anything still outstanding when the connection is lost
stays :class:`PublishOutcome.UNKNOWN`, so the ambiguity is handed back to the
caller instead of being guessed at.

The tracker never publishes, retries or reconnects. It correlates evidence the
broker and the transport give it; deciding what to do with an unknown outcome
is the caller's responsibility.
"""

from __future__ import annotations

import threading
import uuid
from enum import Enum
from typing import NamedTuple


class PublishOutcome(Enum):
    """Terminal state of a tracked publish.

    :cvar CONFIRMED: the broker answered ``Basic.Ack`` for the delivery tag.
    :cvar NACKED: the broker answered ``Basic.Nack``; the broker holds the
        message and the caller decides whether to republish.
    :cvar NOT_SENT: the transport failed before the publish frame was written,
        so the broker never saw it.
    :cvar UNKNOWN: the frame was written but no confirmation arrived before the
        connection was lost. The broker may or may not have the message.
    """

    CONFIRMED = 'confirmed'
    NACKED = 'nacked'
    NOT_SENT = 'not_sent'
    UNKNOWN = 'unknown'


class PublishResult(NamedTuple):
    """Evidence for one publish, keyed by a public tracking id.

    :param tracking_id: opaque id returned to the caller at publish time. It is
        the only handle later calls accept, so the broker's per-connection
        delivery tag never leaks across connection boundaries.
    :param outcome: the terminal state.
    :param connection_id: id of the connection the publish was attempted on.
    :param delivery_tag: broker delivery tag on that connection, or ``None``
        when the publish never got far enough to be assigned one.
    :param multiple: whether the broker confirmed the tag with a ``multiple``
        ack/nack, meaning every lower outstanding tag shared the outcome.
    """

    tracking_id: str
    outcome: PublishOutcome
    connection_id: str
    delivery_tag: int | None
    multiple: bool = False


class _PendingPublish(NamedTuple):
    tracking_id: str
    connection_id: str
    delivery_tag: int
    event: threading.Event


class PublishTracker:
    """Correlate publisher confirms with the publishes they answer.

    One instance belongs to one connection. Delivery tags start at one on every
    connection, so a tag is only meaningful paired with the connection id; the
    public :attr:`tracking_id` is unique across connections and is what callers
    store. Two trackers (two connections) therefore never merge records even
    when the broker reuses the same delivery tag number.

    The tracker is thread-safe: the publishing thread records a publish while
    the I/O thread reports confirmations and disconnects.
    """

    def __init__(self, connection_id: str | None = None) -> None:
        """
        :param connection_id: stable id for this connection. A random id is
            generated when omitted, which is what keeps same-numbered delivery
            tags distinguishable across connections.
        """
        self.connection_id = connection_id or uuid.uuid4().hex
        self._lock = threading.Lock()
        self._next_delivery_tag = 1
        self._pending: dict[int, _PendingPublish] = {}
        self._results: dict[str, PublishResult] = {}
        self._closed = False

    def record_publish(self, tracking_id: str | None = None) -> PublishResult:
        """Reserve the next delivery tag for a publish about to be sent.

        Call this immediately before writing the frame to the socket. The
        returned result is in the non-terminal :class:`PublishOutcome.UNKNOWN`
        state; it becomes terminal through :meth:`record_ack`,
        :meth:`record_nack`, :meth:`mark_not_sent` or :meth:`mark_all_unknown`.

        :param tracking_id: caller-chosen public id. Generated when omitted.
            Reusing an id raises ``ValueError`` rather than merging records.
        :raises ValueError: if ``tracking_id`` was already used on this tracker.
        :raises RuntimeError: if the tracker was closed by a disconnect.
        """
        tracking_id = tracking_id or uuid.uuid4().hex
        with self._lock:
            if self._closed:
                raise RuntimeError(
                    'cannot record a publish on a tracker whose connection is '
                    'closed')
            if tracking_id in self._results:
                raise ValueError(
                    f'tracking id {tracking_id!r} was already used')
            delivery_tag = self._next_delivery_tag
            self._next_delivery_tag += 1
            self._pending[delivery_tag] = _PendingPublish(
                tracking_id=tracking_id,
                connection_id=self.connection_id,
                delivery_tag=delivery_tag,
                event=threading.Event())
            result = PublishResult(tracking_id, PublishOutcome.UNKNOWN,
                                   self.connection_id, delivery_tag)
            self._results[tracking_id] = result
            return result

    def record_ack(self,
                   delivery_tag: int,
                   multiple: bool = False) -> list[PublishResult]:
        """Record a ``Basic.Ack`` from the broker.

        :param delivery_tag: tag the broker acknowledged.
        :param multiple: when true, every outstanding tag up to and including
            ``delivery_tag`` is confirmed.
        :returns: every result transitioned by this ack.
        :raises KeyError: if the tag has no outstanding publish.
        """
        return self._resolve(delivery_tag, multiple, PublishOutcome.CONFIRMED)

    def record_nack(self,
                    delivery_tag: int,
                    multiple: bool = False) -> list[PublishResult]:
        """Record a ``Basic.Nack`` from the broker.

        A nack means the broker received but refused responsibility for the
        message. The tracker does not republish; the caller owns that decision.

        :param delivery_tag: tag the broker rejected.
        :param multiple: when true, every outstanding tag up to and including
            ``delivery_tag`` shares the nack.
        :returns: every result transitioned by this nack.
        :raises KeyError: if the tag has no outstanding publish.
        """
        return self._resolve(delivery_tag, multiple, PublishOutcome.NACKED)

    def mark_not_sent(self, tracking_id: str) -> PublishResult:
        """Mark a publish whose frame never reached the socket.

        Use this when the transport raises before the bytes are written, so the
        broker could not have seen the message. The delivery tag is released
        back to the broker's numbering by not being confirmed; the caller may
        republish under a new tracking id.

        :param tracking_id: id returned by :meth:`record_publish`.
        :raises KeyError: if the id is unknown or already terminal.
        """
        with self._lock:
            pending = self._pop_pending_by_tracking_id(tracking_id)
            result = PublishResult(tracking_id, PublishOutcome.NOT_SENT,
                                   self.connection_id, pending.delivery_tag)
            self._store_result(result)
            pending.event.set()
            return result

    def mark_all_unknown(self) -> list[PublishResult]:
        """Close the tracker and leave every outstanding publish unknown.

        Call this when the connection is lost after one or more frames were
        written but before their confirmations arrived. No outstanding publish
        is guessed at: each stays :class:`PublishOutcome.UNKNOWN` and the
        tracker refuses further publishes.

        :returns: the results left unknown, in delivery-tag order.
        """
        with self._lock:
            self._closed = True
            ordered = [self._pending[tag] for tag in sorted(self._pending)]
            for pending in ordered:
                result = PublishResult(pending.tracking_id,
                                       PublishOutcome.UNKNOWN,
                                       self.connection_id, pending.delivery_tag)
                self._store_result(result)
                pending.event.set()
            self._pending.clear()
            return [self._results[pending.tracking_id] for pending in ordered]

    def get_result(self, tracking_id: str) -> PublishResult:
        """Return the current result for a tracking id.

        The result is terminal once its outcome is not
        :class:`PublishOutcome.UNKNOWN`; a result still unknown may transition
        later, so poll or use :meth:`wait_for_result`.

        :raises KeyError: if the id was never recorded.
        """
        with self._lock:
            return self._results[tracking_id]

    def wait_for_result(self,
                        tracking_id: str,
                        timeout: float | None = None) -> PublishResult:
        """Block until the result for ``tracking_id`` becomes terminal.

        :param timeout: maximum seconds to wait, or ``None`` to wait without a
            deadline.
        :returns: the terminal result.
        :raises KeyError: if the id was never recorded.
        :raises TimeoutError: if ``timeout`` elapses first.
        """
        with self._lock:
            result = self._results[tracking_id]
            if result.outcome is not PublishOutcome.UNKNOWN:
                return result
            # An unknown publish is still pending and so always holds a tag.
            delivery_tag = result.delivery_tag
            assert delivery_tag is not None
            event = self._pending[delivery_tag].event
        if not event.wait(timeout):
            raise TimeoutError(
                f'no confirmation for tracking id {tracking_id!r} within '
                f'{timeout} seconds')
        return self.get_result(tracking_id)

    @property
    def pending_count(self) -> int:
        """Number of publishes written but not yet resolved."""
        with self._lock:
            return len(self._pending)

    @property
    def is_closed(self) -> bool:
        """Whether a disconnect has ended tracking on this connection."""
        with self._lock:
            return self._closed

    def _resolve(self, delivery_tag: int, multiple: bool,
                 outcome: PublishOutcome) -> list[PublishResult]:
        with self._lock:
            if delivery_tag not in self._pending:
                raise KeyError(
                    f'no outstanding publish for delivery tag {delivery_tag!r} '
                    f'on connection {self.connection_id!r}')
            if multiple:
                tags = [tag for tag in self._pending if tag <= delivery_tag]
            else:
                tags = [delivery_tag]
            resolved: list[PublishResult] = []
            for tag in tags:
                pending = self._pending.pop(tag)
                result = PublishResult(pending.tracking_id, outcome,
                                       self.connection_id, pending.delivery_tag,
                                       multiple)
                self._store_result(result)
                pending.event.set()
                resolved.append(result)
            return resolved

    def _pop_pending_by_tracking_id(self, tracking_id: str) -> _PendingPublish:
        for delivery_tag, pending in self._pending.items():
            if pending.tracking_id == tracking_id:
                return self._pending.pop(delivery_tag)
        raise KeyError(
            f'no outstanding publish for tracking id {tracking_id!r}')

    def _store_result(self, result: PublishResult) -> None:
        self._results[result.tracking_id] = result
