# This file is a part of Dramatiq.
#
# Copyright (C) 2017,2018,2019,2020 CLEARTYPE SRL <bogdan@cleartype.io>
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

"""Local work-queue scheduling primitives.

These primitives let an operator reserve worker slots for selected
task types so that high-priority work (e.g. emergency shutdown
notifications) can always be picked up even when a bulk import has
flooded the local work queue.

The reservation is enforced at dispatch time, inside the worker
process, so ordering guarantees provided by the underlying broker are
preserved: messages belonging to the same actor still leave the work
queue in FIFO order.  Messages that are not yet due (delayed messages)
remain on the delay queue and never occupy a worker slot.
"""

from __future__ import annotations

import heapq
import threading
import time
from queue import Empty
from typing import TYPE_CHECKING, Callable, Mapping, Optional

from .common import getenv_int

if TYPE_CHECKING:
    from .worker import _WorkQueueItem


#: The number of milliseconds a non-reserved message may be denied a
#: slot before its reservation is waived.  This bounds how long a
#: regular task may wait and guarantees it is never starved forever.
RESERVATION_MAX_AGE_MS = getenv_int("dramatiq_reservation_max_age_ms") or 30_000


class ReservationPolicy:
    """Tracks which worker slots are reserved for which actors.

    A reservation guarantees that, out of ``total_slots`` worker
    threads, at least ``reserved_slots[actor_name]`` threads are kept
    available for the given actor whenever it has work to do.
    Non-reserved actors share the remaining "general" slots.

    To avoid indefinite starvation, a message that has waited longer
    than ``max_age_ms`` is admitted to any free slot even if doing so
    temporarily borrows a reserved one.

    Parameters:
      total_slots(int): The total number of worker threads.
      reserved_slots(Mapping[str, int]): A mapping of actor names to
        the number of slots that must be kept available for them.
      max_age_ms(int): The maximum age, in milliseconds, a message may
        reach before its reservation is waived.
      clock(Callable[[], int]): A zero-argument callable returning the
        current monotonic time in nanoseconds.  Overridable for
        deterministic tests.
    """

    def __init__(
        self,
        total_slots: int,
        reserved_slots: Optional[Mapping[str, int]] = None,
        *,
        max_age_ms: int = RESERVATION_MAX_AGE_MS,
        clock: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        if total_slots <= 0:
            raise ValueError("total_slots must be a positive integer.")
        if max_age_ms <= 0:
            raise ValueError("max_age_ms must be a positive integer.")

        reservations: dict[str, int] = {}
        for actor_name, slot_count in (reserved_slots or {}).items():
            if not isinstance(slot_count, int) or slot_count <= 0:
                raise ValueError("Reserved slot counts must be positive integers.")
            reservations[actor_name] = slot_count

        reserved_total = sum(reservations.values())
        if reserved_total > total_slots:
            raise ValueError("The total number of reserved slots cannot exceed the number of worker threads.")

        self.total_slots = total_slots
        self.reserved_slots = reservations
        self.max_age_ms = max_age_ms
        self.clock = clock

        self._in_flight: dict[str, int] = {}
        self._lock = threading.Lock()

    @property
    def general_slot_count(self) -> int:
        """The number of slots that are not dedicated to a reservation."""
        return self.total_slots - sum(self.reserved_slots.values())

    def in_flight(self, actor_name: Optional[str] = None) -> int:
        """The number of currently occupied slots, optionally for one actor."""
        with self._lock:
            if actor_name is None:
                return sum(self._in_flight.values())
            return self._in_flight.get(actor_name, 0)

    def try_acquire(self, actor_name: str, enqueued_at_ns: int) -> bool:
        """Attempt to reserve a worker slot for a message.

        Returns ``True`` when a slot was granted and ``False`` when the
        message must keep waiting for a reserved slot to free up.

        Parameters:
          actor_name(str): The actor the message is bound to.
          enqueued_at_ns(int): The monotonic time, in nanoseconds, at
            which the message entered the work queue.
        """
        with self._lock:
            if sum(self._in_flight.values()) >= self.total_slots:
                return False

            # A message that has outlived the reservation window is
            # admitted to any free slot so ordinary tasks never wait
            # indefinitely behind a flood of lower-priority work.
            age_ms = (self.clock() - enqueued_at_ns) / 1_000_000
            if age_ms >= self.max_age_ms:
                self._in_flight[actor_name] = self._in_flight.get(actor_name, 0) + 1
                return True

            if actor_name in self.reserved_slots:
                self._in_flight[actor_name] = self._in_flight.get(actor_name, 0) + 1
                return True

            general_in_flight = sum(
                count for actor, count in self._in_flight.items() if actor not in self.reserved_slots
            )
            if general_in_flight < self.general_slot_count:
                self._in_flight[actor_name] = self._in_flight.get(actor_name, 0) + 1
                return True

            return False

    def release(self, actor_name: str) -> None:
        """Give back the slot occupied by a finished message."""
        with self._lock:
            count = self._in_flight.get(actor_name, 0)
            if count <= 1:
                self._in_flight.pop(actor_name, None)
            else:
                self._in_flight[actor_name] = count - 1


class ReservedWorkQueue:
    """A priority work queue that dispatches messages through a
    :class:`ReservationPolicy`.

    Messages are still ordered exactly like a plain priority queue
    (actor priority first, then FIFO for messages of equal priority),
    but a message whose actor has no admissible slot is held back while
    later, admissible messages are allowed to overtake it.  This keeps
    a slot free for the reserved actor instead of letting a flood of
    ordinary messages occupy every worker thread.

    The public surface mirrors the parts of :class:`queue.PriorityQueue`
    that the worker relies on.
    """

    def __init__(self, policy: ReservationPolicy) -> None:
        self.policy = policy
        self._heap: list[tuple["_WorkQueueItem", int]] = []
        self._counter = 0
        self._unfinished_tasks = 0
        self._cond = threading.Condition()
        self._all_tasks_done = threading.Condition()

    def put(self, item: "_WorkQueueItem") -> None:
        """Add a work-queue item and wake up waiting worker threads."""
        with self._cond:
            self._counter += 1
            heapq.heappush(self._heap, (item, self._counter))
            self._unfinished_tasks += 1
            self._cond.notify_all()

    def get(self, timeout: Optional[float] = None) -> "_WorkQueueItem":
        """Pop the highest-priority admissible item, blocking until one
        becomes available or the timeout elapses.

        Raises:
          Empty: When no admissible item is available in time.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._cond:
            while True:
                index = self._admissible_index()
                if index is not None:
                    item, _ = self._heap.pop(index)
                    heapq.heapify(self._heap)
                    return item

                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise Empty
                else:
                    remaining = None

                self._cond.wait(remaining)

    def _admissible_index(self) -> Optional[int]:
        """Return the heap index of the highest-priority item that may
        currently claim a worker slot, or ``None`` if none may."""
        # A heap is not stored in sorted order, so consider the entries in
        # dispatch order (priority, then FIFO) and return the first one
        # the reservation policy grants a slot.  A denied try_acquire()
        # has no side effect, so scanning past blocked items is safe.
        ordered_indexes = sorted(range(len(self._heap)), key=lambda idx: self._heap[idx])
        for index in ordered_indexes:
            item, _ = self._heap[index]
            if self.policy.try_acquire(item.message.actor_name, item.enqueued_at):
                return index
        return None

    def task_done(self, actor_name: str) -> None:
        """Mark a previously dispatched item as finished."""
        self.policy.release(actor_name)
        with self._all_tasks_done:
            self._unfinished_tasks -= 1
            if self._unfinished_tasks <= 0:
                self._all_tasks_done.notify_all()
        with self._cond:
            self._cond.notify_all()

    def join(self) -> None:
        """Block until every dispatched item has been marked done."""
        with self._all_tasks_done:
            while self._unfinished_tasks:
                self._all_tasks_done.wait()

    def qsize(self) -> int:
        """The number of items currently waiting on the queue."""
        with self._cond:
            return len(self._heap)

    @property
    def unfinished_tasks(self) -> int:
        return self._unfinished_tasks

    def drain(self) -> list["_WorkQueueItem"]:
        """Remove and return every waiting item.

        Used during worker shutdown to requeue undelivered messages.
        Dispatched items are unaffected: their slots and task counts are
        released through :meth:`task_done` when the workers finish.
        """
        with self._cond:
            items = [item for item, _ in self._heap]
            drained = len(items)
            self._heap = []
            self._unfinished_tasks -= drained
            return items
