# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Versioned, atomically publishable role graph for distributed Casbin workers.

A plain :class:`~casbin.rbac.default_role_manager.RoleManager` mutates its edges in
place, so a reader that walks the graph while another thread is editing it can observe
a role that keeps half of an old edge set and half of a new one.  This module keeps
every readable role graph in an immutable :class:`RoleGraphSnapshot`.  A change builds a
brand new snapshot (copy-on-write) and swaps it in with a single reference assignment,
so concurrent readers always see one complete graph, never a torn mix of two versions.

Each change moves through three layers that the upper layer can tell apart:

1. **Committed / effective** - the change was persisted by the adapter and its snapshot
   was atomically published.  Local checks read exactly this graph.
2. **Readable version** - the snapshot currently handed out to readers.  It is always a
   fully built, immutable graph and carries a monotonically increasing version number.
3. **Pending distribution** - the change is already effective locally, but at least one
   worker has not acknowledged it yet.  The receipt reports which change is still in
   flight so the caller can decide whether to retry.

Persistence and distribution fail independently: a persistence failure aborts before
the local graph moves; a distribution failure leaves the new graph effective locally and
only marks the change as awaiting distribution, retryable through
:meth:`RoleGraphCoordinator.retry_distribution`.
"""

import threading
import uuid
from collections import namedtuple
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

from casbin.rbac.default_role_manager import RoleManager

# A single directed edge ``user -> role`` inside an optional ``domain``.
Link = namedtuple("Link", ["user", "role", "domain"])


class ChangeKind(Enum):
    """The kind of edge mutation a :class:`RoleChange` performs."""

    ADD = "add"
    REMOVE = "remove"


class ChangeStatus(Enum):
    """Lifecycle state of a role-graph change.

    ``PERSIST_FAILED``: the adapter rejected the change, nothing moved locally.
    ``PENDING_DISTRIBUTION``: persisted and effective locally, not confirmed by workers.
    ``CONFIRMED``: persisted, effective, and every targeted worker acknowledged it.
    """

    PERSIST_FAILED = "persist_failed"
    PENDING_DISTRIBUTION = "pending_distribution"
    CONFIRMED = "confirmed"


class DistributionState(Enum):
    """Coarse-grained view of how far a change has propagated."""

    NOT_PERSISTED = "not_persisted"
    PENDING = "pending"
    CONFIRMED = "confirmed"


@dataclass(frozen=True)
class RoleChange:
    """An immutable request to add or remove one ``user -> role`` edge."""

    kind: ChangeKind
    user: str
    role: str
    domain: str = ""
    change_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    @property
    def link(self):
        return Link(self.user, self.role, self.domain)

    @staticmethod
    def add(user, role, domain="", change_id=None):
        return RoleChange(ChangeKind.ADD, user, role, domain, change_id or uuid.uuid4().hex)

    @staticmethod
    def remove(user, role, domain="", change_id=None):
        return RoleChange(ChangeKind.REMOVE, user, role, domain, change_id or uuid.uuid4().hex)


@dataclass(frozen=True)
class RoleGraphSnapshot:
    """An immutable, fully built role graph.

    ``version`` starts at 0 for the empty graph and grows by one every time a batch of
    changes is published.  ``role_manager`` is an independent :class:`RoleManager` that
    is never mutated after the snapshot is published, which is what makes concurrent
    reads safe.
    """

    version: int
    role_manager: RoleManager
    links: Tuple[Link, ...]
    change_ids: Tuple[str, ...]


class VersionedRoleGraph:
    """Holds the current readable snapshot and the bookkeeping of every change."""

    def __init__(self, max_hierarchy_level=10):
        self._lock = threading.RLock()
        self._max_hierarchy_level = max_hierarchy_level
        self._snapshot = self._build_snapshot(0, (), ())
        # change_id -> _ChangeRecord, retained for receipts and retries
        self._records = {}

    # -- snapshots ---------------------------------------------------------

    def _build_snapshot(self, version, links, change_ids):
        role_manager = RoleManager(self._max_hierarchy_level)
        for link in links:
            role_manager.add_link(link.user, link.role)
        return RoleGraphSnapshot(version, role_manager, tuple(links), tuple(change_ids))

    def current_snapshot(self):
        """Returns the immutable snapshot currently visible to readers."""
        with self._lock:
            return self._snapshot

    def current_version(self):
        """Returns the version number of the readable snapshot."""
        with self._lock:
            return self._snapshot.version

    # -- local checks (always run against a complete graph) ---------------

    def has_link(self, user, role, domain=""):
        return self.current_snapshot().role_manager.has_link(user, role, domain)

    def get_roles(self, user, domain=""):
        return self.current_snapshot().role_manager.get_roles(user, domain)

    def get_users(self, role, domain=""):
        return self.current_snapshot().role_manager.get_users(role, domain)

    # -- mutation ----------------------------------------------------------

    def apply(self, changes):
        """Publishes a new snapshot that incorporates ``changes`` atomically.

        Returns the published snapshot.  The whole batch becomes visible together, so a
        reader can never observe only part of it.
        """
        with self._lock:
            links = list(self._snapshot.links)
            for change in changes:
                link = change.link
                if change.kind is ChangeKind.ADD:
                    if link not in links:
                        links.append(link)
                else:
                    if link in links:
                        links.remove(link)
            next_version = self._snapshot.version + 1
            snapshot = self._build_snapshot(
                next_version, links, tuple(change.change_id for change in changes)
            )
            # One reference assignment: readers either keep the old snapshot or take the
            # new one, but never a half-built graph.
            self._snapshot = snapshot
            return snapshot

    # -- change records ----------------------------------------------------

    def record(self, change_id):
        with self._lock:
            record = self._records.get(change_id)
            return None if record is None else record.snapshot_view()

    def pending_changes(self):
        """Returns change ids that are effective locally but not fully distributed.

        Changes that never persisted (and therefore never became effective) are not
        reported here; callers learn about them from their own failed receipt.
        """
        with self._lock:
            return [
                cid
                for cid, rec in self._records.items()
                if rec.status is ChangeStatus.PENDING_DISTRIBUTION
            ]

    def _put_record(self, record):
        with self._lock:
            self._records[record.change_id] = record

    def _get_record(self, change_id):
        with self._lock:
            return self._records.get(change_id)

    def _update_distribution(self, change_id, status, unacked_workers, error):
        """Updates a record's distribution outcome under the graph lock."""
        with self._lock:
            record = self._records.get(change_id)
            if record is None:
                return None
            record.status = status
            record.unacked_workers = list(unacked_workers)
            record.error = error
            return record.snapshot_view()


@dataclass
class _ChangeRecord:
    change_id: str
    change: RoleChange
    version: int
    status: ChangeStatus
    unacked_workers: List[str] = field(default_factory=list)
    error: str = ""

    def snapshot_view(self):
        return ChangeReceipt(
            change_id=self.change_id,
            change=self.change,
            adopted_version=self.version if self.status is not ChangeStatus.PERSIST_FAILED else None,
            readable_version=self.version if self.status is not ChangeStatus.PERSIST_FAILED else None,
            status=self.status,
            distribution_state=_distribution_state(self.status),
            pending_workers=list(self.unacked_workers),
            error=self.error,
        )


def _distribution_state(status):
    if status is ChangeStatus.PERSIST_FAILED:
        return DistributionState.NOT_PERSISTED
    if status is ChangeStatus.PENDING_DISTRIBUTION:
        return DistributionState.PENDING
    return DistributionState.CONFIRMED


@dataclass(frozen=True)
class ChangeReceipt:
    """Reports the outcome of one change to the upper layer.

    ``adopted_version`` is the snapshot version that now contains the change (``None``
    when persistence failed).  ``pending_workers`` names the workers that have not
    confirmed it yet; an empty list together with ``CONFIRMED`` means full distribution.
    """

    change_id: str
    change: RoleChange
    adopted_version: Optional[int]
    readable_version: Optional[int]
    status: ChangeStatus
    distribution_state: DistributionState
    pending_workers: List[str]
    error: str = ""

    @property
    def persisted(self):
        return self.status is not ChangeStatus.PERSIST_FAILED

    @property
    def fully_distributed(self):
        return self.status is ChangeStatus.CONFIRMED

    @property
    def retryable(self):
        """True when the change is effective locally but still awaits distribution."""
        return self.status is ChangeStatus.PENDING_DISTRIBUTION


class RoleGraphDispatcher:
    """Interface for fanning a change out to remote workers."""

    def dispatch(self, change, workers):
        """Sends ``change`` to every worker in ``workers``.

        Returns the list of workers that did *not* acknowledge the change.  Raising an
        exception signals a transport-level failure before any acknowledgement, which the
        coordinator treats as every worker being unacknowledged.
        """
        raise NotImplementedError

    def workers(self):
        """Returns the static set of worker ids a change should reach."""
        raise NotImplementedError


class InMemoryRoleGraphDispatcher(RoleGraphDispatcher):
    """Deterministic in-process dispatcher used to drive retries in tests.

    A worker id registered through :meth:`fail_once` rejects its first delivery (raising
    :class:`DistributionError`) and accepts every later attempt, which models a transient
    outage that clears on retry.
    """

    def __init__(self, worker_ids):
        self._workers = list(worker_ids)
        self._fail_once = set()
        self.delivered = []
        self._lock = threading.Lock()

    def workers(self):
        return list(self._workers)

    def fail_once(self, worker_id):
        if worker_id not in self._workers:
            raise KeyError(worker_id)
        self._fail_once.add(worker_id)

    def dispatch(self, change, workers):
        with self._lock:
            unacked = []
            transport_failure = False
            for worker_id in workers:
                if worker_id in self._fail_once:
                    self._fail_once.discard(worker_id)
                    unacked.append(worker_id)
                    transport_failure = True
                    continue
                self.delivered.append((worker_id, change.change_id))
            if transport_failure:
                raise DistributionError(
                    "workers did not acknowledge change %s: %s" % (change.change_id, unacked),
                    unacked=unacked,
                )
            return unacked


class DistributionError(RuntimeError):
    """Raised when one or more workers fail to acknowledge a distribution."""

    def __init__(self, message, unacked):
        super().__init__(message)
        self.unacked = list(unacked)


class RoleGraphStore:
    """Interface for persisting role-graph changes before they are published."""

    def commit(self, change):
        raise NotImplementedError

    def rollback(self, change):
        raise NotImplementedError


class InMemoryRoleGraphStore(RoleGraphStore):
    """A store that keeps committed edges in a list and can be told to fail."""

    def __init__(self):
        self.committed = []
        self.fail_next = False

    def commit(self, change):
        if self.fail_next:
            self.fail_next = False
            raise PersistError("simulated persistence failure")
        link = change.link
        if change.kind is ChangeKind.ADD:
            if link not in self.committed:
                self.committed.append(link)
        else:
            if link in self.committed:
                self.committed.remove(link)

    def rollback(self, change):
        link = change.link
        if change.kind is ChangeKind.ADD:
            if link in self.committed:
                self.committed.remove(link)
        else:
            if link not in self.committed:
                self.committed.append(link)


class AdapterRoleGraphStore(RoleGraphStore):
    """Adapts a Casbin :class:`~casbin.persist.Adapter` to the :class:`RoleGraphStore`.

    Persistence happens through the adapter's single-rule ``add_policy`` /
    ``remove_policy`` hooks (``sec="g"``), so an existing file or database adapter can be
    reused without implementing a new storage interface.
    """

    def __init__(self, adapter, ptype="g"):
        self._adapter = adapter
        self._ptype = ptype

    def _rule(self, change):
        if change.domain:
            return [change.user, change.role, change.domain]
        return [change.user, change.role]

    def commit(self, change):
        rule = self._rule(change)
        if change.kind is ChangeKind.ADD:
            self._adapter.add_policy("g", self._ptype, rule)
        else:
            self._adapter.remove_policy("g", self._ptype, rule)

    def rollback(self, change):
        rule = self._rule(change)
        if change.kind is ChangeKind.ADD:
            self._adapter.remove_policy("g", self._ptype, rule)
        else:
            self._adapter.add_policy("g", self._ptype, rule)


class PersistError(RuntimeError):
    """Raised when an adapter refuses to persist a change."""


class RoleGraphCoordinator:
    """Orchestrates persist -> atomic publish -> distribute for role changes.

    The ordering is deliberate: the adapter commit runs first and, on failure, aborts
    before the local graph moves.  Only a successfully persisted change is published as a
    new immutable snapshot and then handed to the dispatcher.  A distribution failure
    therefore never rolls the local graph back; the change stays effective and is recorded
    as pending so :meth:`retry_distribution` can finish it later.
    """

    def __init__(self, store, dispatcher=None, max_hierarchy_level=10):
        self._store = store
        self._dispatcher = dispatcher
        self.graph = VersionedRoleGraph(max_hierarchy_level=max_hierarchy_level)

    def submit(self, change):
        """Persists, publishes and distributes a single change, returning its receipt."""
        return self.submit_batch([change])[0]

    def submit_batch(self, changes):
        """Applies ``changes`` as one atomic version, returning one receipt per change."""
        if not changes:
            return []

        # Phase 1: persist every change first.  A failure aborts the whole batch so the
        # readable graph cannot advance past storage.
        persisted = []
        for index, change in enumerate(changes):
            try:
                self._store.commit(change)
                persisted.append(change)
            except Exception as exc:
                for done in reversed(persisted):
                    self._safe_rollback(done)
                failed_record = _ChangeRecord(
                    change_id=change.change_id,
                    change=change,
                    version=self.graph.current_version(),
                    status=ChangeStatus.PERSIST_FAILED,
                    error=str(exc),
                )
                self.graph._put_record(failed_record)
                # Remaining changes were never attempted; mark them failed as well.
                receipts = [failed_record.snapshot_view()]
                for skipped in changes[index + 1 :]:
                    skipped_record = _ChangeRecord(
                        change_id=skipped.change_id,
                        change=skipped,
                        version=self.graph.current_version(),
                        status=ChangeStatus.PERSIST_FAILED,
                        error="aborted after an earlier persistence failure",
                    )
                    self.graph._put_record(skipped_record)
                    receipts.append(skipped_record.snapshot_view())
                return receipts

        # Phase 2: publish one immutable snapshot containing the whole batch.
        snapshot = self.graph.apply(persisted)
        workers = self._dispatcher.workers() if self._dispatcher is not None else []

        # Phase 3: distribute.  The graph is already effective; failures only flag the
        # change as awaiting acknowledgement.
        receipts = []
        for change in persisted:
            status, unacked, error = self._distribute(change, workers)
            record = _ChangeRecord(
                change_id=change.change_id,
                change=change,
                version=snapshot.version,
                status=status,
                unacked_workers=unacked,
                error=error,
            )
            self.graph._put_record(record)
            receipts.append(record.snapshot_view())
        return receipts

    def retry_distribution(self, change_id):
        """Re-sends a pending change to the workers that have not acknowledged it."""
        record = self.graph._get_record(change_id)
        if record is None:
            raise KeyError("unknown change id: %s" % change_id)
        if record.status is ChangeStatus.PERSIST_FAILED:
            raise ValueError("change %s was never persisted" % change_id)
        if record.status is ChangeStatus.CONFIRMED:
            return record.snapshot_view()

        status, unacked, error = self._distribute(record.change, list(record.unacked_workers))
        return self.graph._update_distribution(change_id, status, unacked, error)

    def pending(self):
        """Returns receipts for every effective change still awaiting distribution."""
        return [self.graph.record(cid) for cid in self.graph.pending_changes()]

    def receipt(self, change_id):
        return self.graph.record(change_id)

    def _distribute(self, change, workers):
        if self._dispatcher is None or not workers:
            return ChangeStatus.CONFIRMED, [], ""
        try:
            unacked = self._dispatcher.dispatch(change, workers)
        except DistributionError as exc:
            return ChangeStatus.PENDING_DISTRIBUTION, exc.unacked, str(exc)
        except Exception as exc:  # a transport failure means nobody acknowledged
            return ChangeStatus.PENDING_DISTRIBUTION, list(workers), str(exc)
        if unacked:
            return ChangeStatus.PENDING_DISTRIBUTION, list(unacked), ""
        return ChangeStatus.CONFIRMED, [], ""

    def _safe_rollback(self, change):
        try:
            self._store.rollback(change)
        except Exception:
            pass
