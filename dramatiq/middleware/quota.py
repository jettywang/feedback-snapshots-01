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
# You should have received a copy of the GNU Lesser General Public
# License along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import annotations

import time
import uuid
from threading import Lock
from typing import Callable, Dict, NamedTuple, Optional

from ..logging import get_logger
from .middleware import Middleware, SkipMessage

#: The default amount of time in milliseconds a quota lease may be
#: held before it is considered abandoned (e.g. by a lost worker).
DEFAULT_LEASE_TTL = 30000

#: The default delay in milliseconds before a message that was
#: rejected due to quota exhaustion is retried.
DEFAULT_RETRY_DELAY = 1000


class QuotaLease(NamedTuple):
    """A handle on a set of acquired quota slots.

    The ``token`` acts as a fencing token: it uniquely identifies this
    lease so that a stale (expired) lease can never release slots that
    have since been handed out to another lease.
    """

    #: The unique fencing token of this lease.
    token: str

    #: The scopes this lease holds a slot in.
    scopes: tuple

    #: The point in time (on the backend's clock) at which this lease
    #: expires and its slots may be handed out to someone else.
    expires_at: float


class QuotaBackend:
    """ABC for quota backends.

    Backends hand out leases over named scopes, each scope allowing at
    most a fixed number of concurrent leases.  Leases expire after a
    TTL so that slots held by workers that disappear (crash, network
    partition, kill -9) are eventually reclaimed.
    """

    def acquire(self, limits: Dict[str, int], ttl: int) -> Optional[QuotaLease]:  # pragma: no cover
        """Atomically acquire one slot in each of the given scopes.

        Parameters:
          limits(dict): A mapping of scope name to the maximum number
            of concurrent leases allowed in that scope.
          ttl(int): The time in milliseconds after which the lease
            expires if it is not released.

        Returns:
          QuotaLease: The acquired lease, or ``None`` if any of the
          scopes is exhausted.
        """
        raise NotImplementedError

    def release(self, lease: QuotaLease) -> bool:  # pragma: no cover
        """Release a previously acquired lease.

        Releases are fenced by the lease's token: releasing a lease
        that has already expired is a no-op and never frees slots that
        were re-acquired by another lease in the meantime.

        Parameters:
          lease(QuotaLease): The lease to release.

        Returns:
          bool: True if the lease was still valid and its slots were
          freed, False if the lease had already expired.
        """
        raise NotImplementedError


class MemoryQuotaBackend(QuotaBackend):
    """An in-memory quota backend.

    This backend is process-local: it only coordinates workers that
    share the same broker object in the same process.  Use it for
    tests and single-process deployments; for multi-process or
    multi-host deployments you need a backend on top of a shared
    store (e.g. Redis) with the same fencing semantics.

    Parameters:
      clock(callable): A monotonic clock returning seconds.  Injected
        so tests can control the passage of time.
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self.mutex = Lock()
        self.leases: Dict[str, Dict[str, float]] = {}

    def acquire(self, limits, ttl):
        now = self.clock()
        expires_at = now + ttl / 1000
        with self.mutex:
            for scope, limit in limits.items():
                if len(self._active(scope, now)) >= limit:
                    return None

            token = uuid.uuid4().hex
            for scope in limits:
                self.leases.setdefault(scope, {})[token] = expires_at

            return QuotaLease(token=token, scopes=tuple(limits), expires_at=expires_at)

    def release(self, lease):
        now = self.clock()
        released = False
        with self.mutex:
            for scope in lease.scopes:
                entries = self.leases.get(scope)
                if not entries:
                    continue

                expires_at = entries.get(lease.token)
                if expires_at is None:
                    # Our token is gone from this scope (expired and
                    # purged).  Whatever slots exist there now belong
                    # to other leases; leave them alone.
                    continue

                del entries[lease.token]
                if expires_at > now:
                    released = True

        return released

    def _active(self, scope, now):
        entries = self.leases.get(scope)
        if not entries:
            return ()

        expired = [token for token, expires_at in entries.items() if expires_at <= now]
        for token in expired:
            del entries[token]
        return entries


class Quota(Middleware):
    """Middleware that caps how many messages may be processed
    concurrently, both per scope (e.g. per customer) and globally.

    Actors opt in by setting the ``quota_scope`` option to a string or
    to a callable that maps the message being processed to a scope
    name::

        @dramatiq.actor(quota_scope=lambda message: message.args[0])
        def import_data(customer_id):
            ...

    When a message's scope (or the global pool) is exhausted, the
    message is rejected: it is re-enqueued with a delay and the
    current delivery is skipped.  Rejected messages keep coming back
    until a slot frees up; they do not consume retries from the
    :class:`Retries<dramatiq.middleware.Retries>` middleware.

    Slots are leased: a message holds its slot for at most
    ``lease_ttl`` milliseconds.  If a worker is lost while holding a
    slot, the lease expires and the slot is handed out again.  Every
    lease carries a fencing token, so a worker that comes back to life
    and releases a stale lease cannot free a slot that has since been
    acquired by another message.

    Note:

      Lease expiry is evaluated lazily against the backend's clock
      when slots are acquired or released, so a lost worker's slot
      becomes available at some point *after* ``lease_ttl`` has
      elapsed, not at an exact instant.  Choose ``lease_ttl``
      comfortably larger than your actors' runtime and treat the
      effective release time as approximate.

    Note:

      The included :class:`MemoryQuotaBackend` is process-local and
      only coordinates workers inside one process.  Enforcement across
      multiple worker processes or hosts requires a shared-store
      backend; none is included here, so multi-process behaviour of
      this middleware is currently untested.

    Parameters:
      backend(QuotaBackend): The backend to store leases in.
      per_scope_limit(int): The maximum number of concurrent messages
        per scope.  Defaults to 2.
      global_limit(int): The maximum number of concurrent messages
        across all scopes.  Unbounded by default.
      lease_ttl(int): The time in milliseconds a slot may be held
        before the lease expires.  Defaults to 30 seconds.
      retry_delay(int): The delay in milliseconds before a rejected
        message is retried.  Defaults to 1 second.
    """

    def __init__(
        self,
        backend: QuotaBackend,
        *,
        per_scope_limit: int = 2,
        global_limit: Optional[int] = None,
        lease_ttl: int = DEFAULT_LEASE_TTL,
        retry_delay: int = DEFAULT_RETRY_DELAY,
    ) -> None:
        assert per_scope_limit >= 1, "per_scope_limit must be positive"
        assert global_limit is None or global_limit >= 1, "global_limit must be positive"

        self.logger = get_logger(__name__, type(self))
        self.backend = backend
        self.per_scope_limit = per_scope_limit
        self.global_limit = global_limit
        self.lease_ttl = lease_ttl
        self.retry_delay = retry_delay
        self.leases: Dict[str, QuotaLease] = {}

    @property
    def actor_options(self):
        return {"quota_scope"}

    def before_process_message(self, broker, message):
        actor = broker.get_actor(message.actor_name)
        scope = message.options.get("quota_scope") or actor.options.get("quota_scope")
        if scope is None:
            return

        if callable(scope):
            scope = scope(message)

        limits = {"quota:scope:%s" % scope: self.per_scope_limit}
        if self.global_limit is not None:
            limits["quota:global"] = self.global_limit

        lease = self.backend.acquire(limits, ttl=self.lease_ttl)
        if lease is None:
            self.logger.info("Quota exhausted for scope %r; requeueing message %r.", scope, message.message_id)
            broker.enqueue(message, delay=self.retry_delay)
            raise SkipMessage

        self.leases[message.message_id] = lease

    def after_process_message(self, broker, message, *, result=None, exception=None):
        self._release(message)

    def after_skip_message(self, broker, message):
        self._release(message)

    def _release(self, message):
        lease = self.leases.pop(message.message_id, None)
        if lease is not None:
            self.backend.release(lease)
