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
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import annotations

import contextvars
import enum
import threading
import warnings
from typing import TYPE_CHECKING, Optional

from ..logging import get_logger
from .middleware import Middleware
from .threading import (
    Interrupt,
    current_platform,
    is_gevent_active,
    raise_thread_exception,
    supported_platforms,
)

if TYPE_CHECKING:
    from ..actor import Actor
    from ..broker import Broker, MessageProxy


class Shutdown(Interrupt):
    """Exception used to interrupt worker threads when their worker
    processes have been signaled for termination.
    """


class ShutdownPolicy(str, enum.Enum):
    """The per-actor contract that decides what happens to a message
    when its worker shuts down.

    Policies are declared with the ``shutdown_policy`` actor option (or
    the same message option) and only take effect once declared.  When
    no policy is declared, the legacy ``notify_shutdown`` behaviour is
    used unchanged.

    Attributes:
      REQUEUE: Interrupt work that is in flight.  A message that hasn't
        reached its sensitive phase may be handed to another worker.
        Once an actor has called
        :meth:`ShutdownGuard.enter_sensitive_phase`, an interrupted
        message is cleaned up and acknowledged instead of being
        requeued, so a successor worker can never inherit it.
      FINISH: Never interrupt work that is in flight; let the actor run
        to completion.  Messages that haven't started may be requeued.
      REVOKE: Never hand any message for this actor back to the broker.
        Messages that haven't started are dropped, and interrupted
        messages are cleaned up and acknowledged.  Use this when the
        message itself carries one-shot credentials or when every run
        must be tied to the worker that received it.
    """

    REQUEUE = "requeue"
    FINISH = "finish"
    REVOKE = "revoke"


class ShutdownDisposition(str, enum.Enum):
    """The decision made for a single message during shutdown.

    Attributes:
      REQUEUE: The message may be processed by another worker.
      CLEANUP: The actor is already in its sensitive phase.  It must run
        its cleanup and the message must then be acknowledged.
      DROP: The message must not run anywhere; acknowledge it without
        processing.
    """

    REQUEUE = "requeue"
    CLEANUP = "cleanup"
    DROP = "drop"


class ShutdownGuard:
    """Marks the point inside an actor after which the work is
    sensitive and must not be handed to another worker.

    Example:

      >>> @dramatiq.actor(shutdown_policy="revoke")
      ... def redeem(token):
      ...     authorization = authorize(token)
      ...     ShutdownGuard.enter_sensitive_phase()
      ...     try:
      ...         use(authorization)
      ...     finally:
      ...         revoke(authorization)
    """

    _STATE: contextvars.ContextVar[Optional["_InFlightMessage"]] = contextvars.ContextVar(
        "dramatiq_shutdown_state",
        default=None,
    )

    @classmethod
    def enter_sensitive_phase(cls) -> bool:
        """Mark the message being processed on this thread as having
        entered its sensitive phase.

        Call this immediately after acquiring an authorization or any
        other one-shot credential.  Once marked, an interrupted message
        is cleaned up and acknowledged instead of being requeued, so a
        successor worker can't inherit that authorization.

        Returns:
          bool: True when a message was marked.  False when called
          outside of an actor or when the shutdown middleware isn't
          installed.
        """
        state = cls._STATE.get()
        if state is None:
            return False
        state.sensitive = True
        return True

    @classmethod
    def is_shutting_down(cls) -> bool:
        """Return whether the current actor's worker has begun shutting
        down.  Actors with a ``revoke`` policy can use this to avoid
        starting work with credentials that arrived too late.
        """
        state = cls._STATE.get()
        return state is not None and state.middleware is not None and state.middleware.shutting_down

    @classmethod
    def is_sensitive(cls) -> bool:
        """Return whether the current thread's message is in its
        sensitive phase.
        """
        state = cls._STATE.get()
        return state is not None and state.sensitive


class ShutdownNotifications(Middleware):
    """Middleware that interrupts actors whose worker process has been
    signaled for termination.
    Currently, this is only available on CPython.

    Note:
      This works by setting an async exception in the worker thread
      that runs the actor.  This means that the exception will only get
      called the next time that thread acquires the GIL.  Concretely,
      this means that this middleware can't cancel system calls.

    Parameters:
      notify_shutdown(bool): When True, the actor will be interrupted
        if the worker process was terminated.
        Defaults to False, meaning actors will not be interrupted, and allowed to finish.
    """

    def __init__(self, notify_shutdown: bool = False) -> None:
        self.logger = get_logger(__name__, type(self))
        self.notify_shutdown = notify_shutdown
        self.shutting_down = False

        self.manager: _ShutdownManager
        if is_gevent_active():
            self.manager = _GeventShutdownManager(self.logger)
        else:
            self.manager = _CtypesShutdownManager(self.logger)

    @property
    def actor_options(self):
        return {"notify_shutdown", "shutdown_policy"}

    def get_policy(self, actor: Actor, message: MessageProxy) -> Optional[ShutdownPolicy]:
        """Get the shutdown policy declared by a message or its actor.

        Message options take precedence, matching ``notify_shutdown``.
        """
        policy = message.options.get("shutdown_policy")
        if policy is None:
            policy = actor.options.get("shutdown_policy")
        if policy is None:
            return None
        try:
            return ShutdownPolicy(policy)
        except ValueError:
            raise ValueError(
                "Invalid shutdown_policy %r for actor %r; expected one of %s."
                % (policy, actor.actor_name, ", ".join(p.value for p in ShutdownPolicy))
            ) from None

    def should_notify(self, actor, message):
        policy = self.get_policy(actor, message)
        if policy is ShutdownPolicy.FINISH:
            return False
        if policy is not None:
            return True

        notify = message.options.get("notify_shutdown")
        if notify is None:
            notify = actor.options.get("notify_shutdown")
        if notify is None:
            notify = self.notify_shutdown
        return bool(notify)

    def classify(
        self,
        broker: Broker,
        message: MessageProxy,
        *,
        started: bool,
        sensitive: Optional[bool] = None,
    ) -> ShutdownDisposition:
        """Decide what may happen to a message during shutdown.

        Parameters:
          broker(Broker): The broker that owns the actor.
          message(MessageProxy): The message being classified.
          started(bool): Whether the actor began executing the message.
          sensitive(bool): Whether the actor entered its sensitive
            phase.  Only meaningful when ``started`` is True.
        """
        actor = broker.get_actor(message.actor_name)
        policy = self.get_policy(actor, message) or ShutdownPolicy.REQUEUE

        if not started:
            if policy is ShutdownPolicy.REVOKE:
                return ShutdownDisposition.DROP
            return ShutdownDisposition.REQUEUE

        if policy is ShutdownPolicy.REVOKE:
            return ShutdownDisposition.CLEANUP

        if policy is ShutdownPolicy.FINISH:
            return ShutdownDisposition.REQUEUE

        if sensitive:
            return ShutdownDisposition.CLEANUP
        return ShutdownDisposition.REQUEUE

    def can_requeue_on_shutdown(self, broker: Broker, message: MessageProxy) -> bool:
        """Return whether a message that never started may be handed
        back to the broker.  Used by the worker for its in-memory queue.

        Outside of shutdown every message is allowed to run, so this
        only revokes work once shutdown has begun.
        """
        if not self.shutting_down:
            return True
        return self.classify(broker, message, started=False) is ShutdownDisposition.REQUEUE

    def classify_shutdown_exception(
        self,
        broker: Broker,
        message: MessageProxy,
        exception: BaseException,
    ) -> Optional[ShutdownDisposition]:
        """Classify a message whose actor raised :class:`Shutdown`.

        Returns None when this middleware doesn't apply (no policy was
        declared, or the worker isn't shutting down), in which case the
        worker keeps its legacy behaviour.
        """
        if not self.shutting_down or not isinstance(exception, Shutdown):
            return None

        actor = broker.get_actor(message.actor_name)
        if self.get_policy(actor, message) is None:
            return None

        state = ShutdownGuard._STATE.get()
        sensitive = state.sensitive if state is not None else False
        return self.classify(broker, message, started=True, sensitive=sensitive)

    def after_process_boot(self, broker):
        if current_platform not in supported_platforms:  # pragma: no cover
            msg = "ShutdownNotifications cannot kill threads on your current platform (%r)."
            warnings.warn(msg % current_platform, category=RuntimeWarning, stacklevel=2)

    def before_worker_shutdown(self, broker, worker):
        self.logger.debug("Sending shutdown notification to worker threads...")
        self.shutting_down = True
        self.manager.shutdown()

    def before_process_message(self, broker, message):
        actor = broker.get_actor(message.actor_name)
        ShutdownGuard._STATE.set(_InFlightMessage(self, self.get_policy(actor, message)))

        if self.should_notify(actor, message):
            self.manager.add_notification()

    def after_process_message(self, broker, message, *, result=None, exception=None):
        ShutdownGuard._STATE.set(None)
        self.manager.remove_notification()

    after_skip_message = after_process_message


class _InFlightMessage:
    def __init__(self, middleware: "ShutdownNotifications", policy: Optional[ShutdownPolicy]) -> None:
        self.middleware = middleware
        self.policy = policy
        self.sensitive = False


class _ShutdownManager:

    def __init__(self, logger=None) -> None:  # pragma: no cover
        raise NotImplementedError

    def add_notification(self) -> None:  # pragma: no cover
        raise NotImplementedError

    def remove_notification(self) -> None:  # pragma: no cover
        raise NotImplementedError

    def shutdown(self) -> None:  # pragma: no cover
        raise NotImplementedError


class _CtypesShutdownManager(_ShutdownManager):

    def __init__(self, logger=None):
        self.logger = logger or get_logger(__name__, type(self))
        self.notifications = set()

    def add_notification(self):
        self.notifications.add(threading.get_ident())

    def remove_notification(self):
        self.notifications.discard(threading.get_ident())

    def shutdown(self):
        for thread_id in self.notifications:
            self.logger.info(
                "Worker shutdown notification. Raising exception in worker thread %r.",
                thread_id,
            )
            raise_thread_exception(thread_id, Shutdown)


if is_gevent_active():
    from gevent import getcurrent

    class _GeventShutdownManager(_ShutdownManager):

        def __init__(self, logger=None):
            self.logger = logger or get_logger(__name__, type(self))
            self.notification_greenlets = set()

        def add_notification(self):
            current_greenlet = getcurrent()
            # Get and store the threading ident rather than using the greenlet's
            # minimal_ident for logging consistency with the time limit middleware.
            thread_id = threading.get_ident()
            self.notification_greenlets.add((thread_id, current_greenlet))

        def remove_notification(self):
            current_greenlet = getcurrent()
            thread_id = threading.get_ident()
            self.notification_greenlets.discard((thread_id, current_greenlet))

        def shutdown(self):
            for thread_id, greenlet in self.notification_greenlets:
                self.logger.info(
                    "Worker shutdown notification. Raising exception in worker thread %r.",
                    thread_id,
                )
                greenlet.kill(Shutdown, block=False)
