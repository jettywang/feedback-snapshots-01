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

from typing import Callable, Optional

from ..logging import get_logger
from .middleware import Middleware, SkipMessage

#: The message option that carries the identity of the publisher that
#: dispatched the message.
PUBLISHER_OPTION = "publisher"

#: The message option under which the reason a message was denied is
#: recorded before the message is rejected.  Monitoring middleware can
#: read this option from ``after_skip_message`` (or from dead-lettered
#: messages) in order to tell why a message was dropped.
DENIED_REASON_OPTION = "authorization_denied_reason"


class AuthorizationDenied(SkipMessage):
    """Raised by :class:`TaskAuthorization` (or by an authorizer) when
    a message's publisher is not authorized to dispatch it.  Because
    this is a subclass of :class:`SkipMessage`, the actor and its
    success callbacks never run for denied messages.

    Parameters:
      reason(str): A human-readable explanation of why the message was
        denied.
      actor_name(str): The name of the actor the message targeted.
      queue_name(str): The queue the message was delivered on.
      publisher(str): The identity of the publisher, if any.
    """

    def __init__(
        self,
        reason: str,
        *,
        actor_name: Optional[str] = None,
        queue_name: Optional[str] = None,
        publisher: Optional[str] = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.actor_name = actor_name
        self.queue_name = queue_name
        self.publisher = publisher


class TaskAuthorization(Middleware):
    """Middleware that checks an optional authorization policy before
    a worker invokes an actor.

    This is useful when multiple services share a broker and each
    service is only allowed to dispatch a subset of the available
    tasks.  Publishers identify themselves via a message option (see
    :data:`PUBLISHER_OPTION`) and the ``authorizer`` decides, per
    message, whether the actor may run.  Denied messages are failed
    (and thereby dead-lettered) before the actor runs; the denial
    reason is recorded on the message under
    :data:`DENIED_REASON_OPTION` so monitoring can tell why the
    message was dropped.

    Parameters:
      authorizer: A callable taking ``(actor_name, queue_name,
        publisher, message)`` and returning a truthy value to allow
        the message.  It may return a falsy value or raise
        :class:`AuthorizationDenied` to deny the message.  When
        ``None``, all messages are allowed.
      publisher_option(str): The message option that carries the
        publisher's identity.  Defaults to ``"publisher"``.
    """

    def __init__(
        self,
        authorizer: Optional[Callable[..., bool]] = None,
        *,
        publisher_option: str = PUBLISHER_OPTION,
    ) -> None:
        self.logger = get_logger(__name__, type(self))
        self.authorizer = authorizer
        self.publisher_option = publisher_option

    def before_process_message(self, broker, message):
        if self.authorizer is None:
            return

        actor_name = message.actor_name
        queue_name = message.queue_name
        publisher = message.options.get(self.publisher_option)

        try:
            allowed = self.authorizer(actor_name, queue_name, publisher, message)
        except AuthorizationDenied as denied:
            self._deny(message, denied)

        if not allowed:
            self._deny(
                message,
                AuthorizationDenied(
                    "publisher %r is not authorized to dispatch actor %r on queue %r"
                    % (publisher, actor_name, queue_name),
                    actor_name=actor_name,
                    queue_name=queue_name,
                    publisher=publisher,
                ),
            )

    def _deny(self, message, denied: AuthorizationDenied):
        message.options[DENIED_REASON_OPTION] = denied.reason
        message.fail()
        self.logger.warning(
            "Message %s was denied authorization: %s",
            message.message_id,
            denied.reason,
        )
        raise denied


class PermissionPolicy:
    """A ready-made authorizer for :class:`TaskAuthorization` that
    keeps an allow-list of which publishers may dispatch which actors
    on which queues.

    Grants can be added and revoked at runtime; workers check the
    policy every time a message is delivered, so revoking a grant
    takes effect immediately.
    """

    def __init__(self) -> None:
        self._grants: dict[str, dict[str, set[str]]] = {}

    def grant(self, publisher: str, actor_name: str, queue_name: str) -> None:
        """Allow ``publisher`` to dispatch ``actor_name`` on ``queue_name``."""
        self._grants.setdefault(publisher, {}).setdefault(actor_name, set()).add(queue_name)

    def revoke(
        self,
        publisher: str,
        actor_name: Optional[str] = None,
        queue_name: Optional[str] = None,
    ) -> None:
        """Revoke grants previously given to ``publisher``.

        Revokes every grant for the publisher by default, every grant
        for an actor when ``actor_name`` is given, or a single queue
        grant when both ``actor_name`` and ``queue_name`` are given.
        """
        if actor_name is None:
            self._grants.pop(publisher, None)
            return

        actors = self._grants.get(publisher)
        if not actors:
            return

        if queue_name is None:
            actors.pop(actor_name, None)
        else:
            queues = actors.get(actor_name, set())
            queues.discard(queue_name)

    def __call__(self, actor_name, queue_name, publisher, message) -> bool:
        grants = self._grants.get(publisher) if publisher is not None else None
        if grants is None:
            raise AuthorizationDenied(
                "unknown publisher %r" % (publisher,),
                actor_name=actor_name,
                queue_name=queue_name,
                publisher=publisher,
            )

        queues = grants.get(actor_name)
        if not queues:
            raise AuthorizationDenied(
                "publisher %r may not dispatch actor %r" % (publisher, actor_name),
                actor_name=actor_name,
                queue_name=queue_name,
                publisher=publisher,
            )

        if queue_name not in queues:
            raise AuthorizationDenied(
                "publisher %r may not dispatch actor %r on queue %r" % (publisher, actor_name, queue_name),
                actor_name=actor_name,
                queue_name=queue_name,
                publisher=publisher,
            )

        return True
