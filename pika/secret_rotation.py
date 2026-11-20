"""Observable contract for renewing the secret of an open AMQP connection.

`pika.connection.Connection.update_secret` sends the broker a
`Connection.UpdateSecret` frame but gives the caller no state to inspect
afterwards: whether the broker confirmed the new secret, whether a reply is
still outstanding, and which secret the next reconnect must present. The
coordinator in this module owns that bookkeeping.

The coordinator never logs a secret value. It refers to each candidate by a
monotonic generation, so logs show the ordering and the retry conditions
without disclosing the secret itself.
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pika.exceptions
from pika import frame, spec

if TYPE_CHECKING:
    from pika.connection import Connection

LOGGER = logging.getLogger(__name__)


class RotationState(enum.Enum):
    """Lifecycle of the secret rotation contract.

    :ivar CONFIRMED: no update is in flight and the active secret was accepted
        by the broker. This is the initial and steady state.
    :ivar PENDING: an `UpdateSecret` frame was sent and `UpdateSecretOk` has
        not been received.
    :ivar UNCONFIRMED: the connection closed while an update was pending, so
        the broker never answered. The candidate secret is retained for a
        retry on a connection that is open again.
    """

    CONFIRMED = 'confirmed'
    PENDING = 'pending'
    UNCONFIRMED = 'unconfirmed'


@dataclass(frozen=True)
class RotationSnapshot:
    """Point-in-time view of the rotation contract.

    A snapshot is immutable, so callers reading it while the IOLoop drives a
    reply cannot observe a torn state. It never carries a secret value.

    :param state: current rotation state
    :param generation: generation of the active secret; zero is the secret the
        coordinator was constructed with
    :param pending_generation: generation awaiting a broker reply, or `None`
        when no update is in flight
    :param attempts: how many times the current candidate has been sent,
        including the in-flight attempt; zero before the first rotation
    :param retriable: whether a candidate is waiting to be retried on the next
        open connection
    """

    state: RotationState
    generation: int
    pending_generation: int | None
    attempts: int
    retriable: bool


class SecretRotationCoordinator:
    """Track secret rotations against the broker's confirmations.

    The coordinator wraps the connection's `update_secret` RPC. A rotation
    moves through `RotationState.PENDING` and only reaches
    `RotationState.CONFIRMED` once the broker returns
    `Connection.UpdateSecretOk`. A connection closing before that reply leaves
    the candidate in `RotationState.UNCONFIRMED`, which is the retriable
    condition. A reply that arrives after the connection closed or for a
    superseded generation is ignored.

    The secret used for a reconnect is always the last *confirmed* secret,
    exposed by `secret_for_reconnect`. An unconfirmed candidate is never used
    to authenticate a new connection because the broker may have rejected it.
    """

    def __init__(self,
                 connection: Connection,
                 initial_secret: str,
                 logger: logging.Logger | None = None) -> None:
        """Bind the contract to a connection and its current secret.

        :param connection: open connection whose `update_secret` is driven by
            this coordinator
        :param initial_secret: secret the connection authenticated with; held
            as the confirmed secret until a later rotation is acknowledged
        :param logger: override the module logger, mainly for tests

        :raises ValueError: if `initial_secret` is not a string
        """
        if not isinstance(initial_secret, str):
            raise ValueError(
                f'initial_secret must be a str, but got {type(initial_secret).__name__}'
            )
        self._connection = connection
        self._logger = logger if logger is not None else LOGGER
        self._generation = 0
        self._next_generation = 1
        self._attempts = 0
        self._state = RotationState.CONFIRMED
        self._confirmed_secret = initial_secret
        self._pending_secret: str | None = None
        self._pending_generation: int | None = None

    @property
    def state(self) -> RotationState:
        """Current rotation state."""
        return self._state

    @property
    def generation(self) -> int:
        """Generation of the last confirmed secret.

        Generation zero is the constructor's `initial_secret`.
        """
        return self._generation

    @property
    def retriable(self) -> bool:
        """Whether a candidate is waiting to be retried on an open connection."""
        return self._state is RotationState.UNCONFIRMED

    def snapshot(self) -> RotationSnapshot:
        """Return an immutable copy of the observable contract state."""
        return RotationSnapshot(
            state=self._state,
            generation=self._generation,
            pending_generation=self._pending_generation,
            attempts=self._attempts,
            retriable=self.retriable,
        )

    def secret_for_reconnect(self) -> str:
        """Return the secret to authenticate a new connection with.

        This is the last confirmed secret, never a candidate whose
        confirmation is outstanding or lost.
        """
        return self._confirmed_secret

    def bind(self, connection: Connection) -> None:
        """Point the contract at a replacement connection.

        An unconfirmed candidate stays retriable and can be re-sent with
        `retry`. A pending candidate cannot move to a new connection, because
        the old connection owns the outstanding RPC, so binding while pending
        raises rather than silently dropping the reply.

        :param connection: the open connection to drive future rotations on

        :raises pika.exceptions.ConnectionWrongStateError: if a rotation is still pending
        """
        if self._state is RotationState.PENDING:
            raise pika.exceptions.ConnectionWrongStateError(
                'Cannot rebind while a secret update is pending; close or wait '
                'for the outstanding connection first')
        self._connection = connection
        self._logger.info(
            'bound rotation coordinator to a new connection; state=%s generation=%i',
            self._state.value, self._generation)

    def rotate(self, new_secret: str, reason: str) -> int:
        """Send a new secret to the broker and move to the pending state.

        :param new_secret: candidate secret replacing the confirmed one
        :param reason: broker-facing reason string for the update
        :returns: the generation assigned to this candidate

        :raises ValueError: if `new_secret` is not a string
        :raises pika.exceptions.ConnectionWrongStateError: if an update is already pending
        :raises pika.exceptions.ConnectionWrongStateError: if the connection is
            not open, propagated from `Connection.update_secret`
        """
        if not isinstance(new_secret, str):
            raise ValueError(
                f'new_secret must be a str, but got {type(new_secret).__name__}'
            )
        if self._state is RotationState.PENDING:
            raise pika.exceptions.ConnectionWrongStateError(
                f'Secret update generation {self._pending_generation} is still pending'
            )

        if self._state is RotationState.UNCONFIRMED:
            # A newer secret supersedes the candidate the broker never answered.
            self._logger.info(
                'discarding unconfirmed generation %i in favour of a new candidate',
                self._pending_generation)

        self._pending_generation = self._next_generation
        self._next_generation += 1
        self._pending_secret = new_secret
        self._attempts = 1
        self._state = RotationState.PENDING
        self._logger.info(
            'sending secret update generation=%i reason=%r attempts=%i',
            self._pending_generation, reason, self._attempts)
        self._connection.update_secret(new_secret, reason, self._on_update_ok)
        return self._pending_generation

    def retry(self, reason: str) -> int:
        """Re-send the candidate lost when the previous connection closed.

        :param reason: broker-facing reason string for the update
        :returns: the generation of the retried candidate

        :raises pika.exceptions.ConnectionWrongStateError: if nothing is retriable
        :raises pika.exceptions.ConnectionWrongStateError: if the bound
            connection is not open
        """
        if self._state is not RotationState.UNCONFIRMED:
            raise pika.exceptions.ConnectionWrongStateError(
                f'No unconfirmed secret to retry; state is {self._state.value}')
        assert self._pending_secret is not None
        assert self._pending_generation is not None
        self._attempts += 1
        self._state = RotationState.PENDING
        self._logger.info('retrying secret update generation=%i attempts=%i',
                          self._pending_generation, self._attempts)
        self._connection.update_secret(self._pending_secret, reason,
                                       self._on_update_ok)
        return self._pending_generation

    def on_connection_closed(self) -> None:
        """Mark an in-flight candidate unconfirmed after the connection closes.

        A pending update becomes retriable. Calling this in any other state is
        harmless, since a confirmed secret needs no retry.
        """
        if self._state is not RotationState.PENDING:
            self._logger.info(
                'connection closed with no update in flight; state=%s',
                self._state.value)
            return
        self._state = RotationState.UNCONFIRMED
        self._logger.warning(
            'connection closed before broker confirmed generation=%i; '
            'candidate retained for retry attempts=%i',
            self._pending_generation, self._attempts)

    def _on_update_ok(
            self,
            method_frame: frame.Method[spec.Connection.UpdateSecretOk]) -> None:
        """Handle the broker's `UpdateSecretOk` reply.

        A reply only confirms the candidate currently in flight. Replies for a
        superseded generation or arriving after the connection closed are
        logged and ignored, so they cannot promote a secret nobody validated.
        """
        generation = self._pending_generation
        if self._state is not RotationState.PENDING:
            self._logger.info(
                'ignoring late UpdateSecretOk for generation=%s in state=%s',
                generation, self._state.value)
            return
        assert self._pending_secret is not None
        assert generation is not None
        self._confirmed_secret = self._pending_secret
        self._generation = generation
        self._pending_secret = None
        self._pending_generation = None
        self._attempts = 0
        self._state = RotationState.CONFIRMED
        self._logger.info(
            'broker confirmed secret update generation=%i; now the reconnect secret',
            generation)
