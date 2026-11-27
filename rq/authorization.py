"""Least-privilege authorization for the worker control command chain.

Some operators are only allowed to manage the workers serving a specific set of
queues. The policies in this module decide whether an operator may send a control
command to a worker. Decisions are always made from the worker's *registered
identity and current queues* as stored in Redis, rather than from a worker object
that may be stale (for example after a queue migration or a normal restart).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Sequence

from .defaults import RQ_KEY_PREFIX
from .exceptions import AuthorizationError, IdentityConflictError
from .utils import as_text

if TYPE_CHECKING:
    from redis import Redis

#: Control commands supported by the pubsub command chain.
CONTROL_COMMANDS: frozenset[str] = frozenset(
    {'shutdown', 'kill-horse', 'stop-job', 'stop-execution'}
)


@dataclass(frozen=True)
class AuthorizationEvent:
    """A single authorization decision, suitable for in-memory audit callbacks.

    Attributes:
        allowed: Whether the command was authorized.
        command: The control command that was requested.
        operator_id: Identity of the operator requesting the command.
        worker_name: Registered name of the target worker.
        queue_names: The worker's current queues when the decision was made.
        reason: Human readable explanation, populated for denials and conflicts.
    """

    allowed: bool
    command: str
    operator_id: str
    worker_name: str
    queue_names: tuple[str, ...] = field(default_factory=tuple)
    reason: str = ''


# A policy maps an operator to the queues they are allowed to manage.
QueuePolicy = dict[str, frozenset[str]]
# Callbacks receive every decision, e.g. to append it to an in-memory audit log.
AuthorizationCallback = Callable[[AuthorizationEvent], None]


class QueueAuthorizationPolicy:
    """Authorizes operators based on the queues they are permitted to manage.

    An operator may control a worker only when every queue the worker currently
    serves is present in the operator's allowlist. Operators without an entry,
    and workers that are no longer registered, are denied.
    """

    def __init__(
        self,
        allowed_queues: QueuePolicy | None = None,
        callback: AuthorizationCallback | None = None,
    ):
        self._allowed_queues: QueuePolicy = {
            operator: frozenset(queues) for operator, queues in (allowed_queues or {}).items()
        }
        self.callback = callback

    def allow(self, operator_id: str, queue_names: Sequence[str]) -> bool:
        """Return whether the operator may manage a worker on the given queues."""
        permitted = self._allowed_queues.get(operator_id)
        if permitted is None:
            return False
        return all(queue_name in permitted for queue_name in queue_names)

    def authorize(
        self,
        operator_id: str,
        worker_name: str,
        queue_names: Sequence[str],
        command: str,
    ) -> AuthorizationEvent:
        """Evaluate a request and record the decision through the callback."""
        allowed = self.allow(operator_id, queue_names)
        if allowed:
            reason = ''
        elif self._allowed_queues.get(operator_id) is None:
            reason = f'operator {operator_id!r} has no managed queues'
        else:
            reason = (
                f'operator {operator_id!r} is not allowed to manage all of '
                f'{list(queue_names)}'
            )
        event = AuthorizationEvent(
            allowed=allowed,
            command=command,
            operator_id=operator_id,
            worker_name=worker_name,
            queue_names=tuple(queue_names),
            reason=reason,
        )
        if self.callback is not None:
            self.callback(event)
        return event


def get_worker_queues(connection: Redis, worker_name: str) -> tuple[str, ...]:
    """Return the current queues of a registered worker, read live from Redis.

    The worker hash's ``queues`` field is the identity the worker registered on
    its last birth/heartbeat. An empty tuple means the worker is not registered.
    """
    raw_queues = connection.hget(worker_key(worker_name), 'queues')
    if not raw_queues:
        return ()
    return tuple(name for name in as_text(raw_queues).split(',') if name)


def worker_key(worker_name: str) -> str:
    """Redis hash key for a worker name."""
    return f'{RQ_KEY_PREFIX}:worker:{worker_name}'


def resolve_execution_worker(
    connection: Redis,
    job_id: str,
    execution_id: str,
    expected_worker_name: str | None = None,
) -> str:
    """Resolve the exact worker recorded on a (possibly late) execution.

    Late heartbeats can outlive the worker that started them, so the target is
    read from the execution hash rather than assumed. When an expected worker is
    supplied and the record points elsewhere, an :class:`IdentityConflictError`
    is raised so callers never act on the wrong worker.
    """
    from .executions import Execution

    execution = Execution(id=execution_id, job_id=job_id, connection=connection)
    try:
        execution.refresh()
    except ValueError:
        raise IdentityConflictError(
            f'execution {execution_id} of job {job_id} cannot be located'
        )
    recorded_worker = execution.worker_name
    if not recorded_worker:
        raise IdentityConflictError(
            f'execution {execution_id} of job {job_id} records no worker identity'
        )
    if expected_worker_name is not None and recorded_worker != expected_worker_name:
        raise IdentityConflictError(
            f'execution {execution_id} of job {job_id} belongs to worker '
            f'{recorded_worker!r}, not {expected_worker_name!r}'
        )
    return recorded_worker


def evaluate_control_command(
    connection: Redis,
    operator_id: str,
    worker_name: str,
    command: str,
    policy: QueueAuthorizationPolicy | None = None,
    queue_names: Sequence[str] | None = None,
) -> AuthorizationEvent:
    """Evaluate a control command against the worker's live registration.

    With no policy the historical control API is preserved: every command is
    allowed. With a policy, the worker's current queues are read from Redis and
    the operator must be permitted to manage all of them. The decision (including
    denials) is recorded through the policy's callback, but no exception is raised,
    which makes this safe to call from the worker's pubsub thread.
    """
    if queue_names is None:
        queue_names = get_worker_queues(connection, worker_name)
    queue_names = tuple(queue_names)

    if policy is None:
        return AuthorizationEvent(
            allowed=True,
            command=command,
            operator_id=operator_id,
            worker_name=worker_name,
            queue_names=queue_names,
        )

    if not queue_names:
        event = AuthorizationEvent(
            allowed=False,
            command=command,
            operator_id=operator_id,
            worker_name=worker_name,
            queue_names=(),
            reason=f'worker {worker_name!r} is not registered',
        )
        if policy.callback is not None:
            policy.callback(event)
        return event

    return policy.authorize(operator_id, worker_name, queue_names, command)


def authorize_control_command(
    connection: Redis,
    operator_id: str,
    worker_name: str,
    command: str,
    policy: QueueAuthorizationPolicy | None = None,
    queue_names: Sequence[str] | None = None,
) -> AuthorizationEvent:
    """Sender-side gate: evaluate a command and raise on denial.

    This runs before anything is published, so a denied request fails closed with
    an :class:`AuthorizationError`. Use :func:`evaluate_control_command` on the
    receiving worker, where raising inside the pubsub thread is undesirable.
    """
    event = evaluate_control_command(
        connection=connection,
        operator_id=operator_id,
        worker_name=worker_name,
        command=command,
        policy=policy,
        queue_names=queue_names,
    )
    if not event.allowed:
        raise AuthorizationError(event.reason)
    return event
