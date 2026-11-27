import json
import os
import signal
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from redis import Redis

    from .authorization import QueueAuthorizationPolicy
    from .worker import BaseWorker

from rq.authorization import authorize_control_command, resolve_execution_worker
from rq.defaults import RQ_KEY_PREFIX
from rq.exceptions import InvalidJobOperation
from rq.executions import Execution
from rq.job import Job

PUBSUB_CHANNEL_TEMPLATE = RQ_KEY_PREFIX + ':pubsub:%s'


def send_command(
    connection: 'Redis',
    worker_name: str,
    command: str,
    operator_id: str | None = None,
    policy: 'QueueAuthorizationPolicy | None' = None,
    **kwargs,
):
    """
    Sends a command to a worker.
    A command is just a string, available commands are:
        - `shutdown`: Shuts down a worker
        - `kill-horse`: Command for the worker to kill the current working horse
        - `stop-execution`: A command for the worker to stop one execution of a job
        - `stop-job`: A command for the worker to stop the currently running job

    The command string will be parsed into a dictionary and send to a PubSub Topic.
    Workers listen to the PubSub, and `handle` the specific command.

    When a `policy` is supplied, the request is authorized against the worker's
    live registered identity and current queues before anything is published.

    Args:
        connection (Redis): A Redis Connection
        worker_name (str): The Job ID
        operator_id (Optional[str]): Identity of the operator, required with a policy
        policy (Optional[QueueAuthorizationPolicy]): Least-privilege policy to enforce
    """
    if policy is not None:
        authorize_control_command(
            connection=connection,
            operator_id=operator_id or '',
            worker_name=worker_name,
            command=command,
            policy=policy,
        )
    payload = {'command': command}
    if operator_id is not None:
        payload['operator_id'] = operator_id
    if kwargs:
        payload.update(kwargs)
    connection.publish(PUBSUB_CHANNEL_TEMPLATE % worker_name, json.dumps(payload))


def parse_payload(payload: dict[Any, Any]) -> dict[Any, Any]:
    """
    Returns a dict of command data

    Args:
        payload (dict): Parses the payload dict.
    """
    return json.loads(payload['data'].decode())


def send_shutdown_command(
    connection: 'Redis',
    worker_name: str,
    operator_id: str | None = None,
    policy: 'QueueAuthorizationPolicy | None' = None,
):
    """
    Sends a command to shutdown a worker.

    Args:
        connection (Redis): A Redis Connection
        worker_name (str): The Job ID
        operator_id (Optional[str]): Identity of the operator, required with a policy
        policy (Optional[QueueAuthorizationPolicy]): Least-privilege policy to enforce
    """
    send_command(
        connection, worker_name, 'shutdown', operator_id=operator_id, policy=policy
    )


def send_kill_horse_command(
    connection: 'Redis',
    worker_name: str,
    operator_id: str | None = None,
    policy: 'QueueAuthorizationPolicy | None' = None,
):
    """
    Tell worker to kill it's horse

    Args:
        connection (Redis): A Redis Connection
        worker_name (str): The Job ID
        operator_id (Optional[str]): Identity of the operator, required with a policy
        policy (Optional[QueueAuthorizationPolicy]): Least-privilege policy to enforce
    """
    send_command(
        connection, worker_name, 'kill-horse', operator_id=operator_id, policy=policy
    )


def send_stop_execution_command(
    connection: 'Redis',
    job_id: str,
    execution_id: str,
    operator_id: str | None = None,
    policy: 'QueueAuthorizationPolicy | None' = None,
):
    """
    Instruct a worker to stop one execution of a job.

    The execution record (which may be a late heartbeat) resolves the exact target
    worker; an identity mismatch raises instead of guessing the recipient.

    Args:
        connection (Redis): A Redis Connection
        job_id (str): The Job ID
        execution_id (str): The Execution ID
        operator_id (Optional[str]): Identity of the operator, required with a policy
        policy (Optional[QueueAuthorizationPolicy]): Least-privilege policy to enforce
    """
    try:
        execution = Execution.fetch(id=execution_id, job_id=job_id, connection=connection)
    except ValueError:
        raise InvalidJobOperation('Execution is not running')
    # Re-read the (possibly late) record and fail on any identity drift instead of
    # sending the command to a worker the record no longer points to.
    recorded_worker = resolve_execution_worker(
        connection=connection,
        job_id=job_id,
        execution_id=execution_id,
        expected_worker_name=execution.worker_name,
    )
    send_command(
        connection,
        recorded_worker,
        'stop-execution',
        operator_id=operator_id,
        policy=policy,
        job_id=job_id,
        execution_id=execution_id,
    )


def send_stop_job_command(
    connection: 'Redis',
    job_id: str,
    serializer=None,
    operator_id: str | None = None,
    policy: 'QueueAuthorizationPolicy | None' = None,
):
    """
    Instruct a worker to stop a job

    Args:
        connection (Redis): A Redis Connection
        job_id (str): The Job ID
        serializer (): The serializer
        operator_id (Optional[str]): Identity of the operator, required with a policy
        policy (Optional[QueueAuthorizationPolicy]): Least-privilege policy to enforce
    """
    job = Job.fetch(job_id, connection=connection, serializer=serializer)
    if not job.worker_name:
        raise InvalidJobOperation('Job is not currently executing')
    send_command(
        connection,
        job.worker_name,
        'stop-job',
        operator_id=operator_id,
        policy=policy,
        job_id=job_id,
    )


def handle_command(
    worker: 'BaseWorker',
    payload: dict[Any, Any],
    policy: 'QueueAuthorizationPolicy | None' = None,
    operator_id: str | None = None,
):
    """Parses payload and routes commands to the worker.

    When a policy is supplied, the worker re-authorizes the request against its
    own live registered identity and current queues before acting. The worker's
    `on_control_authorization` callback always records the decision so in-memory
    audit hooks can prove which executor handled the command and on which queues.

    Args:
        worker (Worker): The worker to use
        payload (Dict[Any, Any]): The Payload
        policy (Optional[QueueAuthorizationPolicy]): Least-privilege policy to enforce
        operator_id (Optional[str]): Identity of the operator, required with a policy
    """
    from rq.authorization import AuthorizationEvent, evaluate_control_command, get_worker_queues

    command = payload['command']
    queue_names = get_worker_queues(worker.connection, worker.name) or tuple(worker.queue_names())

    if policy is not None:
        # Never raise here: this runs on the pubsub thread where an exception would
        # stop command delivery. A denial is recorded and the command is skipped.
        event = evaluate_control_command(
            connection=worker.connection,
            operator_id=operator_id or payload.get('operator_id', ''),
            worker_name=worker.name,
            command=command,
            policy=policy,
            queue_names=queue_names,
        )
    else:
        event = AuthorizationEvent(
            allowed=True,
            command=command,
            operator_id=operator_id or payload.get('operator_id', ''),
            worker_name=worker.name,
            queue_names=queue_names,
        )

    # The hook records every decision (including denials) with the live executor
    # identity and current queues, even when no policy is configured.
    worker.on_control_authorization(event)

    if policy is not None and not event.allowed:
        worker.log.warning(
            'Worker %s: command %r denied: %s', worker.name, command, event.reason
        )
        return

    if command == 'stop-execution':
        handle_stop_execution_command(worker, payload)
    elif command == 'stop-job':
        handle_stop_job_command(worker, payload)
    elif command == 'shutdown':
        handle_shutdown_command(worker)
    elif command == 'kill-horse':
        handle_kill_worker_command(worker, payload)


def handle_shutdown_command(worker: 'BaseWorker'):
    """Perform shutdown command.

    Args:
        worker (Worker): The worker to use.
    """
    worker.log.info('Received shutdown command, sending SIGINT signal.')
    pid = os.getpid()
    os.kill(pid, signal.SIGINT)


def handle_kill_worker_command(worker: 'BaseWorker', payload: dict[Any, Any]):
    """
    Stops work horse

    Args:
        worker (Worker): The worker to stop
        payload (Dict[Any, Any]): The payload.
    """

    worker.log.info('Received kill horse command.')
    if worker.horse_pid:
        worker.log.info('Killing horse...')
        worker.kill_horse()
    else:
        worker.log.info('Worker is not working, kill horse command ignored')


def handle_stop_execution_command(worker: 'BaseWorker', payload: dict[Any, Any]):
    """Handles stop execution command.

    Args:
        worker (Worker): The worker to use
        payload (Dict[Any, Any]): The payload.
    """
    job_id = payload.get('job_id', '')
    execution_id = payload.get('execution_id', '')
    worker.log.debug('Received command to stop execution %s of job %s', execution_id, job_id)
    worker.request_stop_execution(execution_id)


def handle_stop_job_command(worker: 'BaseWorker', payload: dict[Any, Any]):
    """Handles stop job command.

    Args:
        worker (Worker): The worker to use
        payload (Dict[Any, Any]): The payload.
    """
    job_id = payload.get('job_id')
    worker.log.debug('Received command to stop job %s', job_id)
    if job_id and worker.get_current_job_id() == job_id:
        # Sets the '_stopped_job_id' so that the job failure handler knows it
        # was intentional.
        worker._stopped_job_id = job_id
        worker.kill_horse()
    else:
        worker.log.warning('Not working on job %s, command ignored.', job_id)
