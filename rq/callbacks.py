from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from .defaults import CALLBACK_TIMEOUT
from .timeouts import JobTimeoutException
from .utils import parse_timeout, resolve_function_reference
from .visibility import CallbackOutcome

if TYPE_CHECKING:
    from .job import Job
    from .timeouts import BaseDeathPenalty


class Callback:
    def __init__(self, func: str | Callable[..., Any], timeout: Any | None = None):
        if not isinstance(func, str) and not inspect.isfunction(func) and not inspect.isbuiltin(func):
            raise ValueError('Callback `func` must be a string or function')

        self.func = func
        self.timeout = parse_timeout(timeout) if timeout else CALLBACK_TIMEOUT

    @property
    def name(self) -> str:
        if isinstance(self.func, str):
            return self.func
        _, func_name = resolve_function_reference(self.func)
        return func_name


def _public_result(job: Job, result: Any) -> Any:
    """Return the result value as the external callback is allowed to see it."""
    if job.visibility is None:
        return result
    return job.visibility.redact(result)


def execute_success_callback(
    job: Job, death_penalty_class: type[BaseDeathPenalty], result: Any
) -> CallbackOutcome | None:
    """Run the job's success callback under its timeout.

    With a visibility policy the callback receives the redacted value; the full value stays
    on the job/result for approved internal observers. Returns the callback outcome, or None
    when the job has no success callback.
    """
    callback = job.success_callback
    if callback is None:
        return None
    if inspect.iscoroutinefunction(callback):
        raise TypeError('Coroutine success callbacks are not supported')

    job.log.debug('Job %s: running success callback...', job.id)
    try:
        with death_penalty_class(job.success_callback_timeout, JobTimeoutException, job_id=job.id):
            callback(job, job.connection, _public_result(job, result))
    except Exception:
        job.log.exception('Job %s: error while executing success callback', job.id)
        raise
    return CallbackOutcome('success', 'succeeded')


def execute_failure_callback(
    job: Job, death_penalty_class: type[BaseDeathPenalty], *exc_info
) -> CallbackOutcome | None:
    """Run the job's failure callback under its timeout.

    With a visibility policy the callback receives an exception summary without the original
    message or traceback frames. Returns the callback outcome, or None when the job has no
    failure callback.
    """
    callback = job.failure_callback
    if callback is None:
        return None
    if inspect.iscoroutinefunction(callback):
        raise TypeError('Coroutine failure callbacks are not supported')

    if job.visibility is not None:
        exc_info = job.visibility.public_exc_info(exc_info, job_id=job.id)

    job.log.debug('Job %s: running failure callback...', job.id)
    try:
        with death_penalty_class(job.failure_callback_timeout, JobTimeoutException, job_id=job.id):
            callback(job, job.connection, *exc_info)
    except Exception:
        job.log.exception('Job %s: error while executing failure callback', job.id)
        raise
    return CallbackOutcome('failure', 'succeeded')


def execute_stopped_callback(job: Job, death_penalty_class: type[BaseDeathPenalty]) -> CallbackOutcome | None:
    """Run the job's stopped callback under its timeout."""
    callback = job.stopped_callback
    if callback is None:
        return None
    if inspect.iscoroutinefunction(callback):
        raise TypeError('Coroutine stopped callbacks are not supported')

    job.log.debug('Job %s: running stopped callback...', job.id)
    try:
        with death_penalty_class(job.stopped_callback_timeout, JobTimeoutException, job_id=job.id):
            callback(job, job.connection)
    except Exception:
        job.log.exception('Job %s: error while executing stopped callback', job.id)
        raise
    return CallbackOutcome('stopped', 'succeeded')
