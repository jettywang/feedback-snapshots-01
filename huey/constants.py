WORKER_THREAD = 'thread'
WORKER_GREENLET = 'greenlet'
WORKER_PROCESS = 'process'
WORKER_TYPES = (WORKER_THREAD, WORKER_GREENLET, WORKER_PROCESS)


class EmptyData(object):
    pass


class ResultState(object):
    """
    Terminal / observable states for a task result.

    ``pending`` means no completion record is visible yet. ``success`` and
    ``failed`` mean a result value is available (a failed result raises
    ``TaskException`` when read). ``cancelled`` is a task that was explicitly
    cancelled. ``destroyed`` means the task finished successfully, but its
    result was removed according to the task's retention policy (read-once
    consumed or the retention TTL elapsed).
    """
    PENDING = 'pending'
    SUCCESS = 'success'
    FAILED = 'failed'
    CANCELLED = 'cancelled'
    DESTROYED = 'destroyed'
    EXPIRED = 'expired'  # Task expired before it could run.

    # Convenience alias for callers that use "unfinished".
    UNFINISHED = PENDING
