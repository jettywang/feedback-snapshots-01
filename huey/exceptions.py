class HueyException(Exception): pass
class ConfigurationError(HueyException): pass
class TaskLockedException(HueyException): pass
class ResultTimeout(HueyException): pass
class TaskTimeout(HueyException): pass


class RescheduleDenied(HueyException, ValueError):
    """Raised when an operations-initiated reschedule is not allowed.

    The exception carries enough context for the caller to report or audit the
    refusal without having to infer it from a generic error message.
    """
    def __init__(self, reason, task_id=None, task_type=None, state=None,
                 approval_id=None, record=None):
        self.reason = reason
        self.task_id = task_id
        self.task_type = task_type
        self.state = state
        self.approval_id = approval_id
        self.record = record
        super(RescheduleDenied, self).__init__(reason)

    def __str__(self):
        parts = [self.reason]
        if self.task_id is not None:
            parts.append('task=%s' % (self.task_id,))
        if self.task_type is not None:
            parts.append('type=%s' % (self.task_type,))
        if self.state is not None:
            parts.append('state=%s' % (self.state,))
        return ': '.join(parts)


# Aliases retained for callers that prefer a domain-specific name.
OpsRescheduleDenied = RescheduleDenied
TaskRescheduleDenied = RescheduleDenied
RescheduleError = RescheduleDenied

class RateLimitExceeded(HueyException):
    def __init__(self, key, delay, retry=True):
        self.key, self.delay, self.retry = key, delay, retry
        super(RateLimitExceeded, self).__init__(key, delay, retry)

    def __str__(self):
        if self.retry:
            return 'Rate limit exceeded on "%s", retry in %0.1fs' % (
                self.key, self.delay)
        return 'Rate limit exceeded on "%s"' % self.key

class CancelExecution(Exception):
    def __init__(self, msg=None, retry=None):
        self.retry = retry
        args = () if msg is None else (msg,)
        super(CancelExecution, self).__init__(*args)
class RetryTask(Exception):
    def __init__(self, msg=None, eta=None, delay=None, *args, **kwargs):
        self.eta, self.delay = eta, delay
        super(RetryTask, self).__init__(msg, *args, **kwargs)
class TaskException(Exception):
    def __init__(self, metadata=None, *args):
        self.metadata = metadata or {}
        super(TaskException, self).__init__(*args)

    def __str__(self):
        return self.metadata.get('error') or 'unknown error'


# Not failures while a retry is pending.
RETRYING_EXCEPTIONS = (RetryTask, RateLimitExceeded, TaskLockedException)
