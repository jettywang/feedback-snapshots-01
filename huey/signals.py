import itertools
import logging


logger = logging.getLogger('huey')

SIGNAL_CANCELED = 'canceled'
SIGNAL_COMPLETE = 'complete'
SIGNAL_ERROR = 'error'
SIGNAL_EXECUTING = 'executing'
SIGNAL_EXPIRED = 'expired'
SIGNAL_LOCKED = 'locked'
SIGNAL_RETRYING = 'retrying'
SIGNAL_REVOKED = 'revoked'
SIGNAL_SCHEDULED = 'scheduled'
SIGNAL_INTERRUPTED = 'interrupted'
SIGNAL_ENQUEUED = 'enqueued'
SIGNAL_TIMEOUT = 'timeout'
SIGNAL_RATE_LIMITED = 'rate-limited'


class TaskView(object):
    """
    Public, argument-free view of a task passed to restricted signal receivers.

    A restricted receiver only needs enough information to identify what ran:
    the public task id, the task category (function name and module) and the
    queue. Task arguments, keyword arguments and exception instances are
    deliberately not exposed -- they stay in the task's execution path and are
    only available to unrestricted receivers.

    Instances are read-only. They are built without touching ``task.args``,
    ``task.kwargs``, ``repr(task)`` or ``str(task)``.
    """
    __slots__ = ('_id', '_name', '_module', '_queue')

    def __init__(self, id, name, module='', queue=None):
        object.__setattr__(self, '_id', id)
        object.__setattr__(self, '_name', name)
        object.__setattr__(self, '_module', module)
        object.__setattr__(self, '_queue', queue)

    def __setattr__(self, key, value):
        raise AttributeError('TaskView is read-only')

    @classmethod
    def from_task(cls, task, queue=None):
        task_type = type(task)
        name = getattr(task_type, '__name__', None) or ''
        module = getattr(task_type, '__module__', None) or ''
        # Never touch task.args / task.kwargs, and never call repr() or
        # str() on the task instance.
        try:
            task_id = task.id
        except Exception:
            task_id = None
        return cls(task_id, name, module, queue)

    @property
    def id(self):
        """Public task id, usable to look up the result."""
        return self._id

    @property
    def public_id(self):
        return self._id

    @property
    def task_id(self):
        return self._id

    @property
    def name(self):
        """Task function name (the task category)."""
        return self._name

    @property
    def category(self):
        return self._name

    @property
    def module(self):
        return self._module

    @property
    def task(self):
        """Fully-qualified task category, e.g. ``myapp.tasks.send_email``."""
        return '%s.%s' % (self._module, self._name) if self._module else \
                self._name

    @property
    def task_name(self):
        return self.task

    @property
    def full_name(self):
        return self.task

    @property
    def queue(self):
        return self._queue

    def __repr__(self):
        return '<TaskView: %s: %s>' % (self.task, self.id)


def _receiver_name(receiver):
    # Never fall back to repr(receiver): a callable's repr may include
    # arguments or other customer data, and a broken repr must not prevent
    # the remaining receivers from running.
    try:
        name = getattr(receiver, '__name__', None)
    except Exception:
        name = None
    return name if isinstance(name, str) else '<receiver>'


class Signal(object):
    __slots__ = ('receivers', 'queue')

    def __init__(self, queue=None):
        self.receivers = {'any': []}
        self.queue = queue

    def connect(self, receiver, *signals, restricted=False):
        if not signals:
            signals = ('any',)
        entry = (receiver, restricted)
        for signal in signals:
            self.receivers.setdefault(signal, [])
            self.receivers[signal].append(entry)

    def disconnect(self, receiver, *signals):
        if not signals:
            signals = list(self.receivers)
        for signal in signals:
            entries = self.receivers.get(signal)
            if entries is not None:
                self.receivers[signal] = [
                    entry for entry in entries if entry[0] is not receiver]

    def send(self, signal, task, *args, **kwargs):
        receivers = itertools.chain(self.receivers.get(signal, ()),
                                    self.receivers['any'])
        view = None
        for receiver, restricted in receivers:
            try:
                if restricted:
                    if view is None:
                        view = TaskView.from_task(task, self.queue)
                    # Extra signal arguments (e.g. the exception) are withheld
                    # from restricted receivers.
                    receiver(signal, view)
                else:
                    receiver(signal, task, *args, **kwargs)
            except Exception as exc:
                name = _receiver_name(receiver)
                if restricted:
                    # Restricted receivers never get task data, so nothing
                    # from the task can leak. The listener's own exception
                    # message and traceback are also withheld: they are
                    # listener-controlled and must not turn into a data leak
                    # in the log.
                    logger.error('Error occurred in restricted receiver "%s" '
                                 'for signal "%s" (%s)', name, signal,
                                 type(exc).__name__)
                else:
                    logger.exception('Error occurred in receiver "%s" for '
                                     'signal "%s"', name, signal)
