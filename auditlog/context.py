import contextlib
import itertools
import time
from contextvars import ContextVar
from functools import partial

from django.contrib.auth import get_user_model
from django.db.models.signals import pre_save

from auditlog import get_logentry_model

auditlog_value = ContextVar("auditlog_value")
auditlog_disabled = ContextVar("auditlog_disabled", default=False)
_context_counter = itertools.count()


@contextlib.contextmanager
def set_actor(actor, remote_addr=None, remote_port=None):
    context_data = {
        "actor": actor,
        "remote_addr": remote_addr,
        "remote_port": remote_port,
    }
    with _push_context(context_data):
        yield


@contextlib.contextmanager
def set_on_behalf_of(
    on_behalf_of, actor=None, remote_addr=None, remote_port=None
):
    """Log entries created inside this context are attributed to a represented user.

    The authenticated user performing the action (the operator) is passed as
    ``actor`` while ``on_behalf_of`` is the user on whose behalf the action is
    performed. Nested contexts are supported: when this context exits, the
    previously active context (if any) is restored unchanged.
    """
    context_data = {
        "on_behalf_of": on_behalf_of,
    }
    if actor is not None:
        context_data["actor"] = actor
    if remote_addr is not None:
        context_data["remote_addr"] = remote_addr
    if remote_port is not None:
        context_data["remote_port"] = remote_port
    with _push_context(context_data):
        yield


@contextlib.contextmanager
def set_extra_data(context_data):
    with _push_context(context_data):
        yield


def _get_stack():
    try:
        return list(auditlog_value.get())
    except LookupError:
        return []


def _effective_context():
    """Merge every active frame, outer frames first so inner frames win."""
    effective = {}
    for frame in _get_stack():
        for key, value in frame.items():
            if key != "signal_duid":
                effective[key] = value
    return effective


@contextlib.contextmanager
def _push_context(context_data):
    """Push a context frame, connect its receiver, and restore the stack on exit."""
    LogEntry = get_logentry_model()

    frame = dict(context_data)
    frame["signal_duid"] = ("set_actor", next(_context_counter), time.time_ns())

    stack = _get_stack()
    token = auditlog_value.set(stack + [frame])

    # Connect signal for automatic logging
    set_extra_data_receiver = partial(
        _set_extra_data,
        signal_duid=frame["signal_duid"],
    )
    pre_save.connect(
        set_extra_data_receiver,
        sender=LogEntry,
        dispatch_uid=frame["signal_duid"],
        weak=False,
    )

    try:
        yield
    finally:
        try:
            auditlog_value.reset(token)
        except ValueError:
            # The context variable was modified further down the stack; fall
            # back to removing the frame explicitly.
            stack = [
                item
                for item in _get_stack()
                if item["signal_duid"] != frame["signal_duid"]
            ]
            auditlog_value.set(stack)
        pre_save.disconnect(sender=LogEntry, dispatch_uid=frame["signal_duid"])


def _set_actor(auditlog, instance, sender):
    LogEntry = get_logentry_model()
    auth_user_model = get_user_model()
    if "actor" in auditlog:
        actor = auditlog.get("actor")
        if (
            sender == LogEntry
            and isinstance(actor, auth_user_model)
            and instance.actor is None
        ):
            instance.actor = actor
            instance.actor_email = getattr(actor, "email", None)


def _set_on_behalf_of(auditlog, instance, sender):
    LogEntry = get_logentry_model()
    auth_user_model = get_user_model()
    if "on_behalf_of" in auditlog:
        on_behalf_of = auditlog.get("on_behalf_of")
        if (
            sender == LogEntry
            and isinstance(on_behalf_of, auth_user_model)
            and instance.on_behalf_of is None
        ):
            instance.on_behalf_of = on_behalf_of
            instance.on_behalf_of_email = getattr(on_behalf_of, "email", None)


def _set_extra_data(sender, instance, signal_duid, **kwargs):
    """Signal receiver with extra 'user' and 'signal_duid' kwargs.

    This function becomes a valid signal receiver when it is curried with the actor and a dispatch id.
    """
    LogEntry = get_logentry_model()
    stack = _get_stack()
    if not stack or signal_duid != stack[-1]["signal_duid"]:
        # Signals are dispatched last-connected-first, so the innermost frame
        # applies the merged context exactly once even with nested contexts.
        return

    auditlog = _effective_context()

    _set_actor(auditlog, instance, sender)
    _set_on_behalf_of(auditlog, instance, sender)

    for key in auditlog:
        if key not in ("actor", "on_behalf_of") and hasattr(LogEntry, key):
            if callable(auditlog[key]):
                setattr(instance, key, auditlog[key]())
            else:
                setattr(instance, key, auditlog[key])


@contextlib.contextmanager
def disable_auditlog():
    token = auditlog_disabled.set(True)
    try:
        yield
    finally:
        try:
            auditlog_disabled.reset(token)
        except LookupError:
            pass
