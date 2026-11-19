"""Shared ``post_log`` recorder for the transaction semantics tests."""

from types import SimpleNamespace


class PostLogRecorder:
    """Collect every ``post_log`` message without touching the database."""

    def __init__(self):
        self.calls = []

    def __call__(self, signal, sender, **kwargs):
        self.calls.append(
            SimpleNamespace(
                sender=sender,
                instance=kwargs["instance"],
                action=kwargs["action"],
                error=kwargs["error"],
                log_entry=kwargs["log_entry"],
                log_created=kwargs["log_created"],
                changes=kwargs["changes"],
                instance_old=kwargs.get("instance_old"),
                instance_db=getattr(kwargs["instance"]._state, "db", None),
                log_db=(kwargs["log_entry"]._state.db if kwargs["log_entry"] else None),
            )
        )
