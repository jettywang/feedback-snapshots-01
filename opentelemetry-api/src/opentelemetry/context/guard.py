# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Optional runtime guard for :mod:`opentelemetry.context`.

The guard wraps a :class:`~opentelemetry.context.context._RuntimeContext` and
keeps a small, bounded history of attach/detach operations. It is disabled by
default. Enable it explicitly with :func:`enable`, or set
:envvar:`OTEL_PYTHON_CONTEXT_GUARD` to ``true`` before importing
``opentelemetry.context``.

The guard is diagnostic only. It delegates every operation to the wrapped
runtime, so synchronously nested and parallel (task/thread) context usage keeps
working exactly as before. Records never contain context values or baggage.
Public log lines are restricted to the request correlation id and the phase, as
set with :func:`diagnostics`.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import weakref
from collections import OrderedDict, deque
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from enum import Enum
from itertools import count
from typing import Any

from opentelemetry.context.context import Context, _RuntimeContext
from opentelemetry.environment_variables import (
    OTEL_PYTHON_CONTEXT_GUARD,
    OTEL_PYTHON_CONTEXT_GUARD_LOG,
)

logger = logging.getLogger(__name__)

_CORRELATION_ID = ContextVar("otel_context_guard_correlation_id", default=None)
_PHASE = ContextVar("otel_context_guard_phase", default=None)

_MAX_LABEL_LENGTH = 256
_DEFAULT_MAX_RECORDS = 1024
_DEFAULT_MAX_USED_TOKENS = 1024


class GuardOutcome(str, Enum):
    """Outcome recorded for an attach or detach operation."""

    ATTACHED = "attached"
    ATTACH_FAILED = "attach_failed"
    DETACHED = "detached"
    DETACHED_AFTER_CANCEL = "detached_after_cancel"
    DETACHED_UNTRACKED = "detached_untracked"
    DETACHED_FOREIGN_OWNER = "detached_foreign_owner"
    FOREIGN_OWNER = "foreign_owner"
    INVALID_TOKEN = "invalid_token"
    DUPLICATE_DETACH = "duplicate_detach"
    CROSS_CONTEXT = "cross_context"
    RELEASED_BY_CANCEL = "released_by_cancel"
    ABANDONED = "abandoned"
    ERROR = "error"


class _Operation(str, Enum):
    ATTACH = "attach"
    DETACH = "detach"


@dataclass(frozen=True, slots=True)
class ContextGuardRecord:
    """A single, context-free diagnostic record.

    ``owner`` is an opaque execution-unit identifier (for example
    ``task:140234...`` or ``thread:1234``). ``token_id`` is ``id(token)`` and
    is only meant to correlate attach/detach pairs inside the process. Neither
    field, nor anything else in this record, contains context values.
    """

    sequence: int
    operation: str
    outcome: GuardOutcome
    owner: str
    correlation_id: str | None = None
    phase: str | None = None
    token_id: int | None = None
    cancelled: bool = False

    def log_fields(self) -> dict[str, str | None]:
        """Return the fields that may appear in public logs.

        Only the request correlation id and phase are taken from the request;
        operational fields are constant strings. Baggage and context values are
        deliberately absent.
        """

        return {
            "operation": self.operation,
            "outcome": self.outcome.value,
            "correlation_id": self.correlation_id,
            "phase": self.phase,
        }

    def format(self) -> str:
        """Format the full record for local diagnostics.

        This is intended for local debugging and tests. It includes the opaque
        owner and token id, but still no context values or baggage.
        """

        return (
            f"sequence={self.sequence} operation={self.operation} "
            f"outcome={self.outcome.value} owner={self.owner} "
            f"correlation_id={self.correlation_id} phase={self.phase} "
            f"token_id={self.token_id} cancelled={self.cancelled}"
        )


@dataclass(slots=True)
class _PendingAttachment:
    token: Token[Context]
    owner: str
    correlation_id: str | None
    phase: str | None


def _clean_label(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\r", " ").replace("\n", " ")
    return text[:_MAX_LABEL_LENGTH]


def _parse_bool(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() == "true"


def guard_enabled_from_env() -> bool:
    """Whether :envvar:`OTEL_PYTHON_CONTEXT_GUARD` enables the guard."""

    return _parse_bool(os.environ.get(OTEL_PYTHON_CONTEXT_GUARD))


def guard_log_enabled_from_env() -> bool:
    """Whether the guard should emit its own debug/warning log lines."""

    return _parse_bool(os.environ.get(OTEL_PYTHON_CONTEXT_GUARD_LOG))


def _current_task() -> Any:
    try:
        import asyncio

        return asyncio.current_task()
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def _is_cancelling(task: Any) -> bool:
    if task is not None:
        cancelling = getattr(task, "cancelling", None)
        if cancelling is not None:
            try:
                return bool(cancelling())
            except Exception:  # pylint: disable=broad-exception-caught
                pass
    exception = sys.exc_info()[1]
    return type(exception).__name__ == "CancelledError"


def current_owner() -> str:
    """Return the opaque identifier of the current execution unit."""

    task = _current_task()
    if task is not None:
        return f"task:{id(task)}"
    return f"thread:{threading.get_ident()}"


def current_diagnostics() -> tuple[str | None, str | None]:
    """Return the current ``(correlation_id, phase)`` pair."""

    return _CORRELATION_ID.get(), _PHASE.get()


@contextmanager
def diagnostics(
    *,
    correlation_id: object | None = None,
    phase: object | None = None,
) -> Iterator[None]:
    """Attach request diagnostics to context operations in this scope.

    Only the request correlation id and the phase are recorded. Context values
    and baggage are never inspected or logged. ``None`` leaves a field
    unchanged; use :func:`clear_diagnostics` to reset both.
    """

    tokens = []
    if correlation_id is not None:
        tokens.append((_CORRELATION_ID, _CORRELATION_ID.set(_clean_label(correlation_id))))
    if phase is not None:
        tokens.append((_PHASE, _PHASE.set(_clean_label(phase))))
    try:
        yield
    finally:
        for variable, token in reversed(tokens):
            variable.reset(token)


def clear_diagnostics() -> None:
    """Clear the correlation id and phase for the current execution unit."""

    _CORRELATION_ID.set(None)
    _PHASE.set(None)


class ContextRuntimeGuard(_RuntimeContext):
    """Wrap a runtime context and record owned attach/detach operations.

    Args:
        delegate: The runtime context that performs the actual work.
        log_records: Emit safe debug/warning log lines. Only the correlation id
            and phase from the request are included.
        max_records: Maximum number of records retained.
        max_used_tokens: Maximum number of detached token ids retained for
            duplicate detection.
    """

    def __init__(
        self,
        delegate: _RuntimeContext,
        *,
        log_records: bool = False,
        max_records: int = _DEFAULT_MAX_RECORDS,
        max_used_tokens: int = _DEFAULT_MAX_USED_TOKENS,
    ) -> None:
        self._delegate = delegate
        self._log_records = log_records
        self._lock = threading.Lock()
        self._records: deque[ContextGuardRecord] = deque(maxlen=max_records)
        self._pending: dict[int, _PendingAttachment] = {}
        # Retain the token objects themselves so their ids cannot be reused
        # while they are still relevant for duplicate detection.
        self._used_tokens: OrderedDict[int, Token[Context]] = OrderedDict()
        self._max_used_tokens = max_used_tokens
        self._sequence = count(1)
        self._tracked_tasks: weakref.WeakSet[Any] = weakref.WeakSet()

    @property
    def delegate(self) -> _RuntimeContext:
        return self._delegate

    @property
    def log_records(self) -> bool:
        return self._log_records

    @log_records.setter
    def log_records(self, value: bool) -> None:
        self._log_records = bool(value)

    @property
    def records(self) -> tuple[ContextGuardRecord, ...]:
        """The retained records, oldest first."""

        with self._lock:
            return tuple(self._records)

    @property
    def pending_count(self) -> int:
        """Number of attachments that have not been detached or finalized."""

        with self._lock:
            return len(self._pending)

    def get_current(self) -> Context:
        return self._delegate.get_current()

    def attach(self, context: Context) -> Token[Context]:
        owner = current_owner()
        correlation_id, phase = current_diagnostics()
        try:
            token = self._delegate.attach(context)
        except Exception:  # pylint: disable=broad-exception-caught
            self._record(
                _Operation.ATTACH,
                GuardOutcome.ATTACH_FAILED,
                owner,
                correlation_id,
                phase,
                None,
            )
            raise

        token_id = id(token) if token is not None else None
        if token_id is not None:
            with self._lock:
                self._used_tokens.pop(token_id, None)
                self._pending[token_id] = _PendingAttachment(
                    token=token,
                    owner=owner,
                    correlation_id=correlation_id,
                    phase=phase,
                )
            self._register_task_cleanup(_current_task(), owner)

        self._record(
            _Operation.ATTACH,
            GuardOutcome.ATTACHED,
            owner,
            correlation_id,
            phase,
            token_id,
        )
        return token

    def detach(self, token: Token[Context]) -> None:
        owner = current_owner()
        cancelled = _is_cancelling(_current_task())
        correlation_id, phase = current_diagnostics()
        token_id = id(token) if token is not None else None

        with self._lock:
            pending = self._pending.get(token_id) if token_id is not None else None
            was_used = token_id in self._used_tokens if token_id is not None else False

        try:
            self._delegate.detach(token)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            outcome = self._classify_failure(exc, pending, owner, was_used)
            self._record(
                _Operation.DETACH,
                outcome,
                owner,
                correlation_id,
                phase,
                token_id,
                cancelled,
            )
            raise

        if pending is None:
            outcome = GuardOutcome.DETACHED_UNTRACKED
        elif pending.owner != owner:
            outcome = GuardOutcome.DETACHED_FOREIGN_OWNER
        elif cancelled:
            outcome = GuardOutcome.DETACHED_AFTER_CANCEL
        else:
            outcome = GuardOutcome.DETACHED

        with self._lock:
            if pending is not None:
                self._pending.pop(token_id, None)
            if token_id is not None:
                self._used_tokens[token_id] = token
                self._used_tokens.move_to_end(token_id)
                while len(self._used_tokens) > self._max_used_tokens:
                    self._used_tokens.popitem(last=False)

        self._record(
            _Operation.DETACH,
            outcome,
            owner,
            correlation_id,
            phase,
            token_id,
            cancelled,
        )

    def _classify_failure(
        self,
        exc: BaseException,
        pending: _PendingAttachment | None,
        owner: str,
        was_used: bool,
    ) -> GuardOutcome:
        if was_used:
            return GuardOutcome.DUPLICATE_DETACH
        if isinstance(exc, TypeError):
            return GuardOutcome.INVALID_TOKEN
        if isinstance(exc, RuntimeError) and "already been used" in str(exc):
            return GuardOutcome.DUPLICATE_DETACH
        if isinstance(exc, ValueError) and "different Context" in str(exc):
            if pending is not None and pending.owner != owner:
                return GuardOutcome.FOREIGN_OWNER
            return GuardOutcome.CROSS_CONTEXT
        return GuardOutcome.ERROR

    def _register_task_cleanup(self, task: Any, owner: str) -> None:
        if task is None:
            return
        try:
            with self._lock:
                if task in self._tracked_tasks:
                    return
                self._tracked_tasks.add(task)
            guard_ref = weakref.ref(self)
            task.add_done_callback(
                lambda finished: _finalize_owner(guard_ref, owner, finished)
            )
        except Exception:  # pylint: disable=broad-exception-caught
            # Async cleanup is best effort; never break attach for it.
            pass

    def _finalize_owner(self, owner: str, task: Any) -> None:
        cancelled = bool(getattr(task, "cancelled", lambda: False)())
        with self._lock:
            pending = [
                (token_id, attachment)
                for token_id, attachment in self._pending.items()
                if attachment.owner == owner
            ]
            for token_id, attachment in pending:
                self._pending.pop(token_id, None)
        with self._lock:
            for token_id, attachment in pending:
                self._used_tokens[token_id] = attachment.token
                self._used_tokens.move_to_end(token_id)
                while len(self._used_tokens) > self._max_used_tokens:
                    self._used_tokens.popitem(last=False)
        for token_id, attachment in pending:
            self._record(
                _Operation.DETACH,
                GuardOutcome.RELEASED_BY_CANCEL
                if cancelled
                else GuardOutcome.ABANDONED,
                owner,
                attachment.correlation_id,
                attachment.phase,
                token_id,
                cancelled,
            )

    def _record(
        self,
        operation: _Operation,
        outcome: GuardOutcome,
        owner: str,
        correlation_id: str | None,
        phase: str | None,
        token_id: int | None,
        cancelled: bool = False,
    ) -> ContextGuardRecord:
        with self._lock:
            record = ContextGuardRecord(
                sequence=next(self._sequence),
                operation=operation.value,
                outcome=outcome,
                owner=owner,
                correlation_id=correlation_id,
                phase=phase,
                token_id=token_id,
                cancelled=cancelled,
            )
            self._records.append(record)
        if self._log_records:
            self._log(record)
        return record

    def _log(self, record: ContextGuardRecord) -> None:
        level = (
            logging.DEBUG
            if record.outcome
            in (
                GuardOutcome.ATTACHED,
                GuardOutcome.DETACHED,
                GuardOutcome.DETACHED_AFTER_CANCEL,
                GuardOutcome.DETACHED_UNTRACKED,
            )
            else logging.WARNING
        )
        # log_fields() intentionally excludes context values, baggage, owner
        # and token ids from public output.
        logger.log(
            level,
            "context guard operation=%(operation)s outcome=%(outcome)s "
            "correlation_id=%(correlation_id)s phase=%(phase)s",
            record.log_fields(),
        )


def _finalize_owner(
    guard_ref: weakref.ReferenceType[ContextRuntimeGuard],
    owner: str,
    task: Any,
) -> None:
    guard = guard_ref()
    if guard is not None:
        guard._finalize_owner(owner, task)  # pylint: disable=protected-access


def get_guard() -> ContextRuntimeGuard | None:
    """Return the active guard, or ``None`` when the guard is disabled."""

    # Imported lazily to avoid a circular import at package load time.
    from opentelemetry import context as context_module  # noqa: PLC0415

    runtime = context_module._RUNTIME_CONTEXT  # pylint: disable=protected-access
    return runtime if isinstance(runtime, ContextRuntimeGuard) else None


def enable(
    *,
    log_records: bool | None = None,
    runtime: _RuntimeContext | None = None,
) -> ContextRuntimeGuard:
    """Enable the guard around the active runtime context.

    Args:
        log_records: Emit safe log lines. Defaults to
            :envvar:`OTEL_PYTHON_CONTEXT_GUARD_LOG`.
        runtime: The runtime to wrap. Defaults to the active runtime context.
            The guard is installed globally in either case.

    Calling this more than once is a no-op and returns the active guard.
    """

    from opentelemetry import context as context_module  # noqa: PLC0415

    if runtime is None:
        runtime = context_module._RUNTIME_CONTEXT  # pylint: disable=protected-access
    if isinstance(runtime, ContextRuntimeGuard):
        if log_records is not None:
            runtime.log_records = log_records
        return runtime
    if log_records is None:
        log_records = guard_log_enabled_from_env()
    guard = ContextRuntimeGuard(runtime, log_records=log_records)
    context_module._RUNTIME_CONTEXT = guard  # pylint: disable=protected-access
    return guard


def disable() -> ContextRuntimeGuard | None:
    """Disable the guard, restoring the wrapped runtime context.

    Returns the disabled guard (which still holds its records), or ``None`` if
    the guard was not active.
    """

    from opentelemetry import context as context_module  # noqa: PLC0415

    current = context_module._RUNTIME_CONTEXT  # pylint: disable=protected-access
    if not isinstance(current, ContextRuntimeGuard):
        return None
    context_module._RUNTIME_CONTEXT = current.delegate  # pylint: disable=protected-access
    return current


__all__ = [
    "ContextGuardRecord",
    "ContextRuntimeGuard",
    "GuardOutcome",
    "clear_diagnostics",
    "current_diagnostics",
    "current_owner",
    "diagnostics",
    "disable",
    "enable",
    "get_guard",
    "guard_enabled_from_env",
    "guard_log_enabled_from_env",
]
