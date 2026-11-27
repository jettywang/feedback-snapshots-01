from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

REDACTED = '[redacted]'
"""Placeholder written where a restricted value was removed."""

_WILDCARD = '*'


class PublicJobError(Exception):
    """Exception passed to public (external) failure callbacks when a visibility policy is set.

    It intentionally carries only the exception class name and the correlation identifiers of
    the execution that failed. The original message and traceback stay in the internal worker
    log and in the stored internal result, where an `InternalObserver` can read them.
    """

    def __init__(self, error_type: str, *, job_id: str, execution_id: str | None = None):
        self.error_type = error_type
        self.job_id = job_id
        self.execution_id = execution_id
        super().__init__(self.public_message())

    def public_message(self) -> str:
        location = f'job {self.job_id}'
        if self.execution_id:
            location += f', execution {self.execution_id}'
        return f'{self.error_type}: details withheld ({location}; internal observers only)'


@dataclass(frozen=True)
class CallbackOutcome:
    """Record of whether one callback ran and whether it raised.

    The outcome carries no arguments or values from the job, so it can be attached to a
    result record that public consumers can correlate.
    """

    callback_type: str
    status: str
    error_type: str | None = None

    def __post_init__(self) -> None:
        if self.callback_type not in ('success', 'failure', 'stopped'):
            raise ValueError(f'unknown callback type {self.callback_type!r}')
        if self.status not in ('succeeded', 'failed'):
            raise ValueError(f'unknown callback status {self.status!r}')

    def to_dict(self) -> dict[str, str | None]:
        return {'status': self.status, 'error_type': self.error_type}


@dataclass(frozen=True)
class InternalObserver:
    """Capability required to read unredacted results and exception details.

    Constructing one is the approval step: only trusted, server-side diagnostics code should
    hold an observer. Public consumers (callbacks, webhooks, status pages) receive views
    produced by `VisibilityPolicy` instead.
    """

    name: str = 'internal'
    approved_by: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError('InternalObserver requires a non-empty name')

    def read_results(self, job: Any) -> list[Any]:
        """Return every stored `Result` with internal values intact."""
        return job.results()

    def read_latest_result(self, job: Any) -> Any | None:
        """Return the newest stored `Result` with internal values intact."""
        return job.latest_result()

    def read_result(self, result: Any) -> dict[str, Any]:
        """Return the internal view of one `Result`: full return value and traceback."""
        return {
            'result_id': result.id,
            'job_id': result.job_id,
            'execution_id': result.execution_id,
            'type': result.type.name,
            'created_at': result.created_at,
            'worker_name': result.worker_name,
            'return_value': result.return_value,
            'exc_string': result.exc_string,
            'callback_outcomes': {name: outcome.to_dict() for name, outcome in result.callback_outcomes.items()},
            'callback_exc_string': result.callback_exc_string,
        }


def _path_parts(path: str) -> tuple[str, ...]:
    if not isinstance(path, str):
        raise TypeError(f'restricted path must be a string, got {type(path).__name__}')
    return tuple(part for part in path.split('.') if part)


def _path_matches(path: tuple[str, ...], pattern: tuple[str, ...]) -> bool:
    if len(path) != len(pattern):
        return False
    return all(expected == _WILDCARD or expected == actual for actual, expected in zip(path, pattern))


@dataclass(frozen=True)
class VisibilityPolicy:
    """Declares which parts of a job result may be published to external consumers.

    Restricted paths are dotted and rooted at the result value. A `*` segment matches one
    mapping key or sequence index, e.g. `customers.*.token`. Matching subtrees are replaced
    with `placeholder`; nothing else about the result is changed.

    The original return value is still stored internally so an `InternalObserver` can read it.
    Public callbacks, webhooks and the `public_*` accessors only ever see the redacted view.
    """

    restricted_paths: tuple[str, ...] = ()
    placeholder: str = REDACTED
    hide_exception_details: bool = True

    def __init__(
        self,
        restricted_paths: Sequence[str] = (),
        placeholder: str = REDACTED,
        hide_exception_details: bool = True,
    ):
        if isinstance(restricted_paths, str):
            restricted_paths = (restricted_paths,)
        parts = tuple(_path_parts(path) for path in restricted_paths)
        object.__setattr__(self, 'restricted_paths', tuple('.'.join(part) for part in parts))
        if not isinstance(placeholder, str):
            raise TypeError('placeholder must be a string')
        object.__setattr__(self, 'placeholder', placeholder)
        object.__setattr__(self, 'hide_exception_details', bool(hide_exception_details))

    def __repr__(self) -> str:
        return (
            f'VisibilityPolicy(restricted_paths={self.restricted_paths!r}, '
            f'placeholder={self.placeholder!r}, hide_exception_details={self.hide_exception_details!r})'
        )

    @property
    def _patterns(self) -> tuple[tuple[str, ...], ...]:
        return tuple(_path_parts(path) for path in self.restricted_paths)

    def to_dict(self) -> dict[str, Any]:
        return {
            'restricted_paths': list(self.restricted_paths),
            'placeholder': self.placeholder,
            'hide_exception_details': self.hide_exception_details,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VisibilityPolicy:
        if not isinstance(data, Mapping):
            raise TypeError('visibility policy must be a mapping')
        return cls(
            restricted_paths=data.get('restricted_paths', ()),
            placeholder=data.get('placeholder', REDACTED),
            hide_exception_details=data.get('hide_exception_details', True),
        )

    def redact(self, value: Any) -> Any:
        """Return a deep copy of `value` with every restricted path replaced."""
        patterns = self._patterns
        if not patterns:
            return copy.deepcopy(value)
        return self._redact(value, (), patterns)

    def _redact(self, value: Any, path: tuple[str, ...], patterns: tuple[tuple[str, ...], ...]) -> Any:
        if any(_path_matches(path, pattern) for pattern in patterns):
            return self.placeholder
        if isinstance(value, Mapping):
            return {key: self._redact(item, path + (str(key),), patterns) for key, item in value.items()}
        if isinstance(value, list):
            return [self._redact(item, path + (str(index),), patterns) for index, item in enumerate(value)]
        if isinstance(value, tuple):
            return tuple(self._redact(item, path + (str(index),), patterns) for index, item in enumerate(value))
        return copy.deepcopy(value)

    def public_exc_string(
        self, exc_string: str | None, *, job_id: str = '', execution_id: str | None = None
    ) -> str | None:
        """Summarize an internal traceback for public consumers, without its message or frames."""
        if exc_string is None:
            return None
        if not self.hide_exception_details:
            return exc_string
        error_type = exception_type_name(exc_string)
        return PublicJobError(error_type, job_id=job_id, execution_id=execution_id).public_message()

    def public_exc_info(
        self,
        exc_info: tuple[type | None, BaseException | None, Any],
        *,
        job_id: str = '',
        execution_id: str | None = None,
    ) -> tuple[type, BaseException, None]:
        """Return `(type, value, traceback)` safe to hand to a public failure callback."""
        exc_type = exc_info[0]
        error_type = exc_type.__name__ if isinstance(exc_type, type) else 'Exception'
        if not self.hide_exception_details:
            # Keep the original exception type but still withhold the traceback frames.
            if exc_info[1] is not None:
                return exc_type or PublicJobError, exc_info[1], None
        return PublicJobError, PublicJobError(error_type, job_id=job_id, execution_id=execution_id), None


def exception_type_name(exc_string: str) -> str:
    for line in reversed(exc_string.strip().splitlines()):
        line = line.strip()
        if not line:
            continue
        return line.split(':', 1)[0].strip() or 'Exception'
    return 'Exception'


__all__ = [
    'CallbackOutcome',
    'exception_type_name',
    'InternalObserver',
    'PublicJobError',
    'REDACTED',
    'VisibilityPolicy',
]
