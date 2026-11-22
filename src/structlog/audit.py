# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

"""
A separately routable, auditable channel for security events.

When the default business-log level is raised to save log volume, security
audit events must still be:

- **archived** at their original security level, and
- **accountable**: whenever an event does *not* reach the normal log output,
  the on-call engineer can look up *why* it was filtered.

The `SecurityAuditRouter` in this module is deliberately independent of the
configured wrapper class and only relies on the small duck-typed surface that
every logger shares:

- a level predicate (``getEffectiveLevel`` / ``isEnabledFor``), and
- the log methods themselves (``debug`` ... ``critical``).

Therefore it works unchanged with a logger that *inherits* its level, one
that *sets its own* level, and a plain standard-library `logging.Logger`.

Witnesses (`FilterWitness`) are plain, JSON-serializable data so they can be
shipped to a reconciliation sink without importing any application code.

A typical processor chain looks like this::

    [
        SecurityAuditRouter(sink),          # route + witness level drops
        structlog.stdlib.filter_by_level,    # ordinary business filtering
        structlog.stdlib.add_log_level,
        ...
        renderer,
    ]
"""

from __future__ import annotations

import time

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from typing import Any, Protocol, runtime_checkable

from ._log_levels import LEVEL_TO_NAME, NAME_TO_LEVEL
from .exceptions import DropEvent
from .typing import EventDict, WrappedLogger


__all__ = [
    "FILTER_REASON_DISABLED",
    "FILTER_REASON_LEVEL",
    "AuditSink",
    "FilterWitness",
    "ListAuditSink",
    "SecurityAuditRouter",
    "is_security_event",
]


FILTER_REASON_LEVEL = "below_effective_level"
"""
The event's level was below the logger's effective level.
"""

FILTER_REASON_DISABLED = "logger_disabled"
"""
The logger was explicitly disabled.
"""


def is_security_event(event_dict: EventDict) -> bool:
    """
    Return whether *event_dict* carries the security-audit marker.

    The marker is the truthy ``security_audit`` key, typically bound once via
    ``logger.bind(security_audit=True)``.
    """
    return bool(event_dict.get("security_audit"))


@dataclass(frozen=True)
class FilterWitness:
    """
    An immutable, JSON-serializable statement that a security event was
    filtered and why.

    Every field exists to answer a single reconciliation question:

    - ``event`` / ``audit_event_id``: *which* event was filtered,
    - ``level`` / ``level_number``: the security level it was filed at,
    - ``reason``: the machine-readable filter cause,
    - ``effective_level`` / ``effective_level_name``: the threshold that
      decided the outcome,
    - ``logger_name``: the logger that applied the threshold,
    - ``filtered_at``: a Unix timestamp for ordering and retention.

    The original event dict is never mutated or consumed by the witness; the
    archive keeps the event's original security level.
    """

    event: str
    audit_event_id: str
    level: str
    level_number: int
    reason: str
    effective_level: int
    effective_level_name: str
    logger_name: str
    filtered_at: float

    def to_dict(self) -> dict[str, Any]:
        """
        Return a plain ``dict`` suitable for JSON rendering.
        """
        return asdict(self)


@runtime_checkable
class AuditSink(Protocol):
    """
    **Protocol**: a destination for archived events and filter witnesses.

    The two methods are the two independently reconcilable exits of the
    security channel.  They intentionally do not raise: a sink must never
    change whether a business log call succeeds.
    """

    def emit_archived(self, event_dict: EventDict) -> None:
        """
        Accept a security event that reached the normal logging output.
        """

    def emit_witness(self, witness: FilterWitness) -> None:
        """
        Accept a witness for a security event that was filtered.
        """


class ListAuditSink:
    """
    An `AuditSink` that keeps everything in memory.

    It is primarily useful in tests and as a reference implementation of the
    two-exit contract.  ``archived`` and ``witnesses`` are append-only lists;
    archived event dicts are copied on entry so later processor mutations
    cannot rewrite history.
    """

    archived: list[EventDict]
    witnesses: list[FilterWitness]

    def __init__(self) -> None:
        self.archived = []
        self.witnesses = []

    def emit_archived(self, event_dict: EventDict) -> None:
        self.archived.append(dict(event_dict))

    def emit_witness(self, witness: FilterWitness) -> None:
        self.witnesses.append(witness)


def _level_number(method_name: str) -> int:
    return NAME_TO_LEVEL[method_name]


def _level_name(level_number: int) -> str:
    return LEVEL_TO_NAME.get(level_number, "notset")


class _AuditBase:
    """
    Shared sink bookkeeping, witness construction and overhead timing.
    """

    def __init__(
        self,
        sink: AuditSink,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._sink = sink
        self._clock = clock
        self.archived_count = 0
        self.filtered_count = 0
        self.sink_ns = 0

    def _effective_level(self, logger: WrappedLogger) -> int:
        get_effective = getattr(logger, "getEffectiveLevel", None)
        if get_effective is not None:
            return int(get_effective())

        is_enabled_for = getattr(logger, "isEnabledFor", None)
        if is_enabled_for is None:
            msg = (
                "logger must expose getEffectiveLevel() or "
                "isEnabledFor(level) to route security events"
            )
            raise TypeError(msg)

        # Reconstruct the threshold by binary probing the predicate.
        for candidate in sorted(NAME_TO_LEVEL.values(), reverse=True):
            if is_enabled_for(candidate):
                return candidate

        return 0

    def build_witness(
        self,
        logger: WrappedLogger,
        method_name: str,
        event_dict: EventDict,
        reason: str,
        effective_level: int | None = None,
    ) -> FilterWitness:
        level_number = _level_number(method_name)
        if effective_level is None:
            effective_level = self._effective_level(logger)

        return FilterWitness(
            event=str(event_dict.get("event", "")),
            audit_event_id=str(event_dict.get("audit_event_id", "")),
            level=_level_name(level_number),
            level_number=level_number,
            reason=reason,
            effective_level=effective_level,
            effective_level_name=_level_name(effective_level),
            logger_name=getattr(logger, "name", logger.__class__.__name__),
            filtered_at=self._clock(),
        )

    def _record_witness(
        self,
        logger: WrappedLogger,
        method_name: str,
        event_dict: EventDict,
        reason: str,
        effective_level: int | None = None,
    ) -> FilterWitness:
        witness = self.build_witness(
            logger,
            method_name,
            event_dict,
            reason,
            effective_level,
        )
        start = time.perf_counter_ns()
        self._sink.emit_witness(witness)
        self.sink_ns += time.perf_counter_ns() - start
        self.filtered_count += 1
        return witness

    def stats(self) -> Mapping[str, int | float]:
        """
        Return counters and the accumulated nanoseconds spent in the sink.

        ``sink_ns`` measures only the sink calls (archive + witness), never
        the level lookup or other processor work, so the per-event overhead of
        accountability can be reported precisely.
        """
        return {
            "archived": self.archived_count,
            "filtered": self.filtered_count,
            "sink_ns": self.sink_ns,
        }


class SecurityAuditRouter(_AuditBase):
    """
    Route security audit events around ordinary level filtering.

    The router is a *processor*: put it first in the processor chain, before
    any expensive work and before `structlog.stdlib.filter_by_level`.  It only
    touches events where `is_security_event` is true; every other event is
    returned unchanged so the default caller level rules keep working.

    Security events take one of two exits:

    - if the wrapped logger would accept the level, processing continues and a
      copy is sent to ``sink.emit_archived`` (the event keeps its original
      level for archival),
    - if the logger would filter it, a `FilterWitness` explaining the decision
      is sent to ``sink.emit_witness`` and `structlog.DropEvent` is raised so
      the event does not leak into ordinary output.

    Args:
        sink: Destination for archived events and filter witnesses.
        clock: Callable returning the Unix timestamp recorded on witnesses.
        level_predicate: Optional override deciding whether *method_name* is
            enabled on the wrapped logger.  By default the router speaks both
            the stdlib surface (``getEffectiveLevel`` / ``disabled``) and any
            object exposing ``isEnabledFor``.
    """

    def __init__(
        self,
        sink: AuditSink,
        clock: Callable[[], float] = time.time,
        level_predicate: Callable[[WrappedLogger, str], bool] | None = None,
    ) -> None:
        super().__init__(sink, clock)
        self._uses_default_predicate = level_predicate is None
        self._level_predicate = level_predicate or self._default_is_enabled

    @staticmethod
    def _default_is_enabled(logger: WrappedLogger, method_name: str) -> bool:
        level_number = _level_number(method_name)
        get_effective = getattr(logger, "getEffectiveLevel", None)
        if get_effective is not None:
            disabled = getattr(logger, "disabled", False)
            return not disabled and level_number >= get_effective()

        is_enabled_for = getattr(logger, "isEnabledFor", None)
        if is_enabled_for is not None:
            return bool(is_enabled_for(level_number))

        msg = (
            "logger must expose getEffectiveLevel() or isEnabledFor(level) "
            "to route security events"
        )
        raise TypeError(msg)

    def _evaluate(
        self, logger: WrappedLogger, method_name: str
    ) -> tuple[bool, int | None]:
        """
        Return ``(enabled, effective_level)`` using a single threshold read.
        """
        level_number = _level_number(method_name)
        get_effective = getattr(logger, "getEffectiveLevel", None)
        if get_effective is not None:
            effective_level = int(get_effective())
            disabled = getattr(logger, "disabled", False)
            return (
                not disabled and level_number >= effective_level,
                effective_level,
            )

        is_enabled_for = getattr(logger, "isEnabledFor", None)
        if is_enabled_for is None:
            msg = (
                "logger must expose getEffectiveLevel() or "
                "isEnabledFor(level) to route security events"
            )
            raise TypeError(msg)

        return bool(is_enabled_for(level_number)), None

    def __call__(
        self,
        logger: WrappedLogger,
        method_name: str,
        event_dict: EventDict,
    ) -> EventDict:
        if not is_security_event(event_dict):
            return event_dict

        if self._uses_default_predicate:
            enabled, effective_level = self._evaluate(logger, method_name)
        else:
            enabled = self._level_predicate(logger, method_name)
            effective_level = None

        if not enabled:
            reason = (
                FILTER_REASON_DISABLED
                if getattr(logger, "disabled", False)
                else FILTER_REASON_LEVEL
            )
            self._record_witness(
                logger,
                method_name,
                event_dict,
                reason,
                effective_level,
            )
            raise DropEvent

        start = time.perf_counter_ns()
        self._sink.emit_archived(event_dict)
        self.sink_ns += time.perf_counter_ns() - start
        self.archived_count += 1

        return event_dict
