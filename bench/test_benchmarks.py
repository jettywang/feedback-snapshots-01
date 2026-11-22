# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

"""
Benchmark structlog using CodSpeed.
"""

from __future__ import annotations

import logging

import pytest

import structlog


pytestmark = pytest.mark.benchmark()

ROUNDS = 1_000

# A typical set of key/value pairs that gets bound to a logger in a web
# application.
KWARGS = {
    "user_id": 42,
    "request_id": "b1f2b3c4-d5e6-4f7a-8b9c-0d1e2f3a4b5c",
    "path": "/api/v1/orders",
    "method": "POST",
    "status": 201,
    "duration_ms": 12.34,
}

INFO_LOGGER_CLASS = structlog.make_filtering_bound_logger(logging.INFO)


def make_logger(*processors):
    """
    Create a bound logger that filters at info level, runs *processors*, and
    logs into the void.
    """
    return structlog.wrap_logger(
        structlog.testing.ReturnLogger(),
        processors=list(processors),
        wrapper_class=INFO_LOGGER_CLASS,
    ).bind()


def test_create_bound_logger():
    """
    Benchmark wrapping a logger and binding initial values to it.
    """
    for _ in range(ROUNDS):
        structlog.wrap_logger(
            structlog.testing.ReturnLogger(),
            processors=[structlog.processors.JSONRenderer()],
            wrapper_class=INFO_LOGGER_CLASS,
        ).bind(**KWARGS)


def test_bind():
    """
    Benchmark binding key/value pairs to an existing bound logger.
    """
    log = make_logger(structlog.processors.JSONRenderer())

    for _ in range(ROUNDS):
        log.bind(**KWARGS)


def test_log_event_json():
    """
    Benchmark logging an event through a typical production processor chain
    that renders to JSON.
    """
    log = make_logger(
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.JSONRenderer(),
    ).bind(**KWARGS)

    for _ in range(ROUNDS):
        log.info("request handled")


def test_log_event_console():
    """
    Benchmark logging an event using the development ConsoleRenderer.
    """
    log = make_logger(
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M.%S", utc=True),
        structlog.dev.ConsoleRenderer(colors=True),
    ).bind(**KWARGS)

    for _ in range(ROUNDS):
        log.info("request handled")


def test_log_event_key_value():
    """
    Benchmark logging an event using the classic KeyValueRenderer.
    """
    log = make_logger(
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.KeyValueRenderer(
            key_order=["timestamp", "level", "event"]
        ),
    ).bind(**KWARGS)

    for _ in range(ROUNDS):
        log.info("request handled")


def test_log_event_filtered_out():
    """
    Benchmark a log call that gets dropped by the level filter.
    """
    log = make_logger(structlog.processors.JSONRenderer()).bind(**KWARGS)

    for _ in range(ROUNDS):
        log.debug("nobody will ever see this")


def test_log_event_with_contextvars():
    """
    Benchmark logging an event that merges context-local values.
    """
    log = make_logger(
        structlog.contextvars.merge_contextvars,
        structlog.processors.JSONRenderer(),
    )

    structlog.contextvars.bind_contextvars(**KWARGS)

    for _ in range(ROUNDS):
        log.info("request handled")

    structlog.contextvars.clear_contextvars()


def test_bind_and_clear_contextvars():
    """
    Benchmark binding and clearing context-local values, like a middleware
    does once per request.
    """
    for _ in range(ROUNDS):
        structlog.contextvars.bind_contextvars(**KWARGS)
        structlog.contextvars.clear_contextvars()


def _bottom():
    raise ValueError("d'oh")


def _middle():
    _bottom()


def _top():
    _middle()


def test_log_exception_as_dict():
    """
    Benchmark extracting and rendering an exception into structured data
    using dict_tracebacks.
    """
    log = make_logger(
        structlog.processors.add_log_level,
        structlog.processors.dict_tracebacks,
        structlog.processors.JSONRenderer(),
    ).bind(**KWARGS)

    try:
        _top()
    except ValueError:
        for _ in range(ROUNDS):
            log.exception("cannot compute")


def test_log_exception_formatted():
    """
    Benchmark formatting an exception into a traceback string using
    format_exc_info.
    """
    log = make_logger(
        structlog.processors.add_log_level,
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ).bind(**KWARGS)

    try:
        _top()
    except ValueError:
        for _ in range(ROUNDS):
            log.exception("cannot compute")


class _BenchLevelLogger:
    """
    Minimal logger exposing the duck-typed level surface.
    """

    name = "bench.security"
    disabled = False

    def __init__(self, effective_level):
        self._effective_level = effective_level

    def getEffectiveLevel(self):
        return self._effective_level

    def isEnabledFor(self, level):
        return level >= self._effective_level

    def __getattr__(self, name):
        def _log(*args, **kwargs):
            return None

        return _log


def test_security_audit_router_filtered():
    """
    Benchmark the accountable path for a security event that is filtered:
    one level check, one witness write, no rendering.
    """
    sink = structlog.audit.ListAuditSink()
    router = structlog.audit.SecurityAuditRouter(sink)
    log = structlog.wrap_logger(
        _BenchLevelLogger(logging.WARNING),
        processors=[router, structlog.processors.JSONRenderer()],
    ).bind(security_audit=True)

    for _ in range(ROUNDS):
        log.info("filtered_security_event")


def test_security_audit_router_archived():
    """
    Benchmark the accepted path: archive copy plus normal rendering.
    """
    sink = structlog.audit.ListAuditSink()
    router = structlog.audit.SecurityAuditRouter(sink)
    log = structlog.wrap_logger(
        _BenchLevelLogger(logging.DEBUG),
        processors=[router, structlog.processors.JSONRenderer()],
    ).bind(security_audit=True)

    for _ in range(ROUNDS):
        log.info("archived_security_event", **KWARGS)


def test_security_audit_router_business_passthrough():
    """
    Benchmark ordinary business events, which must pay only the marker
    lookup and skip the sink entirely.
    """
    sink = structlog.audit.ListAuditSink()
    router = structlog.audit.SecurityAuditRouter(sink)
    log = structlog.wrap_logger(
        _BenchLevelLogger(logging.WARNING),
        processors=[router, structlog.processors.JSONRenderer()],
    )

    for _ in range(ROUNDS):
        log.info("ordinary_business_event", **KWARGS)

    assert sink.archived == []
    assert sink.witnesses == []
