# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

"""
Tests for the separately routable, auditable security-event channel.

The three fakes stand in for the three production configurations mentioned in
the ticket:

- `InheritingLevelLogger` -- a business logger that inherits the raised default
  level (never calls ``setLevel`` itself),
- `ExplicitLevelLogger` -- a logger whose level was changed on purpose,
- `StdlibLogger` -- a third-party component using the standard ``logging``
  module directly.
"""

from __future__ import annotations

import dataclasses
import json
import logging

import pytest

import structlog

from structlog import wrap_logger
from structlog._generic import BoundLogger
from structlog.audit import (
    FILTER_REASON_DISABLED,
    FILTER_REASON_LEVEL,
    FilterWitness,
    ListAuditSink,
    SecurityAuditRouter,
    is_security_event,
)
from structlog.exceptions import DropEvent
from structlog.testing import CapturingLogger


class _ListHandler(logging.Handler):
    """
    Capture `logging.LogRecord` objects in a plain list.
    """

    def __init__(self):
        super().__init__()
        self.buffer = []

    def emit(self, record):
        self.buffer.append(record)


class _LevelProbeMixin:
    """
    Record level lookups so the tests can prove how a decision was reached.
    """

    def __init__(self, name, effective_level, *, disabled=False):
        self.name = name
        self.disabled = disabled
        self._effective_level = effective_level
        self.level_lookups = 0
        self.calls = []

    def getEffectiveLevel(self):
        self.level_lookups += 1
        return self._effective_level

    def isEnabledFor(self, level):
        self.level_lookups += 1
        return not self.disabled and level >= self._effective_level

    def _record(self, method_name, event, kw):
        self.calls.append((method_name, event, kw))

    def debug(self, event=None, *a, **kw):
        self._record("debug", event, kw)

    def info(self, event=None, *a, **kw):
        self._record("info", event, kw)

    def warning(self, event=None, *a, **kw):
        self._record("warning", event, kw)

    warn = warning

    def error(self, event=None, *a, **kw):
        self._record("error", event, kw)

    def critical(self, event=None, *a, **kw):
        self._record("critical", event, kw)


class InheritingLevelLogger(_LevelProbeMixin):
    """
    A business logger that never sets its own level.

    Its effective level is whatever the raised root default gives it, so it
    models "inherit the default".
    """


class ExplicitLevelLogger(_LevelProbeMixin):
    """
    A logger whose operator changed the level deliberately.

    The only difference from the inheriting fake is intent; mechanically it
    carries an explicit threshold that diverges from the root default.
    """

    def setLevel(self, level):
        self._effective_level = level


class StdlibLogger:
    """
    A third-party component logging through the standard library.

    It wraps a real `logging.Logger` (with a capture handler attached) and
    exposes the same duck-typed surface the router relies on.
    """

    def __init__(self, name, level):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(level)
        self.handler = _ListHandler()
        self._logger.addHandler(self.handler)

    @property
    def name(self):
        return self._logger.name

    @property
    def disabled(self):
        return self._logger.disabled

    def getEffectiveLevel(self):
        return self._logger.getEffectiveLevel()

    def isEnabledFor(self, level):
        return self._logger.isEnabledFor(level)

    def __getattr__(self, item):
        return getattr(self._logger, item)


def make_router(clock=None):
    sink = ListAuditSink()
    if clock is None:
        return sink, SecurityAuditRouter(sink)

    return sink, SecurityAuditRouter(sink, clock=clock)


def build_logger(underlying, *processors):
    return wrap_logger(
        underlying,
        processors=list(processors),
        wrapper_class=BoundLogger,
    )


# A fixed clock makes the timestamp field deterministic.
FIXED_TS = 1_763_000_000.0


class TestIsSecurityEvent:
    def test_marker_required(self):
        assert is_security_event({"security_audit": True})
        assert is_security_event({"security_audit": 1})
        assert not is_security_event({"security_audit": False})
        assert not is_security_event({})


class TestInheritingLogger:
    def test_low_level_security_event_witnessed_not_emitted(self):
        """
        An event below the raised default never reaches the logger, but the
        sink keeps a witness explaining the filter.
        """
        underlying = InheritingLevelLogger("billing.app", logging.WARNING)
        sink, router = make_router(clock=lambda: FIXED_TS)
        log = build_logger(underlying, router).bind(security_audit=True)

        assert log.info("token_refreshed", audit_event_id="EVT-1") is None

        assert underlying.calls == []
        assert sink.archived == []
        assert len(sink.witnesses) == 1

        witness = sink.witnesses[0]
        assert isinstance(witness, FilterWitness)
        assert witness.event == "token_refreshed"
        assert witness.audit_event_id == "EVT-1"
        assert witness.level == "info"
        assert witness.level_number == logging.INFO
        assert witness.reason == FILTER_REASON_LEVEL
        assert witness.effective_level == logging.WARNING
        assert witness.effective_level_name == "warning"
        assert witness.logger_name == "billing.app"
        assert witness.filtered_at == FIXED_TS

        stats = router.stats()
        assert stats["archived"] == 0
        assert stats["filtered"] == 1
        assert stats["sink_ns"] > 0

    def test_high_level_security_event_archived_and_emitted(self):
        """
        An event at/above the default reaches the logger and the archive,
        keeping its original level.
        """
        underlying = InheritingLevelLogger("billing.app", logging.WARNING)
        sink, router = make_router()
        log = build_logger(underlying, router).bind(security_audit=True)

        log.error("privilege_escalated", audit_event_id="EVT-2")

        assert len(underlying.calls) == 1
        method, event, kw = underlying.calls[0]
        assert method == "error"
        assert event == "privilege_escalated"
        assert kw["security_audit"] is True
        assert kw["audit_event_id"] == "EVT-2"

        assert len(sink.archived) == 1
        archived = sink.archived[0]
        assert archived["event"] == "privilege_escalated"
        assert archived["audit_event_id"] == "EVT-2"
        assert sink.witnesses == []
        assert router.stats()["archived"] == 1
        assert router.stats()["filtered"] == 0

    def test_business_event_skips_router_completely(self):
        """
        Non-security events are returned untouched: default caller level
        rules are unchanged and the sink stays empty.
        """
        underlying = InheritingLevelLogger("billing.app", logging.WARNING)
        sink, router = make_router()
        log = build_logger(underlying, router)

        log.debug("ordinary_debug")
        log.info("ordinary_info")

        # Router never archived or witnessed anything.
        assert sink.archived == []
        assert sink.witnesses == []
        assert router.stats() == {
            "archived": 0,
            "filtered": 0,
            "sink_ns": 0,
        }
        # The logger still received both calls; downstream filter_by_level
        # (not present here) would apply business rules as usual.
        assert [call[0] for call in underlying.calls] == ["debug", "info"]


class TestExplicitLevelLogger:
    def test_lowered_threshold_accepts_archived_events(self):
        """
        An operator who lowers a logger's level gets those events through;
        accepted security events are archived.
        """
        underlying = ExplicitLevelLogger("auth.debugger", logging.ERROR)
        sink, router = make_router()
        log = build_logger(underlying, router).bind(security_audit=True)

        log.info("login_attempt", audit_event_id="EVT-3")
        assert sink.witnesses[0].reason == FILTER_REASON_LEVEL
        assert underlying.calls == []

        underlying.setLevel(logging.DEBUG)
        log.info("login_attempt", audit_event_id="EVT-4")

        assert len(underlying.calls) == 1
        assert sink.archived[0]["audit_event_id"] == "EVT-4"
        stats = router.stats()
        assert stats["filtered"] == 1
        assert stats["archived"] == 1

    def test_disabled_logger_emits_disabled_reason(self):
        underlying = ExplicitLevelLogger("frozen.service", logging.DEBUG, disabled=True)
        sink, router = make_router(clock=lambda: FIXED_TS)
        log = build_logger(underlying, router).bind(security_audit=True)

        log.critical("admin_action", audit_event_id="EVT-5")

        assert underlying.calls == []
        witness = sink.witnesses[0]
        assert witness.reason == FILTER_REASON_DISABLED
        assert witness.level == "critical"
        assert witness.level_number == logging.CRITICAL
        assert witness.effective_level == logging.DEBUG


class TestStdlibLogger:
    def test_routes_through_real_logging_handler(self):
        """
        Third-party standard-library logging: filtered events produce a
        witness and no record; accepted events hit the handler and archive.
        """
        underlying = StdlibLogger("thirdparty.vendor", logging.WARNING)
        sink, router = make_router(clock=lambda: FIXED_TS)
        log = wrap_logger(
            underlying,
            processors=[router, structlog.processors.JSONRenderer()],
            wrapper_class=BoundLogger,
        ).bind(security_audit=True)

        log.info("api_key_rotated", audit_event_id="EVT-6")
        log.warning("rate_limit_breached", audit_event_id="EVT-7")

        records = list(underlying.handler.buffer)
        assert [record.levelno for record in records] == [logging.WARNING]
        assert json.loads(records[0].msg)["event"] == "rate_limit_breached"

        assert len(sink.witnesses) == 1
        witness = sink.witnesses[0]
        assert witness.event == "api_key_rotated"
        assert witness.reason == FILTER_REASON_LEVEL
        assert witness.effective_level == logging.WARNING
        assert witness.logger_name == "thirdparty.vendor"

        assert sink.archived[0]["event"] == "rate_limit_breached"

    def test_works_alongside_filter_by_level(self):
        """
        With the real stdlib processor chain, the router runs first and
        witnesses drops before ``filter_by_level`` would raise DropEvent.
        """
        underlying = StdlibLogger("vendor.chain", logging.ERROR)
        sink, _ = make_router()
        log = wrap_logger(
            underlying,
            processors=[
                SecurityAuditRouter(sink),
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_log_level,
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
        ).bind(security_audit=True)

        log.info("blocked_login", audit_event_id="EVT-8")
        log.error("account_locked", audit_event_id="EVT-9")

        witness = sink.witnesses[0]
        assert witness.event == "blocked_login"
        assert witness.level == "info"
        assert witness.effective_level == logging.ERROR

        records = underlying.handler.buffer
        assert len(records) == 1
        payload = json.loads(records[0].msg)
        assert payload["event"] == "account_locked"
        assert payload["level"] == "error"
        assert payload["audit_event_id"] == "EVT-9"
        # The archived copy keeps the original level marker too.
        assert sink.archived[0]["audit_event_id"] == "EVT-9"


class TestWitnessContract:
    def test_witness_is_json_serializable_and_frozen(self):
        sink, router = make_router(clock=lambda: FIXED_TS)
        underlying = InheritingLevelLogger("svc", logging.WARNING)
        log = build_logger(underlying, router).bind(security_audit=True)

        log.info("frozen_event", audit_event_id="EVT-10")

        witness = sink.witnesses[0]
        encoded = json.dumps(witness.to_dict())
        decoded = json.loads(encoded)
        assert decoded["reason"] == FILTER_REASON_LEVEL
        assert decoded["filtered_at"] == FIXED_TS

        with pytest.raises(dataclasses.FrozenInstanceError):
            witness.reason = "tampered"

    def test_archive_copy_is_defensive(self):
        """
        Later mutation of the event dict cannot rewrite the archived copy.
        """
        sink, _ = make_router()
        underlying = CapturingLogger()
        router = SecurityAuditRouter(
            sink, level_predicate=lambda logger, method_name: True
        )
        log = wrap_logger(
            underlying,
            processors=[router, _mutate_then_return],
        ).bind(security_audit=True)

        log.warning("immutable", audit_event_id="EVT-11")

        assert sink.archived[0]["event"] == "immutable"


def _mutate_then_return(logger, method_name, event_dict):
    event_dict["event"] = "mutated"
    return event_dict


class TestOverhead:
    def test_non_security_event_avoids_sink_and_clock(self):
        """
        The hot path for ordinary logs is one dict lookup plus an early
        return: no clock call, no sink call, no witness allocation.
        """

        class ExplodingSink(ListAuditSink):
            def emit_archived(self, event_dict):
                raise AssertionError("sink must not run")

            def emit_witness(self, witness):
                raise AssertionError("sink must not run")

        router = SecurityAuditRouter(ExplodingSink(), clock=_exploding_clock)
        underlying = InheritingLevelLogger("svc", logging.WARNING)
        log = build_logger(underlying, router)

        for _ in range(100):
            log.info("business_only")

        assert underlying.level_lookups == 0

    def test_filtered_event_minimal_lookups(self):
        """
        A filtered security event only pays level lookups and one sink
        write: nothing is rendered or sent to the logger.
        """
        underlying = InheritingLevelLogger("svc", logging.WARNING)
        sink, router = make_router()
        log = build_logger(underlying, router).bind(security_audit=True)

        log.info("cheap_drop", audit_event_id="EVT-12")

        # A single effective-level read drives both the decision and the
        # threshold recorded on the witness.
        assert underlying.level_lookups == 1
        assert underlying.calls == []
        assert len(sink.witnesses) == 1
        assert router.stats()["sink_ns"] > 0

    def test_router_raises_drop_event(self):
        sink, _ = make_router()
        router = SecurityAuditRouter(sink)
        underlying = InheritingLevelLogger("svc", logging.WARNING)

        with pytest.raises(DropEvent):
            router(
                underlying,
                "debug",
                {"event": "x", "security_audit": True},
            )

    def test_logger_without_level_api_is_rejected(self):
        class BareLogger:
            name = "bare"

        sink, _ = make_router()
        router = SecurityAuditRouter(sink)

        with pytest.raises(TypeError):
            router(
                BareLogger(),
                "info",
                {"event": "x", "security_audit": True},
            )


def _exploding_clock():
    raise AssertionError("clock must not run for business events")
