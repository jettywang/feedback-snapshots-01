# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

"""
Tests for the size-budgeted exception renderer.

The fixtures live in :mod:`tests.processors._exception_fixtures` and build
wide stacks and long exception chains purely in memory, so both the size
accounting and the chosen detail levels are deterministic.
"""

from __future__ import annotations

import json

import pytest

import structlog

from structlog.processors import (
    BUDGET_TRUNCATION_KEY,
    BudgetedExceptionRenderer,
    JSONRenderer,
    MIN_STRUCTURED_BUDGET,
)
from structlog.testing import CapturingLogger
from structlog.tracebacks import ExceptionDictTransformer

from ._exception_fixtures import (
    WideStackError,
    chained_exception,
    chained_wide_exception,
    rendered_size,
    wide_exception,
)


class TestValidation:
    def test_rejects_non_positive_budget(self) -> None:
        """
        A budget below one byte cannot hold anything and is rejected.
        """
        with pytest.raises(ValueError, match="max_size"):
            BudgetedExceptionRenderer(max_size=0)

        with pytest.raises(ValueError, match="max_size"):
            BudgetedExceptionRenderer(max_size=-10)

    def test_accepts_positive_budget(self) -> None:
        """
        Any positive budget is accepted; small ones degrade gracefully.
        """
        assert BudgetedExceptionRenderer(max_size=1).max_size == 1


class TestNoException:
    def test_passes_event_dict_through_unchanged(self) -> None:
        """
        Without an ``exc_info`` key, the event dict is returned untouched.
        """
        renderer = BudgetedExceptionRenderer()
        event_dict = {"event": "plain", "answer": 42}

        assert renderer(None, "info", event_dict) is event_dict

    def test_ignores_falsey_exc_info(self) -> None:
        """
        A falsey ``exc_info`` value is consumed without rendering anything,
        matching the unbudgeted ExceptionRenderer.
        """
        renderer = BudgetedExceptionRenderer()
        event_dict = {"event": "plain", "exc_info": None}

        assert renderer(None, "info", event_dict) == {"event": "plain"}


class TestUnderBudget:
    def test_renders_full_without_metadata(self) -> None:
        """
        An exception whose rendering fits is kept verbatim and carries no
        truncation metadata.
        """
        renderer = BudgetedExceptionRenderer(max_size=10_000)
        event_dict = renderer(
            None, "error", {"exc_info": wide_exception(depth=5)}
        )

        assert BUDGET_TRUNCATION_KEY not in event_dict
        assert "Traceback (most recent call last):" in event_dict["exception"]

    def test_matches_plain_exception_renderer(self) -> None:
        """
        When the budget is generous, output equals the unbudgeted formatter.
        """
        from structlog.processors import format_exc_info

        exc = wide_exception(depth=5)
        budgeted = BudgetedExceptionRenderer(max_size=10_000)(
            None, "error", {"exc_info": exc}
        )
        plain = format_exc_info(None, "error", {"exc_info": exc})

        assert budgeted["exception"] == plain["exception"]


class TestStringBudget:
    def test_never_exceeds_budget(self) -> None:
        """
        The rendered exception field stays within the budget at every size.
        """
        exc = wide_exception(depth=30)
        for budget in (2, 16, 64, 256, 1_024, 4_096):
            result = BudgetedExceptionRenderer(max_size=budget)(
                None, "error", {"exc_info": exc}
            )
            assert rendered_size(result["exception"]) <= budget

    def test_two_byte_budget_is_the_floor(self) -> None:
        """
        A string field needs two quote bytes, so a two-byte budget yields an
        empty string rather than overflowing.
        """
        exc = wide_exception(depth=20)
        result = BudgetedExceptionRenderer(max_size=2)(
            None, "error", {"exc_info": exc}
        )

        assert result["exception"] == ""
        assert rendered_size(result["exception"]) == 2

    def test_retains_root_cause_summary(self) -> None:
        """
        A tight budget still keeps a traceable root-cause line.
        """
        exc = wide_exception(depth=30)
        assert isinstance(exc, WideStackError)
        result = BudgetedExceptionRenderer(max_size=200)(
            None, "error", {"exc_info": exc}
        )

        assert "WideStackError" in result["exception"]
        assert "wide-root" in result["exception"]
        assert result[BUDGET_TRUNCATION_KEY]["detail"] == "root_summary"

    def test_truncation_metadata_records_sizes(self) -> None:
        """
        Metadata reports original/final size and the bytes saved.
        """
        exc = wide_exception(depth=30)
        renderer = BudgetedExceptionRenderer(max_size=300)
        result = renderer(None, "error", {"exc_info": exc})
        info = result[BUDGET_TRUNCATION_KEY]

        assert info["original_size"] > 300
        assert info["rendered_size"] == rendered_size(result["exception"])
        assert info["rendered_size"] <= 300
        assert info["dropped_bytes"] == (
            info["original_size"] - info["rendered_size"]
        )
        assert info["detail"] in {"root_traceback", "root_summary"}

    def test_marker_present_when_shrunk(self) -> None:
        """
        Output that had to be cut announces itself with a marker.
        """
        exc = wide_exception(depth=30)
        result = BudgetedExceptionRenderer(max_size=120)(
            None, "error", {"exc_info": exc}
        )

        assert result["exception"].startswith("[truncated] ")

    def test_summary_without_cutting_keeps_root_line(self) -> None:
        """
        When the root-cause line fits as-is, no marker is prepended but the
        detail level still records the reduction.
        """
        exc = wide_exception(depth=30)
        result = BudgetedExceptionRenderer(max_size=400)(
            None, "error", {"exc_info": exc}
        )
        info = result[BUDGET_TRUNCATION_KEY]

        assert not result["exception"].startswith("[truncated] ")
        assert "WideStackError" in result["exception"]
        assert info["detail"] == "root_summary"

    def test_budget_below_marker_still_respected(self) -> None:
        """
        Budgets too small for the marker drop it instead of overflowing.
        """
        exc = wide_exception(depth=20)
        result = BudgetedExceptionRenderer(max_size=8)(
            None, "error", {"exc_info": exc}
        )

        assert rendered_size(result["exception"]) <= 8
        assert not result["exception"].startswith("[truncated] ")

    def test_multibyte_text_respects_byte_budget(self) -> None:
        """
        Budgets are byte budgets, so multi-byte characters are cut correctly.
        """

        class WideError(Exception):
            """Exception carrying a multi-byte message."""

        exc = WideError("é" * 200)
        result = BudgetedExceptionRenderer(max_size=40)(
            None, "error", {"exc_info": exc}
        )

        assert rendered_size(result["exception"]) <= 40
        # At most 38 content bytes once quotes are accounted for.
        assert len(result["exception"].encode("utf-8")) <= 38


class TestChainHandling:
    @pytest.mark.parametrize("implicit", [False, True])
    def test_keeps_deepest_root_of_chain(self, implicit: bool) -> None:
        """
        Both explicit and implicit chains are walked to their deepest cause.
        """
        exc = chained_exception(length=10, implicit=implicit)
        result = BudgetedExceptionRenderer(max_size=250)(
            None, "error", {"exc_info": exc}
        )
        info = result[BUDGET_TRUNCATION_KEY]

        assert info["chain_length"] == 10
        # The root is the ValueError created at the deepest link.
        assert "ValueError" in result["exception"]
        assert "chain-root-0" in result["exception"]

    def test_chain_metadata_reflects_full_depth(self) -> None:
        """
        The reported chain length counts every link, not just the survivor.
        """
        exc = chained_exception(length=6)
        info = BudgetedExceptionRenderer(max_size=200)(
            None, "error", {"exc_info": exc}
        )[BUDGET_TRUNCATION_KEY]

        assert info["chain_length"] == 6

    def test_chain_loop_does_not_hang(self) -> None:
        """
        A self-referential cause chain terminates instead of looping.
        """
        try:
            raise ValueError("loopy")
        except ValueError as exc:
            exc.__cause__ = exc
            result = BudgetedExceptionRenderer(max_size=1_000)(
                None, "error", {"exc_info": exc}
            )

        assert "ValueError" in result["exception"]


class TestStructuredBudget:
    @pytest.fixture(
        params=[
            ExceptionDictTransformer(show_locals=False),
            ExceptionDictTransformer(show_locals=True),
        ]
    )
    def transformer(
        self, request: pytest.FixtureRequest
    ) -> ExceptionDictTransformer:
        """
        Exercise both the locals-free and locals-rich structured formatters.
        """
        return request.param

    def test_never_exceeds_budget(
        self, transformer: ExceptionDictTransformer
    ) -> None:
        """
        Structured output stays within every feasible budget.
        """
        exc = chained_exception(length=8)
        for budget in (
            MIN_STRUCTURED_BUDGET,
            64,
            128,
            256,
            512,
            1_024,
            2_048,
        ):
            renderer = BudgetedExceptionRenderer(
                max_size=budget, exception_formatter=transformer
            )
            result = renderer(None, "error", {"exc_info": exc})
            assert rendered_size(result["exception"]) <= budget

    def test_json_serializable(
        self, transformer: ExceptionDictTransformer
    ) -> None:
        """
        The trimmed structure remains valid JSON.
        """
        exc = wide_exception(depth=20)
        result = BudgetedExceptionRenderer(
            max_size=500, exception_formatter=transformer
        )(None, "error", {"exc_info": exc})

        json.dumps(result["exception"])

    def test_locals_removed_before_frames_capped(self) -> None:
        """
        The first reduction strips bulky locals while keeping every frame.
        """
        exc = wide_exception(depth=40)
        transformer = ExceptionDictTransformer(show_locals=True)
        full = transformer((type(exc), exc, exc.__traceback__))
        result = BudgetedExceptionRenderer(
            max_size=rendered_size(full) - 100,
            exception_formatter=transformer,
        )(None, "error", {"exc_info": exc})
        info = result[BUDGET_TRUNCATION_KEY]

        assert info["detail"] == "locals_removed"
        for stack in result["exception"]:
            assert all("locals" not in frame for frame in stack["frames"])

    def test_frames_capped_and_locals_removed(self) -> None:
        """
        A tighter budget caps frame count after locals have been removed.
        """
        exc = wide_exception(depth=60, payload="x" * 20)
        transformer = ExceptionDictTransformer(show_locals=True)
        result = BudgetedExceptionRenderer(
            max_size=7_000, exception_formatter=transformer
        )(None, "error", {"exc_info": exc})
        info = result[BUDGET_TRUNCATION_KEY]

        assert info["detail"] == "frames_capped"
        for stack in result["exception"]:
            assert all("locals" not in frame for frame in stack["frames"])
            assert len(stack["frames"]) <= 50

    def test_root_stack_keeps_only_final_stack(self) -> None:
        """
        A tighter budget collapses the chain to its root-cause stack.
        """
        exc = chained_wide_exception()
        transformer = ExceptionDictTransformer(show_locals=False)
        result = BudgetedExceptionRenderer(
            max_size=5_000, exception_formatter=transformer
        )(None, "error", {"exc_info": exc})
        info = result[BUDGET_TRUNCATION_KEY]

        assert info["detail"] == "root_stack"
        surviving = result["exception"]
        assert len(surviving) == 1
        assert surviving[0]["exc_type"] == "ValueError"

    def test_root_summary_keeps_single_frame(self) -> None:
        """
        An even tighter budget keeps one root-cause frame without locals.
        """
        exc = chained_wide_exception()
        transformer = ExceptionDictTransformer(show_locals=False)
        result = BudgetedExceptionRenderer(
            max_size=800, exception_formatter=transformer
        )(None, "error", {"exc_info": exc})
        info = result[BUDGET_TRUNCATION_KEY]

        assert info["detail"] == "root_summary"
        surviving = result["exception"]
        assert len(surviving) == 1
        assert surviving[0]["exc_type"] == "ValueError"
        assert len(surviving[0]["frames"]) == 1
        assert all(
            "locals" not in frame for frame in surviving[0]["frames"]
        )

    def test_minimal_fallback_keeps_type_and_value(self) -> None:
        """
        At the structural minimum, the fallback still names the root type.
        """
        exc = chained_exception(length=6, message_width=400)
        transformer = ExceptionDictTransformer(show_locals=False)
        result = BudgetedExceptionRenderer(
            max_size=MIN_STRUCTURED_BUDGET, exception_formatter=transformer
        )(None, "error", {"exc_info": exc})
        info = result[BUDGET_TRUNCATION_KEY]

        assert info["detail"] == "root_cause_only"
        assert set(result["exception"]) == {"exc_type", "exc_value"}
        assert rendered_size(result["exception"]) <= MIN_STRUCTURED_BUDGET


class TestBrokenFormatter:
    def test_formatter_error_does_not_drop_event(self) -> None:
        """
        A formatter that raises is replaced by an error note, keeping the
        event alive.
        """

        def broken(_exc_info: object) -> str:
            """Stand in for a formatter that fails while rendering."""
            msg = "formatter exploded"
            raise RuntimeError(msg)

        result = BudgetedExceptionRenderer(
            max_size=1_000, exception_formatter=broken
        )(None, "error", {"exc_info": wide_exception(depth=3)})

        assert "exception-formatter-error" in result["exception"]
        assert "RuntimeError" in result["exception"]


class TestEndToEnd:
    def _configured_logger(
        self, budget: int
    ) -> tuple[structlog.BoundLogger, CapturingLogger]:
        """
        Build a bound logger whose sink is a CapturingLogger and whose chain
        ends in a JSONRenderer, mirroring a real centralized-logging setup.
        """
        sink = CapturingLogger()
        logger = structlog.BoundLogger(
            logger=sink,
            processors=[
                BudgetedExceptionRenderer(max_size=budget),
                JSONRenderer(),
            ],
            context={},
        )
        return logger, sink

    def test_ordinary_events_after_oversized_are_not_dropped(self) -> None:
        """
        An over-budget exception is recorded in a bounded form, and ordinary
        events logged immediately afterwards still reach the sink.
        """
        logger, sink = self._configured_logger(budget=300)

        try:
            raise wide_exception(depth=30)
        except ValueError as error:
            logger.error("something broke", exc_info=error)

        logger.info("ordinary event", request_id="abc-123")
        logger.warning("another ordinary event")

        assert len(sink.calls) == 3

        oversized = json.loads(sink.calls[0].args[0])
        assert BUDGET_TRUNCATION_KEY in oversized
        assert rendered_size(oversized["exception"]) <= 300

        follow_up = json.loads(sink.calls[1].args[0])
        assert follow_up["event"] == "ordinary event"
        assert follow_up["request_id"] == "abc-123"
        assert BUDGET_TRUNCATION_KEY not in follow_up

        assert (
            json.loads(sink.calls[2].args[0])["event"]
            == "another ordinary event"
        )

    def test_full_event_under_platform_limit(self) -> None:
        """
        The whole serialized event stays close to the configured platform
        limit because the dominant field -- the exception -- is bounded.
        """
        platform_limit = 700
        logger, sink = self._configured_logger(budget=400)

        try:
            raise chained_exception(length=10)
        except RuntimeError as error:
            logger.error("failure", service="payments", exc_info=error)

        line = sink.calls[0].args[0]
        assert len(line.encode("utf-8")) <= platform_limit

    def test_exception_event_is_never_dropped(self) -> None:
        """
        Even at a one-byte string budget, the exception event is emitted.
        """
        logger, sink = self._configured_logger(budget=2)

        try:
            raise wide_exception(depth=20)
        except ValueError as error:
            logger.error("failure", exc_info=error)

        assert len(sink.calls) == 1
        emitted = json.loads(sink.calls[0].args[0])
        assert "exception" in emitted
        assert emitted[BUDGET_TRUNCATION_KEY]["detail"]


class TestCustomTruncationKey:
    def test_uses_configured_metadata_key(self) -> None:
        """
        Truncation metadata is stored under a user-provided key.
        """
        result = BudgetedExceptionRenderer(
            max_size=200, truncation_key="budget_info"
        )(None, "error", {"exc_info": wide_exception(depth=20)})

        assert "budget_info" in result
        assert BUDGET_TRUNCATION_KEY not in result
        assert result["budget_info"]["detail"]
