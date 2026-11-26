# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Guarded tracing across copied contexts in asynchronous jobs.

Two local coroutines start from the same initial copy of a request context.
One makes a normal nested stand-in call and releases its tokens in order. The
other is cancelled and then replays its old token. Afterwards the parent task
and an active child task each create a span, so the real parents, the guard
records and the recovery state after the duplicate release can be checked.
"""

from __future__ import annotations

import asyncio
import unittest

from opentelemetry import context
from opentelemetry.context import guard
from opentelemetry.context.contextvars_context import ContextVarsRuntimeContext
from opentelemetry.context.guard import ContextRuntimeGuard, GuardOutcome
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

CORRELATION_ID = "req-async-173"
BUSINESS_VALUE = "customer-tier=platinum"
PHASE_STANDIN = "standin"
PHASE_CANCELLED = "cancelled"


class TestAsyncContextGuard(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.previous_runtime = context._RUNTIME_CONTEXT  # pylint: disable=protected-access
        self.guard = ContextRuntimeGuard(ContextVarsRuntimeContext())
        context._RUNTIME_CONTEXT = self.guard  # pylint: disable=protected-access

        self.exporter = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.tracer = provider.get_tracer(__name__)

    def tearDown(self) -> None:
        context._RUNTIME_CONTEXT = self.previous_runtime  # pylint: disable=protected-access

    def _span(self, name: str):
        return next(span for span in self.exporter.get_finished_spans() if span.name == name)

    async def test_copied_contexts_keep_values_spans_and_guard_records(self) -> None:
        request_key = context.create_key("request")
        business_key = context.create_key("business")
        job_key = context.create_key("job")

        # The request context shared by both coroutines.
        request_token = context.attach(
            context.set_value(
                business_key,
                BUSINESS_VALUE,
                context.set_value(request_key, CORRELATION_ID),
            )
        )

        # The parent task creates its real span first, then copies the context.
        with guard.diagnostics(correlation_id=CORRELATION_ID, phase="parent"):
            with self.tracer.start_as_current_span("request_span") as request_span:
                request_context = request_span.get_span_context()
                shared = context.Context(context.get_current())

        nested_ready = asyncio.Event()
        cancelled_ready = asyncio.Event()
        replay_error: list[str] = []
        standin_parents: dict[str, object] = {}
        inherited: dict[str, object] = {}
        child_result: dict[str, object] = {}

        async def nested_job() -> None:
            copy_token = context.attach(context.Context(shared))
            try:
                inherited["request"] = context.get_value(request_key)
                inherited["business"] = context.get_value(business_key)
                with guard.diagnostics(correlation_id=CORRELATION_ID, phase=PHASE_STANDIN):
                    outer_token = context.attach(context.Context(context.get_current()))
                    try:
                        # A normal nested stand-in call.
                        with self.tracer.start_as_current_span("standin_outer") as outer:
                            with self.tracer.start_as_current_span("standin_inner") as inner:
                                standin_parents["outer"] = outer.parent
                                standin_parents["inner"] = inner.parent
                                standin_parents["outer_context"] = outer.get_span_context()
                        nested_ready.set()
                    finally:
                        context.detach(outer_token)
            finally:
                context.detach(copy_token)

        async def cancelled_job() -> None:
            copy_token = context.attach(context.Context(shared))
            try:
                with guard.diagnostics(correlation_id=CORRELATION_ID, phase=PHASE_CANCELLED):
                    job_token = context.attach(context.set_value(job_key, "cancelled"))
                    cancelled_ready.set()
                    try:
                        await asyncio.sleep(30)
                    except asyncio.CancelledError:
                        self.guard.detach(job_token)
                        try:
                            # Replay the stale token: the guard must record the
                            # duplicate and leave the context usable.
                            self.guard.detach(job_token)
                        except RuntimeError as exc:
                            replay_error.append(str(exc))
                        raise
            finally:
                context.detach(copy_token)

        nested_task = asyncio.create_task(nested_job())
        cancelled_task = asyncio.create_task(cancelled_job())

        await asyncio.wait_for(nested_ready.wait(), timeout=5)
        await asyncio.wait_for(cancelled_ready.wait(), timeout=5)
        cancelled_task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(cancelled_task, timeout=5)
        await asyncio.wait_for(nested_task, timeout=5)

        # Copies inherited the original values.
        self.assertEqual(inherited["request"], CORRELATION_ID)
        self.assertEqual(inherited["business"], BUSINESS_VALUE)

        # Nested stand-in spans: outer is rooted at the copied request span,
        # inner is a real child of outer.
        self.assertEqual(standin_parents["outer"], request_context)
        self.assertEqual(standin_parents["inner"], standin_parents["outer_context"])

        # The cancelled coroutine could not replay its own token.
        self.assertEqual(len(replay_error), 1)
        self.assertIn("already been used", replay_error[0])

        # The parent task still sees its request context after cancellation,
        # and a span created there gets the request span as its parent.
        self.assertEqual(context.get_value(request_key), CORRELATION_ID)
        self.assertEqual(context.get_value(business_key), BUSINESS_VALUE)
        resume_token = context.attach(shared)
        try:
            with guard.diagnostics(correlation_id=CORRELATION_ID, phase="parent"):
                with self.tracer.start_as_current_span("parent_span") as parent_span:
                    parent_context = parent_span.get_span_context()

                    # An active child task started from the parent's span context.
                    child_ready = asyncio.Event()

                    async def active_child() -> None:
                        with self.tracer.start_as_current_span("active_child_span") as child_span:
                            child_result["parent"] = child_span.parent
                            child_result["span_context"] = child_span.get_span_context()
                            child_ready.set()
                            await asyncio.sleep(0)

                    child_task = asyncio.create_task(active_child())
                    await asyncio.wait_for(child_ready.wait(), timeout=5)
                    await asyncio.wait_for(child_task, timeout=5)
        finally:
            context.detach(resume_token)

        self.assertEqual(child_result["parent"], parent_context)
        self.assertNotEqual(child_result["span_context"], parent_context)

        # Finished spans carry the real parent links.
        self.assertEqual(self._span("request_span").parent, None)
        self.assertEqual(self._span("parent_span").parent, request_context)
        self.assertEqual(self._span("active_child_span").parent, parent_context)

        # The guard recorded owned detach, cancellation and duplicate release.
        outcomes = [record.outcome for record in self.guard.records]
        self.assertIn(GuardOutcome.DETACHED, outcomes)
        self.assertIn(GuardOutcome.DETACHED_AFTER_CANCEL, outcomes)
        self.assertIn(GuardOutcome.DUPLICATE_DETACH, outcomes)

        cancelled_records = [
            record
            for record in self.guard.records
            if record.correlation_id == CORRELATION_ID and record.phase == PHASE_CANCELLED
        ]
        self.assertTrue(any(record.cancelled for record in cancelled_records))
        self.assertTrue(any(record.outcome is GuardOutcome.DUPLICATE_DETACH for record in cancelled_records))
        self.assertTrue(all(record.owner.startswith("task:") for record in cancelled_records))

        # Diagnostics stay within the correlation id and phase: the business
        # value and context keys never reach the public log fields.
        for record in self.guard.records:
            fields = record.log_fields()
            self.assertNotIn(BUSINESS_VALUE, str(fields))
            self.assertNotIn("business", str(fields))
            self.assertNotIn("token_id", fields)
            self.assertNotIn("owner", fields)

        # Recovery: only the request attach is still outstanding.
        self.assertEqual(self.guard.pending_count, 1)
        context.detach(request_token)
        self.assertEqual(self.guard.pending_count, 0)


if __name__ == "__main__":
    unittest.main()
