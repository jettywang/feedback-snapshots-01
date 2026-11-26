# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import contextvars
import logging
import threading
import unittest
from typing import Any
from unittest.mock import patch

from opentelemetry import baggage, context
from opentelemetry.context import guard
from opentelemetry.context.contextvars_context import ContextVarsRuntimeContext
from opentelemetry.context.guard import (
    ContextRuntimeGuard,
    GuardOutcome,
)


class TestGuardRecords(unittest.TestCase):
    def setUp(self) -> None:
        self.previous = context._RUNTIME_CONTEXT  # pylint: disable=protected-access
        self.guard = ContextRuntimeGuard(ContextVarsRuntimeContext())
        context._RUNTIME_CONTEXT = self.guard  # pylint: disable=protected-access

    def tearDown(self) -> None:
        context._RUNTIME_CONTEXT = self.previous  # pylint: disable=protected-access

    def test_owned_attach_and_detach_are_recorded(self) -> None:
        token = context.attach(context.set_value("key", "value"))
        self.assertEqual(context.get_value("key"), "value")
        context.detach(token)

        records = self.guard.records
        self.assertEqual([record.outcome for record in records], [GuardOutcome.ATTACHED, GuardOutcome.DETACHED])
        self.assertEqual(records[0].token_id, records[1].token_id)
        self.assertTrue(records[0].owner.startswith("thread:"))
        self.assertEqual(self.guard.pending_count, 0)

    def test_nested_attach_keeps_previous_context(self) -> None:
        outer = context.attach(context.set_value("a", "outer"))
        inner = context.attach(context.set_value("a", "inner"))
        self.assertEqual(context.get_value("a"), "inner")
        context.detach(inner)
        self.assertEqual(context.get_value("a"), "outer")
        context.detach(outer)
        self.assertIsNone(context.get_value("a"))

        outcomes = [record.outcome for record in self.guard.records]
        self.assertEqual(
            outcomes,
            [
                GuardOutcome.ATTACHED,
                GuardOutcome.ATTACHED,
                GuardOutcome.DETACHED,
                GuardOutcome.DETACHED,
            ],
        )

    def test_invalid_token_is_recorded_then_raised(self) -> None:
        invalid_token: Any = object()
        with self.assertRaises(TypeError):
            self.guard.detach(invalid_token)

        record = self.guard.records[-1]
        self.assertEqual(record.outcome, GuardOutcome.INVALID_TOKEN)
        self.assertEqual(record.operation, "detach")

    def test_duplicate_detach_is_recorded_and_base_api_swallows_it(self) -> None:
        token = context.attach(context.set_value("a", "value"))
        context.detach(token)
        with self.assertLogs("opentelemetry.context", level=logging.ERROR):
            context.detach(token)

        self.assertEqual(self.guard.records[-1].outcome, GuardOutcome.DUPLICATE_DETACH)
        self.assertEqual(context.get_value("a"), None)

    def test_detach_from_another_sync_context_is_recorded(self) -> None:
        # A duplicated context (a plain ``contextvars.copy_context()`` copy)
        # must not be able to release a token owned by the original.
        token = self.guard.attach(context.set_value("a", "value"))
        copied = contextvars.copy_context()
        self.assertEqual(copied.run(context.get_value, "a"), "value")

        def detach_foreign() -> None:
            with self.assertRaises(ValueError):
                self.guard.detach(token)

        copied.run(detach_foreign)
        record = self.guard.records[-1]
        self.assertEqual(record.outcome, GuardOutcome.CROSS_CONTEXT)
        # The failed cross-context release must leave the original attachment
        # usable and cleanly detachable.
        self.assertEqual(context.get_value("a"), "value")
        context.detach(token)

    def test_detach_from_a_foreign_thread_is_recorded(self) -> None:
        token = self.guard.attach(context.set_value("a", "owner"))
        errors: list[BaseException] = []

        def foreign_release() -> None:
            try:
                self.guard.detach(token)
            except BaseException as exc:  # pylint: disable=broad-exception-caught
                errors.append(exc)

        worker = threading.Thread(target=foreign_release)
        worker.start()
        worker.join()

        self.assertIsInstance(errors[0], ValueError)
        record = self.guard.records[-1]
        self.assertEqual(record.outcome, GuardOutcome.FOREIGN_OWNER)
        self.assertNotEqual(record.owner, self.guard.records[0].owner)
        # The original owner can still release it normally.
        self.assertEqual(context.get_value("a"), "owner")
        context.detach(token)
        self.assertEqual(self.guard.pending_count, 0)

    def test_records_are_context_free_and_logs_only_expose_request_fields(self) -> None:
        with guard.diagnostics(correlation_id="req-42", phase="dispatch"):
            token = context.attach(context.set_value("secret", "super-secret"))
            context.detach(token)

        for record in self.guard.records:
            self.assertNotIn("super-secret", record.format())
            self.assertNotIn("secret", record.log_fields())

        self.guard.log_records = True
        with self.assertLogs("opentelemetry.context.guard", level=logging.DEBUG) as captured:
            with guard.diagnostics(correlation_id="req-42", phase="dispatch"):
                token = context.attach(context.set_value("secret", "super-secret"))
                context.detach(token)

        output = "\n".join(captured.output)
        self.assertIn("correlation_id=req-42", output)
        self.assertIn("phase=dispatch", output)
        self.assertNotIn("super-secret", output)
        self.assertNotIn("secret", output)
        self.assertNotIn("token_id", output)

    def test_baggage_values_never_reach_records_or_logs(self) -> None:
        ctx = baggage.set_baggage("tier", "platinum-secret")
        self.guard.log_records = True
        with self.assertLogs("opentelemetry.context.guard", level=logging.DEBUG) as captured:
            with guard.diagnostics(correlation_id="req-baggage", phase="attach"):
                token = context.attach(ctx)
                context.detach(token)

        output = "\n".join(captured.output)
        self.assertIn("correlation_id=req-baggage", output)
        self.assertNotIn("platinum-secret", output)
        self.assertNotIn("tier", output)
        for record in self.guard.records:
            self.assertNotIn("platinum-secret", record.format())
            self.assertNotIn("tier", record.format())


class TestGuardAsync(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.previous = context._RUNTIME_CONTEXT  # pylint: disable=protected-access
        self.guard = ContextRuntimeGuard(ContextVarsRuntimeContext())
        context._RUNTIME_CONTEXT = self.guard  # pylint: disable=protected-access

    def tearDown(self) -> None:
        context._RUNTIME_CONTEXT = self.previous  # pylint: disable=protected-access

    async def test_cancelled_task_detach_is_distinguished(self) -> None:
        seen: list[GuardOutcome] = []

        async def worker() -> None:
            with guard.diagnostics(correlation_id="req-cancel", phase="worker"):
                token = context.attach(context.set_value("job", "running"))
                try:
                    await asyncio.sleep(30)
                except asyncio.CancelledError:
                    context.detach(token)
                    seen.append(self.guard.records[-1].outcome)
                    raise

        task = asyncio.create_task(worker())
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=5)

        self.assertEqual(seen, [GuardOutcome.DETACHED_AFTER_CANCEL])
        record = self.guard.records[-1]
        self.assertTrue(record.cancelled)
        self.assertEqual(record.correlation_id, "req-cancel")
        self.assertEqual(record.phase, "worker")
        self.assertEqual(self.guard.pending_count, 0)

    async def test_tokens_are_owned_per_task(self) -> None:
        parent_token = context.attach(context.set_value("scope", "parent"))
        ready = asyncio.Event()

        async def worker() -> None:
            child_token = context.attach(context.set_value("scope", "child"))
            self.assertEqual(context.get_value("scope"), "child")
            # The child must not touch the parent's token, nor may the parent
            # release the child's.
            with self.assertRaises(ValueError):
                self.guard.detach(parent_token)
            ready.set()
            self.guard.detach(child_token)

        task = asyncio.create_task(worker())
        await asyncio.wait_for(ready.wait(), timeout=5)
        await asyncio.wait_for(task, timeout=5)
        self.assertEqual(context.get_value("scope"), "parent")
        context.detach(parent_token)

        foreign = next(record for record in self.guard.records if record.outcome is GuardOutcome.FOREIGN_OWNER)
        self.assertTrue(foreign.owner.startswith("task:"))
        self.assertEqual(foreign.correlation_id, None)
        self.assertEqual(self.guard.pending_count, 0)

    async def test_task_that_finishes_without_detaching_is_abandoned(self) -> None:
        async def worker() -> None:
            context.attach(context.set_value("job", "still-attached"))

        await asyncio.wait_for(asyncio.create_task(worker()), timeout=5)
        await asyncio.sleep(0)

        record = self.guard.records[-1]
        self.assertEqual(record.outcome, GuardOutcome.ABANDONED)
        self.assertFalse(record.cancelled)
        self.assertEqual(self.guard.pending_count, 0)

    async def test_cancelled_task_that_never_detaches_is_released_by_cancel(self) -> None:
        async def worker() -> None:
            context.attach(context.set_value("job", "leaked"))
            await asyncio.sleep(30)

        task = asyncio.create_task(worker())
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=5)
        # Let the task done callback run.
        await asyncio.sleep(0)

        record = self.guard.records[-1]
        self.assertEqual(record.outcome, GuardOutcome.RELEASED_BY_CANCEL)
        self.assertTrue(record.cancelled)
        self.assertEqual(self.guard.pending_count, 0)


class TestGuardEnable(unittest.TestCase):
    def setUp(self) -> None:
        self.previous = context._RUNTIME_CONTEXT  # pylint: disable=protected-access

    def tearDown(self) -> None:
        context._RUNTIME_CONTEXT = self.previous  # pylint: disable=protected-access

    def test_enable_and_disable(self) -> None:
        guard.disable()
        runtime = ContextVarsRuntimeContext()
        enabled = guard.enable(runtime=runtime)
        self.assertIs(enabled.delegate, runtime)
        self.assertIs(context._RUNTIME_CONTEXT, enabled)  # pylint: disable=protected-access
        self.assertIs(guard.get_guard(), enabled)
        # Enabling twice returns the same instance.
        self.assertIs(guard.enable(), enabled)
        self.assertIs(guard.get_guard(), enabled)

        disabled = guard.disable()
        self.assertIs(disabled, enabled)
        self.assertIs(disabled.delegate, runtime)
        self.assertIs(context._RUNTIME_CONTEXT, runtime)  # pylint: disable=protected-access
        self.assertIsNone(guard.get_guard())

    def test_enabled_by_environment(self) -> None:
        with patch.dict("os.environ", {"OTEL_PYTHON_CONTEXT_GUARD": "true"}):
            runtime = context._load_runtime_context()  # pylint: disable=protected-access
        self.assertIsInstance(runtime, ContextRuntimeGuard)

    def test_disabled_by_default(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            runtime = context._load_runtime_context()  # pylint: disable=protected-access
        self.assertNotIsInstance(runtime, ContextRuntimeGuard)

    def test_invalid_environment_value_keeps_guard_disabled(self) -> None:
        with patch.dict("os.environ", {"OTEL_PYTHON_CONTEXT_GUARD": "yes-please"}):
            runtime = context._load_runtime_context()  # pylint: disable=protected-access
        self.assertNotIsInstance(runtime, ContextRuntimeGuard)


if __name__ == "__main__":
    unittest.main()
