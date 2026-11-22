# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the MIT License.  See the LICENSE file in the root of this
# repository for complete details.

import asyncio
import contextvars
import inspect
import secrets
import threading

from concurrent.futures import ThreadPoolExecutor

import pytest

import structlog

from structlog.contextvars import (
    _CONTEXT_VARS,
    bind_contextvars,
    bound_contextvars,
    clear_contextvars,
    copy_restricted_context,
    get_contextvars,
    get_merged_contextvars,
    merge_contextvars,
    reset_contextvars,
    restricted_contextvars,
    unbind_contextvars,
)


@pytest.fixture(autouse=True)
def _clear_contextvars():
    """
    Make sure all tests start with a clean slate.
    """
    clear_contextvars()


class TestContextvars:
    async def test_bind(self):
        """
        Binding a variable causes it to be included in the result of
        merge_contextvars.
        """
        event_loop = asyncio.get_running_loop()

        async def coro():
            bind_contextvars(a=1)
            return merge_contextvars(None, None, {"b": 2})

        assert {"a": 1, "b": 2} == await event_loop.create_task(coro())

    async def test_multiple_binds(self):
        """
        Multiple calls to bind_contextvars accumulate values instead of
        replacing them. But they override redefined ones.
        """
        event_loop = asyncio.get_running_loop()

        async def coro():
            bind_contextvars(a=1, c=3)
            bind_contextvars(c=333, d=4)
            return merge_contextvars(None, None, {"b": 2})

        assert {
            "a": 1,
            "b": 2,
            "c": 333,
            "d": 4,
        } == await event_loop.create_task(coro())

    async def test_reset(self):
        """
        reset_contextvars allows resetting contexvars to
        previously-set values.
        """
        event_loop = asyncio.get_running_loop()

        async def coro():
            bind_contextvars(a=1)

            assert {"a": 1} == get_contextvars()

            await event_loop.create_task(nested_coro())

        async def nested_coro():
            tokens = bind_contextvars(a=2, b=3)

            assert {"a": 2, "b": 3} == get_contextvars()

            reset_contextvars(**tokens)

            assert {"a": 1} == get_contextvars()

        await event_loop.create_task(coro())

    async def test_nested_async_bind(self):
        """
        Context is passed correctly between "nested" concurrent operations.
        """
        event_loop = asyncio.get_running_loop()

        async def coro():
            bind_contextvars(a=1)
            return await event_loop.create_task(nested_coro())

        async def nested_coro():
            bind_contextvars(c=3)
            return merge_contextvars(None, None, {"b": 2})

        assert {"a": 1, "b": 2, "c": 3} == await event_loop.create_task(coro())

    async def test_merge_works_without_bind(self):
        """
        merge_contextvars returns values as normal even when there has
        been no previous calls to bind_contextvars.
        """
        event_loop = asyncio.get_running_loop()

        async def coro():
            return merge_contextvars(None, None, {"b": 2})

        assert {"b": 2} == await event_loop.create_task(coro())

    async def test_merge_overrides_bind(self):
        """
        Variables included in merge_contextvars override previously
        bound variables.
        """
        event_loop = asyncio.get_running_loop()

        async def coro():
            bind_contextvars(a=1)
            return merge_contextvars(None, None, {"a": 111, "b": 2})

        assert {"a": 111, "b": 2} == await event_loop.create_task(coro())

    async def test_clear(self):
        """
        The context-local context can be cleared, causing any previously bound
        variables to not be included in merge_contextvars's result.
        """
        event_loop = asyncio.get_running_loop()

        async def coro():
            bind_contextvars(a=1)
            clear_contextvars()
            return merge_contextvars(None, None, {"b": 2})

        assert {"b": 2} == await event_loop.create_task(coro())

    async def test_clear_without_bind(self):
        """
        The context-local context can be cleared, causing any previously bound
        variables to not be included in merge_contextvars's result.
        """
        event_loop = asyncio.get_running_loop()

        async def coro():
            clear_contextvars()
            return merge_contextvars(None, None, {})

        assert {} == await event_loop.create_task(coro())

    async def test_unbind(self):
        """
        Unbinding a previously bound variable causes it to be removed from the
        result of merge_contextvars.
        """
        event_loop = asyncio.get_running_loop()

        async def coro():
            bind_contextvars(a=1)
            unbind_contextvars("a")
            return merge_contextvars(None, None, {"b": 2})

        assert {"b": 2} == await event_loop.create_task(coro())

    async def test_unbind_not_bound(self):
        """
        Unbinding a not bound variable causes doesn't raise an exception.
        """
        event_loop = asyncio.get_running_loop()

        async def coro():
            # Since unbinding means "setting to Ellipsis", we have to make
            # some effort to ensure that the ContextVar never existed.
            unbind_contextvars("a" + secrets.token_hex())

            return merge_contextvars(None, None, {"b": 2})

        assert {"b": 2} == await event_loop.create_task(coro())

    async def test_parallel_binds(self):
        """
        Binding a variable causes it to be included in the result of
        merge_contextvars.
        """
        event_loop = asyncio.get_running_loop()
        coro1_bind = asyncio.Event()
        coro2_bind = asyncio.Event()

        bind_contextvars(c=3)

        async def coro1():
            bind_contextvars(a=1)

            coro1_bind.set()
            await coro2_bind.wait()

            return merge_contextvars(None, None, {"b": 2})

        async def coro2():
            bind_contextvars(a=2)

            await coro1_bind.wait()
            coro2_bind.set()

            return merge_contextvars(None, None, {"b": 2})

        coro1_task = event_loop.create_task(coro1())
        coro2_task = event_loop.create_task(coro2())

        assert {"a": 1, "b": 2, "c": 3} == await coro1_task
        assert {"a": 2, "b": 2, "c": 3} == await coro2_task

    def test_get_only_gets_structlog_without_deleted(self):
        """
        get_contextvars returns only the structlog-specific key-values with
        the prefix removed. Deleted keys (= Ellipsis) are ignored.
        """
        bind_contextvars(a=1, b=2)
        unbind_contextvars("b")
        _CONTEXT_VARS["foo"] = "bar"

        assert {"a": 1} == get_contextvars()

    def test_get_merged_merges_context(self):
        """
        get_merged_contextvars merges a bound context into the copy.
        """
        bind_contextvars(x=1)
        log = structlog.get_logger().bind(y=2)

        assert {"x": 1, "y": 2} == get_merged_contextvars(log)


class TestBoundContextvars:
    def test_cleanup(self):
        """
        Bindings are cleaned up
        """
        with bound_contextvars(x=42, y="foo"):
            assert {"x": 42, "y": "foo"} == get_contextvars()

        assert {} == get_contextvars()

    def test_cleanup_conflict(self):
        """
        Overwritten keys are restored after the clean up
        """
        bind_contextvars(x="original", z="unrelated")
        with bound_contextvars(x=42, y="foo"):
            assert {"x": 42, "y": "foo", "z": "unrelated"} == get_contextvars()

        assert {"x": "original", "z": "unrelated"} == get_contextvars()

    def test_preserve_independent_bind(self):
        """
        New bindings inside bound_contextvars are preserved after the clean up
        """
        with bound_contextvars(x=42):
            bind_contextvars(y="foo")
            assert {"x": 42, "y": "foo"} == get_contextvars()

        assert {"y": "foo"} == get_contextvars()

    def test_nesting_works(self):
        """
        bound_contextvars binds and unbinds even when nested
        """
        with bound_contextvars(l1=1):
            assert {"l1": 1} == get_contextvars()

            with bound_contextvars(l2=2):
                assert {"l1": 1, "l2": 2} == get_contextvars()

            assert {"l1": 1} == get_contextvars()

        assert {} == get_contextvars()

    def test_as_decorator(self):
        """
        bound_contextvars can be used as a decorator and it preserves the
        name, signature and documentation of the wrapped function.
        """

        @bound_contextvars(x=42)
        def wrapped(arg1):
            """Wrapped documentation"""
            bind_contextvars(y=arg1)
            assert {"x": 42, "y": arg1} == get_contextvars()

        wrapped(23)

        assert "wrapped" == wrapped.__name__
        assert "(arg1)" == str(inspect.signature(wrapped))
        assert "Wrapped documentation" == wrapped.__doc__


class TestRestrictedContextvars:
    def test_only_allowed_keys_visible(self):
        """
        Inside the block only the allow-listed keys are visible; the others
        are restored afterwards.
        """
        bind_contextvars(trace_id="t1", customer="alice", email="a@x.io")

        with restricted_contextvars("trace_id"):
            assert {"trace_id": "t1"} == get_contextvars()

        assert {
            "trace_id": "t1",
            "customer": "alice",
            "email": "a@x.io",
        } == get_contextvars()

    def test_missing_allowed_key_is_ignored(self):
        """
        Allow-listed keys that are not bound do not raise and simply do not
        appear.
        """
        bind_contextvars(customer="alice")

        with restricted_contextvars("trace_id", "customer"):
            assert {"customer": "alice"} == get_contextvars()

    def test_no_allowed_keys_hides_everything(self):
        """
        An empty allow-list hides all structlog context variables.
        """
        bind_contextvars(trace_id="t1", customer="alice")

        with restricted_contextvars():
            assert {} == get_contextvars()

        assert {"trace_id": "t1", "customer": "alice"} == get_contextvars()

    def test_keys_bound_inside_block_are_removed(self):
        """
        Keys bound inside the block that were not there before do not leak
        out of it.
        """
        bind_contextvars(trace_id="t1")

        with restricted_contextvars("trace_id"):
            bind_contextvars(customer="intruder")
            assert {
                "trace_id": "t1",
                "customer": "intruder",
            } == get_contextvars()

        assert {"trace_id": "t1"} == get_contextvars()

    def test_restores_overwritten_values(self):
        """
        Values overwritten inside the block are restored to their original
        values afterwards.
        """
        bind_contextvars(trace_id="t1", customer="alice")

        with restricted_contextvars("trace_id"):
            bind_contextvars(trace_id="t2")
            assert {"trace_id": "t2"} == get_contextvars()

        assert {"trace_id": "t1", "customer": "alice"} == get_contextvars()

    def test_nesting(self):
        """
        Nested blocks intersect their allow-lists and each restores the
        state of the surrounding block.
        """
        bind_contextvars(trace_id="t1", customer="alice", email="a@x.io")

        with restricted_contextvars("trace_id", "customer"):
            assert {"trace_id": "t1", "customer": "alice"} == get_contextvars()
            with restricted_contextvars("trace_id"):
                assert {"trace_id": "t1"} == get_contextvars()
            assert {
                "trace_id": "t1",
                "customer": "alice",
            } == get_contextvars()

        assert {
            "trace_id": "t1",
            "customer": "alice",
            "email": "a@x.io",
        } == get_contextvars()

    def test_as_decorator(self):
        """
        restricted_contextvars can be used as a decorator while preserving
        the wrapped function's metadata.
        """

        @restricted_contextvars("trace_id")
        def wrapped(arg1):
            """Wrapped documentation"""
            assert {"trace_id": arg1} == get_contextvars()

        bind_contextvars(trace_id=42, customer="alice")
        wrapped(42)

        assert {"trace_id": 42, "customer": "alice"} == get_contextvars()
        assert "wrapped" == wrapped.__name__
        assert "(arg1)" == str(inspect.signature(wrapped))
        assert "Wrapped documentation" == wrapped.__doc__


class TestCopyRestrictedContext:
    def test_contains_only_allowed_keys(self):
        """
        The forked context exposes nothing but the allow-listed keys.
        """
        bind_contextvars(trace_id="t1", customer="alice", email="a@x.io")

        ctx = copy_restricted_context("trace_id")

        assert {"trace_id": "t1"} == ctx.run(get_contextvars)

    def test_does_not_touch_parent_context(self):
        """
        Forking never modifies the caller's context and changes inside the
        fork stay inside it.
        """
        bind_contextvars(trace_id="t1", customer="alice")

        ctx = copy_restricted_context("trace_id")
        ctx.run(bind_contextvars, customer="stowaway")

        # The fork keeps its own mutation, the parent never sees it.
        assert {
            "trace_id": "t1",
            "customer": "stowaway",
        } == ctx.run(get_contextvars)
        assert {"trace_id": "t1", "customer": "alice"} == get_contextvars()

    def test_ignores_missing_allowed_keys(self):
        """
        Allow-listed keys absent from the parent do not appear in the fork.
        """
        bind_contextvars(customer="alice")

        ctx = copy_restricted_context("trace_id")

        assert {} == ctx.run(get_contextvars)

    def test_empty_allow_list_has_no_structlog_vars(self):
        """
        A fork without allowed keys contains no structlog context at all.
        """
        bind_contextvars(trace_id="t1", customer="alice")

        assert {} == copy_restricted_context().run(get_contextvars)

    def test_non_structlog_contextvars_are_not_copied(self):
        """
        Only structlog-managed context variables cross the boundary; other
        ContextVars are left behind.
        """
        bind_contextvars(trace_id="t1")
        external = contextvars.ContextVar("external_secret")
        external.set("shh")

        ctx = copy_restricted_context("trace_id")

        assert external.name not in {var.name for var in ctx.keys()}
        assert {"trace_id": "t1"} == ctx.run(get_contextvars)

    def test_two_forks_are_independent(self):
        """
        Forks created from the same parent do not share state.
        """
        bind_contextvars(trace_id="t1", customer="alice")

        first = copy_restricted_context("trace_id")
        second = copy_restricted_context("trace_id")
        first.run(bind_contextvars, trace_id="mutated")

        assert {"trace_id": "mutated"} == first.run(get_contextvars)
        assert {"trace_id": "t1"} == second.run(get_contextvars)


class TestBackgroundTaskHandoff:
    """
    End-to-end behavior requested for spawning background work: children
    only carry approved fields, parent requests keep their own context and
    recycled worker threads never see a previous task's data.
    """

    def test_parallel_requests_isolate_context_and_cancel_tasks(self):
        """
        Two requests with same-named fields each keep their own context,
        their spawned tasks only see the approved trace_id, a cancelled task
        never runs and the reused worker thread cannot observe the previous
        task's data.
        """
        request_one = {
            "trace_id": "trace-1",
            "customer": "alice",
            "email": "alice@example.com",
        }
        request_two = {
            "trace_id": "trace-2",
            "customer": "bob",
            "email": "bob@example.com",
        }
        results: dict[str, tuple[dict, object]] = {}
        # Task one occupies the single worker and blocks on this event, so
        # both tasks spawned afterwards stay queued and are cancelable.
        first_running = threading.Event()
        release_worker = threading.Event()
        second_queued = threading.Event()

        def handle_one() -> None:
            def blocking_task() -> dict:
                first_running.set()
                release_worker.wait(timeout=5)
                return get_contextvars()

            clear_contextvars()
            bind_contextvars(**request_one)
            parent_context = get_contextvars()

            ctx = copy_restricted_context("trace_id")
            running_future = pool.submit(lambda: ctx.run(blocking_task))
            first_running.wait(timeout=5)

            # Wait until request two's task is queued behind ours, then
            # spawn and immediately cancel another background task.
            second_queued.wait(timeout=5)
            cancelled_future = pool.submit(
                lambda: ctx.run(get_contextvars)
            )
            assert cancelled_future.cancel()

            release_worker.set()
            assert running_future.result() == {"trace_id": "trace-1"}
            results["one"] = (parent_context, cancelled_future)

        def handle_two() -> None:
            clear_contextvars()
            bind_contextvars(**request_two)
            parent_context = get_contextvars()

            ctx = copy_restricted_context("trace_id")
            future = pool.submit(lambda: ctx.run(get_contextvars))
            second_queued.set()
            child_context = future.result()

            results["two"] = (parent_context, child_context)

        with ThreadPoolExecutor(max_workers=1) as pool:
            first = threading.Thread(target=handle_one)
            second = threading.Thread(target=handle_two)
            first.start()
            second.start()
            first.join()
            second.join()

        parent_one, cancelled_task = results["one"]
        parent_two, child_context = results["two"]

        # Parent requests retain their complete, distinct contexts.
        assert parent_one == request_one
        assert parent_two == request_two
        assert parent_one["trace_id"] != parent_two["trace_id"]

        # The cancelled task never executed.
        assert cancelled_task.cancelled()
        assert not cancelled_task.running()

        # The executed child task only carries the approved field.
        assert child_context == {"trace_id": "trace-2"}
        assert "customer" not in child_context
        assert "email" not in child_context

    def test_worker_reuse_sees_no_leftover_task_data(self):
        """
        After a task finishes, the recycled worker thread starts the next
        task with exactly that task's restricted context.
        """
        seen: list[dict] = []

        with ThreadPoolExecutor(max_workers=1) as pool:
            for i in range(3):
                # Simulate a fresh request with its own full context.
                clear_contextvars()
                bind_contextvars(
                    trace_id=f"trace-{i}", customer=f"cust-{i}"
                )
                ctx = copy_restricted_context("trace_id")
                seen.append(pool.submit(ctx.run, get_contextvars).result())

        assert seen == [{"trace_id": f"trace-{i}"} for i in range(3)]
        assert all("customer" not in ctx for ctx in seen)

        # The main test thread still holds only the last request's context,
        # and none of the worker mutations ever leaked back.
        assert {
            "trace_id": "trace-2",
            "customer": "cust-2",
        } == get_contextvars()

    async def test_asyncio_task_handoff(self):
        """
        The same restricted context can be handed to an asyncio task via
        its context argument without leaking the parent's customer data.
        """
        bind_contextvars(trace_id="t1", customer="alice")
        ctx = copy_restricted_context("trace_id")

        async def background_task() -> dict:
            return get_contextvars()

        task = asyncio.get_running_loop().create_task(
            background_task(), context=ctx
        )

        assert {"trace_id": "t1"} == await task
        # The parent request context is untouched.
        assert {"trace_id": "t1", "customer": "alice"} == get_contextvars()
