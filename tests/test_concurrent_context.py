from __future__ import annotations

import asyncio
import sys
import threading

import pytest

from dynaconf import Dynaconf

pytestmark = pytest.mark.usefixtures("no_deprecations")


# A real, importable loader module written into the per-test tmp dir (on
# sys.path via the ``go_to_tmpdir`` autouse fixture). It is synchronous and
# parks on a threading.Event shared through a Gate, so it can block a worker
# thread while the event loop keeps running the sibling coroutine.
LOADER_SOURCE = '''
from dynaconf.loaders.base import SourceMetadata

IDENTIFIER = SourceMetadata(loader="pausing", identifier="pausing")
gate = None
fail = False
calls = []


def load(obj, env=None, silent=True, key=None, **kwargs):
    calls.append(env or "default")
    if gate is not None and key == "RELOADED":
        gate.entered.set()
        # Block this (worker) thread until the sibling coroutine releases us.
        gate.release.wait()
    if fail:
        raise RuntimeError("pausing loader instructed to fail")
    obj.set(key or "RELOADED", f"fresh-{env}", loader_identifier=IDENTIFIER)
'''


class Gate:
    """Thread-safe synchronization shared with the synchronous loader."""

    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()


def _make_settings(tmp_path, gate, module_name="pausing_loader"):
    settings_file = tmp_path / "settings.toml"
    settings_file.write_text(
        """
[default]
SHARED = "base-value"
TASK_SCOPED = "from-file"

[production]
SHARED = "prod-value"
TASK_SCOPED = "prod-from-file"
"""
    )

    (tmp_path / f"{module_name}.py").write_text(LOADER_SOURCE)
    sys.modules.pop(module_name, None)
    loader_module = __import__(module_name)
    loader_module.gate = gate
    loader_module.fail = False
    loader_module.calls = []

    settings = Dynaconf(
        environments=True,
        ENV_FOR_DYNACONF="DEFAULT",
        LOADERS_FOR_DYNACONF=[module_name],
        SETTINGS_FILE_FOR_DYNACONF=str(settings_file),
        ROOT_PATH_FOR_DYNACONF=str(tmp_path),
    )
    return settings, loader_module


def test_two_coroutines_isolate_nested_overrides_on_shared_snapshot(
    tmp_path,
):
    """Two coroutines take the same-named env on one shared settings object.

    Stable, already-loaded config is shared read-only; each coroutine's
    temporary nested override stays private to its own read context.
    """
    settings, _ = _make_settings(
        tmp_path, Gate(), module_name="coro_loader"
    )
    observations: dict = {}
    parked: asyncio.Event | None = None
    proceed: asyncio.Event | None = None

    async def task_a(parked, proceed):
        with settings.using_env("PRODUCTION"):
            settings.set("TASK_SCOPED", "a-override")
            parked.set()
            # Park inside the nested read so B can interleave its own read.
            await proceed.wait()
            observations["a_inside"] = {
                "shared": settings.SHARED,
                "scoped": settings.TASK_SCOPED,
                "env": settings.current_env,
            }
        observations["a_outer"] = {
            "shared": settings.SHARED,
            "scoped": settings.TASK_SCOPED,
            "env": settings.current_env,
        }

    async def task_b(parked, proceed):
        await parked.wait()
        with settings.using_env("PRODUCTION"):
            settings.set("TASK_SCOPED", "b-override")
            observations["b_inside"] = {
                "shared": settings.SHARED,
                "scoped": settings.TASK_SCOPED,
                "env": settings.current_env,
            }
        observations["b_outer"] = {
            "shared": settings.SHARED,
            "scoped": settings.TASK_SCOPED,
            "env": settings.current_env,
        }
        proceed.set()

    async def run_coroutines():
        nonlocal parked, proceed
        parked = asyncio.Event()
        proceed = asyncio.Event()
        await asyncio.gather(task_a(parked, proceed), task_b(parked, proceed))

    asyncio.run(run_coroutines())

    # Stable snapshot is shared and identical for both coroutines.
    assert observations["a_inside"]["shared"] == "prod-value"
    assert observations["b_inside"]["shared"] == "prod-value"

    # Temporary overrides are confined to the owning coroutine.
    assert observations["a_inside"]["scoped"] == "a-override"
    assert observations["b_inside"]["scoped"] == "b-override"

    # Back in the outer scope both coroutines keep their own default settings.
    assert observations["a_outer"] == {
        "shared": "base-value",
        "scoped": "from-file",
        "env": "DEFAULT",
    }
    assert observations["b_outer"] == {
        "shared": "base-value",
        "scoped": "from-file",
        "env": "DEFAULT",
    }

    # The shared base object is untouched by either per-task candidate value.
    assert settings.current_env == "DEFAULT"
    assert settings.SHARED == "base-value"
    assert settings.get("TASK_SCOPED") == "from-file"


def test_paused_loader_failure_does_not_leak_across_tasks(tmp_path):
    """One task's nested fresh read parks in the loader, then fails; the
    sibling completes normally and the failing task resumes on its own outer
    settings without any cross-task contamination."""
    gate = Gate()
    settings, loader = _make_settings(tmp_path, gate)
    observations: dict = {}

    def task_a_blocking():
        # Runs in a worker thread so the blocking loader leaves the event loop
        # free for task_b. asyncio.to_thread copies the contextvars context,
        # so the read context established here stays private to this task.
        with settings.using_env("PRODUCTION"):
            settings.set("TASK_SCOPED", "a-override")
            try:
                value = settings.get_fresh("RELOADED")
            except RuntimeError as exc:
                # The loader's deliberate failure, not an event-loop error.
                assert str(exc) == "pausing loader instructed to fail"
                value = "RAISED"
            observations["a_inside"] = {
                "shared": settings.SHARED,
                "scoped": settings.TASK_SCOPED,
                "reloaded": value,
                "env": settings.current_env,
                "reload_calls": list(loader.calls),
            }
        observations["a_outer"] = {
            "shared": settings.SHARED,
            "scoped": settings.TASK_SCOPED,
            "env": settings.current_env,
        }

    async def task_b():
        # Wait until A is parked inside its loader on the worker thread.
        await asyncio.to_thread(gate.entered.wait)
        with settings.using_env("PRODUCTION"):
            settings.set("TASK_SCOPED", "b-override")
            observations["b_inside"] = {
                "shared": settings.SHARED,
                "scoped": settings.TASK_SCOPED,
                "env": settings.current_env,
            }
        observations["b_outer"] = {
            "shared": settings.SHARED,
            "scoped": settings.TASK_SCOPED,
            "env": settings.current_env,
        }
        # Make A's parked loader fail, then release the worker thread.
        loader.fail = True
        gate.release.set()

    async def run_tasks():
        await asyncio.gather(
            asyncio.to_thread(task_a_blocking), task_b()
        )

    asyncio.run(run_tasks())

    # A's inner fresh read surfaced the loader failure; B was unaffected.
    assert observations["a_inside"]["reloaded"] == "RAISED"
    # The fresh reload history belongs to A's context only.
    assert observations["a_inside"]["reload_calls"][-1] == "PRODUCTION"

    # Overrides remain task-local even though A's inner read failed.
    assert observations["a_inside"]["scoped"] == "a-override"
    assert observations["b_inside"]["scoped"] == "b-override"

    # Each task resumes on its own outer settings after the inner scope ends.
    assert observations["a_outer"]["env"] == "DEFAULT"
    assert observations["b_outer"]["env"] == "DEFAULT"
    assert observations["a_outer"]["shared"] == "base-value"
    assert observations["b_outer"]["shared"] == "base-value"

    # The shared base object still serves independent reads.
    assert settings.current_env == "DEFAULT"
    assert settings.SHARED == "base-value"
    assert settings.get("TASK_SCOPED") == "from-file"


def test_fresh_context_is_isolated_between_tasks(tmp_path):
    settings, _ = _make_settings(
        tmp_path, Gate(), module_name="fresh_loader"
    )
    settings.set("VOLATILE", "original", loader_identifier="test")

    results = {}

    async def reader_a():
        with settings.fresh():
            results["a_fresh_flag"] = (
                settings.__core__.active_config.fresh
            )
            await asyncio.sleep(0)
            results["a_fresh_flag_after_yield"] = (
                settings.__core__.active_config.fresh
            )

    async def reader_b():
        await asyncio.sleep(0)
        results["b_fresh_flag"] = settings.__core__.context.is_active()
        results["b_value"] = settings.VOLATILE

    async def run_readers():
        await asyncio.gather(reader_a(), reader_b())

    asyncio.run(run_readers())

    assert results["a_fresh_flag"] is True
    assert results["a_fresh_flag_after_yield"] is True
    # B never entered a fresh context and reads the shared stable value.
    assert results["b_fresh_flag"] is False
    assert results["b_value"] == "original"
    # Shared state is not left in fresh mode after the context exits.
    assert settings.__core__.context.is_active() is False
    assert settings.__core__.config.fresh is False


def test_inner_failure_restores_outer_context_settings(tmp_path):
    settings, _ = _make_settings(
        tmp_path, Gate(), module_name="restore_loader"
    )

    with settings.using_env("PRODUCTION"):
        outer_env = settings.current_env
        outer_shared = settings.SHARED
        settings.set("TASK_SCOPED", "outer-override")
        settings.set("OUTER_ONLY", "outer", loader_identifier="test")
        with pytest.raises(RuntimeError):
            with settings.using_env("DEFAULT"):
                raise RuntimeError("boom before any read completes")
        # The inner scope raised, yet the outer scope is fully restored.
        assert settings.current_env == outer_env == "PRODUCTION"
        assert settings.SHARED == outer_shared == "prod-value"
        assert settings.TASK_SCOPED == "outer-override"
        assert settings.OUTER_ONLY == "outer"

    # Leaving everything returns the shared object to its original state.
    assert settings.current_env == "DEFAULT"
    assert settings.SHARED == "base-value"
    assert settings.TASK_SCOPED == "from-file"
