"""A tox environment that can build packages."""

from __future__ import annotations

__lazy_modules__ = [
    "contextlib",
    "filelock",
    "functools",
    "pathlib",
    "threading",
    "tox.util.path",
    "types",
]

import functools
import logging
from abc import ABC, abstractmethod
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from types import MethodType
from typing import TYPE_CHECKING, Any, Final, ParamSpec, TypeVar

from filelock import BaseFileLock, FileLock

from tox.util.path import ensure_private_dir
from tox.util.typing_compat import override

from .api import ToxEnv, ToxEnvCreateArgs

_P = ParamSpec("_P")
_R = TypeVar("_R")

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterator

    from tox.config.main import Config
    from tox.config.sets import EnvConfigSet

    from .runner import RunToxEnv

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)

_LOCK_FREE_METHODS: Final[frozenset[str]] = frozenset(
    {
        # an interrupt must reach a build that currently holds the package lock, and the lease bookkeeping must stay
        # answerable while a build runs; each of these methods only takes the short state lock
        "acquire_lease",
        "cancellation_receipts",
        "child_pkg_envs",
        "display_context",
        "interrupt",
        "interrupt_for",
        "lease_count",
        "lease_holders",
        "mark_active_run_env",
        "release_lease",
        "teardown_env",
        "_log_context",
    },
)


@dataclass(frozen=True, slots=True, kw_only=True)
class CancellationReceipt:
    """The record of one run environment being cancelled while it used a shared package environment.

    :param run_env: the run environment that was cancelled
    :param shared_env: the package environment it was using
    :param build_generation: the build the cancellation met, ``None`` when no build was in progress
    :param interrupted_build: whether a build started for the cancelled run environment was interrupted
    :param invalidated: whether that build's artifacts were discarded instead of entering a later execution
    :param kept_for: the remaining run environments that still hold the shared environment

    """

    run_env: str
    shared_env: str
    build_generation: int | None
    interrupted_build: bool
    invalidated: bool
    kept_for: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        """Get the receipt as a JSON-compatible mapping.

        :returns: the receipt fields

        """
        return {
            "run_env": self.run_env,
            "shared_env": self.shared_env,
            "build_generation": self.build_generation,
            "interrupted_build": self.interrupted_build,
            "invalidated": self.invalidated,
            "kept_for": list(self.kept_for),
        }


class Package:
    """package."""

    def __init__(self) -> None:
        #: the build generation that produced this package, ``0`` when it did not come from a tracked build
        self.generation = 0


class PathPackage(Package):
    """A package given by a path on the local file system.

    :param path: the path of the package

    """

    def __init__(self, path: Path) -> None:
        super().__init__()
        self.path = path

    @override
    def __str__(self) -> str:
        return str(self.path)


class PackageToxEnv(ToxEnv, ABC):
    """The base of the tox environments that build a package to install into the run environments.

    :param create_args: the arguments the environment is created with

    """

    def __init__(self, create_args: ToxEnvCreateArgs) -> None:
        self._thread_lock = RLock()
        self._file_lock: BaseFileLock | None = None
        self._state_lock = RLock()
        self._envs: set[str] = set()
        self._teardown_deferred = False
        self._packaging_requester: str | None = None
        self._packaging_generation: int | None = None
        self._packaging_complete = False
        self._generation = 0
        self._cancelled_generations: set[int] = set()
        self._cancelled_latest: set[str] = set()
        self._generation_artifacts: dict[int, set[Path]] = {}
        self._cancellation_receipts: dict[str, CancellationReceipt] = {}
        super().__init__(create_args)

    @override
    def __getattribute__(self, name: str) -> Any:
        # the packaging class might be used by multiple environments in parallel, hold a lock for operations on it
        obj = object.__getattribute__(self, name)
        if isinstance(obj, MethodType) and name not in _LOCK_FREE_METHODS:
            obj = PackageToxEnv._lock_method(self._thread_lock, self._file_lock, obj)
        return obj

    @staticmethod
    def _lock_method(thread_lock: RLock, file_lock: BaseFileLock | None, meth: Callable[_P, _R]) -> Callable[_P, _R]:
        @functools.wraps(meth)
        def _func(*args: _P.args, **kwargs: _P.kwargs) -> _R:
            # A pre-existing package environment link must not redirect the lock file.
            with (
                thread_lock,
                file_lock
                if file_lock is not None
                and file_lock.is_locked is False
                and not Path(file_lock.lock_file).parent.is_symlink()
                else nullcontext(),
            ):
                return meth(*args, **kwargs)

        return _func

    @override
    def register_config(self) -> None:
        super().register_config()
        env_dir: Final[Path] = self.conf.get("env_dir", Path)
        self._file_lock = FileLock(env_dir / "file.lock")
        if not env_dir.is_symlink():
            ensure_private_dir(env_dir)
        self.conf.add_config(
            keys=["package_root", "setupdir"],
            of_type=Path,
            default=self.core.get("package_root", Path),
            post_process=self._relative_to_tox_root,
            desc="indicates where the packaging root file exists (historically setup.py file or pyproject.toml now)",
        )

    @override
    def _recreate_default(self, conf: Config, value: str | None) -> bool:
        return self.options.no_recreate_pkg is False and super()._recreate_default(conf, value)

    @abstractmethod
    def perform_packaging(self, for_env: EnvConfigSet) -> list[Package]:
        """Build the packages of the environment.

        :param for_env: the configuration of the run environment the packages are for

        :returns: the packages that were built

        """
        raise NotImplementedError

    # base hook, subclasses override it
    def register_run_env(self, run_env: RunToxEnv) -> Generator[tuple[str, str], PackageToxEnv, None]:  # ruff:ignore[unused-method-argument, no-self-use]
        """Register a run environment that uses the packages of this environment.

        :param run_env: the run environment

        :yields: the package types and the names of the run environment settings the packages are read from

        """
        return  # empty generator by default
        yield ("", "")  # unreachable, exists to establish yield type

    def acquire_lease(self, run_env_name: str) -> None:
        """Take a lease for a run environment, so the shared environment lives until every lease is released.

        :param run_env_name: the name of the run environment that will use the shared environment

        """
        with self._state_lock:
            self._envs.add(run_env_name)
        _LOGGER.debug("acquire package environment %s lease of %s (%d held)", self.name, run_env_name, self.lease_count)

    def release_lease(self, run_env_name: str) -> bool:
        """Release a run environment's lease, and tear the shared environment down on the last release.

        :param run_env_name: the name of the run environment that no longer uses the shared environment

        :returns: whether this was the last lease, so the shared environment was released

        """
        with self._state_lock:
            held = run_env_name in self._envs
            self._envs.discard(run_env_name)
            last = held and not self._envs
            deferred = self._teardown_deferred
            remaining = len(self._envs)
        _LOGGER.debug(
            "release package environment %s lease of %s (%d held)%s",
            self.name,
            run_env_name,
            remaining,
            ", last release" if last else "",
        )
        if last or (deferred and remaining == 0):
            self._finish_shared_teardown()
        return last

    @property
    def lease_holders(self) -> tuple[str, ...]:
        """The run environments that currently hold the shared environment."""
        with self._state_lock:
            return tuple(sorted(self._envs))

    @property
    def lease_count(self) -> int:
        """The number of leases currently held on the shared environment."""
        with self._state_lock:
            return len(self._envs)

    @property
    def cancellation_receipts(self) -> tuple[CancellationReceipt, ...]:
        """The cancellation receipts the shared environment issued, in the order it issued them."""
        with self._state_lock:
            return tuple(self._cancellation_receipts.values())

    def mark_active_run_env(self, run_env: RunToxEnv) -> None:
        """Mark a run environment as active, so the packages are kept until it is torn down.

        :param run_env: the run environment

        """
        self.acquire_lease(run_env.conf.name)

    def teardown_env(self, conf: EnvConfigSet) -> None:
        """Tear the packaging environment down, once no run environment uses it.

        :param conf: the configuration of the run environment that is torn down

        """
        self.release_lease(conf.name)

    @override
    def teardown(self) -> None:
        """Tear the shared environment down, or defer it while run environments still hold leases."""
        with self._state_lock:
            held = bool(self._envs)
            if held:
                self._teardown_deferred = True
                _LOGGER.debug(
                    "defer package environment %s teardown while %s still hold it",
                    self.name,
                    ", ".join(sorted(self._envs)),
                )
                return
        super().teardown()

    def _finish_shared_teardown(self) -> None:
        with self._state_lock:
            self._teardown_deferred = False
        super().teardown()

    def interrupt_for(self, run_env_name: str) -> CancellationReceipt:
        """Cancel the work of one run environment without cancelling the shared environment for the others.

        :param run_env_name: the run environment that is cancelled

        :returns: the receipt of the cancellation

        """
        # A run environment queued behind another build is not the requester, so it has no build to interrupt yet; mark
        # it so the build it is waiting to start leaves right away instead of running for a cancelled environment.
        with self._state_lock:
            requester = self._packaging_requester
            generation = self._packaging_generation
            # the run environment that started the build owns it, whether it runs here or in a nested child build
            interrupted_build = requester == run_env_name and generation is not None and not self._packaging_complete
            if interrupted_build:
                self._cancelled_generations.add(generation)
            else:
                self._cancelled_latest.add(run_env_name)
            kept_for = tuple(sorted(self._envs - {run_env_name}))
            receipt = CancellationReceipt(
                run_env=run_env_name,
                shared_env=self.name,
                build_generation=generation if interrupted_build else None,
                interrupted_build=interrupted_build,
                invalidated=interrupted_build,
                kept_for=kept_for,
            )
            self._cancellation_receipts[run_env_name] = receipt
            # the package environment runs only the cancelled build under its own interruption state, so every
            # in-flight request belongs to it; stopping them here never touches another run environment's build
            statuses = [status for status in self._interruption.running.values() if status.outcome is None]
        if interrupted_build:
            _LOGGER.warning("interrupt tox environment: %s", self.name)
            _LOGGER.warning(
                "cancel tox environment: %s - discard build %d of package environment %s, kept for %s",
                run_env_name,
                generation,
                self.name,
                ", ".join(kept_for) or "no other environment",
            )
        else:
            _LOGGER.warning(
                "cancel tox environment: %s - package environment %s keeps its artifacts and stays available for %s",
                run_env_name,
                self.name,
                ", ".join(kept_for) or "no other environment",
            )
        for status in statuses:  # reach the build without waiting for the package lock it holds
            status.interrupt()
        return receipt

    def build_packages(self, for_env: EnvConfigSet) -> list[Package]:
        """Build packages for a run environment, in its own build generation.

        :param for_env: the configuration of the run environment the packages are for

        :returns: the packages that were built

        :raises SystemExit: when the run environment was cancelled before the build completed

        """
        with self._state_lock:  # a cancellation may have arrived while this call was queued for the build lock
            if for_env.name in self._cancelled_latest:
                self._cancelled_latest.discard(for_env.name)
                raise SystemExit(-2)
        with self._packaging_scope(for_env.name) as generation:
            packages = self.perform_packaging(for_env)
            with self._state_lock:
                cancelled = generation in self._cancelled_generations
                self._packaging_complete = True
            if cancelled:
                # the scope discards the generation while unwinding, so the artifact never reaches an install
                raise SystemExit(-2)
            for package in packages:
                package.generation = package.generation or generation
            return packages

    @contextmanager
    def track_build(self, run_env_name: str) -> Generator[None, None, None]:
        """Attribute a nested build to a run environment, so its cancellation reaches this environment too.

        :param run_env_name: the run environment the nested build is for

        :yields: nothing, the build in the block belongs to the run environment

        """
        with self._packaging_scope(run_env_name):
            yield

    @contextmanager
    def _packaging_scope(self, run_env_name: str) -> Generator[int, None, None]:
        with self._state_lock:
            self._generation += 1
            generation = self._generation
            previous = (self._packaging_requester, self._packaging_generation, self._packaging_complete)
            self._packaging_requester = run_env_name
            self._packaging_generation = generation
            self._packaging_complete = False
        try:
            yield generation
        except BaseException:
            with self._state_lock:
                cancelled = generation in self._cancelled_generations
            self._discard_generation(generation)
            if cancelled:
                raise SystemExit(-2) from None
            raise
        finally:
            # a nested build restores the enclosing build's attribution, so cancelling it still reaches the parent
            with self._state_lock:
                self._packaging_requester, self._packaging_generation, self._packaging_complete = previous

    def register_artifact(self, path: Path) -> None:
        """Record an artifact of the build in progress, so cancelling the build can discard it.

        :param path: the path of the artifact the build in progress produced

        """
        with self._state_lock:
            generation = self._packaging_generation
            if generation is not None:
                self._generation_artifacts.setdefault(generation, set()).add(path)

    def _discard_generation(self, generation: int) -> None:
        with self._state_lock:
            paths = self._generation_artifacts.pop(generation, set())
        self._invalidate_generation(generation)
        for path in paths:
            if path.exists():
                logging.debug("delete package %s", path)
                try:
                    path.unlink()
                except OSError as exception:
                    logging.warning("failed to delete package %s: %s", path, exception)
        for parent in {path.parent for path in paths}:
            try:
                parent.rmdir()
            except OSError:
                pass

    def _invalidate_generation(self, generation: int) -> None:  # ruff:ignore[unused-method-argument]  # hook
        """React to a discarded build generation, for subclasses that cache build results.

        :param generation: the discarded build generation

        """

    def _execution_cancelled(self) -> bool:
        # a cancelled generation must not issue another backend request; the build that owns it is unwinding
        with self._state_lock:
            generation = self._packaging_generation
            return generation is not None and generation in self._cancelled_generations

    @abstractmethod
    def child_pkg_envs(self, run_conf: EnvConfigSet) -> Iterator[PackageToxEnv]:
        """Get the packaging environments the packaging environment of a run environment depends on.

        :param run_conf: the configuration of the run environment

        :returns: the packaging environments

        """
        raise NotImplementedError


def packages_valid(packages: list[Package]) -> bool:
    """Check that every artifact exists and is not empty before it may enter an installation.

    :param packages: the packages a build returned

    :returns: whether every package is complete

    """
    for package in packages:
        if isinstance(package, PathPackage):
            path = package.path
            if path.is_dir():
                continue
            if not path.is_file() or path.stat().st_size == 0:
                return False
    return True


__all__ = [
    "CancellationReceipt",
    "Package",
    "PackageToxEnv",
    "PathPackage",
    "packages_valid",
]
