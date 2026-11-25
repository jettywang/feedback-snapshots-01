"""
In-memory locker for offline audits and tests.

It resolves from a registry instead of an index, writes a PEP 751-shaped lockfile so
evidence remains inspectable, and can be told to fail at a chosen stage.  This makes it
possible to exercise the audit when one candidate fails after another one already
reported its versions.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from hatch.env.lockers.interface import LockerInterface
from hatch.utils.fs import Path

if TYPE_CHECKING:
    from hatch.env.plugin.interface import EnvironmentInterface


FAILURE_STAGES = ("generate", "report", "apply")


class MemoryLocker(LockerInterface):
    """A deterministic locker backed by an in-process registry."""

    PLUGIN_NAME = "memory"

    _versions: dict[str, dict[str, str]] = {}
    _failures: dict[str, str] = {}
    _calls: list[tuple[str, str, str]] = []

    @classmethod
    def supports(cls, _environment: EnvironmentInterface) -> bool:
        return True

    @classmethod
    def reset(cls) -> None:
        cls._versions.clear()
        cls._failures.clear()
        cls._calls.clear()

    @classmethod
    def configure(
        cls,
        environment: str,
        versions: dict[str, str] | None = None,
        *,
        fail_at: str | None = None,
        error: str = "in-memory resolution failed",
    ) -> None:
        if fail_at is not None and fail_at not in FAILURE_STAGES:
            message = f"Failure stage must be one of: {', '.join(FAILURE_STAGES)}"
            raise ValueError(message)

        from hatch.utils.metadata import normalize_project_name

        if versions:
            cls._versions[environment] = {
                normalize_project_name(str(name)): str(version) for name, version in versions.items()
            }
        if fail_at is not None:
            cls._failures[environment] = f"{fail_at}:{error}"
        else:
            cls._failures.pop(environment, None)

    @classmethod
    def calls(cls) -> list[tuple[str, str, str]]:
        return list(cls._calls)

    @classmethod
    def state_file(cls) -> Path | None:
        import os

        path = os.environ.get("HATCH_MEMORY_LOCKER_STATE")
        return Path(path) if path else None

    @classmethod
    def _load_state(cls) -> None:
        path = cls.state_file()
        if path is None or not path.is_file():
            return

        data = json.loads(path.read_text(encoding="utf-8"))
        for environment, entry in data.get("environments", {}).items():
            cls.configure(
                environment,
                entry.get("versions"),
                fail_at=entry.get("fail_at"),
                error=entry.get("error", "in-memory resolution failed"),
            )

    @classmethod
    def _environments(cls, environment: EnvironmentInterface) -> list[str]:
        # A matrix environment inherits the registry entry of its generator.
        names = [environment.name]
        if "." in environment.name:
            names.append(environment.name.split(".", 1)[0])
        return names

    @classmethod
    def _entry(cls, environment: EnvironmentInterface) -> tuple[dict[str, str], str | None]:
        cls._load_state()
        for name in cls._environments(environment):
            failure = cls._failures.get(name)
            versions = cls._versions.get(name)
            if failure is not None or versions is not None:
                return versions or {}, failure
        return {}, None

    @classmethod
    def _check_failure(cls, environment: EnvironmentInterface, stage: str) -> None:
        _, failure = cls._entry(environment)
        if failure is None:
            return
        failed_stage, _, message = failure.partition(":")
        if failed_stage == stage:
            cls._calls.append((environment.name, stage, "failed"))
            raise RuntimeError(message or "in-memory resolution failed")
        cls._calls.append((environment.name, stage, "ok"))

    @classmethod
    def generate(
        cls,
        environment: EnvironmentInterface,
        dependencies: list[str],
        output_path: Path,
        *,
        upgrade: bool = False,
        upgrade_packages: tuple[str, ...] = (),
        layered: bool = False,
        lock_extras: tuple[str, ...] = (),
        lock_groups: tuple[str, ...] = (),
    ) -> None:
        _ = dependencies, upgrade, upgrade_packages, layered, lock_extras, lock_groups
        cls._calls.append((environment.name, "generate", "started"))
        cls._check_failure(environment, "generate")
        versions, _ = cls._entry(environment)
        lines = ['lock-version = "1.0"', 'created-by = "hatch-memory-locker"']
        for name in sorted(versions):
            lines.extend(("", "[[packages]]", f'name = "{name}"', f'version = "{versions[name]}"'))
        output_path.parent.ensure_dir_exists()
        output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    @classmethod
    def report_versions(
        cls,
        environment: EnvironmentInterface,
        lockfile: Path,
        *,
        target: str = "",
        marker: str = "",
    ) -> dict[str, str]:
        _ = lockfile, marker
        cls._calls.append((environment.name, "report", target))
        cls._check_failure(environment, "report")
        versions, _ = cls._entry(environment)
        return dict(versions)

    @classmethod
    def in_sync(
        cls,
        environment: EnvironmentInterface,
        dependencies: list[str],
        output_path: Path,
        *,
        upgrade: bool = False,
        upgrade_packages: tuple[str, ...] = (),
        layered: bool = False,
        lock_extras: tuple[str, ...] = (),
        lock_groups: tuple[str, ...] = (),
    ) -> bool:
        _ = dependencies, upgrade, upgrade_packages, layered, lock_extras, lock_groups
        versions, _ = cls._entry(environment)
        from hatch.env.lock_audit import read_lockfile_versions

        return read_lockfile_versions(output_path) == versions

    @classmethod
    def apply_lock(cls, environment: EnvironmentInterface, lock_path: Path) -> None:
        _ = lock_path
        cls._check_failure(environment, "apply")

    @classmethod
    def install_matches_lock(cls, environment: EnvironmentInterface, lock_path: Path) -> bool:
        _ = lock_path
        try:
            _, failure = cls._entry(environment)
        except Exception:  # noqa: BLE001
            return False
        return not (failure and failure.startswith("apply:"))

    @classmethod
    def describe(cls) -> dict[str, Any]:
        return {"versions": cls._versions, "failures": cls._failures, "calls": cls._calls}
