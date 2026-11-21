from __future__ import annotations

__lazy_modules__ = [
    "hashlib",
    "importlib.metadata",
    "json",
    "packaging.utils",
    "pipx.commands.common",
    "pipx.options",
    "pipx.paths",
    "pipx.pipx_metadata_file",
    "pipx.trash",
    "pipx.util",
    "shutil",
]

import hashlib
import json
import logging
import shutil
import tempfile
from dataclasses import dataclass, replace
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING, Final

from packaging.utils import InvalidName, canonicalize_name

from pipx.commands.common import expose_package_resources
from pipx.constants import MAN_SECTIONS, WINDOWS, ExitCode
from pipx.options import ExposureOptions
from pipx.paths import CTX
from pipx.pipx_metadata_file import PIPX_INFO_FILENAME, PackageInfo, PackageResources, PipxMetadata
from pipx.result import OperationData, OperationError, OperationResult, OutputLevel, OutputMessage, OutputStream
from pipx.trash import rmdir
from pipx.util import PipxError, get_venv_paths, is_file_name, mkdir
from pipx.wrap import pipx_wrap

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)
#: Name of the record that keeps a staged environment in quarantine.
STAGE_INFO_FILENAME: Final[str] = "pipx_takeover.json"
_STAGE_VERSION: Final[str] = "1"
# files in a bin directory that belong to the environment itself rather than to a package entry point
_ENVIRONMENT_FILES: Final[frozenset[str]] = frozenset(
    {
        "activate",
        "activate.bat",
        "activate.csh",
        "activate.fish",
        "activate.nu",
        "activate.ps1",
        "activate_this.py",
        "deactivate.bat",
        "pip",
        "pip.exe",
        "pip3",
        "pip3.exe",
        "python",
        "python.exe",
        "python3",
        "python3.exe",
        "pythonw.exe",
    }
)


# a launcher and a man page that verified, plus what the backup claimed but could not prove
@dataclass(frozen=True, slots=True, kw_only=True)
class _Inspection:
    package: str | None
    package_source: str
    version: str
    python_version: str | None
    apps: tuple[str, ...]
    man_pages: tuple[str, ...]
    missing: tuple[str, ...]
    unowned: tuple[str, ...]
    warnings: tuple[str, ...]
    problems: tuple[str, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class _StagedEnvironment(OperationData):
    """An environment waiting for approval.

    :ivar name: the environment name.
    :ivar path: the directory in quarantine.
    :ivar package: the package the environment holds, when it could be established.
    :ivar package_source: where the package name came from, such as the recorded metadata.
    :ivar version: the recorded package version.
    :ivar python_version: the Python version recorded by the backup.
    :ivar source: where the backup came from, or None.
    :ivar apps: the verified app names that would be exposed.
    :ivar man_pages: the verified man pages that would be exposed.
    :ivar missing: content a package declares but the environment does not hold.
    :ivar unowned: files that no package claims, which approval would not expose.
    :ivar warnings: reasons some resources are left unexposed.
    :ivar problems: reasons the environment cannot be approved.
    """

    name: str
    path: str
    package: str | None
    package_source: str
    version: str
    python_version: str | None
    source: str | None
    apps: tuple[str, ...]
    man_pages: tuple[str, ...]
    missing: tuple[str, ...]
    unowned: tuple[str, ...]
    warnings: tuple[str, ...]
    problems: tuple[str, ...]
    digest: str


@dataclass(frozen=True, slots=True, kw_only=True)
class TakeoverData(OperationData):
    """Result data of the takeover commands.

    :ivar environments: the staged environments the command acted on.
    """

    environments: tuple[_StagedEnvironment, ...]


def stage_backup(
    backup: Path,
    *,
    name: str | None = None,
    source: str | None = None,
    quarantine: Path | None = None,
) -> OperationResult[TakeoverData]:
    """Copy a virtual environment backup into quarantine and inspect it without running anything from it.

    :param backup: the directory of the backup.
    :param name: the environment name to stage under, or None to take the package name.
    :param source: where the backup came from, recorded for the reviewer.
    :param quarantine: the quarantine directory, the configured one when None.
    :returns: the result describing the staged environment and what approval would expose.
    :raises PipxError: when the backup cannot be staged.
    """
    source_dir: Final[Path] = _checked_source(backup)
    quarantine_dir: Final[Path] = quarantine if quarantine is not None else CTX.quarantine
    if quarantine_dir.resolve().is_relative_to(source_dir.resolve()):
        # copying a directory into itself would recurse, and the quarantine must outlive the transfer medium
        msg = f"{source_dir} is inside the quarantine {quarantine_dir}; point takeover at the backup outside it"
        raise PipxError(msg)
    metadata_view: Final[_RecordedPackage] = _recorded_package(source_dir)
    if name is None and metadata_view.package is None:
        msg = (
            f"{source_dir} records no package name, and its distribution metadata names no single package either; "
            "pass --name to say what the environment holds"
        )
        raise PipxError(msg)
    environment: Final[str] = _stage_name(name or metadata_view.package or source_dir.name)
    _refuse_existing_venv(environment)

    if quarantine_dir.resolve().is_relative_to(source_dir):
        msg = f"{source_dir} contains the quarantine {quarantine_dir}; point takeover at a backup outside it"
        raise PipxError(msg)
    _refuse_special_files(source_dir)
    stage_dir: Final[Path] = quarantine_dir / environment
    if stage_dir.exists():
        msg = (
            f"{environment} is already quarantined at {stage_dir}; approve it, or remove it with "
            f"'pipx takeover remove {environment}'."
        )
        raise PipxError(msg)
    mkdir(quarantine_dir)
    staged: Final[Path] = quarantine_dir / f".{environment}.staging"
    rmdir(staged, safe_rm=False)
    try:
        shutil.copytree(source_dir, staged, symlinks=True)
        # the backup's own record is evidence, never replayed; the staged record replaces it with what was verified
        (staged / PIPX_INFO_FILENAME).unlink(missing_ok=True)
        inspection: Final[_Inspection] = _inspect(staged, environment, metadata_view)
        _write_stage_record(
            staged, environment, inspection, source=source, backup=source_dir, digest=_tree_digest(staged)
        )
        staged.rename(stage_dir)
    except Exception:
        rmdir(staged, safe_rm=False)
        raise

    return _stage_result(stage_dir, inspection)


def list_staged(quarantine: Path | None = None) -> OperationResult[TakeoverData]:
    """List the environments waiting in quarantine.

    :param quarantine: the quarantine directory, the configured one when None.
    :returns: the result listing each staged environment.
    """
    quarantine_dir: Final[Path] = quarantine if quarantine is not None else CTX.quarantine
    staged: Final[list[_StagedEnvironment]] = [
        _read_stage(candidate)
        for candidate in (sorted(quarantine_dir.iterdir()) if quarantine_dir.is_dir() else ())
        if candidate.is_dir() and not candidate.name.startswith(".") and (candidate / STAGE_INFO_FILENAME).is_file()
    ]
    messages: Final[tuple[OutputMessage, ...]] = (
        tuple(OutputMessage(text=_summary(stage)) for stage in staged)
        if staged
        else (OutputMessage(text="pipx has no environments in quarantine."),)
    )
    return OperationResult(
        command=("takeover", "list"),
        data=TakeoverData(environments=tuple(staged)),
        messages=messages,
        exit_code=ExitCode(1 if any(stage.problems for stage in staged) else 0),
        errors=tuple(
            OperationError(code="environment_takeover_unverified", message=problem, environment=stage.name)
            for stage in staged
            for problem in stage.problems
        ),
        succeeded=bool(staged),
    )


def check_staged(environment: str, quarantine: Path | None = None) -> OperationResult[TakeoverData]:
    """Re-check a staged environment before approval, without running or exposing anything.

    :param environment: the name of the staged environment.
    :param quarantine: the quarantine directory, the configured one when None.
    :returns: the result of the check.
    """
    stage_dir: Final[Path] = _stage_dir(environment, quarantine)
    stage: Final[_StagedEnvironment] = _read_stage(stage_dir)
    try:
        _refuse_changed_tree(stage_dir, stage)
    except PipxError as error:
        problems_before: Final[tuple[str, ...]] = (*stage.problems, str(error))
    else:
        problems_before = stage.problems
    refreshed: Final[_Inspection] = _inspect(stage_dir, stage.name, _recorded_from_stage(stage))
    problems: Final[tuple[str, ...]] = tuple(dict.fromkeys((*problems_before, *refreshed.problems)))
    messages: Final[list[OutputMessage]] = [
        OutputMessage(text=_summary(stage)),
        *(
            OutputMessage(text=f"{stage.name}: would expose {resource}", stream=OutputStream.STDOUT)
            for resource in _would_expose(stage)
        ),
        *(
            OutputMessage(text=f"{stage.name}: not exposed: {warning}", level=OutputLevel.NORMAL)
            for warning in refreshed.warnings
        ),
        *(
            OutputMessage(text=f"{stage.name}: {problem}", stream=OutputStream.STDERR, level=OutputLevel.ERROR)
            for problem in problems
        ),
    ]
    if not problems:
        messages.append(
            OutputMessage(text=f"{stage.name}: ready; approve it with 'pipx takeover approve {stage.name}'")
        )
    return OperationResult(
        command=("takeover", "check"),
        data=TakeoverData(environments=(_with_problems(stage, problems),)),
        messages=tuple(messages),
        exit_code=ExitCode(1 if problems else 0),
        errors=tuple(
            OperationError(code="environment_takeover_unverified", message=problem, environment=stage.name)
            for problem in problems
        ),
        succeeded=not problems,
    )


def approve_staged(
    environment: str,
    local_bin_dir: Path,
    local_man_dir: Path,
    *,
    quarantine: Path | None = None,
) -> OperationResult[TakeoverData]:
    """Move an approved environment out of quarantine and expose only the resources that verified.

    :param environment: the name of the staged environment.
    :param local_bin_dir: the directory the app links are placed in.
    :param local_man_dir: the directory the man pages are placed in.
    :param quarantine: the quarantine directory, the configured one when None.
    :returns: the result of the approval.
    :raises PipxError: when the staged environment fails verification.
    """
    quarantine_dir: Final[Path] = quarantine if quarantine is not None else CTX.quarantine
    stage_dir: Final[Path] = _stage_dir(environment, quarantine_dir)
    stage: Final[_StagedEnvironment] = _read_stage(stage_dir)
    if stage.problems:
        raise PipxError(
            pipx_wrap(
                "\n".join(
                    [
                        f"{stage.name} cannot be approved until these are fixed:",
                        *(f"  - {problem}" for problem in stage.problems),
                    ]
                )
            )
        )
    _refuse_changed_tree(stage_dir, stage)
    refreshed: Final[_Inspection] = _inspect(stage_dir, stage.name, _recorded_from_stage(stage))
    if refreshed.problems:
        raise PipxError(
            pipx_wrap(
                "\n".join(
                    [
                        f"{stage.name} has problems that block approval:",
                        *(f"  - {problem}" for problem in refreshed.problems),
                    ]
                )
            )
        )
    if not refreshed.apps:
        msg = f"{stage.name} has no verified app to expose; refusing to approve an entry point that cannot be run"
        raise PipxError(msg)
    _refuse_existing_venv(stage.name)

    target: Final[Path] = CTX.venvs / stage.name
    mkdir(CTX.venvs)
    # the record travels with the tree, so a failed move back leaves a stage that list and remove can still find
    stage_dir.rename(target)
    try:
        # the shebang of a launcher copied from another machine names that machine's interpreter; point it at this
        # environment only after the move, so it names the final path rather than the quarantine
        _repoint_launchers(target, refreshed.apps)
    except OSError as error:
        # leave nothing half adopted in the managed store; the reviewed tree goes back to quarantine
        target.rename(stage_dir)
        msg = f"pipx could not prepare {stage.name} for approval: {error}"
        raise PipxError(msg) from error
    (target / STAGE_INFO_FILENAME).unlink(missing_ok=True)

    pipx_metadata: Final[PipxMetadata] = _build_venv_metadata(target, stage, refreshed)
    pipx_metadata.write()
    collisions: Final[list[Path]] = expose_package_resources(
        pipx_metadata.main_package, local_bin_dir, local_man_dir, force=False
    )
    # exposure stays enabled even after a collision, so `pipx expose` can retry once the other file is gone
    pipx_metadata.exposure_enabled = True
    pipx_metadata.write()

    collided: Final[frozenset[str]] = frozenset(path.name for path in collisions)
    messages: Final[list[OutputMessage]] = [
        OutputMessage(text=f"{stage.name}: taken over from quarantine"),
        *(
            OutputMessage(text=f"{stage.name}: exposed {resource}")
            for resource in _would_expose(stage)
            if Path(resource).name not in collided
        ),
        *(
            OutputMessage(text=f"{stage.name}: not exposed: {warning}", level=OutputLevel.NORMAL)
            for warning in refreshed.warnings
        ),
        *(
            OutputMessage(
                text=f"{stage.name}: left {path} in place because another file already owns that name",
                stream=OutputStream.STDERR,
                level=OutputLevel.ERROR,
            )
            for path in collisions
        ),
    ]
    return OperationResult(
        command=("takeover", "approve"),
        data=TakeoverData(environments=(stage,)),
        messages=tuple(messages),
        exit_code=ExitCode(1 if collisions else 0),
        errors=tuple(
            OperationError(
                code="environment_takeover_conflict",
                message=f"{path} already exists and does not belong to {stage.name}",
                environment=stage.name,
            )
            for path in collisions
        ),
        succeeded=not collisions,
    )


def remove_staged(environment: str, *, quarantine: Path | None = None) -> OperationResult[TakeoverData]:
    """Discard a staged environment without exposing anything.

    :param environment: the name of the staged environment.
    :param quarantine: the quarantine directory, the configured one when None.
    :returns: the result of the removal.
    """
    stage_dir: Final[Path] = _stage_dir(environment, quarantine)
    stage: Final[_StagedEnvironment] = _read_stage(stage_dir)
    rmdir(stage_dir)
    return OperationResult(
        command=("takeover", "remove"),
        data=TakeoverData(environments=(stage,)),
        messages=(OutputMessage(text=f"{stage.name}: removed from quarantine"),),
        succeeded=True,
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class _RecordedPackage:
    package: str | None
    version: str
    python_version: str | None
    source: str


def _recorded_package(root: Path) -> _RecordedPackage:
    # every pipx metadata generation names the package somewhere: 0.1-0.12 all keep main_package.package
    payload: Final[Mapping[str, object]] = _read_json_object(root / PIPX_INFO_FILENAME)
    main_package: Final[object] = payload.get("main_package")
    package_data: Final[Mapping[str, object]] = main_package if isinstance(main_package, dict) else {}
    package: Final[object] = package_data.get("package")
    version: Final[object] = package_data.get("package_version")
    python_version: Final[object] = payload.get("python_version")
    if isinstance(package, str) and package.strip():
        return _RecordedPackage(
            package=package.strip(),
            version=version if isinstance(version, str) else "",
            python_version=python_version if isinstance(python_version, str) else None,
            source=PIPX_INFO_FILENAME,
        )
    inferred: Final[tuple[str, str] | None] = _single_distribution(root)
    if inferred is None:
        return _RecordedPackage(package=None, version="", python_version=None, source="missing")
    return _RecordedPackage(
        package=inferred[0], version=inferred[1], python_version=None, source="distribution metadata"
    )


def _recorded_from_stage(stage: _StagedEnvironment) -> _RecordedPackage:
    return _RecordedPackage(
        package=stage.package,
        version=stage.version,
        python_version=stage.python_version,
        source=stage.package_source,
    )


def _single_distribution(root: Path) -> tuple[str, str] | None:
    distributions: Final[list[metadata.Distribution]] = _distributions(root)
    names: Final[dict[str, str]] = {}
    for dist in distributions:
        try:
            name: Final[str] = canonicalize_name(dist.name or "", validate=True)
            version: Final[str] = dist.version
        except Exception:  # ruff:ignore[blind-except]  # malformed distribution files are a finding, not a crash
            continue
        names.setdefault(name, version)
    return next(iter(names.items())) if len(names) == 1 else None


def _distributions(root: Path) -> list[metadata.Distribution]:
    # read the on-disk metadata directly: MetadataPathFinder reads the interpreter's sys.path, not the argument
    distributions: Final[list[metadata.Distribution]] = []
    for site_packages in _site_packages(root):
        distributions.extend(
            metadata.PathDistribution(Path(entry))
            for entry in Path(site_packages).iterdir()
            if entry.suffix == ".dist-info"
        )
    return distributions


def _site_packages(root: Path) -> list[str]:
    directories: Final[list[Path]] = [
        root / "Lib" / "site-packages",
        *sorted(root.glob("lib/python3*/site-packages")),
        *sorted(root.glob("lib64/python3*/site-packages")),
    ]
    return [str(directory) for directory in dict.fromkeys(directories) if directory.is_dir()]


def _inspect(root: Path, environment: str, recorded: _RecordedPackage) -> _Inspection:
    bin_dir, python_path, man_dir = get_venv_paths(root)
    if not root.is_dir():
        msg = f"{root} is not a directory"
        raise PipxError(msg)
    problems: Final[list[str]] = []
    warnings: Final[list[str]] = []
    if not (root / "pyvenv.cfg").is_file():
        problems.append("pyvenv.cfg is missing, so this is not a virtual environment")
    if not python_path.is_file():
        problems.append(f"the interpreter is missing at {python_path}")

    package: Final[str | None] = recorded.package
    version: Final[str] = recorded.version
    package_name: Final[str | None] = canonicalize_name(package) if package else None
    if package_name is None:
        problems.append("the backup records no package name, and its files name no single package either")
    elif package_name != environment and not _same_environment_name(package_name, environment):
        problems.append(f"the backup names package {package_name!r}, which does not match environment {environment!r}")

    claimed: Final[dict[str, str]] = _entry_points(root)
    installed_version: Final[str | None] = _installed_version(root, package_name) if package_name else None
    if installed_version is not None and version and installed_version != version:
        warnings.append(f"the backup records {package_name} {version}, but its files hold {installed_version}")

    apps: Final[list[str]] = []
    missing: Final[list[str]] = []
    for app, owner in sorted(claimed.items()):
        if not _claimable_app(app, owner, package_name):
            # an entry point of a dependency still gets exposed only when the backup recorded exposure for it
            continue
        state: Final[_LauncherState] = _launcher_state(bin_dir, app, root)
        _record_launcher(app, state, apps, missing, warnings)

    unowned: Final[list[str]] = [
        entry.name for entry in (sorted(bin_dir.iterdir()) if bin_dir.is_dir() else ()) if _unowned(entry, claimed)
    ]
    if unowned:
        warnings.append(f"no package claims {', '.join(unowned)}; approval leaves them unexposed")

    man_pages, unverified_man = _man_pages(man_dir, root)
    if unverified_man:
        warnings.append(f"no regular man page claims {', '.join(unverified_man)}")

    if package_name is not None and not apps and not missing:
        problems.append(f"no console entry point of {package_name} is recorded, so approval would expose nothing")
    return _Inspection(
        package=package_name,
        package_source=recorded.source,
        version=version or (installed_version or ""),
        python_version=recorded.python_version,
        apps=tuple(apps),
        man_pages=tuple(man_pages),
        missing=tuple(missing),
        unowned=tuple(unowned),
        warnings=tuple(dict.fromkeys(warnings)),
        problems=tuple(dict.fromkeys(problems)),
    )


def _claimable_app(app: str, owner: str, package_name: str | None) -> bool:
    return is_file_name(app) and app not in _ENVIRONMENT_FILES and (package_name is None or owner == package_name)


def _record_launcher(app: str, state: _LauncherState, apps: list[str], missing: list[str], warnings: list[str]) -> None:
    if state.verified:
        apps.append(app)
        if state.repointed:
            warnings.append(f"{app} will point at this environment's interpreter on approval")
    else:
        missing.append(app)
        warnings.append(f"{app} is declared but {state.reason}")


def _same_environment_name(package: str, environment: str) -> bool:
    # an environment installed with --suffix keeps the bare package name and appends the suffix to the venv name
    return len(environment) > len(package) and environment.startswith(package)


@dataclass(frozen=True, slots=True, kw_only=True)
class _LauncherState:
    verified: bool
    reason: str = ""
    repointed: bool = False


def _launcher_state(bin_dir: Path, app: str, root: Path) -> _LauncherState:  # noqa: PLR0911
    launcher: Final[Path] = bin_dir / (f"{app}.exe" if WINDOWS else app)
    if not launcher.exists() and not launcher.is_symlink():
        return _LauncherState(verified=False, reason=f"its launcher {launcher.name} is missing")
    if launcher.is_symlink():
        try:
            target: Final[Path] = launcher.resolve()
        except (OSError, RuntimeError):
            return _LauncherState(verified=False, reason=f"its launcher {launcher.name} cannot be resolved")
        if not target.is_relative_to(root):
            return _LauncherState(verified=False, reason=f"its launcher {launcher.name} links outside the environment")
        return (
            _LauncherState(verified=True)
            if target.is_file()
            else _LauncherState(verified=False, reason=f"its launcher {launcher.name} links to a missing file")
        )
    if not launcher.is_file():
        return _LauncherState(verified=False, reason=f"its launcher {launcher.name} is not a regular file")
    data: Final[bytes | None] = _read_launcher(launcher)
    if data is None:
        return _LauncherState(verified=False, reason=f"its launcher {launcher.name} cannot be read")
    named: Final[Path | None] = _shebang_path(data)
    if WINDOWS:
        # a Windows launcher is an .exe stub with an appended zip, not a script with a shebang
        return _LauncherState(verified=True)
    if named is None:
        return _LauncherState(verified=False, reason=f"its launcher {launcher.name} has no Python shebang")
    if launcher.stat().st_mode & 0o111 == 0:
        return _LauncherState(verified=False, reason=f"its launcher {launcher.name} is not executable")
    if named.is_relative_to(root):
        return _LauncherState(verified=True)
    if _python_like(named):
        return _LauncherState(verified=True, repointed=True)
    reason: Final[str] = f"its launcher {launcher.name} starts {named}, outside the environment"
    return _LauncherState(verified=False, reason=reason)


def _python_like(path: Path) -> bool:
    return path.name.lower().startswith("python")


def _read_launcher(launcher: Path) -> bytes | None:
    try:
        return launcher.read_bytes()
    except OSError:
        return None


def _shebang_path(data: bytes) -> Path | None:
    first_line, _, rest = data.partition(b"\n")
    if not first_line.startswith(b"#!"):
        return None
    line: Final[bytes] = first_line[2:].strip()
    if line == b"/bin/sh" and rest.startswith(b"'''exec' "):
        words: Final[list[bytes]] = rest.split(b"\n", 1)[0].split()
        return Path(words[1].decode(errors="replace")) if len(words) > 1 else None
    parts: Final[list[bytes]] = line.split()
    return Path(parts[0].decode(errors="replace")) if parts else None


def _entry_points(root: Path) -> dict[str, str]:
    # console and GUI entry points, keyed by the launcher name, with the canonical distribution that claims each
    claimed: Final[dict[str, str]] = {}
    for dist in _distributions(root):
        try:
            name: Final[str] = canonicalize_name(dist.name or "", validate=True)
            entry_points: Final = dist.entry_points
        except Exception:  # ruff:ignore[blind-except]  # malformed distribution files are a finding, not a crash
            continue
        for entry_point in entry_points:
            if entry_point.group in {"console_scripts", "gui_scripts"}:
                claimed.setdefault(entry_point.name, name)
    return claimed


def _installed_version(root: Path, package: str) -> str | None:
    for dist in _distributions(root):
        try:
            name: Final[str] = canonicalize_name(dist.name or "", validate=True)
            version: Final[str] = dist.version
        except Exception:  # ruff:ignore[blind-except]  # malformed distribution files are a finding, not a crash
            continue
        if name == package:
            return version
    return None


def _unowned(entry: Path, claimed: Mapping[str, str]) -> bool:
    if entry.is_dir() or entry.name in claimed or entry.name in _ENVIRONMENT_FILES or entry.name.startswith("."):
        return False
    return not (
        WINDOWS and entry.suffix.lower() in {".exe", ".cmd", ".bat", ".ps1"} and entry.stem in _ENVIRONMENT_FILES
    )


def _man_pages(man_dir: Path, root: Path) -> tuple[list[str], list[str]]:
    verified: Final[list[str]] = []
    unverified: Final[list[str]] = []
    if not man_dir.is_dir():
        return verified, unverified
    for section in MAN_SECTIONS:
        section_dir: Final[Path] = man_dir / section
        if not section_dir.is_dir():
            continue
        for entry in sorted(section_dir.iterdir()):
            if entry.is_symlink() and not entry.resolve().is_relative_to(root):
                unverified.append(f"{section}/{entry.name}")
            elif entry.is_file():
                verified.append(f"{section}/{entry.name}")
    return verified, unverified


def _would_expose(stage: _StagedEnvironment) -> tuple[str, ...]:
    return (*stage.apps, *stage.man_pages)


def _stage_name(candidate: str) -> str:
    try:
        canonical: Final[str] = canonicalize_name(candidate, validate=True)
    except InvalidName as error:
        msg = f"{candidate!r} is not a valid environment name"
        raise PipxError(msg) from error
    if Path(canonical).name != canonical or canonical in {".", ".."}:
        msg = f"{candidate!r} is not a valid environment name"
        raise PipxError(msg)
    return canonical


def _refuse_special_files(root: Path) -> None:
    # copying a FIFO blocks forever, and a device node or socket has no place in a virtual environment backup
    for path in root.rglob("*"):
        if path.is_symlink() or path.is_dir() or path.is_file():
            continue
        msg = f"{path} is not a regular file, directory or symlink; refusing to copy an unusual backup entry"
        raise PipxError(msg)


def _checked_source(backup: Path) -> Path:
    source: Final[Path] = backup.expanduser()
    if source.is_symlink():
        msg = f"{backup} is a symlink; copy the backup to a stable directory and point takeover at that"
        raise PipxError(msg)
    if not source.is_dir():
        msg = f"{backup} is not a directory; point takeover at a virtual environment backup"
        raise PipxError(msg)
    return source.resolve()


def _refuse_existing_venv(name: str) -> None:
    target: Final[Path] = CTX.venvs / name
    # exists() follows a link, so a dangling one at the target would still let approve rename over a link
    if target.exists() or target.is_symlink():
        msg = f"pipx already manages an environment named {name!r}; choose another name with --name"
        raise PipxError(msg)


def _stage_dir(environment: str, quarantine: Path | None = None) -> Path:
    quarantine_dir: Final[Path] = quarantine if quarantine is not None else CTX.quarantine
    try:
        canonical: Final[str] = canonicalize_name(environment, validate=True)
    except InvalidName as error:
        msg = f"{environment!r} is not a staged environment"
        raise PipxError(msg) from error
    stage_dir: Final[Path] = quarantine_dir / canonical
    if stage_dir.is_symlink():
        # a link would be renamed into venvs as is, adopting whatever it points at instead of the reviewed tree
        msg = f"{stage_dir} is a symlink; refusing to treat it as a staged environment"
        raise PipxError(msg)
    if stage_dir.parent != quarantine_dir or not (stage_dir / STAGE_INFO_FILENAME).is_file():
        msg = f"pipx has no staged environment named {environment!r}"
        raise PipxError(msg)
    return stage_dir


def _tree_digest(root: Path) -> str:
    # the digest binds approval to the exact tree a reviewer looked at: a change after staging, whether accidental or
    # deliberate, makes approval refuse rather than expose something that was never checked
    digest: Final = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path == root / STAGE_INFO_FILENAME:
            continue
        relative: Final[str] = path.relative_to(root).as_posix()
        if path.is_symlink():
            digest.update(f"link\0{relative}\0{path.readlink()}\n".encode())
        elif path.is_dir():
            digest.update(f"dir\0{relative}\n".encode())
        elif path.is_file():
            mode: Final[int] = path.stat().st_mode
            digest.update(f"file\0{relative}\0{mode & 0o111:o}\0".encode())
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            digest.update(b"\n")
    return digest.hexdigest()


def _refuse_changed_tree(stage_dir: Path, stage: _StagedEnvironment) -> None:
    # a digest only binds the tree whose entries it covered; a special file would also block the next check
    _refuse_special_files(stage_dir)
    if stage.digest and _tree_digest(stage_dir) != stage.digest:
        msg = (
            f"{stage.name} changed after it was staged; review it again by removing it with "
            f"'pipx takeover remove {stage.name}' and staging the backup afresh"
        )
        raise PipxError(msg)


def _write_stage_record(  # noqa: PLR0913
    root: Path, environment: str, inspection: _Inspection, *, source: str | None, backup: Path, digest: str
) -> None:
    (root / STAGE_INFO_FILENAME).write_text(
        json.dumps(
            {
                "stage_version": _STAGE_VERSION,
                "environment": environment,
                "source": source,
                "backup": str(backup),
                "package": inspection.package,
                "package_source": inspection.package_source,
                "version": inspection.version,
                "python_version": inspection.python_version,
                "apps": list(inspection.apps),
                "man_pages": list(inspection.man_pages),
                "missing": list(inspection.missing),
                "unowned": list(inspection.unowned),
                "warnings": list(inspection.warnings),
                "problems": list(inspection.problems),
                "digest": digest,
            },
            indent=4,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _read_stage(stage_dir: Path) -> _StagedEnvironment:
    record: Final[Mapping[str, object]] = _read_json_object(stage_dir / STAGE_INFO_FILENAME)
    name: Final[object] = record.get("environment")
    if not isinstance(name, str) or not name:
        msg = f"{stage_dir} has no usable takeover record"
        raise PipxError(msg)
    # the record is a file in the admin's own home, but approval must not act on a name edited to a path: renaming to
    # CTX.venvs / "/etc" would land outside the store
    if _stage_name(name) != stage_dir.name:
        msg = f"{stage_dir} records the environment name {name!r}, which does not match its directory"
        raise PipxError(msg)
    package: Final[object] = record.get("package")
    package_source: Final[object] = record.get("package_source")
    version: Final[object] = record.get("version")
    python_version: Final[object] = record.get("python_version")
    source: Final[object] = record.get("source")
    digest: Final[object] = record.get("digest")
    return _StagedEnvironment(
        name=name,
        path=str(stage_dir),
        package=package if isinstance(package, str) else None,
        package_source=package_source if isinstance(package_source, str) else "takeover record",
        version=version if isinstance(version, str) else "",
        python_version=python_version if isinstance(python_version, str) else None,
        source=source if isinstance(source, str) else None,
        apps=tuple(_str_list(record.get("apps"))),
        man_pages=tuple(_str_list(record.get("man_pages"))),
        missing=tuple(_str_list(record.get("missing"))),
        unowned=tuple(_str_list(record.get("unowned"))),
        warnings=tuple(_str_list(record.get("warnings"))),
        problems=tuple(_str_list(record.get("problems"))),
        digest=digest if isinstance(digest, str) else "",
    )


def _read_json_object(path: Path) -> Mapping[str, object]:
    try:
        payload: Final[object] = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _with_problems(stage: _StagedEnvironment, problems: tuple[str, ...]) -> _StagedEnvironment:
    return replace(stage, problems=problems) if problems != stage.problems else stage


def _str_list(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _repoint_launchers(root: Path, apps: Iterable[str]) -> None:
    # a copied launcher still names the interpreter of the machine the backup came from; point the verified ones at
    # this environment, writing a new inode so a hard-linked wheel file is not changed for anyone else
    bin_dir, python_path, _ = get_venv_paths(root)
    for app in apps:
        if not is_file_name(app):
            continue
        launcher: Final[Path] = bin_dir / (f"{app}.exe" if WINDOWS else app)
        if launcher.is_symlink() or not launcher.is_file():
            continue
        data: Final[bytes] = launcher.read_bytes()
        named: Final[Path | None] = _shebang_path(data)
        if named is None or named.is_relative_to(root) or not _python_like(named):
            continue
        first_line, newline, rest = data.partition(b"\n")
        if first_line[2:].strip() == b"/bin/sh":
            lines: Final[list[bytes]] = rest.split(b"\n", 1)
            if not lines[0].startswith(b"'''exec' "):
                continue
            words: Final[list[bytes]] = lines[0].split()
            words[1] = str(python_path).encode()
            rest = b"\n".join([b" ".join(words), *lines[1:]])
        else:
            first_line = b"#!" + str(python_path).encode()
        # write a new inode: uv may hard-link a launcher to a shared cache, and editing it in place would change the
        # file for every environment that shares it
        with tempfile.NamedTemporaryFile(dir=launcher.parent, prefix=f".{launcher.name}.", delete=False) as handle:
            temporary: Final[Path] = Path(handle.name)
            handle.write(first_line + newline + rest)
        try:
            shutil.copymode(launcher, temporary)
            temporary.chmod(temporary.stat().st_mode | 0o100)
            temporary.replace(launcher)
        except OSError:
            temporary.unlink(missing_ok=True)
            raise


def _build_venv_metadata(target: Path, stage: _StagedEnvironment, inspection: _Inspection) -> PipxMetadata:
    bin_dir, _, man_dir = get_venv_paths(target)
    pipx_metadata: Final[PipxMetadata] = PipxMetadata(target, read=False)
    pipx_metadata.environment = stage.name
    pipx_metadata.python_version = inspection.python_version
    pipx_metadata.main_package = PackageInfo(
        package=inspection.package,
        package_or_url=inspection.package,
        pip_args=[],
        exposure=ExposureOptions(),
        resources=PackageResources(
            apps=list(inspection.apps),
            app_paths=[bin_dir / app for app in inspection.apps],
            apps_of_dependencies=[],
            app_paths_of_dependencies={},
            man_pages=list(inspection.man_pages),
            man_paths=[man_dir / man_page for man_page in inspection.man_pages],
        ),
        package_version=inspection.version,
    )
    return pipx_metadata


def _summary(stage: _StagedEnvironment) -> str:
    package: Final[str] = f" ({stage.package} {stage.version})" if stage.package else ""
    source: Final[str] = f" from {stage.source}" if stage.source else ""
    state: Final[str] = " [not approvable]" if stage.problems else ""
    return (
        f"{stage.name}{package}: {len(stage.apps)} verified app(s), "
        f"{len(stage.man_pages)} man page(s){source}{state}"
    )


def _stage_result(stage_dir: Path, inspection: _Inspection) -> OperationResult[TakeoverData]:
    stage: Final[_StagedEnvironment] = _read_stage(stage_dir)
    provenance: Final[str] = f" from {stage.source}" if stage.source else ""
    messages: Final[list[OutputMessage]] = [
        OutputMessage(text=f"{stage.name}: staged in quarantine at {stage_dir}{provenance}"),
        *(OutputMessage(text=f"{stage.name}: would expose {resource}") for resource in _would_expose(stage)),
        *(
            OutputMessage(text=f"{stage.name}: not exposed: {warning}", level=OutputLevel.NORMAL)
            for warning in inspection.warnings
        ),
        *(
            OutputMessage(text=f"{stage.name}: {problem}", stream=OutputStream.STDERR, level=OutputLevel.ERROR)
            for problem in inspection.problems
        ),
    ]
    if not inspection.problems:
        messages.append(
            OutputMessage(text=f"{stage.name}: review it with 'pipx takeover check {stage.name}', then approve it")
        )
    return OperationResult(
        command=("takeover", "stage"),
        data=TakeoverData(environments=(stage,)),
        messages=tuple(messages),
        exit_code=ExitCode(1 if inspection.problems else 0),
        errors=tuple(
            OperationError(code="environment_takeover_unverified", message=problem, environment=stage.name)
            for problem in inspection.problems
        ),
        succeeded=not inspection.problems,
    )


__all__ = [
    "STAGE_INFO_FILENAME",
    "TakeoverData",
    "approve_staged",
    "check_staged",
    "list_staged",
    "remove_staged",
    "stage_backup",
]
