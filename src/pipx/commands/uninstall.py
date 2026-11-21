from __future__ import annotations

__lazy_modules__ = ["pipx.commands.common", "pipx.paths", "pipx.trash", "pipx.venv", "shutil"]

import logging
from dataclasses import dataclass
from shutil import which
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from pathlib import Path

    from pipx.pipx_metadata_file import PackageInfo
    from pipx.result import JsonValue

from pipx.commands.common import (
    OwnershipEvidence,
    get_venv_package_infos,
    get_venv_resource_paths_by_type,
    get_venv_resource_sources,
    ownership_evidence,
    reuse_resource_dir_scans,
)
from pipx.constants import (
    EXIT_CODE_OK,
    EXIT_CODE_UNINSTALL_ERROR,
    EXIT_CODE_UNINSTALL_VENV_NONEXISTENT,
)
from pipx.emojis import HAZARD, SLEEP, STARS
from pipx.paths import CTX
from pipx.result import OperationData, OperationError, OperationResult, OutputMessage, OutputStream
from pipx.trash import rmdir_via_trash, safe_unlink
from pipx.venv import Venv, VenvContainer

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)


def uninstall_all(
    venv_container: VenvContainer,
    local_bin_dir: Path,
    local_man_dir: Path,
    *,
    verbose: bool,
) -> OperationResult[UninstallData]:
    """Uninstall every environment, with the apps and man pages it exposes.

    :param venv_container: the container of the environments.
    :param local_bin_dir: the directory the apps are exposed in.
    :param local_man_dir: the directory the man pages are exposed in.
    :param verbose: show the progress of the uninstall.
    :returns: the result listing the uninstalled packages and the errors.
    """
    errors: Final[list[OperationError]] = []
    messages: Final[list[OutputMessage]] = []
    packages: Final[list[_UninstalledPackage]] = []
    with reuse_resource_dir_scans():
        for venv_dir in venv_container.iter_venv_dirs():
            with venv_container.venv_lock(venv_dir):
                result: Final = uninstall(venv_dir, local_bin_dir, local_man_dir, verbose=verbose)
            errors.extend(result.errors)
            messages.extend(result.messages)
            packages.extend(result.data.packages)

    return OperationResult(
        command=("uninstall-all",),
        data=UninstallData(
            packages=tuple(sorted(packages, key=lambda package: package.environment)),
        ),
        messages=tuple(messages),
        exit_code=EXIT_CODE_UNINSTALL_ERROR if errors else EXIT_CODE_OK,
        errors=tuple(sorted(errors, key=lambda error: error.environment or "")),
        succeeded=bool(packages),
    )


def uninstall(
    venv_dir: Path,
    local_bin_dir: Path,
    local_man_dir: Path,
    *,
    verbose: bool,
    dry_run: bool = False,
) -> OperationResult[UninstallData]:
    """Uninstall an environment, with the apps and man pages it exposes.

    :param venv_dir: the directory of the environment.
    :param local_bin_dir: the directory the apps are exposed in.
    :param local_man_dir: the directory the man pages are exposed in.
    :param verbose: show the progress of the uninstall.
    :param dry_run: report the ownership evidence and what would be removed, without changing anything.
    :returns: the result of the uninstall.
    """
    if not venv_dir.exists():
        messages: Final[list[OutputMessage]] = [OutputMessage(text=f"Nothing to uninstall for {venv_dir.name} {SLEEP}")]
        if app := which(venv_dir.name):
            messages.append(
                OutputMessage(text=f"{HAZARD}  Note: '{app}' still exists on your system and is on your PATH")
            )
        return OperationResult(
            command=("uninstall",),
            data=UninstallData(packages=()),
            messages=tuple(messages),
            exit_code=EXIT_CODE_UNINSTALL_VENV_NONEXISTENT,
            errors=(
                OperationError(
                    code="environment_uninstall_failed",
                    message=f"Nothing to uninstall for {venv_dir.name}.",
                    environment=venv_dir.name,
                ),
            ),
        )

    venv: Final[Venv] = Venv(venv_dir, verbose=verbose)
    package_infos: Final[tuple[PackageInfo, ...] | None] = get_venv_package_infos(venv)
    resources: Final[dict[str, set[Path]]] = get_venv_resource_paths_by_type(
        venv, local_bin_dir, local_man_dir, package_infos
    )
    if dry_run:
        return _preview(venv, resources, local_bin_dir, local_man_dir, package_infos)

    for path in _reclaimable_paths(venv, resources, local_bin_dir, local_man_dir, package_infos):
        _remove_resource(path)

    package_info: Final[PackageInfo | None] = next(
        (package_info for package_info in package_infos or () if package_info.package == venv.main_package_name),
        None,
    )
    # a removal killed halfway could drop the record but keep the package, which reinstall reads as a venv from pipx
    # before 0.15
    rmdir_via_trash(venv_dir)
    return OperationResult(
        command=("uninstall",),
        data=UninstallData(
            packages=(
                _UninstalledPackage(
                    environment=venv.name,
                    package=str(package_info.package) if package_info is not None else venv.name,
                    version=None if package_info is None else package_info.package_version or None,
                    location=str(venv.root),
                ),
            )
        ),
        messages=(OutputMessage(text=f"uninstalled {venv.name}! {STARS}"),),
    )


def _preview(
    venv: Venv,
    resources: dict[str, set[Path]],
    local_bin_dir: Path,
    local_man_dir: Path,
    package_infos: tuple[PackageInfo, ...] | None,
) -> OperationResult[UninstallData]:
    # the preview runs the same classification as the removal, so the reported evidence is what the real run acts on
    evidence: Final[dict[str, tuple[OwnershipEvidence, ...]]] = _evidence(
        venv, resources, local_bin_dir, local_man_dir, package_infos
    )
    claims: Final[tuple[OwnershipEvidence, ...]] = tuple(claim for claims in evidence.values() for claim in claims)
    reclaimable: Final[tuple[str, ...]] = tuple(str(claim.path) for claim in claims if claim.reclaimable)
    kept: Final[tuple[str, ...]] = tuple(str(claim.path) for claim in claims if not claim.reclaimable)
    package_info: Final[PackageInfo | None] = next(
        (package_info for package_info in package_infos or () if package_info.package == venv.main_package_name),
        None,
    )
    return OperationResult(
        command=("uninstall",),
        data=UninstallData(
            packages=(
                _UninstalledPackage(
                    environment=venv.name,
                    package=str(package_info.package) if package_info is not None else venv.name,
                    version=None if package_info is None else package_info.package_version or None,
                    location=str(venv.root),
                ),
            ),
            dry_run=True,
            would_remove=reclaimable,
            retained=kept,
            evidence=claims,
        ),
        messages=(
            *(_preview_message(claim) for claim in claims),
            OutputMessage(
                text=(
                    f"Would uninstall {venv.name} and remove {len(reclaimable)} "
                    f"resource{'s' if len(reclaimable) != 1 else ''}, keeping {len(kept)} it does not own."
                )
            ),
        ),
    )


def _evidence(
    venv: Venv,
    resources: dict[str, set[Path]],
    local_bin_dir: Path,
    local_man_dir: Path,
    package_infos: tuple[PackageInfo, ...] | None,
) -> dict[str, tuple[OwnershipEvidence, ...]]:
    sources: Final[dict[Path, list[Path]]] = get_venv_resource_sources(package_infos, local_bin_dir, local_man_dir)
    venv_dirs: Final[tuple[Path, ...]] = tuple(VenvContainer(CTX.venvs).iter_venv_dirs())
    return {
        resource_type: tuple(
            ownership_evidence(
                paths,
                resource_type=resource_type,
                venv_root=venv.root,
                venv_bin_path=venv.bin_path,
                venv_dirs=venv_dirs,
                sources=sources,
            )
        )
        for resource_type, paths in sorted(resources.items())
    }


def _reclaimable_paths(
    venv: Venv,
    resources: dict[str, set[Path]],
    local_bin_dir: Path,
    local_man_dir: Path,
    package_infos: tuple[PackageInfo, ...] | None,
) -> tuple[Path, ...]:
    # re-checked directly before removal, so a path another environment took over since the scan stays put
    claims: Final[dict[str, tuple[OwnershipEvidence, ...]]] = _evidence(
        venv, resources, local_bin_dir, local_man_dir, package_infos
    )
    return tuple(
        sorted(
            claim.path for claims in claims.values() for claim in claims if claim.reclaimable and claim.kind != "absent"
        )
    )


def _preview_message(claim: OwnershipEvidence) -> OutputMessage:
    action: Final[str] = "remove" if claim.reclaimable else "keep"
    # the kept line is a notice, so plain and JSON runs both surface why an entry stays without failing the command
    return OutputMessage(
        text=f"{action} {claim.path} ({claim.resource_type}, {claim.kind}): {claim.claim}: {claim.detail}",
        stream=OutputStream.STDOUT if claim.reclaimable else OutputStream.STDERR,
        notice=not claim.reclaimable,
    )


def _remove_resource(path: Path) -> None:
    try:
        safe_unlink(path)
    except FileNotFoundError:
        _LOGGER.info("pipx did not find resource %s", path)
    else:
        _LOGGER.info("pipx removed resource %s", path)


@dataclass(frozen=True, slots=True, kw_only=True)
class _UninstalledPackage:
    environment: str
    package: str
    version: str | None
    location: str


@dataclass(frozen=True, slots=True, kw_only=True)
class UninstallData(OperationData):
    """Result data of the uninstall commands.

    :ivar packages: the uninstalled packages.
    :ivar dry_run: whether the command only reported what it would remove.
    :ivar would_remove: the exposed paths a removal would take away.
    :ivar retained: the exposed paths the environment does not own, which a removal leaves in place.
    :ivar evidence: the ownership evidence for each exposed path, in a stable order.
    """

    packages: tuple[_UninstalledPackage, ...]
    dry_run: bool = False
    would_remove: tuple[str, ...] = ()
    retained: tuple[str, ...] = ()
    evidence: tuple[OwnershipEvidence, ...] = ()

    def to_dict(self) -> dict[str, JsonValue]:
        """Return the data in the shape the command reports.

        A real uninstall keeps its established payload; the preview adds the evidence it reviewed.

        :returns: the JSON-ready dictionary.
        """
        packages: Final[list[JsonValue]] = [
            {"environment": p.environment, "package": p.package, "version": p.version, "location": p.location}
            for p in self.packages
        ]
        if not self.dry_run:
            return {"packages": packages}
        return {
            "packages": packages,
            "dry_run": True,
            "would_remove": list(self.would_remove),
            "retained": list(self.retained),
            "evidence": [claim.to_dict() for claim in self.evidence],
        }


__all__ = [
    "UninstallData",
    "uninstall",
    "uninstall_all",
]
