from __future__ import annotations

__lazy_modules__ = [
    "pipx.shared_libs",
    "pipx.shared_profiles",
    "pipx.trash",
    "pipx.venv_inspect",
]

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from pipx.constants import EXIT_CODE_OK, ExitCode
from pipx.result import OperationData, OperationError, OperationResult, OutputMessage, OutputStream
from pipx.shared_libs import _SharedLibs, shared_libs_for
from pipx.shared_profiles import (
    DEFAULT_PROFILE,
    Profile,
    bump,
    check_pip_override,
    declare,
    gc_candidates,
    installed_pip_version,
    iter_profile_names,
    load,
    profile_root,
    referencing_environments,
    validate_profile_name,
)
from pipx.util import PipxError

if TYPE_CHECKING:
    from pipx.options import SharedProfileOptions


@dataclass(frozen=True, slots=True, kw_only=True)
class _ProfileRow:
    name: str
    root: str
    requires: str
    registered: bool
    revision: int
    pip_version: str | None
    referenced_by: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Return the row as a dictionary, as the operation data contract requires.

        :returns: the fields of the row.
        """
        return {
            "name": self.name,
            "root": self.root,
            "requires": self.requires,
            "registered": self.registered,
            "revision": self.revision,
            "pip_version": self.pip_version,
            "referenced_by": list(self.referenced_by),
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class SharedProfilesData(OperationData):
    """Result data of the shared-profile commands.

    :ivar profiles: the profiles of this pipx home.
    """

    profiles: tuple[_ProfileRow, ...]


def list_profiles() -> OperationResult[SharedProfilesData]:
    """Report every shared profile that exists, and the environments that reference it.

    :returns: the result listing the profiles.
    """
    rows: Final[tuple[_ProfileRow, ...]] = tuple(_row(name) for name in iter_profile_names())
    if not rows:
        return OperationResult(
            command=("profile", "list"),
            data=SharedProfilesData(profiles=()),
            messages=(OutputMessage(text="No shared profiles exist."),),
        )
    messages: Final[tuple[OutputMessage, ...]] = tuple(
        OutputMessage(text=_describe(row), stream=OutputStream.STDOUT) for row in rows
    )
    return OperationResult(command=("profile", "list"), data=SharedProfilesData(profiles=rows), messages=messages)


def _row(name: str) -> _ProfileRow:
    profile: Final[Profile] = load(name)
    return _ProfileRow(
        name=name,
        root=str(profile.root),
        requires=profile.effective_requires or "",
        registered=profile.registered,
        revision=profile.revision,
        pip_version=profile.pip_version or installed_pip_version(profile.root),
        referenced_by=referencing_environments(name),
    )


def _describe(row: _ProfileRow) -> str:
    state: Final[str] = "declared" if row.registered else "undeclared"
    requirement: Final[str] = row.requires or "no requirement"
    pip: Final[str] = row.pip_version or "no pip installed"
    users: Final[str] = ", ".join(row.referenced_by) or "unused"
    return f"{row.name}: {requirement} ({state}, {pip}, revision {row.revision}); used by: {users}"


def declare_profile(name: str, options: SharedProfileOptions) -> OperationResult[SharedProfilesData]:
    """Record what a profile satisfies and, when asked, create or upgrade its environment now.

    :param name: the profile name.
    :param options: the declaration and the operation options.
    :returns: the result listing the profile.
    :raises PipxError: when the declaration is invalid or the operation fails.
    """
    validated: Final[str] = validate_profile_name(name)
    # validate before touching the environment so a rejected declaration leaves everything as it was
    shared: Final[_SharedLibs] = shared_libs_for(validated)
    previous: Final[Profile] = load(validated)
    overridden: Final[bool] = check_pip_override(
        _synthetic(validated, options.requires), options.pip_args, force=options.force
    )
    base: Final[Profile] = declare(
        validated,
        requires=options.requires,
        python_requires=options.python_requires,
        pip_version=previous.pip_version,
        python_version=previous.python_version,
    )

    messages: Final[list[OutputMessage]] = []
    if options.apply:
        if shared.is_valid:
            shared.upgrade(verbose=options.verbose, pip_args=options.pip_args, raises=True, override=overridden)
        else:
            shared.create(verbose=options.verbose, pip_args=options.pip_args)
        _record_after_operation(base, shared, overridden=overridden)
        messages.append(OutputMessage(text=f"Applied shared profile {validated!r} in {shared.root}."))
    else:
        messages.append(OutputMessage(text=f"Declared shared profile {validated!r} in {base.root}."))
        messages.append(
            OutputMessage(
                text=(
                    f"Environments using it keep pip {previous.pip_version or 'as installed'}; "
                    f"run `pipx profile upgrade {validated}` to install {base.requires}."
                ),
                notice=True,
            )
        )
    return OperationResult(
        command=("profile", "declare"),
        data=SharedProfilesData(profiles=(_row(validated),)),
        messages=tuple(messages),
    )


def _synthetic(name: str, requires: str) -> Profile:
    return Profile(name=name, root=profile_root(name), requires=requires, registered=True)


def _record_after_operation(profile: Profile, shared: _SharedLibs, *, overridden: bool = False) -> None:
    from pipx.shared_profiles import write  # ruff:ignore[import-outside-top-level]  # only the mutating commands write

    write(
        bump(
            profile,
            pip_version=installed_pip_version(shared.root),
            overridden=overridden,
        )
    )


def upgrade_profile(name: str, options: SharedProfileOptions) -> OperationResult[SharedProfilesData]:
    """Upgrade one profile's environment, leaving every other profile alone.

    :param name: the profile name.
    :param options: the operation options.
    :returns: the result listing the profile.
    :raises PipxError: when the profile is undeclared, the override crosses its declaration, or the upgrade fails.
    """
    validated: Final[str] = validate_profile_name(name)
    profile: Final[Profile] = load(validated)
    if not profile.registered and profile.effective_requires is None:
        msg = (
            f"Shared profile {validated!r} has no declaration. Declare it first with "
            f"`pipx profile declare {validated} --requires 'pip<X.Y'`."
        )
        raise PipxError(msg)
    overridden: Final[bool] = check_pip_override(profile, options.pip_args, force=options.force)
    shared: Final[_SharedLibs] = shared_libs_for(validated)
    shared.upgrade(verbose=options.verbose, pip_args=options.pip_args, raises=True, override=overridden)
    _record_after_operation(profile, shared, overridden=overridden)
    return OperationResult(
        command=("profile", "upgrade"),
        data=SharedProfilesData(profiles=(_row(validated),)),
        messages=(OutputMessage(text=f"Upgraded shared profile {validated!r} in {shared.root}."),),
    )


def reclaim_profile(name: str, *, dry_run: bool) -> OperationResult[SharedProfilesData]:
    """Remove one profile's environment when no environment references it.

    :param name: the profile name.
    :param dry_run: report what would be removed without removing it.
    :returns: the result listing the profile.
    :raises PipxError: when the profile is the default or is still referenced.
    """
    validated: Final[str] = validate_profile_name(name)
    if validated == DEFAULT_PROFILE:
        msg = "The default shared profile is never reclaimed; use `pipx reset` to remove all of pipx's state."
        raise PipxError(msg)
    referencing: Final[tuple[str, ...]] = referencing_environments(validated)
    if referencing:
        msg = (
            f"Shared profile {validated!r} is still used by {', '.join(referencing)}. "
            "Reinstall those environments onto another profile before reclaiming it."
        )
        raise PipxError(msg)
    root: Final = profile_root(validated)
    if not root.is_dir():
        msg = f"Shared profile {validated!r} has no environment to reclaim."
        raise PipxError(msg)
    if not dry_run:
        from pipx.trash import rmdir_via_trash  # ruff:ignore[import-outside-top-level]  # only reclamation removes

        rmdir_via_trash(root)
    action: Final[str] = "Would reclaim" if dry_run else "Reclaimed"
    return OperationResult(
        command=("profile", "reclaim"),
        data=SharedProfilesData(profiles=()),
        messages=(OutputMessage(text=f"{action} shared profile {validated!r} at {root}."),),
    )


def gc_profiles(*, dry_run: bool) -> OperationResult[SharedProfilesData]:
    """Reclaim every non-default profile that no environment references.

    :param dry_run: report what would be removed without removing it.
    :returns: the result listing the reclaimed profiles.
    """
    candidates: Final[tuple[Profile, ...]] = gc_candidates()
    removed: Final[list[_ProfileRow]] = []
    errors: Final[list[OperationError]] = []
    for profile in candidates:
        try:
            reclaim_profile(profile.name, dry_run=dry_run)
        except PipxError as error:
            errors.append(OperationError(code="profile_reclaim_failed", message=str(error), environment=profile.name))
        else:
            removed.append(_row(profile.name))
    verb: Final[str] = "Would reclaim" if dry_run else "Reclaimed"
    if not candidates:
        text: Final[str] = "No unused shared profiles to reclaim."
    elif errors:
        text = f"{verb} {len(removed)} of {len(candidates)} unused shared profile(s)."
    else:
        text = f"{verb} {len(removed)} unused shared profile(s): {', '.join(row.name for row in removed)}."
    return OperationResult(
        command=("profile", "gc"),
        data=SharedProfilesData(profiles=tuple(removed)),
        messages=(OutputMessage(text=text),),
        exit_code=ExitCode(1) if errors else EXIT_CODE_OK,
        errors=tuple(errors),
        succeeded=bool(removed),
    )


__all__ = [
    "SharedProfilesData",
    "declare_profile",
    "gc_profiles",
    "list_profiles",
    "reclaim_profile",
    "upgrade_profile",
]
