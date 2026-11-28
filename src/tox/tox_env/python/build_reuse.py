"""Track the build dependencies a package was built with, and decide when tox may reuse it.

The ledger lives outside the packaging environment, so recreating that environment keeps earlier package records and
artifacts available for comparison. Each artifact gets a provenance document next to it that states the build dependency
versions and approval records the build used.
"""

from __future__ import annotations

__lazy_modules__ = [
    "datetime",
    "hashlib",
    "importlib.metadata",
    "json",
    "os",
    "packaging.utils",
    "pathlib",
    "tempfile",
    "zipfile",
    "tox.util.path",
    "collections",
]

import hashlib
import json
import os
import tempfile
from collections.abc import Mapping
from datetime import datetime, timezone
from importlib.metadata import distributions
from pathlib import Path
from typing import TYPE_CHECKING, Final
from zipfile import BadZipFile, ZipFile

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from tox.util.path import ensure_private_dir

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

_LEDGER_VERSION: Final[int] = 1
_MAX_DECISIONS: Final[int] = 200
_PROVENANCE_SUFFIX: Final[str] = ".provenance.json"
_ARCHIVE_DIR: Final[str] = "artifacts"
_LEDGER_FILE: Final[str] = "ledger.json"
_SKIP_DIRECTORIES: Final[frozenset[str]] = frozenset({
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
})


class BuildApprovalError(ValueError):
    """A build dependency approval record is missing or malformed."""


def file_sha256(path: Path) -> str:
    """Compute the SHA-256 digest of a file.

    :param path: the file to read

    :returns: the hexadecimal digest

    """
    digest = hashlib.sha256()
    with path.open("rb") as file_handler:
        for chunk in iter(lambda: file_handler.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_digest(root: Path, exclude: Sequence[Path] = ()) -> str:
    """Compute a digest over the source files of a project.

    Symbolic links contribute their target text instead of the content they point at, so a link cannot pull files from
    outside the project into the digest. Directories excluded from the build, such as the work directory and dependency
    inputs, are skipped.

    :param root: the source directory to read
    :param exclude: the files or directories to leave out

    :returns: the hexadecimal digest

    """
    excluded = {_resolve(item) for item in exclude}
    digest = hashlib.sha256()
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        current = _resolve(Path(directory))
        if current in excluded:
            dirnames[:] = []
            continue
        dirnames[:] = sorted(
            name for name in dirnames if name not in _SKIP_DIRECTORIES and current / name not in excluded
        )
        for filename in sorted(filenames):
            path = Path(directory) / filename
            if _resolve(path) in excluded:
                continue
            digest.update(path.relative_to(root).as_posix().encode())
            digest.update(b"\0")
            if path.is_symlink():
                digest.update(b"link\0")
                digest.update(os.readlink(path).encode())
            else:
                try:
                    size = path.stat().st_size
                except OSError:
                    size = 0
                digest.update(str(size).encode())
                digest.update(b"\0")
                try:
                    with path.open("rb") as file_handler:
                        for chunk in iter(lambda: file_handler.read(1 << 20), b""):
                            digest.update(chunk)
                except OSError:
                    digest.update(b"unreadable")
            digest.update(b"\0")
    return digest.hexdigest()


def _resolve(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:  # a dangling link or an unavailable path keeps its literal form
        return path


def installed_versions(site_dirs: Iterable[Path]) -> dict[str, str]:
    """Read the versions installed in the given site directories, without running the environment.

    :param site_dirs: the site package directories to read

    :returns: the versions keyed by normalized project name

    """
    result: dict[str, str] = {}
    seen: set[str] = set()
    for site_dir in site_dirs:
        if not site_dir.is_dir():
            continue
        for distribution in distributions(path=[str(site_dir)]):
            name = distribution.metadata["Name"]
            version = distribution.version
            if not name or not version:  # pragma: no branch  # incomplete metadata
                continue
            normalized = canonicalize_name(name)
            if normalized in seen:
                continue
            seen.add(normalized)
            result[normalized] = version
    return result


def restrict_resolved(declared: Sequence[str], resolved: Mapping[str, str]) -> dict[str, str]:
    """Keep only the installed versions of the declared build requirements.

    :param declared: the requested build requirements
    :param resolved: the installed versions keyed by normalized project name

    :returns: the matching versions

    """
    names: set[str] = set()
    for entry in declared:
        try:
            names.add(canonicalize_name(Requirement(entry).name))
        except InvalidRequirement:  # a bare path names no project
            continue
    return {name: version for name, version in resolved.items() if name in names}


def load_approvals(path: Path) -> list[dict[str, object]]:
    """Load the build dependency approval records from a JSON document.

    :param path: the approval file

    :returns: one record per approval, sorted by normalized project name

    :raises tox.tox_env.python.build_reuse.BuildApprovalError: when the document is missing or malformed

    """
    if path.is_symlink():
        msg = f"build dependency approval file {path} is a link"
        raise BuildApprovalError(msg)
    try:
        content = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exception:
        msg = f"build dependency approval file {path} does not exist"
        raise BuildApprovalError(msg) from exception
    except (OSError, ValueError) as exception:
        msg = f"cannot read build dependency approval file {path}: {exception}"
        raise BuildApprovalError(msg) from exception
    if not isinstance(content, dict) or not isinstance(entries := content.get("approvals"), list):
        msg = f"build dependency approval file {path} must hold an 'approvals' list"
        raise BuildApprovalError(msg)
    records: list[dict[str, object]] = []
    names: set[str] = set()
    for at, entry in enumerate(entries):
        if not isinstance(entry, dict):
            msg = f"approval #{at} in {path} must be an object"
            raise BuildApprovalError(msg)
        record = _approval_record(entry, path, at)
        name = str(record["name"])
        if name in names:
            msg = f"duplicate approval for {name} in {path}"
            raise BuildApprovalError(msg)
        names.add(name)
        records.append(record)
    return sorted(records, key=lambda item: str(item["name"]))


def _approval_record(entry: Mapping[str, object], path: Path, at: int) -> dict[str, object]:
    name = entry.get("name")
    specifier = entry.get("specifier")
    approved_by = entry.get("approved_by")
    approved_at = entry.get("approved_at")
    if not isinstance(name, str) or not name.strip():
        msg = f"approval #{at} in {path} needs a project name"
        raise BuildApprovalError(msg)
    if not isinstance(specifier, str) or not specifier.strip():
        msg = f"approval #{at} in {path} needs a PEP 440 specifier"
        raise BuildApprovalError(msg)
    if not specifier.strip().startswith(("==", "!=", "<=", ">=", "<", ">", "~=", "===")):
        msg = f"approval for {name} in {path} has an invalid specifier {specifier!r}: expected a comparison operator"
        raise BuildApprovalError(msg)
    if not isinstance(approved_by, str) or not approved_by.strip():
        msg = f"approval #{at} in {path} needs an approved_by record"
        raise BuildApprovalError(msg)
    if not isinstance(approved_at, str) or not approved_at.strip():
        msg = f"approval #{at} in {path} needs an approved_at record"
        raise BuildApprovalError(msg)
    try:
        requirement = Requirement(f"{name}{specifier}")
    except InvalidRequirement as exception:
        msg = f"approval for {name} in {path} has an invalid specifier {specifier!r}: {exception}"
        raise BuildApprovalError(msg) from exception
    record: dict[str, object] = {
        "name": canonicalize_name(requirement.name),
        "specifier": specifier.strip(),
        "approved_by": approved_by.strip(),
        "approved_at": approved_at.strip(),
    }
    for optional in ("ticket", "note"):
        value = entry.get(optional)
        if isinstance(value, str) and value.strip():
            record[optional] = value.strip()
    return record


def evaluate_approvals(
    approvals: Sequence[Mapping[str, object]],
    declared: Sequence[str],
    resolved: Mapping[str, str],
    *,
    configured: bool,
) -> tuple[bool, list[str], list[dict[str, object]]]:
    """Check that the resolved build dependencies meet their approval records.

    :param approvals: the loaded approval records
    :param declared: the requested build requirements
    :param resolved: the installed versions keyed by normalized project name
    :param configured: whether an approval file was configured

    :returns: whether every declared dependency is approved, the unmet descriptions, and the approval records that apply

    """
    if not configured:
        return True, [], []
    by_name = {canonicalize_name(str(item["name"])): item for item in approvals}
    unmet: list[str] = []
    applied: list[dict[str, object]] = []
    names: list[str] = []
    for entry in declared:
        try:
            name = canonicalize_name(Requirement(entry).name)
        except InvalidRequirement:  # a bare path names no project, so no approval can apply
            continue
        if name not in names:
            names.append(name)
    for name in sorted(names):
        version = resolved.get(name)
        record = by_name.get(name)
        if record is None:
            unmet.append(f"{name} (no approval record)")
        elif version is None:
            unmet.append(f"{name}{record['specifier']} (not installed)")
        elif not Requirement(f"{name}{record['specifier']}").specifier.contains(version, prereleases=True):
            unmet.append(f"{name}{record['specifier']} (resolved {version})")
        else:
            applied.append(dict(record))
    return not unmet, unmet, applied


def dependency_records(
    declared: Sequence[str], resolved: Mapping[str, str], approvals: Sequence[Mapping[str, object]]
) -> list[dict[str, object]]:
    """Describe the build dependencies a build requested and the versions that were installed.

    :param declared: the requested build requirements
    :param resolved: the installed versions keyed by normalized project name
    :param approvals: the approval records that applied to the build

    :returns: one record per declared dependency, sorted by name

    """
    approval_by_name = {canonicalize_name(str(item["name"])): item for item in approvals}
    requests: dict[str, str] = {}
    for entry in declared:
        try:
            name = canonicalize_name(Requirement(entry).name)
        except InvalidRequirement:  # a bare path names no project
            continue
        requests.setdefault(name, entry)
    result: list[dict[str, object]] = []
    for name, request in sorted(requests.items()):
        version = resolved.get(name)
        approval = approval_by_name.get(name)
        approved = approval is not None and version is not None and Requirement(
            f"{name}{approval['specifier']}"
        ).specifier.contains(version, prereleases=True)
        result.append({
            "name": name,
            "requested": request,
            "resolved": version,
            "approval": dict(approval) if approval is not None else None,
            "approved": approved,
        })
    return result


def source_change_reasons(
    records: Iterable[Mapping[str, object]], *, source: str, package_type: str, backend: str
) -> list[str]:
    """Describe a recorded build of the same package type for another source.

    :param records: the ledger records
    :param source: the digest of the current source files
    :param package_type: the current package type
    :param backend: the current build backend

    :returns: the reason a changed source blocks reuse, empty when no earlier build exists

    """
    for record in records:
        if record.get("package_type") != package_type or record.get("backend") != backend:
            continue
        previous = record.get("source")
        if isinstance(previous, str) and previous != source:
            return [f"source changed since the last build ({previous[:12]} -> current)"]
    return []


def reuse_key(package_type: str, backend: str, source: str, target: Mapping[str, object]) -> str:
    """Build the identity of a package built from the same source for the same target.

    :param package_type: the package type, such as ``wheel``
    :param backend: the build backend key
    :param source: the digest of the source files
    :param target: the target environment descriptor

    :returns: the hexadecimal identity

    """
    material = json.dumps(
        {"package_type": package_type, "backend": backend, "source": source, "target": dict(target)},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode()).hexdigest()


def diff_record(
    record: Mapping[str, object],
    *,
    declared: Sequence[str],
    resolved: Mapping[str, str],
    approvals: Sequence[Mapping[str, object]],
    unmet: Sequence[str],
) -> list[str]:
    """List why an existing package record no longer matches the current build inputs.

    :param record: the recorded provenance
    :param declared: the current build requirements
    :param resolved: the currently installed versions keyed by normalized project name
    :param approvals: the current approval records
    :param unmet: the current approvals that do not hold

    :returns: the reasons the package cannot be reused, empty when it can

    """
    reasons: list[str] = []
    old_declared = _string_list(record.get("declared"))
    if old_declared != list(declared):
        added = sorted(set(declared) - set(old_declared))
        removed = sorted(set(old_declared) - set(declared))
        detail = ", ".join(
            part
            for part in (
                f"added {', '.join(added)}" if added else "",
                f"removed {', '.join(removed)}" if removed else "",
            )
            if part
        )
        reasons.append(f"build requirements changed ({detail})")
    if _approval_signature(record.get("approvals")) != _approval_signature(approvals):
        reasons.append("build dependency approvals changed")
    old_resolved = {
        str(item["name"]): item.get("resolved")
        for item in _mapping_list(record.get("dependencies"))
        if "name" in item
    }
    for name in sorted(set(old_resolved) | set(resolved)):
        if name not in old_resolved:
            reasons.append(f"build dependency added: {name} {resolved[name]}")
        elif name not in resolved:
            reasons.append(f"build dependency removed: {name} {old_resolved[name]}")
        elif old_resolved[name] != resolved[name]:
            reasons.append(f"build dependency revision changed: {name} {old_resolved[name]} -> {resolved[name]}")
    reasons.extend(f"build dependency approval not satisfied: {item}" for item in unmet)
    return reasons


def _string_list(value: object) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def _mapping_list(value: object) -> list[Mapping[str, object]]:
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, list) else []


def _approval_signature(values: object) -> list[tuple[str, str, str, str]]:
    if not isinstance(values, list):
        return []
    return sorted(
        (
            str(item.get("name")),
            str(item.get("specifier")),
            str(item.get("approved_by")),
            str(item.get("approved_at")),
        )
        for item in values
        if isinstance(item, Mapping)
    )


def target_change_reasons(
    records: Iterable[Mapping[str, object]],
    *,
    source: str,
    package_type: str,
    backend: str,
    target: Mapping[str, object],
) -> list[str]:
    """Describe a matching build that targeted another environment.

    :param records: the ledger records
    :param source: the digest of the current source files
    :param package_type: the current package type
    :param backend: the current build backend
    :param target: the current target environment descriptor

    :returns: the reasons another target blocks reuse, empty when none matches

    """
    for record in records:
        if (
            record.get("source") != source
            or record.get("package_type") != package_type
            or record.get("backend") != backend
        ):
            continue
        old_target = record.get("target")
        if isinstance(old_target, Mapping) and dict(old_target) != dict(target):
            old = f"{old_target.get('implementation')} {old_target.get('version')}"
            new = f"{target.get('implementation')} {target.get('version')}"
            return [f"target environment changed: {old} -> {new}"]
    return []


def read_wheel_metadata(path: Path) -> tuple[str | None, str | None]:
    """Read the project name and version from the metadata of a wheel.

    :param path: the wheel file

    :returns: the name and version, ``None`` when either is missing

    """
    try:
        with ZipFile(path) as wheel:
            metadata_name = next((name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")), None)
            if metadata_name is None:
                return None, None
            text = wheel.read(metadata_name).decode("utf-8", "replace")
    except (BadZipFile, OSError):
        return None, None
    name = version = None
    for line in text.splitlines():
        if line.startswith("Name: "):
            name = line[len("Name: ") :].strip()
        elif line.startswith("Version: "):
            version = line[len("Version: ") :].strip()
    return name, version


def provenance_path(artifact: Path) -> Path:
    """Get the path of the provenance document that belongs to an artifact.

    The document sits next to the archived copy, so the build directory keeps only the package a user expects.

    :param artifact: the artifact path

    :returns: the sidecar path

    """
    return artifact.with_name(f"{artifact.name}{_PROVENANCE_SUFFIX}")


def write_json(path: Path, value: object) -> None:
    """Write a JSON document, replacing the path itself so a link cannot redirect the write.

    :param path: the file to write
    :param value: the JSON value

    """
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f"{path.name}.", suffix=".tmp")
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handler:
            json.dump(value, handler, indent=2, sort_keys=True)
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)


class BuildReuseStore:
    """The on-disk ledger of built packages, their artifacts, and the decisions taken about reusing them.

    :param root: the directory that holds the ledger and the archived artifacts

    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.entries: dict[str, list[dict[str, object]]] = {}
        self.decisions: list[dict[str, object]] = []
        self._load()

    @property
    def _path(self) -> Path:
        return self.root / _LEDGER_FILE

    def _load(self) -> None:
        if self._path.is_symlink():
            return  # never read a ledger another account planted as a link
        try:
            content = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(content, dict):
            return
        entries = content.get("entries")
        if isinstance(entries, dict):
            self.entries = {
                str(key): [item for item in value if isinstance(item, dict)]
                for key, value in entries.items()
                if isinstance(value, list)
            }
        decisions = content.get("decisions")
        if isinstance(decisions, list):
            self.decisions = [item for item in decisions if isinstance(item, dict)]

    def latest(self, key: str) -> dict[str, object] | None:
        """Get the most recent record for a package identity.

        :param key: the package identity

        :returns: the record, ``None`` when the identity was never built

        """
        entries = self.entries.get(key, [])
        return entries[-1] if entries else None

    def all_records(self) -> Iterable[dict[str, object]]:
        """:returns: every recorded package, newest last per identity"""
        for entries in self.entries.values():
            yield from entries

    def add_entry(self, key: str, record: dict[str, object]) -> None:
        """Append a built package record, keeping earlier revisions for comparison.

        :param key: the package identity
        :param record: the record to add

        """
        self.entries.setdefault(key, []).append(record)

    def add_decision(self, item: dict[str, object]) -> None:
        """Append a reuse or rebuild decision.

        :param item: the decision to add

        """
        self.decisions.append(item)
        del self.decisions[:-_MAX_DECISIONS]

    def archive(self, artifact: Path) -> Path:
        """Copy an artifact into the store, keyed by its digest, and return the archived path.

        The artifact keeps its original file name, so installers still read the distribution name from it.

        :param artifact: the artifact to archive

        :returns: the archived path, relative to the store root

        """
        digest = file_sha256(artifact)
        target_dir = self.root / _ARCHIVE_DIR / digest
        ensure_private_dir(target_dir)
        target = target_dir / artifact.name
        if not target.exists() or file_sha256(target) != digest:
            file_descriptor, temporary_name = tempfile.mkstemp(
                dir=target_dir, prefix=f"{artifact.name}.", suffix=".tmp"
            )
            temporary_path = Path(temporary_name)
            try:
                with artifact.open("rb") as source, os.fdopen(file_descriptor, "wb") as handler:
                    for chunk in iter(lambda: source.read(1 << 20), b""):
                        handler.write(chunk)
                temporary_path.replace(target)
            finally:
                temporary_path.unlink(missing_ok=True)
        return target

    def artifact_path(self, record: Mapping[str, object]) -> Path | None:
        """Resolve the archived artifact of a record.

        :param record: the provenance document

        :returns: the artifact path, ``None`` when it is missing or was changed

        """
        name = record.get("artifact")
        digest = record.get("artifact_sha256")
        if not isinstance(name, str) or not isinstance(digest, str):
            return None
        artifact = self.root / _ARCHIVE_DIR / digest / name
        if not artifact.is_file() or file_sha256(artifact) != digest:
            return None
        return artifact

    def save(self) -> None:
        """Write the ledger."""
        ensure_private_dir(self.root)
        write_json(
            self._path,
            {"version": _LEDGER_VERSION, "entries": self.entries, "decisions": self.decisions},
        )


def decision(
    *,
    mode: str,
    key: str,
    reasons: Sequence[str],
    artifact: str | None,
    record: Mapping[str, object] | None,
) -> dict[str, object]:
    """Describe a package reuse decision in a form both the journal and the ledger can hold.

    :param mode: ``reuse`` or ``rebuild``
    :param key: the package identity
    :param reasons: why the package was rebuilt
    :param artifact: the artifact file name
    :param record: the provenance that either justified the reuse or was just written

    :returns: the decision

    """
    return {
        "mode": mode,
        "key": key,
        "reasons": list(reasons),
        "artifact": artifact,
        "provenance": dict(record) if record is not None else None,
        "created": datetime.now(timezone.utc).isoformat(),
    }


__all__ = [
    "BuildApprovalError",
    "BuildReuseStore",
    "decision",
    "dependency_records",
    "diff_record",
    "evaluate_approvals",
    "file_sha256",
    "installed_versions",
    "load_approvals",
    "provenance_path",
    "read_wheel_metadata",
    "restrict_resolved",
    "reuse_key",
    "source_change_reasons",
    "source_digest",
    "target_change_reasons",
    "write_json",
]
