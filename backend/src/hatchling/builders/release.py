from __future__ import annotations

import json
import os
import re
import shutil
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

if TYPE_CHECKING:
    from collections.abc import Iterator

    from hatchling.metadata.core import ProjectMetadata

# Release approval is opt-in through the ``tool.hatch.build.release`` table. A target may override
# the global table with ``tool.hatch.build.targets.<TARGET>.release``. Each channel is a named
# approval rule and is evaluated against the *actual* version recorded in the built artifact, never
# against a version that was merely configured or expected beforehand.
RELEASE_CONFIG = "release"
CHANNEL_KEY = "channels"
APPROVED_KEY = "approved"

# Build data field through which a build hook may declare the version that should be written to the
# artifact metadata. The approval gate always re-reads the artifact, so a declaration made during
# the build cannot widen the approval that was granted before the build started.
BUILD_DATA_VERSION_KEY = "declared_version"

REPORT_FILE_NAME = "release-approval.json"
REJECTED_DIRECTORY = "release-rejected"

STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_INDETERMINATE = "indeterminate"

METADATA_VERSION_PATTERN = re.compile(r"(?m)^Version:\s*(?P<version>\S+)\s*$")


@dataclass
class ChannelRule:
    name: str
    allow_prerelease: bool = False
    allow_local: bool = False
    version_specifier: SpecifierSet | None = None

    @property
    def definition(self) -> dict[str, Any]:
        definition: dict[str, Any] = {
            "name": self.name,
            "allow-prerelease": self.allow_prerelease,
            "allow-local": self.allow_local,
        }
        if self.version_specifier is not None:
            definition["version"] = str(self.version_specifier)

        return definition

    def evaluate(self, version: str) -> tuple[bool, str]:
        """
        Return whether ``version`` is approved by this rule and, when it is not, a reason that stays
        local to this target and rule.
        """
        try:
            parsed = Version(version)
        except InvalidVersion:
            return False, f"version `{version}` is not a valid PEP 440 version"

        if parsed.is_devrelease:
            if not self.allow_prerelease:
                return False, f"version `{version}` is a development release and channel `{self.name}` forbids it"
        elif parsed.is_prerelease and not self.allow_prerelease:
            return False, f"version `{version}` is a prerelease and channel `{self.name}` forbids it"

        if parsed.local is not None and not self.allow_local:
            return False, f"version `{version}` has a local segment and channel `{self.name}` forbids it"

        if self.version_specifier is not None and not self.version_specifier.contains(version, prereleases=True):
            return (
                False,
                f"version `{version}` does not match channel `{self.name}` specifier `{self.version_specifier}`",
            )

        return True, ""


@dataclass
class ReleaseConfig:
    channels: dict[str, ChannelRule] = field(default_factory=dict)

    def channel_for(self, version: str) -> ChannelRule | None:
        """Return the first channel (in declaration order) that approves ``version``."""
        for rule in self.channels.values():
            approved, _ = rule.evaluate(version)
            if approved:
                return rule

        return None

    @property
    def definition(self) -> dict[str, Any]:
        return {"channels": [rule.definition for rule in self.channels.values()]}


@dataclass
class ReleaseDecision:
    target: str
    version: str
    status: str
    channel: str | None = None
    reason: str = ""
    project: str | None = None
    artifact: str | None = None
    prepared_version: str | None = None
    changed_after_preparation: bool = False
    rules: list[dict[str, Any]] = field(default_factory=list)

    @property
    def approved(self) -> bool:
        return self.status == STATUS_APPROVED

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "target": self.target,
            "version": self.version,
            "status": self.status,
            "channel": self.channel,
            "reason": self.reason,
            "rules": self.rules,
        }
        if self.project is not None:
            data["project"] = self.project
        if self.artifact is not None:
            data["artifact"] = self.artifact
        if self.prepared_version is not None:
            data["prepared-version"] = self.prepared_version
            data["changed-after-preparation"] = self.changed_after_preparation

        return data


def _as_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        message = f"Field `{field_name}` must be a boolean"
        raise TypeError(message)

    return value


def load_release_config(
    build_config: dict[str, Any], target_config: dict[str, Any] | None = None
) -> ReleaseConfig | None:
    """
    Parse the release approval table for a single target. The target table takes precedence over the
    global ``tool.hatch.build.release`` table. Return ``None`` when approval is not enabled so that
    dynamic version sources and ordinary builds keep working untouched.
    """
    if target_config is not None and RELEASE_CONFIG in target_config:
        raw = target_config[RELEASE_CONFIG]
        location = f"tool.hatch.build.targets.<target>.{RELEASE_CONFIG}"
    elif RELEASE_CONFIG in build_config:
        raw = build_config[RELEASE_CONFIG]
        location = f"tool.hatch.build.{RELEASE_CONFIG}"
    else:
        return None

    if not isinstance(raw, dict):
        message = f"Field `{location}` must be a table"
        raise TypeError(message)

    raw_channels = raw.get(CHANNEL_KEY)
    if raw_channels is None:
        message = f"Field `{location}.{CHANNEL_KEY}` is required when `{location}` is defined"
        raise ValueError(message)

    if not isinstance(raw_channels, dict):
        message = f"Field `{location}.{CHANNEL_KEY}` must be a table"
        raise TypeError(message)

    channels: dict[str, ChannelRule] = {}
    for name, data in raw_channels.items():
        if not isinstance(data, dict):
            message = f"Field `{location}.{CHANNEL_KEY}.{name}` must be a table"
            raise TypeError(message)

        prefix = f"{location}.{CHANNEL_KEY}.{name}"
        if not _as_bool(data.get(APPROVED_KEY, False), f"{prefix}.{APPROVED_KEY}"):
            continue

        allow_prerelease = _as_bool(data.get("allow-prerelease", False), f"{prefix}.allow-prerelease")
        allow_local = _as_bool(data.get("allow-local", False), f"{prefix}.allow-local")

        raw_version = data.get("version")
        version_specifier: SpecifierSet | None = None
        if raw_version is not None:
            if not isinstance(raw_version, str):
                message = f"Field `{prefix}.version` must be a string"
                raise TypeError(message)

            try:
                version_specifier = SpecifierSet(raw_version)
            except InvalidSpecifier as e:
                message = f"Field `{prefix}.version` is not a valid specifier: {e}"
                raise ValueError(message) from None

        channels[name] = ChannelRule(
            name=name,
            allow_prerelease=allow_prerelease,
            allow_local=allow_local,
            version_specifier=version_specifier,
        )

    return ReleaseConfig(channels=channels)


def normalize_version(version: str) -> str:
    try:
        return str(Version(version))
    except InvalidVersion:
        return version


def evaluate_version(
    config: ReleaseConfig | None,
    target: str,
    version: str,
    *,
    project: str | None = None,
    artifact: str | None = None,
    prepared_version: str | None = None,
) -> ReleaseDecision:
    """
    Evaluate an already resolved version against the configured channels. This never resolves the
    version itself, so callers can feed it the version read back from an actual artifact.
    """
    rules = [rule.definition for rule in config.channels.values()] if config is not None else []
    changed = prepared_version is not None and normalize_version(prepared_version) != normalize_version(version)
    common: dict[str, Any] = {
        "project": project,
        "artifact": artifact,
        "prepared_version": prepared_version,
        "changed_after_preparation": changed,
        "rules": rules,
    }

    if config is None:
        return ReleaseDecision(
            target=target,
            version=version,
            status=STATUS_INDETERMINATE,
            reason="release approval is not configured",
            **common,
        )

    if not config.channels:
        return ReleaseDecision(
            target=target,
            version=version,
            status=STATUS_REJECTED,
            reason="no channel is approved for release",
            **common,
        )

    rule = config.channel_for(version)
    if rule is not None:
        return ReleaseDecision(
            target=target,
            version=version,
            status=STATUS_APPROVED,
            channel=rule.name,
            **common,
        )

    reasons = []
    for candidate in config.channels.values():
        _, reason = candidate.evaluate(version)
        if reason:
            reasons.append(reason)

    return ReleaseDecision(
        target=target,
        version=version,
        status=STATUS_REJECTED,
        reason="; ".join(reasons),
        **common,
    )


def read_artifact_version(path: str) -> str:
    """Read the ``Version`` field from a built wheel or sdist without trusting its file name."""
    if path.endswith(".whl"):
        return _read_wheel_version(path)

    if path.endswith(".tar.gz"):
        return _read_sdist_version(path)

    message = f"Unsupported artifact type: {path}"
    raise ValueError(message)


def _read_wheel_version(path: str) -> str:
    import zipfile

    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            root = name.split("/", 1)[0]
            if root.endswith(".dist-info") and name == f"{root}/METADATA":
                return _extract_version(archive.read(name).decode("utf-8"), path)

    message = f"Could not find a `METADATA` file in wheel: {path}"
    raise ValueError(message)


def _read_sdist_version(path: str) -> str:
    import tarfile

    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            if member.isfile() and member.name.count("/") == 1 and member.name.endswith("/PKG-INFO"):
                extracted = archive.extractfile(member)
                if extracted is not None:
                    return _extract_version(extracted.read().decode("utf-8"), path)

    message = f"Could not find a `PKG-INFO` file in sdist: {path}"
    raise ValueError(message)


def _extract_version(metadata: str, path: str) -> str:
    match = METADATA_VERSION_PATTERN.search(metadata)
    if match is None:
        message = f"Could not find a `Version` field in artifact metadata: {path}"
        raise ValueError(message)

    return match.group("version")


def decide_artifact(
    config: ReleaseConfig | None,
    target: str,
    artifact: str,
    *,
    project: str | None,
    prepared_version: str | None,
) -> ReleaseDecision:
    """
    Read the actual version from ``artifact`` and decide its release status. Failures to read the
    metadata produce an ``indeterminate`` decision that keeps the local reason instead of raising, so
    one unreadable artifact never aborts the other targets sharing a workspace.
    """
    artifact_name = os.path.basename(artifact)
    try:
        actual_version = read_artifact_version(artifact)
    except Exception as e:  # noqa: BLE001
        decision = evaluate_version(
            config,
            target,
            "",
            project=project,
            artifact=artifact_name,
            prepared_version=prepared_version,
        )
        decision.status = STATUS_INDETERMINATE
        decision.reason = f"unable to read the artifact metadata: {e}"
        return decision

    return evaluate_version(
        config,
        target,
        actual_version,
        project=project,
        artifact=artifact_name,
        prepared_version=prepared_version,
    )


def finalize_artifact(
    directory: str,
    decision: ReleaseDecision,
    artifact: str,
) -> str:
    """
    Record ``decision`` in the exportable report and return the path the artifact now occupies.
    Approved artifacts stay in place; rejected or indeterminate artifacts are relocated so they
    cannot enter the release result while remaining available locally.
    """
    if decision.status != STATUS_APPROVED:
        decision.artifact = relocate_rejected(artifact, directory, decision.project)

    write_report(directory, [decision])
    if decision.status == STATUS_APPROVED:
        return artifact

    return os.path.join(directory, decision.artifact)


def load_report(directory: str, report_name: str = REPORT_FILE_NAME) -> dict[str, Any] | None:
    path = os.path.join(directory, report_name)
    if not os.path.isfile(path):
        return None

    with open(path, encoding="utf-8") as f:
        return json.load(f)


def merge_report_decisions(
    existing: dict[str, Any] | None,
    decisions: list[ReleaseDecision],
) -> dict[str, Any]:
    """
    Merge new decisions into an existing report. Each ``(project, target)`` entry is independent so
    that targets sharing a build directory never overwrite one another's outcome.
    """
    merged: dict[tuple[str | None, str], dict[str, Any]] = {}
    if existing is not None:
        for entry in existing.get("decisions", []):
            merged[(entry.get("project"), entry["target"])] = entry

    for decision in decisions:
        merged[(decision.project, decision.target)] = decision.to_dict()

    return {"version": 1, "decisions": list(merged.values())}


def write_report(
    directory: str,
    decisions: list[ReleaseDecision],
    report_name: str = REPORT_FILE_NAME,
) -> str | None:
    """
    Write an exportable rule report describing the decisions. Return ``None`` when there is nothing
    to write so that ordinary builds never gain a stray artifact.
    """
    if not decisions:
        return None

    os.makedirs(directory, exist_ok=True)
    payload = merge_report_decisions(load_report(directory, report_name), decisions)
    report_path = os.path.join(directory, report_name)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)

    return report_path


def prune_report(
    directory: str,
    project: str | None,
    target: str,
    report_name: str = REPORT_FILE_NAME,
) -> None:
    """Remove the decision for ``(project, target)`` so a clean build cannot inherit a stale one."""
    report = load_report(directory, report_name)
    if report is None:
        return

    remaining = {
        (entry.get("project"), entry["target"]): entry
        for entry in report.get("decisions", [])
        if (entry.get("project"), entry["target"]) != (project, target)
    }

    report_path = os.path.join(directory, report_name)
    if not remaining:
        os.remove(report_path)
        return

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump({"version": 1, "decisions": list(remaining.values())}, f, indent=2, sort_keys=True)


def relocate_rejected(artifact: str, directory: str, project: str | None) -> str:
    """
    Move a rejected artifact out of the release output so that it never enters the release result,
    while keeping it available locally (and pointing the report at it) for inspection.
    """
    rejected_root = os.path.join(directory, REJECTED_DIRECTORY)
    # Keep the artifact's own name; grouping by project keeps multiple rejected members distinct when
    # they share a build directory.
    if project:
        target = os.path.join(rejected_root, project, os.path.basename(artifact))
    else:
        target = os.path.join(rejected_root, os.path.basename(artifact))

    os.makedirs(os.path.dirname(target), exist_ok=True)
    shutil.move(artifact, target)
    return os.path.relpath(target, directory)


def expand_artifacts(paths: list[str], root: str | None = None) -> list[str]:
    """Expand directories into their wheel and sdist members while leaving files untouched."""
    expanded: list[str] = []
    for raw_path in paths:
        path = raw_path
        if not os.path.isabs(path) and root is not None:
            path = os.path.join(root, path)

        if os.path.isfile(path):
            expanded.append(path)
        elif os.path.isdir(path):
            expanded.extend(
                os.path.join(path, name)
                for name in sorted(os.listdir(path))
                if name.endswith((".whl", ".tar.gz"))
            )

    return expanded


def load_reports(directories: list[str], report_name: str = REPORT_FILE_NAME) -> dict[str, Any] | None:
    """Combine reports found in any of ``directories`` into a single merged report."""
    merged: dict[tuple[str | None, str], dict[str, Any]] = {}
    found = False
    for directory in directories:
        report = load_report(directory, report_name)
        if report is None:
            continue

        found = True
        for entry in report.get("decisions", []):
            merged[(entry.get("project"), entry["target"])] = entry

    if not found:
        return None

    return {"version": 1, "decisions": list(merged.values())}


def select_release_artifacts(
    paths: list[str],
    report: dict[str, Any] | None,
) -> tuple[list[str], list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Partition artifacts into release-eligible and held-back members using ``report``.

    Returns ``(approved_paths, rejected_entries, unknown_entries)``. When no report is available,
    every path is returned so projects without approval are unaffected. An artifact that has no
    matching decision cannot be proven approved and is therefore held back when a report exists.
    """
    if report is None:
        return paths, [], []

    decisions = report.get("decisions", [])
    by_artifact = {entry.get("artifact"): entry for entry in decisions if entry.get("artifact")}
    approved = [
        path
        for path in paths
        if (entry := by_artifact.get(os.path.basename(path))) is not None and entry.get("status") == STATUS_APPROVED
    ]
    held_back = [entry for entry in decisions if entry.get("status") != STATUS_APPROVED]
    unknown = [path for path in paths if os.path.basename(path) not in by_artifact]

    return approved, held_back, unknown


@contextmanager
def temporary_metadata_version(metadata: ProjectMetadata, version: str | None) -> Iterator[None]:
    """
    Temporarily expose ``version`` as the resolved project version so that artifact metadata and
    file names reflect a hook's declaration. All cached values are restored afterwards, keeping
    each target's decision independent.
    """
    if not version:
        yield
        return

    original_raw = metadata._original_version  # noqa: SLF001
    original_normalized = metadata._version  # noqa: SLF001

    # Materialize the core metadata so its cached version can be restored afterwards
    core = metadata.core
    core_raw = core._version  # noqa: SLF001
    core_set = core._version_set  # noqa: SLF001

    metadata._version = normalize_version(version)  # noqa: SLF001
    metadata._original_version = version.strip()  # noqa: SLF001
    core._version = version  # noqa: SLF001
    core._version_set = True  # noqa: SLF001

    try:
        yield
    finally:
        metadata._version = original_normalized  # noqa: SLF001
        metadata._original_version = original_raw  # noqa: SLF001
        core._version = core_raw  # noqa: SLF001
        core._version_set = core_set  # noqa: SLF001
