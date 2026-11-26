"""
Optional release approval verification.

A release pipeline can split metadata preparation (PEP 517
``prepare_metadata_for_build_wheel``) from the actual wheel build
(``build_wheel`` / ``build_editable``). Between the two steps a release
approval may be recorded for the prepared ``.dist-info`` directory.

When approval mode is enabled through ``config_settings`` the wheel build
verifies that the metadata it is about to ship still matches the approved
identity, dependencies and entry points. A description-only change can be
explicitly allowed through configuration. Any extra metadata files written
by the front-end (the approval tooling itself) are left untouched and end up
in the final wheel.
"""

from __future__ import annotations

import json

from dataclasses import dataclass
from email.message import Message
from email.parser import BytesParser
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Any


if TYPE_CHECKING:
    from poetry.core.masonry.builders.builder import Builder


APPROVAL_RECORD_FILE = "approval.json"

# config_settings keys
APPROVAL_MODE_SETTING = "approval-mode"
APPROVAL_METADATA_SETTING = "approval-metadata-directory"
ALLOW_DESCRIPTION_CHANGE_SETTING = "approval-allow-description-change"


class ApprovalError(RuntimeError):
    """Raised when the metadata to build does not match the approval."""


@dataclass(frozen=True)
class ApprovalRecord:
    """The subset of metadata that an approval pins down."""

    name: str
    version: str
    requires_dist: tuple[str, ...]
    provides_extra: tuple[str, ...]
    requires_python: str | None
    entry_points: tuple[str, ...]
    summary: str | None
    description: str | None

    @classmethod
    def from_dist_info(cls, dist_info: Path) -> ApprovalRecord:
        metadata = _parse_metadata(dist_info / "METADATA")
        entry_points_path = dist_info / "entry_points.txt"
        entry_points = (
            tuple(entry_points_path.read_text(encoding="utf-8").splitlines())
            if entry_points_path.is_file()
            else ()
        )
        return cls(
            name=_require_header(metadata, "Name", dist_info),
            version=_require_header(metadata, "Version", dist_info),
            requires_dist=tuple(metadata.get_all("Requires-Dist", [])),
            provides_extra=tuple(metadata.get_all("Provides-Extra", [])),
            requires_python=metadata.get("Requires-Python"),
            entry_points=_normalize_entry_points(entry_points),
            summary=metadata.get("Summary"),
            description=_normalize_body(metadata.get_payload()),
        )

    @classmethod
    def from_builder(cls, builder: Builder) -> ApprovalRecord:
        meta = builder._meta
        entry_points = tuple(
            line
            for group_name, specs in builder.convert_entry_points().items()
            for line in [f"[{group_name}]", *specs]
        )
        return cls(
            name=meta.name,
            version=meta.version,
            requires_dist=tuple(sorted(meta.requires_dist)),
            provides_extra=tuple(sorted(meta.provides_extra)),
            requires_python=meta.requires_python,
            entry_points=_normalize_entry_points(entry_points),
            summary=meta.summary,
            description=_normalize_body(meta.description),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "requires_dist": list(self.requires_dist),
            "provides_extra": list(self.provides_extra),
            "requires_python": self.requires_python,
            "entry_points": list(self.entry_points),
            "summary": self.summary,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ApprovalRecord:
        try:
            return cls(
                name=data["name"],
                version=data["version"],
                requires_dist=tuple(data.get("requires_dist", [])),
                provides_extra=tuple(data.get("provides_extra", [])),
                requires_python=data.get("requires_python"),
                entry_points=_normalize_entry_points(
                    tuple(data.get("entry_points", []))
                ),
                summary=data.get("summary"),
                description=data.get("description"),
            )
        except KeyError as e:
            raise ApprovalError(
                f"Approval record is missing the required key '{e.args[0]}'."
            ) from e


def _normalize_entry_points(lines: tuple[str, ...]) -> tuple[str, ...]:
    # The on-disk entry_points.txt is written without spaces around "=", while
    # convert_entry_points() keeps them. Compare on the canonical form.
    return tuple(line.replace(" ", "") for line in lines if line.strip())


def _normalize_body(value: str | None) -> str | None:
    if not value or not value.strip():
        return None
    return value.strip()


def write_approval(dist_info: Path) -> Path:
    """Create the approval record next to the prepared dist-info metadata."""
    record = ApprovalRecord.from_dist_info(dist_info)
    destination = dist_info / APPROVAL_RECORD_FILE
    destination.write_text(
        json.dumps(record.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return destination


def read_approval(dist_info: Path) -> ApprovalRecord:
    record_path = dist_info / APPROVAL_RECORD_FILE
    if not record_path.is_file():
        raise ApprovalError(
            f"Approval mode is enabled but no {APPROVAL_RECORD_FILE} was found in"
            f" '{dist_info}'."
        )
    try:
        data = json.loads(record_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ApprovalError(
            f"Approval record '{record_path}' is not valid JSON: {e.msg}."
        ) from e
    if not isinstance(data, dict):
        raise ApprovalError(
            f"Approval record '{record_path}' must contain a JSON object."
        )
    return ApprovalRecord.from_dict(data)


def approval_enabled(config_settings: dict[str, Any]) -> bool:
    return bool(config_settings.get(APPROVAL_MODE_SETTING))


def description_change_allowed(config_settings: dict[str, Any]) -> bool:
    return bool(config_settings.get(ALLOW_DESCRIPTION_CHANGE_SETTING))


def approved_dist_info(config_settings: dict[str, Any], fallback: Path) -> Path:
    """Resolve the dist-info directory carrying the approval.

    Front-ends pass the directory handed back by
    ``prepare_metadata_for_build_wheel`` through
    ``approval-metadata-directory``. When it is not provided the regular
    PEP 517 ``metadata_directory`` (already available on the builder) is used.
    """
    configured = config_settings.get(APPROVAL_METADATA_SETTING)
    return Path(configured) if configured else fallback


def verify_approval(
    builder: Builder,
    approved_dist_info_dir: Path,
    allow_description_change: bool = False,
) -> None:
    """Compare the metadata about to be built with the approved metadata."""
    approved = read_approval(approved_dist_info_dir)
    current = ApprovalRecord.from_builder(builder)

    differences = _collect_differences(
        approved, current, allow_description_change=allow_description_change
    )
    if differences:
        details = "\n".join(f"  - {difference}" for difference in differences)
        raise ApprovalError(
            "Package metadata does not match the approved release metadata:\n"
            f"{details}"
        )


def _collect_differences(
    approved: ApprovalRecord,
    current: ApprovalRecord,
    allow_description_change: bool,
) -> list[str]:
    differences: list[str] = []

    if approved.name != current.name:
        differences.append(
            f"name: approved '{approved.name}' but build produces '{current.name}'"
        )
    if approved.version != current.version:
        differences.append(
            "version: approved"
            f" '{approved.version}' but build produces '{current.version}'"
        )

    differences.extend(
        _field_differences(
            "Requires-Dist", approved.requires_dist, current.requires_dist
        )
    )
    differences.extend(
        _field_differences(
            "Provides-Extra", approved.provides_extra, current.provides_extra
        )
    )

    if approved.requires_python != current.requires_python:
        differences.append(
            "Requires-Python: approved"
            f" '{approved.requires_python}' but build produces"
            f" '{current.requires_python}'"
        )

    differences.extend(
        _field_differences(
            "entry points", approved.entry_points, current.entry_points
        )
    )

    if not allow_description_change:
        if approved.summary != current.summary:
            differences.append(
                f"Summary: approved '{approved.summary}' but build produces"
                f" '{current.summary}'"
            )
        if approved.description != current.description:
            differences.append("project description (readme) changed after approval")

    return differences


def _field_differences(
    label: str, approved: tuple[str, ...], current: tuple[str, ...]
) -> list[str]:
    approved_set = set(approved)
    current_set = set(current)
    differences: list[str] = []
    for missing in sorted(approved_set - current_set):
        differences.append(
            f"{label}: approved entry missing from build: '{missing}'"
        )
    for added in sorted(current_set - approved_set):
        differences.append(
            f"{label}: unapproved entry added by build: '{added}'"
        )
    return differences


def _parse_metadata(path: Path) -> Message:
    if not path.is_file():
        raise ApprovalError(f"Metadata file '{path}' does not exist.")
    return BytesParser().parsebytes(path.read_bytes())


def _require_header(metadata: Message, header: str, dist_info: Path) -> str:
    value = metadata.get(header)
    if value is None:
        raise ApprovalError(
            f"Metadata in '{dist_info}' is missing required header '{header}'."
        )
    return value
