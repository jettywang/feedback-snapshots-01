from __future__ import annotations

from contextlib import suppress
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hatchling.metadata.core import CoreMetadata, ProjectMetadata
    from hatchling.metadata.plugin.interface import MetadataHookInterface

# The project metadata fields that can be represented in a read report. This
# mirrors the keys emitted by `hatchling.metadata.utils.resolve_metadata_fields`.
RESOLVABLE_FIELDS: tuple[str, ...] = (
    "name",
    "version",
    "description",
    "readme",
    "requires-python",
    "license",
    "authors",
    "maintainers",
    "keywords",
    "classifiers",
    "urls",
    "scripts",
    "gui-scripts",
    "entry-points",
    "dependencies",
    "optional-dependencies",
)


class FieldStatus(str, Enum):
    """The confidence attached to a single reported metadata field."""

    # The value was read directly from static configuration without running any plugin.
    STATIC = "static"
    # The value was produced by a metadata plugin that the reviewer explicitly approved.
    DYNAMIC_APPROVED = "dynamic-approved"
    # The value requires a plugin that was not approved, so it must be confirmed later.
    DYNAMIC_PENDING = "dynamic-pending"


@dataclass(frozen=True)
class FieldReport:
    """A single metadata field together with how the value was obtained."""

    field: str
    status: FieldStatus
    value: Any = None
    #: The name of the metadata hook that produced an approved dynamic value, if any.
    source: str | None = None
    #: The reason a field could not be confirmed during a read-only inspection.
    reason: str | None = None

    @property
    def confirmed(self) -> bool:
        return self.status is not FieldStatus.DYNAMIC_PENDING


class SafeReadReport:
    """
    The result of a read-only metadata inspection.

    Fields are never silently treated as confirmed: anything that depends on a
    metadata plugin which was not explicitly approved is reported as
    :attr:`FieldStatus.DYNAMIC_PENDING` and keeps no value.
    """

    def __init__(self) -> None:
        self._fields: dict[str, FieldReport] = {}
        # How many times each approved hook's `update` callback was invoked.
        self.callback_counts: dict[str, int] = {}
        # The hooks that were configured but not approved for this inspection.
        self.unapproved_hooks: tuple[str, ...] = ()

    def add(self, report: FieldReport) -> None:
        self._fields[report.field] = report

    def get(self, field: str) -> FieldReport | None:
        return self._fields.get(field)

    @property
    def fields(self) -> dict[str, FieldReport]:
        return dict(self._fields)

    @property
    def static_fields(self) -> dict[str, Any]:
        return {field: report.value for field, report in self._fields.items() if report.status is FieldStatus.STATIC}

    @property
    def approved_dynamic_fields(self) -> dict[str, Any]:
        return {
            field: report.value
            for field, report in self._fields.items()
            if report.status is FieldStatus.DYNAMIC_APPROVED
        }

    @property
    def pending_fields(self) -> tuple[str, ...]:
        return tuple(field for field, report in self._fields.items() if report.status is FieldStatus.DYNAMIC_PENDING)

    @property
    def confirmed_fields(self) -> dict[str, Any]:
        """Every field that may influence a release decision."""
        return {field: report.value for field, report in self._fields.items() if report.confirmed}

    def is_confirmed(self, field: str) -> bool:
        report = self._fields.get(field)
        return report is not None and report.confirmed

    def to_dict(self) -> dict[str, Any]:
        return {
            field: {
                "status": report.status.value,
                "value": report.value,
                "source": report.source,
                "reason": report.reason,
                "confirmed": report.confirmed,
            }
            for field, report in self._fields.items()
        }

    def verify_artifact(self, artifact_metadata: dict[str, Any]) -> dict[str, Any]:
        """
        Re-check the values embedded in a built artifact against this report.

        Only fields that were confirmed during the read-only inspection are
        compared. Pending fields are surfaced separately so that a reviewer can
        sign off on the values produced by the formal build environment; they are
        never reported as confirmed on their own.
        """
        verification: dict[str, Any] = {"verified": {}, "mismatched": {}, "pending": {}}

        for field, report in self._fields.items():
            if not report.confirmed:
                verification["pending"][field] = {
                    "expected_status": report.status.value,
                    "artifact_value": artifact_metadata.get(field),
                    "reason": report.reason,
                }
                continue

            artifact_value = artifact_metadata.get(field)
            # Empty fields are omitted from built metadata, so an absent artifact
            # value is equivalent to an empty string, list, dictionary, or a readme
            # whose body is empty.
            is_empty = not report.value or (isinstance(report.value, dict) and not report.value.get("text"))
            if artifact_value == report.value or (is_empty and artifact_value is None):
                verification["verified"][field] = report.value
            else:
                verification["mismatched"][field] = {
                    "approved_value": report.value,
                    "artifact_value": artifact_value,
                }

        return verification


class SafeMetadataReader:
    """
    Reads project metadata without executing arbitrary project plugins.

    Static configuration is always available. A metadata hook is only instantiated
    and its ``update`` callback invoked when its name is included in
    ``approved_hooks``; every dynamic field that would require another plugin is
    left pending instead of being resolved.
    """

    def __init__(self, metadata: ProjectMetadata[Any], approved_hooks: tuple[str, ...] = ()) -> None:
        self.metadata = metadata
        self.approved_hooks = tuple(dict.fromkeys(approved_hooks))

    def read(self) -> SafeReadReport:
        report = SafeReadReport()

        configured_hooks = tuple(self.metadata.hatch.metadata.hook_config)
        approved = tuple(name for name in configured_hooks if name in self.approved_hooks)
        report.unapproved_hooks = tuple(name for name in configured_hooks if name not in approved)

        # The fields the project declares as dynamic, before any depopulation.
        dynamic_fields = set(self.metadata.dynamic)

        # Work on a private copy so an approved hook never mutates the project's
        # own cached raw metadata.
        raw_metadata = deepcopy(self.metadata.core_raw_metadata)
        static_fields = set(raw_metadata)

        # Instantiate only the hooks that were explicitly approved. This avoids
        # importing or executing the build scripts behind unapproved hooks.
        hooks = self._get_approved_hooks(approved)

        produced_fields: dict[str, str] = {}
        for hook_name, hook in hooks:
            before = set(raw_metadata)
            hook.update(raw_metadata)
            report.callback_counts[hook_name] = report.callback_counts.get(hook_name, 0) + 1

            for new_field in set(raw_metadata) - before:
                if new_field not in dynamic_fields:
                    message = (
                        f"The field `{new_field}` was set dynamically and therefore must be "
                        f"listed in `project.dynamic`"
                    )
                    raise ValueError(message)

                produced_fields[new_field] = hook_name

        # The version is resolved through the configured version source, which is
        # itself a plugin, so it is only read when the reviewer approved the
        # metadata hooks that drive the dynamic build.
        resolved_version: str | None = None
        version_source: str | None = None
        if "version" in dynamic_fields and "version" not in static_fields and self._version_allowed(approved):
            resolved_version = self._resolve_version(raw_metadata)
            if resolved_version is not None:
                version_source = self.metadata.hatch.version.source_name

        # Build an isolated core metadata view over the private copy. Its property
        # accessors only read configuration, so this never invokes a project hook.
        core = self._build_core(raw_metadata)

        # Mirror the real build: fields filled by approved hooks (and the resolved
        # version) are no longer dynamic from the core metadata's point of view.
        for resolved_field in set(produced_fields):
            with suppress(ValueError):
                core.dynamic.remove(resolved_field)

        if resolved_version is not None:
            produced_fields["version"] = version_source

        for field in RESOLVABLE_FIELDS:
            if field in dynamic_fields and field not in static_fields:
                self._report_dynamic(field, produced_fields, core, resolved_version, report)
            elif field == "version" and "version" not in static_fields:
                # No static version and no dynamic declaration: nothing to report.
                report.add(FieldReport(field, FieldStatus.STATIC, value=None))
            else:
                report.add(FieldReport(field, FieldStatus.STATIC, value=self._resolve_value(field, core, None)))

        return report

    def _get_approved_hooks(self, approved: tuple[str, ...]) -> list[tuple[str, MetadataHookInterface]]:
        hooks = []
        for hook_name in approved:
            hook = self.metadata.hatch.metadata.hooks[hook_name]
            hooks.append((hook_name, hook))
        return hooks

    def _version_allowed(self, approved: tuple[str, ...]) -> bool:
        # With no metadata hooks configured there is no arbitrary project code to
        # run, so the version source is safe to evaluate. Otherwise an explicit
        # approval is required.
        if not self.metadata.hatch.metadata.hook_config:
            return True
        return bool(approved)

    def _resolve_version(self, raw_metadata: dict[str, Any]) -> str | None:
        version = self.metadata.hatch.version.cached
        raw_metadata["version"] = version
        return version

    def _build_core(self, raw_metadata: dict[str, Any]) -> CoreMetadata:
        from hatchling.metadata.core import CoreMetadata

        return CoreMetadata(
            self.metadata.root,
            raw_metadata,
            self.metadata.hatch.metadata,
            self.metadata.context,
        )

    def _report_dynamic(
        self,
        field: str,
        produced_fields: dict[str, str],
        core: CoreMetadata,
        resolved_version: str | None,
        report: SafeReadReport,
    ) -> None:
        if field in produced_fields:
            report.add(
                FieldReport(
                    field,
                    FieldStatus.DYNAMIC_APPROVED,
                    value=self._resolve_value(field, core, resolved_version),
                    source=produced_fields[field],
                )
            )
        else:
            report.add(
                FieldReport(
                    field,
                    FieldStatus.DYNAMIC_PENDING,
                    reason=("Dynamic field requires an approved metadata plugin or a formal build environment"),
                )
            )

    def _resolve_value(self, field: str, core: CoreMetadata, resolved_version: str | None) -> Any:
        if field == "name":
            return core.name
        if field == "version":
            return resolved_version if resolved_version is not None else core.version
        if field == "description":
            return core.description
        if field == "readme":
            return {"content-type": core.readme_content_type, "text": core.readme}
        if field == "requires-python":
            return core.requires_python
        if field == "license":
            return core.license_expression or core.license
        if field == "authors":
            return core.authors
        if field == "maintainers":
            return core.maintainers
        if field == "keywords":
            return core.keywords
        if field == "classifiers":
            return core.classifiers
        if field == "urls":
            return core.urls
        if field == "scripts":
            return core.scripts
        if field == "gui-scripts":
            return core.gui_scripts
        if field == "entry-points":
            return core.entry_points
        if field == "dependencies":
            return core.dependencies
        if field == "optional-dependencies":
            return core.optional_dependencies

        message = f"Unknown metadata field: {field}"
        raise ValueError(message)
