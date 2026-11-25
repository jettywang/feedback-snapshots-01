from __future__ import annotations

import zipfile

import pytest
from hatchling.builders.wheel import WheelBuilder
from hatchling.metadata.core import ProjectMetadata
from hatchling.metadata.plugin.interface import MetadataHookInterface
from hatchling.metadata.safe import FieldStatus, SafeMetadataReader
from hatchling.metadata.spec import project_metadata_from_core_metadata
from hatchling.plugin import hookimpl
from hatchling.plugin.manager import PluginManager

APPROVED_HOOK = "approved"
PENDING_HOOK = "pending"

APPROVED_DESCRIPTION = "set by the approved hook"
PENDING_KEYWORDS = ["pending", "dynamic"]

PROJECT_CONFIG = {
    "project": {
        "name": "safe-read-demo",
        "dynamic": ["version", "description", "keywords"],
        "dependencies": ["requests"],
    },
    "tool": {
        "hatch": {
            "version": {"path": "pkg/__init__.py"},
            "metadata": {"hooks": {APPROVED_HOOK: {}, PENDING_HOOK: {}}},
            "build": {"targets": {"wheel": {"packages": ["pkg"]}}},
        }
    },
}


class ApprovedMetadataHook(MetadataHookInterface):
    PLUGIN_NAME = APPROVED_HOOK
    call_count = 0

    def update(self, metadata):
        type(self).call_count += 1
        metadata["description"] = APPROVED_DESCRIPTION


class PendingMetadataHook(MetadataHookInterface):
    PLUGIN_NAME = PENDING_HOOK
    call_count = 0

    def update(self, metadata):
        type(self).call_count += 1
        metadata["keywords"] = PENDING_KEYWORDS


def _plugin_manager() -> PluginManager:
    plugin_manager = PluginManager()

    class _Registration:
        @hookimpl
        def hatch_register_metadata_hook(self):
            return [ApprovedMetadataHook, PendingMetadataHook]

    plugin_manager.manager.register(_Registration())
    return plugin_manager


@pytest.fixture
def safe_project(temp_dir):
    (temp_dir / "pkg").mkdir()
    (temp_dir / "pkg" / "__init__.py").write_text('__version__ = "1.2.3"\n')

    ApprovedMetadataHook.call_count = 0
    PendingMetadataHook.call_count = 0

    return ProjectMetadata(str(temp_dir), _plugin_manager(), PROJECT_CONFIG)


class TestSafeReadStatuses:
    def test_static_fields_are_confirmed_without_running_hooks(self, safe_project):
        report = SafeMetadataReader(safe_project).read()

        assert report.is_confirmed("name")
        assert report.get("name").status is FieldStatus.STATIC
        assert report.get("name").value == "safe-read-demo"

        assert report.get("dependencies").status is FieldStatus.STATIC
        assert report.get("dependencies").value == ["requests"]

        # Nothing was approved, so neither plugin may be executed.
        assert report.callback_counts == {}
        assert report.unapproved_hooks == (APPROVED_HOOK, PENDING_HOOK)
        assert ApprovedMetadataHook.call_count == 0
        assert PendingMetadataHook.call_count == 0

    def test_approved_dynamic_field_is_confirmed(self, safe_project):
        report = SafeMetadataReader(safe_project, approved_hooks=(APPROVED_HOOK,)).read()

        description = report.get("description")
        assert description.status is FieldStatus.DYNAMIC_APPROVED
        assert description.value == APPROVED_DESCRIPTION
        assert description.source == APPROVED_HOOK
        assert report.is_confirmed("description")

        # The version source is allowed once a hook is approved.
        version = report.get("version")
        assert version.status is FieldStatus.DYNAMIC_APPROVED
        assert version.value == "1.2.3"
        assert report.is_confirmed("version")

        assert report.callback_counts == {APPROVED_HOOK: 1}
        assert ApprovedMetadataHook.call_count == 1

    def test_unapproved_dynamic_field_stays_pending(self, safe_project):
        report = SafeMetadataReader(safe_project, approved_hooks=(APPROVED_HOOK,)).read()

        keywords = report.get("keywords")
        assert keywords.status is FieldStatus.DYNAMIC_PENDING
        assert keywords.value is None
        assert keywords.reason is not None
        assert not report.is_confirmed("keywords")

        # The pending plugin's callback must never have run.
        assert PENDING_HOOK not in report.callback_counts
        assert PendingMetadataHook.call_count == 0
        assert report.pending_fields == ("keywords",)
        assert report.unapproved_hooks == (PENDING_HOOK,)

    def test_pending_value_is_absent_from_release_decision(self, safe_project):
        report = SafeMetadataReader(safe_project, approved_hooks=(APPROVED_HOOK,)).read()

        confirmed = report.confirmed_fields
        assert "keywords" not in confirmed
        assert "description" in confirmed and "version" in confirmed

    def test_all_three_statuses_coexist_in_one_project(self, safe_project):
        report = SafeMetadataReader(safe_project, approved_hooks=(APPROVED_HOOK,)).read()

        statuses = {field: report.get(field).status for field in ("dependencies", "description", "keywords")}
        assert statuses == {
            "dependencies": FieldStatus.STATIC,
            "description": FieldStatus.DYNAMIC_APPROVED,
            "keywords": FieldStatus.DYNAMIC_PENDING,
        }

    def test_no_approval_leaves_every_dynamic_field_pending(self, safe_project):
        report = SafeMetadataReader(safe_project).read()

        for field in ("version", "description", "keywords"):
            assert report.get(field).status is FieldStatus.DYNAMIC_PENDING
            assert not report.is_confirmed(field)

        assert set(report.pending_fields) == {"version", "description", "keywords"}
        assert report.callback_counts == {}
        assert ApprovedMetadataHook.call_count == 0
        assert PendingMetadataHook.call_count == 0

    def test_approving_unknown_hook_name_is_ignored(self, safe_project):
        report = SafeMetadataReader(safe_project, approved_hooks=("does-not-exist",)).read()

        assert report.callback_counts == {}
        assert report.get("description").status is FieldStatus.DYNAMIC_PENDING


class TestFullyStaticProject:
    def test_every_field_is_static_without_plugins(self, temp_dir):
        config = {
            "project": {
                "name": "static-demo",
                "version": "0.1.0",
                "description": "entirely static",
                "dependencies": ["click"],
            }
        }
        project = ProjectMetadata(str(temp_dir), PluginManager(), config)

        report = SafeMetadataReader(project).read()

        assert report.callback_counts == {}
        assert report.unapproved_hooks == ()
        assert report.pending_fields == ()
        assert report.get("version").status is FieldStatus.STATIC
        assert report.get("version").value == "0.1.0"
        assert report.confirmed_fields["name"] == "static-demo"
        assert report.confirmed_fields["dependencies"] == ["click"]


class TestSafeReadDoesNotMutateProject:
    def test_approved_hook_uses_private_metadata_copy(self, safe_project):
        SafeMetadataReader(safe_project, approved_hooks=(APPROVED_HOOK,)).read()

        # The project's own raw metadata must not gain the dynamically produced key.
        assert "description" not in safe_project.core_raw_metadata


class TestUnapprovedBuildScriptIsNeverImported:
    def test_custom_hook_script_not_loaded_without_approval(self, temp_dir, helpers):
        from hatchling.utils.constants import DEFAULT_BUILD_SCRIPT

        sentinel = temp_dir / "imported.txt"

        # Module-level code runs at import time; if the script is loaded the
        # sentinel file appears even before `update()` is called.
        (temp_dir / DEFAULT_BUILD_SCRIPT).write_text(
            helpers.dedent(
                f"""
                from pathlib import Path

                Path({str(sentinel)!r}).write_text("imported")

                from hatchling.metadata.plugin.interface import MetadataHookInterface

                class CustomHook(MetadataHookInterface):
                    def update(self, metadata):
                        metadata['description'] = "should never run"
                """
            )
        )

        config = {
            "project": {"name": "unsafe-script", "dynamic": ["description"]},
            "tool": {"hatch": {"metadata": {"hooks": {"custom": {}}}}},
        }
        project = ProjectMetadata(str(temp_dir), PluginManager(), config)

        report = SafeMetadataReader(project).read()

        assert not sentinel.is_file()
        assert report.callback_counts == {}
        assert report.get("description").status is FieldStatus.DYNAMIC_PENDING
        assert report.unapproved_hooks == ("custom",)

    def test_custom_hook_script_runs_when_approved(self, temp_dir, helpers):
        from hatchling.utils.constants import DEFAULT_BUILD_SCRIPT

        sentinel = temp_dir / "imported.txt"

        (temp_dir / DEFAULT_BUILD_SCRIPT).write_text(
            helpers.dedent(
                f"""
                from pathlib import Path

                Path({str(sentinel)!r}).write_text("imported")

                from hatchling.metadata.plugin.interface import MetadataHookInterface

                class CustomHook(MetadataHookInterface):
                    def update(self, metadata):
                        metadata['description'] = "approved value"
                """
            )
        )

        config = {
            "project": {"name": "safe-script", "dynamic": ["description"]},
            "tool": {"hatch": {"metadata": {"hooks": {"custom": {}}}}},
        }
        project = ProjectMetadata(str(temp_dir), PluginManager(), config)

        report = SafeMetadataReader(project, approved_hooks=("custom",)).read()

        assert sentinel.is_file()
        assert report.callback_counts == {"custom": 1}
        assert report.get("description").status is FieldStatus.DYNAMIC_APPROVED
        assert report.get("description").value == "approved value"


class TestArtifactVerification:
    def test_built_wheel_values_can_be_re_reviewed(self, temp_dir):
        (temp_dir / "pkg").mkdir()
        (temp_dir / "pkg" / "__init__.py").write_text('__version__ = "1.2.3"\n')

        # Read-only inspection before building: only the approved hook runs.
        read_metadata = ProjectMetadata(str(temp_dir), _plugin_manager(), PROJECT_CONFIG)
        report = SafeMetadataReader(read_metadata, approved_hooks=(APPROVED_HOOK,)).read()
        assert report.callback_counts == {APPROVED_HOOK: 1}
        assert PendingMetadataHook.call_count == 0

        # The formal build runs every configured hook, including the pending one.
        builder = WheelBuilder(str(temp_dir), _plugin_manager(), PROJECT_CONFIG)
        (wheel_path,) = builder.build(directory=str(temp_dir / "dist"))

        with zipfile.ZipFile(str(wheel_path)) as archive:
            metadata_name = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
            artifact_metadata = project_metadata_from_core_metadata(archive.read(metadata_name).decode("utf-8"))

        verification = report.verify_artifact(artifact_metadata)

        # Static and approved-dynamic values embedded in the artifact match the report.
        assert verification["verified"]["name"] == "safe-read-demo"
        assert verification["verified"]["description"] == APPROVED_DESCRIPTION
        assert verification["mismatched"] == {}

        # The previously pending field is surfaced for review, never auto-confirmed.
        assert "keywords" in verification["pending"]
        assert set(verification["pending"]["keywords"]["artifact_value"]) == set(PENDING_KEYWORDS)

        # The real artifact carries the value the pending hook produced.
        assert set(artifact_metadata["keywords"]) == set(PENDING_KEYWORDS)

    def test_mismatched_artifact_value_is_flagged(self, safe_project):
        report = SafeMetadataReader(safe_project, approved_hooks=(APPROVED_HOOK,)).read()

        verification = report.verify_artifact({"name": "tampered-name", "description": APPROVED_DESCRIPTION})

        assert "name" in verification["mismatched"]
        assert verification["mismatched"]["name"]["artifact_value"] == "tampered-name"
        assert "keywords" in verification["pending"]
