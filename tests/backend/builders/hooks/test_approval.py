from __future__ import annotations

import os
import shutil
import tempfile
import zipfile
from typing import TYPE_CHECKING

import pytest

from hatchling.builders.approval import HookApprovalError
from hatchling.builders.sdist import SdistBuilder
from hatchling.builders.wheel import WheelBuilder
from hatchling.utils.constants import DEFAULT_BUILD_SCRIPT

if TYPE_CHECKING:
    from hatch.utils.fs import Path


HOOK_SOURCE = """
import os
import tempfile

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomHook(BuildHookInterface):
    def initialize(self, version, build_data):
        self.scratch = tempfile.mkdtemp(prefix="hatch-approval-")
        self.generated = os.path.join(self.scratch, "shared.txt")
        try:
            with open(self.generated, "w", encoding="utf-8") as f:
                f.write(self.target_name)

            # The same source file name is mapped to a different, per-target distribution path.
            build_data["force_include"][self.generated] = f"channels/{self.target_name}/shared.txt"

            # Each target only approves its own relocation; the other target must reject it.
            build_data["force_include"][self.generated] = f"relocated/{self.target_name}/shared.txt"
        except BaseException:
            # If an approval (or anything else) aborts initialization, finalize never runs, so the
            # temporary working directory must be reclaimed here instead of leaking it.
            self._cleanup()
            raise

    def _cleanup(self):
        generated = getattr(self, "generated", "")
        scratch = getattr(self, "scratch", "")
        if generated and os.path.isfile(generated):
            os.remove(generated)
        if scratch and os.path.isdir(scratch):
            os.rmdir(scratch)

    def clean(self, versions):
        # Hooks-only runs never call finalize, so the cleanup hook is also exposed here.
        self._cleanup()

    def finalize(self, version, build_data, artifact_path):
        try:
            if self.target_name == "sdist":
                raise RuntimeError("post-processing failure requested by the test")
        finally:
            # The hook only ever writes into the temporary directory and must clean it up.
            self._cleanup()
"""


def write_project(project_path: Path, helpers) -> None:
    package = project_path / "my_app"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (project_path / "pyproject.toml").write_text("")
    (project_path / DEFAULT_BUILD_SCRIPT).write_text(helpers.dedent(HOOK_SOURCE))


def build_config() -> dict:
    return {
        "project": {"name": "my-app", "version": "0.0.1"},
        "tool": {
            "hatch": {
                "build": {
                    "hooks": {"custom": {"path": DEFAULT_BUILD_SCRIPT}},
                    "targets": {
                        "wheel": {
                            "packages": ["my_app"],
                            "hooks": {
                                "custom": {
                                    "path": DEFAULT_BUILD_SCRIPT,
                                    "managed": True,
                                    "approvals": {
                                        "add": [
                                            "channels/wheel/shared.txt",
                                            "relocated/wheel/shared.txt",
                                        ],
                                        "relocate": [
                                            {
                                                "path": "relocated/wheel/shared.txt",
                                                "source": "shared.txt",
                                            }
                                        ],
                                    },
                                }
                            },
                        },
                        "sdist": {
                            "packages": ["my_app"],
                            "hooks": {
                                "custom": {
                                    "path": DEFAULT_BUILD_SCRIPT,
                                    "managed": True,
                                    "approvals": {
                                        "add": [
                                            "channels/sdist/shared.txt",
                                            "relocated/sdist/shared.txt",
                                        ],
                                        "relocate": [
                                            {
                                                "path": "relocated/sdist/shared.txt",
                                                "source": "shared.txt",
                                            }
                                        ],
                                    },
                                }
                            },
                        },
                    },
                }
            }
        },
    }


def test_managed_hook_per_target_approval_isolation_and_receipt(helpers, temp_dir):
    project_path = temp_dir / "project"
    project_path.mkdir()
    write_project(project_path, helpers)
    config = build_config()

    dist = project_path / "dist"
    dist.mkdir()

    temp_root = tempfile.gettempdir()
    preexisting = {name for name in os.listdir(temp_root) if name.startswith("hatch-approval-")}

    wheel_builder = WheelBuilder(str(project_path), config=config)
    sdist_builder = SdistBuilder(str(project_path), config=config)

    with project_path.as_cwd():
        wheel_artifacts = list(wheel_builder.build(directory=str(dist)))

        # The sdist target's post-processing (finalize) deliberately fails.
        with pytest.raises(RuntimeError, match="post-processing failure"):
            list(sdist_builder.build(directory=str(dist)))

    # --- The successful wheel artifact keeps only its approved members ---
    assert len(wheel_artifacts) == 1
    with zipfile.ZipFile(wheel_artifacts[0], "r") as archive:
        wheel_members = set(archive.namelist())

    assert "relocated/wheel/shared.txt" in wheel_members
    assert "my_app/__init__.py" in wheel_members
    # The mapping approved only for the sdist target must not leak into the wheel.
    assert not any("channels/sdist" in member or "relocated/sdist" in member for member in wheel_members)

    # The successful wheel artifact is present even though the other target failed.
    dist_files = os.listdir(str(dist))
    assert os.path.basename(wheel_artifacts[0]) in dist_files

    # --- The hook's temporary working directory was cleaned up ---
    leftover_temp = [
        name
        for name in os.listdir(temp_root)
        if name.startswith("hatch-approval-") and name not in preexisting
    ]
    assert leftover_temp == []
    assert not list(project_path.rglob("shared.txt"))

    # --- Each target produced its own receipt describing what actually entered the result ---
    wheel_receipts = wheel_builder.receipts
    sdist_receipts = sdist_builder.receipts
    assert len(wheel_receipts) == 1
    assert len(sdist_receipts) == 1

    wheel_receipt = wheel_receipts[0]
    sdist_receipt = sdist_receipts[0]

    assert wheel_receipt.target == "wheel"
    assert wheel_receipt.status == "success"
    assert sdist_receipt.target == "sdist"
    assert sdist_receipt.status == "failed"
    assert "post-processing failure" in (sdist_receipt.error or "")

    # Every recorded wheel operation was applied and belongs to the wheel namespace.
    assert wheel_receipt.denied_operations == []
    applied_paths = {operation.path for operation in wheel_receipt.applied_operations}
    assert applied_paths == {"channels/wheel/shared.txt", "relocated/wheel/shared.txt"}

    # The receipt exposes the final membership that actually made it into the wheel.
    wheel_forced = wheel_receipt.result["members"]["force_include"]
    assert list(wheel_forced.values()) == ["relocated/wheel/shared.txt"]

    # The failed sdist still recorded the add/relocate it attempted before failing.
    sdist_paths = {operation.path for operation in sdist_receipt.operations}
    assert sdist_paths == {"channels/sdist/shared.txt", "relocated/sdist/shared.txt"}
    assert all(operation.applied for operation in sdist_receipt.operations)


def test_managed_hook_rejects_unapproved_membership(helpers, temp_dir):
    project_path = temp_dir / "project"
    project_path.mkdir()
    write_project(project_path, helpers)
    config = build_config()

    # Restrict the wheel policy so the relocation is no longer approved.
    wheel_hook = config["tool"]["hatch"]["build"]["targets"]["wheel"]["hooks"]["custom"]
    wheel_hook["approvals"]["relocate"] = []

    dist = project_path / "dist"
    dist.mkdir()
    wheel_builder = WheelBuilder(str(project_path), config=config)

    with project_path.as_cwd(), pytest.raises(HookApprovalError, match="not approved to relocate"):
        list(wheel_builder.build(directory=str(dist)))

    receipt = wheel_builder.receipts[0]
    assert receipt.status == "failed"
    assert len(receipt.denied_operations) == 1
    denied = receipt.denied_operations[0]
    assert denied.kind == "relocate"
    assert denied.path == "relocated/wheel/shared.txt"
    assert denied.applied is False

    # The rejected relocation never produced an artifact.
    assert os.listdir(str(dist)) == []


def test_managed_hook_records_receipt_in_hooks_only_mode(helpers, temp_dir):
    project_path = temp_dir / "project"
    project_path.mkdir()
    write_project(project_path, helpers)
    config = build_config()

    temp_root = tempfile.gettempdir()
    preexisting = {name for name in os.listdir(temp_root) if name.startswith("hatch-approval-")}

    dist = project_path / "dist"
    dist.mkdir()
    wheel_builder = WheelBuilder(str(project_path), config=config)

    with project_path.as_cwd():
        artifacts = list(wheel_builder.build(directory=str(dist), hooks_only=True))

    # No archive is built in hooks-only mode, but a receipt is still recorded exactly once.
    assert artifacts == []
    assert len(wheel_builder.receipts) == 1
    receipt = wheel_builder.receipts[0]
    assert receipt.status == "success"
    assert len(receipt.applied_operations) == 2
    assert not os.listdir(str(dist))

    # The hooks-only run created exactly one scratch directory that did not leak into the project.
    created = [
        name
        for name in os.listdir(temp_root)
        if name.startswith("hatch-approval-") and name not in preexisting
    ]
    assert len(created) == 1
    assert not list(project_path.rglob("shared.txt"))

    # Since finalize never runs in this mode, reclaim the scratch directory the same way the
    # project's clean workflow would invoke the hook's clean method.
    shutil.rmtree(os.path.join(temp_root, created[0]))
