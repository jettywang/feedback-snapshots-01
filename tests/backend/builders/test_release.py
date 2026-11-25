from __future__ import annotations

import json
import os
import tarfile
import zipfile

import pytest

from hatchling.builders.release import (
    REPORT_FILE_NAME,
    REJECTED_DIRECTORY,
    STATUS_APPROVED,
    STATUS_INDETERMINATE,
    STATUS_REJECTED,
    ChannelRule,
    ReleaseConfig,
    evaluate_version,
    load_release_config,
    load_report,
    read_artifact_version,
    select_release_artifacts,
    write_report,
)
from hatchling.builders.sdist import SdistBuilder
from hatchling.builders.wheel import WheelBuilder


def build_project(temp_dir, version, *, channel_config=None, target_config=None):
    package = temp_dir / "demo"
    package.ensure_dir_exists()
    (package / "__init__.py").touch()

    tool_config = {"hatch": {"build": {}}}
    if channel_config is not None:
        tool_config["hatch"]["build"]["release"] = channel_config
    if target_config is not None:
        tool_config["hatch"]["build"]["targets"] = target_config

    return {
        "project": {"name": "demo", "version": version},
        "tool": tool_config,
    }


class TestLoadReleaseConfig:
    def test_disabled(self):
        assert load_release_config({}) is None

    def test_global(self):
        config = load_release_config({
            "release": {
                "channels": {
                    "stable": {"approved": True},
                    "candidate": {"approved": True, "allow-prerelease": True, "version": ">=2.0"},
                }
            }
        })

        assert list(config.channels) == ["stable", "candidate"]
        assert config.channels["candidate"].allow_prerelease is True
        assert str(config.channels["candidate"].version_specifier) == ">=2.0"

    def test_target_overrides_global(self):
        target_config = {"release": {"channels": {"only": {"approved": True}}}}
        config = load_release_config({"release": {"channels": {"stable": {"approved": True}}}}, target_config)

        assert list(config.channels) == ["only"]

    def test_skips_unapproved(self):
        config = load_release_config({
            "release": {"channels": {"draft": {"approved": False}, "stable": {"approved": True}}}
        })

        assert list(config.channels) == ["stable"]

    def test_not_table(self):
        with pytest.raises(TypeError, match="Field `tool.hatch.build.release` must be a table"):
            load_release_config({"release": []})

    def test_missing_channels(self):
        with pytest.raises(ValueError, match="is required when `tool.hatch.build.release` is defined"):
            load_release_config({"release": {}})

    def test_invalid_specifier(self):
        with pytest.raises(ValueError, match="is not a valid specifier"):
            load_release_config({"release": {"channels": {"stable": {"approved": True, "version": "not-a-spec"}}}})

    def test_definition_export(self):
        config = load_release_config({
            "release": {"channels": {"candidate": {"approved": True, "allow-prerelease": True}}}
        })

        assert config.definition == {
            "channels": [{"name": "candidate", "allow-prerelease": True, "allow-local": False}]
        }


class TestEvaluateVersion:
    def test_not_configured(self):
        decision = evaluate_version(None, "wheel", "1.0.0")

        assert decision.status == STATUS_INDETERMINATE

    def test_approved(self):
        config = ReleaseConfig(channels={"stable": ChannelRule("stable")})
        decision = evaluate_version(config, "wheel", "1.0.0")

        assert decision.status == STATUS_APPROVED
        assert decision.channel == "stable"

    def test_prerelease_rejected_by_stable(self):
        config = ReleaseConfig(channels={"stable": ChannelRule("stable")})
        decision = evaluate_version(config, "wheel", "1.0.0rc1")

        assert decision.status == STATUS_REJECTED
        assert "prerelease" in decision.reason

    def test_prerelease_allowed_by_candidate(self):
        config = ReleaseConfig(channels={"stable": ChannelRule("stable"), "candidate": ChannelRule("candidate", True)})
        decision = evaluate_version(config, "wheel", "1.0.0rc1")

        assert decision.status == STATUS_APPROVED
        assert decision.channel == "candidate"

    def test_local_rejected(self):
        config = ReleaseConfig(channels={"stable": ChannelRule("stable")})
        decision = evaluate_version(config, "wheel", "1.0.0+local")

        assert decision.status == STATUS_REJECTED
        assert "local" in decision.reason

    def test_invalid_version(self):
        config = ReleaseConfig(channels={"stable": ChannelRule("stable")})
        decision = evaluate_version(config, "wheel", "not a version")

        assert decision.status == STATUS_REJECTED

    def test_no_channel_approved(self):
        config = ReleaseConfig(channels={"draft": ChannelRule("draft", allow_prerelease=False)})
        decision = evaluate_version(config, "wheel", "1.0")

        assert decision.status == STATUS_APPROVED  # allow_prerelease irrelevant for a stable version

    def test_empty_channels(self):
        decision = evaluate_version(ReleaseConfig(), "wheel", "1.0")

        assert decision.status == STATUS_REJECTED

    def test_changed_after_preparation(self):
        config = ReleaseConfig(channels={"stable": ChannelRule("stable")})
        decision = evaluate_version(config, "wheel", "2.0.0rc1", prepared_version="2.0.0")

        assert decision.status == STATUS_REJECTED
        assert decision.changed_after_preparation is True
        assert decision.to_dict()["changed-after-preparation"] is True


class TestBuildApproval:
    def test_candidate_approved_with_target_override(self, temp_dir):
        config = build_project(
            temp_dir,
            "2.0.0rc1",
            target_config={"wheel": {"release": {"channels": {"candidate": {"approved": True, "allow-prerelease": True}}}}},
        )
        builder = WheelBuilder(str(temp_dir), config=config)
        build_directory = temp_dir / "dist"
        build_directory.mkdir()

        with temp_dir.as_cwd():
            artifacts = list(builder.build(directory=str(build_directory), versions=["standard"]))

        assert len(artifacts) == 1
        assert (build_directory / "demo-2.0.0rc1-py2.py3-none-any.whl").is_file()

        report = load_report(str(build_directory))
        assert report["decisions"][0]["status"] == STATUS_APPROVED
        assert report["decisions"][0]["version"] == "2.0.0rc1"
        assert report["decisions"][0]["artifact"] == "demo-2.0.0rc1-py2.py3-none-any.whl"

    def test_stable_rejects_prerelease(self, temp_dir):
        config = build_project(temp_dir, "2.0.0rc1", channel_config={"channels": {"stable": {"approved": True}}})
        builder = WheelBuilder(str(temp_dir), config=config)
        build_directory = temp_dir / "dist"
        build_directory.mkdir()

        with temp_dir.as_cwd():
            artifacts = list(builder.build(directory=str(build_directory), versions=["standard"]))

        # The rejected artifact is held out of the release result
        assert len(artifacts) == 1
        assert REJECTED_DIRECTORY in artifacts[0]
        assert not (build_directory / "demo-2.0.0rc1-py2.py3-none-any.whl").exists()
        assert (build_directory / REJECTED_DIRECTORY / "demo" / "demo-2.0.0rc1-py2.py3-none-any.whl").is_file()

        report = load_report(str(build_directory))
        decision = report["decisions"][0]
        assert decision["status"] == STATUS_REJECTED
        assert "prerelease" in decision["reason"]

    def test_sdist_metadata_used(self, temp_dir):
        config = build_project(temp_dir, "2.0.0", channel_config={"channels": {"stable": {"approved": True}}})
        builder = SdistBuilder(str(temp_dir), config=config)
        build_directory = temp_dir / "dist"
        build_directory.mkdir()

        with temp_dir.as_cwd():
            artifacts = list(builder.build(directory=str(build_directory), versions=["standard"]))

        assert artifacts == [str(build_directory / "demo-2.0.0.tar.gz")]
        assert read_artifact_version(artifacts[0]) == "2.0.0"

    def test_targets_independent_in_shared_directory(self, temp_dir):
        config = build_project(
            temp_dir,
            "2.0.0rc1",
            target_config={
                "wheel": {"release": {"channels": {"candidate": {"approved": True, "allow-prerelease": True}}}},
                "sdist": {"release": {"channels": {"stable": {"approved": True}}}},
            },
        )
        build_directory = temp_dir / "dist"
        build_directory.mkdir()

        with temp_dir.as_cwd():
            wheel_artifacts = list(WheelBuilder(str(temp_dir), config=config).build(directory=str(build_directory)))
            sdist_artifacts = list(SdistBuilder(str(temp_dir), config=config).build(directory=str(build_directory)))

        assert wheel_artifacts == [str(build_directory / "demo-2.0.0rc1-py2.py3-none-any.whl")]
        assert REJECTED_DIRECTORY in sdist_artifacts[0]

        report = load_report(str(build_directory))
        decisions = {entry["target"]: entry for entry in report["decisions"]}
        assert decisions["wheel"]["status"] == STATUS_APPROVED
        assert decisions["sdist"]["status"] == STATUS_REJECTED

    def test_dynamic_version_source_keeps_working(self, temp_dir):
        package = temp_dir / "demo"
        package.ensure_dir_exists()
        (package / "__init__.py").touch()
        (package / "__about__.py").write_text('__version__ = "1.5.0"\n')

        config = {
            "project": {"name": "demo", "dynamic": ["version"]},
            "tool": {
                "hatch": {
                    "version": {"path": "demo/__about__.py"},
                    "build": {"release": {"channels": {"stable": {"approved": True}}}},
                }
            },
        }
        builder = WheelBuilder(str(temp_dir), config=config)
        build_directory = temp_dir / "dist"
        build_directory.mkdir()

        with temp_dir.as_cwd():
            artifacts = list(builder.build(directory=str(build_directory), versions=["standard"]))

        assert artifacts == [str(build_directory / "demo-1.5.0-py2.py3-none-any.whl")]
        assert load_report(str(build_directory))["decisions"][0]["status"] == STATUS_APPROVED


class TestBuildHookDeclaration:
    def test_hook_cannot_widen_approval(self, temp_dir, helpers):
        package = temp_dir / "demo"
        package.ensure_dir_exists()
        (package / "__init__.py").touch()
        (package / "__about__.py").write_text('__version__ = "2.5.0"\n')
        (temp_dir / "hatch_build.py").write_text(
            helpers.dedent(
                """
                from hatchling.builders.hooks.plugin.interface import BuildHookInterface

                class Hook(BuildHookInterface):
                    def initialize(self, version, build_data):
                        build_data["declared_version"] = "3.0.0rc1"
                """
            )
        )

        config = {
            "project": {"name": "demo", "dynamic": ["version"]},
            "tool": {
                "hatch": {
                    "version": {"path": "demo/__about__.py"},
                    "build": {
                        "hooks": {"custom": {"path": "hatch_build.py"}},
                        "release": {"channels": {"stable": {"approved": True}}},
                    },
                }
            },
        }
        builder = WheelBuilder(str(temp_dir), config=config)
        build_directory = temp_dir / "dist"
        build_directory.mkdir()

        with temp_dir.as_cwd():
            artifacts = list(builder.build(directory=str(build_directory), versions=["standard"]))

        decision = load_report(str(build_directory))["decisions"][0]
        assert decision["version"] == "3.0.0rc1"
        assert decision["prepared-version"] == "2.5.0"
        assert decision["changed-after-preparation"] is True
        assert decision["status"] == STATUS_REJECTED
        assert REJECTED_DIRECTORY in artifacts[0]


class TestArtifactVersion:
    def test_wheel_and_sdist_versions_match_metadata(self, temp_dir):
        config = build_project(temp_dir, "1.2.3")
        build_directory = temp_dir / "dist"
        build_directory.mkdir()

        with temp_dir.as_cwd():
            wheel = list(WheelBuilder(str(temp_dir), config=config).build(directory=str(build_directory)))[0]
            sdist = list(SdistBuilder(str(temp_dir), config=config).build(directory=str(build_directory)))[0]

        assert read_artifact_version(wheel) == "1.2.3"
        assert read_artifact_version(sdist) == "1.2.3"

        with zipfile.ZipFile(wheel) as archive:
            metadata = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
            assert "Version: 1.2.3" in archive.read(metadata).decode()

        with tarfile.open(sdist, "r:gz") as archive:
            pkg_info = next(member for member in archive.getmembers() if member.name.endswith("/PKG-INFO"))
            assert "Version: 1.2.3" in archive.extractfile(pkg_info).read().decode()


class TestReport:
    def test_write_and_merge(self, temp_dir):
        config = ReleaseConfig(channels={"stable": ChannelRule("stable")})
        first = evaluate_version(config, "wheel", "1.0.0", project="demo", artifact="demo-1.0.0.whl")
        second = evaluate_version(config, "sdist", "1.0.0rc1", project="demo", artifact="demo-1.0.0rc1.tar.gz")

        write_report(str(temp_dir), [first])
        write_report(str(temp_dir), [second])

        report = load_report(str(temp_dir))
        assert len(report["decisions"]) == 2
        assert {entry["target"] for entry in report["decisions"]} == {"wheel", "sdist"}

    def test_select_release_artifacts(self, temp_dir):
        config = ReleaseConfig(channels={"stable": ChannelRule("stable")})
        approved = evaluate_version(config, "wheel", "1.0.0", project="demo", artifact="demo-1.0.0.whl")
        rejected = evaluate_version(config, "sdist", "1.0.0rc1", project="demo", artifact="demo-1.0.0rc1.tar.gz")
        write_report(str(temp_dir), [approved, rejected])

        wheel = temp_dir / "demo-1.0.0.whl"
        sdist = temp_dir / "demo-1.0.0rc1.tar.gz"
        extra = temp_dir / "demo-2.0.0-py3-none-any.whl"
        for path in (wheel, sdist, extra):
            path.touch()

        approved_paths, held_back, unknown = select_release_artifacts(
            [str(wheel), str(sdist), str(extra)], load_report(str(temp_dir))
        )

        assert approved_paths == [str(wheel)]
        assert [entry["artifact"] for entry in held_back] == ["demo-1.0.0rc1.tar.gz"]
        assert unknown == [str(extra)]

    def test_no_report_leaves_paths_unchanged(self, temp_dir):
        path = temp_dir / "demo-1.0.0.whl"
        path.touch()

        approved_paths, held_back, unknown = select_release_artifacts([str(path)], None)

        assert approved_paths == [str(path)]
        assert held_back == []
        assert unknown == []

    def test_report_artifact_is_exportable(self, temp_dir):
        config = load_release_config({
            "release": {"channels": {"candidate": {"approved": True, "allow-prerelease": True}}}
        })
        decision = evaluate_version(config, "wheel", "2.0.0rc1", project="demo", artifact="demo-2.0.0rc1.whl")
        write_report(str(temp_dir), [decision])

        data = json.loads((temp_dir / REPORT_FILE_NAME).read_text())
        assert data["decisions"][0]["rules"] == [
            {"name": "candidate", "allow-prerelease": True, "allow-local": False}
        ]


class TestWorkspaceIndependence:
    def test_distinct_projects_keep_separate_reports(self, temp_dir):
        build_directory = temp_dir / "dist"
        build_directory.mkdir()

        approved_config = ReleaseConfig(channels={"stable": ChannelRule("stable")})
        rejected_config = ReleaseConfig(channels={"stable": ChannelRule("stable")})
        approved = evaluate_version(approved_config, "wheel", "1.0.0", project="member-a", artifact="a-1.0.0.whl")
        rejected = evaluate_version(rejected_config, "wheel", "1.0.0rc1", project="member-b", artifact="b-1.0.0rc1.whl")

        write_report(str(build_directory), [approved])
        write_report(str(build_directory), [rejected])

        report = load_report(str(build_directory))
        decisions = {entry["project"]: entry["status"] for entry in report["decisions"]}

        assert decisions == {"member-a": STATUS_APPROVED, "member-b": STATUS_REJECTED}

    def test_rejected_project_does_not_remove_other_artifact(self, temp_dir):
        build_directory = temp_dir / "dist"
        build_directory.mkdir()

        config = build_project(temp_dir, "1.0.0", channel_config={"channels": {"stable": {"approved": True}}})
        builder = WheelBuilder(str(temp_dir), config=config)

        with temp_dir.as_cwd():
            list(builder.build(directory=str(build_directory), versions=["standard"]))

        # Simulate a second, independent artifact sharing the directory
        other = build_directory / "other-1.0.0rc1.tar.gz"
        other.touch()

        from hatchling.builders.release import finalize_artifact

        config = ReleaseConfig(channels={"stable": ChannelRule("stable")})
        decision = evaluate_version(config, "sdist", "1.0.0rc1", project="other", artifact="other-1.0.0rc1.tar.gz")
        finalize_artifact(str(build_directory), decision, str(other))

        assert (build_directory / "demo-1.0.0-py2.py3-none-any.whl").is_file()
        assert not other.exists()
        assert (build_directory / REJECTED_DIRECTORY / "other" / "other-1.0.0rc1.tar.gz").is_file()


class TestClean:
    def test_clean_prunes_only_own_decision(self, temp_dir):
        from hatchling.builders.release import prune_report

        build_directory = temp_dir / "dist"
        build_directory.mkdir()
        config = ReleaseConfig(channels={"stable": ChannelRule("stable")})
        write_report(str(build_directory), [evaluate_version(config, "wheel", "1.0.0", project="a", artifact="a.whl")])
        write_report(str(build_directory), [evaluate_version(config, "sdist", "1.0.0", project="a", artifact="a.tar.gz")])

        prune_report(str(build_directory), "a", "wheel")

        report = load_report(str(build_directory))
        assert [(entry["project"], entry["target"]) for entry in report["decisions"]] == [("a", "sdist")]

    def test_clean_removes_report_when_last_decision(self, temp_dir):
        from hatchling.builders.release import prune_report

        build_directory = temp_dir / "dist"
        build_directory.mkdir()
        config = ReleaseConfig(channels={"stable": ChannelRule("stable")})
        write_report(str(build_directory), [evaluate_version(config, "wheel", "1.0.0", project="a", artifact="a.whl")])

        prune_report(str(build_directory), "a", "wheel")

        assert load_report(str(build_directory)) is None


class TestBuildClean:
    def test_clean_replaces_stale_decision(self, temp_dir):
        config = build_project(temp_dir, "2.0.0", channel_config={"channels": {"stable": {"approved": True}}})
        build_directory = temp_dir / "dist"
        build_directory.mkdir()

        with temp_dir.as_cwd():
            list(WheelBuilder(str(temp_dir), config=config).build(directory=str(build_directory)))

        # Rewrite the report as though a previous, now-rejected build had run
        stale = evaluate_version(
            ReleaseConfig(channels={"stable": ChannelRule("stable")}),
            "wheel",
            "1.0.0rc1",
            project="demo",
            artifact="demo-1.0.0rc1-py2.py3-none-any.whl",
        )
        write_report(str(build_directory), [stale])
        assert load_report(str(build_directory))["decisions"][0]["status"] == STATUS_REJECTED

        # A clean build must re-evaluate and record a fresh approved decision
        with temp_dir.as_cwd():
            list(WheelBuilder(str(temp_dir), config=config).build(directory=str(build_directory), clean=True))

        decisions = load_report(str(build_directory))["decisions"]
        assert len(decisions) == 1
        assert decisions[0]["status"] == STATUS_APPROVED
        assert decisions[0]["version"] == "2.0.0"


class TestFinalizeArtifact:
    def test_approved_artifact_stays_in_place(self, temp_dir):
        from hatchling.builders.release import finalize_artifact

        artifact = temp_dir / "demo-1.0.0-py2.py3-none-any.whl"
        artifact.touch()
        config = ReleaseConfig(channels={"stable": ChannelRule("stable")})
        decision = evaluate_version(config, "wheel", "1.0.0", project="demo", artifact=artifact.name)

        result = finalize_artifact(str(temp_dir), decision, str(artifact))

        assert result == str(artifact)
        assert artifact.is_file()
        assert not (temp_dir / REJECTED_DIRECTORY).exists()
        assert load_report(str(temp_dir))["decisions"][0]["status"] == STATUS_APPROVED

    def test_indeterminate_artifact_relocated_with_reason(self, temp_dir):
        from hatchling.builders.release import finalize_artifact

        artifact = temp_dir / "demo-1.0.0-py2.py3-none-any.whl"
        artifact.write_text("not a zip")
        config = ReleaseConfig(channels={"stable": ChannelRule("stable")})

        from hatchling.builders.release import decide_artifact

        decision = decide_artifact(config, "wheel", str(artifact), project="demo", prepared_version="1.0.0")
        assert decision.status == STATUS_INDETERMINATE

        result = finalize_artifact(str(temp_dir), decision, str(artifact))

        assert REJECTED_DIRECTORY in result
        assert not artifact.exists()
        entry = load_report(str(temp_dir))["decisions"][0]
        assert entry["status"] == STATUS_INDETERMINATE
        assert "unable to read" in entry["reason"]
