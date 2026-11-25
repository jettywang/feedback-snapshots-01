from __future__ import annotations

import json

import pytest

from hatchling.builders import release as release_module
from hatchling.builders.release import ChannelRule, ReleaseConfig, evaluate_version, write_report


class RecordingApp:
    def __init__(self):
        self.warnings: list[str] = []
        self.errors: list[str] = []

    def display_warning(self, message, **kwargs):
        self.warnings.append(message)

    def display_error(self, message, **kwargs):
        self.errors.append(message)

    def display_info(self, message="", **kwargs):
        pass

    def abort(self, message="", code=1, **kwargs):
        if message:
            self.errors.append(message)
        raise SystemExit(code)


class TestReleaseGate:
    def _publisher(self, app, root):
        from hatch.publish.index import IndexPublisher

        return IndexPublisher(app, root, None, {}, {})

    def test_without_report_returns_unchanged(self, temp_dir):
        app = RecordingApp()
        publisher = self._publisher(app, temp_dir)
        path = temp_dir / "demo-1.0.0.whl"
        path.touch()

        assert publisher._apply_release_approval([str(temp_dir)]) == [str(temp_dir)]

    def test_only_approved_artifacts_survive(self, temp_dir):
        config = ReleaseConfig(channels={"stable": ChannelRule("stable")})
        approved = evaluate_version(config, "wheel", "1.0.0", project="demo", artifact="demo-1.0.0.whl")
        rejected = evaluate_version(config, "sdist", "1.0.0rc1", project="demo", artifact="demo-1.0.0rc1.tar.gz")
        write_report(str(temp_dir), [approved, rejected])

        for name in ("demo-1.0.0.whl", "demo-1.0.0rc1.tar.gz"):
            (temp_dir / name).touch()

        app = RecordingApp()
        selected = self._publisher(app, temp_dir)._apply_release_approval([str(temp_dir)])

        assert [name.split("/")[-1] for name in selected] == ["demo-1.0.0.whl"]
        assert any("demo-1.0.0rc1.tar.gz" in warning for warning in app.warnings)

    def test_unknown_artifact_held_back(self, temp_dir):
        config = ReleaseConfig(channels={"stable": ChannelRule("stable")})
        approved = evaluate_version(config, "wheel", "1.0.0", project="demo", artifact="demo-1.0.0.whl")
        write_report(str(temp_dir), [approved])

        (temp_dir / "demo-1.0.0.whl").touch()
        (temp_dir / "demo-2.0.0.whl").touch()

        app = RecordingApp()
        selected = self._publisher(app, temp_dir)._apply_release_approval([str(temp_dir)])

        assert [name.split("/")[-1] for name in selected] == ["demo-1.0.0.whl"]
        assert any("demo-2.0.0.whl" in warning for warning in app.warnings)

    def test_no_approved_artifacts_aborts(self, temp_dir):
        config = ReleaseConfig(channels={"stable": ChannelRule("stable")})
        rejected = evaluate_version(config, "wheel", "1.0.0rc1", project="demo", artifact="demo-1.0.0rc1.whl")
        write_report(str(temp_dir), [rejected])
        (temp_dir / "demo-1.0.0rc1.whl").touch()

        app = RecordingApp()
        with pytest.raises(SystemExit):
            self._publisher(app, temp_dir)._apply_release_approval([str(temp_dir)])

    def test_reports_from_multiple_directories_merge(self, temp_dir):
        root = temp_dir / "root"
        member = temp_dir / "member"
        root.mkdir()
        member.mkdir()
        config = ReleaseConfig(channels={"stable": ChannelRule("stable")})
        write_report(str(root), [evaluate_version(config, "wheel", "1.0.0", project="root", artifact="root-1.0.0.whl")])
        write_report(
            str(member),
            [evaluate_version(config, "wheel", "1.0.0", project="member", artifact="member-1.0.0.whl")],
        )
        (root / "root-1.0.0.whl").touch()
        (member / "member-1.0.0.whl").touch()

        app = RecordingApp()
        publisher = self._publisher(app, temp_dir)
        selected = publisher._apply_release_approval([str(root), str(member)])

        assert sorted(name.split("/")[-1] for name in selected) == ["member-1.0.0.whl", "root-1.0.0.whl"]
