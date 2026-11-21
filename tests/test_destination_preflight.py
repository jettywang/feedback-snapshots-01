"""Destination collision preflight and approved migration plans."""

import json

import pytest

from py7zr import (
    DestinationConflictError,
    DestinationEntry,
    DestinationMember,
    DestinationProfile,
    MigrationPlan,
    SevenZipFile,
)
from py7zr.io import Py7zIO, WriterFactory
from py7zr.preflight import preflight

WINDOWS = "windows"
MACOS = "macos"
LINUX = "linux"


def write_archive(path, members):
    with SevenZipFile(path, "w") as archive:
        for name, data in members:
            archive.writestr(data, name)


class RecordingWriter(Py7zIO):
    def __init__(self):
        self.chunks = []
        self.finished = False

    def write(self, s):
        self.chunks.append(bytes(s))
        return len(s)

    def read(self, size=None):
        data = b"".join(self.chunks)
        return data if size is None else data[:size]

    def seek(self, offset, whence=0):
        return 0

    def flush(self):
        pass

    def size(self):
        return sum(len(chunk) for chunk in self.chunks)

    def close(self):
        self.finished = True


class RecordingFactory(WriterFactory):
    def __init__(self):
        self.created = []

    def create(self, filename):
        product = RecordingWriter()
        self.created.append((filename, product))
        return product


def test_case_conflict_reports_both_members_by_archive_index(tmp_path):
    archive = tmp_path / "case.7z"
    write_archive(archive, [("Report.txt", b"first"), ("report.txt", b"second")])
    with SevenZipFile(archive, "r") as szf:
        report = szf.preflight_destination(WINDOWS)
    assert not report.ok
    assert report.conflict_count == 1
    conflict = report.conflicts[0]
    assert conflict.kind == "case"
    assert conflict.indices == (0, 1)
    assert conflict.names == ("Report.txt", "report.txt")
    assert {member.index for member in conflict.members} == {0, 1}
    assert "Report.txt" in report.summary()
    assert "report.txt" in report.summary()


def test_case_sensitive_destination_accepts_distinct_spellings(tmp_path):
    archive = tmp_path / "case.7z"
    write_archive(archive, [("Report.txt", b"first"), ("report.txt", b"second")])
    factory = RecordingFactory()
    with SevenZipFile(archive, "r") as szf:
        report = szf.preflight_destination(LINUX)
        assert report.ok
        plan = report.plan
        assert plan.approved
        szf.extractall(factory=factory, plan=plan)
    assert [name for name, _ in factory.created] == ["Report.txt", "report.txt"]
    assert factory.created[0][1].read() == b"first"
    assert factory.created[1][1].read() == b"second"


def test_directory_name_conflict_preserves_both_members(tmp_path):
    archive = tmp_path / "dirs.7z"
    members = [("bundle/Docs/a.txt", b"upper"), ("bundle/docs/b.txt", b"lower")]
    write_archive(archive, members)
    with SevenZipFile(archive, "r") as szf:
        report = szf.preflight_destination(WINDOWS)
        directory_conflicts = [conflict for conflict in report.conflicts if conflict.kind == "directory"]
        assert directory_conflicts, report.summary()
        collision = directory_conflicts[0]
        assert any("Docs" in member.target for member in collision.members)
        assert any("docs" in member.target for member in collision.members)
        plan = report.approve("rename")
        szf.extractall(tmp_path / "out", plan=plan)
    files = {
        path.relative_to(tmp_path / "out").as_posix(): path.read_bytes()
        for path in (tmp_path / "out").rglob("*")
        if path.is_file()
    }
    assert files["bundle/Docs/a.txt"] == b"upper"
    assert files["bundle/Docs/b.txt"] == b"lower"


def test_directory_members_with_different_case_are_reported():
    report = preflight(
        [DestinationMember(0, "Docs/", True), DestinationMember(1, "docs/", True)],
        destination=WINDOWS,
    )
    assert report.conflict_count == 1
    assert report.conflicts[0].kind == "directory"
    assert report.conflicts[0].indices == (0, 1)


def test_existing_destination_entry_is_reported(tmp_path):
    archive = tmp_path / "existing.7z"
    write_archive(archive, [("Team/Report.txt", b"archive")])
    with SevenZipFile(archive, "r") as szf:
        report = szf.preflight_destination(
            DestinationProfile(case_sensitive=False, name="share"),
            existing=[DestinationEntry("team/report.txt", is_directory=False)],
        )
    assert report.conflict_count == 1
    conflict = report.conflicts[0]
    assert conflict.kind == "existing"
    assert conflict.existing is not None
    assert conflict.existing.path == "team/report.txt"
    assert conflict.indices == (0,)
    assert "Team/Report.txt" in report.summary()


def test_existing_directory_suffix_and_mapping_forms(tmp_path):
    with SevenZipFile(tmp_path / "empty.7z", "w"):
        pass
    members = [DestinationMember(0, "team/report.txt")]
    by_mapping = preflight(members, destination=WINDOWS, existing={"team/": True})
    assert by_mapping.ok
    blocking_file = preflight(members, destination=WINDOWS, existing={"team": False})
    assert not blocking_file.ok
    assert blocking_file.conflicts[0].kind == "type"
    trailing = preflight(members, destination=WINDOWS, existing=["team/"])
    assert trailing.ok


def test_reject_policy_has_no_side_effects(tmp_path):
    archive = tmp_path / "reject.7z"
    write_archive(archive, [("a.txt", b"one"), ("A.txt", b"two"), ("ok.txt", b"three")])
    out = tmp_path / "out"
    factory = RecordingFactory()
    with SevenZipFile(archive, "r") as szf:
        report = szf.preflight_destination(WINDOWS)
        assert not report.ok
        assert not report.plan.approved
        with pytest.raises(DestinationConflictError):
            szf.extractall(out, plan=report.plan)
        assert not out.exists()
        assert factory.created == []
        with pytest.raises(DestinationConflictError):
            szf.extractall(factory=factory, plan=report.plan)
        assert factory.created == []


def test_unapproved_plan_is_refused_before_directory_creation(tmp_path):
    archive = tmp_path / "unapproved.7z"
    write_archive(archive, [("only.txt", b"data")])
    out = tmp_path / "out"
    with SevenZipFile(archive, "r") as szf:
        report = szf.preflight_destination(WINDOWS)
        plan = report.plan
        assert plan.approved
        unapproved = MigrationPlan(
            profile=plan.profile,
            policy=plan.policy,
            entries=plan.entries,
            conflicts=plan.conflicts,
            unresolved=plan.unresolved,
            archive_fingerprint=plan.archive_fingerprint,
            approved=False,
        )
        with pytest.raises(DestinationConflictError):
            szf.extractall(out, plan=unapproved)
    assert not out.exists()


def test_approved_plan_extracts_normal_members_and_resolves_conflicts(tmp_path):
    archive = tmp_path / "approved.7z"
    write_archive(archive, [("Report.txt", b"upper"), ("report.txt", b"lower"), ("notes.txt", b"notes")])
    out = tmp_path / "out"
    with SevenZipFile(archive, "r") as szf:
        report = szf.preflight_destination(WINDOWS)
        plan = report.approve("rename")
        assert plan.approved and plan.ok
        szf.extractall(out, plan=plan)
    assert (out / "Report.txt").read_bytes() == b"upper"
    renamed = [path for path in out.iterdir() if path.name.startswith("report~")]
    assert len(renamed) == 1
    assert renamed[0].read_bytes() == b"lower"
    assert (out / "notes.txt").read_bytes() == b"notes"


def test_skip_policy_extracts_only_first_and_other_members(tmp_path):
    archive = tmp_path / "skip.7z"
    write_archive(archive, [("same.txt", b"first"), ("same.txt", b"second"), ("other.txt", b"other")])
    out = tmp_path / "out"
    with SevenZipFile(archive, "r") as szf:
        report = szf.preflight_destination(WINDOWS)
        plan = report.approve("skip")
        szf.extractall(out, plan=plan)
    assert (out / "same.txt").read_bytes() == b"first"
    assert (out / "other.txt").read_bytes() == b"other"
    assert sorted(path.name for path in out.iterdir()) == ["other.txt", "same.txt"]


def test_selected_members_respect_plan(tmp_path):
    archive = tmp_path / "selected.7z"
    write_archive(archive, [("Report.txt", b"upper"), ("report.txt", b"lower"), ("other.txt", b"other")])
    out = tmp_path / "out"
    with SevenZipFile(archive, "r") as szf:
        report = szf.preflight_destination(WINDOWS)
        plan = report.approve("rename")
        szf.extract(out, targets=["Report.txt", "report.txt"], plan=plan)
    assert (out / "Report.txt").read_bytes() == b"upper"
    assert not (out / "other.txt").exists()
    assert [path for path in out.iterdir() if path.name.startswith("report~")]


def test_writer_factory_receives_planned_names(tmp_path):
    archive = tmp_path / "factory.7z"
    write_archive(archive, [("Report.txt", b"upper"), ("report.txt", b"lower")])
    factory = RecordingFactory()
    with SevenZipFile(archive, "r") as szf:
        report = szf.preflight_destination(WINDOWS)
        plan = report.approve("rename")
        szf.extractall(factory=factory, plan=plan)
    names = [name for name, _ in factory.created]
    assert names == ["Report.txt", "report~1.txt"]
    assert factory.created[0][1].read() == b"upper"
    assert factory.created[1][1].read() == b"lower"


def test_report_serializes_to_json(tmp_path):
    archive = tmp_path / "report.7z"
    write_archive(archive, [("Report.txt", b"upper"), ("report.txt", b"lower")])
    with SevenZipFile(archive, "r") as szf:
        payload = szf.preflight_destination(WINDOWS).to_dict()
    parsed = json.loads(json.dumps(payload))
    assert parsed["ok"] is False
    conflict = parsed["conflicts"][0]
    assert [member["index"] for member in conflict["members"]] == [0, 1]
    assert parsed["plan"]["policy"] == "reject"


def test_platform_profiles_and_invalid_arguments():
    windows = DestinationProfile.for_platform("windows")
    linux = DestinationProfile.for_platform("linux")
    macos = DestinationProfile.for_platform("darwin")
    assert windows.case_sensitive is False and windows.strip_trailing_dots_and_spaces
    assert linux.case_sensitive is True
    assert macos.case_sensitive is False and macos.unicode_normalization == "NFD"
    with pytest.raises(ValueError):
        DestinationProfile.for_platform("amiga")
    with pytest.raises(ValueError):
        DestinationProfile(unicode_normalization="NFX")
    with pytest.raises(ValueError):
        preflight([DestinationMember(0, "a")], destination=WINDOWS, policy="explode")


def test_unicode_normalization_collision_on_macos():
    composed = "café.txt"
    decomposed = "café.txt"
    report = preflight(
        [DestinationMember(0, composed), DestinationMember(1, decomposed)],
        destination=MACOS,
    )
    assert report.conflict_count == 1
    assert report.conflicts[0].kind == "unicode"
    plan = report.approve("rename")
    assert isinstance(plan.effective_name(0), str)
    assert plan.effective_name(1) != plan.effective_name(0)


def test_trailing_dots_conflict_on_windows():
    report = preflight(
        [DestinationMember(0, "report."), DestinationMember(1, "report")],
        destination=WINDOWS,
    )
    assert report.conflict_count == 1
    assert report.conflicts[0].kind == "trailing"


def test_plan_is_bound_to_archive_version(tmp_path):
    archive = tmp_path / "bound.7z"
    write_archive(archive, [("a.txt", b"data")])
    other = tmp_path / "other.7z"
    write_archive(other, [("b.txt", b"data")])
    with SevenZipFile(archive, "r") as szf:
        plan = szf.preflight_destination(WINDOWS).plan
    with SevenZipFile(other, "r") as szf:
        with pytest.raises(ValueError):
            szf.extractall(tmp_path / "out", plan=plan)
    assert not (tmp_path / "out").exists()


def test_existing_directory_cover_issue(tmp_path):
    archive = tmp_path / "nested.7z"
    write_archive(archive, [("a/b/c.txt", b"data")])
    with SevenZipFile(archive, "r") as szf:
        report = szf.preflight_destination(WINDOWS, existing=[DestinationEntry("a", True)])
    assert report.ok
    plan = report.plan
    assert plan.effective_name(0) == "a/b/c.txt"


def test_forged_plan_cannot_escape_destination(tmp_path):
    import dataclasses

    from py7zr.preflight import PlannedMember

    archive = tmp_path / "forged.7z"
    write_archive(archive, [("inside.txt", b"data")])
    out = tmp_path / "out"
    with SevenZipFile(archive, "r") as szf:
        plan = szf.preflight_destination(WINDOWS).plan
        forged = dataclasses.replace(
            plan,
            entries=(PlannedMember(0, "inside.txt", "../../escaped.txt", "extract"),),
            approved=True,
        )
        with pytest.raises(DestinationConflictError):
            szf.extractall(out, plan=forged)
    assert not out.exists()
    assert not (tmp_path / "escaped.txt").exists()


def test_overwrite_policy_replaces_existing_file(tmp_path):
    archive = tmp_path / "overwrite.7z"
    write_archive(archive, [("team/report.txt", b"new")])
    destination = tmp_path / "existing"
    (destination / "team").mkdir(parents=True)
    (destination / "team" / "report.txt").write_bytes(b"old")
    factory = RecordingFactory()
    with SevenZipFile(archive, "r") as szf:
        report = szf.preflight_destination(
            DestinationProfile(case_sensitive=False, name="share"),
            existing=[DestinationEntry("team/report.txt", is_directory=False)],
        )
        plan = report.approve("overwrite")
        assert plan.ok
        assert szf.extractall(factory=factory, plan=plan) is None
    assert [name for name, _ in factory.created] == ["team/report.txt"]
    assert factory.created[0][1].read() == b"new"


def test_existing_directory_is_merged_not_reported(tmp_path):
    with SevenZipFile(tmp_path / "empty.7z", "w"):
        pass
    report = preflight(
        [DestinationMember(0, "Team/", True), DestinationMember(1, "team/note.txt")],
        destination=DestinationProfile(case_sensitive=False, name="share"),
        existing=[DestinationEntry("team", True)],
    )
    assert report.ok
    assert report.plan.effective_name(1) == "team/note.txt"
    blocking = preflight(
        [DestinationMember(0, "Team/", True)],
        destination=DestinationProfile(case_sensitive=False, name="share"),
        existing=[DestinationEntry("team", False)],
    )
    assert not blocking.ok
    assert blocking.conflicts[0].kind == "type"
    assert blocking.conflicts[0].existing is not None


def test_report_and_plan_summary_are_actionable(tmp_path):
    archive = tmp_path / "summary.7z"
    write_archive(archive, [("Report.txt", b"upper"), ("report.txt", b"lower")])
    with SevenZipFile(archive, "r") as szf:
        report = szf.preflight_destination(WINDOWS)
    text = report.summary()
    assert "member 0 'Report.txt'" in text
    assert "member 1 'report.txt'" in text
    assert "reject" in text
    plan_text = report.plan_for("rename").summary()
    assert "report~1.txt" in plan_text
