"""Tests for the read-only archive comparison entry point.

These tests build their own archives so that compression settings, timestamps
and the failure fixtures are all under local control.  They also assert the
central promise of the feature: comparison never writes member plaintext to
disk.
"""

import io
import json
import os
import pathlib
import shutil
import stat

import pytest

import py7zr
import py7zr.cli
import py7zr.forensics
from py7zr.forensics import MemberVerdict

pytestmark = pytest.mark.misc


def _make_source(base: pathlib.Path, files: dict[str, bytes]) -> pathlib.Path:
    source = base / "src"
    source.mkdir(exist_ok=True)
    for name, data in files.items():
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return source


def _archive(base: pathlib.Path, name: str, source: pathlib.Path, filters=None, mtime: int | None = None):
    """Archive *source*'s files under ``docs/`` with a controllable mtime."""
    target = base / name
    if mtime is not None:
        for item in source.rglob("*"):
            os.utime(item, (mtime, mtime))
    with py7zr.SevenZipFile(target, "w", filters=filters) as archive:
        for item in sorted(source.iterdir()):
            archive.write(item, f"docs/{item.name}")
    return target


def _by_name(comparison):
    return {member.name: member for member in comparison.members}


def _snapshot_tree(root: pathlib.Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


LZMA_FILTERS = [{"id": py7zr.FILTER_LZMA2, "preset": 1}]
BZIP2_FILTERS = [{"id": py7zr.FILTER_BZIP2}]


@pytest.fixture
def compression_pair(tmp_path):
    """Same member bytes, two different compression settings and mtimes."""
    source = _make_source(tmp_path, {"alpha.txt": b"alpha\n" * 200, "beta.bin": bytes(range(256)) * 20})
    left = _archive(tmp_path, "left.7z", source, filters=LZMA_FILTERS, mtime=1_600_000_000)
    right = _archive(tmp_path, "right.7z", source, filters=BZIP2_FILTERS, mtime=1_700_000_000)
    return left, right


def test_different_compression_is_packaging_only(compression_pair):
    left, right = compression_pair
    comparison = py7zr.compare_archives(left, right)

    assert comparison.only_packaging_changes is True
    assert comparison.has_content_changes is False
    assert comparison.has_unverifiable is False
    assert comparison.summary() == {
        "members": 2,
        "content_changed": 0,
        "packaging_changed": 2,
        "unverifiable": 0,
        "identical": 0,
    }
    assert set(comparison.archive_changes) >= {"methods", "size"}
    for member in comparison.packaging_changes:
        assert member.left.sha256 == member.right.sha256
        assert member.left.sha256 is not None
        assert "methods" in member.changes
        assert "lastwritetime" in member.changes


def test_content_change_is_traceable_to_the_member(tmp_path):
    source = _make_source(tmp_path, {"same.txt": b"unchanged", "changed.txt": b"before"})
    left = _archive(tmp_path, "left.7z", source, filters=LZMA_FILTERS)
    (source / "changed.txt").write_bytes(b"after, genuinely different")
    right = _archive(tmp_path, "right.7z", source, filters=LZMA_FILTERS)

    comparison = py7zr.compare_archives(left, right)
    members = _by_name(comparison)

    assert comparison.has_content_changes is True
    changed = members["docs/changed.txt"]
    assert changed.verdict is MemberVerdict.CONTENT_CHANGED
    assert changed.evidence == "sha256"
    assert changed.left.sha256 != changed.right.sha256
    assert changed.left.size != changed.right.size
    # The unchanged neighbour is not smeared into the content-change group.
    assert members["docs/same.txt"].verdict is MemberVerdict.IDENTICAL
    # Evidence is specific enough to locate the member in the archive.
    assert comparison.content_changes == (changed,)


def test_added_and_removed_members_are_content_changes(tmp_path):
    source = _make_source(tmp_path, {"kept.txt": b"k", "removed.txt": b"r"})
    left = _archive(tmp_path, "left.7z", source, filters=LZMA_FILTERS)
    (source / "removed.txt").unlink()
    (source / "added.txt").write_bytes(b"a")
    right = _archive(tmp_path, "right.7z", source, filters=LZMA_FILTERS)

    members = _by_name(py7zr.compare_archives(left, right))
    assert members["docs/removed.txt"].verdict is MemberVerdict.REMOVED
    assert members["docs/added.txt"].verdict is MemberVerdict.ADDED
    assert members["docs/kept.txt"].verdict is MemberVerdict.IDENTICAL


def test_byte_identical_archives_are_identical(tmp_path):
    source = _make_source(tmp_path, {"a.txt": b"a" * 100, "nested/b.txt": b"b" * 100})
    with py7zr.SevenZipFile(tmp_path / "left.7z", "w") as archive:
        archive.writeall(source, "docs")
    with py7zr.SevenZipFile(tmp_path / "right.7z", "w") as archive:
        archive.writeall(source, "docs")

    comparison = py7zr.compare_archives(tmp_path / "left.7z", tmp_path / "right.7z")
    assert comparison.only_packaging_changes is True
    assert comparison.summary()["identical"] == 4  # two directories and two files
    assert all(member.verdict is MemberVerdict.IDENTICAL for member in comparison.members)
    assert all(member.left.sha256 == member.right.sha256 for member in comparison.members)


def test_comparison_never_writes_plaintext(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    source = _make_source(work, {"alpha.txt": b"alpha\n" * 200, "beta.bin": bytes(range(256)) * 20})
    left = _archive(work, "left.7z", source, filters=LZMA_FILTERS)
    right = _archive(work, "right.7z", source, filters=BZIP2_FILTERS)

    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    shutil.move(left, sandbox / "left.7z")
    shutil.move(right, sandbox / "right.7z")
    before = _snapshot_tree(sandbox)

    comparison = py7zr.compare_archives(sandbox / "left.7z", sandbox / "right.7z")

    assert comparison.members
    # No member was materialised next to the archives or anywhere in the sandbox.
    assert _snapshot_tree(sandbox) == before
    assert sorted(path.name for path in sandbox.iterdir()) == ["left.7z", "right.7z"]


def test_duplicate_member_names_are_matched_by_occurrence(tmp_path):
    left = tmp_path / "left.7z"
    with py7zr.SevenZipFile(left, "w", filters=LZMA_FILTERS) as archive:
        archive.writef(io.BytesIO(b"first copy"), "same.txt")
        archive.writef(io.BytesIO(b"second copy"), "same.txt")
    right = tmp_path / "right.7z"
    with py7zr.SevenZipFile(right, "w", filters=LZMA_FILTERS) as archive:
        archive.writef(io.BytesIO(b"first copy"), "same.txt")
        archive.writef(io.BytesIO(b"second copy changed"), "same.txt")

    comparison = py7zr.compare_archives(left, right)
    first, second = comparison.members
    assert (first.name, first.occurrence) == ("same.txt", 0)
    assert (second.name, second.occurrence) == ("same.txt", 1)
    # Occurrence 0 is byte-identical; its only differences are wrapper timestamps.
    assert first.left.sha256 == first.right.sha256
    assert first.verdict is MemberVerdict.PACKAGING_CHANGED
    # Occurrence 1 is the member that really changed, and is named accordingly.
    assert second.verdict is MemberVerdict.CONTENT_CHANGED
    assert second.left.sha256 != second.right.sha256
    assert second.display_name == "same.txt#2"


def test_unreadable_archive_is_unverifiable_not_removed(tmp_path):
    source = _make_source(tmp_path, {"a.txt": b"same content"})
    left = _archive(tmp_path, "left.7z", source, filters=LZMA_FILTERS)
    locked = tmp_path / "locked.7z"
    locked.write_bytes(left.read_bytes())
    os.chmod(locked, 0)

    try:
        if os.access(locked, os.R_OK):  # running as a privileged user defeats the fixture
            pytest.skip("cannot make an unreadable file for this user")
        comparison = py7zr.compare_archives(left, locked)
    finally:
        os.chmod(locked, stat.S_IRUSR | stat.S_IWUSR)

    assert comparison.left.error is None
    assert comparison.right.error is not None
    assert comparison.has_content_changes is False
    assert [m.name for m in comparison.unverifiable] == ["docs/a.txt"]
    assert "could not be read" in comparison.unverifiable[0].notes[0]


def test_encrypted_archive_is_unverifiable_without_password(tmp_path):
    source = _make_source(tmp_path, {"secret.txt": b"secret"})
    left = _archive(tmp_path, "left.7z", source, filters=LZMA_FILTERS)
    encrypted = tmp_path / "encrypted.7z"
    with py7zr.SevenZipFile(encrypted, "w", password="pw") as archive:
        for item in sorted(source.iterdir()):
            archive.write(item, f"docs/{item.name}")

    comparison = py7zr.compare_archives(left, encrypted)
    assert [m.name for m in comparison.unverifiable] == ["docs/secret.txt"]
    assert comparison.has_content_changes is False

    with_password = py7zr.compare_archives(left, encrypted, password="pw")
    assert with_password.unverifiable == ()
    assert with_password.only_packaging_changes is True


def test_report_is_json_serialisable_and_carries_digests_only(compression_pair):
    left, right = compression_pair
    comparison = py7zr.compare_archives(left, right)
    record = comparison.to_dict()
    rendered = json.dumps(record)
    assert record["read_only"] is True
    assert record["digest_algorithm"] == "sha256"
    assert all(member["left"]["sha256"] is not None for member in record["members"])
    # Evidence contains digests, never member bytes.
    assert ("alpha\n" * 200) not in rendered
    assert bytes(range(256)) * 20 not in rendered.encode("latin-1", "ignore")
    for member in record["members"]:
        assert member["left"]["sha256"] == member["right"]["sha256"]


def test_cli_compare_exit_codes_and_json(compression_pair, capsys):
    left, right = compression_pair
    cli = py7zr.cli.Cli()

    assert cli.run(["compare", str(left), str(right)]) == 0
    text, _ = capsys.readouterr()
    assert "Packaging only (2)" in text
    assert "Content changed (0)" in text

    assert cli.run(["compare", str(left), str(right), "--json"]) == 0
    payload, _ = capsys.readouterr()
    parsed = json.loads(payload)
    assert parsed["summary"]["packaging_changed"] == 2


def test_cli_compare_reports_content_change_exit_code(tmp_path, capsys):
    source = _make_source(tmp_path, {"doc.txt": b"v1"})
    left = _archive(tmp_path, "left.7z", source, filters=LZMA_FILTERS)
    (source / "doc.txt").write_bytes(b"v2 changed")
    right = _archive(tmp_path, "right.7z", source, filters=LZMA_FILTERS)

    cli = py7zr.cli.Cli()
    assert cli.run(["compare", str(left), str(right)]) == 1
    out, _ = capsys.readouterr()
    assert "[content_changed] docs/doc.txt" in out


@pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX permission fixture")
def test_cli_compare_unverifiable_exit_code(tmp_path, capsys):
    source = _make_source(tmp_path, {"doc.txt": b"content"})
    left = _archive(tmp_path, "left.7z", source, filters=LZMA_FILTERS)
    locked = tmp_path / "locked.7z"
    locked.write_bytes(left.read_bytes())
    os.chmod(locked, 0)
    try:
        if os.access(locked, os.R_OK):
            pytest.skip("cannot make an unreadable file for this user")
        code = py7zr.cli.Cli().run(["compare", str(left), str(locked)])
    finally:
        os.chmod(locked, stat.S_IRUSR | stat.S_IWUSR)
    out, _ = capsys.readouterr()
    assert code == 2
    assert "Unverifiable (1)" in out


def test_missing_archive_is_reported_by_cli(tmp_path, capsys):
    source = _make_source(tmp_path, {"a.txt": b"a"})
    left = _archive(tmp_path, "left.7z", source, filters=LZMA_FILTERS)
    code = py7zr.cli.Cli().run(["compare", str(left), str(tmp_path / "absent.7z")])
    out, _ = capsys.readouterr()
    assert code == 1
    assert "not found" in out


def test_local_fixture_archives_compare_cleanly(tmp_path):
    """Run the entry point against repository fixtures, not just archives made here."""
    fixture = pathlib.Path(__file__).parent / "data" / "lzma2_1.7z"
    copy = tmp_path / "copy.7z"
    copy.write_bytes(fixture.read_bytes())

    comparison = py7zr.compare_archives(fixture, copy)
    assert comparison.left.member_count == comparison.right.member_count > 0
    assert comparison.has_content_changes is False
    assert comparison.has_unverifiable is False
    assert len(comparison.identical) == comparison.left.member_count


def test_corrupt_payload_keeps_members_but_marks_them_unverifiable(tmp_path):
    """A damaged payload leaves the member list intact and never manufactures removals."""
    source = _make_source(tmp_path, {"first.txt": b"A" * 4096, "second.txt": b"B" * 4096, "third.txt": b"C" * 4096})
    left = _archive(tmp_path, "left.7z", source, filters=LZMA_FILTERS)
    right = tmp_path / "right.7z"
    right.write_bytes(left.read_bytes())

    with py7zr.SevenZipFile(right, "r") as archive:
        payload_start = archive.pack_data_start
        payload_end = payload_start + archive.header.main_streams.packinfo.packpositions[-1]
    assert payload_end > payload_start
    blob = bytearray(right.read_bytes())
    # Flip bytes in the middle of the main packed stream, leaving the header streams intact.
    middle = payload_start + (payload_end - payload_start) // 2
    for offset in range(middle, middle + 8):
        blob[offset] ^= 0xFF
    right.write_bytes(bytes(blob))

    comparison = py7zr.compare_archives(left, right)
    assert comparison.left.error is None
    assert comparison.has_content_changes is False
    # Every member is accounted for; the damaged ones are unverifiable, not removed.
    assert {m.name for m in comparison.members} == {"docs/first.txt", "docs/second.txt", "docs/third.txt"}
    assert comparison.unverifiable, "corrupt payload should not verify"
    assert comparison.right.error is None, "a damaged payload must not hide the member list"
    assert comparison.right.member_count == 3
    for member in comparison.unverifiable:
        assert member.right is not None and member.right.sha256 is None and member.right.error


def test_empty_and_directory_only_archives(tmp_path):
    empty_left = tmp_path / "empty-left.7z"
    empty_right = tmp_path / "empty-right.7z"
    with py7zr.SevenZipFile(empty_left, "w"):
        pass
    with py7zr.SevenZipFile(empty_right, "w"):
        pass
    empty = py7zr.compare_archives(empty_left, empty_right)
    assert empty.members == ()
    assert empty.left.error is None
    assert empty.only_packaging_changes is True

    source = _make_source(tmp_path, {})
    (source / "sub").mkdir()
    left = tmp_path / "dirs-left.7z"
    right = tmp_path / "dirs-right.7z"
    with py7zr.SevenZipFile(left, "w") as archive:
        archive.write(source / "sub", "docs/sub")
    with py7zr.SevenZipFile(right, "w") as archive:
        archive.write(source / "sub", "docs/sub")
    directories = py7zr.compare_archives(left, right)
    assert [m.left.kind for m in directories.members if m.left is not None] == ["directory"]
    assert directories.members[0].left.sha256 is None
    assert directories.members[0].verdict is MemberVerdict.IDENTICAL


def test_missing_archive_via_api_is_unverifiable(tmp_path):
    source = _make_source(tmp_path, {"a.txt": b"a"})
    left = _archive(tmp_path, "left.7z", source, filters=LZMA_FILTERS)
    comparison = py7zr.compare_archives(left, tmp_path / "does-not-exist.7z")

    assert comparison.right.error is not None
    assert comparison.right.exists is False
    assert comparison.has_content_changes is False
    assert [m.verdict for m in comparison.members] == [MemberVerdict.UNVERIFIABLE]


def test_cli_show_identical(tmp_path, capsys):
    source = _make_source(tmp_path, {"a.txt": b"a" * 64, "b.txt": b"b" * 64})
    fixed = 1_700_000_000
    left = _archive(tmp_path, "left.7z", source, filters=LZMA_FILTERS, mtime=fixed)
    right = _archive(tmp_path, "right.7z", source, filters=LZMA_FILTERS, mtime=fixed)

    hidden, _ = (py7zr.cli.Cli().run(["compare", str(left), str(right)]), capsys.readouterr())[1]
    assert "Identical (2)" not in hidden

    code = py7zr.cli.Cli().run(["compare", str(left), str(right), "--show-identical"])
    out, _ = capsys.readouterr()
    assert code == 0
    assert "Identical (2)" in out
