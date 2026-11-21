# Tests for the protected document archive entry point.
#
# Threat model: a leaked archive must not reveal the report names (the table
# of contents) or the report bodies without the password, and a failed write
# or append must not leave a half-protected or damaged artifact behind.
import os
import pathlib

import pytest

import py7zr
from py7zr.exceptions import InvalidPasswordError, PasswordRequired, ProtectionRequired

PASSWORD = "tmp-document-password"


def _report(path: pathlib.Path, text: str = "quarterly confidential report\n") -> pathlib.Path:
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.security
def test_document_archive_hides_names_and_content(tmp_path):
    report = _report(tmp_path / "report.txt")
    target = tmp_path / "report.7z"

    with py7zr.open_document_archive(target, "w", password=PASSWORD) as doc:
        doc.write(report, "report.txt")

    raw = target.read_bytes()
    assert b"report.txt" not in raw
    assert b"quarterly confidential" not in raw

    # No password: the directory cannot even be read.
    with pytest.raises(PasswordRequired):
        py7zr.open_document_archive(target, "r")

    # Wrong password: a locatable error, not a generic parse failure.
    with pytest.raises(InvalidPasswordError) as ei:
        py7zr.open_document_archive(target, "r", password="wrong")
    assert os.fspath(ei.value.path) == os.fspath(target)

    # Correct password: names and content.
    with py7zr.open_document_archive(target, "r", password=PASSWORD) as doc:
        assert doc.namelist() == ["report.txt"]
        assert doc.protection_status() == {
            "header_encrypted": True,
            "content_encrypted": True,
            "password_protected": True,
            "satisfies_policy": True,
        }
        out = tmp_path / "out"
        doc.extractall(out)
    assert (out / "report.txt").read_text(encoding="utf-8") == "quarterly confidential report\n"


@pytest.mark.security
def test_document_archive_requires_password_before_writing(tmp_path):
    target = tmp_path / "report.7z"
    with pytest.raises(ProtectionRequired) as ei:
        py7zr.open_document_archive(target, "w")
    assert ei.value.missing == ("password",)
    assert os.fspath(ei.value.path) == os.fspath(target)
    assert not target.exists()


@pytest.mark.security
def test_document_archive_rejects_clear_filters_before_writing(tmp_path):
    target = tmp_path / "report.7z"
    filters = [{"id": py7zr.FILTER_LZMA2}]
    with pytest.raises(ProtectionRequired) as ei:
        py7zr.open_document_archive(target, "w", password=PASSWORD, filters=filters)
    assert ei.value.missing == ("content_encryption",)
    assert not target.exists()


@pytest.mark.security
def test_document_archive_does_not_downgrade_on_append(tmp_path):
    report = _report(tmp_path / "report.txt")
    target = tmp_path / "report.7z"
    with py7zr.open_document_archive(target, "w", password=PASSWORD) as doc:
        doc.write(report, "report.txt")
    before = target.read_bytes()

    # Even when the caller relaxes the policy, the existing encrypted header
    # is preserved instead of being rewritten in clear text.
    with py7zr.open_document_archive(
        target, "a", password=PASSWORD, require_header_encryption=False
    ) as doc:
        doc.write(report, "next.txt")
        assert doc.protection_status()["header_encrypted"] is True

    assert target.read_bytes() != before
    raw = target.read_bytes()
    assert b"next.txt" not in raw
    with py7zr.open_document_archive(target, "r", password=PASSWORD) as doc:
        assert doc.namelist() == ["report.txt", "next.txt"]


@pytest.mark.security
def test_low_level_append_wrong_password_preserves_target(tmp_path):
    report = _report(tmp_path / "report.txt")
    target = tmp_path / "report.7z"
    with py7zr.SevenZipFile(target, "w", password=PASSWORD, header_encryption=True) as z:
        z.write(report, "report.txt")
    before = target.read_bytes()

    # Appending with the wrong password used to be treated as "not a 7z
    # archive" and replaced the target with a fresh archive.
    with pytest.raises(InvalidPasswordError):
        with py7zr.SevenZipFile(target, "a", password="wrong", header_encryption=True) as z:
            z.write(report, "next.txt")
    assert target.read_bytes() == before
    with py7zr.SevenZipFile(target, "r", password=PASSWORD) as z:
        assert z.namelist() == ["report.txt"]


@pytest.mark.security
def test_low_level_append_rejects_header_downgrade(tmp_path):
    report = _report(tmp_path / "report.txt")
    target = tmp_path / "report.7z"
    with py7zr.SevenZipFile(target, "w", password=PASSWORD, header_encryption=True) as z:
        z.write(report, "report.txt")
    before = target.read_bytes()

    with pytest.raises(ProtectionRequired) as ei:
        py7zr.SevenZipFile(target, "a", password=PASSWORD, header_encryption=False)
    assert ei.value.missing == ("header_encryption",)
    assert target.read_bytes() == before


@pytest.mark.security
def test_document_archive_append_keeps_policy(tmp_path):
    report = _report(tmp_path / "report.txt")
    second = _report(tmp_path / "next.txt", "next confidential page\n")
    target = tmp_path / "report.7z"
    with py7zr.open_document_archive(target, "w", password=PASSWORD) as doc:
        doc.write(report, "report.txt")

    with py7zr.open_document_archive(target, "a", password=PASSWORD) as doc:
        doc.write(second, "next.txt")
        assert doc.protection_status()["header_encrypted"] is True

    raw = target.read_bytes()
    assert b"next.txt" not in raw
    with py7zr.open_document_archive(target, "r", password=PASSWORD) as doc:
        assert doc.namelist() == ["report.txt", "next.txt"]
        out = tmp_path / "out"
        doc.extractall(out)
    assert (out / "next.txt").read_text(encoding="utf-8") == "next confidential page\n"


@pytest.mark.security
def test_document_archive_append_rejects_plain_target(tmp_path):
    report = _report(tmp_path / "report.txt")
    target = tmp_path / "plain.7z"
    with py7zr.SevenZipFile(target, "w") as z:
        z.write(report, "report.txt")
    before = target.read_bytes()

    with pytest.raises(ProtectionRequired) as ei:
        py7zr.open_document_archive(target, "a", password=PASSWORD)
    assert ei.value.missing == ("header_encryption", "content_encryption")
    assert target.read_bytes() == before


@pytest.mark.security
def test_document_archive_append_wrong_password_preserves_target(tmp_path):
    report = _report(tmp_path / "report.txt")
    target = tmp_path / "report.7z"
    with py7zr.open_document_archive(target, "w", password=PASSWORD) as doc:
        doc.write(report, "report.txt")
    before = target.read_bytes()

    with pytest.raises(InvalidPasswordError):
        py7zr.open_document_archive(target, "a", password="wrong")
    assert target.read_bytes() == before
    with py7zr.open_document_archive(target, "r", password=PASSWORD) as doc:
        assert doc.namelist() == ["report.txt"]


@pytest.mark.security
def test_document_archive_overwrite_failure_keeps_old_artifact(tmp_path):
    report = _report(tmp_path / "report.txt")
    target = tmp_path / "report.7z"
    with py7zr.open_document_archive(target, "w", password="first-pass") as doc:
        doc.write(report, "old.txt")
    before = target.read_bytes()

    with pytest.raises(ProtectionRequired):
        py7zr.open_document_archive(target, "w", password=None)
    assert target.read_bytes() == before
    with py7zr.open_document_archive(target, "r", password="first-pass") as doc:
        assert doc.namelist() == ["old.txt"]

    # A successful overwrite replaces the artifact and is reopenable.
    with py7zr.open_document_archive(target, "w", password="second-pass") as doc:
        doc.write(report, "new.txt")
    with py7zr.open_document_archive(target, "r", password="second-pass") as doc:
        assert doc.namelist() == ["new.txt"]


@pytest.mark.security
def test_document_archive_read_reports_missing_protection(tmp_path):
    report = _report(tmp_path / "report.txt")
    target = tmp_path / "content-only.7z"
    with py7zr.SevenZipFile(target, "w", password=PASSWORD, header_encryption=False) as z:
        z.write(report, "report.txt")

    with pytest.raises(ProtectionRequired) as ei:
        py7zr.open_document_archive(target, "r", password=PASSWORD)
    assert ei.value.missing == ("header_encryption",)
    assert os.fspath(ei.value.path) == os.fspath(target)


@pytest.mark.security
def test_document_archive_policy_cannot_be_disabled_after_open(tmp_path):
    report = _report(tmp_path / "report.txt")
    target = tmp_path / "report.7z"
    with py7zr.open_document_archive(target, "w", password=PASSWORD) as doc:
        doc.write(report, "report.txt")
        with pytest.raises(ProtectionRequired):
            doc.set_encrypted_header(False)
    with py7zr.open_document_archive(target, "r", password=PASSWORD) as doc:
        assert doc.namelist() == ["report.txt"]


@pytest.mark.security
def test_document_archive_can_extend_existing_artifact(tmp_path):
    # An archive produced with the lower-level API remains a valid starting
    # point when it already meets the policy.
    report = _report(tmp_path / "report.txt")
    target = tmp_path / "existing.7z"
    with py7zr.SevenZipFile(target, "w", password=PASSWORD, header_encryption=True) as z:
        z.write(report, "report.txt")

    with py7zr.open_document_archive(target, "a", password=PASSWORD) as doc:
        doc.write(report, "added.txt")
    with py7zr.open_document_archive(target, "r", password=PASSWORD) as doc:
        assert doc.namelist() == ["report.txt", "added.txt"]
