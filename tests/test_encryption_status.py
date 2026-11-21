import logging
import secrets

import pytest

import py7zr
from py7zr import Bad7zFile, EncryptionStatus, PasswordError, PasswordRequired

# Generated on the machine running the tests; never a real credential.
PASSWORD = secrets.token_urlsafe(18)
WRONG_PASSWORD = secrets.token_urlsafe(18)
DOC_A = b"alpha document\n"
DOC_B = b"beta document\n"
DOC_C = b"gamma document\n"
NAMES = ["docs/alpha.txt", "docs/beta.txt", "gamma.txt"]


def _assert_absent(secret, text, where):
    """Keep the generated credential out of pytest's failure output."""
    assert secret not in text, f"credential leaked into {where}"


def _write(path, password=None, header_encryption=False):
    with py7zr.SevenZipFile(path, "w", password=password, header_encryption=header_encryption) as archive:
        archive.writestr(DOC_A, "docs/alpha.txt")
        archive.writestr(DOC_B, "docs/beta.txt")
        archive.writestr(DOC_C, "gamma.txt")
    return path


def _read(path, password=None):
    return py7zr.SevenZipFile(path, "r", password=password)


def test_plain_archive_is_not_encrypted(tmp_path):
    archive = _write(tmp_path / "plain.7z")
    info = py7zr.get_encryption_info(archive)
    assert info.status is EncryptionStatus.NOT_ENCRYPTED
    assert info.directory_known is True
    assert info.member_count == 3
    assert info.needs_password is False
    with _read(archive) as reader:
        assert reader.needs_password() is False
        assert reader.encryption_status() is EncryptionStatus.NOT_ENCRYPTED
        assert reader.getnames() == NAMES
        assert [f.filename for f in reader.list()] == NAMES
        reader.extractall(path=tmp_path / "out")
    assert (tmp_path / "out/docs/alpha.txt").read_bytes() == DOC_A
    assert (tmp_path / "out/docs/beta.txt").read_bytes() == DOC_B
    assert (tmp_path / "out/gamma.txt").read_bytes() == DOC_C


def test_plain_archive_ignores_supplied_password(tmp_path):
    archive = _write(tmp_path / "plain.7z")
    with _read(archive, PASSWORD) as reader:
        assert reader.needs_password() is False
        assert reader.encryption_status() is EncryptionStatus.NOT_ENCRYPTED


def test_content_encrypted_directory_is_readable(tmp_path):
    archive = _write(tmp_path / "content.7z", password=PASSWORD)
    info = py7zr.get_encryption_info(archive)
    assert info.status is EncryptionStatus.CONTENT_ENCRYPTED
    assert info.directory_known is True
    assert info.member_count == 3
    assert info.needs_password is True
    with _read(archive) as reader:
        assert reader.needs_password() is True
        assert reader.encryption_status() is EncryptionStatus.CONTENT_ENCRYPTED
        assert reader.getnames() == NAMES
        members = reader.list()
        assert [m.filename for m in members] == NAMES
        assert all(m.is_file and not m.is_directory for m in members)
        assert [m.uncompressed for m in members] == [len(DOC_A), len(DOC_B), len(DOC_C)]
        assert reader.getinfo("docs/alpha.txt").uncompressed == len(DOC_A)


def test_content_encrypted_without_password_fails_on_data(tmp_path):
    archive = _write(tmp_path / "content.7z", password=PASSWORD)
    with _read(archive) as reader:
        with pytest.raises(PasswordRequired):
            reader.extractall(path=tmp_path / "out")
    with _read(archive) as reader:
        with pytest.raises(PasswordRequired):
            reader.testzip()


def test_content_encrypted_with_correct_password_reads_data(tmp_path):
    archive = _write(tmp_path / "content.7z", password=PASSWORD)
    with _read(archive, PASSWORD) as reader:
        assert reader.testzip() is None
        reader.reset()
        reader.extractall(path=tmp_path / "out")
    assert (tmp_path / "out/docs/alpha.txt").read_bytes() == DOC_A
    assert (tmp_path / "out/docs/beta.txt").read_bytes() == DOC_B
    assert (tmp_path / "out/gamma.txt").read_bytes() == DOC_C


def test_content_encrypted_with_wrong_password_is_rejected(tmp_path):
    archive = _write(tmp_path / "content.7z", password=PASSWORD)
    with _read(archive, WRONG_PASSWORD) as reader:
        with pytest.raises(PasswordError) as error:
            reader.testzip()
        _assert_absent(WRONG_PASSWORD, str(error.value), "exception message")
        reader.reset()
        with pytest.raises(PasswordError):
            reader.extractall(path=tmp_path / "out")


def test_header_encrypted_directory_is_hidden(tmp_path):
    archive = _write(tmp_path / "header.7z", password=PASSWORD, header_encryption=True)
    info = py7zr.get_encryption_info(archive)
    assert info.status is EncryptionStatus.HEADER_ENCRYPTED
    assert info.directory_known is False
    assert info.member_count is None
    assert info.needs_password is True
    with pytest.raises(PasswordRequired):
        _read(archive)


def test_header_encrypted_but_plain_content_still_needs_password(tmp_path):
    # A header may be encrypted while member data uses a non-crypto filter.
    # The report must follow the header, not the data coder chain.
    archive = tmp_path / "header-only.7z"
    with py7zr.SevenZipFile(
        archive,
        "w",
        password=PASSWORD,
        filters=[{"id": py7zr.FILTER_LZMA2}],
        header_encryption=True,
    ) as writer:
        writer.writestr(DOC_A, "docs/alpha.txt")

    info = py7zr.get_encryption_info(archive)
    assert info.status is EncryptionStatus.HEADER_ENCRYPTED
    assert info.directory_known is False
    with _read(archive, PASSWORD) as reader:
        assert reader.needs_password() is True
        assert reader.encryption_status() is EncryptionStatus.HEADER_ENCRYPTED
        assert reader.getnames() == ["docs/alpha.txt"]


def test_header_encrypted_with_correct_password_reads_data(tmp_path):
    archive = _write(tmp_path / "header.7z", password=PASSWORD, header_encryption=True)
    with _read(archive, PASSWORD) as reader:
        assert reader.needs_password() is True
        assert reader.encryption_status() is EncryptionStatus.HEADER_ENCRYPTED
        assert reader.getnames() == NAMES
        assert reader.testzip() is None
        reader.reset()
        reader.extractall(path=tmp_path / "out")
    assert (tmp_path / "out/gamma.txt").read_bytes() == DOC_C


def test_header_encrypted_with_wrong_password_is_rejected(tmp_path):
    archive = _write(tmp_path / "header.7z", password=PASSWORD, header_encryption=True)
    with pytest.raises(PasswordError) as error:
        _read(archive, WRONG_PASSWORD)
    _assert_absent(WRONG_PASSWORD, str(error.value), "exception message")
    assert not isinstance(error.value, Bad7zFile)


def test_header_encrypted_password_required_error_does_not_leak(tmp_path):
    archive = _write(tmp_path / "header.7z", password=PASSWORD, header_encryption=True)
    with pytest.raises(PasswordRequired) as error:
        _read(archive)
    _assert_absent(PASSWORD, str(error.value), "exception message")


def test_encryption_info_accepts_file_object(tmp_path):
    archive = _write(tmp_path / "content.7z", password=PASSWORD)
    with archive.open("rb") as stream:
        info = py7zr.get_encryption_info(stream)
        assert info.status is EncryptionStatus.CONTENT_ENCRYPTED
        assert stream.tell() == 0


def test_encryption_info_rejects_non_7z(tmp_path):
    bogus = tmp_path / "bogus.7z"
    bogus.write_bytes(b"not a 7z archive")
    with pytest.raises(Bad7zFile):
        py7zr.get_encryption_info(bogus)
    with pytest.raises(TypeError):
        py7zr.get_encryption_info(b"bogus")


def test_encryption_info_does_not_log_password(tmp_path, caplog):
    archive = _write(tmp_path / "content.7z", password=PASSWORD)
    caplog.set_level(logging.DEBUG)
    py7zr.get_encryption_info(archive)
    with pytest.raises(PasswordError):
        with _read(archive, WRONG_PASSWORD) as reader:
            reader.testzip()
    _assert_absent(PASSWORD, caplog.text, "log output")
    _assert_absent(WRONG_PASSWORD, caplog.text, "log output")


def test_encryption_info_repr_does_not_contain_password(tmp_path):
    archive = _write(tmp_path / "content.7z", password=PASSWORD)
    info = py7zr.get_encryption_info(archive)
    _assert_absent(PASSWORD, repr(info), "repr")
