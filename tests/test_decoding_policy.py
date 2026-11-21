"""Tests for the configurable decoding capability list (``allowed_methods``).

An internal import service only approves compression methods that operations
has validated.  ``SevenZipFile(..., allowed_methods=...)`` lets a caller reject
members whose folder uses a disallowed method while keeping the archive
directory listing (which only reads the header) available.

The checks run on header metadata before any decoder or ``WriterFactory``
product is created.
"""

import os
import pathlib

import pytest

import py7zr
from py7zr import (
    FILTER_DEFLATE,
    FILTER_LZMA2,
    SupportedMethods,
    UnsupportedCompressionMethodError,
    WriterFactory,
)
from py7zr.io import Py7zBytesIO

testdata_path = pathlib.Path(os.path.dirname(__file__)).joinpath("data")

# One off-policy local archive (LZ4 is not decodable by py7zr at all) and two
# ordinary archives that use validated, in-policy methods.
OFF_POLICY_ARCHIVE = testdata_path.joinpath("lz4.7z")
LZMA2_ARCHIVE = testdata_path.joinpath("lzma2_1.7z")
DEFLATE_ARCHIVE = testdata_path.joinpath("deflate.7z")

# A typical validated capability set used by the import service.
APPROVED_METHODS = [FILTER_LZMA2, FILTER_DEFLATE]


class RecordingFactory(WriterFactory):
    """WriterFactory that records every member it was asked to create."""

    def __init__(self) -> None:
        self.created: list[str] = []
        self.products: dict[str, Py7zBytesIO] = {}

    def create(self, filename: str):
        self.created.append(filename)
        product = Py7zBytesIO(filename, 10_000_000)
        self.products[filename] = product
        return product


@pytest.mark.security
def test_off_policy_archive_listing_remains_available():
    """The directory of a policy-out archive can still be inspected safely."""
    with py7zr.SevenZipFile(OFF_POLICY_ARCHIVE, allowed_methods=APPROVED_METHODS) as archive:
        names = archive.getnames()
        assert "scripts" in names
        assert "setup.py" in names
        members = archive.list()
        assert any(member.is_directory and member.filename == "scripts" for member in members)


@pytest.mark.security
def test_off_policy_archive_extraction_is_rejected(tmp_path):
    """A member using a disallowed method is rejected, not extracted."""
    with py7zr.SevenZipFile(OFF_POLICY_ARCHIVE, allowed_methods=APPROVED_METHODS) as archive:
        with pytest.raises(UnsupportedCompressionMethodError):
            archive.extractall(path=tmp_path)
    assert not any(tmp_path.iterdir())


@pytest.mark.security
def test_off_policy_archive_rejected_before_writer_factory_runs():
    """No WriterFactory product may be created for a rejected member."""
    factory = RecordingFactory()
    with py7zr.SevenZipFile(OFF_POLICY_ARCHIVE, allowed_methods=APPROVED_METHODS) as archive:
        with pytest.raises(UnsupportedCompressionMethodError):
            archive.extractall(factory=factory)
    assert factory.created == []


@pytest.mark.security
def test_off_policy_archive_testzip_is_rejected():
    with py7zr.SevenZipFile(OFF_POLICY_ARCHIVE, allowed_methods=APPROVED_METHODS) as archive:
        with pytest.raises(UnsupportedCompressionMethodError):
            archive.testzip()


@pytest.mark.security
@pytest.mark.parametrize(
    "archive_path",
    [LZMA2_ARCHIVE, DEFLATE_ARCHIVE],
)
def test_compliant_archives_extract_with_approved_policy(tmp_path, archive_path):
    """Both ordinary archives succeed when their methods are approved."""
    with py7zr.SevenZipFile(archive_path, allowed_methods=APPROVED_METHODS) as archive:
        archive.extractall(path=tmp_path)
    assert any(tmp_path.iterdir())


@pytest.mark.security
def test_compliant_archive_extracts_through_writer_factory():
    factory = RecordingFactory()
    with py7zr.SevenZipFile(DEFLATE_ARCHIVE, allowed_methods=APPROVED_METHODS) as archive:
        archive.extractall(factory=factory)
    assert sorted(factory.products) == ["test/test2.txt", "test1.txt"]


@pytest.mark.security
def test_tightening_the_policy_rejects_an_otherwise_supported_archive(tmp_path):
    """The same ordinary archive fails when its method is left off the list."""
    with py7zr.SevenZipFile(LZMA2_ARCHIVE, allowed_methods=[FILTER_DEFLATE]) as archive:
        # Listing is still available.
        assert archive.getnames()
        with pytest.raises(UnsupportedCompressionMethodError):
            archive.extractall(path=tmp_path)
    assert not any(tmp_path.iterdir())


@pytest.mark.security
def test_default_behavior_without_policy_is_unchanged(tmp_path):
    """Without allowed_methods the library behaves exactly as before."""
    with py7zr.SevenZipFile(DEFLATE_ARCHIVE) as archive:
        archive.extractall(path=tmp_path)
    assert any(tmp_path.iterdir())


@pytest.mark.security
def test_full_capability_list_allows_every_known_method(tmp_path):
    allowlist = SupportedMethods.supported_filter_ids()
    with py7zr.SevenZipFile(LZMA2_ARCHIVE, allowed_methods=allowlist) as archive:
        archive.extractall(path=tmp_path)
    assert any(tmp_path.iterdir())


@pytest.mark.security
def test_directory_only_selection_needs_no_decoder(tmp_path):
    """Selecting just a directory never decodes data, so it stays allowed."""
    with py7zr.SevenZipFile(OFF_POLICY_ARCHIVE, allowed_methods=APPROVED_METHODS) as archive:
        archive.extract(path=tmp_path, targets=["scripts"], recursive=False)
    assert tmp_path.joinpath("scripts").is_dir()


@pytest.mark.security
def test_policy_is_enforced_per_folder_in_mixed_archive(tmp_path):
    """A disallowed folder is rejected while an allowed member still extracts."""
    archive_path = tmp_path.joinpath("mixed.7z")
    with py7zr.SevenZipFile(archive_path, "w", filters=[{"id": FILTER_LZMA2}]) as archive:
        archive.writestr(b"lzma2-data" * 50, "a_lzma2.txt")
    with py7zr.SevenZipFile(archive_path, "a", filters=[{"id": FILTER_DEFLATE}]) as archive:
        archive.writestr(b"deflate-data" * 50, "b_deflate.txt")

    with py7zr.SevenZipFile(archive_path, allowed_methods=[FILTER_DEFLATE]) as archive:
        # The whole directory is still visible.
        assert archive.getnames() == ["a_lzma2.txt", "b_deflate.txt"]
        with pytest.raises(UnsupportedCompressionMethodError):
            archive.extractall(path=tmp_path.joinpath("all"))
        # The single member whose folder is allowed can still be extracted.
        archive.extract(path=tmp_path.joinpath("one"), targets=["b_deflate.txt"])
    assert (tmp_path / "one" / "b_deflate.txt").read_text() == "deflate-data" * 50
    assert not (tmp_path / "all").exists()
