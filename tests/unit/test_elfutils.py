from __future__ import annotations

from typing import Any
from unittest.mock import Mock, patch

import pytest
from elftools.common.exceptions import ELFError

from auditwheel.elfutils import (
    elf_exported_symbols,
    elf_file_filter,
    elf_find_imported_symbols,
    elf_find_versioned_symbols,
    elf_find_ucs2_symbols,
    elf_read_dt_needed,
    elf_references_pyfpe_jbuf,
    elf_symbol_versions,
    get_undefined_symbols,
)

from .candidate_fixtures import Needs, Provides, build_export_elf, build_import_elf


class MockSymbol(dict[str, Any]):
    """Mock representing a Symbol in ELFTools."""

    def __init__(self, name: str, **kwargs):  # type: ignore[no-untyped-def]
        super().__init__(**kwargs)
        self._name = name

    @property
    def name(self):
        return self._name


@patch("auditwheel.elfutils.ELFFile")
class TestElfReadDt:
    def test_missing_section(self, elffile_mock, tmp_path):
        fake = tmp_path / "fake.so"

        # GIVEN
        fake.touch()
        elffile_mock.return_value.get_section_by_name.return_value = None

        # THEN
        with pytest.raises(ValueError, match=r"^Could not find \.dynamic section.*"):
            # WHEN
            elf_read_dt_needed(fake)

    def test_needed_libs(self, elffile_mock, tmp_path):
        fake = tmp_path / "fake.so"

        # GIVEN
        fake.touch()
        section_mock = Mock()
        tag1 = Mock(needed="libz.so")
        tag1.entry.d_tag = "DT_NEEDED"
        tag2 = Mock(needed="libfoo.so")
        tag2.entry.d_tag = "DT_NEEDED"
        section_mock.iter_tags.return_value = [tag1, tag2]
        elffile_mock.return_value.get_section_by_name.return_value = section_mock

        # WHEN
        needed = elf_read_dt_needed(fake)

        # THEN
        assert len(needed) == 2
        assert "libz.so" in needed
        assert "libfoo.so" in needed


@patch("auditwheel.elfutils.ELFFile")
class TestElfFileFilter:
    def test_filter(self, elffile_mock, tmp_path):  # noqa: ARG002
        file1 = tmp_path / "file1.so"
        file2 = tmp_path / "file2.so"
        file1.touch()
        file2.touch()
        result = elf_file_filter([file1, file2])
        assert len(list(result)) == 2

    def test_some_py_files(self, elffile_mock, tmp_path):  # noqa: ARG002
        file1 = tmp_path / "file1.py"
        file2 = tmp_path / "file2.so"
        file3 = tmp_path / "file3.py"
        file1.touch()
        file2.touch()
        file3.touch()
        result = elf_file_filter([file1, file2, file3])
        assert len(list(result)) == 1

    def test_not_elf(self, elffile_mock, tmp_path):
        file1 = tmp_path / "file1.notelf"
        file2 = tmp_path / "file2.notelf"

        # GIVEN
        file1.touch()
        file2.touch()
        elffile_mock.side_effect = ELFError

        # WHEN
        result = elf_file_filter([file1, file2])

        # THEN
        assert len(list(result)) == 0


class TestElfFindVersionedSymbols:
    def test_find_symbols(self):
        # GIVEN
        elf = Mock()
        verneed = Mock()
        verneed.configure_mock(name="foo-lib")
        veraux = Mock()
        veraux.configure_mock(name="foo-lib")
        elf.get_section_by_name.return_value.iter_versions.return_value = ((verneed, [veraux]),)

        # WHEN
        symbols = list(elf_find_versioned_symbols(elf))

        # THEN
        assert symbols == [("foo-lib", "foo-lib")]

    @pytest.mark.parametrize("ld_name", ["ld-linux", "ld64.so.2", "ld64.so.1"])
    def test_only_ld_linux(self, ld_name):
        # GIVEN
        elf = Mock()
        verneed = Mock()
        verneed.configure_mock(name=ld_name)
        veraux = Mock()
        veraux.configure_mock(name="foo-lib")
        elf.get_section_by_name.return_value.iter_versions.return_value = ((verneed, [veraux]),)

        # WHEN
        symbols = list(elf_find_versioned_symbols(elf))

        # THEN
        assert len(symbols) == 0

    def test_empty_section(self):
        # GIVEN
        elf = Mock()
        elf.get_section_by_name.return_value = None

        # WHEN
        symbols = list(elf_find_versioned_symbols(elf))

        # THEN
        assert len(symbols) == 0


class TestFindUcs2Symbols:
    def test_missing_dynsym_section(self):
        # GIVEN
        elf = Mock()
        elf.get_section_by_name.return_value = None

        # THEN
        result = list(elf_find_ucs2_symbols(elf))
        assert result == []

    def test_elf_find_ucs2_symbols(self):
        # GIVEN
        elf = Mock()

        asunicode = MockSymbol(
            "PyUnicodeUCS2_AsUnicode",
            st_shndx="SHN_UNDEF",
            st_info={"type": "STT_FUNC"},
        )
        elf_symbols = (asunicode, Mock())
        elf_symbols[1].name = "foobar"
        elf.get_section_by_name.return_value.iter_symbols.return_value = elf_symbols

        # WHEN
        symbols = list(elf_find_ucs2_symbols(elf))

        # THEN
        assert len(symbols) == 1
        assert symbols[0] == "PyUnicodeUCS2_AsUnicode"

    def test_elf_find_ucs2_symbols_no_symbol(self):
        # GIVEN
        elf = Mock()

        elf_symbols = (MockSymbol("FooSymbol"),)
        elf.get_section_by_name.return_value.iter_symbols.return_value = elf_symbols

        # WHEN/THEN
        symbols = list(elf_find_ucs2_symbols(elf))
        assert len(symbols) == 0


class TestElfReferencesPyPFE:
    def test_elf_references_pyfpe_jbuf(self):
        # GIVEN
        elf = Mock()
        symbols = (
            MockSymbol(
                "PyFPE_jbuf",
                st_shndx="SHN_UNDEF",
                st_info={"type": "STT_FUNC"},
            ),
        )

        elf.get_section_by_name.return_value.iter_symbols.return_value = symbols

        # WHEN/THEN
        assert elf_references_pyfpe_jbuf(elf) is True

    def test_elf_references_pyfpe_jbuf_false(self):
        # GIVEN
        elf = Mock()
        symbols = (
            MockSymbol(
                "SomeSymbol",
                st_shndx="SHN_UNDEF",
                st_info={"type": "STT_FUNC"},
            ),
        )

        elf.get_section_by_name.return_value.iter_symbols.return_value = symbols

        # WHEN/THEN
        assert elf_references_pyfpe_jbuf(elf) is False

    def test_elf_references_pyfpe_jbuf_no_section(self):
        # GIVEN
        elf = Mock()

        # WHEN
        elf.get_section_by_name.return_value = None

        # WHEN/THEN
        assert elf_references_pyfpe_jbuf(elf) is False


@patch("auditwheel.elfutils.ELFFile")
class TestGetUndefinedSymbols:
    def test_missing_dynsym_section(self, elffile_mock, tmp_path):
        fake = tmp_path / "fake.so"

        # GIVEN
        fake.touch()
        elffile_mock.return_value.get_section_by_name.return_value = None

        # THEN
        result = get_undefined_symbols(fake)
        assert result == set()


class TestElfImportedSymbols:
    def test_find_real_symbol_names_and_versions(self, tmp_path):
        path = tmp_path / "import.so"
        path.write_bytes(
            build_import_elf(
                [
                    Needs("libm.so.6", "GLIBC_2.29", ["pow"]),
                    Needs("libc.so.6", "GLIBC_2.17", ["memcpy", "socket"]),
                ]
            )
        )

        versioned, names = elf_symbol_versions(path)

        assert versioned == {
            "libm.so.6": {"GLIBC_2.29"},
            "libc.so.6": {"GLIBC_2.17"},
        }
        assert names == {
            "libm.so.6": {"pow"},
            "libc.so.6": {"memcpy", "socket"},
        }

    def test_versioned_symbols_do_not_include_symbol_names(self, tmp_path):
        path = tmp_path / "import.so"
        path.write_bytes(build_import_elf([Needs("libm.so.6", "GLIBC_2.29", ["pow"])]))

        with path.open("rb") as f:
            assert list(elf_find_versioned_symbols(_open_elf(f))) == [
                ("libm.so.6", "GLIBC_2.29")
            ]
            f.seek(0)
            imported = elf_find_imported_symbols(_open_elf(f))

        assert imported == {"libm.so.6": {"pow": {"GLIBC_2.29"}}}

    def test_non_elf_returns_empty(self, tmp_path):
        path = tmp_path / "plain.txt"
        path.write_text("not an elf")
        assert elf_symbol_versions(path) == ({}, {})
        assert elf_exported_symbols(path) == {}


class TestElfExportedSymbols:
    def test_group_by_version(self, tmp_path):
        path = tmp_path / "export.so"
        path.write_bytes(
            build_export_elf(
                [
                    Provides("GLIBC_2.29", ["pow"]),
                    Provides("GLIBC_2.17", ["memcpy"]),
                ]
            )
        )

        assert elf_exported_symbols(path) == {
            "GLIBC_2.29": {"pow"},
            "GLIBC_2.17": {"memcpy"},
        }

    def test_candidate_runtime_requirements_are_separate(self, tmp_path):
        path = tmp_path / "export.so"
        path.write_bytes(
            build_export_elf(
                [Provides("GLIBC_2.29", ["pow"])],
                needs=[Needs("libc.so.6", "GLIBC_2.17", ["memcpy"])],
            )
        )

        assert elf_exported_symbols(path) == {"GLIBC_2.29": {"pow"}}
        assert elf_symbol_versions(path) == (
            {"libc.so.6": {"GLIBC_2.17"}},
            {"libc.so.6": {"memcpy"}},
        )


def _open_elf(handle):
    from elftools.elf.elffile import ELFFile

    return ELFFile(handle)
