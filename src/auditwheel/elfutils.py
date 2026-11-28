from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, TypeVar

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.gnuversions import GNUVerNeedSection, GNUVerSymSection
from elftools.elf.sections import Section, SymbolTableSection

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from pathlib import Path

    _SectionT = TypeVar("_SectionT", bound=Section)


def _get_section_by_type(elf: ELFFile, type_: type[_SectionT]) -> _SectionT | None:
    name = {
        DynamicSection: ".dynamic",
        GNUVerNeedSection: ".gnu.version_r",
        GNUVerSymSection: ".gnu.version",
        SymbolTableSection: ".dynsym",
    }[type_]
    section = elf.get_section_by_name(name)
    if TYPE_CHECKING:
        assert section is None or isinstance(section, type_)
    return section


def elf_read_dt_needed(fn: Path) -> list[str]:
    needed: list[str] = []
    with fn.open("rb") as f:
        elf = ELFFile(f)
        section = _get_section_by_type(elf, DynamicSection)
        if section is None:
            msg = f"Could not find .dynamic section in {fn}"
            raise ValueError(msg)
        needed.extend(t.needed for t in section.iter_tags() if t.entry.d_tag == "DT_NEEDED")  # type: ignore[attr-defined]
    return needed


def elf_file_filter(paths: Iterable[Path]) -> Iterator[tuple[Path, ELFFile]]:
    """Filter through an iterator of filenames and load up only ELF
    files
    """
    for path in paths:
        if path.name.endswith(".py"):
            continue
        else:
            try:
                with path.open("rb") as f:
                    candidate = ELFFile(f)
                    yield path, candidate
            except ELFError:
                # not an elf file
                continue


def elf_find_versioned_symbols(elf: ELFFile) -> Iterator[tuple[str, str]]:
    if section := _get_section_by_type(elf, GNUVerNeedSection):
        for verneed, verneed_iter in section.iter_versions():
            if TYPE_CHECKING:
                # this should be enforced some other way in pyelftools
                assert verneed.name is not None
            if verneed.name.startswith("ld-linux") or verneed.name in [
                "ld64.so.2",
                "ld64.so.1",
            ]:
                continue
            for vernaux in verneed_iter:
                yield (verneed.name, vernaux.name)


def elf_find_versioned_symbol_names(elf: ELFFile) -> Iterator[tuple[str, str, str]]:
    """Report the real symbol names behind each required symbol version.

    Unlike :func:`elf_find_versioned_symbols`, which only reports the version
    node (``GLIBC_2.29``), this walks ``.gnu.version`` together with ``.dynsym``
    so a report can point at the actual imported symbol (``pow``) that is not
    covered by a candidate library.

    Yields ``(library, symbol_version, symbol_name)`` for every non-weak,
    undefined dynamic symbol that carries a version from ``.gnu.version_r``.
    """
    verneed_section = _get_section_by_type(elf, GNUVerNeedSection)
    versym_section = _get_section_by_type(elf, GNUVerSymSection)
    dynsym_section = _get_section_by_type(elf, SymbolTableSection)
    if verneed_section is None or versym_section is None or dynsym_section is None:
        return

    for index in range(min(versym_section.num_symbols(), dynsym_section.num_symbols())):
        symbol = dynsym_section.get_symbol(index)
        if symbol["st_shndx"] != "SHN_UNDEF" or symbol["st_info"]["bind"] == "STB_WEAK":
            continue
        version_index = versym_section.get_symbol(index)["ndx"]
        if not isinstance(version_index, int):
            # VER_NDX_LOCAL / VER_NDX_GLOBAL: no version node attached
            continue
        # The high bit flags hidden versions and is not part of the index.
        version_index &= 0x7FFF
        version = verneed_section.get_version(version_index)
        if version is None:
            continue
        verneed, vernaux = version
        if TYPE_CHECKING:
            assert verneed.name is not None
        if verneed.name.startswith("ld-linux") or verneed.name in ["ld64.so.2", "ld64.so.1"]:
            continue
        yield verneed.name, vernaux.name, symbol.name


def elf_find_imported_symbols(elf: ELFFile) -> dict[str, dict[str, set[str]]]:
    """Return ``{library: {symbol: {version, ...}}}`` for versioned imports."""
    imported: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for library, version, name in elf_find_versioned_symbol_names(elf):
        imported[library][name].add(version)
    return {library: dict(symbols) for library, symbols in imported.items()}


def elf_find_ucs2_symbols(elf: ELFFile) -> Iterator[str]:
    if section := _get_section_by_type(elf, SymbolTableSection):
        # look for UCS2 symbols that are externally referenced
        for sym in section.iter_symbols():
            if (
                "PyUnicodeUCS2_" in sym.name
                and sym["st_shndx"] == "SHN_UNDEF"
                and sym["st_info"]["type"] == "STT_FUNC"
            ):
                yield sym.name


def elf_references_pyfpe_jbuf(elf: ELFFile) -> bool:
    offending_symbol_names = ("PyFPE_jbuf", "PyFPE_dummy", "PyFPE_counter")
    if section := _get_section_by_type(elf, SymbolTableSection):
        # look for symbols that are externally referenced
        for sym in section.iter_symbols():
            if (
                sym.name in offending_symbol_names
                and sym["st_shndx"] == "SHN_UNDEF"
                and sym["st_info"]["type"] in ("STT_FUNC", "STT_NOTYPE")
            ):
                return True
    return False


def elf_is_python_extension(fn: Path, elf: ELFFile) -> tuple[bool, int | None]:
    modname = fn.name.split(".", 1)[0]
    module_init_f = {
        "init" + modname: 2,
        "PyInit_" + modname: 3,
        "_cffi_pypyinit_" + modname: 2,
    }

    sect = _get_section_by_type(elf, SymbolTableSection)
    if sect is None:
        return False, None

    for sym in sect.iter_symbols():
        if (
            sym.name in module_init_f
            and sym["st_shndx"] != "SHN_UNDEF"
            and sym["st_info"]["type"] == "STT_FUNC"
        ):
            return True, module_init_f[sym.name]

    return False, None


def elf_find_exported_symbols(elf: ELFFile) -> dict[str, set[str]]:
    """Return the symbols an ELF file exports, grouped by symbol version.

    Unversioned symbols are grouped under the empty string.  Only globally
    visible or weak symbols are reported; local symbols are implementation
    details and cannot satisfy a dependency.
    """
    dynsym_section = _get_section_by_type(elf, SymbolTableSection)
    if dynsym_section is None:
        return {}

    versym_section = _get_section_by_type(elf, GNUVerSymSection)
    verdef_section = elf.get_section_by_name(".gnu.version_d")
    if TYPE_CHECKING:
        from elftools.elf.gnuversions import GNUVerDefSection

        assert verdef_section is None or isinstance(verdef_section, GNUVerDefSection)

    exported: dict[str, set[str]] = defaultdict(set)
    for index in range(dynsym_section.num_symbols()):
        symbol = dynsym_section.get_symbol(index)
        if symbol["st_shndx"] == "SHN_UNDEF":
            continue
        if symbol["st_info"]["bind"] not in {"STB_GLOBAL", "STB_WEAK"}:
            continue
        version = ""
        if versym_section is not None and verdef_section is not None:
            version_index = versym_section.get_symbol(index)["ndx"]
            if isinstance(version_index, int):
                version_index &= 0x7FFF
                if version_index > 1:
                    defined = verdef_section.get_version(version_index)
                    if defined is not None:
                        # verdef auxiliaries are yielded as an iterator whose
                        # first entry holds the version name.
                        version = next(iter(defined[1])).name
        exported[version].add(symbol.name)
    return dict(exported)


def elf_symbol_versions(
    fn: Path,
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Return ``(versioned_symbols, versioned_symbol_names)`` for one ELF file.

    ``versioned_symbols`` maps a library name to the symbol versions it must
    provide, e.g. ``{"libm.so.6": {"GLIBC_2.29"}}``.  ``versioned_symbol_names``
    maps the same library name to the real imported symbol names, e.g.
    ``{"libm.so.6": {"pow"}}``.  Both are empty for non-ELF files.
    """
    versioned_symbols: dict[str, set[str]] = defaultdict(set)
    versioned_symbol_names: dict[str, set[str]] = defaultdict(set)
    try:
        with fn.open("rb") as f:
            elf = ELFFile(f)
            for library, version in elf_find_versioned_symbols(elf):
                versioned_symbols[library].add(version)
            for library, _, name in elf_find_versioned_symbol_names(elf):
                versioned_symbol_names[library].add(name)
    except ELFError:
        pass
    return dict(versioned_symbols), dict(versioned_symbol_names)


def elf_exported_symbols(fn: Path) -> dict[str, set[str]]:
    """Return the symbol versions exported by one ELF file.

    The result maps a version name (empty string for unversioned symbols) to
    the set of exported symbol names.
    """
    try:
        with fn.open("rb") as f:
            return elf_find_exported_symbols(ELFFile(f))
    except ELFError:
        return {}


def get_undefined_symbols(path: Path) -> set[str]:
    undef_symbols = set()
    with path.open("rb") as f:
        elf = ELFFile(f)
        if section := _get_section_by_type(elf, SymbolTableSection):
            # look for all undef symbols
            # if the symbol is weak don't consider it as undefined, it's "optional"
            for sym in section.iter_symbols():
                if sym["st_shndx"] == "SHN_UNDEF" and sym["st_info"]["bind"] != "STB_WEAK":
                    undef_symbols.add(sym.name)
    return undef_symbols


def filter_undefined_symbols(
    path: Path,
    symbols: dict[str, frozenset[str]],
) -> dict[str, list[str]]:
    if not symbols:
        return {}
    undef_symbols = set("*") | get_undefined_symbols(path)
    result = {}
    for lib, sym_list in symbols.items():
        intersection = sym_list & undef_symbols
        if intersection:
            result[lib] = sorted(intersection)
    return result
