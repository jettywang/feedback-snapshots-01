#-------------------------------------------------------------------------------
# binding_analysis: restricted static binding analysis built on pyelftools
#
# Statically models how undefined dynamic symbols of one ELF module would bind
# against an explicitly provided, ordered set of ELF modules. Nothing is
# loaded or executed; all facts come from parsing section headers, .dynamic,
# .dynsym and the GNU version sections with pyelftools.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
"""Static view of one ELF module's dynamic binding surface."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.gnuversions import (
    GNUVerDefSection, GNUVerNeedSection, GNUVerSymSection)
from elftools.elf.sections import SymbolTableSection

# Visibilities whose definitions never leave the defining module.
LOCAL_VISIBILITIES = frozenset({'STV_HIDDEN', 'STV_INTERNAL'})

_DT_FLAGS = {
    0x1: 'DF_ORIGIN',
    0x2: 'DF_SYMBOLIC',
    0x4: 'DF_TEXTREL',
    0x8: 'DF_BIND_NOW',
    0x10: 'DF_STATIC_TLS',
}
_DT_FLAGS_1 = {
    0x1: 'DF_1_NOW',
    0x2: 'DF_1_GLOBAL',
    0x4: 'DF_1_GROUP',
    0x8: 'DF_1_NODELETE',
    0x400: 'DF_1_INTERPOSE',
    0x80000: 'DF_1_SYMINTPOSE',
}


@dataclass(frozen=True)
class SymbolEvidence:
    """One dynamic symbol table entry, as binding evidence."""
    module: str           # display name of the owning module
    index: int            # .dynsym index
    name: str
    binding: str          # STB_GLOBAL / STB_WEAK / ...
    visibility: str       # STV_DEFAULT / STV_PROTECTED / ...
    defined: bool
    version: str | None   # version name from .gnu.version, if any
    version_hidden: bool  # GNU hidden-version bit (name@VER vs name@@VER)
    value: int            # st_value

    def describe(self) -> str:
        parts = [self.binding, self.visibility]
        if self.version is not None:
            parts.append('version %s%s' % (
                self.version, ' (hidden)' if self.version_hidden else ''))
        if self.defined:
            parts.append('defined value=0x%x' % self.value)
        else:
            parts.append('undefined')
        return '%s[%d] %s: %s' % (
            self.module, self.index, self.name, ', '.join(parts))


@dataclass
class LoadedModule:
    """Statically parsed binding-relevant facts of one ELF file."""
    path: str
    name: str                              # DT_SONAME or file name
    needed: list[str] = field(default_factory=list)
    flags: frozenset[str] = frozenset()    # DT_FLAGS names, e.g. DF_SYMBOLIC
    flags1: frozenset[str] = frozenset()   # DT_FLAGS_1 names
    defs: dict[str, list[SymbolEvidence]] = field(default_factory=dict)
    refs: list[SymbolEvidence] = field(default_factory=list)
    verdef_names: frozenset[str] = frozenset()
    verneeds: list[tuple[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Caller-supplied loading-policy hints that are not recorded in the file
    # itself (RTLD_DEEPBIND is a dlopen() flag, not an ELF bit).
    deepbind: bool = False

    @property
    def symbolic(self) -> bool:
        return 'DF_SYMBOLIC' in self.flags

    @property
    def has_verdefs(self) -> bool:
        return bool(self.verdef_names)

    @classmethod
    def from_path(cls, path: str) -> 'LoadedModule':
        with open(path, 'rb') as stream:
            elf = ELFFile(stream)
            dynamic = None
            dynsym = None
            versym = None
            verdef_names = set()
            verneeds = []
            for section in elf.iter_sections():
                if isinstance(section, DynamicSection):
                    dynamic = section
                elif isinstance(section, SymbolTableSection) and (
                        section['sh_type'] == 'SHT_DYNSYM'):
                    dynsym = section
                elif isinstance(section, GNUVerSymSection):
                    versym = section
                elif isinstance(section, GNUVerDefSection):
                    for _verdef, aux_iter in section.iter_versions():
                        for aux in aux_iter:
                            verdef_names.add(aux.name)
                elif isinstance(section, GNUVerNeedSection):
                    for verneed, aux_iter in section.iter_versions():
                        for aux in aux_iter:
                            verneeds.append((verneed.name, aux.name))

            name = os.path.basename(path)
            needed = []
            flags = frozenset()
            flags1 = frozenset()
            if dynamic is not None:
                for tag in dynamic.iter_tags():
                    if tag.entry.d_tag == 'DT_SONAME':
                        name = tag.soname
                    elif tag.entry.d_tag == 'DT_NEEDED':
                        needed.append(tag.needed)
                    elif tag.entry.d_tag == 'DT_FLAGS':
                        flags = frozenset(_flag_names(tag['d_val'], _DT_FLAGS))
                    elif tag.entry.d_tag == 'DT_FLAGS_1':
                        flags1 = frozenset(
                            _flag_names(tag['d_val'], _DT_FLAGS_1))

            module = cls(
                path=path, name=name, needed=needed, flags=flags,
                flags1=flags1, verdef_names=frozenset(verdef_names),
                verneeds=verneeds)

            if dynsym is None:
                module.notes.append('no .dynsym section; module is opaque')
                return module

            for index in range(dynsym.num_symbols()):
                symbol = dynsym.get_symbol(index)
                bind = symbol['st_info']['bind']
                if bind == 'STB_LOCAL' or not symbol.name:
                    continue
                version, version_hidden = _symbol_version(
                    versym, index, module.notes)
                evidence = SymbolEvidence(
                    module=name,
                    index=index,
                    name=symbol.name,
                    binding=bind,
                    visibility=symbol['st_other']['visibility'],
                    defined=symbol['st_shndx'] != 'SHN_UNDEF',
                    version=version,
                    version_hidden=version_hidden,
                    value=symbol['st_value'])
                if evidence.defined:
                    module.defs.setdefault(evidence.name, []).append(evidence)
                else:
                    module.refs.append(evidence)
            return module


def _flag_names(value: int, table: dict[int, str]) -> list[str]:
    return [flag_name for bit, flag_name in sorted(table.items())
            if value & bit]


def _symbol_version(versym, index, notes):
    """(version name, hidden bit) for dynsym entry index, or (None, False)."""
    if versym is None:
        return None, False
    try:
        info = versym.get_symbol_version(index)
    except ELFError as exc:
        notes.append('versym[%d] inconsistent: %s' % (index, exc))
        return None, False
    if info is None or info['index'] in ('VER_NDX_LOCAL', 'VER_NDX_GLOBAL'):
        return None, False
    return info['name'], info['hidden']
