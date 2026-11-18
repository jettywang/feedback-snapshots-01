#-------------------------------------------------------------------------------
# elftools: dwarf/debugnames.py
#
# DWARFv5 .debug_names section decoding (accelerated access name index)
#
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

from functools import cached_property
from typing import IO, TYPE_CHECKING, NamedTuple

from ..common.exceptions import DWARFError
from ..common.utils import dwarf_assert, parse_cstring_from_stream, struct_parse
from ..construct.lib.container import Container
from .enums import DW_FORM_raw2name, DW_IDX_raw2name, ENUM_DW_TAG
from .structs import DWARFStructs

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .compileunit import CompileUnit
    from .dwarfinfo import DWARFInfo
    from .typeunit import TypeUnit


_DW_TAG_raw2name = dict((v, k) for k, v in ENUM_DW_TAG.items())


def djb_hash(name: bytes) -> int:
    """ The DJB hash function used for symbol names in the .debug_names
        hash table (DWARFv5 section 6.1.1.4.1).
    """
    h = 5381
    for c in name:
        h = ((h << 5) + h + c) & 0xFFFFFFFF
    return h


class NameIndexEntry(NamedTuple):
    """ A single candidate for a name lookup in a .debug_names index.

        unit:
            The actual CompileUnit or TypeUnit object this entry belongs
            to. Entries with the same name coming from different units are
            distinct candidates; they are never merged into one result.

        die_offset:
            The offset of the DIE in the section that holds the unit
            (.debug_info for a CU, .debug_types for a TU), i.e. the unit
            offset plus the unit-relative DW_IDX_die_offset value.

        tag:
            The DW_TAG_* name of the entry, as declared by its abbreviation
            in the entry pool.

        attributes:
            A Container with the raw DW_IDX_* attributes of the entry.
            Attributes with an unrecognized (e.g. vendor specific) index
            are preserved under a 'DW_IDX_unknown_0x...' key.
    """
    unit: CompileUnit | TypeUnit
    die_offset: int
    tag: str
    attributes: Container


class NameIndex:
    """ A single name index unit within the .debug_names section.
    """
    def __init__(
        self,
        stream: IO[bytes],
        size: int,
        offset: int,
        structs: DWARFStructs,
        dwarfinfo: DWARFInfo,
    ) -> None:
        self._stream = stream
        self._section_size = size
        self.offset = offset
        self._dwarfinfo = dwarfinfo
        self._parse(structs)

    def lookup(self, name: bytes) -> list[NameIndexEntry]:
        """ Return the list of NameIndexEntry candidates for the given
            (bytes) symbol name. The list is empty if the name is not in
            this index.
        """
        entries: list[NameIndexEntry] = []
        for i in self._candidate_name_indices(name):
            entries.extend(self._parse_entries(self._entry_offsets[i]))
        return entries

    #------ PRIVATE ------#

    def _parse(self, base_structs: DWARFStructs) -> None:
        stream = self._stream
        # The DWARF format (32/64) of a name index unit is determined by
        # its own initial length field, like for CUs.
        initial_length = struct_parse(
            base_structs.the_Dwarf_uint32, stream, self.offset)
        dwarf_format = 64 if initial_length == 0xFFFFFFFF else 32
        structs = DWARFStructs(
            little_endian=base_structs.little_endian,
            dwarf_format=dwarf_format,
            address_size=base_structs.address_size,
            dwarf_version=5)
        self._structs = structs

        header = struct_parse(
            structs.Dwarf_debug_names_header, stream, self.offset)
        dwarf_assert(
            header.version == 5,
            f"Unsupported .debug_names version {header.version}")
        self.header = header

        # Level 1: the whole unit must fit in the section.
        unit_end = (self.offset + header.unit_length +
                    structs.initial_length_field_size())
        dwarf_assert(
            unit_end <= self._section_size,
            f".debug_names unit at {self.offset} exceeds section bounds")
        self._unit_end = unit_end

        # Level 2: every fixed-size array following the header must fit
        # within the unit.
        self._cu_offsets = self._read_array(
            header.comp_unit_count, structs.the_Dwarf_offset,
            structs.dwarf_format // 8, 'CU list')
        self._tu_offsets = self._read_array(
            header.local_type_unit_count, structs.the_Dwarf_offset,
            structs.dwarf_format // 8, 'local TU list')
        self._foreign_sigs = self._read_array(
            header.foreign_type_unit_count, structs.Dwarf_uint64(''),
            8, 'foreign TU list')
        self._buckets = self._read_array(
            header.bucket_count, structs.the_Dwarf_uint32, 4, 'hash buckets')
        self._hashes = self._read_array(
            header.name_count, structs.the_Dwarf_uint32, 4, 'name hashes')
        self._str_offsets = self._read_array(
            header.name_count, structs.the_Dwarf_offset,
            structs.dwarf_format // 8, 'name string offsets')
        self._entry_offsets = self._read_array(
            header.name_count, structs.the_Dwarf_offset,
            structs.dwarf_format // 8, 'entry offsets')

        # Level 2 (cont.): the abbreviations table must fit in the unit;
        # the entry pool occupies the rest of the unit.
        abbrev_start = stream.tell()
        dwarf_assert(
            abbrev_start + header.abbrev_table_size <= unit_end,
            f".debug_names abbrev table at {self.offset} exceeds unit bounds")
        self._abbrevs = self._parse_abbrevs(abbrev_start)
        self._entry_pool_start = abbrev_start + header.abbrev_table_size
        self._entry_pool_size = unit_end - self._entry_pool_start
        dwarf_assert(
            self._entry_pool_size >= 0,
            f".debug_names entry pool at {self.offset} exceeds unit bounds")

    def _read_array(
        self,
        count: int,
        struct,
        elem_size: int,
        what: str,
    ) -> list[int]:
        dwarf_assert(
            self._stream.tell() + count * elem_size <= self._unit_end,
            f".debug_names {what} at {self.offset} exceeds unit bounds")
        return [struct_parse(struct, self._stream) for _ in range(count)]

    def _parse_abbrevs(self, abbrev_start: int) -> dict[int, tuple[int, list[tuple[int, int]]]]:
        """ Parse the entry pool abbreviations table: a sequence of
            (code, tag, (idx, form)*, 0, 0) declarations terminated by a
            zero code.
        """
        structs = self._structs
        abbrev_end = abbrev_start + self.header.abbrev_table_size
        abbrevs: dict[int, tuple[int, list[tuple[int, int]]]] = {}
        while True:
            dwarf_assert(
                self._stream.tell() < abbrev_end,
                f".debug_names abbrev table at {self.offset} is not terminated")
            code = struct_parse(structs.the_Dwarf_uleb128, self._stream)
            if code == 0:
                break
            tag = struct_parse(structs.the_Dwarf_uleb128, self._stream)
            attrs: list[tuple[int, int]] = []
            while True:
                idx = struct_parse(structs.the_Dwarf_uleb128, self._stream)
                form = struct_parse(structs.the_Dwarf_uleb128, self._stream)
                if idx == 0 and form == 0:
                    break
                attrs.append((idx, form))
            abbrevs[code] = (tag, attrs)
        return abbrevs

    def _candidate_name_indices(self, name: bytes) -> Iterator[int]:
        """ Yield indices into the name table whose hash and string match
            the given name, walking the hash bucket chain if a hash table
            is present.
        """
        header = self.header
        target = djb_hash(name)
        if header.bucket_count:
            bucket_index = target % header.bucket_count
            name_index = self._buckets[bucket_index]
            # Names in a bucket are chained consecutively; the chain ends
            # at a name whose hash falls into a different bucket.
            while (0 < name_index <= header.name_count and
                   self._hashes[name_index - 1] % header.bucket_count == bucket_index):
                i = name_index - 1
                if self._hashes[i] == target and self._name_at(i) == name:
                    yield i
                name_index += 1
        else:
            # No hash table: scan the whole name table.
            for i in range(header.name_count):
                if self._hashes[i] == target and self._name_at(i) == name:
                    yield i

    def _name_at(self, index: int) -> bytes | None:
        str_offset = self._str_offsets[index]
        debug_str_sec = self._dwarfinfo.debug_str_sec
        dwarf_assert(
            debug_str_sec is not None,
            '.debug_names requires a .debug_str section')
        # Level 3: the string offset must be within .debug_str.
        dwarf_assert(
            str_offset < debug_str_sec.size,
            f".debug_names string offset {str_offset} beyond .debug_str size")
        return parse_cstring_from_stream(debug_str_sec.stream, str_offset)

    def _parse_entries(self, entry_offset: int) -> list[NameIndexEntry]:
        """ Parse the run of entries for one name in the entry pool. The
            run is terminated by a zero abbreviation code.
        """
        # Level 3: the entry offset must be within the entry pool.
        dwarf_assert(
            entry_offset < self._entry_pool_size,
            f".debug_names entry offset {entry_offset} beyond entry pool")
        structs = self._structs
        self._stream.seek(self._entry_pool_start + entry_offset)
        entries: list[NameIndexEntry] = []
        while True:
            dwarf_assert(
                self._stream.tell() < self._unit_end,
                f".debug_names entry at {self.offset} runs past unit bounds")
            code = struct_parse(structs.the_Dwarf_uleb128, self._stream)
            if code == 0:
                break
            dwarf_assert(
                code in self._abbrevs,
                f".debug_names entry references unknown abbrev code {code}")
            tag, attrs = self._abbrevs[code]
            values = Container()
            for idx, form in attrs:
                form_name = DW_FORM_raw2name.get(form)
                form_struct = structs.Dwarf_dw_form.get(form_name) \
                    if form_name is not None else None
                dwarf_assert(
                    form_struct is not None,
                    f".debug_names entry uses unsupported form 0x{form:x}")
                value = struct_parse(form_struct, self._stream)
                # Unknown (e.g. vendor specific) indexes are parsed by
                # their form and preserved under a synthesized key.
                idx_name = DW_IDX_raw2name.get(
                    idx, f'DW_IDX_unknown_0x{idx:x}')
                values[idx_name] = value
            dwarf_assert(
                self._stream.tell() <= self._unit_end,
                f".debug_names entry at {self.offset} runs past unit bounds")
            entries.append(self._make_entry(tag, values))
        return entries

    def _make_entry(self, tag: int, values: Container) -> NameIndexEntry:
        dwarf_assert(
            'DW_IDX_die_offset' in values,
            '.debug_names entry without DW_IDX_die_offset')
        die_offset = values['DW_IDX_die_offset']
        if 'DW_IDX_type_unit' in values:
            tu_index = values['DW_IDX_type_unit']
            if tu_index < len(self._tu_offsets):
                unit = self._dwarfinfo.get_TU_at(self._tu_offsets[tu_index])
            else:
                sig_index = tu_index - len(self._tu_offsets)
                dwarf_assert(
                    sig_index < len(self._foreign_sigs),
                    f'.debug_names TU index {tu_index} out of range')
                unit = self._dwarfinfo.get_TU_by_sig8(
                    self._foreign_sigs[sig_index])
        elif 'DW_IDX_compile_unit' in values:
            cu_index = values['DW_IDX_compile_unit']
            dwarf_assert(
                cu_index < len(self._cu_offsets),
                f'.debug_names CU index {cu_index} out of range')
            unit = self._dwarfinfo.get_CU_at(self._cu_offsets[cu_index])
        elif len(self._cu_offsets) == 1:
            unit = self._dwarfinfo.get_CU_at(self._cu_offsets[0])
        else:
            raise DWARFError(
                '.debug_names entry does not identify its unit')
        return NameIndexEntry(
            unit=unit,
            die_offset=unit.cu_offset + die_offset,
            tag=_DW_TAG_raw2name.get(tag, f'DW_TAG_unknown_0x{tag:x}'),
            attributes=values)


class DebugNames:
    """ The decoded .debug_names section: a sequence of name index units.

        Usage:

        debug_names = dwarf_info.get_debug_names()
        for entry in debug_names.lookup('some_name'):
            die = dwarf_info.get_DIE_from_name_index_entry(entry)
            ...
    """
    def __init__(
        self,
        stream: IO[bytes],
        size: int,
        structs: DWARFStructs,
        dwarfinfo: DWARFInfo,
    ) -> None:
        self._stream = stream
        self._size = size
        self._structs = structs
        self._dwarfinfo = dwarfinfo

    @cached_property
    def name_indexes(self) -> list[NameIndex]:
        """ All name index units in the section, in order of appearance.
        """
        indexes = []
        offset = 0
        while offset < self._size:
            index = NameIndex(
                self._stream, self._size, offset, self._structs,
                self._dwarfinfo)
            indexes.append(index)
            offset = index._unit_end
        return indexes

    def lookup(self, name: str | bytes) -> list[NameIndexEntry]:
        """ Return the list of NameIndexEntry candidates for the given
            symbol name, from all name index units in the section. Same
            named entities from different units are returned as separate
            candidates. The list is empty if the name is not indexed.
        """
        if isinstance(name, str):
            name = name.encode('utf-8')
        entries: list[NameIndexEntry] = []
        for index in self.name_indexes:
            entries.extend(index.lookup(name))
        return entries

    def get(
        self,
        name: str | bytes,
        default: list[NameIndexEntry] | None = None,
    ) -> list[NameIndexEntry] | None:
        """ Like lookup(), but returns default if the name is not indexed.
        """
        entries = self.lookup(name)
        return entries if entries else default

    def __getitem__(self, name: str | bytes) -> list[NameIndexEntry]:
        entries = self.lookup(name)
        if not entries:
            raise KeyError(name)
        return entries
