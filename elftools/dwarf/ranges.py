#-------------------------------------------------------------------------------
# elftools: dwarf/ranges.py
#
# DWARF ranges section decoding (.debug_ranges)
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

import os
from typing import IO, TYPE_CHECKING, NamedTuple, NoReturn

from ..common.exceptions import DWARFError, ELFParseError
from ..common.utils import preserve_stream_pos, struct_parse
from .dwarf_util import _get_base_offset, _iter_CUs_in_section

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence

    from ..construct.lib.container import Container
    from .compileunit import CompileUnit
    from .die import AttributeValue
    from .dwarfinfo import DWARFInfo
    from .structs import DWARFStructs


class RangeEntry(NamedTuple):
    entry_offset: int
    entry_length: int
    begin_offset: int
    end_offset: int
    is_absolute: bool


class BaseAddressEntry(NamedTuple):
    entry_offset: int
    base_address: int


# Status values for RangeInterval. A zero-length interval is reported
# separately from one whose addresses could not be resolved.
RANGE_RESOLVED = 'resolved'
RANGE_EMPTY = 'empty'
RANGE_UNKNOWN = 'unknown'


class RangeInterval(NamedTuple):
    """One DWARFv5 range list entry after base-address resolution.

    begin/end are code addresses when status is RANGE_RESOLVED, are equal for
    RANGE_EMPTY, and are None for RANGE_UNKNOWN. base/base_source describe the
    effective base address used for a relative entry (None for absolute ones).
    """
    entry_offset: int
    entry_length: int
    entry_type: str
    begin: int | None
    end: int | None
    status: str
    base: int | None
    base_source: str | None
    reason: str | None


class RangeListState:
    """Independent state for resolving one DWARFv5 range list.

    The state belongs to exactly one CU and one list. The effective base
    starts as the CU's DW_AT_low_pc (which is undefined when the attribute is
    absent), is changed only by base-address entries in this list, and is
    never inherited from another list or another CU.

    Address indexes are resolved through this CU's DW_AT_addr_base, so the
    same DW_FORM_rnglistx index or DW_RLE_* index in two CUs denotes different
    things whenever their section contributions differ.

    The return value of get_range_list_state() exposes three disjoint views:
    .ranges (RANGE_RESOLVED), .empty_ranges (RANGE_EMPTY) and .unknown_ranges
    (RANGE_UNKNOWN). An end-of-list-only list has no intervals and sets
    .is_empty_list.
    """
    def __init__(
        self,
        cu: CompileUnit,
        list_offset: int,
        entries: Sequence[Container],
    ) -> None:
        self.cu = cu
        self.list_offset = list_offset
        self.cu_base = _get_cu_range_base(cu)
        self.addr_base = _get_optional_attr(cu, 'DW_AT_addr_base')
        self.rnglists_base = _get_optional_attr(cu, 'DW_AT_rnglists_base')

        # These are reset for every instance, i.e. for every range list.
        self.base = self.cu_base
        self.base_source: str | None = 'DW_AT_low_pc' if self.cu_base is not None else None
        self.base_error: str | None = (
            None if self.cu_base is not None else
            'no base address: DW_AT_low_pc is absent and no preceding base-address entry')
        self.intervals: list[RangeInterval] = []
        self._content_entries = 0
        self._addr_end_checked = False
        self._addr_end: int | None = None

        for entry in entries:
            if entry.entry_type != 'DW_RLE_end_of_list':
                self._content_entries += 1
            self._consume(entry)

    @property
    def is_empty_list(self) -> bool:
        """Whether the list contains only the end-of-list marker."""
        return self._content_entries == 0

    @property
    def ranges(self) -> list[RangeInterval]:
        return [i for i in self.intervals if i.status == RANGE_RESOLVED]

    @property
    def empty_ranges(self) -> list[RangeInterval]:
        return [i for i in self.intervals if i.status == RANGE_EMPTY]

    @property
    def unknown_ranges(self) -> list[RangeInterval]:
        return [i for i in self.intervals if i.status == RANGE_UNKNOWN]

    #------ PRIVATE ------#

    def _consume(self, entry: Container) -> None:
        kind: str = entry.entry_type
        if kind == 'DW_RLE_end_of_list':
            return
        if kind == 'DW_RLE_base_address':
            self._set_base(entry.address, kind)
            return
        if kind == 'DW_RLE_base_addressx':
            address, reason = self._address_from_index(entry.index)
            if address is None:
                self.base = None
                self.base_source = None
                self.base_error = f'DW_RLE_base_addressx: {reason}'
            else:
                self._set_base(address, kind)
            return
        if kind == 'DW_RLE_offset_pair':
            self._relative_interval(entry, entry.start_offset, entry.end_offset)
            return
        if kind == 'DW_RLE_start_end':
            self._absolute_interval(entry, entry.start_address, entry.end_address)
            return
        if kind == 'DW_RLE_start_length':
            self._absolute_length(entry, entry.start_address, entry.length)
            return
        if kind == 'DW_RLE_startx_endx':
            self._indexed_interval(entry, entry.start_index, entry.end_index)
            return
        if kind == 'DW_RLE_startx_length':
            self._indexed_length(entry, entry.start_index, entry.length)
            return
        raise DWARFError(f'Unknown DW_RLE entry type: {kind}')

    def _set_base(self, address: int, source: str) -> None:
        self.base = address
        self.base_source = source
        self.base_error = None

    def _base_for_relative(self) -> tuple[int | None, str | None]:
        if self.base is None:
            return None, self.base_error
        return self.base, None

    def _relative_interval(self, entry: Container, start_offset: int, end_offset: int) -> None:
        base, reason = self._base_for_relative()
        if base is None:
            # Without a base the entry is not valid, even when both offsets
            # are equal. Do not claim a concrete empty range.
            self.intervals.append(self._make_interval(
                entry, None, None, RANGE_UNKNOWN, None, self.base_source, reason))
            return
        begin, end = base + start_offset, base + end_offset
        self._append_bounded(entry, begin, end, base, self.base_source)

    def _absolute_interval(self, entry: Container, begin: int, end: int) -> None:
        self._append_bounded(entry, begin, end, None, None)

    def _absolute_length(self, entry: Container, begin: int, length: int) -> None:
        self._append_bounded(entry, begin, begin + length, None, None)

    def _indexed_interval(self, entry: Container, start_index: int, end_index: int) -> None:
        begin, begin_reason = self._address_from_index(start_index)
        end, end_reason = self._address_from_index(end_index)
        reason = begin_reason or end_reason
        if begin is None or end is None:
            self.intervals.append(self._make_interval(
                entry, None, None, RANGE_UNKNOWN, None, None, reason))
            return
        self._append_bounded(entry, begin, end, None, None)

    def _indexed_length(self, entry: Container, start_index: int, length: int) -> None:
        begin, reason = self._address_from_index(start_index)
        if begin is None:
            self.intervals.append(self._make_interval(
                entry, None, None, RANGE_UNKNOWN, None, None, reason))
            return
        self._append_bounded(entry, begin, begin + length, None, None)

    def _append_bounded(
        self,
        entry: Container,
        begin: int,
        end: int,
        base: int | None,
        base_source: str | None,
    ) -> None:
        status = RANGE_EMPTY if begin == end else RANGE_RESOLVED
        self.intervals.append(self._make_interval(
            entry, begin, end, status, base, base_source, None))

    def _make_interval(
        self,
        entry: Container,
        begin: int | None,
        end: int | None,
        status: str,
        base: int | None,
        base_source: str | None,
        reason: str | None,
    ) -> RangeInterval:
        return RangeInterval(
            entry_offset=entry.entry_offset,
            entry_length=entry.entry_length,
            entry_type=entry.entry_type,
            begin=begin,
            end=end,
            status=status,
            base=base,
            base_source=base_source,
            reason=reason)

    def _address_from_index(self, index: int) -> tuple[int | None, str | None]:
        if self.addr_base is None:
            return None, 'DW_AT_addr_base is absent'
        debug_addr_sec = self.cu.dwarfinfo.debug_addr_sec
        if debug_addr_sec is None:
            return None, 'the file has no .debug_addr section'
        address_size = self.cu.header.address_size
        offset = self.addr_base + index * address_size
        if index < 0 or offset < 0 or offset + address_size > debug_addr_sec.size:
            return None, f'address index {index} is outside the .debug_addr section'
        contribution_end = self._addr_contribution_end()
        if contribution_end is not None and offset + address_size > contribution_end:
            return None, (f'address index {index} is outside this CU\'s '
                          '.debug_addr contribution')
        with preserve_stream_pos(debug_addr_sec.stream):
            address: int = struct_parse(
                self.cu.structs.the_Dwarf_target_addr,
                debug_addr_sec.stream,
                offset)
        return address, None

    def _addr_contribution_end(self) -> int | None:
        """End offset of this CU's .debug_addr contribution, when derivable.

        DW_AT_addr_base points just past the address table header, so the
        header can be located by stepping back over its fixed-size part. The
        header's unit_length then bounds the contribution. Without this check
        an index in one CU would silently read a neighboring CU's entry.
        """
        if self._addr_end_checked:
            return self._addr_end
        self._addr_end_checked = True
        debug_addr_sec = self.cu.dwarfinfo.debug_addr_sec
        if debug_addr_sec is None or not 0 <= self.addr_base < debug_addr_sec.size:
            return None

        stream = debug_addr_sec.stream
        for header_size in (8, 16):
            header_start = self.addr_base - header_size
            if header_start < 0:
                continue
            with preserve_stream_pos(stream):
                stream.seek(header_start)
                raw_length = stream.read(4)
                if len(raw_length) != 4:
                    continue
                is64 = raw_length == b'\xff\xff\xff\xff'
                if (header_size == 16) != is64:
                    continue
                try:
                    header = struct_parse(
                        self.cu.structs.Dwarf_address_table_header,
                        stream, header_start)
                except (DWARFError, ELFParseError):
                    continue
            if (header.version != 5
                    or header.address_size != self.cu.header.address_size
                    or header.segment_selector_size != 0):
                continue
            length_field_size = 12 if is64 else 4
            end = header_start + length_field_size + header.unit_length
            if end > debug_addr_sec.size:
                continue
            self._addr_end = end
            return end
        return None


def _get_optional_attr(cu: CompileUnit, name: str) -> int | None:
    attr = cu.get_top_DIE().attributes.get(name)
    return None if attr is None else int(attr.value)


def _get_cu_range_base(cu: CompileUnit) -> int | None:
    """The base address of a CU, as defined in DWARFv5 section 3.1.1.

    Only DW_AT_low_pc defines it. Other attributes are deliberately not
    consulted, because using them would alter the meaning of relative
    DW_RLE_offset_pair entries.
    """
    return _get_optional_attr(cu, 'DW_AT_low_pc')

# If we ever see a list with a base entry at the end, there will be an error that entry_length is not a field.

def _translate_startx_length(e: Container, cu: CompileUnit) -> RangeEntry:
    start_offset = cu.dwarfinfo.get_addr(cu, e.start_index)
    return RangeEntry(e.entry_offset, e.entry_length, start_offset, start_offset + e.length, True)

# Maps parsed entry types to RangeEntry/BaseAddressEntry objects
entry_translate: dict[str, Callable[[Container, CompileUnit], RangeEntry | BaseAddressEntry]] = {
    'DW_RLE_base_address' : lambda e, cu: BaseAddressEntry(e.entry_offset, e.address),
    'DW_RLE_offset_pair'  : lambda e, cu: RangeEntry(e.entry_offset, e.entry_length, e.start_offset, e.end_offset, False),
    'DW_RLE_start_end'    : lambda e, cu: RangeEntry(e.entry_offset, e.entry_length, e.start_address, e.end_address, True),
    'DW_RLE_start_length' : lambda e, cu: RangeEntry(e.entry_offset, e.entry_length, e.start_address, e.start_address + e.length, True),
    'DW_RLE_base_addressx': lambda e, cu: BaseAddressEntry(e.entry_offset, cu.dwarfinfo.get_addr(cu, e.index)),  # type: ignore[has-type]
    'DW_RLE_startx_endx'  : lambda e, cu: RangeEntry(e.entry_offset, e.entry_length, cu.dwarfinfo.get_addr(cu, e.start_index), cu.dwarfinfo.get_addr(cu, e.end_index), True),  # type: ignore[has-type]
    'DW_RLE_startx_length': _translate_startx_length
}

class RangeListsPair:
    """For those binaries that contain both a debug_ranges and a debug_rnglists section,
    it holds a RangeLists object for both and forwards API calls to the right one based
    on the CU version.
    """
    def __init__(
        self,
        streamv4: IO[bytes],
        streamv5: IO[bytes],
        structs: DWARFStructs,
        dwarfinfo: DWARFInfo | None = None,
    ) -> None:
        self._ranges = RangeLists(streamv4, structs, 4, dwarfinfo)
        self._rnglists = RangeLists(streamv5, structs, 5, dwarfinfo)

    def get_range_list_at_offset(
        self,
        offset: int,
        cu: CompileUnit | None = None,
    ) -> list[RangeEntry | BaseAddressEntry]:
        """Forwards the call to either v4 section or v5 one,
        depending on DWARF version in the CU.
        """
        if cu is None:
            raise DWARFError("For this binary, \"cu\" needs to be provided")
        section = self._rnglists if cu.header.version >= 5 else self._ranges
        return section.get_range_list_at_offset(offset, cu)

    def get_range_list_at_offset_ex(self, offset: int) -> Container:
        """Gets an untranslated v5 rangelist from the v5 section.
        """
        return self._rnglists.get_range_list_at_offset_ex(offset)

    def iter_range_lists(self) -> NoReturn:
        """Tricky proposition, since the structure of ranges and rnglists
        is not identical. A realistic readelf implementation needs to be aware of both.
        """
        raise DWARFError("Iterating through two sections is not supported")

    def iter_CUs(self) -> Iterator[CompileUnit]:
        """See RangeLists.iter_CUs()

        CU structure is only present in DWARFv5 rnglists sections. A well written
        section dumper should check if one is present.
        """
        return self._rnglists.iter_CUs()

    def iter_CU_range_lists_ex(self, cu: Container) -> Iterator[CompileUnit]:
        """See RangeLists.iter_CU_range_lists_ex()

        CU structure is only present in DWARFv5 rnglists sections. A well written
        section dumper should check if one is present.
        """
        return self._rnglists.iter_CU_range_lists_ex(cu)

    def translate_v5_entry(
        self,
        entry: Container,
        cu: CompileUnit,
    ) -> RangeEntry | BaseAddressEntry:
        """Forwards a V5 entry translation request to the V5 section
        """
        return self._rnglists.translate_v5_entry(entry, cu)

    def get_range_list_state(
        self,
        attr: AttributeValue,
        cu: CompileUnit,
    ) -> RangeListState:
        """See RangeLists.get_range_list_state().
        """
        if cu.header.version < 5:
            raise DWARFError("Range list states are only defined for DWARFv5")
        return self._rnglists.get_range_list_state(attr, cu)

class RangeLists:
    """ A single range list is a Python list consisting of RangeEntry or
        BaseAddressEntry objects.

        Since v0.29, two new parameters - version and dwarfinfo

        version is used to distinguish DWARFv5 rnglists section from
        the DWARF<=4 ranges section. Only the 4/5 distinction matters.

        The dwarfinfo is needed for enumeration, because enumeration
        requires scanning the DIEs, because ranges may overlap, even on DWARF<=4
    """
    def __init__(
        self,
        stream: IO[bytes],
        structs: DWARFStructs,
        version: int,
        dwarfinfo: DWARFInfo | None,
    ) -> None:
        self.stream = stream
        self.structs = structs
        self._max_addr = 2 ** (self.structs.address_size * 8) - 1
        self.version = version
        self._dwarfinfo = dwarfinfo

    def get_range_list_at_offset(
        self,
        offset: int,
        cu: CompileUnit | None = None,
    ) -> list[RangeEntry | BaseAddressEntry]:
        """ Get a range list at the given offset in the section.

            The cu argument is necessary if the ranges section is a
            DWARFv5 debug_rnglists one, and the target rangelist
            contains indirect encodings
        """
        self.stream.seek(offset, os.SEEK_SET)
        return self._parse_range_list_from_stream(cu)

    def get_range_list_at_offset_ex(self, offset: int) -> Container:
        """Get a DWARF v5 range list, addresses and offsets unresolved,
        at the given offset in the section
        """
        return struct_parse(self.structs.Dwarf_rnglists_entries, self.stream, offset)

    def get_range_list_state(
        self,
        attr: AttributeValue,
        cu: CompileUnit,
    ) -> RangeListState:
        """Resolve the range list named by a DW_AT_ranges-like attribute.

        The attribute itself is the entry point, so the caller does not get to
        supply an already-resolved offset. For DW_FORM_rnglistx the raw index
        is resolved through this CU's DW_AT_rnglists_base, exactly as the DIE
        layer does. Address indexes inside the list are then resolved through
        this CU's DW_AT_addr_base. The returned state is local to this call and
        this CU; no base or partial result survives into another list.
        """
        if self.version < 5:
            raise DWARFError("Range list states are only defined for DWARFv5")
        list_offset = self.resolve_range_list_offset(attr, cu)
        with preserve_stream_pos(self.stream):
            entries = self.get_range_list_at_offset_ex(list_offset)
        return RangeListState(cu, list_offset, entries)

    def resolve_range_list_offset(
        self,
        attr: AttributeValue,
        cu: CompileUnit,
    ) -> int:
        """Map a range-list attribute to its offset in .debug_rnglists.

        A DW_FORM_rnglistx value is an index into the CU's offset table, not a
        section offset. The offset table is located by DW_AT_rnglists_base;
        DW_AT_addr_base belongs to a different section and is not a substitute
        for it.
        """
        if attr.form == 'DW_FORM_rnglistx':
            return self._resolve_rnglistx(attr.raw_value, cu)
        if attr.form == 'DW_FORM_sec_offset':
            return int(attr.value)
        raise DWARFError(
            f'DW_AT_ranges uses unsupported form {attr.form}')

    def _resolve_rnglistx(self, index: int, cu: CompileUnit) -> int:
        """Resolve a DW_FORM_rnglistx index within this CU's contribution.

        DW_AT_rnglists_base points at the first offset-table entry, so the
        enclosing contribution can be identified and the index range-checked.
        A base that does not match any contribution, or an index outside its
        offset table, is reported instead of silently reading a neighboring
        CU's list.
        """
        base = _get_base_offset(cu, 'DW_AT_rnglists_base')
        contribution = self._contribution_at_offset_table(base)
        if contribution is None:
            raise DWARFError(
                f'DW_AT_rnglists_base 0x{base:x} does not point at an offset '
                'table in .debug_rnglists')
        if index < 0 or index >= contribution.offset_count:
            raise DWARFError(
                f'DW_FORM_rnglistx index {index} is outside the offset table '
                f'at 0x{base:x} (entry count {contribution.offset_count})')

        offset_size = 8 if contribution.is64 else 4
        table_entry = base + index * offset_size
        offset_parser = (cu.structs.Dwarf_uint64('') if offset_size == 8
                         else cu.structs.Dwarf_uint32(''))
        with preserve_stream_pos(self.stream):
            list_offset = base + struct_parse(
                offset_parser, self.stream, table_entry)
        unit_end = contribution.offset_after_length + contribution.unit_length
        if not base <= list_offset < unit_end:
            raise DWARFError(
                f'DW_FORM_rnglistx index {index} resolves to 0x{list_offset:x}, '
                f'outside the range list contribution at 0x{contribution.cu_offset:x}')
        return list_offset

    def _contribution_at_offset_table(self, base: int) -> Container | None:
        """Find the .debug_rnglists contribution whose offset table starts at base."""
        with preserve_stream_pos(self.stream):
            for contribution in _iter_CUs_in_section(
                    self.stream, self.structs,
                    self.structs.Dwarf_rnglists_CU_header):
                if contribution.offset_table_offset == base:
                    return contribution
                if contribution.cu_offset > base:
                    break
        return None

    def iter_range_lists(self) -> Iterator[list[RangeEntry | BaseAddressEntry]]:
        """ Yields all range lists found in the section according to readelf rules.
        Scans the DIEs for rangelist offsets, then pulls those.
        Returned rangelists are always translated into lists of BaseAddressEntry/RangeEntry objects.
        """
        # Rangelists can overlap. That is, one DIE points at the rangelist beginning, and another
        # points at the middle of the same. Therefore, enumerating them is not a well defined
        # operation - do you count those as two different (but overlapping) ones, or as a single one?
        # For debugging utility, you want two. That's what readelf does. For faithfully
        # representing the section contents, you want one.
        # That was the behaviour of pyelftools 0.28 and below - calling
        # parse until the stream end. Leaving aside the question of correctless,
        # that's uncompatible with readelf.

        ver5 = self.version >= 5
        # This maps list offset to CU
        cu_map = {die.attributes['DW_AT_ranges'].value : cu
            for cu in self._dwarfinfo.iter_CUs()  # type: ignore[union-attr] # ty: ignore[unresolved-attribute]
            for die in cu.iter_DIEs()
            if 'DW_AT_ranges' in die.attributes and (cu['version'] >= 5) == ver5}
        all_offsets = list(cu_map.keys())
        all_offsets.sort()

        for offset in all_offsets:
            yield self.get_range_list_at_offset(offset, cu_map[offset])

    def iter_CUs(self) -> Iterator[CompileUnit]:
        """For DWARF5 returns an array of objects, where each one has an array of offsets
        """
        if self.version < 5:
            raise DWARFError("CU iteration in rnglists is not supported with DWARF<5")

        assert self._dwarfinfo is not None
        structs = next(self._dwarfinfo.iter_CUs()).structs # Just pick one
        return _iter_CUs_in_section(self.stream, structs, structs.Dwarf_rnglists_CU_header)

    def iter_CU_range_lists_ex(self, cu: Container) -> Iterator[CompileUnit]:
        """For DWARF5, returns untranslated rangelists in the CU, where CU comes from iter_CUs above
        """
        stream = self.stream
        stream.seek(cu.offset_table_offset + (64 if cu.is64 else 32) * cu.offset_count)
        while stream.tell() < cu.offset_after_length + cu.unit_length:
            yield struct_parse(self.structs.Dwarf_rnglists_entries, stream)

    def translate_v5_entry(
        self,
        entry: Container,
        cu: CompileUnit,
    ) -> RangeEntry | BaseAddressEntry:
        """Translates entries in a DWARFv5 rangelist from raw parsed format to
        a list of BaseAddressEntry/RangeEntry, using the CU
        """
        return entry_translate[entry.entry_type](entry, cu)

    #------ PRIVATE ------#

    def _parse_range_list_from_stream(
        self,
        cu: CompileUnit | None,
    ) -> list[RangeEntry | BaseAddressEntry]:
        if self.version >= 5:
            assert cu is not None
            return [entry_translate[entry.entry_type](entry, cu)
                for entry
                in struct_parse(self.structs.Dwarf_rnglists_entries, self.stream)]
        else:
            lst: list[RangeEntry | BaseAddressEntry] = []
            while True:
                entry_offset = self.stream.tell()
                begin_offset = struct_parse(
                    self.structs.the_Dwarf_target_addr, self.stream)
                end_offset = struct_parse(
                    self.structs.the_Dwarf_target_addr, self.stream)
                if begin_offset == 0 and end_offset == 0:
                    # End of list - we're done.
                    break
                elif begin_offset == self._max_addr:
                    # Base address selection entry
                    lst.append(BaseAddressEntry(entry_offset=entry_offset, base_address=end_offset))
                else:
                    # Range entry
                    lst.append(RangeEntry(
                        entry_offset=entry_offset,
                        entry_length=self.stream.tell() - entry_offset,
                        begin_offset=begin_offset,
                        end_offset=end_offset,
                        is_absolute=False))
            return lst
