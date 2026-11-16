# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import collections
import functools
import logging
import math
import struct
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Tuple

from volatility3 import classproperty
from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import linear

vollog = logging.getLogger(__name__)

INTEL_TRANSLATION_DEBUGGING = False

# Flags found in the low bits of an Intel paging-structure entry
_PAGE_BIT_RW = 1  # Read/write bit
_PAGE_BIT_NX = 63  # No-execute bit (only present on 8-byte entries)
_PAGE_RW = 1 << _PAGE_BIT_RW
_PAGE_NX = 1 << _PAGE_BIT_NX

# Status values reported by :meth:`Intel.explain`
EXPLAIN_STATUS_MAPPED = "mapped"
EXPLAIN_STATUS_NOT_PRESENT = "not-present"
EXPLAIN_STATUS_UNREADABLE_TABLE = "unreadable-table"


class PageTableEntryRecord(NamedTuple):
    """One entry observed while walking the paging structures.

    The record only describes what is stored in the memory image; it never
    infers processor state that is not part of the page tables (such as the
    current CR0/CR4/EFER register values).

    Args:
        level_name: Name of the paging-structure level this entry belongs to
        entry_index: Index of the entry within its table, or ``None`` for the
            synthesized root (page-map) record
        entry_value: Raw value of the entry as stored in memory, or ``None``
            when the physical page holding the entry could not be read
        entry_location: Physical address at which the entry bytes live, or
            ``None`` for the synthesized root record
        table_location: Physical base address of the table containing the
            entry, or ``None`` for the synthesized root record
        present: Whether the entry's present bit was set according to the
            layer's own validity rules; ``None`` when the entry was unreadable
        writable_bit: Value of the read/write bit (bit 1); ``None`` when the
            entry was unreadable
        execute_disabled_bit: Value of the no-execute bit (bit 63); ``None``
            when the entry format has no NX bit or the entry was unreadable
        large_page: Whether the entry terminates the walk as a large page
    """

    level_name: str
    entry_index: Optional[int]
    entry_value: Optional[int]
    entry_location: Optional[int]
    table_location: Optional[int]
    present: Optional[bool]
    writable_bit: Optional[bool]
    execute_disabled_bit: Optional[bool]
    large_page: bool


class PermissionExplanation(NamedTuple):
    """Effective page permissions derived from the page table entries.

    The verdict fields are tri-state: ``True`` allows the access according to
    the paging entries, ``False`` is denied by at least one traversed entry,
    and ``None`` means the entries that were readable do not settle the
    question because part of the walk could not be inspected. "Could not
    check" is therefore never reported as a denial.

    Args:
        writable: Effective writable verdict across all traversed entries
        executable: Effective executable verdict; ``None`` when the entry
            format cannot express execute permission at all (32-bit non-PAE)
        write_basis: Human-readable justification for the writable verdict
        execute_basis: Human-readable justification for the executable verdict
    """

    writable: Optional[bool]
    executable: Optional[bool]
    write_basis: str
    execute_basis: str


class AddressExplanation(NamedTuple):
    """Result of explaining a single virtual address from the page tables.

    Args:
        virtual_address: Virtual address that was explained
        status: One of the ``EXPLAIN_STATUS_*`` constants
        incomplete_reason: Why the walk stopped before a present leaf, if it did
        walk: Every entry observed, in traversal order including the root
        large_page: Whether translation terminated at a large-page entry
        page_size: Bytes covered by the terminal mapping, when present
        physical_address: Translated physical address, when a present leaf was
            reached; this matches the layer's regular read/translate interface
        permissions: Effective permissions, when the walk reached a leaf
    """

    virtual_address: int
    status: str
    incomplete_reason: Optional[str]
    walk: List[PageTableEntryRecord]
    large_page: bool
    page_size: Optional[int]
    physical_address: Optional[int]
    permissions: Optional[PermissionExplanation]


class Intel(linear.LinearlyMappedLayer):
    """Translation Layer for the Intel IA32 memory mapping."""

    _PAGE_BIT_PRESENT = 0
    _PAGE_BIT_PSE = 7  # Page Size Extension: 4 MB (or 2MB) page
    _PAGE_BIT_PROTNONE = 8
    _PAGE_BIT_PAT_LARGE = 12  # 2MB or 1GB pages

    _PAGE_PRESENT = 1 << _PAGE_BIT_PRESENT
    _PAGE_PSE = 1 << _PAGE_BIT_PSE
    _PAGE_PROTNONE = 1 << _PAGE_BIT_PROTNONE
    _PAGE_PAT_LARGE = 1 << _PAGE_BIT_PAT_LARGE

    _entry_format = "<I"
    _page_size_in_bits = 12
    _bits_per_register = 32
    # NOTE: _maxphyaddr is MAXPHYADDR as defined in the Intel specs *NOT* the maximum physical address
    _maxphyaddr = 32
    _maxvirtaddr = _maxphyaddr
    _structure = [("page directory", 10, True), ("page table", 10, False)]
    _direct_metadata = collections.ChainMap(
        {"architecture": "Intel32"},
        {"mapped": True},
        interfaces.layers.TranslationLayerInterface._direct_metadata,
    )

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            context=context, config_path=config_path, name=name, metadata=metadata
        )
        self._base_layer = self.config["memory_layer"]
        self._swap_layers: List[str] = []
        self._page_map_offset = self.config["page_map_offset"]

        # Assign constants
        self._initial_position = min(self._maxvirtaddr, self._bits_per_register) - 1
        self._initial_entry = (
            self._mask(self._page_map_offset, self._initial_position, 0) | 0x1
        )
        self._entry_size = struct.calcsize(self._entry_format)
        self._entry_number = self.page_size // self._entry_size
        self._canonical_prefix = self._mask(
            (1 << self._bits_per_register) - 1,
            self._bits_per_register,
            self._maxvirtaddr,
        )

        # These can vary depending on the type of space
        self._index_shift = math.ceil(math.log2(struct.calcsize(self._entry_format)))

    @classproperty
    @functools.lru_cache
    def page_shift(cls) -> int:
        """Page shift for the intel memory layers."""
        return cls._page_size_in_bits

    @classproperty
    @functools.lru_cache
    def page_size(cls) -> int:
        """Page size for the intel memory layers.

        All Intel layers work on 4096 byte pages
        """
        return 1 << cls._page_size_in_bits

    @classproperty
    @functools.lru_cache
    def page_mask(cls) -> int:
        """Page mask for the intel memory layers."""
        return ~(cls.page_size - 1)

    @classproperty
    @functools.lru_cache
    def bits_per_register(cls) -> int:
        """Returns the bits_per_register to determine the range of an
        IntelTranslationLayer."""
        return cls._bits_per_register

    @classproperty
    @functools.lru_cache
    def minimum_address(cls) -> int:
        return 0

    @classproperty
    @functools.lru_cache
    def maximum_address(cls) -> int:
        return (1 << cls._maxvirtaddr) - 1

    @classproperty
    def structure(cls) -> List[Tuple[str, int, bool]]:
        return cls._structure

    @staticmethod
    def _mask(value: int, high_bit: int, low_bit: int) -> int:
        """Returns the bits of a value between highbit and lowbit inclusive."""
        high_mask = (1 << (high_bit + 1)) - 1
        low_mask = (1 << low_bit) - 1
        mask = high_mask ^ low_mask
        return value & mask

    @staticmethod
    def _page_is_valid(entry: int) -> bool:
        """Returns whether a particular page is valid based on its entry."""
        return bool(entry & 1)

    @staticmethod
    def _page_is_dirty(entry: int) -> bool:
        """Returns whether a particular page is dirty based on its entry."""
        return bool(entry & (1 << 6))

    def canonicalize(self, addr: int) -> int:
        """Canonicalizes an address by performing an appropriate sign extension on the higher addresses"""
        if self._bits_per_register <= self._maxvirtaddr:
            return addr & self.address_mask
        elif addr < (1 << self._maxvirtaddr - 1):
            return addr
        return self._mask(addr, self._maxvirtaddr, 0) + self._canonical_prefix

    def decanonicalize(self, addr: int) -> int:
        """Removes canonicalization to ensure an address fits within the correct range if it has been canonicalized

        This will produce an address outside the range if the canonicalization is incorrect
        """
        if addr < (1 << self._maxvirtaddr - 1):
            return addr
        return addr ^ self._canonical_prefix

    def _translate(self, offset: int) -> Tuple[int, int, str]:
        """Translates a specific offset based on paging tables.

        Returns the translated offset, the contiguous pagesize that the
        translated address lives in and the layer_name that the address
        lives in
        """
        entry, position = self._translate_entry(offset & self.page_mask)

        # Now we're done
        if not self._page_is_valid(entry):
            raise exceptions.PagedInvalidAddressException(
                self.name,
                offset,
                position + 1,
                entry,
                f"Page Fault at entry {hex(entry)} in page entry",
            )

        pfn = self._pte_pfn(entry)
        page_offset = self._mask(offset, position, 0)
        page = pfn << self.page_shift | page_offset

        return page, 1 << (position + 1), self._base_layer

    def _pte_pfn(self, entry: int) -> int:
        """Extracts the page frame number (PFN) from the page table entry (PTE) entry"""
        return self._mask(entry, self._maxphyaddr - 1, 0) >> self.page_shift

    @functools.lru_cache(maxsize=1024)
    def _translate_entry(self, page_address: int) -> int:
        """Translates a page address based on paging tables.

        Args:
            page_address: The page base address

        Returns:
            the translated entry value
        """
        # Setup the entry and how far we are through the offset
        # Position maintains the number of bits left to process
        # We or with 0x1 to ensure our page_map_offset is always valid
        position = self._initial_position
        entry = self._initial_entry

        if not (
            self.minimum_address
            <= (page_address & self.address_mask)
            <= self.maximum_address
        ):
            raise exceptions.PagedInvalidAddressException(
                self.name,
                page_address,
                position + 1,
                entry,
                "Entry outside virtual address range: " + hex(entry),
            )

        # Run through the offset in various chunks
        for name, size, large_page in self._structure:
            # Check we're valid
            if not self._page_is_valid(entry):
                raise exceptions.PagedInvalidAddressException(
                    self.name,
                    page_address,
                    position + 1,
                    entry,
                    "Page Fault at entry " + hex(entry) + " in table " + name,
                )

            # Grab the base address of the table we'll be getting the next entry from
            base_address = self._mask(
                entry, self._maxphyaddr - 1, size + self._index_shift
            )

            table = self._get_valid_table(base_address)
            if table is None:
                raise exceptions.PagedInvalidAddressException(
                    self.name,
                    page_address,
                    position + 1,
                    entry,
                    "Page Fault at entry " + hex(entry) + " in table " + name,
                )

            # Figure out how much of the offset we should be using
            start = position
            position -= size
            index = self._mask(page_address, start, position + 1) >> (position + 1)

            # Read the data for the next entry
            entry_data_start = index << self._index_shift
            entry_data = table[entry_data_start : entry_data_start + self._entry_size]

            if INTEL_TRANSLATION_DEBUGGING:
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"Entry {hex(entry)} at index {hex(index)} gives data {hex(struct.unpack(self._entry_format, entry_data)[0])} as {name}",
                )

            # Read out the new entry from memory
            (entry,) = struct.unpack(self._entry_format, entry_data)

            # Check if we're a large page
            if large_page and (entry & self._PAGE_PSE):
                # Mask off the PAT bit
                if entry & self._PAGE_PAT_LARGE:
                    entry -= self._PAGE_PAT_LARGE
                # We're a large page, the rest is finished below
                # If we want to implement PSE-36, it would need to be done here
                break

        return entry, position

    @functools.lru_cache(maxsize=1025)
    def _get_valid_table(self, base_address: int) -> Optional[bytes]:
        """Extracts the table, validates it and returns it if it's valid."""
        try:
            table = self._context.layers.read(
                self._base_layer, base_address, self.page_size
            )
        except exceptions.InvalidAddressException:
            return None

        ####
        # If the table is entirely duplicates, then mark the whole table as bad
        # This is because Windows 10 onwards has a tendency to map unused pages as present
        # This had the following consequences:
        #  - Used very litle physical memory
        #  - Exploded virtual memory
        #  - Causes *scan plugins to take multiple hours to complete even on small images

        # Previous versions of volatility would ignore a page during a scan when it matched
        # the one directly preceding it in physical memory.
        # This could trip if only two pages were identical and still required enumerating all
        # the invalid pages (which itself was quite time consuming)

        # For this reason, volatility 3 shifted to looking at entire page tables (1,024 pages)
        # and if all the pages mapped to the same place the table wouuld be skipped
        # This could also be applied to the Directory level as well as the Table level, allowing
        # Volatility to skip huge sections of virtual memory very efficiently, without missing
        # any pages that were distinct within a particular page table (or directory).

        # In order to work at this level, the logic was moved out of the scanning component and
        # directly into the layer logic itself.  This does have the side effect of preventing
        # entirely duplicated page tables from reporting as present, however, the trade off between
        # Windows 10+ reduced scanning times (common amongst scan plugins) versus incorrectly reporting
        # entire page tables of identically mapped repeating *valid* data (rare) was accepted in favour
        # of the more common occurance.
        if table == table[: self._entry_size] * self._entry_number:
            return None
        return table

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns whether the address offset can be translated to a valid
        address."""
        try:
            # TODO: Consider reimplementing this, since calls to mapping can call is_valid
            return all(
                self._context.layers[layer].is_valid(mapped_offset)
                for _, _, mapped_offset, _, layer in self.mapping(offset, length)
            )
        except exceptions.InvalidAddressException:
            return False

    def is_dirty(self, offset: int) -> bool:
        """Returns whether the page at offset is marked dirty"""
        return self._page_is_dirty(self._translate_entry(offset & self.page_mask)[0])

    def _has_nx_bit(self) -> bool:
        """Returns whether this entry format can carry a no-execute bit.

        8-byte entries (PAE, Intel32e) encode NX in bit 63; 4-byte 32-bit
        entries have no field for execute permission.
        """
        return self._entry_size == struct.calcsize("<Q")

    def _nx_bit(self, entry: int) -> bool:
        """Returns the value of the no-execute bit stored in an entry."""
        return bool(entry & _PAGE_NX)

    def _explain_permissions(
        self, walk: List[PageTableEntryRecord], complete: bool
    ) -> PermissionExplanation:
        """Combines the permission bits of every confirmed walk entry.

        A denial recorded in any traversed entry is conclusive even when
        lower levels could not be read. Without a confirmed denial, an
        incomplete walk yields ``None`` rather than reporting a denial.
        """
        evidence = [
            record
            for record in walk
            if record.entry_location is not None
            and record.entry_value is not None
            and record.present
        ]

        write_denial = next(
            (record for record in evidence if record.writable_bit is False), None
        )
        if write_denial is not None:
            writable: Optional[bool] = False
            write_basis = (
                "read/write bit clear in the "
                f"{write_denial.level_name} entry (index {write_denial.entry_index})"
            )
        elif complete:
            writable = True
            write_basis = "read/write bit set in every traversed page table entry"
        else:
            unread = next(
                record for record in walk if record.entry_value is None
            )
            writable = None
            write_basis = (
                "no readable entry forbids writing, but the "
                f"{unread.level_name} table at physical address "
                f"{hex(unread.table_location)} could not be inspected"
            )

        if not self._has_nx_bit():
            executable: Optional[bool] = None
            execute_basis = (
                "this paging format has no no-execute bit, so execute "
                "permission cannot be established from the page tables alone"
            )
        else:
            execute_denial = next(
                (
                    record
                    for record in evidence
                    if record.execute_disabled_bit is True
                ),
                None,
            )
            if execute_denial is not None:
                executable = False
                execute_basis = (
                    "no-execute bit set in the "
                    f"{execute_denial.level_name} entry "
                    f"(index {execute_denial.entry_index})"
                )
            elif complete:
                executable = True
                execute_basis = (
                    "no-execute bit clear in every traversed page table entry"
                )
            else:
                unread = next(
                    record for record in walk if record.entry_value is None
                )
                executable = None
                execute_basis = (
                    "no readable entry forbids execution, but the "
                    f"{unread.level_name} table at physical address "
                    f"{hex(unread.table_location)} could not be inspected"
                )

        return PermissionExplanation(
            writable=writable,
            executable=executable,
            write_basis=write_basis,
            execute_basis=execute_basis,
        )

    def explain(self, offset: int) -> AddressExplanation:
        """Explains, read-only, how the page tables treat ``offset``.

        The walk records each paging-structure entry's raw value, the physical
        address at which that value was read, and its permission bits. Large
        pages terminate the walk early, exactly as during ordinary
        translation. If an intermediate table cannot be read, every entry
        confirmed before the failure is retained and the permission verdicts
        stay unconfirmed (``None``) instead of being reported as denials.

        Only permission bits actually stored in the page tables are examined;
        processor register state such as CR0.WP, CR4.SMEP or EFER.NXE is not
        inferred.

        Args:
            offset: Virtual address to explain (it is page aligned internally)

        Returns:
            An :class:`AddressExplanation` containing the ordered entry walk,
            the terminal mapping (if present) and the effective permissions
        """
        page_address = offset & self.page_mask
        walk: List[PageTableEntryRecord] = []

        position = self._initial_position
        entry = self._initial_entry

        if not (
            self.minimum_address
            <= (page_address & self.address_mask)
            <= self.maximum_address
        ):
            raise exceptions.PagedInvalidAddressException(
                self.name,
                page_address,
                position + 1,
                entry,
                "Entry outside virtual address range: " + hex(entry),
            )

        # Synthesized root record: the page map offset itself, not an entry
        # stored in a table, so it carries no physical entry location and does
        # not participate in the effective permission calculation.
        walk.append(
            PageTableEntryRecord(
                level_name="page map",
                entry_index=None,
                entry_value=entry,
                entry_location=None,
                table_location=None,
                present=True,
                writable_bit=bool(entry & _PAGE_RW),
                execute_disabled_bit=(
                    self._nx_bit(entry) if self._has_nx_bit() else None
                ),
                large_page=False,
            )
        )

        status = EXPLAIN_STATUS_NOT_PRESENT
        incomplete_reason: Optional[str] = None
        large_page = False
        mapped = False

        for name, size, large_page_capable in self._structure:
            if not self._page_is_valid(entry):
                status = EXPLAIN_STATUS_NOT_PRESENT
                incomplete_reason = (
                    f"Entry {hex(entry)} in {name} is not present; "
                    "the walk stopped before reaching this level"
                )
                break

            base_address = self._mask(
                entry, self._maxphyaddr - 1, size + self._index_shift
            )
            table = self._get_valid_table(base_address)

            start = position
            position -= size
            index = (
                self._mask(page_address, start, position + 1) >> (position + 1)
            )
            entry_location = base_address + (index << self._index_shift)

            if table is None:
                walk.append(
                    PageTableEntryRecord(
                        level_name=name,
                        entry_index=index,
                        entry_value=None,
                        entry_location=entry_location,
                        table_location=base_address,
                        present=None,
                        writable_bit=None,
                        execute_disabled_bit=None,
                        large_page=False,
                    )
                )
                status = EXPLAIN_STATUS_UNREADABLE_TABLE
                incomplete_reason = (
                    f"The {name} table at physical address "
                    f"{hex(base_address)} could not be read"
                )
                break

            entry_data_start = index << self._index_shift
            entry_data = table[
                entry_data_start : entry_data_start + self._entry_size
            ]
            (entry,) = struct.unpack(self._entry_format, entry_data)

            is_large_page = bool(
                large_page_capable and (entry & self._PAGE_PSE)
            )
            walk.append(
                PageTableEntryRecord(
                    level_name=name,
                    entry_index=index,
                    entry_value=entry,
                    entry_location=entry_location,
                    table_location=base_address,
                    present=self._page_is_valid(entry),
                    writable_bit=bool(entry & _PAGE_RW),
                    execute_disabled_bit=(
                        self._nx_bit(entry) if self._has_nx_bit() else None
                    ),
                    large_page=is_large_page,
                )
            )

            if is_large_page:
                large_page = True
                # The PAT large-page bit occupies a physical-address bit; the
                # raw value remains in the walk record, translation drops it.
                if entry & self._PAGE_PAT_LARGE:
                    entry = entry - self._PAGE_PAT_LARGE
                if not self._page_is_valid(entry):
                    status = EXPLAIN_STATUS_NOT_PRESENT
                    incomplete_reason = (
                        f"Large page entry {hex(entry)} in {name} "
                        "is not present"
                    )
                    break
                mapped = True
                status = EXPLAIN_STATUS_MAPPED
                break

            if not self._page_is_valid(entry):
                status = EXPLAIN_STATUS_NOT_PRESENT
                incomplete_reason = (
                    f"Entry {hex(entry)} in {name} is not present"
                )
                break
        else:
            if self._page_is_valid(entry):
                mapped = True
                status = EXPLAIN_STATUS_MAPPED

        physical_address: Optional[int] = None
        page_size: Optional[int] = None
        permissions: Optional[PermissionExplanation] = None

        if mapped:
            # Reuse the ordinary translation path so the explained physical
            # address is guaranteed to match read()/mapping() byte for byte.
            physical_address, page_size, _layer_name = self._translate(offset)
            permissions = self._explain_permissions(walk, complete=True)
        elif status == EXPLAIN_STATUS_UNREADABLE_TABLE:
            permissions = self._explain_permissions(walk, complete=False)

        return AddressExplanation(
            virtual_address=offset,
            status=status,
            incomplete_reason=incomplete_reason,
            walk=walk,
            large_page=large_page,
            page_size=page_size,
            physical_address=physical_address,
            permissions=permissions,
        )

    def mapping(
        self, offset: int, length: int, ignore_errors: bool = False
    ) -> Iterable[Tuple[int, int, int, int, str]]:
        """Returns a sorted iterable of (offset, sublength, mapped_offset, mapped_length, layer)
        mappings.

        This allows translation layers to provide maps of contiguous
        regions in one layer
        """
        stashed_offset = stashed_mapped_offset = stashed_size = stashed_mapped_size = (
            stashed_map_layer
        ) = None
        for offset, size, mapped_offset, mapped_size, map_layer in self._mapping(
            offset, length, ignore_errors
        ):
            if (
                stashed_offset is None
                or (stashed_offset + stashed_size != offset)
                or (stashed_mapped_offset + stashed_mapped_size != mapped_offset)
                or (stashed_map_layer != map_layer)
            ):
                # The block isn't contiguous
                if stashed_offset is not None:
                    yield (
                        stashed_offset,
                        stashed_size,
                        stashed_mapped_offset,
                        stashed_mapped_size,
                        stashed_map_layer,
                    )
                # Update all the stashed values after output
                stashed_offset = offset
                stashed_mapped_offset = mapped_offset
                stashed_size = size
                stashed_mapped_size = mapped_size
                stashed_map_layer = map_layer
            else:
                # Part of an existing block
                stashed_size += size
                stashed_mapped_size += mapped_size
        # Yield whatever's left
        if (
            stashed_offset is not None
            and stashed_mapped_offset is not None
            and stashed_size is not None
            and stashed_mapped_size is not None
            and stashed_map_layer is not None
        ):
            yield (
                stashed_offset,
                stashed_size,
                stashed_mapped_offset,
                stashed_mapped_size,
                stashed_map_layer,
            )

    def _mapping(
        self, offset: int, length: int, ignore_errors: bool = False
    ) -> Iterable[Tuple[int, int, int, int, str]]:
        """Returns a sorted iterable of (offset, sublength, mapped_offset, mapped_length, layer)
        mappings.

        This allows translation layers to provide maps of contiguous
        regions in one layer
        """
        if length == 0:
            try:
                mapped_offset, _, layer_name = self._translate(offset)
                if not self._context.layers[layer_name].is_valid(mapped_offset):
                    raise exceptions.InvalidAddressException(
                        layer_name=layer_name, invalid_address=mapped_offset
                    )
            except exceptions.InvalidAddressException:
                if not ignore_errors:
                    raise
                return None
            yield offset, length, mapped_offset, length, layer_name
            return None
        while length > 0:
            skip_mask = None
            try:
                chunk_offset, page_size, layer_name = self._translate(offset)
                # Page align the chunk size value
                chunk_size = min(page_size - (offset % page_size), length)
                if not self._context.layers[layer_name].is_valid(
                    chunk_offset, chunk_size
                ):
                    # Virtual -> physical is contiguous in the chunk_size range.
                    # If we fail, we can jump directly to the end as we know all bytes in between
                    # aren't mapped (virtually and) physically anyway.
                    skip_mask = chunk_size - 1
                    raise exceptions.InvalidAddressException(
                        layer_name=layer_name, invalid_address=chunk_offset
                    )
            except (
                exceptions.PagedInvalidAddressException,
                exceptions.InvalidAddressException,
            ) as excp:
                if not ignore_errors:
                    raise
                if skip_mask is None:
                    # We can jump more if we know where the page fault occured
                    if isinstance(excp, exceptions.PagedInvalidAddressException):
                        skip_mask = (1 << excp.invalid_bits) - 1
                    else:
                        skip_mask = (1 << self._page_size_in_bits) - 1
                length_diff = skip_mask + 1 - (offset & skip_mask)
                length -= length_diff
                offset += length_diff
            else:
                yield offset, chunk_size, chunk_offset, chunk_size, layer_name
                length -= chunk_size
                offset += chunk_size

    @property
    def dependencies(self) -> List[str]:
        """Returns a list of the lower layer names that this layer is dependent
        upon."""
        return [self._base_layer] + self._swap_layers

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="memory_layer", optional=False
            ),
            requirements.LayerListRequirement(name="swap_layers", optional=True),
            requirements.IntRequirement(name="page_map_offset", optional=False),
            requirements.IntRequirement(name="kernel_virtual_offset", optional=True),
            requirements.StringRequirement(name="kernel_banner", optional=True),
        ]


class IntelPAE(Intel):
    """Class for handling Physical Address Extensions for Intel
    architectures."""

    _entry_format = "<Q"
    _bits_per_register = 32
    _maxphyaddr = 40
    _maxvirtaddr = 32
    _structure = [
        ("page directory pointer", 2, False),
        ("page directory", 9, True),
        ("page table", 9, False),
    ]
    _direct_metadata = collections.ChainMap({"pae": True}, Intel._direct_metadata)


class Intel32e(Intel):
    """Class for handling 64-bit (32-bit extensions) for Intel
    architectures."""

    _direct_metadata = collections.ChainMap(
        {"architecture": "Intel64"}, Intel._direct_metadata
    )
    _entry_format = "<Q"
    _bits_per_register = 64
    _maxphyaddr = 52
    _maxvirtaddr = 48
    _structure = [
        ("page map layer 4", 9, False),
        ("page directory pointer", 9, True),
        ("page directory", 9, True),
        ("page table", 9, False),
    ]


class WindowsMixin(Intel):
    @staticmethod
    def _page_is_valid(entry: int) -> bool:
        """Returns whether a particular page is valid based on its entry.

        Windows uses additional "available" bits to store flags
        These flags allow windows to determine whether a page is still valid

        Bit 11 is the transition flag, and Bit 10 is the prototype flag

        For more information, see Windows Internals (6th Ed, Part 2, pages 268-269)
        """
        return bool((entry & 1) or ((entry & 1 << 11) and not entry & 1 << 10))

    def _translate_swap(
        self, layer: Intel, offset: int, bit_offset: int
    ) -> Tuple[int, int, str]:
        try:
            return super()._translate(offset)
        except exceptions.PagedInvalidAddressException as excp:
            entry = excp.entry
            tbit = bool(entry & (1 << 11))
            pbit = bool(entry & (1 << 10))
            unknown_bit = bool(entry & (1 << 7))
            n = (entry >> 1) & 0xF
            vbit = bool(entry & 1)
            if (not tbit and not pbit and not vbit and unknown_bit) and (
                (entry >> bit_offset) != 0
            ):
                swap_offset = entry >> bit_offset << excp.invalid_bits

                if layer.config.get("swap_layers", False):
                    swap_layer_name = layer.config.get(
                        interfaces.configuration.path_join(
                            "swap_layers", "swap_layers" + str(n)
                        ),
                        None,
                    )
                    if swap_layer_name:
                        return swap_offset, 1 << excp.invalid_bits, swap_layer_name
                raise exceptions.SwappedInvalidAddressException(
                    layer_name=excp.layer_name,
                    invalid_address=excp.invalid_address,
                    invalid_bits=excp.invalid_bits,
                    entry=excp.entry,
                    swap_offset=swap_offset,
                )
            raise


### These must be full separate classes so that JSON configs re-create them properly


class WindowsIntel(WindowsMixin, Intel):
    def _translate(self, offset):
        return self._translate_swap(self, offset, self._page_size_in_bits)


class WindowsIntelPAE(WindowsMixin, IntelPAE):
    def _translate(self, offset: int) -> Tuple[int, int, str]:
        return self._translate_swap(self, offset, self._bits_per_register)


class WindowsIntel32e(WindowsMixin, Intel32e):
    # TODO: Fix appropriately in a future release.
    # Currently just a temporary workaround to deal with custom bit flag
    # in the PFN field for pages in transition state.
    # See https://github.com/volatilityfoundation/volatility3/pull/475
    _maxphyaddr = 45

    def _translate(self, offset: int) -> Tuple[int, int, str]:
        return self._translate_swap(self, offset, self._bits_per_register // 2)


class LinuxMixin(Intel):
    @functools.cached_property
    def _register_mask(self) -> int:
        return (1 << self._bits_per_register) - 1

    @functools.cached_property
    def _physical_mask(self) -> int:
        # From kernels 4.18 the physical mask is dynamic: See AMD SME, Intel Multi-Key Total
        # Memory Encryption and CONFIG_DYNAMIC_PHYSICAL_MASK: 94d49eb30e854c84d1319095b5dd0405a7da9362
        physical_mask = (1 << self._maxphyaddr) - 1
        # TODO: Come back once SME support is available in the framework
        return physical_mask

    @functools.cached_property
    def page_mask(self) -> int:
        # Note that within the Intel class it's a class method. However, since it uses
        # complement operations and we are working in Python, it would be more careful to
        # limit it to the architecture's pointer size.
        return ~(self.page_size - 1) & self._register_mask

    @functools.cached_property
    def _physical_page_mask(self) -> int:
        return self.page_mask & self._physical_mask

    @functools.cached_property
    def _pte_pfn_mask(self) -> int:
        return self._physical_page_mask

    @functools.cached_property
    def _pte_flags_mask(self) -> int:
        return ~self._pte_pfn_mask & self._register_mask

    def _pte_flags(self, pte) -> int:
        return pte & self._pte_flags_mask

    def _is_pte_present(self, entry: int) -> bool:
        return (
            self._pte_flags(entry) & (self._PAGE_PRESENT | self._PAGE_PROTNONE)
        ) != 0

    def _page_is_valid(self, entry: int) -> bool:
        # Overrides the Intel static method with the Linux-specific implementation
        return self._is_pte_present(entry)

    def _pte_needs_invert(self, entry) -> bool:
        # Entries that were set to PROT_NONE (PAGE_PRESENT) are inverted
        # A clear PTE shouldn't be inverted. See f19f5c4
        return entry and not (entry & self._PAGE_PRESENT)

    def _protnone_mask(self, entry: int) -> int:
        """Gets a mask to XOR with the page table entry to get the correct PFN"""
        return self._register_mask if self._pte_needs_invert(entry) else 0

    def _pte_pfn(self, entry: int) -> int:
        """Extracts the page frame number from the page table entry"""
        pfn = entry ^ self._protnone_mask(entry)
        return (pfn & self._pte_pfn_mask) >> self.page_shift


class LinuxIntel(LinuxMixin, Intel):
    pass


class LinuxIntelPAE(LinuxMixin, IntelPAE):
    pass


class LinuxIntel32e(LinuxMixin, Intel32e):
    # In the Linux kernel, the __PHYSICAL_MASK_SHIFT is a mask used to extract the
    # physical address from a PTE. In Volatility3, this is referred to as _maxphyaddr.
    #
    # Until kernel version 4.17, Linux x86-64 used a 46-bit mask. With commit
    # b83ce5ee91471d19c403ff91227204fb37c95fb2, this was extended to 52 bits,
    # applying to both 4 and 5-level page tables.
    #
    # We initially used 52 bits for all Intel 64-bit systems, but this produced incorrect
    # results for PROT_NONE pages. Since the mask value is defined by a preprocessor macro,
    # it's difficult to detect the exact bit shift used in the current kernel.
    # Using 46 bits has proven reliable for our use case, as seen in tools like crashtool.
    _maxphyaddr = 46
