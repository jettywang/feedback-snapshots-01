# -------------------------------------------------------------------------------
# elftools: ehabi/ehabiinfo.py
#
# Decoder for ARM exception handler bytecode.
#
# LeadroyaL (leadroyal@qq.com)
# This code is in the public domain
# -------------------------------------------------------------------------------
from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING, Any, NamedTuple

from .constants import (
    EHABI_INDEX_ENTRY_SIZE,
    EXIDX_CANTUNWIND,
    PREL31_SIGN_BIT,
    PREL31_SIGN_EXTEND,
    PREL31_VALUE_MASK,
)
from ..common.utils import preserve_stream_pos
from .decoder import EHABIBytecodeDecoder

if TYPE_CHECKING:
    from .decoder import MnemonicItem
    from .unwind import EHABIUnwindResult
    from ..elf.sections import Section


class EHABIAddressLookup(NamedTuple):
    """ Result of resolving an instruction address against an .ARM.exidx table.

        status:
            'found'         the address is covered by the reported entry.
            'not_covered'   the address is outside every indexed function.
            'ambiguous'     the table cannot support a definite answer, for
                            example because two entries share a function
                            offset, offsets decrease, or a corrupt entry sits
                            between the address and the next known function.
            'unknown_extent' the entry was found but the end of the last
                            function cannot be established from sh_link or the
                            start of .ARM.exidx.
            'empty_extent'  the entry describes an empty address range.
            'invalid'       the requested address is not a non-negative int.

        entry is still useful for 'unknown_extent' and 'empty_extent'; it is
        None for 'not_covered', 'ambiguous' and 'invalid'.
    """

    address: int
    status: str
    reason: str
    entry_index: int | None
    entry: EHABIEntry | None
    function_start: int | None
    function_end: int | None


class EHABIInfo:
    """ ARM exception handler abi information class.

        Parameters:

            arm_idx_section:
                elf.sections.Section object, section which type is SHT_ARM_EXIDX.

            little_endian:
                bool, endianness of elf file.
    """

    def __init__(self, arm_idx_section: Section, little_endian: bool) -> None:
        self._arm_idx_section = arm_idx_section
        self._little_endian = little_endian

    def section_name(self) -> str:
        return self._arm_idx_section.name

    def section_offset(self) -> int:
        return self._arm_idx_section['sh_offset']

    def section_address(self) -> int:
        return self._arm_idx_section['sh_addr']

    def num_entry(self) -> int:
        """ Number of complete exception handler entries in the section.
        """
        return self._num_entry

    @property
    def trailing_bytes(self) -> int:
        """ Bytes at the end of .ARM.exidx that do not form a full entry.

            A non-zero value means the section is short by that many bytes;
            those bytes are not interpreted as an entry.
        """
        return self._arm_idx_section['sh_size'] % EHABI_INDEX_ENTRY_SIZE

    @cached_property
    def _num_entry(self) -> int:
        return self._arm_idx_section['sh_size'] // EHABI_INDEX_ENTRY_SIZE

    def get_entry(self, n: int) -> EHABIEntry:
        """ Get the exception handler entry at index #n. (EHABIEntry object or a subclass)

            A short entry or a pointer outside the file is reported as a
            CorruptEHABIEntry instead of raising, so that callers can explain
            which part of the table is usable. An out-of-range index still
            raises IndexError.
        """
        if not isinstance(n, int) or isinstance(n, bool) or n < 0 or n >= self.num_entry():
            raise IndexError(f'Invalid entry {n}/{self.num_entry()}')

        entry_file_offset = self.section_offset() + n * EHABI_INDEX_ENTRY_SIZE
        entry = self._get_entry(n, entry_file_offset)
        entry.index = n
        entry.exidx_entry_offset = entry_file_offset
        return entry

    def iter_entries(self) -> list[EHABIEntry]:
        """ Return all entries in index order.
        """
        return [self.get_entry(i) for i in range(self.num_entry())]

    @cached_property
    def _entries(self) -> tuple[EHABIEntry, ...]:
        return tuple(self.get_entry(i) for i in range(self.num_entry()))

    def lookup_address(self, address: int) -> EHABIAddressLookup:
        """ Find the .ARM.exidx entry that covers an instruction address.

            Coverage is taken from the function offset of the entry up to the
            next known function offset. The last entry is bounded by the
            section referenced from sh_link, falling back to the start of
            .ARM.exidx. A corrupt entry has no usable function offset, so it
            makes the interval around it ambiguous rather than silently
            assigning those instructions to a neighbour.
        """
        if not isinstance(address, int) or isinstance(address, bool) or address < 0:
            return EHABIAddressLookup(address, 'invalid', 'address must be a non-negative integer',
                                      None, None, None, None)

        entries = list(self._entries)
        known: list[tuple[int, int]] = [
            (i, entry.function_offset)
            for i, entry in enumerate(entries)
            if entry.function_offset is not None]

        if not known:
            return EHABIAddressLookup(
                address, 'ambiguous', 'the .ARM.exidx table has no usable function offsets',
                None, None, None, None)

        for (prev_i, prev_start), (next_i, next_start) in zip(known, known[1:]):
            if next_start < prev_start:
                return EHABIAddressLookup(
                    address, 'ambiguous',
                    f'function offsets decrease at entries {prev_i} and {next_i}; '
                    'the table is not sorted',
                    None, None, None, None)

        # Rightmost known start <= address.
        candidate_pos = None
        for pos, (_, start) in enumerate(known):
            if start <= address:
                candidate_pos = pos
            else:
                break

        if candidate_pos is None:
            leading_corrupt = [i for i in range(known[0][0])
                               if entries[i].function_offset is None]
            if leading_corrupt:
                return EHABIAddressLookup(
                    address, 'ambiguous',
                    'corrupt entry/entries {} precede the first known function '
                    'and could cover this address'.format(
                        ', '.join(str(i) for i in leading_corrupt)),
                    None, None, None, None)
            return EHABIAddressLookup(
                address, 'not_covered',
                f'address is before the first indexed function at {known[0][1]:#x}',
                None, None, None, None)

        index, start = known[candidate_pos]
        entry = entries[index]

        same_start = [i for i, other_start in known if other_start == start]
        if len(same_start) > 1:
            return EHABIAddressLookup(
                address, 'ambiguous',
                'entries {} share the function offset {:#x}'.format(
                    ', '.join(str(i) for i in same_start), start),
                None, None, start, None)

        if candidate_pos + 1 < len(known):
            next_index, end = known[candidate_pos + 1]
            corrupt_between = [
                i for i in range(index + 1, next_index)
                if entries[i].function_offset is None]
        else:
            end = self._last_function_end(start)
            corrupt_between = [
                i for i in range(index + 1, len(entries))
                if entries[i].function_offset is None]

        if corrupt_between:
            return EHABIAddressLookup(
                address, 'ambiguous',
                'corrupt entry/entries {} prevent assigning coverage'.format(
                    ', '.join(str(i) for i in corrupt_between)),
                index, None, start, None)

        if end is None:
            return EHABIAddressLookup(
                address, 'unknown_extent',
                'cannot determine the end of the final indexed function',
                index, entry, start, None)

        if end == start:
            if address == start:
                return EHABIAddressLookup(
                    address, 'empty_extent',
                    f'entry {index} describes an empty range at {start:#x}',
                    index, entry, start, end)
            return EHABIAddressLookup(
                address, 'not_covered',
                f'address is beyond the empty range {start:#x} of entry {index}',
                None, None, None, None)

        if end < start:
            return EHABIAddressLookup(
                address, 'ambiguous',
                f'entry {index} ends before it starts ({end:#x} < {start:#x})',
                index, None, start, None)

        if not (start <= address < end):
            return EHABIAddressLookup(
                address, 'not_covered',
                f'address is outside [{start:#x}, {end:#x})',
                None, None, None, None)

        return EHABIAddressLookup(address, 'found', 'address is covered by this entry',
                                  index, entry, start, end)

    def unwind_by_address(
        self,
        address: int,
        registers: Any,
        memory: Any,
        *,
        max_steps: int | None = None,
    ) -> EHABIUnwindResult:
        """ Resolve an instruction address and evaluate its compact bytecode.

            registers and memory are supplied by the caller; this method never
            reads host process memory or executes a personality routine from
            the sample. See elftools.ehabi.unwind for the accepted shapes and
            the exact restricted semantics.
        """
        from .unwind import make_no_entry_result, unwind_entry

        lookup = self.lookup_address(address)
        if lookup.status != 'found' or lookup.entry is None:
            return make_no_entry_result(lookup, registers)

        return unwind_entry(
            lookup.entry, registers, memory, address=address,
            lookup=lookup, max_steps=max_steps)

    def _last_function_end(self, start: int) -> int | None:
        """ End address for the last indexed function, or None if unknown.
        """
        elf = getattr(self._arm_idx_section, 'elffile', None)
        link = self._arm_idx_section['sh_link']
        if elf is not None and isinstance(link, int) and 0 <= link < elf.num_sections():
            linked = elf.get_section(link)
            linked_end = linked['sh_addr'] + linked['sh_size']
            if linked['sh_addr'] <= start <= linked_end:
                return linked_end

        exidx_start = self.section_address()
        if exidx_start > start:
            return exidx_start
        return None

    def _get_entry(self, n: int, entry_file_offset: int) -> EHABIEntry:
        raw = self._read_at(entry_file_offset, EHABI_INDEX_ENTRY_SIZE)
        if raw is None:
            return CorruptEHABIEntry(
                f'Corrupt ARM exception handler table entry: {n:x} (short .ARM.exidx entry)')

        word0 = int.from_bytes(raw[0:4], self._byte_order())
        word1 = int.from_bytes(raw[4:8], self._byte_order())

        if word0 & 0x80000000 != 0:
            return CorruptEHABIEntry(f'Corrupt ARM exception handler table entry: {n:x}')

        function_offset = arm_expand_prel31(
            word0, self.section_address() + n * EHABI_INDEX_ENTRY_SIZE)

        if word1 == EXIDX_CANTUNWIND:
            return CannotUnwindEHABIEntry(function_offset)
        elif word1 & 0x80000000 == 0:
            # Highest bit is zero: word1 is a PREL31 pointer into .ARM.extab.
            table_address = arm_expand_prel31(
                word1, self.section_address() + n * EHABI_INDEX_ENTRY_SIZE + 4)
            return self._get_extab_entry(n, function_offset, table_address)
        else:
            # Highest bit is one: inline compact model, which must be model 0.
            if word1 & 0x7f000000 != 0:
                return CorruptEHABIEntry(f'Corrupt ARM compact model table entry: {n:x}')
            bytecode = [(word1 >> 16) & 0xff, (word1 >> 8) & 0xff, word1 & 0xff]
            offsets = self._inline_bytecode_offsets(entry_file_offset)
            return EHABIEntry(
                function_offset, 0, bytecode,
                bytecode_source='inline',
                bytecode_file_offsets=offsets)

    def _get_extab_entry(
        self,
        n: int,
        function_offset: int,
        table_address: int,
    ) -> EHABIEntry:
        resolved = self._resolve_address(table_address)
        if resolved is None:
            return CorruptEHABIEntry(
                f'Corrupt ARM exception handler table entry: {n:x} '
                f'(.ARM.extab pointer {table_address:#x} is outside the file)')

        table_file_offset, available, section_name = resolved
        if section_name is not None and 'extab' not in section_name:
            return CorruptEHABIEntry(
                f'Corrupt ARM exception handler table entry: {n:x} '
                f'(.ARM.extab pointer {table_address:#x} names section '
                f'{section_name!r}, not unwind bytecode)')
        header = self._read_at(table_file_offset, 4)
        if header is None:
            return CorruptEHABIEntry(
                f'Corrupt ARM exception handler table entry: {n:x} '
                f'(short .ARM.extab header at {table_address:#x})')

        word0 = int.from_bytes(header, self._byte_order())
        if word0 & 0x80000000 == 0:
            # Generic model. The personality pointer is retained as evidence;
            # it is never called.
            return GenericEHABIEntry(function_offset, arm_expand_prel31(word0, table_address))

        if word0 & 0x70000000 != 0:
            return CorruptEHABIEntry(f'Corrupt ARM compact model table entry: {n:x}')

        per_index = (word0 >> 24) & 0x0f
        if per_index == 0:
            bytecode = [(word0 >> 16) & 0xff, (word0 >> 8) & 0xff, word0 & 0xff]
            offsets = self._extab_group_offsets(table_file_offset, 3)
            return EHABIEntry(
                function_offset, 0, bytecode, eh_table_offset=table_address,
                bytecode_source='extab', bytecode_file_offsets=offsets)

        if per_index not in (1, 2):
            return CorruptEHABIEntry(
                f'Unknown ARM compact model {int(per_index)} at table entry: {n:x}')

        more_word = (word0 >> 16) & 0xff
        bytecode = [(word0 >> 8) & 0xff, word0 & 0xff]
        offsets = self._extab_low_byte_offsets(table_file_offset, 4, 2)

        # Continuation words must stay inside the section (or, failing that,
        # the file) that holds the entry. A declared word count must not walk
        # into unrelated sections.
        available_words = max(0, (available - 4) // 4)
        words_read = 0
        while words_read < min(more_word, available_words):
            word_offset = table_file_offset + 4 + words_read * 4
            raw = self._read_at(word_offset, 4)
            if raw is None:
                break
            word = int.from_bytes(raw, self._byte_order())
            bytecode.extend([(word >> 24) & 0xff, (word >> 16) & 0xff,
                             (word >> 8) & 0xff, word & 0xff])
            offsets.extend(self._extab_group_offsets(word_offset, 4))
            words_read += 1

        truncated = words_read < more_word
        reason = None
        if truncated:
            where = f' section {section_name!r}' if section_name else ' the file'
            reason = (f'.ARM.extab entry at {table_address:#x} declares '
                      f'{int(more_word)} continuation word(s), only '
                      f'{int(words_read)} available in{where}')
            # Unlike a corrupt entry, the header and the words that are
            # present are still valid evidence. Keep them, but never mark the
            # entry as safe to interpret as a complete program.

        return EHABIEntry(
            function_offset, per_index, bytecode,
            eh_table_offset=table_address,
            truncated=truncated,
            truncation_reason=reason,
            bytecode_source='extab',
            bytecode_file_offsets=offsets)

    def _byte_order(self) -> str:
        return 'little' if self._little_endian else 'big'

    def _stream_size(self) -> int:
        elf = getattr(self._arm_idx_section, 'elffile', None)
        size = getattr(elf, 'stream_len', None)
        if isinstance(size, int):
            return size
        stream = self._arm_idx_section.stream
        with preserve_stream_pos(stream):
            stream.seek(0, 2)
            size = stream.tell()
        return size

    def _read_at(self, offset: int, size: int) -> bytes | None:
        """ Read a file-backed range without crossing the end of the file.
        """
        if offset < 0 or size < 0:
            return None
        file_size = self._stream_size()
        if offset > file_size or size > file_size - offset:
            return None
        stream = self._arm_idx_section.stream
        with preserve_stream_pos(stream):
            stream.seek(offset)
            data = stream.read(size)
        if len(data) != size:
            return None
        return data

    @cached_property
    def _sections(self) -> list[tuple[int, int, int, str]]:
        """ (address, size, file offset, name) for sections of the container.
        """
        elf = getattr(self._arm_idx_section, 'elffile', None)
        if elf is None:
            return []
        result = []
        for section in elf.iter_sections():
            size = section['sh_size']
            # SHT_NOBITS occupies no file bytes; its sh_offset names unrelated
            # data, so it must never satisfy an .ARM.extab pointer.
            if size and section['sh_type'] not in ('SHT_NULL', 'SHT_NOBITS'):
                result.append((section['sh_addr'], size, section['sh_offset'], section.name))
        return result

    def _resolve_address(self, address: int) -> tuple[int, int, str | None] | None:
        """ Map a virtual address to (file offset, available bytes, section name).

            When no section covers the address, fall back to treating it as a
            file offset, as several ARM objects use identical link-time
            addresses and file offsets. The file bound is still enforced.
        """
        for start, size, offset, name in self._sections:
            if start <= address < start + size:
                file_offset = offset + (address - start)
                available = min(size - (address - start),
                                self._stream_size() - file_offset)
                return file_offset, max(0, available), name

        # Some hand-built and object-like tables use the same value for
        # sh_addr and sh_offset. Only then is an address usable as a file
        # offset; otherwise it may name unrelated section data.
        file_size = self._stream_size()
        if (self.section_address() == self.section_offset()
                and 0 <= address < file_size):
            return address, file_size - address, None
        return None

    def _inline_bytecode_offsets(self, entry_file_offset: int) -> tuple[int, int, int]:
        if self._little_endian:
            return (entry_file_offset + 6, entry_file_offset + 5, entry_file_offset + 4)
        return (entry_file_offset + 5, entry_file_offset + 6, entry_file_offset + 7)

    def _extab_group_offsets(self, group_file_offset: int, count: int) -> list[int]:
        """ File offsets for all bytes of a word in decoder order.

            The decoder orders bytes from the most significant byte down.
        """
        if self._little_endian:
            return [group_file_offset + count - 1 - i for i in range(count)]
        return [group_file_offset + i for i in range(count)]

    def _extab_low_byte_offsets(
        self, group_file_offset: int, word_size: int, count: int,
    ) -> list[int]:
        """ File offsets for the lowest `count` bytes of a word.

            Used by compact model 1/2, whose header carries only two payload
            bytes in the low half of the word.
        """
        all_offsets = self._extab_group_offsets(group_file_offset, word_size)
        return all_offsets[word_size - count:]


class EHABIEntry:
    """ Exception handler abi entry.

        Accessible attributes:

            function_offset:
                Integer.
                None if corrupt. (Reference: CorruptEHABIEntry)

            personality:
                Integer.
                None if corrupt or unwindable. (Reference: CorruptEHABIEntry, CannotUnwindEHABIEntry)
                0/1/2 for ARM personality compact format.
                Others for generic personality.

            bytecode_array:
                Integer array.
                None if corrupt or unwindable or generic personality.
                (Reference: CorruptEHABIEntry, CannotUnwindEHABIEntry, GenericEHABIEntry)

            eh_table_offset:
                Integer.
                Only entries who point to .ARM.extab contains this field, otherwise return None.

            unwindable:
                bool. Whether this function is unwindable.

            corrupt:
                bool. Whether this entry is corrupt.

            truncated:
                bool. Whether the compact bytecode claims more bytes than the
                containing table/file provides.

            truncation_reason:
                String explaining that truncation, or None.

            bytecode_source:
                'inline' when the compact bytecode is packed into .ARM.exidx,
                'extab' when it came from .ARM.extab, None for generic or
                corrupt entries.

            bytecode_file_offsets:
                File offset of each byte in bytecode_array, in the decoder's
                canonical order, or None when not applicable.

            index / exidx_entry_offset:
                Set by EHABIInfo.get_entry for the entry's index and file
                offset in .ARM.exidx. None for entries created directly.

    """

    def __init__(
        self,
        function_offset: int | None,
        personality: int | None,
        bytecode_array: list[int] | None,
        eh_table_offset: int | None = None,
        unwindable: bool = True,
        corrupt: bool = False,
        *,
        truncated: bool = False,
        truncation_reason: str | None = None,
        bytecode_source: str | None = None,
        bytecode_file_offsets: tuple[int, ...] | list[int] | None = None,
    ) -> None:
        self.function_offset = function_offset
        self.personality = personality
        self.bytecode_array = bytecode_array
        self.eh_table_offset = eh_table_offset
        self.unwindable = unwindable
        self.corrupt = corrupt
        self.truncated = truncated
        self.truncation_reason = truncation_reason
        self.bytecode_source = bytecode_source
        self.bytecode_file_offsets = (
            tuple(bytecode_file_offsets) if bytecode_file_offsets is not None else None)
        # Set by EHABIInfo.get_entry; None for entries built directly.
        self.index: int | None = None
        self.exidx_entry_offset: int | None = None

    def mnmemonic_array(self) -> list[MnemonicItem] | None:
        if self.bytecode_array:
            return EHABIBytecodeDecoder(self.bytecode_array).mnemonic_array
        else:
            return None

    def instructions(self) -> list[Any] | None:
        """ Structured compact instructions; see decoder.EHABIInstruction.
        """
        if self.bytecode_array:
            return list(EHABIBytecodeDecoder(self.bytecode_array).instructions)
        return None

    def unwind(self, registers: Any, memory: Any, *,
               max_steps: int | None = None) -> EHABIUnwindResult:
        """ Evaluate this entry's compact bytecode against caller-provided
            registers and memory. Generic personality entries are not
            evaluated.
        """
        from .unwind import unwind_entry
        return unwind_entry(self, registers, memory, max_steps=max_steps)

    def __repr__(self) -> str:
        fo = self.function_offset
        to = self.eh_table_offset
        return (
            "<EHABIEntry"
            f" function_offset={'' if fo is None else f'{fo:#x}'}"
            f", personality={self.personality}"
            f"{f', eh_table_offset={to:#x}' if to else ''}"
            f", bytecode={self.bytecode_array}"
            f"{', truncated' if self.truncated else ''}"
            ">"
        )


class CorruptEHABIEntry(EHABIEntry):
    """ This entry is corrupt. Attribute #corrupt will be True.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(function_offset=None, personality=None, bytecode_array=None,
                                                corrupt=True)
        self.reason = reason

    def __repr__(self) -> str:
        return f"<CorruptEHABIEntry reason={self.reason}>"


class CannotUnwindEHABIEntry(EHABIEntry):
    """ This function cannot be unwind. Attribute #unwindable will be False.
    """

    if TYPE_CHECKING:
        function_offset: int  # instead of `int|None` to save `is None` checks everywhere

    def __init__(self, function_offset: int) -> None:
        super().__init__(function_offset, personality=None, bytecode_array=None,
                                                     unwindable=False)

    def __repr__(self) -> str:
        return f"<CannotUnwindEHABIEntry function_offset=0x{self.function_offset:x}>"


class GenericEHABIEntry(EHABIEntry):
    """ This entry is generic model rather than ARM compact model.Attribute #bytecode_array will be None.
    """

    if TYPE_CHECKING:
        function_offset: int  # instead of `int|None` to save `is None` checks everywhere
        personality: int

    def __init__(self, function_offset: int, personality: int) -> None:
        super().__init__(function_offset, personality, bytecode_array=None)

    def __repr__(self) -> str:
        return f"<GenericEHABIEntry function_offset=0x{self.function_offset:x}, personality=0x{self.personality:x}>"


def arm_expand_prel31(address: int, place: int) -> int:
    """ Expand a PREL31 value into an absolute address.

       address: uint32 PREL31 value (bit 31 must be zero)
       place: uint32 address of the PREL31 field
       return: uint64 absolute address
    """
    location = address & PREL31_VALUE_MASK
    if location & PREL31_SIGN_BIT:
        location |= PREL31_SIGN_EXTEND
    return location + place & 0xffffffffffffffff
