#-------------------------------------------------------------------------------
# elftools tests
#
# This code is in the public domain
#-------------------------------------------------------------------------------
"""Tests for the restricted DWARFv5 .debug_macro reader."""
from __future__ import annotations

import io
import os
import unittest

from elftools.dwarf.dwarfinfo import DwarfConfig, DebugSectionDescriptor
from elftools.elf.elffile import ELFFile
from elftools.dwarf.macinfo import (
    DEFINE,
    DEFINE_STRP,
    END_FILE,
    IMPORT,
    IMPORT_SUP,
    START_FILE,
    UNDEF,
    UNDEF_STRX,
    MacroInfo,
)


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _cstr(value: bytes) -> bytes:
    return value + b'\x00'


def _header(
    flags: int = 0,
    line_offset: int | None = None,
    opcode_operands: bytes = b'',
) -> bytes:
    out = bytearray((5).to_bytes(2, 'little'))
    out.append(flags)
    if flags & 0x02:
        assert line_offset is not None
        out += line_offset.to_bytes(4, 'little')
    if flags & 0x04:
        out += opcode_operands
    return bytes(out)


def _define(text: bytes, line: int = 1) -> bytes:
    return bytes((DEFINE,)) + _uleb(line) + _cstr(text)


def _undef(text: bytes, line: int = 1) -> bytes:
    return bytes((UNDEF,)) + _uleb(line) + _cstr(text)


def _define_strp(offset: int, line: int = 1) -> bytes:
    return bytes((DEFINE_STRP,)) + _uleb(line) + offset.to_bytes(4, 'little')


def _undef_strx(index: int, line: int = 1) -> bytes:
    return bytes((UNDEF_STRX,)) + _uleb(line) + _uleb(index)


def _start_file(line: int, index: int) -> bytes:
    return bytes((START_FILE,)) + _uleb(line) + _uleb(index)


_END_FILE = bytes((END_FILE,))
_TERM = b'\x00'


class _NoStrings:
    """Minimal DWARFInfo stand-in with only the attributes the reader uses."""
    debug_str_sec = None
    debug_str_offsets_sec = None
    supplementary_dwarfinfo = None
    config = DwarfConfig(little_endian=True, default_address_size=4, machine_arch='x64')


class _MacroTestCase(unittest.TestCase):
    def _info(self, section: bytes, cu=None) -> MacroInfo:
        return MacroInfo(_NoStrings(), io.BytesIO(section), len(section), cu)


class TestMacroUnits(_MacroTestCase):

    def test_header_fields_and_offsets(self):
        # No line offset, so the header is 3 bytes and events start right away.
        body = _header(flags=0) + _define(b'A 1') + _TERM
        info = self._info(body)
        units = info.iter_units()
        self.assertEqual(len(units), 1)
        header = units[0].header
        self.assertEqual(header.version, 5)
        self.assertEqual(header.offset_size, 4)
        self.assertEqual(header.header_size, 3)
        self.assertEqual(header.events_offset, 3)
        self.assertFalse(header.has_debug_line_offset)
        self.assertEqual(header.end_offset, len(body))

        event = units[0].events[0]
        self.assertEqual(event.offset, 3)
        self.assertEqual(event.end_offset, 9)
        self.assertEqual(event.line, 1)
        self.assertEqual(event.string, b'A 1')

    def test_offset_size_flag_controls_operands(self):
        # A 64-bit macro section in a 32-bit DWARF file: the operand width
        # must follow the header's offset_size_flag, not the CU format.
        data = b'rounded-out'
        string_sec = DebugSectionDescriptor(io.BytesIO(_cstr(data)), '.debug_str', 0, len(data) + 1, 0)
        dwarf = _NoStrings()
        dwarf.debug_str_sec = string_sec

        body = _header(flags=0x01) + bytes((DEFINE_STRP, 1)) + (0).to_bytes(8, 'little') + _TERM
        info = MacroInfo(dwarf, io.BytesIO(body), len(body))
        unit = info.iter_units()[0]
        self.assertEqual(unit.header.offset_size, 8)
        self.assertEqual(unit.events[0].string, b'rounded-out')
        self.assertEqual(unit.events[0].string_offset, 0)
        self.assertEqual(unit.events[0].raw, b'')

    def test_redefinitions_are_preserved_in_order(self):
        body = (_header(0)
                + _define(b'X 1', 1)
                + _undef(b'X', 2)
                + _define(b'X 3', 3)
                + _TERM)
        unit = self._info(body).iter_units()[0]
        defs = unit.definitions()
        self.assertEqual([(d.name, d.state, d.line) for d in defs],
                         [(b'X', 'defined', 1), (b'X', 'undefined', 2),
                          (b'X', 'defined', 3)])
        self.assertEqual(defs[2].definition, b'3')
        self.assertEqual([e.offset for e in unit.events], sorted(e.offset for e in unit.events))

    def test_function_like_macro_split(self):
        body = _header(0) + _define(b'F(x,y) ((x)+(y))', 7) + _TERM
        d = self._info(body).iter_units()[0].definitions()[0]
        self.assertEqual(d.name, b'F(x,y)')
        self.assertEqual(d.definition, b'((x)+(y))')

    def test_unit_boundaries_are_terminated_not_length_prefixed(self):
        first = _header(0) + _define(b'A 1') + _TERM
        second = _header(0) + _define(b'B 2') + _TERM
        units = self._info(first + second).iter_units()
        self.assertEqual(len(units), 2)
        self.assertEqual(units[0].header.unit_offset, 0)
        self.assertEqual(units[1].header.unit_offset, len(first))
        self.assertEqual(units[1].header.end_offset, len(first) + len(second))
        self.assertEqual(units[1].events[0].offset, len(first) + 3)

    def test_unterminated_unit_is_truncated_and_stops_enumeration(self):
        body = _header(0) + _define(b'A 1')
        unit = self._info(body).iter_units()[0]
        self.assertTrue(unit.truncated)
        self.assertEqual(len(unit.events), 1)

    def test_unknown_opcode_kept_and_remainder_preserved(self):
        body = _header(0) + b'\xee\x01\x02' + _define(b'AFTER 1') + _TERM
        unit = self._info(body).iter_units()[0]
        self.assertTrue(unit.truncated)
        self.assertFalse(unit.events[0].resolved)
        self.assertEqual(unit.events[0].opcode, 0xee)
        # The opcode byte belongs to the unresolved event; later bytes cannot
        # be aligned and are preserved verbatim from just after it.
        self.assertEqual(unit.unparsed, b'\x01\x02' + _define(b'AFTER 1') + _TERM)

    def test_truncated_opcode_operands_table_is_reported(self):
        # Count says 2 but only a partial first entry is present.
        body = _header(0x04, opcode_operands=b'\x02\xe1') + _define(b'A 1') + _TERM
        unit = self._info(body).iter_units()[0]
        self.assertTrue(unit.header.truncated_opcode_operands)
        self.assertTrue(unit.truncated)
        self.assertEqual(unit.events, [])
        # Everything from the first table entry that could not be decoded in
        # full is preserved, including bytes that later entries would have used.
        self.assertTrue(unit.header.unparsed_opcode_operands)
        self.assertTrue(unit.header.unparsed_opcode_operands.startswith(b'A'))

    def test_declared_opcode_operands_keep_later_events_aligned(self):
        # Header describes vendor opcode 0xe1 with one data2 operand.
        operands = b'\x01\xe1\x01\x05'  # count=1, opcode=0xe1, 1 operand, data2
        body = (_header(0x04, opcode_operands=operands)
                + b'\xe1\x34\x12'
                + _define(b'ALIGNED 1')
                + _TERM)
        unit = self._info(body).iter_units()[0]
        self.assertEqual(unit.header.opcode_operands[0].opcode, 0xe1)
        self.assertEqual(unit.header.opcode_operands[0].operands[0].form_name,
                         'DW_FORM_data2')
        vendor = unit.events[0]
        self.assertFalse(vendor.resolved)
        self.assertEqual(vendor.raw, b'\xe1\x34\x12')
        self.assertEqual(unit.events[1].string, b'ALIGNED 1')
        self.assertFalse(unit.truncated)

    def test_unresolved_strp_is_kept_not_fabricated(self):
        body = _header(0) + _define_strp(0x1234) + _TERM
        unit = self._info(body).iter_units()[0]
        event = unit.events[0]
        self.assertFalse(event.resolved)
        self.assertIsNone(event.string)
        self.assertEqual(event.string_offset, 0x1234)
        self.assertEqual(unit.unparsed, b'')

    def test_unresolved_strx_without_cu(self):
        body = _header(0) + _undef_strx(3, 9) + _TERM
        unit = self._info(body).iter_units()[0]
        event = unit.events[0]
        self.assertFalse(event.resolved)
        self.assertIsNone(event.string)
        self.assertEqual(event.string_offset, 3)
        self.assertEqual(event.line, 9)


class TestMacroImports(_MacroTestCase):
    def _section(self) -> tuple[bytes, int, int]:
        main = bytearray(_header(0))
        main += _start_file(0, 0)
        main += _define(b'MAIN 1', 1)
        main += _undef(b'MAIN', 2)
        import_at = len(main)
        main += bytes((IMPORT,)) + (0).to_bytes(4, 'little')  # patched below
        main += _start_file(3, 1)
        main += _define(b'TAIL 9', 4)
        main += _END_FILE
        main += _TERM

        imported_at = len(main)
        imported = _header(0) + _define(b'IMPORTED 7', 1) + _END_FILE
        imported = imported[:-len(_END_FILE)] + _TERM
        main += imported

        # Point the import operand at the imported unit.
        main[import_at + 1:import_at + 5] = imported_at.to_bytes(4, 'little')
        return bytes(main), import_at, imported_at

    def test_import_is_expanded_in_place(self):
        section, import_at, imported_at = self._section()
        info = MacroInfo(_NoStrings(), io.BytesIO(section), len(section))
        unit = info.iter_units()[0]
        names = [e.opcode_name for e in unit.events]
        self.assertEqual(names, [
            'DW_MACRO_start_file', 'DW_MACRO_define', 'DW_MACRO_undef',
            'DW_MACRO_import', 'DW_MACRO_define', 'DW_MACRO_start_file',
            'DW_MACRO_define', 'DW_MACRO_end_file'])
        imported_event = unit.events[4]
        self.assertEqual(imported_event.string, b'IMPORTED 7')
        self.assertEqual(imported_event.unit_offset, imported_at)
        self.assertEqual(imported_event.import_chain, (imported_at,))
        self.assertEqual(unit.events[3].offset, import_at)
        self.assertEqual([i.target_offset for i in unit.imports if i.supported], [imported_at])
        self.assertFalse(unit.truncated)

    def test_unresolved_events_keep_their_reference(self):
        body = _header(0) + _define_strp(0x999) + _TERM
        unit = self._info(body).iter_units()[0]
        event = unit.events[0]
        self.assertFalse(event.resolved)
        self.assertEqual(event.string_offset, 0x999)
        self.assertEqual(event.raw, bytes((DEFINE_STRP, 1)) + (0x999).to_bytes(4, 'little'))

    def test_cyclic_import_is_bounded(self):
        body = bytearray(_header(0))
        import_at = len(body)
        body += bytes((IMPORT,)) + (0).to_bytes(4, 'little')
        body += _TERM
        # Self-import: the target is the unit's own header offset.
        body[import_at + 1:import_at + 5] = (0).to_bytes(4, 'little')
        info = MacroInfo(_NoStrings(), io.BytesIO(bytes(body)), len(body))
        unit = info.iter_units()[0]
        self.assertEqual(len(unit.events), 1)
        self.assertEqual(unit.imports[-1].reason, 'cyclic import')
        self.assertFalse(unit.imports[-1].supported)
        self.assertFalse(unit.events[0].import_supported)

    def test_mutual_cycle_is_bounded(self):
        body = bytearray(_header(0))
        first_import = len(body)
        body += bytes((IMPORT,)) + (0).to_bytes(4, 'little') + _TERM
        second_at = len(body)
        body[first_import + 1:first_import + 5] = second_at.to_bytes(4, 'little')
        body += _header(0)
        second_import = len(body)
        body += bytes((IMPORT,)) + (0).to_bytes(4, 'little') + _TERM
        body[second_import + 1:second_import + 5] = (0).to_bytes(4, 'little')
        info = MacroInfo(_NoStrings(), io.BytesIO(bytes(body)), len(body))
        unit = info.iter_units()[0]
        reasons = [i.reason for i in unit.imports if not i.supported]
        self.assertIn('cyclic import', reasons)
        self.assertLessEqual(len(unit.events), 2)

    def test_import_target_outside_section_is_reported(self):
        body = _header(0) + bytes((IMPORT,)) + (0x1000).to_bytes(4, 'little') + _TERM
        unit = self._info(body).iter_units()[0]
        imp = unit.imports[-1]
        self.assertFalse(imp.supported)
        self.assertEqual(imp.target_offset, 0x1000)
        self.assertIsNone(imp.target_unit_offset)
        self.assertEqual(imp.reason, 'import target outside .debug_macro')

    def test_supplementary_import_is_recorded_not_followed(self):
        body = _header(0) + bytes((IMPORT_SUP,)) + (0x40).to_bytes(4, 'little') + _TERM
        unit = self._info(body).iter_units()[0]
        imp = unit.imports[-1]
        self.assertFalse(imp.supported)
        self.assertEqual(imp.target_offset, 0x40)
        self.assertIsNone(imp.target_unit_offset)
        self.assertEqual(unit.events[0].opcode_name, 'DW_MACRO_import_sup')
        self.assertFalse(unit.events[0].import_supported)

    def test_imported_unit_keeps_its_own_file_index(self):
        """An imported unit's start_file must not inherit the importer's stack.

        The importer enters file 0 and then imports a unit whose start_file
        names its own file 1. If the importer's stack were applied, the
        imported events would wrongly be attributed to file 0.
        """
        body = bytearray(_header(0x02, line_offset=0))
        body += _start_file(0, 0)
        body += _define(b'OUTER 1', 1)
        import_at = len(body)
        body += bytes((IMPORT,)) + (0).to_bytes(4, 'little')
        body += _END_FILE
        body += _TERM
        imported_at = len(body)
        body[import_at + 1:import_at + 5] = imported_at.to_bytes(4, 'little')
        body += _header(0)
        body += _start_file(0, 1)
        body += _define(b'INNER 1', 1)
        body += _END_FILE
        body += _TERM

        # Only the importer has a .debug_line offset; provide it a file table
        # with two names. The imported unit's header has none, so its file
        # index stays unresolved rather than borrowing the importer's table.
        class LP:
            header = {
                'file_names': [
                    {'DW_LNCT_path': b'outer.c'},
                    {'DW_LNCT_path': b'inner.c'},
                ]
            }

        info = MacroInfo(_NoStrings(), io.BytesIO(bytes(body)), len(body))
        info._line_programs[0] = LP()
        unit = info.get_unit(0)
        self.assertIsNotNone(unit)
        outer = [e for e in unit.events if e.unit_offset == 0]
        inner = [e for e in unit.events if e.unit_offset == imported_at]
        self.assertEqual(outer[1].file_name, b'outer.c')
        inner_define = [e for e in inner if e.opcode_name == 'DW_MACRO_define'][0]
        self.assertIsNone(inner_define.file_name)
        self.assertIsNone(inner_define.file_index)
        self.assertEqual(inner_define.file.file_index, 1)
        self.assertIsNone(inner_define.file.name)


class TestMacroFileTable(_MacroTestCase):
    def test_missing_file_table_preserves_indices(self):
        body = _header(0) + _start_file(0, 7) + _define(b'A 1') + _TERM
        unit = self._info(body).iter_units()[0]
        self.assertTrue(unit.missing_file_table)
        start = unit.events[0]
        self.assertEqual(start.file_index, 7)
        self.assertIsNone(start.file_name)
        self.assertIsNone(unit.get_file(7))

    def test_pre_v5_line_table_is_one_based(self):
        # A DWARFv5 macro unit may point at a v4 line table, whose file numbers
        # start at 1 and reserve 0 for "no file".
        class LP:
            header = {
                'version': 4,
                'file_entry': [
                    {'name': b'main.c'},
                    {'name': b'inc.h'},
                ],
            }

        body = (_header(0x02, line_offset=0)
                + _start_file(0, 1)
                + _define(b'IN 1', 1)
                + _start_file(0, 0)
                + _define(b'NONE 2', 2)
                + _TERM)
        info = MacroInfo(_NoStrings(), io.BytesIO(body), len(body))
        info._line_programs[0] = LP()
        unit = info.get_unit(0)
        self.assertEqual(unit.events[1].file_name, b'main.c')
        self.assertEqual(unit.events[3].file_name, None)
        self.assertIsNone(unit.get_file(0))
        self.assertEqual(unit.get_file(1)['name'], b'main.c')

    def test_file_stack_returns_on_end_file(self):
        class LP:
            header = {
                'file_names': [
                    {'DW_LNCT_path': b'main.c'},
                    {'DW_LNCT_path': b'inc.h'},
                ]
            }

        body = (_header(0x02, line_offset=0)
                + _start_file(0, 0)
                + _start_file(1, 1)
                + _define(b'IN 1', 1)
                + _END_FILE
                + _define(b'OUT 2', 2)
                + _TERM)
        info = MacroInfo(_NoStrings(), io.BytesIO(body), len(body))
        info._line_programs[0] = LP()
        unit = info.get_unit(0)
        self.assertFalse(unit.missing_file_table)
        self.assertEqual(unit.file_names, [b'main.c', b'inc.h'])
        self.assertEqual(unit.events[2].file_name, b'inc.h')
        self.assertEqual(unit.events[4].file_name, b'main.c')


class TestMacroFixture(_MacroTestCase):
    """End-to-end checks on a real DWARFv5 object with .debug_macro."""

    def test_section_is_discovered_and_bound_to_cu(self):
        with open(os.path.join('test', 'testfiles_for_unittests',
                               'dwarf_macro.o.elf'), 'rb') as f:
            elf = ELFFile(f)
            dwarf = elf.get_dwarf_info()
            self.assertTrue(dwarf.has_macro_info())
            cu = next(dwarf.iter_CUs())
            top = cu.get_top_DIE()
            self.assertIn('DW_AT_macros', top.attributes)
            self.assertIsNotNone(dwarf.get_macro_info(cu))
            self.assertIsNotNone(dwarf.get_macro_unit(cu))
            no_attr = type('CU', (), {
                'get_top_DIE': lambda self: type('D', (), {'attributes': {}})()
            })()
            self.assertIsNone(dwarf.get_macro_unit(no_attr))

    def test_definition_events_carry_file_and_line(self):
        with open(os.path.join('test', 'testfiles_for_unittests',
                               'dwarf_macro.o.elf'), 'rb') as f:
            elf = ELFFile(f)
            dwarf = elf.get_dwarf_info()
            cu = next(dwarf.iter_CUs())
            unit = dwarf.get_macro_info(cu).iter_units()[0]
            self.assertFalse(unit.missing_file_table)
            self.assertFalse(unit.truncated)
            defs = unit.definitions()
            self.assertEqual(defs[0].name, b'OUTER')
            self.assertEqual(defs[0].state, 'defined')
            self.assertEqual(defs[0].line, 1)
            self.assertEqual(defs[0].file.name, b'mfix.c')

            inner = [d for d in defs if d.name == b'INNER']
            self.assertEqual([d.state for d in inner],
                             ['defined', 'undefined', 'defined'])
            self.assertEqual([d.line for d in inner], [1, 2, 3])
            self.assertEqual({d.file.name for d in inner}, {b'mfix.h'})

            outer = [d for d in defs if d.name == b'OUTER']
            self.assertEqual([d.state for d in outer],
                             ['defined', 'undefined', 'defined'])

    def test_definitions_are_events_not_code_ranges(self):
        """Definitions are directives, not statements about machine code.

        The reader reports no address or range for a definition, so a caller
        cannot mistake a declaration for proof that a code span was compiled
        under it.
        """
        from elftools.dwarf.macinfo import MacroDefinition
        fields = MacroDefinition.__dataclass_fields__
        self.assertNotIn('address', fields)
        self.assertNotIn('low_pc', fields)
        self.assertNotIn('high_pc', fields)
        with open(os.path.join('test', 'testfiles_for_unittests',
                               'dwarf_macro.o.elf'), 'rb') as f:
            elf = ELFFile(f)
            dwarf = elf.get_dwarf_info()
            cu = next(dwarf.iter_CUs())
            events = dwarf.get_macro_info(cu).iter_units()[0].events
            for event in events:
                self.assertFalse(hasattr(event, 'address'))


if __name__ == '__main__':
    unittest.main()
