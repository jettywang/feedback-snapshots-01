#------------------------------------------------------------------------------
# elftools tests
#
# Cross-version regression for DWARF type units reached through
# DW_FORM_ref_sig8. The point of this test is to prove that the type DIE
# returned for a signature really is the type identified by that signature -
# the DIE named by the type unit header's type_offset field - and not merely
# whatever DIE happens to sit at the same numeric offset in some unit.
#
# The debug sections are synthesized byte-by-byte rather than read from a
# compiler artifact, so that the exact unit/type-DIE layout is under the
# test's control. An independent layout table (see LAYOUT) records, for each
# signature, which unit owns it and the name/size of the type DIE it must
# resolve to; the parser is then checked against that table.
#
# Coverage:
#   * DWARF v4 type units in .debug_types, several of them in one section,
#     including two types that share a name but carry different signatures.
#   * DWARF v5 type units (DW_UT_type) living in .debug_info.
#   * References resolved both directly via get_DIE_by_sig8 and end-to-end
#     through a DW_AT_type attribute encoded as DW_FORM_ref_sig8.
#   * Missing signatures and unsupported reference forms being reported.
#   * Duplicate signatures being rejected instead of overwritten by load
#     order.
#   * Interleaved, repeated queries keeping type identity and field layout.
#   * A check that resolver variants which mistake the unit header offset
#     (or the unit's first DIE) for the type DIE offset fail this test.
#
# This code is in the public domain.
#------------------------------------------------------------------------------
import io
import struct
import unittest

from elftools.common.exceptions import DWARFError
from elftools.dwarf.dwarfinfo import (
    DebugSectionDescriptor,
    DwarfConfig,
    DWARFInfo,
)

# DWARF tags
DW_TAG_compile_unit = 0x11
DW_TAG_structure_type = 0x13
DW_TAG_variable = 0x34
DW_TAG_type_unit = 0x41

# DWARF attributes
DW_AT_name = 0x03
DW_AT_byte_size = 0x0B
DW_AT_type = 0x49

# DWARF forms
DW_FORM_string = 0x08
DW_FORM_data1 = 0x0B
DW_FORM_ref_sig8 = 0x20
DW_FORM_ref_sup4 = 0x1C

# children flag
DW_CHILDREN_no = 0x00
DW_CHILDREN_yes = 0x01

# DWARF v5 unit types
DW_UT_compile = 0x01
DW_UT_type = 0x02

# Signatures used by the synthesized sections.
SIG_A = 0xA0A0A0A0A0A0A0A0
SIG_B = 0xB0B0B0B0B0B0B0B0
SIG_C = 0xC0C0C0C0C0C0C0C0
SIG_MISSING = 0x0123456789ABCDEF

# Shared abbreviation table codes, stable across every unit so that one
# .debug_abbrev section can back all of them. The table itself is built by
# _build_abbrev:
#   1: DW_TAG_type_unit, children, no attributes
#   2: DW_TAG_structure_type, no children, name + byte_size
#   3: DW_TAG_variable, no children, DW_AT_type as DW_FORM_ref_sig8
#   4: DW_TAG_compile_unit, children, no attributes
#   5: DW_TAG_variable, no children, DW_AT_type as DW_FORM_ref_sup4


def _uleb128(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _build_abbrev():
    entries = [
        (1, DW_TAG_type_unit, DW_CHILDREN_yes, ()),
        (2, DW_TAG_structure_type, DW_CHILDREN_no,
            ((DW_AT_name, DW_FORM_string),
             (DW_AT_byte_size, DW_FORM_data1))),
        (3, DW_TAG_variable, DW_CHILDREN_no,
            ((DW_AT_type, DW_FORM_ref_sig8),)),
        (4, DW_TAG_compile_unit, DW_CHILDREN_yes, ()),
        (5, DW_TAG_variable, DW_CHILDREN_no,
            ((DW_AT_type, DW_FORM_ref_sup4),)),
    ]
    out = bytearray()
    for code, tag, has_children, specs in entries:
        out += _uleb128(code) + _uleb128(tag) + bytes([has_children])
        for attr, form in specs:
            out += _uleb128(attr) + _uleb128(form)
        out += b'\x00\x00'
    out += b'\x00'  # end of abbreviation table
    return bytes(out)


# --- DIE builders -----------------------------------------------------------

def _die(abbrev_code, *payload):
    return _uleb128(abbrev_code) + b''.join(payload)


def _structure_die(name, byte_size):
    return _die(2, name.encode('ascii') + b'\x00', bytes([byte_size]))


def _sig8_variable_die(signature):
    return _die(3, struct.pack('<Q', signature))


def _sup4_variable_die(reference):
    return _die(5, struct.pack('<I', reference))


def _null_die():
    return b'\x00'


# --- unit builders (32-bit DWARF, little endian) ----------------------------

# Size of a DWARF v4 .debug_types unit header, including the 4-byte initial
# length: initial_length(4) + version(2) + debug_abbrev_offset(4) +
# address_size(1) + signature(8) + type_offset(4).
V4_TU_HEADER_SIZE = 4 + 2 + 4 + 1 + 8 + 4

# Size of a DWARF v5 type unit header, including the initial length:
# initial_length(4) + version(2) + unit_type(1) + address_size(1) +
# debug_abbrev_offset(4) + type_signature(8) + type_offset(4).
V5_TU_HEADER_SIZE = 4 + 2 + 1 + 1 + 4 + 8 + 4


def _wrap_unit(body):
    """Prepend the 32-bit DWARF initial length to a unit body."""
    return struct.pack('<I', len(body)) + body


def _build_v4_type_unit(signature, type_name, byte_size):
    """Build one DWARF v4 .debug_types unit.

    Returns (unit_bytes, type_offset). The v4 type_offset field is
    section-relative, so when the unit is not placed at the start of
    .debug_types the caller must rebase it via _rebase_v4_type_offset.
    """
    top_die = _die(1)
    type_die = _structure_die(type_name, byte_size)
    type_offset = V4_TU_HEADER_SIZE + len(top_die)  # section-relative base
    body = (
        struct.pack('<H', 4) +            # version
        struct.pack('<I', 0) +            # debug_abbrev_offset
        struct.pack('<B', 8) +            # address_size
        struct.pack('<Q', signature) +    # signature
        struct.pack('<I', type_offset) +  # type_offset (patched per unit)
        top_die + type_die + _null_die()
    )
    return _wrap_unit(body), type_offset


def _build_v5_type_unit(signature, type_name, byte_size):
    """Build one DWARF v5 DW_UT_type unit (stored in .debug_info)."""
    top_die = _die(1)
    type_die = _structure_die(type_name, byte_size)
    # In v5 type_offset is relative to the start of the unit header.
    type_offset = V5_TU_HEADER_SIZE + len(top_die)
    body = (
        struct.pack('<H', 5) +                 # version
        bytes([DW_UT_type]) +                  # unit_type
        bytes([8]) +                           # address_size
        struct.pack('<I', 0) +                 # debug_abbrev_offset
        struct.pack('<Q', signature) +         # type_signature
        struct.pack('<I', type_offset) +       # type_offset (unit-relative)
        top_die + type_die + _null_die()
    )
    return _wrap_unit(body), type_offset


def _build_v5_compile_unit(dies):
    body = (
        struct.pack('<H', 5) +                 # version
        bytes([DW_UT_compile]) +               # unit_type
        bytes([8]) +                           # address_size
        struct.pack('<I', 0) +                 # debug_abbrev_offset
        dies
    )
    return _wrap_unit(body)


def _build_v4_compile_unit(dies):
    body = (
        struct.pack('<H', 4) +                 # version
        struct.pack('<I', 0) +                 # debug_abbrev_offset
        struct.pack('<B', 8) +                 # address_size
        dies
    )
    return _wrap_unit(body)


def _make_dwarfinfo(debug_info=b'', debug_types=b''):
    abbrev = _build_abbrev()
    sections = dict(
        config=DwarfConfig(
            little_endian=True,
            default_address_size=8,
            machine_arch='x64'),
        debug_info_sec=DebugSectionDescriptor(
            io.BytesIO(debug_info), '.debug_info', None,
            len(debug_info), 0) if debug_info else None,
        debug_abbrev_sec=DebugSectionDescriptor(
            io.BytesIO(abbrev), '.debug_abbrev', None, len(abbrev), 0),
        debug_types_sec=DebugSectionDescriptor(
            io.BytesIO(debug_types), '.debug_types', None,
            len(debug_types), 0) if debug_types else None,
    )
    for name in (
            'debug_aranges_sec', 'debug_frame_sec', 'eh_frame_sec',
            'debug_str_sec', 'debug_loc_sec', 'debug_ranges_sec',
            'debug_line_sec', 'debug_pubtypes_sec', 'debug_pubnames_sec',
            'debug_addr_sec', 'debug_str_offsets_sec',
            'debug_line_str_sec', 'debug_loclists_sec',
            'debug_rnglists_sec', 'debug_sup_sec',
            'gnu_debugaltlink_sec'):
        sections[name] = None
    return DWARFInfo(**sections)


class TestTypeUnitRefSig8(unittest.TestCase):
    def setUp(self):
        # ---- DWARF v4 .debug_types: two units, same type name, different
        # signatures and distinct layouts (16 vs 32 byte structures).
        tu_a, _ = _build_v4_type_unit(SIG_A, 'Shared', 16)
        tu_b, _ = _build_v4_type_unit(SIG_B, 'Shared', 32)

        # v4 type_offset is section-relative: offset the second unit's value
        # by the position of its unit in the section.
        tu_b = self._rebase_v4_type_offset(tu_b, len(tu_a))

        self.debug_types = tu_a + tu_b

        # ---- DWARF v5 .debug_info: a type unit plus a compile unit that
        # references it through a DW_FORM_ref_sig8 attribute.
        v5_tu, _ = _build_v5_type_unit(SIG_C, 'V5Type', 24)
        v5_cu = _build_v5_compile_unit(
            _die(4) + _sig8_variable_die(SIG_C) + _null_die())
        self.debug_info_v5 = v5_tu + v5_cu

        # A v4 compile unit that references SIG_A and a missing signature.
        self.debug_info_v4_refs = _build_v4_compile_unit(
            _die(4) +
            _sig8_variable_die(SIG_A) +
            _sig8_variable_die(SIG_MISSING) +
            _null_die())

        # Independent layout table: what each signature must resolve to.
        # `section` records where the owning unit lives; `name`/`byte_size`
        # are the field layout the resolved type DIE must carry.
        self.layout = {
            SIG_A: dict(section='debug_types', name=b'Shared', byte_size=16),
            SIG_B: dict(section='debug_types', name=b'Shared', byte_size=32),
            SIG_C: dict(section='debug_info', name=b'V5Type', byte_size=24),
        }

    @staticmethod
    def _rebase_v4_type_offset(unit_bytes, unit_position):
        """Rewrite a v4 unit's type_offset to be section-relative given the
            unit's position in .debug_types.
        """
        # type_offset is the last 4 bytes of the fixed header (offset 19..22).
        offset_field = V4_TU_HEADER_SIZE - 4
        current = struct.unpack_from('<I', unit_bytes, offset_field)[0]
        rebased = current + unit_position
        patched = bytearray(unit_bytes)
        struct.pack_into('<I', patched, offset_field, rebased)
        return bytes(patched)

    def _check_layout_table(self, dwarfinfo, signatures=None):
        """Resolve each given signature and verify the type DIE against the
            independent layout table. Defaults to every signature the object
            is expected to contain.
        """
        if signatures is None:
            signatures = self.layout
        for signature in signatures:
            expected = self.layout[signature]
            die = dwarfinfo.get_DIE_by_sig8(signature)
            self.assertEqual(die.tag, 'DW_TAG_structure_type')
            self.assertEqual(
                die.attributes['DW_AT_name'].value, expected['name'])
            self.assertEqual(
                die.attributes['DW_AT_byte_size'].value,
                expected['byte_size'])
            # The owning unit really belongs to the expected section.
            unit = dwarfinfo.get_TU_by_sig8(signature)
            self.assertIs(die.cu, unit)
            if expected['section'] == 'debug_types':
                self.assertTrue(hasattr(unit, 'tu_offset'))
            else:
                self.assertFalse(hasattr(unit, 'tu_offset'))

    def test_dwarf4_type_units_resolve_to_real_type_dies(self):
        dwarfinfo = _make_dwarfinfo(debug_types=self.debug_types)
        self.assertEqual(len(list(dwarfinfo.iter_TUs())), 2)
        self._check_layout_table(dwarfinfo, (SIG_A, SIG_B))

        # Both type DIEs sit at the SAME unit-relative offset, which is the
        # trap this regression guards against: a lookup keyed on the offset
        # alone could not tell them apart.
        die_a = dwarfinfo.get_DIE_by_sig8(SIG_A)
        die_b = dwarfinfo.get_DIE_by_sig8(SIG_B)
        unit_a = dwarfinfo.get_TU_by_sig8(SIG_A)
        unit_b = dwarfinfo.get_TU_by_sig8(SIG_B)
        self.assertEqual(
            die_a.offset - unit_a.cu_offset,
            die_b.offset - unit_b.cu_offset)
        # Yet the signatures resolve to distinct, correctly laid-out DIEs.
        self.assertNotEqual(die_a.offset, die_b.offset)
        self.assertNotEqual(
            die_a.attributes['DW_AT_byte_size'].value,
            die_b.attributes['DW_AT_byte_size'].value)

    def test_dwarf5_type_unit_in_debug_info(self):
        dwarfinfo = _make_dwarfinfo(debug_info=self.debug_info_v5)
        self._check_layout_table(dwarfinfo, (SIG_C,))

        # The first unit in .debug_info is the type unit, the second is the
        # compile unit that references it.
        units = list(dwarfinfo.iter_CUs())
        self.assertEqual(units[0].header['unit_type'], 'DW_UT_type')
        self.assertEqual(units[1].header['unit_type'], 'DW_UT_compile')

        # End-to-end: DW_AT_type in DW_FORM_ref_sig8 form reaches the type.
        variable = next(units[1].get_top_DIE().iter_children())
        self.assertEqual(
            variable.attributes['DW_AT_type'].form, 'DW_FORM_ref_sig8')
        referenced = variable.get_DIE_from_attribute('DW_AT_type')
        self.assertIs(referenced, dwarfinfo.get_DIE_by_sig8(SIG_C))
        self.assertEqual(
            referenced.attributes['DW_AT_name'].value, b'V5Type')

    def test_cross_version_lookup_in_one_object(self):
        dwarfinfo = _make_dwarfinfo(
            debug_info=self.debug_info_v5,
            debug_types=self.debug_types)
        # v4 (.debug_types) and v5 (.debug_info) signatures coexist and each
        # resolves to its own type DIE.
        self._check_layout_table(dwarfinfo)
        self.assertIsNotNone(dwarfinfo.get_TU_by_sig8(SIG_A))
        self.assertIsNotNone(dwarfinfo.get_TU_by_sig8(SIG_C))

    def test_end_to_end_sig8_reference_in_dwarf4_cu(self):
        dwarfinfo = _make_dwarfinfo(
            debug_info=self.debug_info_v4_refs,
            debug_types=self.debug_types)
        cu = next(dwarfinfo.iter_CUs())
        variables = list(cu.get_top_DIE().iter_children())
        self.assertEqual(len(variables), 2)

        # First variable points at SIG_A and resolves to the real type DIE.
        resolved = variables[0].get_DIE_from_attribute('DW_AT_type')
        self.assertIs(resolved, dwarfinfo.get_DIE_by_sig8(SIG_A))
        self.assertEqual(
            resolved.attributes['DW_AT_name'].value, b'Shared')
        self.assertEqual(
            resolved.attributes['DW_AT_byte_size'].value, 16)

        # Second variable names a signature that no type unit carries.
        with self.assertRaises(KeyError):
            variables[1].get_DIE_from_attribute('DW_AT_type')

    def test_missing_signature_is_reported(self):
        dwarfinfo = _make_dwarfinfo(
            debug_info=self.debug_info_v5,
            debug_types=self.debug_types)
        with self.assertRaises(KeyError):
            dwarfinfo.get_DIE_by_sig8(SIG_MISSING)
        with self.assertRaises(KeyError):
            dwarfinfo.get_TU_by_sig8(SIG_MISSING)

    def test_duplicate_signature_is_rejected_not_overwritten(self):
        # Two v4 type units claiming the same signature. If the index simply
        # assigned by load order, the second would silently replace the first.
        first, _ = _build_v4_type_unit(SIG_A, 'Shared', 16)
        second, _ = _build_v4_type_unit(SIG_A, 'Other', 8)
        second = self._rebase_v4_type_offset(second, len(first))
        dwarfinfo = _make_dwarfinfo(debug_types=first + second)

        with self.assertRaises(DWARFError):
            dwarfinfo.get_DIE_by_sig8(SIG_A)
        # The conflict is also visible when indexing explicitly.
        with self.assertRaises(DWARFError):
            _ = dwarfinfo._type_units_by_sig

    def test_duplicate_dwarf5_signature_is_rejected(self):
        # Same guard on the DWARF v5 path: two DW_UT_type units in
        # .debug_info claiming one signature must be reported, not merged by
        # load order.
        first, _ = _build_v5_type_unit(SIG_C, 'V5Type', 24)
        second, _ = _build_v5_type_unit(SIG_C, 'Other', 4)
        dwarfinfo = _make_dwarfinfo(debug_info=first + second)
        with self.assertRaises(DWARFError):
            dwarfinfo.get_DIE_by_sig8(SIG_C)

    def test_unsupported_reference_form_is_reported(self):
        # DW_FORM_ref_sup4 needs supplementary DWARF info, which is not
        # loaded here; the unsupported form must be reported explicitly.
        debug_info = _build_v4_compile_unit(
            _die(4) + _sup4_variable_die(0x10) + _null_die())
        dwarfinfo = _make_dwarfinfo(debug_info=debug_info)
        variable = next(next(dwarfinfo.iter_CUs())
                        .get_top_DIE().iter_children())
        self.assertEqual(
            variable.attributes['DW_AT_type'].form, 'DW_FORM_ref_sup4')
        with self.assertRaises(NotImplementedError):
            variable.get_DIE_from_attribute('DW_AT_type')

    def test_interleaved_repeated_queries_keep_identity_and_layout(self):
        dwarfinfo = _make_dwarfinfo(
            debug_info=self.debug_info_v5,
            debug_types=self.debug_types)
        order = [SIG_C, SIG_A, SIG_B, SIG_A, SIG_C, SIG_B, SIG_A, SIG_C]

        seen_die = {}
        seen_layout = {}
        for signature in order:
            die = dwarfinfo.get_DIE_by_sig8(signature)
            layout = (
                die.offset,
                die.attributes['DW_AT_name'].value,
                die.attributes['DW_AT_byte_size'].value,
            )
            if signature in seen_die:
                self.assertIs(seen_die[signature], die)
                self.assertEqual(seen_layout[signature], layout)
            else:
                seen_die[signature] = die
                seen_layout[signature] = layout

            # Interleave unit-level and DIE-level access across sections.
            unit = dwarfinfo.get_TU_by_sig8(signature)
            self.assertIs(die.cu, unit)

        # Every recorded layout still matches the independent table.
        for signature, expected in self.layout.items():
            self.assertEqual(
                seen_layout[signature][1], expected['name'])
            self.assertEqual(
                seen_layout[signature][2], expected['byte_size'])

    def test_unit_header_offset_is_not_a_valid_type_offset(self):
        # Regression guard: a resolver that treats the unit header offset (or
        # the unit's first DIE) as the type DIE offset must fail the layout
        # table. The correct resolver is the library under test.
        dwarfinfo = _make_dwarfinfo(
            debug_info=self.debug_info_v5,
            debug_types=self.debug_types)

        def correct(signature):
            return dwarfinfo.get_DIE_by_sig8(signature)

        def buggy_header_offset(signature):
            unit = dwarfinfo._type_units_by_sig[signature]
            return unit._get_cached_DIE(unit.cu_offset)

        def buggy_first_die(signature):
            unit = dwarfinfo._type_units_by_sig[signature]
            return unit._get_cached_DIE(unit.cu_die_offset)

        def matches_layout(resolver, signature):
            expected = self.layout[signature]
            try:
                die = resolver(signature)
            except Exception:
                return False
            return (
                die.tag == 'DW_TAG_structure_type' and
                die.attributes['DW_AT_name'].value == expected['name'] and
                die.attributes['DW_AT_byte_size'].value ==
                expected['byte_size'])

        signatures = list(self.layout)
        # The real resolver satisfies every layout entry.
        self.assertTrue(
            all(matches_layout(correct, sig) for sig in signatures))
        # Each buggy resolver must be rejected by at least one entry; in
        # practice all of them reject it.
        for buggy in (buggy_header_offset, buggy_first_die):
            self.assertFalse(
                all(matches_layout(buggy, sig) for sig in signatures))


if __name__ == '__main__':
    unittest.main()
