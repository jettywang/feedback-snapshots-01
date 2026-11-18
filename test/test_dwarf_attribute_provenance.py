#-------------------------------------------------------------------------------
# elftools tests
#
# Tests for explicit DWARF attribute provenance through abstract-origin and
# specification chains.
#-------------------------------------------------------------------------------
import os
import unittest
from types import SimpleNamespace

from elftools.dwarf.die import AttributeValue
from elftools.dwarf.provenance import (
    DIEProvenanceResolver,
    ProvenanceStatus,
    resolve_attribute,
)
from elftools.elf.elffile import ELFFile


class _FakeDIE:
    """A tiny DIE graph used to exercise resolution without a binary."""

    def __init__(self, offset, tag, attributes, cu):
        self.offset = offset
        self.tag = tag
        self.attributes = attributes
        self.cu = cu
        self.dwarfinfo = cu.dwarfinfo
        self._references = {}

    def get_DIE_from_attribute(self, name):
        target = self._references[name]
        if isinstance(target, Exception):
            raise target
        return target


def _attr(name, value, form='DW_FORM_ref4'):
    return AttributeValue(
        name=name, form=form, value=value, raw_value=value,
        offset=0, indirection_length=0)


def _unit(offset, dwarfinfo=None):
    return SimpleNamespace(
        cu_offset=offset,
        dwarfinfo=dwarfinfo or SimpleNamespace(),
    )


def _die(offset, attributes, unit):
    return _FakeDIE(offset, 'DW_TAG_subprogram', attributes, unit)


def _link(die, name, target=None, error=None):
    die._references[name] = target if error is None else error
    if target is not None:
        die.attributes[name] = _attr(name, target.offset)
    else:
        die.attributes[name] = _attr(name, 0xdead)


class TestAttributeProvenance(unittest.TestCase):
    def resolve(self, die, name):
        return DIEProvenanceResolver(die.dwarfinfo).resolve(die, name)

    def test_direct_attribute_wins_and_reports_shadowed_branch(self):
        unit = _unit(0)
        origin = _die(0x20, {
            'DW_AT_name': _attr('DW_AT_name', 'inherited', 'DW_FORM_string')},
            unit)
        die = _die(0x40, {
            'DW_AT_name': _attr('DW_AT_name', 'direct', 'DW_FORM_string')},
            unit)
        _link(die, 'DW_AT_abstract_origin', origin)

        result = self.resolve(die, 'DW_AT_name')

        self.assertEqual(result.status, ProvenanceStatus.DIRECT)
        self.assertEqual(result.value, 'direct')
        self.assertEqual(result.chain, ())
        self.assertEqual(len(result.candidates), 1)
        shadowed = result.candidates[0]
        self.assertEqual(shadowed.status, ProvenanceStatus.INHERITED)
        self.assertEqual(shadowed.value, 'inherited')
        self.assertEqual(shadowed.chain[0].attribute, 'DW_AT_abstract_origin')

    def test_name_and_location_follow_different_chains(self):
        unit = _unit(0x100)
        declaration = _die(0x180, {
            'DW_AT_name': _attr('DW_AT_name', 'declared', 'DW_FORM_string'),
            'DW_AT_decl_file': _attr('DW_AT_decl_file', 7, 'DW_FORM_data1'),
            'DW_AT_decl_line': _attr('DW_AT_decl_line', 42, 'DW_FORM_data1'),
        }, unit)
        abstract = _die(0x140, {
            'DW_AT_decl_line': _attr('DW_AT_decl_line', 99, 'DW_FORM_data1'),
        }, unit)
        _link(abstract, 'DW_AT_specification', declaration)
        concrete = _die(0x1c0, {}, unit)
        _link(concrete, 'DW_AT_abstract_origin', abstract)

        name = self.resolve(concrete, 'DW_AT_name')
        line = self.resolve(concrete, 'DW_AT_decl_line')
        file = self.resolve(concrete, 'DW_AT_decl_file')

        self.assertEqual(name.value, 'declared')
        self.assertEqual(
            [link.attribute for link in name.chain],
            ['DW_AT_abstract_origin', 'DW_AT_specification'])
        self.assertEqual(line.value, 99)
        self.assertEqual(
            [link.attribute for link in line.chain],
            ['DW_AT_abstract_origin'])
        self.assertEqual(file.value, 7)
        self.assertEqual(
            [link.attribute for link in file.chain],
            ['DW_AT_abstract_origin', 'DW_AT_specification'])
        self.assertEqual(
            [candidate.status for candidate in name.candidates],
            [ProvenanceStatus.INHERITED])

    def test_chain_records_units_for_cross_unit_reference(self):
        primary = SimpleNamespace()
        origin_unit = _unit(0x1000, primary)
        concrete_unit = _unit(0x2000, primary)
        origin = _die(0x1040, {
            'DW_AT_name': _attr('DW_AT_name', 'inlined', 'DW_FORM_string')},
            origin_unit)
        concrete = _die(0x2080, {}, concrete_unit)
        _link(concrete, 'DW_AT_abstract_origin', origin)

        result = self.resolve(concrete, 'DW_AT_name')

        self.assertEqual(result.status, ProvenanceStatus.INHERITED)
        self.assertEqual(result.root.unit.unit_offset, 0x2000)
        self.assertEqual(result.source.unit.unit_offset, 0x1000)
        link = result.chain[0]
        self.assertEqual(link.source.unit.unit_offset, 0x2000)
        self.assertEqual(link.target.unit.unit_offset, 0x1000)
        self.assertEqual(link.form, 'DW_FORM_ref4')

    def test_supplementary_units_keep_separate_identity(self):
        primary = SimpleNamespace()
        supplementary = SimpleNamespace()
        primary.supplementary_dwarfinfo = supplementary
        root_unit = _unit(0x10, primary)
        supp_unit = _unit(0x10, supplementary)
        target = _die(0x20, {
            'DW_AT_name': _attr('DW_AT_name', 'shared', 'DW_FORM_string')},
            supp_unit)
        die = _die(0x30, {}, root_unit)
        _link(die, 'DW_AT_specification', target)

        result = DIEProvenanceResolver(primary).resolve(die, 'DW_AT_name')

        self.assertEqual(result.status, ProvenanceStatus.INHERITED)
        self.assertEqual(result.root.unit.unit_offset, 0x10)
        self.assertEqual(result.source.unit.unit_offset, 0x10)
        self.assertFalse(result.root.unit.is_supplementary)
        self.assertTrue(result.source.unit.is_supplementary)
        self.assertNotEqual(result.root.unit, result.source.unit)
        self.assertEqual(result.chain[0].target_unit, result.source.unit)

    def test_missing_attribute_is_not_fabricated(self):
        unit = _unit(0)
        origin = _die(0x20, {}, unit)
        die = _die(0x40, {}, unit)
        _link(die, 'DW_AT_abstract_origin', origin)

        result = self.resolve(die, 'DW_AT_type')

        self.assertEqual(result.status, ProvenanceStatus.MISSING)
        self.assertIsNone(result.value)
        self.assertIsNone(result.source)
        self.assertEqual(result.chain, ())
        self.assertEqual(len(result.candidates), 1)

    def test_broken_reference_is_reported_with_its_chain(self):
        unit = _unit(0)
        die = _die(0x40, {}, unit)
        _link(die, 'DW_AT_abstract_origin', error=ValueError('outside unit'))

        result = self.resolve(die, 'DW_AT_name')

        self.assertEqual(result.status, ProvenanceStatus.BROKEN_REFERENCE)
        self.assertIsNone(result.value)
        self.assertEqual(len(result.chain), 1)
        self.assertEqual(result.chain[0].target, None)
        self.assertIn('outside unit', result.reason)
        self.assertIn('outside unit', result.chain[0].error or '')

    def test_broken_branch_is_not_hidden_by_a_value_from_another_branch(self):
        unit = _unit(0)
        declaration = _die(0x80, {
            'DW_AT_name': _attr('DW_AT_name', 'well-formed', 'DW_FORM_string')},
            unit)
        abstract = _die(0x40, {}, unit)
        _link(abstract, 'DW_AT_specification', declaration)
        die = _die(0xc0, {}, unit)
        _link(die, 'DW_AT_abstract_origin', abstract)
        _link(die, 'DW_AT_specification', error=KeyError('bad form'))

        result = self.resolve(die, 'DW_AT_name')

        self.assertEqual(result.status, ProvenanceStatus.BROKEN_REFERENCE)
        self.assertIsNone(result.value)
        self.assertEqual(
            [candidate.status for candidate in result.candidates],
            [ProvenanceStatus.INHERITED,
             ProvenanceStatus.BROKEN_REFERENCE])

    def test_conflicting_inherited_values_are_unresolved(self):
        unit = _unit(0)
        abstract = _die(0x40, {
            'DW_AT_name': _attr('DW_AT_name', 'from-origin', 'DW_FORM_string')},
            unit)
        declaration = _die(0x80, {
            'DW_AT_name': _attr('DW_AT_name', 'from-spec', 'DW_FORM_string')},
            unit)
        die = _die(0xc0, {}, unit)
        _link(die, 'DW_AT_abstract_origin', abstract)
        _link(die, 'DW_AT_specification', declaration)

        result = self.resolve(die, 'DW_AT_name')

        self.assertEqual(result.status, ProvenanceStatus.CONFLICT)
        self.assertIsNone(result.value)
        self.assertEqual(len(result.candidates), 2)

    def test_self_cycle_is_reported_and_does_not_recurse(self):
        unit = _unit(0)
        die = _die(0x40, {}, unit)
        _link(die, 'DW_AT_abstract_origin', die)

        result = self.resolve(die, 'DW_AT_name')

        self.assertEqual(result.status, ProvenanceStatus.CYCLE)
        self.assertIsNone(result.value)
        self.assertEqual(len(result.chain), 1)
        self.assertEqual(result.chain[0].target.offset, 0x40)

    def test_two_die_cycle_keeps_the_repeated_link(self):
        unit = _unit(0)
        first = _die(0x40, {}, unit)
        second = _die(0x80, {}, unit)
        _link(first, 'DW_AT_abstract_origin', second)
        _link(second, 'DW_AT_specification', first)

        result = self.resolve(first, 'DW_AT_type')

        self.assertEqual(result.status, ProvenanceStatus.CYCLE)
        self.assertEqual(
            [link.attribute for link in result.chain],
            ['DW_AT_abstract_origin', 'DW_AT_specification'])
        self.assertEqual(result.chain[-1].target.offset, 0x40)

    def test_resolving_does_not_modify_die_attributes(self):
        unit = _unit(0)
        origin = _die(0x20, {
            'DW_AT_name': _attr('DW_AT_name', 'origin', 'DW_FORM_string')},
            unit)
        die = _die(0x40, {}, unit)
        _link(die, 'DW_AT_abstract_origin', origin)
        before = dict(die.attributes)

        result = self.resolve(die, 'DW_AT_name')

        self.assertEqual(result.value, 'origin')
        self.assertEqual(die.attributes, before)
        self.assertNotIn('DW_AT_name', die.attributes)

    def test_resolve_many_includes_all_reachable_names(self):
        unit = _unit(0)
        declaration = _die(0x80, {
            'DW_AT_type': _attr('DW_AT_type', 0x999),
            'DW_AT_decl_line': _attr('DW_AT_decl_line', 3),
        }, unit)
        abstract = _die(0x40, {
            'DW_AT_name': _attr('DW_AT_name', 'abstract', 'DW_FORM_string')},
            unit)
        _link(abstract, 'DW_AT_specification', declaration)
        die = _die(0xc0, {
            'DW_AT_low_pc': _attr('DW_AT_low_pc', 0x1000, 'DW_FORM_addr')},
            unit)
        _link(die, 'DW_AT_abstract_origin', abstract)

        results = DIEProvenanceResolver(unit.dwarfinfo).resolve_many(die)

        self.assertEqual(
            set(results), {'DW_AT_low_pc', 'DW_AT_name',
                           'DW_AT_type', 'DW_AT_decl_line'})
        self.assertEqual(results['DW_AT_name'].value, 'abstract')
        self.assertEqual(results['DW_AT_decl_line'].value, 3)
        self.assertEqual(results['DW_AT_type'].status,
                         ProvenanceStatus.INHERITED)

    def test_unit_labels_distinguish_supplementary_identity(self):
        primary = SimpleNamespace()
        supplementary = SimpleNamespace()
        primary.supplementary_dwarfinfo = supplementary
        root = DIEProvenanceResolver(primary).identify(
            _die(0x10, {}, _unit(0x20, primary)))
        other = DIEProvenanceResolver(primary).identify(
            _die(0x10, {}, _unit(0x20, supplementary)))

        self.assertIn('.debug_info', root.label)
        self.assertIn('supplementary', other.label)
        self.assertNotEqual(root.label, other.label)
        self.assertNotEqual(root.unit.identity, other.unit.identity)

    def test_result_origin_helpers(self):
        unit = _unit(0)
        origin = _die(0x20, {
            'DW_AT_name': _attr('DW_AT_name', 'origin', 'DW_FORM_string')},
            unit)
        die = _die(0x40, {
            'DW_AT_decl_line': _attr('DW_AT_decl_line', 5)},
            unit)
        _link(die, 'DW_AT_abstract_origin', origin)

        inherited = self.resolve(die, 'DW_AT_name')
        direct = self.resolve(die, 'DW_AT_decl_line')
        missing = self.resolve(die, 'DW_AT_type')

        self.assertEqual(inherited.origin, 'DW_AT_abstract_origin')
        self.assertEqual(inherited.source_kind, 'abstract_origin')
        self.assertEqual(direct.origin, 'direct')
        self.assertEqual(missing.origin, 'missing')
        self.assertTrue(missing.has_unresolved_branches)

    def test_shadowed_unresolved_branch_remains_visible(self):
        unit = _unit(0)
        die = _die(0x40, {
            'DW_AT_name': _attr('DW_AT_name', 'direct', 'DW_FORM_string')},
            unit)
        _link(die, 'DW_AT_abstract_origin', error=ValueError('gone'))

        result = self.resolve(die, 'DW_AT_name')

        self.assertEqual(result.status, ProvenanceStatus.DIRECT)
        self.assertTrue(result.has_unresolved_branches)
        self.assertEqual(
            [failure.status for failure in result.unresolved_candidates],
            [ProvenanceStatus.BROKEN_REFERENCE])

    def test_helper_functions_match_method_result(self):
        unit = _unit(0)
        origin = _die(0x20, {
            'DW_AT_name': _attr('DW_AT_name', 'helper', 'DW_FORM_string')},
            unit)
        die = _die(0x40, {}, unit)
        _link(die, 'DW_AT_abstract_origin', origin)

        result = resolve_attribute(die, 'DW_AT_name')

        self.assertEqual(result.status, ProvenanceStatus.INHERITED)
        self.assertEqual(result.value, 'helper')


class TestAttributeProvenanceOnRealDWARF(unittest.TestCase):
    def test_cross_cu_abstract_origin(self):
        path = os.path.join(
            'test', 'testfiles_for_unittests', 'note_tc3xxx_blinky.elf')
        with open(path, 'rb') as f:
            dwarfinfo = ELFFile(f).get_dwarf_info(follow_links=False)
            die = dwarfinfo.get_CU_containing(0x1ab288).get_DIE_from_refaddr(
                0x1ab288)

            result = dwarfinfo.get_attribute_provenance(die, 'DW_AT_name')

            self.assertEqual(result.status, ProvenanceStatus.INHERITED)
            self.assertEqual(result.chain[0].attribute, 'DW_AT_abstract_origin')
            self.assertEqual(result.chain[0].form, 'DW_FORM_ref_addr')
            self.assertEqual(result.root.unit.unit_offset, 0x1ab144)
            self.assertEqual(result.source.unit.unit_offset, 0x12c90f)
            self.assertNotEqual(result.root.unit, result.source.unit)

    def test_abstract_origin_then_specification(self):
        path = os.path.join(
            'test', 'testfiles_for_unittests', 'arm_exidx_test.so.elf')
        with open(path, 'rb') as f:
            dwarfinfo = ELFFile(f).get_dwarf_info(follow_links=False)
            die = dwarfinfo.get_CU_containing(0x8356).get_DIE_from_refaddr(
                0x8356)

            result = die.get_attribute_provenance('DW_AT_name')

            self.assertEqual(result.status, ProvenanceStatus.INHERITED)
            self.assertEqual(
                [link.attribute for link in result.chain],
                ['DW_AT_abstract_origin', 'DW_AT_specification'])
            self.assertEqual(result.chain[0].source.offset, 0x8356)
            self.assertEqual(result.chain[0].target.offset, 0x8479)
            self.assertEqual(result.chain[1].target.offset, 0x7c09)

    def test_bound_supplementary_units_keep_container_identity(self):
        path = os.path.join(
            'test', 'testfiles_for_unittests', 'test_debugsup1.debug')
        with ELFFile.load_from_path(path) as elffile:
            dwarfinfo = elffile.get_dwarf_info()
            supplementary = dwarfinfo.supplementary_dwarfinfo
            self.assertIsNotNone(supplementary)
            self.assertIs(supplementary.primary_dwarfinfo, dwarfinfo)

            main_die = dwarfinfo.get_CU_containing(0x50).get_DIE_from_refaddr(
                0x50)
            supp_die = main_die.get_DIE_from_attribute('DW_AT_type')
            resolver = DIEProvenanceResolver(dwarfinfo)

            main = resolver.identify(main_die)
            supp = resolver.identify(supp_die)

            self.assertFalse(main.unit.is_supplementary)
            self.assertTrue(supp.unit.is_supplementary)
            self.assertNotEqual(main.unit, supp.unit)
            self.assertNotEqual(main.unit.container_id, supp.unit.container_id)
            self.assertEqual(supp.unit.unit_offset, supp_die.cu.cu_offset)


if __name__ == '__main__':
    unittest.main()
