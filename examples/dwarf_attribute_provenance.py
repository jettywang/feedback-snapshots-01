#-------------------------------------------------------------------------------
# elftools example: dwarf_attribute_provenance.py
#
# Show where the effective name, type, and declaration coordinates of an
# inlined function come from: a direct attribute, DW_AT_abstract_origin, or
# DW_AT_specification. Unresolved reference graphs are printed explicitly.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import sys

from elftools.common.utils import bytes2str
from elftools.elf.elffile import ELFFile


ATTRIBUTES = (
    'DW_AT_name',
    'DW_AT_linkage_name',
    'DW_AT_type',
    'DW_AT_decl_file',
    'DW_AT_decl_line',
    'DW_AT_decl_column',
)


def describe_value(value):
    if isinstance(value, bytes):
        return bytes2str(value)
    return str(value)


def process_file(filename):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        if not elffile.has_dwarf_info(strict=True):
            print('  file has no DWARF info')
            return

        dwarfinfo = elffile.get_dwarf_info()
        for cu in dwarfinfo.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != 'DW_TAG_inlined_subroutine':
                    continue
                print(f'  inlined subroutine at {die.offset:#x}')
                for name in ATTRIBUTES:
                    result = die.get_attribute_provenance(name)
                    if result.status == 'missing':
                        continue
                    if result.is_resolved:
                        print(f'    {name}: {describe_value(result.value)} '
                              f'({result.status})')
                    else:
                        print(f'    {name}: unresolved ({result.status})')
                    for link in result.chain:
                        target = link.target
                        target_text = (
                            f'{target.unit.kind} 0x{target.unit.unit_offset:x} '
                            f'DIE 0x{target.offset:x}'
                            if target is not None else '<unresolved>')
                        supplementary = (
                            ', supplementary' if
                            target is not None and target.is_supplementary
                            else '')
                        print(f'      via {link.attribute} [{link.form}] '
                              f'-> {target_text}{supplementary}')
                    if result.status in ('broken_reference', 'cycle', 'conflict'):
                        print(f'      reason: {result.reason}')


if __name__ == '__main__':
    filenames = sys.argv[1:]
    if filenames[:1] == ['--test']:
        filenames = filenames[1:]
    if not filenames:
        sys.exit(f'Usage: {sys.argv[0]} <elf-file> [...]')
    for filename in filenames:
        process_file(filename)
