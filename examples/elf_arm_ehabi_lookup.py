#-------------------------------------------------------------------------------
# elftools example: elf_arm_ehabi_lookup.py
#
# Resolve ARM instruction addresses to .ARM.exidx unwind entries and evaluate
# the restricted compact bytecode against caller-provided registers and memory.
#
# Registers and memory are supplied by the caller. Nothing is read from the
# host process, and a personality routine found in the sample is never called.
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
#-------------------------------------------------------------------------------
import sys

from elftools.elf.elffile import ELFFile


def process_file(filename, addresses):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        elf = ELFFile(f)
        if not elf.has_ehabi_info():
            print('  No .ARM.exidx section')
            return

        for info in elf.get_ehabi_infos():
            section = info.section_name()
            print(f'  Unwind section {section!r} at 0x{info.section_offset():x} '
                  f'with {info.num_entry()} entries')
            if info.trailing_bytes:
                print(f'  Trailing bytes not forming an entry: '
                      f'{info.trailing_bytes}')

            for address in addresses:
                lookup = info.lookup_address(address)
                print(f'  Address 0x{address:x}: {lookup.status} '
                      f'({lookup.reason})')
                if lookup.entry is None:
                    continue

                entry = lookup.entry
                print(f'    Entry index:       {lookup.entry_index}')
                if lookup.function_end is not None:
                    print(f'    Function range:    '
                          f'0x{lookup.function_start:x}..0x{lookup.function_end:x}')
                else:
                    print(f'    Function start:    0x{lookup.function_start:x}')
                print(f'    Personality:       {entry.personality}')
                print(f'    Table unwindable:  {entry.unwindable}')

                for instruction in entry.instructions() or []:
                    print(f'    Bytecode:          {instruction.mnemonic}')

                # A simulated caller stack: VSP and 64 bytes of memory. This
                # is illustrative input, not a recovered process stack.
                registers = {'sp': 0x10000, 'r7': 0x10000}
                memory = _zeros(0x10000, 64)
                result = info.unwind_by_address(address, registers, memory)
                print(f'    Evaluation:        {result.status} '
                      f'({result.reason})')
                if result.final_vsp is None:
                    print('    VSP:               unknown')
                else:
                    print(f'    VSP:               0x{result.initial_vsp:x} -> '
                          f'0x{result.final_vsp:x}')
                print(f'    Definite:          {result.definite}')
                if result.missing:
                    for item in result.missing:
                        print(f'    Missing input:     {item}')


def _zeros(base, size):
    class _ZeroMemory:
        def read_word(self, address):
            if base <= address and address + 4 <= base + size:
                return 0
            return None

    return _ZeroMemory()


if __name__ == '__main__':
    args = sys.argv[1:]
    if args and args[0] == '--test':
        args = args[1:]
    if not args:
        print('usage: elf_arm_ehabi_lookup.py [--test] <elffile> [address ...]')
        sys.exit(1)
    process_file(args[0], [int(a, 0) for a in args[1:]])
