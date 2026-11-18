#-------------------------------------------------------------------------------
# elftools example: elf_core_prstatus.py
#
# Interpret NT_PRSTATUS notes from an ELF core dump. Each note is decoded for
# the core's own target ABI (ELF class and byte order from its header, never
# the host's), and the thread id, raw register words and exact note range are
# preserved.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
import os
import sys
from io import BytesIO

# The synthetic core builder lives with the tests.
sys.path.append(os.path.join(os.path.dirname(__file__), os.pardir, 'test'))

from synthetic_core import SyntheticCore, prstatus_desc  # noqa: E402

from elftools.elf.elffile import ELFFile  # noqa: E402


def report(label, core_bytes):
    elffile = ELFFile(BytesIO(core_bytes))
    core = elffile.get_core_registers()
    print(f'  {label}: ELFCLASS{core.elfclass}, '
          f'{"little" if core.little_endian else "big"}-endian, '
          f'machine={core.machine}')
    print(f'    Threads with NT_PRSTATUS notes: {len(core.threads)}')
    for thread in core.threads:
        print(f'    Thread {thread.tid}:')
        print(f'      note range: offset=0x{thread.raw_status.note_range.offset:x} '
              f'size={thread.raw_status.note_range.size}')
        if thread.status is None:
            partial = thread.partial_registers
            if partial is None:
                print('      registers: unavailable (raw note preserved)')
            else:
                print(f'      registers: incomplete, {partial.register_count} '
                      'whole words preserved')
            continue
        status = thread.status
        print(f'      ABI: {status.label}')
        for word in status.registers:
            if word.name in ('eip', 'rip', 'pc', 'sp'):
                print(f'      {word.name:>4s} = 0x{word.value:x}')
    if core.unassociated_notes:
        print(f'    Unassociated thread notes: '
              f'{len(core.unassociated_notes)} (kept raw)')


def demo():
    # Two little-endian x86-64 threads; the second note is followed by an
    # FPREGSET that must not be glued onto it.
    x86 = SyntheticCore(64, True)
    x86.add_note('CORE', 1, prstatus_desc(
        64, True, pid=101, registers=[0x100 + i for i in range(27)]))
    x86.add_note('CORE', 2, b'\xAA' * 16)
    x86.add_note('CORE', 1, prstatus_desc(
        64, True, pid=102, registers=[0x200 + i for i in range(27)]))
    print('Two-thread x86-64 core:')
    report('target', x86.build())

    # A 32-bit big-endian target, decoded with its own ABI.
    mips = SyntheticCore(32, False, machine=8)
    mips.add_note('CORE', 1, prstatus_desc(
        32, False, pid=201, registers=[0x300 + i for i in range(17)]))
    print('Big-endian 32-bit core with an unsupported register layout:')
    report('target', mips.build())


def process_file(filename):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        core = elffile.get_core_registers()
        print(f'  Target: ELFCLASS{core.elfclass}, '
              f'{"little" if core.little_endian else "big"}-endian, '
              f'machine={core.machine}')
        print(f'  Threads with NT_PRSTATUS notes: {len(core.threads)}')
        for thread in core.threads:
            print(f'  Thread {thread.tid}:')
            print(f'    note range: offset=0x{thread.raw_status.note_range.offset:x} '
                  f'size={thread.raw_status.note_range.size}')
            if thread.status is None:
                partial = thread.partial_registers
                if partial is None:
                    print('    registers: unavailable (raw note preserved)')
                else:
                    print(f'    registers: incomplete, {partial.register_count} '
                          'whole words preserved')
                continue
            status = thread.status
            print(f'    ABI: {status.label}')
            for word in status.registers:
                if word.name is not None:
                    print(f'    {word.name:>8s} = 0x{word.value:x}')
        if core.unassociated_notes:
            print(f'  Unassociated thread notes: '
                  f'{len(core.unassociated_notes)} (kept raw)')


if __name__ == '__main__':
    if sys.argv[1] == '--test':
        demo()
        for filename in sys.argv[2:]:
            process_file(filename)
