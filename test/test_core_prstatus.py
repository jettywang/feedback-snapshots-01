#------------------------------------------------------------------------------
# elftools tests
#
# Tests for NT_PRSTATUS interpretation in ELF core dumps. They cover:
#   * per-ABI register decoding from the core's own ELF class/byte order,
#   * preservation of thread ids, raw register words and the exact note
#     range,
#   * two threads in one core, including a note order that is not enough to
#     bind thread-scoped notes by adjacency,
#   * 32/64-bit and little/big-endian targets, independent of the host,
#   * truncated register areas and unknown architectures,
#   * notes that cannot be associated and therefore create no thread state.
#
# This code is in the public domain
#------------------------------------------------------------------------------
import os
import struct
import sys
import unittest
from io import BytesIO

sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))

from synthetic_core import (
    EM_386,
    EM_AARCH64,
    EM_ARM,
    EM_RISCV,
    EM_X86_64,
    SyntheticCore,
    pad4,
    prstatus_desc,
)

from elftools.elf.elffile import ELFFile
from elftools.elf.prstatus import (
    NoteRange,
    register_layout_for,
)
from elftools.elf.segments import NoteSegment

CORE32 = os.path.join('test', 'testfiles_for_unittests', 'core_linux32.elf')
CORE64 = os.path.join('test', 'testfiles_for_unittests', 'core_linux64.elf')
CORE_MIPS = os.path.join(
    'test', 'testfiles_for_unittests', 'core_linux32_qemu_mips.elf')

X86_32_REGS = [
    0x11111111, 0x22222222, 0x33333333, 0x44444444,
    0x55555555, 0x66666666, 0x77777777, 0x2b, 0x2b, 0x0, 0x63,
    0xdeadbeef, 0x08048400, 0x23, 0x202, 0xbfff0000, 0x2b,
]

X86_64_REGS = [
    0x101, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107, 0x108,
    0x109, 0x10a, 0x10b, 0x10c, 0x10d, 0x10e, 0x10f, 0x110,
    0x7fff00000000, 0x33, 0x246, 0x7fffffffe000, 0x2b,
    0x7ffff7ffd000, 0x7ffff7ffe000, 0x0, 0x0, 0x0, 0x0,
]


def prstatus_note_index(core: bytes, nth: int = 0) -> tuple[int, int]:
    """Return (n_offset, n_size) of the nth NT_PRSTATUS note."""
    found = 0
    elf = ELFFile(BytesIO(core))
    for segment in elf.iter_segments():
        if not isinstance(segment, NoteSegment):
            continue
        for note in segment.iter_notes():
            if note['n_type'] != 'NT_PRSTATUS':
                continue
            if found == nth:
                return note['n_offset'], note['n_size']
            found += 1
    raise LookupError('NT_PRSTATUS note not found')


def raw_register_words(
    core: bytes, desc_offset: int, desc_size: int,
    elfclass: int, little_endian: bool,
) -> list[int]:
    """Read pr_reg directly from the file, bypassing the library decoder.

    The descriptor starts right after the 12-byte note header and the rounded
    note name; pr_reg in turn starts at the ABI header size.
    """
    words = 4 if elfclass == 32 else 8
    header = 72 if elfclass == 32 else 112
    fmt = '<' if little_endian else '>'
    fmt += 'I' if words == 4 else 'Q'
    name = b'CORE\x00'
    reg_off = desc_offset + 12 + pad4(len(name)) + header
    end = desc_offset + desc_size
    count = (end - reg_off) // words
    return [struct.unpack_from(fmt, core, reg_off + i * words)[0]
            for i in range(count)]


class TestRealCorePrstatus(unittest.TestCase):
    def test_32bit_thread_registers(self):
        with ELFFile.load_from_path(CORE32) as elf:
            core_regs = elf.get_core_registers()
        self.assertEqual(core_regs.elfclass, 32)
        self.assertTrue(core_regs.little_endian)
        self.assertEqual(len(core_regs.threads), 1)
        thread = core_regs.threads[0]
        self.assertEqual(thread.tid, 11038)
        self.assertEqual(thread.pid, 11038)
        self.assertIsNotNone(thread.status)
        status = thread.status
        self.assertEqual(status.label, 'i386')
        self.assertEqual(status.register('eip'), 0xf7f38079)
        self.assertEqual(status.register('esp'), 0xffdad160)
        self.assertEqual(status.register('eax'), 0)
        self.assertEqual(status.register('cs'), 0x23)
        self.assertEqual(status.register_count, 17)
        # The raw pr_reg block is still available exactly as stored.
        self.assertEqual(len(status.raw_pr_reg), 17 * 4)

    def test_64bit_thread_registers(self):
        with ELFFile.load_from_path(CORE64) as elf:
            core_regs = elf.get_core_registers()
        self.assertEqual(core_regs.elfclass, 64)
        self.assertEqual(len(core_regs.threads), 1)
        status = core_regs.threads[0].status
        self.assertIsNotNone(status)
        self.assertEqual(core_regs.threads[0].tid, 23395)
        self.assertEqual(status.label, 'x86-64')
        self.assertEqual(status.register('rip'), 0x7fa4593e3428)
        self.assertEqual(status.register('rsp'), 0x7ffe2e5a0358)
        self.assertEqual(status.register('orig_rax'), 234)
        self.assertEqual(status.register_count, 27)

    def test_unknown_architecture_keeps_raw_material(self):
        # The MIPS core has a real NT_PRSTATUS note, but no MIPS register
        # layout is supported: no thread status may be fabricated.
        with ELFFile.load_from_path(CORE_MIPS) as elf:
            self.assertIsNone(register_layout_for(elf))
            core_regs = elf.get_core_registers()
        self.assertEqual(len(core_regs.threads), 1)
        thread = core_regs.threads[0]
        self.assertIsNone(thread.status)
        self.assertEqual(thread.tid, 449015)
        self.assertEqual(len(thread.raw_status.descdata), 256)
        self.assertEqual(thread.raw_status.kind, 'prstatus')

    def test_unsupported_arch_note_desc_stays_raw(self):
        with ELFFile.load_from_path(CORE_MIPS) as elf:
            notes = [
                note
                for segment in elf.iter_segments()
                if isinstance(segment, NoteSegment)
                for note in segment.iter_notes()
                if note['n_type'] == 'NT_PRSTATUS'
            ]
        self.assertEqual(len(notes), 1)
        self.assertIsInstance(notes[0]['n_desc'], bytes)
        self.assertEqual(len(notes[0]['n_desc']), 256)
        self.assertEqual(len(notes[0]['n_descdata']), 256)

    def test_note_range_matches_file(self):
        with open(CORE64, 'rb') as fh:
            core = fh.read()
        with open(CORE64, 'rb') as fh:
            elf = ELFFile(fh)
            thread = elf.get_core_registers().threads[0]
        status = thread.status
        offset, size = prstatus_note_index(core)
        self.assertEqual(status.note_range, NoteRange(offset, size))
        # The range includes the note header, CORE name, descriptor and the
        # alignment padding that follows it.
        self.assertEqual(size, 12 + 8 + 336)
        self.assertEqual(thread.raw_status.note_range, status.note_range)
        self.assertEqual(len(thread.raw_status.descdata), 336)


class TestSyntheticTwoThreads(unittest.TestCase):
    def _make_core(self, elfclass=64, little_endian=True, machine=EM_X86_64):
        regs = X86_64_REGS if elfclass == 64 else X86_32_REGS
        core = SyntheticCore(elfclass, little_endian, machine)
        core.add_note('CORE', 1, prstatus_desc(
            elfclass, little_endian, pid=1001, registers=regs))
        core.add_note('CORE', 1, prstatus_desc(
            elfclass, little_endian, pid=1002, registers=regs[::-1]))
        return core.build()

    def test_two_threads_preserve_ids_and_values(self):
        for elfclass, endian in ((32, True), (64, True), (32, False), (64, False)):
            with self.subTest(elfclass=elfclass, endian=endian):
                core = self._make_core(elfclass, endian,
                                       EM_X86_64 if elfclass == 64 else EM_386)
                elf = ELFFile(BytesIO(core))
                result = elf.get_core_registers()
                self.assertEqual([t.tid for t in result.threads], [1001, 1002])
                first, second = result.threads
                expected = X86_64_REGS if elfclass == 64 else X86_32_REGS
                reg_name = 'rip' if elfclass == 64 else 'eip'
                index = 16 if elfclass == 64 else 12
                self.assertEqual(first.status.register(reg_name), expected[index])
                self.assertEqual(
                    second.status.register(reg_name), expected[::-1][index])
                self.assertEqual(first.status.elfclass, elfclass)
                self.assertEqual(first.status.little_endian, endian)

    def test_register_words_match_raw_file_bytes(self):
        # Verify each target ABI is decoded with its own endianness, not the
        # host's. The expected values are compared against bytes read straight
        # from the file at the note's recorded range.
        cases = [
            (32, True, EM_386, 72, X86_32_REGS),
            (32, False, EM_386, 72, X86_32_REGS),
            (64, True, EM_X86_64, 112, X86_64_REGS),
            (64, False, EM_X86_64, 112, X86_64_REGS),
        ]
        for elfclass, endian, machine, header, regs in cases:
            with self.subTest(elfclass=elfclass, endian=endian, machine=machine):
                core = SyntheticCore(elfclass, endian, machine)
                core.add_note('CORE', 1, prstatus_desc(
                    elfclass, endian, pid=77, registers=regs))
                data = core.build()
                elf = ELFFile(BytesIO(data))
                status = elf.get_core_registers().threads[0].status
                self.assertIsNotNone(status)
                desc_off, desc_size = prstatus_note_index(data)
                # File-side words include the trailing pr_fpvalid word.
                raw_words = raw_register_words(
                    data, desc_off, desc_size, elfclass, endian)
                self.assertEqual(
                    [w.value for w in status.registers],
                    raw_words[:len(status.registers)])
                self.assertEqual(len(status.registers), len(regs))
                self.assertEqual(status.raw_pr_reg, b''.join(w.raw for w in status.registers))
                self.assertEqual(
                    status.raw_descdata[header:header + len(status.raw_pr_reg)],
                    status.raw_pr_reg)

    def test_host_bitness_does_not_affect_target(self):
        # A 32-bit big-endian core is decoded as 32-bit big-endian regardless
        # of what Python reports for the host.
        core = SyntheticCore(32, False, EM_386)
        core.add_note('CORE', 1, prstatus_desc(
            32, False, pid=3003, registers=X86_32_REGS))
        data = core.build()
        elf = ELFFile(BytesIO(data))
        status = elf.get_core_registers().threads[0].status
        self.assertEqual(status.elfclass, 32)
        self.assertFalse(status.little_endian)
        self.assertEqual(status.register('eip'), 0x08048400)
        self.assertEqual(status.register('ebx'), 0x11111111)
        # The big-endian byte order is visible directly in the raw words.
        self.assertEqual(status.register_raw('ebx'), b'\x11\x11\x11\x11')

    def test_other_supported_architectures(self):
        cases = [
            (32, EM_ARM, 18, 'pc'),
            (64, EM_AARCH64, 34, 'pc'),
            (64, EM_RISCV, 32, 'pc'),
        ]
        for elfclass, machine, count, name in cases:
            with self.subTest(machine=machine):
                regs = list(range(0xA0, 0xA0 + count))
                core = SyntheticCore(elfclass, True, machine)
                core.add_note('CORE', 1, prstatus_desc(
                    elfclass, True, pid=5005, registers=regs))
                elf = ELFFile(BytesIO(core.build()))
                status = elf.get_core_registers().threads[0].status
                self.assertIsNotNone(status)
                self.assertEqual(status.register_count, count)
                position = {
                    'EM_ARM': 15, 'EM_AARCH64': 32, 'EM_RISCV': 0,
                }[status.machine]
                self.assertEqual(status.register(name), regs[position])


class TestNoteAssociation(unittest.TestCase):
    def test_fpregset_is_not_merged_by_adjacency(self):
        core = SyntheticCore(64, True, EM_X86_64)
        core.add_note('CORE', 1, prstatus_desc(
            64, True, pid=2001, registers=X86_64_REGS))
        core.add_note('CORE', 2, b'\xAA' * 512)   # NT_FPREGSET
        core.add_note('CORE', 1, prstatus_desc(
            64, True, pid=2002, registers=X86_64_REGS))
        core.add_note('CORE', 0x202, b'\xBB' * 128)  # NT_X86_XSTATE
        elf = ELFFile(BytesIO(core.build()))
        result = elf.get_core_registers()
        self.assertEqual([t.tid for t in result.threads], [2001, 2002])
        for thread in result.threads:
            self.assertEqual(thread.attached_notes, ())
        # Unbound thread-scoped notes stay raw and never create a thread.
        self.assertEqual(len(result.unassociated_notes), 2)
        self.assertEqual(
            [n.descdata for n in result.unassociated_notes],
            [b'\xAA' * 512, b'\xBB' * 128])
        self.assertIsNone(result.thread(2003))

    def test_unknown_owner_note_creates_no_thread(self):
        # A NOTE with a non-CORE owner and type 1 is not NT_PRSTATUS.
        core = SyntheticCore(64, True, EM_X86_64)
        core.add_note('GNU', 1, b'\x00' * 336)
        elf = ELFFile(BytesIO(core.build()))
        result = elf.get_core_registers()
        self.assertEqual(result.threads, ())
        self.assertEqual(result.unassociated_notes, ())

    def test_truncated_prstatus_keeps_raw_note(self):
        # Every pr_reg byte is gone (the note ends in the header/fpvalid
        # area): the thread id survives, but there is no register evidence.
        for cut in (217, 221, 224, 225, 240):
            with self.subTest(cut=cut):
                core = SyntheticCore(64, True, EM_X86_64)
                core.add_note('CORE', 1, prstatus_desc(
                    64, True, pid=4004, registers=X86_64_REGS, truncate=cut))
                data = core.build()
                elf = ELFFile(BytesIO(data))
                result = elf.get_core_registers()
                if cut > 224:
                    # Too short for the status header: no thread is created.
                    self.assertEqual(result.threads, ())
                    self.assertEqual(len(result.unassociated_notes), 1)
                    continue
                self.assertEqual(len(result.threads), 1)
                thread = result.threads[0]
                self.assertIsNone(thread.status)
                self.assertEqual(thread.tid, 4004)
                offset, size = prstatus_note_index(data)
                self.assertEqual(thread.raw_status.note_range, NoteRange(offset, size))
                self.assertEqual(len(thread.raw_status.descdata), 336 - cut)

    def test_truncated_register_area_preserves_whole_words(self):
        # Cut in the middle of pr_reg: only whole words that are actually
        # present may appear, never a fabricated zero fill for the rest.
        cut = 3 * 8 + 5   # drop 3 whole words, then fpvalid, padding and 5 bytes
        core = SyntheticCore(64, True, EM_X86_64)
        core.add_note('CORE', 1, prstatus_desc(
            64, True, pid=4005, registers=X86_64_REGS, truncate=cut))
        data = core.build()
        elf = ELFFile(BytesIO(data))
        thread = elf.get_core_registers().threads[0]
        # No full status may be claimed from an incomplete descriptor.
        self.assertIsNone(thread.status)
        status = thread.partial_registers
        self.assertIsNotNone(status)
        self.assertFalse(status.complete)
        self.assertEqual(status.tid, 4005)
        self.assertEqual(status.register_count, 24)
        self.assertEqual(
            [w.value for w in status.registers], X86_64_REGS[:24])
        self.assertIsNone(status.register('gs'))
        self.assertIsNone(status.pr_fpvalid)
        offset, size = prstatus_note_index(data)
        self.assertEqual(status.note_range, NoteRange(offset, size))
        self.assertEqual(len(status.raw_descdata), 336 - cut)
        self.assertEqual(thread.raw_status.descdata, status.raw_descdata)
        # Raw words and raw descriptor keep the file's own bytes.
        self.assertEqual(status.raw_descdata[112:112 + len(status.raw_pr_reg)],
                         status.raw_pr_reg)
        self.assertEqual(len(status.raw_pr_reg), 24 * 8)
        # The decoded words are still compared against the file itself.
        raw_words = raw_register_words(data, offset, size, 64, True)
        self.assertEqual(
            [w.value for w in status.registers], raw_words[:24])

    def test_complete_and_truncated_threads_coexist(self):
        core = SyntheticCore(64, True, EM_X86_64)
        core.add_note('CORE', 1, prstatus_desc(
            64, True, pid=6001, registers=X86_64_REGS))
        core.add_note('CORE', 1, prstatus_desc(
            64, True, pid=6002, registers=X86_64_REGS, truncate=64))
        elf = ELFFile(BytesIO(core.build()))
        result = elf.get_core_registers()
        self.assertEqual([t.tid for t in result.threads], [6001, 6002])
        self.assertIsNotNone(result.thread(6001).status)
        self.assertIsNone(result.thread(6002).status)
        partial = result.thread(6002).partial_registers
        self.assertIsNotNone(partial)
        self.assertEqual(partial.register_count, 20)
        self.assertFalse(partial.complete)
        # The truncated thread's partial words still match the file.
        self.assertEqual(
            [w.value for w in partial.registers], X86_64_REGS[:20])
        # Note ranges are distinct and point at their own notes.
        self.assertNotEqual(
            result.thread(6001).raw_status.note_range,
            result.thread(6002).raw_status.note_range)

    def test_short_descriptor_is_unassociated(self):
        # Shorter than the status header: even the tid is unavailable, so the
        # note is raw material rather than a thread with a guessed id.
        core = SyntheticCore(64, True, EM_X86_64)
        core.add_note('CORE', 1, b'\x00' * 40)
        elf = ELFFile(BytesIO(core.build()))
        result = elf.get_core_registers()
        self.assertEqual(result.threads, ())
        self.assertEqual(len(result.unassociated_notes), 1)
        self.assertEqual(result.unassociated_notes[0].descdata, b'\x00' * 40)

    def test_trailing_alignment_padding_is_optional(self):
        # A descriptor cut at the end of pr_fpvalid (no word alignment
        # padding) is still a complete layout: the padding has no meaning.
        core = SyntheticCore(64, True, EM_X86_64)
        core.add_note('CORE', 1, prstatus_desc(
            64, True, pid=9009, registers=X86_64_REGS, truncate=4))
        elf = ELFFile(BytesIO(core.build()))
        status = elf.get_core_registers().threads[0].status
        self.assertIsNotNone(status)
        self.assertTrue(status.complete)
        self.assertEqual(len(status.raw_descdata), 332)
        self.assertEqual(status.pr_fpvalid, 0)
        self.assertFalse(status.fpvalid)
        self.assertEqual(status.register('rip'), X86_64_REGS[16])

    def test_note_segment_entry_point(self):
        core = SyntheticCore(32, True, EM_386)
        core.add_note('CORE', 1, prstatus_desc(
            32, True, pid=7007, registers=X86_32_REGS))
        elf = ELFFile(BytesIO(core.build()))
        segments = [s for s in elf.iter_segments() if isinstance(s, NoteSegment)]
        self.assertEqual(len(segments), 1)
        threads = list(segments[0].iter_core_thread_registers())
        self.assertEqual([t.tid for t in threads], [7007])
        self.assertEqual(threads[0].status.register('eip'),
                         X86_32_REGS[12])

    def test_note_desc_is_decoded_only_when_complete(self):
        core = SyntheticCore(64, True, EM_X86_64)
        core.add_note('CORE', 1, prstatus_desc(
            64, True, pid=8008, registers=X86_64_REGS))
        core.add_note('CORE', 1, prstatus_desc(
            64, True, pid=8009, registers=X86_64_REGS, truncate=16))
        data = core.build()
        elf = ELFFile(BytesIO(data))
        descs = [
            note['n_desc']
            for segment in elf.iter_segments()
            if isinstance(segment, NoteSegment)
            for note in segment.iter_notes()
            if note['n_type'] == 'NT_PRSTATUS'
        ]
        self.assertEqual(descs[0].tid, 8008)
        self.assertEqual(descs[0].note_range.offset,
                         data.find(b'CORE\x00') - 12)
        # The truncated note keeps its raw descriptor; only a complete
        # layout becomes a decoded n_desc.
        self.assertIsInstance(descs[1], bytes)
        self.assertEqual(len(descs[1]), 336 - 16)


if __name__ == '__main__':
    unittest.main()
