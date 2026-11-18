# ------------------------------------------------------------------------------
# elftools tests
#
# Tests for NT_AUXV interpretation in ELF core dumps. These cover per-ABI
# decoding of the auxiliary vector, preservation of the raw key/value pairs,
# strictly bounded pointer reads, the AT_SECURE flag, and load-offset
# derivation from mutually consistent AUXV/ELF fields.
#
# This code is in the public domain
# ------------------------------------------------------------------------------
from io import BytesIO
import os
import struct
import sys
import unittest

sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))

from synthetic_core import SyntheticCoreBuilder

from elftools.elf.elffile import ELFFile
from elftools.elf.segments import NoteSegment

CORE64 = os.path.join("test", "testfiles_for_unittests", "core_linux64.elf")
CORE32 = os.path.join("test", "testfiles_for_unittests", "core_linux32.elf")


def get_auxv(stream):
    elf = ELFFile(stream)
    for segment in elf.iter_segments():
        if isinstance(segment, NoteSegment):
            for note in segment.iter_notes():
                if note["n_type"] == "NT_AUXV":
                    return elf, note["n_desc"], note["n_descdata"]
    raise LookupError("NT_AUXV not found")


class TestRealCoreAuxv(unittest.TestCase):
    def test_64bit_decode_and_raw_preservation(self):
        with open(CORE64, "rb") as fh:
            elf, vector, raw = get_auxv(fh)
        self.assertEqual(vector.elfclass, 64)
        self.assertTrue(vector.little_endian)
        # The raw descriptor still holds every untouched pair.
        self.assertEqual(len(raw), 304)
        # Known tags become names; numeric values are preserved.
        types = [e.a_type for e in vector.entries]
        self.assertIn("AT_PHDR", types)
        self.assertEqual(types[-1], "AT_NULL")
        self.assertEqual(vector.value("AT_PHDR"), 0x400040)
        self.assertEqual(vector.value("AT_ENTRY"), 0x400430)
        self.assertEqual(vector.value("AT_PHENT"), 0x38)
        self.assertEqual(vector.value("AT_PHNUM"), 9)
        self.assertEqual(vector.value("AT_PAGESZ"), 0x1000)
        # Re-encode the decoded pairs and compare with the raw bytes.
        words = b"".join(
            struct.pack(
                "<QQ",
                e.a_type if isinstance(e.a_type, int) else _tag_num(e.a_type),
                e.a_val,
            )
            for e in vector.entries
        )
        self.assertEqual(words, raw)

    def test_32bit_decode(self):
        with open(CORE32, "rb") as fh:
            elf, vector, raw = get_auxv(fh)
        self.assertEqual(vector.elfclass, 32)
        self.assertEqual(vector.value("AT_PHDR"), 0x56624034)
        self.assertEqual(vector.value("AT_PHENT"), 0x20)
        self.assertEqual(vector.value("AT_PHNUM"), 9)
        words = b"".join(
            struct.pack("<II", _tag_num(e.a_type), e.a_val) for e in vector.entries
        )
        self.assertEqual(words, raw)

    def test_bounded_string_and_binary_reads(self):
        with open(CORE64, "rb") as fh:
            _elf, vector, _raw = get_auxv(fh)
        statuses = {r.a_type: r for r in vector.reads}
        # Strings are read only inside saved PT_LOAD ranges.
        self.assertEqual(vector.string("AT_PLATFORM"), b"x86_64")
        self.assertEqual(vector.string("AT_EXECFN"), b"./coredump_self")
        platform = statuses["AT_PLATFORM"]
        self.assertEqual(platform.status, "ok")
        self.assertEqual(platform.size, len(b"x86_64"))
        self.assertIsNotNone(platform.file_offset)
        # A binary pointer reads exactly one target word.
        phdr = statuses["AT_PHDR"]
        self.assertEqual(phdr.status, "ok")
        self.assertEqual(phdr.size, 8)
        self.assertEqual(phdr.data, b"\x06\x00\x00\x00\x05\x00\x00\x00")

    def test_at_secure_is_just_a_value(self):
        with open(CORE64, "rb") as fh:
            _elf, vector, _raw = get_auxv(fh)
        # AT_SECURE carries no pointer and no inferred environment state.
        self.assertEqual(vector.value("AT_SECURE"), 0)
        secure_entry = next(e for e in vector.entries if e.a_type == "AT_SECURE")
        self.assertFalse(secure_entry.is_pointer)
        self.assertIsNone(secure_entry.read)


class TestSyntheticAuxv(unittest.TestCase):
    def _build_main_elf(
        self, pie, entry, phdr_vaddr, first_load, phnum=9, phentsize=0x38
    ):
        ehsize = 64
        eh = bytearray(ehsize)
        eh[0:4] = b"\x7fELF"
        eh[4], eh[5], eh[6] = 2, 1, 1
        struct.pack_into("<H", eh, 16, 3 if pie else 2)
        struct.pack_into("<H", eh, 18, 0x3E)
        struct.pack_into("<I", eh, 20, 1)
        struct.pack_into("<Q", eh, 24, entry)
        struct.pack_into("<Q", eh, 32, ehsize)
        struct.pack_into("<H", eh, 52, ehsize)
        struct.pack_into("<H", eh, 54, phentsize)
        struct.pack_into("<H", eh, 56, phnum)

        def phdr(p_type, flags, off, vaddr, filesz, memsz, align=0x1000):
            return struct.pack(
                "<IIQQQQQQ", p_type, flags, off, vaddr, vaddr, filesz, memsz, align
            )

        phs = phdr(6, 5, ehsize, phdr_vaddr, phentsize * phnum, phentsize * phnum, 8)
        phs += phdr(1, 5, 0, first_load, 0x1000, 0x1000)
        for i in range(phnum - 2):
            phs += phdr(
                1, 4, 0x1000 + i * 0x10, first_load + 0x1000 + i * 0x1000, 0x100, 0x100
            )
        return bytes(eh) + phs

    def test_confirmed_exec_offset_pie(self):
        slide = 0x555555554000
        main_elf = self._build_main_elf(True, 0x430, 0x40, 0x0)
        builder = SyntheticCoreBuilder(64)
        builder.add_auxv_note(
            [
                (3, slide + 0x40),
                (4, 0x38),
                (5, 9),
                (9, slide + 0x430),
                (23, 1),
                (0, 0),
            ]
        )
        builder.add_load(slide, b"\x00" * 0x1000)
        elf = ELFFile(BytesIO(builder.build()))
        vector = next(
            n["n_desc"]
            for s in elf.iter_segments()
            if isinstance(s, NoteSegment)
            for n in s.iter_notes()
            if n["n_type"] == "NT_AUXV"
        )
        evidence = vector.executable_load_offset(ELFFile(BytesIO(main_elf)))
        self.assertEqual(evidence.offset, slide)
        self.assertIn("AT_PHDR - PT_PHDR.vaddr", evidence.sources)
        self.assertIn("AT_ENTRY - e_entry", evidence.sources)
        self.assertIn("AT_PHENT == e_phentsize", evidence.sources)
        self.assertIn("AT_PHNUM == e_phnum", evidence.sources)
        self.assertEqual(evidence.conflicts, ())

    def test_confirmed_et_exec_zero_base(self):
        main_elf = self._build_main_elf(False, 0x400430, 0x400040, 0x400000)
        builder = SyntheticCoreBuilder(64)
        builder.add_auxv_note(
            [
                (3, 0x400040),
                (4, 0x38),
                (5, 9),
                (9, 0x400430),
                (0, 0),
            ]
        )
        builder.add_load(0x400000, b"\x00" * 0x1000)
        elf = ELFFile(BytesIO(builder.build()))
        vector = next(
            n["n_desc"]
            for s in elf.iter_segments()
            if isinstance(s, NoteSegment)
            for n in s.iter_notes()
            if n["n_type"] == "NT_AUXV"
        )
        evidence = vector.executable_load_offset(ELFFile(BytesIO(main_elf)))
        self.assertEqual(evidence.offset, 0)

    def test_disagreeing_estimates_stay_unknown(self):
        # AT_PHDR implies one slide, AT_ENTRY implies a different one.
        slide = 0x555555554000
        main_elf = self._build_main_elf(True, 0x430, 0x40, 0x0)
        builder = SyntheticCoreBuilder(64)
        builder.add_auxv_note(
            [
                (3, slide + 0x40),
                (4, 0x38),
                (5, 9),
                (9, slide + 0x9999),
                (0, 0),
            ]
        )
        builder.add_load(slide, b"\x00" * 0x1000)
        elf = ELFFile(BytesIO(builder.build()))
        vector = next(
            n["n_desc"]
            for s in elf.iter_segments()
            if isinstance(s, NoteSegment)
            for n in s.iter_notes()
            if n["n_type"] == "NT_AUXV"
        )
        evidence = vector.executable_load_offset(ELFFile(BytesIO(main_elf)))
        self.assertIsNone(evidence.offset)
        self.assertTrue(evidence.conflicts)
        self.assertIn("disagree", evidence.note)

    def test_phdr_description_mismatch_still_crosschecked(self):
        # Same implied slide, but the AUXV claims a different PHNUM.
        slide = 0x555555554000
        main_elf = self._build_main_elf(True, 0x430, 0x40, 0x0, phnum=9)
        builder = SyntheticCoreBuilder(64)
        builder.add_auxv_note(
            [
                (3, slide + 0x40),
                (4, 0x38),
                (5, 7),
                (9, slide + 0x430),
                (0, 0),
            ]
        )
        builder.add_load(slide, b"\x00" * 0x1000)
        elf = ELFFile(BytesIO(builder.build()))
        vector = next(
            n["n_desc"]
            for s in elf.iter_segments()
            if isinstance(s, NoteSegment)
            for n in s.iter_notes()
            if n["n_type"] == "NT_AUXV"
        )
        evidence = vector.executable_load_offset(ELFFile(BytesIO(main_elf)))
        # The two offset estimates agree, but PHNUM no longer corroborates.
        self.assertEqual(evidence.offset, slide)
        self.assertNotIn("AT_PHNUM == e_phnum", evidence.sources)

    def test_missing_page_reads_are_unmapped_and_offset_unknown(self):
        slide = 0x555555554000
        main_elf = self._build_main_elf(True, 0x430, 0x40, 0x0)
        builder = SyntheticCoreBuilder(64)
        builder.add_auxv_note(
            [
                (3, slide + 0x40),
                (4, 0x38),
                (5, 9),
                (15, 0x7FFF0000),
                (31, 0x7FFF1000),
                (0, 0),
            ]
        )
        builder.add_load(0x700000, b"\x00" * 0x1000)
        elf = ELFFile(BytesIO(builder.build()))
        vector = next(
            n["n_desc"]
            for s in elf.iter_segments()
            if isinstance(s, NoteSegment)
            for n in s.iter_notes()
            if n["n_type"] == "NT_AUXV"
        )
        # Every pointer target is outside the sole saved segment.
        self.assertTrue(vector.reads)
        for read in vector.reads:
            self.assertEqual(read.status, "unmapped")
            self.assertIsNone(read.data)
            self.assertIsNone(read.file_offset)
        # The strings cannot be recovered from an unsaved page.
        self.assertIsNone(vector.string("AT_PLATFORM"))
        self.assertIsNone(vector.string("AT_EXECFN"))
        # Only AT_PHDR can estimate a slide; without AT_ENTRY it is unknown.
        evidence = vector.executable_load_offset(ELFFile(BytesIO(main_elf)))
        self.assertIsNone(evidence.offset)
        self.assertIn("AT_ENTRY", evidence.missing)

    def test_unterminated_string_is_bounded(self):
        builder = SyntheticCoreBuilder(64)
        # A full page with no NUL terminator at the AT_PLATFORM target.
        builder.add_auxv_note([(15, 0x600000), (0, 0)])
        builder.add_load(0x600000, b"A" * 0x1000)
        elf = ELFFile(BytesIO(builder.build()))
        vector = next(
            n["n_desc"]
            for s in elf.iter_segments()
            if isinstance(s, NoteSegment)
            for n in s.iter_notes()
            if n["n_type"] == "NT_AUXV"
        )
        read = vector.reads[0]
        self.assertEqual(read.status, "unterminated")
        self.assertLessEqual(read.size, 0x1000)
        self.assertIsNone(vector.string("AT_PLATFORM"))

    def test_unknown_tag_preserved_as_integer(self):
        builder = SyntheticCoreBuilder(64)
        builder.add_auxv_note([(0x7777, 0x1234), (0, 0)])
        elf = ELFFile(BytesIO(builder.build()))
        vector = next(
            n["n_desc"]
            for s in elf.iter_segments()
            if isinstance(s, NoteSegment)
            for n in s.iter_notes()
            if n["n_type"] == "NT_AUXV"
        )
        self.assertEqual(vector.entries[0].a_type, 0x7777)
        self.assertEqual(vector.entries[0].a_val, 0x1234)

    def test_32bit_synthetic_abi(self):
        builder = SyntheticCoreBuilder(32)
        builder.add_auxv_note(
            [(3, 0x56624034), (4, 0x20), (5, 9), (15, 0x56625000), (0, 0)]
        )
        builder.add_load(0x56625000, b"i686\x00" + b"\x00" * (0x1000 - 5))
        elf = ELFFile(BytesIO(builder.build()))
        vector = next(
            n["n_desc"]
            for s in elf.iter_segments()
            if isinstance(s, NoteSegment)
            for n in s.iter_notes()
            if n["n_type"] == "NT_AUXV"
        )
        self.assertEqual(vector.elfclass, 32)
        self.assertEqual(vector.value("AT_PHENT"), 0x20)
        self.assertEqual(vector.string("AT_PLATFORM"), b"i686")
        platform = next(r for r in vector.reads if r.a_type == "AT_PLATFORM")
        # String bytes exclude the NUL terminator.
        self.assertEqual(platform.size, 4)
        self.assertEqual(platform.data, b"i686")

    def test_abi_mismatch_between_core_and_executable_stays_unknown(self):
        # A 64-bit core paired with a 32-bit main program cannot be compared.
        main_elf32 = self._build_main_elf(True, 0x430, 0x40, 0x0)
        # Rewrite the ELF class byte to 32 and shrink the phent to 0x20.
        blob = bytearray(main_elf32)
        blob[4] = 1
        struct.pack_into("<H", blob, 54, 0x20)
        builder = SyntheticCoreBuilder(64)
        slide = 0x555555554000
        builder.add_auxv_note(
            [(3, slide + 0x40), (4, 0x38), (5, 9), (9, slide + 0x430), (0, 0)]
        )
        builder.add_load(slide, b"\x00" * 0x1000)
        elf = ELFFile(BytesIO(builder.build()))
        vector = next(
            n["n_desc"]
            for s in elf.iter_segments()
            if isinstance(s, NoteSegment)
            for n in s.iter_notes()
            if n["n_type"] == "NT_AUXV"
        )
        evidence = vector.executable_load_offset(ELFFile(BytesIO(bytes(blob))))
        self.assertIsNone(evidence.offset)
        self.assertIn("ABI", evidence.note)


def _tag_num(name):
    from elftools.elf.enums import ENUM_AUXV_TYPE

    return ENUM_AUXV_TYPE[name]


if __name__ == "__main__":
    unittest.main()
