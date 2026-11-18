# -------------------------------------------------------------------------------
# elftools example: elf_core_auxv.py
#
# Interpret the NT_AUXV note of ELF core dumps. The auxiliary vector is
# decoded for the target process's ABI, every raw (type, value) pair is kept,
# and pointer-like entries are read only from the memory ranges the core
# actually saved. Given a caller-supplied main program ELF, the executable's
# load offset is derived solely from mutually consistent AUXV/ELF fields.
#
# Three synthetic cores make the boundary between confirmed and unknown
# conclusions explicit:
#   1. an ET_EXEC main program loaded at its link base (offset 0)
#   2. a PIE main program relocated to a nonzero base
#   3. a "missing page" core whose pointer targets were not dumped
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
# -------------------------------------------------------------------------------
from __future__ import annotations

import os
import struct
import sys
from io import BytesIO

# The synthetic core builder lives with the tests.
sys.path.append(os.path.join(os.path.dirname(__file__), os.pardir, "test"))

from synthetic_core import SyntheticCoreBuilder  # noqa: E402

from elftools.elf.auxv import AuxvVector  # noqa: E402
from elftools.elf.elffile import ELFFile  # noqa: E402
from elftools.elf.segments import NoteSegment  # noqa: E402

PAGE = 0x1000


def build_main_elf(*, pie: bool, entry: int, phdr_vaddr: int, first_load: int) -> bytes:
    """A tiny 64-bit program header table describing the main program."""
    phnum, phentsize = 9, 0x38
    ehsize = 64
    eh = bytearray(ehsize)
    eh[0:4] = b"\x7fELF"
    eh[4], eh[5], eh[6] = 2, 1, 1
    struct.pack_into("<H", eh, 16, 3 if pie else 2)  # ET_DYN / ET_EXEC
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

    phs = phdr(
        6, 5, ehsize, phdr_vaddr, phentsize * phnum, phentsize * phnum, 8
    )  # PT_PHDR
    phs += phdr(1, 5, 0, first_load, PAGE, PAGE)  # first PT_LOAD
    for i in range(phnum - 2):
        phs += phdr(1, 4, PAGE + i * 0x10, first_load + PAGE + i * PAGE, 0x100, 0x100)
    return bytes(eh) + phs


def auxv_note_vector(core_bytes: bytes) -> AuxvVector:
    elf = ELFFile(BytesIO(core_bytes))
    for segment in elf.iter_segments():
        if isinstance(segment, NoteSegment):
            for note in segment.iter_notes():
                if note["n_type"] == "NT_AUXV":
                    return note["n_desc"]
    raise LookupError("core has no NT_AUXV note")


def print_pointer_reads(vector: AuxvVector) -> None:
    print("  bounded pointer reads (target -> saved file range):")
    for read in vector.reads:
        if read.status == "unmapped":
            print(
                f"    {read.a_type:18s} vaddr={read.vaddr:#018x} "
                f"status=UNMAPPED (no PT_LOAD covers it; 0 bytes read)"
            )
            continue
        seg_end = read.segment_vaddr + read.segment_filesz
        print(
            f"    {read.a_type:18s} vaddr={read.vaddr:#018x} " f"status={read.status}"
        )
        print(
            f"        segment vaddr=[{read.segment_vaddr:#x},"
            f"{seg_end:#x}) "
            f"file_offset={read.file_offset:#x} bytes_read={read.size} "
            f"data={read.data!r}"
        )


def report(
    title: str, core_bytes: bytes, main_elf_bytes: bytes | None, *, secure: int
) -> None:
    print("=" * 78)
    print(title)
    print("=" * 78)
    vector = auxv_note_vector(core_bytes)
    print(
        f'  ABI: ELFCLASS{vector.elfclass}, '
        f'{"little" if vector.little_endian else "big"} endian, '
        f'{vector.elfclass // 8}-byte words; {len(vector.entries)} entries'
    )
    print("  raw auxiliary pairs (original keys/values preserved):")
    for entry in vector.entries:
        name = (
            entry.a_type if isinstance(entry.a_type, str) else f"AT_0x{entry.a_type:x}"
        )
        print(f"    [{entry.index:2d}] {name:18s} {entry.a_val:#018x}")
    print_pointer_reads(vector)

    print(f"  AT_SECURE raw value = {secure}")
    print("      (this is only the kernel flag; any actual environment/")
    print("       sanitization must be established separately from memory.)")

    print("  interpreter load base (AT_BASE, single-field evidence):")
    interp = vector.interpreter_load_offset()
    print(
        f"      offset={interp.offset:#x}"
        if interp.offset is not None
        else f"      unknown; missing={interp.missing}"
    )

    if main_elf_bytes is None:
        print("  executable load offset: UNKNOWN (no main program ELF given)")
        return
    main_elf = ELFFile(BytesIO(main_elf_bytes))
    evidence = vector.executable_load_offset(main_elf)
    if evidence.offset is None:
        print("  executable load offset: UNKNOWN")
        if evidence.sources:
            print(f"      agreeing fields: {evidence.sources}")
        if evidence.conflicts:
            print("      conflicting estimates:")
            for name, value in evidence.conflicts:
                print(f"        {name} = {value:#x}")
        if evidence.missing:
            print(f"      missing fields: {evidence.missing}")
        if evidence.note:
            print(f"      reason: {evidence.note}")
    else:
        print(f"  executable load offset: {evidence.offset:#x} (CONFIRMED)")
        print("      derived from mutually consistent fields:")
        for source in evidence.sources:
            print(f"        - {source}")
        if evidence.missing:
            print(f"      not available: {evidence.missing}")
    print()


def main() -> None:
    # ---- case 1: ET_EXEC, linked and loaded at base 0 -------------------
    exec_elf = build_main_elf(
        pie=False, entry=0x400430, phdr_vaddr=0x400040, first_load=0x400000
    )
    b1 = SyntheticCoreBuilder(64)
    b1.add_load(0x400000, b"\x00" * PAGE)
    b1.add_load(0x401000, b"x86_64\x00" + b"\x00" * (PAGE - 7))
    b1.add_load(0x402000, b"./et_exec_demo\x00" + b"\x00" * (PAGE - 14))
    # Point the string AUXV entries into their own, fully saved pages.
    b1_pairs = [
        (3, 0x400040),  # AT_PHDR
        (4, 0x38),  # AT_PHENT
        (5, 9),  # AT_PHNUM
        (7, 0x7F000000),  # AT_BASE (interpreter)
        (9, 0x400430),  # AT_ENTRY
        (15, 0x401000),  # AT_PLATFORM (string, saved)
        (23, 0),  # AT_SECURE
        (31, 0x402000),  # AT_EXECFN (string, saved)
        (0, 0),
    ]
    b1.add_auxv_note(b1_pairs)
    report(
        "Case 1 - ET_EXEC main program, loaded at its link base",
        b1.build(),
        exec_elf,
        secure=0,
    )

    # ---- case 2: PIE, relocated to a nonzero load base ------------------
    slide = 0x555555554000
    pie_elf = build_main_elf(pie=True, entry=0x430, phdr_vaddr=0x40, first_load=0x0)
    b2 = SyntheticCoreBuilder(64)
    b2.add_auxv_note(
        [
            (3, slide + 0x40),  # AT_PHDR  = slide + PT_PHDR.vaddr
            (4, 0x38),
            (5, 9),
            (7, 0x7FAAAA000000),
            (9, slide + 0x430),  # AT_ENTRY = slide + e_entry
            (15, slide + 0x1000),
            (23, 1),  # secure execution requested
            (31, slide + 0x2000),
            (0, 0),
        ]
    )
    b2.add_load(slide, b"\x00" * PAGE)
    b2.add_load(slide + 0x1000, b"x86_64\x00" + b"\x00" * (PAGE - 7))
    b2.add_load(slide + 0x2000, b"./pie_demo\x00" + b"\x00" * (PAGE - 10))
    report(
        "Case 2 - PIE main program, relocated by a nonzero slide",
        b2.build(),
        pie_elf,
        secure=1,
    )

    # ---- case 3: missing page, pointer targets were not dumped ----------
    # The AUXV survives, but the program-header page and every string target
    # were excluded from the dump. AT_ENTRY is also absent, so the single
    # remaining offset estimate cannot be cross-checked and stays unknown.
    b3 = SyntheticCoreBuilder(64)
    b3.add_auxv_note(
        [
            (3, slide + 0x40),  # AT_PHDR -> page not present
            (4, 0x38),
            (5, 9),
            (15, 0x7FFF0000),  # AT_PLATFORM -> no PT_LOAD covers it
            (31, 0x7FFF1000),  # AT_EXECFN  -> no PT_LOAD covers it
            (23, 0),
            (0, 0),
        ]
    )
    # Only an unrelated page is saved; none of the AUXV pointers hit it.
    b3.add_load(0x700000, b"\x00" * PAGE)
    report(
        "Case 3 - missing-page core (pointer targets not in the dump)",
        b3.build(),
        pie_elf,
        secure=0,
    )


if __name__ == "__main__":
    # The examples test harness invokes every script with "--test <file>".
    # This demo builds its own cores, so any extra argument is accepted but
    # ignored to keep the reference output deterministic.
    main()
