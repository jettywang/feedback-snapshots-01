#------------------------------------------------------------------------------
# elftools tests
#
# A small in-memory ET_CORE builder used by the NT_PRSTATUS tests. It gives
# full control over the target ABI (ELF class, byte order, machine), the note
# order and the descriptor bytes, so decode/refusal behavior can be checked
# without a host-specific core dump.
#
# This code is in the public domain
#------------------------------------------------------------------------------
from __future__ import annotations

import struct

# e_machine numbers used by the tests.
EM_386 = 3
EM_MIPS = 8
EM_PPC64 = 21
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183
EM_RISCV = 243

_NOTE_ALIGN = 4


def pad4(value: int) -> int:
    return (value + _NOTE_ALIGN - 1) // _NOTE_ALIGN * _NOTE_ALIGN


class SyntheticCore:
    """Build an ET_CORE with a single PT_NOTE segment and no PT_LOADs."""

    def __init__(
        self,
        elfclass: int = 64,
        little_endian: bool = True,
        machine: int = EM_X86_64,
    ) -> None:
        assert elfclass in (32, 64)
        self.elfclass = elfclass
        self.little_endian = little_endian
        self.machine = machine
        self._notes: list[tuple[str, int, bytes]] = []

    @property
    def endian(self) -> str:
        return '<' if self.little_endian else '>'

    def add_note(self, name: str, n_type: int, desc: bytes) -> None:
        self._notes.append((name, n_type, desc))

    def build(self) -> bytes:
        note_blob = self._build_notes()
        ehsize = 64 if self.elfclass == 64 else 52
        phentsize = 56 if self.elfclass == 64 else 32
        phoff = ehsize
        note_off = phoff + phentsize
        note_off = (note_off + _NOTE_ALIGN - 1) // _NOTE_ALIGN * _NOTE_ALIGN
        header = self._build_ehdr(ehsize, phentsize, 1, phoff)
        phdr = self._build_phdr(note_off, len(note_blob))
        blob = header + phdr
        blob += b'\x00' * (note_off - len(blob))
        blob += note_blob
        return blob

    # -- internals ------------------------------------------------------- #

    def _build_notes(self) -> bytes:
        blob = bytearray()
        for name, n_type, desc in self._notes:
            name_b = name.encode() + b'\x00'
            name_pad = pad4(len(name_b)) - len(name_b)
            desc_pad = pad4(len(desc)) - len(desc)
            blob += struct.pack(self.endian + 'III', len(name_b), len(desc), n_type)
            blob += name_b + b'\x00' * name_pad
            blob += desc + b'\x00' * desc_pad
        return bytes(blob)

    def _build_ehdr(self, ehsize: int, phentsize: int, phnum: int, phoff: int) -> bytes:
        ident = b'\x7fELF' + bytes([
            2 if self.elfclass == 64 else 1,
            1 if self.little_endian else 2,
            1,
            0,
        ]) + b'\x00' * 8
        if self.elfclass == 64:
            eh = bytearray(ehsize)
            eh[0:16] = ident
            struct.pack_into(self.endian + 'H', eh, 16, 4)  # ET_CORE
            struct.pack_into(self.endian + 'H', eh, 18, self.machine)
            struct.pack_into(self.endian + 'I', eh, 20, 1)
            struct.pack_into(self.endian + 'Q', eh, 32, phoff)
            struct.pack_into(self.endian + 'H', eh, 52, ehsize)
            struct.pack_into(self.endian + 'H', eh, 54, phentsize)
            struct.pack_into(self.endian + 'H', eh, 56, phnum)
            return bytes(eh)
        eh = bytearray(ehsize)
        eh[0:16] = ident
        struct.pack_into(self.endian + 'H', eh, 16, 4)  # ET_CORE
        struct.pack_into(self.endian + 'H', eh, 18, self.machine)
        struct.pack_into(self.endian + 'I', eh, 20, 1)
        struct.pack_into(self.endian + 'I', eh, 28, phoff)
        struct.pack_into(self.endian + 'H', eh, 40, ehsize)
        struct.pack_into(self.endian + 'H', eh, 42, phentsize)
        struct.pack_into(self.endian + 'H', eh, 44, phnum)
        return bytes(eh)

    def _build_phdr(self, p_offset: int, p_filesz: int) -> bytes:
        if self.elfclass == 64:
            return struct.pack(
                self.endian + 'IIQQQQQQ',
                4, 0, p_offset, 0, 0, p_filesz, p_filesz, 4)
        return struct.pack(
            self.endian + 'IIIIIIII',
            4, p_offset, 0, 0, p_filesz, p_filesz, 0, 4)


def prstatus_desc(
    elfclass: int,
    little_endian: bool,
    *,
    pid: int,
    registers: list[int] | tuple[int, ...],
    ppid: int = 1,
    pgrp: int = None,
    sid: int = None,
    cursig: int = 11,
    signo: int = 11,
    sigpend: int = 0,
    sighold: int = 0,
    truncate: int = 0,
    extra_desc: int = 4,
) -> bytes:
    """Build one elf_prstatus descriptor for a target ABI.

    registers are written verbatim into pr_reg. extra_desc appends that many
    bytes after the register block (4 covers pr_fpvalid; 0 makes the note end
    right after pr_reg). truncate cuts bytes off the end after assembly, to
    model an incomplete register area.
    """
    endian = '<' if little_endian else '>'
    word = 4 if elfclass == 32 else 8
    if pgrp is None:
        pgrp = pid
    if sid is None:
        sid = pid

    timeval = struct.pack(endian + 'ii', 0, 0)
    if elfclass == 32:
        header = struct.pack(
            endian + '3ih2xIIiiii',
            0, 0, 0, cursig, sigpend, sighold, pid, ppid, pgrp, sid)
        header += timeval * 4
    else:
        header = struct.pack(
            endian + '3ih2xQQiiii',
            0, 0, 0, cursig, sigpend, sighold, pid, ppid, pgrp, sid)
        header += timeval * 4 * 2  # 16-byte timevals
    assert len(header) == (72 if elfclass == 32 else 112)

    reg_bytes = b''.join(
        struct.pack(endian + ('I' if word == 4 else 'Q'), value & (2 ** (word * 8) - 1))
        for value in registers
    )
    desc = header + reg_bytes + b'\x00' * extra_desc
    desc += b'\x00' * (word - len(desc) % word) if len(desc) % word else b''
    if truncate:
        desc = desc[:-truncate]
    return desc
