# -------------------------------------------------------------------------------
# test/synthetic_core.py
#
# A minimal in-memory ET_CORE builder used by the NT_AUXV tests and the
# elf_core_auxv example. It builds cores whose saved memory is fully under the
# caller's control, including cores that deliberately omit a page so pointer
# reads can be observed failing without consulting the host process.
#
# This code is in the public domain
# -------------------------------------------------------------------------------
from __future__ import annotations

import struct


class SyntheticCoreBuilder:
    """Build a little-endian ELF core from explicit notes and PT_LOAD ranges."""

    def __init__(self, elfclass: int = 64) -> None:
        assert elfclass in (32, 64)
        self.elfclass = elfclass
        self._loads: list[tuple[int, int, bytes]] = []
        self._notes: list[tuple[str, int, bytes]] = []

    def add_load(self, vaddr: int, data: bytes) -> None:
        """Add a PT_LOAD segment presenting data at vaddr."""
        self._loads.append((vaddr, len(data), data))

    def add_note(self, name: str, n_type: int, desc: bytes) -> None:
        self._notes.append((name, n_type, desc))

    def add_auxv_note(self, pairs: list[tuple[int, int]]) -> None:
        code = "Q" if self.elfclass == 64 else "I"
        desc = b"".join(
            struct.pack(f"<2{code}", a_type, a_val) for a_type, a_val in pairs
        )
        self.add_note("CORE", 6, desc)

    def build(self) -> bytes:
        note_blob = self._build_notes()
        ehsize = 64 if self.elfclass == 64 else 52
        phentsize = 56 if self.elfclass == 64 else 32
        phnum = 1 + len(self._loads)
        phoff = ehsize
        note_off = phoff + phentsize * phnum
        # Program header segments must be aligned for a realistic layout.
        cursor = self._align(note_off + len(note_blob))

        load_records = []
        for vaddr, filesz, data in self._loads:
            off = cursor
            load_records.append((vaddr, filesz, off))
            cursor = self._align(off + filesz)

        header = self._build_ehdr(ehsize, phentsize, phnum, phoff)
        note_ph = self._build_phdr(4, note_off, 0, len(note_blob), 0)
        parts = [header, note_ph]
        for vaddr, filesz, off in load_records:
            parts.append(self._build_phdr(1, off, vaddr, filesz, filesz))
        parts.append(b"\x00" * (note_off - len(b"".join(parts))))
        parts.append(note_blob)
        for (vaddr, filesz, data), (rv, rfsz, off) in zip(self._loads, load_records):
            built = b"".join(parts)
            if len(built) < off:
                parts.append(b"\x00" * (off - len(built)))
            parts.append(data)
        return b"".join(parts)

    # -- internals ------------------------------------------------------- #

    @staticmethod
    def _align(value: int) -> int:
        return (value + 0xFFF) & ~0xFFF

    def _build_notes(self) -> bytes:
        blob = bytearray()
        for name, n_type, desc in self._notes:
            name_b = name.encode() + b"\x00"
            name_pad = self._pad4(len(name_b))
            desc_pad = self._pad4(len(desc))
            blob += struct.pack("<III", len(name_b), len(desc), n_type)
            blob += name_b + b"\x00" * name_pad
            blob += desc + b"\x00" * desc_pad
        return bytes(blob)

    @staticmethod
    def _pad4(size: int) -> int:
        return (4 - size % 4) % 4

    def _build_ehdr(self, ehsize, phentsize, phnum, phoff) -> bytes:
        if self.elfclass == 64:
            ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
            eh = bytearray(64)
            eh[0:16] = ident
            struct.pack_into("<H", eh, 16, 4)  # ET_CORE
            struct.pack_into("<H", eh, 18, 0x3E)  # EM_X86_64
            struct.pack_into("<I", eh, 20, 1)
            struct.pack_into("<Q", eh, 32, phoff)
            struct.pack_into("<H", eh, 52, ehsize)
            struct.pack_into("<H", eh, 54, phentsize)
            struct.pack_into("<H", eh, 56, phnum)
            return bytes(eh)
        ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 8
        eh = bytearray(52)
        eh[0:16] = ident
        struct.pack_into("<H", eh, 16, 4)  # ET_CORE
        struct.pack_into("<H", eh, 18, 3)  # EM_386
        struct.pack_into("<I", eh, 20, 1)
        struct.pack_into("<I", eh, 28, phoff)
        struct.pack_into("<H", eh, 40, ehsize)
        struct.pack_into("<H", eh, 42, phentsize)
        struct.pack_into("<H", eh, 44, phnum)
        return bytes(eh)

    def _build_phdr(self, p_type, p_offset, p_vaddr, p_filesz, p_memsz) -> bytes:
        if self.elfclass == 64:
            return struct.pack(
                "<IIQQQQQQ",
                p_type,
                4 if p_type == 1 else 0,
                p_offset,
                p_vaddr,
                p_vaddr,
                p_filesz,
                p_memsz,
                0x1000,
            )
        return struct.pack(
            "<IIIIIIII",
            p_type,
            p_offset,
            p_vaddr,
            p_vaddr,
            p_filesz,
            p_memsz,
            4 if p_type == 1 else 0,
            0x1000,
        )
