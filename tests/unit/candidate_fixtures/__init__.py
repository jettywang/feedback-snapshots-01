"""Helpers to synthesize tiny offline ELF files for candidate tests."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

SHT_STRTAB = 3
SHT_DYNSYM = 11
SHT_GNU_VERNEED = 0x6FFFFFFE
SHT_GNU_VERSYM = 0x6FFFFFFF
SHT_GNU_VERDEF = 0x6FFFFFFD
SHF_ALLOC = 2

EM_AARCH64 = 183
EM_X86_64 = 62


def _elf_hash(name: str) -> int:
    h = 0
    for byte in name.encode():
        h = (h << 4) + byte
        high = h & 0xF0000000
        if high:
            h ^= high >> 24
        h &= ~high
    return h & 0xFFFFFFFF


class _StrTab:
    def __init__(self) -> None:
        self.data = bytearray(b"\0")
        self.offsets: dict[str, int] = {}

    def add(self, value: str) -> int:
        if value in self.offsets:
            return self.offsets[value]
        offset = len(self.data)
        self.offsets[value] = offset
        self.data += value.encode() + b"\0"
        return offset


@dataclass
class Needs:
    """Describe an undefined (imported) symbol and the version it needs."""

    library: str
    version: str
    symbols: list[str] = field(default_factory=list)


@dataclass
class Provides:
    """Describe an exported symbol and the version it belongs to."""

    version: str
    symbols: list[str] = field(default_factory=list)


def build_import_elf(needs: list[Needs], *, machine: int = EM_X86_64) -> bytes:
    """Build an ELF shared object that imports versioned symbols.

    The resulting file has ``.dynsym``, ``.gnu.version`` and
    ``.gnu.version_r`` (verneed) sections, which is what auditwheel reads.
    """
    strtab = _StrTab()
    version_index: dict[tuple[str, str], int] = {}
    index = 2
    for group in needs:
        version_index[(group.library, group.version)] = index
        index += 1

    dynsym = bytearray(b"\0" * 24)
    versym = bytearray(struct.pack("<H", 0))
    for group in needs:
        for name in group.symbols:
            dynsym += struct.pack("<IBBHQQ", strtab.add(name), (1 << 4) | 2, 0, 0, 0, 0)
            versym += struct.pack("<H", version_index[(group.library, group.version)])

    verneed = bytearray()
    for group_index, group in enumerate(needs):
        start = len(verneed)
        verneed += b"\0" * 16
        aux_start = len(verneed)
        aux_offsets = []
        for _ in group.symbols:
            aux_offsets.append(len(verneed))
            verneed += b"\0" * 16
        next_offset = len(verneed) if group_index + 1 < len(needs) else 0
        struct.pack_into(
            "<HHIII",
            verneed,
            start,
            1,
            1,
            strtab.add(group.library),
            aux_start - start,
            next_offset,
        )
        struct.pack_into(
            "<IHHII",
            verneed,
            aux_offsets[0],
            _elf_hash(group.version),
            0,
            version_index[(group.library, group.version)],
            strtab.add(group.version),
            0,
        )

    return _assemble(
        [
            (".dynstr", SHT_STRTAB, SHF_ALLOC, bytes(strtab.data), 0, 0, 1, 0),
            (".dynsym", SHT_DYNSYM, SHF_ALLOC, bytes(dynsym), 1, 1, 8, 24),
            (".gnu.version", SHT_GNU_VERSYM, SHF_ALLOC, bytes(versym), 2, 0, 2, 2),
            (".gnu.version_r", SHT_GNU_VERNEED, SHF_ALLOC, bytes(verneed), 1, len(needs), 8, 16),
        ],
        machine=machine,
    )


def build_export_elf(
    provides: list[Provides],
    *,
    needs: list[Needs] | None = None,
    machine: int = EM_X86_64,
) -> bytes:
    """Build an ELF shared object that exports (and optionally imports) symbols.

    ``provides`` become version definitions (verdef) and ``needs`` become
    version requirements (verneed), so a candidate can both satisfy the
    wheel's imports and declare the platform it itself runs on.
    """
    strtab = _StrTab()
    version_index: dict[tuple[str, str], int] = {}
    index = 2
    for group in provides:
        version_index[("provide", group.version)] = index
        index += 1
    for group in needs or []:
        version_index[(group.library, group.version)] = index
        index += 1

    dynsym = bytearray(b"\0" * 24)
    versym = bytearray(struct.pack("<H", 0))
    # Version indexes for definitions and requirements must agree with the
    # indexes allocated above, so use one shared counter below.
    assert len(version_index) == index - 2
    provide_index = {group.version: version_index[("provide", group.version)] for group in provides}
    need_index = {
        (group.library, group.version): version_index[(group.library, group.version)]
        for group in (needs or [])
    }
    for group in provides:
        for name in group.symbols:
            dynsym += struct.pack("<IBBHQQ", strtab.add(name), (1 << 4) | 2, 1, 0x1000, 16, 0)
            versym += struct.pack("<H", provide_index[group.version])
    for group in needs or []:
        for name in group.symbols:
            dynsym += struct.pack("<IBBHQQ", strtab.add(name), (1 << 4) | 2, 0, 0, 0, 0)
            versym += struct.pack("<H", need_index[(group.library, group.version)])

    verdef = bytearray()
    for group_index, group in enumerate(provides):
        start = len(verdef)
        verdef += b"\0" * 20
        aux_start = len(verdef)
        verdef += b"\0" * 8
        next_offset = len(verdef) if group_index + 1 < len(provides) else 0
        struct.pack_into(
            "<HHHHIII",
            verdef,
            start,
            1,
            0,
            version_index[("provide", group.version)],
            1,
            _elf_hash(group.version),
            aux_start - start,
            next_offset,
        )
        struct.pack_into(
            "<II",
            verdef,
            aux_start,
            strtab.add(group.version),
            0,
        )

    # Build verneed before snapshotting .dynstr: both sections share it.
    verneed = _build_verneed(strtab, version_index, needs or [])
    sections = [
        (".dynstr", SHT_STRTAB, SHF_ALLOC, bytes(strtab.data), 0, 0, 1, 0),
        (".dynsym", SHT_DYNSYM, SHF_ALLOC, bytes(dynsym), 1, 1, 8, 24),
        (".gnu.version", SHT_GNU_VERSYM, SHF_ALLOC, bytes(versym), 2, 0, 2, 2),
        (".gnu.version_d", SHT_GNU_VERDEF, SHF_ALLOC, bytes(verdef), 1, len(provides), 8, 20),
    ]
    if verneed:
        sections.append(
            (".gnu.version_r", SHT_GNU_VERNEED, SHF_ALLOC, verneed, 1, len(needs or []), 8, 16)
        )
    return _assemble(sections, machine=machine)


def _build_verneed(
    strtab: _StrTab,
    version_index: dict[tuple[str, str], int],
    needs: list[Needs],
) -> bytes:
    if not needs:
        return b""
    verneed = bytearray()
    for group_index, group in enumerate(needs):
        start = len(verneed)
        verneed += b"\0" * 16
        aux_start = len(verneed)
        verneed += b"\0" * 16
        next_offset = len(verneed) if group_index + 1 < len(needs) else 0
        struct.pack_into(
            "<HHIII",
            verneed,
            start,
            1,
            1,
            strtab.add(group.library),
            aux_start - start,
            next_offset,
        )
        struct.pack_into(
            "<IHHII",
            verneed,
            aux_start,
            _elf_hash(group.version),
            0,
            version_index[(group.library, group.version)],
            strtab.add(group.version),
            0,
        )
    return bytes(verneed)


def _assemble(
    sections: list[tuple[str, int, int, bytes, int, int, int, int]],
    *,
    machine: int,
) -> bytes:
    shstr = _StrTab()
    names = ["", ".shstrtab", *(entry[0] for entry in sections)]
    for name in names:
        shstr.add(name)
    sections = [
        ("", 0, 0, b"", 0, 0, 0, 0),
        *sections,
        (".shstrtab", SHT_STRTAB, 0, bytes(shstr.data), 0, 0, 1, 0),
    ]
    shstrndx = len(sections) - 1

    ehsize = 64
    offset = ehsize
    layout = []
    for _, _, _, data, _, _, align, _ in sections:
        pad = (-offset) % align if align else 0
        offset += pad
        layout.append((offset, pad))
        offset += len(data)
    shoff = offset

    header = bytearray(b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8)
    header += struct.pack(
        "<HHIQQQIHHHHHH",
        3,
        machine,
        1,
        0,
        0,
        shoff,
        0,
        ehsize,
        0,
        0,
        64,
        len(sections),
        shstrndx,
    )
    out = header
    for (_, _, _, data, _, _, _, _), (start, pad) in zip(sections, layout, strict=True):
        out += b"\0" * pad
        assert len(out) == start
        out += data
    assert len(out) == shoff
    for (name, kind, flags, data, link, info, align, entsize), (start, _) in zip(
        sections, layout, strict=True
    ):
        out += struct.pack(
            "<IIQQQQIIQQ",
            shstr.offsets[name],
            kind,
            flags,
            0,
            start,
            len(data),
            link,
            info,
            align,
            entsize,
        )
    return bytes(out)
