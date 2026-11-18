# -------------------------------------------------------------------------------
# elftools: elf/auxv.py
#
# Interpretation of the NT_AUXV note found in ET_CORE files.
#
# The auxiliary vector is a sequence of (a_type, a_val) word pairs that the
# kernel hands to a freshly loaded program. In a core file it is captured as
# the descriptor of an NT_AUXV note. This module decodes those pairs for the
# target process's ABI (word size and endianness taken from the core header),
# preserves every raw pair, and only dereferences pointer-like values inside
# the memory ranges the core itself saved. Nothing is ever filled in from the
# host process or from ranges the dump did not capture.
#
# This code is in the public domain
# -------------------------------------------------------------------------------
from __future__ import annotations

from dataclasses import dataclass, field
import struct
from typing import TYPE_CHECKING, BinaryIO

from ..common.utils import preserve_stream_pos
from .enums import ENUM_AUXV_TYPE

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .elffile import ELFFile


# Auxiliary types whose a_val is a pointer into the dumped program's memory.
# AT_EXECFD is a file descriptor, not a pointer, and is intentionally absent.
_POINTER_TYPES = frozenset(
    {
        "AT_PHDR",
        "AT_BASE",
        "AT_ENTRY",
        "AT_PLATFORM",
        "AT_BASE_PLATFORM",
        "AT_RANDOM",
        "AT_EXECFN",
        "AT_SYSINFO",
        "AT_SYSINFO_EHDR",
    }
)

# Pointer types that point at a NUL-terminated string rather than a binary
# structure or code address.
_STRING_TYPES = frozenset(
    {
        "AT_PLATFORM",
        "AT_BASE_PLATFORM",
        "AT_EXECFN",
    }
)

# Upper bound on how many bytes a single string read will consume, so a
# missing terminator cannot make a read run away across a whole segment.
_MAX_STRING_READ = 4096


@dataclass(frozen=True)
class PointerRead:
    """The outcome of one bounded pointer dereference.

    vaddr is the requested target address. When the address fell inside a
    saved PT_LOAD range, file_offset/size describe the exact file bytes
    that were read and status is 'ok' (or 'unterminated' for a string
    whose NUL was not found inside the saved range). Otherwise no bytes
    were read, status is 'unmapped', and file_offset/size are None.
    """

    a_type: str
    vaddr: int
    status: str
    file_offset: int | None = None
    size: int | None = None
    data: bytes | None = None
    segment_vaddr: int | None = None
    segment_filesz: int | None = None


@dataclass(frozen=True)
class AuxvEntry:
    """One decoded auxiliary vector entry.

    a_type holds the symbolic name for known ABI values and the raw
    integer for unknown ones. a_val is always the untouched numeric value
    from the note, so the original key/value pair is never lost. For
    pointer-like types, read records the bounded dereference attempt.
    """

    a_type: str | int
    a_val: int
    index: int
    read: PointerRead | None = None

    @property
    def is_pointer(self) -> bool:
        return isinstance(self.a_type, str) and self.a_type in _POINTER_TYPES

    @property
    def is_string(self) -> bool:
        return isinstance(self.a_type, str) and self.a_type in _STRING_TYPES


@dataclass(frozen=True)
class LoadOffsetEvidence:
    """The mutually consistent fields supporting one load offset result.

    Each candidate field contributes an independent estimate; an offset is
    only reported when every available estimate agrees. sources lists the
    AUXV/ELF fields that agreed, conflicts lists estimates that differed,
    and missing lists fields the dump did not capture.
    """

    offset: int | None
    kind: str
    sources: tuple[str, ...] = ()
    conflicts: tuple[tuple[str, int], ...] = ()
    missing: tuple[str, ...] = ()
    note: str | None = None


@dataclass
class AuxvVector:
    """Decoded NT_AUXV contents plus evidence derived purely from the core."""

    elfclass: int
    little_endian: bool
    entries: list[AuxvEntry] = field(default_factory=list)
    reads: list[PointerRead] = field(default_factory=list)

    # ---- construction -------------------------------------------------- #

    @classmethod
    def from_core(cls, elffile: ELFFile, desc_data: bytes) -> AuxvVector:
        """Decode an NT_AUXV descriptor for elffile's ABI and resolve every
        pointer-like value against the memory ranges saved in the core.
        """
        vector = cls(
            elfclass=elffile.elfclass,
            little_endian=elffile.little_endian,
        )
        word = elffile.elfclass // 8
        if len(desc_data) % (2 * word) != 0:
            # A truncated trailing pair cannot be decoded; keep the bytes that
            # form whole pairs rather than guessing at the remainder.
            desc_data = desc_data[: len(desc_data) - (len(desc_data) % (2 * word))]
        endian = "<" if elffile.little_endian else ">"
        pair_format = f'{endian}2{"Q" if word == 8 else "I"}'
        tag_names = {
            value: name for name, value in ENUM_AUXV_TYPE.items() if name != "_default_"
        }
        for index, off in enumerate(range(0, len(desc_data), 2 * word)):
            a_type_num, a_val = struct.unpack(
                pair_format,
                desc_data[off : off + 2 * word],
            )
            a_type = tag_names.get(a_type_num, a_type_num)
            read = None
            if isinstance(a_type, str) and a_type in _POINTER_TYPES:
                want_string = a_type in _STRING_TYPES
                read = vector._read_pointer(elffile, a_type, a_val, want_string)
                vector.reads.append(read)
            vector.entries.append(
                AuxvEntry(a_type=a_type, a_val=a_val, index=index, read=read)
            )
            if a_type == "AT_NULL":
                break
        return vector

    # ---- bounded memory access ---------------------------------------- #

    def _resolve_segment(
        self, elffile: ELFFile, vaddr: int
    ) -> tuple[BinaryIO, int, int, int] | None:
        """Map a virtual address to the saved PT_LOAD bytes, or None.

        Only the file-backed portion (p_filesz) of a segment counts. Bytes
        between p_filesz and p_memsz were not dumped and must not be read,
        and nothing is ever taken from the host process.
        """
        for segment in elffile.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            start = segment["p_vaddr"]
            saved_end = start + segment["p_filesz"]
            if start <= vaddr < saved_end:
                file_offset = segment["p_offset"] + (vaddr - start)
                return (
                    elffile.stream,
                    file_offset,
                    segment["p_filesz"],
                    start,
                )
        return None

    def _read_pointer(
        self,
        elffile: ELFFile,
        a_type: str,
        vaddr: int,
        want_string: bool,
    ) -> PointerRead:
        location = self._resolve_segment(elffile, vaddr)
        if location is None:
            return PointerRead(a_type=a_type, vaddr=vaddr, status="unmapped")

        stream, file_offset, segment_filesz, segment_vaddr = location
        if want_string:
            return self._read_string(
                elffile, a_type, vaddr, file_offset, segment_filesz, segment_vaddr
            )

        # Binary pointer: read one target word, the natural evidence unit.
        size = self.elfclass // 8
        with preserve_stream_pos(stream):
            stream.seek(file_offset)
            data = stream.read(size)
        if len(data) != size:
            return PointerRead(
                a_type=a_type,
                vaddr=vaddr,
                status="unmapped",
                segment_vaddr=segment_vaddr,
                segment_filesz=segment_filesz,
            )
        return PointerRead(
            a_type=a_type,
            vaddr=vaddr,
            status="ok",
            file_offset=file_offset,
            size=size,
            data=data,
            segment_vaddr=segment_vaddr,
            segment_filesz=segment_filesz,
        )

    def _read_string(
        self,
        elffile: ELFFile,
        a_type: str,
        vaddr: int,
        file_offset: int,
        segment_filesz: int,
        segment_vaddr: int,
    ) -> PointerRead:
        # Read only up to the end of the saved segment, capped so a missing
        # NUL cannot drag in an unbounded amount of memory.
        saved_remaining = segment_vaddr + segment_filesz - vaddr
        size = min(saved_remaining, _MAX_STRING_READ)
        with preserve_stream_pos(elffile.stream):
            elffile.stream.seek(file_offset)
            data = elffile.stream.read(size)
        nul = data.find(b"\x00")
        if nul >= 0:
            return PointerRead(
                a_type=a_type,
                vaddr=vaddr,
                status="ok",
                file_offset=file_offset,
                size=nul,
                data=data[:nul],
                segment_vaddr=segment_vaddr,
                segment_filesz=segment_filesz,
            )
        return PointerRead(
            a_type=a_type,
            vaddr=vaddr,
            status="unterminated",
            file_offset=file_offset,
            size=len(data),
            data=data,
            segment_vaddr=segment_vaddr,
            segment_filesz=segment_filesz,
        )

    # ---- convenient lookups ------------------------------------------- #

    def value(self, name: str) -> int | None:
        """The raw a_val of the last entry of this type, or None if absent."""
        result = None
        for entry in self.entries:
            if entry.a_type == name:
                result = entry.a_val
        return result

    def string(self, name: str) -> bytes | None:
        """The decoded string for an AT_* string pointer, or None when the
        text was not saved in the core.
        """
        for entry in self.entries:
            if entry.a_type == name and entry.read is not None:
                if entry.read.status == "ok":
                    return entry.read.data
                return None
        return None

    def iter_entries(self) -> Iterator[AuxvEntry]:
        return iter(self.entries)

    # ---- load-offset derivation --------------------------------------- #

    def executable_load_offset(self, executable: ELFFile) -> LoadOffsetEvidence:
        """Derive the main executable's load offset from AT_PHDR/AT_ENTRY and
        the caller-provided main program ELF, using only mutually
        consistent fields. Returns an unknown result with an explanation
        when the dump lacks the memory or fields needed.
        """
        return _derive_executable_offset(self, executable)

    def interpreter_load_offset(self) -> LoadOffsetEvidence:
        """The dynamic linker's load base, taken from AT_BASE. This is a
        single AUXV field, so there is nothing to cross-check; the value
        is reported as evidence only when AT_BASE is present.
        """
        base = self.value("AT_BASE")
        if base is None:
            return LoadOffsetEvidence(
                offset=None, kind="interpreter", missing=("AT_BASE",)
            )
        return LoadOffsetEvidence(offset=base, kind="interpreter", sources=("AT_BASE",))


# --------------------------------------------------------------------------- #
# Cross-checking helpers
# --------------------------------------------------------------------------- #


def _executable_phdr_info(
    executable: ELFFile,
) -> tuple[int | None, int]:
    """Return (PT_PHDR vaddr or None, e_entry) from the main program ELF."""
    phdr_vaddr = None
    for segment in executable.iter_segments():
        if segment["p_type"] == "PT_PHDR":
            phdr_vaddr = segment["p_vaddr"]
    return phdr_vaddr, executable["e_entry"]


def _check_phdr_consistency(
    vector: AuxvVector, executable: ELFFile
) -> tuple[list[str], list[str]]:
    """Compare the AUXV description of the program header table against the
    caller-provided main program ELF. Returns (matched_fields, missing).
    """
    matched: list[str] = []
    missing: list[str] = []

    at_phent = vector.value("AT_PHENT")
    if at_phent is None:
        missing.append("AT_PHENT")
    elif at_phent == executable["e_phentsize"]:
        matched.append("AT_PHENT == e_phentsize")

    at_phnum = vector.value("AT_PHNUM")
    if at_phnum is None:
        missing.append("AT_PHNUM")
    elif at_phnum == executable["e_phnum"]:
        matched.append("AT_PHNUM == e_phnum")

    return matched, missing


def _derive_executable_offset(
    vector: AuxvVector, executable: ELFFile
) -> LoadOffsetEvidence:
    # The AUXV word size belongs to the core's target ABI. A main program
    # built for a different class/endianness cannot be meaningfully compared.
    if (
        executable.elfclass != vector.elfclass
        or executable.little_endian != vector.little_endian
    ):
        return LoadOffsetEvidence(
            offset=None,
            kind="executable",
            note=(
                "main program ELF ABI "
                f"(ELFCLASS{executable.elfclass}) does not match the core "
                f"(ELFCLASS{vector.elfclass})"
            ),
        )

    if not executable.num_segments():
        return LoadOffsetEvidence(
            offset=None,
            kind="executable",
            missing=("executable PT_LOAD",),
            note="main program ELF has no program headers",
        )

    phdr_link_vaddr, link_entry = _executable_phdr_info(executable)

    estimates: list[tuple[str, int]] = []
    missing: list[str] = []

    # Estimate 1: runtime AT_PHDR minus the PT_PHDR vaddr baked into the ELF.
    at_phdr = vector.value("AT_PHDR")
    if at_phdr is None:
        missing.append("AT_PHDR")
    elif phdr_link_vaddr is None:
        missing.append("executable PT_PHDR")
    else:
        estimates.append(("AT_PHDR - PT_PHDR.vaddr", at_phdr - phdr_link_vaddr))

    # Estimate 2: runtime AT_ENTRY minus the ELF's link-time e_entry.
    at_entry = vector.value("AT_ENTRY")
    if at_entry is None:
        missing.append("AT_ENTRY")
    elif link_entry == 0:
        missing.append("ELF e_entry")
    else:
        estimates.append(("AT_ENTRY - e_entry", at_entry - link_entry))

    matched, check_missing = _check_phdr_consistency(vector, executable)
    missing.extend(check_missing)

    if not estimates:
        return LoadOffsetEvidence(
            offset=None,
            kind="executable",
            missing=tuple(missing),
            note="insufficient AUXV fields to derive an offset",
        )

    # A single estimate cannot confirm anything: there is no independent field
    # left to agree with it, so the offset stays unknown.
    if len(estimates) < 2:
        return LoadOffsetEvidence(
            offset=None,
            kind="executable",
            missing=tuple(missing),
            note=(
                "only one offset estimate available; need mutually "
                "consistent AT_PHDR and AT_ENTRY to confirm"
            ),
        )

    # An offset is only confirmed when every independent estimate is equal.
    values = {value for _name, value in estimates}
    if len(values) != 1:
        return LoadOffsetEvidence(
            offset=None,
            kind="executable",
            conflicts=tuple(estimates),
            missing=tuple(missing),
            note="independent offset estimates disagree",
        )

    offset = values.pop()
    return LoadOffsetEvidence(
        offset=offset,
        kind="executable",
        sources=tuple(name for name, _ in estimates) + tuple(matched),
        missing=tuple(missing),
    )
