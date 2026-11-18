#-------------------------------------------------------------------------------
# elftools: elf/prstatus.py
#
# Interpretation of NT_PRSTATUS notes in ET_CORE files.
#
# A core dump records one NT_PRSTATUS note per thread. Each descriptor starts
# with an ABI-independent status header (elf_siginfo, pr_cursig, the pending
# and held signal sets, the pr_*id fields and four timevals) followed by
# pr_reg, an architecture-specific register block whose layout is defined by
# the *target* ABI, never by the host running pyelftools.
#
# This module decodes the layouts pyelftools knows about, keeps every raw
# register word and the exact note range, and refuses to invent thread state.
# Notes that cannot be associated with a thread, registers that are
# truncated, and architectures without a known layout all retain their raw
# material instead of producing a partially-populated thread.
#
# This code is in the public domain
#-------------------------------------------------------------------------------
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .enums import ENUM_CORE_NOTE_N_TYPE

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from .elffile import ELFFile
    from .segments import NoteSegment


# The NT_PRSTATUS note type is owned by "CORE". The numeric value is used
# here so a note stays recognizable even when its owner name could not be
# parsed or was spelled differently.
NT_PRSTATUS = 1

# Note types whose contents describe thread state and therefore must not be
# glued onto a thread merely because they follow its NT_PRSTATUS note:
#   NT_FPREGSET (2), NT_X86_XSTATE (0x202), NT_ARM_VFP (0x400),
#   NT_ARM_TLS (0x401), NT_ARM_HW_BREAK (0x402), NT_ARM_HW_WATCH (0x403),
#   NT_ARM_SVE (0x405), NT_ARM_PAC_MASK (0x406), NT_ARM_PACA_KEYS (0x407),
#   NT_ARM_PACG_KEYS (0x408), NT_ARM_TAGGED_ADDR_CTRL (0x409),
#   NT_ARM_PAC_ENABLED_KEYS (0x40a), NT_ARM_SSVE (0x40b), NT_ARM_ZA (0x40c),
#   NT_ARM_ZT (0x40d), NT_ARM_FPMR (0x40e).
# A plain ELF core carries no thread id in these notes, so they stay
# unassociated rather than being attached by position.
_THREAD_SCOPED_TYPES: frozenset[int] = frozenset({
    2, 0x202,
    0x400, 0x401, 0x402, 0x403, 0x404, 0x405, 0x406, 0x407, 0x408,
    0x409, 0x40a, 0x40b, 0x40c, 0x40d, 0x40e, 0x40f,
})
# The same types as names the CORE enum decodes them to, so a recognized
# thread-scoped note is handled whether its type is a name or a number.
THREAD_SCOPED_NOTE_TYPES: frozenset[str | int] = _THREAD_SCOPED_TYPES | {
    name for name, value in ENUM_CORE_NOTE_N_TYPE.items()
    if name != '_default_' and value in _THREAD_SCOPED_TYPES
}

_PRSTATUS_HEADER_32 = 72
_PRSTATUS_HEADER_64 = 112
_PR_FPVALID_SIZE = 4


@dataclass(frozen=True)
class RegisterLayout:
    """The pr_reg block of one target ABI.

    names has one entry per register slot. A name of None marks a slot that
    exists in the ABI's gregset but has no single register meaning (padding
    or an unspecified word); its raw value is still preserved.
    """

    machine: str
    label: str
    elfclass: int
    header_size: int
    word_size: int
    names: tuple[str | None, ...]

    @property
    def register_count(self) -> int:
        return len(self.names)

    @property
    def register_block_size(self) -> int:
        return self.register_count * self.word_size

    @property
    def payload_size(self) -> int:
        """Size through the trailing pr_fpvalid int (padding excluded)."""
        return self.header_size + self.register_block_size + _PR_FPVALID_SIZE

    @property
    def descriptor_size(self) -> int:
        """Expected elf_prstatus size, aligned to the register word size.

        A kernel writes this many bytes; shorter descriptors are treated as
        a layout that was not fully captured. Trailing alignment padding
        carries no information, so complete decoding only needs
        payload_size bytes.
        """
        return _align(self.payload_size, self.word_size)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


# i386: include/uapi/asm-generic/elfcore.h together with
# arch/x86/include/asm/user_32.h; pr_reg is struct user_regs_struct (17 words).
_I386_NAMES = (
    'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'eax', 'ds', 'es', 'fs', 'gs',
    'orig_eax', 'eip', 'cs', 'eflags', 'esp', 'ss',
)

# x86-64: include/uapi/asm-generic/elfcore.h together with
# arch/x86/include/asm/user_64.h; pr_reg is struct user_regs_struct (27 words).
_X86_64_NAMES = (
    'r15', 'r14', 'r13', 'r12', 'rbp', 'rbx', 'r11', 'r10', 'r9', 'r8',
    'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'orig_rax', 'rip', 'cs', 'eflags',
    'rsp', 'ss', 'fs_base', 'gs_base', 'ds', 'es', 'fs', 'gs',
)

# ARM (AArch32): arch/arm/include/uapi/asm/ptrace.h; elf_gregset_t is
# struct pt_regs with the 18-word uregs array.
_ARM_NAMES = (
    'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
    'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc',
    'cpsr', 'orig_r0',
)

# AArch64: arch/arm64/include/uapi/asm/ptrace.h; elf_gregset_t is
# struct user_pt_regs (x0..x30, sp, pc, pstate).
_AARCH64_NAMES = (
    'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7',
    'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15',
    'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23',
    'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30', 'sp',
    'pc', 'pstate',
)

# RISC-V: arch/riscv/include/uapi/asm/ptrace.h; elf_gregset_t is
# struct user_regs_struct (pc, ra, sp, gp, tp and x5..x31 under ABI names).
_RISCV_NAMES = (
    'pc', 'ra', 'sp', 'gp', 'tp', 't0', 't1', 't2',
    's0', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5',
    'a6', 'a7', 's2', 's3', 's4', 's5', 's6', 's7',
    's8', 's9', 's10', 's11', 't3', 't4', 't5', 't6',
)


_REGISTER_LAYOUTS: dict[tuple[str, int], RegisterLayout] = {
    ('EM_386', 32): RegisterLayout(
        machine='EM_386', label='i386', elfclass=32,
        header_size=_PRSTATUS_HEADER_32, word_size=4, names=_I386_NAMES),
    ('EM_X86_64', 64): RegisterLayout(
        machine='EM_X86_64', label='x86-64', elfclass=64,
        header_size=_PRSTATUS_HEADER_64, word_size=8, names=_X86_64_NAMES),
    ('EM_ARM', 32): RegisterLayout(
        machine='EM_ARM', label='ARM', elfclass=32,
        header_size=_PRSTATUS_HEADER_32, word_size=4, names=_ARM_NAMES),
    ('EM_AARCH64', 64): RegisterLayout(
        machine='EM_AARCH64', label='AArch64', elfclass=64,
        header_size=_PRSTATUS_HEADER_64, word_size=8, names=_AARCH64_NAMES),
    ('EM_RISCV', 32): RegisterLayout(
        machine='EM_RISCV', label='RISC-V 32', elfclass=32,
        header_size=_PRSTATUS_HEADER_32, word_size=4, names=_RISCV_NAMES),
    ('EM_RISCV', 64): RegisterLayout(
        machine='EM_RISCV', label='RISC-V 64', elfclass=64,
        header_size=_PRSTATUS_HEADER_64, word_size=8, names=_RISCV_NAMES),
}


def register_layout_for_machine(
    machine: str | int,
    elfclass: int,
) -> RegisterLayout | None:
    """The pr_reg layout for one machine/ELF class, or None if unknown."""
    if not isinstance(machine, str):
        return None
    return _REGISTER_LAYOUTS.get((machine, elfclass))


def register_layout_for(elffile: ELFFile) -> RegisterLayout | None:
    """The pr_reg layout for elffile's target ABI, or None if unknown.

    The ELF class and byte order come from the core's own header, so a
    64-bit host cannot change how a 32-bit (or big-endian) target is read.
    """
    return register_layout_for_machine(elffile['e_machine'], elffile.elfclass)


@dataclass(frozen=True)
class NoteRange:
    """The exact file range occupied by one note, padding included."""

    offset: int
    size: int

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass(frozen=True)
class RegisterWord:
    """One raw word of pr_reg, with the layout-provided name if any."""

    index: int
    name: str | None
    raw: bytes
    value: int


@dataclass(frozen=True)
class PrstatusHeader:
    """The ABI-independent status header of an NT_PRSTATUS descriptor.

    Decoding this header only needs the target ELF class and byte order; it
    does not imply that pr_reg was understood. Thread and process ids are
    the values recorded in the target, so they remain usable as evidence
    even when the register area is truncated or its architecture is unknown.
    """

    elfclass: int
    little_endian: bool
    pr_cursig: int
    pr_sigpend: int
    pr_sighold: int
    pid: int
    ppid: int
    pgrp: int
    sid: int


def parse_prstatus_header(
    descdata: bytes,
    elfclass: int,
    little_endian: bool,
) -> PrstatusHeader | None:
    """Decode the status header, or None if the descriptor is too short.

    This never looks at pr_reg, so it is safe to use for notes whose
    register layout is unknown: it can still recover the recorded thread id.
    """
    header_size = _PRSTATUS_HEADER_32 if elfclass == 32 else _PRSTATUS_HEADER_64
    if len(descdata) < header_size:
        return None

    endian = '<' if little_endian else '>'
    if elfclass == 32:
        # elf_siginfo (3 int), short pr_cursig, 2 bytes padding, two
        # unsigned longs, four pid_t, then four 32-bit timevals.
        (pr_signo, pr_code, pr_errno,
         pr_cursig, pr_sigpend, pr_sighold,
         pid, ppid, pgrp, sid) = struct.unpack_from(
            endian + '3ih2xIIiiii', descdata, 0)
    else:
        # elf_siginfo (3 int), short pr_cursig, padding to 8, two 64-bit
        # unsigned longs, four pid_t, then four 16-byte timevals. pr_pid
        # and friends are still 32-bit values.
        (pr_signo, pr_code, pr_errno,
         pr_cursig, pr_sigpend, pr_sighold,
         pid, ppid, pgrp, sid) = struct.unpack_from(
            endian + '3ih2xQQiiii', descdata, 0)

    return PrstatusHeader(
        elfclass=elfclass,
        little_endian=little_endian,
        pr_cursig=pr_cursig,
        pr_sigpend=pr_sigpend,
        pr_sighold=pr_sighold,
        pid=pid,
        ppid=ppid,
        pgrp=pgrp,
        sid=sid,
    )


@dataclass(frozen=True)
class PrstatusEvidence:
    """Decoded NT_PRSTATUS evidence for a known, complete target ABI layout.

    tid is the target thread identifier taken from pr_pid. Registers holds
    every raw pr_reg word in file order, including unnamed slots, so the
    original register material is never replaced by a name-keyed view.
    raw_descdata preserves the entire descriptor; note_range locates the
    note (header, name, descriptor and padding) in the core file.
    """

    note_range: NoteRange
    machine: str
    label: str
    elfclass: int
    little_endian: bool
    header: PrstatusHeader
    registers: tuple[RegisterWord, ...]
    pr_fpvalid: int | None
    raw_pr_reg: bytes
    raw_descdata: bytes
    complete: bool = True

    @property
    def fpvalid(self) -> bool:
        """Whether the target reported a saved FP register set.

        Only meaningful for a complete status; an incomplete descriptor
        leaves this False rather than assuming the missing word was zero.
        """
        return self.pr_fpvalid == 1

    @property
    def tid(self) -> int:
        return self.header.pid

    @property
    def pid(self) -> int:
        return self.header.pid

    @property
    def register_count(self) -> int:
        return len(self.registers)

    def register(self, name: str) -> int | None:
        """The value of the last pr_reg word called name, or None."""
        result = None
        for word in self.registers:
            if word.name == name:
                result = word.value
        return result

    def register_raw(self, name: str) -> bytes | None:
        """The raw bytes of the last pr_reg word called name, or None."""
        result = None
        for word in self.registers:
            if word.name == name:
                result = word.raw
        return result

    def register_map(self) -> dict[str, int]:
        """All named registers, keyed by ABI name."""
        return {w.name: w.value for w in self.registers if w.name is not None}


def _register_block(
    descdata: bytes,
    layout: RegisterLayout,
    little_endian: bool,
) -> tuple[tuple[RegisterWord, ...], int]:
    """Decode the complete pr_reg block and the pr_fpvalid int."""
    word_format = '<' if little_endian else '>'
    word_format += 'I' if layout.word_size == 4 else 'Q'
    registers: list[RegisterWord] = []
    off = layout.header_size
    for index, name in enumerate(layout.names):
        raw = descdata[off:off + layout.word_size]
        registers.append(RegisterWord(
            index=index,
            name=name,
            raw=raw,
            value=struct.unpack(word_format, raw)[0],
        ))
        off += layout.word_size
    pr_fpvalid = struct.unpack_from(
        ('<' if little_endian else '>') + 'i',
        descdata,
        layout.header_size + layout.register_block_size,
    )[0]
    return tuple(registers), pr_fpvalid


def decode_prstatus_partial(
    descdata: bytes,
    layout: RegisterLayout,
    little_endian: bool,
    note_range: NoteRange,
) -> PrstatusEvidence | None:
    """Decode a descriptor whose pr_reg block is cut short.

    Every whole register word that is present is decoded and preserved;
    words past the truncated end are simply absent, never filled with zero.
    pr_fpvalid is only available when the full layout was captured, so it
    is None otherwise. Returns None when no complete register word exists.
    """
    if len(descdata) <= layout.header_size:
        return None
    header = parse_prstatus_header(descdata, layout.elfclass, little_endian)
    if header is None:
        return None

    word_format = '<' if little_endian else '>'
    word_format += 'I' if layout.word_size == 4 else 'Q'
    available = (len(descdata) - layout.header_size) // layout.word_size
    usable = min(available, layout.register_count)
    if usable == 0:
        # No complete register word survived; there is no register evidence.
        return None
    registers: list[RegisterWord] = []
    for index, name in enumerate(layout.names[:usable]):
        off = layout.header_size + index * layout.word_size
        raw = descdata[off:off + layout.word_size]
        registers.append(RegisterWord(
            index=index,
            name=name,
            raw=raw,
            value=struct.unpack(word_format, raw)[0],
        ))
    raw_pr_reg = descdata[
        layout.header_size:layout.header_size + usable * layout.word_size]

    pr_fpvalid = None
    if len(descdata) >= layout.payload_size:
        pr_fpvalid = struct.unpack_from(
            ('<' if little_endian else '>') + 'i',
            descdata,
            layout.header_size + layout.register_block_size,
        )[0]

    return PrstatusEvidence(
        note_range=note_range,
        machine=layout.machine,
        label=layout.label,
        elfclass=layout.elfclass,
        little_endian=little_endian,
        header=header,
        registers=tuple(registers),
        pr_fpvalid=pr_fpvalid,
        raw_pr_reg=bytes(raw_pr_reg),
        raw_descdata=bytes(descdata),
        complete=False,
    )


def decode_prstatus(
    descdata: bytes,
    layout: RegisterLayout,
    little_endian: bool,
    note_range: NoteRange,
) -> PrstatusEvidence | None:
    """Decode one NT_PRSTATUS descriptor, or None when it is incomplete.

    A descriptor that does not hold the complete status header, the complete
    pr_reg block and the trailing pr_fpvalid int is not partially decoded:
    the caller keeps the raw note instead, so a truncated register area can
    never look like a thread whose missing registers happen to be zero.
    """
    header = parse_prstatus_header(descdata, layout.elfclass, little_endian)
    if header is None:
        return None
    if len(descdata) < layout.payload_size:
        return decode_prstatus_partial(
            descdata, layout, little_endian, note_range)

    registers, pr_fpvalid = _register_block(descdata, layout, little_endian)
    return PrstatusEvidence(
        note_range=note_range,
        machine=layout.machine,
        label=layout.label,
        elfclass=layout.elfclass,
        little_endian=little_endian,
        header=header,
        registers=registers,
        pr_fpvalid=pr_fpvalid,
        raw_pr_reg=bytes(
            descdata[layout.header_size:
                     layout.header_size + layout.register_block_size]),
        raw_descdata=bytes(descdata),
        complete=True,
    )


@dataclass(frozen=True)
class ThreadNote:
    """A thread-related note kept as raw material, with its file range."""

    kind: str
    n_type: str | int
    n_name: str | None
    note_range: NoteRange
    descdata: bytes


@dataclass(frozen=True)
class ThreadRegisters:
    """Register evidence for one thread of a core file.

    status is present only when the thread's whole NT_PRSTATUS descriptor,
    including the complete pr_reg block, could be decoded for the target
    ABI. partial_registers carries the whole pr_reg words that survived a
    truncated descriptor (marked complete=False); missing words are never
    filled in and no complete status is claimed. attached_notes holds only
    notes explicitly bound to this thread by structure; a plain ELF core
    has no such binding for FP/XSTATE notes, so notes that merely follow a
    prstatus note in the file are never merged into it.
    """

    tid: int
    pid: int
    status: PrstatusEvidence | None
    raw_status: ThreadNote
    partial_registers: PrstatusEvidence | None = None
    attached_notes: tuple[ThreadNote, ...] = ()


@dataclass(frozen=True)
class CoreRegisters:
    """All thread register evidence found in one core file.

    threads contains one entry per NT_PRSTATUS note, in file order. A note
    with an unknown architecture or a truncated register area still yields
    a thread with a preserved raw_status (and a tid when the header was
    readable) but status=None: no register values are fabricated.

    unassociated_notes preserves thread-scoped notes (NT_FPREGSET, XSTATE,
    ARM/VFP and similar extensions) that are not explicitly bound to any
    thread. They never create a thread and are never merged by adjacency.
    """

    elfclass: int
    little_endian: bool
    machine: str | int
    threads: tuple[ThreadRegisters, ...]
    unassociated_notes: tuple[ThreadNote, ...]

    def thread(self, tid: int) -> ThreadRegisters | None:
        """The first thread whose recorded pr_pid is tid, or None."""
        for thread in self.threads:
            if thread.tid == tid:
                return thread
        return None

    def iter_threads(self) -> Iterator[ThreadRegisters]:
        return iter(self.threads)


def _thread_note(note: Mapping[str, Any]) -> ThreadNote:
    return ThreadNote(
        kind='prstatus' if note['n_type'] == 'NT_PRSTATUS' else 'auxiliary',
        n_type=note['n_type'],
        n_name=note.get('n_name'),
        note_range=NoteRange(note['n_offset'], note['n_size']),
        descdata=bytes(note['n_descdata']),
    )


def _note_is_core_prstatus(note: Mapping[str, Any], is_core: bool) -> bool:
    if not is_core:
        return False
    n_type = note.get('n_type')
    if n_type == 'NT_PRSTATUS':
        return True
    # An unrecognized owner name keeps its numeric type; NT_PRSTATUS is
    # still recognizable by value when the note says it belongs to CORE.
    return n_type == NT_PRSTATUS and note.get('n_name') == 'CORE'


def collect_core_registers(
    elffile: ELFFile,
    segment: NoteSegment | None = None,
) -> CoreRegisters:
    """Collect NT_PRSTATUS evidence from the core's note segments.

    Notes are never associated by file adjacency. Each NT_PRSTATUS note is
    decoded on its own and becomes one thread; other thread-scoped notes
    stay in unassociated_notes. When segment is given, only notes inside
    that PT_NOTE segment are considered. Data from a NoteSection is only
    consulted when the file has no note segments, so a section-backed copy
    of the same note cannot duplicate a thread.
    """
    is_core = elffile['e_type'] == 'ET_CORE'
    layout = register_layout_for(elffile)

    notes: list[Mapping[str, Any]] = []
    if segment is not None:
        notes.extend(segment.iter_notes())
    elif elffile.num_segments():
        for pt_note in elffile.iter_segments(type='PT_NOTE'):
            notes.extend(pt_note.iter_notes())
    else:
        for section in elffile.iter_sections(type='SHT_NOTE'):
            notes.extend(section.iter_notes())

    threads: list[ThreadRegisters] = []
    unassociated: list[ThreadNote] = []

    for note in notes:
        if _note_is_core_prstatus(note, is_core):
            descdata = bytes(note['n_descdata'])
            note_range = NoteRange(note['n_offset'], note['n_size'])
            raw = _thread_note(note)
            header = parse_prstatus_header(
                descdata, elffile.elfclass, elffile.little_endian)
            evidence = None
            if layout is not None:
                evidence = decode_prstatus(
                    descdata, layout, elffile.little_endian, note_range)
            if evidence is not None and evidence.complete:
                threads.append(ThreadRegisters(
                    tid=evidence.tid,
                    pid=evidence.pid,
                    status=evidence,
                    raw_status=raw,
                ))
            elif evidence is not None:
                # A truncated register area never yields a full status; the
                # whole words that were captured stay available separately.
                threads.append(ThreadRegisters(
                    tid=evidence.tid,
                    pid=evidence.pid,
                    status=None,
                    raw_status=raw,
                    partial_registers=evidence,
                ))
            elif header is not None:
                # The thread identity is real even when pr_reg is truncated
                # or its architecture is unsupported; registers are not.
                threads.append(ThreadRegisters(
                    tid=header.pid,
                    pid=header.pid,
                    status=None,
                    raw_status=raw,
                ))
            else:
                unassociated.append(raw)
            continue

        n_type = note.get('n_type')
        if (is_core and note.get('n_name') == 'CORE'
                and n_type in THREAD_SCOPED_NOTE_TYPES):
            unassociated.append(_thread_note(note))

    return CoreRegisters(
        elfclass=elffile.elfclass,
        little_endian=elffile.little_endian,
        machine=elffile['e_machine'],
        threads=tuple(threads),
        unassociated_notes=tuple(unassociated),
    )


def iter_thread_registers(elffile: ELFFile) -> Iterator[ThreadRegisters]:
    """Yield the register evidence of each thread in a core file."""
    return iter(collect_core_registers(elffile).threads)
