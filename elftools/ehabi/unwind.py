# -------------------------------------------------------------------------------
# elftools: ehabi/unwind.py
#
# Restricted evaluation of ARM EHABI compact unwind bytecode.
#
# This code is in the public domain
# -------------------------------------------------------------------------------
from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, NamedTuple

from .decoder import EHABIBytecodeDecoder, EHABIInstruction

if TYPE_CHECKING:
    from .ehabiinfo import EHABIAddressLookup, EHABIEntry


# Decoder-style canonical names for r0..r15.
GPR_NAMES = ("r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
             "r8", "r9", "r10", "fp", "ip", "sp", "lr", "pc")

_REGISTER_ALIASES = {
    "r11": "fp",
    "r12": "ip",
    "r13": "sp",
    "r14": "lr",
    "r15": "pc",
}


class EHABIBytesMemory:
    """ Adapter for caller-provided raw memory bytes.

        The caller states the byte order and the address of the first byte.
        Reads outside the buffer return None instead of guessing zeroes.
    """

    def __init__(self, data: bytes | bytearray | memoryview, base: int = 0,
                 little_endian: bool = True) -> None:
        self._data = memoryview(data)
        self._base = base
        self._byteorder = 'little' if little_endian else 'big'

    def read_word(self, address: int) -> int | None:
        return self._read(address, 4)

    def read_double(self, address: int) -> int | None:
        return self._read(address, 8)

    def _read(self, address: int, size: int) -> int | None:
        offset = address - self._base
        if offset < 0 or size > len(self._data) - offset:
            return None
        return int.from_bytes(self._data[offset:offset + size], self._byteorder)


class EHABIStep(NamedTuple):
    """ One evaluated compact instruction.

        bytecode and file_offsets are parallel: file_offsets[i] is the file
        offset of bytecode[i] when the entry came from a real .ARM.exidx or
        .ARM.extab section, otherwise None.

        registers_written maps canonical register names to the loaded value,
        or None when the required memory was not supplied.
    """

    index: int
    offset: int
    bytecode: tuple[int, ...]
    file_offsets: tuple[int | None, ...]
    mnemonic: str
    kind: str
    action: str
    vsp_before: int | None
    vsp_after: int | None
    registers_written: dict[str, int | None]
    note: str | None = None


class EHABIUnwindResult:
    """ Outcome of resolving an address and interpreting compact bytecode.

        status:
            'completed'          the supported bytecode ran to finish/pc.
            'refused'            the bytecode contains "refuse to unwind".
            'cannot_unwind'      the exidx entry is EXIDX_CANTUNWIND.
            'generic_personality' an .ARM.extab generic personality was found,
                                 but it was not executed or interpreted.
            'corrupt'            the exidx/extab entry is unusable.
            'truncated'          the bytecode is cut short by its container.
            'unsupported'        a compact operation without modelled stack
                                 semantics (spare/reserved) was reached.
            'incomplete'         finished without a terminal op, or lacked
                                 the initial VSP/register needed to continue.
            'not_covered'        no entry covers the address.
            'ambiguous'          the table cannot support a definite answer.
            'unknown_extent'     the last function has no known end.
            'empty_extent'       the mapped entry describes an empty range.
            'invalid'            the address was not a non-negative integer.

        complete is True only when the compact bytecode was fully interpreted
        with every required input available. It says nothing about frames
        beyond the one described by this entry.

        definite is True for the narrower set of results that can be used as a
        definite unwind basis (completed, refused or cannot_unwind). No
        call-stack frames are synthesized in any case.

        table_unwindable mirrors the entry flag (False for EXIDX_CANTUNWIND)
        and is independent of whether the caller supplied enough material.
        personality_executed is always False: the sample is data, not code.
    """

    def __init__(
        self,
        status: str,
        reason: str,
        *,
        lookup: EHABIAddressLookup | None = None,
        entry: EHABIEntry | None = None,
        address: int | None = None,
        initial_vsp: int | None = None,
        final_vsp: int | None = None,
        registers_after: dict[str, int] | None = None,
        changed_registers: dict[str, int | None] | None = None,
        steps: list[EHABIStep] | None = None,
        missing: list[str] | None = None,
        tail: tuple[int, ...] = (),
        complete: bool = False,
        definite: bool = False,
        personality: int | None = None,
        personality_executed: bool = False,
        unwindable: bool | None = None,
        table_unwindable: bool | None = None,
    ) -> None:
        self.status = status
        self.reason = reason
        self.lookup = lookup
        self.entry = entry
        self.address = address
        self.initial_vsp = initial_vsp
        self.final_vsp = final_vsp
        self.registers_after = registers_after or {}
        self.changed_registers = changed_registers or {}
        self.steps = steps or []
        self.missing = missing or []
        self.tail = tail
        self.complete = complete
        self.definite = definite
        self.personality = personality
        self.personality_executed = personality_executed
        self.unwindable = unwindable
        self.table_unwindable = table_unwindable

    def __repr__(self) -> str:
        return (
            f"<EHABIUnwindResult status={self.status!r}"
            f" address={'' if self.address is None else f'{self.address:#x}'}"
            f" steps={len(self.steps)} vsp={self.initial_vsp!r}->{self.final_vsp!r}"
            f" complete={self.complete} definite={self.definite}>"
        )


def make_no_entry_result(lookup: EHABIAddressLookup, registers: Any) -> EHABIUnwindResult:
    """ Build a result for an address that did not resolve to an entry.
    """
    initial = _canonical_registers(registers)
    vsp = initial.get('sp')
    return EHABIUnwindResult(
        lookup.status,
        lookup.reason,
        lookup=lookup,
        address=lookup.address,
        initial_vsp=vsp,
        final_vsp=vsp,
        registers_after=initial,
        complete=False,
        definite=False,
    )


def unwind_entry(
    entry: EHABIEntry,
    registers: Any,
    memory: Any,
    *,
    address: int | None = None,
    lookup: EHABIAddressLookup | None = None,
    vsp: int | None = None,
    max_steps: int | None = None,
) -> EHABIUnwindResult:
    """ Interpret one EHABI entry using caller-provided registers and memory.

        Never calls the personality routine found in the sample. A generic
        personality produces evidence only.
    """
    from .ehabiinfo import CannotUnwindEHABIEntry, CorruptEHABIEntry, GenericEHABIEntry

    initial = _canonical_registers(registers)
    initial_vsp = vsp if vsp is not None else initial.get('sp')
    common = dict(
        lookup=lookup,
        entry=entry,
        address=address,
        initial_vsp=initial_vsp,
        final_vsp=initial_vsp,
        registers_after=initial,
        personality=entry.personality,
        table_unwindable=entry.unwindable,
    )

    if isinstance(entry, CorruptEHABIEntry):
        return EHABIUnwindResult('corrupt', entry.reason, **common)

    if isinstance(entry, CannotUnwindEHABIEntry):
        return EHABIUnwindResult(
            'cannot_unwind',
            'the .ARM.exidx entry is EXIDX_CANTUNWIND',
            unwindable=False,
            personality_executed=False,
            definite=True,
            **common)

    if isinstance(entry, GenericEHABIEntry):
        return EHABIUnwindResult(
            'generic_personality',
            f'generic personality at {entry.personality:#x} was not executed; '
            'the sample is not trusted as code',
            personality_executed=False,
            **common)

    if entry.bytecode_array is None:
        return EHABIUnwindResult(
            'incomplete', 'entry has no compact bytecode to interpret',
            personality_executed=False, **common)

    decoder = EHABIBytecodeDecoder(entry.bytecode_array)

    if entry.truncated or decoder.truncated:
        partial_steps, partial_missing = _partial_decoded_steps(entry, decoder)
        reasons = []
        if entry.truncation_reason:
            reasons.append(entry.truncation_reason)
        if decoder.truncation_reason:
            reasons.append(decoder.truncation_reason)
        reason = '; '.join(reasons) or 'compact bytecode is truncated'
        return EHABIUnwindResult(
            'truncated',
            reason,
            steps=partial_steps,
            missing=[reason, *partial_missing],
            personality_executed=False,
            **common)

    steps: list[EHABIStep] = []
    missing: list[str] = []
    changed: dict[str, int | None] = {}
    current = dict(initial)
    current_vsp = initial_vsp
    limit = len(decoder.instructions) if max_steps is None else max_steps
    if limit < 0:
        limit = 0

    status = 'completed'
    reason = 'compact bytecode reached finish'
    tail: tuple[int, ...] = ()
    terminal_offset: int | None = None
    executed = 0

    for ordinal, instruction in enumerate(decoder.instructions):
        if instruction.kind == 'truncated':
            status = 'truncated'
            reason = 'compact bytecode ends inside an instruction'
            missing.append('complete trailing compact instruction')
            terminal_offset = instruction.offset
            break
        if executed >= limit:
            status = 'incomplete'
            reason = f'max_steps={limit} reached before a terminal operation'
            missing.append('remaining bytecode not interpreted because max_steps was reached')
            terminal_offset = instruction.offset
            break
        executed += 1

        file_offsets = _instruction_file_offsets(entry, instruction)
        vsp_before = current_vsp
        action = 'applied'
        note = None
        written: dict[str, int | None] = {}

        if instruction.kind in ('vsp_plus', 'vsp_minus', 'vsp_plus_uleb'):
            if current_vsp is None:
                status = 'incomplete'
                reason = 'VSP is not known: no initial sp/r13 was supplied yet'
                missing.append('initial VSP (sp/r13)')
                action = 'missing_vsp'
                current_vsp = None
                steps.append(EHABIStep(
                    index=ordinal, offset=instruction.offset,
                    bytecode=instruction.bytecode, file_offsets=file_offsets,
                    mnemonic=instruction.mnemonic, kind=instruction.kind,
                    action=action, vsp_before=None, vsp_after=None,
                    registers_written={}, note=reason))
                terminal_offset = instruction.offset + len(instruction.bytecode)
                tail = tuple(entry.bytecode_array[terminal_offset:])
                break
            amount = instruction.operands['amount']
            if instruction.kind == 'vsp_minus':
                current_vsp -= amount
            else:
                current_vsp += amount
            note = f'VSP {"-" if instruction.kind == "vsp_minus" else "+"}{amount}'

        elif instruction.kind == 'vsp_from_reg':
            reg = GPR_NAMES[instruction.operands['register']]
            value = current.get(reg)
            if value is None:
                status = 'incomplete'
                reason = f'cannot set VSP from {reg}: the caller did not supply that register'
                missing.append(f'register {reg} required by "vsp = {reg}"')
                action = 'missing_register'
                current_vsp = None
            else:
                current_vsp = value
                note = f'VSP copied from {reg}'

        elif instruction.kind in ('pop_gpr', 'pop_gpr_low', 'pop_range_gpr',
                              'pop_vfp'):
            if current_vsp is None:
                status = 'incomplete'
                reason = 'VSP is not known: no initial sp/r13 was supplied yet'
                missing.append('initial VSP (sp/r13)')
                steps.append(EHABIStep(
                    index=ordinal, offset=instruction.offset,
                    bytecode=instruction.bytecode, file_offsets=file_offsets,
                    mnemonic=instruction.mnemonic, kind=instruction.kind,
                    action='missing_vsp', vsp_before=None, vsp_after=None,
                    registers_written={}, note=reason))
                terminal_offset = instruction.offset + len(instruction.bytecode)
                tail = tuple(entry.bytecode_array[terminal_offset:])
                break
            mask = instruction.operands['mask']
            is_double = instruction.kind == 'pop_vfp'
            if mask == 0:
                # 0x80 0x00 is decoded as "refuse to unwind" by the decoder;
                # an empty range mask never has stack effects to model.
                steps.append(EHABIStep(
                    index=ordinal, offset=instruction.offset,
                    bytecode=instruction.bytecode, file_offsets=file_offsets,
                    mnemonic=instruction.mnemonic, kind=instruction.kind,
                    action='unsupported', vsp_before=vsp_before,
                    vsp_after=current_vsp, registers_written={},
                    note='empty pop mask has no modelled register effect'))
                status = 'unsupported'
                reason = 'empty pop mask has no modelled register effect'
                missing.append('empty pop mask semantics')
                terminal_offset = instruction.offset + len(instruction.bytecode)
                tail = tuple(entry.bytecode_array[terminal_offset:])
                break
            width = 8 if is_double else 4
            if not is_double and mask & (1 << 13):
                # A GPR pop mask naming sp has no single well-defined stack
                # effect; refuse rather than invent one.
                status = 'unsupported'
                reason = 'GPR pop mask names sp (r13)'
                missing.append('semantics for a GPR pop that includes sp')
                steps.append(EHABIStep(
                    index=ordinal, offset=instruction.offset,
                    bytecode=instruction.bytecode, file_offsets=file_offsets,
                    mnemonic=instruction.mnemonic, kind=instruction.kind,
                    action='unsupported', vsp_before=vsp_before,
                    vsp_after=current_vsp, registers_written={},
                    note=reason))
                terminal_offset = instruction.offset + len(instruction.bytecode)
                tail = tuple(entry.bytecode_array[terminal_offset:])
                break
            for bit in range(32):
                if mask & (1 << bit) == 0:
                    continue
                if is_double:
                    name = f'd{bit}'
                elif bit < 16:
                    name = GPR_NAMES[bit]
                else:
                    # A two-byte GPR mask can only name r0..r15; refuse rather
                    # than silently dropping the bit.
                    status = 'unsupported'
                    reason = f'GPR pop mask bit {bit} is outside r0..r15'
                    action = 'unsupported'
                    terminal_offset = instruction.offset + len(instruction.bytecode)
                    tail = tuple(entry.bytecode_array[terminal_offset:])
                    missing.append(f'mask bit {bit}')
                    break
                address_to_read = current_vsp
                value, why = _read_memory(memory, address_to_read, width)
                written[name] = value
                changed[name] = value
                current[name] = value if value is not None else None
                if value is None:
                    missing.append(
                        f'memory at {address_to_read:#x} ({width} bytes) for {name}: {why}')
                    if status == 'completed':
                        status = 'incomplete'
                        reason = 'the stack memory needed to read popped registers was not supplied'
                    action = 'missing_memory'
                current_vsp += width

        elif instruction.kind == 'finish':
            action = 'terminal'
            note = 'unwind bytecode ends here'
            terminal_offset = instruction.offset + len(instruction.bytecode)

        elif instruction.kind == 'refuse_to_unwind':
            status = 'refused'
            reason = 'the bytecode explicitly refuses to unwind this function'
            action = 'terminal'
            terminal_offset = instruction.offset + len(instruction.bytecode)

        else:
            status = 'unsupported'
            reason = f'compact operation {instruction.kind!r} has no restricted stack model'
            action = 'unsupported'
            terminal_offset = instruction.offset + len(instruction.bytecode)
            required = (f'{instruction.mnemonic} at bytecode offset '
                        f'{instruction.offset}')
            if required not in missing:
                missing.append(required)

        steps.append(EHABIStep(
            index=ordinal,
            offset=instruction.offset,
            bytecode=instruction.bytecode,
            file_offsets=file_offsets,
            mnemonic=instruction.mnemonic,
            kind=instruction.kind,
            action=action,
            vsp_before=vsp_before,
            vsp_after=current_vsp,
            registers_written=written,
            note=note,
        ))

        if terminal_offset is not None:
            tail = tuple(entry.bytecode_array[terminal_offset:])
            break
        if current_vsp is None:
            terminal_offset = instruction.offset + len(instruction.bytecode)
            tail = tuple(entry.bytecode_array[terminal_offset:])
            break

    else:
        # Ran out of instructions without finish/pc/refuse.
        if status == 'completed':
            popped_pc = any(step.kind in ('pop_gpr', 'pop_gpr_low',
                                          'pop_range_gpr')
                            and 'pc' in step.registers_written
                            for step in steps)
            if popped_pc:
                reason = 'compact bytecode restored pc by pop'
            else:
                status = 'incomplete'
                reason = 'compact bytecode ended without a terminal operation (finish or pc restore)'
                missing.append('terminal compact operation (finish or pc in pop mask)')

    complete = status in ('completed', 'refused')
    definite = status in ('completed', 'refused', 'cannot_unwind')
    unwindable = True if status == 'completed' else (
        False if status in ('refused', 'cannot_unwind') else None)

    return EHABIUnwindResult(
        status,
        reason,
        initial_vsp=initial_vsp,
        final_vsp=current_vsp,
        registers_after={k: v for k, v in current.items() if v is not None},
        changed_registers=changed,
        steps=steps,
        missing=missing,
        tail=tail,
        complete=complete,
        definite=definite,
        personality=entry.personality,
        personality_executed=False,
        unwindable=unwindable,
        table_unwindable=entry.unwindable,
        lookup=lookup,
        entry=entry,
        address=address,
    )


def _partial_decoded_steps(entry: EHABIEntry, decoder: EHABIBytecodeDecoder) -> tuple[list[EHABIStep], list[str]]:
    """ Decode as much as possible and report the trailing partial bytes.

        These steps are provenance only: no register or VSP effect is applied,
        because the bytecode could not be interpreted completely.
    """
    steps = []
    for ordinal, instruction in enumerate(decoder.instructions):
        if instruction.kind == 'truncated':
            note = (decoder.truncation_reason
                    or 'the bytecode ends inside this instruction')
        else:
            note = 'decoded for provenance only; evaluation did not run'
        steps.append(EHABIStep(
            index=ordinal,
            offset=instruction.offset,
            bytecode=instruction.bytecode,
            file_offsets=_instruction_file_offsets(entry, instruction),
            mnemonic=instruction.mnemonic,
            kind=instruction.kind,
            action='decoded_not_applied',
            vsp_before=None,
            vsp_after=None,
            registers_written={},
            note=note,
        ))
    missing = []
    if decoder.truncated:
        missing.append(decoder.truncation_reason or 'truncated compact instruction')
    return steps, missing


def _canonical_registers(registers: Any) -> dict[str, int]:
    """ Read the caller's registers without mutating them.

        Accepts a mapping or an object with get_register(name). Unknown names
        are ignored; aliases r11..r15 are folded to fp/ip/sp/lr/pc.
    """
    result: dict[str, int] = {}
    for name in GPR_NAMES:
        value = None
        getter = getattr(registers, 'get_register', None)
        if callable(getter):
            try:
                value = getter(name)
            except (KeyError, LookupError):
                value = None
        elif isinstance(registers, Mapping):
            value = registers.get(name)
        if value is None:
            for alias, canonical in _REGISTER_ALIASES.items():
                if canonical == name:
                    if callable(getter):
                        try:
                            value = getter(alias)
                        except (KeyError, LookupError):
                            value = None
                    elif isinstance(registers, Mapping):
                        value = registers.get(alias)
                    if value is not None:
                        break
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            result[name] = value
    return result


def _read_memory(memory: Any, address: int, size: int) -> tuple[int | None, str]:
    """ Read one integer value from caller-provided memory.

        Accepted shapes:
          * object with read_word(address) (size 4) or read_double(address)
            (size 8);
          * object with read(address, size) returning an integer;
          * mapping from address to integer.
        Nothing is fabricated: a missing value is reported to the caller.
    """
    if memory is None:
        return None, 'no memory object was supplied'

    reader = getattr(memory, 'read_word' if size == 4 else 'read_double', None)
    if callable(reader):
        try:
            value = reader(address)
        except (KeyError, LookupError):
            return None, 'the supplied memory has no value at this address'
        if value is None:
            return None, 'the supplied memory reports this range as unavailable'
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return None, 'the supplied memory returned a non-integer value'
        return value, 'ok'

    generic = getattr(memory, 'read', None)
    if callable(generic):
        try:
            value = generic(address, size)
        except (KeyError, LookupError):
            return None, 'the supplied memory has no value at this address'
        if value is None:
            return None, 'the supplied memory reports this range as unavailable'
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return None, 'the supplied memory returned a non-integer value'
        return value, 'ok'

    if isinstance(memory, Mapping):
        try:
            value = memory[address]
        except KeyError:
            return None, 'the supplied mapping has no value at this address'
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return None, 'the supplied mapping value is not a non-negative integer'
        return value, 'ok'

    return None, 'the memory object does not implement a supported read method'


def _instruction_file_offsets(
    entry: EHABIEntry,
    instruction: EHABIInstruction,
) -> tuple[int | None, ...]:
    if entry.bytecode_file_offsets is None:
        return tuple(None for _ in instruction.bytecode)
    start = instruction.offset
    end = start + len(instruction.bytecode)
    offsets = entry.bytecode_file_offsets[start:end]
    if len(offsets) != len(instruction.bytecode):
        return tuple(None for _ in instruction.bytecode)
    return tuple(offsets)
