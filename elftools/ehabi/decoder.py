# -------------------------------------------------------------------------------
# elftools: ehabi/decoder.py
#
# Decode ARM exception handler bytecode.
#
# LeadroyaL (leadroyal@qq.com)
# This code is in the public domain
# -------------------------------------------------------------------------------
from __future__ import annotations

from collections.abc import Callable
from typing import NamedTuple


class EHABITruncatedBytecode(Exception):
    """ Raised internally when a compact instruction lacks an operand.
    """


class EHABIInstruction(NamedTuple):
    """ One decoded compact instruction.

        offset:
            Byte offset of the instruction inside the bytecode array.

        bytecode:
            Exactly the bytes this instruction consumed.

        mnemonic:
            Human-readable form, matching the historical printer output.

        kind:
            Machine-readable operation. GPR/VFP/iWMMX pops, VSP adjustments,
            and finish/refuse have an intentionally restricted, documented
            meaning; spare/reserved have none.

        operands:
            Normalized operands used by the restricted evaluator. Operations
            without modelled operands use an empty mapping.
    """

    offset: int
    bytecode: tuple[int, ...]
    mnemonic: str
    kind: str
    operands: dict[str, int]


class _Decoded(NamedTuple):
    mnemonic: str
    kind: str
    operands: dict[str, int]


class EHABIBytecodeDecoder:
    """ Decoder of a sequence of ARM exception handler abi bytecode.

        Reference:
        https://github.com/llvm/llvm-project/blob/master/llvm/tools/llvm-readobj/ARMEHABIPrinter.h
        https://developer.arm.com/documentation/ihi0038/b/

        Accessible attributes:

            instructions:
                EHABIInstruction array with the bytes consumed by each step.

            mnemonic_array:
                MnemonicItem array, kept for compatibility with callers that
                print the unwind table.

            truncated:
                True when an instruction was cut short by the end of the
                bytecode array.

            truncation_reason:
                Human-readable explanation of that truncation.

        Parameters:

            bytecode_array:
                Integer array, raw data of bytecode.
    """

    def __init__(self, bytecode_array: list[int]) -> None:
        self._bytecode_array = list(bytecode_array)
        self._index: int = 0
        self.instructions: list[EHABIInstruction] = []
        self.mnemonic_array: list[MnemonicItem] | None = None
        self.truncated: bool = False
        self.truncation_reason: str | None = None
        self._decode()

    def _remaining(self) -> int:
        return len(self._bytecode_array) - self._index

    def _require(self, count: int, what: str) -> None:
        if self._remaining() < count:
            raise EHABITruncatedBytecode(
                f'missing {what}: need {count} byte(s), have {self._remaining()}')

    def _decode(self) -> None:
        """ Decode bytecode array, put result into instructions/mnemonic_array.
        """
        self._index = 0
        self.instructions = []
        self.mnemonic_array = []
        self.truncated = False
        self.truncation_reason = None

        while self._index < len(self._bytecode_array):
            opcode = self._bytecode_array[self._index]
            for mask, value, handler in self.ring:
                if (opcode & mask) == value:
                    start_idx = self._index
                    try:
                        decoded = handler(self)
                    except EHABITruncatedBytecode as e:
                        self.truncated = True
                        self.truncation_reason = str(e)
                        # Record the bytes that were available for this
                        # instruction, including a lone leading opcode byte,
                        # so callers can point at the cut-off material.
                        self._index = len(self._bytecode_array)
                        self.instructions.append(EHABIInstruction(
                            offset=start_idx,
                            bytecode=tuple(self._bytecode_array[start_idx:]),
                            mnemonic='truncated',
                            kind='truncated',
                            operands={}))
                        break
                    self.instructions.append(EHABIInstruction(
                        offset=start_idx,
                        bytecode=tuple(self._bytecode_array[start_idx:self._index]),
                        mnemonic=decoded.mnemonic,
                        kind=decoded.kind,
                        operands=decoded.operands))
                    break
            else:
                # No recipe matched; consume the byte so decoding terminates.
                # This cannot happen with the current ring, but keep the
                # decoder bounded for malformed input.
                start_idx = self._index
                self._index += 1
                self.instructions.append(EHABIInstruction(
                    offset=start_idx,
                    bytecode=(opcode,),
                    mnemonic='spare',
                    kind='spare',
                    operands={}))

            if self.truncated:
                break

        self.mnemonic_array = [
            MnemonicItem(list(instruction.bytecode), instruction.mnemonic)
            for instruction in self.instructions]

    def _decode_00xxxxxx(self) -> _Decoded:
        #   SW.startLine() << format("0x%02X      ; vsp = vsp + %u\n", Opcode,
        #                            ((Opcode & 0x3f) << 2) + 4);
        self._require(1, 'compact 0x00 opcode')
        opcode = self._bytecode_array[self._index]
        self._index += 1
        amount = int(((opcode & 63) << 2) + 4)
        return _Decoded(f'vsp = vsp + {amount}', 'vsp_plus', {'amount': amount})

    def _decode_01xxxxxx(self) -> _Decoded:
        #   SW.startLine() << format("0x%02X      ; vsp = vsp - %u\n", Opcode,
        #                          ((Opcode & 0x3f) << 2) + 4);
        self._require(1, 'compact 0x40 opcode')
        opcode = self._bytecode_array[self._index]
        self._index += 1
        amount = int(((opcode & 63) << 2) + 4)
        return _Decoded(f'vsp = vsp - {amount}', 'vsp_minus', {'amount': amount})

    gpr_register_names = ("r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
                          "r8", "r9", "r10", "fp", "ip", "sp", "lr", "pc")

    def _calculate_range(self, start: int, count: int) -> int:
        return ((1 << (count + 1)) - 1) << start

    def _printGPR(self, gpr_mask: int) -> str:
        hits = [self.gpr_register_names[i] for i in range(32) if gpr_mask & (1 << i) != 0]
        return '{{{}}}'.format(', '.join(hits))

    def _print_registers(self, vfp_mask: int, prefix: str) -> str:
        hits = [prefix + str(i) for i in range(32) if vfp_mask & (1 << i) != 0]
        return '{{{}}}'.format(', '.join(hits))

    def _decode_1000iiii_iiiiiiii(self) -> _Decoded:
        self._require(2, 'two-byte GPR pop')
        op0 = self._bytecode_array[self._index]
        self._index += 1
        op1 = self._bytecode_array[self._index]
        self._index += 1
        #   uint16_t GPRMask = (Opcode1 << 4) | ((Opcode0 & 0x0f) << 12);
        gpr_mask = (op1 << 4) | ((op0 & 0x0f) << 12)
        if gpr_mask == 0:
            return _Decoded('refuse to unwind', 'refuse_to_unwind', {'mask': 0})
        return _Decoded(f'pop {self._printGPR(gpr_mask)}', 'pop_gpr', {'mask': gpr_mask})

    def _decode_10011101(self) -> _Decoded:
        self._require(1, 'compact 0x9d opcode')
        self._index += 1
        return _Decoded('reserved (ARM MOVrr)', 'reserved', {})

    def _decode_10011111(self) -> _Decoded:
        self._require(1, 'compact 0x9f opcode')
        self._index += 1
        return _Decoded('reserved (WiMMX MOVrr)', 'reserved', {})

    def _decode_1001nnnn(self) -> _Decoded:
        # SW.startLine() << format("0x%02X      ; vsp = r%u\n", Opcode, (Opcode & 0x0f));
        self._require(1, 'compact 0x90 opcode')
        opcode = self._bytecode_array[self._index]
        self._index += 1
        reg = int(opcode & 15)
        return _Decoded(f'vsp = r{reg}', 'vsp_from_reg', {'register': reg})

    def _decode_10100nnn(self) -> _Decoded:
        #   PrintGPR((((1 << ((Opcode & 0x7) + 1)) - 1) << 4));
        self._require(1, 'compact 0xa0 opcode')
        opcode = self._bytecode_array[self._index]
        self._index += 1
        mask = self._calculate_range(4, opcode & 0x07)
        return _Decoded(f'pop {self._printGPR(mask)}', 'pop_range_gpr', {'mask': mask})

    def _decode_10101nnn(self) -> _Decoded:
        #   PrintGPR((((1 << ((Opcode & 0x7) + 1)) - 1) << 4) | (1 << 14));
        self._require(1, 'compact 0xa8 opcode')
        opcode = self._bytecode_array[self._index]
        self._index += 1
        mask = self._calculate_range(4, opcode & 0x07) | (1 << 14)
        return _Decoded(f'pop {self._printGPR(mask)}', 'pop_range_gpr', {'mask': mask})

    def _decode_10110000(self) -> _Decoded:
        # SW.startLine() << format("0x%02X      ; finish\n", Opcode);
        self._require(1, 'compact 0xb0 opcode')
        self._index += 1
        return _Decoded('finish', 'finish', {})

    def _decode_10110001_0000iiii(self) -> _Decoded:
        self._require(2, 'compact 0xb1 pop')
        self._index += 1  # skip constant byte
        op1 = self._bytecode_array[self._index]
        self._index += 1
        if (op1 & 0xf0) != 0 or op1 == 0x00:
            return _Decoded('spare', 'spare', {})
        mask = op1 & 0x0f
        return _Decoded(f'pop {self._printGPR(mask)}', 'pop_gpr_low', {'mask': mask})

    def _decode_10110010_uleb128(self) -> _Decoded:
        #  do { ULEB.push_back(Opcodes[OI ^ 3]); } while (Opcodes[OI++ ^ 3] & 0x80);
        #  ULEB values are little-endian base-128: stop at the first byte with
        #  its high bit clear.
        self._require(1, 'compact 0xb2 opcode')
        self._index += 1   # skip constant byte
        value = 0
        shift = 0
        while True:
            if self._index >= len(self._bytecode_array):
                raise EHABITruncatedBytecode('missing ULEB128 continuation byte')
            byte = self._bytecode_array[self._index]
            self._index += 1
            value |= (byte & 0x7f) << shift
            if byte & 0x80 == 0:
                break
            shift += 7
            if shift > 63:
                raise EHABITruncatedBytecode('ULEB128 operand is too long')
        amount = int(0x204 + (value << 2))
        return _Decoded(f'vsp = vsp + {amount}', 'vsp_plus_uleb', {'amount': amount})

    def _decode_10110011_sssscccc(self) -> _Decoded:
        # b3 uses the same VFP register range encoding as c9.
        return self._pop_d_range(0, 'compact 0xb3 pop')

    def _decode_101101nn(self) -> _Decoded:
        self._require(1, 'compact 0xb4 opcode')
        self._index += 1
        return _Decoded('spare', 'spare', {})

    def _decode_10111nnn(self) -> _Decoded:
        #  PrintRegisters((((1 << ((Opcode & 0x07) + 1)) - 1) << 8), "d");
        self._require(1, 'compact 0xb8 pop')
        opcode = self._bytecode_array[self._index]
        self._index += 1
        mask = self._calculate_range(8, opcode & 0x07)
        return _Decoded('pop {}'.format(self._print_registers(mask, 'd')),
                        'pop_vfp', {'mask': mask})

    def _decode_11000110_sssscccc(self) -> _Decoded:
        #  PrintRegisters((((1 << (Count + 1)) - 1) << Start), "wR");
        self._require(2, 'compact 0xc6 pop')
        self._index += 1  # skip constant byte
        op1 = self._bytecode_array[self._index]
        self._index += 1
        start = ((op1 & 0xf0) >> 4)
        count = ((op1 & 0x0f) >> 0)
        mask = self._calculate_range(start, count)
        return _Decoded('pop {}'.format(self._print_registers(mask, 'wR')),
                        'pop_iwmmx', {'mask': mask})

    def _decode_11000111_0000iiii(self) -> _Decoded:
        self._require(2, 'compact 0xc7 pop')
        self._index += 1  # skip constant byte
        op1 = self._bytecode_array[self._index]
        self._index += 1
        if (op1 & 0xf0) != 0 or op1 == 0x00:
            return _Decoded('spare', 'spare', {})
        mask = op1 & 0x0f
        return _Decoded('pop {}'.format(self._print_registers(mask, 'wCGR')),
                        'pop_iwmmx_cgr', {'mask': mask})

    def _pop_d_range(self, start: int, what: str) -> _Decoded:
        self._require(2, what)
        self._index += 1  # skip constant byte
        op1 = self._bytecode_array[self._index]
        self._index += 1
        start = start + ((op1 & 0xf0) >> 4)
        count = ((op1 & 0x0f) >> 0)
        mask = self._calculate_range(start, count)
        return _Decoded('pop {}'.format(self._print_registers(mask, 'd')),
                        'pop_vfp', {'mask': mask})

    def _decode_11001000_sssscccc(self) -> _Decoded:
        return self._pop_d_range(16, 'compact 0xc8 pop')

    def _decode_11001001_sssscccc(self) -> _Decoded:
        return self._pop_d_range(0, 'compact 0xc9 pop')

    def _decode_11001yyy(self) -> _Decoded:
        self._require(1, 'compact 0xc0 opcode')
        self._index += 1
        return _Decoded('spare', 'spare', {})

    def _decode_11000nnn(self) -> _Decoded:
        #   PrintRegisters((((1 << ((Opcode & 0x07) + 1)) - 1) << 10), "wR");
        self._require(1, 'compact 0xc0 pop')
        opcode = self._bytecode_array[self._index]
        self._index += 1
        mask = self._calculate_range(10, opcode & 0x07)
        return _Decoded('pop {}'.format(self._print_registers(mask, 'wR')),
                        'pop_iwmmx', {'mask': mask})

    def _decode_11010nnn(self) -> _Decoded:
        # these two decoders are equal
        return self._decode_10111nnn()

    def _decode_11xxxyyy(self) -> _Decoded:
        self._require(1, 'compact 0xd0 opcode')
        self._index += 1
        return _Decoded('spare', 'spare', {})

    class _DECODE_RECIPE_TYPE(NamedTuple):
        mask: int
        value: int
        handler: Callable[[EHABIBytecodeDecoder], _Decoded]

    ring = (
        _DECODE_RECIPE_TYPE(mask=0xc0, value=0x00, handler=_decode_00xxxxxx),
        _DECODE_RECIPE_TYPE(mask=0xc0, value=0x40, handler=_decode_01xxxxxx),
        _DECODE_RECIPE_TYPE(mask=0xf0, value=0x80, handler=_decode_1000iiii_iiiiiiii),
        _DECODE_RECIPE_TYPE(mask=0xff, value=0x9d, handler=_decode_10011101),
        _DECODE_RECIPE_TYPE(mask=0xff, value=0x9f, handler=_decode_10011111),
        _DECODE_RECIPE_TYPE(mask=0xf0, value=0x90, handler=_decode_1001nnnn),
        _DECODE_RECIPE_TYPE(mask=0xf8, value=0xa0, handler=_decode_10100nnn),
        _DECODE_RECIPE_TYPE(mask=0xf8, value=0xa8, handler=_decode_10101nnn),
        _DECODE_RECIPE_TYPE(mask=0xff, value=0xb0, handler=_decode_10110000),
        _DECODE_RECIPE_TYPE(mask=0xff, value=0xb1, handler=_decode_10110001_0000iiii),
        _DECODE_RECIPE_TYPE(mask=0xff, value=0xb2, handler=_decode_10110010_uleb128),
        _DECODE_RECIPE_TYPE(mask=0xff, value=0xb3, handler=_decode_10110011_sssscccc),
        _DECODE_RECIPE_TYPE(mask=0xfc, value=0xb4, handler=_decode_101101nn),
        _DECODE_RECIPE_TYPE(mask=0xf8, value=0xb8, handler=_decode_10111nnn),
        _DECODE_RECIPE_TYPE(mask=0xff, value=0xc6, handler=_decode_11000110_sssscccc),
        _DECODE_RECIPE_TYPE(mask=0xff, value=0xc7, handler=_decode_11000111_0000iiii),
        _DECODE_RECIPE_TYPE(mask=0xff, value=0xc8, handler=_decode_11001000_sssscccc),
        _DECODE_RECIPE_TYPE(mask=0xff, value=0xc9, handler=_decode_11001001_sssscccc),
        _DECODE_RECIPE_TYPE(mask=0xc8, value=0xc8, handler=_decode_11001yyy),
        _DECODE_RECIPE_TYPE(mask=0xf8, value=0xc0, handler=_decode_11000nnn),
        _DECODE_RECIPE_TYPE(mask=0xf8, value=0xd0, handler=_decode_11010nnn),
        _DECODE_RECIPE_TYPE(mask=0xc0, value=0xc0, handler=_decode_11xxxyyy),
    )


class MnemonicItem:
    """ Single mnemonic item.
    """

    def __init__(self, bytecode: list[int], mnemonic: str) -> None:
        self.bytecode = bytecode
        self.mnemonic = mnemonic

    def __repr__(self) -> str:
        return '{} ; {}'.format(' '.join([f'0x{x:02x}' for x in self.bytecode]), self.mnemonic)
