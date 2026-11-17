'''Static interpretation of dependency expressions (DEPEX).

The byte programs are intentionally short. One group exercises the boolean
interpreter (true, false, unknown and invalid expressions); three separate
classes exercise the BEFORE/AFTER ordering constraints, which are kept apart
from the boolean result. Every interpretation must be traceable back to the
instruction and offset it came from.
'''

import struct
import unittest
import uuid

from uefi_firmware.depex import (
    AND, AFTER, BEFORE, END, FALSE, NOT, OR, PUSH, SOR, TRUE,
    decode_depex, interpret_depex, normalize_protocols)
from uefi_firmware.uefi import parse_depex

GUID_A = uuid.UUID("01234567-89ab-4def-8123-456789abcdef")
GUID_B = uuid.UUID("fedcba98-7654-3210-fedc-ba9876543210")
GUID_C = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")


def push(guid):
    return bytes([PUSH]) + guid.bytes_le


def before(guid):
    return bytes([BEFORE]) + guid.bytes_le


def after(guid):
    return bytes([AFTER]) + guid.bytes_le


class DecodeTest(unittest.TestCase):

    def test_opcodes_and_offsets_are_recorded(self):
        blob = push(GUID_A) + bytes([AND, TRUE, END])
        instructions, problems = decode_depex(blob)
        self.assertEqual(problems, [])
        self.assertEqual(
            [instruction['op'] for instruction in instructions],
            ['PUSH', 'AND', 'TRUE', 'END'])
        # The GUID operand spans 17 bytes, so the AND opcode lands at offset 17.
        self.assertEqual(
            [instruction['offset'] for instruction in instructions],
            [0, 17, 18, 19])
        self.assertEqual(instructions[0]['size'], 17)
        self.assertEqual(instructions[0]['guid'], str(GUID_A))

    def test_unknown_and_truncated_opcodes_are_invalid(self):
        _, problems = decode_depex(b'\xee\x08')
        self.assertEqual(problems[0]['code'], 'unknown_opcode')
        _, problems = decode_depex(bytes([PUSH]) + b'\x00\x01')
        self.assertEqual(problems[0]['code'], 'truncated_guid')

    def test_legacy_disassembly_matches_the_decoder(self):
        blob = after(GUID_A) + bytes([TRUE, FALSE, AND, SOR, END, 0xee])
        self.assertEqual(
            [entry['op'] for entry in parse_depex(blob)],
            ['AFTER', 'TRUE', 'FALSE', 'AND', 'SOR', 'END', 0xee])


class BooleanExpressionTest(unittest.TestCase):
    '''Short byte programs for true, false, unknown and invalid results.'''

    def test_true_from_literal_and_satisfied_protocol(self):
        result = interpret_depex(bytes([TRUE, END]))
        self.assertTrue(result['valid'])
        self.assertEqual(result['result'], 'true')

        result = interpret_depex(
            push(GUID_A) + bytes([END]), known_protocols=[GUID_A])
        self.assertEqual(result['result'], 'true')
        self.assertEqual(result['dependencies'][0]['available'], 'true')

    def test_false_from_literal_and_absent_protocol(self):
        result = interpret_depex(bytes([FALSE, END]))
        self.assertTrue(result['valid'])
        self.assertEqual(result['result'], 'false')

        result = interpret_depex(
            push(GUID_A) + bytes([END]), unavailable_protocols=[GUID_A])
        self.assertEqual(result['result'], 'false')
        self.assertEqual(result['dependencies'][0]['available'], 'false')

    def test_unknown_protocol_stays_unknown(self):
        # A missing entry in the evidence sets is not proof of absence.
        result = interpret_depex(push(GUID_A) + bytes([END]))
        self.assertEqual(result['result'], 'unknown')
        self.assertEqual(result['dependencies'][0]['available'], 'unknown')
        self.assertEqual(
            [reason['code'] for reason in result['unknown_reasons']],
            ['protocol_unknown'])
        # Passing a different, known protocol must not decide GUID_A.
        result = interpret_depex(
            push(GUID_A) + bytes([END]), known_protocols=[GUID_B])
        self.assertEqual(result['result'], 'unknown')

    def test_kleene_propagation_through_and_or_not(self):
        # TRUE OR unknown is still TRUE, FALSE AND unknown is still FALSE.
        self.assertEqual(
            interpret_depex(
                push(GUID_A) + bytes([TRUE, OR, END]))['result'], 'true')
        self.assertEqual(
            interpret_depex(
                push(GUID_A) + bytes([FALSE, AND, END]))['result'], 'false')
        # NOT unknown is unknown, so no dispatch claim is made.
        self.assertEqual(
            interpret_depex(push(GUID_A) + bytes([NOT, END]))['result'],
            'unknown')
        # NOT FALSE is TRUE.
        self.assertEqual(
            interpret_depex(bytes([FALSE, NOT, END]))['result'], 'true')

    def test_unknown_does_not_prove_execution(self):
        result = interpret_depex(push(GUID_A) + bytes([END]))
        self.assertNotIn(result['result'], ('true', 'false'))
        self.assertFalse(result['valid'] is False)

    def test_invalid_stack_programs(self):
        cases = {
            bytes([AND, END]): 'stack_underflow',
            bytes([NOT, END]): 'stack_underflow',
            bytes([TRUE, END, TRUE]): 'instructions_after_end',
            bytes([TRUE, OR, END]): 'stack_underflow',
            bytes([TRUE]): 'missing_end',
            b'': 'empty_expression',
        }
        for blob, code in cases.items():
            with self.subTest(blob=blob):
                result = interpret_depex(blob)
                self.assertFalse(result['valid'])
                self.assertEqual(result['result'], 'invalid')
                self.assertIn(code, [p['code'] for p in result['problems']])

    def test_end_must_leave_a_single_value(self):
        # Two literals with no operator leave two values on the stack.
        result = interpret_depex(bytes([TRUE, FALSE, END]))
        self.assertFalse(result['valid'])
        self.assertIn(
            'stack_not_single', [p['code'] for p in result['problems']])

    def test_guid_operand_input_formats(self):
        canonical = normalize_protocols(
            [str(GUID_A), GUID_A, GUID_A.bytes_le])
        self.assertEqual(canonical, {str(GUID_A)})

    def test_overlapping_evidence_is_rejected(self):
        with self.assertRaises(ValueError):
            interpret_depex(
                push(GUID_A) + bytes([END]),
                known_protocols=[GUID_A],
                unavailable_protocols=[GUID_A])


class OrderingWithoutSorTest(unittest.TestCase):
    '''Conflict module one: BEFORE/AFTER used without a SOR wrapper.'''

    def test_before_without_sor_is_invalid(self):
        result = interpret_depex(before(GUID_A) + bytes([TRUE, END]))
        codes = [p['code'] for p in result['problems']]
        self.assertIn('ordering_without_sor', codes)
        self.assertFalse(result['valid'])
        self.assertFalse(result['ordering']['satisfiable'])
        self.assertEqual(
            result['ordering']['conflicts'][0]['code'],
            'ordering_without_sor')

    def test_after_without_sor_is_invalid(self):
        result = interpret_depex(after(GUID_A) + bytes([TRUE, END]))
        self.assertIn(
            'ordering_without_sor',
            [p['code'] for p in result['problems']])


class SorCombinationTest(unittest.TestCase):
    '''Conflict module two: SOR/END/ordering combinations and phase rules.'''

    def sor_program(self, ordering):
        # SOR <restriction TRUE> END <ordering GUID_A> <main TRUE> END
        return bytes([SOR, TRUE, END]) + ordering + bytes([TRUE, END])

    def test_well_formed_sor_is_valid_in_dxe(self):
        result = interpret_depex(self.sor_program(before(GUID_A)), 'dxe')
        self.assertTrue(result['valid'], result['problems'])
        self.assertEqual(result['result'], 'true')
        self.assertEqual(
            result['ordering']['constraints'][0]['relation'], 'before')
        self.assertEqual(result['ordering']['conflicts'], [])

    def test_sor_is_rejected_in_pei_and_smm(self):
        for phase in ('pei', 'smm'):
            with self.subTest(phase=phase):
                result = interpret_depex(
                    self.sor_program(before(GUID_A)), phase)
                self.assertIn(
                    'sor_phase', [p['code'] for p in result['problems']])
                self.assertFalse(result['ordering']['satisfiable'])

    def test_sor_without_before_or_after(self):
        # SOR TRUE END then a main expression, with no ordering opcode.
        result = interpret_depex(
            bytes([SOR, TRUE, END, TRUE, END]), 'dxe')
        self.assertIn(
            'sor_without_ordering',
            [p['code'] for p in result['problems']])

    def test_sor_must_be_first(self):
        result = interpret_depex(
            bytes([TRUE, SOR, TRUE, END]) + before(GUID_A) +
            bytes([TRUE, END]), 'dxe')
        self.assertIn(
            'sor_not_first', [p['code'] for p in result['problems']])


class ConflictingOrderingTest(unittest.TestCase):
    '''Conflict module three: contradictory before/after requirements.'''

    def test_same_guid_required_before_and_after(self):
        # A malformed stream carrying both relations on GUID_A; the boolean
        # grammar failure is reported separately from the ordering conflict.
        blob = (bytes([SOR, TRUE, END]) + before(GUID_A) +
                bytes([SOR, TRUE, END]) + after(GUID_A) +
                bytes([TRUE, END]))
        result = interpret_depex(blob, 'dxe')
        conflict_codes = [
            c['code'] for c in result['ordering']['conflicts']]
        self.assertIn('conflicting_ordering', conflict_codes)
        conflict = next(
            c for c in result['ordering']['conflicts']
            if c['code'] == 'conflicting_ordering')
        self.assertEqual(conflict['guid'], str(GUID_A))
        self.assertEqual(len(conflict['instructions']), 2)
        self.assertFalse(result['ordering']['satisfiable'])

    def test_consistent_ordering_has_no_conflict(self):
        result = interpret_depex(
            bytes([SOR, TRUE, END]) + before(GUID_A) +
            bytes([TRUE, END]), 'dxe')
        self.assertEqual(result['ordering']['conflicts'], [])
        self.assertTrue(result['ordering']['satisfiable'])


class TracebackTest(unittest.TestCase):
    '''Each interpreted step must map back to an original instruction.'''

    def test_trace_follows_offsets_and_stack(self):
        blob = push(GUID_A) + bytes([TRUE, AND, END])
        result = interpret_depex(blob, known_protocols=[GUID_A])
        offsets = [step['instruction']['offset'] for step in result['trace']]
        self.assertEqual(offsets, [0, 17, 18, 19])
        # The final AND step must show the two operands it consumed.
        and_step = next(
            step for step in result['trace']
            if step['instruction']['op'] == 'AND')
        self.assertEqual(and_step['stack_before'], ['true', 'true'])
        self.assertEqual(and_step['stack_after'], ['true'])

    def test_trace_offsets_match_raw_bytes(self):
        blob = bytes([TRUE, FALSE, OR, END])
        result = interpret_depex(blob)
        for step in result['trace']:
            offset = step['instruction']['offset']
            self.assertEqual(
                blob[offset],
                result['instructions'][step['instruction']['index']][
                    'opcode'])

    def test_dependency_points_at_its_push_instruction(self):
        result = interpret_depex(push(GUID_C) + bytes([END]))
        dependency = result['dependencies'][0]
        instruction = result['instructions'][
            dependency['instruction']['index']]
        self.assertEqual(instruction['op'], 'PUSH')
        self.assertEqual(instruction['guid'], str(GUID_C))
        self.assertEqual(instruction['offset'], 0)

    def test_sor_trace_separates_restriction_and_main(self):
        blob = (bytes([SOR, TRUE, END]) + before(GUID_A) +
                push(GUID_B) + bytes([END]))
        result = interpret_depex(blob, 'dxe')
        parts = {
            step['instruction']['op']: step.get('part')
            for step in result['trace'] if step['action'] == 'evaluate'}
        self.assertEqual(parts['TRUE'], 'restriction')
        self.assertEqual(parts['PUSH'], 'main')
        self.assertEqual(result['result'], 'unknown')


if __name__ == '__main__':
    unittest.main()
