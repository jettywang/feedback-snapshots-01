'''Static interpretation of UEFI dependency expressions (DEPEX).

A DEPEX section is a small postfix (Reverse Polish) program evaluated on a
boolean stack. The PI specification (UEFI PI 1.7, Volume 2, 9.2) defines the
opcodes and the grammar the dispatcher relies on:

    Expression := PushOp (Op)? EndOp
    PushOp     := PUSH [TRUE | FALSE]
    Op         := AND OR NOT | PushOp [Op]?
    EndOp      := END
    SORExp     := SOR Expression (BEFORE|AFTER) GUID Expression END

This module does more than list opcodes. :func:`interpret_depex` decodes the
instructions, checks the structural rules (stack depth, GUID operands and the
END / SOR combinations) and statically evaluates the boolean part against the
set of protocols known to be available at a given dispatch phase. Anything that
depends on runtime state that was not supplied stays ``unknown``; an unknown
protocol never proves that the driver was, or was not, dispatched.
'''

from .guids import get_guid_name
from .utils import sguid

# PI 1.7 Vol. 2, table "EFI dependency expression opcodes".
BEFORE = 0x00
AFTER = 0x01
PUSH = 0x02
AND = 0x03
OR = 0x04
NOT = 0x05
TRUE = 0x06
FALSE = 0x07
END = 0x08
SOR = 0x09

# Opcodes that carry a 16-byte EFI_GUID operand.
GUID_OPCODES = (BEFORE, AFTER, PUSH)

# Opcodes that only manipulate the boolean stack; SOR/BEFORE/AFTER describe
# dispatch ordering and are not boolean operators.
BOOLEAN_UNARY = (NOT,)
BOOLEAN_BINARY = (AND, OR)
STACK_LITERALS = (TRUE, FALSE)

OPCODE_NAMES = {
    BEFORE: 'BEFORE',
    AFTER: 'AFTER',
    PUSH: 'PUSH',
    AND: 'AND',
    OR: 'OR',
    NOT: 'NOT',
    TRUE: 'TRUE',
    FALSE: 'FALSE',
    END: 'END',
    SOR: 'SOR',
}

# Dispatch phases a DEPEX section can belong to (section types 0x13, 0x1b and
# 0x1c). SOR restrictions are defined for DXE dispatchers only.
PHASES = ('dxe', 'pei', 'smm')
SOR_PHASES = ('dxe',)

# Kleene three-valued logic results.
TRI_TRUE = 'true'
TRI_FALSE = 'false'
TRI_UNKNOWN = 'unknown'

NOT_RESULT = {
    TRI_TRUE: TRI_FALSE,
    TRI_FALSE: TRI_TRUE,
    TRI_UNKNOWN: TRI_UNKNOWN,
}


def _and(left, right):
    if left == TRI_FALSE or right == TRI_FALSE:
        return TRI_FALSE
    if left == TRI_TRUE and right == TRI_TRUE:
        return TRI_TRUE
    return TRI_UNKNOWN


def _or(left, right):
    if left == TRI_TRUE or right == TRI_TRUE:
        return TRI_TRUE
    if left == TRI_FALSE and right == TRI_FALSE:
        return TRI_FALSE
    return TRI_UNKNOWN


def decode_depex(data):
    '''Split a DEPEX blob into instruction dictionaries.

    Each instruction keeps its opcode, the slice offset it was decoded from and
    the bytes it spans, so an interpretation can always be traced back to the
    original bytes. A truncated GUID operand or an unrecognised opcode is
    returned with ``valid`` set to False; decoding stops at the first failure.

    Returns:
        tuple(list, list): The decoded instructions and structural problems
        found while decoding.
    '''
    instructions = []
    problems = []
    offset = 0
    while offset < len(data):
        start = offset
        opcode = data[offset]
        offset += 1
        name = OPCODE_NAMES.get(opcode)
        instruction = {
            'index': len(instructions),
            'offset': start,
            'opcode': opcode,
            'op': name if name is not None else opcode,
            'size': 1,
            'valid': True,
        }
        if name is None:
            instruction['valid'] = False
            problems.append({
                'code': 'unknown_opcode',
                'instruction': len(instructions),
                'offset': start,
                'message': 'opcode 0x%02x is not a defined DEPEX opcode' % (
                    opcode),
            })
            instructions.append(instruction)
            break
        if opcode in GUID_OPCODES:
            if offset + 16 > len(data):
                instruction['valid'] = False
                problems.append({
                    'code': 'truncated_guid',
                    'instruction': len(instructions),
                    'offset': start,
                    'message': '%s expects a 16-byte GUID but the section ends'
                    ' after %d byte(s)' % (name, len(data) - offset),
                })
                instructions.append(instruction)
                break
            raw_guid = data[offset:offset + 16]
            offset += 16
            instruction['size'] = 17
            instruction['guid'] = sguid(raw_guid)
            instruction['name'] = get_guid_name(raw_guid)
        instructions.append(instruction)
    return instructions, problems


def _normalize_guid(guid):
    '''Accept canonical GUID strings, uuid.UUID objects or 16 raw bytes.'''
    if isinstance(guid, (bytes, bytearray)) and len(guid) == 16:
        return sguid(bytes(guid))
    if hasattr(guid, 'bytes_le'):
        return sguid(guid.bytes_le)
    return str(guid).lower()


def normalize_protocols(protocols):
    '''Turn a caller's known protocol set into a set of canonical GUIDs.'''
    if not protocols:
        return set()
    return {_normalize_guid(guid) for guid in protocols}


def _instruction_ref(instruction):
    return {
        'index': instruction['index'],
        'offset': instruction['offset'],
        'op': instruction['op'],
    }


def _check_boolean_grammar(instructions, start, end, problems, add):
    '''Check stack depth over instructions[start:end], a boolean sub-program.

    The slice excludes both END opcodes of a SOR expression; each must leave
    exactly one value on its own stack.
    '''
    depth = 0
    for instruction in instructions[start:end]:
        opcode = instruction['opcode']
        if opcode in (PUSH, TRUE, FALSE):
            depth += 1
        elif opcode in BOOLEAN_UNARY:
            if depth < 1:
                add('stack_underflow', instruction,
                    '%s needs one value but the stack is empty' % (
                        instruction['op']))
                return
        elif opcode in BOOLEAN_BINARY:
            if depth < 2:
                add('stack_underflow', instruction,
                    '%s needs two values but the stack only holds %d' % (
                        instruction['op'], depth))
                return
            depth -= 1
    if depth != 1:
        add('stack_not_single', instructions[end - 1],
            'the sub-expression leaves %d value(s); it must leave exactly one'
            % depth)


def _check_structure(instructions, decode_problems, phase):
    '''Validate the grammar independently of any known protocol values.'''
    problems = list(decode_problems)

    def add(code, instruction, message):
        entry = {
            'code': code,
            'instruction': instruction['index'],
            'offset': instruction['offset'],
            'message': message,
        }
        problems.append(entry)
        instruction.setdefault('issues', []).append(code)

    if not instructions:
        problems.append({
            'code': 'empty_expression',
            'instruction': None,
            'offset': None,
            'message': 'the dependency expression contains no instructions',
        })
        return problems, []

    truncated = any(
        problem['code'] in ('unknown_opcode', 'truncated_guid')
        for problem in problems)

    sor_indices = [
        instruction['index'] for instruction in instructions
        if instruction['opcode'] == SOR]
    if len(sor_indices) > 1:
        for instruction in instructions:
            if instruction['opcode'] == SOR and instruction['index'] != \
                    sor_indices[0]:
                add('multiple_sor', instruction,
                    'only one SOR restriction may appear in an expression')
    if sor_indices and sor_indices[0] != 0:
        add('sor_not_first', instructions[sor_indices[0]],
            'SOR must be the first instruction of the expression')
    if phase not in SOR_PHASES:
        for instruction in instructions:
            if instruction['opcode'] == SOR:
                add('sor_phase', instruction,
                    'SOR restrictions are only valid for DXE dispatch, not %s'
                    ' phase' % phase.upper())

    if truncated:
        return problems, sor_indices

    last = instructions[-1]
    if last['opcode'] != END:
        add('missing_end', last,
            'an expression must finish with END, but it finishes with %s' % (
                last['op']))

    if not sor_indices:
        # Plain expression: zero or more BEFORE/AFTER are illegal without SOR,
        # and a single boolean program terminated by one END.
        for instruction in instructions:
            if instruction['opcode'] in (BEFORE, AFTER):
                add('ordering_without_sor', instruction,
                    '%s is only allowed inside a SOR restriction' % (
                        instruction['op']))
        if last['opcode'] == END:
            _check_boolean_grammar(
                instructions, 0, len(instructions) - 1, problems, add)
        early_ends = [
            instruction for instruction in instructions
            if instruction['opcode'] == END and instruction['index'] !=
            len(instructions) - 1]
        if early_ends:
            add('instructions_after_end',
                instructions[early_ends[0]['index'] + 1],
                'no instructions may follow the terminating END')
            for instruction in early_ends[1:]:
                add('multiple_end', instruction,
                    'a non-SOR expression contains more than one END')
        return problems, sor_indices

    # SOR form: SOR <restriction boolean> END (BEFORE|AFTER) GUID
    #           <main boolean> END
    end_indices = [
        instruction['index'] for instruction in instructions
        if instruction['opcode'] == END]
    if not end_indices:
        add('sor_without_ordering', instructions[0],
            'SOR needs a restriction sub-expression ending in END, then a'
            ' BEFORE or AFTER GUID')
        return problems, sor_indices

    restriction_end = end_indices[0]
    ordering_index = restriction_end + 1
    if ordering_index >= len(instructions) or \
            instructions[ordering_index]['opcode'] not in (BEFORE, AFTER):
        add('sor_without_ordering', instructions[0],
            'the restriction END must be followed by BEFORE or AFTER with a'
            ' GUID')
        return problems, sor_indices
    ordering = instructions[ordering_index]

    if instructions[-1]['opcode'] != END:
        add('missing_end', instructions[-1],
            'the main sub-expression must finish with END')
    if len(end_indices) != 2:
        for index in end_indices[1:]:
            if index != len(instructions) - 1:
                add('multiple_end', instructions[index],
                    'a SOR expression has only the restriction and main ENDs')

    # Restriction sub-program sits between SOR (index 0) and its END.
    _check_boolean_grammar(
        instructions, 1, restriction_end, problems, add)
    # Main sub-program sits after the ordering GUID and before the final END.
    if instructions[-1]['opcode'] == END:
        _check_boolean_grammar(
            instructions, ordering['index'] + 1, len(instructions) - 1,
            problems, add)
    return problems, sor_indices


def _evaluate(instructions, known_protocols, unavailable_protocols,
              sor_indices):
    '''Run the boolean program with three-valued stack entries.

    Returns the trace, the final boolean result, the protocol dependencies and
    the reasons a result could not be decided. In a SOR expression the
    restriction sub-program is decoded for dependencies but its value is not the
    driver's dispatch result; the main sub-program after BEFORE/AFTER is.
    Protocols in neither evidence set stay unknown: absence from what the caller
    supplied is not proof that a protocol will never be installed.
    '''
    known = normalize_protocols(known_protocols)
    unavailable = normalize_protocols(unavailable_protocols)
    stack = []
    restriction_stack = []
    trace = []
    dependencies = []
    unknown_reasons = []

    # The main sub-program starts after the ordering GUID of a SOR expression.
    main_start = 0
    if sor_indices:
        for index, instruction in enumerate(instructions):
            if instruction['opcode'] in (BEFORE, AFTER):
                main_start = index + 1
                break

    for instruction in instructions:
        if not instruction['valid']:
            continue
        opcode = instruction['opcode']
        in_main = instruction['index'] >= main_start
        active_stack = stack if in_main else restriction_stack
        before = list(active_stack)

        if opcode == SOR:
            trace.append({
                'instruction': _instruction_ref(instruction),
                'action': 'sor',
                'stack_before': before,
                'stack_after': list(active_stack),
            })
            continue

        if opcode in (BEFORE, AFTER):
            trace.append({
                'instruction': _instruction_ref(instruction),
                'action': 'ordering',
                'stack_before': before,
                'stack_after': list(active_stack),
            })
            continue

        result = None
        if opcode == PUSH:
            guid = instruction['guid']
            if guid in known:
                availability = TRI_TRUE
                result = TRI_TRUE
            elif guid in unavailable:
                availability = TRI_FALSE
                result = TRI_FALSE
            else:
                availability = TRI_UNKNOWN
                result = TRI_UNKNOWN
                unknown_reasons.append({
                    'code': 'protocol_unknown',
                    'guid': guid,
                    'name': instruction.get('name'),
                    'instruction': _instruction_ref(instruction),
                    'message': 'availability of protocol %s is not known at'
                    ' this phase' % guid,
                })
            dependencies.append({
                'guid': guid,
                'name': instruction.get('name'),
                'available': availability,
                'part': 'main' if in_main else 'restriction',
                'instruction': _instruction_ref(instruction),
            })
        elif opcode == TRUE:
            result = TRI_TRUE
        elif opcode == FALSE:
            result = TRI_FALSE
        elif opcode == NOT:
            if active_stack:
                result = NOT_RESULT[active_stack.pop()]
        elif opcode in (AND, OR):
            if len(active_stack) >= 2:
                right = active_stack.pop()
                left = active_stack.pop()
                result = _and(left, right) if opcode == AND else _or(
                    left, right)
        elif opcode == END:
            trace.append({
                'instruction': _instruction_ref(instruction),
                'action': 'end',
                'part': 'main' if in_main else 'restriction',
                'stack_before': before,
                'stack_after': list(active_stack),
            })
            if not in_main:
                restriction_stack = []
            continue

        if result is not None:
            active_stack.append(result)
        trace.append({
            'instruction': _instruction_ref(instruction),
            'action': 'evaluate',
            'part': 'main' if in_main else 'restriction',
            'value': result,
            'stack_before': before,
            'stack_after': list(active_stack),
        })

    return trace, (stack[-1] if stack else TRI_UNKNOWN), dependencies, \
        unknown_reasons


def _ordering_constraints(instructions, sor_indices, phase):
    '''Extract BEFORE/AFTER restrictions and flag conflicting combinations.'''
    constraints = []
    conflicts = []
    in_restriction = bool(sor_indices) and sor_indices and \
        sor_indices[0] == 0
    for instruction in instructions:
        if not instruction['valid']:
            continue
        if instruction['opcode'] == SOR:
            in_restriction = True
            continue
        if instruction['opcode'] in (BEFORE, AFTER):
            relation = 'before' if instruction['opcode'] == BEFORE else 'after'
            entry = {
                'relation': relation,
                'guid': instruction['guid'],
                'name': instruction.get('name'),
                'instruction': _instruction_ref(instruction),
            }
            constraints.append(entry)
            if not in_restriction:
                conflicts.append({
                    'code': 'ordering_without_sor',
                    'instruction': _instruction_ref(instruction),
                    'message': '%s must be wrapped in a SOR restriction' % (
                        instruction['op']),
                })
            in_restriction = False

    relations = {}
    for constraint in constraints:
        relations.setdefault(constraint['guid'], []).append(constraint)
    for guid, entries in relations.items():
        distinct = {entry['relation'] for entry in entries}
        if len(distinct) > 1:
            conflicts.append({
                'code': 'conflicting_ordering',
                'guid': guid,
                'instructions': [
                    entry['instruction'] for entry in entries],
                'message': 'protocol %s is required both before and after this'
                ' driver' % guid,
            })

    if constraints and phase not in SOR_PHASES:
        conflicts.append({
            'code': 'ordering_phase',
            'message': 'BEFORE/AFTER ordering is dispatched by DXE only, not by'
            ' %s phase' % phase.upper(),
        })
    return constraints, conflicts


def interpret_depex(data, phase='dxe', known_protocols=None,
                    unavailable_protocols=None):
    '''Statically interpret a DEPEX blob for one dispatch phase.

    Args:
        data (bytes): The raw DEPEX section contents.
        phase (str): ``'dxe'``, ``'pei'`` or ``'smm'``; controls which SOR and
            ordering combinations are legal.
        known_protocols (iterable): Protocol GUIDs (canonical strings,
            ``uuid.UUID`` or 16 raw bytes) already installed at this phase.
        unavailable_protocols (iterable): GUIDs positively known not to be
            installed at this phase, evaluated as FALSE. A GUID in neither set
            stays unknown rather than being assumed absent.

    Returns:
        dict: A structured interpretation with the tri-state ``result``, its
        dependencies, every reason it could not be decided, the separate
        ordering constraints, structural validity problems and a per-
        instruction trace back to the original bytes.
    '''
    phase = (phase or 'dxe').lower()
    if phase not in PHASES:
        raise ValueError('unknown DEPEX phase %r; expected one of %s' % (
            phase, ', '.join(PHASES)))

    known = normalize_protocols(known_protocols)
    unavailable = normalize_protocols(unavailable_protocols)
    overlap = known & unavailable
    if overlap:
        raise ValueError(
            'protocol(s) listed as both present and absent: %s' % (
                ', '.join(sorted(overlap))))

    instructions, decode_problems = decode_depex(data)
    problems, sor_indices = _check_structure(
        instructions, decode_problems, phase)
    trace, result, dependencies, unknown_reasons = _evaluate(
        instructions, known, unavailable, sor_indices or [])
    constraints, ordering_conflicts = _ordering_constraints(
        instructions, sor_indices or [], phase)

    valid = not problems
    if problems:
        result = 'invalid'
        # A structurally broken program may still have produced a stack value,
        # but it cannot be trusted as the expression's result.
        invalid_reasons = [
            {
                'code': problem['code'],
                'message': problem['message'],
                'instruction': None if problem.get('instruction') is None
                else _instruction_ref(instructions[problem['instruction']]),
            }
            for problem in problems
        ]
    else:
        invalid_reasons = []

    return {
        'phase': phase,
        'valid': valid,
        'result': result,
        'dependencies': dependencies,
        'unknown_reasons': unknown_reasons + invalid_reasons,
        'ordering': {
            'constraints': constraints,
            'conflicts': ordering_conflicts,
            'satisfiable': not ordering_conflicts,
        },
        'problems': problems,
        'instructions': instructions,
        'trace': trace,
    }
