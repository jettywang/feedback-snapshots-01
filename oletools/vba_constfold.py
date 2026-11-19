# -*- coding: utf-8 -*-
"""
vba_constfold.py - Traceable static constant-expression folding for VBA

This module performs *static* evaluation of VBA constant expressions to help a
reviewer understand which plain string a deobfuscated expression yields, and
exactly which source fragments it was derived from.

Design guarantees (these are constraints on the implementation, not aspirations):

1. No VBA code is ever executed and Python ``eval``/``exec``/``compile`` are
   never used.  Every value is produced by explicit, hand-written arithmetic and
   string helpers in this module, so each transformation can be recomputed by
   hand from the recorded derivation steps.
2. Only a fixed whitelist of pure, side-effect-free operations is understood:
   integer arithmetic (``+ - * \\ Mod ^``), bitwise operators
   (``Not And Or Xor``, shifts), string concatenation (``&`` / ``+`` on
   strings), parentheses, nesting, line continuations and the documented string
   functions below.
3. Anything outside that whitelist *stops* evaluation instead of being guessed:
   unknown variables/identifiers, member/object calls (``a.b``, ``a!b``),
   unsupported functions, comparison/logical operators, floating point,
   division by zero or a value that would overflow the declared VBA type.
4. Results carry an explicit VBA type boundary (Integer/Long/LongLong) and are
   range-checked against it.  Overflow is reported as a stop, never wrapped.
5. Every result is bound to the originating module name and the exact character
   span of the expression; every recorded step references a real source span.

The module deliberately does NOT scan the whole text for encoded strings and
decode them in bulk.  Only expressions actually parsed out of the module are
evaluated, and the value is attached to that expression's span.

Whitelisted functions:
    Chr / Chr$ / ChrB / ChrB$ / ChrW / ChrW$
    Asc / AscB / AscW
    Str / CStr, CInt, CLng, Hex
    Len, Left, Right, Mid, UCase, LCase, Trim, LTrim, RTrim, Space,
    String, Replace, StrReverse

Status of a fold:
    FoldResult.FULL    - the whole expression reduced to one constant
    FoldResult.PARTIAL - some sub-expressions reduced, but the whole could not
    FoldResult.STOPPED - nothing could be reduced; a reason is provided
"""

import math
import os
import sys

# Enable "import oletools.vba_constfold" both from a source checkout and when
# installed, the same way olevba.py does:
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)


# === EXCEPTIONS ==============================================================

class FoldError(Exception):
    """Base class for all constant-folding errors."""


class FoldStop(FoldError):
    """
    Raised when folding must stop because the expression is not statically
    decidable under the supported whitelist.  These are expected, safe
    outcomes - never a reason to guess a value.
    """
    def __init__(self, reason, span=None):
        super(FoldStop, self).__init__(reason)
        self.reason = reason
        self.span = span


class FoldSyntaxError(FoldError):
    """Raised on a tokenising/parsing error (malformed expression)."""


# === VBA TYPE BOUNDARIES =====================================================
# MS-VBAL integer storage sizes. Every arithmetic result is checked against one
# of these explicit ranges instead of relying on Python's unbounded integers.

TYPE_INTEGER = 'Integer'    # 16-bit signed
TYPE_LONG = 'Long'          # 32-bit signed
TYPE_LONGLONG = 'LongLong'  # 64-bit signed (VBA7 x64)
TYPE_STRING = 'String'

TYPE_BOUNDS = {
    TYPE_INTEGER: (-32768, 32767),
    TYPE_LONG: (-2147483648, 2147483647),
    TYPE_LONGLONG: (-9223372036854775808, 9223372036854775807),
}
TYPE_RANK = {TYPE_INTEGER: 2, TYPE_LONG: 4, TYPE_LONGLONG: 8}

# A safety cap for string-repeating built-ins so a huge constant cannot exhaust
# memory. VBA itself caps String length at about 2^31 chars; we stay far lower.
MAX_REPEAT = 65535


# === TOKENS ==================================================================

TOK_NUM = 'num'
TOK_FLOAT = 'float'
TOK_STR = 'str'
TOK_ID = 'id'
TOK_OP = 'op'
TOK_NEWLINE = 'newline'
TOK_EOF = 'eof'

# Characters that terminate an expression at statement level in VBA: a line
# break, the ':' statement separator, '=' (assignment), a comma between
# arguments/calls or a closing parenthesis belonging to an outer group.
STATEMENT_TERMINATORS = frozenset(('\n', ':', '=', ',', ')'))

# Binary operators and their precedence (higher binds tighter). Comparison and
# logical operators are listed so they can be parsed and explicitly rejected,
# rather than silently mis-evaluated.
_PRECEDENCE = {
    '=': 1, '<>': 1, '<': 1, '>': 1, '<=': 1, '>=': 1, 'Like': 1, 'Is': 1,
    'And': 2, 'Or': 2, 'Xor': 2, 'Eqv': 2, 'Imp': 2,
    '<<': 3, '>>': 3,
    '+': 4, '-': 4,
    '&': 5,
    '\\': 6, 'Mod': 6,
    '*': 7, '/': 7,
    '^': 8,
}
# Comparison and Boolean-logical operators yield a value whose runtime
# semantics (string comparison, short-circuit logic, Variant truthiness) are
# outside the pure-integer whitelist; they are rejected explicitly. Note that
# the bitwise operators And/Or/Xor on integers ARE supported and are therefore
# intentionally absent here.
_UNSUPPORTED_OPERATORS = frozenset(
    ('=', '<>', '<', '>', '<=', '>=', 'Like', 'Is', 'Eqv', 'Imp'))


def _is_identifier_start(ch):
    return ch == '_' or ch.isalpha()


def _is_identifier_body(ch):
    return ch == '_' or ch.isalnum()


def tokenize(text):
    """
    Convert a VBA expression into tokens. Each token is a dict:
        {kind, value, start, end}
    Positions are offsets into ``text``.
    """
    tokens = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in ' \t\r':
            i += 1
            continue
        if ch == '\n':
            tokens.append(dict(kind=TOK_NEWLINE, value=ch, start=i, end=i + 1))
            i += 1
            continue
        # Remainder-of-line comment. (VBA has no block comments.)
        if ch == "'":
            while i < n and text[i] != '\n':
                i += 1
            continue
        start = i
        # Quoted string with "" as an escaped quote (MS-VBAL 3.3.4).
        if ch == '"':
            i += 1
            buf = []
            while True:
                if i >= n:
                    raise FoldSyntaxError('unterminated string literal')
                if text[i] == '"':
                    if i + 1 < n and text[i + 1] == '"':
                        buf.append('"')
                        i += 2
                        continue
                    i += 1
                    break
                buf.append(text[i])
                i += 1
            tokens.append(dict(kind=TOK_STR, value=''.join(buf),
                               start=start, end=i))
            continue
        # Number literal: decimal, &H hex or &O octal, with optional suffix.
        if ch.isdigit() or (ch == '&' and i + 1 < n and
                            text[i + 1] in 'hHoO'):
            token, i = _consume_number(text, i)
            tokens.append(token)
            continue
        # Identifier / keyword.
        if _is_identifier_start(ch):
            j = i + 1
            while j < n and _is_identifier_body(text[j]):
                j += 1
            word = text[i:j]
            tokens.append(dict(kind=TOK_ID, value=word, start=i, end=j))
            i = j
            continue
        # Multi-char operators first.
        two = text[i:i + 2]
        if two in ('<>', '<=', '>=', '<<', '>>'):
            tokens.append(dict(kind=TOK_OP, value=two, start=i, end=i + 2))
            i += 2
            continue
        if ch in '+-*/&^\\=.<>()!,:':
            tokens.append(dict(kind=TOK_OP, value=ch, start=i, end=i + 1))
            i += 1
            continue
        raise FoldSyntaxError('unexpected character %r at offset %d' % (ch, i))
    # Note: no EOF token is appended. A Parser may operate on a slice of this
    # list (see evaluate_module), and it detects the end by position instead,
    # which keeps token offsets valid for any slice.
    return tokens


def _consume_number(text, i):
    """
    Consume one number literal starting at ``i`` and return a token dict and
    the new index. Floating-point literals are tokenised but tagged TOK_FLOAT;
    the parser turns them into an explicit FoldStop instead of guessing.
    """
    n = len(text)
    start = i
    if text[i] == '&':
        kind = text[i + 1].lower()
        j = i + 2
        while j < n and (text[j].isalnum() or text[j] == '_'):
            j += 1
        raw = text[i:j]
        digits = raw[2:].replace('_', '')
        base = 16 if kind == 'h' else 8
        try:
            int(digits, base)
        except ValueError:
            raise FoldSyntaxError('malformed %s literal %r' % (kind, raw))
        suffix = ''
        while j < n and text[j] in '%&^@!#':
            suffix += text[j]
            j += 1
        return dict(kind=TOK_NUM, value=(raw, suffix), start=start, end=j), j
    j = i
    while j < n and (text[j].isdigit() or text[j] == '_'):
        j += 1
    is_float = False
    if j < n and text[j] == '.':
        is_float = True
        j += 1
        while j < n and text[j].isdigit():
            j += 1
    if j < n and text[j] in 'eE':
        is_float = True
        j += 1
        if j < n and text[j] in '+-':
            j += 1
        while j < n and text[j].isdigit():
            j += 1
    if is_float:
        # consume any trailing type suffix as part of the literal
        while j < n and text[j] in '@!#&':
            j += 1
        return dict(kind=TOK_FLOAT, value=text[start:j], start=start, end=j), j
    raw_digits = text[i:j]
    suffix = ''
    while j < n and text[j] in '%&^@!#':
        suffix += text[j]
        j += 1
    return dict(kind=TOK_NUM, value=(raw_digits, suffix), start=start, end=j), j


# === ABSTRACT SYNTAX TREE ====================================================

class Node(object):
    """Base AST node. ``start``/``end`` are offsets into the expression text."""
    def __init__(self, start, end):
        self.start = start
        self.end = end


class IntLit(Node):
    def __init__(self, raw, start, end):
        super(IntLit, self).__init__(start, end)
        self.raw = raw          # tuple (digits_text, suffix_text)

    def __repr__(self):
        return 'IntLit(%r)' % (self.raw,)


class StrLit(Node):
    def __init__(self, value, start, end):
        super(StrLit, self).__init__(start, end)
        self.value = value

    def __repr__(self):
        return 'StrLit(%r)' % self.value


class UnaryOp(Node):
    def __init__(self, op, operand, start, end):
        super(UnaryOp, self).__init__(start, end)
        self.op = op
        self.operand = operand


class BinaryOp(Node):
    def __init__(self, op, left, right, start, end):
        super(BinaryOp, self).__init__(start, end)
        self.op = op
        self.left = left
        self.right = right


class FuncCall(Node):
    def __init__(self, name, args, start, end):
        super(FuncCall, self).__init__(start, end)
        self.name = name
        self.args = args


class Unknown(Node):
    """
    A syntactically recognised but statically undecidable fragment (a bare
    variable, an object/member access, ...). It is parsed into the tree so the
    surrounding expression keeps a valid shape, but the fold engine always
    stops on it with an explicit reason rather than guessing a value.
    """
    def __init__(self, reason, start, end):
        super(Unknown, self).__init__(start, end)
        self.reason = reason

    def __repr__(self):
        return 'Unknown(%r)' % self.reason


class Parser(object):
    """Recursive-descent / Pratt parser for the supported expression subset."""

    def __init__(self, text, tokens, start=0, limit=None):
        self.text = text
        self.tokens = tokens
        # Operate on tokens[start:limit] of the shared list without slicing, so
        # every token keeps its module-level offset and the parser cannot run
        # into the following statement.
        self.pos = start
        self.limit = len(tokens) if limit is None else limit

    def peek(self):
        if self.pos >= self.limit:
            end = self.tokens[self.limit - 1]['end'] if self.limit else len(self.text)
            return dict(kind=TOK_EOF, value=None, start=end, end=end)
        return self.tokens[self.pos]

    def next(self):
        tok = self.peek()
        if tok['kind'] != TOK_EOF:
            self.pos += 1
        return tok

    def expect(self, value):
        tok = self.peek()
        if tok['kind'] != TOK_OP or tok['value'] != value:
            raise FoldSyntaxError('expected %r but found %r'
                                  % (value, tok['value']))
        return self.next()

    def parse(self):
        node = self.parse_expression(0)
        # A clean expression ends at end-of-input or at a statement boundary.
        # '=' is deliberately not a boundary here: assignment '=' was already
        # split off during segmentation, so an '=' reached by the parser is a
        # comparison operator and must be folded (and rejected) rather than
        # truncating the left operand.
        tok = self.peek()
        if tok['kind'] not in (TOK_EOF, TOK_NEWLINE) and \
                not (tok['kind'] == TOK_OP and tok['value'] in (':', ',')):
            raise FoldSyntaxError('unexpected token %r' % tok['value'])
        return node

    def parse_expression(self, min_prec):
        left = self.parse_unary()
        while True:
            tok = self.peek()
            if tok['kind'] in (TOK_EOF, TOK_NEWLINE):
                break
            if tok['kind'] == TOK_OP and tok['value'] in (':', ',', ')'):
                break
            if tok['kind'] == TOK_ID and tok['value'].capitalize() in _PRECEDENCE:
                op = tok['value'].capitalize()
                prec = _PRECEDENCE[op]
            elif tok['kind'] == TOK_OP and tok['value'] in _PRECEDENCE:
                op = tok['value']
                prec = _PRECEDENCE[op]
            else:
                # Any other token (a bare identifier starting another call,
                # a member dot, ...) cannot continue this expression.
                break
            if prec < min_prec:
                break
            self.next()
            # '^' is right-associative in VBA; everything else is left.
            next_min = prec if op == '^' else prec + 1
            right = self.parse_expression(next_min)
            left = BinaryOp(op, left, right, left.start, right.end)
        return left

    def parse_unary(self):
        tok = self.peek()
        if tok['kind'] == TOK_OP and tok['value'] in ('-', '+'):
            self.next()
            operand = self.parse_unary()
            if tok['value'] == '-':
                return UnaryOp('-', operand, tok['start'], operand.end)
            return operand
        if tok['kind'] == TOK_ID and tok['value'].lower() == 'not':
            self.next()
            operand = self.parse_unary()
            return UnaryOp('Not', operand, tok['start'], operand.end)
        return self.parse_primary()

    def parse_primary(self):
        tok = self.peek()
        if tok['kind'] == TOK_NUM:
            self.next()
            return IntLit(tok['value'], tok['start'], tok['end'])
        if tok['kind'] == TOK_FLOAT:
            self.next()
            return Unknown('floating-point literal %r is not supported'
                           % tok['value'], tok['start'], tok['end'])
        if tok['kind'] == TOK_STR:
            self.next()
            return StrLit(tok['value'], tok['start'], tok['end'])
        if tok['kind'] == TOK_OP and tok['value'] == '(':
            return self.parse_parenthesised()
        if tok['kind'] == TOK_ID:
            return self.parse_identifier_or_call()
        if tok['kind'] == TOK_EOF:
            raise FoldSyntaxError('unexpected end of expression')
        raise FoldSyntaxError('unexpected token %r' % tok['value'])

    def parse_parenthesised(self):
        open_tok = self.expect('(')
        inner = self.parse_expression(0)
        self.expect(')')
        # Keep the parentheses' span on the node so the source range is exact.
        inner.start = open_tok['start']
        inner.end = self.tokens[self.pos - 1]['end']
        return inner

    def parse_identifier_or_call(self):
        tok = self.next()
        name = tok['value']
        low = name.lower()
        # Boolean literals have no numeric meaning we are willing to assume.
        if low in ('true', 'false', 'nothing', 'empty', 'null'):
            return Unknown('literal %r is not a supported constant' % name,
                           tok['start'], tok['end'])
        if self.peek()['kind'] == TOK_OP and self.peek()['value'] == '(':
            self.next()
            args = []
            if not (self.peek()['kind'] == TOK_OP and self.peek()['value'] == ')'):
                args.append(self.parse_expression(0))
                while self.peek()['kind'] == TOK_OP and \
                        self.peek()['value'] == ',':
                    self.next()
                    args.append(self.parse_expression(0))
            close = self.expect(')')
            node = FuncCall(name, args, tok['start'], close['end'])
            return self._check_member_access(node)
        # Bare identifier: a variable or unknown name, no value can be assumed.
        ident = Unknown('unknown variable or identifier %r (no constant '
                        'value available)' % name, tok['start'], tok['end'])
        return self._check_member_access(ident)

    def _check_member_access(self, node):
        """Object.member / object!member calls are not statically decidable."""
        tok = self.peek()
        if tok['kind'] == TOK_OP and tok['value'] in ('.', '!'):
            start = node.start
            self.next()
            member = self.peek()
            if member['kind'] == TOK_ID:
                self.next()
            if self.peek()['kind'] == TOK_OP and self.peek()['value'] == '(':
                self._consume_balanced_parens()
            end = self.tokens[self.pos - 1]['end']
            return Unknown('object/member access is not supported',
                           start, end)
        return node

    def _consume_balanced_parens(self):
        """Consume a balanced (...) group starting at the current '(' token."""
        self.expect('(')
        depth = 1
        while depth:
            tok = self.next()
            if tok['kind'] == TOK_EOF:
                raise FoldSyntaxError('unbalanced parentheses')
            if tok['kind'] == TOK_OP and tok['value'] == '(':
                depth += 1
            elif tok['kind'] == TOK_OP and tok['value'] == ')':
                depth -= 1


def parse_expression(text):
    """Tokenise and parse one expression string into an AST."""
    return Parser(text, tokenize(text)).parse()


# === FOLD ENGINE =============================================================

class _Value(object):
    """A folded value tagged with its VBA type."""
    __slots__ = ('value', 'vtype', 'flexible')

    def __init__(self, value, vtype, flexible=False):
        self.value = value
        # flexible=True means the value comes from bare integer literals whose
        # arithmetic VBA is allowed to widen on overflow (Integer -> Long ->
        # LongLong). An explicit type suffix or a typed function fixes the
        # boundary (flexible=False) and overflow must then stop evaluation.
        self.vtype = vtype
        self.flexible = flexible


class FoldEngine(object):
    """
    Evaluates an AST using only explicit helpers, recording every successful
    reduction as a recomputable step. Raises FoldStop as soon as a node cannot
    be decided under the whitelist.
    """

    def __init__(self, working_text, source_text=None):
        # working_text is the preprocessed text the AST offsets refer to;
        # source_text, when given, is the original module used only to quote
        # source fragments (so line-continuation characters stay visible).
        self.text = working_text
        self.source_text = source_text if source_text is not None else working_text
        self.steps = []

    def _record(self, node, operation, result, vtype, flexible=False,
                derived=True):
        step = {
            'start': node.start,
            'end': node.end,
            'source': self.source_text[node.start:node.end],
            'operation': operation,
            'result': result,
            'type': vtype,
            # False for quoted input literals, True for anything computed from
            # them. PARTIAL requires at least one derived step.
            'derived': derived,
        }
        self.steps.append(step)
        return _Value(result, vtype, flexible)

    # -- entry point ---------------------------------------------------------
    def fold(self, node):
        if isinstance(node, IntLit):
            return self._fold_int_literal(node)
        if isinstance(node, StrLit):
            return self._record(node, 'string literal', node.value,
                                TYPE_STRING, derived=False)
        if isinstance(node, Unknown):
            raise FoldStop(node.reason, (node.start, node.end))
        if isinstance(node, UnaryOp):
            return self._fold_unary(node)
        if isinstance(node, BinaryOp):
            return self._fold_binary(node)
        if isinstance(node, FuncCall):
            return self._fold_call(node)
        raise FoldStop('unsupported expression node %r' % type(node).__name__)

    def _fold_int_literal(self, node):
        digits, suffix = node.raw
        if digits.startswith('&'):
            kind_char = digits[1].lower()
            base = 16 if kind_char == 'h' else 8
            value = int(digits[2:].replace('_', ''), base)
        else:
            base = 10
            value = int(digits.replace('_', ''), base)
        if suffix in ('@', '#', '!'):
            raise FoldStop('non-integer literal type suffix %r is not '
                           'supported' % suffix, (node.start, node.end))
        if suffix == '%':
            vtype = TYPE_INTEGER
        elif suffix == '&':
            vtype = TYPE_LONG
        elif suffix == '^':
            vtype = TYPE_LONGLONG
        else:
            # Unsuffixed "integer literal": smallest fitting type, but VBA may
            # widen it on overflow, so mark the value as flexible.
            vtype = self._smallest_type(value)
            low, high = TYPE_BOUNDS[vtype]
            if not low <= value <= high:
                raise FoldStop('literal %s overflows %s' % (digits, vtype),
                               (node.start, node.end))
            return self._record(node, 'integer literal', value, vtype,
                                flexible=True, derived=False)
        low, high = TYPE_BOUNDS[vtype]
        if not low <= value <= high:
            raise FoldStop('literal %s overflows %s' % (digits, vtype),
                           (node.start, node.end))
        return self._record(node, 'integer literal', value, vtype,
                            derived=False)

    @staticmethod
    def _smallest_type(value):
        for vtype in (TYPE_INTEGER, TYPE_LONG, TYPE_LONGLONG):
            low, high = TYPE_BOUNDS[vtype]
            if low <= value <= high:
                return vtype
        raise FoldStop('integer literal outside LongLong range')

    def _fold_unary(self, node):
        operand = self.fold(node.operand)
        if node.op == '-':
            if operand.vtype == TYPE_STRING:
                raise FoldStop('unary minus on a String')
            result = self._check_int(-operand.value, operand.vtype,
                                     flexible=operand.flexible)[0]
            return self._record(node, 'unary -', result, operand.vtype,
                                flexible=operand.flexible)
        if node.op == 'Not':
            if operand.vtype == TYPE_STRING:
                raise FoldStop('bitwise Not on a String')
            result = self._bit_not(operand.value, operand.vtype)
            return self._record(node, 'bitwise Not', result, operand.vtype)
        raise FoldStop('unsupported unary operator %r' % node.op)

    def _fold_binary(self, node):
        op = node.op
        if op in _UNSUPPORTED_OPERATORS:
            raise FoldStop('operator %r is a comparison/logical operator not '
                           'supported by the constant folder' % op,
                           (node.start, node.end))
        left = self.fold(node.left)
        right = self.fold(node.right)
        if op == '&':
            return self._concat(node, left, right)
        if left.vtype == TYPE_STRING or right.vtype == TYPE_STRING:
            if op == '+':
                return self._concat(node, left, right)
            raise FoldStop('operator %r is not defined on a String' % op)
        if op == '+':
            result, vtype, flexible = self._int_arith(left, right, lambda a, b: a + b)
        elif op == '-':
            result, vtype, flexible = self._int_arith(left, right, lambda a, b: a - b)
        elif op == '*':
            result, vtype, flexible = self._int_arith(left, right, lambda a, b: a * b)
        elif op == '\\':
            result, vtype, flexible = self._integer_divide(node, left, right)
        elif op == 'Mod':
            result, vtype, flexible = self._modulo(left, right)
        elif op == '^':
            result, vtype, flexible = self._power(node, left, right)
        elif op in ('And', 'Or', 'Xor'):
            return self._bitwise(node, op, left, right)
        elif op in ('<<', '>>'):
            return self._shift(node, op, left, right)
        elif op == '/':
            raise FoldStop('floating-point division "/" is not supported; '
                           'use integer division "\\"')
        else:
            raise FoldStop('operator %r is not supported by the constant '
                           'folder' % op, (node.start, node.end))
        return self._record(node, op, result, vtype, flexible=flexible)

    def _concat(self, node, left, right):
        if left.vtype not in (TYPE_STRING,) or right.vtype not in (TYPE_STRING,):
            # VBA coerces numbers with &, but implicit coercion rules depend on
            # locale and type; do not guess - require explicit CStr.
            raise FoldStop('concatenation requires String operands; use CStr '
                           'for an explicit conversion')
        result = left.value + right.value
        return self._record(node, 'string concatenation', result, TYPE_STRING)

    # -- integer arithmetic with explicit type checks ------------------------
    def _effective_type(self, left, right):
        return TYPE_INTEGER if max(TYPE_RANK[left.vtype],
                                   TYPE_RANK[right.vtype]) == 2 else (
            TYPE_LONG if max(TYPE_RANK[left.vtype],
                             TYPE_RANK[right.vtype]) == 4
            else TYPE_LONGLONG)

    def _check_int(self, value, vtype, flexible):
        """
        Range-check ``value``. A flexible (bare-literal-only) sub-expression is
        allowed to widen to the next VBA type, mirroring VBA's promotion of
        literal arithmetic; a hard-typed operand fixes the boundary.
        """
        low, high = TYPE_BOUNDS[vtype]
        if low <= value <= high:
            return value, vtype
        if flexible:
            for wider in (TYPE_LONG, TYPE_LONGLONG):
                wlow, whigh = TYPE_BOUNDS[wider]
                if wlow <= value <= whigh:
                    return value, wider
        raise FoldStop('overflow: value %d does not fit %s' % (value, vtype))

    def _int_arith(self, left, right, operation):
        vtype = self._effective_type(left, right)
        flexible = left.flexible and right.flexible
        value = operation(left.value, right.value)
        result, result_type = self._check_int(value, vtype, flexible)
        return result, result_type, flexible

    def _integer_divide(self, node, left, right):
        if right.value == 0:
            raise FoldStop('division by zero', (node.start, node.end))
        # VBA rounds to nearest with .5 rounding toward even (banker's rounding)
        # before truncating; implement it explicitly rather than via Python's //.
        numerator = left.value
        denominator = right.value
        quotient = numerator / denominator
        rounded = self._bankers_round(quotient)
        vtype = self._effective_type(left, right)
        flexible = left.flexible and right.flexible
        result, vtype = self._check_int(rounded, vtype, flexible)
        return result, vtype, flexible

    @staticmethod
    def _bankers_round(x):
        floor = math.floor(x)
        diff = x - floor
        if diff > 0.5:
            return floor + 1
        if diff < 0.5:
            return floor
        return floor if floor % 2 == 0 else floor + 1

    def _modulo(self, left, right):
        if right.value == 0:
            raise FoldStop('Mod by zero')
        # VBA Mod first rounds operands (banker's), then truncates toward zero.
        a = self._bankers_round(float(left.value))
        b = self._bankers_round(float(right.value))
        if b == 0:
            raise FoldStop('Mod by zero')
        result = int(abs(a) % abs(b))
        if a < 0:
            result = -result
        vtype = self._effective_type(left, right)
        result, vtype = self._check_int(result, vtype,
                                        left.flexible and right.flexible)
        return result, vtype, left.flexible and right.flexible

    def _power(self, node, left, right):
        exponent = right.value
        if exponent < 0 or exponent > 64:
            raise FoldStop('exponent %d is outside the supported safe range '
                           '(0..64)' % exponent, (node.start, node.end))
        value = left.value ** exponent
        vtype = self._effective_type(left, right)
        flexible = left.flexible and right.flexible
        return self._check_int(value, vtype, flexible) + (flexible,)

    @staticmethod
    def _bit_not(value, vtype):
        return _truncate_signed(~value, vtype)

    def _bitwise(self, node, op, left, right):
        vtype = self._effective_type(left, right)
        a = _to_unsigned(left.value, vtype)
        b = _to_unsigned(right.value, vtype)
        if op == 'And':
            raw = a & b
        elif op == 'Or':
            raw = a | b
        else:
            raw = a ^ b
        result = _to_signed(raw, vtype)
        return self._record(node, 'bitwise ' + op, result, vtype)

    def _shift(self, node, op, left, right):
        vtype = left.vtype
        amount = right.value
        if amount < 0:
            raise FoldStop('negative shift amount')
        bits = TYPE_RANK[vtype] * 8
        if amount >= bits:
            raise FoldStop('shift amount %d exceeds %d-bit width'
                           % (amount, bits))
        unsigned = _to_unsigned(left.value, vtype)
        if op == '<<':
            raw = (unsigned << amount) & ((1 << bits) - 1)
        else:
            raw = unsigned >> amount
        result = _to_signed(raw, vtype)
        return self._record(node, 'shift ' + op, result, vtype)

    # -- whitelisted functions ----------------------------------------------
    def _fold_call(self, node):
        lname = node.name.rstrip('$').lower()
        args = [self.fold(arg) for arg in node.args]
        handler = _FUNCTION_HANDLERS.get(lname)
        if handler is None:
            raise FoldStop('function %r is not in the supported constant '
                           'whitelist' % node.name, (node.start, node.end))
        return handler(self, node, args)


# -- signed/unsigned helpers for bitwise operations ---------------------------

def _to_unsigned(value, vtype):
    low, high = TYPE_BOUNDS[vtype]
    width = high - low + 1            # 2^k
    return value % width


def _to_signed(unsigned, vtype):
    low, high = TYPE_BOUNDS[vtype]
    width = high - low + 1
    if unsigned >= width // 2:
        return unsigned - width
    return unsigned


def _truncate_signed(value, vtype):
    return _to_signed(_to_unsigned(value, vtype), vtype)


# === WHITELISTED FUNCTION HANDLERS ===========================================
# Each handler returns a _Value via engine._record so the reduction is logged.

def _arity(node, args, expected):
    if len(args) != expected:
        raise FoldStop('function %r expects %d argument(s), got %d'
                       % (node.name, expected, len(args)),
                       (node.start, node.end))


def h_chr(engine, node, args):
    _arity(node, args, 1)
    code = args[0]
    if code.vtype == TYPE_STRING:
        raise FoldStop('Chr requires a numeric code point')
    value = code.value
    if not 0 <= value <= 255:
        raise FoldStop('Chr code point %d outside 0..255' % value,
                       (node.start, node.end))
    return engine._record(node, node.name, chr(value), TYPE_STRING)


def h_chrw(engine, node, args):
    _arity(node, args, 1)
    code = args[0]
    if code.vtype == TYPE_STRING:
        raise FoldStop('ChrW requires a numeric code point')
    value = code.value
    if value < 0:
        value += 65536                # MS-VBAL negative code point rule
    if not 0 <= value <= 65535:
        raise FoldStop('ChrW code point outside 0..65535',
                       (node.start, node.end))
    return engine._record(node, node.name, chr(value), TYPE_STRING)


def h_asc(engine, node, args):
    _arity(node, args, 1)
    text = args[0]
    if text.vtype != TYPE_STRING or len(text.value) == 0:
        raise FoldStop('%s requires a non-empty string' % node.name)
    value = ord(text.value[0])
    vtype = engine._smallest_type(value)
    return engine._record(node, node.name, value, vtype)


def h_cstr(engine, node, args):
    _arity(node, args, 1)
    arg = args[0]
    if arg.vtype == TYPE_STRING:
        text = arg.value
    else:
        text = str(arg.value)        # explicit, locale-independent integer text
    return engine._record(node, node.name, text, TYPE_STRING)


def h_str(engine, node, args):
    _arity(node, args, 1)
    arg = args[0]
    if arg.vtype == TYPE_STRING:
        text = arg.value
    else:
        # VBA Str reserves a leading space for the sign of non-negative numbers.
        text = str(arg.value) if arg.value < 0 else ' ' + str(arg.value)
    return engine._record(node, node.name, text, TYPE_STRING)


def _convert_int(arg, vtype, node):
    if arg.vtype == TYPE_STRING:
        try:
            value = int(arg.value.strip())
        except ValueError:
            raise FoldStop('%s cannot parse %r as an integer'
                           % (node.name, arg.value), (node.start, node.end))
    else:
        value = arg.value
    low, high = TYPE_BOUNDS[vtype]
    if not low <= value <= high:
        raise FoldStop('%s value %d overflows %s' % (node.name, value, vtype),
                       (node.start, node.end))
    return value


def h_cint(engine, node, args):
    _arity(node, args, 1)
    value = _convert_int(args[0], TYPE_INTEGER, node)
    return engine._record(node, node.name, value, TYPE_INTEGER)


def h_clng(engine, node, args):
    _arity(node, args, 1)
    value = _convert_int(args[0], TYPE_LONG, node)
    return engine._record(node, node.name, value, TYPE_LONG)


def h_hex(engine, node, args):
    _arity(node, args, 1)
    arg = args[0]
    if arg.vtype == TYPE_STRING:
        raise FoldStop('Hex requires a numeric argument')
    value = arg.value
    if value < 0:
        # VBA Hex on a negative value prints the two's-complement representation.
        value = _to_unsigned(value, arg.vtype)
    return engine._record(node, node.name, '%X' % value, TYPE_STRING)


def h_len(engine, node, args):
    _arity(node, args, 1)
    if args[0].vtype != TYPE_STRING:
        raise FoldStop('Len requires a string argument here')
    value = len(args[0].value)
    vtype = engine._smallest_type(value)
    return engine._record(node, node.name, value, vtype)


def h_left(engine, node, args):
    if len(args) != 2:
        raise FoldStop('Left requires 2 arguments')
    text, count = _string_and_count(node, args)
    if count < 0:
        raise FoldStop('Left length is negative')
    return engine._record(node, node.name, text[:count], TYPE_STRING)


def h_right(engine, node, args):
    if len(args) != 2:
        raise FoldStop('Right requires 2 arguments')
    text, count = _string_and_count(node, args)
    if count < 0:
        raise FoldStop('Right length is negative')
    return engine._record(node, node.name,
                          text[len(text) - count:] if count else '', TYPE_STRING)


def h_mid(engine, node, args):
    if not 2 <= len(args) <= 3:
        raise FoldStop('Mid requires 2 or 3 arguments')
    if args[0].vtype != TYPE_STRING or args[1].vtype == TYPE_STRING:
        raise FoldStop('Mid argument type mismatch')
    text = args[0].value
    start = args[1].value
    if start < 1:
        raise FoldStop('Mid start position must be >= 1')
    begin = start - 1
    if len(args) == 3:
        if args[2].vtype == TYPE_STRING:
            raise FoldStop('Mid length must be numeric')
        length = args[2].value
        if length < 0:
            raise FoldStop('Mid length is negative')
        result = text[begin:begin + length]
    else:
        result = text[begin:]
    return engine._record(node, node.name, result, TYPE_STRING)


def h_ucase(engine, node, args):
    _arity(node, args, 1)
    if args[0].vtype != TYPE_STRING:
        raise FoldStop('UCase requires a string')
    return engine._record(node, node.name, args[0].value.upper(), TYPE_STRING)


def h_lcase(engine, node, args):
    _arity(node, args, 1)
    if args[0].vtype != TYPE_STRING:
        raise FoldStop('LCase requires a string')
    return engine._record(node, node.name, args[0].value.lower(), TYPE_STRING)


def h_trim(engine, node, args):
    _arity(node, args, 1)
    if args[0].vtype != TYPE_STRING:
        raise FoldStop('%s requires a string' % node.name)
    mode = node.name.lower()
    text = args[0].value
    if mode == 'ltrim':
        result = text.lstrip(' ')
    elif mode == 'rtrim':
        result = text.rstrip(' ')
    else:
        result = text.strip(' ')
    return engine._record(node, node.name, result, TYPE_STRING)


def h_space(engine, node, args):
    _arity(node, args, 1)
    count = _repeat_count(node, args[0], 'Space')
    return engine._record(node, node.name, ' ' * count, TYPE_STRING)


def h_string(engine, node, args):
    _arity(node, args, 2)
    count = _repeat_count(node, args[0], 'String')
    if args[1].vtype != TYPE_STRING or len(args[1].value) == 0:
        raise FoldStop('String requires a non-empty string character argument')
    char = args[1].value[0]
    return engine._record(node, node.name, char * count, TYPE_STRING)


def h_replace(engine, node, args):
    if not 3 <= len(args) <= 6:
        raise FoldStop('Replace requires 3 to 6 arguments')
    for arg in args[:3]:
        if arg.vtype != TYPE_STRING:
            raise FoldStop('Replace first three arguments must be strings')
    expression, find, replacement = (args[0].value, args[1].value,
                                     args[2].value)
    if find == '':
        raise FoldStop('Replace find-text must not be empty')
    # Optional count/compare args may be non-constant (then we stop), but with
    # exactly three constant string args the default semantics are unambiguous.
    if len(args) > 3:
        raise FoldStop('optional Replace parameters are not supported')
    return engine._record(node, node.name,
                          expression.replace(find, replacement), TYPE_STRING)


def h_strreverse(engine, node, args):
    _arity(node, args, 1)
    if args[0].vtype != TYPE_STRING:
        raise FoldStop('StrReverse requires a string')
    return engine._record(node, node.name, args[0].value[::-1], TYPE_STRING)


def _string_and_count(node, args):
    if args[0].vtype != TYPE_STRING or args[1].vtype == TYPE_STRING:
        raise FoldStop('%s argument type mismatch' % node.name)
    return args[0].value, args[1].value


def _repeat_count(node, arg, func):
    if arg.vtype == TYPE_STRING:
        raise FoldStop('%s count must be numeric' % func)
    count = arg.value
    if count < 0:
        raise FoldStop('%s count is negative' % func)
    if count > MAX_REPEAT:
        raise FoldStop('%s count %d exceeds safety cap %d'
                       % (func, count, MAX_REPEAT), (node.start, node.end))
    return count


_FUNCTION_HANDLERS = {
    'chr': h_chr, 'chrb': h_chr, 'chrw': h_chrw,
    'asc': h_asc, 'ascb': h_asc, 'ascw': h_asc,
    'str': h_str, 'cstr': h_cstr,
    'cint': h_cint, 'clng': h_clng, 'hex': h_hex,
    'len': h_len, 'left': h_left, 'right': h_right, 'mid': h_mid,
    'ucase': h_ucase, 'lcase': h_lcase,
    'trim': h_trim, 'ltrim': h_trim, 'rtrim': h_trim,
    'space': h_space, 'string': h_string,
    'replace': h_replace, 'strreverse': h_strreverse,
}


# === PUBLIC RESULT OBJECT ====================================================

class FoldResult(object):
    """Outcome of folding one expression, bound to its source location."""

    FULL = 'full'
    PARTIAL = 'partial'
    STOPPED = 'stopped'

    def __init__(self, source, module_name, start, end, line, status,
                 value=None, vtype=None, steps=None, stop_reason=None,
                 stop_span=None):
        self.source = source            # exact expression text from the module
        self.module_name = module_name
        self.start = start              # absolute char offset in the module
        self.end = end
        self.line = line                # 1-based line of ``start``
        self.status = status
        self.value = value              # present only when status == FULL
        self.vtype = vtype
        self.steps = steps or []        # recomputable derivation steps
        self.stop_reason = stop_reason
        self.stop_span = stop_span

    def __repr__(self):
        return 'FoldResult(%s, %r, line=%d, status=%s)' % (
            self.status, self.source, self.line, self.module_name)

    def to_dict(self):
        return {
            'module': self.module_name,
            'line': self.line,
            'start': self.start,
            'end': self.end,
            'expression': self.source,
            'status': self.status,
            'value': self.value,
            'type': self.vtype,
            'steps': self.steps,
            'stop_reason': self.stop_reason,
            'stop_span': self.stop_span,
        }


# === PREPROCESSING AND SCANNING ==============================================

def _preprocess(text):
    """
    Collapse VBA line continuations (" _" followed by a line break) into
    spaces so a split expression becomes one line. Every character of the
    continuation (space, underscore, CR and/or LF) is replaced by a space, so
    the total string length - and therefore every character offset - is
    preserved.
    """
    for newline in ('\r\n', '\r', '\n'):
        text = text.replace(' _' + newline, ' ' * (2 + len(newline)))
    return text


def _line_at(text, offset):
    return text.count('\n', 0, offset) + 1


def _has_produced_value(steps):
    """
    Decide whether a failed fold still derived something a reviewer can use
    (PARTIAL) rather than nothing at all (STOPPED).

    A step is ``derived`` when it transforms input (a function call,
    arithmetic, bitwise operation or concatenation). Quoted literals are input
    data (``derived=False``). Thus ``"Shell" & Unknown`` is PARTIAL because the
    literal is retained as a concrete string fragment of an incomplete
    concatenation, while ``Asc("")`` or ``10 \\ 0`` are STOPPED because no
    transformation ever completed.
    """
    return any(step.get('derived', True) for step in steps)


def fold_expression(expression, module_name='<expression>'):
    """
    Fold a single standalone expression. Always returns a FoldResult (never
    raises for an expected FoldStop/FoldSyntaxError), so callers can report why
    evaluation had to stop.
    """
    original = expression
    text = _preprocess(expression)
    base_line = 1
    try:
        ast = parse_expression(text)
    except FoldStop as exc:
        return FoldResult(original.strip(), module_name, 0, len(original),
                          base_line, FoldResult.STOPPED,
                          stop_reason=exc.reason, stop_span=exc.span)
    except FoldSyntaxError as exc:
        return FoldResult(original.strip(), module_name, 0, len(original),
                          base_line, FoldResult.STOPPED,
                          stop_reason='syntax error: %s' % exc)
    engine = FoldEngine(text)
    try:
        value = engine.fold(ast)
    except FoldStop as exc:
        status = FoldResult.PARTIAL if _has_produced_value(engine.steps) \
            else FoldResult.STOPPED
        return FoldResult(original.strip(), module_name, 0, len(original),
                          base_line, status, steps=list(engine.steps),
                          stop_reason=exc.reason, stop_span=exc.span)
    return FoldResult(original.strip(), module_name, 0, len(original),
                      base_line, FoldResult.FULL, value=value.value,
                      vtype=value.vtype, steps=list(engine.steps))


def _segment_token_ranges(tokens):
    """
    Split a module token stream into statement-level expression segments.

    A segment ends at a line break, a ':' statement separator, an assignment
    '=' or a comma. Parentheses are tracked so commas/newlines inside a call do
    not split it. Only segments that contain an actual obfuscated expression (a
    function call or a computation over literals) are returned; segments made
    of a single bare literal carry no transformation and are skipped, so encoded
    strings appearing in the text are never bulk-decoded out of context.
    """
    segments = []
    depth = 0
    segment_start = 0
    index = 0
    n = len(tokens)
    while index < n:
        tok = tokens[index]
        kind = tok['kind']
        value = tok['value']
        if kind == TOK_OP and value == '(':
            depth += 1
        elif kind == TOK_OP and value == ')':
            depth = max(0, depth - 1)
        at_boundary = (
            kind == TOK_NEWLINE or
            (depth == 0 and kind == TOK_OP and value in (':', '=', ','))
        )
        if at_boundary:
            if index > segment_start:
                segments.append((segment_start, index))
            segment_start = index + 1
        index += 1
    if segment_start < n:
        segments.append((segment_start, n))

    # Operators that actually transform operands. A segment containing only
    # literals and none of these (or a function call) is just a constant
    # declaration / assignment, not an obfuscated expression, and must not be
    # "decoded" out of context.
    computation_operators = frozenset(
        ('+', '-', '*', '/', '\\', '^', '&', '<<', '>>'))

    foldable = []
    for seg_start, seg_end in segments:
        has_construct = False
        for j in range(seg_start, seg_end):
            tok = tokens[j]
            # A whitelisted (or any) function call.
            if tok['kind'] == TOK_ID:
                nxt = tokens[j + 1] if j + 1 < seg_end else None
                if nxt is not None and nxt['kind'] == TOK_OP and \
                        nxt['value'] == '(':
                    has_construct = True
                    break
            # An explicit computation over literals.
            if tok['kind'] == TOK_OP and tok['value'] in computation_operators:
                has_construct = True
                break
        if has_construct:
            foldable.append((seg_start, seg_end))
    return foldable


def evaluate_module(module_name, code, include_stops=False):
    """
    Scan one VBA module and statically fold every foldable constant expression
    found in it. Results are bound to ``module_name`` and to exact character
    spans; only outermost expressions are returned (inner sub-expressions are
    retained as derivation steps of the outer result).

    :param module_name: str, name of the VBA module the code comes from
    :param code: str, raw VBA source of that module
    :param include_stops: bool, if True also return STOPPED results for
        expressions that could not be evaluated at all, each carrying the
        reason. Defaults to False so that only evidence-bearing results
        (FULL/PARTIAL) are reported.
    :return: list[FoldResult]
    """
    text = _preprocess(code)
    try:
        tokens = tokenize(text)
    except (FoldSyntaxError, FoldStop):
        # An unsupported token (e.g. a floating-point literal) or malformed
        # text means no safe whole-module token stream is available.
        return []

    raw_results = []
    for seg_start, seg_end in _segment_token_ranges(tokens):
        parser = Parser(text, tokens, start=seg_start, limit=seg_end)
        try:
            ast = parser.parse()
        except (FoldSyntaxError, FoldStop):
            continue
        start = tokens[seg_start]['start']
        end = ast.end
        # Preprocessing is length-preserving, so offsets map one-to-one onto
        # the original module; always quote the original source (including any
        # line-continuation characters) for the reviewer.
        source = code[start:end]
        engine = FoldEngine(text, source_text=code)
        in_scope = lambda step: start <= step['start'] and step['end'] <= end
        try:
            value = engine.fold(ast)
        except FoldStop as exc:
            steps = [step for step in engine.steps if in_scope(step)]
            if not _has_produced_value(engine.steps):
                # A pure stop: no transformation completed, but any quoted
                # input literals are retained so the reviewer sees what was
                # known before evaluation had to give up.
                if include_stops:
                    raw_results.append(FoldResult(
                        source, module_name, start, end,
                        _line_at(code, start), FoldResult.STOPPED,
                        steps=steps, stop_reason=exc.reason,
                        stop_span=exc.span))
                continue
            raw_results.append(FoldResult(
                source, module_name, start, end,
                _line_at(code, start), FoldResult.PARTIAL,
                steps=steps, stop_reason=exc.reason,
                stop_span=exc.span))
            continue
        steps = [step for step in engine.steps if in_scope(step)]
        raw_results.append(FoldResult(
            source, module_name, start, end,
            _line_at(code, start), FoldResult.FULL,
            value=value.value, vtype=value.vtype, steps=steps))

    # Keep only outermost spans; an inner result is already represented by the
    # derivation steps of the enclosing one.
    outermost = []
    for result in raw_results:
        contained = any(other is not result and
                        other.start <= result.start and
                        result.end <= other.end for other in raw_results)
        if not contained:
            outermost.append(result)
    outermost.sort(key=lambda r: (r.start, r.end))
    return outermost


# === HUMAN-READABLE TRACE ====================================================

def _format_value(value, vtype):
    if vtype == TYPE_STRING:
        return '%r (%s)' % (value, TYPE_STRING)
    return '%s (%s)' % (value, vtype)


def format_trace(results):
    """Render FoldResult objects as an indented, reviewer-friendly trace."""
    lines = []
    for result in results:
        header = '[%s] module=%s line=%d span=%d:%d' % (
            result.status.upper(), result.module_name, result.line,
            result.start, result.end)
        lines.append(header)
        lines.append('  expression: %s' % result.source)
        if result.status == FoldResult.FULL:
            lines.append('  result:     %s'
                         % _format_value(result.value, result.vtype))
        for number, step in enumerate(result.steps, 1):
            lines.append('    %2d. %-22s %-30s => %s' % (
                number, step['operation'],
                repr(step['source']) if len(step['source']) <= 28
                else repr(step['source'][:25] + '...'),
                _format_value(step['result'], step['type'])))
        if result.status in (FoldResult.PARTIAL, FoldResult.STOPPED):
            lines.append('  stopped:    %s' % result.stop_reason)
    return '\n'.join(lines)
