import string
import warnings
from json import loads

from jmespath.exceptions import LexerError, EmptyExpressionError
from jmespath.spans import CharacterSpan


class Token(dict):
    """A lexer token.

    This remains a ``dict`` (and therefore compares equal to the historical
    token dictionaries) but also carries an accurate source ``span``
    attribute.  The ``start``/``end`` keys are kept for backwards
    compatibility.
    """

    def __init__(self, values, span):
        super(Token, self).__init__(values)
        self.span = span


class Lexer(object):
    START_IDENTIFIER = set(string.ascii_letters + '_')
    VALID_IDENTIFIER = set(string.ascii_letters + string.digits + '_')
    VALID_NUMBER = set(string.digits)
    WHITESPACE = set(" \t\n\r")
    SIMPLE_TOKENS = {
        '.': 'dot',
        '*': 'star',
        ']': 'rbracket',
        ',': 'comma',
        ':': 'colon',
        '@': 'current',
        '(': 'lparen',
        ')': 'rparen',
        '{': 'lbrace',
        '}': 'rbrace',
    }

    def _token(self, type_, value, start, end, span_end=None):
        if span_end is None:
            span_end = end
        return Token(
            {'type': type_, 'value': value, 'start': start, 'end': end},
            CharacterSpan(start, max(start, span_end)))

    def tokenize(self, expression):
        self._initialize_for_expression(expression)
        while self._current is not None:
            if self._current in self.SIMPLE_TOKENS:
                yield self._token(self.SIMPLE_TOKENS[self._current],
                                  self._current,
                                  self._position, self._position + 1)
                self._next()
            elif self._current in self.START_IDENTIFIER:
                start = self._position
                buff = self._current
                while self._next() in self.VALID_IDENTIFIER:
                    buff += self._current
                yield self._token('unquoted_identifier', buff,
                                  start, start + len(buff))
            elif self._current in self.WHITESPACE:
                self._next()
            elif self._current == '[':
                start = self._position
                next_char = self._next()
                if next_char == ']':
                    self._next()
                    yield self._token('flatten', '[]', start, start + 2)
                elif next_char == '?':
                    self._next()
                    yield self._token('filter', '[?', start, start + 2)
                else:
                    yield self._token('lbracket', '[', start, start + 1)
            elif self._current == "'":
                yield self._consume_raw_string_literal()
            elif self._current == '|':
                yield self._match_or_else('|', 'or', 'pipe')
            elif self._current == '&':
                yield self._match_or_else('&', 'and', 'expref')
            elif self._current == '`':
                yield self._consume_literal()
            elif self._current in self.VALID_NUMBER:
                start = self._position
                buff = self._consume_number()
                yield self._token('number', int(buff),
                                  start, start + len(buff))
            elif self._current == '-':
                # Negative number.
                start = self._position
                buff = self._consume_number()
                if len(buff) > 1:
                    yield self._token('number', int(buff),
                                      start, start + len(buff))
                else:
                    raise LexerError(lexer_position=start,
                                     lexer_value=buff,
                                     message="Unknown token '%s'" % buff,
                                     end_position=start + 1)
            elif self._current == '"':
                yield self._consume_quoted_identifier()
            elif self._current == '<':
                yield self._match_or_else('=', 'lte', 'lt')
            elif self._current == '>':
                yield self._match_or_else('=', 'gte', 'gt')
            elif self._current == '!':
                yield self._match_or_else('=', 'ne', 'not')
            elif self._current == '=':
                if self._next() == '=':
                    yield self._token('eq', '==',
                                      self._position - 1, self._position,
                                      span_end=self._position + 1)
                    self._next()
                else:
                    if self._current is None:
                        # If we're at the EOF, we never advanced
                        # the position so we don't need to rewind
                        # it back one location.
                        position = self._position
                    else:
                        position = self._position - 1
                    raise LexerError(
                        lexer_position=position,
                        lexer_value='=',
                        message="Unknown token '='",
                        end_position=position + 1)
            else:
                raise LexerError(lexer_position=self._position,
                                 lexer_value=self._current,
                                 message="Unknown token %s" % self._current,
                                 end_position=self._position + 1)
        yield self._token('eof', '', self._length, self._length)

    def _consume_number(self):
        start = self._position
        buff = self._current
        while self._next() in self.VALID_NUMBER:
            buff += self._current
        return buff

    def _delimiter_end(self):
        # Set by ``_consume_until``: the index immediately past the closing
        # delimiter.
        return self._last_delimiter_end

    def _initialize_for_expression(self, expression):
        if not expression:
            raise EmptyExpressionError()
        self._position = 0
        self._expression = expression
        self._chars = list(self._expression)
        self._current = self._chars[self._position]
        self._length = len(self._expression)

    def _next(self):
        if self._position == self._length - 1:
            self._current = None
        else:
            self._position += 1
            self._current = self._chars[self._position]
        return self._current

    def _consume_until(self, delimiter):
        # Consume until the delimiter is reached,
        # allowing for the delimiter to be escaped with "\".
        start = self._position
        buff = ''
        self._next()
        while self._current != delimiter:
            if self._current == '\\':
                buff += '\\'
                self._next()
            if self._current is None:
                # We're at the EOF.
                raise LexerError(lexer_position=start,
                                 lexer_value=self._expression[start:],
                                 message="Unclosed %s delimiter" % delimiter,
                                 end_position=self._length)
            buff += self._current
            self._next()
        # The scanner is on the closing delimiter.  Record the position
        # immediately past it before skipping.
        self._last_delimiter_end = min(self._position + 1, self._length)
        # Skip the closing delimiter.
        self._next()
        return buff

    def _consume_literal(self):
        start = self._position
        lexeme = self._consume_until('`').replace('\\`', '`')
        try:
            # Assume it is valid JSON and attempt to parse.
            parsed_json = loads(lexeme)
        except ValueError:
            try:
                # Invalid JSON values should be converted to quoted
                # JSON strings during the JEP-12 deprecation period.
                parsed_json = loads('"%s"' % lexeme.lstrip())
                warnings.warn("deprecated string literal syntax",
                              PendingDeprecationWarning)
            except ValueError:
                raise LexerError(lexer_position=start,
                                 lexer_value=self._expression[start:],
                                 message="Bad token %s" % lexeme,
                                 end_position=self._length)
        token_len = self._position - start
        # The opening backtick is excluded here.  ``_consumed_end`` returns
        # the absolute index just past the closing delimiter.
        return self._token('literal', parsed_json, start, token_len,
                           span_end=self._delimiter_end())

    def _consume_quoted_identifier(self):
        start = self._position
        lexeme = '"' + self._consume_until('"') + '"'
        try:
            token_len = self._position - start
            return self._token('quoted_identifier', loads(lexeme),
                               start, token_len,
                               span_end=self._delimiter_end())
        except ValueError as e:
            error_message = str(e).split(':')[0]
            raise LexerError(lexer_position=start,
                             lexer_value=lexeme,
                             message=error_message,
                             end_position=self._delimiter_end())

    def _consume_raw_string_literal(self):
        start = self._position
        lexeme = self._consume_until("'").replace("\\'", "'")
        token_len = self._position - start
        return self._token('literal', lexeme, start, token_len,
                           span_end=self._delimiter_end())

    def _match_or_else(self, expected, match_type, else_type):
        start = self._position
        current = self._current
        next_char = self._next()
        if next_char == expected:
            self._next()
            return self._token(match_type, current + next_char,
                               start, start + 1, span_end=start + 2)
        return self._token(else_type, current, start, start,
                           span_end=start + 1)
