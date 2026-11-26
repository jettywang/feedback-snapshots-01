"""Source location primitives used by JMESPath diagnostics.

All offsets in this module are character offsets into the original
expression string.  Python strings are sequences of Unicode code points,
so these offsets stay correct when the expression contains multi-byte
characters.  They are deliberately not byte offsets.
"""

from jmespath.compat import with_str_method


@with_str_method
class CharacterSpan(object):
    """A half-open character range.

    ``start`` is inclusive and ``end`` is exclusive.  A zero-length span
    (``start == end``) is valid and is used for positions at end of input.
    """

    __slots__ = ('start', 'end')

    def __init__(self, start, end):
        if not isinstance(start, int) or not isinstance(end, int):
            raise TypeError('character span offsets must be integers')
        if start < 0 or end < start:
            raise ValueError('invalid character span: %r:%r' % (start, end))
        self.start = start
        self.end = end

    def __len__(self):
        return self.end - self.start

    def __eq__(self, other):
        if isinstance(other, CharacterSpan):
            return self.start == other.start and self.end == other.end
        return NotImplemented

    def __hash__(self):
        return hash((self.start, self.end))

    def __repr__(self):
        return 'CharacterSpan(%r, %r)' % (self.start, self.end)

    def __str__(self):
        return '%s:%s' % (self.start, self.end)

    def to_dict(self):
        return {'start': self.start, 'end': self.end}
