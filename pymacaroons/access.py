from __future__ import unicode_literals

import calendar
import datetime
import re
import unicodedata

from six import string_types

from pymacaroons.exceptions import (
    MacaroonAccessCaveatException,
    MacaroonAccessContextException,
    MacaroonAccessException,
)
from pymacaroons.utils import convert_to_string


ACCESS_NAMESPACE = 'access.'
RESOURCE_FIELD = 'resource'
METHOD_FIELD = 'method'
EXPIRES_FIELD = 'expires'

# The access layer deliberately understands a small, closed method set.
# A typo such as "GEET" must not silently become an unconstrained caveat.
HTTP_METHODS = frozenset([
    'GET',
    'HEAD',
    'POST',
    'PUT',
    'PATCH',
    'DELETE',
    'OPTIONS',
    'TRACE',
    'CONNECT',
])

_EXPIRES_RE = re.compile(
    r'^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})'
    r'(?:\.(\d{1,6}))?([Zz]|[+-]\d{2}:\d{2})$'
)
_HEX_RE = re.compile(r'^[0-9A-Fa-f]{2}$')
_FIELD_RE = re.compile(r'^[a-z][a-z0-9_]*$')

# Delimiters that must never arrive percent-encoded. Decoding these would
# change how a path is split or let a second decode step reinterpret it.
_FORBIDDEN_ENCODED_BYTES = frozenset([
    0x23,  # '#'
    0x25,  # '%'
    0x2f,  # '/'
    0x3b,  # ';' (path parameters are framework-specific)
    0x3f,  # '?'
    0x5c,  # '\\'
])
_FORBIDDEN_LITERAL_CHARS = frozenset(['\\', '?', '#', ';'])


def _canonicalize_path(value, error_class):
    try:
        value = convert_to_string(value)
    except (TypeError, UnicodeError):
        raise error_class('Path must be a UTF-8 string.')

    if not value or not value.startswith('/'):
        raise error_class('Path must be absolute and start with "/".')

    decoded_bytes = bytearray()
    index = 0
    while index < len(value):
        char = value[index]
        if char == '%':
            if index + 2 >= len(value):
                raise error_class('Truncated percent-encoding in path.')
            hex_pair = value[index + 1:index + 3]
            if not _HEX_RE.match(hex_pair):
                raise error_class('Invalid percent-encoding in path.')
            encoded_byte = int(hex_pair, 16)
            if encoded_byte in _FORBIDDEN_ENCODED_BYTES:
                raise error_class(
                    'Percent-encoded path delimiters are not allowed: '
                    '%{0}'.format(hex_pair)
                )
            decoded_bytes.append(encoded_byte)
            index += 3
        else:
            if char in _FORBIDDEN_LITERAL_CHARS:
                raise error_class(
                    'Path contains a reserved character: {0}'.format(char)
                )
            try:
                decoded_bytes.extend(char.encode('utf-8'))
            except UnicodeError:
                raise error_class('Path is not valid UTF-8.')
            index += 1

    try:
        decoded = bytes(decoded_bytes).decode('utf-8')
    except UnicodeDecodeError:
        raise error_class('Path is not valid UTF-8 after decoding.')

    # A remaining percent sign means the input was percent-encoded twice.
    # Rejecting it keeps one decode pass from turning into a second pass.
    if '%' in decoded:
        raise error_class('Path must not be double percent-encoded.')

    for char in decoded:
        code_point = ord(char)
        if code_point < 0x20 or code_point == 0x7f:
            raise error_class('Path contains a control character.')
        if char != ' ' and char.isspace():
            raise error_class('Path contains non-space whitespace.')

    decoded = unicodedata.normalize('NFC', decoded)
    if ' = ' in decoded:
        raise error_class(
            'Path must not contain the caveat field separator " = ".'
        )
    if decoded == '/':
        return decoded
    if decoded.endswith('/'):
        decoded = decoded[:-1]

    segments = decoded.split('/')
    if not segments or segments[0] != '':
        raise error_class('Path must be absolute.')
    for segment in segments[1:]:
        if segment == '':
            raise error_class('Path contains an empty segment.')
        if segment in ('.', '..'):
            raise error_class('Path contains a dot segment.')
        if segment != segment.strip(' '):
            raise error_class(
                'Path segment must not start or end with a space.'
            )
    return decoded


def canonicalize_path(path):
    """Return the single canonical form used by request and caveat paths.

    Percent-encoding is decoded exactly once. Encoded path delimiters,
    double-encoded input, dot segments, empty segments, control characters,
    non-space whitespace, and non-UTF-8 input are rejected.
    """
    return _canonicalize_path(path, MacaroonAccessCaveatException)


def _canonicalize_method(method):
    try:
        method = convert_to_string(method)
    except (TypeError, UnicodeError):
        raise MacaroonAccessContextException(
            'HTTP method must be a UTF-8 string.'
        )
    if method not in HTTP_METHODS:
        raise MacaroonAccessContextException(
            'Unsupported HTTP method: {0}'.format(method)
        )
    return method


def _datetime_to_epoch_micros(value, error_class):
    if not isinstance(value, datetime.datetime):
        raise error_class('Time must be a datetime object.')
    offset = value.utcoffset()
    if offset is None:
        raise error_class(
            'Time must be timezone-aware (use datetime.timezone.utc).'
        )
    value = value - offset
    seconds = calendar.timegm(value.utctimetuple())
    return seconds * 1000000 + value.microsecond


def _parse_expires(value):
    match = _EXPIRES_RE.match(value)
    if not match:
        raise MacaroonAccessCaveatException(
            'Expiry must be an RFC 3339 timestamp with a UTC offset.'
        )
    groups = match.groups()
    try:
        parsed = datetime.datetime(
            int(groups[0]),
            int(groups[1]),
            int(groups[2]),
            int(groups[3]),
            int(groups[4]),
            int(groups[5]),
        )
    except ValueError:
        raise MacaroonAccessCaveatException('Expiry timestamp is invalid.')

    fraction = groups[6] or ''
    microseconds = int(fraction.ljust(6, '0')) if fraction else 0

    zone = groups[7]
    if zone in ('Z', 'z'):
        offset = datetime.timedelta(0)
    else:
        sign = 1 if zone[0] == '+' else -1
        hours = int(zone[1:3])
        minutes = int(zone[4:6])
        if hours > 23 or minutes > 59:
            raise MacaroonAccessCaveatException(
                'Expiry timestamp has an invalid UTC offset.'
            )
        offset = sign * datetime.timedelta(hours=hours, minutes=minutes)

    parsed = parsed - offset
    seconds = calendar.timegm(parsed.timetuple())
    return seconds * 1000000 + microseconds


def _format_expires(epoch_micros):
    seconds, microseconds = divmod(epoch_micros, 1000000)
    utc = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=seconds)
    formatted = utc.strftime('%Y-%m-%dT%H:%M:%S')
    if microseconds:
        formatted += '.{0:06d}'.format(microseconds)
    return formatted + 'Z'


def _deadline_to_epoch_micros(deadline):
    if isinstance(deadline, datetime.datetime):
        return _datetime_to_epoch_micros(
            deadline, MacaroonAccessCaveatException
        )
    if isinstance(deadline, string_types):
        try:
            deadline = convert_to_string(deadline)
        except UnicodeError:
            raise MacaroonAccessCaveatException(
                'Expiry must be a UTF-8 string.'
            )
        return _parse_expires(deadline)
    raise MacaroonAccessCaveatException(
        'Expiry must be a datetime or an RFC 3339 UTC string.'
    )


def resource_caveat(path):
    """Build a canonical ``access.resource`` caveat predicate."""
    return '{0}{1} = {2}'.format(
        ACCESS_NAMESPACE,
        RESOURCE_FIELD,
        _canonicalize_path(path, MacaroonAccessCaveatException),
    )


def method_caveat(method):
    """Build a canonical ``access.method`` caveat predicate."""
    try:
        method = convert_to_string(method)
    except (TypeError, UnicodeError):
        raise MacaroonAccessCaveatException(
            'HTTP method must be a UTF-8 string.'
        )
    if method not in HTTP_METHODS:
        raise MacaroonAccessCaveatException(
            'Unsupported HTTP method: {0}'.format(method)
        )
    return '{0}{1} = {2}'.format(
        ACCESS_NAMESPACE, METHOD_FIELD, method
    )


def expires_caveat(deadline):
    """Build a canonical ``access.expires`` caveat predicate."""
    return '{0}{1} = {2}'.format(
        ACCESS_NAMESPACE,
        EXPIRES_FIELD,
        _format_expires(_deadline_to_epoch_micros(deadline)),
    )


class RequestContext(object):
    """Immutable request data constructed once by the backend.

    Proxy headers must be resolved by the backend before this object is
    created. Structured interpreters only read these canonical fields, so a
    header cannot be interpreted differently by different verifiers.
    """

    __slots__ = ('_method', '_path', '_now', '_now_epoch_micros')

    def __init__(self, method, path, now):
        canonical_method = _canonicalize_method(method)
        canonical_path = _canonicalize_path(
            path, MacaroonAccessContextException
        )
        now_epoch_micros = _datetime_to_epoch_micros(
            now, MacaroonAccessContextException
        )
        object.__setattr__(self, '_method', canonical_method)
        object.__setattr__(self, '_path', canonical_path)
        object.__setattr__(self, '_now', now)
        object.__setattr__(self, '_now_epoch_micros', now_epoch_micros)

    def __setattr__(self, name, value):
        raise AttributeError('RequestContext is immutable.')

    @property
    def method(self):
        return self._method

    @property
    def path(self):
        return self._path

    @property
    def now(self):
        return self._now

    @property
    def now_epoch_micros(self):
        return self._now_epoch_micros

    def __repr__(self):
        return 'RequestContext(method={0!r}, path={1!r}, now={2!r})'.format(
            self._method, self._path, self._now
        )


class _ResourceInterpreter(object):

    def compile(self, value):
        return _canonicalize_path(value, MacaroonAccessCaveatException)

    def satisfied_by(self, constraint, context):
        if constraint == '/':
            return True
        return (
            context.path == constraint or
            context.path.startswith(constraint + '/')
        )


class _MethodInterpreter(object):

    def compile(self, value):
        if value not in HTTP_METHODS:
            raise MacaroonAccessCaveatException(
                'Unsupported HTTP method: {0}'.format(value)
            )
        return value

    def satisfied_by(self, constraint, context):
        return context.method == constraint


class _ExpiresInterpreter(object):

    def compile(self, value):
        return _parse_expires(value)

    def satisfied_by(self, constraint, context):
        # The deadline itself is inclusive. One microsecond later fails.
        return context.now_epoch_micros <= constraint


# Exactly one interpreter exists for each supported field. Adding a field
# means registering exactly one implementation here; everything else is
# rejected as unknown.
_INTERPRETERS = {
    RESOURCE_FIELD: _ResourceInterpreter(),
    METHOD_FIELD: _MethodInterpreter(),
    EXPIRES_FIELD: _ExpiresInterpreter(),
}


def is_structured_predicate(predicate):
    """Return True if a predicate belongs to the reserved access namespace.

    Detection is intentionally broad: a malformed ``access.*`` caveat is
    still claimed and rejected. It must never fall through to a permissive
    general callback.
    """
    try:
        predicate = convert_to_string(predicate)
    except (TypeError, UnicodeError):
        return False
    # Claim case variants too. "Access.method = GET" is not valid syntax,
    # and it must be rejected rather than handed to a permissive callback.
    return predicate.lstrip().lower().startswith(ACCESS_NAMESPACE)


def _split_structured_predicate(predicate):
    predicate = convert_to_string(predicate)
    if not predicate.startswith(ACCESS_NAMESPACE):
        raise MacaroonAccessCaveatException(
            'Malformed structured caveat: {0!r}'.format(predicate)
        )

    body = predicate[len(ACCESS_NAMESPACE):]
    parts = body.split(' = ')
    if len(parts) != 2:
        raise MacaroonAccessCaveatException(
            'Structured caveat must contain exactly one " = " separator.'
        )
    field, value = parts
    if not field or not value:
        raise MacaroonAccessCaveatException(
            'Structured caveat field and value must not be empty.'
        )
    if not _FIELD_RE.match(field):
        raise MacaroonAccessCaveatException(
            'Invalid structured caveat field: {0!r}'.format(field)
        )
    return field, value


def restrict(macaroon, resource=None, method=None, expires=None):
    """Append canonical structured caveats to a macaroon.

    Calling this again with another value for the same field further narrows
    access. Each caveat is evaluated independently at verification time, so
    the effective constraint is the intersection of all appended values.
    """
    if resource is None and method is None and expires is None:
        raise MacaroonAccessCaveatException(
            'At least one access constraint is required.'
        )
    if resource is not None:
        macaroon.add_first_party_caveat(resource_caveat(resource))
    if method is not None:
        macaroon.add_first_party_caveat(method_caveat(method))
    if expires is not None:
        macaroon.add_first_party_caveat(expires_caveat(expires))
    return macaroon


class StructuredCaveatVerifier(object):
    """Verify ``access.*`` predicates against one request context.

    Each caveat is evaluated independently, so appending another caveat for
    the same field narrows access (intersection) instead of replacing the
    previous value. A missing context fails closed.
    """

    def __init__(self, request_context=None):
        self._request_context = request_context

    @property
    def request_context(self):
        return self._request_context

    def claims(self, predicate):
        return is_structured_predicate(predicate)

    def check(self, predicate):
        """Return whether a structured predicate is met.

        Unknown fields, malformed syntax, and missing request context raise
        instead of returning a value that a caller could accidentally treat
        as satisfied.
        """
        if not self.claims(predicate):
            raise MacaroonAccessCaveatException(
                'Not a structured access caveat: {0!r}'.format(predicate)
            )

        field, value = _split_structured_predicate(predicate)
        interpreter = _INTERPRETERS.get(field)
        if interpreter is None:
            raise MacaroonAccessCaveatException(
                'Unknown structured caveat field: {0!r}'.format(field)
            )
        constraint = interpreter.compile(value)

        if self._request_context is None:
            raise MacaroonAccessContextException(
                'A RequestContext is required for structured caveats.'
            )
        return interpreter.satisfied_by(constraint, self._request_context)

    def verify(self, predicate):
        try:
            return self.check(predicate)
        except MacaroonAccessException:
            return False


__all__ = [
    'ACCESS_NAMESPACE',
    'HTTP_METHODS',
    'RequestContext',
    'StructuredCaveatVerifier',
    'canonicalize_path',
    'expires_caveat',
    'is_structured_predicate',
    'method_caveat',
    'resource_caveat',
    'restrict',
]
