"""
Handled exceptions raised by REST framework.

In addition, Django's built in 403 and 404 exceptions are handled.
(`django.http.Http404` and `django.core.exceptions.PermissionDenied`)
"""
import math

from django.http import JsonResponse
from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _
from django.utils.translation import ngettext

from rest_framework import status
from rest_framework.utils.serializer_helpers import ReturnDict, ReturnList


def _get_error_details(data, default_code=None):
    """
    Descend into a nested data structure, forcing any
    lazy translation strings or strings into `ErrorDetail`.
    """
    if isinstance(data, (list, tuple)):
        ret = [
            _get_error_details(item, default_code) for item in data
        ]
        if isinstance(data, ReturnList):
            return ReturnList(ret, serializer=data.serializer)
        return ret
    elif isinstance(data, dict):
        ret = {
            key: _get_error_details(value, default_code)
            for key, value in data.items()
        }
        if isinstance(data, ReturnDict):
            return ReturnDict(ret, serializer=data.serializer)
        return ret

    text = force_str(data)
    code = getattr(data, 'code', default_code)
    return ErrorDetail(text, code)


def _get_codes(detail):
    if isinstance(detail, list):
        return [_get_codes(item) for item in detail]
    elif isinstance(detail, dict):
        return {key: _get_codes(value) for key, value in detail.items()}
    return detail.code


def _get_full_details(detail):
    if isinstance(detail, list):
        return [_get_full_details(item) for item in detail]
    elif isinstance(detail, dict):
        return {key: _get_full_details(value) for key, value in detail.items()}
    return {
        'message': detail,
        'code': detail.code
    }


# Error codes that describe something a caller can act on. Any other code is
# treated as an internal implementation detail and is not exposed verbatim in
# projected bulk errors.
BULK_ERROR_PUBLIC_CODES = frozenset({
    'blank',
    'date',
    'datetime',
    'does_not_exist',
    'empty',
    'incorrect_match',
    'incorrect_type',
    'invalid',
    'invalid_choice',
    'invalid_image',
    'invalid_unicode',
    'make_aware',
    'max_decimal_places',
    'max_digits',
    'max_length',
    'max_string_length',
    'max_value',
    'max_whole_digits',
    'min_length',
    'min_value',
    'no_match',
    'no_name',
    'not_a_dict',
    'not_a_list',
    'null',
    'overflow',
    'required',
    'unique',
})

BULK_ERROR_INTERNAL_CODE = 'internal'
BULK_ERROR_INTERNAL_MESSAGE = _(
    'This row failed an internal validation rule and cannot be corrected '
    'from the submitted data.'
)


def _is_error_message_list(value):
    return not any(
        isinstance(item, (dict, list, tuple)) for item in value
    )


def _find_row_containers(detail, path, non_field_errors_key, containers):
    """
    Collect the mappings that describe submitted rows.

    A row container is a non-empty mapping keyed by item indexes, or a list
    whose items are mappings or lists. Containers may be nested under a field
    name (eg. ``{'items': {1: {...}}}``); row positions recorded by callers
    are always relative to the submitted list, so the container path is kept
    alongside the rows.
    """
    if isinstance(detail, dict):
        if detail and all(isinstance(key, int) for key in detail):
            containers.append((path, detail))
            return
        for key, value in detail.items():
            if key == non_field_errors_key:
                # Errors for the containing object, not child positions.
                continue
            child_path = path + (key if isinstance(key, int) else str(key),)
            _find_row_containers(
                value, child_path, non_field_errors_key, containers
            )
        return
    if isinstance(detail, (list, tuple)):
        if detail and not _is_error_message_list(detail):
            containers.append((path, detail))


def _iter_error_leaves(detail, path, non_field_errors_key):
    """
    Yield ``(path, message)`` for every leaf error in a validation detail
    tree. ``path`` contains submitted field names and indices only, so the
    caller can rebuild the position in the original input.

    A plain list may either contain error messages for the current position
    (eg. ``{'name': ['required']}``) or error details for child items (eg.
    ``[{'name': ['required']}, {}]``). Message lists do not add an index to
    the path, while lists containing mappings or lists are treated as item
    positions.
    """
    if isinstance(detail, str):
        yield path, detail
        return
    if isinstance(detail, dict):
        for key, value in detail.items():
            if key == non_field_errors_key:
                # Errors for the object itself, not for a child position.
                yield from _iter_error_leaves(
                    value, path, non_field_errors_key
                )
            elif isinstance(key, int):
                yield from _iter_error_leaves(
                    value, path + (key,), non_field_errors_key
                )
            else:
                yield from _iter_error_leaves(
                    value, path + (str(key),), non_field_errors_key
                )
        return
    if isinstance(detail, (list, tuple)):
        if not _is_error_message_list(detail):
            for index, item in enumerate(detail):
                if isinstance(item, (dict, list, tuple)):
                    yield from _iter_error_leaves(
                        item, path + (index,), non_field_errors_key
                    )
                else:
                    # A message at the level of the containing collection.
                    yield from _iter_error_leaves(
                        item, path, non_field_errors_key
                    )
            return
        for item in detail:
            yield from _iter_error_leaves(item, path, non_field_errors_key)
        return
    yield path, detail


def _iter_bulk_error_leaves(detail, non_field_errors_key):
    """
    Yield ``(container_path, row, row_path, message)`` for every leaf error
    attached to a submitted row. ``row_path`` is relative to the row.
    """
    containers = []
    _find_row_containers(detail, (), non_field_errors_key, containers)

    for container_path, rows in containers:
        items = rows.items() if isinstance(rows, dict) else enumerate(rows)
        for row, row_detail in items:
            for row_path, message in _iter_error_leaves(
                    row_detail, (), non_field_errors_key):
                yield container_path, row, row_path, message


def _error_field_path(path):
    """
    Format a submitted-input path as ``items[0].sku`` style notation.
    """
    ret = ''
    for part in path:
        if isinstance(part, int):
            ret += '[%d]' % part
        else:
            if ret:
                ret += '.'
            ret += part
    return ret or None


def _error_pointer(path):
    """
    Format a submitted-input path as an RFC 6901 JSON Pointer.
    """
    return ''.join(
        '/' + str(part).replace('~', '~0').replace('/', '~1')
        for part in path
    )


def _error_code(message):
    code = getattr(message, 'code', None)
    return str(code) if code is not None else ''


def _position_sort_key(container_path, row, row_path=()):
    """
    Sort submitted positions numerically rather than by pointer text, so
    row 10 follows row 9 and nested indices keep their natural order.
    """
    return (
        tuple((0, part) if isinstance(part, int) else (1, part)
              for part in container_path),
        row,
        tuple((0, part) if isinstance(part, int) else (1, part)
              for part in row_path),
    )


def project_bulk_errors(detail, *, public_codes=None,
                        non_field_errors_key='non_field_errors'):
    """
    Project a list-serializer error detail into a renderer-agnostic public
    structure.

    Each entry identifies the zero-based submitted row, the field path
    relative to that row, an RFC 6901 JSON Pointer rooted at the submitted
    payload, and a public classification code. Errors whose codes are not in
    ``public_codes`` are collapsed into a single generic ``internal`` entry
    for that row, so internal diagnostics never leak or move public
    positions.

    Return ``None`` if ``detail`` does not describe a list of items.
    """
    containers = []
    _find_row_containers(detail, (), non_field_errors_key, containers)
    if not containers:
        return None

    if public_codes is None:
        public_codes = BULK_ERROR_PUBLIC_CODES
    public_codes = frozenset(public_codes) - {BULK_ERROR_INTERNAL_CODE}

    records = []
    internal_rows = {}
    seen = set()

    for container_path, row, row_path, message in _iter_bulk_error_leaves(
            detail, non_field_errors_key):
        code = _error_code(message)
        if code not in public_codes:
            internal_rows[(container_path, row)] = _position_sort_key(
                container_path, row
            )
            continue

        pointer = _error_pointer(container_path + (row,) + row_path)
        key = (pointer, code, force_str(message))
        if key in seen:
            continue
        seen.add(key)
        records.append((
            _position_sort_key(container_path, row, row_path),
            {
                'row': row,
                'field': _error_field_path(row_path),
                'pointer': pointer,
                'code': code,
                'message': force_str(message),
            },
        ))

    # Internal failures are collapsed to one stable, row-level entry. Adding
    # or removing internal-only nodes therefore leaves every public row and
    # field position untouched.
    for (container_path, row), order in internal_rows.items():
        records.append((
            order,
            {
                'row': row,
                'field': None,
                'pointer': _error_pointer(container_path + (row,)),
                'code': BULK_ERROR_INTERNAL_CODE,
                'message': force_str(BULK_ERROR_INTERNAL_MESSAGE),
            },
        ))

    records.sort(key=lambda item: (item[0], item[1]['code']))
    return {'errors': [record for _, record in records]}


def get_error_paths(detail, *, non_field_errors_key='non_field_errors'):
    """
    Return every leaf error with its absolute RFC 6901 JSON Pointer.

    This is the support-facing view of a validation failure: unlike
    ``project_bulk_errors()`` it retains internal codes and original messages.
    For details that do not describe submitted rows, pointers are relative to
    the top-level error structure.
    """
    containers = []
    _find_row_containers(detail, (), non_field_errors_key, containers)

    records = []
    if containers:
        for container_path, row, row_path, message in (
                _iter_bulk_error_leaves(detail, non_field_errors_key)):
            records.append((
                _position_sort_key(container_path, row, row_path),
                {
                    'row': row,
                    'pointer': _error_pointer(
                        container_path + (row,) + row_path
                    ),
                    'code': _error_code(message) or None,
                    'message': force_str(message),
                },
            ))
    else:
        for path, message in _iter_error_leaves(
                detail, (), non_field_errors_key):
            records.append((
                _position_sort_key((), 0, path),
                {
                    'row': None,
                    'pointer': _error_pointer(path),
                    'code': _error_code(message) or None,
                    'message': force_str(message),
                },
            ))

    records.sort(key=lambda item: item[0])
    return [record for _, record in records]


class ErrorDetail(str):
    """
    A string-like object that can additionally have a code.
    """
    code = None

    def __new__(cls, string, code=None):
        self = super().__new__(cls, string)
        self.code = code
        return self

    def __eq__(self, other):
        result = super().__eq__(other)
        if result is NotImplemented:
            return NotImplemented
        try:
            return result and self.code == other.code
        except AttributeError:
            return result

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return NotImplemented
        return not result

    def __repr__(self):
        return 'ErrorDetail(string=%r, code=%r)' % (
            str(self),
            self.code,
        )

    def __hash__(self):
        return hash(str(self))


class APIException(Exception):
    """
    Base class for REST framework exceptions.
    Subclasses should provide `.status_code` and `.default_detail` properties.
    """
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = _('A server error occurred.')
    default_code = 'error'

    def __init__(self, detail=None, code=None):
        if detail is None:
            detail = self.default_detail
        if code is None:
            code = self.default_code

        self.detail = _get_error_details(detail, code)

    def __str__(self):
        return str(self.detail)

    def get_codes(self):
        """
        Return only the code part of the error details.

        Eg. {"name": ["required"]}
        """
        return _get_codes(self.detail)

    def get_full_details(self):
        """
        Return both the message & code parts of the error details.

        Eg. {"name": [{"message": "This field is required.", "code": "required"}]}
        """
        return _get_full_details(self.detail)

    def get_error_paths(self, *, non_field_errors_key='non_field_errors'):
        """
        Return the full diagnostic view of the error details as a flat list of
        messages with RFC 6901 JSON Pointers.

        Unlike projections used for external consumers, this retains internal
        codes and original messages. It is intended for logging, support
        tooling and custom exception handlers.
        """
        return get_error_paths(
            self.detail, non_field_errors_key=non_field_errors_key
        )

    def get_bulk_errors(self, *, public_codes=None,
                        non_field_errors_key='non_field_errors'):
        """
        Return a renderer-agnostic public projection of list-serializer
        errors, or `None` if the details do not describe a list of items.
        """
        return project_bulk_errors(
            self.detail,
            public_codes=public_codes,
            non_field_errors_key=non_field_errors_key,
        )


# The recommended style for using `ValidationError` is to keep it namespaced
# under `serializers`, in order to minimize potential confusion with Django's
# built in `ValidationError`. For example:
#
# from rest_framework import serializers
# raise serializers.ValidationError('Value was invalid')

class ValidationError(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = _('Invalid input.')
    default_code = 'invalid'

    def __init__(self, detail=None, code=None):
        if detail is None:
            detail = self.default_detail
        if code is None:
            code = self.default_code

        # For validation failures, we may collect many errors together,
        # so the details should always be coerced to a list if not already.
        if isinstance(detail, tuple):
            detail = list(detail)
        elif not isinstance(detail, dict) and not isinstance(detail, list):
            detail = [detail]

        self.detail = _get_error_details(detail, code)


class ParseError(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = _('Malformed request.')
    default_code = 'parse_error'


class AuthenticationFailed(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = _('Incorrect authentication credentials.')
    default_code = 'authentication_failed'


class NotAuthenticated(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = _('Authentication credentials were not provided.')
    default_code = 'not_authenticated'


class PermissionDenied(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = _('You do not have permission to perform this action.')
    default_code = 'permission_denied'


class NotFound(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = _('Not found.')
    default_code = 'not_found'


class MethodNotAllowed(APIException):
    status_code = status.HTTP_405_METHOD_NOT_ALLOWED
    default_detail = _('Method "{method}" not allowed.')
    default_code = 'method_not_allowed'

    def __init__(self, method, detail=None, code=None):
        if detail is None:
            detail = force_str(self.default_detail).format(method=method)
        super().__init__(detail, code)


class NotAcceptable(APIException):
    status_code = status.HTTP_406_NOT_ACCEPTABLE
    default_detail = _('Could not satisfy the request Accept header.')
    default_code = 'not_acceptable'

    def __init__(self, detail=None, code=None, available_renderers=None):
        self.available_renderers = available_renderers
        super().__init__(detail, code)


class UnsupportedMediaType(APIException):
    status_code = status.HTTP_415_UNSUPPORTED_MEDIA_TYPE
    default_detail = _('Unsupported media type "{media_type}" in request.')
    default_code = 'unsupported_media_type'

    def __init__(self, media_type, detail=None, code=None):
        if detail is None:
            detail = force_str(self.default_detail).format(media_type=media_type)
        super().__init__(detail, code)


class Throttled(APIException):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    default_detail = _('Request was throttled.')
    extra_detail_singular = _('Expected available in {wait} second.')
    extra_detail_plural = _('Expected available in {wait} seconds.')
    default_code = 'throttled'

    def __init__(self, wait=None, detail=None, code=None):
        if detail is None:
            detail = force_str(self.default_detail)
        if wait is not None:
            wait = math.ceil(wait)
            detail = ' '.join((
                detail,
                force_str(ngettext(self.extra_detail_singular.format(wait=wait),
                                   self.extra_detail_plural.format(wait=wait),
                                   wait))))
        self.wait = wait
        super().__init__(detail, code)


def server_error(request, *args, **kwargs):
    """
    Generic 500 error handler.
    """
    data = {
        'error': 'Server Error (500)'
    }
    return JsonResponse(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def bad_request(request, exception, *args, **kwargs):
    """
    Generic 400 error handler.
    """
    data = {
        'error': 'Bad Request (400)'
    }
    return JsonResponse(data, status=status.HTTP_400_BAD_REQUEST)
