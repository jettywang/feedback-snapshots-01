# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Operation-level authorization for credentialed requests.

Scopes describe which Google APIs a credential may call, but they do not
describe what an application intends to do with a particular resource. An
:class:`OperationPermission` lets an application approve the concrete HTTP
method and URL of a request separately from the credential's scopes.

Permissions are checked immediately before each application request is sent,
including requests retried after a credential refresh. They are therefore
evaluated against the method and URL that are actually transmitted.
"""

import collections.abc
import logging
import re

from google.auth import exceptions

_LOGGER = logging.getLogger(__name__)

_UNSET = object()

_OPERATION_PERMISSION_KWARGS = (
    "operation_permission",
    "operation_permissions",
    "operation_approval",
    "permission",
    "approval",
    "operation_authorizer",
    "permission_checker",
)


def _extract_operation_permission(kwargs, default=None):
    """Pops an operation permission argument from ``kwargs``.

    ``operation_permission`` is the documented argument. The other names are
    accepted as aliases so callers can use the terminology that fits their
    application.

    Args:
        kwargs (dict): Keyword arguments to search. Recognized keys are
            removed.
        default: The value to return when no permission argument was given.

    Returns:
        The supplied permission, or ``default``. An explicitly supplied
        ``None`` is returned as ``None``.
    """
    operation_permission = kwargs.pop("operation_permission", _UNSET)
    for alias in _OPERATION_PERMISSION_KWARGS[1:]:
        value = kwargs.pop(alias, _UNSET)
        if operation_permission is _UNSET and value is not _UNSET:
            operation_permission = value

    if operation_permission is _UNSET:
        return default
    return operation_permission


class OperationPermission:
    """Approves specific HTTP methods on specific resources.

    Example::

        permission = OperationPermission(
            {
                "GET": [r"https://storage\\.googleapis\\.com/b/bucket/object"],
                "PUT": [r"https://storage\\.googleapis\\.com/b/bucket/object"],
            }
        )
        authed_session = AuthorizedSession(
            credentials, operation_permission=permission
        )

    Args:
        allowed_methods (Union[Mapping[str, Sequence[str]], Sequence[Tuple[str, str]]]):
            A mapping from an HTTP method to resources that method may be used
            with, or a sequence of ``(method, resource)`` pairs. A resource may
            be an exact URL or a regular expression matched against the full
            request URL. A method with an empty sequence is rejected.
        allow_all_methods (Sequence[str]): HTTP methods that may be used with
            any URL. This is useful for read-only access to an API.
        deny_methods (Sequence[str]): HTTP methods that are never allowed. This
            takes precedence over the other arguments.

    Raises:
        google.auth.exceptions.InvalidType: If an argument is not the expected
            type.
        google.auth.exceptions.InvalidValue: If an HTTP method is empty or a
            URL pattern is not a valid regular expression.
    """

    def __init__(
        self,
        allowed_methods=None,
        allow_all_methods=None,
        deny_methods=None,
    ):
        self._allowed_methods = {}
        self._allow_all_methods = set()
        self._deny_methods = set()

        if allowed_methods is not None:
            allowed_methods = _normalize_allowed_methods(
                _details_to_allowed_methods(allowed_methods)
            )
            for method, patterns in allowed_methods.items():
                normalized_method = _normalize_method(method)
                patterns = _as_pattern_sequence(patterns)
                self._allowed_methods[normalized_method] = tuple(
                    _compile_pattern(pattern) for pattern in patterns
                )

        if allow_all_methods is not None:
            allow_all_methods = _as_pattern_sequence(allow_all_methods)
            self._allow_all_methods = {
                _normalize_method(method) for method in allow_all_methods
            }

        if deny_methods is not None:
            deny_methods = _as_pattern_sequence(deny_methods)
            self._deny_methods = {_normalize_method(method) for method in deny_methods}

    def allows(self, method, url):
        """Returns whether the given operation is approved.

        Args:
            method (str): The HTTP method that will be sent.
            url (str): The URL that will be sent.

        Returns:
            bool: ``True`` if the operation is approved.
        """
        try:
            normalized_method = _normalize_method(method)
        except exceptions.InvalidType:
            return False

        if not isinstance(url, str):
            return False

        if normalized_method in self._deny_methods:
            return False

        if normalized_method in self._allow_all_methods:
            return True

        return any(
            pattern.matches(url)
            for pattern in self._allowed_methods.get(normalized_method, ())
        )

    def check(self, method, url):
        """Raises if the given operation is not approved.

        Args:
            method (str): The HTTP method that will be sent.
            url (str): The URL that will be sent.

        Raises:
            google.auth.exceptions.OperationNotPermitted: If the operation is
                not approved.
        """
        if not self.allows(method, url):
            _raise_operation_denied(method, url)

    def __call__(self, method, url):
        """Callable form used by :class:`AuthorizedSession`.

        Returns:
            bool: ``True`` if the operation is approved.
        """
        return self.allows(method, url)


def check_operation_permission(operation_permission, method, url):
    """Checks an operation permission supplied to an authorized transport.

    ``operation_permission`` may be an :class:`OperationPermission`, a callable
    taking ``(method, url)`` and returning a truthy value, a mapping of methods
    to resources, a sequence of ``(method, resource)`` pairs, or ``None`` (no
    additional restriction).

    Args:
        operation_permission (Optional[Union[OperationPermission, Mapping, Sequence, Callable]]):
            The configured operation permission.
        method (str): The HTTP method to be sent.
        url (str): The URL to be sent.

    Raises:
        google.auth.exceptions.OperationNotPermitted: If the operation is not
            approved.
    """
    if operation_permission is None:
        return

    if not isinstance(operation_permission, OperationPermission):
        if callable(operation_permission):
            pass
        elif hasattr(operation_permission, "allows") and callable(
            operation_permission.allows
        ):
            allowed = operation_permission.allows(method, url)
            if not allowed:
                _raise_operation_denied(method, url)
            return
        else:
            operation_permission = OperationPermission(
                _details_to_allowed_methods(operation_permission)
            )

    allowed = operation_permission(method, url)
    if not allowed:
        _raise_operation_denied(method, url)


def _raise_operation_denied(method, url):
    _LOGGER.warning("Operation not permitted: %s %s", method, _redact_url(url))
    raise exceptions.OperationNotPermitted(
        "The {} request to {} is not approved by the active operation "
        "permission.".format(method, _redact_url(url))
    )


def _normalize_method(method):
    if not isinstance(method, str) or not method:
        raise exceptions.InvalidType("HTTP method must be a non-empty string.")
    return method.upper()


def _details_to_allowed_methods(details):
    """Converts authorization details into method-to-resource entries.

    A mapping with ``type``, ``actions`` and ``locations`` is treated as an
    OAuth Rich Authorization Request style authorization detail. A mapping of
    methods to resources is passed through unchanged.
    """
    if isinstance(details, collections.abc.Mapping):
        if "actions" in details and "locations" in details:
            return [
                (action, location)
                for action in _as_pattern_sequence(details["actions"])
                for location in _as_pattern_sequence(details["locations"])
            ]
        return details
    return details


def _normalize_allowed_methods(allowed_methods):
    if isinstance(allowed_methods, collections.abc.Mapping):
        return dict(allowed_methods)

    try:
        items = list(allowed_methods)
    except TypeError as caught_exc:
        raise exceptions.InvalidType(
            "allowed_methods must be a mapping or a sequence of (method, resource) pairs."
        ) from caught_exc

    normalized = {}
    for item in items:
        if isinstance(item, collections.abc.Mapping):
            try:
                method = item["method"]
                resource = item["resource"]
            except KeyError as caught_exc:
                raise exceptions.InvalidValue(
                    "Each operation must contain 'method' and 'resource'."
                ) from caught_exc
        else:
            try:
                method, resource = item
            except (TypeError, ValueError) as caught_exc:
                raise exceptions.InvalidType(
                    "Each operation must be a (method, resource) pair."
                ) from caught_exc
        normalized.setdefault(method, []).append(resource)
    return normalized


def _as_pattern_sequence(value):
    if isinstance(value, str):
        return [value]
    try:
        return list(value)
    except TypeError as caught_exc:
        raise exceptions.InvalidType(
            "HTTP methods must be supplied as a string or a sequence of strings."
        ) from caught_exc


class _UrlPattern:
    """Matches an exact resource URL or a regular expression for it."""

    def __init__(self, pattern):
        self._literal = pattern
        try:
            self._regex = re.compile(pattern)
        except re.error as caught_exc:
            raise exceptions.InvalidValue(
                "Invalid URL pattern {!r}: {}".format(pattern, caught_exc)
            ) from caught_exc

    def matches(self, url):
        return url == self._literal or self._regex.fullmatch(url) is not None


def _compile_pattern(pattern):
    if not isinstance(pattern, str):
        raise exceptions.InvalidType("URL patterns must be strings.")
    return _UrlPattern(pattern)


def _redact_url(url):
    """Removes query parameters and fragments from a URL for logs and errors."""
    if not isinstance(url, str):
        return url
    return url.split("?", 1)[0].split("#", 1)[0]
