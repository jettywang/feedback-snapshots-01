"""
h2/push
~~~~~~~

Tools for deciding whether pushed streams should be admitted.

This module provides a ready-made admission policy for use with the
``push_promise_admission_callback`` setting of
:class:`H2Configuration <h2.config.H2Configuration>`. The policy ensures that
a client only consumes resources pushed for origins it trusts, rather than
accepting arbitrary resources just because the connection itself is
authenticated.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Callable, Iterable

    from hpack.struct import Header


def _to_str(value: bytes | str) -> str:
    """
    Normalize a header name or value to text for comparison purposes.
    """
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _request_target(headers: Iterable[Header] | None) -> tuple[str, str, str, str] | None:
    """
    Extract the (method, scheme, authority, path) tuple from a request header
    block. Returns ``None`` if any of the pseudo-headers is missing.
    """
    if headers is None:
        return None

    method = scheme = authority = path = None
    for name, value in headers:
        str_name = _to_str(name)
        if str_name == ":method":
            method = _to_str(value)
        elif str_name == ":scheme":
            scheme = _to_str(value).lower()
        elif str_name == ":authority":
            authority = _to_str(value).lower()
        elif str_name == ":path":
            path = _to_str(value)

    if method is None or scheme is None or authority is None or path is None:
        return None
    return method, scheme, authority, path


def _normalize_origin(origin: str | tuple[str, str]) -> tuple[str, str]:
    """
    Normalize an origin, given either as a ``"scheme://authority"`` string or
    as a ``(scheme, authority)`` tuple, to a lowercase ``(scheme, authority)``
    tuple.
    """
    if isinstance(origin, str):
        scheme, separator, authority = origin.partition("://")
        if not separator:
            msg = f"Invalid origin {origin!r}: expected 'scheme://authority'"
            raise ValueError(msg)
        return scheme.lower(), authority.lower()
    scheme, authority = origin
    return scheme.lower(), authority.lower()


class PushPromiseAdmissionPolicy:
    """
    A ready-made PUSH_PROMISE admission callback that only admits resources
    pushed from trusted origins, subject to a caller-supplied resource
    policy.

    A promise is admitted only if all of the following hold:

    - push is currently enabled in the local settings;
    - the promised request carries all of the ``:method``, ``:scheme``,
      ``:authority`` and ``:path`` pseudo-headers;
    - the origin of the promised request either matches the origin of the
      parent request or appears in ``trusted_origins``;
    - the same resource (method, scheme, authority and path) has not already
      been admitted on this connection, preventing duplicate promises;
    - ``resource_policy``, if given, accepts the promised request.

    Anything else is refused: refused pushes produce no events and the
    promised stream is immediately reset.

    This object is stateful (it tracks the resources already admitted), so a
    separate instance must be used for each connection.

    :param trusted_origins: Additional origins, beyond the origin of the
        parent request, that are allowed to push resources. Each origin may
        be given as a ``"scheme://authority"`` string or as a
        ``(scheme, authority)`` tuple. Defaults to the empty set, meaning
        only same-origin pushes are admitted.
    :type trusted_origins: iterable of ``str`` or ``(str, str)`` tuples

    :param resource_policy: An optional callable invoked with
        ``(method, scheme, authority, path)`` for each candidate push. It
        must return ``True`` to admit the resource. Defaults to ``None``,
        which admits every resource from a trusted origin.
    :type resource_policy: callable or ``None``

    .. versionadded:: 4.5.0
    """

    def __init__(self,
                 trusted_origins: Iterable[str | tuple[str, str]] = (),
                 resource_policy: Callable[[str, str, str, str], bool] | None = None) -> None:
        self.trusted_origins = frozenset(
            _normalize_origin(origin) for origin in trusted_origins
        )
        self.resource_policy = resource_policy
        self._admitted_resources: set[tuple[str, str, str, str]] = set()

    def __call__(self,
                 parent_headers: Iterable[Header] | None,
                 promised_headers: Iterable[Header] | None,
                 push_enabled: bool) -> bool:
        if not push_enabled:
            return False

        promised_target = _request_target(promised_headers)
        if promised_target is None:
            return False

        method, scheme, authority, _path = promised_target
        promised_origin = (scheme, authority)
        parent_target = _request_target(parent_headers)
        parent_origin = (
            (parent_target[1], parent_target[2])
            if parent_target is not None else None
        )

        if promised_origin != parent_origin and promised_origin not in self.trusted_origins:
            return False

        if promised_target in self._admitted_resources:
            return False

        if self.resource_policy is not None and not self.resource_policy(*promised_target):
            return False

        self._admitted_resources.add(promised_target)
        return True
