# This file is a part of Dramatiq.
#
# Copyright (C) 2017,2018,2019,2020 CLEARTYPE SRL <bogdan@cleartype.io>
#
# Dramatiq is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at
# your option) any later version.
#
# Dramatiq is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import annotations

import hashlib
import time
import typing
from urllib.parse import quote

from ..common import compute_backoff, q_name
from ..encoder import Encoder
from .errors import ResultMissing, ResultTimeout
from .result import unwrap_result, wrap_exception, wrap_result

#: The default timeout for blocking get operations in milliseconds.
DEFAULT_TIMEOUT = 10000

#: The minimum amount of time in ms to wait between polls.
BACKOFF_FACTOR = 100

#: Canary value that is returned when a result hasn't been set yet.
Missing = type("Missing", (object,), {})()

#: A type alias representing backend results.
Result = typing.Any

#: A union representing a Result that may or may not be there.
MResult = typing.Union[typing.Type[object], Result]

#: The message option that carries the scope a result belongs to.
RESULT_SCOPE_OPTION = "result_scope"

#: The scope used by callers that don't pass one explicitly.  It is
#: deliberately unscoped so legacy results remain readable.
DEFAULT_SCOPE: typing.Optional[str] = None

#: Attribute used to remember which scope a message belongs to when it
#: is decoded from a broker.  It is intentionally separate from
#: ``options`` so message options are never mutated by reads.
RESULT_SCOPE_ATTRIBUTE = "_result_scope"


def normalize_scope(scope: typing.Optional[str]) -> typing.Optional[str]:
    """Normalize a scope for use in keys and comparisons.

    ``None`` represents unscoped, legacy access.
    """
    if scope is None:
        return None
    if not isinstance(scope, str):
        raise TypeError("scope must be a string or None")
    if not scope:
        raise ValueError("scope must be a non-empty string")
    return scope


def get_message_scope(message) -> typing.Optional[str]:
    """Return the scope a message was produced for, if any."""
    scope = getattr(message, RESULT_SCOPE_ATTRIBUTE, None)
    if scope is not None:
        return normalize_scope(scope)

    options = getattr(message, "options", None) or {}
    scope = options.get(RESULT_SCOPE_OPTION)
    if scope is None:
        scope = options.get("scope")
    return normalize_scope(scope)


class ResultBackend:
    """ABC for result backends.

    Results are partitioned by an explicit scope.  Callers from
    different teams can therefore share a result backend while only
    being able to read the results stored under their own scope, even
    when message ids collide.

    Parameters:
      namespace(str): The logical namespace under which the data
        should be stored.
      encoder(Encoder): The encoder to use when storing and retrieving
        result data.  Defaults to :class:`.JSONEncoder`.
      use_namespace_prefix_keys(bool): When True, the keys used to store results
        use the format ``<namespace>:<scope>:<queue>:<actor>:<message_id>``
        for scoped results and ``<namespace>:<queue>:<actor>:<message_id>``
        for unscoped results, so that the keys are human-readable and
        can be scanned or expired by namespace in the backend.
        When False (the default) the keys are MD5 hashes of the format
        described above, so the namespace is not visible in the stored keys.
      allow_legacy_results(bool): Whether results written by older
        Dramatiq versions (which had no scope) may be read by scoped
        callers.  Defaults to False so that records with unknown
        ownership aren't exposed unless explicitly enabled.  Unscoped
        reads are always allowed.
      default_scope(str): The scope callers get when they don't pass
        one and their message doesn't carry one.  Defaults to None
        (unscoped) so existing usage keeps working.
      scope(str): Alias for ``default_scope``.  Set this when each
        caller process should only ever see its own team's results.
      result_scope(str): Alias for ``default_scope``.
      allow_legacy(bool): Alias for ``allow_legacy_results``.
    """

    def __init__(
        self,
        *,
        namespace: str = "dramatiq-results",
        encoder: typing.Optional[Encoder] = None,
        use_namespace_prefix_keys: bool = False,
        allow_legacy_results: bool = False,
        allow_legacy: bool = False,
        default_scope: typing.Optional[str] = DEFAULT_SCOPE,
        scope: typing.Optional[str] = None,
        result_scope: typing.Optional[str] = None,
    ):
        from ..message import get_encoder

        configured_scopes = [s for s in (scope, default_scope, result_scope) if s is not None]
        if len({normalize_scope(s) for s in configured_scopes}) > 1:
            raise ValueError("scope, default_scope and result_scope disagree")

        self.namespace = namespace
        self.encoder = encoder or get_encoder()
        self.use_namespace_prefix_keys = use_namespace_prefix_keys
        self.allow_legacy_results = bool(allow_legacy_results or allow_legacy)
        self.default_scope = normalize_scope(configured_scopes[0]) if configured_scopes else None
        self.scope = self.default_scope

    def unwrap_result(self, res):
        """Unwrap the serialized result.  Passes through to
        :func:`unwrap_result` by default, but can be overridden to
        complement changes to how :meth:`store_result` or
        :meth:`store_exception` serialize their results.

        Parameters:
          res(object): The result data, typically a dict.

        Returns:
          object: The result.
        """
        return unwrap_result(res)

    def resolve_scope(self, message, scope: typing.Optional[str] = None) -> typing.Optional[str]:
        """Resolve the scope a caller may access for a message.

        A per-call scope is authoritative.  Otherwise a scope
        configured on this backend instance wins, so a caller can't be
        redirected to another team's partition by message metadata.
        Only when neither is set does the message's own scope apply.
        """
        if scope is not None:
            return normalize_scope(scope)
        if self.scope is not None:
            return self.scope
        return get_message_scope(message)

    def get_result(
        self,
        message,
        *,
        block: bool = False,
        timeout: typing.Optional[int] = None,
        scope: typing.Optional[str] = None,
    ) -> Result:
        """Get a result from the backend.

        Parameters:
          message(Message)
          block(bool): Whether or not to block until a result is set.
          timeout(int): The maximum amount of time, in ms, to wait for
            a result when block is True.  Defaults to 10 seconds.
          scope(str): The scope the caller may read from.  Omitting it
            uses the backend's configured scope, then the message's
            own scope.
            Legacy (unscoped) results are only consulted when
            ``allow_legacy_results`` is enabled.

        Raises:
          ResultMissing: When block is False and the result isn't set.
          ResultTimeout: When waiting for a result times out.

        Returns:
          object: The result.
        """
        if timeout is None:
            timeout = DEFAULT_TIMEOUT

        resolved_scope = self.resolve_scope(message, scope)
        end_time = time.monotonic() + timeout / 1000
        message_keys = self.build_message_keys(message, scope=resolved_scope)

        attempts = 0
        while True:
            result = Missing
            for message_key in message_keys:
                result = self._get(message_key)
                if result is not Missing:
                    break

            if result is Missing and block:
                attempts, delay = compute_backoff(attempts, factor=BACKOFF_FACTOR)
                delay_seconds = delay / 1000
                if time.monotonic() + delay_seconds > end_time:
                    raise ResultTimeout(message, scope=resolved_scope)

                time.sleep(delay_seconds)
                continue

            elif result is Missing:
                raise ResultMissing(message, scope=resolved_scope)

            else:
                return self.unwrap_result(result)

    def store_result(
        self,
        message,
        result: Result,
        ttl: int,
        *,
        scope: typing.Optional[str] = None,
    ) -> None:
        """Store a result in the backend.

        Parameters:
          message(Message)
          result(object): Must be serializable.
          ttl(int): The maximum amount of time the result may be
            stored in the backend for.
          scope(str): The scope the result belongs to.
        """
        message_key = self._store_key(message, self.resolve_scope(message, scope))
        return self._store(message_key, wrap_result(result), ttl)

    def store_exception(
        self,
        message,
        exception: Exception,
        ttl: int,
        *,
        scope: typing.Optional[str] = None,
    ) -> None:
        """Store an exception in the backend.

        Parameters:
          message(Message)
          exception(Exception)
          ttl(int): The maximum amount of time the exception may be
            stored in the backend for.
          scope(str): The scope the exception belongs to.
        """
        message_key = self._store_key(message, self.resolve_scope(message, scope))
        return self._store(message_key, wrap_exception(exception), ttl)

    def build_message_keys(
        self,
        message,
        *,
        scope: typing.Optional[str] = None,
    ) -> list[str]:
        """Return the keys a caller may read, in priority order.

        The scoped key always comes first.  The legacy key is only
        included when ``allow_legacy_results`` is enabled and the
        caller is scoped, so records with unknown ownership stay
        invisible unless configured otherwise.
        """
        resolved_scope = self.resolve_scope(message, scope)
        keys = [self._key_for(message, resolved_scope)]
        if resolved_scope is not None and self.allow_legacy_results:
            legacy_key = self.build_legacy_message_key(message)
            if legacy_key not in keys:
                keys.append(legacy_key)
        return keys

    def _key_for(self, message, scope: typing.Optional[str]) -> str:
        """Build the key for a resolved scope.

        Unscoped keys go through :meth:`build_message_key` so custom
        backends that override it retain their key format.
        """
        if scope is None:
            return self.build_message_key(message)
        return self._format_message_key(message, scope)

    def build_message_key(self, message, *, scope: typing.Optional[str] = None) -> str:
        """Given a message, return its key.

        Without a scope or configured backend scope this returns the
        legacy key, so existing subclasses that override this method
        keep working.  Custom backends that need to see every scope
        should override :meth:`_format_message_key`.
        """
        resolved_scope = scope if scope is not None else self.scope
        return self._format_message_key(message, resolved_scope)

    def _store_key(self, message, scope: typing.Optional[str]) -> str:
        if scope is None and self.scope is None:
            return self.build_message_key(message)
        return self._format_message_key(message, scope)

    def build_legacy_message_key(self, message) -> str:
        """Given a message, return its unscoped (pre-scope) key."""
        return self._format_message_key(message, None)

    def _format_message_key(self, message, scope: typing.Optional[str]) -> str:
        scope = normalize_scope(scope)
        key_parts = [
            ("namespace", self.namespace),
        ]
        if scope is not None:
            key_parts.append(("scope", quote(scope, safe="")))
        key_parts.extend(
            [
                ("queue_name", q_name(message.queue_name)),
                ("actor_name", message.actor_name),
                ("message_id", message.message_id),
            ]
        )

        message_key = ":".join(value for _, value in key_parts)
        if self.use_namespace_prefix_keys:
            return message_key
        else:
            return hashlib.md5(message_key.encode("utf-8")).hexdigest()

    def _get(self, message_key: str) -> MResult:  # pragma: no cover
        """Get a result from the backend.  Subclasses may implement
        this method if they want to use the default, polling,
        implementation of get_result.
        """
        raise NotImplementedError(
            "%(classname)r does not implement _get()"
            % {
                "classname": type(self).__name__,
            }
        )

    def _store(self, message_key: str, result: Result, ttl: int) -> None:  # pragma: no cover
        """Store a result in the backend.  Subclasses may implement
        this method if they want to use the default implementation of
        set_result.
        """
        raise NotImplementedError(
            "%(classname)r does not implement _store()"
            % {
                "classname": type(self).__name__,
            }
        )
