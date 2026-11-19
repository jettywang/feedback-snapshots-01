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

import time

import redis

from ...common import compute_backoff
from ..backend import BACKOFF_FACTOR, DEFAULT_TIMEOUT, ResultBackend, ResultMissing, ResultTimeout


class RedisBackend(ResultBackend):
    """A result backend for Redis_.  This is the recommended result
    backend as waiting for a result is resource efficient.

    Parameters:
      namespace(str): A string with which to prefix result keys.
      encoder(Encoder): The encoder to use when storing and retrieving
        result data.  Defaults to :class:`.JSONEncoder`.
      use_namespace_prefix_keys(bool): When True, the keys used to store results
        use the format ``<namespace>:<scope>:<queue>:<actor>:<message_id>``
        for scoped results and ``<namespace>:<queue>:<actor>:<message_id>``
        for unscoped results, so that the keys are human-readable and can be
        scanned or expired by namespace in the backend.
        When False (the default) the keys are MD5 hashes of the format described above,
        so the namespace is not visible in the stored keys.
      allow_legacy_results(bool): Whether scoped callers may fall back to
        results written without a scope.  Defaults to False.
      allow_legacy(bool): Alias for ``allow_legacy_results``.
      default_scope(str): The scope to use when neither the call nor the
        message provides one.
      scope(str): Alias for ``default_scope``.
      result_scope(str): Alias for ``default_scope``.
      client(Redis): An optional client.  If this is passed,
        then all other parameters are ignored.
      url(str): An optional connection URL.  If both a URL and
        connection parameters are provided, the URL is used.
      **parameters: Connection parameters are passed directly
        to :class:`redis.Redis`.

    .. _redis: https://redis.io
    """

    def __init__(
        self,
        *,
        namespace="dramatiq-results",
        encoder=None,
        use_namespace_prefix_keys=False,
        allow_legacy_results=False,
        allow_legacy=False,
        default_scope=None,
        scope=None,
        result_scope=None,
        client=None,
        url=None,
        **parameters,
    ):
        super().__init__(
            namespace=namespace,
            encoder=encoder,
            use_namespace_prefix_keys=use_namespace_prefix_keys,
            allow_legacy_results=allow_legacy_results,
            allow_legacy=allow_legacy,
            default_scope=default_scope,
            scope=scope,
            result_scope=result_scope,
        )

        if url:
            parameters["connection_pool"] = redis.ConnectionPool.from_url(url)

        self.client = client or redis.Redis(**parameters)

    def get_result(self, message, *, block=False, timeout=None, scope=None):
        """Get a result from the backend.

        Warning:
          Sub-second timeouts are not respected by this backend.

        Parameters:
          message(Message)
          block(bool): Whether or not to block until a result is set.
          timeout(int): The maximum amount of time, in ms, to wait for
            a result when block is True.  Defaults to 10 seconds.
          scope(str): The scope the caller may read from.

        Raises:
          ResultMissing: When block is False and the result isn't set.
          ResultTimeout: When waiting for a result times out.

        Returns:
          object: The result.
        """
        if timeout is None:
            timeout = DEFAULT_TIMEOUT

        resolved_scope = self.resolve_scope(message, scope)
        message_keys = self.build_message_keys(message, scope=resolved_scope)

        if block:
            timeout = int(timeout / 1000)
            data = None
            # Poll each permitted key in turn so scoped and legacy
            # records are treated identically, without ever reading a
            # key the caller is not allowed to see.
            if timeout == 0:
                data = self._blocking_get(message_keys, 0)
            else:
                data = self._blocking_get(message_keys, timeout)

            if data is None:
                raise ResultTimeout(message, scope=resolved_scope)

        else:
            data = None
            for message_key in message_keys:
                data = self.client.lindex(message_key, 0)
                if data is not None:
                    break

            if data is None:
                raise ResultMissing(message, scope=resolved_scope)

        return self.unwrap_result(self.encoder.decode(data))

    def _blocking_get(self, message_keys, timeout):
        if len(message_keys) == 1:
            message_key = message_keys[0]
            if timeout == 0:
                return self.client.rpoplpush(message_key, message_key)
            return self.client.brpoplpush(message_key, message_key, timeout)

        # Multiple permitted keys are polled within a single overall
        # timeout so the caller can't extend their wait by accident.
        end_time = time.monotonic() + timeout
        attempts = 0
        while True:
            for message_key in message_keys:
                data = self.client.rpoplpush(message_key, message_key)
                if data is not None:
                    return data

            if time.monotonic() >= end_time:
                return None

            attempts, delay = compute_backoff(attempts, factor=BACKOFF_FACTOR)
            time.sleep(min(delay / 1000, max(0, end_time - time.monotonic())))

    def _store(self, message_key, result, ttl):
        with self.client.pipeline() as pipe:
            pipe.delete(message_key)
            pipe.lpush(message_key, self.encoder.encode(result))
            pipe.pexpire(message_key, ttl)
            pipe.execute()
