"""JWKS retrieval that tolerates a temporarily unavailable source.

The only thing this module replaces is the network and cache layer used to
obtain verification keys.  Token parsing, token classes and the translation
from ``PyJWKClientError`` to Simple JWT's ``TokenBackendError`` stay in their
original modules.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from typing import Any, Callable

try:
    from jwt import PyJWKClient, PyJWKClientError, PyJWTError, PyJWKSet
except ImportError:  # pragma: no cover - PyJWT 1.7.1 has no JWKS client
    PyJWKClient = None  # type: ignore[misc,assignment]
    PyJWKClientError = Exception  # type: ignore[misc,assignment]
    PyJWTError = Exception  # type: ignore[misc,assignment]
    PyJWKSet = None  # type: ignore[misc,assignment]

logger = logging.getLogger("rest_framework_simplejwt.jwks")

DEFAULT_CACHE_LIFESPAN = 300.0
DEFAULT_TIMEOUT = 5.0
DEFAULT_REFRESH_COOLDOWN = 30.0


_JWK_CLIENT_BASE = PyJWKClient if PyJWKClient is not None else object


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects so a forwarder response cannot retarget the fetch."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ResilientJWKClient(_JWK_CLIENT_BASE):  # type: ignore[misc,valid-type]
    """Fetch a JWK Set and keep the last good copy across source outages.

    Behaviour during a refresh failure is deliberately different for the two
    kinds of requests a verifier can receive:

    * a token whose ``kid`` is present in the last good JWK Set is served from
      that cached key (stale-if-error);
    * a token whose ``kid`` is unknown cannot be verified and fails, waiting
      for the forwarder to come back.

    A successful refresh replaces the whole set.  Keys that disappeared from
    the source are therefore retired immediately; the cache is never merged
    with the new response.
    """

    def __init__(
        self,
        uri: str,
        *,
        lifespan: float = DEFAULT_CACHE_LIFESPAN,
        timeout: float = DEFAULT_TIMEOUT,
        headers: dict[str, Any] | None = None,
        allow_stale: bool = True,
        refresh_cooldown: float = DEFAULT_REFRESH_COOLDOWN,
        clock: Callable[[], float] | None = None,
    ) -> None:
        super().__init__(uri=uri, headers=headers, timeout=timeout)
        # This client owns the cache.  Leaving PyJWT's cache enabled would
        # discard the last good set as soon as its lifespan expires, which is
        # exactly the set needed during a source outage.
        self.jwk_set_cache = None
        self.cache_lifespan = float(lifespan)
        self.allow_stale = allow_stale
        # After a failed fetch, do not make every request wait on the same
        # dead forwarder.  Known keys are served stale in the meantime.
        self.refresh_cooldown = max(0.0, float(refresh_cooldown))
        self._retry_after: float | None = None
        # Separate budget for refreshes triggered by an unknown kid, so a
        # stream of random kids cannot turn into a fetch storm.
        self._unknown_kid_retry_after: float | None = None
        # Injectable only so tests can produce a deterministic timeline.
        # Production uses the monotonic clock.
        self._clock = clock or time.monotonic

        self._lock = threading.RLock()
        self._fetch_lock = threading.Lock()
        self._cached_jwk_set: PyJWKSet | None = None
        self._cached_at: float | None = None
        self._last_success_at: float | None = None
        self._last_error: dict[str, Any] | None = None
        self._last_result: dict[str, Any] | None = None
        self._reads: deque[dict[str, Any]] = deque(maxlen=200)

    # -- public lookups -------------------------------------------------
    def get_signing_key(self, kid: str) -> Any:
        with self._lock:
            cached_set = self._cached_jwk_set

            if cached_set is not None:
                cached_key = self._match(cached_set, kid)
                if cached_key is not None:
                    if self._is_fresh() or not self._refresh_due():
                        # Fresh cache hit, or a dead source inside its
                        # cooldown: both serve the last good key without
                        # waiting on the forwarder.
                        stale = not self._is_fresh()
                        self._record(
                            kid,
                            "cache_stale" if stale else "cache",
                            "served",
                            category="source_unavailable" if stale else "fresh",
                            error=self._last_error_type() if stale else None,
                        )
                        if stale:
                            # The failure itself was logged when it was
                            # observed; do not repeat it on every request.
                            logger.debug(
                                "jwks_stale_key_served kid=%s uri=%s",
                                kid,
                                self.uri,
                                extra={
                                    "event": "jwks_stale_key_served",
                                    "kid": kid,
                                    "uri": self.uri,
                                },
                            )
                        else:
                            logger.debug(
                                "jwks_cache_hit kid=%s uri=%s",
                                kid,
                                self.uri,
                                extra={
                                    "event": "jwks_cache_hit",
                                    "kid": kid,
                                    "uri": self.uri,
                                },
                            )
                        return cached_key

                    # The key is known but its cache has expired; ask the
                    # source.  On failure, prefer service over freshness.
                    try:
                        refreshed = self._refresh(kid, "cache_expired")
                    except PyJWKClientError as exc:
                        if not self.allow_stale:
                            self._load_failure(kid, "cache_expired", exc)
                            raise
                        self._note_error(kid, "cache_expired", exc)
                        self._record(
                            kid,
                            "cache_stale",
                            "served",
                            category="source_unavailable",
                            error=type(exc).__name__,
                        )
                        logger.warning(
                            "jwks_stale_key_served kid=%s uri=%s error=%s",
                            kid,
                            self.uri,
                            type(exc).__name__,
                            extra={
                                "event": "jwks_stale_key_served",
                                "kid": kid,
                                "uri": self.uri,
                                "error": type(exc).__name__,
                            },
                        )
                        return cached_key

                    refreshed_key = self._match(refreshed, kid)
                    if refreshed_key is not None:
                        self._record(kid, "network", "served", category="refreshed")
                        return refreshed_key
                    # A successful refresh is authoritative: the key has
                    # been retired even though it is still in the cache.
                    self._retired(kid, refreshed)
                    raise self._unknown_key(kid)

                # The cached set is usable, but not for this token.  A new
                # key may have been published, so try the source once -- if
                # its cooldown permits.  A cached miss is never a cache hit:
                # no cached key can carry this request.
                if not self._refresh_due() or not self._unknown_kid_refresh_due():
                    self._cached_miss(kid)
                    raise self._unknown_key(kid)
                try:
                    refreshed = self._refresh(kid, "unknown_kid")
                except PyJWKClientError as exc:
                    self._note_error(kid, "cached_key_missing", exc)
                    self._record(
                        kid,
                        "cache",
                        "unknown_key",
                        category="source_unavailable",
                        error=type(exc).__name__,
                    )
                    logger.warning(
                        "jwks_key_not_found kid=%s uri=%s kids=%s "
                        "source_error=%s",
                        kid,
                        self.uri,
                        ",".join(self._kids(cached_set)),
                        type(exc).__name__,
                        extra={
                            "event": "jwks_key_not_found",
                            "kid": kid,
                            "uri": self.uri,
                            "kids": self._kids(cached_set),
                            "source_error": type(exc).__name__,
                        },
                    )
                    raise self._unknown_key(kid) from None
                refreshed_key = self._match(refreshed, kid)
                if refreshed_key is not None:
                    self._record(kid, "network", "served", category="refreshed")
                    return refreshed_key
                self._retired(kid, refreshed)
                raise self._unknown_key(kid)

            # Cold start: there is no key that could carry this request.
            if not self._refresh_due():
                exc = PyJWKClientError("JWKS source is cooling down")
                self._load_failure(kid, "no_cache", exc)
                raise exc
            try:
                jwk_set = self._refresh(kid, "cold_start")
            except PyJWKClientError as exc:
                self._load_failure(kid, "no_cache", exc)
                raise
            signing_key = self._match(jwk_set, kid)
            if signing_key is not None:
                self._record(kid, "network", "served", category="refreshed")
                return signing_key
            self._retired(kid, jwk_set)
            raise self._unknown_key(kid)

    def _cached_miss(self, kid: str) -> None:
        # A fresh set that has just been fetched but does not contain the kid
        # is authoritative: the key is retired.  A stale set without a recent
        # successful fetch means the source itself is unavailable.
        retired = self._is_fresh() and self._retry_after is None
        category = "retired" if retired else "source_unavailable"
        error = None if retired else (self._last_error_type() or "cooldown")
        self._record(
            kid,
            "cache",
            "unknown_key",
            category=category,
            error=error,
        )
        logger.warning(
            "jwks_key_not_found kid=%s uri=%s kids=%s source_error=%s",
            kid,
            self.uri,
            ",".join(self._kids(self._cached_jwk_set)),
            error,
            extra={
                "event": "jwks_key_not_found",
                "kid": kid,
                "uri": self.uri,
                "kids": self._kids(self._cached_jwk_set),
                "source_error": error,
            },
        )

    def _last_error_type(self) -> str | None:
        if self._last_error is None:
            return None
        return self._last_error.get("type")

    def get_signing_key_from_jwt(self, token: str | bytes) -> Any:
        try:
            return super().get_signing_key_from_jwt(token)
        except PyJWKClientError:
            raise
        except PyJWTError as exc:
            # A malformed token is an invalid token, not a broken JWKS
            # source.  Backend.get_verifying_key already translates
            # PyJWKClientError into the public TokenBackendError message.
            raise PyJWKClientError("Unable to read token header") from exc

    def cache_status(self) -> dict[str, Any]:
        """Return a point-in-time snapshot suitable for diagnostics."""
        with self._lock:
            age = (
                None
                if self._cached_at is None
                else max(0.0, self._clock() - self._cached_at)
            )
            return {
                "uri": self.uri,
                "cached": self._cached_jwk_set is not None,
                "cached_kids": self._kids(self._cached_jwk_set),
                "cache_age_seconds": age,
                "cache_fresh": self._is_fresh(),
                "last_success_at": self._last_success_at,
                "last_error": dict(self._last_error)
                if self._last_error is not None
                else None,
                "last_result": dict(self._last_result)
                if self._last_result is not None
                else None,
                "retry_after_seconds": self._retry_after_seconds(),
                "unknown_kid_retry_after_seconds": (
                    self._unknown_kid_retry_after_seconds()
                ),
                "reads": [dict(read) for read in self._reads],
            }

    # -- cache and fetch internals --------------------------------------
    def _refresh_due(self) -> bool:
        return self._retry_after is None or self._clock() >= self._retry_after

    def _unknown_kid_refresh_due(self) -> bool:
        return (
            self._unknown_kid_retry_after is None
            or self._clock() >= self._unknown_kid_retry_after
        )

    def _retry_after_seconds(self) -> float | None:
        if self._retry_after is None:
            return None
        return max(0.0, self._retry_after - self._clock())

    def _unknown_kid_retry_after_seconds(self) -> float | None:
        if self._unknown_kid_retry_after is None:
            return None
        return max(0.0, self._unknown_kid_retry_after - self._clock())

    def _refresh(self, kid: str | None, reason: str) -> PyJWKSet:
        # Only one thread talks to the forwarder; others wait and then use
        # the result instead of piling up timed-out requests.
        with self._fetch_lock:
            return self._refresh_locked(kid, reason)

    def _refresh_locked(self, kid: str | None, reason: str) -> PyJWKSet:
        # Another thread may have failed while this one waited for the lock.
        # Re-check the cooldown so a burst of requests produces one fetch.
        if not self._refresh_due():
            raise PyJWKClientError("JWKS source is cooling down")
        if reason == "unknown_kid" and not self._unknown_kid_refresh_due():
            raise PyJWKClientError("JWKS unknown-kid refresh is cooling down")

        started = self._clock()
        try:
            data = self.fetch_data()
            if isinstance(data, PyJWKSet):
                jwk_set = data
            elif isinstance(data, dict):
                jwk_set = PyJWKSet.from_dict(data)
            else:
                raise PyJWKClientError("The JWKS endpoint did not return a JSON object")
        except PyJWKClientError:
            self._retry_after = started + self.refresh_cooldown
            raise
        except (PyJWTError, OSError, ValueError, TypeError, KeyError) as exc:
            self._retry_after = started + self.refresh_cooldown
            raise PyJWKClientError(f"Unable to load JWKS: {exc}") from exc

        # One assignment: a failed or partial refresh can never expose a
        # half-updated key set to another thread.
        self._cached_jwk_set = jwk_set
        self._cached_at = started
        self._last_success_at = self._wall_time()
        self._last_error = None
        self._retry_after = None
        logger.info(
            "jwks_refresh_ok kid=%s reason=%s uri=%s kids=%s",
            kid,
            reason,
            self.uri,
            ",".join(self._kids(jwk_set)),
            extra={
                "event": "jwks_refresh_ok",
                "kid": kid,
                "reason": reason,
                "uri": self.uri,
                "kids": self._kids(jwk_set),
            },
        )
        return jwk_set

    def fetch_data(self) -> Any:
        """Fetch the raw JWK Set payload from the forwarder.

        Overridable so tests can inject an outage without opening a socket.
        """
        request = urllib.request.Request(url=self.uri, headers=self.headers)
        opener = urllib.request.build_opener(_NoRedirectHandler())
        try:
            with opener.open(request, timeout=self.timeout) as response:
                return json.load(response)
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            ValueError,
        ) as exc:
            raise PyJWKClientError(f"Unable to fetch JWKS: {exc}") from exc

    def _match(self, jwk_set: PyJWKSet, kid: str) -> Any:
        for key in jwk_set.keys:
            # Mirror PyJWT's signing-key filter: only keys explicitly
            # marked for signing (or with no 'use') and carrying a kid
            # can be selected.
            if key.public_key_use in ("sig", None) and key.key_id:
                if key.key_id == kid:
                    return key
        return None

    def _is_fresh(self) -> bool:
        return (
            self._cached_jwk_set is not None
            and self._cached_at is not None
            and self.cache_lifespan > 0
            and self._clock() - self._cached_at < self.cache_lifespan
        )

    def _record(
        self,
        kid: str,
        source: str,
        outcome: str,
        *,
        category: str,
        error: str | None = None,
    ) -> None:
        read = {
            "kid": kid,
            "source": source,
            "outcome": outcome,
            "category": category,
            "at": self._wall_time(),
            "cached_kids": self._kids(self._cached_jwk_set),
            "error": error,
        }
        self._last_result = read
        self._reads.append(read)

    @staticmethod
    def _wall_time() -> float:
        return time.time()

    def _note_error(
        self, kid: str, cache_state: str, exc: PyJWKClientError
    ) -> None:
        self._last_error = {
            "type": type(exc).__name__,
            "message": str(exc),
            "at": self._wall_time(),
            "kid": kid,
            "cache_state": cache_state,
        }

    def _load_failure(
        self, kid: str, cache_state: str, exc: PyJWKClientError
    ) -> None:
        self._note_error(kid, cache_state, exc)
        self._record(
            kid,
            "network",
            "failed",
            category="source_unavailable",
            error=type(exc).__name__,
        )
        logger.warning(
            "jwks_refresh_failed kid=%s cache=%s uri=%s error=%s",
            kid,
            cache_state,
            self.uri,
            type(exc).__name__,
            extra={
                "event": "jwks_refresh_failed",
                "kid": kid,
                "cache": cache_state,
                "uri": self.uri,
                "error": type(exc).__name__,
            },
        )

    def _retired(self, kid: str, jwk_set: PyJWKSet) -> None:
        self._unknown_kid_retry_after = self._clock() + self.refresh_cooldown
        self._record(kid, "network", "unknown_key", category="retired")
        logger.warning(
            "jwks_key_not_found kid=%s uri=%s kids=%s",
            kid,
            self.uri,
            ",".join(self._kids(jwk_set)),
            extra={
                "event": "jwks_key_not_found",
                "kid": kid,
                "uri": self.uri,
                "kids": self._kids(jwk_set),
            },
        )

    @staticmethod
    def _unknown_key(kid: str) -> PyJWKClientError:
        return PyJWKClientError(f'Unable to find a signing key that matches: "{kid}"')

    @staticmethod
    def _kids(jwk_set: PyJWKSet | None) -> list[str]:
        if jwk_set is None:
            return []
        return sorted(key.key_id for key in jwk_set.keys if key.key_id)
