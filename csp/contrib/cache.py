"""CSP-aware drop-in replacements for Django's two-part cache middleware.

Django's :class:`~django.middleware.cache.UpdateCacheMiddleware` and
:class:`~django.middleware.cache.FetchFromCacheMiddleware` cache whole rendered
responses. A response that contains a per-request CSP nonce cannot be cached
verbatim, so these subclasses apply the save/rebuild convention from
:mod:`csp.caching` while leaving the surrounding cache boundary (cache key,
timeout, ``Vary`` handling) exactly as Django defines it.

Use them in place of the stock middleware, keeping ``CSPMiddleware`` between
the two::

    MIDDLEWARE = [
        "csp.contrib.cache.CSPUpdateCacheMiddleware",
        # ...
        "csp.middleware.CSPMiddleware",
        # ...
        "csp.contrib.cache.CSPFetchFromCacheMiddleware",
    ]

* Responses without a nonce are cached and served unchanged.
* Nonce-bearing responses are stored with their nonce neutralised and rebuilt
  with the current request's fresh nonce on a hit.
* If a stored entry cannot be rebuilt, it is evicted and the request falls
  through to a normal, fresh render instead of reusing a stale nonce.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.core.cache import caches
from django.middleware.cache import FetchFromCacheMiddleware, UpdateCacheMiddleware
from django.utils.cache import get_cache_key, get_max_age, has_vary_header, learn_cache_key, patch_response_headers

from csp.caching import prepare_for_cache, restore_from_cache
from csp.exceptions import CSPCacheError
from csp.middleware import CSPMiddleware

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase


class CSPUpdateCacheMiddleware(UpdateCacheMiddleware):
    """Store a nonce-neutralised copy while returning the live response.

    Mirrors :meth:`UpdateCacheMiddleware.process_response` but swaps in the
    output of :func:`csp.caching.prepare_for_cache` only for the object written
    to the cache. The response returned to the current request keeps its real,
    per-request nonce.
    """

    def process_response(self, request: HttpRequest, response: HttpResponseBase) -> HttpResponseBase:
        if not self._should_update_cache(request, response):
            return response

        if response.streaming or response.status_code not in (200, 304):
            return response

        # Don't cache responses that set a user-specific (and maybe security
        # sensitive) cookie while varying on Cookie.
        if response.cookies and has_vary_header(response, "Cookie"):
            return response

        # Don't cache responses when the Cache-Control header is set to
        # private, no-cache, or no-store.
        cache_control = response.get("Cache-Control", "").lower()
        if cache_control and any(directive in cache_control for directive in ("private", "no-cache", "no-store")):
            return response

        # Don't cache responses when the Vary header contains '*'.
        if has_vary_header(response, "*"):
            return response

        timeout = self.page_timeout
        if timeout is None:
            timeout = get_max_age(response)
            if timeout is None:
                timeout = self.cache_timeout
            elif timeout == 0:
                # max-age was set to 0, don't cache.
                return response
        patch_response_headers(response, timeout)
        if timeout and response.status_code == 200:
            cache_key = learn_cache_key(request, response, timeout, self.key_prefix, cache=self.cache)
            # Neutralise nonces on the object that is stored; the live response
            # keeps its real nonce and is still returned to this request.
            cached_response = prepare_for_cache(response)
            self.cache.set(cache_key, cached_response, timeout)
        return response


class CSPFetchFromCacheMiddleware(FetchFromCacheMiddleware):
    """Rebuild a cached nonce response, falling back to a fresh render on failure."""

    # On a cache hit the view chain (and therefore CSPMiddleware.process_request)
    # never runs, so attach the lazily-generated request nonce ourselves before
    # rebuilding. The get_response callable is never invoked.
    _csp_middleware = CSPMiddleware(lambda request: None)

    def _ensure_request_nonce(self, request: HttpRequest) -> None:
        if not hasattr(request, "csp_nonce"):
            self._csp_middleware.process_request(request)

    def _evict(self, request: HttpRequest) -> None:
        cache = caches[self.cache_alias]
        cache_key = get_cache_key(request, self.key_prefix, request.method, cache=cache)
        if cache_key is not None:
            cache.delete(cache_key)

    def process_request(self, request: HttpRequest) -> HttpResponseBase | None:
        cached_response = super().process_request(request)
        if cached_response is None:
            # Cache miss: the view will be rendered and, if cacheable, stored.
            return None
        self._ensure_request_nonce(request)
        try:
            return restore_from_cache(request, cached_response)
        except CSPCacheError:
            # The entry cannot be safely rebuilt for this request. Evict it and
            # force a fresh render rather than serving a reused nonce.
            self._evict(request)
            request._cache_update_cache = True
            return None
