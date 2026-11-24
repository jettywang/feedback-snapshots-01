================================
Caching pages that use a nonce
================================

A CSP nonce is **per request**: the value embedded in a page's inline
``<script>`` tags has to match the value in that same response's
``Content-Security-Policy`` header, and it must never be reused for another
request. That means a rendered, nonce-bearing response cannot be stored
verbatim in Django's page cache, because every later cache hit would hand out
the same stale nonce.

Django's :class:`~django.middleware.cache.UpdateCacheMiddleware` and
:class:`~django.middleware.cache.FetchFromCacheMiddleware` cache whole rendered
responses and are unaware of this constraint. django-csp ships CSP-aware
replacements that keep the existing cache boundary (cache key, timeout,
``Vary`` handling) but add an explicit save/rebuild convention:

* **Saving (cold render)** — before a response is cached, every real nonce, in
  both the response body and the CSP headers, is replaced with a fixed
  placeholder, and the security policy the nonce was issued under is recorded
  on the response. The live response returned to the current request keeps its
  real nonce; only the stored copy is neutralised.
* **Rebuilding (cache hit)** — the stored response is cross-checked against the
  policy the current request would use, then the placeholder is replaced with
  the current request's freshly generated nonce in the body and headers.
* **Cannot rebuild** — if the stored entry has no placeholder, its recorded
  policy no longer matches the current request's policy, or there is no current
  nonce, the entry is evicted and the request falls through to a normal, fresh
  render. A reused nonce is never served.

Responses that do not use a nonce are cached and served completely unchanged,
so ordinary pages keep their normal cache behaviour.

Middleware setup
================

Use the two CSP-aware middleware in place of Django's stock cache middleware,
keeping ``CSPMiddleware`` between them so it runs after the fetch step and
before the update step::

    MIDDLEWARE = [
        "csp.contrib.cache.CSPUpdateCacheMiddleware",
        # ...
        "csp.middleware.CSPMiddleware",
        # ...
        "csp.contrib.cache.CSPFetchFromCacheMiddleware",
    ]

The standard Django cache settings apply as usual, for example
``CACHE_MIDDLEWARE_SECONDS``, ``CACHE_MIDDLEWARE_KEY_PREFIX`` and
``CACHE_MIDDLEWARE_ALIAS``.

How a request flows
===================

* **Cold render (cache miss):** the view renders with a fresh nonce,
  ``CSPMiddleware`` writes the matching CSP header, and the update middleware
  stores a neutralised copy whose body and header contain the placeholder
  instead of the real nonce.
* **Cache hit:** the fetch middleware returns the neutralised copy and rebuilds
  it with the current request's new nonce. The browser receives a body and CSP
  header that match, with a nonce it has never seen before. The entry stored in
  the cache is left neutralised.
* **Un-rebuildable entry:** a policy change, a missing placeholder or a missing
  request nonce raises :class:`csp.exceptions.CSPCacheError`. The fetch
  middleware deletes the bad entry and re-renders the page rather than reusing
  the old nonce.

Using the primitives directly
=============================

If you manage caching yourself (for example a custom cache backend or the
:func:`django.views.decorators.cache.cache_page` decorator family) you can use
the underlying functions from :mod:`csp.caching` instead of the middleware:

* :func:`csp.caching.prepare_for_cache(response)` returns a cache-safe copy of a
  nonce-bearing response, or the original response untouched when it has no
  nonce.
* :func:`csp.caching.restore_from_cache(request, response)` rebuilds a cached
  nonce response for the current request or raises
  :class:`~csp.exceptions.CSPCacheError` when it cannot be rebuilt.
