from __future__ import annotations

import re

from django.core.cache import cache
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from django.utils.cache import get_cache_key

from csp.caching import CACHED_NONCE_ATTR, NONCE_CACHE_PLACEHOLDER
from csp.constants import HEADER, HEADER_REPORT_ONLY, NONCE
from csp.contrib.cache import CSPFetchFromCacheMiddleware, CSPUpdateCacheMiddleware
from csp.middleware import CSPMiddleware

rf = RequestFactory()
_NONCE_HEADER_RE = re.compile(r"'nonce-([^']+)'")


def _nonce_view(request):
    # The inline authorization script consumes the per-request nonce.
    nonce = str(request.csp_nonce)
    return HttpResponse(f'<script nonce="{nonce}">authorize();</script>')


def _plain_view(request):
    return HttpResponse("<p>ordinary cacheable page</p>")


def _build_stack(view):
    # Mirror the documented two-part cache layout around CSPMiddleware.
    csp_mw = CSPMiddleware(view)
    fetch_mw = CSPFetchFromCacheMiddleware(csp_mw)
    update_mw = CSPUpdateCacheMiddleware(fetch_mw)
    return update_mw


def _header_nonce(response, header: str = HEADER) -> str | None:
    match = _NONCE_HEADER_RE.search(response.get(header, ""))
    return match.group(1) if match else None


def _body_nonce(response) -> str | None:
    match = re.search(rb'nonce="(.*?)"', response.content)
    return match.group(1).decode() if match else None


def _stored_response(path: str):
    request = rf.get(path)
    cache_key = get_cache_key(request, "", "GET", cache=cache)
    assert cache_key is not None, "expected the view to have been cached"
    return cache_key, cache.get(cache_key)


_CACHE_SETTINGS = {
    "ALLOWED_HOSTS": ["testserver"],
    "CACHE_MIDDLEWARE_SECONDS": 300,
    "CACHE_MIDDLEWARE_KEY_PREFIX": "",
    "CACHE_MIDDLEWARE_ALIAS": "default",
}


@override_settings(
    **_CACHE_SETTINGS,
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["'self'", NONCE]}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": ["'self'", NONCE]}},
)
def test_cold_render_then_cache_hit_rebuilds_fresh_nonce() -> None:
    cache.clear()
    path = "/nonce-page/"
    stack = _build_stack(_nonce_view)

    # First request: cold render. The view runs, the nonce is generated, and the
    # neutralised response is written to the cache.
    first_response = stack(rf.get(path))
    first_nonce = _header_nonce(first_response)

    assert first_nonce is not None
    assert _body_nonce(first_response) == first_nonce
    assert f"'nonce-{first_nonce}'" in first_response[HEADER]

    # Inspect what actually landed in the cache: a placeholder, never the nonce.
    _, stored = _stored_response(path)
    assert getattr(stored, CACHED_NONCE_ATTR, False) is True
    assert first_nonce not in stored.content.decode()
    assert first_nonce not in stored[HEADER]
    assert f'nonce="{NONCE_CACHE_PLACEHOLDER}"' in stored.content.decode()
    assert f"'nonce-{NONCE_CACHE_PLACEHOLDER}'" in stored[HEADER]
    assert f"'nonce-{NONCE_CACHE_PLACEHOLDER}'" in stored[HEADER_REPORT_ONLY]

    # Second request: cache hit, rebuilt with a brand-new per-request nonce.
    second_response = stack(rf.get(path))
    second_nonce = _header_nonce(second_response)

    assert second_nonce is not None
    assert second_nonce != first_nonce
    assert _body_nonce(second_response) == second_nonce
    assert f"'nonce-{second_nonce}'" in second_response[HEADER]
    assert _header_nonce(second_response) == second_nonce
    assert _header_nonce(second_response, HEADER_REPORT_ONLY) == second_nonce
    assert first_nonce not in second_response.content.decode()
    assert NONCE_CACHE_PLACEHOLDER not in second_response.content.decode()

    # The stored entry is still neutralised after serving the hit.
    _, stored_after = _stored_response(path)
    assert f"'nonce-{NONCE_CACHE_PLACEHOLDER}'" in stored_after[HEADER]


@override_settings(**_CACHE_SETTINGS)
def test_unrebuildable_entry_is_evicted_and_page_re_rendered() -> None:
    cache.clear()
    path = "/nonce-page-broken/"
    stack = _build_stack(_nonce_view)

    cold_response = stack(rf.get(path))
    cold_nonce = _header_nonce(cold_response)

    # Corrupt the stored nonce entry so it can no longer be rebuilt.
    cache_key, stored = _stored_response(path)
    stored[HEADER] = stored[HEADER].replace(NONCE_CACHE_PLACEHOLDER, "deadbeef")
    stored.content = stored.content.replace(NONCE_CACHE_PLACEHOLDER.encode(), b"deadbeef")
    cache.set(cache_key, stored, 300)

    hit_response = stack(rf.get(path))
    fresh_nonce = _header_nonce(hit_response)

    # A fresh render happened: no stale/dead nonce is served to the browser.
    assert fresh_nonce is not None
    assert fresh_nonce != cold_nonce
    assert "deadbeef" not in hit_response.content.decode()
    assert _body_nonce(hit_response) == fresh_nonce
    assert f"'nonce-{fresh_nonce}'" in hit_response[HEADER]

    # The dead entry was evicted and replaced by a freshly neutralised one.
    _, re_stored = _stored_response(path)
    assert getattr(re_stored, CACHED_NONCE_ATTR, False) is True
    assert f"'nonce-{NONCE_CACHE_PLACEHOLDER}'" in re_stored[HEADER]
    assert "deadbeef" not in re_stored.content.decode()


@override_settings(**_CACHE_SETTINGS)
def test_plain_page_without_nonce_keeps_cache_hit() -> None:
    cache.clear()
    path = "/plain-page/"
    stack = _build_stack(_plain_view)

    first_response = stack(rf.get(path))
    assert "nonce-" not in first_response[HEADER]

    second_response = stack(rf.get(path))

    # The ordinary page is served from cache unchanged (identical body/header).
    assert second_response.content == first_response.content
    assert second_response[HEADER] == first_response[HEADER]
    assert not getattr(second_response, CACHED_NONCE_ATTR, False)
    assert "nonce-" not in second_response[HEADER]
