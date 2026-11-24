from __future__ import annotations

import re

from django.http import HttpResponse, StreamingHttpResponse
from django.test import RequestFactory, override_settings

import pytest

from csp.caching import (
    NONCE_CACHE_PLACEHOLDER,
    is_prepared_nonce_response,
    prepare_for_cache,
    response_requires_nonce,
    restore_from_cache,
)
from csp.constants import HEADER
from csp.exceptions import CSPCacheError
from csp.middleware import CSPMiddleware

rf = RequestFactory()
mw = CSPMiddleware(lambda request: None)

_NONCE_HEADER_RE = re.compile(r"'nonce-([^']+)'")


def _nonced_request(path: str = "/"):
    request = rf.get(path)
    mw.process_request(request)
    return request


def _render_nonced_response(request, *, report_only: bool = False) -> HttpResponse:
    """Simulate a view whose inline authorization script reads the nonce."""
    nonce = str(request.csp_nonce)
    response = HttpResponse(f'<script nonce="{nonce}">doAuth();</script>')
    mw.process_response(request, response)
    return response


def _header_nonce(response, header: str = HEADER) -> str | None:
    match = _NONCE_HEADER_RE.search(response.get(header, ""))
    return match.group(1) if match else None


def test_plain_response_does_not_require_nonce() -> None:
    request = _nonced_request()
    response = HttpResponse("<p>no scripts here</p>")
    mw.process_response(request, response)
    assert response_requires_nonce(response) is False


def test_nonced_response_requires_nonce() -> None:
    request = _nonced_request()
    response = _render_nonced_response(request)
    assert response_requires_nonce(response) is True


def test_prepare_for_cache_passes_plain_response_through_unchanged() -> None:
    request = _nonced_request()
    response = HttpResponse("<p>cache me</p>")
    mw.process_response(request, response)

    cached = prepare_for_cache(response)

    assert cached is response
    assert is_prepared_nonce_response(cached) is False
    assert HEADER in cached
    assert "nonce-" not in cached[HEADER]


def test_prepare_for_cache_neutralises_nonce_in_body_and_header() -> None:
    request = _nonced_request()
    response = _render_nonced_response(request)
    real_nonce = str(request.csp_nonce)

    cached = prepare_for_cache(response)

    # The live response handed to the current request keeps its real nonce.
    assert f'nonce="{real_nonce}"' in response.content.decode()
    assert f"'nonce-{real_nonce}'" in response[HEADER]

    # The cached copy carries only the placeholder, never the real nonce.
    assert is_prepared_nonce_response(cached) is True
    assert real_nonce not in cached.content.decode()
    assert real_nonce not in cached[HEADER]
    assert f'nonce="{NONCE_CACHE_PLACEHOLDER}"' in cached.content.decode()
    assert f"'nonce-{NONCE_CACHE_PLACEHOLDER}'" in cached[HEADER]


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": ["'self'"]}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": ["'self'"]}},
)
def test_prepare_for_cache_records_enforced_and_report_only_policies() -> None:
    request = _nonced_request()
    response = _render_nonced_response(request)

    cached = prepare_for_cache(response)

    assert getattr(cached, "_csp_cached_policy") == "default-src 'self'"
    assert getattr(cached, "_csp_cached_policy_ro") == "default-src 'self'"


def test_restore_rebuilds_with_current_request_nonce() -> None:
    cold_request = _nonced_request()
    cold_response = _render_nonced_response(cold_request)
    old_nonce = str(cold_request.csp_nonce)
    cached = prepare_for_cache(cold_response)

    hit_request = _nonced_request()
    rebuilt = restore_from_cache(hit_request, cached)
    new_nonce = str(hit_request.csp_nonce)

    assert new_nonce != old_nonce
    assert _header_nonce(rebuilt) == new_nonce
    assert f'nonce="{new_nonce}"' in rebuilt.content.decode()
    # The stale nonce never reappears and the stored entry stays neutralised.
    assert old_nonce not in rebuilt.content.decode()
    assert old_nonce not in rebuilt[HEADER]
    assert NONCE_CACHE_PLACEHOLDER not in rebuilt.content.decode()
    assert f"'nonce-{NONCE_CACHE_PLACEHOLDER}'" not in rebuilt[HEADER]


def test_restore_does_not_mutate_the_stored_cache_entry() -> None:
    cold_request = _nonced_request()
    cached = prepare_for_cache(_render_nonced_response(cold_request))

    hit_request = _nonced_request()
    restore_from_cache(hit_request, cached)

    # The object held by the cache must remain a neutralised placeholder.
    assert is_prepared_nonce_response(cached) is True
    assert f"'nonce-{NONCE_CACHE_PLACEHOLDER}'" in cached[HEADER]
    assert f'nonce="{NONCE_CACHE_PLACEHOLDER}"' in cached.content.decode()


def test_restore_passes_plain_cached_response_through() -> None:
    request = _nonced_request()
    response = HttpResponse("<p>ordinary page</p>")
    mw.process_response(request, response)

    assert restore_from_cache(request, response) is response


def test_restore_raises_when_current_request_has_no_nonce() -> None:
    cold_request = _nonced_request()
    cached = prepare_for_cache(_render_nonced_response(cold_request))

    # A request whose nonce was never generated before the response phase closed
    # access to it: reading it now raises, so no rebuild nonce is available.
    bare_request = rf.get("/")
    mw.process_request(bare_request)
    mw.process_response(bare_request, HttpResponse())
    assert not getattr(bare_request, "_csp_nonce", None)

    with pytest.raises(CSPCacheError, match="no nonce"):
        restore_from_cache(bare_request, cached)


def test_restore_raises_when_csp_nonce_attribute_is_absent() -> None:
    cold_request = _nonced_request()
    cached = prepare_for_cache(_render_nonced_response(cold_request))

    # A request that never went through CSPMiddleware at all.
    unattached_request = rf.get("/")
    assert not hasattr(unattached_request, "csp_nonce")

    with pytest.raises(CSPCacheError, match="no nonce"):
        restore_from_cache(unattached_request, cached)


def test_restore_raises_on_policy_mismatch() -> None:
    cold_request = _nonced_request()
    cached = prepare_for_cache(_render_nonced_response(cold_request))

    # Simulate the security policy changing between render and cache hit.
    setattr(cached, "_csp_cached_policy", "default-src 'self' https://cdn.example.com")

    hit_request = _nonced_request()
    with pytest.raises(CSPCacheError, match="policy"):
        restore_from_cache(hit_request, cached)


def test_restore_raises_when_placeholder_is_missing() -> None:
    cold_request = _nonced_request()
    cached = prepare_for_cache(_render_nonced_response(cold_request))

    # Tamper with the stored entry so it no longer holds a rebuildable placeholder.
    cached[HEADER] = cached[HEADER].replace(NONCE_CACHE_PLACEHOLDER, "stale-real-nonce")
    cached.content = cached.content.replace(NONCE_CACHE_PLACEHOLDER.encode(), b"stale-real-nonce")

    hit_request = _nonced_request()
    with pytest.raises(CSPCacheError, match="placeholder"):
        restore_from_cache(hit_request, cached)


def test_prepare_for_cache_rejects_streaming_response() -> None:
    request = _nonced_request()
    nonce = str(request.csp_nonce)
    streaming = StreamingHttpResponse(iter([f'<script nonce="{nonce}">x</script>']))
    mw.process_response(request, streaming)

    with pytest.raises(CSPCacheError, match="Streaming"):
        prepare_for_cache(streaming)


def test_restore_handles_single_quoted_and_multiple_nonces() -> None:
    cold_request = _nonced_request()
    nonce = str(cold_request.csp_nonce)
    response = HttpResponse(f"<script nonce='{nonce}'>a();</script><script nonce=\"{nonce}\">b();</script>")
    mw.process_response(cold_request, response)

    cached = prepare_for_cache(response)
    assert nonce not in cached.content.decode()
    assert cached.content.count(NONCE_CACHE_PLACEHOLDER.encode()) == 2

    hit_request = _nonced_request()
    rebuilt = restore_from_cache(hit_request, cached)
    new_nonce = str(hit_request.csp_nonce)

    assert rebuilt.content.count(f'nonce="{new_nonce}"'.encode()) == 1
    assert rebuilt.content.count(f"nonce='{new_nonce}'".encode()) == 1
    assert new_nonce != nonce
    assert nonce not in rebuilt.content.decode()
    assert NONCE_CACHE_PLACEHOLDER not in rebuilt.content.decode()
