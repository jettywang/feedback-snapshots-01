"""Cache-safe handling of Content-Security-Policy nonces.

A CSP nonce is per-request: the value embedded in a page must match the value
in that response's ``Content-Security-Policy`` header and must never be reused
across requests. That makes a rendered, nonce-bearing response unsafe to store
verbatim in Django's per-site/per-view cache, because a later request would be
served a stale nonce.

This module defines an explicit save/rebuild convention:

* :func:`prepare_for_cache` is called before a response is cached. A response
  without a nonce is returned unchanged so ordinary pages keep caching. A
  response that carries a nonce has every real nonce value (in both the body
  and the CSP headers) replaced with :data:`NONCE_CACHE_PLACEHOLDER`, and the
  security policy the nonce was issued under is recorded on the response.
* :func:`restore_from_cache` is called on a cache hit. It cross-checks the
  policy recorded on the stored response against the policy the current request
  would use, then rebuilds the body and headers with the current request's
  fresh nonce. If the stored response cannot be rebuilt (no placeholder, a
  policy mismatch, or no current nonce), :class:`~csp.exceptions.CSPCacheError`
  is raised so the caller can evict the entry and render the page again.
"""

from __future__ import annotations

import copy
import re
from dataclasses import asdict
from typing import TYPE_CHECKING

from csp.constants import HEADER, HEADER_REPORT_ONLY
from csp.exceptions import CSPCacheError, CSPNonceError
from csp.middleware import CSPMiddleware
from csp.utils import build_policy

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase

# Sentinel written in place of a real nonce while a response is cached. It is
# deliberately not a valid base64 nonce value so it can never be mistaken for
# one served to a browser.
NONCE_CACHE_PLACEHOLDER = "csp-nonce-placeholder"

# Marker attribute set on a response once its nonces have been neutralised.
CACHED_NONCE_ATTR = "_csp_nonce_cached"
# Records the enforced policy (nonce stripped) the response was rendered under.
CACHED_POLICY_ATTR = "_csp_cached_policy"
# Records the report-only policy, when one was present.
CACHED_POLICY_RO_ATTR = "_csp_cached_policy_ro"

# Matches a `'nonce-<value>'` source inside a CSP header, capturing the value.
_NONCE_HEADER_RE = re.compile(r"'nonce-([^']+)'")
# Matches a `nonce="<value>"` attribute inside the response body.
_NONCE_BODY_RE = re.compile(rb'nonce=(["\'])(.*?)\1')
# The neutralised form written into a cached body, preserving the quote style.
_PLACEHOLDER_BODY_RE = re.compile(rb'nonce=(["\'])' + re.escape(NONCE_CACHE_PLACEHOLDER.encode("ascii")) + rb"\1")

# Reused to derive what the current request's policy *would* be. The
# ``get_response`` callable is never invoked for policy generation.
_policy_middleware = CSPMiddleware(lambda request: None)


def _canonical_policy(policy: str | None) -> str | None:
    """Normalise a policy string by removing its nonce source.

    Two policies that only differ by their per-request nonce value must compare
    equal so a rebuilt response can be cross-checked against the current
    request's policy.
    """
    if not policy:
        return None
    without_nonce = _NONCE_HEADER_RE.sub("", policy)
    # Collapse whitespace left behind by removing the nonce source, then put the
    # directives back into a stable form.
    directives = [re.sub(r"\s+", " ", directive).strip() for directive in without_nonce.split(";")]
    return "; ".join(directive for directive in directives if directive)


def current_policies(request: HttpRequest, response: HttpResponseBase) -> tuple[str | None, str | None]:
    """Return the (enforced, report-only) policies the current request would use.

    The values are canonicalised with the nonce stripped so they can be compared
    against the policies stored on a cached response.
    """
    policy_parts = _policy_middleware.get_policy_parts(request=request, response=response, report_only=False)
    policy = build_policy(**asdict(policy_parts))
    policy_parts_ro = _policy_middleware.get_policy_parts(request=request, response=response, report_only=True)
    policy_ro = build_policy(**asdict(policy_parts_ro), report_only=True)
    return _canonical_policy(policy), _canonical_policy(policy_ro)


def response_requires_nonce(response: HttpResponseBase) -> bool:
    """Return True if the response embeds a CSP nonce in a header or its body."""
    for header in (HEADER, HEADER_REPORT_ONLY):
        if header in response and _NONCE_HEADER_RE.search(response[header]):
            return True
    content = response.content if not response.streaming else b"".join(response.streaming_content)
    return bool(_NONCE_BODY_RE.search(content))


def prepare_for_cache(response: HttpResponseBase) -> HttpResponseBase:
    """Neutralise nonces on a response that is about to be cached.

    Responses without a nonce are returned untouched so they cache exactly as
    before. Nonce-bearing responses are copied, their real nonce values are
    replaced with :data:`NONCE_CACHE_PLACEHOLDER` in both the body and the CSP
    headers, and the originating policy is recorded for later verification.
    """
    if not response_requires_nonce(response):
        return response
    if response.streaming:
        # Django's cache middleware never stores streaming responses, so there
        # is no cache entry to neutralise. Refuse rather than consume the stream.
        raise CSPCacheError("Streaming responses cannot be neutralised for caching.")

    cached = copy.deepcopy(response)

    for header in (HEADER, HEADER_REPORT_ONLY):
        if header in cached:
            cached[header] = _NONCE_HEADER_RE.sub(f"'nonce-{NONCE_CACHE_PLACEHOLDER}'", cached[header])

    cached.content = _NONCE_BODY_RE.sub(
        lambda match: b"nonce=" + match.group(1) + NONCE_CACHE_PLACEHOLDER.encode("ascii") + match.group(1),
        cached.content,
    )

    setattr(cached, CACHED_NONCE_ATTR, True)
    setattr(cached, CACHED_POLICY_ATTR, _canonical_policy(response.get(HEADER)))
    setattr(cached, CACHED_POLICY_RO_ATTR, _canonical_policy(response.get(HEADER_REPORT_ONLY)))
    return cached


def is_prepared_nonce_response(response: HttpResponseBase) -> bool:
    """Return True if the response holds a neutralised, cache-safe nonce."""
    return getattr(response, CACHED_NONCE_ATTR, False) is True


def _copy_cached_response(response: HttpResponseBase) -> HttpResponseBase:
    # A cache backend may return the very object it stores. Work on a fully
    # independent copy so rebuilding never mutates the cached entry itself.
    try:
        return copy.deepcopy(response)
    except Exception as exc:  # pragma: no cover - defensive, deepcopy is the normal path
        raise CSPCacheError("The cached response could not be copied for rebuilding.") from exc


def restore_from_cache(request: HttpRequest, response: HttpResponseBase) -> HttpResponseBase:
    """Rebuild a cached, nonce-bearing response for the current request.

    The stored placeholder nonce is replaced with the current request's fresh
    nonce in both the body and the CSP headers. The policy recorded when the
    response was cached is cross-checked against the current request's policy;
    any mismatch, a missing placeholder, or the absence of a current nonce
    raises :class:`~csp.exceptions.CSPCacheError` so the caller can discard the
    stale entry and re-render.
    """
    if not is_prepared_nonce_response(response):
        # Nothing to rebuild: ordinary cached responses pass straight through.
        return response

    nonce = getattr(request, "_csp_nonce", None)
    if not isinstance(nonce, str):
        # A hit on a nonce-bearing response always needs a nonce, so force the
        # request's lazily-generated value into existence. Reading it after the
        # response phase raises CSPNonceError, which here means there is no
        # nonce available to rebuild with.
        lazy_nonce = getattr(request, "csp_nonce", None)
        if lazy_nonce is None:
            raise CSPCacheError(
                "A cached nonce response cannot be rebuilt because the current request has no nonce. "
                "Discard the cached entry and render the page again."
            )
        try:
            nonce = str(lazy_nonce)
        except CSPNonceError as exc:
            raise CSPCacheError(
                "A cached nonce response cannot be rebuilt because the current request has no nonce. "
                "Discard the cached entry and render the page again."
            ) from exc

    current_policy, current_policy_ro = current_policies(request, response)
    stored_policy = getattr(response, CACHED_POLICY_ATTR, None)
    stored_policy_ro = getattr(response, CACHED_POLICY_RO_ATTR, None)
    if stored_policy != current_policy or stored_policy_ro != current_policy_ro:
        raise CSPCacheError(
            "The cached response's CSP policy does not match the current request's policy. " "Discard the cached entry and render the page again."
        )

    rebuilt = _copy_cached_response(response)
    placeholder_header = f"'nonce-{NONCE_CACHE_PLACEHOLDER}'"
    rebuilt_any = False
    for header in (HEADER, HEADER_REPORT_ONLY):
        if header in rebuilt and placeholder_header in rebuilt[header]:
            rebuilt[header] = rebuilt[header].replace(placeholder_header, f"'nonce-{nonce}'")
            rebuilt_any = True

    body = rebuilt.content if not rebuilt.streaming else b"".join(rebuilt.streaming_content)
    placeholder_body = _PLACEHOLDER_BODY_RE.search(body)
    if placeholder_body is not None:
        body = _PLACEHOLDER_BODY_RE.sub(
            lambda match: b"nonce=" + match.group(1) + nonce.encode("ascii") + match.group(1),
            body,
        )
        rebuilt_any = True
    if not rebuilt.streaming:
        rebuilt.content = body

    if not rebuilt_any:
        raise CSPCacheError(
            "The cached response no longer contains a rebuildable nonce placeholder. " "Discard the cached entry and render the page again."
        )

    return rebuilt
