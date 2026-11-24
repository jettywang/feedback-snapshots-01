from __future__ import annotations

import base64
import http.client as http_client
import os
import warnings
from dataclasses import asdict, dataclass, replace
from functools import partial
from typing import TYPE_CHECKING

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject, empty

from csp.approvals import PolicySnapshot, capture_snapshot
from csp.constants import HEADER, HEADER_REPORT_ONLY
from csp.exceptions import CSPNonceError
from csp.utils import DIRECTIVES_T, build_policy

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase


@dataclass
class PolicyParts:
    # A dataclass is used rather than a namedtuple so that the attributes are mutable
    config: DIRECTIVES_T | None = None
    update: DIRECTIVES_T | None = None
    replace: DIRECTIVES_T | None = None
    nonce: str | None = None


class CheckableLazyObject(SimpleLazyObject):
    """A SimpleLazyObject where bool(obj) returns True if no longer lazy"""

    def __bool__(self) -> bool:
        """
        If the wrapped function has been evaluated, return True.
        If the wrapped function has not been evalated, return False.
        """
        return getattr(self, "_wrapped") is not empty


class CSPMiddleware(MiddlewareMixin):
    """
    Implements the Content-Security-Policy response header, which
    conforming user-agents can use to restrict the permitted sources
    of various content.

    See http://www.w3.org/TR/CSP/

    Can be customised by subclassing and extending the get_policy_parts method.
    """

    def _make_nonce(self, request: HttpRequest) -> str:
        # Ensure that any subsequent calls to request.csp_nonce return the same value
        stored_nonce = getattr(request, "_csp_nonce", None)
        if isinstance(stored_nonce, str):
            return stored_nonce
        nonce = base64.b64encode(os.urandom(16)).decode("ascii")
        setattr(request, "_csp_nonce", nonce)
        return nonce

    @staticmethod
    def _csp_nonce_post_response() -> None:
        raise CSPNonceError(
            "The 'csp_nonce' attribute is not available after the CSP header has been written. Consider adjusting your MIDDLEWARE order."
        )

    def process_request(self, request: HttpRequest) -> None:
        nonce = partial(self._make_nonce, request)
        setattr(request, "csp_nonce", CheckableLazyObject(nonce))

    def process_response(self, request: HttpRequest, response: HttpResponseBase) -> HttpResponseBase:
        # Check for debug view
        exempted_debug_codes = (
            http_client.INTERNAL_SERVER_ERROR,
            http_client.NOT_FOUND,
        )
        if response.status_code in exempted_debug_codes and settings.DEBUG:
            return response

        policy_parts = self.get_policy_parts(request=request, response=response)
        csp = build_policy(**asdict(policy_parts))
        if csp:
            # Only set header if not already set and not an excluded prefix and not exempted.
            is_not_exempt = getattr(response, "_csp_exempt", False) is False
            no_header = HEADER not in response
            policy = getattr(settings, "CONTENT_SECURITY_POLICY", None) or {}
            prefixes = policy.get("EXCLUDE_URL_PREFIXES", None) or ()
            is_not_excluded = not request.path_info.startswith(tuple(prefixes))
            if no_header and is_not_exempt and is_not_excluded:
                response[HEADER] = csp

        policy_parts_ro = self.get_policy_parts(request=request, response=response, report_only=True)
        csp_ro = build_policy(**asdict(policy_parts_ro), report_only=True)
        if csp_ro:
            # Only set header if not already set and not an excluded prefix and not exempted.
            is_not_exempt = getattr(response, "_csp_exempt_ro", False) is False
            no_header = HEADER_REPORT_ONLY not in response
            policy = getattr(settings, "CONTENT_SECURITY_POLICY_REPORT_ONLY", None) or {}
            prefixes = policy.get("EXCLUDE_URL_PREFIXES", None) or ()
            is_not_excluded = not request.path_info.startswith(tuple(prefixes))
            if no_header and is_not_exempt and is_not_excluded:
                response[HEADER_REPORT_ONLY] = csp_ro

        # Once we've written the header, accessing the `request.csp_nonce` will no longer trigger
        # the nonce to be added to the header. Instead we throw an error here to catch this since
        # this has security implications.
        if getattr(request, "_csp_nonce", None) is None:
            setattr(request, "csp_nonce", CheckableLazyObject(self._csp_nonce_post_response))

        return response

    def build_policy(self, request: HttpRequest, response: HttpResponseBase) -> str:
        warnings.warn("deprecated in favor of get_policy_parts", DeprecationWarning)
        policy_parts = self.get_policy_parts(request=request, response=response, report_only=False)
        return build_policy(**asdict(policy_parts))

    def build_policy_ro(self, request: HttpRequest, response: HttpResponseBase) -> str:
        warnings.warn("deprecated in favor of get_policy_parts", DeprecationWarning)
        policy_parts_ro = self.get_policy_parts(request=request, response=response, report_only=True)
        return build_policy(**asdict(policy_parts_ro), report_only=True)

    def get_policy_parts(
        self,
        request: HttpRequest,
        response: HttpResponseBase,
        report_only: bool = False,
    ) -> PolicyParts:
        if report_only:
            config = getattr(response, "_csp_config_ro", None)
            update = getattr(response, "_csp_update_ro", None)
            replace = getattr(response, "_csp_replace_ro", None)
        else:
            config = getattr(response, "_csp_config", None)
            update = getattr(response, "_csp_update", None)
            replace = getattr(response, "_csp_replace", None)

        nonce = getattr(request, "_csp_nonce", None)

        return PolicyParts(config, update, replace, nonce)

    def get_policy_site(self, request: HttpRequest) -> str:
        """Return the review site identifier for *request*.

        An explicit ``request.csp_site`` (set by routing or a view) wins over
        the ``CSP_POLICY_SITE`` setting, which wins over the request host.
        """

        site = getattr(request, "csp_site", None)
        if site:
            return str(site)
        configured = getattr(settings, "CSP_POLICY_SITE", None)
        if configured:
            return str(configured)
        try:
            return str(request.get_host())
        except Exception:  # pragma: no cover - defensive for bare RequestFactory requests
            return ""

    def get_policy_snapshot(
        self,
        request: HttpRequest,
        response: HttpResponseBase,
        report_only: bool = False,
    ) -> PolicySnapshot:
        """Capture the effective policy that applies to this page.

        This is read-only: it inspects the same response attributes used by
        :meth:`process_response`, so a local view override is recorded as its
        own review basis without changing the header.
        """

        policy_parts = self.get_policy_parts(request=request, response=response, report_only=report_only)
        policy = (
            getattr(
                settings,
                "CONTENT_SECURITY_POLICY_REPORT_ONLY" if report_only else "CONTENT_SECURITY_POLICY",
                None,
            )
            or {}
        )
        prefixes = policy.get("EXCLUDE_URL_PREFIXES", None) or ()
        excluded = request.path_info.startswith(tuple(prefixes))
        exempt = getattr(response, "_csp_exempt_ro" if report_only else "_csp_exempt", False) is True

        snapshot = capture_snapshot(
            site=self.get_policy_site(request),
            page=request.path_info or "/",
            mode="report-only" if report_only else "enforce",
            config=policy_parts.config,
            update=policy_parts.update,
            replace=policy_parts.replace,
        )

        # A header may already exist because another middleware wrote it, or
        # because this snapshot is taken from inside the view before
        # ``process_response`` runs.  Only treat an existing header as the
        # middleware's own evidence when it matches the policy we just
        # resolved; otherwise the snapshot must not claim that policy is
        # delivered.
        header = HEADER_REPORT_ONLY if report_only else HEADER
        existing = response.get(header, "")
        if existing:
            delivered = not excluded and not exempt and self._snapshot_matches_header(snapshot, existing)
        else:
            delivered = not excluded and not exempt

        return replace(snapshot, delivered=delivered)

    @staticmethod
    def _snapshot_matches_header(snapshot: PolicySnapshot, header: str) -> bool:
        """Compare a snapshot to an existing header as directive sets.

        Directive order is not significant, so an exact string comparison would
        produce false negatives for a policy assembled in a different order.
        """

        parsed: dict[str, tuple[str, ...]] = {}
        for part in header.split(";"):
            part = part.strip()
            if not part:
                continue
            name, _, value = part.partition(" ")
            parsed[name] = tuple(value.split())
        return parsed == dict(snapshot.directives)

    def capture_policy_snapshots(
        self,
        request: HttpRequest,
        response: HttpResponseBase,
    ) -> tuple[PolicySnapshot, ...]:
        """Return snapshots for every mode that produced a header."""

        snapshots = []
        for report_only in (False, True):
            snapshot = self.get_policy_snapshot(request, response, report_only=report_only)
            if snapshot.directives:
                snapshots.append(snapshot)
        return tuple(snapshots)
