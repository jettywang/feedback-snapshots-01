from __future__ import annotations

import base64
import http.client as http_client
import logging
import os
import warnings
from dataclasses import asdict, dataclass
from functools import partial
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject, empty

from csp.constants import HEADER, HEADER_REPORT_ONLY
from csp.exceptions import CSPNonceError, CSPPolicyTooLongError
from csp.utils import DIRECTIVES_T, PolicyBuildStatus, build_policy_with_status, default_config

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase

    from csp.utils import PolicyBuildResult

logger = logging.getLogger(__name__)

# Values accepted for the ``ON_POLICY_TOO_LONG`` policy setting.
POLICY_TOO_LONG_RAISE = "raise"
POLICY_TOO_LONG_FALLBACK = "fallback"
POLICY_TOO_LONG_ACTIONS = frozenset({POLICY_TOO_LONG_RAISE, POLICY_TOO_LONG_FALLBACK})


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

        self._write_csp_header(request=request, response=response, report_only=False)
        self._write_csp_header(request=request, response=response, report_only=True)

        # Once we've written the header, accessing the `request.csp_nonce` will no longer trigger
        # the nonce to be added to the header. Instead we throw an error here to catch this since
        # this has security implications.
        if getattr(request, "_csp_nonce", None) is None:
            setattr(request, "csp_nonce", CheckableLazyObject(self._csp_nonce_post_response))

        return response

    def _write_csp_header(self, request: HttpRequest, response: HttpResponseBase, report_only: bool) -> None:
        """Assemble one CSP header and write it only when it can be delivered completely."""
        header = HEADER_REPORT_ONLY if report_only else HEADER
        setting_name = "CONTENT_SECURITY_POLICY_REPORT_ONLY" if report_only else "CONTENT_SECURITY_POLICY"
        exempt_attr = "_csp_exempt_ro" if report_only else "_csp_exempt"

        policy_setting = getattr(settings, setting_name, None) or {}
        prefixes = policy_setting.get("EXCLUDE_URL_PREFIXES", ()) or ()
        is_not_excluded = not request.path_info.startswith(tuple(prefixes))
        is_not_exempt = getattr(response, exempt_attr, False) is False
        # A header already placed on the response (e.g. by an earlier middleware) is an
        # approved, complete policy. Leave it untouched rather than replacing or truncating it.
        no_header = header not in response

        if not (no_header and is_not_exempt and is_not_excluded):
            return

        policy_parts = self.get_policy_parts(request=request, response=response, report_only=report_only)
        size_limit = policy_setting.get("POLICY_SIZE_LIMIT")
        result = build_policy_with_status(**asdict(policy_parts), report_only=report_only, size_limit=size_limit)
        if result.status is PolicyBuildStatus.EMPTY:
            return

        if result.status is PolicyBuildStatus.WITHIN_LIMIT:
            response[header] = result.policy
            return

        # The assembled policy is too long. Never write a truncated policy.
        action = policy_setting.get("ON_POLICY_TOO_LONG", POLICY_TOO_LONG_RAISE)
        if action == POLICY_TOO_LONG_FALLBACK:
            fallback = self._build_fallback_policy(policy_setting=policy_setting, nonce=policy_parts.nonce)
            if fallback.status is PolicyBuildStatus.WITHIN_LIMIT and fallback.policy:
                logger.error(
                    "%s exceeded POLICY_SIZE_LIMIT (%s > %s bytes); directive %r caused the overflow. "
                    "Delivering the configured fallback policy instead. Full policy: %r",
                    header,
                    result.policy_size,
                    result.size_limit,
                    result.offending_directive,
                    result.policy,
                )
                response[header] = fallback.policy
                return

        raise CSPPolicyTooLongError(result=result, header=header)

    @staticmethod
    def _build_fallback_policy(policy_setting: dict[str, Any], nonce: str | None) -> PolicyBuildResult:
        directives = policy_setting.get("FALLBACK_DIRECTIVES")
        config = default_config(directives) if directives is not None else None
        return build_policy_with_status(
            config=config,
            nonce=nonce,
            size_limit=policy_setting.get("POLICY_SIZE_LIMIT"),
        )

    def build_policy(self, request: HttpRequest, response: HttpResponseBase) -> str:
        warnings.warn("deprecated in favor of get_policy_parts", DeprecationWarning)
        policy_parts = self.get_policy_parts(request=request, response=response, report_only=False)
        return build_policy_with_status(**asdict(policy_parts)).policy

    def build_policy_ro(self, request: HttpRequest, response: HttpResponseBase) -> str:
        warnings.warn("deprecated in favor of get_policy_parts", DeprecationWarning)
        policy_parts_ro = self.get_policy_parts(request=request, response=response, report_only=True)
        return build_policy_with_status(**asdict(policy_parts_ro), report_only=True).policy

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
