from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.utils.deprecation import MiddlewareMixin

from csp.constants import HEADER, HEADER_REPORT_ONLY
from csp.policy_floor import (
    SOURCE_ABSENT,
    SOURCE_EXISTING_HEADER,
    PolicyFloorReport,
    evaluate_policy_floor,
    get_floor_directives,
)

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase

logger = logging.getLogger(__name__)


class PolicyFloorMiddleware(MiddlewareMixin):
    """Enforce an application-wide minimum Content-Security-Policy.

    The middleware never rewrites responses. It inspects the final CSP headers
    that will actually be delivered and compares each one against the policy
    floor configured in settings, reporting conflicts and their origin.
    """

    def process_response(
        self,
        request: HttpRequest,
        response: HttpResponseBase,
    ) -> HttpResponseBase:
        reports = [
            self._check_header(response, HEADER, report_only=False),
            self._check_header(response, HEADER_REPORT_ONLY, report_only=True),
        ]
        response._csp_floor_reports = [report for report in reports if report is not None]
        return response

    @staticmethod
    def _header_source(response: HttpResponseBase, header: str) -> str:
        tracked = getattr(response, "_csp_header_sources", {}).get(header)
        if tracked is not None:
            return tracked
        if header not in response:
            return SOURCE_ABSENT
        # The header was present before django-csp ran (e.g. set by a resource
        # middleware or another component) and was left untouched.
        return SOURCE_EXISTING_HEADER

    def _check_header(
        self,
        response: HttpResponseBase,
        header: str,
        report_only: bool,
    ) -> PolicyFloorReport | None:
        if not get_floor_directives(report_only):
            return None

        source = self._header_source(response, header)
        delivered_policy = response.get(header, "")
        report = evaluate_policy_floor(
            header=header,
            delivered_policy=delivered_policy,
            header_source=source,
            report_only=report_only,
        )
        if not report.compliant:
            for conflict in report.conflicts:
                logger.warning(
                    "CSP policy floor violation in %s (source=%s): %s",
                    header,
                    source,
                    conflict.reason,
                )
        return report
