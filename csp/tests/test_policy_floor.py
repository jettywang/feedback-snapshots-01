from __future__ import annotations

import logging

from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

from csp.constants import HEADER, HEADER_REPORT_ONLY, NONE, SELF, UNSAFE_INLINE
from csp.decorators import csp_exempt, csp_update
from csp.middleware import CSPMiddleware
from csp.policy_floor import (
    SOURCE_ABSENT,
    SOURCE_EXISTING_HEADER,
    SOURCE_SETTINGS,
    SOURCE_VIEW,
    DirectiveConflict,
    PolicyFloorReport,
    evaluate_policy_floor,
    parse_policy,
)
from csp.policy_middleware import PolicyFloorMiddleware
from csp.tests.utils import response

rf = RequestFactory()
csp_mw = CSPMiddleware(response())
floor_mw = PolicyFloorMiddleware(response())

FLOOR = {"DIRECTIVES": {"default-src": [SELF], "object-src": [NONE]}}


def run_stack(middlewares, request: HttpRequest, resp: HttpResponse) -> HttpResponse:
    for middleware in middlewares:
        resp = middleware.process_response(request, resp)
    return resp


# --------------------------------------------------------------------------- #
# parse_policy
# --------------------------------------------------------------------------- #
def test_parse_policy_splits_directives_and_sources() -> None:
    parsed = parse_policy("default-src 'self'; object-src 'none'; upgrade-insecure-requests")
    assert parsed == {
        "default-src": (SELF,),
        "object-src": (NONE,),
        "upgrade-insecure-requests": (),
    }


def test_parse_policy_handles_blank_parts() -> None:
    assert parse_policy("") == {}
    assert parse_policy("default-src 'self'; ; ") == {"default-src": (SELF,)}


# --------------------------------------------------------------------------- #
# evaluate_policy_floor
# --------------------------------------------------------------------------- #
@override_settings(CONTENT_SECURITY_POLICY_FLOOR=FLOOR)
def test_compliant_policy_is_subset_of_floor() -> None:
    report = evaluate_policy_floor(
        header=HEADER,
        delivered_policy="default-src 'self'; object-src 'none'",
        header_source=SOURCE_SETTINGS,
    )
    assert isinstance(report, PolicyFloorReport)
    assert report.enforced is True
    assert report.compliant is True
    assert report.conflicts == []
    assert report.header_source == SOURCE_SETTINGS


@override_settings(CONTENT_SECURITY_POLICY_FLOOR=FLOOR)
def test_extra_source_is_conflict_with_reason_and_source() -> None:
    report = evaluate_policy_floor(
        header=HEADER,
        delivered_policy="default-src 'self' cdn.example.com; object-src 'none'",
        header_source=SOURCE_VIEW,
    )
    assert report.compliant is False
    assert len(report.conflicts) == 1
    conflict = report.conflicts[0]
    assert isinstance(conflict, DirectiveConflict)
    assert conflict.directive == "default-src"
    assert conflict.source == SOURCE_VIEW
    assert "cdn.example.com" in conflict.reason
    assert conflict.floor_sources == (SELF,)
    assert conflict.delivered_sources == (SELF, "cdn.example.com")
    assert report.reasons == [conflict.reason]


@override_settings(
    CONTENT_SECURITY_POLICY_FLOOR={"DIRECTIVES": {"default-src": [SELF], "base-uri": [SELF]}}
)
def test_missing_directive_is_reported() -> None:
    report = evaluate_policy_floor(
        header=HEADER,
        # base-uri is absent and does not fall back to default-src.
        delivered_policy="default-src 'self'",
        header_source=SOURCE_SETTINGS,
    )
    assert report.compliant is False
    conflict = report.conflicts[0]
    assert conflict.directive == "base-uri"
    assert "missing required directive" in conflict.reason
    assert conflict.delivered_sources == ()


@override_settings(CONTENT_SECURITY_POLICY_FLOOR=FLOOR)
def test_fetch_directive_falls_back_to_default_src() -> None:
    # object-src is a fetch directive: default-src governs it when absent.
    report = evaluate_policy_floor(
        header=HEADER,
        delivered_policy="default-src 'none'",
        header_source=SOURCE_SETTINGS,
    )
    assert report.compliant is True


@override_settings(CONTENT_SECURITY_POLICY_FLOOR={"DIRECTIVES": {"base-uri": [SELF]}})
def test_non_fetch_directive_has_no_default_src_fallback() -> None:
    # base-uri does not fall back to default-src, so it is a missing conflict.
    report = evaluate_policy_floor(
        header=HEADER,
        delivered_policy="default-src 'self'",
        header_source=SOURCE_SETTINGS,
    )
    assert report.compliant is False
    assert report.conflicts[0].directive == "base-uri"


@override_settings(CONTENT_SECURITY_POLICY_FLOOR={"DIRECTIVES": {"script-src": [SELF]}})
def test_none_satisfies_any_floor() -> None:
    report = evaluate_policy_floor(
        header=HEADER,
        delivered_policy="script-src 'none'",
        header_source=SOURCE_SETTINGS,
    )
    assert report.compliant is True


@override_settings(
    CONTENT_SECURITY_POLICY_FLOOR={"DIRECTIVES": {"upgrade-insecure-requests": True}}
)
def test_boolean_directive_present_is_compliant() -> None:
    report = evaluate_policy_floor(
        header=HEADER,
        delivered_policy="upgrade-insecure-requests",
        header_source=SOURCE_SETTINGS,
    )
    assert report.compliant is True


@override_settings(
    CONTENT_SECURITY_POLICY_FLOOR={"DIRECTIVES": {"upgrade-insecure-requests": True}}
)
def test_boolean_directive_absent_is_conflict() -> None:
    report = evaluate_policy_floor(
        header=HEADER,
        delivered_policy="default-src 'self'",
        header_source=SOURCE_SETTINGS,
    )
    assert report.compliant is False
    assert report.conflicts[0].directive == "upgrade-insecure-requests"


@override_settings(
    CONTENT_SECURITY_POLICY_FLOOR={"DIRECTIVES": {"default-src": [SELF]}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY_FLOOR={
        "DIRECTIVES": {"default-src": [SELF, UNSAFE_INLINE]}
    },
)
def test_report_only_uses_its_own_floor() -> None:
    # A report-only floor that allows unsafe-inline accepts a looser header.
    ro_report = evaluate_policy_floor(
        header=HEADER_REPORT_ONLY,
        delivered_policy=f"default-src {SELF} {UNSAFE_INLINE}",
        header_source=SOURCE_SETTINGS,
        report_only=True,
    )
    assert ro_report.enforced is False
    assert ro_report.compliant is True

    # The enforced floor still rejects unsafe-inline.
    enforced_report = evaluate_policy_floor(
        header=HEADER,
        delivered_policy=f"default-src {SELF} {UNSAFE_INLINE}",
        header_source=SOURCE_SETTINGS,
    )
    assert enforced_report.enforced is True
    assert enforced_report.compliant is False


@override_settings(CONTENT_SECURITY_POLICY_FLOOR=FLOOR)
def test_empty_delivered_policy_conflicts_on_every_floor_directive() -> None:
    report = evaluate_policy_floor(
        header=HEADER,
        delivered_policy="",
        header_source=SOURCE_ABSENT,
    )
    assert report.compliant is False
    assert report.header_source == SOURCE_ABSENT
    assert {conflict.directive for conflict in report.conflicts} == {
        "default-src",
        "object-src",
    }


# --------------------------------------------------------------------------- #
# PolicyFloorMiddleware + CSPMiddleware integration
# --------------------------------------------------------------------------- #
@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF], "object-src": [NONE]}},
    CONTENT_SECURITY_POLICY_FLOOR=FLOOR,
)
def test_settings_policy_passes_and_is_attributed_to_settings() -> None:
    request = rf.get("/")
    resp = run_stack([csp_mw, floor_mw], request, HttpResponse())
    assert HEADER in resp
    reports = resp._csp_floor_reports
    assert len(reports) == 1
    report = reports[0]
    assert report.header == HEADER
    assert report.compliant is True
    assert report.header_source == SOURCE_SETTINGS


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF, "cdn.example.com"]}},
    CONTENT_SECURITY_POLICY_FLOOR=FLOOR,
)
def test_settings_policy_too_loose_is_rejected_with_source_and_reason(caplog) -> None:
    request = rf.get("/")
    with caplog.at_level(logging.WARNING, logger="csp.policy_middleware"):
        resp = run_stack([csp_mw, floor_mw], request, HttpResponse())
    report = resp._csp_floor_reports[0]
    assert report.compliant is False
    assert report.header_source == SOURCE_SETTINGS
    assert "cdn.example.com" in report.reasons[0]
    assert any("policy floor violation" in record.message for record in caplog.records)


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF, "cdn.example.com"]}},
    CONTENT_SECURITY_POLICY_FLOOR=FLOOR,
)
def test_middleware_order_swap_changes_what_the_floor_can_see() -> None:
    # Floor middleware innermost (runs last on response): it inspects the
    # final delivered header produced by CSPMiddleware and rejects it.
    request_after = rf.get("/")
    resp_after = run_stack([csp_mw, floor_mw], request_after, HttpResponse())
    report_after = resp_after._csp_floor_reports[0]
    assert resp_after[HEADER] == "default-src 'self' cdn.example.com"
    assert report_after.header_source == SOURCE_SETTINGS
    assert report_after.compliant is False
    assert "cdn.example.com" in report_after.reasons[0]

    # Floor middleware outermost (runs first on response): the CSP header has
    # not been written yet, so it audits an absent header rather than the
    # policy CSPMiddleware is about to add.
    request_before = rf.get("/")
    resp_before = run_stack([floor_mw, csp_mw], request_before, HttpResponse())
    # CSPMiddleware still wrote the same final header afterwards.
    assert resp_before[HEADER] == resp_after[HEADER]
    report_before = resp_before._csp_floor_reports[0]
    assert report_before.header_source == SOURCE_ABSENT
    assert report_before.compliant is False
    assert "missing required directive 'default-src'" in report_before.reasons[0]


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF]}},
    CONTENT_SECURITY_POLICY_FLOOR={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_pre_existing_header_is_not_overwritten_and_is_attributed_to_existing() -> None:
    request = rf.get("/")
    resp = HttpResponse()
    resp[HEADER] = "default-src 'self' evil.example.com"
    resp = run_stack([csp_mw, floor_mw], request, resp)

    # django-csp must not replace a header another component wrote.
    assert resp[HEADER] == "default-src 'self' evil.example.com"
    report = resp._csp_floor_reports[0]
    assert report.header_source == SOURCE_EXISTING_HEADER
    assert report.compliant is False
    assert "evil.example.com" in report.reasons[0]


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF]}},
    CONTENT_SECURITY_POLICY_FLOOR={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_pre_existing_header_compliant_passes() -> None:
    request = rf.get("/")
    resp = HttpResponse()
    resp[HEADER] = "default-src 'self'"
    resp = run_stack([csp_mw, floor_mw], request, resp)
    report = resp._csp_floor_reports[0]
    assert report.compliant is True
    assert report.header_source == SOURCE_EXISTING_HEADER


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF]}},
    CONTENT_SECURITY_POLICY_FLOOR={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_view_exception_via_decorator_is_attributed_to_view() -> None:
    @csp_update({"default-src": ["widgets.example.com"]})
    def view(request: HttpRequest) -> HttpResponse:
        return HttpResponse()

    request = rf.get("/")
    resp = view(request)
    resp = run_stack([csp_mw, floor_mw], request, resp)

    assert "widgets.example.com" in resp[HEADER]
    report = resp._csp_floor_reports[0]
    assert report.header_source == SOURCE_VIEW
    assert report.compliant is False
    assert "widgets.example.com" in report.reasons[0]


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF]}},
    CONTENT_SECURITY_POLICY_FLOOR={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_exempt_view_without_header_is_absent_and_noncompliant() -> None:
    @csp_exempt()
    def view(request: HttpRequest) -> HttpResponse:
        return HttpResponse()

    request = rf.get("/")
    resp = view(request)
    resp = run_stack([csp_mw, floor_mw], request, resp)

    assert HEADER not in resp
    report = resp._csp_floor_reports[0]
    assert report.compliant is False
    assert report.header_source == SOURCE_ABSENT
    assert "missing required directive 'default-src'" in report.reasons[0]


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF]}},
    CONTENT_SECURITY_POLICY_FLOOR={"DIRECTIVES": {"default-src": [SELF]}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={
        "DIRECTIVES": {"default-src": [SELF, UNSAFE_INLINE]}
    },
    CONTENT_SECURITY_POLICY_REPORT_ONLY_FLOOR={
        "DIRECTIVES": {"default-src": [SELF, UNSAFE_INLINE]}
    },
)
def test_enforced_and_report_only_headers_checked_against_their_own_floors() -> None:
    request = rf.get("/")
    resp = run_stack([csp_mw, floor_mw], request, HttpResponse())

    assert HEADER in resp and HEADER_REPORT_ONLY in resp
    by_header = {report.header: report for report in resp._csp_floor_reports}
    assert by_header[HEADER].enforced is True
    assert by_header[HEADER].compliant is True
    assert by_header[HEADER_REPORT_ONLY].enforced is False
    assert by_header[HEADER_REPORT_ONLY].compliant is True


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF, UNSAFE_INLINE]}},
    CONTENT_SECURITY_POLICY_FLOOR={"DIRECTIVES": {"default-src": [SELF]}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY={
        "DIRECTIVES": {"default-src": [SELF, UNSAFE_INLINE]}
    },
    CONTENT_SECURITY_POLICY_REPORT_ONLY_FLOOR={
        "DIRECTIVES": {"default-src": [SELF, UNSAFE_INLINE]}
    },
)
def test_enforced_rejected_while_report_only_accepted() -> None:
    request = rf.get("/")
    resp = run_stack([csp_mw, floor_mw], request, HttpResponse())
    by_header = {report.header: report for report in resp._csp_floor_reports}
    assert by_header[HEADER].compliant is False
    assert UNSAFE_INLINE in by_header[HEADER].reasons[0]
    assert by_header[HEADER_REPORT_ONLY].compliant is True


@override_settings(
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF]}},
    CONTENT_SECURITY_POLICY_REPORT_ONLY_FLOOR={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_report_only_view_exception_is_attributed_to_view() -> None:
    @csp_update({"default-src": ["telemetry.example.com"]}, REPORT_ONLY=True)
    def view(request: HttpRequest) -> HttpResponse:
        return HttpResponse()

    request = rf.get("/")
    resp = view(request)
    resp = run_stack([csp_mw, floor_mw], request, resp)

    # Only a report-only floor is configured, so just that header is audited.
    assert len(resp._csp_floor_reports) == 1
    report = resp._csp_floor_reports[0]
    assert report.header == HEADER_REPORT_ONLY
    assert report.enforced is False
    assert report.header_source == SOURCE_VIEW
    assert report.compliant is False
    assert "telemetry.example.com" in report.reasons[0]


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_no_floor_configured_produces_no_reports() -> None:
    request = rf.get("/")
    resp = run_stack([csp_mw, floor_mw], request, HttpResponse())
    assert resp._csp_floor_reports == []


@override_settings(
    CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF]}},
    CONTENT_SECURITY_POLICY_FLOOR={"DIRECTIVES": {"default-src": [SELF]}},
)
def test_both_headers_present_before_csp_middleware_are_both_attributed_to_existing() -> None:
    request = rf.get("/")
    resp = HttpResponse()
    resp[HEADER] = "default-src 'self'"
    resp[HEADER_REPORT_ONLY] = "default-src 'self' unsafe-inline.example"
    # No report-only floor configured: only the enforced header is checked.
    resp = run_stack([csp_mw, floor_mw], request, resp)
    assert resp._csp_header_sources == {
        HEADER: SOURCE_EXISTING_HEADER,
        HEADER_REPORT_ONLY: SOURCE_EXISTING_HEADER,
    }
    report = resp._csp_floor_reports[0]
    assert report.header == HEADER
    assert report.header_source == SOURCE_EXISTING_HEADER
    assert report.compliant is True
