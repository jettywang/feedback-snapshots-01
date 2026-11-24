#!/usr/bin/env python
# ruff: noqa: T201
"""Replay old-proxy and new-entry requests through django-csp 4.0.

Run from the repository root:

    .venv/bin/python scripts/csp_mount_audit.py

The script uses Django's RequestFactory, so each request is a real
django.core.handlers.wsgi.WSGIRequest built from a WSGI environ. It does not
bind a network port.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

import django
from django.conf import settings

BASE_ENFORCED_POLICY: dict[str, Any] = {
    "DIRECTIVES": {"default-src": ["'self'"]},
}
BASE_REPORT_ONLY_POLICY: dict[str, Any] = {
    "DIRECTIVES": {
        "default-src": ["'self'"],
        "report-uri": ["/csp-report/"],
    },
}

if not settings.configured:
    settings.configure(
        DEBUG=False,
        SECRET_KEY="local-csp-mount-audit-only",
        ROOT_URLCONF=__name__,
        ALLOWED_HOSTS=["testserver", "new.example", "old.example"],
        DATABASES={},
        INSTALLED_APPS=[],
        MIDDLEWARE=[],
        CONTENT_SECURITY_POLICY=BASE_ENFORCED_POLICY,
        CONTENT_SECURITY_POLICY_REPORT_ONLY=BASE_REPORT_ONLY_POLICY,
    )

django.setup()

from django.http import HttpResponse  # noqa: E402
from django.test import RequestFactory, override_settings  # noqa: E402
from django.urls import include, path, resolve  # noqa: E402

from csp.constants import HEADER, HEADER_REPORT_ONLY  # noqa: E402
from csp.decorators import csp_exempt  # noqa: E402
from csp.middleware import CSPMiddleware  # noqa: E402
from csp.utils import build_policy  # noqa: E402

OLD_MOUNT = "/legacy"
NEW_MOUNT = "/new-entry"
APPROVED_APP_PATH = "/approved/"
PRESET_VALUE = "default-src 'preset-by-view'"

rf = RequestFactory()
stock_middleware = CSPMiddleware(lambda request: HttpResponse())


def approved_view(request: Any) -> HttpResponse:
    return HttpResponse("approved response\n")


@csp_exempt()
def view_exempt_enforced(request: Any) -> HttpResponse:
    return HttpResponse("view exemption response\n")


def preset_header_view(request: Any) -> HttpResponse:
    response = HttpResponse("preset header response\n")
    response[HEADER] = PRESET_VALUE
    return response


app_urlpatterns = [
    path("approved/", approved_view, name="approved"),
    path("view-exempt/", view_exempt_enforced, name="view-exempt"),
    path("preset-header/", preset_header_view, name="preset-header"),
]

urlpatterns = [
    path("", include(app_urlpatterns)),
    path("legacy/", include(app_urlpatterns)),
    path("new-entry/", include(app_urlpatterns)),
]


class TrustedScriptNamePrefixMiddleware(CSPMiddleware):
    """Make the trusted WSGI SCRIPT_NAME visible to stock path_info rules.

    The temporary value is script_name + path_info (equivalent to
    request.path for WSGIRequest). SCRIPT_NAME must be set by the WSGI server
    or a trusted proxy-normalization layer. Never derive it directly from an
    unauthenticated request header.
    """

    def process_response(self, request: Any, response: HttpResponse) -> HttpResponse:
        original_path_info = request.path_info
        script_name = request.META.get("SCRIPT_NAME", "") or ""
        request.path_info = f"{script_name.rstrip('/')}{original_path_info}"
        try:
            return super().process_response(request, response)
        finally:
            request.path_info = original_path_info


trusted_mount_middleware = TrustedScriptNamePrefixMiddleware(lambda request: HttpResponse())


def make_request(
    app_path: str,
    mount: str = "",
    *,
    send_forwarded_prefix: str | None = None,
) -> Any:
    environ_extra: dict[str, str] = {}
    if mount:
        environ_extra["SCRIPT_NAME"] = mount
    if send_forwarded_prefix is not None:
        environ_extra["HTTP_X_FORWARDED_PREFIX"] = send_forwarded_prefix

    request = rf.get(app_path, **environ_extra)
    match = resolve(app_path)
    request.resolver_match = match
    return request


def header_text(response: HttpResponse, header_name: str) -> str:
    if header_name in response:
        return str(response[header_name])
    return "<absent>"


def print_request_facts(case_id: str, title: str, request: Any) -> None:
    print(f"\n=== {case_id}: {title} ===")
    print(f"  request.META['SCRIPT_NAME']            = {request.META.get('SCRIPT_NAME', '')!r}")
    print(f"  request.META['PATH_INFO']              = {request.META.get('PATH_INFO', '')!r}")
    print(f"  request.headers['X-Forwarded-Prefix']  = {request.headers.get('x-forwarded-prefix', '<not sent>')!r}")
    print(f"  request.path_info                      = {request.path_info!r}  # csp/middleware.py:90 and :102")
    print(f"  request.path                           = {request.path!r}  # SCRIPT_NAME + PATH_INFO, not read by stock django-csp")
    print(f"  request.resolver_match.view_name       = {request.resolver_match.view_name!r}")


def trace_header_decision(
    label: str,
    request: Any,
    response: HttpResponse,
    *,
    report_only: bool,
    effective_path: str | None = None,
) -> dict[str, Any]:
    if report_only:
        header_name = HEADER_REPORT_ONLY
        exempt_attribute = "_csp_exempt_ro"
        settings_name = "CONTENT_SECURITY_POLICY_REPORT_ONLY"
        exempt_line = 98
        header_line = 99
        policy_line = 100
        prefix_line = 101
        path_line = 102
        condition_line = 103
        set_line = 104
    else:
        header_name = HEADER
        exempt_attribute = "_csp_exempt"
        settings_name = "CONTENT_SECURITY_POLICY"
        exempt_line = 86
        header_line = 87
        policy_line = 88
        prefix_line = 89
        path_line = 90
        condition_line = 91
        set_line = 92

    policy = getattr(settings, settings_name, None) or {}
    prefixes = tuple(policy.get("EXCLUDE_URL_PREFIXES", None) or ())
    matcher_path = request.path_info if effective_path is None else effective_path
    prefix_hit = matcher_path.startswith(prefixes)
    is_not_exempt = getattr(response, exempt_attribute, False) is False
    no_header = header_name not in response
    is_not_excluded = not prefix_hit

    parts = stock_middleware.get_policy_parts(request=request, response=response, report_only=report_only)
    built_policy = build_policy(**asdict(parts), report_only=report_only)
    will_set = bool(built_policy) and no_header and is_not_exempt and is_not_excluded

    exempt_value = getattr(response, exempt_attribute, False)
    print(f"  [{label}] csp/middleware.py:{exempt_line} " f"response.{exempt_attribute} = {exempt_value!r}; is_not_exempt={is_not_exempt}")
    print(f"  [{label}] csp/middleware.py:{header_line} {header_name!r} already preset = {not no_header}; no_header={no_header}")
    print(f"  [{label}] csp/middleware.py:{policy_line} settings.{settings_name}")
    print(f"  [{label}] csp/middleware.py:{prefix_line} EXCLUDE_URL_PREFIXES = {list(prefixes)!r}")
    print(f"  [{label}] csp/middleware.py:{path_line} request.path_info matcher value = {matcher_path!r}")
    print(f"  [{label}] startswith({list(prefixes)!r}) = {prefix_hit}; is_not_excluded={is_not_excluded}")
    print(f"  [{label}] built policy = {built_policy!r}")
    action = "sets header" if will_set else "does not set header"
    print(f"  [{label}] csp/middleware.py:{condition_line} conjunction true? {will_set} " f"-> line {set_line} {action}")

    return {
        "header": header_name,
        "prefix_hit": prefix_hit,
        "will_set": will_set,
    }


def print_final_headers(response: HttpResponse) -> None:
    print("  FINAL " + HEADER + ": " + header_text(response, HEADER))
    print("  FINAL " + HEADER_REPORT_ONLY + ": " + header_text(response, HEADER_REPORT_ONLY))


def replay_stock_case(
    case_id: str,
    title: str,
    app_path: str,
    mount: str,
) -> tuple[HttpResponse, dict[str, Any], dict[str, Any]]:
    request = make_request(app_path, mount)
    response = request.resolver_match.func(request)
    print_request_facts(case_id, title, request)
    enforced_decision = trace_header_decision("enforce", request, response, report_only=False)
    report_decision = trace_header_decision("report ", request, response, report_only=True)
    stock_middleware.process_response(request, response)
    print_final_headers(response)
    return response, enforced_decision, report_decision


def replay_trusted_mount_case(
    case_id: str,
    title: str,
    app_path: str,
    mount: str,
    *,
    send_forwarded_prefix: str | None = None,
) -> tuple[HttpResponse, str]:
    request = make_request(app_path, mount, send_forwarded_prefix=send_forwarded_prefix)
    response = request.resolver_match.func(request)
    print_request_facts(case_id, title, request)

    actual_path_info = request.path_info
    script_name = request.META.get("SCRIPT_NAME", "") or ""
    effective_path = f"{script_name.rstrip('/')}{actual_path_info}"
    print("  [mount] TrustedScriptNamePrefixMiddleware reads META['SCRIPT_NAME'] only")
    print(f"  [mount] actual path_info={actual_path_info!r}; temporarily gives stock matcher path={effective_path!r}")
    if send_forwarded_prefix is not None:
        print("  [mount] X-Forwarded-Prefix was received but is not promoted to SCRIPT_NAME; it is untrusted in this replay")

    trace_header_decision("enforce", request, response, report_only=False, effective_path=effective_path)
    trace_header_decision("report ", request, response, report_only=True, effective_path=effective_path)
    trusted_mount_middleware.process_response(request, response)
    print_final_headers(response)
    return response, effective_path


def main() -> int:
    failures: list[str] = []

    def check(condition: bool, message: str) -> None:
        marker = "PASS" if condition else "FAIL"
        print(f"  ASSERT {marker}: {message}")
        if not condition:
            failures.append(message)

    naive_settings = override_settings(
        CONTENT_SECURITY_POLICY={
            **BASE_ENFORCED_POLICY,
            "EXCLUDE_URL_PREFIXES": ["/approved/"],
        },
        CONTENT_SECURITY_POLICY_REPORT_ONLY={
            **BASE_REPORT_ONLY_POLICY,
            "EXCLUDE_URL_PREFIXES": ["/approved/"],
        },
    )

    print("#" * 100)
    print("# PART 1: STOCK django-csp 4.0 WITH A PATH-ONLY MIGRATION")
    print("# Settings migrate the old prefix verbatim to EXCLUDE_URL_PREFIXES=['/approved/'].")
    print("#" * 100)
    with naive_settings:
        old_response, old_enf, old_ro = replay_stock_case(
            "1A", "old proxy entry; approved exception should keep working", APPROVED_APP_PATH, OLD_MOUNT
        )
        check(HEADER not in old_response, "old entry has no enforced CSP header")
        check(HEADER_REPORT_ONLY not in old_response, "old entry has no report-only header because both policies exclude it")
        check(old_enf["prefix_hit"] and old_ro["prefix_hit"], "both stock matchers hit /approved/")

        new_response, new_enf, new_ro = replay_stock_case(
            "1B", "new entry on same URLconf; old-only approval must not apply", APPROVED_APP_PATH, NEW_MOUNT
        )
        check(new_enf["prefix_hit"] and new_ro["prefix_hit"], "stock still sees the same path_info and matches /approved/")
        check(HEADER not in new_response and HEADER_REPORT_ONLY not in new_response, "NAIVE RESULT: new entry is also unprotected")
        print("  MIGRATION VERDICT: a bare /approved/ rule cannot represent an old-entry-only approval after prefix stripping.")

        exempt_response, _, exempt_ro = replay_stock_case(
            "1C", "view exception @csp_exempt() is response-scoped, not mount-scoped", "/view-exempt/", NEW_MOUNT
        )
        check(HEADER not in exempt_response, "@csp_exempt() suppresses the enforced header")
        check(HEADER_REPORT_ONLY in exempt_response, "@csp_exempt() does not set _csp_exempt_ro, so report-only remains")
        check(exempt_ro["will_set"] is True, "report-only conjunction remains true")

        preset_response, _, _ = replay_stock_case("1D", "view/upstream preset enforced header is never overwritten", "/preset-header/", NEW_MOUNT)
        check(preset_response[HEADER] == PRESET_VALUE, "preset Content-Security-Policy value is preserved verbatim")
        check(HEADER_REPORT_ONLY in preset_response, "absence of a preset report-only header lets django-csp add its own")

    preserved_prefix_settings = override_settings(
        CONTENT_SECURITY_POLICY={
            **BASE_ENFORCED_POLICY,
            "EXCLUDE_URL_PREFIXES": ["/legacy/approved/"],
        },
        CONTENT_SECURITY_POLICY_REPORT_ONLY={
            **BASE_REPORT_ONLY_POLICY,
            "EXCLUDE_URL_PREFIXES": ["/legacy/approved/"],
        },
    )

    print("\n" + "#" * 100)
    print("# PART 2: STOCK SUCCESS CASE WHEN THE OLD PREFIX STAYS IN PATH_INFO")
    print("# Proxy does not strip /legacy; root URLconf includes the same app patterns twice.")
    print("#" * 100)
    with preserved_prefix_settings:
        preserved_old, preserved_old_enf, preserved_old_ro = replay_stock_case("2A", "prefix preserved: old entry", "/legacy/approved/", "")
        check(preserved_old_enf["prefix_hit"] and preserved_old_ro["prefix_hit"], "stock path_info starts with /legacy/approved/")
        check(HEADER not in preserved_old and HEADER_REPORT_ONLY not in preserved_old, "preserved-prefix old entry is excepted")

        preserved_new, preserved_new_enf, preserved_new_ro = replay_stock_case("2B", "prefix preserved: new entry", "/new-entry/approved/", "")
        check(not preserved_new_enf["prefix_hit"] and not preserved_new_ro["prefix_hit"], "new path_info does not start with old prefix")
        check(HEADER in preserved_new and HEADER_REPORT_ONLY in preserved_new, "preserved-prefix new entry remains constrained")

    print("\n" + "#" * 100)
    print("# PART 3: STRIPPED PREFIX + DEPLOYABLE OLD-ENTRY-ONLY RULE")
    print("# Proxy/WSGI supplies trusted SCRIPT_NAME; adapter exposes /legacy/approved/ to stock rules.")
    print("#" * 100)
    mount_aware_settings = override_settings(
        CONTENT_SECURITY_POLICY={
            **BASE_ENFORCED_POLICY,
            "EXCLUDE_URL_PREFIXES": ["/legacy/approved/"],
        },
        CONTENT_SECURITY_POLICY_REPORT_ONLY={
            **BASE_REPORT_ONLY_POLICY,
            "EXCLUDE_URL_PREFIXES": ["/legacy/approved/"],
        },
    )

    with mount_aware_settings:
        old_mount_response, _ = replay_trusted_mount_case("3A", "old entry with trusted SCRIPT_NAME=/legacy", APPROVED_APP_PATH, OLD_MOUNT)
        check(HEADER not in old_mount_response, "old entry remains excepted for enforced CSP")
        check(HEADER_REPORT_ONLY not in old_mount_response, "old entry remains excepted for report-only CSP")

        new_mount_response, _ = replay_trusted_mount_case("3B", "new entry with trusted SCRIPT_NAME=/new-entry", APPROVED_APP_PATH, NEW_MOUNT)
        check(HEADER in new_mount_response, "new entry receives enforced CSP")
        check(HEADER_REPORT_ONLY in new_mount_response, "new entry receives report-only CSP")
        check(new_mount_response[HEADER] == "default-src 'self'", "new entry enforced policy is the configured policy")

        spoofed_response, _ = replay_trusted_mount_case(
            "3C",
            "untrusted X-Forwarded-Prefix=/legacy without trusted promotion",
            APPROVED_APP_PATH,
            "",
            send_forwarded_prefix="/legacy",
        )
        check(HEADER in spoofed_response and HEADER_REPORT_ONLY in spoofed_response, "spoofed forwarded prefix does not create the old mount fact")

    print("\n" + "#" * 100)
    if failures:
        print(f"RESULT: {len(failures)} check(s) failed")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("RESULT: all local request comparisons passed")
    print("RERUN: .venv/bin/python scripts/csp_mount_audit.py")
    print("#" * 100)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
