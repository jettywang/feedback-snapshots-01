from __future__ import annotations

from typing import TYPE_CHECKING

from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

import pytest

from csp.approvals import (
    ENFORCE,
    NEEDS_REVIEW,
    PENDING,
    REPORT_ONLY,
    VALID,
    Approval,
    ApprovalRegistry,
    PolicySnapshot,
    capture_snapshot,
    normalize_mode,
    review_approvals,
)
from csp.constants import HEADER, SELF
from csp.decorators import csp_replace
from csp.middleware import CSPMiddleware
from csp.tests.utils import response
from csp.utils import build_directives, build_policy

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase

mw = CSPMiddleware(response())
rf = RequestFactory()

PARTNER_CDN = "cdn.partner.example"
PARTNER_JS = "js.partner.example"


def test_normalize_mode_keeps_enforced_and_report_only_distinct() -> None:
    assert normalize_mode(None) == ENFORCE
    assert normalize_mode("enforce") == ENFORCE
    assert normalize_mode("report-only") == REPORT_ONLY
    assert normalize_mode("report_only") == REPORT_ONLY
    with pytest.raises(ValueError):
        normalize_mode("audit")


def test_approval_can_be_built_from_a_table_row() -> None:
    approval = Approval.from_dict(
        {
            "id": "AP-1",
            "site": "shop.example",
            "directive": "img-src",
            "source": PARTNER_CDN,
            "mode": "enforce",
            "scope": ["/checkout/"],
        }
    )
    assert approval.approval_id == "AP-1"
    assert approval.sources == (PARTNER_CDN,)
    assert approval.pages == ("/checkout/",)
    assert approval.covers_page("/checkout/thanks/")
    assert not approval.covers_page("/orders/")


def test_page_prefix_does_not_spill_to_a_sibling_path() -> None:
    approval = Approval("AP-1", site="shop.example", directive="img-src", sources=PARTNER_CDN, pages=["/checkout"])
    assert approval.covers_page("/checkout")
    assert approval.covers_page("/checkout/")
    assert approval.covers_page("/checkout/thanks/")
    assert not approval.covers_page("/checkoutx")
    assert not approval.covers_page("/checkout-outside/")


def test_approval_requires_identity_and_sources() -> None:
    with pytest.raises(ValueError):
        Approval("", site="shop.example", directive="img-src", sources=PARTNER_CDN)
    with pytest.raises(ValueError):
        Approval("AP-1", site="shop.example", directive="img-src", sources=())


def test_build_policy_still_matches_previous_construction() -> None:
    policy = build_policy(
        config={"default-src": [SELF], "img-src": ["example.com"]},
        update={"img-src": "example2.com"},
    )
    assert sorted(policy.split("; ")) == ["default-src 'self'", "img-src example.com example2.com"]


def test_build_directives_matches_build_policy_tokens() -> None:
    config = {"default-src": [SELF], "img-src": ["example.com"]}
    update = {"img-src": "example2.com"}
    directives = build_directives(config=config, update=update)
    assert directives["img-src"] == "example.com example2.com"
    assert build_policy(config=config, update=update) == "; ".join(f"{name} {value}".strip() for name, value in directives.items())


def _checkout_view(request: HttpRequest) -> HttpResponseBase:
    response = HttpResponse()
    setattr(response, "_csp_update", {"img-src": PARTNER_CDN})
    return response


def _orders_view(request: HttpRequest) -> HttpResponseBase:
    response = HttpResponse()
    # A page-local source that has no page-scoped approval of its own.
    setattr(response, "_csp_update", {"img-src": PARTNER_CDN})
    return response


def _plain_view(request: HttpRequest) -> HttpResponseBase:
    return HttpResponse()


def _render(request: HttpRequest, response: HttpResponseBase) -> tuple[HttpRequest, HttpResponseBase]:
    mw.process_request(request)
    mw.process_response(request, response)
    return request, response


def _snapshot(path: str, view: object = _plain_view, *, site: str = "shop.example", mode: str = ENFORCE) -> PolicySnapshot:
    request = rf.get(path)
    setattr(request, "csp_site", site)
    response = view(request)  # type: ignore[operator]
    _render(request, response)
    snapshots = mw.capture_policy_snapshots(request, response)
    matching = [snapshot for snapshot in snapshots if snapshot.mode == mode]
    assert matching, f"no {mode} snapshot captured for {path}"
    snapshot = matching[0]
    assert snapshot.site == site
    assert snapshot.page == path
    return snapshot


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {
            "default-src": [SELF],
            "img-src": [SELF],
            "script-src": [SELF],
            "report-uri": "/csp-report/",
        }
    },
    CONTENT_SECURITY_POLICY_REPORT_ONLY=None,
)
def test_snapshot_records_actual_sources_and_view_origin() -> None:
    snapshot = _snapshot("/checkout/", _checkout_view)
    assert snapshot.sources_for("img-src") == (SELF, PARTNER_CDN)
    assert snapshot.origin_for("img-src", PARTNER_CDN) == "view"
    assert snapshot.origin_for("img-src", SELF) == "settings"


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {
            "default-src": [SELF],
            "img-src": [SELF],
            "script-src": [SELF],
            "report-uri": "/csp-report/",
        }
    },
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF], "img-src": [SELF]}},
)
def test_snapshot_distinguishes_enforced_and_report_only() -> None:
    def ro_view(request: HttpRequest) -> HttpResponseBase:
        response = HttpResponse()
        setattr(response, "_csp_update_ro", {"img-src": PARTNER_CDN})
        return response

    snapshot = _snapshot("/checkout/", ro_view, mode=REPORT_ONLY)
    assert snapshot.mode == REPORT_ONLY
    assert snapshot.origin_for("img-src", PARTNER_CDN) == "view"
    assert snapshot.mode != normalize_mode("enforce")


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {
            "default-src": [SELF],
            "img-src": [SELF],
            "script-src": [SELF],
            "report-uri": "/csp-report/",
        }
    },
    CONTENT_SECURITY_POLICY_REPORT_ONLY=None,
)
def test_capture_snapshot_marks_excluded_page_as_not_delivered() -> None:
    request = rf.get("/checkout/")
    response = _checkout_view(request)
    _render(request, response)
    # Simulate the middleware's exclusion decision with the same evidence hook.
    snapshot = mw.get_policy_snapshot(request, response)
    assert snapshot.delivered is True

    setattr(response, "_csp_exempt", True)
    snapshot = mw.get_policy_snapshot(request, response)
    assert snapshot.delivered is False


def _checkout_snapshot() -> PolicySnapshot:
    return _snapshot("/checkout/", _checkout_view)


def _orders_snapshot() -> PolicySnapshot:
    return _snapshot("/orders/", _orders_view)


def _support_snapshot() -> PolicySnapshot:
    return capture_snapshot(
        site="support.example",
        page="/",
        config={"default-src": [SELF], "script-src": [SELF, PARTNER_JS]},
    )


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {
            "default-src": [SELF],
            "img-src": [SELF],
            "script-src": [SELF],
            "report-uri": "/csp-report/",
        }
    },
    CONTENT_SECURITY_POLICY_REPORT_ONLY=None,
)
def test_review_two_sites_and_three_approvals_after_local_change() -> None:
    # Approval table: two sites, three small approvals.  The partner CDN is
    # only allowed on the shop checkout page, and only in enforced mode.  The
    # partner JS host is allowed site-wide on support.
    approvals = [
        Approval("AP-SHOP-IMG", site="shop.example", directive="img-src", sources=PARTNER_CDN, pages=["/checkout/"]),
        Approval(
            "AP-SHOP-IMG-RO",
            site="shop.example",
            directive="img-src",
            sources=PARTNER_CDN,
            pages=["/checkout/"],
            mode=REPORT_ONLY,
        ),
        Approval("AP-SUPPORT-JS", site="support.example", directive="script-src", sources=PARTNER_JS),
    ]

    registry = ApprovalRegistry(approvals=approvals, managed_sources=[PARTNER_CDN, PARTNER_JS])
    registry.record_snapshot(_checkout_snapshot())
    registry.record_snapshot(_support_snapshot())
    registry.record_snapshot(
        capture_snapshot(
            site="shop.example",
            page="/checkout/",
            mode=REPORT_ONLY,
            config={"default-src": [SELF], "img-src": [SELF]},
        )
    )

    report = registry.review()
    statuses = {result.approval_id: result.status for result in report.results}
    assert statuses["AP-SHOP-IMG"] == VALID
    assert statuses["AP-SUPPORT-JS"] == VALID
    # The report-only policy does not carry the partner CDN even though the
    # enforced policy does; content equality does not bridge the mode.
    assert statuses["AP-SHOP-IMG-RO"] == NEEDS_REVIEW
    assert report.unapproved_uses == ()

    # Change one local declaration: checkout now points at a different CDN.
    changed = capture_snapshot(
        site="shop.example",
        page="/checkout/",
        mode=ENFORCE,
        update={"img-src": "new-cdn.partner.example"},
    )
    registry.record_snapshot(changed)

    report = registry.review()
    result = {item.approval_id: item for item in report.results}
    assert result["AP-SHOP-IMG"].status == NEEDS_REVIEW
    assert PARTNER_CDN in result["AP-SHOP-IMG"].reasons[0]
    assert result["AP-SUPPORT-JS"].status == VALID
    assert result["AP-SHOP-IMG-RO"].status == NEEDS_REVIEW
    assert [result.approval_id for result in report.valid] == ["AP-SUPPORT-JS"]
    assert "AP-SHOP-IMG" in [result.approval_id for result in report.needs_review]


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {
            "default-src": [SELF],
            "img-src": [SELF],
            "script-src": [SELF],
            "report-uri": "/csp-report/",
        }
    },
    CONTENT_SECURITY_POLICY_REPORT_ONLY=None,
)
def test_review_does_not_extend_page_approval_to_other_pages() -> None:
    registry = ApprovalRegistry(
        approvals=[Approval("AP-CHECKOUT", site="shop.example", directive="img-src", sources=PARTNER_CDN, pages=["/checkout/"])]
    )
    registry.record_snapshot(_checkout_snapshot())
    registry.record_snapshot(_orders_snapshot())

    report = registry.review()
    assert [result.approval_id for result in report.valid] == ["AP-CHECKOUT"]
    # /checkout/ is covered, but the same partner source on /orders/ is not.
    assert [use.page for use in report.unapproved_uses] == ["/orders/"]

    # The same partner source on /orders/ has no approval for that page.
    unapproved = [
        use.to_dict()
        for use in review_approvals(
            approvals=registry.approvals,
            snapshots=[
                _checkout_snapshot(),
                capture_snapshot(
                    site="shop.example",
                    page="/orders/",
                    update={"img-src": PARTNER_CDN},
                ),
            ],
        ).unapproved_uses
    ]
    assert unapproved == [
        {
            "site": "shop.example",
            "page": "/orders/",
            "mode": ENFORCE,
            "directive": "img-src",
            "source": PARTNER_CDN,
            "policy_source": "view",
        }
    ]


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {
            "default-src": [SELF],
            "img-src": [SELF],
            "script-src": [SELF],
            "report-uri": "/csp-report/",
        }
    },
    CONTENT_SECURITY_POLICY_REPORT_ONLY={"DIRECTIVES": {"default-src": [SELF], "img-src": [SELF]}},
)
def test_same_source_does_not_share_approval_across_modes() -> None:
    enforce = capture_snapshot(site="shop.example", page="/checkout/", update={"img-src": PARTNER_CDN})
    report_only = capture_snapshot(site="shop.example", page="/checkout/", mode=REPORT_ONLY)

    report = review_approvals(
        approvals=[
            Approval("AP-ENFORCE", site="shop.example", directive="img-src", sources=PARTNER_CDN, pages=["/checkout/"]),
            Approval(
                "AP-RO",
                site="shop.example",
                directive="img-src",
                sources=PARTNER_CDN,
                pages=["/checkout/"],
                mode=REPORT_ONLY,
            ),
        ],
        snapshots=[enforce, report_only],
    )
    statuses = {result.approval_id: result.status for result in report.results}
    assert statuses["AP-ENFORCE"] == VALID
    assert statuses["AP-RO"] == NEEDS_REVIEW


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {
            "default-src": [SELF],
            "img-src": [SELF],
            "script-src": [SELF],
        }
    },
)
def test_approval_bound_to_site_does_not_cover_another_site() -> None:
    snapshot = capture_snapshot(site="other.example", page="/checkout/", update={"img-src": PARTNER_CDN})
    report = review_approvals(
        approvals=[Approval("AP-SHOP", site="shop.example", directive="img-src", sources=PARTNER_CDN, pages=["/checkout/"])],
        snapshots=[snapshot],
    )
    assert report.results[0].status == PENDING
    assert [use.source for use in report.unapproved_uses] == [PARTNER_CDN]
    assert report.unapproved_uses[0].site == "other.example"


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {
            "default-src": [SELF],
            "img-src": [SELF],
            "script-src": [SELF],
            "report-uri": "/csp-report/",
        }
    },
    CONTENT_SECURITY_POLICY_REPORT_ONLY=None,
)
def test_registry_uses_settings_table_and_settings_snapshots() -> None:
    rows = [
        {
            "id": "AP-1",
            "site": "shop.example",
            "directive": "img-src",
            "source": PARTNER_CDN,
            "scope": ["/checkout/"],
        }
    ]
    with override_settings(
        CSP_POLICY_APPROVALS=rows,
        CSP_POLICY_SNAPSHOTS=[
            {
                "site": "shop.example",
                "page": "/checkout/",
                "directives": {"img-src": [SELF, PARTNER_CDN]},
                "origins": {"img-src": "settings+view"},
                "source_origins": {"img-src": {SELF: "settings", PARTNER_CDN: "view"}},
            }
        ],
    ):
        registry = ApprovalRegistry.from_settings()
    assert registry.approvals[0].approval_id == "AP-1"


def test_review_report_serializes_valid_and_stale_decisions() -> None:
    registry = ApprovalRegistry(approvals=[Approval("AP-1", site="shop.example", directive="img-src", sources=PARTNER_CDN, pages=["/checkout/"])])
    registry.record_snapshot(capture_snapshot(site="shop.example", page="/checkout/", update={"img-src": PARTNER_CDN}))
    data = registry.review().to_dict()
    assert data["valid"] == ["AP-1"]
    assert data["needs_review"] == []
    assert data["approvals"][0]["pages"][0]["source_origins"][PARTNER_CDN] == "view"


def test_report_distinguishes_non_delivered_policy_from_pending_evidence() -> None:
    snapshot = capture_snapshot(
        site="shop.example",
        page="/checkout/",
        update={"img-src": PARTNER_CDN},
        delivered=False,
    )
    report = review_approvals(
        approvals=[Approval("AP-1", site="shop.example", directive="img-src", sources=PARTNER_CDN)],
        snapshots=[snapshot],
    )
    assert report.results[0].status == PENDING
    assert report.results[0].pages[0].status == "not_delivered"


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {
            "default-src": [SELF],
            "img-src": [SELF],
            "script-src": [SELF],
        }
    },
    CONTENT_SECURITY_POLICY_REPORT_ONLY=None,
)
def test_snapshot_matches_delivered_header_tokens() -> None:
    request = rf.get("/checkout/")
    setattr(request, "csp_site", "shop.example")
    response = _checkout_view(request)
    _render(request, response)

    snapshot = mw.get_policy_snapshot(request, response)
    delivered = response[HEADER]
    header_directives = dict(part.split(" ", 1) if " " in part else (part, "") for part in delivered.split("; "))
    header_tokens = {name: tuple(value.split()) for name, value in header_directives.items()}
    assert dict(snapshot.directives) == header_tokens


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {
            "default-src": [SELF],
            "img-src": [SELF],
            "script-src": [SELF],
        }
    },
    CONTENT_SECURITY_POLICY_REPORT_ONLY=None,
)
def test_decorated_view_produces_its_own_review_basis() -> None:
    @csp_replace({"img-src": [PARTNER_CDN]})
    def decorated(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    request = rf.get("/checkout/")
    setattr(request, "csp_site", "shop.example")
    response = decorated(request)
    _render(request, response)

    snapshot = mw.get_policy_snapshot(request, response)
    assert snapshot.sources_for("img-src") == (PARTNER_CDN,)
    assert snapshot.origin_for("img-src", PARTNER_CDN) == "view"
    assert sorted(response[HEADER].split("; ")) == [
        "default-src 'self'",
        "img-src cdn.partner.example",
        "script-src 'self'",
    ]


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {
            "default-src": [SELF],
            "img-src": [SELF],
            "script-src": [SELF],
        }
    },
    CONTENT_SECURITY_POLICY_REPORT_ONLY=None,
)
def test_conflicting_preexisting_header_is_not_delivery_evidence() -> None:
    request = rf.get("/checkout/")
    response = _checkout_view(request)
    response[HEADER] = "default-src 'self'"
    mw.process_request(request)
    mw.process_response(request, response)

    assert response[HEADER] == "default-src 'self'"
    snapshot = mw.get_policy_snapshot(request, response)
    assert snapshot.delivered is False
