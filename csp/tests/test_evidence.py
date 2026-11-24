from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from django.http import HttpResponse
from django.test import RequestFactory
from django.test.utils import override_settings

from csp.constants import HEADER, NONCE, SELF
from csp.decorators import csp_replace, csp_update
from csp.evidence import PolicyEvidence, export_policy_evidence
from csp.middleware import CSPMiddleware
from csp.tests.utils import response

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase


rf = RequestFactory()
mw = CSPMiddleware(response())


def _settings() -> dict[str, Any]:
    return {
        "CONTENT_SECURITY_POLICY": {
            "DIRECTIVES": {
                "default-src": [SELF],
                "connect-src": [SELF, "https://api.public.example.com"],
                "img-src": [SELF, "https://images.corp.internal", NONCE],
            }
        },
        "CONTENT_SECURITY_POLICY_REPORT_ONLY": {
            "DIRECTIVES": {
                "default-src": [SELF],
                "img-src": [SELF, "https://preview.corp.internal"],
            }
        },
    }


def _build(with_view_change: bool = True, generate_nonce: bool = True) -> tuple[HttpRequest, HttpResponseBase]:
    request = rf.get("/")

    def view(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    if with_view_change:
        view = csp_replace({"connect-src": [SELF, "https://uploads.public.example.com"]})(view)  # type: ignore[method-assign]

    mw.process_request(request)
    if generate_nonce:
        str(getattr(request, "csp_nonce"))
    response = view(request)
    mw.process_response(request, response)
    return request, response


def _directive(public: dict[str, Any], mode: str, name: str) -> dict[str, Any]:
    policy = next(policy for policy in public["policies"] if policy["mode"] == mode)
    return next(directive for directive in policy["directives"] if directive["directive"] == name)


@override_settings(**_settings())
def test_public_report_redacts_private_sources_and_nonce() -> None:
    request, response = _build()
    evidence = export_policy_evidence(request, response)

    assert isinstance(evidence, PolicyEvidence)
    public_json = evidence.public_json()
    assert "images.corp.internal" not in public_json
    assert "preview.corp.internal" not in public_json
    assert "nonce-" not in public_json

    img = _directive(evidence.public, "enforced", "img-src")
    private = next(source for source in img["sources"] if source["kind"] == "private-network")
    assert private["redacted"] is True
    assert private["value"].startswith("hmac-sha256:")
    assert "images.corp.internal" not in private["value"]

    nonce = next(source for source in img["sources"] if source["kind"] == "dynamic-nonce")
    assert nonce["redacted"] is True
    assert nonce["value"].startswith("hmac-sha256:")

    assert img["runtime_nonce"] is True


@override_settings(**_settings())
def test_public_report_keeps_public_sources_and_modes() -> None:
    request, response = _build()
    evidence = export_policy_evidence(request, response)

    connect = _directive(evidence.public, "enforced", "connect-src")
    assert [source["value"] for source in connect["sources"]] == ["'self'", "https://uploads.public.example.com"]
    assert all(source["origin"] == "view:csp_replace" for source in connect["sources"])
    assert all(source["kind"] == "host" or source["kind"] == "keyword" for source in connect["sources"])
    assert connect["changed"] is True
    assert connect["change_sources"] == ["view:csp_replace"]

    report_only = next(policy for policy in evidence.public["policies"] if policy["mode"] == "report-only")
    assert report_only["setting"] == "CONTENT_SECURITY_POLICY_REPORT_ONLY"
    assert report_only["header_present"] is True


@override_settings(**_settings())
def test_receipt_confirms_redacted_values() -> None:
    request, response = _build()
    evidence = export_policy_evidence(request, response)

    receipt_json = evidence.receipt_json()
    assert "images.corp.internal" in receipt_json
    assert "preview.corp.internal" in receipt_json
    assert evidence.receipt["public_report_fingerprint"].startswith("hmac-sha256:")

    img = _directive(evidence.public, "enforced", "img-src")
    private = next(source for source in img["sources"] if source["kind"] == "private-network")
    match = next(item for item in evidence.receipt["redactions"] if item["marker"] == private["value"])
    assert match["value"] == "https://images.corp.internal"
    assert match["directive"] == "img-src"
    assert match["mode"] == "enforced"


@override_settings(**_settings())
def test_fingerprints_are_stable_with_key_and_differ_across_keys() -> None:
    request, response = _build()
    first = export_policy_evidence(request, response, key="review-key")
    second = export_policy_evidence(request, response, key="review-key")
    other = export_policy_evidence(request, response, key="other-key")

    def marker(evidence: PolicyEvidence) -> str:
        img = _directive(evidence.public, "enforced", "img-src")
        return next(source["value"] for source in img["sources"] if source["kind"] == "private-network")

    assert marker(first) == marker(second)
    assert marker(first) != marker(other)


@override_settings(**_settings())
def test_export_does_not_change_response_or_nonce() -> None:
    request = rf.get("/")

    def view(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    mw.process_request(request)
    response = view(request)
    mw.process_response(request, response)

    before_headers = dict(response.headers)
    evidence = export_policy_evidence(request, response)
    assert dict(response.headers) == before_headers
    assert "nonce-" not in response[HEADER]
    assert evidence.public["policies"][0]["policy_present"] is True

    # Reading the internal receipt must not generate a nonce after the response.
    assert "nonce-" not in response[HEADER]


@override_settings(**_settings())
def test_report_only_and_enforced_are_separate() -> None:
    request, response = _build()
    evidence = export_policy_evidence(request, response)

    enforced = _directive(evidence.public, "enforced", "img-src")
    report_only = _directive(evidence.public, "report-only", "img-src")
    assert [source["redacted"] for source in enforced["sources"]] == [False, True, True]
    assert [source["redacted"] for source in report_only["sources"]] == [False, True]
    assert report_only["setting"] == "CONTENT_SECURITY_POLICY_REPORT_ONLY"


@override_settings(**_settings())
def test_ungenerated_nonce_is_marked_pending_without_a_value() -> None:
    request, response = _build(generate_nonce=False)
    evidence = export_policy_evidence(request, response)

    img = _directive(evidence.public, "enforced", "img-src")
    nonce = next(source for source in img["sources"] if source["kind"] == "dynamic-nonce")
    assert nonce["available"] is False
    assert nonce["value"] == "<runtime-nonce>"
    assert "nonce-" not in evidence.public_json()

    pending = [item for item in evidence.receipt["redactions"] if item.get("pending")]
    assert len(pending) == 1
    assert pending[0]["marker"] is None
    assert "nonce-" not in evidence.receipt_json()


@override_settings(**_settings())
def test_removed_directive_is_visible_in_report() -> None:
    request = rf.get("/")

    @csp_replace({"img-src": None})
    def view(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    mw.process_request(request)
    response = view(request)
    mw.process_response(request, response)

    evidence = export_policy_evidence(request, response)
    removed = _directive(evidence.public, "enforced", "img-src")
    assert removed["removed"] is True
    assert removed["present"] is False
    assert removed["changed"] is True
    assert removed["change_sources"] == ["view:csp_replace"]
    assert removed["basis"]["description"] == (
        "view csp_replace removed the directive; CONTENT_SECURITY_POLICY value is not used"
    )
    policy = next(policy for policy in evidence.public["policies"] if policy["mode"] == "enforced")
    assert "img-src" in policy["changed_directives"]
    assert "img-src" not in policy["policy_redacted"]


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {"default-src": [SELF]}})
def test_default_settings_are_marked_as_defaults() -> None:
    request, response = _build(with_view_change=False)
    evidence = export_policy_evidence(request, response)

    default_src = _directive(evidence.public, "enforced", "default-src")
    assert default_src["from_approved_settings"] is True
    assert default_src["basis"]["declared_in_settings"] is True
    assert default_src["change_source"] == "settings"


@override_settings(CONTENT_SECURITY_POLICY={"DIRECTIVES": {}})
def test_implicit_default_is_reported_as_default() -> None:
    request, response = _build(with_view_change=False)
    evidence = export_policy_evidence(request, response)

    default_src = _directive(evidence.public, "enforced", "default-src")
    assert default_src["basis"]["defaults_applied"] is True
    assert default_src["change_source"] == "default"
    assert default_src["basis"]["description"] == "django-csp default value; no explicit setting"


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {
            "default-src": [SELF],
            "img-src": [
                "10.1.2.3",
                "127.0.0.1",
                "https://[::1]",
                "printer",
                "https://foo.localhost",
                "https://cdn.example.net",
            ],
        }
    }
)
def test_private_host_detection_covers_local_ranges_and_single_labels() -> None:
    request, response = _build(with_view_change=False)
    evidence = export_policy_evidence(request, response)

    img = _directive(evidence.public, "enforced", "img-src")
    kinds = {source["value"] if not source["redacted"] else source["kind"]: source["kind"] for source in img["sources"]}
    public_json = evidence.public_json()
    for value in ("10.1.2.3", "127.0.0.1", "::1", "printer", "foo.localhost"):
        assert value not in public_json
    assert kinds["https://cdn.example.net"] == "host"
    assert [source["redacted"] for source in img["sources"]] == [True, True, True, True, True, False]


@override_settings(**_settings())
def test_private_hosts_override_adds_site_specific_names() -> None:
    request, response = _build(with_view_change=False)
    evidence = export_policy_evidence(request, response, private_hosts=["cdn.example.net"])
    img = _directive(evidence.public, "enforced", "img-src")
    cdn = next(source for source in img["sources"] if source["value"].startswith("hmac-"))
    assert cdn["redacted"] is True


@override_settings(**_settings())
def test_update_records_both_settings_and_view_origin() -> None:
    request = rf.get("/")

    @csp_update({"connect-src": ["https://uploads.public.example.com"]})
    def view(request: HttpRequest) -> HttpResponseBase:
        return HttpResponse()

    mw.process_request(request)
    response = view(request)
    mw.process_response(request, response)

    connect = _directive(export_policy_evidence(request, response).public, "enforced", "connect-src")
    assert connect["changed"] is True
    assert connect["change_sources"] == ["view:csp_update"]
    assert connect["basis"]["declared_in_settings"] is True
    assert connect["basis"]["declared_in_view"] is True
    assert connect["basis"]["description"] == (
        "CONTENT_SECURITY_POLICY directive extended by view csp_update"
    )
    assert [source["origin"] for source in connect["sources"]] == ["settings", "settings", "view:csp_update"]


@override_settings(
    CONTENT_SECURITY_POLICY={
        "DIRECTIVES": {
            "default-src": [SELF],
            "upgrade-insecure-requests": True,
            "block-all-mixed-content": False,
        }
    }
)
def test_boolean_directives_are_reported_without_sources() -> None:
    request, response = _build(with_view_change=False)
    evidence = export_policy_evidence(request, response)

    upgrade = _directive(evidence.public, "enforced", "upgrade-insecure-requests")
    assert upgrade["boolean"] is True
    assert upgrade["sources"] == []
    policy = next(policy for policy in evidence.public["policies"] if policy["mode"] == "enforced")
    assert "upgrade-insecure-requests" in policy["policy_redacted"]
    assert "block-all-mixed-content" not in policy["policy_redacted"]


@override_settings(**_settings())
def test_public_and_receipt_are_json_serializable() -> None:
    request, response = _build()
    evidence = export_policy_evidence(request, response)

    assert json.loads(evidence.public_json())["kind"] == "csp-policy-evidence"
    assert json.loads(evidence.receipt_json())["kind"] == "csp-policy-evidence-receipt"
    assert "default-src 'self'" in evidence.receipt["policies"][0]["policy"].split("; ")
