"""Read-only preflight checks for OIDC and SAML login configuration."""

from __future__ import annotations

import socket
from typing import Any
from unittest.mock import patch

import pytest

from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.preflight import (
    inspect_backend,
    inspect_oidc_backend,
    inspect_saml_backend,
    inspect_strategy,
    render_text_report,
    resolve_setting,
)
from social_core.tests.models import TestStorage
from social_core.tests.strategy import TestStrategy

CALLBACK = "/auth/complete/oidc/"
SAML_CALLBACK = "/auth/complete/saml/"

DISCOVERY = {
    "issuer": "https://idp.acme.example/tenant",
    "authorization_endpoint": "https://idp.acme.example/tenant/authorize",
    "token_endpoint": "https://idp.acme.example/tenant/token",
    "userinfo_endpoint": "https://idp.acme.example/tenant/userinfo",
    "jwks_uri": "https://idp.acme.example/tenant/jwks",
}

SAML_METADATA = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://idp.umbrella.example/idp">
  <md:IDPSSODescriptor
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>FAKE-IDP-CERT</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.umbrella.example/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"""


class MinimalSAMLBackend:
    """Backend surface the SAML preflight reads, without the SAML toolkit."""

    name = "saml"

    def __init__(self, strategy: TestStrategy, redirect_uri: str | None = None) -> None:
        self.strategy = strategy
        self.redirect_uri = strategy.absolute_uri(redirect_uri)


def make_strategy(**settings: Any) -> TestStrategy:
    strategy = TestStrategy(TestStorage)
    strategy.set_settings(settings)
    return strategy


def oidc_backend(strategy: TestStrategy) -> OpenIdConnectAuth:
    return OpenIdConnectAuth(strategy, redirect_uri=CALLBACK)


def setting(report, key: str):
    return next(item for item in report.settings if item.key == key)


@pytest.fixture
def network_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    def deny(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("preflight must not open a network connection")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "create_connection", deny)


def test_oidc_matching_configuration_resolves_and_records_sources(
    network_guard: None,
) -> None:
    strategy = make_strategy(
        SOCIAL_AUTH_OIDC_KEY="client-id",
        SOCIAL_AUTH_OIDC_SECRET="placeholder-secret",
        SOCIAL_AUTH_OIDC_OIDC_ENDPOINT="https://idp.acme.example/tenant",
        SOCIAL_AUTH_OIDC_AUTHORIZATION_URL=(
            "https://idp.acme.example/tenant/authorize"
        ),
    )
    report = inspect_oidc_backend(oidc_backend(strategy), DISCOVERY)

    assert report.status == "ok"
    assert report.callback_url == "http://myapp.com/auth/complete/oidc/"
    assert report.findings == []
    assert setting(report, "AUTHORIZATION_URL").source.kind == "setting"
    assert setting(report, "ACCESS_TOKEN_URL").source.kind == "oidc_discovery"
    assert setting(report, "ID_TOKEN_ISSUER").value == DISCOVERY["issuer"]
    assert setting(report, "SECRET").display_value() == "<redacted>"
    assert strategy._session == {}


def test_oidc_unconfigured_tenant_is_reported_without_discovery(
    network_guard: None,
) -> None:
    strategy = make_strategy(SOCIAL_AUTH_OIDC_KEY="client-id")
    report = inspect_oidc_backend(oidc_backend(strategy))

    assert report.status == "unconfigured"
    codes = {finding.code for finding in report.findings}
    assert "tenant_unconfigured" in codes
    assert setting(report, "OIDC_ENDPOINT").display_value() == "<not set>"


def test_oidc_endpoint_without_fixture_requires_live_discovery(
    network_guard: None,
) -> None:
    strategy = make_strategy(
        SOCIAL_AUTH_OIDC_KEY="client-id",
        SOCIAL_AUTH_OIDC_SECRET="placeholder-secret",
        SOCIAL_AUTH_OIDC_OIDC_ENDPOINT="https://idp.globex.example",
    )
    report = inspect_oidc_backend(oidc_backend(strategy))

    assert report.status == "unconfigured"
    assert all(finding.code == "discovery_required" for finding in report.findings)


def test_oidc_intent_conflict_between_setting_and_discovery(
    network_guard: None,
) -> None:
    strategy = make_strategy(
        SOCIAL_AUTH_OIDC_KEY="client-id",
        SOCIAL_AUTH_OIDC_SECRET="placeholder-secret",
        SOCIAL_AUTH_OIDC_OIDC_ENDPOINT="https://idp.acme.example/tenant",
        SOCIAL_AUTH_OIDC_AUTHORIZATION_URL="https://wrong.example/authorize",
    )
    report = inspect_oidc_backend(oidc_backend(strategy), DISCOVERY)

    assert report.status == "conflict"
    conflict = next(
        finding for finding in report.findings if finding.code == "intent_conflict"
    )
    assert conflict.severity == "warning"
    assert "wrong.example" in conflict.message


def test_oidc_optional_claim_absent_from_discovery_is_warning(
    network_guard: None,
) -> None:
    document = {
        key: value for key, value in DISCOVERY.items() if key != "userinfo_endpoint"
    }
    strategy = make_strategy(
        SOCIAL_AUTH_OIDC_KEY="client-id",
        SOCIAL_AUTH_OIDC_SECRET="placeholder-secret",
        SOCIAL_AUTH_OIDC_OIDC_ENDPOINT="https://idp.acme.example/tenant",
        SOCIAL_AUTH_OIDC_AUTHORIZATION_URL=DISCOVERY["authorization_endpoint"],
    )
    report = inspect_oidc_backend(oidc_backend(strategy), document)

    assert report.status == "ok"
    assert [finding.code for finding in report.findings] == ["endpoint_unavailable"]
    assert setting(report, "USERINFO_URL").source.kind == "class_default"


def test_backend_scoped_setting_takes_precedence_over_global() -> None:
    strategy = make_strategy(
        SOCIAL_AUTH_KEY="global-client",
        SOCIAL_AUTH_OIDC_KEY="tenant-client",
        SOCIAL_AUTH_OIDC_OIDC_ENDPOINT="https://idp.acme.example/tenant",
    )
    value, source, consulted = resolve_setting(oidc_backend(strategy), "KEY")
    assert value == "tenant-client"
    assert source.label == "SOCIAL_AUTH_OIDC_KEY"
    assert [candidate.label for candidate in consulted] == [
        "SOCIAL_AUTH_OIDC_KEY",
        "SOCIAL_AUTH_KEY",
        "KEY",
    ]


def test_discovery_fixture_replaces_network_fetch(network_guard: None) -> None:
    strategy = make_strategy(
        SOCIAL_AUTH_OIDC_KEY="client-id",
        SOCIAL_AUTH_OIDC_SECRET="placeholder-secret",
        SOCIAL_AUTH_OIDC_OIDC_ENDPOINT="https://idp.acme.example/tenant",
    )
    backend = oidc_backend(strategy)
    with patch.object(backend, "get_json") as get_json:
        report = inspect_oidc_backend(backend, DISCOVERY)
    get_json.assert_not_called()
    assert report.status == "ok"


def test_saml_unconfigured_without_enabled_idps(network_guard: None) -> None:
    strategy = make_strategy(SOCIAL_AUTH_SAML_ENABLED_IDPS={})
    reports = inspect_saml_backend(
        MinimalSAMLBackend(strategy, redirect_uri=SAML_CALLBACK)
    )
    assert len(reports) == 1
    assert reports[0].status == "unconfigured"
    assert reports[0].findings[0].code == "tenant_unconfigured"


def test_saml_matching_idp_reports_ok(network_guard: None) -> None:
    strategy = make_strategy(
        SOCIAL_AUTH_SAML_SP_ENTITY_ID="https://app.example/metadata/",
        SOCIAL_AUTH_SAML_SP_PUBLIC_CERT="FAKE-SP-CERT",
        SOCIAL_AUTH_SAML_SP_PRIVATE_KEY="FAKE-SP-KEY",
        SOCIAL_AUTH_SAML_ENABLED_IDPS={
            "umbrella": {
                "entity_id": "https://idp.umbrella.example/idp",
                "url": "https://idp.umbrella.example/sso",
                "x509cert": "FAKE-IDP-CERT",
            }
        },
    )
    reports = inspect_saml_backend(
        MinimalSAMLBackend(strategy, redirect_uri=SAML_CALLBACK),
        {"umbrella": SAML_METADATA},
    )
    assert len(reports) == 1
    report = reports[0]
    assert report.status == "ok"
    assert report.target == "umbrella"
    assert report.callback_url == "http://myapp.com/auth/complete/saml/"
    assert setting(report, "SP_PRIVATE_KEY").display_value() == "<redacted>"
    assert setting(report, "IDP_ENTITY_ID").metadata_value == (
        "https://idp.umbrella.example/idp"
    )


def test_saml_idp_without_metadata_fixture_is_unconfigured(
    network_guard: None,
) -> None:
    strategy = make_strategy(
        SOCIAL_AUTH_SAML_SP_ENTITY_ID="https://app.example/metadata/",
        SOCIAL_AUTH_SAML_SP_PUBLIC_CERT="FAKE-SP-CERT",
        SOCIAL_AUTH_SAML_SP_PRIVATE_KEY="FAKE-SP-KEY",
        SOCIAL_AUTH_SAML_ENABLED_IDPS={
            "umbrella": {
                "entity_id": "https://idp.umbrella.example/idp",
                "url": "https://idp.umbrella.example/sso",
                "x509cert": "FAKE-IDP-CERT",
            }
        },
    )
    reports = inspect_saml_backend(
        MinimalSAMLBackend(strategy, redirect_uri=SAML_CALLBACK)
    )
    assert reports[0].status == "unconfigured"
    assert reports[0].findings[0].code == "metadata_required"


def test_saml_intent_conflict_flags_staging_sso_url(network_guard: None) -> None:
    strategy = make_strategy(
        SOCIAL_AUTH_SAML_SP_ENTITY_ID="https://app.example/metadata/",
        SOCIAL_AUTH_SAML_SP_PUBLIC_CERT="FAKE-SP-CERT",
        SOCIAL_AUTH_SAML_SP_PRIVATE_KEY="FAKE-SP-KEY",
        SOCIAL_AUTH_SAML_ENABLED_IDPS={
            "umbrella": {
                "entity_id": "https://idp.umbrella.example/idp",
                "url": "https://staging.umbrella.example/sso",
                "x509cert": "FAKE-IDP-CERT",
            }
        },
    )
    reports = inspect_saml_backend(
        MinimalSAMLBackend(strategy, redirect_uri=SAML_CALLBACK),
        {"umbrella": SAML_METADATA},
    )
    report = reports[0]
    assert report.status == "conflict"
    assert report.findings[0].code == "sso_url_conflict"


def test_saml_certificate_conflict(network_guard: None) -> None:
    strategy = make_strategy(
        SOCIAL_AUTH_SAML_SP_ENTITY_ID="https://app.example/metadata/",
        SOCIAL_AUTH_SAML_SP_PUBLIC_CERT="FAKE-SP-CERT",
        SOCIAL_AUTH_SAML_SP_PRIVATE_KEY="FAKE-SP-KEY",
        SOCIAL_AUTH_SAML_ENABLED_IDPS={
            "umbrella": {
                "entity_id": "https://idp.umbrella.example/idp",
                "url": "https://idp.umbrella.example/sso",
                "x509cert": "DIFFERENT-CERT",
            }
        },
    )
    reports = inspect_saml_backend(
        MinimalSAMLBackend(strategy, redirect_uri=SAML_CALLBACK),
        {"umbrella": SAML_METADATA},
    )
    codes = {finding.code for finding in reports[0].findings}
    assert "certificate_conflict" in codes
    assert reports[0].status == "conflict"


def test_saml_metadata_parser_tracks_each_entity() -> None:
    from social_core.preflight import _saml_metadata_entities

    document = """<?xml version="1.0" encoding="UTF-8"?>
    <md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
      <md:EntityDescriptor entityID="https://idp-one.example/idp">
        <md:IDPSSODescriptor
            protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
          <md:SingleSignOnService
              Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
              Location="https://idp-one.example/sso"/>
        </md:IDPSSODescriptor>
      </md:EntityDescriptor>
      <md:EntityDescriptor entityID="https://idp-two.example/idp">
        <md:IDPSSODescriptor
            protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
          <md:SingleSignOnService
              Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
              Location="https://idp-two.example/sso"/>
        </md:IDPSSODescriptor>
      </md:EntityDescriptor>
    </md:EntitiesDescriptor>"""
    entities = _saml_metadata_entities(document)
    assert [entity["entity_id"] for entity in entities] == [
        "https://idp-one.example/idp",
        "https://idp-two.example/idp",
    ]
    assert entities[0]["sso_url"] == "https://idp-one.example/sso"


def test_saml_invalid_metadata_is_invalid_status(network_guard: None) -> None:
    strategy = make_strategy(
        SOCIAL_AUTH_SAML_SP_ENTITY_ID="sp",
        SOCIAL_AUTH_SAML_SP_PUBLIC_CERT="c",
        SOCIAL_AUTH_SAML_SP_PRIVATE_KEY="k",
        SOCIAL_AUTH_SAML_ENABLED_IDPS={
            "umbrella": {
                "entity_id": "e",
                "url": "https://idp.umbrella.example/sso",
                "x509cert": "FAKE-IDP-CERT",
            }
        },
    )
    reports = inspect_saml_backend(
        MinimalSAMLBackend(strategy, redirect_uri=SAML_CALLBACK),
        {"umbrella": "<not-xml>"},
    )
    assert reports[0].status == "invalid"
    assert reports[0].findings[0].code == "invalid_metadata"


def test_saml_missing_required_sp_settings(network_guard: None) -> None:
    strategy = make_strategy(
        SOCIAL_AUTH_SAML_ENABLED_IDPS={
            "umbrella": {
                "entity_id": "https://idp.umbrella.example/idp",
                "url": "https://idp.umbrella.example/sso",
                "x509cert": "FAKE-IDP-CERT",
            }
        }
    )
    reports = inspect_saml_backend(
        MinimalSAMLBackend(strategy, redirect_uri=SAML_CALLBACK),
        {"umbrella": SAML_METADATA},
    )
    codes = {finding.code for finding in reports[0].findings}
    assert "missing_setting" in codes
    assert reports[0].status == "invalid"


def test_inspect_backend_dispatches_by_protocol(network_guard: None) -> None:
    oidc_strategy = make_strategy(
        SOCIAL_AUTH_OIDC_KEY="client-id",
        SOCIAL_AUTH_OIDC_OIDC_ENDPOINT="https://idp.acme.example/tenant",
    )
    oidc_reports = inspect_backend(
        oidc_backend(oidc_strategy), oidc_discovery_document=DISCOVERY
    )
    assert [report.protocol for report in oidc_reports] == ["oidc"]

    saml_strategy = make_strategy(SOCIAL_AUTH_SAML_ENABLED_IDPS={})
    saml_reports = inspect_backend(
        MinimalSAMLBackend(saml_strategy, redirect_uri=SAML_CALLBACK)
    )
    assert [report.protocol for report in saml_reports] == ["saml"]


def test_inspect_strategy_loads_backends_through_registry(
    network_guard: None,
) -> None:
    strategy = make_strategy(
        AUTHENTICATION_BACKENDS=[
            "social_core.backends.open_id_connect.OpenIdConnectAuth"
        ],
        SOCIAL_AUTH_OIDC_KEY="client-id",
        SOCIAL_AUTH_OIDC_SECRET="placeholder-secret",
        SOCIAL_AUTH_OIDC_OIDC_ENDPOINT="https://idp.acme.example/tenant",
    )
    reports = inspect_strategy(
        strategy,
        [
            "social_core.backends.open_id_connect.OpenIdConnectAuth",
        ],
        oidc_documents={"oidc": DISCOVERY},
        redirect_uris={"oidc": CALLBACK},
    )
    assert len(reports) == 1
    assert reports[0].backend == "oidc"
    assert reports[0].status == "ok"


def test_render_text_report_and_machine_readable_dict() -> None:
    strategy = make_strategy(SOCIAL_AUTH_OIDC_KEY="client-id")
    report = inspect_oidc_backend(oidc_backend(strategy))
    text = render_text_report([report])
    assert "oidc (oidc): UNCONFIGURED" in text
    assert "tenant_unconfigured" in text

    payload = report.to_dict()
    assert payload["status"] == "unconfigured"
    assert all("value" in item and "source" in item for item in payload["settings"])
