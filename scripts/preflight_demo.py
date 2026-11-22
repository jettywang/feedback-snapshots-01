"""Pre-release preflight demo for two OIDC tenants and one SAML IdP.

Run from the repository root with the test dependencies available:

    .venv/bin/python scripts/preflight_demo.py

Everything is local and read-only. The discovery documents and SAML metadata
are fake fixtures, every credential is a placeholder, and the check opens no
network connection. It demonstrates three outcomes:

1. an OIDC tenant whose explicit settings match its discovery metadata;
2. an OIDC tenant that is not configured for the environment;
3. a SAML IdP whose local configuration conflicts with its metadata intent.
"""

from __future__ import annotations

import json
from typing import Any

from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.preflight import (
    BackendReport,
    inspect_backend,
    render_text_report,
)
from social_core.strategy import BaseStrategy
from social_core.tests.strategy import TEST_URI, TestTemplateStrategy


class PreflightStrategy(BaseStrategy[Any]):
    """In-memory strategy holding the environment's effective settings."""

    DEFAULT_TEMPLATE_STRATEGY = TestTemplateStrategy

    def __init__(self, settings: dict[str, Any]) -> None:
        self._settings = dict(settings)
        super().__init__(storage=None)

    def get_setting(self, name: str) -> Any:
        return self._settings[name]

    def build_absolute_uri(self, path: str | None = None) -> str:
        path = path or ""
        if path.startswith(("http://", "https://")):
            return path
        return TEST_URI + path

    def get_request_data(self, merge: bool = True) -> dict[str, Any]:
        return {}

    def request_host(self) -> str:
        return "myapp.com"

    def request_is_secure(self) -> bool:
        return True

    def request_path(self) -> str:
        return ""

    def request_port(self) -> int:
        return 443

    def request_get(self) -> dict[str, Any]:
        return {}

    def request_post(self) -> dict[str, Any]:
        return {}

    def session_get(self, name: str, default: Any = None) -> Any:
        return default

    def session_set(self, name: str, value: Any) -> None:
        pass

    def session_pop(self, name: str) -> Any:
        return None

    def redirect(self, url: str) -> Any:
        return url

    def html(self, content: str) -> Any:
        return content


class AcmeOIDC(OpenIdConnectAuth):
    """First OIDC tenant, configured correctly for this environment."""

    name = "oidc-acme"
    title = "Acme OIDC"


class GlobexOIDC(OpenIdConnectAuth):
    """Second OIDC tenant, missing its per-tenant endpoint configuration."""

    name = "oidc-globex"
    title = "Globex OIDC"


class SamlLikeBackend:
    """Minimal backend surface the SAML preflight reads.

    The real production backend is ``social_core.backends.saml.SAMLAuth``; the
    preflight only resolves settings and parses metadata, so the optional
    python3-saml toolkit is not needed to run this offline demo.
    """

    name = "saml"

    def __init__(
        self, strategy: PreflightStrategy, redirect_uri: str | None = None
    ) -> None:
        self.strategy = strategy
        self.redirect_uri = strategy.absolute_uri(redirect_uri)


ACME_DISCOVERY = {
    "issuer": "https://idp.acme.example/realms/main",
    "authorization_endpoint": "https://idp.acme.example/realms/main/protocol/openid-connect/auth",
    "token_endpoint": "https://idp.acme.example/realms/main/protocol/openid-connect/token",
    "userinfo_endpoint": "https://idp.acme.example/realms/main/protocol/openid-connect/userinfo",
    "jwks_uri": "https://idp.acme.example/realms/main/protocol/openid-connect/certs",
}

GLOBEX_DISCOVERY = {
    "issuer": "https://login.globex.example/tenant-globex/v2",
    "authorization_endpoint": "https://login.globex.example/tenant-globex/v2/authorize",
    "token_endpoint": "https://login.globex.example/tenant-globex/v2/token",
    "jwks_uri": "https://login.globex.example/tenant-globex/v2/keys",
}

UMBRELLA_METADATA = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://idp.umbrella.example/idp/shibboleth">
  <md:IDPSSODescriptor
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>FAKE-UMBRELLA-IDP-CERT</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.umbrella.example/idp/profile/SAML2/Redirect/SSO"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"""


def build_strategy() -> PreflightStrategy:
    return PreflightStrategy(
        {
            # Acme: endpoint and an explicit authorization URL that match the
            # discovery fixture; remaining endpoints are discovery-driven.
            "SOCIAL_AUTH_OIDC_ACME_KEY": "acme-placeholder-client-id",
            "SOCIAL_AUTH_OIDC_ACME_SECRET": "acme-placeholder-secret",
            "SOCIAL_AUTH_OIDC_ACME_OIDC_ENDPOINT": "https://idp.acme.example/realms/main",
            "SOCIAL_AUTH_OIDC_ACME_AUTHORIZATION_URL": (
                "https://idp.acme.example/realms/main/protocol/openid-connect/auth"
            ),
            # Globex: credentials were provisioned but the per-tenant endpoint
            # was never set in this environment.
            "SOCIAL_AUTH_OIDC_GLOBEX_KEY": "globex-placeholder-client-id",
            "SOCIAL_AUTH_OIDC_GLOBEX_SECRET": "globex-placeholder-secret",
            # SAML service provider and one enabled IdP. The local SSO URL does
            # not match what the IdP metadata advertises.
            "SOCIAL_AUTH_SAML_SP_ENTITY_ID": "https://app.example.com/auth/saml/metadata/",
            "SOCIAL_AUTH_SAML_SP_PUBLIC_CERT": "FAKE-SP-PUBLIC-CERT",
            "SOCIAL_AUTH_SAML_SP_PRIVATE_KEY": "FAKE-SP-PRIVATE-KEY",
            "SOCIAL_AUTH_SAML_ENABLED_IDPS": {
                "umbrella": {
                    "entity_id": "https://idp.umbrella.example/idp/shibboleth",
                    "url": "https://staging.umbrella.example/idp/profile/SAML2/Redirect/SSO",
                    "x509cert": "FAKE-UMBRELLA-IDP-CERT",
                }
            },
        }
    )


def main() -> int:
    strategy = build_strategy()

    acme = AcmeOIDC(strategy, redirect_uri="/auth/complete/oidc-acme/")
    globex = GlobexOIDC(strategy, redirect_uri="/auth/complete/oidc-globex/")
    saml = SamlLikeBackend(strategy, redirect_uri="/auth/complete/saml/")

    reports: list[BackendReport] = []
    reports.extend(inspect_backend(acme, oidc_discovery_document=ACME_DISCOVERY))
    # The Globex fixture documents what the tenant *should* use, but without a
    # configured endpoint the backend cannot reach it in this environment.
    reports.extend(inspect_backend(globex))
    reports.extend(
        inspect_backend(saml, saml_metadata_fixtures={"umbrella": UMBRELLA_METADATA})
    )

    print(render_text_report(reports))
    print("\nMachine-readable report:")
    print(
        json.dumps(
            [report.to_dict() for report in reports], indent=2, ensure_ascii=False
        )
    )

    statuses = {
        f"{report.backend}:{report.target or ''}": report.status for report in reports
    }
    failures = [name for name, status in statuses.items() if status == "invalid"]
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
