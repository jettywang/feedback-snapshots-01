"""
Federation boundary acceptance tests.

Two local stand-in OIDC providers share a subject value.  The tests show that
the same ``sub`` never collapses the providers into one another, and that
verification, ordinary authentication and application-bound authorization are
three distinct conclusions.
"""

from datetime import timedelta

import jwt
import pytest
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient, APIRequestFactory

from rest_framework_simplejwt import authentication, federation
from rest_framework_simplejwt.exceptions import (
    AuthenticationFailed,
    FederationConfigurationError,
    FederationTokenError,
)
from rest_framework_simplejwt.federation import (
    FederatedPrincipal,
    FederatedToken,
    OIDCProvider,
    OIDCProviderRegistry,
)
from rest_framework_simplejwt.federation_authentication import (
    FederatedJWTAuthentication,
)
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.utils import aware_utcnow, datetime_to_epoch

from .keys import PRIVATE_KEY, PRIVATE_KEY_2, PUBLIC_KEY, PUBLIC_KEY_2
from .utils import override_api_settings

User = get_user_model()

SHARED_SUBJECT = "same-subject-everywhere"

COMPANY_ISSUER = "https://company-idp.example"
COMPANY_AUDIENCE = "company-api"
COMPANY_JWKS = "https://company-idp.example/.well-known/jwks.json"
COMPANY_METADATA = {
    "issuer": COMPANY_ISSUER,
    "jwks_uri": COMPANY_JWKS,
    "id_token_signing_alg_values_supported": ["RS256"],
}

PARTNER_ISSUER = "https://partner-idp.example"
PARTNER_AUDIENCE = "partner-api"
PARTNER_JWKS = "https://partner-idp.example/keys"
PARTNER_METADATA = {
    "issuer": PARTNER_ISSUER,
    "jwks_uri": PARTNER_JWKS,
    "id_token_signing_alg_values_supported": ["RS256"],
}

PROVIDERS = {
    "company": {
        "metadata": COMPANY_METADATA,
        "issuer": COMPANY_ISSUER,
        "audiences": {COMPANY_AUDIENCE: "company-portal"},
        "verifying_key": PUBLIC_KEY,
        "applications": {"company-crm": "billing"},
        "identity": {
            "claim": "email",
            "template": "company:{value}",
            "lookup_field": "username",
        },
        "projected_claims": ("email", "roles"),
    },
    "partner": {
        "metadata": PARTNER_METADATA,
        "issuer": PARTNER_ISSUER,
        "audiences": {PARTNER_AUDIENCE: "partner-portal"},
        "verifying_key": PUBLIC_KEY_2,
        "applications": {"partner-crm": "support"},
        "identity": {
            "claim": "email",
            "template": "partner:{value}",
            "lookup_field": "username",
        },
        "projected_claims": ("email",),
    },
}


def encode(
    *,
    issuer: str,
    audience: str,
    private_key: str = PRIVATE_KEY,
    subject: str = SHARED_SUBJECT,
    email: str = "shared@example.com",
    applications=None,
    lifetime: timedelta = timedelta(minutes=5),
    extra: dict | None = None,
) -> str:
    now = aware_utcnow()
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "email": email,
        "iat": datetime_to_epoch(now),
        "exp": datetime_to_epoch(now + lifetime),
    }
    if applications is not None:
        payload["applications"] = applications
    if extra:
        payload.update(extra)
    return jwt.encode(payload, private_key, algorithm="RS256")


def company_token(**kwargs) -> str:
    kwargs.setdefault("issuer", COMPANY_ISSUER)
    kwargs.setdefault("audience", COMPANY_AUDIENCE)
    return encode(**kwargs)


def partner_token(**kwargs) -> str:
    kwargs.setdefault("issuer", PARTNER_ISSUER)
    kwargs.setdefault("audience", PARTNER_AUDIENCE)
    kwargs.setdefault("private_key", PRIVATE_KEY_2)
    return encode(**kwargs)


class FederationSettingsMixin:
    def setUp(self):
        super().setUp()
        self._settings = override_api_settings(FEDERATION_PROVIDERS=PROVIDERS)
        self._settings.__enter__()

    def tearDown(self):
        self._settings.__exit__(None, None, None)
        super().tearDown()

    @staticmethod
    def authenticate(token: str):
        request = APIRequestFactory().get(
            "/", HTTP_AUTHORIZATION=f"Bearer {token}"
        )
        return FederatedJWTAuthentication().authenticate(request)


class TestProviderRegistry(FederationSettingsMixin, TestCase):
    def test_registry_registers_both_providers_by_issuer(self):
        registry = federation.default_provider_registry()

        self.assertEqual(len(registry), 2)
        self.assertEqual(registry.by_name("company").issuer, COMPANY_ISSUER)
        self.assertEqual(registry.by_issuer(PARTNER_ISSUER).name, "partner")

    def test_duplicate_issuer_is_rejected(self):
        registry = OIDCProviderRegistry()
        registry.register(
            OIDCProvider(
                name="a",
                issuer=COMPANY_ISSUER,
                audiences={COMPANY_AUDIENCE: "one"},
                verifying_key=PUBLIC_KEY,
            )
        )
        with pytest.raises(FederationConfigurationError):
            registry.register(
                OIDCProvider(
                    name="b",
                    issuer=COMPANY_ISSUER,
                    audiences={COMPANY_AUDIENCE: "two"},
                    verifying_key=PUBLIC_KEY_2,
                )
            )

    def test_provider_requires_an_explicit_issuer_and_audience(self):
        with pytest.raises(FederationConfigurationError):
            OIDCProvider(name="x", issuer="", audiences={"a": "p"})
        with pytest.raises(FederationConfigurationError):
            OIDCProvider(name="x", issuer=COMPANY_ISSUER, audiences={})

    def test_metadata_issuer_must_match_configuration(self):
        config = dict(PROVIDERS["company"])
        config["issuer"] = "https://someone-else.example"
        with pytest.raises(FederationConfigurationError):
            OIDCProvider.from_config("company", config)

    def test_provider_cannot_reuse_local_issuer(self):
        config = {"company": dict(PROVIDERS["company"])}
        with override_api_settings(ISSUER=COMPANY_ISSUER):
            with pytest.raises(FederationConfigurationError):
                federation.OIDCProviderRegistry.from_settings(config)

    def test_provider_cannot_reuse_local_hmac_key(self):
        config = {
            "shared": {
                "issuer": "https://shared-key.example",
                "audiences": {"shared-api": "shared"},
                "algorithm": "HS256",
                "verifying_key": "not very secret in tests",
            }
        }
        with override_api_settings(
            ISSUER="local-issuer",
            ALGORITHM="HS256",
            SIGNING_KEY="not very secret in tests",
        ):
            with pytest.raises(FederationConfigurationError):
                federation.OIDCProviderRegistry.from_settings(config)

    def test_provider_cannot_reuse_local_asymmetric_verifying_key(self):
        config = {
            "shared": {
                "issuer": "https://shared-key.example",
                "audiences": {"shared-api": "shared"},
                "algorithm": "RS256",
                "verifying_key": PUBLIC_KEY,
            }
        }
        with override_api_settings(
            ISSUER="local-issuer",
            ALGORITHM="RS256",
            VERIFYING_KEY=PUBLIC_KEY,
        ):
            with pytest.raises(FederationConfigurationError):
                federation.OIDCProviderRegistry.from_settings(config)

    def test_metadata_algorithm_must_be_supported(self):
        metadata = dict(COMPANY_METADATA)
        metadata["id_token_signing_alg_values_supported"] = ["ES256"]
        config = dict(PROVIDERS["company"])
        config["metadata"] = metadata
        config["algorithm"] = "RS256"
        with pytest.raises(FederationConfigurationError):
            OIDCProvider.from_config("company", config)


class TestFederatedTokenMapping(FederationSettingsMixin, TestCase):
    def test_same_subject_maps_to_distinct_local_identities(self):
        company = FederatedToken(company_token())
        partner = FederatedToken(partner_token())

        self.assertEqual(company.subject, SHARED_SUBJECT)
        self.assertEqual(partner.subject, SHARED_SUBJECT)
        self.assertNotEqual(company.provider.name, partner.provider.name)

        company_identity = company.provider.map_identity(company.payload)
        partner_identity = partner.provider.map_identity(partner.payload)

        self.assertEqual(company_identity, "company:shared@example.com")
        self.assertEqual(partner_identity, "partner:shared@example.com")
        self.assertNotEqual(company_identity, partner_identity)

    def test_subject_is_qualified_by_default(self):
        provider = OIDCProvider(
            name="raw",
            issuer=COMPANY_ISSUER,
            audiences={COMPANY_AUDIENCE: "p"},
            verifying_key=PUBLIC_KEY,
        )
        payload = {"sub": "42", "aud": COMPANY_AUDIENCE, "iss": COMPANY_ISSUER}
        self.assertEqual(provider.map_identity(payload), "raw:42")

    def test_identity_mapping_must_be_explicit(self):
        provider = OIDCProvider(
            name="mapped",
            issuer=COMPANY_ISSUER,
            audiences={COMPANY_AUDIENCE: "p"},
            verifying_key=PUBLIC_KEY,
            identity_claim="email",
            identity_mapping={"allowed@example.com": "local-user"},
        )
        with pytest.raises(FederationTokenError) as e:
            provider.map_identity({"email": "other@example.com"})
        self.assertEqual(e.value.code, "identity_not_mapped")

    def test_application_mapping_drops_unknown_values(self):
        token = FederatedToken(
            company_token(applications=["company-crm", "billing", "unknown"])
        )
        # Only explicitly mapped external values survive, and the local name is
        # derived from the map rather than the raw external string.
        self.assertEqual(token.applications, ("billing",))

    def test_purpose_comes_from_audience_map(self):
        self.assertEqual(FederatedToken(company_token()).purpose, "company-portal")
        self.assertEqual(FederatedToken(partner_token()).purpose, "partner-portal")

    def test_audience_spanning_two_purposes_is_rejected(self):
        provider = OIDCProvider(
            name="multi",
            issuer=COMPANY_ISSUER,
            audiences={"a": "one", "b": "two"},
            verifying_key=PUBLIC_KEY,
        )
        with pytest.raises(FederationTokenError) as e:
            provider.resolve_purpose({"aud": ["a", "b"]})
        self.assertEqual(e.value.code, "ambiguous_purpose")

    def test_unregistered_issuer_is_rejected_before_signature_checks(self):
        token = encode(
            issuer="https://unknown.example",
            audience=COMPANY_AUDIENCE,
            extra={"applications": ["company-crm"]},
        )
        with pytest.raises(FederationTokenError) as e:
            FederatedToken(token)
        self.assertEqual(e.value.code, "unknown_issuer")

    def test_token_signed_with_another_providers_key_is_rejected(self):
        # Correct issuer and audience, but signed with the partner key.
        token = company_token(private_key=PRIVATE_KEY_2)
        with pytest.raises(FederationTokenError) as e:
            FederatedToken(token)
        self.assertEqual(e.value.code, "invalid_token")

    def test_issuer_swap_with_valid_signature_is_rejected(self):
        # Sign with the company key but claim the partner issuer.
        token = partner_token(private_key=PRIVATE_KEY)
        with pytest.raises(FederationTokenError) as e:
            FederatedToken(token)
        self.assertEqual(e.value.code, "invalid_token")

    def test_unapproved_audience_is_rejected(self):
        # The provider-pinned backend rejects the audience during decode; the
        # public error intentionally stays generic.
        token = company_token(audience="some-other-client")
        with pytest.raises(FederationTokenError) as e:
            FederatedToken(token)
        self.assertEqual(e.value.code, "invalid_token")

        provider = federation.default_provider_registry().by_name("company")
        with pytest.raises(FederationTokenError) as e:
            provider.resolve_purpose({"aud": "some-other-client"})
        self.assertEqual(e.value.code, "audience_not_allowed")

    def test_expired_foreign_token_is_rejected(self):
        token = company_token(lifetime=-timedelta(seconds=1))
        with pytest.raises(FederationTokenError) as e:
            FederatedToken(token)
        self.assertEqual(e.value.code, "token_expired")

    def test_projected_claims_are_allow_listed(self):
        token = FederatedToken(
            company_token(extra={"roles": ["admin"], "is_staff": True})
        )
        self.assertEqual(
            token.claims, {"email": "shared@example.com", "roles": ["admin"]}
        )
        self.assertNotIn("is_staff", token.claims)

    def test_federated_token_is_not_a_local_token(self):
        token = FederatedToken(company_token())
        self.assertNotIsInstance(token, AccessToken)
        self.assertNotIn("user_id", token)


class TestLocalIssuance(TestCase):
    def test_local_token_still_uses_local_authentication(self):
        user = User.objects.create_user(username="local-user")
        token = AccessToken.for_user(user)

        validated = authentication.JWTAuthentication().get_validated_token(str(token))
        self.assertIsInstance(validated, AccessToken)
        self.assertEqual(validated["user_id"], str(user.id))

    def test_local_backend_is_not_federation_aware(self):
        from rest_framework_simplejwt.state import token_backend

        self.assertFalse(hasattr(token_backend, "federation_providers"))


class TestFederatedAuthentication(FederationSettingsMixin, TestCase):
    def setUp(self):
        super().setUp()
        User.objects.create_user(username="company:shared@example.com")
        User.objects.create_user(username="partner:shared@example.com")

    def test_identity_authentication_does_not_grant_application_access(self):
        principal, token = self.authenticate(company_token())
        self.assertIsInstance(principal, FederatedPrincipal)
        self.assertEqual(principal.id, "company:shared@example.com")
        self.assertEqual(token.purpose, "company-portal")
        self.assertEqual(token.applications, ())
        # Authenticated identity has no permissions unless a local user is
        # linked, and even then application access is a downstream check.
        self.assertFalse(principal.has_perm("billing.view"))
        self.assertFalse(principal.is_staff)

    def test_claim_cannot_escalate_principal(self):
        principal, _ = self.authenticate(
            company_token(extra={"is_staff": True, "is_superuser": True})
        )
        self.assertFalse(principal.is_staff)
        self.assertFalse(principal.is_superuser)

    def test_linked_local_user_permissions_come_from_user_model(self):
        principal, _ = self.authenticate(company_token())
        self.assertEqual(principal.id, "company:shared@example.com")
        self.assertFalse(principal.has_perm("billing.view"))

    def test_inactive_linked_user_is_rejected(self):
        user = User.objects.get(username="company:shared@example.com")
        user.is_active = False
        user.save()
        with pytest.raises(AuthenticationFailed):
            self.authenticate(company_token())

    def test_unknown_issuer_is_not_authenticated(self):
        token = encode(issuer="https://unknown.example", audience=COMPANY_AUDIENCE)
        with pytest.raises(AuthenticationFailed):
            self.authenticate(token)


class TestFederatedHTTPFlows(FederationSettingsMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.client = APIClient()
        User.objects.create_user(username="company:shared@example.com")
        User.objects.create_user(username="partner:shared@example.com")

    def bearer(self, token: str) -> str:
        return f"Bearer {token}"

    def test_verify_reports_identity_not_authorization(self):
        token = company_token(applications=["company-crm"])
        response = self.client.post(
            "/federation/verify/", data={"token": token}, format="json"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["provider"], "company")
        self.assertEqual(response.data["purpose"], "company-portal")
        self.assertEqual(response.data["applications"], ["billing"])
        # Verification does not decide business authorization.
        self.assertEqual(response.data["authorization"], "not_evaluated")

    def test_verify_and_normal_auth_agree_on_identity_but_not_authorization(self):
        token = company_token(applications=["company-crm"])

        verify = self.client.post(
            "/federation/verify/", data={"token": token}, format="json"
        )
        identity = self.client.get(
            "/federation/identity/", HTTP_AUTHORIZATION=self.bearer(token)
        )

        self.assertEqual(verify.status_code, 200)
        self.assertEqual(identity.status_code, 200)
        self.assertEqual(verify.data["subject"], SHARED_SUBJECT)
        self.assertEqual(identity.data["identity"], "company:shared@example.com")
        self.assertEqual(identity.data["token_kind"], "federated")

    def test_purpose_restricted_auth_accepts_only_its_provider(self):
        company = self.client.get(
            "/federation/company-portal/",
            HTTP_AUTHORIZATION=self.bearer(company_token()),
        )
        partner = self.client.get(
            "/federation/company-portal/",
            HTTP_AUTHORIZATION=self.bearer(partner_token()),
        )

        self.assertEqual(company.status_code, 200)
        self.assertEqual(company.data["purpose"], "company-portal")
        self.assertEqual(partner.status_code, 401)

    def test_normal_auth_succeeds_and_mapped_application_request_allows(self):
        # company token only maps to billing, not support.
        token = company_token(applications=["company-crm"])

        identity = self.client.get(
            "/federation/identity/", HTTP_AUTHORIZATION=self.bearer(token)
        )
        billing = self.client.get(
            "/federation/billing/", HTTP_AUTHORIZATION=self.bearer(token)
        )
        self.assertEqual(identity.status_code, 200)
        self.assertEqual(billing.status_code, 200)

    def test_application_bound_request_denies_unmapped_application(self):
        # company token approved for identity but not for billing application.
        token = company_token()
        identity = self.client.get(
            "/federation/identity/", HTTP_AUTHORIZATION=self.bearer(token)
        )
        billing = self.client.get(
            "/federation/billing/", HTTP_AUTHORIZATION=self.bearer(token)
        )

        self.assertEqual(identity.status_code, 200)
        self.assertEqual(billing.status_code, 403)

    def test_same_subject_from_other_provider_is_a_different_principal(self):
        company = self.client.get(
            "/federation/identity/",
            HTTP_AUTHORIZATION=self.bearer(company_token()),
        )
        partner = self.client.get(
            "/federation/identity/",
            HTTP_AUTHORIZATION=self.bearer(partner_token()),
        )

        self.assertEqual(company.status_code, 200)
        self.assertEqual(partner.status_code, 200)
        self.assertEqual(company.data["provider"], "company")
        self.assertEqual(partner.data["provider"], "partner")
        self.assertNotEqual(company.data["identity"], partner.data["identity"])

    def test_application_mapping_is_provider_scoped(self):
        # Partner token names the partner's external application, which maps to
        # "support"; it cannot claim company's billing mapping.
        partner = self.client.get(
            "/federation/billing/",
            HTTP_AUTHORIZATION=self.bearer(
                partner_token(applications=["partner-crm"])
            ),
        )
        self.assertEqual(partner.status_code, 403)

    def test_local_token_still_authenticates_on_composed_view(self):
        user = User.objects.create_user(username="local-user")
        token = AccessToken.for_user(user)

        response = self.client.get(
            "/federation/local-or-federated/",
            HTTP_AUTHORIZATION=self.bearer(str(token)),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["token_kind"], "local")
        self.assertEqual(response.data["identity"], str(user.id))

    def test_local_token_cannot_bypass_application_permission(self):
        user = User.objects.create_user(username="local-user")
        token = AccessToken.for_user(user)

        response = self.client.get(
            "/federation/billing/", HTTP_AUTHORIZATION=self.bearer(str(token))
        )

        self.assertEqual(response.status_code, 403)

    def test_invalid_signature_is_401_on_normal_auth(self):
        token = company_token(private_key=PRIVATE_KEY_2)
        response = self.client.get(
            "/federation/identity/", HTTP_AUTHORIZATION=self.bearer(token)
        )
        self.assertEqual(response.status_code, 401)

    def test_local_verify_endpoint_does_not_accept_foreign_tokens(self):
        response = self.client.post(
            "/token/verify/", data={"token": company_token()}, format="json"
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["code"], "token_not_valid")

    def test_local_only_view_does_not_accept_foreign_tokens(self):
        response = self.client.get(
            "/test-view/", HTTP_AUTHORIZATION=self.bearer(company_token())
        )
        self.assertEqual(response.status_code, 401)

    def test_unknown_issuer_is_401_on_verify(self):
        token = encode(issuer="https://unknown.example", audience=COMPANY_AUDIENCE)
        response = self.client.post(
            "/federation/verify/", data={"token": token}, format="json"
        )
        self.assertEqual(response.status_code, 401)
