"""Tenant-attribution review: which provider fields can gate federated login.

Local, reproducible fixtures for two fake organizations:

- Contoso Ltd   -> Azure AD tenant ``CONTOSO_TENANT_ID`` (azuread-tenant-oauth2)
- Fabrikam Inc  -> Okta org whose users carry a ``groups`` claim (okta-oauth2)

The migration cases use ``azuread-v2-tenant-oauth2`` (ID_KEY ``sub``, legacy
key ``preferred_username``) with one migratable legacy record and one record
whose evidence is insufficient once unverified migration is disabled.
"""

from __future__ import annotations

from unittest import TestCase

from social_core.backends.azuread_tenant import (
    AzureADTenantOAuth2,
    AzureADV2TenantOAuth2,
)
from social_core.backends.google import GoogleOAuth2
from social_core.backends.okta import OktaOAuth2
from social_core.exceptions import (
    AuthAssociationError,
    AuthPolicyError,
    AuthResponseError,
)
from social_core.pipeline.social_auth import auth_allowed, social_uid, social_user
from social_core.tests.models import TestStorage, TestUserSocialAuth, User
from social_core.tests.strategy import TestStrategy

CONTOSO_TENANT_ID = "11111111-1111-1111-1111-111111111111"
FABRIKAM_TENANT_ID = "22222222-2222-2222-2222-222222222222"


class AzureTenantClaimTest(TestCase):
    """The signed ``tid`` claim is the strongest tenant signal: it is checked
    during token validation, before any pipeline step runs."""

    def setUp(self) -> None:
        self.strategy = TestStrategy(TestStorage)
        self.strategy.set_settings(
            {"SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_TENANT_ID": CONTOSO_TENANT_ID}
        )
        self.backend = AzureADTenantOAuth2(self.strategy)

    def test_configured_tenant_token_is_accepted(self) -> None:
        self.backend.validate_configured_tenant({"tid": CONTOSO_TENANT_ID})

    def test_other_tenant_token_is_rejected(self) -> None:
        with self.assertRaises(AuthResponseError) as caught:
            self.backend.validate_configured_tenant({"tid": FABRIKAM_TENANT_ID})
        self.assertEqual(caught.exception.code, "invalid_claim")
        self.assertEqual(caught.exception.claim, "tid")
        self.assertEqual(caught.exception.stage, "token_validation")

    def test_missing_tid_is_rejected(self) -> None:
        with self.assertRaises(AuthResponseError) as caught:
            self.backend.validate_configured_tenant({})
        self.assertEqual(caught.exception.code, "missing_claim")

    def test_non_uuid_tenant_setting_skips_enforcement(self) -> None:
        # "common"/"organizations"/"consumers" are valid TENANT_ID values but
        # carry no tenant guarantee; only a UUID tenant id is enforced.
        self.strategy.set_settings(
            {"SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_TENANT_ID": "common"}
        )
        backend = AzureADTenantOAuth2(self.strategy)
        backend.validate_configured_tenant({})
        backend.validate_configured_tenant({"tid": FABRIKAM_TENANT_ID})


class OktaGroupClaimTest(TestCase):
    """A configured ``groups`` claim plus ``ALLOW_GROUPS`` gates membership at
    the pipeline ``auth_allowed`` step and fails closed."""

    def setUp(self) -> None:
        self.strategy = TestStrategy(TestStorage)
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_OKTA_OAUTH2_GROUPS_KEY": "groups",
                "SOCIAL_AUTH_OKTA_OAUTH2_ALLOW_GROUPS": ["contoso-employees"],
            }
        )
        self.backend = OktaOAuth2(self.strategy)

    def test_member_of_contoso_group_is_allowed(self) -> None:
        response = {"sub": "okta-1", "groups": ["contoso-employees", "everyone"]}
        self.assertTrue(self.backend.auth_allowed(response, {}))
        self.assertIsNone(auth_allowed(self.backend, {}, response))

    def test_fabrikam_only_user_is_denied_by_pipeline(self) -> None:
        response = {"sub": "okta-2", "groups": ["fabrikam-contractors"]}
        self.assertFalse(self.backend.auth_allowed(response, {}))
        with self.assertRaises(AuthPolicyError) as caught:
            auth_allowed(self.backend, {}, response)
        self.assertEqual(caught.exception.code, "authentication_disallowed")

    def test_missing_groups_claim_fails_closed(self) -> None:
        with self.assertRaises(AuthResponseError) as caught:
            auth_allowed(self.backend, {}, {"sub": "okta-3"})
        self.assertEqual(caught.exception.code, "missing_claim")
        self.assertEqual(caught.exception.claim, "groups")

    def test_overage_groups_claim_is_not_authoritative(self) -> None:
        response = {
            "sub": "okta-4",
            "groups": ["contoso-employees"],
            "_claim_names": {"groups": "src1"},
        }
        with self.assertRaises(AuthResponseError) as caught:
            auth_allowed(self.backend, {}, response)
        self.assertEqual(caught.exception.code, "invalid_claim")


class EmailDomainAllowlistTest(TestCase):
    """``WHITELISTED_DOMAINS`` is the weakest signal: it trusts the provider's
    email claim, so it is only as strong as that provider's verification."""

    def setUp(self) -> None:
        self.strategy = TestStrategy(TestStorage)
        self.strategy.set_settings(
            {"SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS": ["contoso.example"]}
        )
        self.backend = GoogleOAuth2(self.strategy)

    def test_contoso_email_is_allowed(self) -> None:
        self.assertTrue(self.backend.auth_allowed({}, {"email": "ada@contoso.example"}))

    def test_other_domain_and_missing_email_are_denied(self) -> None:
        self.assertFalse(
            self.backend.auth_allowed({}, {"email": "ada@fabrikam.example"})
        )
        self.assertFalse(self.backend.auth_allowed({}, {}))


class LegacyAssociationMigrationTest(TestCase):
    """Existing users migrate smoothly only when the stored row carries
    evidence of the new stable identifier (``sub`` in ``extra_data``)."""

    def setUp(self) -> None:
        User.reset_cache()
        TestUserSocialAuth.reset_cache()
        self.strategy = TestStrategy(TestStorage)
        # Company hardening: never migrate on an unverified legacy identifier.
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_AZUREAD_V2_TENANT_OAUTH2_TENANT_ID": CONTOSO_TENANT_ID,
                "SOCIAL_AUTH_AZUREAD_V2_TENANT_OAUTH2_ALLOW_UNVERIFIED_LEGACY_UID_MIGRATION": False,
            }
        )
        self.backend = AzureADV2TenantOAuth2(self.strategy)
        self.user = User("ada", email="ada@contoso.example")
        self.response = {
            "sub": "contoso-sub-001",
            "preferred_username": "ada@contoso.example",
        }

    def identifiers(self):
        return social_uid(self.backend, {}, self.response)

    def legacy_row(self, extra_data):
        return TestUserSocialAuth(
            self.user,
            "azuread-v2-tenant-oauth2",
            "ada@contoso.example",
            extra_data=extra_data,
            id_key="preferred_username",
        )

    def test_row_with_stored_sub_evidence_migrates(self) -> None:
        legacy = self.legacy_row({"sub": "contoso-sub-001"})
        result = social_user(self.backend, **self.identifiers())
        self.assertIs(result["social"], legacy)
        self.assertFalse(result["is_new"])
        self.assertEqual((legacy.uid, legacy.id_key), ("contoso-sub-001", "sub"))

    def test_row_without_evidence_is_refused(self) -> None:
        legacy = self.legacy_row({})
        with self.assertRaises(AuthAssociationError) as caught:
            social_user(self.backend, **self.identifiers())
        self.assertEqual(caught.exception.code, "identifier_migration_conflict")
        # The unverifiable row is left untouched for account recovery.
        self.assertEqual(
            (legacy.uid, legacy.id_key), ("ada@contoso.example", "preferred_username")
        )

    def test_conflicting_evidence_is_refused(self) -> None:
        legacy = self.legacy_row({"sub": "someone-else"})
        with self.assertRaises(AuthAssociationError) as caught:
            social_user(self.backend, **self.identifiers())
        self.assertEqual(caught.exception.code, "identifier_migration_conflict")
        self.assertEqual(legacy.uid, "ada@contoso.example")

    def test_default_policy_still_allows_audited_transition(self) -> None:
        # Without the explicit opt-out, azuread-v2-tenant-oauth2 is on the
        # audited UNVERIFIED_LEGACY_TRANSITIONS list and migrates unkeyed
        # historical rows with a warning. The company opt-out above is what
        # turns "insufficient evidence" into a hard stop.
        strategy = TestStrategy(TestStorage)
        backend = AzureADV2TenantOAuth2(strategy)
        legacy = TestUserSocialAuth(
            self.user,
            "azuread-v2-tenant-oauth2",
            "ada@contoso.example",
            extra_data={},
            id_key="",
        )
        result = social_user(backend, **self.identifiers())
        self.assertIs(result["social"], legacy)
        self.assertEqual((legacy.uid, legacy.id_key), ("contoso-sub-001", "sub"))
