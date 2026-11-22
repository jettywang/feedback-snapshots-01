from __future__ import annotations

from unittest import TestCase
from unittest.mock import Mock, patch

from social_core.backends.azuread import AzureADOAuth2
from social_core.backends.base import BaseAuth
from social_core.backends.cas import CASOpenIdConnectAuth
from social_core.backends.discourse import DiscourseAuth
from social_core.backends.keycloak import KeycloakOAuth2
from social_core.backends.okta import OktaOAuth2
from social_core.backends.okta_openidconnect import OktaOpenIdConnect
from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.exceptions import AuthConfigurationError, AuthResponseError
from social_core.groups import (
    GroupGrant,
    group_sync_targets,
    normalize_group_grants,
    plan_group_sync,
)
from social_core.pipeline.social_auth import social_details
from social_core.pipeline.user import sync_groups
from social_core.pipeline.utils import partial_prepare
from social_core.tests.models import (
    TestGroupGrant,
    TestGroupGrantStorage,
    TestStorage,
    TestUserSocialAuth,
    User,
)
from social_core.tests.strategy import TestStrategy


class GroupsTest(TestCase):
    def setUp(self) -> None:
        self.strategy = TestStrategy(TestStorage)
        self.backend = KeycloakOAuth2(self.strategy)
        User.reset_cache()
        TestUserSocialAuth.reset_cache()
        TestGroupGrantStorage.reset_cache()
        self.addCleanup(User.reset_cache)
        self.addCleanup(TestUserSocialAuth.reset_cache)
        self.addCleanup(TestGroupGrantStorage.reset_cache)

    def configure(self, **kwargs) -> None:
        self.strategy.set_settings(
            {f"SOCIAL_AUTH_KEYCLOAK_{key}": value for key, value in kwargs.items()}
        )

    def test_extraction_is_opt_in(self) -> None:
        self.assertIsNone(self.backend.get_user_groups({"groups": ["admin"]}))
        self.configure(GROUPS_KEY="groups")
        self.assertEqual(
            self.backend.get_user_groups({"groups": ["a", "a", "b"]}), ["a", "b"]
        )
        self.assertEqual(self.backend.get_user_groups({"groups": []}), [])

    def test_okta_oauth2_extraction_and_validation(self) -> None:
        value: object
        backend = OktaOAuth2(self.strategy)
        self.assertIsNone(backend.get_user_groups({"groups": ["a"]}))
        self.strategy.set_settings({"SOCIAL_AUTH_OKTA_OAUTH2_GROUPS_KEY": "teams"})
        self.assertEqual(
            backend.get_user_groups({"teams": ["a", "a", "b"]}), ["a", "b"]
        )
        self.assertEqual(backend.get_user_groups({"teams": []}), [])
        with self.assertRaises(AuthResponseError) as caught:
            backend.get_user_groups({"groups": ["a"]})
        self.assertEqual(caught.exception.code, "missing_claim")
        self.strategy.set_settings(
            {"SOCIAL_AUTH_OKTA_OAUTH2_GROUPS_MISSING_AS_EMPTY": True}
        )
        self.assertEqual(backend.get_user_groups({}), [])
        for value in (None, "a", {}, [1], [""], ["a", None]):
            with self.subTest(value=value), self.assertRaises(AuthResponseError):
                backend.get_user_groups({"teams": value})

    def test_okta_oauth2_groups_reach_sync_step(self) -> None:
        backend = OktaOAuth2(self.strategy)
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_OKTA_OAUTH2_GROUPS_KEY": "groups",
                "SOCIAL_AUTH_OKTA_OAUTH2_GROUPS_MAP": {"a": ["A"], "b": ["B"]},
            }
        )
        response = {"sub": "user", "groups": ["a", "unknown"]}
        result = social_details(backend, {}, response)
        self.assertEqual(
            group_sync_targets(backend, result["groups"], response), ({"A"}, {"A", "B"})
        )
        strategy = Mock()
        user = Mock()
        sync_groups(strategy, backend, response, user=user, **result)
        strategy.sync_user_groups.assert_called_once_with(
            user,
            ["a", "unknown"],
            backend=backend,
            response=response,
            details=result["details"],
        )

    def test_okta_openidconnect_preserves_token_precedence_and_subject_check(
        self,
    ) -> None:
        backend = OktaOpenIdConnect(self.strategy)
        self.strategy.set_settings(
            {"SOCIAL_AUTH_OKTA_OPENIDCONNECT_GROUPS_KEY": "groups"}
        )
        backend.id_token = {"sub": "user", "groups": []}
        self.assertEqual(backend.get_user_groups({"sub": "user", "groups": ["a"]}), [])
        backend.id_token = {"sub": "user"}
        self.assertEqual(
            backend.get_user_groups({"sub": "user", "groups": ["a"]}), ["a"]
        )
        for response in ({"groups": ["a"]}, {"sub": "other", "groups": ["a"]}):
            with self.subTest(response=response), self.assertRaises(AuthResponseError):
                backend.get_user_groups(response)

    def test_okta_group_scope_preserves_defaults(self) -> None:
        for backend_class, prefix in (
            (OktaOAuth2, "OKTA_OAUTH2"),
            (OktaOpenIdConnect, "OKTA_OPENIDCONNECT"),
        ):
            with self.subTest(backend=prefix):
                self.strategy.set_settings({f"SOCIAL_AUTH_{prefix}_SCOPE": ["groups"]})
                backend = backend_class(self.strategy)
                self.assertEqual(
                    backend.get_scope_argument(),
                    {"scope": "groups openid profile email"},
                )

    def test_missing_and_malformed_claims(self) -> None:
        value: object
        self.configure(GROUPS_KEY="groups")
        with self.assertRaises(AuthResponseError) as caught:
            self.backend.get_user_groups({})
        self.assertEqual(caught.exception.code, "missing_claim")
        self.configure(GROUPS_MISSING_AS_EMPTY=True)
        self.assertEqual(self.backend.get_user_groups({}), [])
        for value in (None, "admin", {}, [1], [""], ["admin", None]):
            with self.subTest(value=value), self.assertRaises(AuthResponseError):
                self.backend.get_user_groups({"groups": value})

    def test_invalid_claim_selection_and_missing_policy_are_configuration_errors(
        self,
    ) -> None:
        key: object
        for key in ("", [], 1):
            self.configure(GROUPS_KEY=key)
            with self.subTest(key=key), self.assertRaises(AuthConfigurationError):
                self.backend.get_user_groups({})
        self.configure(GROUPS_KEY="groups", GROUPS_MISSING_AS_EMPTY="false")
        with self.assertRaises(AuthConfigurationError):
            self.backend.get_user_groups({})

    def test_allow_list_and_email_policy(self) -> None:
        self.configure(
            GROUPS_KEY="groups",
            ALLOW_GROUPS=["a", "b"],
            WHITELISTED_DOMAINS=["example.com"],
        )
        self.assertTrue(
            self.backend.auth_allowed({"groups": ["b"]}, {"email": "user@example.com"})
        )
        self.assertFalse(
            self.backend.auth_allowed({"groups": []}, {"email": "user@example.com"})
        )
        self.assertFalse(
            self.backend.auth_allowed(
                {"groups": ["a"]}, {"email": "user@elsewhere.com"}
            )
        )
        self.configure(GROUPS_KEY=None)
        with self.assertRaises(AuthConfigurationError):
            self.backend.auth_allowed({}, {})

    def test_cas_legacy_allow_list(self) -> None:
        backend = CASOpenIdConnectAuth(self.strategy)
        self.strategy.set_settings({"SOCIAL_AUTH_CAS_ALLOW_GROUPS": ["users"]})
        self.assertTrue(backend.auth_allowed({"groups": ["users"]}, {}))
        self.assertFalse(backend.auth_allowed({}, {}))
        self.assertEqual(backend.get_user_groups({}), [])

    def test_invalid_allow_list_is_a_configuration_error(self) -> None:
        value: object
        self.configure(GROUPS_KEY="groups")
        for value in (None, "admin", {}, [1], [""]):
            self.configure(ALLOW_GROUPS=value)
            with (
                self.subTest(value=value),
                self.assertRaises(AuthConfigurationError) as caught,
            ):
                self.backend.auth_allowed({"groups": ["admin"]}, {})
            self.assertEqual(caught.exception.code, "invalid_setting")
            self.assertEqual(caught.exception.parameter, "ALLOW_GROUPS")

    def test_cas_extraction_requires_group_handling(self) -> None:
        backend = CASOpenIdConnectAuth(self.strategy)
        response = {"groups": "users"}
        self.assertIsNone(backend.get_user_groups(response))
        self.assertTrue(backend.auth_allowed(response, {}))
        for setting, value in (
            ("ALLOW_GROUPS", ["users"]),
            ("GROUPS_MAP", {"users": ["Users"]}),
            ("GROUPS_ENABLED", True),
        ):
            self.strategy.set_settings(
                {
                    "SOCIAL_AUTH_CAS_ALLOW_GROUPS": [],
                    "SOCIAL_AUTH_CAS_GROUPS_MAP": {},
                    "SOCIAL_AUTH_CAS_GROUPS_ENABLED": False,
                    f"SOCIAL_AUTH_CAS_{setting}": value,
                }
            )
            with self.subTest(setting=setting):
                self.assertEqual(
                    backend.get_user_groups({"groups": ["users"]}), ["users"]
                )
                with self.assertRaises(AuthResponseError):
                    backend.get_user_groups(response)

    def test_azure_roles_ignore_group_overage(self) -> None:
        backend = AzureADOAuth2(self.strategy)
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_AZUREAD_OAUTH2_GROUPS_KEY": "groups",
                "SOCIAL_AUTH_AZUREAD_OAUTH2_GROUPS_MISSING_AS_EMPTY": True,
            }
        )
        for response in (
            {"hasgroups": True},
            {"_claim_names": {"groups": "src1"}},
            {"groups": ["partial"], "hasgroups": True},
        ):
            with self.subTest(response=response), self.assertRaises(AuthResponseError):
                backend.get_user_groups(response)
        self.strategy.set_settings({"SOCIAL_AUTH_AZUREAD_OAUTH2_GROUPS_KEY": "roles"})
        self.assertEqual(
            backend.get_user_groups({"hasgroups": True, "roles": ["reviewer"]}),
            ["reviewer"],
        )

    def test_oidc_overage_never_falls_back_to_userinfo(self) -> None:
        backend = OpenIdConnectAuth(self.strategy)
        self.strategy.set_settings({"SOCIAL_AUTH_OIDC_GROUPS_KEY": "groups"})
        backend.id_token = {"sub": "user", "_claim_names": {"groups": "src"}}
        with self.assertRaises(AuthResponseError):
            backend.get_user_groups({"sub": "user", "groups": ["partial"]})

    def test_malformed_overage_metadata_is_not_an_empty_membership_list(self) -> None:
        value: object
        self.configure(GROUPS_KEY="groups", GROUPS_MISSING_AS_EMPTY=True)
        for value in (None, "groups", []):
            with (
                self.subTest(value=value),
                self.assertRaises(AuthResponseError) as caught,
            ):
                self.backend.get_user_groups({"_claim_names": value})
            self.assertEqual(caught.exception.code, "invalid_claim")
            self.assertEqual(caught.exception.claim, "_claim_names")

    def test_oidc_userinfo_overage_prevents_synchronization(self) -> None:
        backend = OpenIdConnectAuth(self.strategy)
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_OIDC_GROUPS_KEY": "groups",
                "SOCIAL_AUTH_OIDC_GROUPS_MISSING_AS_EMPTY": True,
            }
        )
        backend.id_token = {"sub": "user"}
        for indicator in ({"hasgroups": True}, {"_claim_names": {"groups": "src"}}):
            with (
                self.subTest(indicator=indicator),
                patch.object(self.strategy, "sync_user_groups") as synchronize,
            ):
                with self.assertRaises(AuthResponseError) as caught:
                    backend.run_pipeline(
                        [
                            "social_core.pipeline.social_auth.social_details",
                            "social_core.pipeline.user.sync_groups",
                        ],
                        details={},
                        response={"sub": "user", **indicator},
                        user=Mock(),
                    )
                self.assertEqual(caught.exception.code, "invalid_claim")
                synchronize.assert_not_called()
        self.assertEqual(backend.get_user_groups({"sub": "user"}), [])
        backend.id_token = {"sub": "user", "groups": []}
        self.assertEqual(
            backend.get_user_groups({"sub": "user", "hasgroups": True}), []
        )

    def test_oidc_precedence_and_userinfo_subject(self) -> None:
        backend = OpenIdConnectAuth(self.strategy)
        self.strategy.set_settings({"SOCIAL_AUTH_OIDC_GROUPS_KEY": "groups"})
        backend.id_token = {"sub": "user", "groups": []}
        self.assertEqual(backend.get_user_groups({"sub": "user", "groups": ["a"]}), [])
        backend.id_token = {"sub": "user"}
        self.assertEqual(
            backend.get_user_groups({"sub": "user", "groups": ["a"]}), ["a"]
        )
        for response in ({"groups": ["a"]}, {"sub": "other", "groups": ["a"]}):
            with self.subTest(response=response), self.assertRaises(AuthResponseError):
                backend.get_user_groups(response)

    def test_groups_are_separate_and_survive_partial_resume(self) -> None:
        self.configure(GROUPS_KEY="groups")
        response = {"preferred_username": "user", "groups": ["a"]}
        result = social_details(self.backend, {}, response)
        self.assertNotIn("groups", result["details"])
        self.assertEqual(result["groups"], ["a"])
        partial = partial_prepare(
            self.strategy, self.backend, 1, response=response, **result
        )
        self.assertEqual(partial.data["kwargs"]["groups"], ["a"])

    def test_mapping_targets_and_disabled_extraction(self) -> None:
        self.configure(GROUPS_MAP={"a": ["A", "Shared"], "b": ["B", "Shared"]})
        self.assertEqual(
            group_sync_targets(self.backend, ["a", "unknown"], {}),
            ({"A", "Shared"}, {"A", "B", "Shared"}),
        )
        self.assertEqual(group_sync_targets(self.backend, [], {})[0], set())
        with self.assertRaises(AuthConfigurationError):
            group_sync_targets(self.backend, None, {})

    def test_unconfigured_mapping_does_not_require_extraction_or_strategy_support(
        self,
    ) -> None:
        self.assertEqual(group_sync_targets(self.backend, None, {}), (set(), set()))
        self.strategy.sync_user_groups(Mock(), None, backend=self.backend, response={})

    def test_invalid_mapping_and_competing_ownership(self) -> None:
        mapping: object
        for mapping in (None, [], {"a": "A"}, {"": ["A"]}, {"a": [True]}):
            with (
                self.subTest(mapping=mapping),
                self.assertRaises(AuthConfigurationError),
            ):
                self.configure(GROUPS_MAP=mapping)
                group_sync_targets(self.backend, [], {})
        self.configure(GROUPS_MAP={"a": ["A"]})
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_AUTHENTICATION_BACKENDS": [
                    "social_core.backends.gitlab.GitLabOAuth2"
                ],
                "SOCIAL_AUTH_GITLAB_GROUPS_MAP": {"b": ["A"]},
            }
        )
        with self.assertRaises(AuthConfigurationError):
            group_sync_targets(self.backend, ["a"], {})

    def test_sync_step_and_unsupported_strategy(self) -> None:
        strategy = Mock()
        user = Mock()
        sync_groups(strategy, self.backend, {}, user=user, groups=["a"], action="login")
        strategy.sync_user_groups.assert_called_once_with(
            user, ["a"], backend=self.backend, response={}, action="login"
        )
        strategy.reset_mock()
        sync_groups(strategy, self.backend, {}, user=None, groups=["a"])
        with patch.object(self.backend, "ASSOCIATION_ONLY", True):
            sync_groups(strategy, self.backend, {}, user=user, groups=["a"])
        strategy.sync_user_groups.assert_not_called()
        self.configure(GROUPS_MAP={"a": ["A"]})
        with self.assertRaises(AuthConfigurationError):
            self.strategy.sync_user_groups(
                user, ["a"], backend=self.backend, response={}
            )

    def test_discourse_groups_leave_details(self) -> None:
        backend = DiscourseAuth(self.strategy)
        response = {"groups": "translators,reviewers"}
        self.assertNotIn("groups", backend.get_user_details(response))
        self.assertIsNone(backend.get_user_groups(response))
        self.strategy.set_settings({"SOCIAL_AUTH_DISCOURSE_GROUPS_ENABLED": True})
        self.assertEqual(
            backend.get_user_groups(response), ["translators", "reviewers"]
        )
        self.assertEqual(backend.get_user_groups({"groups": ""}), [])

    def test_base_backend_does_not_extract_groups(self) -> None:
        self.assertIsNone(BaseAuth(self.strategy).get_user_groups({"groups": ["a"]}))


class ManagedGroupSyncTest(TestCase):
    """Provider sync removes only the grants its own source recorded."""

    def setUp(self) -> None:
        User.reset_cache()
        TestUserSocialAuth.reset_cache()
        TestGroupGrantStorage.reset_cache()
        self.addCleanup(User.reset_cache)
        self.addCleanup(TestUserSocialAuth.reset_cache)
        self.addCleanup(TestGroupGrantStorage.reset_cache)
        self.strategy = TestStrategy(TestStorage)
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_AUTHENTICATION_BACKENDS": [
                    "social_core.backends.keycloak.KeycloakOAuth2",
                    "social_core.backends.okta.OktaOAuth2",
                ],
                "SOCIAL_AUTH_KEYCLOAK_GROUPS_KEY": "groups",
                "SOCIAL_AUTH_KEYCLOAK_GROUPS_MAP": {
                    "reviewers": ["Reviewers", "Shared"],
                    "translators": ["Translators"],
                },
                "SOCIAL_AUTH_KEYCLOAK_GROUPS_SYNC_MODE": "managed",
                "SOCIAL_AUTH_KEYCLOAK_GROUPS_COMPLETE": True,
                "SOCIAL_AUTH_OKTA_OAUTH2_GROUPS_KEY": "groups",
                "SOCIAL_AUTH_OKTA_OAUTH2_GROUPS_MAP": {
                    "reviewers": ["Shared"],
                    "operators": ["Operators"],
                },
                "SOCIAL_AUTH_OKTA_OAUTH2_GROUPS_SYNC_MODE": "managed",
                "SOCIAL_AUTH_OKTA_OAUTH2_GROUPS_COMPLETE": True,
            }
        )
        self.keycloak = KeycloakOAuth2(self.strategy)
        self.okta = OktaOAuth2(self.strategy)
        self.user = User("managed")

    def sync(self, backend, groups: list[str]):
        return self.strategy.sync_user_groups(
            self.user, groups, backend=backend, response={"groups": groups}
        )

    def grants(self) -> set[tuple[str | int, str | None, str | None]]:
        return {
            (grant.target, grant.provider, grant.source)
            for grant in TestGroupGrantStorage.get_group_grants(self.user)
        }

    def test_local_assignment_and_unrelated_provider_grants_survive(self) -> None:
        TestGroupGrantStorage.assign_local(self.user, "SiteAdmins")
        self.sync(self.keycloak, ["reviewers", "translators"])
        self.assertEqual(
            TestGroupGrantStorage.local_groups(self.user),
            {"SiteAdmins", "Reviewers", "Shared", "Translators"},
        )
        self.sync(self.keycloak, ["reviewers"])
        self.assertEqual(
            TestGroupGrantStorage.local_groups(self.user),
            {"SiteAdmins", "Reviewers", "Shared"},
        )
        self.assertEqual(
            self.grants(),
            {
                ("Reviewers", "keycloak", ""),
                ("Shared", "keycloak", ""),
            },
        )

    def test_same_named_group_keeps_other_providers_membership(self) -> None:
        self.sync(self.keycloak, ["reviewers"])
        self.sync(self.okta, ["reviewers", "operators"])
        self.assertEqual(
            self.grants(),
            {
                ("Reviewers", "keycloak", ""),
                ("Shared", "keycloak", ""),
                ("Shared", "okta-oauth2", ""),
                ("Operators", "okta-oauth2", ""),
            },
        )
        # Keycloak stops reporting the shared group; Okta still grants it.
        self.sync(self.keycloak, [])
        self.assertEqual(
            TestGroupGrantStorage.local_groups(self.user),
            {"Shared", "Operators"},
        )
        self.assertEqual(
            self.grants(),
            {
                ("Shared", "okta-oauth2", ""),
                ("Operators", "okta-oauth2", ""),
            },
        )

    def test_same_provider_sources_are_independent(self) -> None:
        class TwoSourceBackend(BaseAuth):
            name = "two-source"

            def get_group_setting(self, name, response, default=None):
                if name == "GROUPS_MAP":
                    return {"reviewers": ["Shared"], "operators": ["Operators"]}
                if name == "GROUPS_SYNC_MODE":
                    return "managed"
                return default

            def get_group_source(self, response) -> str:
                return response["source"]

            def get_group_complete(self, response) -> bool:
                return True

        backend = TwoSourceBackend(self.strategy)
        first = {"source": "idp-first"}
        second = {"source": "idp-second"}
        self.strategy.sync_user_groups(
            self.user, ["reviewers"], backend=backend, response=first
        )
        self.strategy.sync_user_groups(
            self.user, ["reviewers", "operators"], backend=backend, response=second
        )
        self.assertEqual(
            self.grants(),
            {
                ("Shared", "two-source", "idp-first"),
                ("Shared", "two-source", "idp-second"),
                ("Operators", "two-source", "idp-second"),
            },
        )
        self.strategy.sync_user_groups(self.user, [], backend=backend, response=first)
        self.assertEqual(
            TestGroupGrantStorage.local_groups(self.user), {"Shared", "Operators"}
        )

    def test_admin_assignment_to_a_synced_group_is_independent(self) -> None:
        TestGroupGrantStorage.assign_local(self.user, "Reviewers")
        self.sync(self.keycloak, ["reviewers"])
        self.assertEqual(
            TestGroupGrantStorage.local_groups(self.user), {"Reviewers", "Shared"}
        )
        self.sync(self.keycloak, [])
        # The provider grant is gone, but the administrator still assigned it.
        self.assertEqual(TestGroupGrantStorage.local_groups(self.user), {"Reviewers"})
        self.assertEqual(self.grants(), set())

    def test_partial_snapshot_withholds_revocations(self) -> None:
        self.sync(self.keycloak, ["reviewers", "translators"])
        # The claim is known to be truncated, so absence is not a revocation.
        self.strategy.set_settings({"SOCIAL_AUTH_KEYCLOAK_GROUPS_COMPLETE": False})
        with self.assertLogs("social", level="WARNING") as logs:
            self.sync(self.keycloak, ["reviewers"])
        self.assertEqual(
            TestGroupGrantStorage.local_groups(self.user),
            {"Reviewers", "Shared", "Translators"},
        )
        self.assertIn("incomplete group snapshot", logs.output[0])
        self.strategy.set_settings({"SOCIAL_AUTH_KEYCLOAK_GROUPS_COMPLETE": True})
        self.sync(self.keycloak, ["reviewers"])
        self.assertEqual(
            TestGroupGrantStorage.local_groups(self.user), {"Reviewers", "Shared"}
        )

    def test_explicit_revocation_then_readd(self) -> None:
        self.sync(self.okta, ["operators"])
        self.sync(self.okta, [])
        self.assertEqual(TestGroupGrantStorage.local_groups(self.user), set())
        self.assertEqual(self.grants(), set())
        self.sync(self.okta, ["operators"])
        self.assertEqual(TestGroupGrantStorage.local_groups(self.user), {"Operators"})

    def test_legacy_records_are_reported_and_left_alone(self) -> None:
        TestGroupGrantStorage.grants.append(
            TestGroupGrant(self.user, "HistoricallyGranted")
        )
        TestGroupGrantStorage.assign_local(self.user, "SiteAdmins")
        with self.assertLogs("social", level="WARNING") as logs:
            plan = self.sync(self.keycloak, [])
        self.assertIn("have no recorded source", logs.output[0])
        self.assertIsNotNone(plan)
        self.assertEqual(
            plan.unidentified, (GroupGrant("HistoricallyGranted", None, None),)
        )
        self.assertEqual(
            TestGroupGrantStorage.local_groups(self.user),
            {"SiteAdmins", "HistoricallyGranted"},
        )
        self.assertEqual(self.grants(), {("HistoricallyGranted", None, None)})

    def test_legacy_integrations_opt_in_explicitly(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_KEYCLOAK_GROUPS_SYNC_MODE": "legacy"})
        with self.assertRaises(AuthConfigurationError) as caught:
            self.sync(self.keycloak, ["reviewers"])
        self.assertEqual(caught.exception.code, "unsupported_feature")
        self.assertEqual(caught.exception.parameter, "GROUPS_MAP")
        self.assertEqual(TestGroupGrantStorage.local_groups(self.user), set())

    def test_invalid_mode_and_completeness_are_configuration_errors(self) -> None:
        for name, value in (
            ("GROUPS_SYNC_MODE", "automatic"),
            ("GROUPS_SYNC_MODE", True),
            ("GROUPS_COMPLETE", "yes"),
        ):
            self.strategy.set_settings(
                {
                    "SOCIAL_AUTH_KEYCLOAK_GROUPS_SYNC_MODE": "managed",
                    "SOCIAL_AUTH_KEYCLOAK_GROUPS_COMPLETE": True,
                    f"SOCIAL_AUTH_KEYCLOAK_{name}": value,
                }
            )
            with (
                self.subTest(name=name, value=value),
                self.assertRaises(AuthConfigurationError) as caught,
            ):
                self.sync(self.keycloak, ["reviewers"])
            self.assertEqual(caught.exception.code, "invalid_setting")
            self.assertEqual(caught.exception.parameter, name)

    def test_missing_strategy_or_storage_support_is_reported(self) -> None:
        self.strategy.set_settings({"SOCIAL_AUTH_KEYCLOAK_GROUPS_SYNC_MODE": "managed"})

        class PlainStorage(TestStorage):
            groups = type(
                "UnsupportedGroups",
                (),
                {
                    "get_group_grants": classmethod(
                        lambda cls, user: (_ for _ in ()).throw(
                            NotImplementedError("Implement in subclass")
                        )
                    )
                },
            )

        self.strategy._storage = PlainStorage
        with self.assertRaises(AuthConfigurationError) as caught:
            self.sync(self.keycloak, ["reviewers"])
        self.assertEqual(caught.exception.code, "unsupported_feature")
        self.assertEqual(caught.exception.parameter, "group storage")
        self.assertEqual(caught.exception.stage, "pipeline")

    def test_plan_reports_preserved_and_unidentified_grants(self) -> None:
        grants = [
            GroupGrant("Reviewers", "okta-oauth2", ""),
            GroupGrant("Shared", "okta-oauth2", ""),
            GroupGrant("Legacy", None, None),
        ]
        plan = plan_group_sync(self.keycloak, ["reviewers"], {}, grants)
        self.assertEqual(plan.additions, {"Reviewers", "Shared"})
        self.assertEqual(plan.revocations, frozenset())
        self.assertEqual(plan.preserved, ())
        self.assertEqual(plan.unidentified, (GroupGrant("Legacy", None, None),))

    def test_normalize_rejects_malformed_storage_records(self) -> None:
        for record in (
            Mock(target=True, provider="keycloak", source=""),
            Mock(target="", provider="keycloak", source=""),
            Mock(target="A", provider=1, source=""),
            Mock(target="A", provider="keycloak", source=2),
        ):
            with (
                self.subTest(record=record),
                self.assertRaises(AuthConfigurationError),
            ):
                normalize_group_grants(self.keycloak, [record])
