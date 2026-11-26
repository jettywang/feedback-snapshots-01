import base64
import json
import time
from unittest.mock import patch

import msal
from msal.application import ClientApplication
from msal.scope_policy import StrictScopePolicy
from tests import unittest
from tests.http_client import MinimalResponse


CLIENT_ID = "strict-scope-client"
HOME_ACCOUNT_ID = "uid.utid"
TENANT = "audit-tenant"
PRIMARY_ENV = "login.audit.example"
ALIAS_ENV = "alias.audit.example"
AUTHORITY = "https://{}/{}/".format(PRIMARY_ENV, TENANT)

AUDIT_SCOPE = "api://audit.example/Access"
EXTRA_SCOPE = "api://audit.example/ExportAll"
REQUESTED_SCOPES = [AUDIT_SCOPE]

APPROVED_SOURCE = "backend-audit-consent"
OTHER_SOURCE = "legacy-wide-consent"

OIDC_CONFIG = {
    "authorization_endpoint": "{}/oauth2/v2.0/authorize".format(AUTHORITY),
    "token_endpoint": "{}/oauth2/v2.0/token".format(AUTHORITY),
    "issuer": "https://{}/{}/v2.0".format(PRIMARY_ENV, TENANT),
}


class StrictScopePolicyAcceptanceTest(unittest.TestCase):
    def setUp(self):
        discovery = patch(
            "msal.authority.tenant_discovery", return_value=OIDC_CONFIG)
        discovery.start()
        self.addCleanup(discovery.stop)

        self.cache = msal.SerializableTokenCache()
        self.app = ClientApplication(
            CLIENT_ID,
            authority=AUTHORITY,
            token_cache=self.cache,
            instance_discovery=False,
        )
        self.app._get_authority_aliases = lambda instance: (
            [ALIAS_ENV] if instance == PRIMARY_ENV else [])
        self.account = {"home_account_id": HOME_ACCOUNT_ID}
        self.policy = StrictScopePolicy(approved_sources=[APPROVED_SOURCE])

    def add_access_token(
            self, name, *, scopes, source, environment=PRIMARY_ENV, cache=None):
        cache = cache or self.cache
        now = int(time.time())
        entry = {
            "credential_type": msal.TokenCache.CredentialType.ACCESS_TOKEN,
            "home_account_id": HOME_ACCOUNT_ID,
            "environment": environment,
            "client_id": CLIENT_ID,
            "realm": TENANT,
            "target": " ".join(sorted(scopes)),
            "secret": "token-{}".format(name),
            "token_type": "Bearer",
            "cached_at": str(now),
            "expires_on": str(now + 3600),
            "approval_source": source,
        }
        cache.modify(
            msal.TokenCache.CredentialType.ACCESS_TOKEN, entry, entry)
        return entry

    def add_refresh_token(
            self, name="primary-rt", *, environment=PRIMARY_ENV, cache=None):
        cache = cache or self.cache
        now = int(time.time())
        entry = {
            "credential_type": msal.TokenCache.CredentialType.REFRESH_TOKEN,
            "home_account_id": HOME_ACCOUNT_ID,
            "environment": environment,
            "client_id": CLIENT_ID,
            "secret": name,
            "last_modification_time": str(now),
        }
        cache.modify(
            msal.TokenCache.CredentialType.REFRESH_TOKEN, entry, entry)
        return entry

    def fake_post(self, payload):
        calls = []

        def post(url, **kwargs):
            calls.append({"url": url, "data": kwargs.get("data") or {}})
            return MinimalResponse(
                status_code=200, text=json.dumps(payload))

        return post, calls

    def failing_post(self, message="network/post should not be called"):
        def post(url, **kwargs):
            raise AssertionError(message)
        return post

    def refresh_payload(self, *, scopes, source, token="refreshed-token"):
        client_info = base64.b64encode(json.dumps({
            "uid": "uid", "utid": "utid",
        }).encode()).decode("ascii")
        return {
            "access_token": token,
            "refresh_token": "rotated-rt",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": " ".join(sorted(scopes)),
            "approval_source": source,
            "client_info": client_info,
        }

    def test_normal_request_accepts_each_of_the_three_cache_shapes(self):
        fixtures = (
            ("exact", [AUDIT_SCOPE], APPROVED_SOURCE, PRIMARY_ENV),
            ("broad", [AUDIT_SCOPE, EXTRA_SCOPE], APPROVED_SOURCE, PRIMARY_ENV),
            ("other-source-alias", [AUDIT_SCOPE], OTHER_SOURCE, ALIAS_ENV),
        )
        for name, scopes, source, environment in fixtures:
            with self.subTest(cache_entry=name):
                cache = msal.SerializableTokenCache()
                app = ClientApplication(
                    CLIENT_ID, authority=AUTHORITY, token_cache=cache,
                    instance_discovery=False)
                app._get_authority_aliases = lambda instance: (
                    [ALIAS_ENV] if instance == PRIMARY_ENV else [])
                self.add_access_token(
                    name, scopes=scopes, source=source,
                    environment=environment, cache=cache)
                if environment == ALIAS_ENV:
                    # MSAL's alias fast path only enters the heavyweight AT/RT
                    # lookup when that alias also has a refresh token.
                    self.add_refresh_token(
                        "alias-rt", environment=ALIAS_ENV, cache=cache)

                result = app.acquire_token_silent(
                    REQUESTED_SCOPES,
                    self.account,
                    post=self.failing_post(),
                )
                self.assertIsNotNone(result, name)
                self.assertEqual("token-{}".format(name), result["access_token"])
                self.assertEqual("cache", result["token_source"])

    def test_acceptance_matrix_normal_then_strict_with_one_fake_refresh(self):
        fixtures = (
            ("exact", [AUDIT_SCOPE], APPROVED_SOURCE, PRIMARY_ENV, True),
            ("broad", [AUDIT_SCOPE, EXTRA_SCOPE], APPROVED_SOURCE, PRIMARY_ENV, False),
            ("other-source", [AUDIT_SCOPE], OTHER_SOURCE, ALIAS_ENV, False),
        )
        refresh = self.refresh_payload(
            scopes=[AUDIT_SCOPE], source=APPROVED_SOURCE,
            token="fake-refresh-exact")

        for name, scopes, source, environment, strict_cache_hit in fixtures:
            with self.subTest(fixture=name):
                cache = msal.SerializableTokenCache()
                app = ClientApplication(
                    CLIENT_ID, authority=AUTHORITY, token_cache=cache,
                    instance_discovery=False)
                app._get_authority_aliases = lambda instance: (
                    [ALIAS_ENV] if instance == PRIMARY_ENV else [])
                self.add_access_token(
                    name, scopes=scopes, source=source,
                    environment=environment, cache=cache)
                self.add_refresh_token(
                    "rt-{}".format(name), environment=environment, cache=cache)
                post, calls = self.fake_post(refresh)

                normal = app.acquire_token_silent(
                    REQUESTED_SCOPES, self.account, post=self.failing_post())
                strict = app.acquire_token_silent(
                    REQUESTED_SCOPES, self.account,
                    scope_policy=self.policy, post=post)

                self.assertEqual("token-{}".format(name), normal["access_token"])
                self.assertTrue(strict["strict_scope_match"])
                if strict_cache_hit:
                    self.assertEqual("token-exact", strict["access_token"])
                    self.assertEqual("cache", strict["token_source"])
                    self.assertEqual(0, len(calls))
                else:
                    self.assertEqual(
                        "fake-refresh-exact", strict["access_token"])
                    self.assertEqual(
                        "identity_provider", strict["token_source"])
                    self.assertEqual(1, len(calls))

    def test_combined_cache_normal_and_strict_both_choose_exact_approved(self):
        self.add_access_token(
            "exact", scopes=[AUDIT_SCOPE], source=APPROVED_SOURCE)
        self.add_access_token(
            "broad", scopes=[AUDIT_SCOPE, EXTRA_SCOPE],
            source=APPROVED_SOURCE)
        self.add_access_token(
            "alias", scopes=[AUDIT_SCOPE], source=OTHER_SOURCE,
            environment=ALIAS_ENV)

        normal = self.app.acquire_token_silent(
            REQUESTED_SCOPES, self.account, post=self.failing_post())
        strict = self.app.acquire_token_silent(
            REQUESTED_SCOPES, self.account,
            scope_policy=self.policy, post=self.failing_post())

        self.assertEqual("token-exact", normal["access_token"])
        self.assertEqual("token-exact", strict["access_token"])
        self.assertTrue(strict["strict_scope_match"])
        self.assertEqual(APPROVED_SOURCE, strict["approval_source"])
        self.assertEqual(AUDIT_SCOPE, strict["scope"])

    def test_strict_cache_hit_requires_exact_scope_and_approved_source(self):
        self.add_access_token(
            "exact", scopes=[AUDIT_SCOPE], source=APPROVED_SOURCE)

        result = self.app.acquire_token_silent(
            REQUESTED_SCOPES, self.account,
            strict_scope=True, approved_source=APPROVED_SOURCE,
            post=self.failing_post())

        self.assertEqual("token-exact", result["access_token"])
        self.assertEqual(AUDIT_SCOPE, result["scope"])
        self.assertEqual(APPROVED_SOURCE, result["approval_source"])

    def test_strict_refresh_accepts_exact_approved_response_and_caches_it(self):
        self.add_access_token(
            "broad", scopes=[AUDIT_SCOPE, EXTRA_SCOPE],
            source=APPROVED_SOURCE)
        self.add_refresh_token()
        post, calls = self.fake_post(self.refresh_payload(
            scopes=[AUDIT_SCOPE], source=APPROVED_SOURCE,
            token="refreshed-exact"))

        result = self.app.acquire_token_silent(
            REQUESTED_SCOPES, self.account,
            scope_policy=self.policy, post=post)

        self.assertEqual("refreshed-exact", result["access_token"])
        self.assertEqual("identity_provider", result["token_source"])
        self.assertTrue(result["strict_scope_match"])
        self.assertEqual(APPROVED_SOURCE, result["approval_source"])
        self.assertEqual(1, len(calls))
        self.assertIn(AUDIT_SCOPE, calls[0]["data"]["scope"])

        second = self.app.acquire_token_silent(
            REQUESTED_SCOPES, self.account,
            scope_policy=self.policy, post=self.failing_post())
        self.assertEqual("refreshed-exact", second["access_token"])
        self.assertEqual("cache", second["token_source"])
        self.assertEqual(APPROVED_SOURCE, second["approval_source"])

    def test_strict_refresh_rejects_broader_response_and_reports_interaction(self):
        self.add_access_token(
            "broad", scopes=[AUDIT_SCOPE, EXTRA_SCOPE],
            source=APPROVED_SOURCE)
        self.add_refresh_token()
        payload = self.refresh_payload(
            scopes=[AUDIT_SCOPE, EXTRA_SCOPE], source=APPROVED_SOURCE,
            token="refreshed-broad")
        error_post, error_calls = self.fake_post(payload)

        error = self.app.acquire_token_silent_with_error(
            REQUESTED_SCOPES, self.account,
            scope_policy=self.policy, post=error_post)
        self.assertEqual("strict_scope_policy_violation", error["error"])
        self.assertEqual("scope_mismatch", error["strict_scope_reason"])
        self.assertEqual(1, len(error_calls))

        silent_post, silent_calls = self.fake_post(payload)
        self.assertIsNone(self.app.acquire_token_silent(
            REQUESTED_SCOPES, self.account,
            scope_policy=self.policy, post=silent_post))
        self.assertEqual(1, len(silent_calls))
        secrets = [
            entry.get("secret")
            for entry in self.cache._cache["AccessToken"].values()
        ]
        self.assertNotIn("refreshed-broad", secrets)

    def test_strict_alias_query_rejects_other_source_then_approved_refresh(self):
        self.add_access_token(
            "alias-other", scopes=[AUDIT_SCOPE], source=OTHER_SOURCE,
            environment=ALIAS_ENV)
        self.add_refresh_token("alias-rt", environment=ALIAS_ENV)
        post, calls = self.fake_post(self.refresh_payload(
            scopes=[AUDIT_SCOPE], source=APPROVED_SOURCE,
            token="alias-refreshed-exact"))

        result = self.app.acquire_token_silent(
            REQUESTED_SCOPES, self.account,
            scope_policy=self.policy, post=post)

        self.assertEqual("alias-refreshed-exact", result["access_token"])
        self.assertEqual(1, len(calls))
        self.assertEqual("alias-rt", calls[0]["data"]["refresh_token"])

    def test_strict_alias_refresh_from_other_source_requires_interaction(self):
        self.add_access_token(
            "alias-other", scopes=[AUDIT_SCOPE], source=OTHER_SOURCE,
            environment=ALIAS_ENV)
        self.add_refresh_token("alias-rt", environment=ALIAS_ENV)
        payload = self.refresh_payload(
            scopes=[AUDIT_SCOPE], source=OTHER_SOURCE,
            token="alias-refreshed-wrong-source")
        post, calls = self.fake_post(payload)

        error = self.app.acquire_token_silent_with_error(
            REQUESTED_SCOPES, self.account,
            scope_policy=self.policy, post=post)

        self.assertEqual(
            "strict_scope_policy_violation", error["error"])
        self.assertEqual("source_mismatch", error["strict_scope_reason"])
        self.assertEqual(1, len(calls))
        self.assertEqual("alias-rt", calls[0]["data"]["refresh_token"])
        silent_post, silent_calls = self.fake_post(payload)
        self.assertIsNone(self.app.acquire_token_silent(
            REQUESTED_SCOPES, self.account,
            scope_policy=self.policy, post=silent_post))
        self.assertEqual(1, len(silent_calls))
        self.assertNotIn(
            "alias-refreshed-wrong-source",
            [e.get("secret") for e in self.cache._cache["AccessToken"].values()])

    def test_normal_subset_match_still_returns_broader_cache_item(self):
        self.add_access_token(
            "wide-only", scopes=[AUDIT_SCOPE, EXTRA_SCOPE],
            source=APPROVED_SOURCE)
        result = self.app.acquire_token_silent(
            REQUESTED_SCOPES, self.account, post=self.failing_post())
        self.assertEqual("token-wide-only", result["access_token"])

    def test_policy_normalizes_msal_reserved_oidc_scopes(self):
        policy = StrictScopePolicy(approved_sources=[APPROVED_SOURCE])
        self.assertTrue(policy.scopes_are_equal(
            [AUDIT_SCOPE, "openid", "profile", "offline_access"],
            REQUESTED_SCOPES))
        self.assertFalse(policy.scopes_are_equal(
            [AUDIT_SCOPE, EXTRA_SCOPE], REQUESTED_SCOPES))


if __name__ == "__main__":
    unittest.main()
