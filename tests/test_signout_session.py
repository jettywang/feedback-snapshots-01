"""Regression tests for multi-account sign-out bookkeeping.

These tests use two synthetic accounts that share one token cache. They do not
talk to any identity provider; the refresh endpoint is a local fake.
"""
import json
import threading
from unittest.mock import Mock, patch

import msal
from msal.token_cache import TokenCache
from tests import unittest
from tests.http_client import MinimalResponse
from tests.test_token_cache import build_id_token, build_response


_OIDC_DISCOVERY = "msal.authority.tenant_discovery"
_OIDC_DISCOVERY_MOCK = Mock(return_value={
    "authorization_endpoint": "https://contoso.com/placeholder",
    "token_endpoint": "https://contoso.com/placeholder",
    "issuer": "https://contoso.com/tenant",
})
_CLIENT_ID = "my_app"
_AUTHORITY = "https://login.microsoftonline.com/contoso"


def _account(uid, utid, username):
    return {"uid": uid, "utid": utid, "username": username,
            "home_account_id": "{}.{}".format(uid, utid)}


_ALICE = _account("uid_a", "utid_a", "alice@contoso.com")
_BOB = _account("uid_b", "utid_b", "bob@contoso.com")


def _seed_cache(cache, accounts):
    for a in accounts:
        cache.add({
            "client_id": _CLIENT_ID,
            # Refresh lookups use the decorated (reserved-scope) target,
            # whereas plain AT lookups use exactly what the caller asks.
            "scope": ["s1", "openid", "profile", "offline_access"],
            "token_endpoint": "https://login.microsoftonline.com/placeholder/oauth2/v2.0/token",
            "response": build_response(
                uid=a["uid"], utid=a["utid"],
                access_token="SEEDED-AT-" + a["uid"],
                refresh_token="SEEDED-RT-" + a["uid"],
                id_token=build_id_token(
                    aud=_CLIENT_ID, sub="oid-" + a["uid"],
                    preferred_username=a["username"]),
                ),
            })


def _token_response(account, access_token, refresh_token):
    return build_response(
        uid=account["uid"], utid=account["utid"],
        access_token=access_token, refresh_token=refresh_token,
        id_token=build_id_token(
            aud=_CLIENT_ID, sub="oid-" + account["uid"],
            preferred_username=account["username"]),
        )


def _tokens_for(cache, account, credential_type):
    return [e["secret"] for e in cache.search(
        credential_type, query={"home_account_id": account["home_account_id"]})]


class _ReloginMixin(object):
    def _relogin(self):
        """Re-authorize Alice through the public device-code entry point.

        Device code is used because it needs no PKCE/nonce choreography and
        is not deprecated for public clients.
        """
        return self.app.acquire_token_by_device_flow(
            {"device_code": "the-device-code"},
            post=lambda url, **kwargs: MinimalResponse(
                status_code=200, text=json.dumps(
                    _token_response(_ALICE, "RELOGIN-AT-A", "RELOGIN-RT-A"))))


class TestMultiAccountSignout(_ReloginMixin, unittest.TestCase):

    def setUp(self):
        # unittest's class-level @patch does not reach setUp(), and building the
        # authority is what triggers discovery, so patch it here explicitly.
        self._discovery = patch(_OIDC_DISCOVERY, new=_OIDC_DISCOVERY_MOCK)
        self._discovery.start()
        self.addCleanup(self._discovery.stop)
        self.cache = msal.SerializableTokenCache()
        _seed_cache(self.cache, [_ALICE, _BOB])
        self.app = msal.PublicClientApplication(
            _CLIENT_ID, authority=_AUTHORITY, token_cache=self.cache)

    def _accounts_by_name(self):
        return {a["username"]: a for a in self.app.get_accounts()}

    def test_progress_defaults_to_active_for_a_known_account(self):
        progress = self.app.get_signout_progress(home_account_id=_ALICE["home_account_id"])
        self.assertEqual("active", progress["state"])
        self.assertEqual(0, progress["generation"])
        self.assertIsNone(progress["receipt"])
        self.assertEqual(
            self.app.get_account_session(_ALICE), progress["session"])

    def test_remove_account_hides_it_locally_and_broker_confirms_later(self):
        accounts = self._accounts_by_name()
        receipt = self.app.remove_account(accounts["alice@contoso.com"], return_receipt=True)

        self.assertEqual("completed", receipt["local_signout"])
        self.assertEqual("not_attempted", receipt["broker_signout"],
            "Without broker enabled, local sign-out is the whole story")
        self.assertEqual("confirmed", receipt["state"])
        self.assertEqual([_BOB["username"]],
            [a["username"] for a in self.app.get_accounts()],
            "The account panel must drop the signed-out account immediately")
        self.assertEqual([], _tokens_for(
            self.cache, _ALICE, TokenCache.CredentialType.REFRESH_TOKEN),
            "Local sign-out is complete before any broker reply")

    def test_historical_return_value_is_unchanged(self):
        accounts = self._accounts_by_name()
        self.assertIsNone(self.app.remove_account(accounts["alice@contoso.com"]))

    def test_unknown_broker_cleanup_does_not_count_as_confirmed(self):
        receipt = self.app.token_cache.begin_signout(
            _ALICE["home_account_id"], broker_attempted=True)
        updated = self.app.observe_signout_result(receipt, broker_outcome="unknown_account")
        self.assertEqual("unknown_account", updated["broker_signout"])
        self.assertEqual("pending", updated["state"],
            "An unrecognized cleanup is not proof that sign-out finished")

        confirmed = self.app.observe_signout_result(receipt, broker_outcome="confirmed")
        self.assertEqual("confirmed", confirmed["state"])
        self.assertEqual("confirmed", self.app.get_signout_progress(
            home_account_id=_ALICE["home_account_id"])["state"])

    def test_pending_signout_does_not_block_other_accounts(self):
        accounts = self._accounts_by_name()
        receipt = self.app.token_cache.begin_signout(
            _ALICE["home_account_id"], broker_attempted=True)

        def bob_refresh(url, headers=None, data=None, **kwargs):
            self.assertEqual("SEEDED-RT-" + _BOB["uid"], data.get("refresh_token"))
            return MinimalResponse(status_code=200, text=json.dumps(
                _token_response(_BOB, "NEW-AT-B", "NEW-RT-B")))

        result = self.app.acquire_token_silent_with_error(
            ["s1"], self._accounts_by_name()["bob@contoso.com"],
            force_refresh=True, post=bob_refresh)
        self.assertEqual("NEW-AT-B", result["access_token"])
        self.assertEqual(_BOB["home_account_id"], result["home_account_id"])
        self.assertEqual(
            self.app.get_account_session(_BOB), result["session"],
            "B's result must be attributed to B's own session")
        self.assertEqual("pending", self.app.get_signout_progress(
            home_account_id=_ALICE["home_account_id"])["state"],
            "B's normal work must not advance A's sign-out")

    def test_late_refresh_from_signed_out_session_is_discarded(self):
        started = threading.Event()
        release = threading.Event()

        def fake_post(url, headers=None, data=None, **kwargs):
            if data.get("refresh_token") == "SEEDED-RT-" + _ALICE["uid"]:
                started.set()
                release.wait(10)
                return MinimalResponse(status_code=200, text=json.dumps(
                    _token_response(_ALICE, "LATE-AT-A", "LATE-RT-A")))
            return MinimalResponse(status_code=200, text=json.dumps(
                _token_response(_BOB, "NEW-AT-B", "NEW-RT-B")))

        late = {}
        def refresh_a():
            late.update(self.app.acquire_token_silent_with_error(
                ["s1"], self._accounts_by_name()["alice@contoso.com"],
                force_refresh=True, post=fake_post))

        worker = threading.Thread(target=refresh_a)
        worker.start()
        try:
            self.assertTrue(started.wait(10), "A's refresh should be in flight")
            receipt = self.app.remove_account(
                self._accounts_by_name()["alice@contoso.com"], return_receipt=True)
        finally:
            release.set()
            worker.join(10)

        self.assertEqual("signout_discarded", late.get("error"),
            "The reply belongs to the retired session")
        self.assertNotIn("access_token", late)

        # Deliver the broker confirmation, then verify the cache is clean.
        confirmed = self.app.observe_signout_result(receipt, broker_outcome="confirmed")
        self.assertEqual("confirmed", confirmed["state"])
        self.assertEqual([], _tokens_for(self.cache, _ALICE, TokenCache.CredentialType.ACCESS_TOKEN))
        self.assertEqual([], _tokens_for(self.cache, _ALICE, TokenCache.CredentialType.REFRESH_TOKEN))
        self.assertEqual([], _tokens_for(self.cache, _ALICE, TokenCache.CredentialType.ACCOUNT))
        self.assertEqual([_BOB["username"]],
            [a["username"] for a in self.app.get_accounts()],
            "A's late write must not re-add it to the account panel")

    def test_relogin_gets_a_new_session_and_old_receipt_is_ignored(self):
        accounts = self._accounts_by_name()
        old_receipt = self.app.remove_account(
            accounts["alice@contoso.com"], return_receipt=True)
        old_session = old_receipt["session"]

        relogin = self._relogin()
        self.assertEqual("RELOGIN-AT-A", relogin["access_token"])
        self.assertNotEqual(old_session, relogin["session"],
            "A fresh sign-in must get its own session identifier")
        progress = self.app.get_signout_progress(home_account_id=_ALICE["home_account_id"])
        self.assertEqual("active", progress["state"])
        self.assertEqual(2, progress["generation"])
        self.assertIsNone(progress["receipt"])

        self.assertIsNone(
            self.app.observe_signout_result(old_receipt, broker_outcome="confirmed"),
            "A late confirmation for the old sign-out must be ignored")
        self.assertEqual("active", self.app.get_signout_progress(
            home_account_id=_ALICE["home_account_id"])["state"])

        self.assertIn(_ALICE["username"],
            [a["username"] for a in self.app.get_accounts()])
        self.assertEqual(1, len(_tokens_for(
            self.cache, _ALICE, TokenCache.CredentialType.REFRESH_TOKEN)))

    def test_cached_token_is_not_returned_after_its_session_ended(self):
        self.app.remove_account(self._accounts_by_name()["alice@contoso.com"])
        result = self.app.acquire_token_silent_with_error(
            ["s1"], _ALICE)
        self.assertTrue(
            result is None or result.get("error") == "signout_discarded",
            "A removed account must not yield a usable token")

    def test_bob_still_uses_his_own_cached_token(self):
        self.app.remove_account(self._accounts_by_name()["alice@contoso.com"])
        result = self.app.acquire_token_silent_with_error(["s1"], _BOB)
        self.assertEqual("SEEDED-AT-" + _BOB["uid"], result["access_token"])
        self.assertEqual(self.app._TOKEN_SOURCE_CACHE, result["token_source"])
        self.assertEqual(self.app.get_account_session(_BOB), result["session"])


class TestSignoutWithBroker(_ReloginMixin, unittest.TestCase):
    """The broker is faked; no real broker or network is involved.

    ``msal.broker`` cannot be imported without PyMsalRuntime, so these tests
    install a stub module just for the duration of the test.
    """

    def setUp(self):
        import sys, types
        self._fake_broker = types.ModuleType("msal.broker")
        self._fake_broker._signout_silently = lambda *a, **k: {"status": "confirmed"}
        self._fake_broker._acquire_token_silently = lambda *a, **k: {}
        self._fake_broker._signin_silently = lambda *a, **k: {
            "error": "broker_error", "error_description": "not needed in this test"}
        self._saved_broker = sys.modules.get("msal.broker")
        sys.modules["msal.broker"] = self._fake_broker
        self.addCleanup(self._restore_broker, sys.modules, self._saved_broker)

        self._discovery = patch(_OIDC_DISCOVERY, new=_OIDC_DISCOVERY_MOCK)
        self._discovery.start()
        self.addCleanup(self._discovery.stop)
        self.cache = msal.SerializableTokenCache()
        _seed_cache(self.cache, [_ALICE])
        self.app = msal.ClientApplication(
            _CLIENT_ID, authority=_AUTHORITY, token_cache=self.cache,
            instance_discovery=False)  # These tests never touch the network
        self.app._enable_broker = True
        self.addCleanup(self._reset_broker_flag)

    def _reset_broker_flag(self):
        self.app._enable_broker = False

    @staticmethod
    def _restore_broker(modules, saved):
        if saved is None:
            modules.pop("msal.broker", None)
        else:
            modules["msal.broker"] = saved

    def _remove(self):
        account = self.app.get_accounts()[0]
        return self.app.remove_account(account, return_receipt=True)

    def test_broker_ack_marks_signout_confirmed(self):
        with patch("msal.broker._signout_silently",
                   return_value={"status": "confirmed"}):
            receipt = self._remove()
        self.assertEqual("confirmed", receipt["broker_signout"])
        self.assertEqual("confirmed", receipt["state"])
        self.assertIn("receipt", self.app.get_signout_progress(
            home_account_id=_ALICE["home_account_id"]))
        self.assertEqual([], self.app.get_accounts())

    def test_unconfirmed_broker_keeps_signout_pending(self):
        with patch("msal.broker._signout_silently",
                   return_value={"status": "pending",
                                 "error": {"error": "broker_error"}}):
            receipt = self._remove()
        self.assertEqual("pending", receipt["state"])
        self.assertEqual("pending", self.app.get_signout_progress(
            home_account_id=_ALICE["home_account_id"])["state"])
        self.assertEqual([], self.app.get_accounts(),
            "The local account panel reflects the sign-out regardless")

        updated = self.app.observe_signout_result(receipt, broker_outcome="confirmed")
        self.assertEqual("confirmed", updated["state"])

    def test_late_confirmation_after_relogin_is_ignored(self):
        with patch("msal.broker._signout_silently",
                   return_value={"status": "pending"}):
            receipt = self._remove()

        # With broker enabled this re-authentication goes through the (faked)
        # broker sign-in rather than the ROPC HTTP endpoint.
        relogin = self.app._stamp_new_signin_session(
            self.app._process_broker_response(
                dict(_token_response(_ALICE, "RELOGIN-AT-A", "RELOGIN-RT-A"),
                     _account_id="local-a"),
                ["s1"], {}, establishes_account=True))
        self.assertEqual("RELOGIN-AT-A", relogin["access_token"])

        self.assertIsNone(self.app.observe_signout_result(
            receipt, broker_outcome="confirmed"))
        self.assertEqual("active", self.app.get_signout_progress(
            home_account_id=_ALICE["home_account_id"])["state"],
            "The old broker reply must not touch the fresh session")

    def test_silent_broker_refresh_after_signout_does_not_resurrect_account(self):
        with patch("msal.broker._signout_silently",
                   return_value={"status": "confirmed"}):
            self._remove()

        # A silent call for the removed account must not be treated as a
        # re-login, even though a broker result uses the "broker" grant type.
        stale_account = dict(_ALICE, account_source="broker",
                             local_account_id="local-a")
        late = self.app.acquire_token_silent_with_error(["s1"], stale_account)
        self.assertTrue(
            late is None or late.get("error") == "signout_discarded", late)
        self.assertEqual([], self.app.get_accounts(),
            "A silent call must not re-add the signed-out account")

    def test_broker_exception_leaves_receipt_pending_without_raising(self):
        with patch("msal.broker._signout_silently",
                   side_effect=RuntimeError("broker vanished")):
            receipt = self._remove()
        self.assertEqual("pending", receipt["state"])
        self.assertEqual("completed", receipt["local_signout"])
        self.assertEqual([], self.app.get_accounts())
