"""Tests for trackable claims-challenge interactive upgrades."""

import base64
import json
import threading
import time
import unittest
from unittest.mock import Mock, patch

import msal
from msal import PublicClientApplication, InteractionStatus
from tests.test_token_cache import build_id_token
from tests.http_client import MinimalResponse


CHALLENGE = '{"access_token": {"acrs": {"essential": true, "value": "c1"}}}'
OTHER_CHALLENGE = '{"access_token": {"acrs": {"essential": true, "value": "c2"}}}'
SCOPES = ["api://resource/read"]
OTHER_SCOPES = ["api://other/read"]
UID, UTID = "uid_1", "utid_1"
HOME = "{}.{}".format(UID, UTID)


def _token_response(access_token, uid=UID, utid=UTID, expires_in=3600,
        refresh_token=None, username="user@contoso.com", token_source=None):
    response = {
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "client_info": base64.b64encode(json.dumps({
            "uid": uid, "utid": utid}).encode()).decode(),
        "id_token": build_id_token(
            aud="client_id", sub=uid, preferred_username=username),
        "id_token_claims": {
            "oid": uid, "tid": utid, "preferred_username": username},
    }
    if refresh_token:
        response["refresh_token"] = refresh_token
    if token_source:
        response["token_source"] = token_source
        if token_source == "broker":
            response["_account_id"] = uid
    return response


def _seed_account(app, token="seed_at", scope=SCOPES):
    app.token_cache.add({
        "client_id": app.client_id,
        "scope": list(scope),
        "token_endpoint": "https://{}/{}/oauth2/v2.0/token".format(
            app.authority.instance, app.authority.tenant),
        "response": _token_response(token, refresh_token="seed_rt"),
        "data": {},
        })
    accounts = app.get_accounts()
    assert accounts
    return accounts[0]


DISCOVERY = Mock(return_value={
    "authorization_endpoint": "https://contoso.com/placeholder",
    "token_endpoint": "https://contoso.com/placeholder",
    "issuer": "https://contoso.com/tenant",
})


@patch("msal.authority.tenant_discovery", new=DISCOVERY)
@patch("msal.application._init_broker", new=Mock())
@patch("msal.application.platform.machine", new=Mock(return_value="arm64"))
@patch("sys.platform", new="darwin")
class TestClaimsChallengeUpgrade(unittest.TestCase):

    def _make_app(self, **kwargs):
        app = PublicClientApplication(
            "client_id",
            authority="https://login.microsoftonline.com/common",
            enable_broker_on_mac=True,
            **kwargs)
        app._enable_broker = True
        return app

    def test_normal_silent_read_is_marked_normal(self):
        app = self._make_app()
        account = _seed_account(app)
        result = app.acquire_token_silent(SCOPES, account)
        self.assertEqual(InteractionStatus.NORMAL, result["interaction_status"])
        self.assertNotIn("claims_challenge_receipt", result)

    def test_generic_silent_challenge_is_confirmed_and_isolated(self):
        app = self._make_app()
        app._enable_broker = False  # This path is independent of broker routing
        account = _seed_account(app)
        captured = {}

        def mock_post(url, headers=None, data=None, *args, **kwargs):
            captured.update(data or {})
            return MinimalResponse(status_code=200, text=json.dumps(
                _token_response("challenge_at", refresh_token="challenge_rt")))

        result = app.acquire_token_silent(
            SCOPES, account, claims_challenge=CHALLENGE, post=mock_post)
        self.assertEqual(InteractionStatus.CONFIRMED,
            result["interaction_status"])
        self.assertEqual(
            json.loads(CHALLENGE)["access_token"]["acrs"],
            json.loads(captured["claims"])["access_token"]["acrs"])
        self.assertNotIn("msal_claims_challenge_sha256", captured)

        plain = app.acquire_token_silent(SCOPES, account)
        self.assertEqual("seed_at", plain["access_token"])
        self.assertEqual(InteractionStatus.NORMAL, plain["interaction_status"])
        # claims_challenge intentionally bypasses the AT fast path (existing
        # semantics), so this call may refresh; it must still return its own
        # challenge-bound credential rather than the plain cached one.
        challenge_read = app.acquire_token_silent(
            SCOPES, account, claims_challenge=CHALLENGE,
            post=lambda *args, **kwargs: MinimalResponse(status_code=200,
                text=json.dumps(_token_response(
                    "challenge_2_at", refresh_token="challenge_rt"))))
        self.assertEqual("challenge_2_at", challenge_read["access_token"])
        self.assertEqual(InteractionStatus.CONFIRMED,
            challenge_read["interaction_status"])

    def test_upgrade_requires_account_scopes_and_challenge(self):
        app = self._make_app()
        with self.assertRaises(msal.ClaimsChallengeUpgradeError):
            app.start_claims_challenge_upgrade(SCOPES, None, CHALLENGE)
        with self.assertRaises(msal.ClaimsChallengeUpgradeError):
            app.start_claims_challenge_upgrade([], {"home_account_id": HOME}, CHALLENGE)
        with self.assertRaises(ValueError):
            app.start_claims_challenge_upgrade(
                SCOPES, {"home_account_id": HOME}, "not json")

    def test_broker_cancel_then_browser_fallback_confirms(self):
        app = self._make_app()
        account = _seed_account(app)
        upgrade = app.start_claims_challenge_upgrade(
            SCOPES, account, CHALLENGE,
            )

        def fake_broker(*args, **kwargs):
            return {"error": "broker_error",
                    "error_description": "User cancelled the interaction"}

        with patch.object(app, "_acquire_token_interactive_via_broker",
                side_effect=fake_broker), patch.object(
                app.client, "obtain_token_by_browser",
                return_value=_token_response("upgraded_at")):
            cancelled = upgrade.start()
        self.assertEqual(InteractionStatus.CANCELLED,
            cancelled["interaction_status"])
        self.assertEqual("interaction_cancelled", cancelled["error"])

        with patch.object(app.client, "obtain_token_by_browser",
                return_value=_token_response("upgraded_at")):
            approved = upgrade.reopen(skip_broker=True)
        self.assertEqual(InteractionStatus.CONFIRMED,
            approved["interaction_status"])
        self.assertEqual("upgraded_at", approved["access_token"])
        self.assertEqual("upgraded_at",
            approved["claims_challenge_receipt"]["access_token"])

    def test_broker_result_for_another_account_is_rejected(self):
        app = self._make_app()
        account = _seed_account(app)
        upgrade = app.start_claims_challenge_upgrade(
            SCOPES, account, CHALLENGE)
        with patch.object(app, "_acquire_token_interactive_via_broker",
                return_value=_token_response(
                    "other_account_at", uid="uid_2", utid="utid_2",
                    token_source="broker")):
            result = upgrade.start()
        self.assertEqual(InteractionStatus.CONFIRMATION_REQUIRED,
            result["interaction_status"])
        self.assertEqual("claims_challenge_account_mismatch", result["error"])
        self.assertIsNone(upgrade.receipt)
        self.assertIsNone(result["claims_challenge_receipt"])
        self.assertTrue(any(
            item.get("reason") == "account_mismatch"
            for item in upgrade.timeline))

    def test_upgrade_receipt_does_not_satisfy_plain_silent_read(self):
        app = self._make_app()
        account = _seed_account(app)
        upgrade = app.start_claims_challenge_upgrade(
            SCOPES, account, CHALLENGE)
        with patch.object(app, "_acquire_token_interactive_via_broker",
                return_value=None):
            # Browser failure and then fallback
            with patch.object(app.client, "obtain_token_by_browser",
                    return_value=_token_response("upgraded_at")):
                result = upgrade.start(browser_fallback=True)
        self.assertEqual(InteractionStatus.CONFIRMED,
            result["interaction_status"])

        plain = app.acquire_token_silent(SCOPES, account)
        self.assertEqual("seed_at", plain["access_token"])
        self.assertEqual(InteractionStatus.NORMAL, plain["interaction_status"])

        at_entries = app.token_cache._cache[
            msal.TokenCache.CredentialType.ACCESS_TOKEN]
        self.assertTrue(any(
            entry.get("secret") == "upgraded_at" for entry in at_entries.values()),
            "The confirmed upgrade must leave a challenge-bound cached credential")
        self.assertTrue(any(
            "ext_cache_key" in entry for entry in at_entries.values()
            if entry.get("secret") == "upgraded_at"))

    def test_ordinary_window_stays_normal(self):
        app = self._make_app()
        account = _seed_account(app)
        upgrade = app.start_claims_challenge_upgrade(SCOPES, account, CHALLENGE)
        ordinary = app.acquire_token_silent(SCOPES, account)
        self.assertEqual("seed_at", ordinary["access_token"])
        self.assertEqual(InteractionStatus.NORMAL,
            ordinary["interaction_status"])
        self.assertIsNone(upgrade.receipt)
        self.assertEqual(InteractionStatus.CONFIRMATION_REQUIRED,
            upgrade.status)

    def test_stale_receipt_does_not_change_new_attempt(self):
        app = self._make_app()
        account = _seed_account(app)
        upgrade = app.start_claims_challenge_upgrade(
            SCOPES, account, CHALLENGE)
        old_attempt = upgrade.attempt_id
        # Produce a receipt for the first generation.
        with patch.object(app, "_acquire_token_interactive_via_broker",
                return_value=_token_response("first_upgrade_at", token_source="broker")):
            first = upgrade.start()
        self.assertEqual(InteractionStatus.CONFIRMED,
            first["interaction_status"])
        old_receipt = first["claims_challenge_receipt"]

        # Re-open into a fresh generation.  The new attempt remains pending
        # (broker attempts a silent sign-in first) until the user completes it.
        with patch.object(app.client, "obtain_token_by_browser",
                return_value={"error": "interaction_required",
                    "error_description": "Still needs confirmation"}):
            upgrade.reopen(skip_broker=True)
        self.assertNotEqual(old_attempt, upgrade.attempt_id)
        severity = app.apply_claims_challenge_receipt(old_receipt)
        self.assertFalse(severity)
        self.assertEqual(InteractionStatus.CONFIRMATION_REQUIRED,
            upgrade.status)
        self.assertTrue(any(item["event"] == "stale_receipt_ignored"
            for item in upgrade.timeline))

    def test_receipt_must_match_scope_and_challenge(self):
        app = self._make_app()
        account = _seed_account(app)
        first = app.start_claims_challenge_upgrade(
            SCOPES, account, CHALLENGE)
        with patch.object(app, "_acquire_token_interactive_via_broker",
                return_value=_token_response("upgraded_at", token_source="broker")):
            first.start()
        receipt = first.receipt
        self.assertIsNotNone(receipt)
        self.assertTrue(receipt.matches(account, SCOPES, CHALLENGE))
        self.assertFalse(receipt.matches(account, OTHER_SCOPES, CHALLENGE))
        self.assertFalse(receipt.matches(account, SCOPES, OTHER_CHALLENGE))

        # A receipt cannot be moved to a different upgrade either.
        other = app.start_claims_challenge_upgrade(
            SCOPES, account, CHALLENGE)
        forged = dict(receipt)
        forged["upgrade_id"] = other.upgrade_id
        forged["attempt_id"] = other.attempt_id
        forged["scopes"] = sorted(OTHER_SCOPES)
        self.assertFalse(app.apply_claims_challenge_receipt(forged))
        self.assertEqual(InteractionStatus.CONFIRMATION_REQUIRED, other.status)

    def test_facade_receipt_can_complete_matching_session(self):
        app = self._make_app()
        account = _seed_account(app)
        upgrade = app.start_claims_challenge_upgrade(
            SCOPES, account, CHALLENGE)
        receipt = msal.ClaimsChallengeReceipt({
            "upgrade_id": upgrade.upgrade_id,
            "attempt_id": upgrade.attempt_id,
            "status": InteractionStatus.CONFIRMED,
            "source": "broker",
            "token_source": "broker",
            "home_account_id": HOME,
            "scopes": sorted(SCOPES),
            "claims_challenge_sha256":
                msal.claims_challenge.claims_challenge_sha256(CHALLENGE),
            "expires_on": int(time.time() + 100),
        })
        self.assertTrue(app.apply_claims_challenge_receipt(receipt))
        self.assertEqual(InteractionStatus.CONFIRMED, upgrade.status)
        self.assertEqual(receipt, upgrade.receipt)

    def test_two_windows_run_in_parallel(self):
        app = self._make_app()
        account = _seed_account(app)
        upgrade_a = app.start_claims_challenge_upgrade(
            SCOPES, account, CHALLENGE)
        results = {}
        barrier = threading.Barrier(2)

        def ordinary_window():
            barrier.wait()
            results["ordinary"] = app.acquire_token_silent(SCOPES, account)

        def upgraded_window():
            barrier.wait()
            with patch.object(app, "_acquire_token_interactive_via_broker",
                    return_value={"error": "broker_error",
                        "error_description": "cancelled"}):
                results["cancelled"] = upgrade_a.start()
            with patch.object(app.client, "obtain_token_by_browser",
                    return_value=_token_response("upgrade_at")):
                results["approved"] = upgrade_a.reopen(skip_broker=True)

        threads = [threading.Thread(target=ordinary_window),
                   threading.Thread(target=upgraded_window)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual("seed_at", results["ordinary"]["access_token"])
        self.assertEqual(InteractionStatus.NORMAL,
            results["ordinary"]["interaction_status"])
        self.assertEqual(InteractionStatus.CANCELLED,
            results["cancelled"]["interaction_status"])
        self.assertEqual(InteractionStatus.CONFIRMED,
            results["approved"]["interaction_status"])
        self.assertGreaterEqual(len(upgrade_a.timeline), 6)
        self.assertEqual(InteractionStatus.CONFIRMED, upgrade_a.status)


@patch("msal.authority.tenant_discovery", new=DISCOVERY)
@patch("sys.platform", new="darwin")
@patch("msal.application.platform.machine", new=Mock(return_value="arm64"))
@patch("msal.application._init_broker", new=Mock())
class TestClaimsChallengeTimeline(unittest.TestCase):
    """The timeline must make broker, fallback, and final credential attribution explicit."""

    def _app(self):
        app = PublicClientApplication(
            "client_id",
            authority="https://login.microsoftonline.com/common")
        return app

    def _brokered_app(self):
        app = PublicClientApplication(
            "client_id",
            authority="https://login.microsoftonline.com/common",
            enable_broker_on_mac=True)
        app._enable_broker = True
        return app

    def test_browser_fallback_can_be_disabled_at_construction(self):
        app = PublicClientApplication(
            "client_id",
            authority="https://login.microsoftonline.com/common",
            claims_challenge_browser_fallback=False)
        account = _seed_account(app)
        upgrade = app.start_claims_challenge_upgrade(
            SCOPES, account, CHALLENGE)
        # No broker is enabled here; the browser path is still the only
        # available flow, so disabling fallback must not dead-end it when
        # there was no broker attempt at all.
        with patch.object(app.client, "obtain_token_by_browser",
                return_value=_token_response("direct_browser_at")):
            result = upgrade.start()
        self.assertEqual(InteractionStatus.CONFIRMED,
            result["interaction_status"])

    def test_timeline_attributes_sources(self):
        # This test uses a plain app without broker; browser is the only source.
        app = self._app()
        account = _seed_account(app)
        upgrade = app.start_claims_challenge_upgrade(
            SCOPES, account, CHALLENGE)
        with patch.object(app.client, "obtain_token_by_browser",
                return_value=_token_response("browser_at")):
            result = upgrade.start(skip_broker=True)
        self.assertEqual(InteractionStatus.CONFIRMED,
            result["interaction_status"])
        snapshot = result["claims_challenge_upgrade"]
        self.assertEqual(upgrade.upgrade_id, snapshot["upgrade_id"])
        self.assertEqual(upgrade.attempt_id, snapshot["attempt_id"])
        self.assertEqual("browser_at",
            snapshot["attempts"][-1]["receipt"]["access_token"])
        events = [item["event"] for item in snapshot["timeline"]]
        self.assertIn("attempt_source", events)
        self.assertIn("receipt_accepted", events)

    def test_late_result_from_old_generation_is_ignored(self):
        app = self._app()
        account = _seed_account(app)
        upgrade = app.start_claims_challenge_upgrade(
            SCOPES, account, CHALLENGE)
        old_attempt = upgrade.attempt_id
        with patch.object(app.client, "obtain_token_by_browser",
                return_value={"error": "interaction_required",
                    "error_description": "pending"}):
            upgrade.reopen(skip_broker=True)
        self.assertNotEqual(old_attempt, upgrade.attempt_id)

        late_receipt = msal.ClaimsChallengeReceipt({
            "upgrade_id": upgrade.upgrade_id,
            "attempt_id": old_attempt,
            "status": InteractionStatus.CONFIRMED,
            "source": "broker",
            "token_source": "broker",
            "home_account_id": HOME,
            "scopes": sorted(SCOPES),
            "claims_challenge_sha256":
                msal.claims_challenge.claims_challenge_sha256(CHALLENGE),
            "expires_on": int(time.time() + 100),
        })
        self.assertFalse(app.apply_claims_challenge_receipt(late_receipt))
        self.assertEqual(InteractionStatus.CONFIRMATION_REQUIRED,
            upgrade.status)
        self.assertTrue(any(
            item.get("reason") == "stale_attempt"
            for item in upgrade.timeline))
        self.assertEqual(old_attempt, upgrade.snapshot()["stale_receipts"][0]["attempt_id"])

    def test_broker_fallback_disabled_stays_pending(self):
        app = self._brokered_app()
        account = _seed_account(app)
        upgrade = app.start_claims_challenge_upgrade(
            SCOPES, account, CHALLENGE, browser_fallback=False)
        with patch.object(app, "_acquire_token_interactive_via_broker",
                return_value={"error": "broker_error",
                    "error_description": "Interaction required"}), \
                patch.object(app.client, "obtain_token_by_browser",
                    side_effect=AssertionError("browser must not be launched")):
            result = upgrade.start()
        self.assertEqual(InteractionStatus.CONFIRMATION_REQUIRED,
            result["interaction_status"])
        self.assertEqual("broker_error", result["error"])
        self.assertFalse(any(
            item["event"] == "browser_fallback_started"
            for item in upgrade.timeline))

    def test_foreign_account_receipt_is_rejected(self):
        app = self._app()
        account = _seed_account(app)
        upgrade = app.start_claims_challenge_upgrade(
            SCOPES, account, CHALLENGE)
        forged = msal.ClaimsChallengeReceipt({
            "upgrade_id": upgrade.upgrade_id,
            "attempt_id": upgrade.attempt_id,
            "status": InteractionStatus.CONFIRMED,
            "source": "broker",
            "home_account_id": "someone_else.tenant",
            "scopes": sorted(SCOPES),
            "claims_challenge_sha256":
                msal.claims_challenge.claims_challenge_sha256(CHALLENGE),
            "expires_on": int(time.time() + 100),
        })
        self.assertFalse(app.apply_claims_challenge_receipt(forged))
        self.assertEqual(InteractionStatus.CONFIRMATION_REQUIRED,
            upgrade.status)
        self.assertTrue(any(
            item.get("reason") == "conditions_mismatch"
            for item in upgrade.timeline))


if __name__ == "__main__":
    unittest.main()
