"""Tests for the optional safe cache merge entry point.

The headline case mirrors the acceptance scenario:

* two processes persist their own MSAL serializable cache snapshots;
* one confirms sign-out of an account while the other stays stale and adds an
  independent account / rotates another token;
* the two snapshots are merged in opposite orders and the resulting login-able
  accounts, independent entries and conflict records must agree;
* the merged cache drives ``acquire_token_silent``: merged credentials are
  usable and the signed-out account never comes back.
"""
import json
import os
import tempfile
import time
from unittest.mock import Mock, patch

import msal
from msal import (
    ClientApplication,
    SerializableTokenCache,
    merge_cache_states,
)
from msal.cache_merge import (
    MERGE_METADATA_KEY,
    merge_states,
)
from tests import unittest
from tests.test_token_cache import build_id_token, build_response


AUTHORITY = "https://login.microsoftonline.com/common"
TOKEN_ENDPOINT = AUTHORITY + "/oauth2/v2.0/token"
CLIENT_ID = "merge-test-app"
SCOPES = ["s1", "s2"]
ENV = "login.microsoftonline.com"

_OIDC_DISCOVERY = "msal.authority.tenant_discovery"
_OIDC_DISCOVERY_MOCK = Mock(return_value={
    # Keep the "common" tenant in the mocked token_endpoint, otherwise
    # Authority re-derives a different realm and AT fast-path lookup misses.
    "authorization_endpoint":
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    "token_endpoint": TOKEN_ENDPOINT,
    "issuer": "https://login.microsoftonline.com/common/v2.0",
})


def _canonical(cache_or_state):
    state = getattr(cache_or_state, "_cache", cache_or_state)
    return json.dumps(state, sort_keys=True, ensure_ascii=False)


def _account_entry(home_id, username=None, realm="contoso"):
    uid, utid = home_id.split(".", 1)
    return {
        "home_account_id": home_id,
        "environment": ENV,
        "realm": realm,
        "local_account_id": uid,
        "username": username or (uid + "@example.com"),
        "authority_type": "MSSTS",
    }


class LegacyFormatAndPureMergeTests(unittest.TestCase):

    def test_existing_cache_format_still_reads(self):
        cache = SerializableTokenCache()
        cache.deserialize("""
            {
                "AccessToken": {"an-entry": {"foo": "bar"}},
                "customized": "whatever"
            }
            """)
        self.assertEqual({"foo": "bar"},
                         cache._cache["AccessToken"]["an-entry"])
        self.assertEqual("whatever", cache._cache["customized"])
        self.assertFalse(cache.has_state_changed)

        # Merging an empty snapshot must keep every legacy/undefined key intact.
        report = cache.safe_merge(SerializableTokenCache())
        self.assertEqual({"foo": "bar"},
                         report.merged["AccessToken"]["an-entry"])
        self.assertEqual("whatever", report.merged["customized"])
        self.assertTrue(report.unrecognized)
        self.assertEqual("unknown_top_level_key",
                         report.unrecognized[0]["code"])

    def test_merge_does_not_mutate_inputs(self):
        left = {"Account": {"k": _account_entry("u1.t1")}}
        right = {"Account": {"k2": _account_entry("u2.t2")}}
        left_before = json.dumps(left, sort_keys=True)
        right_before = json.dumps(right, sort_keys=True)
        merge_states(left, right)
        self.assertEqual(left_before, json.dumps(left, sort_keys=True))
        self.assertEqual(right_before, json.dumps(right, sort_keys=True))

    def test_accepts_json_string_and_cache_and_dict(self):
        state = {"Account": {"k": _account_entry("u1.t1")}}
        as_string = json.dumps(state)
        cache = SerializableTokenCache()
        cache.deserialize(as_string)
        for candidate in (state, as_string, cache):
            report = merge_cache_states({}, candidate)
            self.assertEqual(1, report.stats["accounts"])


class ConflictReasonTests(unittest.TestCase):

    def test_undecidable_legacy_collision_reports_reason_and_is_symmetric(self):
        left = {"RefreshToken": {"same-key": {
            "credential_type": "RefreshToken",
            "home_account_id": "legacy.tenant",
            "environment": ENV,
            "secret": "secret-a",
            # Deliberately no last_modification_time / version: old record.
        }}}
        right = {"RefreshToken": {"same-key": {
            "credential_type": "RefreshToken",
            "home_account_id": "legacy.tenant",
            "environment": ENV,
            "secret": "secret-b",
        }}}

        ab = merge_cache_states(left, right)
        ba = merge_cache_states(right, left)

        self.assertEqual(1, len(ab.conflicts))
        conflict = ab.conflicts[0]
        self.assertEqual("RefreshToken", conflict.section)
        self.assertEqual("same-key", conflict.key)
        self.assertTrue(conflict.code)
        self.assertTrue(conflict.reason,
                        "An undecidable legacy record must carry a reason")
        self.assertIn("same-key", conflict.reason)

        # Reverse order must yield the same conflict identity and merged state.
        self.assertEqual(
            [(c.section, c.key, c.code) for c in ab.conflicts],
            [(c.section, c.key, c.code) for c in ba.conflicts])
        self.assertEqual(_canonical(ab.merged), _canonical(ba.merged))
        self.assertEqual(ab.merged["RefreshToken"]["same-key"]["secret"],
                         conflict.chosen["secret"])

        # repr must not leak the token secret.
        self.assertNotIn("secret-a", repr(conflict))
        self.assertNotIn("secret-b", repr(conflict))
        # ...but raw values remain available to authorized callers.
        self.assertEqual(2, len(conflict.candidates))

    def test_malformed_non_object_record_is_reported(self):
        left = {"AccessToken": {"weird": ["not", "an", "object"]}}
        right = {"AccessToken": {"weird": "also-not-an-object"}}
        report = merge_cache_states(left, right)
        self.assertEqual(1, len(report.conflicts))
        self.assertEqual("non_object_record", report.conflicts[0].code)
        self.assertTrue(report.conflicts[0].reason)

    def test_unknown_top_level_divergent_value_is_conflict(self):
        left = {"custom": {"a": 1}}
        right = {"custom": {"a": 2}}
        ab = merge_cache_states(left, right)
        ba = merge_cache_states(right, left)
        self.assertEqual(1, len(ab.conflicts))
        self.assertEqual("opaque_value_conflict", ab.conflicts[0].code)
        self.assertTrue(ab.conflicts[0].reason)
        self.assertEqual(_canonical(ab.merged), _canonical(ba.merged))

    def test_newer_timestamp_wins_without_conflict(self):
        old = {"AccessToken": {"k": {
            "secret": "old-at", "cached_at": "1000",
            "expires_on": "9999999999"}}}
        new = {"AccessToken": {"k": {
            "secret": "new-at", "cached_at": "2000",
            "expires_on": "9999999999"}}}
        report = merge_cache_states(old, new)
        self.assertEqual(0, len(report.conflicts))
        self.assertEqual(1, len(report.resolved))
        self.assertEqual("new-at",
                         report.merged["AccessToken"]["k"]["secret"])
        # Symmetric regardless of argument order.
        reverse = merge_cache_states(new, old)
        self.assertEqual(
            "new-at", reverse.merged["AccessToken"]["k"]["secret"])

    def test_same_secret_records_are_unioned(self):
        left = {"RefreshToken": {"k": {
            "secret": "rt", "home_account_id": "u.t", "only_left": 1}}}
        right = {"RefreshToken": {"k": {
            "secret": "rt", "home_account_id": "u.t", "only_right": 2}}}
        report = merge_cache_states(left, right)
        self.assertEqual(0, len(report.conflicts))
        merged_record = report.merged["RefreshToken"]["k"]
        self.assertEqual(1, merged_record["only_left"])
        self.assertEqual(2, merged_record["only_right"])


class TombstoneTests(unittest.TestCase):

    def test_remove_account_records_realm_independent_tombstone(self):
        cache = SerializableTokenCache()
        account = _account_entry("bob.btenant")
        account["authority_type"] = "MSSTS"
        cache._cache["Account"] = {
            "bob.btenant-" + ENV + "-contoso": account}
        cache.remove_account(account)  # authority_type present

        tombstones = cache.get_signout_tombstones()
        self.assertEqual(1, len(tombstones))
        self.assertEqual("bob.btenant",
                         tombstones[0]["home_account_id"])
        self.assertNotIn("realm", tombstones[0],
                         "Sign-out tombstone must stay realm-independent")
        self.assertIn(MERGE_METADATA_KEY, json.loads(cache.serialize()))

    def test_stale_snapshot_cannot_resurrect_tombstoned_account(self):
        signed_out = {
            MERGE_METADATA_KEY: {"version": 1, "tombstones": [
                {"home_account_id": "bob.btenant", "environment": ENV,
                 "reason": "signed_out", "at": time.time()}]},
        }
        stale = {
            "Account": {"bob-key": _account_entry("bob.btenant")},
            "RefreshToken": {"rt-key": {
                "home_account_id": "bob.btenant", "environment": ENV,
                "secret": "stale-rt"}},
            "AccessToken": {"at-key": {
                "home_account_id": "bob.btenant", "environment": ENV,
                "realm": "contoso", "secret": "stale-at"}},
        }
        ab = merge_cache_states(signed_out, stale)
        ba = merge_cache_states(stale, signed_out)

        self.assertEqual([], ab.accounts)
        self.assertNotIn("bob-key", ab.merged.get("Account", {}))
        self.assertNotIn("rt-key", ab.merged.get("RefreshToken", {}))
        self.assertNotIn("at-key", ab.merged.get("AccessToken", {}))
        suppressed_keys = {(s.section, s.key) for s in ab.suppressed}
        self.assertIn(("Account", "bob-key"), suppressed_keys)
        self.assertIn(("RefreshToken", "rt-key"), suppressed_keys)
        self.assertIn(("AccessToken", "at-key"), suppressed_keys)
        self.assertEqual(_canonical(ab.merged), _canonical(ba.merged))

    def test_legacy_record_with_only_key_identity_is_suppressed(self):
        signed_out = {
            MERGE_METADATA_KEY: {"version": 1, "tombstones": [
                {"home_account_id": "bob.btenant", "environment": ENV,
                 "reason": "signed_out", "at": time.time()}]},
        }
        # Legacy token record omits identity fields; its key carries them.
        legacy_rt_key = "bob.btenant-" + ENV + "-refreshtoken-app--scope"
        stale = {"RefreshToken": {legacy_rt_key: {
            "credential_type": "RefreshToken", "secret": "legacy-rt"}}}
        report = merge_cache_states(signed_out, stale)
        self.assertNotIn(legacy_rt_key,
                         report.merged.get("RefreshToken", {}))
        self.assertIn(("RefreshToken", legacy_rt_key),
                      {(s.section, s.key) for s in report.suppressed})

    def test_clear_signout_allows_future_account_again(self):
        cache = SerializableTokenCache()
        cache.record_signout(home_account_id="bob.btenant", environment=ENV)
        self.assertEqual(1, len(cache.get_signout_tombstones()))
        removed = cache.clear_signout(
            home_account_id="bob.btenant", environment=ENV)
        self.assertEqual(1, removed)
        self.assertEqual([], cache.get_signout_tombstones())

    def test_fresh_account_write_lifts_tombstone(self):
        cache = SerializableTokenCache()
        cache.record_signout(home_account_id="bob.btenant", environment=ENV)
        # A new account write (successful sign-in) goes through modify().
        account = _account_entry("bob.btenant")
        cache.modify("Account", account, dict(account))
        self.assertEqual([], cache.get_signout_tombstones())


@patch(_OIDC_DISCOVERY, new=_OIDC_DISCOVERY_MOCK)
class OppositeOrderAcceptanceScenarioTests(unittest.TestCase):
    """The exact two-snapshot / reverse-order / silent-credential scenario."""

    def _populate(self, cache, uid, username, at_secret, rt_secret, now,
                  id_token=None):
        response_kwargs = dict(
            access_token=at_secret, expires_in=7200,
            refresh_token=rt_secret)
        if id_token is not None:
            response_kwargs["id_token"] = id_token
        cache.add({
            "client_id": CLIENT_ID,
            "scope": SCOPES,
            "token_endpoint": TOKEN_ENDPOINT,
            "data": {"username": username},
            "response": build_response(
                uid=uid + "-uid", utid=uid + "-utid", **response_kwargs),
        }, now=now)

    def _build_snapshots(self):
        now = int(time.time())
        alice_idt = build_id_token(
            sub="alice-sub", preferred_username="alice@example.com",
            exp=now + 86400, iat=now - 3600)

        base = SerializableTokenCache()
        self._populate(base, "alice", "alice@example.com",
                       "alice-at-base", "alice-rt-base", now - 3600,
                       id_token=alice_idt)
        self._populate(base, "bob", "bob@example.com",
                       "bob-at", "bob-rt", now - 3600)
        base_state = base.serialize()

        # Process A: descends from base, then confirms Bob sign-out.
        cache_a = SerializableTokenCache()
        cache_a.deserialize(base_state)
        bob_account = list(cache_a.search(
            "Account", query={"home_account_id": "bob-uid.bob-utid"}))[0]
        cache_a.remove_account(bob_account)
        cache_a._cache["RefreshToken"]["legacy-conflict-key"] = {
            "credential_type": "RefreshToken",
            "home_account_id": "legacy-uid.legacy-utid",
            "environment": ENV,
            "client_id": CLIENT_ID,
            "secret": "legacy-rt-in-a",
        }
        snapshot_a = cache_a.serialize()

        # Process B: stays stale about Bob but adds Carol and rotates Alice.
        cache_b = SerializableTokenCache()
        cache_b.deserialize(base_state)
        self._populate(cache_b, "carol", "carol@example.com",
                       "carol-at", "carol-rt", now)
        self._populate(cache_b, "alice", "alice@example.com",
                       "alice-at-rotated-in-b", "alice-rt-in-b", now,
                       id_token=alice_idt)
        cache_b._cache["RefreshToken"]["legacy-conflict-key"] = {
            "credential_type": "RefreshToken",
            "home_account_id": "legacy-uid.legacy-utid",
            "environment": ENV,
            "client_id": CLIENT_ID,
            "secret": "legacy-rt-in-b-different",
            "legacy_extra": True,
        }
        snapshot_b = cache_b.serialize()
        return snapshot_a, snapshot_b

    def _app(self, cache):
        # instance_discovery=False keeps get_accounts()/miss paths offline.
        return ClientApplication(
            CLIENT_ID, authority=AUTHORITY, token_cache=cache,
            instance_discovery=False)

    def test_reverse_order_comparison_and_silent_state(self):
        snapshot_a, snapshot_b = self._build_snapshots()

        # "Save" the two snapshots in opposite order by folding one into the
        # latest on-disk state in each direction.
        cache_ab = SerializableTokenCache()
        cache_ab.deserialize(snapshot_a)
        report_ab = cache_ab.safe_merge(snapshot_b)

        cache_ba = SerializableTokenCache()
        cache_ba.deserialize(snapshot_b)
        report_ba = cache_ba.safe_merge(snapshot_a)

        # 1) Merged state is identical regardless of save order.
        self.assertEqual(_canonical(cache_ab), _canonical(cache_ba))

        # 2) Login-able accounts agree: Alice + Carol, never Bob.
        def login_accounts(cache):
            app = self._app(cache)
            accounts = app.get_accounts()
            return sorted(a.get("username") for a in accounts), \
                sorted(a["home_account_id"] for a in accounts)

        names_ab, ids_ab = login_accounts(cache_ab)
        names_ba, ids_ba = login_accounts(cache_ba)
        self.assertEqual(["alice@example.com", "carol@example.com"], names_ab)
        self.assertEqual(names_ab, names_ba)
        self.assertEqual(ids_ab, ids_ba)
        self.assertNotIn("bob-uid.bob-utid", ids_ab)

        # 3) Independent new entries match across orders and include Carol.
        independent = lambda report: sorted(
            (item.section, item.key) for item in report.independent_entries)
        self.assertEqual(independent(report_ab), independent(report_ba))
        independent_keys = [key for _, key in independent(report_ab)]
        self.assertTrue(any("carol-uid.carol-utid" in k
                            for k in independent_keys))

        # 4) Conflict records match across orders and give a reason.
        conflict_ids = lambda report: sorted(
            (c.section, c.key, c.code) for c in report.conflicts)
        self.assertEqual(
            conflict_ids(report_ab), conflict_ids(report_ba))
        self.assertEqual(
            [("RefreshToken", "legacy-conflict-key",
              "undecidable_legacy_record")],
            conflict_ids(report_ab))
        self.assertTrue(report_ab.conflicts[0].reason)

        # The confirmed Bob sign-out produced an audit trail of withheld rows.
        self.assertTrue(any(
            item.get("home_account_id") == "bob-uid.bob-utid"
            for item in report_ab.suppressed))

        # 5) Silent credential acquisition reflects the merged state.
        def no_io(*args, **kwargs):
            raise AssertionError("No network/refresh I/O was expected")

        app = self._app(cache_ab)
        accounts = {a["username"]: a for a in app.get_accounts()}

        alice_result = app.acquire_token_silent(
            SCOPES, accounts["alice@example.com"], post=no_io)
        self.assertIsNotNone(alice_result)
        self.assertNotIn("error", alice_result)
        # The winning AT is the rotation that only existed in snapshot B.
        self.assertEqual("alice-at-rotated-in-b",
                         alice_result["access_token"])
        self.assertEqual(app._TOKEN_SOURCE_CACHE,
                         alice_result[app._TOKEN_SOURCE])

        carol_result = app.acquire_token_silent(
            SCOPES, accounts["carol@example.com"], post=no_io)
        self.assertEqual("carol-at", carol_result["access_token"])

        # Bob is not selectable and has no usable merged credentials.
        self.assertNotIn("bob@example.com", accounts)
        bob_result = app.acquire_token_silent(
            SCOPES, {"home_account_id": "bob-uid.bob-utid"}, post=no_io)
        self.assertIsNone(bob_result)

        # The reverse-order cache behaves identically for Alice.
        app_ba = self._app(cache_ba)
        alice_ba = [a for a in app_ba.get_accounts()
                    if a["username"] == "alice@example.com"][0]
        result_ba = app_ba.acquire_token_silent(
            SCOPES, alice_ba, post=no_io)
        self.assertEqual("alice-at-rotated-in-b", result_ba["access_token"])

    def test_same_file_read_merge_atomic_write_recipe(self):
        snapshot_a, snapshot_b = self._build_snapshots()
        tmpdir = tempfile.mkdtemp(prefix="msal-merge-")
        filename = os.path.join(tmpdir, "cache.bin")

        # Process A persists its snapshot (Bob signed out + tombstone).
        with open(filename, "w") as handle:
            handle.write(snapshot_a)

        # Process B independently wrote its stale-but-additive snapshot
        # elsewhere; the application now folds B into the latest file state.
        disk = SerializableTokenCache()
        with open(filename, "r") as handle:
            disk.deserialize(handle.read())
        report = disk.safe_merge(snapshot_b)
        self.assertTrue(disk.has_state_changed)
        self.assertEqual(1, len(report.conflicts))
        serialized = disk.serialize()  # serialize() resets has_state_changed
        tmp_name = filename + ".tmp"
        with open(tmp_name, "w") as handle:
            handle.write(serialized)
        os.replace(tmp_name, filename)

        # A fresh process reads the merged file and observes the right state.
        reopened = SerializableTokenCache()
        with open(filename, "r") as handle:
            reopened.deserialize(handle.read())
        app = self._app(reopened)
        accounts = {a["username"]: a for a in app.get_accounts()}
        self.assertEqual(
            ["alice@example.com", "carol@example.com"],
            sorted(accounts))
        self.assertNotIn("bob@example.com", accounts)
        result = app.acquire_token_silent(
            SCOPES, accounts["alice@example.com"],
            post=lambda *a, **k: (_ for _ in ()).throw(AssertionError("io")))
        self.assertEqual("alice-at-rotated-in-b", result["access_token"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
