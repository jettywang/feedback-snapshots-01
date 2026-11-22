import datetime
import os
import tempfile
import threading

from django.contrib.auth import get_user_model
from django.db import connections
from django.test import Client, TestCase, TransactionTestCase
from django.utils import timezone
from sesame.magiclink import (
    MagicLink,
    MagicLinkAlreadyConsumed,
    MagicLinkExpired,
    MagicLinkInvalid,
    MagicLinkNotFound,
    MagicLinkRevoked,
    MagicLinkUnavailable,
    claim_magic_link,
    consume_magic_link,
    hash_token,
    issue_magic_link,
    release_magic_link,
    resend_magic_link,
    revoke_magic_link,
)
from sesame.utils import get_parameters, get_token

from .mixins import CreateUserMixin
from .urls import MAGIC_LINK_SCOPE

User = get_user_model()


class TestMagicLinkServices(CreateUserMixin, TestCase):
    def test_issue_stores_only_token_hash(self):
        link, token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        self.assertEqual(link.status, MagicLink.ISSUED)
        self.assertEqual(link.scope, MAGIC_LINK_SCOPE)
        self.assertEqual(link.token_hash, hash_token(token))
        self.assertNotIn(token, link.token_hash)
        self.assertIsNone(link.claimed_at)
        self.assertIsNone(link.consumed_at)
        self.assertIsNone(link.revoked_at)

    def test_full_claim_then_consume_lifecycle(self):
        link, token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)

        claimed, claimed_user = claim_magic_link(token, MAGIC_LINK_SCOPE)
        self.assertEqual(claimed.pk, link.pk)
        self.assertEqual(str(claimed_user.pk), str(self.user.pk))
        claimed.refresh_from_db()
        self.assertEqual(claimed.status, MagicLink.CLAIMED)
        self.assertIsNotNone(claimed.claimed_at)

        consume_magic_link(claimed)
        claimed.refresh_from_db()
        self.assertEqual(claimed.status, MagicLink.CONSUMED)
        self.assertIsNotNone(claimed.consumed_at)

        with self.assertRaises(MagicLinkAlreadyConsumed):
            claim_magic_link(token, MAGIC_LINK_SCOPE)

    def test_second_claim_while_claimed_is_rejected(self):
        _link, token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        claim_magic_link(token, MAGIC_LINK_SCOPE)
        with self.assertRaises(MagicLinkUnavailable):
            claim_magic_link(token, MAGIC_LINK_SCOPE)

    def test_release_makes_link_available_again(self):
        link, token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        claimed, _claimed_user = claim_magic_link(token, MAGIC_LINK_SCOPE)
        release_magic_link(claimed)

        claimed.refresh_from_db()
        self.assertEqual(claimed.status, MagicLink.ISSUED)
        self.assertIsNone(claimed.claimed_at)

        again, _again_user = claim_magic_link(token, MAGIC_LINK_SCOPE)
        self.assertEqual(again.pk, link.pk)

    def test_unknown_token(self):
        with self.assertRaises(MagicLinkNotFound):
            claim_magic_link("does-not-exist", MAGIC_LINK_SCOPE)

    def test_token_from_another_scope_is_rejected(self):
        _link, token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        with self.assertRaises(MagicLinkNotFound):
            claim_magic_link(token, "other-scope")
        # The link was never touched.
        self.assertEqual(MagicLink.objects.get().status, MagicLink.ISSUED)

    def test_invalid_token_after_password_change_releases_claim(self):
        link, token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        self.user.set_password("new-password")
        self.user.save()

        with self.assertRaises(MagicLinkInvalid):
            claim_magic_link(token, MAGIC_LINK_SCOPE)

        link.refresh_from_db()
        self.assertEqual(link.status, MagicLink.ISSUED)
        self.assertIsNone(link.claimed_at)
        self.assertIsNone(link.consumed_at)

    def test_expired_link_is_rejected_without_state_change(self):
        link, token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        link.expires_at = timezone.now() - datetime.timedelta(seconds=1)
        link.save(update_fields=["expires_at"])

        with self.assertRaises(MagicLinkExpired):
            claim_magic_link(token, MAGIC_LINK_SCOPE)
        link.refresh_from_db()
        self.assertEqual(link.status, MagicLink.ISSUED)
        self.assertIsNone(link.claimed_at)

    def test_max_age_sets_expiry(self):
        link, _token = issue_magic_link(self.user, MAGIC_LINK_SCOPE, max_age=60)
        self.assertIsNotNone(link.expires_at)
        self.assertGreater(link.expires_at, timezone.now())

    def test_revoked_link_is_rejected(self):
        link, token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        self.assertTrue(revoke_magic_link(link))

        link.refresh_from_db()
        self.assertEqual(link.status, MagicLink.REVOKED)
        self.assertIsNotNone(link.revoked_at)
        with self.assertRaises(MagicLinkRevoked):
            claim_magic_link(token, MAGIC_LINK_SCOPE)

    def test_consumed_and_revoked_states_remain_distinct(self):
        consumed_link, consumed_token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        claimed, _claimed_user = claim_magic_link(consumed_token, MAGIC_LINK_SCOPE)
        consume_magic_link(claimed)

        revoked_link, _revoked_token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        self.assertTrue(revoke_magic_link(revoked_link))

        # A consumed link cannot be turned into a revoked one.
        self.assertFalse(revoke_magic_link(consumed_link))
        consumed_link.refresh_from_db()
        revoked_link.refresh_from_db()
        self.assertEqual(consumed_link.status, MagicLink.CONSUMED)
        self.assertEqual(revoked_link.status, MagicLink.REVOKED)
        self.assertIsNone(consumed_link.revoked_at)
        self.assertIsNone(revoked_link.consumed_at)

    def test_resend_revokes_previous_link_and_issues_a_new_one(self):
        first_link, first_token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        second_link, second_token = resend_magic_link(self.user, MAGIC_LINK_SCOPE)

        first_link.refresh_from_db()
        second_link.refresh_from_db()
        self.assertEqual(first_link.status, MagicLink.REVOKED)
        self.assertIsNotNone(first_link.revoked_at)
        self.assertEqual(second_link.status, MagicLink.ISSUED)
        self.assertNotEqual(first_token, second_token)

        with self.assertRaises(MagicLinkRevoked):
            claim_magic_link(first_token, MAGIC_LINK_SCOPE)
        claimed, _claimed_user = claim_magic_link(second_token, MAGIC_LINK_SCOPE)
        self.assertEqual(claimed.pk, second_link.pk)

    def test_consumed_link_survives_resend(self):
        first_link, first_token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        first_claimed, _first_user = claim_magic_link(first_token, MAGIC_LINK_SCOPE)
        consume_magic_link(first_claimed)
        _second_link, _second_token = resend_magic_link(self.user, MAGIC_LINK_SCOPE)

        first_link.refresh_from_db()
        self.assertEqual(first_link.status, MagicLink.CONSUMED)
        with self.assertRaises(MagicLinkAlreadyConsumed):
            claim_magic_link(first_token, MAGIC_LINK_SCOPE)


class TestMagicLinkView(CreateUserMixin, TestCase):
    def login_url(self, token):
        return f"/magic-link/login/?sesame={token}"

    def test_success_creates_session_and_consumes_link(self):
        link, token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)

        response = self.client.get(self.login_url(token))

        self.assertRedirects(response, "/login/redirect/url/")
        self.assertEqual(response.wsgi_request.user, self.user)
        self.assertEqual(self.client.session.get("_auth_user_id"), str(self.user.pk))
        link.refresh_from_db()
        self.assertEqual(link.status, MagicLink.CONSUMED)
        self.assertIsNotNone(link.consumed_at)

    def test_success_without_redirect(self):
        _link, token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        response = self.client.get(f"/magic-link/login/no_redirect/?sesame={token}")
        self.assertEqual(response.status_code, 204)

    def test_same_link_cannot_create_a_second_session(self):
        _link, token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        first = self.client.get(self.login_url(token))
        self.assertEqual(first.status_code, 302)

        second_client = Client()
        second = second_client.get(self.login_url(token))
        self.assertEqual(second.status_code, 403)
        self.assertNotIn("_auth_user_id", second_client.session)
        self.assertEqual(MagicLink.objects.filter(status=MagicLink.CONSUMED).count(), 1)

    def test_missing_token_is_forbidden(self):
        response = self.client.get("/magic-link/login/")
        self.assertEqual(response.status_code, 403)
        self.assertFalse(MagicLink.objects.exists())

    def test_unknown_token_is_forbidden_and_consumes_nothing(self):
        response = self.client.get(self.login_url("bogus-token"))
        self.assertEqual(response.status_code, 403)
        self.assertFalse(MagicLink.objects.filter(status=MagicLink.CONSUMED).exists())

    def test_pre_login_failure_releases_link_which_stays_usable(self):
        link, token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        self.user.set_password("new-password")
        self.user.save()

        response = self.client.get(self.login_url(token))
        self.assertEqual(response.status_code, 403)
        link.refresh_from_db()
        self.assertEqual(link.status, MagicLink.ISSUED)
        self.assertIsNone(link.claimed_at)

    def test_revoked_link_is_forbidden(self):
        link, token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        revoke_magic_link(link)
        response = self.client.get(self.login_url(token))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(MagicLink.objects.filter(status=MagicLink.CONSUMED).count(), 0)

    def test_expired_link_is_forbidden(self):
        link, token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        link.expires_at = timezone.now() - datetime.timedelta(seconds=1)
        link.save(update_fields=["expires_at"])

        response = self.client.get(self.login_url(token))
        self.assertEqual(response.status_code, 403)
        link.refresh_from_db()
        self.assertEqual(link.status, MagicLink.ISSUED)

    def test_resend_old_link_fails_new_link_succeeds(self):
        _first_link, first_token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        _second_link, second_token = resend_magic_link(self.user, MAGIC_LINK_SCOPE)

        old_response = self.client.get(self.login_url(first_token))
        self.assertEqual(old_response.status_code, 403)

        new_response = self.client.get(self.login_url(second_token))
        self.assertEqual(new_response.status_code, 302)
        self.assertEqual(self.client.session.get("_auth_user_id"), str(self.user.pk))
        self.assertEqual(MagicLink.objects.filter(status=MagicLink.CONSUMED).count(), 1)
        self.assertEqual(MagicLink.objects.filter(status=MagicLink.REVOKED).count(), 1)


class TestScopeIsolation(CreateUserMixin, TestCase):
    def test_default_scope_login_view_still_stateless(self):
        params = get_parameters(self.user)
        response = self.client.get("/login/", params)
        self.assertEqual(response.status_code, 302)
        # The stateless flow never creates a MagicLink row.
        self.assertFalse(MagicLink.objects.exists())

    def test_magic_link_token_rejected_by_default_scope_view(self):
        _link, token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)
        response = self.client.get(f"/login/?sesame={token}")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(MagicLink.objects.get().status, MagicLink.ISSUED)

    def test_default_scope_token_rejected_by_magic_link_view(self):
        token = get_token(self.user)
        response = self.client.get(f"/magic-link/login/?sesame={token}")
        self.assertEqual(response.status_code, 403)
        self.assertFalse(MagicLink.objects.exists())

    def test_other_scoped_decorator_still_works(self):
        token = get_token(self.user, scope="scope")
        response = self.client.get(f"/authenticate/scope/?sesame={token}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), str(self.user))


class TestConcurrentMagicLink(TransactionTestCase):
    """
    Race conditions need a real, file-based SQLite database: the default
    in-memory test database gives every thread its own private database, while
    a shared file lets all contenders hit the same rows and locks.

    A runtime alias (``magiclink_file``) is created on a fresh file, untouched
    by the test runner, and :class:`~tests.db_routers.MagicLinkRouter` sends
    MagicLink queries to it only while these tests run.

    """

    # The magiclink_file alias is declared in tests/settings.py but repointed
    # at a fresh file in setUp; it must be listed here so Django permits
    # threaded connections to it.
    databases = {"default", "magiclink_file"}

    def setUp(self):
        super().setUp()
        self.user = User.objects.using("default").create(username="john")

        _fd, db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(_fd)
        os.unlink(db_path)
        # On macOS /tmp is a symlink to /private/tmp; SQLite opens the resolved
        # path, so use the canonical path to keep all threads on one file.
        self.db_path = os.path.realpath(db_path)

        from . import db_routers

        file_db = connections[db_routers.FILE_DB_ALIAS]
        # Drop the (possibly in-memory) connection left over from a previous
        # test and forget the cached wrapper, so changing NAME below really
        # opens the fresh file instead of reusing an old connection.
        file_db.close()
        del connections[db_routers.FILE_DB_ALIAS]
        file_db = connections[db_routers.FILE_DB_ALIAS]
        # TEST.MIGRATE keeps the runner from turning this alias into an
        # in-memory database, so the file connection reaches every worker.
        file_db.settings_dict["NAME"] = self.db_path
        file_db.settings_dict["OPTIONS"] = {}
        # Only the MagicLink table is needed for these tests.
        with file_db.schema_editor() as schema_editor:
            schema_editor.create_model(MagicLink)
        self.assertGreater(os.path.getsize(self.db_path), 0)

        db_routers.FILE_DB_ACTIVE = True
        self.link, self.token = issue_magic_link(self.user, MAGIC_LINK_SCOPE)

    def tearDown(self):
        from . import db_routers

        db_routers.FILE_DB_ACTIVE = False
        connections.close_all()
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)
        super().tearDown()

    def test_only_one_concurrent_claim_wins(self):
        contenders = 8
        barrier = threading.Barrier(contenders)
        results = []
        results_lock = threading.Lock()

        def contender():
            barrier.wait()
            try:
                link, _user = claim_magic_link(self.token, MAGIC_LINK_SCOPE)
            except Exception as exc:
                outcome = ("error", type(exc).__name__, str(exc)[:40])
            else:
                outcome = ("won", link.pk)
            with results_lock:
                results.append(outcome)
            connections.close_all()

        threads = [threading.Thread(target=contender) for _ in range(contenders)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        winners = [outcome for outcome in results if outcome[0] == "won"]
        self.assertEqual(len(winners), 1, msg=results)
        self.link.refresh_from_db()
        self.assertEqual(self.link.status, MagicLink.CLAIMED)
        self.assertIsNotNone(self.link.claimed_at)

    def test_only_one_concurrent_request_gets_a_session(self):
        contenders = 8
        barrier = threading.Barrier(contenders)
        statuses = []
        sessions = []
        results_lock = threading.Lock()

        def contender():
            client = Client()
            barrier.wait()
            response = client.get(f"/magic-link/login/?sesame={self.token}")
            authenticated = "_auth_user_id" in client.session
            with results_lock:
                statuses.append(response.status_code)
                sessions.append(authenticated)
            connections.close_all()

        threads = [threading.Thread(target=contender) for _ in range(contenders)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(statuses.count(302), 1)
        self.assertEqual(sum(sessions), 1)
        self.link.refresh_from_db()
        self.assertEqual(self.link.status, MagicLink.CONSUMED)
