"""Executable compatibility matrix for using TokenVerifyView as an admission check.

Tokens are issued exactly the way each deployment issues them, then the same
credential is sent to three places:

* the standalone ``/token/verify/`` endpoint,
* a protected API view using ``JWTAuthentication``,
* the refresh endpoint that belongs to the deployment.

The tests assert observed status/body and print Markdown tables.  They are
diagnostic: they document where verify is *not* equivalent to admission.
"""

import json
from dataclasses import dataclass
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from rest_framework_simplejwt.backends import TokenBackend
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.token_blacklist.models import (
    BlacklistedToken,
    OutstandingToken,
)
from rest_framework_simplejwt.tokens import (
    AccessToken,
    RefreshToken,
    SlidingToken,
    UntypedToken,
)

from .utils import override_api_settings
from .verify_support import ServiceAccessToken, ServiceRefreshToken

User = get_user_model()

PROFILES = {
    "access": ("rest_framework_simplejwt.tokens.AccessToken",),
    "sliding": ("rest_framework_simplejwt.tokens.SlidingToken",),
    "custom": ("tests.verify_support.ServiceAccessToken",),
}

PASSWORD = "matrix-password"


def normalize(value):
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalize(item) for item in value]
    return str(value)


def body(res):
    return json.dumps(normalize(res.data), ensure_ascii=False, sort_keys=True)


def verify_label(res):
    if res.status_code == 200:
        return "200 {}"
    if res.status_code == 400 and "non_field_errors" in res.data:
        return f"400 {res.data['non_field_errors'][0]}"
    if res.status_code == 400 and "token" in res.data:
        return f"400 {res.data['token'][0]}"
    if "detail" in res.data:
        return f"{res.status_code} {res.data['detail']}"
    return f"{res.status_code} {body(res)}"


def api_label(res):
    if res.status_code == 200:
        return f"200 subject={res.data.get('subject')}"
    detail = res.data.get("detail") if isinstance(res.data, dict) else None
    return f"{res.status_code} {detail or body(res)}"


def refresh_label(res, field):
    if res.status_code != 200:
        detail = res.data.get("detail") if isinstance(res.data, dict) else None
        return f"{res.status_code} {detail or body(res)}"
    token = res.data.get("access") or res.data.get("token")
    if not token:
        return f"200 {body(res)}"
    claim = api_settings.USER_ID_CLAIM
    subject = UntypedToken(token).get(claim, "no subject")
    return f"200 new-token subject={subject}"


@dataclass
class Row:
    credential: str
    enabled: str
    revocation: str
    verify: str
    verify_subject: str
    api: str
    api_subject: str
    refresh: str
    refresh_subject: str


@override_settings(ROOT_URLCONF="tests.verify_urls")
class VerifyCompatibilityMatrix(TestCase):
    """Cross-product matrix; run with ``pytest -s`` to print the tables."""

    maxDiff = None

    def setUp(self):
        self.client = APIClient()
        self.rows = []

    def make_user(self, username, staff=False):
        return User.objects.create_user(
            username=username, password=PASSWORD, is_staff=staff
        )

    def obtain_access(self, user, password=PASSWORD):
        res = self.client.post(
            reverse("token_obtain_pair"),
            {"username": user.username, "password": password},
        )
        self.assertEqual(res.status_code, 200, body(res))
        return res.data["access"], res.data["refresh"]

    def obtain_sliding(self, user):
        res = self.client.post(
            reverse("token_obtain_sliding"),
            {"username": user.username, "password": PASSWORD},
        )
        self.assertEqual(res.status_code, 200, body(res))
        return res.data["token"]

    def obtain_custom(self, user):
        res = self.client.post(
            reverse("token_custom_pair"),
            {"username": user.username, "password": PASSWORD},
        )
        self.assertEqual(res.status_code, 200, body(res))
        return res.data["access"], res.data["refresh"]

    def probe(
        self,
        token,
        *,
        credential,
        enabled,
        refresh_view,
        refresh_field,
        revocation="fresh",
        check_revoke=False,
        blacklist_after_rotation=True,
    ):
        """Send one token to verify, protected API and its refresh entry."""
        with override_api_settings(
            AUTH_TOKEN_CLASSES=PROFILES[enabled],
            CHECK_REVOKE_TOKEN=check_revoke,
            BLACKLIST_AFTER_ROTATION=blacklist_after_rotation,
        ):
            verify = self.client.post(reverse("token_verify"), {"token": token})
            api = self.client.get(
                reverse("protected"), HTTP_AUTHORIZATION=f"Bearer {token}"
            )
            refresh = self.client.post(
                reverse(refresh_view), {refresh_field: token}
            )

        row = Row(
            credential=credential,
            enabled=enabled,
            revocation=revocation,
            verify=verify_label(verify),
            verify_subject="not resolved",
            api=api_label(api),
            api_subject=api.data.get("subject") if api.status_code == 200 else "-",
            refresh=refresh_label(refresh, refresh_field),
            refresh_subject="-",
        )
        if refresh.status_code == 200:
            field = "token" if refresh_view == "token_refresh_sliding" else "access"
            minted = refresh.data.get(field)
            if minted:
                row.refresh_subject = UntypedToken(minted).get(
                    api_settings.USER_ID_CLAIM, "no subject"
                )
        self.rows.append(row)
        return verify, api, refresh

    def assert_verify(self, res, status=200, text=None):
        self.assertEqual(res.status_code, status, body(res))
        if status == 200:
            self.assertEqual(res.data, {})
        elif text is not None:
            self.assertIn(text, str(res.data))

    def assert_api(self, res, status, subject=None, detail=None):
        self.assertEqual(res.status_code, status, body(res))
        if subject is not None:
            self.assertEqual(res.data.get("subject"), subject)
        if detail is not None:
            self.assertIn(detail, str(res.data))

    def assert_refresh(self, res, status, detail=None):
        self.assertEqual(res.status_code, status, body(res))
        if detail is not None:
            self.assertIn(detail, str(res.data))

    def dump(self, title, rows):
        print(f"\n### {title}\n")
        print(
            "| credential | enabled class | revocation | verify "
            "| API subject resolved | protected API "
            "| refresh entry | refresh subject |"
        )
        print("|---|---|---|---|---|---|---|---|")
        for row in rows:
            print(
                f"| {row.credential} | {row.enabled} | {row.revocation} "
                f"| {row.verify} | {row.verify_subject} "
                f"| {row.api} | {row.refresh} | {row.refresh_subject} |"
            )

    def test_cross_enabled_class_matrix(self):
        """One issued credential x three enabled classes, no state changes."""
        user = self.make_user("matrix-user")
        access, access_refresh = self.obtain_access(user)
        sliding = self.obtain_sliding(user)
        custom_access, custom_refresh = self.obtain_custom(user)

        tokens = [
            ("access token", access, "token_refresh", "refresh", "access", False),
            ("refresh token", access_refresh, "token_refresh", "refresh", "access", True),
            ("sliding token", sliding, "token_refresh_sliding", "token", "sliding", True),
            ("custom access token", custom_access, "token_custom_refresh", "refresh", "custom", False),
            ("custom refresh token", custom_refresh, "token_custom_refresh", "refresh", "custom", True),
        ]

        for label, token, view, field, home, is_refresh_credential in tokens:
            for enabled in PROFILES:
                with self.subTest(token=label, enabled=enabled):
                    verify, api, refresh = self.probe(
                        token,
                        credential=label,
                        enabled=enabled,
                        refresh_view=view,
                        refresh_field=field,
                    )
                    self.assert_verify(verify)
                    if is_refresh_credential:
                        self.assert_refresh(refresh, 200)
                        self.assertEqual(self.rows[-1].refresh_subject, str(user.pk))
                    else:
                        self.assert_refresh(refresh, 401, detail="Token has wrong type")
                    auth_capable = label in (
                        "access token",
                        "sliding token",
                        "custom access token",
                    )
                    if enabled == home and auth_capable:
                        self.assert_api(api, 200, subject=str(user.pk))
                    else:
                        self.assert_api(api, 401, detail="not valid for any token type")

        self.dump("Cross enabled class (same credential in all three gates)", self.rows)

    def test_verify_is_type_blind_revocation_blind(self):
        """Verify accepts refresh/custom types that the API rejects."""
        user = self.make_user("blind-user")
        access, refresh = self.obtain_access(user)
        custom_access, custom_refresh = self.obtain_custom(user)

        blind = [
            ("refresh token", refresh, "access"),
            ("custom access token", custom_access, "access"),
            ("custom refresh token", custom_refresh, "access"),
        ]
        for label, token, enabled in blind:
            with self.subTest(token=label):
                verify, api, _ = self.probe(
                    token,
                    credential=label,
                    enabled=enabled,
                    refresh_view="token_refresh",
                    refresh_field="refresh",
                )
                self.assert_verify(verify)
                self.assert_api(api, 401, detail="not valid for any token type")

        self.columns = self.rows
        self.dump("Verify is type-blind (API enabled class = access)", self.rows)

    def test_blacklist_matrix(self):
        """Blacklist is enforced differently by verify, API and refresh."""
        user = self.make_user("blacklist-user")
        access, refresh = self.obtain_access(user)
        sliding = self.obtain_sliding(user)
        custom_access, custom_refresh = self.obtain_custom(user)

        # Standard access pair: blacklist the refresh half via the normal view.
        res = self.client.post(reverse("token_blacklist"), {"refresh": refresh})
        self.assertEqual(res.status_code, 200, body(res))

        verify, api, refresh_res = self.probe(
            refresh,
            credential="refresh token",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="refresh blacklisted",
        )
        self.assert_verify(verify, 400, "Token is blacklisted")
        self.assert_api(api, 401, detail="not valid for any token type")
        self.assert_refresh(refresh_res, 401, detail="Token is blacklisted")

        verify, api, refresh_res = self.probe(
            access,
            credential="access token (same pair)",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="refresh half blacklisted",
        )
        self.assert_verify(verify)
        self.assert_api(api, 200, subject=str(user.pk))
        self.assert_refresh(refresh_res, 401, detail="Token has wrong type")

        # Same blacklisted refresh token with BLACKLIST_AFTER_ROTATION=False.
        verify, api, refresh_res = self.probe(
            refresh,
            credential="refresh token",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="refresh blacklisted, BAR=False",
            blacklist_after_rotation=False,
        )
        self.assert_verify(verify)
        self.assert_refresh(refresh_res, 401, detail="Token is blacklisted")

        # Sliding: the auth credential is also the refresh credential.
        SlidingToken(sliding).blacklist()
        verify, api, refresh_res = self.probe(
            sliding,
            credential="sliding token",
            enabled="sliding",
            refresh_view="token_refresh_sliding",
            refresh_field="token",
            revocation="sliding blacklisted",
        )
        self.assert_verify(verify, 400, "Token is blacklisted")
        self.assert_api(api, 401, detail="Token is blacklisted")
        self.assert_refresh(refresh_res, 401, detail="Token is blacklisted")

        verify, api, refresh_res = self.probe(
            sliding,
            credential="sliding token",
            enabled="sliding",
            refresh_view="token_refresh_sliding",
            refresh_field="token",
            revocation="sliding blacklisted, BAR=False",
            blacklist_after_rotation=False,
        )
        self.assert_verify(verify)
        self.assert_api(api, 401, detail="Token is blacklisted")
        self.assert_refresh(refresh_res, 401, detail="Token is blacklisted")

        # Custom pair: blacklist the refresh half; the access half is unaffected.
        ServiceRefreshToken(custom_refresh).blacklist()
        verify, api, refresh_res = self.probe(
            custom_refresh,
            credential="custom refresh token",
            enabled="custom",
            refresh_view="token_custom_refresh",
            refresh_field="refresh",
            revocation="custom refresh blacklisted",
        )
        self.assert_verify(verify, 400, "Token is blacklisted")
        self.assert_api(api, 401, detail="not valid for any token type")
        self.assert_refresh(refresh_res, 401, detail="Token is blacklisted")

        verify, api, refresh_res = self.probe(
            custom_access,
            credential="custom access token (same pair)",
            enabled="custom",
            refresh_view="token_custom_refresh",
            refresh_field="refresh",
            revocation="custom refresh half blacklisted",
        )
        self.assert_verify(verify)
        self.assert_api(api, 200, subject=str(user.pk))
        self.assert_refresh(refresh_res, 401, detail="Token has wrong type")

        self.dump("Blacklist matrix", self.rows)

    def test_access_blacklist_row_is_asymmetric(self):
        """Verify rejects an access jti placed on the blacklist; the API ignores it."""
        user = self.make_user("access-row-user")
        access, refresh = self.obtain_access(user)
        token = AccessToken(access)
        outstanding = OutstandingToken.objects.create(
            user=user,
            jti=token["jti"],
            token=access,
            expires_at=token.current_time + timedelta(days=1),
        )
        BlacklistedToken.objects.create(token=outstanding)

        verify, api, refresh_res = self.probe(
            access,
            credential="access token",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="access jti blacklisted (manual row)",
        )
        self.assert_verify(verify, 400, "Token is blacklisted")
        self.assert_api(api, 200, subject=str(user.pk))
        # BlacklistMixin.verify() runs before the token-type check, so the
        # refresh endpoint reports the blacklist first even for a wrong type.
        self.assert_refresh(refresh_res, 401, detail="Token is blacklisted")

        verify, api, refresh_res = self.probe(
            refresh,
            credential="refresh token (same pair)",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="access jti blacklisted (manual row)",
        )
        self.assert_verify(verify)
        self.assert_refresh(refresh_res, 200)

        self.dump("Access-token blacklist asymmetry", self.rows)

    def test_subject_gate_matrix(self):
        """Verify never resolves the subject; API and refresh do (or reject)."""
        user = self.make_user("subject-user")
        access, refresh = self.obtain_access(user)

        # Fresh baseline, both halves.
        verify, api, _ = self.probe(
            access,
            credential="access token",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
        )
        self.assert_verify(verify)
        self.assert_api(api, 200, subject=str(user.pk))

        verify, api, refresh_res = self.probe(
            refresh,
            credential="refresh token",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
        )
        self.assert_verify(verify)
        self.assert_api(api, 401, detail="not valid for any token type")
        self.assert_refresh(refresh_res, 200)

        # Inactive user.
        user.is_active = False
        user.save()
        verify, api, _ = self.probe(
            access,
            credential="access token",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="user inactive",
        )
        self.assert_verify(verify)
        self.assert_api(api, 401, detail="User is inactive")

        verify, api, refresh_res = self.probe(
            refresh,
            credential="refresh token",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="user inactive",
        )
        self.assert_verify(verify)
        self.assert_refresh(refresh_res, 401, detail="No active account")
        user.is_active = True
        user.save()

        # Deleted user.
        user.delete()
        verify, api, _ = self.probe(
            access,
            credential="access token",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="user deleted",
        )
        self.assert_verify(verify)
        self.assert_api(api, 401, detail="User not found")

        verify, api, refresh_res = self.probe(
            refresh,
            credential="refresh token",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="user deleted",
        )
        self.assert_verify(verify)
        self.assert_refresh(refresh_res, 401, detail="No active account")

        self.dump("Subject gate matrix", self.rows)

    def test_revocation_switch_matrix(self):
        """CHECK_REVOKE_TOKEN is invisible to verify but gates API and refresh."""
        # Legacy token, issued before the deployment turns revocation on.
        legacy_user = self.make_user("legacy-user")
        legacy_access, legacy_refresh = self.obtain_access(legacy_user)

        verify, api, _ = self.probe(
            legacy_access,
            credential="access token (pre-switch)",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="issued before CHECK_REVOKE_TOKEN=True",
            check_revoke=True,
        )
        self.assert_verify(verify)
        self.assert_api(api, 401, detail="password has been changed")

        verify, api, refresh_res = self.probe(
            legacy_refresh,
            credential="refresh token (pre-switch)",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="issued before CHECK_REVOKE_TOKEN=True",
            check_revoke=True,
        )
        self.assert_verify(verify)
        self.assert_refresh(refresh_res, 401, detail="password has been changed")

        # Token issued with the switch on, then password changed.
        revoke_user = self.make_user("revoke-user")
        with override_api_settings(CHECK_REVOKE_TOKEN=True):
            revoke_access, revoke_refresh = self.obtain_access(revoke_user)
        revoke_user.set_password("new-" + PASSWORD)
        revoke_user.save()

        verify, api, _ = self.probe(
            revoke_access,
            credential="access token (hash claim present)",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="password changed",
            check_revoke=True,
        )
        self.assert_verify(verify)
        self.assert_api(api, 401, detail="password has been changed")

        verify, api, refresh_res = self.probe(
            revoke_refresh,
            credential="refresh token (hash claim present)",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="password changed",
            check_revoke=True,
        )
        self.assert_verify(verify)
        self.assert_refresh(refresh_res, 401, detail="password has been changed")

        # Same password change, switch off: all three gates agree.
        no_revoke_access, no_revoke_refresh = self.obtain_access(
            revoke_user, "new-" + PASSWORD
        )
        verify, api, _ = self.probe(
            no_revoke_access,
            credential="access token",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="password changed, CHECK_REVOKE_TOKEN=False",
        )
        self.assert_verify(verify)
        self.assert_api(api, 200, subject=str(revoke_user.pk))

        verify, api, refresh_res = self.probe(
            no_revoke_refresh,
            credential="refresh token",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="password changed, CHECK_REVOKE_TOKEN=False",
        )
        self.assert_verify(verify)
        self.assert_refresh(refresh_res, 200)

        self.dump("Revocation switch matrix", self.rows)

    def test_subjectless_and_wrong_signature(self):
        """Verify accepts subjectless tokens; it does check the signature."""
        user = self.make_user("signature-user")

        empty_refresh = RefreshToken()
        empty_access = empty_refresh.access_token

        verify, api, _ = self.probe(
            str(empty_access),
            credential="access token without user_id",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="no user_id claim",
        )
        self.assert_verify(verify)
        self.assert_api(api, 401, detail="no recognizable user identification")

        verify, api, refresh_res = self.probe(
            str(empty_refresh),
            credential="refresh token without user_id",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="no user_id claim",
        )
        self.assert_verify(verify)
        self.assert_refresh(refresh_res, 200)
        self.assertEqual(self.rows[-1].refresh_subject, "no subject")

        legit_access, legit_refresh = self.obtain_access(user)
        wrong_key = TokenBackend("HS256", "definitely-not-the-signing-key").encode(
            AccessToken(legit_access).payload
        )
        verify, api, _ = self.probe(
            wrong_key,
            credential="access token",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="signed with wrong key",
        )
        self.assert_verify(verify, 401, "Token is invalid")
        self.assert_api(api, 401, detail="not valid for any token type")

        verify, api, refresh_res = self.probe(
            legit_refresh,
            credential="refresh token (same pair)",
            enabled="access",
            refresh_view="token_refresh",
            refresh_field="refresh",
            revocation="access signed with wrong key",
        )
        self.assert_verify(verify)
        self.assert_refresh(refresh_res, 200)

        self.dump("Subjectless and signature", self.rows)

    def test_sliding_window_asymmetry(self):
        """Verify uses exp; refresh checks exp first, then refresh_exp."""
        user = self.make_user("sliding-window-user")
        sliding = self.obtain_sliding(user)

        auth_expired = SlidingToken(sliding)
        auth_expired.set_exp(lifetime=-timedelta(seconds=1))
        verify, api, refresh_res = self.probe(
            str(auth_expired),
            credential="sliding token",
            enabled="sliding",
            refresh_view="token_refresh_sliding",
            refresh_field="token",
            revocation="auth exp expired, refresh_exp open",
        )
        self.assert_verify(verify, 401, "Token is expired")
        self.assert_api(api, 401, detail="not valid for any token type")
        self.assert_refresh(refresh_res, 401, detail="Token is expired")

        refresh_expired = SlidingToken(sliding)
        refresh_expired.set_exp(
            api_settings.SLIDING_TOKEN_REFRESH_EXP_CLAIM,
            lifetime=-timedelta(seconds=1),
        )
        verify, api, refresh_res = self.probe(
            str(refresh_expired),
            credential="sliding token",
            enabled="sliding",
            refresh_view="token_refresh_sliding",
            refresh_field="token",
            revocation="auth exp open, refresh_exp expired",
        )
        self.assert_verify(verify)
        self.assert_api(api, 200, subject=str(user.pk))
        self.assert_refresh(refresh_res, 401, detail="refresh_exp")

        self.dump("Sliding window asymmetry", self.rows)

    def test_permission_decision_remains_external(self):
        """A 200 from verify says nothing about staff/permission state."""
        user = self.make_user("plain-user")
        access, _ = self.obtain_access(user)

        with override_api_settings(AUTH_TOKEN_CLASSES=PROFILES["access"]):
            verify = self.client.post(reverse("token_verify"), {"token": access})
            api = self.client.get(
                reverse("admin_only"), HTTP_AUTHORIZATION=f"Bearer {access}"
            )
        self.assert_verify(verify)
        self.assertEqual(api.status_code, 403, body(api))
        self.assertIn("permission", str(api.data).lower())
        self.rows.append(
            Row(
                credential="non-staff access",
                enabled="access",
                revocation="fresh",
                verify=verify_label(verify),
                verify_subject="not resolved",
                api=api_label(api),
                api_subject="-",
                refresh="-",
                refresh_subject="-",
            )
        )

        # Stateless authentication trusts token claims; a forged claim is honoured.
        staff_token = AccessToken.for_user(user)
        staff_token["is_staff"] = True
        with override_api_settings(AUTH_TOKEN_CLASSES=PROFILES["access"]):
            verify = self.client.post(reverse("token_verify"), {"token": str(staff_token)})
            api = self.client.get(
                reverse("admin_only_stateless"),
                HTTP_AUTHORIZATION=f"Bearer {staff_token}",
            )
        self.assert_verify(verify)
        self.assert_api(api, 200, subject=str(user.pk))
        self.rows.append(
            Row(
                credential="is_staff claim, DB user is not staff",
                enabled="access",
                revocation="fresh",
                verify=verify_label(verify),
                verify_subject="not resolved",
                api=api_label(api),
                api_subject=api.data.get("subject"),
                refresh="-",
                refresh_subject="-",
            )
        )

        self.dump("Permission decision", self.rows)

    def test_nonexistent_jti_claim_in_refresh_is_a_500(self):
        """A refresh issued before JTI_CLAIM was renamed crashes the refresh view."""
        user = self.make_user("jti-switch-user")
        access, refresh = self.obtain_access(user)

        with override_api_settings(JTI_CLAIM="jti2"):
            verify = self.client.post(reverse("token_verify"), {"token": access})
            api = self.client.get(
                reverse("protected"), HTTP_AUTHORIZATION=f"Bearer {access}"
            )
            self.assert_verify(verify, 401, "Token has no id")
            self.assert_api(api, 401, detail="Token has no id")

            # BlacklistMixin.check_blacklist indexes JTI_CLAIM directly, so
            # the refresh view raises instead of returning 401.
            with self.assertRaises(KeyError) as caught:
                self.client.post(reverse("token_refresh"), {"refresh": refresh})
            self.assertEqual(caught.exception.args, ("jti2",))
            # Django's test client latches the last request exception.
            self.client.exc_info = None

        # JTI_CLAIM=None is even worse with the blacklist app installed: any
        # refresh (including a freshly issued one) raises KeyError(None).
        fresh_access, fresh_refresh = self.obtain_access(user)
        with override_api_settings(JTI_CLAIM=None):
            self.assert_verify(
                self.client.post(reverse("token_verify"), {"token": fresh_access})
            )
            self.assert_api(
                self.client.get(
                    reverse("protected"), HTTP_AUTHORIZATION=f"Bearer {fresh_access}"
                ),
                200,
                subject=str(user.pk),
            )
            with self.assertRaises(KeyError) as caught:
                self.client.post(
                    reverse("token_refresh"), {"refresh": fresh_refresh}
                )
            self.assertEqual(caught.exception.args, (None,))
            self.client.exc_info = None

        self.dump(
            "JTI_CLAIM rename / disable (tokens issued before the switch)",
            [
                Row(
                    credential="access token",
                    enabled="access",
                    revocation='JTI_CLAIM="jti2"',
                    verify="401 Token has no id",
                    verify_subject="not resolved",
                    api="401 token_not_valid (Token has no id)",
                    api_subject="-",
                    refresh="500 KeyError('jti2')",
                    refresh_subject="-",
                ),
                Row(
                    credential="access token",
                    enabled="access",
                    revocation="JTI_CLAIM=None, blacklist app installed",
                    verify="200 {}",
                    verify_subject="not resolved",
                    api="200 subject=1",
                    api_subject="1",
                    refresh="500 KeyError(None)",
                    refresh_subject="-",
                ),
            ],
        )

    def test_late_enable_blacklist_check_after_startup(self):
        """Enabling BLACKLIST_AFTER_ROTATION in-process can NameError in verify."""
        import importlib
        import sys

        user = self.make_user("late-enable-user")
        access, refresh = self.obtain_access(user)
        RefreshToken(refresh).blacklist()

        # Load a private copy of the serializer module as if the process
        # started with BLACKLIST_AFTER_ROTATION=False.  Avoid touching the
        # live module so the rest of the suite keeps working.
        original_module = sys.modules.pop(
            "rest_framework_simplejwt.serializers", None
        )
        try:
            with override_api_settings(BLACKLIST_AFTER_ROTATION=False):
                cold_module = importlib.import_module(
                    "rest_framework_simplejwt.serializers"
                )
            self.assertFalse(hasattr(cold_module, "BlacklistedToken"))
            with override_api_settings(BLACKLIST_AFTER_ROTATION=True):
                serializer = cold_module.TokenVerifySerializer(
                    data={"token": refresh}
                )
                with self.assertRaises(NameError) as caught:
                    serializer.is_valid(raise_exception=True)
            self.assertIn("BlacklistedToken", str(caught.exception))
        finally:
            sys.modules.pop("rest_framework_simplejwt.serializers", None)
            if original_module is not None:
                sys.modules["rest_framework_simplejwt.serializers"] = original_module
                import rest_framework_simplejwt as package

                package.serializers = original_module

        self.dump(
            "Blacklist check enabled after process start",
            [
                Row(
                    credential="blacklisted refresh token",
                    enabled="access",
                    revocation="BAR=False at import, True at request",
                    verify="500 NameError (BlacklistedToken)",
                    verify_subject="not resolved",
                    api="n/a (serializer-level check)",
                    api_subject="-",
                    refresh="n/a (not exercised)",
                    refresh_subject="-",
                ),
            ],
        )

    def test_missing_jti_crashes_refresh_not_verify(self):
        """Verify/API return 401 for a missing jti; the refresh entry raises."""
        user = self.make_user("missing-jti-user")
        access, refresh = self.obtain_access(user)

        access_no_jti = AccessToken(access)
        del access_no_jti["jti"]
        with override_api_settings(AUTH_TOKEN_CLASSES=PROFILES["access"]):
            verify = self.client.post(
                reverse("token_verify"), {"token": str(access_no_jti)}
            )
            api = self.client.get(
                reverse("protected"),
                HTTP_AUTHORIZATION=f"Bearer {access_no_jti}",
            )
        self.assert_verify(verify, 401, "Token has no id")
        self.assert_api(api, 401, detail="Token has no id")

        refresh_no_jti = RefreshToken(refresh)
        del refresh_no_jti["jti"]
        verify = self.client.post(
            reverse("token_verify"), {"token": str(refresh_no_jti)}
        )
        self.assert_verify(verify, 401, "Token has no id")
        with self.assertRaises(KeyError) as caught:
            self.client.post(
                reverse("token_refresh"), {"refresh": str(refresh_no_jti)}
            )
        self.assertEqual(caught.exception.args, ("jti",))
        self.client.exc_info = None

        self.dump(
            "Missing jti (blacklist app installed)",
            [
                Row(
                    credential="access token",
                    enabled="access",
                    revocation="jti removed",
                    verify="401 Token has no id",
                    verify_subject="not resolved",
                    api="401 token_not_valid (Token has no id)",
                    api_subject="-",
                    refresh="401 Token has wrong type",
                    refresh_subject="-",
                ),
                Row(
                    credential="refresh token",
                    enabled="access",
                    revocation="jti removed",
                    verify="401 Token has no id",
                    verify_subject="not resolved",
                    api="401 token_not_valid",
                    api_subject="-",
                    refresh="500 KeyError('jti')",
                    refresh_subject="-",
                ),
            ],
        )

    def test_token_type_claim_rename_after_restart(self):
        """Old tokens keep their old claim name and stop authenticating."""
        from importlib import reload

        from rest_framework_simplejwt import authentication as auth_module
        from rest_framework_simplejwt import serializers as serializer_module
        from rest_framework_simplejwt import tokens as token_module

        user = self.make_user("type-switch-user")
        access, refresh = self.obtain_access(user)

        try:
            with override_api_settings(TOKEN_TYPE_CLAIM="typ"):
                # Simulate a process restart that picks up the new setting.
                reload(token_module)
                reload(serializer_module)
                reload(auth_module)

                verify = self.client.post(reverse("token_verify"), {"token": access})
                api = self.client.get(
                    reverse("protected"), HTTP_AUTHORIZATION=f"Bearer {access}"
                )
                refresh_res = self.client.post(
                    reverse("token_refresh"), {"refresh": refresh}
                )
                self.assert_verify(verify)  # verify does not know token types
                self.assert_api(api, 401, detail="Token has no type")
                self.assert_refresh(refresh_res, 401, detail="Token has no type")

                new_pair = self.client.post(
                    reverse("token_obtain_pair"),
                    {"username": user.username, "password": PASSWORD},
                )
                self.assertEqual(new_pair.status_code, 200)
                new_access, new_refresh = (
                    new_pair.data["access"],
                    new_pair.data["refresh"],
                )
                self.assertEqual(
                    UntypedToken(new_refresh).payload["typ"], "refresh"
                )
                self.assertEqual(UntypedToken(new_access).payload["typ"], "access")
                self.assert_verify(
                    self.client.post(reverse("token_verify"), {"token": new_access})
                )
                self.assert_api(
                    self.client.get(
                        reverse("protected"),
                        HTTP_AUTHORIZATION=f"Bearer {new_access}",
                    ),
                    200,
                    subject=str(user.pk),
                )
                self.assert_refresh(
                    self.client.post(
                        reverse("token_refresh"), {"refresh": new_refresh}
                    ),
                    200,
                )
        finally:
            reload(token_module)
            reload(serializer_module)
            reload(auth_module)

        self.dump(
            "TOKEN_TYPE_CLAIM rename (tokens issued before the switch)",
            [
                Row(
                    credential="access token",
                    enabled="access",
                    revocation='TOKEN_TYPE_CLAIM="typ"',
                    verify="200 {}",
                    verify_subject="not resolved",
                    api="401 token_not_valid (Token has no type)",
                    api_subject="-",
                    refresh="401 Token has no type",
                    refresh_subject="-",
                ),
                Row(
                    credential="access token issued after switch",
                    enabled="access",
                    revocation='TOKEN_TYPE_CLAIM="typ"',
                    verify="200 {}",
                    verify_subject="not resolved",
                    api="200 subject=1",
                    api_subject="1",
                    refresh="200 new-token subject=1",
                    refresh_subject="1",
                ),
            ],
        )
