from datetime import datetime

import jwt
import pytest
from django.contrib.auth import get_user_model
from django.test import TestCase
from freezegun import freeze_time

from rest_framework_simplejwt.exceptions import (
    TokenBackendError,
    TokenBackendExpiredToken,
    TokenError,
)
from rest_framework_simplejwt.key_rotation import (
    KeyRotationPolicy,
    KeyRotationPolicyError,
    KeyStatus,
    RotatingTokenBackend,
    SigningKeyEntry,
)
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken, Token
from tests.keys import (
    PRIVATE_KEY,
    PRIVATE_KEY_2,
    PUBLIC_KEY,
    PUBLIC_KEY_2,
)

OLD_KEY = "old-signing-secret-with-enough-bytes-000001"
NEW_KEY = "new-signing-secret-with-enough-bytes-000002"
UNKNOWN_KEY = "unrelated-secret-with-enough-bytes-0003"

T0 = "2026-01-01 00:00:00"
T1 = "2026-01-01 12:00:00"
T2 = "2026-01-03 00:00:00"


class PolicyTestCase(TestCase):
    def setUp(self):
        self.policy = KeyRotationPolicy(
            SigningKeyEntry("old", OLD_KEY, KeyStatus.ACTIVE),
            SigningKeyEntry("new", NEW_KEY, KeyStatus.RETIRED),
        )
        self.backend = RotatingTokenBackend(self.policy, "HS256")

    def test_explicit_initial_states(self):
        self.assertEqual(self.policy.active_kid, "old")
        self.assertEqual(
            self.policy.get_entry("old").status, KeyStatus.ACTIVE
        )
        self.assertEqual(
            self.policy.get_entry("new").status, KeyStatus.RETIRED
        )
        self.assertEqual(
            [entry.kid for entry in self.policy.acceptable_entries], ["old"]
        )

    def test_rejects_two_active_keys(self):
        with self.assertRaises(KeyRotationPolicyError):
            KeyRotationPolicy(
                SigningKeyEntry("a", OLD_KEY, KeyStatus.ACTIVE),
                SigningKeyEntry("b", NEW_KEY, KeyStatus.ACTIVE),
            )

    def test_rejects_duplicate_kid(self):
        with self.assertRaises(KeyRotationPolicyError):
            KeyRotationPolicy(
                SigningKeyEntry("same", OLD_KEY, KeyStatus.ACTIVE),
                SigningKeyEntry("same", NEW_KEY, KeyStatus.RETAINED),
            )

    def test_rotation_moves_old_key_to_retained(self):
        self.policy.activate("new")

        self.assertEqual(self.policy.active_kid, "new")
        self.assertEqual(
            self.policy.get_entry("old").status, KeyStatus.RETAINED
        )
        self.assertEqual(
            sorted(entry.kid for entry in self.policy.acceptable_entries),
            ["new", "old"],
        )

    def test_retire_closes_transition_window(self):
        self.policy.activate("new")
        self.policy.retire("old")

        self.assertEqual(
            self.policy.get_entry("old").status, KeyStatus.RETIRED
        )
        self.assertEqual(
            [entry.kid for entry in self.policy.acceptable_entries], ["new"]
        )

    def test_cannot_retire_active_key(self):
        with self.assertRaises(KeyRotationPolicyError):
            self.policy.retire("old")

    def test_cannot_activate_unknown_key(self):
        with self.assertRaises(KeyRotationPolicyError):
            self.policy.activate("missing")

    def test_retired_key_is_rejected_after_window_closes(self):
        # Once the old key has been retired it cannot verify any token, but it
        # also must not silently become active again.
        self.policy.activate("new")
        self.policy.retire("old")
        self.assertEqual(
            self.policy.get_entry("old").status, KeyStatus.RETIRED
        )
        self.assertEqual(self.policy.active_kid, "new")

    def test_retained_key_can_be_reactivated_as_rollback(self):
        self.policy.activate("new")
        # Rollback during the window.
        self.policy.activate("old")

        self.assertEqual(self.policy.active_kid, "old")
        self.assertEqual(
            self.policy.get_entry("new").status, KeyStatus.RETAINED
        )


class RotationFlowTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(
            username="rotation_user", password="test_password"
        )

    def setUp(self):
        from rest_framework_simplejwt import state

        self.policy = KeyRotationPolicy(
            SigningKeyEntry("old", OLD_KEY, KeyStatus.ACTIVE),
            SigningKeyEntry("new", NEW_KEY, KeyStatus.RETIRED),
        )
        self.backend = RotatingTokenBackend(self.policy, "HS256")
        # Route every Token subclass through the rotating policy via the
        # module attribute resolved by Token.get_token_backend().
        self._original_backend = state.token_backend
        state.token_backend = self.backend
        Token._token_backend = None
        self.addCleanup(self._restore_backend)

    def _restore_backend(self):
        from rest_framework_simplejwt import state

        state.token_backend = self._original_backend
        Token._token_backend = None

    def _issue_refresh(self) -> RefreshToken:
        token = RefreshToken.for_user(self.user)
        return token

    def test_new_tokens_are_signed_only_with_active_key(self):
        with freeze_time(T0):
            refresh = self._issue_refresh()
            access = refresh.access_token
            encoded = str(access)

            # Header identifier matches the active key...
            self.assertEqual(
                jwt.get_unverified_header(encoded)["kid"], "old"
            )
            # ...and the token is actually verifiable with that key only.
            self.backend.decode(encoded)
            self.assertEqual(self.backend.identify(encoded).kid, "old")
            with self.assertRaises(jwt.InvalidSignatureError):
                jwt.decode(
                    encoded,
                    NEW_KEY,
                    algorithms=["HS256"],
                    options={"verify_exp": False},
                )

    def test_retained_key_keeps_historical_token_verifiable(self):
        with freeze_time(T0):
            # Refresh tokens live long enough to span the transition window.
            old_token = str(self._issue_refresh())

        # Rotate: old is now retained, new is active.
        self.policy.activate("new")

        with freeze_time(T1):
            self.backend.decode(old_token)
            self.assertEqual(
                self.backend.identify(old_token).kid, "old"
            )
            new_token = str(self._issue_refresh())
            self.assertEqual(
                jwt.get_unverified_header(new_token)["kid"], "new"
            )
            self.assertEqual(
                self.backend.identify(new_token).kid, "new"
            )

    def test_retired_key_rejects_token_despite_matching_kid_header(self):
        with freeze_time(T0):
            old_token = str(self._issue_refresh())

        self.policy.activate("new")
        self.policy.retire("old")

        with freeze_time(T1):
            # The header still advertises "old", but the key is no longer
            # trusted.
            self.assertEqual(
                jwt.get_unverified_header(old_token)["kid"], "old"
            )
            with self.assertRaises(TokenBackendError):
                self.backend.decode(old_token)
            with self.assertRaises(TokenBackendError):
                self.backend.identify(old_token)

            # The raw signature is still cryptographically valid with the old
            # secret, proving rejection is a policy decision, not a bad
            # signature.
            jwt.decode(
                old_token,
                OLD_KEY,
                algorithms=["HS256"],
                options={"verify_exp": False},
            )

    def test_token_with_misleading_kid_is_resolved_by_real_signature(self):
        with freeze_time(T0):
            token = str(self._issue_refresh())
            claims = self.backend.decode(token, verify=False)

        self.policy.activate("new")

        # Re-sign the same claims with the old key but lie about the kid in
        # the header. The token stays cryptographically valid with the old
        # secret; the policy must not select the new key on the strength of the
        # kid identifier alone.
        misleading = jwt.encode(
            claims,
            OLD_KEY,
            algorithm="HS256",
            headers={"kid": "new"},
        )
        self.assertEqual(
            jwt.get_unverified_header(misleading)["kid"], "new"
        )

        with freeze_time(T1):
            with self.assertRaises(jwt.InvalidSignatureError):
                jwt.decode(
                    misleading,
                    NEW_KEY,
                    algorithms=["HS256"],
                    options={"verify_exp": False},
                )

            # The hinted new key fails the signature check, but the retained
            # old key then verifies it: trust follows real signatures.
            self.assertEqual(
                self.backend.identify(misleading).kid, "old"
            )
            self.backend.decode(misleading)

    def test_refresh_across_rotation_follows_single_policy(self):
        with freeze_time(T0):
            refresh = self._issue_refresh()
            old_refresh = str(refresh)
            self.assertEqual(
                jwt.get_unverified_header(old_refresh)["kid"], "old"
            )

        # Rotate before the client comes back to refresh.
        self.policy.activate("new")

        with freeze_time(T1):
            # The historical refresh token is still accepted because old is
            # retained.
            parsed = RefreshToken(old_refresh)
            self.assertEqual(
                self.backend.identify(old_refresh).kid, "old"
            )

            # The freshly issued access token is signed with the now active
            # key, yet verification goes through the very same policy.
            new_access = str(parsed.access_token)
            self.assertEqual(
                jwt.get_unverified_header(new_access)["kid"], "new"
            )
            self.assertEqual(
                self.backend.identify(new_access).kid, "new"
            )
            self.backend.decode(new_access)

    def test_refresh_is_rejected_after_transition_window_closes(self):
        with freeze_time(T0):
            old_refresh = str(self._issue_refresh())

        self.policy.activate("new")
        self.policy.retire("old")

        with freeze_time(T2):
            with self.assertRaises(TokenError):
                RefreshToken(old_refresh)

    def test_refresh_serializer_across_rotation_uses_same_policy(self):
        with freeze_time(T0):
            old_refresh = str(self._issue_refresh())

        self.policy.activate("new")

        with freeze_time(T1):
            data = TokenRefreshSerializer().validate({"refresh": old_refresh})
            new_access = data["access"]

            # Issued under the now active key and verifiable through the same
            # policy that accepted the historical refresh token.
            self.assertEqual(
                jwt.get_unverified_header(new_access)["kid"], "new"
            )
            self.backend.decode(new_access)
            self.assertEqual(
                self.backend.identify(new_access).kid, "new"
            )

    def test_expired_token_signed_by_acceptable_key_raises_expired(self):
        with freeze_time(T0):
            access = self._issue_refresh().access_token
            encoded = str(access)

        self.policy.activate("new")

        expiry = datetime(2026, 1, 1, 0, 10, 0)
        with freeze_time(expiry):
            with self.assertRaises(TokenBackendExpiredToken):
                self.backend.decode(encoded)

    def test_token_signed_by_unknown_key_is_rejected(self):
        forged = jwt.encode(
            {"token_type": "access", "exp": 9999999999},
            UNKNOWN_KEY,
            algorithm="HS256",
            headers={"kid": "old"},
        )
        with self.assertRaises(TokenBackendError):
            self.backend.decode(forged)

    def test_malformed_token_is_rejected(self):
        with self.assertRaises(TokenBackendError):
            self.backend.decode("not-a-jwt")
        with self.assertRaises(TokenBackendError):
            self.backend.identify("not-a-jwt")

    def test_no_active_key_makes_encoding_fail(self):
        policy = KeyRotationPolicy(
            SigningKeyEntry("old", OLD_KEY, KeyStatus.RETAINED),
        )
        backend = RotatingTokenBackend(policy, "HS256")
        with self.assertRaises(KeyRotationPolicyError):
            backend.encode({"foo": "bar"})

    def test_decode_without_verification_uses_hinted_key(self):
        with freeze_time(T0):
            token = str(self._issue_refresh())
        self.policy.activate("new")

        with freeze_time(T1):
            payload = self.backend.decode(token, verify=False)
            self.assertEqual(payload["token_type"], "refresh")


@pytest.mark.parametrize(
    "states,expected_kids",
    [
        (
            {"old": KeyStatus.ACTIVE, "new": KeyStatus.RETIRED},
            ["old"],
        ),
        (
            {"old": KeyStatus.RETAINED, "new": KeyStatus.ACTIVE},
            ["new", "old"],
        ),
        (
            {"old": KeyStatus.RETIRED, "new": KeyStatus.ACTIVE},
            ["new"],
        ),
    ],
)
def test_acceptable_keys_track_lifecycle_states(states, expected_kids):
    policy = KeyRotationPolicy(
        SigningKeyEntry("old", OLD_KEY, states["old"]),
        SigningKeyEntry("new", NEW_KEY, states["new"]),
    )
    assert sorted(
        entry.kid for entry in policy.acceptable_entries
    ) == sorted(expected_kids)


class AsymmetricRotationTestCase(TestCase):
    def setUp(self):
        self.policy = KeyRotationPolicy(
            SigningKeyEntry(
                "rsa-old",
                PRIVATE_KEY,
                KeyStatus.ACTIVE,
                verifying_key=PUBLIC_KEY,
            ),
            SigningKeyEntry(
                "rsa-new",
                PRIVATE_KEY_2,
                KeyStatus.RETIRED,
                verifying_key=PUBLIC_KEY_2,
            ),
        )
        self.backend = RotatingTokenBackend(self.policy, "RS256")

    def test_rotation_uses_public_keys_for_signature_probes(self):
        historical = jwt.encode(
            {"token_type": "access", "exp": 9999999999},
            PRIVATE_KEY,
            algorithm="RS256",
            headers={"kid": "rsa-old"},
        )

        self.policy.activate("rsa-new")

        # Old private key is retained: its public key still verifies history.
        self.assertEqual(self.backend.identify(historical).kid, "rsa-old")
        self.backend.decode(historical)

        # New tokens are signed by the new private key.
        issued = self.backend.encode({"token_type": "access"})
        self.assertEqual(
            jwt.get_unverified_header(issued)["kid"], "rsa-new"
        )
        self.assertEqual(self.backend.identify(issued).kid, "rsa-new")

        # Closing the window rejects the historical token even though its
        # signature remains valid against the old public key.
        self.policy.retire("rsa-old")
        with self.assertRaises(TokenBackendError):
            self.backend.decode(historical)
