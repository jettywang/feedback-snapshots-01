import io
import json
import time
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import jwt
from cryptography.hazmat.primitives import serialization
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from jwt import PyJWKClientError
from rest_framework.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED
from rest_framework.test import APIClient

from rest_framework_simplejwt.backends import TokenBackend
from rest_framework_simplejwt.exceptions import (
    TokenBackendError,
    TokenBackendExpiredToken,
)
from rest_framework_simplejwt.jwks import ResilientJWKClient
from tests.keys import PRIVATE_KEY, PRIVATE_KEY_2, PUBLIC_KEY, PUBLIC_KEY_2

User = get_user_model()

JWK_URL = "http://127.0.0.1:9/.well-known/jwks.json"
KID_1 = "key-2026-11"
KID_2 = "key-2026-12"


def _jwk(public_key: str, kid: str) -> dict:
    key = serialization.load_pem_public_key(public_key.encode())
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key, as_dict=True)
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return jwk


def jwk_set(*kids: str) -> dict:
    keys = {KID_1: PUBLIC_KEY, KID_2: PUBLIC_KEY_2}
    return {"keys": [_jwk(keys[kid], kid) for kid in kids]}


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeForwarder:
    """The local forwarder: a controllable JWKS source."""

    def __init__(self, clock: FakeClock | None = None) -> None:
        self.payload = jwk_set(KID_1)
        self.down = False
        self.calls: list[dict] = []
        self.clock = clock

    def fetch_data(self):
        self.calls.append(
            {
                "at": self.clock() if self.clock else time.monotonic(),
                "served": None if self.down else sorted(
                    key["kid"] for key in self.payload["keys"]
                ),
            }
        )
        if self.down:
            raise PyJWKClientError("forwarder unavailable")
        return self.payload


def make_client(forwarder: FakeForwarder, clock: FakeClock, **kwargs):
    client = ResilientJWKClient(JWK_URL, clock=clock, **kwargs)
    client.fetch_data = forwarder.fetch_data
    return client


def make_token(private_key: str, kid: str, **claims) -> str:
    claims.setdefault("exp", int(time.time()) + 300)
    return jwt.encode(
        claims or {"x": 1},
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )


def resign_with_kid(token: str, private_key: str, kid: str) -> str:
    """Re-sign an already-issued payload with a KID header.

    Production tokens from the forwarder carry ``kid``; Simple JWT's own
    encoder does not add one.  Tests re-sign the real payload rather than
    changing the encoder.
    """
    payload = jwt.decode(token, options={"verify_signature": False})
    return jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )


class TestResilientJWKClient(TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.forwarder = FakeForwarder(self.clock)
        self.client = make_client(self.forwarder, self.clock, lifespan=60)

    def test_existing_kid_is_a_cache_hit_and_no_network_call(self):
        token = make_token(PRIVATE_KEY, KID_1)

        first = self.client.get_signing_key_from_jwt(token)
        second = self.client.get_signing_key_from_jwt(token)

        self.assertEqual(first.key_id, KID_1)
        self.assertEqual(second.key_id, KID_1)
        self.assertEqual(len(self.forwarder.calls), 1)
        self.assertEqual(self.client.cache_status()["reads"][-1]["source"], "cache")

    def test_cache_expiry_refreshes_before_serving(self):
        token = make_token(PRIVATE_KEY, KID_1)
        self.client.get_signing_key_from_jwt(token)

        self.clock.advance(61)
        self.client.get_signing_key_from_jwt(token)

        self.assertEqual(len(self.forwarder.calls), 2)

    def test_expired_cache_with_source_down_serves_cached_key(self):
        token = make_token(PRIVATE_KEY, KID_1)
        self.client.get_signing_key_from_jwt(token)

        self.clock.advance(61)
        self.forwarder.down = True

        key = self.client.get_signing_key_from_jwt(token)

        self.assertEqual(key.key_id, KID_1)
        status = self.client.cache_status()
        self.assertEqual(status["reads"][-1]["source"], "cache_stale")
        self.assertEqual(status["reads"][-1]["outcome"], "served")

    def test_unknown_kid_with_source_down_fails_and_is_not_a_cache_hit(self):
        self.client.get_signing_key_from_jwt(make_token(PRIVATE_KEY, KID_1))
        self.forwarder.down = True

        with self.assertRaises(PyJWKClientError):
            self.client.get_signing_key_from_jwt(make_token(PRIVATE_KEY_2, KID_2))

        status = self.client.cache_status()
        self.assertEqual(status["reads"][-1]["outcome"], "unknown_key")
        self.assertEqual(status["reads"][-1]["category"], "source_unavailable")
        self.assertEqual(status["last_error"]["cache_state"], "cached_key_missing")
        self.assertEqual(status["cached_kids"], [KID_1])

    def test_cold_start_with_source_down_fails(self):
        self.forwarder.down = True

        with self.assertRaises(PyJWKClientError):
            self.client.get_signing_key_from_jwt(make_token(PRIVATE_KEY, KID_1))

        status = self.client.cache_status()
        self.assertFalse(status["cached"])
        self.assertEqual(status["last_error"]["cache_state"], "no_cache")

    def test_recovery_replaces_set_and_retires_old_kid(self):
        old = make_token(PRIVATE_KEY, KID_1)
        self.client.get_signing_key_from_jwt(old)

        self.forwarder.payload = jwk_set(KID_2)
        new = make_token(PRIVATE_KEY_2, KID_2)
        self.assertEqual(
            self.client.get_signing_key_from_jwt(new).key_id,
            KID_2,
        )
        self.assertEqual(self.client.cache_status()["cached_kids"], [KID_2])

        with self.assertRaises(PyJWKClientError):
            self.client.get_signing_key_from_jwt(old)

    def test_deactivated_key_is_not_reintroduced_by_merge(self):
        self.client.get_signing_key_from_jwt(make_token(PRIVATE_KEY, KID_1))
        self.forwarder.payload = jwk_set(KID_2)
        self.client.get_signing_key_from_jwt(make_token(PRIVATE_KEY_2, KID_2))

        # A later refresh that still contains only the new key must not
        # resurrect the retired KID.
        self.clock.advance(61)
        with self.assertRaises(PyJWKClientError):
            self.client.get_signing_key_from_jwt(make_token(PRIVATE_KEY, KID_1))
        self.assertEqual(self.client.cache_status()["cached_kids"], [KID_2])

    def test_allow_stale_false_fails_known_kid_when_source_down(self):
        client = make_client(
            self.forwarder, self.clock, lifespan=60, allow_stale=False
        )
        token = make_token(PRIVATE_KEY, KID_1)
        client.get_signing_key_from_jwt(token)
        self.clock.advance(61)
        self.forwarder.down = True

        with self.assertRaises(PyJWKClientError):
            client.get_signing_key_from_jwt(token)

    def test_failed_refresh_cools_down_and_keeps_serving_cached_key(self):
        token = make_token(PRIVATE_KEY, KID_1)
        self.client.get_signing_key_from_jwt(token)
        self.clock.advance(61)
        self.forwarder.down = True

        self.client.get_signing_key_from_jwt(token)
        calls_after_failure = len(self.forwarder.calls)
        self.clock.advance(5)

        # Within the cooldown, the dead forwarder is not contacted again.
        self.client.get_signing_key_from_jwt(token)
        self.assertEqual(len(self.forwarder.calls), calls_after_failure)
        self.assertGreater(
            self.client.cache_status()["retry_after_seconds"], 0
        )

    def test_cooldown_expires_and_recovery_is_observed(self):
        token = make_token(PRIVATE_KEY, KID_1)
        self.client.get_signing_key_from_jwt(token)
        self.clock.advance(61)
        self.forwarder.down = True
        self.client.get_signing_key_from_jwt(token)

        self.forwarder.down = False
        self.forwarder.payload = jwk_set(KID_2)
        self.clock.advance(31)
        new = make_token(PRIVATE_KEY_2, KID_2)
        self.assertEqual(
            self.client.get_signing_key_from_jwt(new).key_id, KID_2
        )

    def test_repeated_unknown_kids_do_not_storm_the_source(self):
        self.client.get_signing_key_from_jwt(make_token(PRIVATE_KEY, KID_1))
        calls = len(self.forwarder.calls)

        for i in range(5):
            with self.assertRaises(PyJWKClientError):
                self.client.get_signing_key_from_jwt(
                    make_token(PRIVATE_KEY_2, f"random-{i}")
                )

        # One probe for the first unknown kid; the rest are answered from
        # the freshly fetched set without another fetch.
        self.assertEqual(len(self.forwarder.calls), calls + 1)
        self.assertGreater(
            self.client.cache_status()["unknown_kid_retry_after_seconds"], 0
        )

    def test_unknown_kid_during_cooldown_is_source_unavailable(self):
        token = make_token(PRIVATE_KEY, KID_1)
        self.client.get_signing_key_from_jwt(token)
        self.clock.advance(61)
        self.forwarder.down = True
        self.client.get_signing_key_from_jwt(token)  # starts cooldown

        self.clock.advance(5)
        with self.assertRaises(PyJWKClientError):
            self.client.get_signing_key_from_jwt(make_token(PRIVATE_KEY_2, KID_2))

        read = self.client.cache_status()["reads"][-1]
        self.assertEqual(read["outcome"], "unknown_key")
        self.assertEqual(read["category"], "source_unavailable")
        self.assertEqual(read["error"], "PyJWKClientError")

    def test_status_records_actual_reads(self):
        token = make_token(PRIVATE_KEY, KID_1)
        self.client.get_signing_key_from_jwt(token)
        self.clock.advance(61)
        self.forwarder.down = True
        self.client.get_signing_key_from_jwt(token)

        reads = self.client.cache_status()["reads"]
        self.assertEqual([r["source"] for r in reads], ["network", "cache_stale"])
        self.assertEqual(
            [r["category"] for r in reads], ["refreshed", "source_unavailable"]
        )
        self.assertEqual(reads[0]["cached_kids"], [KID_1])


def _opener_returning(body: bytes):
    opener = MagicMock()
    opener.open.return_value.__enter__.return_value = io.BytesIO(body)
    return opener


class TestHttpTransport(TestCase):
    def test_transport_payload_is_parsed_and_cached(self):
        clock = FakeClock()
        client = ResilientJWKClient(JWK_URL, clock=clock, lifespan=60)
        body = json.dumps(jwk_set(KID_1)).encode()
        token = make_token(PRIVATE_KEY, KID_1)
        opener = _opener_returning(body)

        with patch("urllib.request.build_opener", return_value=opener) as build:
            self.assertEqual(
                client.get_signing_key_from_jwt(token).key_id, KID_1
            )
            client.get_signing_key_from_jwt(token)

        self.assertEqual(build.call_count, 1)
        self.assertEqual(opener.open.call_count, 1)

    def test_transport_failure_keeps_cached_key_usable(self):
        clock = FakeClock()
        client = ResilientJWKClient(JWK_URL, clock=clock, lifespan=60)
        body = json.dumps(jwk_set(KID_1)).encode()
        token = make_token(PRIVATE_KEY, KID_1)

        with patch(
            "urllib.request.build_opener", return_value=_opener_returning(body)
        ):
            client.get_signing_key_from_jwt(token)

        clock.advance(61)
        failing = MagicMock()
        failing.open.side_effect = URLError("refused")
        with patch("urllib.request.build_opener", return_value=failing):
            self.assertEqual(
                client.get_signing_key_from_jwt(token).key_id, KID_1
            )
        self.assertEqual(
            client.cache_status()["last_error"]["cache_state"], "cache_expired"
        )

    def test_non_object_payload_is_a_source_failure(self):
        clock = FakeClock()
        client = ResilientJWKClient(JWK_URL, clock=clock, lifespan=60)

        with patch(
            "urllib.request.build_opener",
            return_value=_opener_returning(json.dumps(["not", "a", "set"]).encode()),
        ):
            with self.assertRaises(PyJWKClientError):
                client.get_signing_key_from_jwt(make_token(PRIVATE_KEY, KID_1))

        self.assertEqual(
            client.cache_status()["last_error"]["cache_state"], "no_cache"
        )


class TestTokenBackendOutageSemantics(TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.forwarder = FakeForwarder(self.clock)
        self.client = make_client(self.forwarder, self.clock, lifespan=60)
        self.backend = TokenBackend("RS256", jwk_url=JWK_URL)
        self.backend.jwks_client = self.client

    def test_known_kid_still_decodes_during_outage(self):
        token = make_token(
            PRIVATE_KEY,
            KID_1,
            exp=int(time.time()) + 300,
            token_type="access",
        )
        self.backend.decode(token)
        self.forwarder.down = True
        self.clock.advance(61)

        self.assertEqual(self.backend.decode(token)["token_type"], "access")

    def test_unknown_kid_is_translated_to_token_backend_error(self):
        self.backend.decode(make_token(PRIVATE_KEY, KID_1))
        self.forwarder.down = True

        with self.assertRaisesRegex(TokenBackendError, "Token is invalid"):
            self.backend.decode(make_token(PRIVATE_KEY_2, KID_2))

    def test_expired_token_is_distinct_from_outage(self):
        self.backend.decode(make_token(PRIVATE_KEY, KID_1))

        expired = make_token(PRIVATE_KEY, KID_1, exp=int(time.time()) - 1)
        with self.assertRaises(TokenBackendExpiredToken):
            self.backend.decode(expired)

    def test_retired_kid_is_token_invalid_not_source_failure(self):
        self.backend.decode(make_token(PRIVATE_KEY, KID_1))
        self.forwarder.payload = jwk_set(KID_2)
        self.backend.decode(make_token(PRIVATE_KEY_2, KID_2))
        self.forwarder.down = True

        with self.assertRaisesRegex(TokenBackendError, "Token is invalid"):
            self.backend.decode(make_token(PRIVATE_KEY, KID_1))


class TestApiAcrossOutage(TestCase):
    """Normal API access, refresh and independent verify across an outage.

    The test client and the token backend share one process, but the outage
    is injected at the JWKS fetch boundary only, so serializers, token
    classes and DRF exception translation run unchanged.
    """

    def setUp(self):
        self.clock = FakeClock()
        self.forwarder = FakeForwarder(self.clock)
        self.client = make_client(self.forwarder, self.clock, lifespan=60)
        self.user = User.objects.create_user(
            username="outage-user", password="outage-password"
        )
        self.api = APIClient()

        # Use a real TokenBackend wired to the controlled forwarder.  Patch
        # the module attribute that Token.token_backend imports dynamically,
        # so serializers and token classes stay untouched.
        from rest_framework_simplejwt import state

        self.backend = TokenBackend("RS256", PRIVATE_KEY, "", jwk_url=JWK_URL)
        self.backend.jwks_client = self.client
        self._old_state_backend = state.token_backend
        state.token_backend = self.backend

    def tearDown(self):
        from rest_framework_simplejwt import state

        state.token_backend = self._old_state_backend

    def _obtain_pair(self, kid: str = KID_1, private_key: str = PRIVATE_KEY) -> dict:
        res = self.api.post(
            reverse("token_obtain_pair"),
            {"username": "outage-user", "password": "outage-password"},
            format="json",
        )
        self.assertEqual(res.status_code, HTTP_200_OK)
        return {
            "access": resign_with_kid(res.data["access"], private_key, kid),
            "refresh": resign_with_kid(res.data["refresh"], private_key, kid),
        }

    def _get_protected(self, access: str):
        self.api.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        return self.api.get(reverse("test_view"))

    def test_access_and_refresh_survive_outage_and_recovery(self):
        pair = self._obtain_pair()

        # Warm the JWKS cache through a normal API request.
        self.assertEqual(self._get_protected(pair["access"]).status_code, HTTP_200_OK)
        self.assertEqual(len(self.forwarder.calls), 1)

        # Outage after the cache has expired: old access token still decodes.
        self.clock.advance(61)
        self.forwarder.down = True
        self.assertEqual(self._get_protected(pair["access"]).status_code, HTTP_200_OK)

        # A refresh during the outage also succeeds: the refresh token was
        # signed with the cached KID_1 key.  The access token returned by
        # Simple JWT's own encoder has no ``kid``; re-sign it with the same
        # forwarder key to model the next request in the chain.
        res = self.api.post(
            reverse("token_refresh"), {"refresh": pair["refresh"]}, format="json"
        )
        self.assertEqual(res.status_code, HTTP_200_OK)
        refreshed_access = resign_with_kid(res.data["access"], PRIVATE_KEY, KID_1)
        self.assertEqual(
            self._get_protected(refreshed_access).status_code, HTTP_200_OK
        )

        # Recovery publishes only KID_2.  New tokens use the new key and
        # the old KID is retired, not silently merged back.
        self.forwarder.payload = jwk_set(KID_2)
        self.forwarder.down = False
        self.clock.advance(61)

        # A pair issued by the forwarder after recovery works normally.
        recovered = self._obtain_pair(KID_2, PRIVATE_KEY_2)
        self.assertEqual(
            self._get_protected(recovered["access"]).status_code,
            HTTP_200_OK,
        )
        res = self.api.post(
            reverse("token_refresh"),
            {"refresh": recovered["refresh"]},
            format="json",
        )
        self.assertEqual(res.status_code, HTTP_200_OK)
        self.assertEqual(
            self._get_protected(
                resign_with_kid(res.data["access"], PRIVATE_KEY_2, KID_2)
            ).status_code,
            HTTP_200_OK,
        )

        # The old access token is now retired even though it has not expired.
        self.assertEqual(
            self._get_protected(pair["access"]).status_code,
            HTTP_401_UNAUTHORIZED,
        )

        # Refresh requests signed with the old key are also rejected.
        res = self.api.post(
            reverse("token_refresh"), {"refresh": pair["refresh"]}, format="json"
        )
        self.assertEqual(res.status_code, HTTP_401_UNAUTHORIZED)

    def test_independent_verify_has_its_own_read_path(self):
        pair = self._obtain_pair()
        # Warm the cache first: verify is a read path of its own but, like
        # access, it cannot work before any key has ever been fetched.
        self.assertEqual(self._get_protected(pair["access"]).status_code, HTTP_200_OK)
        self.clock.advance(61)
        self.forwarder.down = True

        res = self.api.post(
            reverse("token_verify"), {"token": pair["access"]}, format="json"
        )
        self.assertEqual(res.status_code, HTTP_200_OK)

        # Without a prior read, verify must wait for the source.
        cold_forwarder = FakeForwarder(self.clock)
        cold_forwarder.down = True
        cold_client = make_client(cold_forwarder, self.clock, lifespan=60)
        with self.assertRaises(PyJWKClientError):
            cold_client.get_signing_key_from_jwt(pair["access"])

        self.forwarder.payload = jwk_set(KID_2)
        self.forwarder.down = False
        self.clock.advance(61)
        res = self.api.post(
            reverse("token_verify"), {"token": pair["access"]}, format="json"
        )
        self.assertEqual(res.status_code, HTTP_401_UNAUTHORIZED)

    def test_refresh_of_old_token_after_rotation_waits_for_new_key(self):
        pair = self._obtain_pair()
        self.assertEqual(self._get_protected(pair["access"]).status_code, HTTP_200_OK)

        self.forwarder.payload = jwk_set(KID_2)
        self.clock.advance(61)

        res = self.api.post(
            reverse("token_refresh"), {"refresh": pair["refresh"]}, format="json"
        )
        self.assertEqual(res.status_code, HTTP_401_UNAUTHORIZED)
        self.assertEqual(res.data["code"], "token_not_valid")
