"""Reproduce the JWKS outage/recovery timeline without network access.

Run from the repository root::

    .venv/bin/python scripts/jwks_outage_timeline.py

The fake forwarder is injected at the HTTP fetch boundary; the token backend,
token classes, serializers and DRF exception translation are unchanged.
Replace ``Forwarder.fetch_data`` with an HTTP GET and bind a local socket to
run the same timeline against a real local forwarder (the sandbox used here
forbids local port binding).
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import django
import jwt
from cryptography.hazmat.primitives import serialization
from django.conf import settings

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if not settings.configured:
    settings.configure(
        DEBUG=True,
        DATABASES={
            "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}
        },
        SECRET_KEY="timeline",
        USE_TZ=True,
        INSTALLED_APPS=(
            "django.contrib.auth",
            "django.contrib.contenttypes",
            "rest_framework",
            "rest_framework_simplejwt",
        ),
        ROOT_URLCONF="tests.urls",
        PASSWORD_HASHERS=("django.contrib.auth.hashers.MD5PasswordHasher",),
    )
    django.setup()

from django.contrib.auth import get_user_model  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.urls import reverse  # noqa: E402
from jwt import PyJWKClientError  # noqa: E402
from rest_framework.test import APIClient  # noqa: E402

from rest_framework_simplejwt import state  # noqa: E402
from rest_framework_simplejwt.backends import TokenBackend  # noqa: E402
from rest_framework_simplejwt.jwks import ResilientJWKClient  # noqa: E402
from tests.keys import (  # noqa: E402
    PRIVATE_KEY,
    PRIVATE_KEY_2,
    PUBLIC_KEY,
    PUBLIC_KEY_2,
)

JWK_URL = "http://127.0.0.1:9/.well-known/jwks.json"
KID_1 = "key-2026-11"
KID_2 = "key-2026-12"


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def jwk(public_key, kid):
    key = serialization.load_pem_public_key(public_key.encode())
    data = jwt.algorithms.RSAAlgorithm.to_jwk(key, as_dict=True)
    data.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return data


def jwk_set(*kids):
    material = {KID_1: PUBLIC_KEY, KID_2: PUBLIC_KEY_2}
    return {"keys": [jwk(material[kid], kid) for kid in kids]}


class Forwarder:
    def __init__(self, clock):
        self.clock = clock
        self.payload = jwk_set(KID_1)
        self.down = False
        self.calls = []

    def fetch_data(self):
        self.calls.append(
            {
                "clock": self.clock(),
                "served": None
                if self.down
                else sorted(k["kid"] for k in self.payload["keys"]),
            }
        )
        if self.down:
            raise PyJWKClientError("forwarder unavailable")
        return self.payload


def resign(token, private_key, kid):
    payload = jwt.decode(token, options={"verify_signature": False})
    return jwt.encode(
        payload, private_key, algorithm="RS256", headers={"kid": kid}
    )


def main():
    call_command("migrate", verbosity=0, run_syncdb=True)

    clock = Clock()
    forwarder = Forwarder(clock)
    client = ResilientJWKClient(JWK_URL, lifespan=60, clock=clock)
    client.fetch_data = forwarder.fetch_data

    backend = TokenBackend("RS256", PRIVATE_KEY, "", jwk_url=JWK_URL)
    backend.jwks_client = client
    state.token_backend = backend

    user = get_user_model().objects.create_user(
        username="timeline", password="timeline"
    )
    api = APIClient()

    rows = []

    def step(name, fn):
        before = len(client.cache_status()["reads"])
        result = fn()
        status = client.cache_status()
        new_reads = status["reads"][before:]
        rows.append(
            {
                "step": name,
                "result": result,
                "read": new_reads[-1] if new_reads else None,
                "cached_kids": status["cached_kids"],
                "cache_fresh": status["cache_fresh"],
                "last_error": status["last_error"],
            }
        )

    def obtain(kid=KID_1, private_key=PRIVATE_KEY):
        res = api.post(
            reverse("token_obtain_pair"),
            {"username": "timeline", "password": "timeline"},
            format="json",
        )
        assert res.status_code == 200, res.data
        return {
            "access": resign(res.data["access"], private_key, kid),
            "refresh": resign(res.data["refresh"], private_key, kid),
        }

    def protected(access):
        api.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        return api.get(reverse("test_view")).status_code

    def refresh(refresh_token):
        return api.post(
            reverse("token_refresh"), {"refresh": refresh_token}, format="json"
        ).status_code

    def verify(access):
        return api.post(
            reverse("token_verify"), {"token": access}, format="json"
        ).status_code

    pair = obtain()

    step("1 warm cache: GET /test-view/", lambda: protected(pair["access"]))

    clock.now += 61
    forwarder.down = True
    step("2 outage + cache expired: GET /test-view/", lambda: protected(pair["access"]))
    step("3 outage: POST /token/refresh/", lambda: refresh(pair["refresh"]))
    step("4 outage: POST /token/verify/", lambda: verify(pair["access"]))

    forwarder.payload = jwk_set(KID_2)
    forwarder.down = False
    clock.now += 61
    step("5 recover with only KID_2: GET old access", lambda: protected(pair["access"]))
    step(
        "6 recover: POST /token/refresh/ old refresh",
        lambda: refresh(pair["refresh"]),
    )
    step("7 recover: POST /token/verify/ old access", lambda: verify(pair["access"]))

    recovered = obtain(KID_2, PRIVATE_KEY_2)
    step(
        "8 issue after recovery: GET new access",
        lambda: protected(recovered["access"]),
    )

    status = client.cache_status()
    report = {
        "uri": JWK_URL,
        "forwarder_fetches": forwarder.calls,
        "steps": rows,
        "final": {k: v for k, v in status.items() if k != "reads"},
        "reads": status["reads"],
    }
    print(json.dumps(report, indent=2))
    print("\n# timeline", file=sys.stderr)
    for row in rows:
        read = row["read"] or {}
        print(
            f"{row['result']:>3}  {row['step']:<50} "
            f"{read.get('category', '-'):<20} {read.get('source', '-')}",
            file=sys.stderr,
        )
    print(
        "\n# final cached kids: " + ", ".join(status["cached_kids"]),
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
