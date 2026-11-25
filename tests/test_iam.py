# Copyright 2017 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import datetime
import http.client as http_client
import json
import os
import threading
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import pytest  # type: ignore

from google.auth import _helpers
from google.auth import _signing_policy
from google.auth import crypt
from google.auth import exceptions
from google.auth import iam
from google.auth import transport
import google.auth.credentials


def make_request(status, data=None):
    response = mock.create_autospec(transport.Response, instance=True)
    response.status = status

    if data is not None:
        response.data = json.dumps(data).encode("utf-8")

    request = mock.create_autospec(transport.Request)
    request.return_value = response
    return request


def make_credentials():
    class CredentialsImpl(google.auth.credentials.Credentials):
        def __init__(self):
            super(CredentialsImpl, self).__init__()
            self.token = "token"
            # Force refresh
            self.expiry = datetime.datetime.min + _helpers.REFRESH_THRESHOLD

        def refresh(self, request):
            pass

        def with_quota_project(self, quota_project_id):
            raise NotImplementedError()

    return CredentialsImpl()


class TestSigner(object):
    def test_constructor(self):
        request = mock.sentinel.request
        credentials = mock.create_autospec(
            google.auth.credentials.Credentials, instance=True
        )

        signer = iam.Signer(request, credentials, mock.sentinel.service_account_email)

        assert signer._request == mock.sentinel.request
        assert signer._credentials == credentials
        assert signer._service_account_email == mock.sentinel.service_account_email

    def test_key_id(self):
        signer = iam.Signer(
            mock.sentinel.request,
            mock.sentinel.credentials,
            mock.sentinel.service_account_email,
        )

        assert signer.key_id is None

    def test_sign_bytes(self):
        signature = b"DEADBEEF"
        encoded_signature = base64.b64encode(signature).decode("utf-8")
        request = make_request(http_client.OK, data={"signedBlob": encoded_signature})
        credentials = make_credentials()

        signer = iam.Signer(request, credentials, mock.sentinel.service_account_email)

        returned_signature = signer.sign("123")

        assert returned_signature == signature
        kwargs = request.call_args[1]
        assert kwargs["headers"]["Content-Type"] == "application/json"
        request.call_count == 1

    def test_sign_bytes_failure(self):
        request = make_request(http_client.UNAUTHORIZED)
        credentials = make_credentials()

        signer = iam.Signer(request, credentials, mock.sentinel.service_account_email)

        with pytest.raises(exceptions.TransportError):
            signer.sign("123")
        request.call_count == 1

    @mock.patch("time.sleep", return_value=None)
    def test_sign_bytes_retryable_failure(self, mock_time):
        request = make_request(http_client.INTERNAL_SERVER_ERROR)
        credentials = make_credentials()

        signer = iam.Signer(request, credentials, mock.sentinel.service_account_email)

        with pytest.raises(exceptions.TransportError):
            signer.sign("123")
        request.call_count == 3


class InMemoryIam(object):
    """In-memory stand-in for the IAM signBlob API backed by real RSA keys.

    Each key has its own signer and public-key verifier. The active key
    decides which key signs every request. A request can be held open via
    :meth:`hold_next_signing_call` so that the signing lifecycle policy can be
    changed while the call is still in flight.
    """

    def __init__(self):
        self._signers = {}
        self._verifiers = {}
        self._active_key = None
        self._gate = threading.Event()
        self._gate.set()
        self._calls = []
        self._lock = threading.Lock()

    def add_key(self, key_id, private_key_pem, public_key_pem, active=False):
        self._signers[key_id] = crypt.RSASigner.from_string(
            private_key_pem, key_id=key_id
        )
        self._verifiers[key_id] = crypt.RSAVerifier.from_string(public_key_pem)
        if active or self._active_key is None:
            self._active_key = key_id

    @property
    def verifiers(self):
        return dict(self._verifiers)

    @property
    def active_key(self):
        return self._active_key

    def set_active_key(self, key_id):
        self._active_key = key_id

    @property
    def calls(self):
        with self._lock:
            return list(self._calls)

    def hold_next_signing_call(self):
        self._gate.clear()

    def release(self):
        self._gate.set()

    def wait_for_in_flight(self, timeout=5):
        deadline = _helpers.utcnow() + datetime.timedelta(seconds=timeout)
        while _helpers.utcnow() < deadline:
            with self._lock:
                if self._calls:
                    return
        raise AssertionError("Timed out waiting for an in-flight signing call.")

    def __call__(self, url, method, body, headers):
        payload = json.loads(body.decode("utf-8"))["payload"]
        message = base64.b64decode(payload)
        with self._lock:
            self._calls.append(
                {
                    "url": url,
                    "method": method,
                    "headers": dict(headers),
                    "message": message,
                    "key_id": self._active_key,
                }
            )
        # Block while the test mutates key state mid-call.
        self._gate.wait()
        key_id = self._active_key
        signature = self._signers[key_id].sign(message)
        data = {
            "keyId": key_id,
            "signedBlob": base64.b64encode(signature).decode("utf-8"),
        }
        response = mock.create_autospec(transport.Response, instance=True)
        response.status = http_client.OK
        response.data = json.dumps(data).encode("utf-8")
        return response


@pytest.fixture
def iam_fake():
    with open(
        os.path.join(os.path.dirname(__file__), "data", "privatekey.pem"), "rb"
    ) as fh:
        old_private_pem = fh.read()
    with open(
        os.path.join(os.path.dirname(__file__), "data", "public_cert.pem"), "rb"
    ) as fh:
        old_public_pem = fh.read()

    new_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    new_private_pem = new_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    new_public_pem = new_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    fake = InMemoryIam()
    fake.add_key("key-old", old_private_pem, old_public_pem, active=True)
    fake.add_key("key-new", new_private_pem, new_public_pem)
    return fake


class TestSigningLifecyclePolicy(object):
    def _make_signer(self, fake, policy):
        return iam.Signer(
            request=fake,
            credentials=make_credentials(),
            service_account_email="sa@example.com",
            signing_policy=policy,
        )

    def _make_policy(self, fake, authorized):
        return _signing_policy.SigningLifecyclePolicy(
            authorized_keys=authorized, verifiers=fake.verifiers
        )

    def test_sign_without_policy_still_returns_signature(self, iam_fake):
        signer = iam.Signer(
            request=iam_fake,
            credentials=make_credentials(),
            service_account_email="sa@example.com",
        )
        signature = signer.sign(b"no policy")
        assert isinstance(signature, bytes)
        assert signer.signing_policy is None
        assert len(iam_fake.calls) == 1

    def test_new_signing_uses_only_authorized_returned_key(self, iam_fake):
        policy = self._make_policy(iam_fake, ["key-new"])
        signer = self._make_signer(iam_fake, policy)
        iam_fake.set_active_key("key-new")

        signature = signer.sign(b"fresh message")

        assert policy.pending_count == 0
        assert iam_fake.verifiers["key-new"].verify(b"fresh message", signature)
        assert iam_fake.calls[-1]["key_id"] == "key-new"

    def test_new_signing_rejected_when_returned_key_retired(self, iam_fake):
        policy = self._make_policy(iam_fake, ["key-old"])
        signer = self._make_signer(iam_fake, policy)
        # IAM rotates to a key the policy never authorized for new signing.
        iam_fake.set_active_key("key-new")

        # The remote call succeeds, but the returned signature must be
        # refused because the key actually used is not authorized.
        with pytest.raises(exceptions.KeyRetirementError):
            signer.sign(b"should be refused")
        assert policy.pending_count == 0
        assert len(iam_fake.calls) == 1

    def test_historical_signature_still_verifiable_after_retirement(
        self, iam_fake
    ):
        policy = self._make_policy(iam_fake, ["key-old", "key-new"])
        signer = self._make_signer(iam_fake, policy)
        archived_message = b"archived message"
        archived_signature = signer.sign(archived_message)

        # Rotate: key-old retires, key-new becomes the only signing key.
        policy.retire_key("key-old", verifier=iam_fake.verifiers["key-old"])
        iam_fake.set_active_key("key-new")

        assert policy.verify_historical(
            "key-old", archived_message, archived_signature
        )
        assert "key-old" in policy.retired_keys

        # New signing still works with the surviving authorized key.
        fresh_signature = signer.sign(b"fresh message")
        assert iam_fake.verifiers["key-new"].verify(
            b"fresh message", fresh_signature
        )

    def test_late_signing_call_rejected_after_mid_call_retirement(
        self, iam_fake
    ):
        policy = self._make_policy(iam_fake, ["key-old"])
        signer = self._make_signer(iam_fake, policy)
        iam_fake.hold_next_signing_call()

        result = {}

        def run():
            try:
                result["signature"] = signer.sign(b"late message")
            except Exception as error:  # noqa: BLE001: re-raised on the main thread.
                result["error"] = error

        worker = threading.Thread(target=run)
        worker.start()
        iam_fake.wait_for_in_flight()

        # The call is outstanding: one pending receipt must be observable,
        # carrying exactly the message being signed.
        assert policy.pending_count == 1
        assert policy.pending_receipts[0]["message"] == b"late message"

        # Retire the key while the remote call has not returned yet, and
        # rotate IAM onto a key the policy no longer authorizes for signing.
        policy.retire_key("key-old", verifier=iam_fake.verifiers["key-old"])
        iam_fake.set_active_key("key-new")
        iam_fake.release()
        worker.join(timeout=5)

        assert not worker.is_alive()
        assert isinstance(result["error"], exceptions.KeyRetirementError)
        assert "signature" not in result
        assert policy.pending_count == 0
        # The remote service was really invoked; only the local acceptance
        # of its result was refused.
        assert len(iam_fake.calls) == 1
        assert iam_fake.calls[0]["message"] == b"late message"

    def test_late_signing_call_accepted_when_returned_key_still_authorized(
        self, iam_fake
    ):
        policy = self._make_policy(iam_fake, ["key-old", "key-new"])
        signer = self._make_signer(iam_fake, policy)
        iam_fake.hold_next_signing_call()

        result = {}

        def run():
            result["signature"] = signer.sign(b"switched message")

        worker = threading.Thread(target=run)
        worker.start()
        iam_fake.wait_for_in_flight()

        # A policy update (rotation) happens mid-call, but the new key is also
        # authorized, so the late result must be accepted.
        policy.retire_key("key-old", verifier=iam_fake.verifiers["key-old"])
        iam_fake.set_active_key("key-new")
        iam_fake.release()
        worker.join(timeout=5)

        assert not worker.is_alive()
        assert policy.pending_count == 0
        assert iam_fake.verifiers["key-new"].verify(
            b"switched message", result["signature"]
        )
        assert "key-old" in policy.retired_keys
