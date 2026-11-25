# Copyright 2026 Google LLC
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

import datetime
import json
from types import SimpleNamespace
import urllib.parse

import pytest

from google.auth import api_key
from google.auth import aws
from google.auth import connection_boundary as cb
from google.auth import exceptions
from google.auth import external_account


PRIVATE_TOKEN_URL = "https://10.0.0.10/v1/token"
PUBLIC_TOKEN_URL = "https://8.8.8.8/v1/token"
METADATA_URL = "http://169.254.169.254/latest/meta-data/identity"
APPROVED_API_URL = "https://authorized.example/v1/data"


class RecordingTransport:
    def __init__(self, responses=None):
        self.requests = []
        self.responses = list(responses or [])

    def __call__(self, url, method="GET", body=None, headers=None, **kwargs):
        self.requests.append(
            {
                "url": url,
                "method": method,
                "body": body,
                "headers": dict(headers or {}),
                "kwargs": kwargs,
            }
        )
        if self.responses:
            return self.responses.pop(0)
        return SimpleNamespace(status=200, data=b"{}", headers={})


def json_response(payload):
    return SimpleNamespace(
        status=200,
        data=json.dumps(payload).encode("utf-8"),
        headers={},
    )


STS_RESPONSE = json_response({"access_token": "google-token", "expires_in": 3600})


class ExampleExternalCredentials(external_account.Credentials):
    def __init__(
        self,
        identity_callback=None,
        metadata_url=None,
        **kwargs
    ):
        kwargs.setdefault("audience", "//iam.googleapis.com/projects/123")
        kwargs.setdefault("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
        kwargs.setdefault("credential_source", {})
        super(ExampleExternalCredentials, self).__init__(**kwargs)
        self.identity_callback = identity_callback or (lambda: "local-subject-token")
        self.metadata_url = metadata_url
        self.callback_requests = []

    def retrieve_subject_token(self, request):
        if self.metadata_url:
            request(
                url=self.metadata_url,
                method="GET",
                headers={"X-aws-ec2-metadata-token": "metadata-token"},
            )
        self.callback_requests.append(request)
        return self.identity_callback()


def make_credentials(boundary=None, token_url=PRIVATE_TOKEN_URL, **kwargs):
    return ExampleExternalCredentials(
        token_url=token_url,
        connection_boundary=boundary,
        scopes=["https://www.googleapis.com/auth/cloud-platform"],
        **kwargs
    )


def test_private_exchange_local_read_and_authorized_request():
    transport = RecordingTransport(
        [
            SimpleNamespace(status=200, data=b"identity-from-metadata", headers={}),
            STS_RESPONSE,
            json_response({}),
        ]
    )
    def callback():
        return "callback-subject-token"

    boundary = cb.ConnectionBoundary(
        exchange_url=PRIVATE_TOKEN_URL,
        credential_read_urls=[METADATA_URL],
        authorization_urls=[APPROVED_API_URL],
    )
    credentials = make_credentials(
        boundary=boundary,
        identity_callback=callback,
        metadata_url=METADATA_URL,
    )

    credentials.refresh(transport)

    assert [call["url"] for call in transport.requests[:2]] == [
        METADATA_URL,
        PRIVATE_TOKEN_URL,
    ]
    assert credentials.token == "google-token"
    assert len(credentials.callback_requests) == 1

    metadata_call, exchange_call = boundary.calls[:2]
    assert metadata_call.stage == cb.CREDENTIAL_READ
    assert metadata_call.credentials == ("aws_imdsv2_token",)
    assert exchange_call.stage == cb.EXCHANGE
    assert exchange_call.credentials == ("external_subject_token",)
    assert "authorization" not in {
        key.lower() for key in exchange_call.headers
    }

    exchange_connection = next(
        connection
        for connection in boundary.connections
        if connection.origin == "https://10.0.0.10"
    )
    assert exchange_connection.built_at == cb.EXCHANGE
    assert exchange_connection.attempts == 1

    headers = {}
    with boundary.operation(credentials) as operation:
        credentials.before_request(transport, "GET", APPROVED_API_URL, headers)
        authorized_transport = operation.guard(transport)
        authorized_transport(url=APPROVED_API_URL, method="GET", headers=headers)

    assert headers["authorization"] == "Bearer google-token"
    authorization_calls = [
        call for call in boundary.calls if call.stage == cb.AUTHORIZATION
    ]
    assert authorization_calls[-1].credentials == ("bearer_access_token",)
    authorization_connection = next(
        connection
        for connection in boundary.connections
        if connection.origin == "https://authorized.example"
    )
    assert authorization_connection.built_at == cb.AUTHORIZATION
    assert authorization_connection.attempts == 1


def test_approved_aws_region_survives_exchange():
    monkeypatch_env = {
        "AWS_ACCESS_KEY_ID": "AKIAEXAMPLE",
        "AWS_SECRET_ACCESS_KEY": "secret",
        "AWS_SESSION_TOKEN": "session",
        "AWS_REGION": "us-east-1",
    }
    import os
    import unittest.mock as mock

    transport = RecordingTransport([STS_RESPONSE])
    boundary = cb.ConnectionBoundary(
        exchange_url=PRIVATE_TOKEN_URL,
        approved_regions=["us-east-1"],
    )
    credential_source = {
        "environment_id": "aws1",
        "regional_cred_verification_url": (
            "https://sts.{region}.amazonaws.com?"
            "Action=GetCallerIdentity&Version=2011-06-15"
        ),
    }
    credentials = aws.Credentials(
        audience="//iam.googleapis.com/projects/123",
        subject_token_type="urn:ietf:params:aws:token-type:aws4_request",
        token_url=PRIVATE_TOKEN_URL,
        credential_source=credential_source,
        scopes=["scope"],
        connection_boundary=boundary,
    )

    with mock.patch.dict(os.environ, monkeypatch_env, clear=False):
        credentials.refresh(transport)

    exchange_body = dict(urllib.parse.parse_qsl(transport.requests[0]["body"].decode("utf-8")))
    wrapped = json.loads(urllib.parse.unquote(exchange_body["subject_token"]))
    assert "sts.us-east-1.amazonaws.com" in wrapped["url"]
    assert boundary.calls[-1].stage == cb.EXCHANGE


def test_retry_reuses_resolver_decision_and_connection():
    resolutions = []

    def resolver(host):
        resolutions.append(host)
        return ["10.1.2.3"]

    boundary = cb.ConnectionBoundary(resolver=resolver)
    operation = cb.BoundaryOperation(boundary)
    transport = RecordingTransport([STS_RESPONSE, STS_RESPONSE])
    guarded = operation.guard(transport)
    url = "https://private.example/token"

    guarded(url=url, method="POST", body=b"subject_token=one", headers={})
    guarded(url=url, method="POST", body=b"subject_token=one", headers={})

    assert resolutions == ["private.example"]
    assert len(transport.requests) == 2
    connection = operation.connections["https://private.example"]
    assert connection.built_at == cb.EXCHANGE
    assert connection.attempts == 2
    assert [call.attempt for call in operation.calls] == [1, 2]


def test_unadmitted_exchange_does_not_touch_transport_and_legacy_client_works():
    recording = RecordingTransport([STS_RESPONSE])
    boundary = cb.ConnectionBoundary()
    blocked = make_credentials(boundary=boundary, token_url=PUBLIC_TOKEN_URL)

    with pytest.raises(exceptions.ConnectionBoundaryError):
        blocked.refresh(recording)

    assert recording.requests == []
    denied_call = boundary.calls[-1]
    assert denied_call.stage == cb.EXCHANGE
    assert denied_call.error is not None

    legacy = make_credentials(boundary=None, token_url=PUBLIC_TOKEN_URL)
    legacy_transport = RecordingTransport([STS_RESPONSE])
    legacy.refresh(legacy_transport)
    assert legacy.token == "google-token"
    assert len(legacy_transport.requests) == 1


def test_authorization_rejection_leaves_old_client_usable():
    boundary = cb.ConnectionBoundary(authorization_urls=[APPROVED_API_URL])
    credentials = make_credentials(boundary=boundary)
    credentials.token = "old-token"
    credentials.expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    headers = {}

    with pytest.raises(exceptions.ConnectionBoundaryError):
        credentials.before_request(None, "GET", "https://evil.example", headers)
    assert headers == {}

    credentials._connection_boundary = None
    credentials.before_request(None, "GET", "https://evil.example", headers)
    assert headers["authorization"] == "Bearer old-token"

    api_boundary = cb.ConnectionBoundary(authorization_urls=[APPROVED_API_URL])
    api_credentials = api_key.Credentials("api-secret", api_boundary)
    with pytest.raises(exceptions.ConnectionBoundaryError):
        api_credentials.before_request(None, "GET", "https://evil.example", {})

    legacy_api_key = api_key.Credentials("api-secret")
    api_headers = {}
    legacy_api_key.before_request(None, "GET", "https://evil.example", api_headers)
    assert api_headers["x-goog-api-key"] == "api-secret"
