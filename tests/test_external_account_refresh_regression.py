"""Offline regression tests for the external account ``Credentials.refresh`` flow.

Every test drives the real ``google.auth.external_account.Credentials.refresh``
entry point against synthetic in-memory configuration and a recording
``transport.Request`` stand-in. No network access, credential files, or
environment state is required.

The subject-token retrieval, STS token exchange, and service account
impersonation (delegation) stages are each forced to surface the same
externally readable error text. The tests prove that the stage at which a
refresh stopped can still be determined from the calls that actually reached
the stand-in endpoints and from the resulting credential state.
"""

import datetime
import http.client as http_client
import json
from unittest import mock

import pytest  # type: ignore

from google.auth import _helpers
from google.auth import exceptions
from google.auth import external_account
from google.auth import transport

# Shared error text surfaced by all three refresh stages. Whoever is on call
# sees this exact string no matter which stage failed, so the failing stage
# must be inferred from the recorded calls and the credential state.
STAGE_AGNOSTIC_ERROR = "synthetic identity backend outage (regression sentinel)"

TOKEN_URL = "https://sts.googleapis.com/v1/token"
AUDIENCE = (
    "//iam.googleapis.com/projects/123456"
    "/locations/global/workloadIdentityPools/pool-id/providers/provider-id"
)
SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
SCOPES = ["scope1", "scope2"]
SERVICE_ACCOUNT_EMAIL = "service-1234@service-name.iam.gserviceaccount.com"
IMPERSONATION_URL = (
    "https://us-east1-iamcredentials.googleapis.com/v1/projects/-"
    "/serviceAccounts/{}:generateAccessToken".format(SERVICE_ACCOUNT_EMAIL)
)
SA_ACCESS_TOKEN = "SA_ACCESS_TOKEN"
STS_SUCCESS_RESPONSE = {
    "access_token": "STS_ACCESS_TOKEN",
    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "scope1 scope2",
}
STS_ERROR_RESPONSE = {
    "error": "invalid_request",
    "error_description": STAGE_AGNOSTIC_ERROR,
}
IMPERSONATION_ERROR_RESPONSE = {
    "error": {
        "code": 400,
        "message": STAGE_AGNOSTIC_ERROR,
        "status": "INVALID_ARGUMENT",
    }
}


class RecordingRequest(object):
    """A ``transport.Request`` stand-in that records every call it receives.

    Responses are queued per URL so a test can prove exactly which synthetic
    endpoints were actually reached, and in which order. A call to an
    unrouted or exhausted URL fails the test immediately.
    """

    def __init__(self):
        self.calls = []
        self._routes = {}

    def add_route(self, url, *responses):
        """Queues ``(status, body)`` responses returned in order for ``url``."""
        self._routes[url] = list(responses)

    def __call__(self, url, method="GET", body=None, headers=None, **kwargs):
        self.calls.append(
            {"url": url, "method": method, "body": body, "headers": headers}
        )
        assert url in self._routes and self._routes[url], (
            "unexpected request to {}".format(url)
        )
        status, data = self._routes[url].pop(0)
        response = mock.create_autospec(transport.Response, instance=True)
        response.status = status
        response.data = json.dumps(data).encode("utf-8")
        return response

    @property
    def urls(self):
        return [call["url"] for call in self.calls]


class CredentialsImpl(external_account.Credentials):
    """External account credentials with a controllable subject token source."""

    def __init__(self, subject_token_error=None, **kwargs):
        super(CredentialsImpl, self).__init__(**kwargs)
        self._subject_token_error = subject_token_error
        self.subject_token_retrievals = 0

    def retrieve_subject_token(self, request):
        self.subject_token_retrievals += 1
        if self._subject_token_error is not None:
            raise self._subject_token_error
        return "synthetic-subject-token"


def make_direct_credentials(subject_token_error=None):
    """Builds credentials for the direct exchange path (no impersonation)."""
    return CredentialsImpl(
        audience=AUDIENCE,
        subject_token_type=SUBJECT_TOKEN_TYPE,
        token_url=TOKEN_URL,
        credential_source={"file": "/synthetic/subject-token"},
        scopes=SCOPES,
        subject_token_error=subject_token_error,
    )


def make_delegating_credentials():
    """Builds credentials for the service account impersonation path."""
    return CredentialsImpl(
        audience=AUDIENCE,
        subject_token_type=SUBJECT_TOKEN_TYPE,
        token_url=TOKEN_URL,
        credential_source={"file": "/synthetic/subject-token"},
        scopes=SCOPES,
        service_account_impersonation_url=IMPERSONATION_URL,
    )


def impersonation_success_response():
    expire_time = (
        _helpers.utcnow().replace(microsecond=0) + datetime.timedelta(seconds=2800)
    ).isoformat("T") + "Z"
    return {"accessToken": SA_ACCESS_TOKEN, "expireTime": expire_time}


def attempt_refresh(credentials, request):
    """Runs the real ``Credentials.refresh`` entry point once and records an
    on-call readable report of the attempt.

    Returns a dict with:
      * ``reached``: stand-in endpoint URLs actually hit during this attempt.
      * ``error``: the externally readable error text, or None on success.
      * ``token`` / ``expiry``: the resulting credential state.
      * ``usable``: whether the credential can authorize requests right now.
    """
    already_recorded = len(request.calls)
    error = None
    try:
        credentials.refresh(request)
    except exceptions.GoogleAuthError as exc:
        error = str(exc)
    return {
        "reached": request.urls[already_recorded:],
        "error": error,
        "token": credentials.token,
        "expiry": credentials.expiry,
        "usable": credentials.valid,
    }


class TestDirectExchange(object):
    """Regression coverage for the direct (non-impersonated) exchange path."""

    def test_subject_token_stage_failure_reaches_no_endpoint(self):
        credentials = make_direct_credentials(
            subject_token_error=exceptions.RefreshError(STAGE_AGNOSTIC_ERROR)
        )
        request = RecordingRequest()
        request.add_route(TOKEN_URL, (http_client.OK, STS_SUCCESS_RESPONSE))

        report = attempt_refresh(credentials, request)

        assert STAGE_AGNOSTIC_ERROR in report["error"]
        # The failure happened before any stand-in was reached, even though a
        # healthy STS route was available.
        assert report["reached"] == []
        assert credentials.subject_token_retrievals == 1
        assert report["token"] is None
        assert not report["usable"]

    def test_sts_stage_failure_reaches_token_endpoint_only(self):
        credentials = make_direct_credentials()
        request = RecordingRequest()
        request.add_route(TOKEN_URL, (http_client.BAD_REQUEST, STS_ERROR_RESPONSE))

        report = attempt_refresh(credentials, request)

        assert STAGE_AGNOSTIC_ERROR in report["error"]
        assert report["reached"] == [TOKEN_URL]
        assert report["token"] is None
        assert not report["usable"]

    def test_direct_exchange_success_yields_usable_sts_token(self):
        credentials = make_direct_credentials()
        request = RecordingRequest()
        request.add_route(TOKEN_URL, (http_client.OK, STS_SUCCESS_RESPONSE))

        report = attempt_refresh(credentials, request)

        assert report["error"] is None
        # Direct exchange stops at the STS endpoint; the impersonation
        # endpoint is not even routed, so reaching it would fail the test.
        assert report["reached"] == [TOKEN_URL]
        assert report["token"] == STS_SUCCESS_RESPONSE["access_token"]
        assert report["usable"]


class TestServiceAccountDelegation(object):
    """Regression coverage for the service account impersonation path."""

    def test_delegation_failure_after_source_exchange_then_approved_retry(self):
        credentials = make_delegating_credentials()
        request = RecordingRequest()
        request.add_route(TOKEN_URL, (http_client.OK, STS_SUCCESS_RESPONSE))
        # The delegation endpoint fails once, then approves the retry.
        request.add_route(
            IMPERSONATION_URL,
            (http_client.BAD_REQUEST, IMPERSONATION_ERROR_RESPONSE),
            (http_client.OK, impersonation_success_response()),
        )

        first = attempt_refresh(credentials, request)

        # The source exchange completed before the delegation stage failed.
        assert first["reached"] == [TOKEN_URL, IMPERSONATION_URL]
        assert STAGE_AGNOSTIC_ERROR in first["error"]
        assert first["token"] is None
        assert not first["usable"]
        # Credential state proves the source exchange happened: the source
        # credentials behind the delegation hold a usable STS token.
        source_credentials = credentials._impersonated_credentials._source_credentials
        assert source_credentials.token == STS_SUCCESS_RESPONSE["access_token"]
        assert source_credentials.valid

        # Approved retry from the same credentials object.
        second = attempt_refresh(credentials, request)

        assert second["error"] is None
        # The source token is still fresh, so only the delegation endpoint is
        # reached again; the STS exchange is not repeated.
        assert second["reached"] == [IMPERSONATION_URL]
        assert second["token"] == SA_ACCESS_TOKEN
        assert second["usable"]
        assert credentials.token == SA_ACCESS_TOKEN

    def test_full_delegation_success_yields_impersonated_token(self):
        credentials = make_delegating_credentials()
        request = RecordingRequest()
        request.add_route(TOKEN_URL, (http_client.OK, STS_SUCCESS_RESPONSE))
        request.add_route(
            IMPERSONATION_URL, (http_client.OK, impersonation_success_response())
        )

        report = attempt_refresh(credentials, request)

        assert report["error"] is None
        assert report["reached"] == [TOKEN_URL, IMPERSONATION_URL]
        # The usable token is the impersonated one, not the STS token.
        assert report["token"] == SA_ACCESS_TOKEN
        assert report["usable"]


class TestStageAttributionFromFinalException(object):
    """The final exception text is identical across stages; only the recorded
    calls and the credential state reveal how far the refresh actually got."""

    @staticmethod
    def _scenario(stage):
        if stage == "subject_token":
            credentials = make_direct_credentials(
                subject_token_error=exceptions.RefreshError(STAGE_AGNOSTIC_ERROR)
            )
            request = RecordingRequest()
            request.add_route(TOKEN_URL, (http_client.OK, STS_SUCCESS_RESPONSE))
            expected_reached = []
        elif stage == "sts_exchange":
            credentials = make_direct_credentials()
            request = RecordingRequest()
            request.add_route(TOKEN_URL, (http_client.BAD_REQUEST, STS_ERROR_RESPONSE))
            expected_reached = [TOKEN_URL]
        else:  # delegation
            credentials = make_delegating_credentials()
            request = RecordingRequest()
            request.add_route(TOKEN_URL, (http_client.OK, STS_SUCCESS_RESPONSE))
            request.add_route(
                IMPERSONATION_URL,
                (http_client.BAD_REQUEST, IMPERSONATION_ERROR_RESPONSE),
            )
            expected_reached = [TOKEN_URL, IMPERSONATION_URL]
        return credentials, request, expected_reached

    @pytest.mark.parametrize("stage", ["subject_token", "sts_exchange", "delegation"])
    def test_identical_error_text_is_attributable_by_stage(self, stage):
        credentials, request, expected_reached = self._scenario(stage)

        # The only check on the raised exception itself: it always carries the
        # same externally readable text, regardless of the failing stage.
        with pytest.raises(exceptions.GoogleAuthError) as excinfo:
            credentials.refresh(request)
        assert STAGE_AGNOSTIC_ERROR in str(excinfo.value)

        # Attribution comes from what actually reached the stand-ins...
        assert request.urls == expected_reached
        # ...and from the credential state left behind.
        assert credentials.token is None
        assert not credentials.valid
        if stage == "delegation":
            # The earlier stages provably happened: the source credentials
            # behind the delegation completed the STS exchange.
            source_credentials = (
                credentials._impersonated_credentials._source_credentials
            )
            assert source_credentials.token == STS_SUCCESS_RESPONSE["access_token"]
            assert source_credentials.valid
        else:
            # No delegation stage was ever set up.
            assert credentials._impersonated_credentials is None
