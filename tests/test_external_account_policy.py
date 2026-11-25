import datetime
from unittest import mock

import pytest

from google.auth import _helpers
from google.auth import exceptions
from google.auth import external_account_policy as policy_module
from google.auth import identity_pool
from google.oauth2 import sts

AUDIENCE = (
    "//iam.googleapis.com/projects/123456/locations/global/"
    "workloadIdentityPools/pool/providers/provider"
)
TOKEN_URL = "https://sts.example.com/v1/token"
SA_EMAIL = "delegate@project.iam.gserviceaccount.com"
IMPERSONATION_URL = (
    "https://iamcredentials.example.com/v1/projects/-/serviceAccounts/"
    + SA_EMAIL
    + ":generateAccessToken"
)
SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


class Recorder:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)


@pytest.fixture
def evidence_file(tmp_path):
    path = tmp_path / "subject-token"
    path.write_text("local-evidence-token")
    return path


@pytest.fixture
def config(evidence_file):
    return {
        "audience": AUDIENCE,
        "subject_token_type": SUBJECT_TOKEN_TYPE,
        "token_url": TOKEN_URL,
        "credential_source": {"file": str(evidence_file)},
        "scopes": SCOPES,
    }


def make_credentials(config, recorder, policy, delegation=False):
    kwargs = dict(config)
    if delegation:
        kwargs["service_account_impersonation_url"] = IMPERSONATION_URL
    return identity_pool.Credentials(
        exchange_policy=policy,
        exchange_recorder=recorder,
        **kwargs,
    )


def sts_response():
    return {"access_token": "sts-access-token", "expires_in": 3600}


def iam_response():
    expiry = _helpers.utcnow() + datetime.timedelta(seconds=3600)
    return "service-account-access-token", expiry


def test_policy_binds_source_audience_and_delegation_target(evidence_file):
    grant = policy_module.ExchangeGrant(
        source=str(evidence_file),
        audience=AUDIENCE,
        service_account=SA_EMAIL,
        impersonation_url=IMPERSONATION_URL,
    )
    policy = policy_module.IdentityExchangePolicy([grant])

    approval = policy.approve(
        source=str(evidence_file),
        audience=AUDIENCE,
        service_account=SA_EMAIL,
        impersonation_url=IMPERSONATION_URL,
    )

    approval.require_evidence()
    approval.require_exchange()
    approval.require_delegation()

    with pytest.raises(exceptions.RefreshError):
        policy.authorize_exchange(
            source=str(evidence_file),
            audience="//iam.googleapis.com/other-audience",
        )
    with pytest.raises(policy_module.ExchangeApprovalRequired):
        policy.authorize_delegation(
            source=str(evidence_file),
            audience=AUDIENCE,
            service_account="other@project.iam.gserviceaccount.com",
        )


def test_pure_exchange_records_evidence_exchange_and_update(config, evidence_file):
    recorder = Recorder()
    policy = policy_module.IdentityExchangePolicy(
        [policy_module.ExchangeGrant(str(evidence_file), AUDIENCE)]
    )
    credentials = make_credentials(config, recorder, policy)

    with mock.patch.object(
        sts.Client,
        "exchange_token",
        autospec=True,
        return_value=sts_response(),
    ) as exchange:
        credentials.refresh(request=None)

    assert credentials.token == "sts-access-token"
    assert recorder.events == ["evidence", "exchange", "credential_update"]
    assert exchange.call_count == 1
    assert exchange.call_args.kwargs["audience"] == AUDIENCE
    assert exchange.call_args.kwargs["subject_token"] == "local-evidence-token"


def test_approved_delegation_records_full_order(config, evidence_file):
    recorder = Recorder()
    policy = policy_module.IdentityExchangePolicy(
        [
            policy_module.ExchangeGrant(
                str(evidence_file),
                AUDIENCE,
                SA_EMAIL,
                impersonation_url=IMPERSONATION_URL,
            )
        ]
    )
    credentials = make_credentials(config, recorder, policy, delegation=True)

    with mock.patch.object(
        sts.Client, "exchange_token", autospec=True, return_value=sts_response()
    ) as exchange, mock.patch(
        "google.auth.impersonated_credentials._make_iam_token_request",
        return_value=iam_response(),
    ) as delegate:
        credentials.refresh(request=None)

    assert credentials.token == "service-account-access-token"
    assert credentials.service_account_email == SA_EMAIL
    assert recorder.events == [
        "evidence",
        "exchange",
        "delegation",
        "credential_update",
    ]
    assert exchange.call_count == 1
    assert delegate.call_count == 1
    assert delegate.call_args.kwargs["principal"] == SA_EMAIL


def test_source_only_approval_leaves_delegation_pending_then_recovers(
    config, evidence_file
):
    recorder = Recorder()
    policy = policy_module.IdentityExchangePolicy(
        [policy_module.ExchangeGrant(str(evidence_file), AUDIENCE)]
    )
    credentials = make_credentials(config, recorder, policy, delegation=True)

    iam = mock.Mock(return_value=iam_response())
    with mock.patch.object(
        sts.Client, "exchange_token", autospec=True, return_value=sts_response()
    ) as exchange, mock.patch(
        "google.auth.impersonated_credentials._make_iam_token_request", iam
    ):
        with pytest.raises(policy_module.ExchangeApprovalRequired) as pending_failure:
            credentials.refresh(request=None)

        pending = pending_failure.value.pending
        assert pending.completed_stages == ("evidence", "exchange")
        assert pending.is_service_account_identity is False
        assert pending.has_usable_token is False
        assert recorder.events == ["evidence", "exchange"]
        assert iam.call_count == 0
        assert credentials.token is None
        assert not credentials.valid
        assert credentials._impersonated_credentials.token is None

        source_credentials = credentials._impersonated_credentials._source_credentials
        assert source_credentials.token == "sts-access-token"

        # The application now adds the missing delegation approval for the
        # same source, audience, and target before the caller retries.
        policy.add(
            policy_module.ExchangeGrant(
                str(evidence_file),
                AUDIENCE,
                SA_EMAIL,
                impersonation_url=IMPERSONATION_URL,
            )
        )
        credentials.refresh(request=None)

    assert exchange.call_count == 1
    assert iam.call_count == 1
    assert credentials.token == "service-account-access-token"
    assert recorder.events == [
        "evidence",
        "exchange",
        "delegation",
        "credential_update",
    ]


def test_retryable_exchange_failure_repeats_full_recovery_order(config, evidence_file):
    recorder = Recorder()
    policy = policy_module.IdentityExchangePolicy(
        [
            policy_module.ExchangeGrant(
                str(evidence_file),
                AUDIENCE,
                SA_EMAIL,
                impersonation_url=IMPERSONATION_URL,
            )
        ]
    )
    credentials = make_credentials(config, recorder, policy, delegation=True)
    retryable = exceptions.RefreshError("temporary STS failure", retryable=True)

    with mock.patch.object(
        sts.Client,
        "exchange_token",
        autospec=True,
        side_effect=[retryable, sts_response()],
    ) as exchange, mock.patch(
        "google.auth.impersonated_credentials._make_iam_token_request",
        return_value=iam_response(),
    ) as iam:
        with pytest.raises(exceptions.RefreshError) as first_failure:
            credentials.refresh(request=None)
        assert first_failure.value.retryable
        assert recorder.events == ["evidence"]
        assert credentials.token is None

        credentials.refresh(request=None)

    assert exchange.call_count == 2
    assert iam.call_count == 1
    recovery_order = recorder.events[1:]
    assert recovery_order == [
        "evidence",
        "exchange",
        "delegation",
        "credential_update",
    ]
    assert credentials.token == "service-account-access-token"


def test_retryable_delegation_failure_can_retry_same_approval(config, evidence_file):
    recorder = Recorder()
    policy = policy_module.IdentityExchangePolicy(
        [
            policy_module.ExchangeGrant(
                str(evidence_file),
                AUDIENCE,
                SA_EMAIL,
                impersonation_url=IMPERSONATION_URL,
            )
        ]
    )
    credentials = make_credentials(config, recorder, policy, delegation=True)
    retryable = exceptions.RefreshError("temporary IAM failure", retryable=True)

    with mock.patch.object(
        sts.Client, "exchange_token", autospec=True, return_value=sts_response()
    ) as exchange, mock.patch(
        "google.auth.impersonated_credentials._make_iam_token_request",
        side_effect=[retryable, iam_response()],
    ) as iam:
        with pytest.raises(exceptions.RefreshError) as failure:
            credentials.refresh(request=None)
        assert failure.value.retryable
        assert credentials.token is None

        credentials.refresh(request=None)

    assert exchange.call_count == 1
    assert iam.call_count == 2
    assert recorder.events == [
        "evidence",
        "exchange",
        "delegation",
        "credential_update",
    ]
    assert credentials.token == "service-account-access-token"


def test_retry_with_wrong_target_approval_does_not_delegate(config, evidence_file):
    recorder = Recorder()
    policy = policy_module.IdentityExchangePolicy(
        [
            policy_module.ExchangeGrant(
                str(evidence_file),
                AUDIENCE,
                SA_EMAIL,
                impersonation_url=IMPERSONATION_URL,
            )
        ]
    )
    credentials = make_credentials(config, recorder, policy, delegation=True)
    retryable = exceptions.RefreshError("temporary IAM failure", retryable=True)

    with mock.patch.object(
        sts.Client, "exchange_token", autospec=True, return_value=sts_response()
    ), mock.patch(
        "google.auth.impersonated_credentials._make_iam_token_request",
        side_effect=[retryable, iam_response()],
    ) as iam:
        with pytest.raises(exceptions.RefreshError):
            credentials.refresh(request=None)

        credentials._exchange_policy = policy_module.IdentityExchangePolicy(
            [
                policy_module.ExchangeGrant(
                    str(evidence_file),
                    AUDIENCE,
                    "other@project.iam.gserviceaccount.com",
                )
            ]
        )
        with pytest.raises(policy_module.ExchangeApprovalRequired):
            credentials.refresh(request=None)

    assert iam.call_count == 1
    assert credentials.token is None
    assert recorder.events == ["evidence", "exchange"]


def test_no_policy_keeps_existing_refresh_path(config):
    credentials = identity_pool.Credentials(**config)

    with mock.patch.object(
        sts.Client,
        "exchange_token",
        autospec=True,
        return_value=sts_response(),
    ):
        credentials.refresh(request=None)

    assert credentials.token == "sts-access-token"
    assert credentials._exchange_session is None
