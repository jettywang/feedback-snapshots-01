import datetime
import json
import threading
import urllib.parse

from google.auth import credentials
from google.auth import downscoped


RESOURCE_A = "//storage.googleapis.com/projects/_/buckets/bucket-a"
RESOURCE_B = "//storage.googleapis.com/projects/_/buckets/bucket-b"
PERMISSION_VIEWER = "inRole:roles/storage.objectViewer"
PERMISSION_CREATOR = "inRole:roles/storage.objectCreator"

OLD_POLICY_TOKEN = "downscoped-v1-late-token"
NEW_POLICY_TOKEN = "downscoped-v2-token"
ACTIVE_V1_TOKEN = "downscoped-v1-active-token"
UNCHANGED_TOKEN = "downscoped-unchanged-token"
REVOKE_URL = "https://sts.googleapis.com/v1/revoke"


class SourceCredentials(credentials.Credentials):
    def refresh(self, request):
        self.token = "source-access-token"
        self.expiry = (
            datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            + datetime.timedelta(hours=1)
        )


class FakeResponse(object):
    def __init__(self, payload, status=200):
        self.status = status
        self.status_code = status
        if isinstance(payload, (bytes, bytearray)):
            self.data = bytes(payload)
        else:
            self.data = json.dumps(payload).encode("utf-8")


def sts_response(token):
    return {
        "access_token": token,
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
    }


def two_rule_boundary():
    return downscoped.CredentialAccessBoundary(
        [
            downscoped.AccessBoundaryRule(RESOURCE_A, [PERMISSION_VIEWER]),
            downscoped.AccessBoundaryRule(RESOURCE_B, [PERMISSION_CREATOR]),
        ]
    )


def tightened_boundary():
    return downscoped.CredentialAccessBoundary(
        [downscoped.AccessBoundaryRule(RESOURCE_A, [PERMISSION_VIEWER])]
    )


def parse_form(body):
    if not body:
        return {}
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    return urllib.parse.parse_qs(body)


def first_value(form, key):
    values = form.get(key)
    return values[0] if values else None


class InterleavingTransport(object):
    """Controllable in-memory STS, revocation, and resource transport."""

    def __init__(
        self,
        first_token=OLD_POLICY_TOKEN,
        second_token=NEW_POLICY_TOKEN,
        block_first_token=True,
    ):
        self.first_token = first_token
        self.second_token = second_token
        self.block_first_token = block_first_token
        self.first_token_entered = threading.Event()
        self.release_first_token = threading.Event()
        self.token_calls = []
        self.revoke_calls = []
        self.api_calls = []
        self._lock = threading.Lock()

    def _boundary_rule_count(self, body):
        form = parse_form(body)
        encoded_options = first_value(form, "options")
        options = json.loads(urllib.parse.unquote(encoded_options))
        return len(options["accessBoundary"]["accessBoundaryRules"])

    def __call__(self, url, method="POST", headers=None, body=None):
        headers = headers or {}

        if url.endswith("/token"):
            with self._lock:
                call_number = len(self.token_calls) + 1
                self.token_calls.append(
                    {
                        "call_number": call_number,
                        "rule_count": self._boundary_rule_count(body),
                        "subject_token": first_value(parse_form(body), "subject_token"),
                    }
                )

            if call_number == 1 and self.block_first_token:
                self.first_token_entered.set()
                assert self.release_first_token.wait(5)
                return FakeResponse(sts_response(self.first_token))

            token = self.first_token if call_number == 1 else self.second_token
            return FakeResponse(sts_response(token))

        if url.endswith("/revoke"):
            form = parse_form(body)
            with self._lock:
                self.revoke_calls.append(
                    {
                        "token": first_value(form, "token"),
                        "token_type_hint": first_value(form, "token_type_hint"),
                    }
                )
            return FakeResponse({})

        authorization = headers.get("authorization") or headers.get("Authorization")
        with self._lock:
            self.api_calls.append(
                {"url": url, "method": method, "authorization": authorization}
            )
        if authorization == "Bearer {}".format(NEW_POLICY_TOKEN):
            return FakeResponse({"ok": True}, status=200)
        return FakeResponse({"error": "forbidden"}, status=403)


class StaticTransport(object):
    def __init__(self, token=ACTIVE_V1_TOKEN):
        self.token = token
        self.token_calls = []
        self.revoke_calls = []
        self.api_calls = []

    def __call__(self, url, method="POST", headers=None, body=None):
        if url.endswith("/token"):
            self.token_calls.append(body)
            return FakeResponse(sts_response(self.token))
        if url.endswith("/revoke"):
            form = parse_form(body)
            self.revoke_calls.append(first_value(form, "token"))
            return FakeResponse({})
        authorization = (headers or {}).get("authorization")
        self.api_calls.append(authorization)
        if authorization == "Bearer {}".format(NEW_POLICY_TOKEN):
            return FakeResponse({"ok": True})
        return FakeResponse({"error": "forbidden"}, status=403)


def test_two_queued_requests_reject_late_v1_sts_callback_and_retry_on_v2():
    journal = downscoped.HandoffJournal()
    boundary_v1 = two_rule_boundary()
    boundary_v2 = tightened_boundary()
    transport = InterleavingTransport()
    credentials = downscoped.Credentials(
        SourceCredentials(),
        boundary_v1,
        revoke_url=REVOKE_URL,
        journal=journal,
    )
    unchanged = downscoped.Credentials(SourceCredentials(), two_rule_boundary())
    handoff = downscoped.AccessBoundaryHandoff(
        credentials, transport, journal=journal
    )

    request_1 = handoff.enqueue(
        request_id="request-1",
        method="GET",
        url="https://storage.example.com/bucket-a/object-1",
    )
    request_2 = handoff.enqueue(
        request_id="request-2",
        method="GET",
        url="https://storage.example.com/bucket-a/object-2",
    )
    assert request_1.queued_policy_version == 1
    assert request_2.queued_policy_version == 1

    worker = threading.Thread(target=lambda: handoff.process("request-1"))
    worker.start()
    try:
        assert transport.first_token_entered.wait(5)
        update_receipt = handoff.update_access_boundary(boundary_v2)
        assert update_receipt.old_policy_version == 1
        assert update_receipt.new_policy_version == 2
        transport.release_first_token.set()
        worker.join(5)
        assert not worker.is_alive()
    finally:
        transport.release_first_token.set()
        worker.join(5)

    result_1 = handoff.results["request-1"]
    assert result_1.succeeded
    assert result_1.retried
    assert [attempt.outcome for attempt in result_1.attempts] == [
        "stale_policy_exchange",
        "sent",
    ]
    assert result_1.sent_policy_versions == [2]
    assert result_1.attempts[0].revocation.succeeded
    assert result_1.retry_result["outcome"] == "sent"

    result_2 = handoff.process("request-2")
    assert result_2.succeeded
    assert not result_2.retried
    assert result_2.sent_policy_versions == [2]

    assert [call["rule_count"] for call in transport.token_calls] == [2, 1]
    assert transport.revoke_calls == [
        {"token": OLD_POLICY_TOKEN, "token_type_hint": "access_token"}
    ]
    assert [call["authorization"] for call in transport.api_calls] == [
        "Bearer {}".format(NEW_POLICY_TOKEN),
        "Bearer {}".format(NEW_POLICY_TOKEN),
    ]

    assert credentials.policy_version == 2
    assert credentials.token_policy_version == 2
    assert credentials.token == NEW_POLICY_TOKEN
    assert len(credentials.revocation_results) == 1
    revocation = credentials.revocation_results[0]
    assert revocation.succeeded
    assert revocation.policy_version == 1
    assert revocation.token == OLD_POLICY_TOKEN

    assert handoff.sent_policy_versions == [2, 2]
    assert [record["policy_version"] for record in handoff.sent_records] == [2, 2]

    assert unchanged.policy_version == 1
    assert len(unchanged.access_boundary.rules) == 2

    event_types = [event["type"] for event in journal.events]
    assert event_types.index("boundary_updated") < event_types.index(
        "sts_exchange_rejected"
    )
    assert event_types.index("sts_exchange_rejected") < event_types.index(
        "token_revocation_succeeded"
    )
    assert event_types.index("token_revocation_succeeded") < event_types.index(
        "request_sent"
    )


def test_update_entry_revokes_active_token_and_new_policy_retry_succeeds():
    journal = downscoped.HandoffJournal()
    transport = StaticTransport(token=ACTIVE_V1_TOKEN)
    credentials = downscoped.Credentials(
        SourceCredentials(),
        two_rule_boundary(),
        revoke_url=REVOKE_URL,
        journal=journal,
    )
    unchanged_transport = StaticTransport(token=UNCHANGED_TOKEN)
    unchanged = downscoped.Credentials(SourceCredentials(), two_rule_boundary())

    credentials.refresh(transport)
    unchanged.refresh(unchanged_transport)

    receipt = credentials.update_access_boundary(
        tightened_boundary(), request=transport
    )

    assert receipt.revocation.succeeded
    assert receipt.revocation.token == ACTIVE_V1_TOKEN
    assert transport.revoke_calls == [ACTIVE_V1_TOKEN]
    assert credentials.token is None
    assert credentials.policy_version == 2

    assert unchanged.policy_version == 1
    assert unchanged.token == UNCHANGED_TOKEN
    assert unchanged.policy_attestation()["policy_version"] == 1

    transport.token = NEW_POLICY_TOKEN
    handoff = downscoped.AccessBoundaryHandoff(
        credentials, transport, journal=journal
    )
    handoff.enqueue(
        request_id="queued-after-tightening",
        url="https://storage.example.com/bucket-a/object",
    )
    result = handoff.process("queued-after-tightening")

    assert result.succeeded
    assert result.sent_policy_versions == [2]
    assert transport.api_calls == ["Bearer {}".format(NEW_POLICY_TOKEN)]
