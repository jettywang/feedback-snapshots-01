import logging

import pytest
import requests
import requests_mock

from hvac import Client
from hvac import audit
from hvac import exceptions
from hvac.constants.client import DEFAULT_URL

JOB_ID = "JOB-42"
MOCK_PATH = "v1/secret/data/foo"
MOCK_URL = f"{DEFAULT_URL}/{MOCK_PATH}"
REQUEST_ID = "abcd-1234-request-id"
SECRET_VALUE = "super-secret-password-value"
SECRET_BODY = {"data": {"password": SECRET_VALUE}}


@pytest.fixture
def client():
    return Client(token="root-token")


class TestAuditReceipts:
    def test_json_success_receipt_preserves_return_type(self, client):
        with requests_mock.Mocker() as mocker:
            mocker.post(
                MOCK_URL,
                status_code=200,
                json={"request_id": REQUEST_ID, "data": SECRET_BODY},
            )

            with client.audit(job_id=JOB_ID) as recorder:
                result = client.write_data(
                    "secret/data/foo",
                    data=SECRET_BODY,
                )

        # The call still returns exactly what the JSONAdapter normally returns.
        assert isinstance(result, dict)
        assert result["data"] == SECRET_BODY

        receipt = recorder.last_receipt
        assert len(recorder.receipts) == 1
        assert receipt.job_id == JOB_ID
        assert receipt.method == "POST"
        assert receipt.url == MOCK_URL
        assert receipt.path == MOCK_PATH
        assert receipt.mount_point == "secret"
        assert receipt.status_code == 200
        assert receipt.request_id == REQUEST_ID
        assert receipt.outcome == audit.OUTCOME_SUCCESS
        assert receipt.error_type is None
        assert receipt.error_message is None
        assert isinstance(receipt.started_at, str)
        assert isinstance(receipt.elapsed_ms, float)

    def test_empty_success_receipt_marks_unobservable_request_id(self, client):
        with requests_mock.Mocker() as mocker:
            mocker.post(MOCK_URL, status_code=204)

            with client.audit(job_id=JOB_ID) as recorder:
                result = client.write_data(
                    "secret/data/foo",
                    data=SECRET_BODY,
                )

        # Non-200 responses are returned as the raw Response by JSONAdapter.
        assert isinstance(result, requests.Response)
        assert result.status_code == 204

        receipt = recorder.last_receipt
        assert receipt.outcome == audit.OUTCOME_SUCCESS
        assert receipt.status_code == 204
        # There is no body, so a server-side request id cannot be observed.
        assert receipt.request_id == audit.UNOBSERVED
        assert receipt.mount_point == "secret"

    def test_permission_denied_receipt(self, client):
        with requests_mock.Mocker() as mocker:
            mocker.post(
                MOCK_URL,
                status_code=403,
                json={"errors": ["permission denied"]},
            )

            with client.audit(job_id=JOB_ID) as recorder:
                with pytest.raises(exceptions.Forbidden):
                    client.write_data("secret/data/foo", data=SECRET_BODY)

        # A receipt is still produced even though the call raised.
        receipt = recorder.last_receipt
        assert receipt.outcome == audit.OUTCOME_PERMISSION_DENIED
        assert receipt.status_code == 403
        assert receipt.request_id == audit.UNOBSERVED
        assert receipt.error_type == "hvac.exceptions.Forbidden"
        assert receipt.error_message == "permission denied"
        assert receipt.mount_point == "secret"
        assert receipt.job_id == JOB_ID

    def test_transport_exception_receipt_marks_state_unobservable(self, client):
        with requests_mock.Mocker() as mocker:
            mocker.post(MOCK_URL, exc=requests.ConnectionError("connection refused"))

            with client.audit(job_id=JOB_ID) as recorder:
                with pytest.raises(requests.ConnectionError):
                    client.write_data("secret/data/foo", data=SECRET_BODY)

        receipt = recorder.last_receipt
        assert receipt.outcome == audit.OUTCOME_TRANSPORT_ERROR
        # No response came back, so HTTP-level state is explicitly unobserved.
        assert receipt.status_code == audit.UNOBSERVED
        assert receipt.request_id == audit.UNOBSERVED
        assert receipt.error_type == "requests.exceptions.ConnectionError"
        assert "connection refused" in receipt.error_message
        assert receipt.mount_point == "secret"
        assert isinstance(receipt.elapsed_ms, float)

    def test_session_restored_after_context(self, client):
        original_request = client.adapter.session.request

        with requests_mock.Mocker() as mocker:
            mocker.post(MOCK_URL, status_code=204)
            with client.audit(job_id=JOB_ID) as recorder:
                client.write_data("secret/data/foo", data=SECRET_BODY)
                assert client.adapter.session.request != original_request

            # Instrumentation is removed even after a normal exit.
            assert client.adapter.session.request == original_request
            client.write_data("secret/data/foo", data=SECRET_BODY)

        # Calls made outside the context produce no receipts.
        assert len(recorder.receipts) == 1

    def test_session_restored_after_raised_exception(self, client):
        original_request = client.adapter.session.request

        with requests_mock.Mocker() as mocker:
            mocker.post(MOCK_URL, exc=requests.Timeout("timed out"))
            with client.audit() as recorder:
                with pytest.raises(requests.Timeout):
                    client.write_data("secret/data/foo", data=SECRET_BODY)

        assert client.adapter.session.request == original_request
        assert len(recorder.receipts) == 1
        assert recorder.last_receipt.outcome == audit.OUTCOME_TRANSPORT_ERROR

    def test_multiple_calls_collect_multiple_receipts_in_order(self, client):
        other_path = "v1/secret/data/bar"
        with requests_mock.Mocker() as mocker:
            mocker.post(MOCK_URL, status_code=200, json={"request_id": "id-1"})
            mocker.post(
                f"{DEFAULT_URL}/{other_path}",
                status_code=200,
                json={"request_id": "id-2"},
            )

            with client.audit(job_id=JOB_ID) as recorder:
                client.write_data("secret/data/foo", data=SECRET_BODY)
                client.write_data("secret/data/bar", data=SECRET_BODY)

        assert [receipt.request_id for receipt in recorder.receipts] == [
            "id-1",
            "id-2",
        ]
        assert all(receipt.job_id == JOB_ID for receipt in recorder.receipts)

    def test_receipts_and_logs_never_contain_secrets(self, client, caplog):
        caplog.set_level(logging.INFO, logger="hvac.audit")

        with requests_mock.Mocker() as mocker:
            mocker.post(
                MOCK_URL,
                status_code=200,
                json={"request_id": REQUEST_ID, "data": SECRET_BODY},
            )
            with client.audit(job_id=JOB_ID) as recorder:
                client.write_data("secret/data/foo", data=SECRET_BODY)

        receipt_dict = recorder.last_receipt.to_dict()
        log_dict = recorder.last_receipt.as_log_dict()

        serialized = [str(receipt_dict), str(log_dict)]
        serialized.extend(record.getMessage() for record in caplog.records)

        for blob in serialized:
            assert SECRET_VALUE not in blob
            assert "root-token" not in blob
            assert "X-Vault-Token" not in blob

        # The log view intentionally omits the full URL and error detail.
        assert "url" not in log_dict
        assert "error_message" not in log_dict
        # But the reconciliation fields remain present in the log view.
        assert log_dict["job_id"] == JOB_ID
        assert log_dict["request_id"] == REQUEST_ID
        assert log_dict["mount_point"] == "secret"

    @pytest.mark.parametrize(
        "url,expected_mount",
        [
            (f"{DEFAULT_URL}/v1/secret/data/foo", "secret"),
            (f"{DEFAULT_URL}/v1/auth/approle/login", "auth/approle"),
            (f"{DEFAULT_URL}/v1/sys/health", None),
            (f"{DEFAULT_URL}/v1/sys/mounts", None),
        ],
    )
    def test_mount_point_derivation(self, url, expected_mount):
        assert audit._derive_mount_point(url) == expected_mount

    def test_receipt_dict_is_serializable(self, client):
        with requests_mock.Mocker() as mocker:
            mocker.post(MOCK_URL, status_code=204)
            with client.audit(job_id=JOB_ID) as recorder:
                client.write_data("secret/data/foo", data=SECRET_BODY)

        receipt_dict = recorder.last_receipt.to_dict()
        expected_keys = {
            "job_id",
            "method",
            "url",
            "path",
            "mount_point",
            "status_code",
            "request_id",
            "outcome",
            "error_type",
            "error_message",
            "started_at",
            "elapsed_ms",
        }
        assert set(receipt_dict.keys()) == expected_keys
        assert receipt_dict["outcome"] == audit.OUTCOME_SUCCESS
