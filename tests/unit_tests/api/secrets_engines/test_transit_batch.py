import base64
import json
import unittest

import requests
import requests_mock

from hvac import Client, adapters, exceptions
from hvac.api.secrets_engines.transit import (
    BATCH_ITEM_ENCRYPTED,
    BATCH_ITEM_FAILED,
    BATCH_ITEM_MISSING,
    BatchEncryptionResult,
)

MOUNT_POINT = "transit"
KEY_NAME = "audit-key"
ENCRYPT_URL = "http://localhost:8200/v1/transit/encrypt/audit-key"


def b64(value):
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")


PLAINTEXTS = [
    b64("audit-secret-one"),
    b64("audit-secret-two"),
    b64("audit-secret-three"),
    b64("audit-secret-four"),
]

MIXED_RESPONSE = {
    "request_id": "req-mixed",
    "lease_id": "",
    "renewable": False,
    "lease_duration": 0,
    "data": {
        "batch_results": [
            {
                "ciphertext": "vault:v3:c2VjcmV0LW9uZQ==",
                "key_version": 3,
            },
            {
                "error": "invalid plaintext: audit-secret-two",
            },
            {
                "ciphertext": "vault:v4:c2VjcmV0LXRocmVl",
                "key_version": 4,
            },
            {
                "error": "ciphertext or plaintext is empty",
            },
        ]
    },
    "wrap_info": None,
    "warnings": None,
    "auth": None,
}

MISSING_RESPONSE = {
    "request_id": "req-missing",
    "data": {
        "batch_results": [
            {
                "ciphertext": "vault:v2:c2VjcmV0LW9uZQ==",
                "key_version": 2,
            }
        ]
    },
    "warnings": None,
    "auth": None,
}

BATCH_FAILURE_RESPONSE = {
    "errors": [
        "1 error occurred:\n\t* encryption key audit-key is not available; "
        "plaintext audit-secret-one rejected"
    ]
}


class TestTransitBatchEncryption(unittest.TestCase):
    """Unit tests for the item-aligned Transit batch encryption contract."""

    def setUp(self):
        self.client = Client(url="http://localhost:8200", token="test-token")

    def _encrypt(self, batch_input):
        return self.client.secrets.transit.encrypt_data_batch(
            name=KEY_NAME,
            batch_input=batch_input,
            mount_point=MOUNT_POINT,
        )

    @requests_mock.Mocker()
    def test_mixed_success_and_failure_preserves_alignment_and_key_versions(
        self, requests_mocker
    ):
        requests_mocker.register_uri(
            method="POST", url=ENCRYPT_URL, json=MIXED_RESPONSE
        )
        batch_input = [
            {"plaintext": plaintext}
            for plaintext in PLAINTEXTS
        ]

        result = self._encrypt(batch_input)

        self.assertIsInstance(result, BatchEncryptionResult)
        self.assertEqual([item.index for item in result.items], [0, 1, 2, 3])
        self.assertEqual(
            [item.status for item in result.items],
            [
                BATCH_ITEM_ENCRYPTED,
                BATCH_ITEM_FAILED,
                BATCH_ITEM_ENCRYPTED,
                BATCH_ITEM_FAILED,
            ],
        )
        self.assertEqual(result.encrypted_indices, (0, 2))
        self.assertEqual(result.failed_indices, (1, 3))
        self.assertEqual(result.missing_indices, ())
        self.assertEqual(result.retry_indices, (1, 3))
        self.assertFalse(result.all_encrypted)

        self.assertEqual(
            result[0].ciphertext, "vault:v3:c2VjcmV0LW9uZQ=="
        )
        self.assertEqual(result[0].key_version, 3)
        self.assertEqual(
            result[2].ciphertext, "vault:v4:c2VjcmV0LXRocmVl"
        )
        self.assertEqual(result[2].key_version, 4)
        self.assertIsNone(result[1].ciphertext)
        self.assertIsNone(result[1].key_version)

        self.assertIn("invalid plaintext", result[1].error)
        self.assertEqual(
            result[3].error, "ciphertext or plaintext is empty"
        )
        for item in result.items:
            self.assertNotIn(PLAINTEXTS[1], item.error or "")
            self.assertNotIn("audit-secret-two", item.error or "")

        self.assertEqual(result.raw_response, MIXED_RESPONSE)
        self.assertEqual(result.as_dict()["items"][0]["key_version"], 3)

    @requests_mock.Mocker()
    def test_missing_results_are_distinct_from_failures(self, requests_mocker):
        requests_mocker.register_uri(
            method="POST", url=ENCRYPT_URL, json=MISSING_RESPONSE
        )
        batch_input = [{"plaintext": plaintext} for plaintext in PLAINTEXTS[:3]]

        result = self._encrypt(batch_input)

        self.assertEqual(len(result.items), len(batch_input))
        self.assertEqual(result.encrypted_indices, (0,))
        self.assertEqual(result.failed_indices, ())
        self.assertEqual(result.missing_indices, (1, 2))
        self.assertEqual(result.retry_indices, (1, 2))
        self.assertFalse(result.all_encrypted)

        for item in result.missing_items:
            self.assertTrue(item.missing)
            self.assertFalse(item.failed)
            self.assertIsNone(item.error)
            self.assertIsNone(item.ciphertext)
            self.assertIsNone(item.key_version)

        self.assertTrue(result[0].encrypted)
        self.assertEqual(result[0].key_version, 2)
        self.assertIsNone(result.batch_error)
        self.assertEqual(result.raw_response, MISSING_RESPONSE)

    @requests_mock.Mocker()
    def test_null_or_empty_batch_slots_are_missing(self, requests_mocker):
        response = {
            "data": {
                "batch_results": [
                    {"ciphertext": "vault:v1:AA==", "key_version": 1},
                    None,
                    {},
                ]
            }
        }
        requests_mocker.register_uri(
            method="POST", url=ENCRYPT_URL, json=response
        )
        batch_input = [{"plaintext": plaintext} for plaintext in PLAINTEXTS[:4]]

        result = self._encrypt(batch_input)

        self.assertEqual(result.encrypted_indices, (0,))
        self.assertEqual(result.failed_indices, ())
        self.assertEqual(result.missing_indices, (1, 2, 3))
        self.assertEqual(result.retry_indices, (1, 2, 3))

    @requests_mock.Mocker()
    def test_batch_wide_failure_marks_every_item_failed(self, requests_mocker):
        requests_mocker.register_uri(
            method="POST",
            url=ENCRYPT_URL,
            status_code=400,
            json=BATCH_FAILURE_RESPONSE,
        )
        batch_input = [{"plaintext": plaintext} for plaintext in PLAINTEXTS[:2]]

        result = self._encrypt(batch_input)

        self.assertEqual(
            [item.status for item in result.items],
            [BATCH_ITEM_FAILED, BATCH_ITEM_FAILED],
        )
        self.assertEqual(result.failed_indices, (0, 1))
        self.assertEqual(result.encrypted_indices, ())
        self.assertEqual(result.missing_indices, ())
        self.assertIsNotNone(result.batch_error)
        self.assertIn("audit-key is not available", result.batch_error)
        for item in result.items:
            self.assertEqual(item.error, result.batch_error)
        self.assertIsInstance(result.raw_response, exceptions.InvalidRequest)

    @requests_mock.Mocker()
    def test_transport_failure_marks_every_item_failed(self, requests_mocker):
        requests_mocker.register_uri(
            method="POST",
            url=ENCRYPT_URL,
            exc=requests.exceptions.ConnectTimeout,
        )
        batch_input = [{"plaintext": PLAINTEXTS[0]}]

        result = self._encrypt(batch_input)

        self.assertEqual(result.failed_indices, (0,))
        self.assertIsNotNone(result.batch_error)
        self.assertEqual(result.items[0].error, result.batch_error)

    @requests_mock.Mocker()
    def test_diagnostics_do_not_echo_plaintext(self, requests_mocker):
        leaked = "invalid plaintext {encoded} decoded {decoded}".format(
            encoded=PLAINTEXTS[0],
            decoded="audit-secret-one",
        )
        response = {
            "data": {
                "batch_results": [
                    {"error": leaked},
                    {"ciphertext": "vault:v1:AA==", "key_version": 1},
                ]
            }
        }
        requests_mocker.register_uri(
            method="POST", url=ENCRYPT_URL, json=response
        )
        batch_input = [
            {"plaintext": PLAINTEXTS[0]},
            {"plaintext": PLAINTEXTS[1]},
        ]

        result = self._encrypt(batch_input)

        self.assertEqual(result.failed_indices, (0,))
        self.assertNotIn(PLAINTEXTS[0], result.items[0].error)
        self.assertNotIn("audit-secret-one", result.items[0].error)
        self.assertIn("[REDACTED]", result.items[0].error)
        self.assertNotIn(PLAINTEXTS[0], json.dumps(result.as_dict()))

    @requests_mock.Mocker()
    def test_batch_level_diagnostics_do_not_echo_plaintext(self, requests_mocker):
        requests_mocker.register_uri(
            method="POST",
            url=ENCRYPT_URL,
            status_code=500,
            json={
                "errors": [
                    "failed encrypting {encoded}".format(encoded=PLAINTEXTS[0])
                ]
            },
        )
        batch_input = [{"plaintext": PLAINTEXTS[0]}]

        result = self._encrypt(batch_input)

        self.assertEqual(result.failed_indices, (0,))
        self.assertNotIn(PLAINTEXTS[0], result.batch_error)
        self.assertIn("[REDACTED]", result.batch_error)

    def test_raw_response_entry_point_is_unchanged(self):
        self.assertTrue(callable(self.client.secrets.transit.encrypt_data))
        self.assertFalse(
            hasattr(
                self.client.secrets.transit.encrypt_data,
                "returns_batch_contract",
            )
        )

    def test_empty_batch_input_is_rejected(self):
        with self.assertRaises(ValueError):
            self._encrypt([])

    def test_non_list_batch_input_is_rejected(self):
        with self.assertRaises(ValueError):
            self._encrypt({"plaintext": PLAINTEXTS[0]})

    def test_non_dict_batch_item_is_rejected(self):
        with self.assertRaises(ValueError):
            self._encrypt([PLAINTEXTS[0]])
