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

import pytest

from google.auth import _signing_policy
from google.auth import exceptions


class FakeVerifier(object):
    def __init__(self, valid):
        self._valid = valid

    def verify(self, message, signature):
        return self._valid


def make_policy(**kwargs):
    return _signing_policy.SigningLifecyclePolicy(**kwargs)


class TestAuthorization(object):
    def test_unrestricted_by_default(self):
        policy = make_policy()
        assert policy.authorized_keys is None
        assert policy.is_authorized("any-key")
        assert not policy.is_authorized(None)

    def test_restricted_to_listed_keys(self):
        policy = make_policy(authorized_keys=["key-1", "key-2"])
        assert policy.authorized_keys == {"key-1", "key-2"}
        assert policy.is_authorized("key-1")
        assert not policy.is_authorized("key-3")
        assert not policy.is_authorized(None)

    def test_empty_authorized_set_rejects_everything(self):
        policy = make_policy(authorized_keys=[])
        assert policy.authorized_keys == set()
        assert not policy.is_authorized("key-1")

    def test_authorize_keys_updates_set(self):
        policy = make_policy(authorized_keys=["key-1"])
        policy.authorize_keys(["key-2"], verifiers={"key-2": FakeVerifier(True)})
        assert policy.is_authorized("key-2")
        assert policy.get_verifier("key-2") is not None

    def test_authorize_keys_makes_unrestricted_policy_restricted(self):
        policy = make_policy()
        policy.authorize_keys(["key-1"])
        assert policy.authorized_keys == {"key-1"}
        assert not policy.is_authorized("other")


class TestRetirement(object):
    def test_retire_key_blocks_new_signing_but_keeps_evidence(self):
        verifier = FakeVerifier(True)
        policy = make_policy(
            authorized_keys=["key-1", "key-2"],
            verifiers={"key-1": verifier, "key-2": FakeVerifier(True)},
        )

        policy.retire_key("key-1")

        assert not policy.is_authorized("key-1")
        assert policy.is_authorized("key-2")
        assert "key-1" in policy.retired_keys
        assert policy.get_verifier("key-1") is verifier

    def test_retire_records_supplied_verifier(self):
        verifier = FakeVerifier(True)
        policy = make_policy(authorized_keys=["key-1"])
        policy.retire_key("key-1", verifier=verifier)
        assert policy.get_verifier("key-1") is verifier

    def test_retire_in_unrestricted_policy_restricts_remaining(self):
        policy = make_policy()
        policy.retire_key("key-1")
        assert not policy.is_authorized("key-1")
        assert policy.authorized_keys == set()

    def test_unrestricted_policy_reports_no_retired_keys(self):
        policy = make_policy(verifiers={"key-1": FakeVerifier(True)})
        assert policy.retired_keys == set()

    def test_historical_signature_remains_verifiable_after_retirement(self):
        message = b"archive me"
        signature = b"old-signature"
        verifier = FakeVerifier(True)
        policy = make_policy(
            authorized_keys=["key-1"], verifiers={"key-1": verifier}
        )

        policy.retire_key("key-1")

        assert policy.verify_historical("key-1", message, signature)
        assert "key-1" in policy.retired_keys

    def test_historical_verification_without_evidence_raises(self):
        policy = make_policy(authorized_keys=["key-1"])
        with pytest.raises(exceptions.InvalidValue):
            policy.verify_historical("unknown", b"msg", b"sig")

    def test_registered_verifier_survives_retirement(self):
        verifier = FakeVerifier(False)
        policy = make_policy(authorized_keys=["key-1"])
        policy.register_verifier("key-1", verifier)
        policy.retire_key("key-1")
        assert not policy.verify_historical("key-1", b"msg", b"sig")


class TestPendingReceipts(object):
    def test_receipt_lifecycle(self):
        policy = make_policy(authorized_keys=["key-1"])

        receipt = policy.begin_signing(b"msg")
        assert policy.pending_count == 1
        assert policy.pending_receipts[0]["message"] == b"msg"

        signature = policy.complete_signing(
            receipt, "key-1", b"sig", verifier=FakeVerifier(True)
        )
        assert signature == b"sig"
        assert policy.pending_count == 0

    def test_complete_rejects_retired_key_even_if_authorized_at_begin(self):
        policy = make_policy(authorized_keys=["key-1"])
        receipt = policy.begin_signing(b"msg")

        # The policy changes while the remote signing call is in flight.
        policy.retire_key("key-1", verifier=FakeVerifier(True))

        with pytest.raises(exceptions.KeyRetirementError):
            policy.complete_signing(receipt, "key-1", b"late-signature")
        # A rejected completion does not leave a dangling pending receipt.
        assert policy.pending_count == 0
        # The rejected signature's key evidence is still retained for history.
        assert "key-1" in policy.retired_keys

    def test_complete_rejects_unknown_key(self):
        policy = make_policy(authorized_keys=["key-1"])
        receipt = policy.begin_signing(b"msg")
        with pytest.raises(exceptions.KeyRetirementError):
            policy.complete_signing(receipt, "key-other", b"sig")
        assert policy.pending_count == 0

    def test_complete_unknown_receipt_raises(self):
        policy = make_policy(authorized_keys=["key-1"])
        receipt = policy.begin_signing(b"msg")
        policy.cancel_signing(receipt)
        with pytest.raises(exceptions.InvalidValue):
            policy.complete_signing(receipt, "key-1", b"sig")

    def test_cancel_removes_receipt(self):
        policy = make_policy()
        receipt = policy.begin_signing(b"msg")
        policy.cancel_signing(receipt)
        assert policy.pending_count == 0
        # Cancelling twice is a no-op.
        policy.cancel_signing(receipt)

    def test_pending_receipts_are_snapshots(self):
        policy = make_policy()
        policy.begin_signing(b"msg")
        receipts = policy.pending_receipts
        receipts.clear()
        assert policy.pending_count == 1
