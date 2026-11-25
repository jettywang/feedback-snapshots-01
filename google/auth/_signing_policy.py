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

"""Signing lifecycle policies for remotely signed credentials.

Credentials that delegate signing to a remote service such as the IAM
``signBlob`` API do not hold the signing key themselves. When one of the
underlying keys is retired, two concerns must be kept separate:

* New signatures may only be produced by keys that are still authorized.
  Because a signing call can be in flight while the policy is updated, the
  key the remote service actually returns is re-checked against the policy
  when the response arrives, not merely when the call started.
* Signatures produced before retirement remain valid. The policy therefore
  retains verification evidence (the public verification material) for every
  key that has ever signed a message through it, even after that key is no
  longer allowed to sign.

The policy is intentionally transport agnostic: it tracks key identifiers
and opaque verification material while the surrounding signer handles the
actual remote call.
"""

import threading
from typing import Any, Dict

from google.auth import exceptions


class SigningLifecyclePolicy(object):
    """Tracks which keys may sign and how retired keys are verified.

    The policy is safe to share across threads. A typical lifecycle is::

        # Both keys may initially sign.
        policy = SigningLifecyclePolicy(
            authorized_keys=["key-1", "key-2"],
            verifiers={"key-1": verifier_1, "key-2": verifier_2},
        )

        # After key-1 is rotated out it can no longer create signatures,
        # but signatures it already produced remain verifiable.
        policy.retire_key("key-1")

    Args:
        authorized_keys (Optional[Iterable[str]]): Identifiers of the keys
            allowed to create new signatures. ``None`` means every key the
            remote service returns is accepted (the default, matching the
            behavior of a signer without a policy). An empty collection means
            no key is authorized and every new signature is rejected.
        verifiers (Optional[Mapping[str, Any]]): Initial verification
            evidence, keyed by key identifier. The values are treated as
            opaque objects capable of verifying signatures produced by the
            matching key.
    """

    def __init__(self, authorized_keys=None, verifiers=None):
        self._lock = threading.RLock()
        # ``None`` is the unrestricted sentinel. An explicit set (even empty)
        # restricts new signing to the listed identifiers.
        self._authorized_keys = (
            None if authorized_keys is None else set(authorized_keys)
        )
        self._verifiers: Dict[str, Any] = dict(verifiers or {})
        self._pending_receipts: Dict[int, Dict[str, Any]] = {}
        self._next_receipt_id = 0

    @property
    def authorized_keys(self):
        """Optional[Set[str]]: Identifiers allowed to create new signatures.

        ``None`` means signing is unrestricted. The returned set is a copy
        and may be inspected without holding the policy lock.
        """
        with self._lock:
            if self._authorized_keys is None:
                return None
            return set(self._authorized_keys)

    @property
    def retired_keys(self):
        """Set[str]: Identifiers that retain verification evidence but can no
        longer create new signatures."""
        with self._lock:
            if self._authorized_keys is None:
                # An unrestricted policy has retired nothing.
                return set()
            return set(self._verifiers) - set(self._authorized_keys)

    def is_authorized(self, key_id):
        """Returns whether ``key_id`` may create a new signature.

        Args:
            key_id (Optional[str]): The key identifier to check.

        Returns:
            bool: ``True`` if the policy is unrestricted or explicitly lists
            ``key_id`` as authorized. A missing or unknown identifier is
            rejected once the policy restricts signing.
        """
        with self._lock:
            if self._authorized_keys is None:
                return key_id is not None
            return key_id in self._authorized_keys

    def authorize_keys(self, key_ids, verifiers=None):
        """Adds keys to the set allowed to create new signatures.

        Args:
            key_ids (Iterable[str]): Identifiers to authorize.
            verifiers (Optional[Mapping[str, Any]]): Verification evidence to
                register for the added keys. Existing evidence is never
                removed.
        """
        with self._lock:
            if self._authorized_keys is None:
                self._authorized_keys = set()
            self._authorized_keys.update(key_ids)
            if verifiers:
                self._verifiers.update(verifiers)

    def retire_key(self, key_id, verifier=None):
        """Revokes a key's ability to sign while preserving its evidence.

        After retirement, :meth:`is_authorized` returns ``False`` for the key
        and new signatures carrying it are rejected, but any verifier
        registered for it remains available so archived signatures stay
        verifiable. Retiring an unknown key simply records its verifier, if
        one is supplied, without erroring.

        Args:
            key_id (str): The identifier of the key to retire.
            verifier (Optional[Any]): Verification evidence to register before
                retiring. Ignored when evidence for the key already exists.
        """
        with self._lock:
            if verifier is not None and key_id not in self._verifiers:
                self._verifiers[key_id] = verifier
            if self._authorized_keys is None:
                # An unrestricted policy becomes a policy that authorizes
                # every key except the retired one.
                self._authorized_keys = set()
            else:
                self._authorized_keys.discard(key_id)

    def register_verifier(self, key_id, verifier):
        """Records verification evidence for a key.

        Evidence is retained for the lifetime of the policy, including after
        the key is retired, so historical signatures can always be checked.

        Args:
            key_id (str): The identifier of the key.
            verifier (Any): An object capable of verifying signatures made by
                the key.
        """
        with self._lock:
            self._verifiers[key_id] = verifier

    def get_verifier(self, key_id):
        """Returns the verification evidence registered for a key.

        Args:
            key_id (str): The identifier of the key.

        Returns:
            Any: The registered verifier, or ``None`` if no evidence is held
            for the key.
        """
        with self._lock:
            return self._verifiers.get(key_id)

    def verify_historical(self, key_id, message, signature):
        """Verifies a signature using a key's retained evidence.

        This works for both active and retired keys; the only requirement is
        that verification evidence for ``key_id`` was registered.

        Args:
            key_id (str): The identifier of the key that produced the
                signature.
            message (Union[str, bytes]): The signed message.
            signature (Union[str, bytes]): The signature to check.

        Returns:
            bool: ``True`` if the retained verifier accepts the signature.

        Raises:
            google.auth.exceptions.InvalidValue: If no verification evidence
                has been registered for the key.
        """
        with self._lock:
            verifier = self._verifiers.get(key_id)
        if verifier is None:
            raise exceptions.InvalidValue(
                "No verification evidence is registered for key {!r}.".format(
                    key_id
                )
            )
        return verifier.verify(message, signature)

    def begin_signing(self, message):
        """Records a signing call as pending and returns its receipt.

        The receipt survives policy updates made while the remote call is in
        flight. It is matched by :meth:`complete_signing` or removed by
        :meth:`cancel_signing`.

        Args:
            message (bytes): The message being sent for signing.

        Returns:
            dict: A receipt with a unique ``receipt_id`` and the ``message``
                being signed. Treat it as read-only.
        """
        with self._lock:
            self._next_receipt_id += 1
            receipt = {"receipt_id": self._next_receipt_id, "message": message}
            self._pending_receipts[self._next_receipt_id] = receipt
            return dict(receipt)

    def complete_signing(self, receipt, key_id, signature, verifier=None):
        """Closes out a pending signing call.

        The key actually returned by the remote service is checked against
        the *current* policy, so a key retired while the call was outstanding
        is rejected even though it was authorized when the call began. On
        success, verification evidence for the returned key is retained and
        the pending receipt is removed.

        Args:
            receipt (dict): The receipt returned by :meth:`begin_signing`.
            key_id (Optional[str]): The identifier of the key the remote
                service actually used.
            signature (bytes): The signature returned by the remote service.
            verifier (Optional[Any]): Verification evidence for the returned
                key. Existing evidence is not overwritten.

        Returns:
            bytes: The accepted signature.

        Raises:
            google.auth.exceptions.KeyRetirementError: If the returned key is
                no longer authorized, or cannot be identified.
            google.auth.exceptions.InvalidValue: If the receipt is unknown.
        """
        receipt_id = receipt["receipt_id"]
        with self._lock:
            if receipt_id not in self._pending_receipts:
                raise exceptions.InvalidValue(
                    "Unknown or already completed signing receipt: {}".format(
                        receipt_id
                    )
                )
            # Completion is terminal: remove the receipt first so a rejected
            # signature never leaves a dangling in-flight record.
            del self._pending_receipts[receipt_id]
            if not self.is_authorized(key_id):
                raise exceptions.KeyRetirementError(
                    "Signing key {!r} is not authorized by the signing "
                    "lifecycle policy; new signatures using it are "
                    "rejected.".format(key_id)
                )
            if verifier is not None and key_id not in self._verifiers:
                self._verifiers[key_id] = verifier
            return signature

    def cancel_signing(self, receipt):
        """Removes a pending receipt after a failed signing call.

        Args:
            receipt (dict): The receipt returned by :meth:`begin_signing`.
        """
        with self._lock:
            self._pending_receipts.pop(receipt["receipt_id"], None)

    @property
    def pending_receipts(self):
        """List[dict]: Snapshots of signing calls currently in flight."""
        with self._lock:
            return [dict(receipt) for receipt in self._pending_receipts.values()]

    @property
    def pending_count(self):
        """int: The number of signing calls currently in flight."""
        with self._lock:
            return len(self._pending_receipts)
