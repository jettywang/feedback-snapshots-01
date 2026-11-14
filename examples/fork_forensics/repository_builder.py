# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""In-memory repository material for the fork forensics demonstration.

This helper builds small, fully signed TUF repositories with real ed25519
keys so that the forensics interface can be exercised without any network
access or pre-generated test fixtures. Both traditional Metadata and DSSE
SimpleEnvelope signature semantics are supported.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from securesystemslib.signer import CryptoSigner

from tuf.api._payload import Root, Targets
from tuf.api.dsse import SimpleEnvelope
from tuf.api.metadata import Metadata
from tuf.api.serialization.json import JSONSerializer
from tuf.ngclient.config import EnvelopeType


def _expiry(days: int = 365) -> datetime:
    return datetime.now(UTC) + timedelta(days=days)


class RepositoryBuilder:
    """Build a single-role repository and signed target observations."""

    def __init__(self, envelope_type: EnvelopeType) -> None:
        self.envelope_type = envelope_type
        self.root_signer = CryptoSigner.generate_ed25519()
        self.targets_signer = CryptoSigner.generate_ed25519()
        self.attacker_signer = CryptoSigner.generate_ed25519()
        self._pretty = JSONSerializer(compact=False)
        self._compact = JSONSerializer(compact=True)

    def build_root(self) -> bytes:
        """Create and sign a version 1 root authorizing the targets role."""
        root = Root(version=1, expires=_expiry())
        root.add_key(self.root_signer.public_key, Root.type)
        root.add_key(self.targets_signer.public_key, Targets.type)
        return self._wrap(root, [self.root_signer])

    def build_rotated_root(self, version: int) -> bytes:
        """Create a higher root version reusing the same root and targets keys.

        Keeping the root signer unchanged means each new root satisfies both
        the previous-root and self-signature requirements of a root chain.
        """
        root = Root(version=version, expires=_expiry())
        root.add_key(self.root_signer.public_key, Root.type)
        root.add_key(self.targets_signer.public_key, Targets.type)
        return self._wrap(root, [self.root_signer])

    def build_targets_with_delegation(
        self,
        delegated_name: str,
        delegated_signer: CryptoSigner,
    ) -> bytes:
        """Create top-level targets that delegates to ``delegated_name``."""
        from tuf.api._payload import DelegatedRole, Delegations

        targets = Targets(version=1, expires=_expiry())
        delegated_role = DelegatedRole(
            delegated_name,
            [delegated_signer.public_key.keyid],
            1,
            False,
            paths=["*"],
        )
        targets.delegations = Delegations(
            keys={
                delegated_signer.public_key.keyid: delegated_signer.public_key
            },
            roles={delegated_name: delegated_role},
        )
        return self._wrap(targets, [self.targets_signer])

    def build_delegated_targets(
        self,
        version: int,
        target_path: str,
        target_hash: str,
        signer: CryptoSigner,
    ) -> bytes:
        """Create delegated targets metadata signed by ``signer``."""
        targets = Targets(version=version, expires=_expiry())
        targets.targets[target_path] = self._target_file(target_hash)
        return self._wrap(targets, [signer])

    def build_targets(
        self,
        version: int,
        target_path: str,
        target_hash: str,
    ) -> bytes:
        """Create and signed targets metadata referencing one target file."""
        targets = Targets(version=version, expires=_expiry())
        targets.targets[target_path] = self._target_file(target_hash)
        return self._wrap(targets, [self.targets_signer])

    def _target_file(self, target_hash: str) -> Any:
        from tuf.api._payload import TargetFile

        return TargetFile(
            length=1024,
            hashes={"sha256": target_hash},
            path="",
        )

    def _wrap(self, signed: Any, signers: list[CryptoSigner]) -> bytes:
        if self.envelope_type is EnvelopeType.SIMPLE:
            envelope = SimpleEnvelope.from_signed(signed)
            for signer in signers:
                envelope.sign(signer)
            return envelope.to_bytes()

        metadata = Metadata(signed)
        for signer in signers:
            metadata.sign(signer, append=True)
        return metadata.to_bytes(self._compact)

    def reformat_envelope(self, data: bytes) -> bytes:
        """Re-serialize the same envelope with different JSON whitespace.

        Signatures stay valid because canonical JSON ignores formatting.
        """
        if self.envelope_type is EnvelopeType.SIMPLE:
            envelope = SimpleEnvelope[Any].from_bytes(data)
            return _pretty_envelope(envelope.to_dict())

        metadata = Metadata[Any].from_bytes(data)
        return metadata.to_bytes(self._pretty)

    def build_root_with_extra_targets_key(self) -> tuple[bytes, CryptoSigner]:
        """Return a root registering an additional targets key.

        The extra signer lets a package carry a second role-authorized
        signature while the payload stays identical, exercising the rule that
        additional valid signatures are not a fork.
        """
        extra_signer = CryptoSigner.generate_ed25519()
        root = Root(version=1, expires=_expiry())
        root.add_key(self.root_signer.public_key, Root.type)
        root.add_key(self.targets_signer.public_key, Targets.type)
        root.add_key(extra_signer.public_key, Targets.type)
        return self._wrap(root, [self.root_signer]), extra_signer

    def sign_targets(
        self, data: bytes, signer: CryptoSigner
    ) -> bytes:
        """Append a signature from ``signer`` to an existing envelope."""
        if self.envelope_type is EnvelopeType.SIMPLE:
            envelope = SimpleEnvelope[Any].from_bytes(data)
            envelope.sign(signer)
            return envelope.to_bytes()

        metadata = Metadata[Any].from_bytes(data)
        metadata.sign(signer, append=True)
        return metadata.to_bytes(self._compact)

    def tamper_payload(self, data: bytes) -> bytes:
        """Mutate signed content while leaving the old signature in place.

        The resulting envelope cannot verify against any publisher key, which
        models a third party modifying observed metadata in transit.
        """
        if self.envelope_type is EnvelopeType.SIMPLE:
            envelope = SimpleEnvelope[Any].from_bytes(data)
            payload = envelope.get_signed()
            payload.targets["malicious-file"] = self._target_file(
                "deadbeef" * 8
            )
            envelope.payload = SimpleEnvelope.from_signed(payload).payload
            return envelope.to_bytes()

        metadata = Metadata[Any].from_bytes(data)
        metadata.signed.targets["malicious-file"] = self._target_file(
            "deadbeef" * 8
        )
        return metadata.to_bytes(self._compact)


def _pretty_envelope(envelope_dict: dict[str, Any]) -> bytes:
    import json

    return json.dumps(envelope_dict, indent=2).encode()
