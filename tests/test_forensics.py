# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit tests for the offline fork forensics interface (``tuf.forensics``)."""

from __future__ import annotations

import json
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from securesystemslib.signer import CryptoSigner

from tuf.api._payload import (
    DelegatedRole,
    Delegations,
    Root,
    TargetFile,
    Targets,
)
from tuf.api.dsse import SimpleEnvelope
from tuf.api.metadata import Metadata
from tuf.api.serialization.json import JSONSerializer
from tuf.forensics import (
    EnvelopeType,
    ForkStatus,
    ObservationError,
    ObservationPackage,
    RefutationReason,
    analyze_fork,
)

FIXTURES = Path(__file__).resolve().parent.parent / "examples"
if str(FIXTURES) not in sys.path:
    sys.path.insert(0, str(FIXTURES))
from fork_forensics.repository_builder import RepositoryBuilder  # noqa: E402


def _expiry() -> datetime:
    return datetime.now(UTC) + timedelta(days=365)


class ForensicsFixture:
    """Build signed repository material for one envelope semantics."""

    def __init__(self, envelope_type: EnvelopeType) -> None:
        self.envelope_type = envelope_type
        self.root_signer = CryptoSigner.generate_ed25519()
        self.targets_signer = CryptoSigner.generate_ed25519()
        self.other_signer = CryptoSigner.generate_ed25519()
        self.compact = JSONSerializer(compact=True)

    def _wrap(self, signed: Any, signers: list[CryptoSigner]) -> bytes:
        if self.envelope_type is EnvelopeType.SIMPLE:
            envelope = SimpleEnvelope.from_signed(signed)
            for signer in signers:
                envelope.sign(signer)
            return envelope.to_bytes()
        metadata = Metadata(signed)
        for signer in signers:
            metadata.sign(signer, append=True)
        return metadata.to_bytes(self.compact)

    def root(self) -> bytes:
        root = Root(version=1, expires=_expiry())
        root.add_key(self.root_signer.public_key, Root.type)
        root.add_key(self.targets_signer.public_key, Targets.type)
        return self._wrap(root, [self.root_signer])

    def rotated_root(self, version: int) -> bytes:
        root = Root(version=version, expires=_expiry())
        root.add_key(self.root_signer.public_key, Root.type)
        root.add_key(self.targets_signer.public_key, Targets.type)
        return self._wrap(root, [self.root_signer])

    def targets(
        self, version: int, target_path: str, digest: str
    ) -> bytes:
        targets = Targets(version=version, expires=_expiry())
        targets.targets[target_path] = TargetFile(
            length=1024, hashes={"sha256": digest}, path=""
        )
        return self._wrap(targets, [self.targets_signer])

    def delegating_targets(
        self, role_name: str, signer: CryptoSigner
    ) -> bytes:
        targets = Targets(version=1, expires=_expiry())
        delegated = DelegatedRole(
            role_name, [signer.public_key.keyid], 1, False, paths=["*"]
        )
        targets.delegations = Delegations(
            keys={signer.public_key.keyid: signer.public_key},
            roles={role_name: delegated},
        )
        return self._wrap(targets, [self.targets_signer])

    def delegated(
        self, version: int, digest: str, signer: CryptoSigner
    ) -> bytes:
        return self._wrap(
            self._delegated_payload(version, digest), [signer]
        )

    def _delegated_payload(
        self, version: int, digest: str
    ) -> Targets:
        targets = Targets(version=version, expires=_expiry())
        targets.targets["delegated.tar.gz"] = TargetFile(
            length=1024, hashes={"sha256": digest}, path=""
        )
        return targets

    def package(
        self, envelope: bytes, root_bytes: bytes, **kwargs: Any
    ) -> ObservationPackage:
        kwargs.setdefault("envelope_type", self.envelope_type)
        return ObservationPackage(envelope, root_bytes, **kwargs)


class ForkForensicsTest(unittest.TestCase):
    def _scenarios(self) -> list[ForensicsFixture]:
        return [
            ForensicsFixture(EnvelopeType.METADATA),
            ForensicsFixture(EnvelopeType.SIMPLE),
        ]

    def test_proven_conflict(self) -> None:
        for fixture in self._scenarios():
            with self.subTest(envelope_type=fixture.envelope_type):
                root = fixture.root()
                good = fixture.targets(1, "release", "aa" * 32)
                evil = fixture.targets(1, "release", "bb" * 32)
                report = analyze_fork(
                    fixture.package(good, root),
                    fixture.package(evil, root),
                )
                self.assertIs(report.status, ForkStatus.PROVEN)
                self.assertTrue(report.fork_proven)
                self.assertTrue(report.first.authenticated)
                self.assertTrue(report.second.authenticated)
                self.assertIsNotNone(report.conflict_fields)
                self.assertIn(
                    "targets.release.hashes.sha256",
                    report.conflict_fields.field_paths,
                )

    def test_whitespace_and_signature_order_not_a_fork(self) -> None:
        for fixture in self._scenarios():
            with self.subTest(envelope_type=fixture.envelope_type):
                root = fixture.root()
                good = fixture.targets(1, "release", "aa" * 32)
                builder = RepositoryBuilder(fixture.envelope_type)
                reformatted = builder.reformat_envelope(good)
                report = analyze_fork(
                    fixture.package(good, root),
                    fixture.package(reformatted, root),
                )
                self.assertIs(report.status, ForkStatus.REFUTED)
                self.assertEqual(
                    report.refutation_reason,
                    RefutationReason.SAME_CANONICAL_CONTENT,
                )
                self.assertEqual(
                    report.first.summary.signed_bytes_sha256,
                    report.second.summary.signed_bytes_sha256,
                )

    def test_additional_valid_signature_not_a_fork(self) -> None:
        for fixture in self._scenarios():
            with self.subTest(envelope_type=fixture.envelope_type):
                builder = RepositoryBuilder(fixture.envelope_type)
                root = builder.build_root()
                good = builder.build_targets(1, "release", "aa" * 32)
                root_extra, extra = (
                    builder.build_root_with_extra_targets_key()
                )
                extra_signed = builder.sign_targets(good, extra)
                report = analyze_fork(
                    ObservationPackage(
                        good, root_extra, envelope_type=fixture.envelope_type
                    ),
                    ObservationPackage(
                        extra_signed,
                        root_extra,
                        envelope_type=fixture.envelope_type,
                    ),
                )
                self.assertIs(report.status, ForkStatus.REFUTED)
                self.assertEqual(
                    report.refutation_reason,
                    RefutationReason.SAME_CANONICAL_CONTENT,
                )

    def test_mixed_envelope_semantics_is_inconclusive(self) -> None:
        metadata_fixture = ForensicsFixture(EnvelopeType.METADATA)
        simple_fixture = ForensicsFixture(EnvelopeType.SIMPLE)
        root = metadata_fixture.root()
        # Each package authenticates against its own correctly signed root,
        # but the two do not share signature semantics.
        first = metadata_fixture.package(
            metadata_fixture.targets(1, "release", "aa" * 32), root
        )
        simple_root = simple_fixture.root()
        second = simple_fixture.package(
            simple_fixture.targets(1, "release", "bb" * 32), simple_root
        )
        report = analyze_fork(first, second)
        self.assertIs(report.status, ForkStatus.INCONCLUSIVE)
        self.assertTrue(
            any("signature semantics" in err for err in report.first.errors)
        )

    def test_different_version_is_refuted(self) -> None:
        for fixture in self._scenarios():
            with self.subTest(envelope_type=fixture.envelope_type):
                root = fixture.root()
                v1 = fixture.targets(1, "release", "aa" * 32)
                v2 = fixture.targets(2, "release", "cc" * 32)
                report = analyze_fork(
                    fixture.package(v1, root), fixture.package(v2, root)
                )
                self.assertIs(report.status, ForkStatus.REFUTED)
                self.assertEqual(
                    report.refutation_reason,
                    RefutationReason.DIFFERENT_VERSION,
                )

    def test_different_role_is_refuted(self) -> None:
        from tuf.api._payload import Snapshot

        fixture = ForensicsFixture(EnvelopeType.METADATA)
        root_payload = Root(version=1, expires=_expiry())
        root_payload.add_key(fixture.root_signer.public_key, Root.type)
        root_payload.add_key(fixture.targets_signer.public_key, Targets.type)
        root_payload.add_key(fixture.targets_signer.public_key, Snapshot.type)
        root = fixture._wrap(root_payload, [fixture.root_signer])

        targets_env = fixture.targets(1, "release", "aa" * 32)
        snapshot_md = Metadata(Snapshot(version=1, expires=_expiry()))
        snapshot_md.sign(fixture.targets_signer)
        snapshot_env = snapshot_md.to_bytes(fixture.compact)

        report = analyze_fork(
            fixture.package(targets_env, root),
            fixture.package(snapshot_env, root),
        )
        self.assertIs(report.status, ForkStatus.REFUTED)
        self.assertTrue(report.first.authenticated)
        self.assertTrue(report.second.authenticated)
        self.assertEqual(
            report.refutation_reason, RefutationReason.DIFFERENT_ROLE
        )

    def test_threshold_requires_enough_valid_signatures(self) -> None:
        from tuf.api._payload import Role

        fixture = ForensicsFixture(EnvelopeType.METADATA)
        second_targets_signer = CryptoSigner.generate_ed25519()
        root_payload = Root(version=1, expires=_expiry())
        root_payload.add_key(fixture.root_signer.public_key, Root.type)
        for signer in (
            fixture.targets_signer,
            second_targets_signer,
        ):
            root_payload.keys[signer.public_key.keyid] = signer.public_key
        root_payload.roles[Targets.type] = Role(
            [
                fixture.targets_signer.public_key.keyid,
                second_targets_signer.public_key.keyid,
            ],
            2,
        )
        root = fixture._wrap(root_payload, [fixture.root_signer])

        def envelope(signers: list[CryptoSigner]) -> bytes:
            targets = Targets(version=1, expires=_expiry())
            targets.targets["release"] = TargetFile(
                length=1, hashes={"sha256": "aa" * 32}, path=""
            )
            return fixture._wrap(targets, signers)

        full = fixture.package(
            envelope([fixture.targets_signer, second_targets_signer]), root
        ).verify()
        partial = fixture.package(
            envelope([fixture.targets_signer]), root
        ).verify()

        self.assertTrue(full.authenticated)
        self.assertEqual(
            len(full.authorization_path.role_path[0].valid_keyids), 2
        )
        self.assertFalse(partial.authenticated)
        self.assertTrue(
            any("1/2" in err for err in partial.errors)
        )

    def test_tampered_package_is_inconclusive(self) -> None:
        for fixture in self._scenarios():
            with self.subTest(envelope_type=fixture.envelope_type):
                builder = RepositoryBuilder(fixture.envelope_type)
                root = builder.build_root()
                good = builder.build_targets(1, "release", "aa" * 32)
                tampered = builder.tamper_payload(good)
                report = analyze_fork(
                    ObservationPackage(
                        good, root, envelope_type=fixture.envelope_type
                    ),
                    ObservationPackage(
                        tampered, root, envelope_type=fixture.envelope_type
                    ),
                )
                self.assertIs(report.status, ForkStatus.INCONCLUSIVE)
                self.assertFalse(report.fork_proven)
                self.assertTrue(report.first.authenticated)
                self.assertFalse(report.second.authenticated)
                self.assertTrue(report.second.errors)
                self.assertIsNone(report.conflict_fields)

    def test_root_rotation_chain(self) -> None:
        for fixture in self._scenarios():
            with self.subTest(envelope_type=fixture.envelope_type):
                root_v1 = fixture.root()
                root_v2 = fixture.rotated_root(2)
                good = fixture.targets(1, "release", "aa" * 32)
                evil = fixture.targets(1, "release", "bb" * 32)
                report = analyze_fork(
                    fixture.package(good, root_v1, root_chain=[root_v2]),
                    fixture.package(evil, root_v1, root_chain=[root_v2]),
                )
                self.assertIs(report.status, ForkStatus.PROVEN)
                chain = report.first.authorization_path.root_chain
                self.assertEqual([hop.root_version for hop in chain], [1, 2])
                self.assertTrue(all(hop.authorized for hop in chain))

    def test_non_sequential_root_chain_is_inconclusive(self) -> None:
        fixture = ForensicsFixture(EnvelopeType.METADATA)
        root_v1 = fixture.root()
        root_v3 = fixture.rotated_root(3)
        good = fixture.targets(1, "release", "aa" * 32)
        verdict = fixture.package(
            good, root_v1, root_chain=[root_v3]
        ).verify()
        self.assertFalse(verdict.authenticated)
        self.assertTrue(
            any("Non-sequential" in err for err in verdict.errors)
        )

    def test_delegated_targets_authorization_path(self) -> None:
        for fixture in self._scenarios():
            with self.subTest(envelope_type=fixture.envelope_type):
                root = fixture.root()
                delegated_signer = CryptoSigner.generate_ed25519()
                top = fixture.delegating_targets("vetted", delegated_signer)
                first = fixture.delegated(1, "aa" * 32, delegated_signer)
                second = fixture.delegated(1, "bb" * 32, delegated_signer)
                kwargs = {
                    "role_name": "vetted",
                    "delegations": {Targets.type: top},
                    "delegation_chain": [],
                }
                report = analyze_fork(
                    fixture.package(first, root, **kwargs),
                    fixture.package(second, root, **kwargs),
                )
                self.assertIs(report.status, ForkStatus.PROVEN)
                path = report.first.authorization_path.role_path
                self.assertEqual(
                    [(hop.delegator, hop.role) for hop in path],
                    [(Root.type, Targets.type), (Targets.type, "vetted")],
                )
                self.assertTrue(all(hop.authorized for hop in path))

    def test_delegated_targets_wrong_signer_is_inconclusive(self) -> None:
        fixture = ForensicsFixture(EnvelopeType.METADATA)
        root = fixture.root()
        delegated_signer = CryptoSigner.generate_ed25519()
        top = fixture.delegating_targets("vetted", delegated_signer)
        forged = fixture.delegated(1, "aa" * 32, fixture.other_signer)
        verdict = fixture.package(
            forged,
            root,
            role_name="vetted",
            delegations={Targets.type: top},
            delegation_chain=[],
        ).verify()
        self.assertFalse(verdict.authenticated)
        self.assertTrue(any("vetted" in err for err in verdict.errors))

    def test_report_is_json_serializable(self) -> None:
        fixture = ForensicsFixture(EnvelopeType.METADATA)
        root = fixture.root()
        report = analyze_fork(
            fixture.package(
                fixture.targets(1, "r", "aa" * 32), root
            ),
            fixture.package(
                fixture.targets(1, "r", "bb" * 32), root
            ),
        )
        encoded = json.dumps(report.to_dict())
        self.assertEqual(json.loads(encoded)["status"], "proven")

    def test_invalid_envelope_raises_observation_error(self) -> None:
        fixture = ForensicsFixture(EnvelopeType.METADATA)
        with self.assertRaises(ObservationError):
            ObservationPackage(
                b"not json", fixture.root(), envelope_type=fixture.envelope_type
            )

    def test_missing_delegation_material_raises(self) -> None:
        fixture = ForensicsFixture(EnvelopeType.METADATA)
        root = fixture.root()
        delegated_signer = CryptoSigner.generate_ed25519()
        envelope = fixture.delegated(1, "aa" * 32, delegated_signer)
        with self.assertRaises(ObservationError):
            ObservationPackage(
                envelope,
                root,
                role_name="vetted",
                envelope_type=fixture.envelope_type,
            )


if __name__ == "__main__":
    unittest.main()
