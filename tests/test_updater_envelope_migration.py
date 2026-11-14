# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test explicit, role/version based METADATA to SIMPLE migration"""

from __future__ import annotations

import os
import tempfile
import unittest
from typing import ClassVar

from tests.repository_simulator import RepositorySimulator
from tuf.api.exceptions import EnvelopePolicyError, UnsignedMetadataError
from tuf.api.metadata import SPECIFICATION_VERSION, DelegatedRole, Targets
from tuf.ngclient import (
    EnvelopeMigrationPolicy,
    EnvelopeRule,
    EnvelopeType,
    Updater,
    UpdaterConfig,
)


class TestEnvelopeMigration(unittest.TestCase):
    """Test caller-configured role/version envelope migration"""

    temp_dir: ClassVar[tempfile.TemporaryDirectory]

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    def setup_repo(self) -> None:
        self.metadata_dir = tempfile.mkdtemp(dir=self.temp_dir.name)
        self.targets_dir = tempfile.mkdtemp(dir=self.temp_dir.name)
        self.sim = RepositorySimulator()

        # one delegated role with a predictable name
        spec_version = ".".join(SPECIFICATION_VERSION)
        targets = Targets(1, spec_version, self.sim.safe_expiry, {}, None)
        role = DelegatedRole("role1", [], 1, False, ["*"], None)
        self.sim.add_delegation("targets", role, targets)
        self.sim.add_target("role1", b"role1 content", "file1.txt")
        self.sim.targets.version += 1
        self.sim.update_snapshot()

    def _updater(
        self, policy: EnvelopeMigrationPolicy | None, *, bootstrap: bytes
    ) -> Updater:
        config = UpdaterConfig(envelope_migration=policy)
        return Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
            config=config,
            bootstrap=bootstrap,
        )

    def test_no_migration_keeps_single_format_configs(self) -> None:
        """The two legacy single-format configurations keep their meaning."""
        self.setup_repo()

        # Default config remains METADATA-only, even for delegated roles.
        updater = Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
            bootstrap=self.sim.signed_roots[0],
        )
        updater.refresh()
        self.assertIsNotNone(updater.get_targetinfo("file1.txt"))

        # SIMPLE-only configuration still accepts an entirely SIMPLE repo.
        self.setup_repo()
        for role in ["root", "timestamp", "snapshot", "targets", "role1"]:
            self.sim.envelope_types[role] = EnvelopeType.SIMPLE
        self.sim.signed_roots.clear()
        self.sim.publish_root()
        self.sim.update_snapshot()
        updater = Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
            config=UpdaterConfig(envelope_type=EnvelopeType.SIMPLE),
            bootstrap=self.sim.signed_roots[0],
        )
        updater.refresh()
        self.assertIsNotNone(updater.get_targetinfo("file1.txt"))

    def test_top_level_migrated_delegate_still_metadata(self) -> None:
        """Demonstrate a migration in progress and then its completion."""
        self.setup_repo()

        # Phase 1: top-level roles are SIMPLE, role1 is still METADATA.
        for role in ["root", "timestamp", "snapshot", "targets"]:
            self.sim.envelope_types[role] = EnvelopeType.SIMPLE
        self.sim.signed_roots.clear()
        self.sim.publish_root()

        policy = EnvelopeMigrationPolicy(
            [
                EnvelopeRule(r, EnvelopeType.SIMPLE)
                for r in ["root", "timestamp", "snapshot", "targets"]
            ]
            + [EnvelopeRule("role1", EnvelopeType.METADATA)]
        )

        updater = self._updater(policy, bootstrap=self.sim.signed_roots[0])
        updater.refresh()
        info = updater.get_targetinfo("file1.txt")
        self.assertIsNotNone(info)

        # Phase 2: role1 moves to SIMPLE and the version range is closed.
        self.sim.envelope_types["role1"] = EnvelopeType.SIMPLE
        self.sim.md_delegates["role1"].signed.version += 1
        self.sim.update_snapshot()

        policy = EnvelopeMigrationPolicy(
            [
                EnvelopeRule(r, EnvelopeType.SIMPLE)
                for r in ["root", "timestamp", "snapshot", "targets", "role1"]
            ]
        )
        # Cache contains role1 v1 as METADATA: policy only allows SIMPLE v1,
        # so the cached copy must be rejected before any remote retry.
        with self.assertRaises(EnvelopePolicyError) as ctx:
            updater = self._updater(policy, bootstrap=self.sim.signed_roots[0])
            updater.refresh()
            updater.get_targetinfo("file1.txt")
        self.assertIn("role1", str(ctx.exception))
        self.assertIn(self.metadata_dir, str(ctx.exception))

        # Start a fresh client whose policy covers the old and new ranges.
        os.remove(os.path.join(self.metadata_dir, "role1.json"))
        self.sim.update_snapshot()
        policy = EnvelopeMigrationPolicy(
            [
                EnvelopeRule("role1", EnvelopeType.METADATA, max_version=1),
                EnvelopeRule("role1", EnvelopeType.SIMPLE, min_version=2),
            ]
            + [
                EnvelopeRule(r, EnvelopeType.SIMPLE)
                for r in ["root", "timestamp", "snapshot", "targets"]
            ]
        )
        updater = self._updater(policy, bootstrap=self.sim.signed_roots[0])
        updater.refresh()
        info = updater.get_targetinfo("file1.txt")
        self.assertIsNotNone(info)

    def test_old_format_in_simple_only_slot_is_rejected(self) -> None:
        """A validly signed METADATA file in a SIMPLE-only slot is refused."""
        self.setup_repo()

        # role1 is SIMPLE from version 2 onwards.
        self.sim.envelope_types["role1"] = EnvelopeType.SIMPLE
        self.sim.md_delegates["role1"].signed.version = 2
        self.sim.update_snapshot()

        policy = EnvelopeMigrationPolicy(
            [EnvelopeRule("role1", EnvelopeType.SIMPLE, min_version=2)]
            + [
                EnvelopeRule(r, EnvelopeType.METADATA)
                for r in ["root", "timestamp", "snapshot", "targets"]
            ]
        )

        # Put a correctly signed METADATA role1 v2 into the version slot.
        original_type = self.sim.envelope_type("role1")
        self.sim.envelope_types["role1"] = EnvelopeType.METADATA
        old_format = self.sim.fetch_metadata("role1")
        self.sim.envelope_types["role1"] = original_type
        self.sim.update_snapshot()
        # snapshot hashes must match the bytes actually served
        md_path = os.path.join(self.metadata_dir, "role1.json")
        with open(md_path, "wb") as f:
            f.write(old_format)

        updater = self._updater(policy, bootstrap=self.sim.signed_roots[0])
        with self.assertRaises(EnvelopePolicyError) as ctx:
            updater.refresh()
            updater.get_targetinfo("file1.txt")
        self.assertIn("role1", str(ctx.exception))
        self.assertIn("version 2", str(ctx.exception))
        self.assertIn(
            os.path.join(self.metadata_dir, "role1.json"), str(ctx.exception)
        )

    def test_policy_gap_is_locatable(self) -> None:
        """An unmatched version raises rather than trying another envelope."""
        self.setup_repo()
        policy = EnvelopeMigrationPolicy(
            [EnvelopeRule("role1", EnvelopeType.SIMPLE, min_version=5)]
            + [
                EnvelopeRule(r, EnvelopeType.METADATA)
                for r in ["root", "timestamp", "snapshot", "targets"]
            ]
        )
        # role1 v1 is METADATA but no rule covers version 1
        updater = self._updater(policy, bootstrap=self.sim.signed_roots[0])
        with self.assertRaises(EnvelopePolicyError) as ctx:
            updater.refresh()
            updater.get_targetinfo("file1.txt")
        self.assertIn("no migration rule", str(ctx.exception))
        self.assertIn("role 'role1' version 1", str(ctx.exception))

    def test_remote_old_format_in_simple_slot_is_rejected(self) -> None:
        """The remote path applies the same policy and names the URL."""
        self.setup_repo()
        self.sim.envelope_types["role1"] = EnvelopeType.METADATA
        self.sim.md_delegates["role1"].signed.version = 2
        self.sim.update_snapshot()
        policy = EnvelopeMigrationPolicy(
            [EnvelopeRule("role1", EnvelopeType.SIMPLE, min_version=2)]
            + [
                EnvelopeRule(r, EnvelopeType.METADATA)
                for r in ["root", "timestamp", "snapshot", "targets"]
            ]
        )
        # no cached role1: the remote copy is a valid METADATA file
        updater = self._updater(policy, bootstrap=self.sim.signed_roots[0])
        with self.assertRaises(EnvelopePolicyError) as ctx:
            updater.refresh()
            updater.get_targetinfo("file1.txt")
        self.assertIn("role1", str(ctx.exception))
        self.assertIn("2.role1.json", str(ctx.exception))

    def test_mixed_root_rotation_and_delegate_closeout(self) -> None:
        """A small publication sequence: root changes, delegate closes last."""
        self.setup_repo()

        # Publish root v2 in SIMPLE while delegated role1 stays METADATA.
        self.sim.envelope_types["root"] = EnvelopeType.SIMPLE
        self.sim.root.version += 1
        self.sim.publish_root()
        policy = EnvelopeMigrationPolicy(
            [
                EnvelopeRule("root", EnvelopeType.METADATA, max_version=1),
                EnvelopeRule("root", EnvelopeType.SIMPLE, min_version=2),
            ]
            + [
                EnvelopeRule(r, EnvelopeType.METADATA)
                for r in ["timestamp", "snapshot", "targets", "role1"]
            ]
        )
        updater = self._updater(policy, bootstrap=self.sim.signed_roots[0])
        updater.refresh()
        self.assertEqual(updater._trusted_set.root.version, 2)

        # Close out: all roles become SIMPLE, including a new root version.
        # Start a fresh client cache: the old cache holds METADATA files.
        self.metadata_dir = tempfile.mkdtemp(dir=self.temp_dir.name)
        for role in ["root", "timestamp", "snapshot", "targets", "role1"]:
            self.sim.envelope_types[role] = EnvelopeType.SIMPLE
        self.sim.root.version += 1
        self.sim.publish_root()
        self.sim.md_delegates["role1"].signed.version += 1
        self.sim.update_snapshot()

        final_policy = EnvelopeMigrationPolicy(
            [
                EnvelopeRule(r, EnvelopeType.SIMPLE)
                for r in ["root", "timestamp", "snapshot", "targets", "role1"]
            ]
        )
        final = self._updater(final_policy, bootstrap=self.sim.signed_roots[-1])
        final.refresh()
        self.assertIsNotNone(final.get_targetinfo("file1.txt"))
        self.assertEqual(final._trusted_set.root.version, 3)

    def test_policy_rule_validation(self) -> None:
        """Overlap, gaps and invalid values are caller errors."""
        with self.assertRaises(ValueError):
            EnvelopeMigrationPolicy([])
        with self.assertRaises(ValueError):
            EnvelopeMigrationPolicy(
                [
                    EnvelopeRule("root", EnvelopeType.METADATA, max_version=3),
                    EnvelopeRule("root", EnvelopeType.SIMPLE, min_version=2),
                ]
            )
        with self.assertRaises(ValueError):
            EnvelopeRule("root", EnvelopeType.SIMPLE, min_version=0)
        with self.assertRaises(ValueError):
            EnvelopeRule(
                "root", EnvelopeType.SIMPLE, min_version=3, max_version=2
            )
        with self.assertRaises(ValueError):
            EnvelopeRule("root", EnvelopeType.METADATA | EnvelopeType.SIMPLE)

        policy = EnvelopeMigrationPolicy(
            [EnvelopeRule("role1", EnvelopeType.METADATA, max_version=2)]
        )
        self.assertIs(
            policy.envelope_type_for("role1", 1), EnvelopeType.METADATA
        )
        self.assertIs(
            policy.envelope_type_for("role1", 2), EnvelopeType.METADATA
        )
        with self.assertRaises(EnvelopePolicyError):
            policy.envelope_type_for("role1", 3)
        with self.assertRaises(EnvelopePolicyError):
            policy.envelope_type_for("role2", 1)

    def test_root_rotation_obeys_policy(self) -> None:
        """Root rotation uses the policy and keeps dual authorization."""
        self.setup_repo()

        # root v2 continues in SIMPLE; everything else stays METADATA.
        self.sim.root.version += 1
        self.sim.envelope_types["root"] = EnvelopeType.SIMPLE
        self.sim.publish_root()
        self.sim.envelope_types["root"] = EnvelopeType.METADATA

        policy = EnvelopeMigrationPolicy(
            [
                EnvelopeRule("root", EnvelopeType.METADATA, max_version=1),
                EnvelopeRule("root", EnvelopeType.SIMPLE, min_version=2),
            ]
            + [
                EnvelopeRule(r, EnvelopeType.METADATA)
                for r in ["timestamp", "snapshot", "targets", "role1"]
            ]
        )
        updater = self._updater(policy, bootstrap=self.sim.signed_roots[0])
        updater.refresh()
        self.assertEqual(updater._trusted_set.root.version, 2)

    def test_root_signature_requirement_is_not_relaxed(self) -> None:
        """A SIMPLE root still needs both old and new root signatures."""
        self.setup_repo()
        self.sim.root.version += 1
        self.sim.envelope_types["root"] = EnvelopeType.SIMPLE
        # publish only self-signed SIMPLE root: previous root did not sign it
        self.sim.signers["root"] = {}
        self.sim.publish_root()

        policy = EnvelopeMigrationPolicy(
            [
                EnvelopeRule("root", EnvelopeType.METADATA, max_version=1),
                EnvelopeRule("root", EnvelopeType.SIMPLE, min_version=2),
            ]
            + [
                EnvelopeRule(r, EnvelopeType.METADATA)
                for r in ["timestamp", "snapshot", "targets", "role1"]
            ]
        )
        with self.assertRaises(UnsignedMetadataError):
            self._updater(policy, bootstrap=self.sim.signed_roots[0]).refresh()


if __name__ == "__main__":
    unittest.main()
