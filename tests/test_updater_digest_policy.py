# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for the explicit client digest (hash algorithm) policy.

The policy is exercised end-to-end through ``Updater`` so that the same
conclusion is reached for content fetched from the (simulated) remote
repository and for content read back from the local cache. A consistent
snapshot hash prefix is only a locator and must never be treated as trusted.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest

from tests.repository_simulator import RepositorySimulator
from tuf.api import exceptions
from tuf.api.metadata import MetaFile, TargetFile
from tuf.ngclient import DigestPolicy, Updater
from tuf.ngclient.config import UpdaterConfig

TARGET_PATH = "targetpath"
TARGET_CONTENT = b"target content"


class TestDigestPolicy(unittest.TestCase):
    """End-to-end digest policy tests on the ngclient Updater."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.targets_dir)

        self.sim = RepositorySimulator()
        # Disable consistent snapshots: the hash-prefixed filename is only a
        # locator, so these tests verify content purely via the digest policy
        # rather than the simulator's prefix bookkeeping.
        self.sim.root.consistent_snapshot = False
        self.sim.root.version += 1
        self.sim.publish_root()
        # Make timestamp/snapshot carry real hashes of the metadata they
        # describe, so metadata digest policies have something to inspect.
        self.sim.compute_metafile_hashes_length = True
        self.sim.add_target("targets", TARGET_CONTENT, TARGET_PATH)
        self.sim.targets.version += 1
        self.sim.update_snapshot()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _updater(self, config: UpdaterConfig | None = None) -> Updater:
        return Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
            config=config,
            bootstrap=self.sim.signed_roots[0],
        )

    def _strict_config(self) -> UpdaterConfig:
        # The simulator hashes metadata with sha256, so metadata descriptions
        # accept sha256. For targets, sha512 plays the "new" accepted
        # algorithm while md5 is the phased-out legacy algorithm.
        return UpdaterConfig(
            metadata_digest_policy=DigestPolicy(
                ["sha256"], require_digest=False
            ),
            target_digest_policy=DigestPolicy(["sha512"], require_digest=True),
        )

    def _dual_digests(self, data: bytes) -> dict[str, str]:
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
        }

    # ------------------------------------------------------------------
    # Default behavior stays compatible.
    # ------------------------------------------------------------------
    def test_default_policy_is_permissive(self) -> None:
        config = UpdaterConfig()
        # No explicit accepted list: every supported algorithm accepted.
        self.assertIsNone(config.target_digest_policy.accepted_algorithms)
        # Metadata descriptions may omit hashes, targets may not.
        self.assertFalse(config.metadata_digest_policy.require_digest)
        self.assertTrue(config.target_digest_policy.require_digest)

        updater = self._updater(config)
        updater.refresh()
        info = updater.get_targetinfo(TARGET_PATH)
        assert info is not None
        path = updater.download_target(info)
        # The same target is accepted from the cache on a later run.
        self.assertEqual(path, updater.find_cached_target(info))

    # ------------------------------------------------------------------
    # Scenario 1: legacy digest correct, modern digest wrong.
    # ------------------------------------------------------------------
    def test_legacy_correct_modern_wrong_rejected_remote_and_cache(
        self,
    ) -> None:
        digests = self._dual_digests(TARGET_CONTENT)
        # Tamper with the modern digest while leaving the legacy one correct.
        digests["sha512"] = "0" * 128
        self.sim.targets.targets[TARGET_PATH] = TargetFile(
            len(TARGET_CONTENT), digests, TARGET_PATH
        )
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        updater = self._updater(self._strict_config())
        updater.refresh()
        info = updater.get_targetinfo(TARGET_PATH)
        assert info is not None

        # Remote download must fail: a correct legacy digest cannot rescue a
        # mismatching modern one.
        with self.assertRaises(exceptions.LengthOrHashMismatchError):
            updater.download_target(info)
        # Nothing was persisted, so the cache lookup reaches the same verdict.
        self.assertIsNone(updater.find_cached_target(info))

    # ------------------------------------------------------------------
    # Scenario 2: only a legacy algorithm is present.
    # ------------------------------------------------------------------
    def test_legacy_only_rejected_remote_and_cache(self) -> None:
        legacy = {"md5": hashlib.md5(TARGET_CONTENT).hexdigest()}
        self.sim.targets.targets[TARGET_PATH] = TargetFile(
            len(TARGET_CONTENT), legacy, TARGET_PATH
        )
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        updater = self._updater(self._strict_config())
        updater.refresh()
        info = updater.get_targetinfo(TARGET_PATH)
        assert info is not None

        with self.assertRaises(exceptions.DisabledAlgorithmError):
            updater.download_target(info)
        self.assertIsNone(updater.find_cached_target(info))

    def test_unknown_algorithm_is_distinct_from_disabled(self) -> None:
        unknown = {"frobnicate-9000": "x" * 64}
        self.sim.targets.targets[TARGET_PATH] = TargetFile(
            len(TARGET_CONTENT), unknown, TARGET_PATH
        )
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        updater = self._updater(self._strict_config())
        updater.refresh()
        info = updater.get_targetinfo(TARGET_PATH)
        assert info is not None

        with self.assertRaises(exceptions.UnknownAlgorithmError):
            updater.download_target(info)
        self.assertIsNone(updater.find_cached_target(info))

    # ------------------------------------------------------------------
    # Scenario 3: legal omission of metadata digests.
    # ------------------------------------------------------------------
    def test_metadata_without_hashes_is_accepted(self) -> None:
        # TUF allows timestamp/snapshot descriptions to omit hashes.
        self.sim.timestamp.snapshot_meta = MetaFile(
            self.sim.snapshot.version, None, None
        )
        for role in self.sim.snapshot.meta:
            self.sim.snapshot.meta[role] = MetaFile(
                self.sim.snapshot.meta[role].version, None, None
            )
        self.sim.timestamp.version += 1

        config = UpdaterConfig(
            metadata_digest_policy=DigestPolicy(
                ["sha256"], require_digest=False
            )
        )
        updater = self._updater(config)
        # Refresh succeeds even though no metadata hashes are present.
        updater.refresh()
        info = updater.get_targetinfo(TARGET_PATH)
        self.assertIsNotNone(info)

    def test_target_missing_digest_is_rejected(self) -> None:
        # Target files always require a digest; model a missing one at the
        # policy boundary (the TargetFile constructor itself rejects {}).
        policy = DigestPolicy(["sha512"], require_digest=True)
        with self.assertRaises(exceptions.MissingDigestError):
            policy.verify_hashes(TARGET_CONTENT, None)

    def test_consistent_snapshot_prefix_is_not_trusted(self) -> None:
        # With consistent snapshots the download URL is hash-prefixed, but
        # that prefix only locates the file. Serve tampered bytes under the
        # same valid prefix: the digest policy must reject them regardless.
        self.sim.root.consistent_snapshot = True
        self.sim.root.version += 1
        self.sim.publish_root()

        modern = {"sha512": hashlib.sha512(TARGET_CONTENT).hexdigest()}
        new_target = TargetFile(len(TARGET_CONTENT), modern, TARGET_PATH)
        self.sim.targets.targets[TARGET_PATH] = new_target
        # Keep the served target's metadata aligned so the consistent-snapshot
        # prefix lookup succeeds before content verification runs.
        self.sim.target_files[TARGET_PATH].target_file = new_target
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        updater = self._updater(self._strict_config())
        updater.refresh()
        info = updater.get_targetinfo(TARGET_PATH)
        assert info is not None

        # A hash-prefixed URL is requested, proving consistent snapshots.
        self.sim.fetch_tracker.targets.clear()
        self.sim.target_files[TARGET_PATH].data = b"tampered bytes"
        with self.assertRaises(exceptions.LengthOrHashMismatchError):
            updater.download_target(info)
        self.assertEqual(self.sim.fetch_tracker.targets[0][1], modern["sha512"])
        self.assertIsNone(updater.find_cached_target(info))

    # ------------------------------------------------------------------
    # A policy-compliant target is accepted from both remote and cache.
    # ------------------------------------------------------------------
    def test_accepted_modern_digest_succeeds_remote_then_cache(self) -> None:
        modern = {"sha512": hashlib.sha512(TARGET_CONTENT).hexdigest()}
        self.sim.targets.targets[TARGET_PATH] = TargetFile(
            len(TARGET_CONTENT), modern, TARGET_PATH
        )
        self.sim.targets.version += 1
        self.sim.update_snapshot()

        updater = self._updater(self._strict_config())
        updater.refresh()
        info = updater.get_targetinfo(TARGET_PATH)
        assert info is not None

        path = updater.download_target(info)
        self.assertEqual(path, updater.find_cached_target(info))

        # A fresh updater reading only the local cache reaches the same
        # conclusion without re-downloading the target.
        second = self._updater(self._strict_config())
        second.refresh()
        cached_info = second.get_targetinfo(TARGET_PATH)
        assert cached_info is not None
        self.assertEqual(path, second.find_cached_target(cached_info))

    # ------------------------------------------------------------------
    # Metadata description with only a legacy digest is rejected at refresh.
    # ------------------------------------------------------------------
    def test_legacy_only_metadata_digest_rejected_at_refresh(self) -> None:
        snapshot_bytes = self.sim.fetch_metadata("snapshot")
        legacy_meta = MetaFile(
            self.sim.snapshot.version,
            len(snapshot_bytes),
            {"md5": hashlib.md5(snapshot_bytes).hexdigest()},
        )
        self.sim.timestamp.snapshot_meta = legacy_meta
        self.sim.timestamp.version += 1

        updater = self._updater(self._strict_config())
        with self.assertRaises(exceptions.DisabledAlgorithmError):
            updater.refresh()

    def test_unknown_metadata_digest_rejected_at_refresh(self) -> None:
        snapshot_bytes = self.sim.fetch_metadata("snapshot")
        unknown_meta = MetaFile(
            self.sim.snapshot.version,
            len(snapshot_bytes),
            {"frobnicate-9000": "x" * 64},
        )
        self.sim.timestamp.snapshot_meta = unknown_meta
        self.sim.timestamp.version += 1

        updater = self._updater(self._strict_config())
        with self.assertRaises(exceptions.UnknownAlgorithmError):
            updater.refresh()


class TestDigestMigration(unittest.TestCase):
    """The two-stage migration: tolerate dual digests, then ban legacy-only."""

    def setUp(self) -> None:
        self.data = b"migration target"
        self.md5 = hashlib.md5(self.data).hexdigest()
        self.sha512 = hashlib.sha512(self.data).hexdigest()

    def _verify(self, hashes: dict[str, str], policy: DigestPolicy) -> None:
        target = TargetFile(len(self.data), hashes, "p")
        policy.verify_hashes(self.data, target.hashes)

    def test_stage_one_dual_digest_compatibility(self) -> None:
        # Stage 1: the legacy algorithm remains accepted, so both dual-digest
        # metadata and not-yet-migrated legacy-only metadata keep working.
        stage_one = DigestPolicy(["md5", "sha512"], require_digest=True)

        self._verify({"md5": self.md5, "sha512": self.sha512}, stage_one)
        self._verify({"md5": self.md5}, stage_one)

    def test_stage_two_legacy_only_banned(self) -> None:
        # Stage 2: drop the legacy algorithm from the accepted set. A modern
        # digest (alone or next to legacy) still passes; legacy-only is now
        # rejected, and a wrong modern digest is not rescued by legacy.
        stage_two = DigestPolicy(["sha512"], require_digest=True)

        self._verify({"sha512": self.sha512}, stage_two)
        self._verify({"md5": self.md5, "sha512": self.sha512}, stage_two)

        with self.assertRaises(exceptions.DisabledAlgorithmError):
            self._verify({"md5": self.md5}, stage_two)
        with self.assertRaises(exceptions.LengthOrHashMismatchError):
            self._verify({"md5": self.md5, "sha512": "0" * 128}, stage_two)


if __name__ == "__main__":
    unittest.main()
