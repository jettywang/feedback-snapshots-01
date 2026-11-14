# Copyright 2021-2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tests for optional usage-time expiry checks in Updater."""

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta

from tests.repository_simulator import RepositorySimulator
from tuf.api.exceptions import (
    TargetExpiredError,
    TargetUsageContextError,
)
from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    DelegatedRole,
    TargetFile,
    Targets,
)
from tuf.ngclient import Updater

SPEC_VER = ".".join(SPECIFICATION_VERSION)


class FixedClock:
    """A controllable usage clock: tests move it without sleeping."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


class TestUsageExpiry(unittest.TestCase):
    """Usage-time expiry of the actual chain that authorized a target."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.targets_dir)

        now = datetime.now(UTC).replace(microsecond=0)
        self.now = now
        self.clock = FixedClock(now)

        # Top-level metadata stays valid far beyond the delegated role used
        # below. This makes the delegated role the only blocker.
        self.sim = RepositorySimulator()
        self.sim.safe_expiry = now + timedelta(days=30)

        # role1 (delegated by top-level targets) expires much sooner.
        self.role1_expires = now + timedelta(days=1)
        role1_targets = Targets(
            1, SPEC_VER, self.role1_expires, {}, None
        )
        self.sim.add_delegation(
            "targets",
            DelegatedRole("role1", [], 1, False, ["*"], None),
            role1_targets,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _init_updater(
        self, usage_clock: FixedClock | None = None
    ) -> Updater:
        return Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
            bootstrap=self.sim.signed_roots[0],
            usage_clock=usage_clock,
        )

    def _add_target(
        self, role: str = "role1", path: str = "package.tar"
    ) -> None:
        self.sim.add_target(role, b"installer content", path)
        self.sim.md_delegates[role].signed.version += 1
        self.sim.update_snapshot()

    def test_top_level_valid_delegated_role_expired(self) -> None:
        """Fixed clock: top-level metadata valid, delegated role expired."""
        self._add_target()

        updater = self._init_updater(self.clock)
        # Usage time is within role1 expiry: lookup succeeds.
        info = updater.get_targetinfo("package.tar")
        assert info is not None
        self.assertEqual(
            updater.download_target(info),
            os.path.join(self.targets_dir, info.path),
        )

        # Move past role1 expiry but keep top-level metadata valid.
        self.clock.now = self.role1_expires + timedelta(hours=1)
        for role in ("root", "timestamp", "snapshot", "targets"):
            self.assertFalse(
                updater._trusted_set[role].is_expired(self.clock.now)
            )

        with self.assertRaises(TargetExpiredError) as caught:
            updater.download_target(info)
        self.assertEqual(caught.exception.role, "role1")
        self.assertEqual(caught.exception.expires, self.role1_expires)
        self.assertIn("role1", str(caught.exception))
        self.assertIn(self.role1_expires.isoformat(), str(caught.exception))

    def test_expiry_between_lookup_and_download(self) -> None:
        """Expiry point sits between target lookup and actual download."""
        self._add_target()
        updater = self._init_updater(self.clock)

        info = updater.get_targetinfo("package.tar")
        assert info is not None
        self.assertEqual(len(self.sim.fetch_tracker.targets), 0)

        # Advance only the usage clock: the refresh reference time and all
        # metadata loaded at lookup stay as they were.
        self.clock.now = self.role1_expires
        target_fetches = list(self.sim.fetch_tracker.targets)
        metadata_fetches = list(self.sim.fetch_tracker.metadata)

        with self.assertRaises(TargetExpiredError) as caught:
            updater.download_target(info)
        self.assertEqual(caught.exception.role, "role1")
        self.assertEqual(caught.exception.expires, self.role1_expires)

        # The refusal happened before fetch: no target request, and no
        # implicit refresh to paper over the expired target.
        self.assertListEqual(self.sim.fetch_tracker.targets, target_fetches)
        self.assertListEqual(self.sim.fetch_tracker.metadata, metadata_fetches)

    def test_cache_hit_checked_before_return(self) -> None:
        """A cached, hash-correct target is still refused when chain expired."""
        self._add_target()
        updater = self._init_updater(self.clock)
        info = updater.get_targetinfo("package.tar")
        assert info is not None
        path = updater.download_target(info)
        self.assertEqual(updater.find_cached_target(info), path)

        self.clock.now = self.role1_expires + timedelta(hours=1)
        with self.assertRaises(TargetExpiredError) as caught:
            updater.find_cached_target(info)
        self.assertEqual(caught.exception.role, "role1")

    def test_clock_rollback_does_not_revive_context(self) -> None:
        """A context judged expired stays expired if the clock moves back."""
        self._add_target()
        updater = self._init_updater(self.clock)
        info = updater.get_targetinfo("package.tar")
        assert info is not None

        self.clock.now = self.role1_expires + timedelta(hours=1)
        with self.assertRaises(TargetExpiredError) as caught:
            updater.find_cached_target(info)
        self.assertEqual(caught.exception.role, "role1")

        # Roll the usage clock back to before the expiry point.
        self.clock.now = self.now
        with self.assertRaises(TargetExpiredError) as caught:
            updater.download_target(info)
        self.assertEqual(caught.exception.role, "role1")
        self.assertEqual(caught.exception.expires, self.role1_expires)
        # Nor may a later lookup of the same target revive the context.
        with self.assertRaises(TargetExpiredError):
            updater.get_targetinfo("package.tar")

    def test_parent_expiry_blocks_child_target(self) -> None:
        """The complete delegation path is checked, not just the leaf role."""
        # role2 (the leaf) and all top-level roles stay valid for 30 days;
        # role1, the intermediate role on the path, expires after one day.
        role2_targets = Targets(
            1, SPEC_VER, self.now + timedelta(days=30), {}, None
        )
        self.sim.add_delegation(
            "role1",
            DelegatedRole("role2", [], 1, False, ["*"], None),
            role2_targets,
        )
        self.sim.add_target("role2", b"nested content", "nested")
        self.sim.update_snapshot()

        updater = self._init_updater(self.clock)
        info = updater.get_targetinfo("nested")
        assert info is not None

        self.clock.now = self.role1_expires + timedelta(hours=1)
        with self.assertRaises(TargetExpiredError) as caught:
            updater.find_cached_target(info)
        self.assertEqual(caught.exception.role, "role1")
        self.assertEqual(caught.exception.expires, self.role1_expires)

    def test_legacy_interface_unchanged(self) -> None:
        """Without usage_clock the old methods keep working after expiry."""
        self._add_target()
        updater = self._init_updater(usage_clock=None)

        info = updater.get_targetinfo("package.tar")
        assert info is not None
        # The delegated metadata is past its usage expiry in test time, but
        # no usage clock was provided: no usage-time refusal.
        self.clock.now = self.role1_expires + timedelta(hours=1)
        path = updater.download_target(info)
        self.assertEqual(updater.find_cached_target(info), path)

    def test_foreign_target_has_no_chain(self) -> None:
        """A target description never returned by lookup has no chain."""
        self._add_target()
        updater = self._init_updater(self.clock)
        info = updater.get_targetinfo("package.tar")
        assert info is not None

        # Same path but a different authenticated description: this is not
        # the target that was looked up.
        foreign_dict = info.to_dict()
        foreign_dict["length"] += 1
        foreign = TargetFile.from_dict(foreign_dict, info.path)
        with self.assertRaises(TargetUsageContextError):
            updater.download_target(foreign)

    def test_equal_description_shares_context(self) -> None:
        """A copy with the same authenticated description keeps its chain."""
        self._add_target()
        updater = self._init_updater(self.clock)
        info = updater.get_targetinfo("package.tar")
        assert info is not None

        copy = TargetFile.from_dict(info.to_dict(), info.path)
        self.assertEqual(
            updater.download_target(copy),
            os.path.join(self.targets_dir, info.path),
        )

        # The shared context still expires at the same moment.
        self.clock.now = self.role1_expires + timedelta(hours=1)
        with self.assertRaises(TargetExpiredError):
            updater.find_cached_target(copy)


if __name__ == "__main__":
    unittest.main()
