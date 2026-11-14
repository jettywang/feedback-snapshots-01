# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test Updater repository namespace isolation.

Two independent publishers share a single cache root directory by giving
each repository a caller-chosen namespace. These tests verify that
metadata (including root history and cached role versions) is isolated
per namespace, that rebinding a namespace to an incompatible trust root
is rejected, and that legacy single-repository caches are only migrated
explicitly.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest

from tests import utils
from tests.repository_simulator import RepositorySimulator
from tuf.api import exceptions
from tuf.api.metadata import DelegatedRole, Metadata, Targets
from tuf.ngclient import Updater


def _dir_digest(path: str) -> str:
    """Hash all file relative paths and contents below path."""
    digest = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames.sort()
        for name in sorted(filenames):
            filepath = os.path.join(dirpath, name)
            digest.update(os.path.relpath(filepath, path).encode())
            with open(filepath, "rb") as f:
                digest.update(f.read())
    return digest.hexdigest()


class TestUpdaterNamespaces(unittest.TestCase):
    """Test namespace isolation between publishers sharing a cache root."""

    # set dump_dir to trigger repository state dumps
    dump_dir: str | None = None

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.shared_cache = os.path.join(self.temp_dir.name, "metadata")
        os.mkdir(self.shared_cache)
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.targets_dir)

        # Two independent publishers that both delegate a role named
        # "packages" and publish different targets through it
        self.sim_a = self._make_publisher(b"package from publisher A")
        self.sim_b = self._make_publisher(b"package from publisher B")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @staticmethod
    def _make_publisher(content: bytes) -> RepositorySimulator:
        sim = RepositorySimulator()
        role = DelegatedRole("packages", [], 1, False, ["*"], None)
        sim.add_delegation("targets", role, Targets(expires=sim.safe_expiry))
        sim.add_target("packages", content, "pkg")
        sim.targets.version += 1
        sim.update_snapshot()
        return sim

    def _init_updater(
        self,
        sim: RepositorySimulator,
        namespace: str | None,
        bootstrap: bytes | None = None,
        metadata_dir: str | None = None,
    ) -> Updater:
        if bootstrap is None:
            bootstrap = sim.signed_roots[0]
        return Updater(
            metadata_dir or self.shared_cache,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            sim,
            bootstrap=bootstrap,
            namespace=namespace,
        )

    def _namespace_dir(self, namespace: str) -> str:
        return os.path.join(self.shared_cache, namespace)

    def _cached_version(self, namespace: str, role: str) -> int:
        path = os.path.join(self._namespace_dir(namespace), f"{role}.json")
        return Metadata.from_file(path).signed.version

    def test_interleaved_refresh_isolation(self) -> None:
        updater_a = self._init_updater(self.sim_a, "publisher-a")
        updater_b = self._init_updater(self.sim_b, "publisher-b")

        # Interleave refreshes and delegated role lookups: both
        # publishers delegate a role named "packages"
        updater_a.refresh()
        updater_b.refresh()
        self.assertIsNotNone(updater_b.get_targetinfo("pkg"))

        # Record publisher B's cache state, then let publisher A work
        digest_b = _dir_digest(self._namespace_dir("publisher-b"))
        self.assertIsNotNone(updater_a.get_targetinfo("pkg"))
        self._init_updater(self.sim_a, "publisher-a").refresh()

        # Both publishers cached a "packages" role, but content differs
        packages_a = os.path.join(
            self._namespace_dir("publisher-a"), "packages.json"
        )
        packages_b = os.path.join(
            self._namespace_dir("publisher-b"), "packages.json"
        )
        with open(packages_a, "rb") as f:
            self.assertEqual(f.read(), self.sim_a.fetch_metadata("packages"))
        with open(packages_b, "rb") as f:
            self.assertEqual(f.read(), self.sim_b.fetch_metadata("packages"))

        # Root history is isolated per namespace as well
        root_a = os.path.join(
            self._namespace_dir("publisher-a"), "root_history", "1.root.json"
        )
        with open(root_a, "rb") as f:
            self.assertEqual(f.read(), self.sim_a.signed_roots[0])

        # No shared files leaked into the shared cache root
        top_level = {
            e.name
            for e in os.scandir(self.shared_cache)
            if not e.name.startswith(".")
        }
        self.assertEqual(top_level, {"publisher-a", "publisher-b"})

        # Publisher A's activity did not touch publisher B's cache
        self.assertEqual(
            digest_b, _dir_digest(self._namespace_dir("publisher-b"))
        )

    def test_interrupted_write_and_rebuild(self) -> None:
        updater_a = self._init_updater(self.sim_a, "publisher-a")
        updater_b = self._init_updater(self.sim_b, "publisher-b")
        updater_a.refresh()
        updater_b.refresh()

        # Record publisher B's cache state and accepted versions
        digest_b = _dir_digest(self._namespace_dir("publisher-b"))
        timestamp_version_b = self._cached_version("publisher-b", "timestamp")
        snapshot_version_b = self._cached_version("publisher-b", "snapshot")

        # Simulate an interrupted write in publisher A's namespace: a
        # truncated timestamp and a leftover temporary file
        dir_a = self._namespace_dir("publisher-a")
        with open(os.path.join(dir_a, "timestamp.json"), "r+b") as f:
            f.truncate(10)
        with open(os.path.join(dir_a, "tmp leftover"), "wb") as f:
            f.write(b"partial")

        # Rebuild publisher A's client from scratch: it recovers by
        # re-downloading the corrupted metadata
        updater_a2 = self._init_updater(self.sim_a, "publisher-a")
        updater_a2.refresh()
        self.assertEqual(
            self._cached_version("publisher-a", "timestamp"),
            self.sim_a.timestamp.version,
        )

        # Publisher B's cache and acceptable versions are unchanged
        self.assertEqual(
            digest_b, _dir_digest(self._namespace_dir("publisher-b"))
        )
        updater_b2 = self._init_updater(
            self.sim_b, "publisher-b", bootstrap=self.sim_b.signed_roots[0]
        )
        updater_b2.refresh()
        self.assertEqual(
            self._cached_version("publisher-b", "timestamp"),
            timestamp_version_b,
        )
        self.assertEqual(
            self._cached_version("publisher-b", "snapshot"),
            snapshot_version_b,
        )

    def test_incompatible_rebind_rejected(self) -> None:
        self._init_updater(self.sim_a, "shared-name").refresh()

        # Rebinding the same identifier to publisher B's trust root fails
        with self.assertRaises(exceptions.RepositoryError) as ctx:
            self._init_updater(self.sim_b, "shared-name")
        self.assertIn("shared-name", str(ctx.exception))

        # The other namespace is not affected by the failed rebind
        updater_a = self._init_updater(self.sim_a, "shared-name")
        updater_a.refresh()

    def test_rebind_after_root_rotation(self) -> None:
        self._init_updater(self.sim_a, "publisher-a").refresh()

        # Rotate to root v2 and let the client cache the new root
        self.sim_a.root.version += 1
        self.sim_a.publish_root()
        self._init_updater(self.sim_a, "publisher-a").refresh()

        # Rebinding with the newer root of the same chain is accepted
        updater = self._init_updater(
            self.sim_a, "publisher-a", bootstrap=self.sim_a.signed_roots[1]
        )
        updater.refresh()

    def test_legacy_cache_requires_explicit_migration(self) -> None:
        legacy_dir = os.path.join(self.temp_dir.name, "legacy")
        os.mkdir(legacy_dir)
        self._init_updater(self.sim_a, None, metadata_dir=legacy_dir).refresh()

        # A namespaced client refuses to share the unmigrated cache root
        with self.assertRaises(exceptions.RepositoryError) as ctx:
            self._init_updater(
                self.sim_a, "publisher-a", metadata_dir=legacy_dir
            )
        self.assertIn("migrate_to_namespace", str(ctx.exception))
        self.assertIn("publisher-a", str(ctx.exception))

        # Explicit migration moves the legacy cache into the namespace
        Updater.migrate_to_namespace(legacy_dir, "publisher-a")
        self.assertFalse(os.path.exists(os.path.join(legacy_dir, "root.json")))
        self.assertTrue(
            os.path.exists(
                os.path.join(
                    legacy_dir, "publisher-a", "root_history", "1.root.json"
                )
            )
        )

        # The migrated cache is usable (cached root as trust anchor)
        updater = Updater(
            legacy_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim_a,
            bootstrap=None,
            namespace="publisher-a",
        )
        updater.refresh()

        # Migration cannot happen twice
        with self.assertRaises(exceptions.RepositoryError):
            Updater.migrate_to_namespace(legacy_dir, "publisher-a")

    def test_invalid_namespace(self) -> None:
        for namespace in ["", ".", "..", "../other", "a/b", ".hidden", "a b"]:
            with (
                self.subTest(namespace=namespace),
                self.assertRaises(ValueError),
            ):
                self._init_updater(self.sim_a, namespace)

    def test_remote_fields_do_not_choose_directory(self) -> None:
        # Remote self-reported fields must not influence the cache location
        self.sim_a.root.unrecognized_fields["namespace"] = "../evil"
        self.sim_a.root.unrecognized_fields["repository"] = "publisher-b"
        self.sim_a.root.version += 1
        self.sim_a.publish_root()

        updater = self._init_updater(
            self.sim_a, "publisher-a", bootstrap=self.sim_a.signed_roots[-1]
        )
        updater.refresh()

        self.assertTrue(
            os.path.isdir(os.path.join(self._namespace_dir("publisher-a")))
        )
        self.assertFalse(
            os.path.exists(os.path.join(self.temp_dir.name, "evil"))
        )
        self.assertFalse(os.path.exists(self._namespace_dir("publisher-b")))


if __name__ == "__main__":
    utils.configure_test_logging(sys.argv)
    unittest.main()
