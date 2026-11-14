# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test the trusted download permit API (``TrustedTarget``).

Two in-memory repositories with independent trust roots serve the same
target path with different content. Lookups and downloads are interleaved
to show that permits are bound to the exact authenticated target
description and to the trust context (Updater) that issued them.
"""

from __future__ import annotations

import copy
import os
import sys
import tempfile
import unittest

from tests.repository_simulator import RepositorySimulator
from tuf.api.metadata import TargetFile
from tuf.ngclient import TrustedTarget, Updater

TARGET_PATH = "file.txt"
CONTENT_A = b"content from repository A"
CONTENT_B = b"content from repository B"


class TestTrustedTargetPermit(unittest.TestCase):
    """Test trusted download permits across two trust contexts."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()

        # Two repositories with independent trust roots, same target path
        self.sim_a = self._make_repo(CONTENT_A)
        self.sim_b = self._make_repo(CONTENT_B)

        self.updater_a = self._make_updater("a", self.sim_a)
        self.updater_b = self._make_updater("b", self.sim_b)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @staticmethod
    def _make_repo(content: bytes) -> RepositorySimulator:
        sim = RepositorySimulator()
        sim.targets.version += 1
        sim.add_target("targets", content, TARGET_PATH)
        sim.update_snapshot()
        return sim

    def _make_updater(self, name: str, sim: RepositorySimulator) -> Updater:
        metadata_dir = os.path.join(self.temp_dir.name, f"metadata-{name}")
        targets_dir = os.path.join(self.temp_dir.name, f"targets-{name}")
        os.mkdir(metadata_dir)
        os.mkdir(targets_dir)
        return Updater(
            metadata_dir,
            "https://example.com/metadata/",
            targets_dir,
            "https://example.com/targets/",
            sim,
            bootstrap=sim.signed_roots[0],
        )

    def _read(self, path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read()

    def test_interleaved_lookup_and_download(self) -> None:
        # Interleave lookups in the two trust contexts
        permit_a = self.updater_a.get_trusted_targetinfo(TARGET_PATH)
        permit_b = self.updater_b.get_trusted_targetinfo(TARGET_PATH)
        assert permit_a is not None
        assert permit_b is not None
        self.assertIsNone(self.updater_a.get_trusted_targetinfo("nonexistent"))

        # Interleave downloads: each permit downloads its own repository's
        # content
        path_a = self.updater_a.download_trusted_target(permit_a)
        path_b = self.updater_b.download_trusted_target(permit_b)
        self.assertEqual(self._read(path_a), CONTENT_A)
        self.assertEqual(self._read(path_b), CONTENT_B)

        # Legitimate permits hit the cache without new fetcher requests
        self.sim_a.fetch_tracker.targets.clear()
        self.sim_b.fetch_tracker.targets.clear()
        self.assertEqual(
            path_a, self.updater_a.find_cached_trusted_target(permit_a)
        )
        self.assertEqual(
            path_b, self.updater_b.find_cached_trusted_target(permit_b)
        )
        self.assertEqual(self.sim_a.fetch_tracker.targets, [])
        self.assertEqual(self.sim_b.fetch_tracker.targets, [])

    def test_cross_repository_permit_rejected(self) -> None:
        permit_a = self.updater_a.get_trusted_targetinfo(TARGET_PATH)
        permit_b = self.updater_b.get_trusted_targetinfo(TARGET_PATH)
        assert permit_a is not None
        assert permit_b is not None

        self.sim_a.fetch_tracker.metadata.clear()
        self.sim_a.fetch_tracker.targets.clear()

        # A permit from repository B grants nothing on updater A
        with self.assertRaises(ValueError):
            self.updater_a.download_trusted_target(permit_b)
        with self.assertRaises(ValueError):
            self.updater_a.find_cached_trusted_target(permit_b)
        with self.assertRaises(ValueError):
            self.updater_b.download_trusted_target(permit_a)

        # The fetcher never received a request
        self.assertEqual(self.sim_a.fetch_tracker.metadata, [])
        self.assertEqual(self.sim_a.fetch_tracker.targets, [])

    def test_altered_description_rejected(self) -> None:
        permit_a = self.updater_a.get_trusted_targetinfo(TARGET_PATH)
        permit_b = self.updater_b.get_trusted_targetinfo(TARGET_PATH)
        assert permit_a is not None
        assert permit_b is not None

        self.sim_a.fetch_tracker.metadata.clear()
        self.sim_a.fetch_tracker.targets.clear()

        # Replace the permit's description with another version of the
        # same path (repository B's description, different hashes/length)
        swapped = self.updater_a.get_trusted_targetinfo(TARGET_PATH)
        assert swapped is not None
        swapped._targetinfo = copy.deepcopy(permit_b.targetinfo)
        with self.assertRaises(ValueError):
            self.updater_a.download_trusted_target(swapped)
        with self.assertRaises(ValueError):
            self.updater_a.find_cached_trusted_target(swapped)

        # Tamper with the bound description in place
        tampered = self.updater_a.get_trusted_targetinfo(TARGET_PATH)
        assert tampered is not None
        tampered.targetinfo.hashes["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.updater_a.download_trusted_target(tampered)

        # The fetcher never received a request
        self.assertEqual(self.sim_a.fetch_tracker.metadata, [])
        self.assertEqual(self.sim_a.fetch_tracker.targets, [])

        # The untouched permit still works
        path_a = self.updater_a.download_trusted_target(permit_a)
        self.assertEqual(self._read(path_a), CONTENT_A)

    def test_plain_targetfile_rejected_by_trusted_api(self) -> None:
        # A TargetFile really returned by get_targetinfo() is still not a
        # permit
        info = self.updater_a.get_targetinfo(TARGET_PATH)
        assert info is not None

        # Neither is a fully self-constructed TargetFile
        forged = TargetFile.from_data(TARGET_PATH, CONTENT_A, ["sha256"])

        self.sim_a.fetch_tracker.metadata.clear()
        self.sim_a.fetch_tracker.targets.clear()

        for not_a_permit in (info, forged):
            with self.assertRaises(TypeError):
                self.updater_a.download_trusted_target(not_a_permit)  # type: ignore[arg-type]
            with self.assertRaises(TypeError):
                self.updater_a.find_cached_trusted_target(not_a_permit)  # type: ignore[arg-type]

        # The fetcher never received a request
        self.assertEqual(self.sim_a.fetch_tracker.metadata, [])
        self.assertEqual(self.sim_a.fetch_tracker.targets, [])

    def test_permit_cannot_be_constructed_directly(self) -> None:
        info = self.updater_a.get_targetinfo(TARGET_PATH)
        assert info is not None
        with self.assertRaises(TypeError):
            TrustedTarget(info, b"", self.updater_a)

    def test_legacy_targetfile_api_still_works(self) -> None:
        # The plain TargetFile workflow is unchanged
        info = self.updater_a.get_targetinfo(TARGET_PATH)
        assert info is not None
        path = self.updater_a.download_target(info)
        self.assertEqual(self._read(path), CONTENT_A)
        self.assertEqual(path, self.updater_a.find_cached_target(info))


if __name__ == "__main__":
    utils = __import__("tests.utils", fromlist=["configure_test_logging"])
    utils.configure_test_logging(sys.argv)
    unittest.main()
