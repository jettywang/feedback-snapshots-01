# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test ngclient Updater toggling consistent snapshot"""

from __future__ import annotations

import contextlib
import hashlib
import os
import sys
import tempfile
import unittest
from typing import TYPE_CHECKING, Any
from unittest import mock
from urllib import parse

from tests import utils
from tests.repository_simulator import RepositorySimulator
from tuf.api import exceptions
from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Root,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.ngclient import Updater
from tuf.ngclient._internal.trusted_metadata_set import TrustedMetadataSet

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator


class TestConsistentSnapshot(unittest.TestCase):
    """Test different combinations of 'consistent_snapshot' and
    'prefix_targets_with_hash' and verify that the correct URLs
    are formed for each combination"""

    # set dump_dir to trigger repository state dumps
    dump_dir: str | None = None

    def setUp(self) -> None:
        self.subtest_count = 0
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_dir = os.path.join(self.temp_dir.name, "metadata")
        self.targets_dir = os.path.join(self.temp_dir.name, "targets")
        os.mkdir(self.metadata_dir)
        os.mkdir(self.targets_dir)
        self.sim: RepositorySimulator

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def setup_subtest(
        self, consistent_snapshot: bool, prefix_targets: bool = True
    ) -> None:
        self.sim = self._init_repo(consistent_snapshot, prefix_targets)

        self.subtest_count += 1
        if self.dump_dir is not None:
            # create subtest dumpdir
            name = f"{self.id().split('.')[-1]}-{self.subtest_count}"
            self.sim.dump_dir = os.path.join(self.dump_dir, name)
            os.mkdir(self.sim.dump_dir)

    def teardown_subtest(self) -> None:
        if self.dump_dir is not None:
            self.sim.write()

        utils.cleanup_metadata_dir(self.metadata_dir)

    def _init_repo(
        self, consistent_snapshot: bool, prefix_targets: bool = True
    ) -> RepositorySimulator:
        """Create a new RepositorySimulator instance"""
        sim = RepositorySimulator()
        sim.root.consistent_snapshot = consistent_snapshot
        sim.root.version += 1
        sim.publish_root()
        sim.prefix_targets_with_hash = prefix_targets

        return sim

    def _init_updater(self) -> Updater:
        """Create a new Updater instance"""
        return Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            self.sim,
            bootstrap=self.sim.signed_roots[-1],
        )

    def _assert_metadata_files_exist(self, roles: Iterable[str]) -> None:
        """Assert that local metadata files exist for 'roles'"""
        local_metadata_files = os.listdir(self.metadata_dir)
        for role in roles:
            self.assertIn(f"{role}.json", local_metadata_files)

    def _assert_targets_files_exist(self, filenames: Iterable[str]) -> None:
        """Assert that local files with 'filenames' exist"""
        local_target_files = os.listdir(self.targets_dir)
        for filename in filenames:
            self.assertIn(filename, local_target_files)

    top_level_roles_data = {
        "consistent_snaphot disabled": {
            "consistent_snapshot": False,
            "calls": [
                ("root", 3),
                ("timestamp", None),
                ("snapshot", None),
                ("targets", None),
            ],
        },
        "consistent_snaphot enabled": {
            "consistent_snapshot": True,
            "calls": [
                ("root", 3),
                ("timestamp", None),
                ("snapshot", 1),
                ("targets", 1),
            ],
        },
    }

    @utils.run_sub_tests_with_dataset(top_level_roles_data)
    def test_top_level_roles_update(
        self, test_case_data: dict[str, Any]
    ) -> None:
        # Test if the client fetches and stores metadata files with the
        # correct version prefix, depending on 'consistent_snapshot' config
        consistent_snapshot: bool = test_case_data["consistent_snapshot"]
        exp_calls: list[Any] = test_case_data["calls"]

        self.setup_subtest(consistent_snapshot)
        updater = self._init_updater()

        # cleanup fetch tracker metadata
        self.sim.fetch_tracker.metadata.clear()
        updater.refresh()

        # metadata files are fetched with the expected version (or None)
        self.assertListEqual(self.sim.fetch_tracker.metadata, exp_calls)
        # metadata files are always persisted without a version prefix
        self._assert_metadata_files_exist(TOP_LEVEL_ROLE_NAMES)

    delegated_roles_data = {
        "consistent_snaphot disabled": {
            "consistent_snapshot": False,
            "expected_version": None,
        },
        "consistent_snaphot enabled": {
            "consistent_snapshot": True,
            "expected_version": 1,
        },
    }

    @utils.run_sub_tests_with_dataset(delegated_roles_data)
    def test_delegated_roles_update(
        self, test_case_data: dict[str, Any]
    ) -> None:
        # Test if the client fetches and stores delegated metadata files with
        # the correct version prefix, depending on 'consistent_snapshot' config
        consistent_snapshot: bool = test_case_data["consistent_snapshot"]
        exp_version: int | None = test_case_data["expected_version"]
        rolenames = ["role1", "..", "."]
        exp_calls = [(role, exp_version) for role in rolenames]

        self.setup_subtest(consistent_snapshot)
        # Add new delegated targets
        spec_version = ".".join(SPECIFICATION_VERSION)
        for role in rolenames:
            delegated_role = DelegatedRole(role, [], 1, False, ["*"], None)
            targets = Targets(1, spec_version, self.sim.safe_expiry, {}, None)
            self.sim.add_delegation("targets", delegated_role, targets)
        self.sim.update_snapshot()
        updater = self._init_updater()
        updater.refresh()

        # cleanup fetch tracker metadata
        self.sim.fetch_tracker.metadata.clear()
        # trigger updater to fetch the delegated metadata
        updater.get_targetinfo("anything")
        # metadata files are fetched with the expected version (or None)
        self.assertListEqual(self.sim.fetch_tracker.metadata, exp_calls)
        # metadata files are always persisted without a version prefix
        self._assert_metadata_files_exist(rolenames)

    targets_download_data = {
        "consistent_snaphot disabled": {
            "consistent_snapshot": False,
            "prefix_targets": True,
            "hash_algo": None,
            "targetpaths": ["file", "file.txt", "..file.ext", "f.le"],
        },
        "consistent_snaphot enabled without prefixed targets": {
            "consistent_snapshot": True,
            "prefix_targets": False,
            "hash_algo": None,
            "targetpaths": ["file", "file.txt", "..file.ext", "f.le"],
        },
        "consistent_snaphot enabled with prefixed targets": {
            "consistent_snapshot": True,
            "prefix_targets": True,
            "hash_algo": "sha256",
            "targetpaths": ["file", "file.txt", "..file.ext", "f.le"],
        },
    }

    @utils.run_sub_tests_with_dataset(targets_download_data)
    def test_download_targets(self, test_case_data: dict[str, Any]) -> None:
        # Test if the client fetches and stores target files with
        # the correct hash prefix, depending on 'consistent_snapshot'
        # and 'prefix_targets_with_hash' config
        consistent_snapshot: bool = test_case_data["consistent_snapshot"]
        prefix_targets_with_hash: bool = test_case_data["prefix_targets"]
        hash_algo: str | None = test_case_data["hash_algo"]
        targetpaths: list[str] = test_case_data["targetpaths"]

        self.setup_subtest(consistent_snapshot, prefix_targets_with_hash)
        # Add targets to repository
        for targetpath in targetpaths:
            self.sim.targets.version += 1
            self.sim.add_target("targets", b"content", targetpath)
        self.sim.update_snapshot()

        updater = self._init_updater()
        updater.config.prefix_targets_with_hash = prefix_targets_with_hash
        updater.refresh()

        for path in targetpaths:
            info = updater.get_targetinfo(path)
            assert isinstance(info, TargetFile)
            updater.download_target(info)

            # target files are always persisted without hash prefix
            self._assert_targets_files_exist([info.path])

            # files are fetched with the expected hash prefix (or None)
            exp_calls = [
                (path, None if not hash_algo else info.hashes[hash_algo])
            ]

            self.assertListEqual(self.sim.fetch_tracker.targets, exp_calls)
            self.sim.fetch_tracker.targets.clear()


@contextlib.contextmanager
def _stale_naming_mutation(
    frozen_consistent_snapshot: bool,
) -> Iterator[None]:
    """Temporarily make the client keep the old root's naming rule.

    Simulates a client that carries the initial root's
    consistent_snapshot value over into the new trust state: every root
    update is rewritten to report the frozen value. Only the client's
    trusted metadata is mutated: the repository is unaffected and the
    persisted root bytes still contain the real value.
    """
    update_root = TrustedMetadataSet.update_root

    def patched_update_root(self: TrustedMetadataSet, data: bytes) -> Root:
        root = update_root(self, data)
        root.consistent_snapshot = frozen_consistent_snapshot
        return root

    with mock.patch.object(
        TrustedMetadataSet, "update_root", patched_update_root
    ):
        yield


class DualNamingRepositorySimulator(RepositorySimulator):
    """Simulates a mirror that serves both consistent-snapshot naming
    schemes at the same time.

    The naming scheme matching ``active_consistent_snapshot`` serves the
    current metadata and target content (via the base class). The other
    scheme serves stale but well-formed data (correctly signed metadata,
    correctly formatted target bytes) so a client that applies the wrong
    naming rule never receives a 404: it receives format-valid data that
    fails verification, which tests can then detect.

    ``active_consistent_snapshot`` is a plain attribute (instead of
    ``root.consistent_snapshot``) so that client-side mutations of the
    trusted root cannot affect request dispatch.
    """

    def __init__(self) -> None:
        super().__init__()
        # The naming rule the repository currently considers correct
        self.active_consistent_snapshot = False
        # Signed stale metadata bytes keyed by role, served on the naming
        # scheme that is not currently active
        self.stale_metadata: dict[str, bytes] = {}
        # Stale target content keyed by exact request filename, served on
        # the naming scheme that is not currently active
        self.stale_targets: dict[str, bytes] = {}
        # All requested URL paths, in order
        self.requested_paths: list[str] = []

    def _fetch(self, url: str) -> Iterator[bytes]:
        path = parse.urlparse(url).path
        self.requested_paths.append(path)
        stale = self._stale_response(path)
        if stale is not None:
            yield stale
        else:
            yield from super()._fetch(url)

    def _stale_response(self, path: str) -> bytes | None:
        """Return stale well-formed data if 'path' uses the naming rule
        that is not currently active, else None."""
        if path.startswith("/metadata/") and path.endswith(".json"):
            return self._stale_metadata_response(path)
        if path.startswith("/targets/"):
            return self._stale_target_response(path)
        return None

    def _stale_metadata_response(self, path: str) -> bytes | None:
        ver_and_name = path[len("/metadata/") :][: -len(".json")]
        version_str, sep, role = ver_and_name.partition(".")
        # root is always version-prefixed, timestamp never is
        if (sep and role == Root.type) or ver_and_name == Timestamp.type:
            return None
        if bool(sep) == self.active_consistent_snapshot:
            return None
        rolename = role if sep else ver_and_name
        data = self.stale_metadata.get(
            parse.unquote(rolename, encoding="utf-8")
        )
        if data is None:
            return None
        version = int(version_str) if sep else None
        self.fetch_tracker.metadata.append((rolename, version))
        return data

    def _stale_target_response(self, path: str) -> bytes | None:
        filename = path.rpartition("/")[2]
        data = self.stale_targets.get(filename)
        if data is None:
            return None
        prefix = None
        target_path = filename
        if not self.active_consistent_snapshot:
            # the stale naming scheme is the hash-prefixed one
            prefix, _, target_path = filename.partition(".")
        self.fetch_tracker.targets.append((target_path, prefix))
        return data


class TestConsistentSnapshotSwitch(unittest.TestCase):
    """Test that toggling root.consistent_snapshot does not leak the old
    root's naming rules into the new trust state.

    The client keeps its local snapshot, targets and delegation caches
    from before the switch, then updates over a chain of consecutively
    signed roots. The mirror serves conflicting files under both naming
    schemes at once: request names, final authenticated content and
    lazily loaded delegations must all follow the final trusted root.
    """

    target_path = "file1"
    old_content = b"content before the switch"
    final_content = b"content after the switch"
    final_hash = hashlib.sha256(final_content).hexdigest()

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _init_dirs(self, name: str) -> None:
        base = os.path.join(self.temp_dir.name, name)
        self.metadata_dir = os.path.join(base, "metadata")
        self.targets_dir = os.path.join(base, "targets")
        os.makedirs(self.metadata_dir)
        os.makedirs(self.targets_dir)

    def _init_updater(
        self, sim: RepositorySimulator, bootstrap: bytes | None = None
    ) -> Updater:
        return Updater(
            self.metadata_dir,
            "https://example.com/metadata/",
            self.targets_dir,
            "https://example.com/targets/",
            sim,
            bootstrap=bootstrap,
        )

    def _setup_repo(
        self, initial_consistent: bool
    ) -> DualNamingRepositorySimulator:
        """Create a repository using 'initial_consistent' naming, with a
        delegated role and a target that only the delegated role serves."""
        sim = DualNamingRepositorySimulator()
        sim.active_consistent_snapshot = initial_consistent
        sim.root.consistent_snapshot = initial_consistent
        sim.root.version += 1
        sim.publish_root()  # root v2

        delegated_role = DelegatedRole("role1", [], 1, False, ["*"], None)
        spec_version = ".".join(SPECIFICATION_VERSION)
        targets = Targets(1, spec_version, sim.safe_expiry, {}, None)
        sim.add_delegation("targets", delegated_role, targets)
        sim.add_target("role1", self.old_content, self.target_path)
        sim.update_snapshot()
        return sim

    def _switch_consistent_snapshot(
        self, sim: DualNamingRepositorySimulator, final_consistent: bool
    ) -> None:
        """Flip consistent_snapshot on the repository.

        The mirror keeps serving the pre-switch metadata and target
        content (stale but well-formed) on the old naming scheme, while
        the new naming scheme serves the new versions and content.
        """
        # capture stale, still correctly signed, metadata and target bytes
        for role in ["snapshot", "targets", "role1"]:
            sim.stale_metadata[role] = sim.fetch_metadata(role)
        if final_consistent:
            # old naming: unversioned metadata, un-prefixed target names
            sim.stale_targets[self.target_path] = self.old_content
        else:
            # old naming: versioned metadata, hash-prefixed target names
            name = f"{self.final_hash}.{self.target_path}"
            sim.stale_targets[name] = self.old_content

        # switch trust state with a chain of consecutively signed roots
        sim.root.consistent_snapshot = final_consistent
        sim.root.version += 1
        sim.publish_root()  # root v3
        sim.root.version += 1
        sim.publish_root()  # root v4

        # publish new metadata versions with the new target content
        sim.targets.version += 1
        sim.md_delegates["role1"].signed.version += 1
        sim.add_target("role1", self.final_content, self.target_path)
        sim.update_snapshot()

        sim.active_consistent_snapshot = final_consistent
        sim.fetch_tracker.metadata.clear()
        sim.fetch_tracker.targets.clear()
        sim.requested_paths.clear()

    switch_data = {
        "disabled to enabled": {"initial": False, "final": True},
        "enabled to disabled": {"initial": True, "final": False},
    }

    @utils.run_sub_tests_with_dataset(switch_data)
    def test_switch_consistent_snapshot(
        self, test_case_data: dict[str, bool]
    ) -> None:
        # Client must apply the final trusted root's naming rule after a
        # switch, for metadata requests, target requests and lazily
        # loaded delegations alike.
        initial: bool = test_case_data["initial"]
        final: bool = test_case_data["final"]
        self._init_dirs(self.case_name)
        sim = self._setup_repo(initial)

        # first client: populate local caches under the old naming rule
        updater = self._init_updater(sim, bootstrap=sim.signed_roots[-1])
        updater.refresh()
        self.assertIsNotNone(updater.get_targetinfo(self.target_path))
        # old snapshot, targets and delegation caches are kept on disk
        for role in ["snapshot", "targets", "role1"]:
            self.assertIn(f"{role}.json", os.listdir(self.metadata_dir))

        self._switch_consistent_snapshot(sim, final)

        # second client on the same cache dir: must follow the final root
        updater = self._init_updater(sim)
        updater.refresh()
        info = updater.get_targetinfo(self.target_path)
        assert isinstance(info, TargetFile)
        path = updater.download_target(info)

        # final authenticated content comes from the final trust state
        with open(path, "rb") as f:
            self.assertEqual(f.read(), self.final_content)
        self.assertEqual(updater._trusted_set.root.version, 4)
        self.assertEqual(updater._trusted_set.snapshot.version, 3)

        # every request used the final root's naming rule
        md_version: int | None = 3 if final else None
        targets_version: int | None = 2 if final else None
        self.assertListEqual(
            sim.fetch_tracker.metadata,
            [
                ("root", 3),
                ("root", 4),
                ("root", 5),  # benign end-of-chain probe
                ("timestamp", None),
                ("snapshot", md_version),
                ("targets", targets_version),
                ("role1", targets_version),
            ],
        )
        target_prefix = self.final_hash if final else None
        self.assertListEqual(
            sim.fetch_tracker.targets, [(self.target_path, target_prefix)]
        )

        # the exact filenames requested on the success path
        target_name = (
            f"{self.final_hash}.{self.target_path}"
            if final
            else self.target_path
        )
        snapshot_name = "3.snapshot" if final else "snapshot"
        targets_name = "2.targets" if final else "targets"
        role1_name = "2.role1" if final else "role1"
        self.assertListEqual(
            sim.requested_paths,
            [
                "/metadata/3.root.json",
                "/metadata/4.root.json",
                "/metadata/5.root.json",
                "/metadata/timestamp.json",
                f"/metadata/{snapshot_name}.json",
                f"/metadata/{targets_name}.json",
                f"/metadata/{role1_name}.json",
                f"/targets/{target_name}",
            ],
        )

        # metadata is still persisted locally without a version prefix
        local_files = os.listdir(self.metadata_dir)
        for role in [*TOP_LEVEL_ROLE_NAMES, "role1"]:
            self.assertIn(f"{role}.json", local_files)
            self.assertNotIn(f"2.{role}.json", local_files)

    @utils.run_sub_tests_with_dataset(switch_data)
    def test_switch_with_stale_naming_mutation(
        self, test_case_data: dict[str, bool]
    ) -> None:
        # Prove the switch tests detect naming-rule mixing: temporarily
        # mutate the client to keep the old root's naming rule and verify
        # the mix is caught. The mirror answers the stale requests with
        # well-formed data, so detection cannot rely on a 404.
        initial: bool = test_case_data["initial"]
        final: bool = test_case_data["final"]
        self._init_dirs(self.case_name)
        sim = self._setup_repo(initial)

        updater = self._init_updater(sim, bootstrap=sim.signed_roots[-1])
        updater.refresh()
        self.assertIsNotNone(updater.get_targetinfo(self.target_path))

        self._switch_consistent_snapshot(sim, final)

        updater = self._init_updater(sim)
        with (
            _stale_naming_mutation(initial),
            self.assertRaises(exceptions.RepositoryError) as ctx,
        ):
            updater.refresh()

        # the failure comes from verifying well-formed stale data (a
        # version mismatch), not from a download error such as a 404
        self.assertIsInstance(ctx.exception, exceptions.BadVersionNumberError)
        self.assertNotIsInstance(ctx.exception, exceptions.DownloadError)

        # the client revealed the stale naming rule in its requests
        stale_snapshot = "snapshot" if final else "3.snapshot"
        self.assertIn(f"/metadata/{stale_snapshot}.json", sim.requested_paths)
        self.assertIn(
            ("snapshot", None if final else 3), sim.fetch_tracker.metadata
        )


if __name__ == "__main__":
    if "--dump" in sys.argv:
        TestConsistentSnapshot.dump_dir = tempfile.mkdtemp()
        print(
            f"Repository Simulator dumps in {TestConsistentSnapshot.dump_dir}"
        )
        sys.argv.remove("--dump")

    utils.configure_test_logging(sys.argv)
    unittest.main()
