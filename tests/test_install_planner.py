# Copyright 2026, python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

from __future__ import annotations

import tempfile
import unittest
from typing import TYPE_CHECKING

from install_planner.demo_repo import (
    APP_PATH,
    CORE_PATH,
    OPTIONAL_PATH,
    PLUGIN_PATH,
    UTIL_PATH,
    add_conflicting_pins,
    add_cycle,
    break_role_signature,
    build_demo_repository,
    remove_optional_target,
    remove_required_target,
    tamper_required_digest,
)
from install_planner.exceptions import (
    DependencyCycleError,
    DependencyDeclarationError,
    DependencyHashMismatchError,
    RepositoryAdmissionError,
    RequiredDependencyMissingError,
    SamePathConflictError,
)
from install_planner.planner import DependencyPlanner, create_planner

if TYPE_CHECKING:
    from tests.repository_simulator import RepositorySimulator

METADATA_URL = "https://example.com/metadata/"
TARGETS_URL = "https://example.com/targets/"


class TestDependencyPlanner(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _planner(self, sim: RepositorySimulator) -> DependencyPlanner:
        return create_planner(
            self.temp_dir.name,
            METADATA_URL,
            TARGETS_URL,
            bootstrap=sim.signed_roots[0],
            fetcher=sim,
        )

    def test_full_closure_admitted_in_stable_order(self) -> None:
        sim = build_demo_repository()
        plan = self._planner(sim).plan(APP_PATH)

        # Every node of the closure is present exactly once.
        self.assertEqual(
            plan.install_order,
            [
                CORE_PATH,
                OPTIONAL_PATH,
                UTIL_PATH,
                PLUGIN_PATH,
                APP_PATH,
            ],
        )
        # Dependencies always precede their dependents.
        position = {path: i for i, path in enumerate(plan.install_order)}
        self.assertLess(position[CORE_PATH], position[UTIL_PATH])
        self.assertLess(position[CORE_PATH], position[PLUGIN_PATH])
        self.assertLess(position[UTIL_PATH], position[PLUGIN_PATH])
        self.assertLess(position[PLUGIN_PATH], position[APP_PATH])

        # Each node records the role that actually answered the TUF lookup.
        authorizations = {
            path: plan.packages[path].authorization
            for path in plan.install_order
        }
        self.assertEqual(authorizations[APP_PATH].role, "targets")
        self.assertEqual(authorizations[APP_PATH].parent_role, "root")
        self.assertEqual(authorizations[CORE_PATH].role, "basic-libs")
        self.assertEqual(authorizations[CORE_PATH].parent_role, "targets")
        self.assertEqual(authorizations[PLUGIN_PATH].role, "app-team")
        self.assertEqual(authorizations[OPTIONAL_PATH].role, "extras-team")

        # The shared dependency is admitted once despite two requirements.
        core = plan.packages[CORE_PATH]
        self.assertEqual(core.sha256, core.authorization.targetfile.hashes["sha256"])

    def test_terminating_delegation_is_authoritative(self) -> None:
        # basic-libs terminates packages/lib/*: its answer must be used even
        # though a later top-level delegation could claim the same prefix.
        sim = build_demo_repository()
        plan = self._planner(sim).plan(APP_PATH)
        self.assertEqual(
            plan.packages[CORE_PATH].authorization.role, "basic-libs"
        )
        self.assertEqual(
            plan.packages[UTIL_PATH].authorization.role, "basic-libs"
        )

    def test_single_snapshot_and_no_target_downloads(self) -> None:
        sim = build_demo_repository()
        planner = self._planner(sim)
        plan = planner.plan(APP_PATH)

        # consistent_snapshot is enabled and every lookup shares the snapshot.
        self.assertTrue(plan.consistent_snapshot)
        fetched_versions = {
            role
            for role, version in sim.fetch_tracker.metadata
            if version is not None
        }
        self.assertTrue(fetched_versions)
        self.assertEqual(
            sim.snapshot.version,
            plan.snapshot_version,
        )
        # Metadata only: the planner must never pull target content.
        self.assertEqual(sim.fetch_tracker.targets, [])

    def test_missing_required_dependency_fails(self) -> None:
        sim = build_demo_repository()
        remove_required_target(sim, CORE_PATH)
        with self.assertRaises(RequiredDependencyMissingError) as ctx:
            self._planner(sim).plan(APP_PATH)
        self.assertEqual(ctx.exception.path, CORE_PATH)

    def test_optional_missing_is_skipped_but_signature_damage_fails(self) -> None:
        sim = build_demo_repository()
        remove_optional_target(sim)
        plan = self._planner(sim).plan(APP_PATH)

        skipped = plan.packages[OPTIONAL_PATH]
        self.assertTrue(skipped.optional)
        self.assertIsNone(skipped.authorization)
        self.assertEqual(
            skipped.to_dict()["status"], "skipped-optional-not-published"
        )
        self.assertNotIn(OPTIONAL_PATH, plan.install_order)

        # A broken signature on the same role must not read as "not published".
        sim = build_demo_repository()
        break_role_signature(sim, "extras-team")
        with self.assertRaises(RepositoryAdmissionError) as ctx:
            self._planner(sim).plan(APP_PATH)
        # The optional path is still attempted and its role's bad signature is
        # surfaced, rather than silently treated as an absent optional target.
        self.assertIn(OPTIONAL_PATH, str(ctx.exception))

    def test_digest_mismatch_fails_whole_plan(self) -> None:
        sim = build_demo_repository()
        bogus = tamper_required_digest(sim, PLUGIN_PATH)
        planner = self._planner(sim)
        with self.assertRaises(DependencyHashMismatchError) as ctx:
            planner.plan(APP_PATH)
        self.assertEqual(ctx.exception.path, PLUGIN_PATH)
        self.assertEqual(ctx.exception.expected, bogus)

        # A failure must not leave behind a usable plan: a fresh retry on a
        # healthy repository still succeeds, and no plan object was returned.
        healthy_plan = self._planner(build_demo_repository()).plan(APP_PATH)
        self.assertEqual(len(healthy_plan.install_order), 5)

    def test_cycle_detection(self) -> None:
        sim = build_demo_repository()
        add_cycle(sim)
        with self.assertRaises(DependencyCycleError) as ctx:
            self._planner(sim).plan(APP_PATH)
        self.assertIn(CORE_PATH, ctx.exception.cycle)
        self.assertIn(UTIL_PATH, ctx.exception.cycle)

    def test_same_path_conflicting_pins_fails(self) -> None:
        sim = build_demo_repository()
        add_conflicting_pins(sim)
        with self.assertRaises(SamePathConflictError) as ctx:
            self._planner(sim).plan(APP_PATH)
        self.assertEqual(ctx.exception.path, CORE_PATH)

    def test_root_path_declaration_is_not_publication_right(self) -> None:
        # Even the root package must pass a real target lookup: unpublishing it
        # means no plan, regardless of what its custom section says.
        sim = build_demo_repository()
        remove_required_target(sim, APP_PATH)
        with self.assertRaises(RequiredDependencyMissingError):
            self._planner(sim).plan(APP_PATH)

    def test_plan_is_deterministic_across_runs(self) -> None:
        orders = []
        for _ in range(3):
            sim = build_demo_repository()
            orders.append(self._planner(sim).plan(APP_PATH).install_order)
        self.assertEqual(orders[0], orders[1])
        self.assertEqual(orders[1], orders[2])

    def test_malformed_dependency_declaration_fails(self) -> None:
        sim = build_demo_repository()
        root_target = sim.targets.targets[APP_PATH]
        root_target.unrecognized_fields["custom"] = {
            "dependencies": [{"path": CORE_PATH}]  # missing sha256
        }
        sim.targets.version += 1
        sim.update_snapshot()
        with self.assertRaises(DependencyDeclarationError):
            self._planner(sim).plan(APP_PATH)

    def test_all_lookups_share_one_updater_snapshot(self) -> None:
        sim = build_demo_repository()
        planner = self._planner(sim)
        plan = planner.plan(APP_PATH)

        # One Updater, one refresh: every authorization comes from the same
        # snapshot, so all targets metadata versions are the snapshot-pinned v2.
        self.assertIsNotNone(planner._updater._trusted_set.snapshot)
        self.assertEqual(
            {
                package.authorization.targetfile_version
                for package in plan.packages.values()
                if package.authorization is not None
            },
            {2},
        )
        # Only metadata endpoints were contacted, never target content.
        self.assertEqual(sim.fetch_tracker.targets, [])


if __name__ == "__main__":
    unittest.main()
