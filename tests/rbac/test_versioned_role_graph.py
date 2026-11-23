# Copyright 2021 The casbin Authors. All Rights Reserved.
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

import threading
from concurrent.futures import ThreadPoolExecutor
from unittest import TestCase

from casbin.rbac import (
    AdapterRoleGraphStore,
    ChangeStatus,
    DistributionError,
    DistributionState,
    InMemoryRoleGraphDispatcher,
    InMemoryRoleGraphStore,
    PersistError,
    RoleChange,
    RoleGraphCoordinator,
    VersionedRoleGraph,
)
from casbin.rbac.default_role_manager import RoleManager


class TestVersionedRoleGraph(TestCase):
    def make_coordinator(self, workers=("w1", "w2")):
        store = InMemoryRoleGraphStore()
        dispatcher = InMemoryRoleGraphDispatcher(list(workers))
        return RoleGraphCoordinator(store, dispatcher), store, dispatcher

    def test_publish_is_versioned_and_local_check_matches_role_manager(self):
        coord, _, _ = self.make_coordinator()
        self.assertEqual(coord.graph.current_version(), 0)

        coord.submit(RoleChange.add("alice", "engineering"))
        coord.submit(RoleChange.add("engineering", "admin"))

        self.assertEqual(coord.graph.current_version(), 2)
        # direct edge and transitive hierarchy both resolve locally
        self.assertTrue(coord.graph.has_link("alice", "engineering"))
        self.assertTrue(coord.graph.has_link("alice", "admin"))
        self.assertEqual(coord.graph.get_roles("alice"), ["engineering"])

        reference = RoleManager(10)
        reference.add_link("alice", "engineering")
        reference.add_link("engineering", "admin")
        self.assertEqual(
            coord.graph.has_link("alice", "admin"), reference.has_link("alice", "admin")
        )

        coord.submit(RoleChange.remove("alice", "engineering"))
        self.assertFalse(coord.graph.has_link("alice", "engineering"))
        self.assertFalse(coord.graph.has_link("alice", "admin"))

    def test_persist_failure_aborts_before_local_graph_moves(self):
        coord, store, dispatcher = self.make_coordinator()
        coord.submit(RoleChange.add("alice", "engineering"))
        version_before = coord.graph.current_version()

        store.fail_next = True
        change = RoleChange.add("bob", "finance")
        receipt = coord.submit(change)

        self.assertEqual(receipt.status, ChangeStatus.PERSIST_FAILED)
        self.assertEqual(receipt.distribution_state, DistributionState.NOT_PERSISTED)
        self.assertIsNone(receipt.adopted_version)
        self.assertTrue(receipt.error)
        self.assertFalse(receipt.retryable)
        # nothing moved locally and nothing was distributed
        self.assertEqual(coord.graph.current_version(), version_before)
        self.assertFalse(coord.graph.has_link("bob", "finance"))
        delivered_ids = [change_id for _, change_id in dispatcher.delivered]
        self.assertNotIn(change.change_id, delivered_ids)
        # the failed change is not listed among pending (effective) changes
        self.assertNotIn(change.change_id, coord.graph.pending_changes())

    def test_distribution_failure_leaves_graph_effective_and_flags_pending(self):
        coord, _, dispatcher = self.make_coordinator()
        dispatcher.fail_once("w2")

        change = RoleChange.add("alice", "engineering")
        receipt = coord.submit(change)

        # persistence and the local publish already happened
        self.assertEqual(receipt.status, ChangeStatus.PENDING_DISTRIBUTION)
        self.assertEqual(receipt.distribution_state, DistributionState.PENDING)
        self.assertEqual(receipt.adopted_version, 1)
        self.assertEqual(receipt.readable_version, 1)
        self.assertEqual(receipt.pending_workers, ["w2"])
        self.assertTrue(receipt.retryable)
        self.assertTrue(coord.graph.has_link("alice", "engineering"))
        # the healthy worker already got it; only the failing one is outstanding
        self.assertIn(("w1", change.change_id), dispatcher.delivered)
        self.assertEqual(coord.pending()[0].change_id, change.change_id)

    def test_retry_distribution_completes_the_change(self):
        coord, _, dispatcher = self.make_coordinator()
        dispatcher.fail_once("w1")
        dispatcher.fail_once("w2")

        change = RoleChange.add("alice", "engineering")
        first = coord.submit(change)
        self.assertEqual(first.status, ChangeStatus.PENDING_DISTRIBUTION)
        self.assertEqual(set(first.pending_workers), {"w1", "w2"})

        # retry only targets workers that have not acknowledged yet
        retried = coord.retry_distribution(change.change_id)
        self.assertEqual(retried.status, ChangeStatus.CONFIRMED)
        self.assertEqual(retried.pending_workers, [])
        self.assertTrue(retried.fully_distributed)
        self.assertEqual(coord.pending(), [])
        # each worker eventually holds exactly one copy of the change
        for worker in ("w1", "w2"):
            self.assertEqual(
                [cid for wid, cid in dispatcher.delivered if wid == worker],
                [change.change_id],
            )

    def test_retry_requires_an_effective_persisted_change(self):
        coord, store, _ = self.make_coordinator()
        store.fail_next = True
        receipt = coord.submit(RoleChange.add("nobody", "ghost"))
        with self.assertRaises(ValueError):
            coord.retry_distribution(receipt.change_id)

    def test_receipt_identifies_adopted_version_and_pending_change(self):
        coord, _, dispatcher = self.make_coordinator()
        dispatcher.fail_once("w2")

        first = coord.submit(RoleChange.add("alice", "engineering"))
        second = coord.submit(RoleChange.add("bob", "finance"))

        self.assertEqual(first.adopted_version, 1)
        self.assertEqual(second.adopted_version, 2)
        self.assertEqual(second.status, ChangeStatus.CONFIRMED)

        pending = coord.pending()
        self.assertEqual(len(pending), 1)
        outstanding = pending[0]
        self.assertEqual(outstanding.change_id, first.change_id)
        self.assertEqual(outstanding.adopted_version, 1)
        self.assertEqual(outstanding.pending_workers, ["w2"])
        # the receipt fetched by id agrees with the pending listing
        self.assertEqual(
            coord.receipt(first.change_id).status, ChangeStatus.PENDING_DISTRIBUTION
        )

    def test_batch_publishes_one_atomic_version(self):
        coord, _, _ = self.make_coordinator()
        changes = [
            RoleChange.add("u", "v"),
            RoleChange.add("v", "w"),
        ]
        receipts = coord.submit_batch(changes)
        self.assertEqual(len(receipts), 2)
        self.assertEqual({r.adopted_version for r in receipts}, {1})
        self.assertEqual(coord.graph.current_version(), 1)
        self.assertTrue(coord.graph.has_link("u", "v"))
        self.assertTrue(coord.graph.has_link("v", "w"))

    def test_batch_rolls_back_when_persistence_fails(self):
        coord, store, _ = self.make_coordinator()
        store.fail_next = True  # fails on the second change
        changes = [
            RoleChange.add("u", "v"),
            RoleChange.add("v", "w"),
        ]
        receipts = coord.submit_batch(changes)
        self.assertTrue(all(r.status is ChangeStatus.PERSIST_FAILED for r in receipts))
        self.assertEqual(coord.graph.current_version(), 0)
        self.assertFalse(coord.graph.has_link("u", "v"))
        self.assertFalse(coord.graph.has_link("v", "w"))
        # the first commit was rolled back in the store as well
        self.assertEqual(store.committed, [])

    def test_readers_always_see_a_complete_graph_under_concurrency(self):
        graph = VersionedRoleGraph()
        # a two-edge chain that must appear or disappear together
        add = [RoleChange.add("u", "v"), RoleChange.add("v", "w")]
        remove = [RoleChange.remove("u", "v"), RoleChange.remove("v", "w")]

        stop = threading.Event()
        violations = []

        def reader():
            while not stop.is_set():
                snap = graph.current_snapshot()
                # the snapshot is immutable: repeated reads inside it are stable
                has_uv = snap.role_manager.has_link("u", "v")
                has_vw = snap.role_manager.has_link("v", "w")
                if has_uv != has_vw:
                    violations.append(snap.version)

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(reader), pool.submit(reader)]
            for _ in range(300):
                graph.apply(add)
                self.assertTrue(graph.has_link("u", "v"))
                self.assertTrue(graph.has_link("v", "w"))
                graph.apply(remove)
                self.assertFalse(graph.has_link("u", "v"))
                self.assertFalse(graph.has_link("v", "w"))
            stop.set()
            for future in futures:
                future.result()

        self.assertEqual(violations, [])

    def test_snapshots_are_immutable_after_publication(self):
        graph = VersionedRoleGraph()
        graph.apply([RoleChange.add("alice", "engineering")])
        first = graph.current_snapshot()
        graph.apply([RoleChange.add("bob", "finance")])
        # holding an old snapshot keeps observing the old complete graph
        self.assertTrue(first.role_manager.has_link("alice", "engineering"))
        self.assertFalse(first.role_manager.has_link("bob", "finance"))
        self.assertEqual(first.version, 1)
        self.assertEqual(graph.current_version(), 2)

    def test_adapter_store_commits_through_casbin_adapter(self):
        adapter = RecordingAdapter()
        store = AdapterRoleGraphStore(adapter)
        coord = RoleGraphCoordinator(store, InMemoryRoleGraphDispatcher(["w1"]))

        receipt = coord.submit(RoleChange.add("alice", "engineering"))
        self.assertEqual(receipt.status, ChangeStatus.CONFIRMED)
        # the grouping rule reached the adapter through the g section
        self.assertEqual(adapter.added, [("g", "g", ["alice", "engineering"])])

        coord.submit(RoleChange.remove("alice", "engineering"))
        self.assertEqual(adapter.removed, [("g", "g", ["alice", "engineering"])])

        # a domain edge is persisted with its domain as the third field
        coord.submit(RoleChange.add("bob", "finance", domain="tenant-1"))
        self.assertEqual(
            adapter.added[-1], ("g", "g", ["bob", "finance", "tenant-1"])
        )

    def test_adapter_persist_failure_is_reported_as_persist_failed(self):
        adapter = FailingAdapter()
        coord = RoleGraphCoordinator(
            AdapterRoleGraphStore(adapter), InMemoryRoleGraphDispatcher(["w1"])
        )
        receipt = coord.submit(RoleChange.add("alice", "engineering"))
        self.assertEqual(receipt.status, ChangeStatus.PERSIST_FAILED)
        self.assertIsInstance(receipt.error, str)
        self.assertFalse(coord.graph.has_link("alice", "engineering"))

    def test_dispatcher_error_surfaces_unacked_workers(self):
        dispatcher = InMemoryRoleGraphDispatcher(["w1"])
        dispatcher.fail_once("w1")
        with self.assertRaises(DistributionError) as ctx:
            dispatcher.dispatch(RoleChange.add("a", "b"), ["w1"])
        self.assertEqual(ctx.exception.unacked, ["w1"])


class RecordingAdapter:
    """Minimal adapter capturing the incremental calls the store must make."""

    def __init__(self):
        self.added = []
        self.removed = []

    def add_policy(self, sec, ptype, rule):
        self.added.append((sec, ptype, list(rule)))

    def remove_policy(self, sec, ptype, rule):
        self.removed.append((sec, ptype, list(rule)))


class FailingAdapter:
    def add_policy(self, sec, ptype, rule):
        raise PersistError("storage unavailable")

    def remove_policy(self, sec, ptype, rule):
        raise PersistError("storage unavailable")
