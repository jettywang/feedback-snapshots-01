# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

import threading
import time
import unittest

from opentelemetry.sdk.memory import (
    BatchingMemoryExporter,
    EntryState,
    Receipt,
)


class ReceiptCollector:
    """Thread-safe user supplied receiver that keeps every per-entry receipt."""

    def __init__(self):
        self._lock = threading.Lock()
        self.receipts: list[Receipt] = []

    def __call__(self, receipt: Receipt) -> None:
        with self._lock:
            self.receipts.append(receipt)

    def states_for(self, entry_id):
        with self._lock:
            return [r.state for r in self.receipts if r.entry_id == entry_id]

    def by_state(self, state):
        with self._lock:
            return [r for r in self.receipts if r.state is state]


class BlockingSink:
    """Sink whose exports block until ``release`` is set."""

    def __init__(self, result=True):
        self.started = threading.Event()
        self.release = threading.Event()
        self.batches: list[list] = []
        self._result = result
        self._lock = threading.Lock()

    def __call__(self, batch):
        with self._lock:
            self.batches.append(list(batch))
        self.started.set()
        self.release.wait(10)
        return self._result


class TestBatchingMemoryExporter(unittest.TestCase):
    def test_enqueue_and_export_success_are_recorded_separately(self):
        collector = ReceiptCollector()
        exporter = BatchingMemoryExporter(
            collector, schedule_delay_millis=0, max_queue_size=10, max_export_batch_size=2
        )
        for value in range(5):
            self.assertTrue(exporter.submit(value))

        self.assertTrue(exporter.force_flush(5000))
        exporter.shutdown(5000)

        # Every entry produced an independent RECEIVED then CONFIRMED receipt.
        for entry_id in range(5):
            self.assertEqual(
                collector.states_for(entry_id),
                [EntryState.RECEIVED, EntryState.CONFIRMED],
            )

        evidence = exporter.get_evidence()
        self.assertEqual(len(evidence), 5)
        self.assertTrue(all(record.state is EntryState.CONFIRMED for record in evidence))
        self.assertEqual(exporter.get_exported_entries(), (0, 1, 2, 3, 4))

        # Batch evidence links entries to the export they actually went out in.
        batches = exporter.get_batch_evidence()
        self.assertEqual(len(batches), 3)
        self.assertTrue(all(batch.success for batch in batches))
        exported_ids = [entry_id for batch in batches for entry_id in batch.entry_ids]
        self.assertEqual(exported_ids, [0, 1, 2, 3, 4])

    def test_entry_links_to_the_batch_that_exported_it(self):
        collector = ReceiptCollector()
        exporter = BatchingMemoryExporter(
            collector, schedule_delay_millis=0, max_queue_size=10, max_export_batch_size=2
        )
        for value in range(4):
            exporter.submit(value)
        exporter.force_flush(5000)
        exporter.shutdown(5000)

        journal = {record.entry_id: record for record in exporter.get_evidence()}
        batch_members = {batch.batch_id: batch.entry_ids for batch in exporter.get_batch_evidence()}
        for record in journal.values():
            self.assertIn(record.entry_id, batch_members[record.batch_id])

    def test_sink_exception_marks_entries_failed_but_keeps_evidence(self):
        collector = ReceiptCollector()
        attempts = {"count": 0}

        def flaky_sink(batch):
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise RuntimeError("intermittent error")
            return True

        exporter = BatchingMemoryExporter(
            collector,
            schedule_delay_millis=0,
            max_queue_size=10,
            max_export_batch_size=2,
            sink=flaky_sink,
        )
        exporter.submit("a")
        exporter.submit("b")
        exporter.submit("c")
        exporter.force_flush(5000)
        exporter.shutdown(5000)

        journal = {record.entry_id: record for record in exporter.get_evidence()}
        self.assertIs(journal[0].state, EntryState.FAILED)
        self.assertIs(journal[1].state, EntryState.FAILED)
        self.assertIn("intermittent error", journal[0].error)
        self.assertIs(journal[2].state, EntryState.CONFIRMED)

        batches = exporter.get_batch_evidence()
        self.assertFalse(batches[0].success)
        self.assertTrue(batches[1].success)
        self.assertEqual(batches[0].entry_ids, (0, 1))

        failed_receipts = collector.by_state(EntryState.FAILED)
        self.assertEqual({r.entry_id for r in failed_receipts}, {0, 1})
        self.assertTrue(all("intermittent error" in r.error for r in failed_receipts))

    def test_sink_returning_false_marks_entries_failed(self):
        collector = ReceiptCollector()
        exporter = BatchingMemoryExporter(collector, schedule_delay_millis=0, sink=lambda batch: False)
        exporter.submit(object())
        exporter.force_flush(5000)
        exporter.shutdown(5000)

        record = exporter.get_evidence()[0]
        self.assertIs(record.state, EntryState.FAILED)
        self.assertFalse(exporter.get_batch_evidence()[0].success)

    def test_submit_blocks_while_at_capacity(self):
        collector = ReceiptCollector()
        sink = BlockingSink()
        exporter = BatchingMemoryExporter(
            collector,
            max_queue_size=2,
            max_export_batch_size=1,
            schedule_delay_millis=100_000,
            sink=sink,
        )
        try:
            exporter.submit(0)
            self.assertTrue(sink.started.wait(5))
            exporter.submit(1)  # one in-flight + one queued == capacity

            result = {}
            thread = threading.Thread(target=lambda: result.setdefault("ok", exporter.submit(2, timeout=5)))
            thread.start()
            time.sleep(0.3)
            self.assertTrue(thread.is_alive(), "submit must suspend while the exporter is full")

            sink.release.set()
            thread.join(10)
            self.assertEqual(result, {"ok": True})
            exporter.force_flush(5000)
        finally:
            sink.release.set()
            exporter.shutdown(5000)

    def test_full_queue_rejects_batch_after_timeout_with_evicted_receipt(self):
        collector = ReceiptCollector()
        sink = BlockingSink()
        exporter = BatchingMemoryExporter(
            collector,
            max_queue_size=2,
            max_export_batch_size=1,
            schedule_delay_millis=100_000,
            sink=sink,
        )
        try:
            exporter.submit(0)
            self.assertTrue(sink.started.wait(5))
            exporter.submit(1)  # exporter is now at capacity

            self.assertFalse(exporter.submit("rejected", timeout=0))

            evicted = collector.by_state(EntryState.EVICTED)
            self.assertEqual(len(evicted), 1)
            self.assertEqual(evicted[0].entry, "rejected")
            self.assertIsNotNone(evicted[0].error)

            journal = exporter.get_evidence()
            self.assertEqual(journal[-1].state, EntryState.EVICTED)
            # Held entries never exceed the configured capacity.
            self.assertLessEqual(len(exporter._queue) + exporter._in_flight, 2)
        finally:
            sink.release.set()
            exporter.shutdown(5000)

    def test_submit_after_shutdown_is_rejected(self):
        collector = ReceiptCollector()
        exporter = BatchingMemoryExporter(collector, schedule_delay_millis=0)
        exporter.shutdown(5000)

        self.assertFalse(exporter.submit("late"))
        receipt = collector.receipts[-1]
        self.assertIs(receipt.state, EntryState.EVICTED)
        self.assertIn("shut down", receipt.error)
        self.assertFalse(exporter.force_flush(5000))

    def test_shutdown_marks_undrained_entries_failed(self):
        collector = ReceiptCollector()
        sink = BlockingSink()
        exporter = BatchingMemoryExporter(
            collector,
            max_queue_size=4,
            max_export_batch_size=1,
            schedule_delay_millis=100_000,
            sink=sink,
        )
        exporter.submit(0)
        self.assertTrue(sink.started.wait(5))
        for value in (1, 2, 3):
            exporter.submit(value)

        # Shutdown while the sink is stuck: the join times out and queued entries fail closed.
        exporter.shutdown(timeout_millis=100)
        sink.release.set()
        time.sleep(0.2)

        states = {record.entry_id: record.state for record in exporter.get_evidence()}
        self.assertIs(states[0], EntryState.CONFIRMED)
        for entry_id in (1, 2, 3):
            self.assertIs(states[entry_id], EntryState.FAILED)

        # The last receipt delivered for every entry is a terminal state.
        last_receipt: dict[int, Receipt] = {}
        for receipt in collector.receipts:
            last_receipt[receipt.entry_id] = receipt
        self.assertTrue(
            all(
                receipt.state in (EntryState.CONFIRMED, EntryState.FAILED, EntryState.EVICTED)
                for receipt in last_receipt.values()
            )
        )

    def test_receiver_exception_does_not_break_export(self):
        def failing_receiver(receipt):
            if receipt.state is EntryState.CONFIRMED:
                raise RuntimeError("receiver broken")

        exporter = BatchingMemoryExporter(failing_receiver, schedule_delay_millis=0)
        exporter.submit("x")
        exporter.force_flush(5000)
        exporter.shutdown(5000)
        self.assertEqual(exporter.get_evidence()[0].state, EntryState.CONFIRMED)

    def test_journal_cap_discards_oldest_evidence(self):
        collector = ReceiptCollector()
        exporter = BatchingMemoryExporter(collector, schedule_delay_millis=0, max_journal_entries=3)
        for value in range(6):
            exporter.submit(value)
        exporter.force_flush(5000)
        exporter.shutdown(5000)

        evidence = exporter.get_evidence()
        self.assertEqual(len(evidence), 3)
        self.assertEqual([record.entry_id for record in evidence], [3, 4, 5])

    def test_invalid_constructor_arguments(self):
        collector = ReceiptCollector()
        with self.assertRaises(ValueError):
            BatchingMemoryExporter(collector, max_queue_size=0)
        with self.assertRaises(ValueError):
            BatchingMemoryExporter(collector, max_export_batch_size=0)
        with self.assertRaises(ValueError):
            BatchingMemoryExporter(collector, max_queue_size=2, max_export_batch_size=3)
        with self.assertRaises(ValueError):
            BatchingMemoryExporter(collector, schedule_delay_millis=-1)
        with self.assertRaises(ValueError):
            BatchingMemoryExporter(collector, max_journal_entries=0)

    def test_force_flush_returns_false_on_timeout(self):
        sink = BlockingSink()
        exporter = BatchingMemoryExporter(
            ReceiptCollector(),
            max_queue_size=2,
            max_export_batch_size=1,
            schedule_delay_millis=100_000,
            sink=sink,
        )
        try:
            exporter.submit(0)
            self.assertTrue(sink.started.wait(5))
            self.assertFalse(exporter.force_flush(timeout_millis=50))
        finally:
            sink.release.set()
            exporter.shutdown(5000)


if __name__ == "__main__":
    unittest.main()
