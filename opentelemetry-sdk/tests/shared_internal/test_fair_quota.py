# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=protected-access

import pytest

from opentelemetry.sdk._shared_internal._fair_quota import (
    DEFAULT_SOURCE_KEY,
    DropReason,
    DropRecord,
    FairQuotaGate,
    QueuedTelemetry,
)


def _source(item):
    return item[0]


class TestFairQuotaGate:
    def test_source_within_quota_is_admitted_without_drops(self):
        gate = FairQuotaGate(max_queue_size=10, fair_quotas={"a": 4, "b": 4}, source_key_extractor=_source)

        for index in range(4):
            decision = gate.admit(("a", index))
            assert isinstance(decision, QueuedTelemetry)
            assert decision.source == "a"
            assert decision.sequence == index

        assert gate.occupancy() == {"a": 4}
        assert gate.dropped_summary() == {}
        assert gate.drop_records() == ()

    def test_idle_quota_is_shareable_with_other_sources(self):
        gate = FairQuotaGate(max_queue_size=10, fair_quotas={"a": 4, "b": 4}, source_key_extractor=_source)

        # "a" borrows the unallocated headroom (2) and the idle reservation of "b" (4).
        admitted = [gate.admit(("a", index)) for index in range(8)]
        assert all(isinstance(decision, QueuedTelemetry) for decision in admitted)
        assert gate.occupancy() == {"a": 8}
        assert gate.dropped_summary() == {}

    def test_hard_queue_cap_is_always_enforced(self):
        gate = FairQuotaGate(max_queue_size=10, fair_quotas={}, source_key_extractor=_source)

        # With no reservations configured, the only limit is the hard queue cap.
        for index in range(10):
            assert isinstance(gate.admit(("a", index)), QueuedTelemetry)

        decision = gate.admit(("a", 10))
        assert decision is DropReason.QUEUE_FULL
        assert gate.dropped_summary() == {"a": {"queue_full": 1}}

    def test_borrowing_never_takes_reserved_slots_while_owner_is_idle(self):
        gate = FairQuotaGate(max_queue_size=10, fair_quotas={"a": 4, "b": 4}, source_key_extractor=_source)

        # "a" reaches its quota (4), the headroom (2) and the idle reservation
        # of "b" (4), but one slot of "b" always stays reclaimable.
        for index in range(9):
            assert isinstance(gate.admit(("a", index)), QueuedTelemetry)
        assert gate.admit(("a", 9)) is DropReason.FAIR_QUOTA_EXCEEDED
        assert gate.occupancy() == {"a": 9}

    def test_source_owning_the_whole_queue_reaches_the_hard_cap(self):
        gate = FairQuotaGate(max_queue_size=10, fair_quotas={"a": 10}, source_key_extractor=_source)

        for index in range(10):
            assert isinstance(gate.admit(("a", index)), QueuedTelemetry)
        assert gate.admit(("a", 10)) is DropReason.QUEUE_FULL
        assert gate.occupancy() == {"a": 10}

    def test_quota_is_visibly_reclaimed_when_owner_resumes(self):
        gate = FairQuotaGate(max_queue_size=10, fair_quotas={"a": 4, "b": 4}, source_key_extractor=_source)
        a_entries = [gate.admit(("a", index)) for index in range(8)]
        gate.admit(("b", 0))
        gate.admit(("b", 1))
        assert gate.occupancy() == {"a": 8, "b": 2}

        # "a" frees one slot while still being over quota (7 occupied vs quota 4).
        gate.release(a_entries[0])

        # The over-quota source cannot re-borrow the slot: "b" reclaims its reservation.
        over_quota_decision = gate.admit(("a", 100))
        assert over_quota_decision is DropReason.FAIR_QUOTA_EXCEEDED

        reclaiming_decision = gate.admit(("b", 100))
        assert isinstance(reclaiming_decision, QueuedTelemetry)
        assert gate.occupancy() == {"a": 7, "b": 3}
        assert gate.dropped_summary() == {"a": {"fair_quota_exceeded": 1}}

    def test_released_capacity_is_borrowable_again_after_flush(self):
        gate = FairQuotaGate(max_queue_size=10, fair_quotas={"a": 4, "b": 4}, source_key_extractor=_source)
        entries = [gate.admit(("a", index)) for index in range(8)]

        for entry in entries:
            gate.release(entry)
        assert gate.occupancy() == {}

        # Idle "b" capacity is once again fully available to "a".
        readmitted = [gate.admit(("a", index)) for index in range(8)]
        assert all(isinstance(decision, QueuedTelemetry) for decision in readmitted)
        assert gate.occupancy() == {"a": 8}

    def test_drop_records_keep_global_receive_order(self):
        gate = FairQuotaGate(max_queue_size=10, fair_quotas={"a": 4, "b": 4}, source_key_extractor=_source)
        a_entries = [gate.admit(("a", index)) for index in range(8)]
        gate.admit(("b", 0))
        gate.admit(("b", 1))
        gate.release(a_entries[0])

        gate.admit(("a", 100))  # rejected, sequence 10
        reclaiming = gate.admit(("b", 100))  # admitted, sequence 11

        records = gate.drop_records()
        assert len(records) == 1
        assert records[0] == DropRecord(10, "a", DropReason.FAIR_QUOTA_EXCEEDED)
        assert reclaiming.sequence == 11

    def test_external_drops_are_recorded_per_source(self):
        gate = FairQuotaGate(max_queue_size=10, fair_quotas={"a": 4}, source_key_extractor=_source)
        gate.record_external_drop(("a", 1), DropReason.ALREADY_SHUTDOWN)
        gate.record_external_drop(("b", 2), DropReason.ALREADY_SHUTDOWN)

        assert gate.dropped_summary() == {
            "a": {"already_shutdown": 1},
            "b": {"already_shutdown": 1},
        }
        assert [record.source for record in gate.drop_records()] == ["a", "b"]

    def test_unknown_sources_have_no_reservation(self):
        gate = FairQuotaGate(max_queue_size=10, fair_quotas={"a": 4}, source_key_extractor=_source)

        # A source without a reservation may borrow every idle slot and reach
        # the hard queue cap, since it owns no reclaimable reservation itself.
        for index in range(10):
            assert isinstance(gate.admit(("unknown", index)), QueuedTelemetry)
        assert gate.admit(("unknown", 10)) is DropReason.QUEUE_FULL
        assert gate.occupancy() == {"unknown": 10}

    def test_failing_extractor_falls_back_to_default_source(self):
        def broken_extractor(_item):
            raise RuntimeError("boom")

        gate = FairQuotaGate(max_queue_size=10, fair_quotas={}, source_key_extractor=broken_extractor)
        decision = gate.admit(("a", 1))
        assert isinstance(decision, QueuedTelemetry)
        assert decision.source == DEFAULT_SOURCE_KEY

    def test_none_extractor_result_falls_back_to_default_source(self):
        gate = FairQuotaGate(max_queue_size=10, fair_quotas={}, source_key_extractor=lambda _item: None)
        decision = gate.admit(("a", 1))
        assert decision.source == DEFAULT_SOURCE_KEY

    def test_reset_clears_occupancy_but_keeps_drop_history(self):
        gate = FairQuotaGate(max_queue_size=10, fair_quotas={"a": 4}, source_key_extractor=_source)
        gate.admit(("a", 0))
        gate.admit(("a", 1))
        gate.reset()

        assert gate.occupancy() == {}
        assert gate.fair_quotas == {"a": 4}

    def test_quotas_larger_than_the_queue_are_rejected(self):
        with pytest.raises(ValueError, match="must not exceed max_queue_size"):
            FairQuotaGate(max_queue_size=10, fair_quotas={"a": 6, "b": 5}, source_key_extractor=_source)

    @pytest.mark.parametrize("invalid_quota", [-1, 1.5, True, "4"])
    def test_invalid_quota_values_are_rejected(self, invalid_quota):
        with pytest.raises(ValueError, match="non-negative integers"):
            FairQuotaGate(max_queue_size=10, fair_quotas={"a": invalid_quota}, source_key_extractor=_source)
