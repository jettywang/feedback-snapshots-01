import json
import os

from aggregate import aggregate
from monitor import find_categories

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")


def _event(resource_id, sequence, observed_at, stage="analysis", outcome="completed", **extra):
    event = {
        "resource_id": resource_id,
        "sequence": sequence,
        "observed_at": observed_at,
        "stage": stage,
        "outcome": outcome,
    }
    event.update(extra)
    return event


def _entry(report, resource_id):
    return next(r for r in report["resources"] if r["resource_id"] == resource_id)


def test_late_stale_result_does_not_overwrite_newer_evidence():
    ticket = {
        "ticket_id": "T1",
        "scope": ["res-a"],
        "events": [
            _event("res-a", 2, "2026-11-24T10:00:20Z", findings=[{"rule": "R1"}]),
            _event("res-a", 1, "2026-11-24T10:00:05Z", findings=[]),
        ],
    }
    entry = _entry(aggregate(ticket), "res-a")
    assert entry["evidence"]["sequence"] == 2
    assert entry["finding"] == "present"
    assert entry["superseded"] == [
        {"sequence": 1, "observed_at": "2026-11-24T10:00:05Z", "reason": "stale"}
    ]


def test_stale_first_arrival_also_loses_to_newer_evidence():
    ticket = {
        "ticket_id": "T2",
        "scope": ["res-a"],
        "events": [
            _event("res-a", 1, "2026-11-24T10:00:05Z", findings=[]),
            _event("res-a", 2, "2026-11-24T10:00:20Z", findings=[{"rule": "R1"}]),
        ],
    }
    entry = _entry(aggregate(ticket), "res-a")
    assert entry["evidence"]["sequence"] == 2
    assert entry["finding"] == "present"


def test_exact_redelivery_is_recorded_as_duplicate_not_applied_twice():
    retry = _event("res-a", 2, "2026-11-24T10:00:20Z", findings=[{"rule": "R1"}])
    ticket = {
        "ticket_id": "T3",
        "scope": ["res-a"],
        "events": [retry, dict(retry)],
    }
    entry = _entry(aggregate(ticket), "res-a")
    assert entry["status"] == "checked"
    assert entry["findings_count"] == 1
    assert entry["superseded"] == [
        {"sequence": 2, "observed_at": "2026-11-24T10:00:20Z", "reason": "duplicate"}
    ]


def test_broken_parser_output_is_quarantined_and_others_stay_handoff_ready():
    ticket = {
        "ticket_id": "T4",
        "scope": ["res-ok", "res-broken"],
        "events": [
            _event("res-ok", 1, "2026-11-24T09:59:10Z", findings=[]),
            _event("res-broken", 1, "2026-11-24T09:59:12Z", stage="parse", outcome="failed",
                   error={"parser": "cfn-yaml", "message": "boom"}),
            {"resource_id": "res-broken", "sequence": 2,
             "observed_at": "2026-11-24T10:01:00Z", "stage": "parse"},
        ],
    }
    report = aggregate(ticket)
    assert len(report["quarantined_events"]) == 1
    assert report["quarantined_events"][0]["missing_fields"] == ["outcome"]
    assert _entry(report, "res-ok")["handoff_ready"] is True
    broken = _entry(report, "res-broken")
    assert broken["status"] == "parse_failed"
    assert broken["handoff_ready"] is False
    assert report["handoff"]["ready"] == ["res-ok"]


def test_resource_without_evidence_is_pending_and_out_of_scope_is_flagged():
    ticket = {
        "ticket_id": "T5",
        "scope": ["res-silent"],
        "events": [_event("res-stray", 1, "2026-11-24T09:59:10Z", findings=[])],
    }
    report = aggregate(ticket)
    assert _entry(report, "res-silent")["status"] == "pending"
    stray = _entry(report, "res-stray")
    assert stray["status"] == "out_of_scope"
    assert stray["handoff_ready"] is True


def test_monitor_identifies_three_categories_in_sample_report():
    with open(os.path.join(SAMPLES_DIR, "report.json"), encoding="utf-8") as handle:
        report = json.load(handle)
    categories = find_categories(report)
    assert categories["parse_not_analyzed"] == ["res-parse-fail"]
    assert categories["confirmed_clean"] == ["res-clean"]
    assert categories["duplicate_results"] == ["res-dup"]


def test_sample_report_is_up_to_date():
    with open(os.path.join(SAMPLES_DIR, "raw_results.json"), encoding="utf-8") as handle:
        ticket = json.load(handle)
    with open(os.path.join(SAMPLES_DIR, "report.json"), encoding="utf-8") as handle:
        expected = json.load(handle)
    assert aggregate(ticket) == expected
