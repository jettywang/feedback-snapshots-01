#!/usr/bin/env python3
"""Aggregate permission-review results from multiple templates into one approval report.

Freshness rule: evidence is ordered by (sequence, observed_at). The newest
evidence wins regardless of arrival order, so a late retry response or a
stale redelivery can never overwrite newer evidence.

Isolation rule: malformed events (e.g. emitted by a broken parser) are
quarantined per item and never abort aggregation of the other items.
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone

STATUS_CHECKED = "checked"  # 已查：分析已完成并有定论
STATUS_PENDING = "pending"  # 待核实：证据未到或分析无定论
STATUS_OUT_OF_SCOPE = "out_of_scope"  # 不在授权范围
STATUS_PARSE_FAILED = "parse_failed"  # 解析失败，未进入分析
STATUS_ANALYSIS_FAILED = "analysis_failed"  # 分析阶段失败

HANDOFF_READY_STATUSES = frozenset({STATUS_CHECKED, STATUS_OUT_OF_SCOPE})

REQUIRED_EVENT_FIELDS = ("resource_id", "sequence", "observed_at", "stage", "outcome")

REPORT_VERSION = "1.0"


def payload_digest(event):
    canonical = json.dumps(
        {key: event.get(key) for key in ("stage", "outcome", "findings", "error")},
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def freshness_key(event):
    return (event["sequence"], event["observed_at"])


def classify_event(event):
    """Map a resource's freshest event to (status, finding, findings_count)."""
    stage = event["stage"]
    outcome = event["outcome"]
    if stage == "parse":
        if outcome == "failed":
            return STATUS_PARSE_FAILED, "unknown", None
        return STATUS_PENDING, "unknown", None
    if stage == "analysis":
        if outcome == "failed":
            return STATUS_ANALYSIS_FAILED, "unknown", None
        if outcome == "inconclusive":
            return STATUS_PENDING, "unknown", None
        findings = event.get("findings") or []
        return STATUS_CHECKED, ("none" if not findings else "present"), len(findings)
    raise ValueError("unknown stage: %r" % stage)


def _build_entry(resource_id, in_scope, resource_events):
    entry = {
        "resource_id": resource_id,
        "in_scope": in_scope,
        "evidence": None,
        "superseded": [],
        "error": None,
    }
    if not in_scope:
        entry["status"] = STATUS_OUT_OF_SCOPE
        entry["finding"] = "unknown"
        entry["note"] = "resource is not covered by the ticket's authorization scope"
        return entry
    if not resource_events:
        entry["status"] = STATUS_PENDING
        entry["finding"] = "unknown"
        entry["note"] = "no evidence received yet"
        return entry

    best = max(resource_events, key=freshness_key)
    best_digest = payload_digest(best)
    for other in resource_events:
        if other is best:
            continue
        if freshness_key(other) < freshness_key(best):
            reason = "stale"
        elif payload_digest(other) == best_digest:
            reason = "duplicate"
        else:
            reason = "conflict"
        entry["superseded"].append(
            {
                "sequence": other["sequence"],
                "observed_at": other["observed_at"],
                "reason": reason,
            }
        )

    status, finding, findings_count = classify_event(best)
    entry["status"] = status
    entry["finding"] = finding
    if findings_count is not None:
        entry["findings_count"] = findings_count
    entry["evidence"] = {
        "sequence": best["sequence"],
        "observed_at": best["observed_at"],
        "stage": best["stage"],
        "outcome": best["outcome"],
        "source": best.get("source"),
    }
    if best.get("error"):
        entry["error"] = best["error"]
    return entry


def aggregate(ticket):
    scope = set(ticket.get("scope", []))

    quarantined = []
    valid = []
    for index, event in enumerate(ticket.get("events", [])):
        missing = [field for field in REQUIRED_EVENT_FIELDS if field not in event]
        if missing:
            quarantined.append({"index": index, "missing_fields": missing, "event": event})
        else:
            valid.append(event)

    by_resource = {}
    for event in valid:
        by_resource.setdefault(event["resource_id"], []).append(event)

    resources = []
    for resource_id in sorted(scope | set(by_resource)):
        entry = _build_entry(resource_id, resource_id in scope, by_resource.get(resource_id, []))
        entry["handoff_ready"] = entry["status"] in HANDOFF_READY_STATUSES
        resources.append(entry)

    summary = {"total": len(resources)}
    for entry in resources:
        summary[entry["status"]] = summary.get(entry["status"], 0) + 1

    generated_at = ticket.get("generated_at")
    if not generated_at:
        generated_at = datetime.now(timezone.utc).isoformat()

    return {
        "report_version": REPORT_VERSION,
        "ticket_id": ticket.get("ticket_id"),
        "generated_at": generated_at,
        "summary": summary,
        "handoff": {
            "ready": [e["resource_id"] for e in resources if e["handoff_ready"]],
            "blocked": [
                {"resource_id": e["resource_id"], "status": e["status"]}
                for e in resources
                if not e["handoff_ready"]
            ],
        },
        "quarantined_events": quarantined,
        "resources": resources,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="raw results JSON (ticket_id, scope, events)")
    parser.add_argument("-o", "--output", help="write report here (default: stdout)")
    args = parser.parse_args(argv)

    with open(args.input, encoding="utf-8") as handle:
        ticket = json.load(handle)
    report = aggregate(ticket)
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
