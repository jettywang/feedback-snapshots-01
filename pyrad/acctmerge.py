# acctmerge.py
#
# Offline merger for verified RADIUS accounting packets.
"""Reconstruct accounting sessions from captured RADIUS Accounting-Requests.

The audit backend receives verified (authenticity already checked)
accounting packets together with their reception times.  The network is
free to duplicate, delay and reorder them, so neither arrival order nor
"last writer wins" reflects what really happened on the NAS.

This module merges such a capture offline:

* Records are grouped into sessions by NAS identity (NAS-Identifier, or
  NAS-IP-Address / NAS-IPv6-Address when no identifier is sent) plus
  Acct-Session-Id.  Sessions are never merged across these keys, so
  several concurrent sessions of the same user stay distinct.
* The event time of a record is Event-Timestamp when the NAS sent one,
  otherwise ``received_at - Acct-Delay-Time``.  Retransmissions of one
  packet only bump Acct-Delay-Time (RFC 2866 section 2.2), so copies of
  one event cluster onto the same event time and are billed once.
* The session timeline is ordered by event time, never by arrival time:
  a late Interim-Update is inserted where it belongs and a retransmitted
  old record can never overwrite a known later event.
* 32-bit counter decreases between consecutive events are treated as a
  single wrap (flagged ``counter-wrap-assumed``) unless the matching
  Acct-*-Gigawords attribute was sent; a decrease with gigawords present
  is a real regression and the interval is marked indeterminate.
* Missing Start, missing Stop, events after Stop and counter
  regressions are kept as explicit uncertainties.  Cumulative totals
  that rest on incomplete evidence are reported with
  ``determinate = false`` plus a lower bound instead of a made-up value.

Feed records with :func:`merge`; :class:`MergeReport.to_dict` yields a
JSON-serialisable timeline per session with references to the original
packets and metered intervals between consecutive events.  A JSON-Lines
command line interface is available via ``python -m pyrad.acctmerge``.
"""
import argparse
import json
import sys
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Iterable
from typing import Mapping
from typing import Optional

WRAP_MODULUS = 2 ** 32

# Metered counters and the gigaword attribute extending them to 64 bit.
_GIGAWORDS = {
    "Acct-Input-Octets": "Acct-Input-Gigawords",
    "Acct-Output-Octets": "Acct-Output-Gigawords",
}
METERED_COUNTERS = (
    "Acct-Input-Octets",
    "Acct-Output-Octets",
    "Acct-Input-Packets",
    "Acct-Output-Packets",
)

# Attributes making up the content signature of an event: retransmitted
# packets only change Acct-Delay-Time, everything else stays identical.
_SIGNATURE_ATTRS = METERED_COUNTERS + tuple(sorted(set(_GIGAWORDS.values()))) + (
    "Acct-Session-Time",
)

_STATUS_BY_CODE = {1: "Start", 2: "Stop", 3: "Interim-Update"}
_STATUS_ALIASES = {
    "start": "Start",
    "stop": "Stop",
    "interim-update": "Interim-Update",
    "interim": "Interim-Update",
    "update": "Interim-Update",
    "alive": "Interim-Update",
}

# Session-level uncertainty codes.
MISSING_START = "missing-start"
MISSING_STOP = "missing-stop"
EVENT_AFTER_STOP = "event-after-stop"
DUPLICATE_START = "duplicate-start"

# Interval-level flags.
COUNTER_WRAP_ASSUMED = "counter-wrap-assumed"
COUNTER_REGRESSION = "counter-regression"
MISSING_COUNTER = "missing-counter"


def _normalise_status(value: Any) -> Optional[str]:
    if isinstance(value, str):
        return _STATUS_ALIASES.get(value.strip().lower())
    if isinstance(value, int):
        return _STATUS_BY_CODE.get(value)
    return None


def _nas_identity(attrs: Mapping[str, Any]) -> Optional[str]:
    for name in ("NAS-Identifier", "NAS-IP-Address", "NAS-IPv6-Address"):
        value = attrs.get(name)
        if value is not None:
            return "%s=%s" % (name, value)
    return None


@dataclass(frozen=True)
class AcctRecord:
    """One verified accounting packet as received by the backend.

    ``packet_ref`` identifies the original datagram in the audit store,
    ``received_at`` is the local reception time (epoch seconds) and
    ``attributes`` maps RADIUS attribute names to decoded values.
    """

    packet_ref: Any
    received_at: float
    attributes: Mapping[str, Any]


@dataclass
class Event:
    """One logical NAS event; retransmissions share a single Event."""

    status_type: str
    event_time: float
    event_time_source: str
    counters: Mapping[str, Any]
    acct_session_time: Optional[int]
    packet_refs: list = field(default_factory=list)
    first_received_at: float = 0.0
    last_received_at: float = 0.0

    @property
    def retransmissions(self) -> int:
        return len(self.packet_refs) - 1

    def to_dict(self) -> dict:
        return {
            "status_type": self.status_type,
            "event_time": self.event_time,
            "event_time_source": self.event_time_source,
            "acct_session_time": self.acct_session_time,
            "counters": dict(self.counters),
            "packet_refs": list(self.packet_refs),
            "retransmissions": self.retransmissions,
            "first_received_at": self.first_received_at,
            "last_received_at": self.last_received_at,
        }


@dataclass
class Interval:
    """Metered span between two consecutive events of one session."""

    from_event: int
    to_event: int
    from_packet_refs: list
    to_packet_refs: list
    duration: float
    deltas: Mapping[str, Optional[int]]
    flags: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "from_event": self.from_event,
            "to_event": self.to_event,
            "from_packet_refs": list(self.from_packet_refs),
            "to_packet_refs": list(self.to_packet_refs),
            "duration": self.duration,
            "deltas": dict(self.deltas),
            "flags": list(self.flags),
        }


@dataclass
class SessionReport:
    key: Mapping[str, str]
    user: Optional[str]
    events: list = field(default_factory=list)
    intervals: list = field(default_factory=list)
    uncertainties: list = field(default_factory=list)
    totals: Mapping[str, Any] = field(default_factory=dict)

    @property
    def closed(self) -> bool:
        return any(event.status_type == "Stop" for event in self.events)

    def to_dict(self) -> dict:
        return {
            "key": dict(self.key),
            "user": self.user,
            "status": "closed" if self.closed else "open",
            "uncertainties": list(self.uncertainties),
            "events": [event.to_dict() for event in self.events],
            "intervals": [interval.to_dict() for interval in self.intervals],
            "totals": self.totals,
        }


@dataclass
class MergeReport:
    sessions: list = field(default_factory=list)
    users: Mapping[str, list] = field(default_factory=dict)
    rejected: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "sessions": [session.to_dict() for session in self.sessions],
            "users": {user: list(keys) for user, keys in self.users.items()},
            "rejected": [dict(entry) for entry in self.rejected],
        }


def _event_time(record: AcctRecord) -> tuple:
    attrs = record.attributes
    timestamp = attrs.get("Event-Timestamp")
    if timestamp is not None:
        return float(timestamp), "event-timestamp"
    delay = attrs.get("Acct-Delay-Time", 0) or 0
    return record.received_at - delay, "delay-adjusted-receipt"


def _signature(attrs: Mapping[str, Any]) -> tuple:
    return tuple(attrs.get(name) for name in _SIGNATURE_ATTRS)


def _counters(attrs: Mapping[str, Any]) -> dict:
    counters = {}
    for name in METERED_COUNTERS + tuple(_GIGAWORDS.values()):
        if name in attrs:
            counters[name] = attrs[name]
    return counters


def _cluster_events(records: list, tolerance: float) -> list:
    """Fold retransmissions into one Event per logical NAS event."""
    timed = []
    for record in records:
        event_time, source = _event_time(record)
        timed.append((event_time, source, record))
    timed.sort(key=lambda item: (item[0], item[2].received_at))

    events = []
    for event_time, source, record in timed:
        attrs = record.attributes
        status = _normalise_status(attrs.get("Acct-Status-Type"))
        signature = _signature(attrs)
        event = events[-1] if events else None
        same_event = (
            event is not None
            and event.status_type == status
            and event._signature == signature
            and event_time - event._max_event_time <= tolerance
        )
        if same_event:
            event.packet_refs.append(record.packet_ref)
            event.last_received_at = max(
                event.last_received_at, record.received_at)
            event.first_received_at = min(
                event.first_received_at, record.received_at)
            event.event_time = min(event.event_time, event_time)
            event._max_event_time = max(event._max_event_time, event_time)
        else:
            event = Event(
                status_type=status,
                event_time=event_time,
                event_time_source=source,
                counters=_counters(attrs),
                acct_session_time=attrs.get("Acct-Session-Time"),
                packet_refs=[record.packet_ref],
                first_received_at=record.received_at,
                last_received_at=record.received_at,
            )
            event._signature = signature
            event._max_event_time = event_time
            events.append(event)
    for event in events:
        del event._signature, event._max_event_time
    return events


def _effective_counter(counters: Mapping[str, Any], name: str):
    """Return (value, wrap_possible) for a metered counter."""
    value = counters.get(name)
    if value is None:
        return None, False
    gigawords = counters.get(_GIGAWORDS.get(name, ""))
    if gigawords is not None:
        return gigawords * WRAP_MODULUS + value, False
    return value, True


def _counter_delta(previous, current, wrap_possible):
    """Return (delta, flag); delta is None when it cannot be determined."""
    if previous is None or current is None:
        return None, MISSING_COUNTER
    delta = current - previous
    if delta >= 0:
        return delta, None
    if wrap_possible:
        # 32-bit counter without gigawords: a decrease means one wrap
        # (a reset is indistinguishable, hence the flag stays on).
        return delta + WRAP_MODULUS, COUNTER_WRAP_ASSUMED
    return None, COUNTER_REGRESSION


def _build_intervals(events: list, metered: tuple) -> list:
    intervals = []
    for index in range(1, len(events)):
        previous, current = events[index - 1], events[index]
        deltas = {}
        flags = []
        for name in metered:
            prev_value, wrap_possible = _effective_counter(
                previous.counters, name)
            cur_value, _ = _effective_counter(current.counters, name)
            delta, flag = _counter_delta(prev_value, cur_value, wrap_possible)
            deltas[name] = delta
            if flag is not None:
                flags.append("%s:%s" % (flag, name))
        intervals.append(Interval(
            from_event=index - 1,
            to_event=index,
            from_packet_refs=list(previous.packet_refs),
            to_packet_refs=list(current.packet_refs),
            duration=current.event_time - previous.event_time,
            deltas=deltas,
            flags=flags,
        ))
    return intervals


def _build_totals(events: list, intervals: list,
                  uncertainties: list, metered: tuple) -> dict:
    totals = {}
    for name in metered:
        known = sum(interval.deltas[name] or 0 for interval in intervals)
        determinate = (
            MISSING_START not in uncertainties
            and all(interval.deltas[name] is not None for interval in intervals)
        )
        totals[name] = {
            "value": known if determinate else None,
            "determinate": determinate,
            "lower_bound": known,
        }
    if events:
        totals["duration"] = {
            "value": events[-1].event_time - events[0].event_time,
            "determinate": MISSING_START not in uncertainties,
            "lower_bound": events[-1].event_time - events[0].event_time,
        }
    return totals


def _build_session(key: Mapping[str, str], records: list,
                   tolerance: float) -> SessionReport:
    events = _cluster_events(records, tolerance)
    # Order the timeline by event time; arrival order must never let an
    # old retransmission overwrite a known later event.
    events.sort(key=lambda event: (event.event_time, event.first_received_at))

    uncertainties = []
    if events and events[0].status_type != "Start":
        uncertainties.append(MISSING_START)
    if events and not any(event.status_type == "Stop" for event in events):
        uncertainties.append(MISSING_STOP)
    if sum(event.status_type == "Start" for event in events) > 1:
        uncertainties.append(DUPLICATE_START)
    stop_times = [event.event_time for event in events
                  if event.status_type == "Stop"]
    if stop_times and any(event.event_time > max(stop_times)
                          for event in events):
        uncertainties.append(EVENT_AFTER_STOP)

    # Only counters the NAS actually reported take part in metering; a
    # counter absent from every event must not poison the totals.
    metered = tuple(name for name in METERED_COUNTERS
                    if any(name in event.counters for event in events))
    intervals = _build_intervals(events, metered)
    users = [record.attributes.get("User-Name") for record in records
             if record.attributes.get("User-Name") is not None]
    return SessionReport(
        key=key,
        user=users[0] if users else None,
        events=events,
        intervals=intervals,
        uncertainties=uncertainties,
        totals=_build_totals(events, intervals, uncertainties, metered),
    )


def merge(records: Iterable[AcctRecord], tolerance: float = 2.0) -> MergeReport:
    """Merge verified accounting records into per-session timelines.

    ``tolerance`` is the slack in seconds when matching retransmissions
    by event time (Acct-Delay-Time has one-second granularity).
    """
    sessions = {}
    rejected = []
    for record in records:
        attrs = record.attributes
        status = _normalise_status(attrs.get("Acct-Status-Type"))
        nas = _nas_identity(attrs)
        session_id = attrs.get("Acct-Session-Id")
        if status is None:
            rejected.append({"packet_ref": record.packet_ref,
                             "reason": "unsupported-status-type"})
            continue
        if nas is None:
            rejected.append({"packet_ref": record.packet_ref,
                             "reason": "missing-nas-identity"})
            continue
        if session_id is None:
            rejected.append({"packet_ref": record.packet_ref,
                             "reason": "missing-acct-session-id"})
            continue
        key = (nas, str(session_id))
        sessions.setdefault(key, []).append(record)

    report = MergeReport()
    users = {}
    for (nas, session_id) in sorted(sessions):
        session = _build_session(
            {"nas": nas, "acct_session_id": session_id},
            sessions[(nas, session_id)], tolerance)
        report.sessions.append(session)
        if session.user is not None:
            users.setdefault(session.user, []).append(
                "%s/%s" % (nas, session_id))
    report.users = users
    report.rejected = rejected
    return report


def _load_jsonl(stream) -> list:
    records = []
    for line_number, line in enumerate(stream, 1):
        line = line.strip()
        if not line:
            continue
        raw = json.loads(line)
        records.append(AcctRecord(
            packet_ref=raw.get("packet_ref", line_number),
            received_at=float(raw["received_at"]),
            attributes=raw["attributes"],
        ))
    return records


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="pyrad.acctmerge",
        description="Merge verified RADIUS accounting packets (JSON Lines)"
                    " into session timelines.")
    parser.add_argument("input", nargs="?", default="-",
                        help="JSON-Lines capture file ('-' for stdin)")
    parser.add_argument("--tolerance", type=float, default=2.0,
                        help="event-time tolerance for retransmission"
                             " matching, in seconds (default: 2.0)")
    args = parser.parse_args(argv)

    if args.input == "-":
        records = _load_jsonl(sys.stdin)
    else:
        with open(args.input, "r", encoding="utf-8") as stream:
            records = _load_jsonl(stream)
    report = merge(records, tolerance=args.tolerance)
    json.dump(report.to_dict(), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
