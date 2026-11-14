import io
import json
import unittest

from pyrad import acctmerge
from pyrad.acctmerge import AcctRecord


BASE = {
    "NAS-Identifier": "nas-1",
    "Acct-Session-Id": "S1",
    "User-Name": "alice",
}


def rec(ref, received_at, status, delay=0, **attrs):
    attributes = dict(BASE)
    attributes["Acct-Status-Type"] = status
    if delay:
        attributes["Acct-Delay-Time"] = delay
    attributes.update(attrs)
    return AcctRecord(packet_ref=ref, received_at=received_at,
                      attributes=attributes)


def canonical_records():
    """A legal send-order capture: Start, two Interims, Stop.

    The input octet counter wraps the 32-bit boundary between the
    second Interim-Update and the Stop.
    """
    return [
        rec("p1", 1000.0, "Start",
            **{"Acct-Input-Octets": 0, "Acct-Output-Octets": 0,
               "Acct-Input-Packets": 0, "Acct-Output-Packets": 0}),
        rec("p2", 1600.0, "Interim-Update",
            **{"Acct-Input-Octets": 100000, "Acct-Output-Octets": 200000,
               "Acct-Input-Packets": 100, "Acct-Output-Packets": 150,
               "Acct-Session-Time": 600}),
        rec("p3", 2200.0, "Interim-Update",
            **{"Acct-Input-Octets": 4000000000, "Acct-Output-Octets": 400000,
               "Acct-Input-Packets": 3000, "Acct-Output-Packets": 40,
               "Acct-Session-Time": 1200}),
        rec("p4", 2800.0, "Stop",
            **{"Acct-Input-Octets": 200, "Acct-Output-Octets": 600000,
               "Acct-Input-Packets": 3100, "Acct-Output-Packets": 50,
               "Acct-Session-Time": 1800}),
    ]


def shuffled_retransmitted_records():
    """The same events as the NAS legally sent them, but duplicated
    (only Acct-Delay-Time changes on retransmission) and reordered."""
    return [
        # Stop retransmission arrives first, delay-adjusted to t=2800.
        rec("r1", 2830.0, "Stop", delay=30,
            **{"Acct-Input-Octets": 200, "Acct-Output-Octets": 600000,
               "Acct-Input-Packets": 3100, "Acct-Output-Packets": 50,
               "Acct-Session-Time": 1800}),
        rec("r2", 2200.0, "Interim-Update",
            **{"Acct-Input-Octets": 4000000000, "Acct-Output-Octets": 400000,
               "Acct-Input-Packets": 3000, "Acct-Output-Packets": 40,
               "Acct-Session-Time": 1200}),
        # Retransmission of the first Interim arrives after the Stop.
        rec("r3", 2900.0, "Interim-Update", delay=1300,
            **{"Acct-Input-Octets": 100000, "Acct-Output-Octets": 200000,
               "Acct-Input-Packets": 100, "Acct-Output-Packets": 150,
               "Acct-Session-Time": 600}),
        rec("r4", 1600.0, "Interim-Update",
            **{"Acct-Input-Octets": 100000, "Acct-Output-Octets": 200000,
               "Acct-Input-Packets": 100, "Acct-Output-Packets": 150,
               "Acct-Session-Time": 600}),
        rec("r5", 1000.0, "Start",
            **{"Acct-Input-Octets": 0, "Acct-Output-Octets": 0,
               "Acct-Input-Packets": 0, "Acct-Output-Packets": 0}),
        rec("r6", 2800.0, "Stop",
            **{"Acct-Input-Octets": 200, "Acct-Output-Octets": 600000,
               "Acct-Input-Packets": 3100, "Acct-Output-Packets": 50,
               "Acct-Session-Time": 1800}),
        # Retransmission of the second Interim, delay-adjusted to t=2200.
        rec("r7", 2210.0, "Interim-Update", delay=10,
            **{"Acct-Input-Octets": 4000000000, "Acct-Output-Octets": 400000,
               "Acct-Input-Packets": 3000, "Acct-Output-Packets": 40,
               "Acct-Session-Time": 1200}),
    ]


def session_totals(report):
    session, = report.sessions
    return session.to_dict()["totals"]


class MergeEquivalenceTests(unittest.TestCase):
    def testShuffledRetransmissionsMatchLegalSendOrder(self):
        in_order = acctmerge.merge(canonical_records())
        shuffled = acctmerge.merge(shuffled_retransmitted_records())

        self.assertEqual(len(in_order.sessions), 1)
        self.assertEqual(len(shuffled.sessions), 1)
        # The merged result is identical to the legal send order, except
        # for packet references and reception bookkeeping.
        self.assertEqual(session_totals(in_order), session_totals(shuffled))
        self.assertEqual(
            [i.to_dict()["deltas"] for i in in_order.sessions[0].intervals],
            [i.to_dict()["deltas"] for i in shuffled.sessions[0].intervals])
        self.assertEqual(
            [(e.status_type, e.event_time) for e in in_order.sessions[0].events],
            [(e.status_type, e.event_time) for e in shuffled.sessions[0].events])

    def testRetransmissionsBilledOnce(self):
        report = acctmerge.merge(shuffled_retransmitted_records())
        session, = report.sessions
        self.assertEqual(len(session.events), 4)
        self.assertEqual(
            [e.status_type for e in session.events],
            ["Start", "Interim-Update", "Interim-Update", "Stop"])
        # Every retransmitted copy is accounted for on its event.
        self.assertEqual(
            [sorted(e.packet_refs) for e in session.events],
            [["r5"], ["r3", "r4"], ["r2", "r7"], ["r1", "r6"]])
        self.assertEqual(
            [e.retransmissions for e in session.events], [0, 1, 1, 1])
        totals = session.totals
        # Input octets wrapped once: 0 -> 100000 -> 4e9 -> 2**32 + 200.
        self.assertEqual(
            totals["Acct-Input-Octets"],
            {"value": 4294967496, "determinate": True,
             "lower_bound": 4294967496})
        self.assertEqual(totals["Acct-Output-Octets"]["value"], 600000)
        self.assertEqual(totals["Acct-Input-Packets"]["value"], 3100)

    def testLateArrivalDoesNotOverwriteLaterEvent(self):
        # The retransmitted first Interim (r3, small counters) is the
        # last record to arrive; the Stop's counters must still win.
        report = acctmerge.merge(shuffled_retransmitted_records())
        session, = report.sessions
        last = session.events[-1]
        self.assertEqual(last.status_type, "Stop")
        self.assertEqual(last.counters["Acct-Input-Octets"], 200)
        self.assertEqual(session.intervals[-1].deltas["Acct-Input-Octets"],
                         4294967496 - 4000000000)

    def testCounterWrapFlaggedOnInterval(self):
        report = acctmerge.merge(canonical_records())
        session, = report.sessions
        self.assertEqual(
            session.intervals[-1].flags,
            ["counter-wrap-assumed:Acct-Input-Octets"])
        self.assertEqual(session.intervals[0].flags, [])


class UncertaintyTests(unittest.TestCase):
    def testMissingStartMarksTotalsIndeterminate(self):
        records = canonical_records()[1:]  # drop the Start
        report = acctmerge.merge(records)
        session, = report.sessions
        self.assertIn(acctmerge.MISSING_START, session.uncertainties)
        totals = session.totals
        self.assertFalse(totals["Acct-Output-Octets"]["determinate"])
        self.assertIsNone(totals["Acct-Output-Octets"]["value"])
        # Lower bound still reflects the observed deltas.
        self.assertEqual(totals["Acct-Output-Octets"]["lower_bound"], 400000)

    def testMissingStopLeavesSessionOpen(self):
        records = canonical_records()[:2]
        report = acctmerge.merge(records)
        session, = report.sessions
        self.assertIn(acctmerge.MISSING_STOP, session.uncertainties)
        self.assertEqual(session.to_dict()["status"], "open")
        # Deltas up to the last known event remain determinate.
        self.assertEqual(
            session.totals["Acct-Output-Octets"]["value"], 200000)

    def testInterimAfterStopFlagged(self):
        records = canonical_records() + [
            rec("p5", 3000.0, "Interim-Update",
                **{"Acct-Input-Octets": 300, "Acct-Output-Octets": 7000,
                   "Acct-Input-Packets": 3200, "Acct-Output-Packets": 60,
                   "Acct-Session-Time": 2000}),
        ]
        report = acctmerge.merge(records)
        session, = report.sessions
        self.assertIn(acctmerge.EVENT_AFTER_STOP, session.uncertainties)

    def testGigawordsMakeWrapDeterminate(self):
        records = [
            rec("g1", 1000.0, "Start",
                **{"Acct-Input-Octets": 4000000000,
                   "Acct-Input-Gigawords": 0}),
            rec("g2", 2000.0, "Stop",
                **{"Acct-Input-Octets": 200,
                   "Acct-Input-Gigawords": 1}),
        ]
        report = acctmerge.merge(records)
        session, = report.sessions
        interval, = session.intervals
        self.assertEqual(interval.flags, [])
        self.assertEqual(interval.deltas["Acct-Input-Octets"], 294967496)
        self.assertEqual(
            session.totals["Acct-Input-Octets"]["value"], 294967496)

    def testCounterRegressionWithGigawordsIndeterminate(self):
        records = [
            rec("g1", 1000.0, "Start",
                **{"Acct-Input-Octets": 500, "Acct-Input-Gigawords": 2}),
            rec("g2", 2000.0, "Stop",
                **{"Acct-Input-Octets": 100, "Acct-Input-Gigawords": 1}),
        ]
        report = acctmerge.merge(records)
        session, = report.sessions
        interval, = session.intervals
        self.assertEqual(
            interval.flags, ["counter-regression:Acct-Input-Octets"])
        self.assertIsNone(interval.deltas["Acct-Input-Octets"])
        self.assertFalse(
            session.totals["Acct-Input-Octets"]["determinate"])

    def testSameUserMultipleSessionsStayDistinct(self):
        records = canonical_records()
        other = []
        for ref, recv, status, kwargs in [
                ("o1", 1050.0, "Start",
                 {"Acct-Output-Octets": 0}),
                ("o2", 1250.0, "Stop",
                 {"Acct-Output-Octets": 42})]:
            attrs = dict(BASE)
            attrs["Acct-Session-Id"] = "S2"
            attrs["Acct-Status-Type"] = status
            attrs.update(kwargs)
            other.append(AcctRecord(packet_ref=ref, received_at=recv,
                                    attributes=attrs))
        report = acctmerge.merge(records + other)
        self.assertEqual(len(report.sessions), 2)
        self.assertEqual(
            sorted(report.users["alice"]),
            ["NAS-Identifier=nas-1/S1", "NAS-Identifier=nas-1/S2"])
        by_id = {s.key["acct_session_id"]: s for s in report.sessions}
        self.assertEqual(
            by_id["S2"].totals["Acct-Output-Octets"]["value"], 42)
        self.assertEqual(
            by_id["S1"].totals["Acct-Output-Octets"]["value"], 600000)

    def testEventTimestampBeatsDelayEstimate(self):
        records = [
            rec("t1", 1000.0, "Start",
                **{"Acct-Output-Octets": 0, "Event-Timestamp": 990}),
            rec("t2", 2200.0, "Stop", delay=300,
                **{"Acct-Output-Octets": 10, "Event-Timestamp": 1890}),
        ]
        report = acctmerge.merge(records)
        session, = report.sessions
        self.assertEqual(
            [e.event_time for e in session.events], [990.0, 1890.0])
        self.assertEqual(
            session.events[0].event_time_source, "event-timestamp")

    def testRejectedRecordsReported(self):
        bad_status = AcctRecord(packet_ref="b1", received_at=1.0,
                                attributes=dict(BASE, **{
                                    "Acct-Status-Type": 7}))
        no_nas = AcctRecord(packet_ref="b2", received_at=1.0,
                            attributes={"Acct-Status-Type": "Start",
                                        "Acct-Session-Id": "S9"})
        no_session = AcctRecord(packet_ref="b3", received_at=1.0,
                                attributes={"Acct-Status-Type": "Start",
                                            "NAS-Identifier": "nas-1"})
        report = acctmerge.merge([bad_status, no_nas, no_session])
        self.assertEqual(report.sessions, [])
        self.assertEqual(
            [(r["packet_ref"], r["reason"]) for r in report.rejected],
            [("b1", "unsupported-status-type"),
             ("b2", "missing-nas-identity"),
             ("b3", "missing-acct-session-id")])


class CommandLineTests(unittest.TestCase):
    def testJsonLinesRoundTrip(self):
        lines = "\n".join(json.dumps({
            "packet_ref": r.packet_ref,
            "received_at": r.received_at,
            "attributes": dict(r.attributes),
        }) for r in shuffled_retransmitted_records())
        import sys
        stdin = sys.stdin
        stdout = sys.stdout
        try:
            sys.stdin = io.StringIO(lines)
            sys.stdout = out = io.StringIO()
            self.assertEqual(acctmerge.main([]), 0)
        finally:
            sys.stdin = stdin
            sys.stdout = stdout
        report = json.loads(out.getvalue())
        session, = report["sessions"]
        self.assertEqual(
            session["totals"]["Acct-Input-Octets"]["value"], 4294967496)
        self.assertEqual(len(session["events"]), 4)


if __name__ == "__main__":
    unittest.main()
