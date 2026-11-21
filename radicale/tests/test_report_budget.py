# This file is part of Radicale - CalDAV and CardDAV server
# Copyright © 2026-2026 Peter Bieringer <pb@bieringer.de>
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Radicale.  If not, see <http://www.gnu.org/licenses/>.

"""REPORT compute budget tests.

A report query may be given a compute budget. Every examined recurrence
instance and every emitted result item costs one unit. The budget belongs
to the request, so a ``Depth: 1`` calendar-query merged over several
calendar collections shares it. A query that cannot afford its answer
fails with ``507 Insufficient Storage`` and no partial multistatus.
"""

import os
from typing import List

import defusedxml.ElementTree as DefusedET

from radicale import xmlutils
from radicale.tests import BaseTest
from radicale.tests.helpers import get_file_content

SHORT_UID = "report-budget-short"
LONG_UID = "report-budget-long"

EXPAND_QUERY = """\
<?xml version="1.0" encoding="utf-8" ?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
    <D:prop>
        <C:calendar-data>
            <C:expand start="20260101T000000Z" end="20260301T000000Z"/>
        </C:calendar-data>
    </D:prop>
    <C:filter>
        <C:comp-filter name="VCALENDAR">
            <C:comp-filter name="VEVENT">
                <C:time-range start="20260101T000000Z" end="20260301T000000Z"/>
            </C:comp-filter>
        </C:comp-filter>
    </C:filter>
</C:calendar-query>"""

SMALL_QUERY = """\
<?xml version="1.0" encoding="utf-8" ?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
    <D:prop>
        <D:getetag/>
    </D:prop>
    <C:filter>
        <C:comp-filter name="VCALENDAR">
            <C:comp-filter name="VEVENT">
                <C:time-range start="20260106T000000Z" end="20260107T000000Z"/>
            </C:comp-filter>
        </C:comp-filter>
    </C:filter>
</C:calendar-query>"""

SYNC_QUERY = """\
<?xml version="1.0" encoding="utf-8" ?>
<D:sync-collection xmlns:D="DAV:">
    <D:sync-token/>
    <D:prop>
        <D:getetag/>
    </D:prop>
</D:sync-collection>"""


class TestReportBudget(BaseTest):

    def setup_method(self) -> None:
        BaseTest.setup_method(self)
        rights_file_path = os.path.join(self.colpath, "rights")
        with open(rights_file_path, "w") as handle:
            handle.write("[all]\nuser: .*\ncollection: .*\npermissions: RrWwRrf\n")
        self.configure({
            "auth": {"type": "none"},
            "rights": {"type": "from_file", "file": rights_file_path}})

    def _prepare(self, budget: int) -> None:
        self.configure({"reporting": {"report_budget": budget}})
        self.mkcol("/team/")
        self.mkcalendar("/team/short.ics/")
        self.mkcalendar("/team/long.ics/")
        self.put("/team/short.ics/series.ics",
                 get_file_content("event_report_budget_short.ics"))
        self.put("/team/long.ics/series.ics",
                 get_file_content("event_report_budget_long.ics"))

    @staticmethod
    def _events(answer: str) -> List[str]:
        return [line for line in answer.splitlines()
                if line.startswith("RECURRENCE-ID:")]

    def _error_tag(self, answer: str) -> str:
        error = DefusedET.fromstring(answer)
        assert error.tag == xmlutils.make_clark("D:error")
        return xmlutils.make_human_tag(list(error)[0].tag)

    def test_within_budget_returns_complete_series(self) -> None:
        """One short series fits a small budget and is returned whole."""
        self._prepare(10)
        status, responses = self.report("/team/short.ics/", EXPAND_QUERY)
        assert status == 207
        assert list(responses) == ["/team/short.ics/series.ics"]
        response = responses["/team/short.ics/series.ics"]
        assert isinstance(response, dict)
        prop_status, element = response["C:calendar-data"]
        assert prop_status == 200 and element.text
        assert element.text.count("BEGIN:VEVENT") == 4
        assert len(self._events(element.text)) == 4
        assert "UID:" + SHORT_UID in element.text

    def test_merged_collections_exceed_budget(self) -> None:
        """The same query over both calendars costs more than one alone."""
        self._prepare(14)
        status, responses = self.report("/team/short.ics/", EXPAND_QUERY)
        assert status == 207
        status, responses = self.report("/team/long.ics/", EXPAND_QUERY)
        assert status == 207
        response = responses["/team/long.ics/series.ics"]
        assert isinstance(response, dict)
        _prop_status, element = response["C:calendar-data"]
        assert element.text and element.text.count("BEGIN:VEVENT") == 8

        status, _headers, answer = self.request(
            "REPORT", "/team/", EXPAND_QUERY, check=507, HTTP_DEPTH="1")
        assert not isinstance(answer, bytes)
        assert "BEGIN:VEVENT" not in answer
        assert "RECURRENCE-ID:" not in answer
        assert self._error_tag(answer) == "C:number-of-matches-within-limits"

    def test_failed_query_keeps_process_serving(self) -> None:
        """A small query after an exhausted one is answered normally."""
        self._prepare(14)
        self.report("/team/", EXPAND_QUERY, check=507, HTTP_DEPTH="1")
        status, responses = self.report("/team/long.ics/", SMALL_QUERY)
        assert status == 207
        response = responses["/team/long.ics/series.ics"]
        assert isinstance(response, dict)
        prop_status, element = response["D:getetag"]
        assert prop_status == 200 and element.text
        status, _headers, answer = self.request(
            "REPORT", "/team/short.ics/", SMALL_QUERY, check=207)
        assert "BEGIN:VEVENT" not in answer

    def test_sync_collection_is_not_charged(self) -> None:
        """A sync-collection REPORT works even with a tiny budget."""
        self._prepare(1)
        status, _headers, answer = self.request(
            "REPORT", "/team/long.ics/", SYNC_QUERY, check=207)
        assert "series.ics" in answer
        assert "sync-token" in answer

    def test_budget_zero_is_unlimited(self) -> None:
        """The default disables accounting, so the merged answer is complete."""
        self._prepare(0)
        status, responses = self.report("/team/", EXPAND_QUERY,
                                        HTTP_DEPTH="1")
        assert status == 207
        assert len(responses) == 2
        assert "/team/short.ics/series.ics" in responses
        assert "/team/long.ics/series.ics" in responses

    def test_freebusy_is_charged(self) -> None:
        """An expanded free-busy query spends the same budget."""
        self._prepare(4)
        freebusy_query = """\
<?xml version="1.0" encoding="utf-8" ?>
<C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav">
    <C:time-range start="20260101T000000Z" end="20260301T000000Z"/>
</C:free-busy-query>"""
        status, _headers, answer = self.request(
            "REPORT", "/team/long.ics/", freebusy_query, check=507)
        assert "BEGIN:VFREEBUSY" not in answer
        assert "FREEBUSY" not in answer
        assert self._error_tag(answer) == "C:number-of-matches-within-limits"
