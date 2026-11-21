# This file is part of Radicale - CalDAV and CardDAV server
# Copyright © 2026-2026 oliviasculley <olivia@sculley.dev>
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

"""The ``n`` right separates writing an item from notifying attendees.

An import-only account holds ``n``: its legal writes land in storage but
the configured hook never fires. A refused write fires nothing either,
and a retry that changes no content stays silent. An account with the
notification right still gets exactly one attributable event per real
change, including a CANCEL that keeps a recurring series in place.
"""

import os

import pytest

from radicale import config
from radicale.tests import BaseTest

HOOK_MODULE = "radicale.tests.test_hook_notify_permission"


class Hook:
    """Recording hook loaded as radicale.tests.test_hook_notify_permission."""

    events: list = []

    def __init__(self, configuration):
        self.configuration = configuration

    @property
    def enabled(self):
        return True

    def notify(self, notification_item):
        Hook.events.append(notification_item)


def _event(uid="evt-1", summary="Event", sequence=1, extra=""):
    return (
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n"
        "METHOD:PUBLISH\r\n"
        "BEGIN:VEVENT\r\nUID:%s\r\nDTSTAMP:20300101T000000Z\r\n"
        "DTSTART:20300101T110000Z\r\nDTEND:20300101T120000Z\r\n"
        "SUMMARY:%s\r\nSEQUENCE:%d\r\n"
        "ORGANIZER:mailto:owner@example.com\r\n"
        "ATTENDEE;CN=Bob:mailto:bob@example.com\r\n%s"
        "END:VEVENT\r\nEND:VCALENDAR\r\n"
        % (uid, summary, sequence, extra))


class TestNotifyPermission(BaseTest):

    def setup_method(self):
        super().setup_method()
        Hook.events = []

    def _grant(self, permissions):
        path = os.path.join(self.colpath, "rights")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "[all]\nuser: .*\ncollection: .*\npermissions: %s\n"
                % permissions)
        self.configure({
            "auth": {"type": "http_x_remote_user"},
            "rights": {"type": "from_file", "file": path},
            "server": {"delay_on_error": "0"},
            "hook": {"type": HOOK_MODULE},
        })

    def _calendar(self, name="/calendar.ics/"):
        self.request("MKCALENDAR", name, None, check=201,
                     HTTP_X_REMOTE_USER="owner")

    def test_import_account_saves_without_notifying(self):
        """The ``n`` right keeps a legal write but silences the hook."""
        self._grant("RrWwn")
        self._calendar()
        status, _, answer = self.request(
            "PUT", "/calendar.ics/event.ics", _event(), check=None,
            HTTP_X_REMOTE_USER="importer")
        assert status == 201 and answer == ""
        # The event is really stored: the import worked.
        assert "UID:evt-1" in self.get("/calendar.ics/event.ics")[1]
        assert Hook.events == []

    def test_notification_right_fires_for_a_real_change(self):
        """Without ``n`` the same legal write reports one event."""
        self._grant("RrWw")
        self._calendar()
        status, _, _ = self.request(
            "PUT", "/calendar.ics/event.ics", _event(), check=None,
            HTTP_X_REMOTE_USER="organizer")
        assert status == 201
        assert len(Hook.events) == 1
        event = Hook.events[0]
        assert event.type == "upsert"
        assert event.actor == "organizer"
        assert event.old_content is None
        assert "UID:evt-1" in event.new_content

    def test_refused_edit_saves_nothing_and_notifies_nothing(self):
        """A write the rights backend rejects never reaches the hook."""
        # The calendar exists, so the refusal is about the item write.
        self._grant("RrWw")
        self._calendar()
        self._grant("Rr")
        status, headers, answer = self.request(
            "PUT", "/calendar.ics/event.ics", _event(), check=None)
        # No remote user: the write is refused before the hook runs.
        assert status == 403 and answer
        assert Hook.events == []
        status, body = self.get("/calendar.ics/event.ics", check=404)
        assert "UID:evt-1" not in body

    def test_unchanged_retry_notifies_nothing(self):
        """Re-uploading identical content is a no-op for the hook."""
        self._grant("RrWw")
        self._calendar()
        body = _event()
        self.request("PUT", "/calendar.ics/event.ics", body, check=201,
                     HTTP_X_REMOTE_USER="organizer")
        assert len(Hook.events) == 1
        # Same bytes again: storage accepts it, the hook must not.
        self.request("PUT", "/calendar.ics/event.ics", body, check=204,
                     HTTP_X_REMOTE_USER="organizer")
        assert len(Hook.events) == 1
        # A material change on the same href does notify again.
        changed = _event(summary="Moved")
        self.request("PUT", "/calendar.ics/event.ics", changed, check=204,
                     HTTP_X_REMOTE_USER="organizer")
        assert len(Hook.events) == 2
        update = Hook.events[1]
        assert update.type == "upsert"
        assert update.old_content is not None
        assert "SUMMARY:Moved" in update.new_content

    def test_whole_collection_retry_skips_identical_items(self):
        """A no-op whole-collection PUT reports no per-item notifications."""
        self._grant("RrWw")
        body = (
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n"
            "BEGIN:VEVENT\r\nUID:one\r\nDTSTAMP:20300101T000000Z\r\n"
            "DTSTART:20300101T110000Z\r\nDTEND:20300101T120000Z\r\n"
            "SUMMARY:One\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
        self.request("PUT", "/team.ics/", body, check=None,
                     HTTP_X_REMOTE_USER="organizer")
        assert len(Hook.events) == 1
        self.request("PUT", "/team.ics/", body, check=None,
                     HTTP_X_REMOTE_USER="organizer")
        assert len(Hook.events) == 1

    def test_import_account_delete_stays_silent(self):
        """The ``n`` right also silences a legal DELETE notification."""
        self._grant("RrWwn")
        self._calendar()
        self.request("PUT", "/calendar.ics/event.ics", _event(), check=201,
                     HTTP_X_REMOTE_USER="importer")
        assert Hook.events == []
        self.delete("/calendar.ics/event.ics",
                    HTTP_X_REMOTE_USER="importer")
        assert Hook.events == []

    def test_notification_denied_on_parent_collection_right(self):
        """An ``n`` on the parent calendar also silences item writes."""
        path = os.path.join(self.colpath, "rights")
        with open(path, "w", encoding="utf-8") as handle:
            # The item's own rule has no n; the parent calendar does.
            handle.write(
                "[item]\nuser: .*\ncollection: [^/]+/[^/]+\n"
                "permissions: rw\n"
                "[calendar]\nuser: .*\ncollection: [^/]+\n"
                "permissions: rwn\n"
                "[root]\nuser: .*\ncollection: .*\n"
                "permissions: RrWw\n")
        self.configure({
            "auth": {"type": "http_x_remote_user"},
            "rights": {"type": "from_file", "file": path},
            "hook": {"type": HOOK_MODULE},
        })
        self._calendar()
        status, _, _ = self.request(
            "PUT", "/calendar.ics/event.ics", _event(), check=None,
            HTTP_X_REMOTE_USER="importer")
        assert status == 201
        assert "UID:evt-1" in self.get("/calendar.ics/event.ics")[1]
        assert Hook.events == []

    def test_authorized_cancel_keeps_series_and_emits_one_event(self):
        """A CANCEL of one occurrence with notification rights reports once.

        The recurring master stays stored alongside the CANCEL override;
        the replacement produces exactly one hook event, attributable
        to the acting account.
        """
        self._grant("RrWw")
        master_calendar = (
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n"
            "METHOD:PUBLISH\r\n"
            "BEGIN:VEVENT\r\nUID:series-1\r\nDTSTAMP:20300101T000000Z\r\n"
            "DTSTART:20300101T110000Z\r\nDTEND:20300101T120000Z\r\n"
            "RRULE:FREQ=DAILY;COUNT=5\r\nSUMMARY:Standup\r\nSEQUENCE:1\r\n"
            "ORGANIZER:mailto:owner@example.com\r\n"
            "ATTENDEE;CN=Bob:mailto:bob@example.com\r\n"
            "END:VEVENT\r\nEND:VCALENDAR\r\n")
        status, _, _ = self.request(
            "PUT", "/team.ics/", master_calendar, check=None,
            HTTP_X_REMOTE_USER="organizer")
        assert status == 201
        assert len(Hook.events) == 1
        Hook.events = []
        # Same collection, now carrying the CANCEL override as well.
        cancelled_calendar = master_calendar.replace(
            "END:VEVENT\r\nEND:VCALENDAR\r\n",
            "END:VEVENT\r\n"
            "BEGIN:VEVENT\r\nUID:series-1\r\n"
            "RECURRENCE-ID:20300102T110000Z\r\n"
            "DTSTAMP:20300101T000000Z\r\n"
            "DTSTART:20300102T110000Z\r\nDTEND:20300102T120000Z\r\n"
            "SUMMARY:Standup\r\nSEQUENCE:2\r\n"
            "ORGANIZER:mailto:owner@example.com\r\n"
            "ATTENDEE;CN=Bob:mailto:bob@example.com\r\n"
            "END:VEVENT\r\nEND:VCALENDAR\r\n").replace(
            "METHOD:PUBLISH", "METHOD:CANCEL", 1)
        status, _, _ = self.request(
            "PUT", "/team.ics/", cancelled_calendar, check=None,
            HTTP_X_REMOTE_USER="organizer")
        assert status in (201, 204)
        # The recurring master survives the occurrence cancellation.
        stored = self.get("/team.ics/")[1]
        assert "RRULE:FREQ=DAILY;COUNT=5" in stored
        assert "RECURRENCE-ID:20300102T110000Z" in stored
        assert len(Hook.events) == 1
        cancel = Hook.events[0]
        assert cancel.type == "upsert"
        assert cancel.actor == "organizer"
        assert cancel.old_content is not None
        assert "RRULE:FREQ=DAILY;COUNT=5" in cancel.old_content
        assert "RECURRENCE-ID:20300102T110000Z" in cancel.new_content


class TestNotifyPermissionValidator:
    """The config layer recognizes the new rights letter."""

    def test_n_is_a_supported_permission(self):
        assert config.rights_permission("RrWwn") == "RrWwn"

    def test_unknown_letter_is_still_rejected(self):
        with pytest.raises(ValueError, match="unsupported permission"):
            config.rights_permission("RrWwz")
