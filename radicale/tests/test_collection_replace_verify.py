# This file is part of Radicale - CalDAV and CardDAV server
# Copyright © 2026-2026 Contributors to Radicale
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

"""A verified whole-collection replacement is published only as one state.

With ``[storage] verify_collection_replace`` enabled the replacement is built
in a temporary staging area and re-checked (item format, membership in the
collection tag, unique UIDs, writability) before it replaces the old
collection. Every failure leaves the old collection, its items and its sync
token usable.
"""

import errno
import os
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple

import pytest

import radicale.item as radicale_item
from radicale import xmlutils
from radicale.tests import BaseTest
from radicale.tests.helpers import get_file_content

BOOK_PATH = "/contacts.vcf/"

SYNC_REPORT = """\
<?xml version="1.0" encoding="utf-8" ?>
<sync-collection xmlns="DAV:">
    <prop><getetag /></prop>
    <sync-token>{token}</sync-token>
</sync-collection>"""


def _vcard(uid: str, fn: str = "Ada") -> str:
    return ("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:%s\r\nFN:%s\r\n"
            "END:VCARD\r\n" % (uid, fn))


def _vevent(uid: str, summary: str = "Event") -> str:
    return (
        "BEGIN:VEVENT\r\nUID:%s\r\nDTSTAMP:20130101T000000Z\r\n"
        "DTSTART:20130901T160000Z\r\nDTEND:20130901T170000Z\r\n"
        "SUMMARY:%s\r\nEND:VEVENT\r\n" % (uid, summary))


def _calendar(*uids: str) -> str:
    events = "".join(_vevent(uid) for uid in uids)
    return ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n"
            + events + "END:VCALENDAR\r\n")


def _item(text: str, collection_path: str = "contacts.vcf"
          ) -> radicale_item.Item:
    return radicale_item.Item(collection_path=collection_path, text=text)


def _grant_write(test: BaseTest) -> None:
    rights = os.path.join(test.colpath, "rights")
    with open(rights, "w") as handle:
        handle.write("[all]\nuser: .*\ncollection: .*\n"
                     "permissions: RrWw\n")
    test.configure({
        "auth": {"type": "none"},
        "rights": {"type": "from_file", "file": rights},
    })


class TestCollectionReplaceVerify(BaseTest):

    def setup_method(self) -> None:
        super().setup_method()
        _grant_write(self)
        self.configure({"storage": {"verify_collection_replace": "True"}})

    def _storage(self):
        return self.application._storage

    def _hrefs(self, path: str) -> List[str]:
        with self._storage().acquire_lock("r", ""):
            collection = next(self._storage().discover(path))
            return sorted(collection._list())

    def _sync_token(self, path: str, old_token: Optional[str] = None
                    ) -> Tuple[str, dict]:
        token_xml = "<sync-token><![CDATA[%s]]></sync-token>" % (
            old_token or "")
        body = SYNC_REPORT.replace(
            "<sync-token>{token}</sync-token>", token_xml)
        status, _, answer = self.request("REPORT", path, body, check=207)
        assert status == 207
        root = ET.fromstring(answer)
        token = root.find(xmlutils.make_clark("D:sync-token")).text.strip()
        assert token
        return token, self.parse_responses(answer)

    def _old_book(self) -> str:
        self.create_addressbook(BOOK_PATH)
        self.put(BOOK_PATH + "old.vcf", _vcard("old-uid", "Old Contact"))
        token, _ = self._sync_token(BOOK_PATH)
        assert self._hrefs(BOOK_PATH) == ["old.vcf"]
        return token

    def test_successful_replace_publishes_one_new_state(self) -> None:
        """A valid import swaps the collection in a single published state."""
        old_token = self._old_book()

        status = self.request(
            "PUT", BOOK_PATH,
            _vcard("new-uid-1", "One") + _vcard("new-uid-2", "Two"),
            check=None)[0]
        assert status in (201, 204)

        assert self._hrefs(BOOK_PATH) == [
            "new-uid-1.vcf", "new-uid-2.vcf"]
        _, answer = self.get(BOOK_PATH + "new-uid-1.vcf")
        assert "UID:new-uid-1" in answer
        # The replacement is one new state: a fresh token describes it and is
        # stable on repeat.
        new_token, responses = self._sync_token(BOOK_PATH)
        assert new_token != old_token
        assert set(responses) == {
            BOOK_PATH + "new-uid-1.vcf", BOOK_PATH + "new-uid-2.vcf"}
        same_token, no_responses = self._sync_token(BOOK_PATH, new_token)
        assert same_token == new_token and no_responses == {}

    def test_successful_calendar_replace(self) -> None:
        """Calendar items pass the staging verification via component_name."""
        calendar_path = "/calendar.ics/"
        self.mkcalendar(calendar_path)
        self.put(calendar_path + "old.ics", _calendar("old-uid"))
        assert self._hrefs(calendar_path) == ["old.ics"]

        body = _calendar("new-uid-1", "new-uid-2")
        status = self.request("PUT", calendar_path, body, check=None)[0]
        assert status in (201, 204)

        assert self._hrefs(calendar_path) == [
            "new-uid-1.ics", "new-uid-2.ics"]
        token, responses = self._sync_token(calendar_path)
        assert set(responses) == {
            calendar_path + "new-uid-1.ics",
            calendar_path + "new-uid-2.ics"}
        same_token, no_responses = self._sync_token(calendar_path, token)
        assert same_token == token and no_responses == {}

    def test_mixed_good_and_bad_entries_are_rejected(self) -> None:
        """One bad entry in the import rejects the whole replacement."""
        old_token = self._old_book()
        mixed = _vcard("good-uid", "Good") + get_file_content(
            "broken-vcard.vcf")

        self.request("PUT", BOOK_PATH, mixed, check=400)

        assert self._hrefs(BOOK_PATH) == ["old.vcf"]
        _, answer = self.get(BOOK_PATH + "old.vcf")
        assert "UID:old-uid" in answer
        token, responses = self._sync_token(BOOK_PATH, old_token)
        assert token == old_token and responses == {}

    def test_duplicate_uid_is_rejected_before_publishing(self) -> None:
        """Two entries sharing a UID fail the staging verification."""
        old_token = self._old_book()
        duplicated = _vcard("same-uid", "First") + _vcard("same-uid",
                                                           "Second")

        self.request("PUT", BOOK_PATH, duplicated, check=400)

        assert self._hrefs(BOOK_PATH) == ["old.vcf"]
        token, responses = self._sync_token(BOOK_PATH, old_token)
        assert token == old_token and responses == {}

    def test_tag_membership_is_checked_in_storage(self) -> None:
        """A calendar entry staged into an address book is rejected."""
        event = get_file_content("event1.ics")
        with pytest.raises(ValueError, match="not supported in "
                                             "'VADDRESSBOOK' collection"):
            with self._storage().acquire_lock("w", ""):
                self._storage().create_collection(
                    BOOK_PATH, items=[_item(event)],
                    props={"tag": "VADDRESSBOOK"})
        assert not os.path.exists(os.path.join(
            self.colpath, "collection-root", "contacts.vcf"))

    def test_unreadable_staged_item_is_rejected(self, monkeypatch) -> None:
        """An item that cannot be parsed back from disk fails verification."""
        good = _item(_vcard("good-uid"))
        collection_class = type(next(self._storage().discover("/")))

        def broken_get(_self, _href, verify_href=True):
            raise ValueError("staged item is broken on disk")

        monkeypatch.setattr(collection_class, "_get", broken_get)
        with pytest.raises(ValueError, match="Failed to verify item"):
            with self._storage().acquire_lock("w", ""):
                self._storage().create_collection(
                    "/broken.vcf/", items=[good],
                    props={"tag": "VADDRESSBOOK"})

    def test_disk_write_failure_keeps_old_collection_and_token(
            self, monkeypatch) -> None:
        """A failed staging write never reaches the publication step."""
        old_token = self._old_book()
        real_open = open

        class BadFile:
            def write(self, _data):
                raise OSError(errno.EIO, "temp write")

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        def fake_open(file, mode="r", *args, **kwargs):
            name = os.fspath(file)
            if (".Radicale.tmp-" in name and "w" in mode and
                    not name.endswith(".Radicale.props")):
                return BadFile()
            return real_open(file, mode, *args, **kwargs)

        monkeypatch.setattr("builtins.open", fake_open)
        with pytest.raises(ValueError, match="temporary collection"):
            with self._storage().acquire_lock("w", ""):
                self._storage().create_collection(
                    BOOK_PATH, items=[_item(_vcard("new-uid"))],
                    props={"tag": "VADDRESSBOOK"})

        assert self._hrefs(BOOK_PATH) == ["old.vcf"]
        _, answer = self.get(BOOK_PATH + "old.vcf")
        assert "UID:old-uid" in answer
        token, responses = self._sync_token(BOOK_PATH, old_token)
        assert token == old_token and responses == {}

    def test_rename_failure_keeps_old_collection(self, monkeypatch) -> None:
        """A failure while publishing the verified staging area rolls back."""
        self._old_book()

        def boom(_src, _dst):
            raise OSError(errno.EIO, "rename failed")

        monkeypatch.setattr(
            "radicale.storage.multifilesystem.create_collection."
            "pathutils.rename_exchange", boom)
        with pytest.raises(ValueError, match="Failed to create collection"):
            with self._storage().acquire_lock("w", ""):
                self._storage().create_collection(
                    BOOK_PATH, items=[_item(_vcard("new-uid"))],
                    props={"tag": "VADDRESSBOOK"})

        assert self._hrefs(BOOK_PATH) == ["old.vcf"]


class TestCollectionReplaceVerifyDisabled(BaseTest):

    def setup_method(self) -> None:
        super().setup_method()
        _grant_write(self)

    def test_duplicate_uid_is_published_without_verification(self) -> None:
        """Without the option the historical behavior stays in effect."""
        storage_ = self.application._storage
        with storage_.acquire_lock("w", ""):
            storage_.create_collection(
                BOOK_PATH, items=[_item(_vcard("same-uid", "First")),
                                  _item(_vcard("same-uid", "Second"))],
                props={"tag": "VADDRESSBOOK"})
        collection = next(storage_.discover(BOOK_PATH))
        hrefs = list(collection._list())
        # Both entries are kept, even though they share one UID.
        assert len(hrefs) == 2
        for href in hrefs:
            item = collection._get(href, verify_href=False)
            assert item is not None and item.uid == "same-uid"
