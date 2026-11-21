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

"""MOVE permission regressions for source and target calendars.

Every case starts from its own local calendars. A denied MOVE must leave
both calendars and their sync markers untouched, while a successful MOVE
must update both sides. ``storage.move`` is observed so a status code
alone cannot hide a handler that returns before the storage operation.
"""

import errno
import json
import os

from radicale.storage.multifilesystem import move as storage_move
from radicale.tests import BaseTest
from radicale.tests.helpers import get_file_content

PROPFIND_SYNC_TOKEN = """\
<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop><D:sync-token /></D:prop>
</D:propfind>"""

SYNC_REPORT = """\
<?xml version="1.0" encoding="utf-8" ?>
<sync-collection xmlns="DAV:">
  <prop><getetag /></prop>
  <sync-token><![CDATA[%s]]></sync-token>
</sync-collection>"""

NOT_ALLOWED_BODY = "Access to the requested resource forbidden."
PRECONDITION_FAILED_BODY = "Precondition failed."
INTERNAL_SERVER_ERROR_BODY = (
    "A server error occurred.  Please contact the administrator.")


class TestMovePermissions(BaseTest):

    def setup_method(self) -> None:
        super().setup_method()
        htpasswd = os.path.join(self.colpath, ".htpasswd")
        with open(htpasswd, "w", encoding="utf-8") as handle:
            handle.write("alice:alicepw\nbob:bobpw\n")
        self.configure({
            "auth": {"type": "htpasswd",
                     "htpasswd_filename": htpasswd,
                     "htpasswd_encryption": "plain",
                     "delay": "0"},
            "rights": {"type": "owner_only"},
            "sharing": {"type": "csv",
                        "collection_by_map": "True",
                        "permit_create_map": "True"},
            "server": {"delay_on_error": "0"},
        })

    def _map_share(self, owner: str, user: str, path_mapped: str,
                   path_token: str, permissions: str) -> None:
        payload = {
            "User": user,
            "PathMapped": path_mapped,
            "PathOrToken": path_token,
            "Permissions": permissions,
            "Enabled": True,
            "Hidden": False,
        }
        status, _, body = self.request(
            "POST", "/.sharing/v1/map/create", json.dumps(payload),
            login=owner, content_type="application/json",
            accept="application/json", check=None)
        assert status == 200, body
        for login in (owner, "%s:%spw" % (user, user)):
            status, _, body = self.request(
                "POST", "/.sharing/v1/map/enable",
                json.dumps({"PathOrToken": path_token}),
                login=login, content_type="application/json",
                accept="application/json", check=None)
            assert status == 200, body

    def _sync_token(self, path: str, login: str) -> str:
        status, responses = self.propfind(
            path, PROPFIND_SYNC_TOKEN, login=login)
        assert status == 207
        response = responses[path]
        assert not isinstance(response, int)
        status, token = response["D:sync-token"]
        assert status == 200 and token.text
        return token.text

    def _sync_changes(self, path: str, token: str, login: str) -> dict:
        status, responses = self.report(path, SYNC_REPORT % token, login=login)
        assert status == 207
        changes = {}
        for href, response in responses.items():
            if isinstance(response, int):
                changes[href] = response
                continue
            status, prop = response["D:getetag"]
            assert status == 200 and prop.text
            changes[href] = 200
        return changes

    def _assert_sync_unchanged(self, path: str, token: str,
                               login: str) -> None:
        assert self._sync_token(path, login) == token
        assert self._sync_changes(path, token, login) == {}

    def _record_move(self, monkeypatch) -> list:
        calls = []
        original = self.application._storage.move

        def record(item, to_collection, to_href):
            calls.append((item.href, to_collection.path, to_href))
            return original(item, to_collection, to_href)

        monkeypatch.setattr(self.application._storage, "move", record)
        return calls

    def _get_etag(self, path: str, login: str) -> str:
        status, headers, _ = self.request("GET", path, login=login)
        assert status == 200
        return headers["ETag"]

    def test_move_from_source_without_write_permission(self, monkeypatch):
        """A readable source share grants no MOVE right to the recipient."""
        self.mkcalendar("/bob/source.ics/", login="bob:bobpw")
        self.put("/bob/source.ics/event1.ics", get_file_content("event1.ics"),
                 login="bob:bobpw")
        self.mkcalendar("/alice/target.ics/", login="alice:alicepw")
        self.put("/alice/target.ics/event2.ics", get_file_content("event2.ics"),
                 login="alice:alicepw")
        self._map_share("bob:bobpw", "alice", "/bob/source.ics/",
                        "/alice/source-read.ics/", "r")

        # Control: the same target accepts a create from a writable source.
        self.request(
            "MOVE", "/alice/target.ics/event2.ics", check=201,
            login="alice:alicepw",
            HTTP_DESTINATION="http://127.0.0.1/alice/target.ics/control.ics")

        source_token = self._sync_token("/bob/source.ics/", "bob:bobpw")
        target_token = self._sync_token("/alice/target.ics/", "alice:alicepw")
        move_calls = self._record_move(monkeypatch)

        status, _, body = self.request(
            "MOVE", "/alice/source-read.ics/event1.ics", check=None,
            login="alice:alicepw",
            HTTP_DESTINATION="http://127.0.0.1/alice/target.ics/stolen.ics")

        assert status == 403
        assert body == NOT_ALLOWED_BODY
        assert move_calls == []

        # The source permission is rejected before the source is looked up,
        # so a missing name under the share is not reported as 404.
        status, _, body = self.request(
            "MOVE", "/alice/source-read.ics/missing.ics", check=None,
            login="alice:alicepw",
            HTTP_DESTINATION=(
                "http://127.0.0.1/alice/target.ics/missing.ics"))
        assert status == 403
        assert body == NOT_ALLOWED_BODY
        assert move_calls == []

        self.get("/bob/source.ics/event1.ics", login="bob:bobpw")
        self.get("/alice/source-read.ics/event1.ics", login="alice:alicepw")
        self.get("/alice/target.ics/stolen.ics", check=404,
                 login="alice:alicepw")
        self.get("/alice/target.ics/control.ics", login="alice:alicepw")
        self._assert_sync_unchanged("/bob/source.ics/", source_token,
                                    "bob:bobpw")
        self._assert_sync_unchanged("/alice/target.ics/", target_token,
                                    "alice:alicepw")

    def test_move_into_read_only_shared_target(self, monkeypatch):
        """A readable target share grants no write right to the recipient."""
        self.mkcalendar("/alice/source.ics/", login="alice:alicepw")
        self.put("/alice/source.ics/event1.ics", get_file_content("event1.ics"),
                 login="alice:alicepw")
        self.mkcalendar("/bob/target.ics/", login="bob:bobpw")
        self.put("/bob/target.ics/event2.ics", get_file_content("event2.ics"),
                 login="bob:bobpw")
        self._map_share("bob:bobpw", "alice", "/bob/target.ics/",
                        "/alice/target-read.ics/", "r")

        source_token = self._sync_token("/alice/source.ics/", "alice:alicepw")
        target_token = self._sync_token("/bob/target.ics/", "bob:bobpw")
        move_calls = self._record_move(monkeypatch)

        status, _, body = self.request(
            "MOVE", "/alice/source.ics/event1.ics", check=None,
            login="alice:alicepw",
            HTTP_DESTINATION="http://127.0.0.1/alice/target-read.ics/event1.ics")

        assert status == 403
        assert body == NOT_ALLOWED_BODY
        assert move_calls == []

        # The target permission is rejected before the source is looked up,
        # so a missing source name is not reported as 404.
        status, _, body = self.request(
            "MOVE", "/alice/source.ics/missing.ics", check=None,
            login="alice:alicepw",
            HTTP_DESTINATION=(
                "http://127.0.0.1/alice/target-read.ics/missing.ics"))
        assert status == 403
        assert body == NOT_ALLOWED_BODY
        assert move_calls == []

        self.get("/alice/source.ics/event1.ics", login="alice:alicepw")
        self.get("/bob/target.ics/event1.ics", check=404, login="bob:bobpw")
        self.get("/bob/target.ics/event2.ics", login="bob:bobpw")
        self._assert_sync_unchanged("/alice/source.ics/", source_token,
                                    "alice:alicepw")
        self._assert_sync_unchanged("/bob/target.ics/", target_token,
                                    "bob:bobpw")

    def test_move_target_allows_create_but_not_overwrite(self, monkeypatch):
        """A writable target still refuses to replace an existing member."""
        self.mkcalendar("/alice/source.ics/", login="alice:alicepw")
        self.put("/alice/source.ics/event1.ics", get_file_content("event1.ics"),
                 login="alice:alicepw")
        self.mkcalendar("/alice/target.ics/", login="alice:alicepw")

        # Control: creating a new member in the target is allowed.
        self.request(
            "MOVE", "/alice/source.ics/event1.ics", check=201,
            login="alice:alicepw",
            HTTP_DESTINATION="http://127.0.0.1/alice/target.ics/created.ics")

        self.put("/alice/source.ics/attempt.ics",
                 get_file_content("event2.ics"), login="alice:alicepw")
        self.put("/alice/target.ics/occupied.ics",
                 get_file_content("event2.ics"), login="alice:alicepw")
        source_etag = self._get_etag("/alice/source.ics/attempt.ics",
                                     "alice:alicepw")
        target_etag = self._get_etag("/alice/target.ics/occupied.ics",
                                     "alice:alicepw")
        source_token = self._sync_token("/alice/source.ics/", "alice:alicepw")
        target_token = self._sync_token("/alice/target.ics/", "alice:alicepw")
        move_calls = self._record_move(monkeypatch)

        status, _, body = self.request(
            "MOVE", "/alice/source.ics/attempt.ics", check=None,
            login="alice:alicepw",
            HTTP_DESTINATION="http://127.0.0.1/alice/target.ics/occupied.ics")

        assert status == 412
        assert body == PRECONDITION_FAILED_BODY
        assert move_calls == []
        self.get("/alice/source.ics/attempt.ics", login="alice:alicepw")
        self.get("/alice/target.ics/occupied.ics", login="alice:alicepw")
        self.get("/alice/target.ics/attempt.ics", check=404,
                 login="alice:alicepw")
        assert self._get_etag("/alice/source.ics/attempt.ics",
                              "alice:alicepw") == source_etag
        assert self._get_etag("/alice/target.ics/occupied.ics",
                              "alice:alicepw") == target_etag
        self._assert_sync_unchanged("/alice/source.ics/", source_token,
                                    "alice:alicepw")
        self._assert_sync_unchanged("/alice/target.ics/", target_token,
                                    "alice:alicepw")

    def test_move_write_failure_leaves_both_sides_unchanged(self, monkeypatch):
        """A storage write failure must not report or persist a move."""
        self.mkcalendar("/alice/source.ics/", login="alice:alicepw")
        self.put("/alice/source.ics/event1.ics", get_file_content("event1.ics"),
                 login="alice:alicepw")
        self.mkcalendar("/alice/target.ics/", login="alice:alicepw")
        source_etag = self._get_etag("/alice/source.ics/event1.ics",
                                     "alice:alicepw")
        source_token = self._sync_token("/alice/source.ics/", "alice:alicepw")
        target_token = self._sync_token("/alice/target.ics/", "alice:alicepw")

        replace_calls = []

        def failing_replace(source, destination):
            replace_calls.append((source, destination))
            raise OSError(errno.EIO, "simulated write failure")

        with monkeypatch.context() as patch:
            patch.setattr(storage_move.os, "replace", failing_replace)
            status, _, body = self.request(
                "MOVE", "/alice/source.ics/event1.ics", check=None,
                login="alice:alicepw",
                HTTP_DESTINATION="http://127.0.0.1/alice/target.ics/event1.ics")

        assert status == 500
        assert body == INTERNAL_SERVER_ERROR_BODY
        assert len(replace_calls) == 1
        assert self._get_etag("/alice/source.ics/event1.ics",
                              "alice:alicepw") == source_etag
        self.get("/alice/target.ics/event1.ics", check=404,
                 login="alice:alicepw")
        self._assert_sync_unchanged("/alice/source.ics/", source_token,
                                    "alice:alicepw")
        self._assert_sync_unchanged("/alice/target.ics/", target_token,
                                    "alice:alicepw")

    def test_move_between_own_calendars(self, monkeypatch):
        """A normal move updates both calendars and keeps the item content."""
        self.mkcalendar("/alice/source.ics/", login="alice:alicepw")
        self.mkcalendar("/alice/target.ics/", login="alice:alicepw")
        self.put("/alice/source.ics/event1.ics", get_file_content("event1.ics"),
                 login="alice:alicepw")
        self.put("/alice/source.ics/event2.ics", get_file_content("event2.ics"),
                 login="alice:alicepw")
        self.put("/alice/target.ics/keep.ics", get_file_content("event2.ics"),
                 login="alice:alicepw")
        source_etag = self._get_etag("/alice/source.ics/event1.ics",
                                     "alice:alicepw")
        source_token = self._sync_token("/alice/source.ics/", "alice:alicepw")
        target_token = self._sync_token("/alice/target.ics/", "alice:alicepw")
        move_calls = self._record_move(monkeypatch)

        status, _, body = self.request(
            "MOVE", "/alice/source.ics/event1.ics", check=None,
            login="alice:alicepw",
            HTTP_DESTINATION="http://127.0.0.1/alice/target.ics/event1.ics")

        assert status == 201
        assert body == ""
        assert len(move_calls) == 1
        href, collection_path, to_href = move_calls[0]
        assert href == "event1.ics"
        assert to_href == "event1.ics"
        assert collection_path == "alice/target.ics"
        self.get("/alice/source.ics/event1.ics", check=404,
                 login="alice:alicepw")
        self.get("/alice/source.ics/event2.ics", login="alice:alicepw")
        self.get("/alice/target.ics/keep.ics", login="alice:alicepw")
        _, answer = self.get("/alice/target.ics/event1.ics",
                             login="alice:alicepw")
        assert "UID:event1" in answer
        assert self._get_etag("/alice/target.ics/event1.ics",
                              "alice:alicepw") == source_etag

        source_token_after = self._sync_token("/alice/source.ics/",
                                              "alice:alicepw")
        target_token_after = self._sync_token("/alice/target.ics/",
                                              "alice:alicepw")
        assert source_token_after != source_token
        assert target_token_after != target_token
        assert self._sync_changes("/alice/source.ics/", source_token,
                                  "alice:alicepw") == {
            "/alice/source.ics/event1.ics": 404}
        assert self._sync_changes("/alice/target.ics/", target_token,
                                  "alice:alicepw") == {
            "/alice/target.ics/event1.ics": 200}

    def test_move_into_authorized_shared_calendar(self, monkeypatch):
        """An authorized share exposes the real target on both sides."""
        self.mkcalendar("/bob/target.ics/", login="bob:bobpw")
        self.put("/bob/target.ics/keep.ics", get_file_content("event2.ics"),
                 login="bob:bobpw")
        self.mkcalendar("/alice/source.ics/", login="alice:alicepw")
        self.put("/alice/source.ics/event1.ics", get_file_content("event1.ics"),
                 login="alice:alicepw")
        self._map_share("bob:bobpw", "alice", "/bob/target.ics/",
                        "/alice/from-bob.ics/", "rw")

        source_etag = self._get_etag("/alice/source.ics/event1.ics",
                                     "alice:alicepw")
        source_token = self._sync_token("/alice/source.ics/", "alice:alicepw")
        target_token = self._sync_token("/bob/target.ics/", "bob:bobpw")
        shared_token = self._sync_token("/alice/from-bob.ics/",
                                        "alice:alicepw")
        assert shared_token == target_token
        move_calls = self._record_move(monkeypatch)

        status, _, body = self.request(
            "MOVE", "/alice/source.ics/event1.ics", check=None,
            login="alice:alicepw",
            HTTP_DESTINATION="http://127.0.0.1/alice/from-bob.ics/event1.ics")

        assert status == 201
        assert body == ""
        assert len(move_calls) == 1
        _, collection_path, to_href = move_calls[0]
        assert to_href == "event1.ics"
        assert collection_path == "bob/target.ics"
        self.get("/alice/source.ics/event1.ics", check=404,
                 login="alice:alicepw")
        self.get("/bob/target.ics/keep.ics", login="bob:bobpw")
        _, owner_answer = self.get("/bob/target.ics/event1.ics",
                                   login="bob:bobpw")
        assert "UID:event1" in owner_answer
        _, shared_answer = self.get("/alice/from-bob.ics/event1.ics",
                                    login="alice:alicepw")
        assert "UID:event1" in shared_answer
        assert self._get_etag("/bob/target.ics/event1.ics",
                              "bob:bobpw") == source_etag

        source_token_after = self._sync_token("/alice/source.ics/",
                                              "alice:alicepw")
        target_token_after = self._sync_token("/bob/target.ics/", "bob:bobpw")
        shared_token_after = self._sync_token("/alice/from-bob.ics/",
                                              "alice:alicepw")
        assert source_token_after != source_token
        assert target_token_after != target_token
        assert shared_token_after == target_token_after
        assert self._sync_changes("/alice/source.ics/", source_token,
                                  "alice:alicepw") == {
            "/alice/source.ics/event1.ics": 404}
        assert self._sync_changes("/bob/target.ics/", target_token,
                                  "bob:bobpw") == {
            "/bob/target.ics/event1.ics": 200}
        assert self._sync_changes("/alice/from-bob.ics/", shared_token,
                                  "alice:alicepw") == {
            "/alice/from-bob.ics/event1.ics": 200}
