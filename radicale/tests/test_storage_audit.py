# This file is part of Radicale - CalDAV and CardDAV server
# Copyright © 2026-2026 Radicale audit contributors
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

"""Tests for the read-only handover audit of multifilesystem storage."""

import builtins
import json
import os
import pickle

import pytest

from radicale import config
from radicale import item as radicale_item
from radicale import storage
from radicale.storage.multifilesystem import audit


def _event(uid: str, summary: str = "Event") -> radicale_item.Item:
    text = (
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//audit//\r\n"
        "BEGIN:VEVENT\r\nUID:%s\r\nSUMMARY:%s\r\n"
        "DTSTART:20130901T160000Z\r\nDTEND:20130901T170000Z\r\n"
        "END:VEVENT\r\nEND:VCALENDAR\r\n" % (uid, summary))
    return radicale_item.Item(collection_path="", text=text)


def _storage(folder, **options):
    configuration = config.load()
    settings = {"filesystem_folder": str(folder), "filesystem_fsync": False}
    settings.update(options)
    configuration.update({"storage": settings}, "test", privileged=True)
    return storage.load(configuration)


def _build_storage(folder):
    storage_ = _storage(folder)
    with storage_.acquire_lock("w"):
        collection = storage_.create_collection(
            "/user/cal/",
            items=[_event("event1"), _event("event2", "Second")],
            props={"tag": "VCALENDAR"})[0]
        collection.sync()
        storage_.create_collection(
            "/user/abook/", items=[], props={"tag": "VADDRESSBOOK"})
    return storage_


def _collection_root(folder):
    return os.path.join(str(folder), "collection-root", "user", "cal")


def _item_cache(folder, href):
    return os.path.join(
        _collection_root(folder), ".Radicale.cache", "item", href)


def _verdict_map(report):
    return {entry["path"]: entry["verdict"] for entry in report["entries"]}


def test_clean_storage_is_fully_verified(tmp_path):
    _build_storage(tmp_path)
    report = audit.audit_storage(str(tmp_path))
    verdicts = set(report["summary"]["verdicts"])
    assert verdicts == {"original-verified", "cache-valid"}
    assert report["summary"]["uncertain_objects"] == 0
    assert report["evidence"]["drift"] == []
    # before/after evidence snapshots describe the same tree
    assert report["evidence"]["before"] == report["evidence"]["after"]
    # every recorded file carries permission evidence
    for entry in report["entries"]:
        assert isinstance(entry["mode"], int)


def test_report_is_deterministic_across_traversal_order(tmp_path, monkeypatch):
    _build_storage(tmp_path)
    reference = audit.audit_storage(str(tmp_path))
    reference_json = json.dumps(reference, sort_keys=True)

    real_scandir = os.scandir

    class ReversedScandir:
        def __init__(self, path):
            with real_scandir(path) as entries:
                self._entries = list(reversed(list(entries)))
            self._index = 0

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def __iter__(self):
            return self

        def __next__(self):
            if self._index >= len(self._entries):
                raise StopIteration
            entry = self._entries[self._index]
            self._index += 1
            return entry

    def reversed_scandir(path):
        return ReversedScandir(path)

    monkeypatch.setattr(audit.os, "scandir", reversed_scandir)
    reordered = audit.audit_storage(str(tmp_path))
    assert json.dumps(reordered, sort_keys=True) == reference_json
    # entries are sorted by path, so the order is part of the contract
    paths = [entry["path"] for entry in reordered["entries"]]
    assert paths == sorted(paths)


def test_missing_cache_is_distinct_from_changed_original(tmp_path):
    _build_storage(tmp_path)
    os.remove(_item_cache(tmp_path, "event1.ics"))
    changed = os.path.join(_collection_root(tmp_path), "event2.ics")
    with open(changed, "ab") as handle:
        handle.write(b"X-TAMPERED: yes\r\n")

    report = audit.audit_storage(str(tmp_path))
    verdicts = _verdict_map(report)
    missing_path = os.path.join(
        "collection-root", "user", "cal", "event1.ics")
    changed_path = os.path.join(
        "collection-root", "user", "cal", "event2.ics")
    assert verdicts[missing_path] == audit.ORIGINAL_CACHE_MISSING
    assert verdicts[changed_path] == audit.ORIGINAL_CACHE_STALE
    # the stale original and its cache entry describe the same mismatch
    cache_entry = next(
        entry for entry in report["entries"]
        if entry["path"].endswith(os.path.join("item", "event2.ics")))
    assert cache_entry["verdict"] == audit.CACHE_STALE
    # a missing cache is itself a firm conclusion, not an uncertain one
    missing_entry = next(
        entry for entry in report["entries"]
        if entry["path"] == missing_path)
    assert missing_entry["uncertain"] is False


def test_damaged_cache_and_orphan_cache_are_unconfirmed(tmp_path):
    _build_storage(tmp_path)
    original = os.path.join(_collection_root(tmp_path), "event3.ics")
    with open(original, "wb") as handle:
        handle.write(
            b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n")
    damaged_cache = _item_cache(tmp_path, "event3.ics")
    with open(damaged_cache, "wb") as handle:
        handle.write(b"not a pickle")
    orphan_cache = _item_cache(tmp_path, "ghost.ics")
    with open(orphan_cache, "wb") as handle:
        pickle.dump(("deadbeef",), handle)

    report = audit.audit_storage(str(tmp_path))
    verdicts = _verdict_map(report)
    damaged_original = os.path.join(
        "collection-root", "user", "cal", "event3.ics")
    assert verdicts[damaged_original] == audit.ORIGINAL_CACHE_DAMAGED
    assert verdicts[orphan_cache.replace(
        str(tmp_path) + os.sep, "").replace(os.sep, "/")] == (
        audit.CACHE_ORPHAN)
    uncertain = {entry["path"] for entry in report["entries"]
                 if entry["uncertain"]}
    assert damaged_original in uncertain
    assert any(path.endswith(os.path.join("item", "ghost.ics"))
               for path in uncertain)


def test_unknown_and_unsafe_names_are_unconfirmed(tmp_path):
    _build_storage(tmp_path)
    stray = os.path.join(_collection_root(tmp_path), "stray.txt")
    with open(stray, "w") as handle:
        handle.write("unexpected")
    tilde = os.path.join(_collection_root(tmp_path), "backup~")
    with open(tilde, "w") as handle:
        handle.write("unsafe component")

    report = audit.audit_storage(str(tmp_path))
    verdicts = _verdict_map(report)
    assert any(value == audit.UNKNOWN_OBJECT
               for value in verdicts.values())
    assert any(value == audit.UNSAFE_NAME for value in verdicts.values())
    assert report["summary"]["categories"]["unconfirmed"] >= 2


def test_original_replaced_during_scan_is_uncertain(tmp_path, monkeypatch):
    _build_storage(tmp_path)
    target = os.path.join(_collection_root(tmp_path), "event2.ics")
    real_open = builtins.open
    reads = {"count": 0}

    def swapping_open(path, *args, **kwargs):
        handle = real_open(path, *args, **kwargs)
        mode = args[0] if args else kwargs.get("mode", "r")
        if "r" in mode and os.path.abspath(str(path)) == os.path.abspath(
                target):
            reads["count"] += 1
            # The pre-scan snapshot is read #1; swap before the audit's
            # own first observation so the two observations differ.
            if reads["count"] == 2:
                replacement = target + ".new"
                with real_open(replacement, "wb") as out:
                    out.write(
                        b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nX-NEW:1\r\n"
                        b"END:VCALENDAR\r\n")
                os.replace(replacement, target)
        return handle

    monkeypatch.setattr(builtins, "open", swapping_open)
    report = audit.audit_storage(str(tmp_path))
    entry = next(
        entry for entry in report["entries"]
        if entry["path"].endswith(os.path.join("cal", "event2.ics"))
        and entry["category"] == "original")
    assert entry["verdict"] == audit.ORIGINAL_REPLACED_DURING_SCAN
    assert entry["uncertain"] is True
    drift_paths = {change["path"] for change in report["evidence"]["drift"]}
    assert any(path.endswith(os.path.join("cal", "event2.ics"))
               for path in drift_paths)


def test_evidence_snapshot_detects_post_scan_permission_change(tmp_path,
                                                               monkeypatch):
    _build_storage(tmp_path)
    target = os.path.join(_collection_root(tmp_path), "event1.ics")
    original_mode = os.stat(target).st_mode
    real_take_snapshot = audit._take_snapshot
    calls = {"count": 0}

    def snapshot_then_chmod(root):
        result = real_take_snapshot(root)
        calls["count"] += 1
        # Flip the permission bits only after the before-snapshot so the
        # same audit run observes a modification in its after-snapshot.
        if calls["count"] == 1:
            os.chmod(target, 0o600)
        return result

    monkeypatch.setattr(audit, "_take_snapshot", snapshot_then_chmod)
    try:
        report = audit.audit_storage(str(tmp_path))
    finally:
        os.chmod(target, original_mode)
    drift = report["evidence"]["drift"]
    assert any(change["change"] == "modified"
               and change["path"].endswith(
                   os.path.join("cal", "event1.ics"))
               for change in drift)
    before_modes = {
        entry["path"]: entry["signature"]["mode"]
        for entry in report["evidence"]["before"]
        if entry["type"] == "file"}
    after_modes = {
        entry["path"]: entry["signature"]["mode"]
        for entry in report["evidence"]["after"]
        if entry["type"] == "file"}
    changed_path = next(
        path for path in after_modes
        if path.endswith(os.path.join("cal", "event1.ics")))
    assert after_modes[changed_path] == 0o600
    assert before_modes[changed_path] != 0o600


def test_mtime_and_size_scheme_uses_stat_hash(tmp_path):
    storage_ = _storage(tmp_path, use_mtime_and_size_for_item_cache=True)
    with storage_.acquire_lock("w"):
        storage_.create_collection(
            "/user/cal/", items=[_event("m1")],
            props={"tag": "VCALENDAR"})
    report = audit.audit_storage(
        str(tmp_path), use_mtime_and_size=True)
    assert report["evidence"]["cache_hash_scheme"] == "mtime-and-size"
    verdicts = set(report["summary"]["verdicts"])
    assert "original-verified" in verdicts
    # the stored hash is the mtime/size string, not a sha256 hex digest
    original_entry = next(
        entry for entry in report["entries"]
        if entry["path"].endswith("m1.ics") and entry["category"] == "original")
    assert original_entry["stored_cache_hash"].startswith(
        storage.CACHE_VERSION.decode())


def test_cache_replaced_during_scan_is_uncertain(tmp_path, monkeypatch):
    _build_storage(tmp_path)
    target = _item_cache(tmp_path, "event1.ics")
    real_open = builtins.open
    reads = {"count": 0}

    def swapping_open(path, *args, **kwargs):
        handle = real_open(path, *args, **kwargs)
        mode = args[0] if args else kwargs.get("mode", "r")
        if "r" in mode and os.path.abspath(str(path)) == os.path.abspath(
                target):
            reads["count"] += 1
            # Snapshot reads happen first; swap at the audit's first read.
            if reads["count"] == 3:
                replacement = target + ".new"
                with real_open(replacement, "wb") as out:
                    out.write(b"x" * 32)
                os.replace(replacement, target)
        return handle

    monkeypatch.setattr(builtins, "open", swapping_open)
    report = audit.audit_storage(str(tmp_path))
    entry = next(
        entry for entry in report["entries"]
        if entry["path"].endswith(os.path.join("item", "event1.ics")))
    assert entry["verdict"] == audit.CACHE_REPLACED_DURING_SCAN
    assert entry["uncertain"] is True


def test_text_report_lists_all_verdicts(tmp_path):
    _build_storage(tmp_path)
    report = audit.audit_storage(str(tmp_path))
    text = audit.render_text_report(report)
    assert text.startswith("# Radicale storage handover audit")
    assert "## objects" in text
    assert "## evidence drift" in text
    assert "(none)" in text


def test_json_report_is_serializable_and_stable(tmp_path):
    _build_storage(tmp_path)
    report = audit.audit_storage(str(tmp_path))
    first = json.dumps(report, indent=2, sort_keys=True)
    second = json.dumps(report, indent=2, sort_keys=True)
    assert first == second
    # round-trip keeps every verdict
    decoded = json.loads(first)
    assert len(decoded["entries"]) == report["summary"]["total_objects"]


def test_nonexistent_root_is_rejected(tmp_path):
    missing = os.path.join(str(tmp_path), "does-not-exist")
    with pytest.raises(FileNotFoundError):
        audit.audit_storage(missing)


def test_external_collection_cache_is_mirrored(tmp_path):
    store = tmp_path
    collection = os.path.join(
        store, "collection-root", "u", "c")
    os.makedirs(collection)
    with open(os.path.join(collection, ".Radicale.props"), "w") as handle:
        handle.write('{"tag": "VCALENDAR"}')
    raw = b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n"
    with open(os.path.join(collection, "e.ics"), "wb") as handle:
        handle.write(raw)
    cache_root = os.path.join(store, "collection-cache")
    item_dir = os.path.join(
        cache_root, "u", "c", ".Radicale.cache", "item")
    os.makedirs(item_dir)
    cache_hash = audit.item_cache_hash(raw)
    with open(os.path.join(item_dir, "e.ics"), "wb") as handle:
        pickle.dump((cache_hash, "uid", '"etag"', "text", "VCALENDAR",
                     "VEVENT", 0, 0), handle)

    report = audit.audit_storage(str(store), cache_root=str(cache_root))
    original_entry = next(
        entry for entry in report["entries"]
        if entry["path"].endswith(os.path.join("u", "c", "e.ics")))
    assert original_entry["verdict"] == audit.ORIGINAL_VERIFIED
    cache_entry = next(
        entry for entry in report["entries"]
        if entry["category"] == "cache")
    assert cache_entry["verdict"] == audit.CACHE_VALID
    assert report["evidence"]["external_cache"]["root"] == str(
        cache_root)


def test_unreadable_original_is_unconfirmed(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root bypasses permission bits")
    _build_storage(tmp_path)
    target = os.path.join(_collection_root(tmp_path), "event1.ics")
    os.chmod(target, 0)
    try:
        report = audit.audit_storage(str(tmp_path))
    finally:
        os.chmod(target, 0o600)
    entry = next(
        entry for entry in report["entries"]
        if entry["path"].endswith(os.path.join("cal", "event1.ics"))
        and entry["category"] == "original")
    assert entry["verdict"] == audit.ORIGINAL_UNREADABLE
    assert entry["uncertain"] is True
    assert report["evidence"]["unreadable"]


def test_symlink_item_is_reported_as_unconfirmed(tmp_path):
    _build_storage(tmp_path)
    target = os.path.join(_collection_root(tmp_path), "event1.ics")
    link = os.path.join(_collection_root(tmp_path), "linked.ics")
    os.symlink(target, link)
    report = audit.audit_storage(str(tmp_path))
    entry = next(
        entry for entry in report["entries"]
        if entry["path"].endswith("linked.ics"))
    assert entry["verdict"] == audit.UNKNOWN_OBJECT
    assert entry["uncertain"] is True


def test_audit_does_not_write_into_the_storage_tree(tmp_path, monkeypatch):
    _build_storage(tmp_path)
    real_open = builtins.open

    def deny_write(path, *args, **kwargs):
        mode = args[0] if args else kwargs.get("mode", "r")
        if any(flag in mode for flag in ("w", "a", "x")):
            raise AssertionError("audit opened %r for writing" % path)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", deny_write)
    report = audit.audit_storage(str(tmp_path))
    assert report["summary"]["uncertain_objects"] == 0
