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

"""Read-only handover audit of a multifilesystem storage copy.

The audit never writes to the audited tree.  It classifies every on-disk
object as an original calendar object, a derived cache object or an object
whose state cannot be confirmed, and records one deterministic verdict per
object so that two runs against the same fixture produce the same
comparable output even when the traversal order changes.

Verdicts distinguish "the derived cache is missing" from "the original file
changed".  Anything observed changing while the scan is running is reported
as uncertain instead of being given a clean verdict.
"""

import hashlib
import json
import os
import pickle
import stat
from typing import Any, Dict, List, Optional, Tuple

from radicale import pathutils, storage
from radicale.storage.multifilesystem.cache import CollectionPartCache

# On-disk layout names used by the multifilesystem backend.
PROPS_NAME = ".Radicale.props"
CACHE_DIR_NAME = ".Radicale.cache"
ITEM_CACHE = "item"
HISTORY_CACHE = "history"
SYNC_TOKEN_CACHE = "sync-token"
ITEM_SUFFIXES = (".ics", ".vcf")

# Stable verdict vocabulary.  Keep these strings out of localisation layers:
# they are part of the handover evidence format.
#
# Original objects.
ORIGINAL_VERIFIED = "original-verified"
ORIGINAL_CACHE_MISSING = "original-cache-missing"
ORIGINAL_CACHE_STALE = "original-cache-stale"
ORIGINAL_CACHE_DAMAGED = "original-cache-damaged"
ORIGINAL_UNREADABLE = "original-unreadable"
ORIGINAL_REPLACED_DURING_SCAN = "original-replaced-during-scan"
# Derived cache objects.
CACHE_VALID = "cache-valid"
CACHE_STALE = "cache-stale"
CACHE_DAMAGED = "cache-damaged"
CACHE_ORPHAN = "cache-orphan"
CACHE_REPLACED_DURING_SCAN = "cache-replaced-during-scan"
# Objects whose state cannot be confirmed.
UNKNOWN_OBJECT = "unknown-object"
UNSAFE_NAME = "unsafe-name"
COLLECTION_PROPS_INVALID = "collection-props-invalid"
COLLECTION_PROPS_REPLACED = "collection-props-replaced-during-scan"

ORIGINAL_VERDICTS = frozenset((
    ORIGINAL_VERIFIED, ORIGINAL_CACHE_MISSING, ORIGINAL_CACHE_STALE,
    ORIGINAL_CACHE_DAMAGED, ORIGINAL_UNREADABLE,
    ORIGINAL_REPLACED_DURING_SCAN))
CACHE_VERDICTS = frozenset((
    CACHE_VALID, CACHE_STALE, CACHE_DAMAGED, CACHE_ORPHAN,
    CACHE_REPLACED_DURING_SCAN))
UNCERTAIN_VERDICTS = frozenset((
    ORIGINAL_CACHE_DAMAGED, ORIGINAL_UNREADABLE,
    ORIGINAL_REPLACED_DURING_SCAN, CACHE_DAMAGED, CACHE_ORPHAN,
    CACHE_REPLACED_DURING_SCAN, UNKNOWN_OBJECT, UNSAFE_NAME,
    COLLECTION_PROPS_INVALID, COLLECTION_PROPS_REPLACED))


def item_cache_hash(raw_text: bytes) -> str:
    """SHA-256 cache hash used by Radicale for an original item."""
    digest = hashlib.sha256()
    digest.update(storage.CACHE_VERSION)
    digest.update(raw_text)
    return digest.hexdigest()


def item_cache_mtime_and_size(size: int, mtime_ns: int) -> str:
    """mtime/size cache hash used by Radicale for an original item."""
    return CollectionPartCache._item_cache_mtime_and_size(size, mtime_ns)


def _relative_posix_path(root: str, path: str) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/")


def _stat_signature(stat_result: os.stat_result) -> Dict[str, int]:
    return {
        "size": stat_result.st_size,
        "mode": stat.S_IMODE(stat_result.st_mode),
        "mtime_ns": stat_result.st_mtime_ns,
        "inode": stat_result.st_ino,
        "device": stat_result.st_dev,
    }


def _take_snapshot(root: str) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    """Walk ``root`` and record identity, content hash and permissions.

    Returns a mapping of relative POSIX path to the recorded signature and a
    sorted list of paths that could not be read.  Directory entry order from
    the operating system is never relied on.
    """
    snapshot: Dict[str, Dict[str, Any]] = {}
    unreadable: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in sorted(dirnames) + sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = _relative_posix_path(root, path)
            entry: Dict[str, Any] = {"path": rel}
            try:
                stat_result = os.lstat(path)
            except OSError:
                unreadable.append(rel)
                entry.update({"type": "unstatable", "readable": False})
                snapshot[rel] = entry
                continue
            entry["type"] = ("symlink" if stat.S_ISLNK(stat_result.st_mode)
                             else "directory" if stat.S_ISDIR(stat_result.st_mode)
                             else "file")
            entry["signature"] = _stat_signature(stat_result)
            if entry["type"] == "file":
                try:
                    with open(path, "rb") as handle:
                        entry["sha256"] = hashlib.sha256(
                            handle.read()).hexdigest()
                    entry["readable"] = True
                except OSError:
                    entry["sha256"] = None
                    entry["readable"] = False
                    unreadable.append(rel)
            else:
                entry["sha256"] = None
                entry["readable"] = True
            snapshot[rel] = entry
    return snapshot, sorted(set(unreadable))


def _load_item_cache_bytes(
        raw_bytes: bytes
) -> Tuple[Optional[str], Optional[Tuple[Any, ...]], Optional[str]]:
    """Return (stored hash, cached content tuple, error) for cache bytes."""
    try:
        loaded = pickle.loads(raw_bytes)
    except (pickle.UnpicklingError, ValueError, KeyError, EOFError,
            AttributeError, ImportError) as error:
        return None, None, type(error).__name__
    if not isinstance(loaded, tuple) or len(loaded) < 2:
        return None, None, "malformed"
    stored_hash = loaded[0]
    if not isinstance(stored_hash, str) or not stored_hash:
        return None, None, "malformed"
    return stored_hash, tuple(loaded[1:]), None


def _load_item_cache(path: str) -> Tuple[Optional[str], Optional[Tuple[Any, ...]], Optional[str]]:
    """Return (stored hash, cached content tuple, error) for an item cache."""
    try:
        with open(path, "rb") as handle:
            raw_bytes = handle.read()
    except FileNotFoundError:
        return None, None, "missing"
    except OSError as error:
        return None, None, type(error).__name__
    return _load_item_cache_bytes(raw_bytes)


class StorageAudit:

    def __init__(self, root: str, use_mtime_and_size: bool = False,
                 cache_root: Optional[str] = None) -> None:
        self.root = os.path.abspath(root)
        self.use_mtime_and_size = use_mtime_and_size
        # When use_cache_subfolder_for_item is enabled the item cache lives
        # under "<filesystem_folder>/collection-cache" mirroring the
        # collection-root layout.  history and sync-token stay in place.
        self.cache_root = (os.path.abspath(cache_root) if cache_root
                           else None)
        self.entries: List[Dict[str, Any]] = []

    def _record(self, **fields: Any) -> Dict[str, Any]:
        entry = dict(sorted(fields.items()))
        self.entries.append(entry)
        return entry

    def _expected_hash(self, raw_text: bytes,
                       stat_result: os.stat_result) -> str:
        if self.use_mtime_and_size:
            return item_cache_mtime_and_size(
                stat_result.st_size, stat_result.st_mtime_ns)
        return item_cache_hash(raw_text)

    def _item_cache_path(self, collection_rel: str, href: str) -> str:
        if self.cache_root is not None:
            # ``collection_rel`` starts with "collection-root"; the external
            # cache root already stands in for that folder, so only the
            # collection path below it is mirrored.
            prefix = "collection-root" + "/"
            mirrored = (collection_rel[len(prefix):]
                        if collection_rel.startswith(prefix)
                        else collection_rel)
            return os.path.join(self.cache_root, mirrored, CACHE_DIR_NAME,
                                ITEM_CACHE, href)
        return os.path.join(self.root, collection_rel, CACHE_DIR_NAME,
                            ITEM_CACHE, href)

    def _audit_original(self, collection_rel: str, href: str,
                        path: str) -> None:
        rel = _relative_posix_path(self.root, path)
        before = os.lstat(path)
        try:
            with open(path, "rb") as handle:
                raw_text = handle.read()
        except OSError as error:
            self._record(
                category="original", path=rel, href=href,
                collection=collection_rel,
                verdict=ORIGINAL_UNREADABLE,
                detail="cannot read original: %s" % type(error).__name__,
                uncertain=True)
            return
        after_read = os.lstat(path)
        content_digest = hashlib.sha256(raw_text).hexdigest()
        expected_hash = self._expected_hash(raw_text, after_read)
        cache_path = self._item_cache_path(collection_rel, href)
        cache_rel = _relative_posix_path(
            self.cache_root if self.cache_root is not None else self.root,
            cache_path)
        stored_hash, cached_content, load_error = _load_item_cache(cache_path)
        verdict: str
        detail = ""
        uncertain = False
        if load_error == "missing":
            verdict = ORIGINAL_CACHE_MISSING
            detail = "no item cache entry for href %r" % href
        elif load_error is not None:
            verdict = ORIGINAL_CACHE_DAMAGED
            detail = "item cache not loadable: %s" % load_error
            uncertain = True
        elif stored_hash != expected_hash:
            verdict = ORIGINAL_CACHE_STALE
            detail = ("cache hash %r does not match current original %r"
                      % (stored_hash, expected_hash))
        else:
            verdict = ORIGINAL_VERIFIED
        # Re-open the original after touching the cache.  A replacement can
        # reuse the same inode (for example an atomic rename on APFS), so the
        # content hash is compared as well as the identity metadata.  Any
        # change between the two observations invalidates an otherwise clean
        # verdict and the object is reported as uncertain.
        try:
            final_stat = os.lstat(path)
            with open(path, "rb") as handle:
                final_raw_text = handle.read()
        except OSError:
            final_stat = None
            final_raw_text = None
        replaced = (
            final_stat is None or final_raw_text is None or
            hashlib.sha256(final_raw_text).hexdigest() != content_digest or
            (final_stat.st_ino, final_stat.st_dev, final_stat.st_mtime_ns,
             final_stat.st_size) !=
            (after_read.st_ino, after_read.st_dev, after_read.st_mtime_ns,
             after_read.st_size) or
            (before.st_ino, before.st_dev) != (after_read.st_ino,
                                               after_read.st_dev))
        if replaced:
            verdict = ORIGINAL_REPLACED_DURING_SCAN
            detail = ("original object changed or was replaced between the "
                      "two scan observations")
            uncertain = True
        self._record(
            category="original", path=rel, href=href,
            collection=collection_rel, verdict=verdict, detail=detail,
            sha256=content_digest,
            size=after_read.st_size, mode=stat.S_IMODE(after_read.st_mode),
            expected_cache_hash=expected_hash,
            stored_cache_hash=stored_hash, cache_path=cache_rel,
            cache_content_matches=(
                cached_content is not None and
                len(cached_content) >= 2 and
                cached_content[1] == raw_text.decode(
                    "utf-8", errors="replace")),
            uncertain=uncertain)

    def _audit_item_cache_file(self, collection_rel: str, href: str,
                               cache_path: str,
                               originals: Dict[str, str]) -> None:
        rel = _relative_posix_path(
            self.cache_root if self.cache_root is not None else self.root,
            cache_path)
        try:
            before = os.lstat(cache_path)
            with open(cache_path, "rb") as handle:
                cache_bytes = handle.read()
        except OSError:
            self._record(category="cache", path=rel, href=href,
                         collection=collection_rel, verdict=CACHE_DAMAGED,
                         detail="cache entry cannot be read",
                         uncertain=True)
            return
        before_digest = hashlib.sha256(cache_bytes).hexdigest()
        original_path = originals.get(href)
        stored_hash, _cached_content, load_error = _load_item_cache_bytes(
            cache_bytes)
        if original_path is None:
            verdict = CACHE_ORPHAN
            detail = "cache entry has no original object %r" % href
            uncertain = True
        elif load_error is not None:
            verdict = CACHE_DAMAGED
            detail = "cache entry not loadable: %s" % load_error
            uncertain = True
        else:
            try:
                with open(original_path, "rb") as handle:
                    raw_text = handle.read()
                original_stat = os.lstat(original_path)
            except OSError as read_error:
                self._record(category="cache", path=rel, href=href,
                             collection=collection_rel,
                             verdict=CACHE_DAMAGED,
                             detail=("original unreadable: %s"
                                     % type(read_error).__name__),
                             uncertain=True)
                return
            expected_hash = self._expected_hash(raw_text, original_stat)
            if stored_hash == expected_hash:
                verdict = CACHE_VALID
                detail = ""
                uncertain = False
            else:
                verdict = CACHE_STALE
                detail = ("cache hash %r differs from hash of the original "
                          "object %r" % (stored_hash, expected_hash))
                uncertain = False
        try:
            after = os.lstat(cache_path)
            with open(cache_path, "rb") as handle:
                after_bytes = handle.read()
        except OSError:
            after = None
            after_bytes = None
        replaced = (
            after is None or after_bytes is None or
            hashlib.sha256(after_bytes).hexdigest() != before_digest or
            (after.st_ino, after.st_dev) != (before.st_ino, before.st_dev))
        if replaced:
            verdict = CACHE_REPLACED_DURING_SCAN
            detail = "cache entry changed or was replaced during the scan"
            uncertain = True
        self._record(category="cache", path=rel, href=href,
                     collection=collection_rel, verdict=verdict,
                     detail=detail, stored_cache_hash=stored_hash,
                     size=before.st_size, mode=stat.S_IMODE(before.st_mode),
                     uncertain=uncertain)

    def _audit_other_cache(self, rel: str, kind: str,
                           cache_path: str) -> None:
        try:
            before = os.lstat(cache_path)
            with open(cache_path, "rb") as handle:
                cache_bytes = handle.read()
        except FileNotFoundError:
            return
        except OSError:
            self._record(category="cache", path=rel,
                         href=os.path.basename(rel),
                         collection=os.path.dirname(rel),
                         verdict=CACHE_DAMAGED,
                         detail="cache entry cannot be read",
                         uncertain=True)
            return
        before_digest = hashlib.sha256(cache_bytes).hexdigest()
        try:
            pickle.loads(cache_bytes)
            loadable = True
            error_name = ""
        except (pickle.UnpicklingError, ValueError, KeyError, EOFError,
                AttributeError, ImportError) as error:
            loadable = False
            error_name = type(error).__name__
        try:
            after = os.lstat(cache_path)
            with open(cache_path, "rb") as handle:
                after_bytes = handle.read()
        except OSError:
            after = None
            after_bytes = None
        replaced = (
            after is None or after_bytes is None or
            hashlib.sha256(after_bytes).hexdigest() != before_digest or
            (after.st_ino, after.st_dev) != (before.st_ino, before.st_dev))
        if replaced:
            verdict = CACHE_REPLACED_DURING_SCAN
            detail = "cache entry changed or was replaced during the scan"
            uncertain = True
        elif loadable:
            verdict = CACHE_VALID
            detail = "%s cache entry is loadable" % kind
            uncertain = False
        else:
            verdict = CACHE_DAMAGED
            detail = "%s cache entry not loadable: %s" % (kind, error_name)
            uncertain = True
        self._record(category="cache", path=rel, href=os.path.basename(rel),
                     collection=os.path.dirname(rel), verdict=verdict,
                     detail=detail, size=before.st_size,
                     mode=stat.S_IMODE(before.st_mode),
                     uncertain=uncertain)

    def _audit_props(self, collection_rel: str,
                     props_path: str) -> None:
        rel = _relative_posix_path(self.root, props_path)
        before = os.lstat(props_path)
        try:
            with open(props_path, "rb") as handle:
                props_bytes = handle.read()
            json.loads(props_bytes.decode("utf-8"))
            valid = True
            detail = ""
        except OSError as error:
            props_bytes = b""
            valid = False
            detail = "cannot read properties: %s" % type(error).__name__
        except ValueError as error:
            valid = False
            detail = "properties are not valid JSON: %s" % error
        try:
            after = os.lstat(props_path)
            with open(props_path, "rb") as handle:
                after_bytes = handle.read()
        except OSError:
            after = None
            after_bytes = None
        replaced = (
            after is None or after_bytes is None or
            hashlib.sha256(after_bytes).hexdigest() !=
            hashlib.sha256(props_bytes).hexdigest() or
            (after.st_ino, after.st_dev, after.st_mtime_ns,
             after.st_size) !=
            (before.st_ino, before.st_dev, before.st_mtime_ns,
             before.st_size))
        if replaced:
            verdict = COLLECTION_PROPS_REPLACED
            detail = "properties changed or were replaced during the scan"
            uncertain = True
        elif valid:
            verdict = ORIGINAL_VERIFIED
            uncertain = False
        else:
            verdict = COLLECTION_PROPS_INVALID
            uncertain = True
        self._record(category="original", path=rel, href=PROPS_NAME,
                     collection=collection_rel, verdict=verdict,
                     detail=detail, size=before.st_size,
                     mode=stat.S_IMODE(before.st_mode),
                     uncertain=uncertain)

    def _find_collections(self) -> List[str]:
        collections: List[str] = []
        for dirpath, dirnames, _filenames in os.walk(self.root):
            if os.path.isfile(os.path.join(dirpath, PROPS_NAME)):
                collections.append(
                    _relative_posix_path(self.root, dirpath))
        return sorted(collections)

    def audit(self) -> Dict[str, Any]:
        if not os.path.isdir(self.root):
            raise FileNotFoundError(
                "storage root is not a directory: %r" % self.root)
        if self.cache_root is not None and not os.path.isdir(
                self.cache_root):
            raise FileNotFoundError(
                "external cache root is not a directory: %r"
                % self.cache_root)
        before_snapshot, before_unreadable = _take_snapshot(self.root)
        if self.cache_root is not None:
            cache_snapshot, cache_unreadable = _take_snapshot(
                self.cache_root)
        else:
            cache_snapshot, cache_unreadable = {}, []
        for collection_rel in self._find_collections():
            collection_path = os.path.join(self.root, collection_rel)
            self._audit_props(collection_rel,
                              os.path.join(collection_path, PROPS_NAME))
            originals: Dict[str, str] = {}
            with os.scandir(collection_path) as entries:
                names = sorted(entry.name for entry in entries)
            for name in names:
                if not pathutils.is_safe_filesystem_path_component(name):
                    if name.startswith(".Radicale"):
                        continue
                    self._record(
                        category="unconfirmed",
                        path=_relative_posix_path(
                            self.root,
                            os.path.join(collection_path, name)),
                        href=name, collection=collection_rel,
                        verdict=UNSAFE_NAME,
                        detail="name is not a safe filesystem component",
                        uncertain=True)
                    continue
                if not name.endswith(ITEM_SUFFIXES):
                    candidate = os.path.join(collection_path, name)
                    try:
                        candidate_stat = os.lstat(candidate)
                    except OSError:
                        self._record(
                            category="unconfirmed",
                            path=_relative_posix_path(self.root, candidate),
                            href=name, collection=collection_rel,
                            verdict=UNKNOWN_OBJECT,
                            detail="object cannot be stated",
                            uncertain=True)
                        continue
                    if stat.S_ISREG(candidate_stat.st_mode):
                        self._record(
                            category="unconfirmed",
                            path=_relative_posix_path(self.root, candidate),
                            href=name, collection=collection_rel,
                            verdict=UNKNOWN_OBJECT,
                            detail="file is neither an item nor Radicale metadata",
                            uncertain=True)
                    continue
                item_path = os.path.join(collection_path, name)
                try:
                    item_stat = os.lstat(item_path)
                except OSError:
                    self._record(
                        category="unconfirmed",
                        path=_relative_posix_path(self.root, item_path),
                        href=name, collection=collection_rel,
                        verdict=UNKNOWN_OBJECT,
                        detail="object cannot be stated",
                        uncertain=True)
                    continue
                if (not stat.S_ISREG(item_stat.st_mode)
                        or stat.S_ISLNK(item_stat.st_mode)):
                    self._record(
                        category="unconfirmed",
                        path=_relative_posix_path(self.root, item_path),
                        href=name, collection=collection_rel,
                        verdict=UNKNOWN_OBJECT,
                        detail="item path is not a regular file",
                        uncertain=True)
                    continue
                originals[name] = item_path
                self._audit_original(collection_rel, name, item_path)
            # Item cache, either inside the collection or mirrored outside.
            item_cache_dir = os.path.dirname(
                self._item_cache_path(collection_rel, ""))
            if os.path.isdir(item_cache_dir):
                with os.scandir(item_cache_dir) as entries:
                    cache_names = sorted(entry.name for entry in entries
                                         if entry.is_file(follow_symlinks=False))
                for name in cache_names:
                    self._audit_item_cache_file(
                        collection_rel, name,
                        os.path.join(item_cache_dir, name), originals)
            # history and sync-token caches stay below the collection.
            cache_base = os.path.join(collection_path, CACHE_DIR_NAME)
            for kind in (HISTORY_CACHE, SYNC_TOKEN_CACHE):
                kind_dir = os.path.join(cache_base, kind)
                if not os.path.isdir(kind_dir):
                    continue
                with os.scandir(kind_dir) as entries:
                    for entry in sorted(entries, key=lambda e: e.name):
                        if entry.is_file(follow_symlinks=False):
                            self._audit_other_cache(
                                _relative_posix_path(
                                    self.root,
                                    os.path.join(kind_dir, entry.name)),
                                kind, os.path.join(kind_dir, entry.name))
        after_snapshot, after_unreadable = _take_snapshot(self.root)
        if self.cache_root is not None:
            after_cache_snapshot, after_cache_unreadable = _take_snapshot(
                self.cache_root)
        else:
            after_cache_snapshot, after_cache_unreadable = {}, []
        drift = self._diff_snapshots(before_snapshot, after_snapshot)
        cache_drift = self._diff_snapshots(cache_snapshot,
                                           after_cache_snapshot)
        self.entries.sort(key=lambda entry: (entry["path"],
                                             entry["category"],
                                             entry["verdict"]))
        return self._build_report(
            before_snapshot, after_snapshot, drift,
            sorted(set(before_unreadable + after_unreadable)),
            cache_snapshot, after_cache_snapshot, cache_drift,
            sorted(set(cache_unreadable + after_cache_unreadable)))

    @staticmethod
    def _diff_snapshots(before: Dict[str, Dict[str, Any]],
                        after: Dict[str, Dict[str, Any]]) -> List[Dict[str, str]]:
        changes: List[Dict[str, str]] = []
        for rel in sorted(set(before) | set(after)):
            old = before.get(rel)
            new = after.get(rel)
            if old is None:
                changes.append({"path": rel, "change": "added"})
            elif new is None:
                changes.append({"path": rel, "change": "removed"})
            elif (old.get("sha256"), old.get("signature"),
                  old.get("type")) != (new.get("sha256"),
                                       new.get("signature"),
                                       new.get("type")):
                changes.append({"path": rel, "change": "modified"})
        return changes

    def _build_report(self, before: Dict[str, Dict[str, Any]],
                      after: Dict[str, Dict[str, Any]],
                      drift: List[Dict[str, str]],
                      unreadable: List[str],
                      cache_before: Dict[str, Dict[str, Any]],
                      cache_after: Dict[str, Dict[str, Any]],
                      cache_drift: List[Dict[str, str]],
                      cache_unreadable: List[str]) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        for entry in self.entries:
            counts[entry["verdict"]] = counts.get(entry["verdict"], 0) + 1
        categories = {"original": 0, "cache": 0, "unconfirmed": 0}
        for entry in self.entries:
            categories[entry["category"]] += 1
        evidence: Dict[str, Any] = {
            "root": self.root,
            "cache_root": self.cache_root,
            "cache_hash_scheme": ("mtime-and-size"
                                  if self.use_mtime_and_size
                                  else "sha256"),
            "cache_version": storage.CACHE_VERSION.decode(),
            "before": self._public_snapshot(before),
            "after": self._public_snapshot(after),
            "drift": drift,
            "unreadable": unreadable,
        }
        if self.cache_root is not None:
            evidence["external_cache"] = {
                "root": self.cache_root,
                "before": self._public_snapshot(cache_before),
                "after": self._public_snapshot(cache_after),
                "drift": cache_drift,
                "unreadable": cache_unreadable,
            }
        return {
            "schema_version": 1,
            "summary": {
                "total_objects": len(self.entries),
                "categories": categories,
                "verdicts": dict(sorted(counts.items())),
                "uncertain_objects": sum(
                    1 for entry in self.entries if entry["uncertain"]),
                "evidence_drift": len(drift) + len(cache_drift),
            },
            "entries": self.entries,
            "evidence": evidence,
        }

    @staticmethod
    def _public_snapshot(snapshot: Dict[str, Dict[str, Any]]
                         ) -> List[Dict[str, Any]]:
        return [snapshot[rel] for rel in sorted(snapshot)]


def render_text_report(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    summary = report["summary"]
    lines.append("# Radicale storage handover audit")
    lines.append("root: %s" % report["evidence"]["root"])
    lines.append("cache hash scheme: %s"
                 % report["evidence"]["cache_hash_scheme"])
    lines.append("cache version: %s" % report["evidence"]["cache_version"])
    lines.append("objects: %d (original %d, cache %d, unconfirmed %d)" % (
        summary["total_objects"], summary["categories"]["original"],
        summary["categories"]["cache"],
        summary["categories"]["unconfirmed"]))
    lines.append("uncertain objects: %d" % summary["uncertain_objects"])
    lines.append("evidence drift entries: %d"
                 % summary["evidence_drift"])
    lines.append("")
    lines.append("## verdicts")
    for verdict, count in sorted(summary["verdicts"].items()):
        lines.append("%s: %d" % (verdict, count))
    lines.append("")
    lines.append("## objects")
    for entry in report["entries"]:
        flag = "UNCERTAIN" if entry["uncertain"] else "ok"
        lines.append("[%s] %s %s -- %s" % (
            flag, entry["category"], entry["path"], entry["verdict"]))
        if entry["detail"]:
            lines.append("    %s" % entry["detail"])
    lines.append("")
    lines.append("## evidence drift")
    for change in report["evidence"]["drift"]:
        lines.append("%s: %s" % (change["change"], change["path"]))
    if not report["evidence"]["drift"]:
        lines.append("(none)")
    return "\n".join(lines) + "\n"


def audit_storage(root: str, use_mtime_and_size: bool = False,
                  cache_root: Optional[str] = None) -> Dict[str, Any]:
    """Audit a read-only storage copy and return the deterministic report."""
    return StorageAudit(root, use_mtime_and_size=use_mtime_and_size,
                        cache_root=cache_root).audit()


def main(argv: Optional[List[str]] = None) -> int:
    """Command line entry point for the read-only handover audit."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="radicale-storage-audit",
        description=("Audit a read-only copy of a Radicale multifilesystem "
                     "storage and print a deterministic handover checklist."))
    parser.add_argument("root", help="storage filesystem_folder to audit")
    parser.add_argument(
        "--cache-root",
        help=("external collection-cache folder when "
              "use_cache_subfolder_for_item is enabled"))
    parser.add_argument(
        "--mtime-size", action="store_true",
        help="use the mtime/size cache hash scheme instead of SHA-256")
    parser.add_argument(
        "--format", choices=("json", "text"), default="text",
        help="output format (default: text)")
    parser.add_argument(
        "--output", help="write the report to this path instead of stdout")
    args = parser.parse_args(argv)
    report = audit_storage(
        args.root, use_mtime_and_size=args.mtime_size,
        cache_root=args.cache_root)
    rendered = (json.dumps(report, indent=2, sort_keys=True)
                if args.format == "json" else render_text_report(report))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
    else:
        print(rendered, end="")
    # A non-zero exit code signals that at least one object is unconfirmed.
    return 1 if report["summary"]["uncertain_objects"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
