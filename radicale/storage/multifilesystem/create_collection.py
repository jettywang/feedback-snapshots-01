# This file is part of Radicale - CalDAV and CardDAV server
# Copyright © 2014 Jean-Marc Martins
# Copyright © 2012-2017 Guillaume Ayoub
# Copyright © 2017-2021 Unrud <unrud@outlook.com>
# Copyright © 2024-2025 Peter Bieringer <pb@bieringer.de>
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

import os
from tempfile import TemporaryDirectory
from typing import Dict, Iterable, List, Optional, Set, Tuple, cast

import radicale.item as radicale_item
from radicale import pathutils
from radicale.log import logger
from radicale.storage import multifilesystem
from radicale.storage.multifilesystem.base import StorageBase


class StoragePartCreateCollection(StorageBase):

    # Item component names that belong to a collection tag.
    _TAG_ITEM_NAMES = {
        "VCALENDAR": frozenset(("VEVENT", "VTODO", "VJOURNAL")),
        "VADDRESSBOOK": frozenset(("VCARD", "VLIST")),
    }

    def _verify_staged_collection(
            self, tmp_collection: "multifilesystem.Collection") -> None:
        """Verify a staged collection before it is published.

        Every item is re-read from the temporary directory so that the format
        on disk, the membership in the collection tag and the uniqueness of
        the UIDs are checked. Raises ValueError on the first problem; the
        caller discards the temporary directory and keeps the existing
        collection untouched.
        """
        tag = tmp_collection.tag
        if tag not in self._TAG_ITEM_NAMES:
            raise ValueError("Unsupported collection tag: %r" % tag)
        allowed_item_names = self._TAG_ITEM_NAMES[tag]
        seen_uids: Set[str] = set()
        for href in tmp_collection._list():
            try:
                item = tmp_collection._get(href, verify_href=False)
            except ValueError as e:
                raise ValueError(
                    "Failed to verify item %r in temporary collection %r: %s" %
                    (href, tmp_collection.path, e)) from e
            if item is None:
                raise ValueError(
                    "Failed to verify item %r in temporary collection %r: "
                    "unreadable" % (href, tmp_collection.path))
            # A calendar item is a VCALENDAR wrapper; its component_name names
            # the contained VEVENT/VTODO/VJOURNAL. An address book item names
            # its component (VCARD/VLIST) directly.
            item_name = (item.component_name
                         if tag == "VCALENDAR" else item.name)
            if item_name not in allowed_item_names:
                raise ValueError(
                    "Item type %r not supported in %r collection (item %r "
                    "in temporary collection %r)" %
                    (item_name, tag, href, tmp_collection.path))
            if item.uid in seen_uids:
                raise ValueError(
                    "UID conflict %r in temporary collection %r (item %r)" %
                    (item.uid, tmp_collection.path, href))
            seen_uids.add(item.uid)
        logger.debug("Verified staged collection %r: %d item(s)",
                     tmp_collection.path, len(seen_uids))

    def _discover_existing_items_pre_overwrite(self,
                                               tmp_collection: "multifilesystem.Collection",
                                               dst_path: str) -> Tuple[Dict[str, radicale_item.Item], List[str]]:
        """Discover existing items in the collection before overwriting them."""
        existing_items = {}
        new_item_hrefs = []

        existing_collection = self._collection_class(
            cast(multifilesystem.Storage, self),
            pathutils.unstrip_path(dst_path, True))
        existing_item_hrefs = set(existing_collection._list())
        tmp_collection_hrefs = set(tmp_collection._list())
        for item_href in tmp_collection_hrefs:
            if item_href not in existing_item_hrefs:
                # Item in temporary collection does not exist in the existing collection (is new)
                new_item_hrefs.append(item_href)
                continue
            # Item exists in both collections, grab the existing item for reference
            try:
                item = existing_collection._get(item_href, verify_href=False)
                if item is not None:
                    existing_items[item_href] = item
            except Exception:
                # TODO: Log exception?
                continue

        return existing_items, new_item_hrefs

    def create_collection(self, href: str,
                          items: Optional[Iterable[radicale_item.Item]] = None,
                          props=None) -> Tuple["multifilesystem.Collection", Dict[str, radicale_item.Item], List[str]]:
        folder = self._get_collection_root_folder()

        # Path should already be sanitized
        sane_path = pathutils.strip_path(href)
        filesystem_path = pathutils.path_to_filesystem(folder, sane_path, self._is_collision_free)
        logger.debug("Create collection: %r", filesystem_path)

        if not props:
            self._makedirs_synced(filesystem_path)
            return self._collection_class(
                cast(multifilesystem.Storage, self),
                pathutils.unstrip_path(sane_path, True)), {}, []

        parent_dir = os.path.dirname(filesystem_path)
        self._makedirs_synced(parent_dir)

        replaced_items: Dict[str, radicale_item.Item] = {}
        new_item_hrefs: List[str] = []

        # Create a temporary directory with an unsafe name
        try:
            with TemporaryDirectory(prefix=".Radicale.tmp-", dir=parent_dir
                                    ) as tmp_dir:
                # The temporary directory itself can't be renamed
                tmp_filesystem_path = os.path.join(tmp_dir, "collection")
                os.makedirs(tmp_filesystem_path)
                col = self._collection_class(
                    cast(multifilesystem.Storage, self),
                    pathutils.unstrip_path(sane_path, True),
                    filesystem_path=tmp_filesystem_path)
                col.set_meta(props)
                if items is not None:
                    if props.get("tag") == "VCALENDAR":
                        col._upload_all_nonatomic(items, suffix=".ics")
                    elif props.get("tag") == "VADDRESSBOOK":
                        col._upload_all_nonatomic(items, suffix=".vcf")

                if self._verify_collection_replace:
                    logger.debug(
                        "Verify staged collection before publishing: %r",
                        filesystem_path)
                    self._verify_staged_collection(col)

                if os.path.lexists(filesystem_path):
                    replaced_items, new_item_hrefs = self._discover_existing_items_pre_overwrite(
                        tmp_collection=col,
                        dst_path=sane_path)
                    pathutils.rename_exchange(tmp_filesystem_path, filesystem_path)
                else:
                    # If the destination path does not exist, obviously all items are new
                    new_item_hrefs = list(col._list())
                    os.rename(tmp_filesystem_path, filesystem_path)
                self._sync_directory(parent_dir)
        except Exception as e:
            raise ValueError("Failed to create collection %r as %r %s" %
                             (href, filesystem_path, e)) from e

        # TODO: Return new-old pairs and just-new items (new vs updated)
        return self._collection_class(
            cast(multifilesystem.Storage, self),
            pathutils.unstrip_path(sane_path, True)), replaced_items, new_item_hrefs
