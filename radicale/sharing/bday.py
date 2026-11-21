# This file is part of Radicale Server - Calendar Server
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

"""Incremental sync for the "bday" conversion.

A birthday share exposes a projection of an address book.  Its sync token and
change list therefore have to be computed from the projected events, not from
the raw VCARD files: a changed phone number, address, revision or internal UID
must not create an update, while a changed birthday or a projected name must.

The projected ETag per member href is the state of a token.  Like the built-in
sync tokens, each token gets its own small file under ``.Radicale.cache/
bday-projection/``; a token only needs the state that belonged to it, and two
clients using different old tokens do not overwrite each other.  The state
holds only the projected ETags already exposed by the share and can be
discarded and rebuilt at any time.

"""

import logging
import os
import pickle
import re
from hashlib import sha256
from typing import Dict, List, Optional, Tuple

from radicale import sharing
from radicale.log import logger

TOKEN_PREFIX: str = sharing.SHARING_BDAY_SYNC_TOKEN_PREFIX
STATE_VERSION: str = "1"
STATE_FOLDER: str = "bday-projection"

_TOKEN_NAME = re.compile(r"^[0-9a-f]{64}$")


def _hash(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def projection_key(share: dict) -> str:
    """Opaque key of the projection a share renders.

    The selected fields and the rendered templates both influence the
    projected events, so they both belong to the key.  A token of a different
    projection is not accepted.

    """
    actions = share.get('Actions') or {}
    config = actions.get('config') or {}
    config_default = actions.get('config_default') or {}
    parts = ["v" + STATE_VERSION]
    for key in sorted(set(config) | set(config_default)):
        parts.append("%s=%r" % (key, config.get(key, config_default.get(key))))
    return _hash("\n".join(parts))[:32]


def _state_folder(collection) -> str:
    return collection._storage._get_collection_cache_subfolder(
        collection._filesystem_path, ".Radicale.cache", STATE_FOLDER)


def _token_name(key: str, state: Dict[str, str]) -> str:
    return _hash(
        key + "\n" + "\n".join(
            "%s/%s" % (href, state[href]) for href in sorted(state)))


def _split_token(token: str) -> Tuple[str, str]:
    if not token.startswith(TOKEN_PREFIX):
        raise ValueError("Malformed token: %r" % token)
    rest = token[len(TOKEN_PREFIX):]
    key, _, name = rest.partition("/")
    if not key or not _TOKEN_NAME.match(name):
        raise ValueError("Malformed token: %r" % token)
    return key, name


def _load_state(collection, name: str) -> Optional[Dict[str, str]]:
    if not _TOKEN_NAME.match(name):
        return None
    path = os.path.join(_state_folder(collection), name)
    try:
        with open(path, "rb") as f:
            version, state = pickle.load(f)
    except (FileNotFoundError, pickle.UnpicklingError, ValueError, EOFError,
            KeyError):
        return None
    if version != STATE_VERSION or not isinstance(state, dict):
        return None
    return state


def _store_state(collection, name: str, state: Dict[str, str]) -> None:
    if not _TOKEN_NAME.match(name):
        raise ValueError("unsafe token name: %r" % name)
    folder = _state_folder(collection)
    collection._storage._makedirs_synced(folder)
    with collection._atomic_write(os.path.join(folder, name), "wb") as f:
        pickle.dump([STATE_VERSION, state], f)


def projection_state(collection, share: dict) -> Dict[str, str]:
    """Projected ETag per member href, for one share projection."""
    state: Dict[str, str] = {}
    actions = share.get('Actions') or {}
    for entry in collection.get_all():
        converted = entry.convert_vcf_to_ics(ShareActions=actions)
        if converted is None:
            continue
        assert entry.href
        state[entry.href] = converted.etag
    return state


def sync_token(collection, share: dict) -> str:
    """Current sync token of a birthday share.

    The token is opaque for a client; storing its state lets a later
    ``sync-collection`` compute the difference from it.

    """
    key = projection_key(share)
    state = projection_state(collection, share)
    name = _token_name(key, state)
    if _load_state(collection, name) is None:
        _store_state(collection, name, state)
    return TOKEN_PREFIX + key + "/" + name


def sync(collection, share: dict, old_token: str) -> Tuple[str, List[str], List[str]]:
    """Compute the incremental changes of a birthday share.

    Returns ``(sync_token, changed_hrefs, removed_hrefs)``.  ``changed_hrefs``
    are member hrefs whose projection is new or changed; ``removed_hrefs`` are
    member hrefs whose projection disappeared (deleted contact or contact
    without a usable birthday any more).

    """
    key = projection_key(share)
    state = projection_state(collection, share)
    name = _token_name(key, state)
    token = TOKEN_PREFIX + key + "/" + name
    if old_token:
        old_key, old_name = _split_token(old_token)
        if old_key != key:
            raise ValueError("Token belongs to a different projection")
        old_state = _load_state(collection, old_name)
        if old_state is None:
            raise ValueError("Token not found: %r" % old_token)
    else:
        old_state = {}
    if old_token == token:
        return token, [], []
    changed = [href for href, etag in state.items()
               if old_state.get(href) != etag]
    removed = [href for href in old_state if href not in state]
    if _load_state(collection, name) is None:
        if logger.isEnabledFor(logging.DEBUG):
            logger.trace("sharing/bday: sync state %r changed=%r removed=%r", key, changed, removed)
        _store_state(collection, name, state)
    return token, changed, removed
