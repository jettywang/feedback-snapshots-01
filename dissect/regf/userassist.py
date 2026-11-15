"""Version-aware parser for UserAssist evidence in NTUSER.DAT hives.

The UserAssist key (``Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist``)
records programs launched through the Windows shell (Explorer). Each subkey named
after a well-known GUID holds a ``Count`` subkey whose values are ROT13-encoded
program identifiers with a small binary record as data.

Two record layouts are documented in public forensic literature:

- Version 3 (Windows XP/2003), 16 bytes::

    0x00  ULONG     session id
    0x04  ULONG     run count, stored with a bias of +5
    0x08  FILETIME  last execution time

- Version 5 (Windows 7 and later), 72 bytes::

    0x00  ULONG     reserved, always 0
    0x04  ULONG     run count
    0x08  ULONG     focus count
    0x0c  ULONG     focus time (milliseconds)
    0x10  44 bytes  reserved
    0x3c  FILETIME  last execution time

Records are only interpreted when they match one of these layouts exactly
(exact size, and for v5 a zero reserved field). Short records, unknown versions
and invalid timestamps are returned with their raw bytes preserved and no
interpreted fields, so evidence is never silently dropped or replaced with
fabricated "zero runs" / "never executed" conclusions.

Program identifiers are ROT13-decoded verbatim. Known-folder GUIDs are
annotated with their symbolic name only; they are never resolved to paths on
the analysis machine, and user paths are kept exactly as recorded.

Limitations of the count field (do not treat it as a reliable run count):

- Version 3 records store the count with a +5 bias; the adjusted value assumes
  documented behaviour and breaks down for anomalous raw values (< 5).
- The counter only tracks launches through the Explorer shell (Start Menu,
  desktop, shortcuts); programs started via the command line, services, tasks
  or other processes are not counted.
- ``UEME_*`` values are shell bookkeeping entries, not program executions.
- The counter is maintained per user and can be reset, cleared or manipulated;
  the whole UserAssist key can be deleted or disabled by policy.
- The count is a 32-bit value maintained by the shell and may wrap.
- A zero/absent timestamp means no time was recorded, not "never executed".
"""

from __future__ import annotations

import codecs
import logging
import os
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.regf.exceptions import RegistryKeyNotFoundError
from dissect.util.ts import wintimestamp

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

    from dissect.regf.regf import RegistryHive

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_REGF", "CRITICAL"))

USERASSIST_KEY_PATH = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"

# Well-known UserAssist subkey GUIDs and what they account for.
USERASSIST_GUIDS = {
    "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "executable file launches",
    "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "shortcut (.lnk) launches",
}

# Symbolic names for known-folder GUIDs commonly seen in decoded identifiers.
# These are annotations only; they must never be resolved to local paths.
KNOWN_FOLDER_GUIDS = {
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "System",
    "{6D809377-6AF0-444B-8957-A3773F02200E}": "ProgramFiles",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "ProgramFiles",
    "{905E63B6-C1BF-494E-B29C-65B732D3D21A}": "ProgramFiles",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "Windows",
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "Desktop",
    "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": "System",
}

VERSION_3 = 3
VERSION_5 = 5

# Field name -> (offset, size) byte provenance within the raw record.
V3_LAYOUT = {
    "session_id": (0x00, 4),
    "count": (0x04, 4),
    "last_execution": (0x08, 8),
}
V5_LAYOUT = {
    "reserved": (0x00, 4),
    "count": (0x04, 4),
    "focus_count": (0x08, 4),
    "focus_time_ms": (0x0C, 4),
    "last_execution": (0x3C, 8),
}

V3_RECORD_SIZE = 16
V5_RECORD_SIZE = 72

# Version 3 records store the run count with this bias.
V3_COUNT_BIAS = 5


@dataclass
class UserAssistEntry:
    """A single UserAssist value with raw evidence and interpreted fields.

    Interpreted fields are ``None`` unless the record matched a documented
    layout. ``field_sources`` maps every interpreted field to its
    ``(offset, size)`` within ``raw_data``.
    """

    raw_name: str
    name: str
    raw_data: bytes
    guid: str | None = None

    version: int | None = None
    status: str = "unknown-version"
    notes: list[str] = field(default_factory=list)

    session_id: int | None = None
    count: int | None = None
    count_raw: int | None = None
    focus_count: int | None = None
    focus_time_ms: int | None = None
    last_execution: datetime | None = None
    timestamp_raw: int | None = None
    timestamp_status: str | None = None

    known_folder: str | None = None
    is_ueme: bool = False

    field_sources: dict[str, tuple[int, int]] = field(default_factory=dict)

    @property
    def parsed(self) -> bool:
        return self.status == "parsed"

    @property
    def guid_description(self) -> str | None:
        if self.guid is None:
            return None
        return _USERASSIST_GUID_DESCRIPTIONS.get(self.guid.upper())


_USERASSIST_GUID_DESCRIPTIONS = {guid.upper(): desc for guid, desc in USERASSIST_GUIDS.items()}


def rot13(text: str) -> str:
    return codecs.decode(text, "rot_13")


def detect_version(data: bytes) -> int | None:
    """Return the record version for documented layouts, else ``None``.

    A 72-byte record is only accepted as version 5 when its reserved field
    is zero, so unknown layouts of the same length are not guessed into a
    known record type.
    """
    if len(data) == V3_RECORD_SIZE:
        return VERSION_3
    if len(data) == V5_RECORD_SIZE and struct.unpack_from("<I", data, V5_LAYOUT["reserved"][0])[0] == 0:
        return VERSION_5
    return None


def _parse_filetime(raw: int) -> tuple[datetime | None, str]:
    if raw == 0:
        return None, "not-recorded"
    try:
        return wintimestamp(raw), "ok"
    except (OverflowError, ValueError, OSError):
        return None, "invalid"


def parse_userassist_value(name: str, data: bytes, guid: str | None = None) -> UserAssistEntry:
    """Parse a single UserAssist value, preserving raw evidence.

    Args:
        name: The raw (ROT13-encoded) registry value name.
        data: The raw registry value data.
        guid: The UserAssist subkey GUID this value was found under, if known.
    """
    raw_data = bytes(data)
    decoded_name = rot13(name)

    entry = UserAssistEntry(raw_name=name, name=decoded_name, raw_data=raw_data, guid=guid)

    if decoded_name.upper().startswith("UEME_"):
        entry.is_ueme = True
        entry.notes.append("UEME_* bookkeeping entry, not a program execution record")

    for folder_guid, folder_name in KNOWN_FOLDER_GUIDS.items():
        if decoded_name.upper().startswith(folder_guid):
            entry.known_folder = folder_name
            break

    version = detect_version(raw_data)
    entry.version = version

    if version is None:
        entry.status = "short-record" if len(raw_data) < V3_RECORD_SIZE else "unknown-version"
        entry.notes.append("record does not match a documented layout; raw evidence preserved")
        return entry

    if version == VERSION_3:
        entry.field_sources = dict(V3_LAYOUT)
        entry.session_id = struct.unpack_from("<I", raw_data, V3_LAYOUT["session_id"][0])[0]
        entry.count_raw = struct.unpack_from("<I", raw_data, V3_LAYOUT["count"][0])[0]
        if entry.count_raw >= V3_COUNT_BIAS:
            entry.count = entry.count_raw - V3_COUNT_BIAS
        else:
            entry.notes.append(
                f"v3 count bias of {V3_COUNT_BIAS} not applicable to raw count {entry.count_raw}; count not adjusted"
            )
        entry.timestamp_raw = struct.unpack_from("<Q", raw_data, V3_LAYOUT["last_execution"][0])[0]
    else:
        entry.field_sources = dict(V5_LAYOUT)
        entry.count_raw = entry.count = struct.unpack_from("<I", raw_data, V5_LAYOUT["count"][0])[0]
        entry.focus_count = struct.unpack_from("<I", raw_data, V5_LAYOUT["focus_count"][0])[0]
        entry.focus_time_ms = struct.unpack_from("<I", raw_data, V5_LAYOUT["focus_time_ms"][0])[0]
        entry.timestamp_raw = struct.unpack_from("<Q", raw_data, V5_LAYOUT["last_execution"][0])[0]

    entry.last_execution, entry.timestamp_status = _parse_filetime(entry.timestamp_raw)
    if entry.timestamp_status == "not-recorded":
        entry.notes.append("no timestamp recorded; this does not imply the program never ran")
    elif entry.timestamp_status == "invalid":
        entry.notes.append(f"invalid FILETIME 0x{entry.timestamp_raw:016x}; raw value preserved")

    entry.status = "parsed"
    return entry


def iter_userassist(hive: RegistryHive, path: str = USERASSIST_KEY_PATH) -> Iterator[UserAssistEntry]:
    """Yield parsed UserAssist entries from a NTUSER.DAT hive.

    Raises:
        RegistryKeyNotFoundError: If the UserAssist key is not present.
    """
    ua_key = hive.open(path)

    for guid_key in ua_key.subkeys():
        guid = guid_key.name
        try:
            count_key = guid_key.subkey("Count")
        except RegistryKeyNotFoundError:
            log.debug("UserAssist subkey %s has no Count subkey", guid)
            continue

        for value in count_key.values():
            yield parse_userassist_value(value.name, value.data, guid=guid)
