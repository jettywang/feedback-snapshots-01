"""Read-only inspection of Btrfs send streams.

A Btrfs send stream is a sequence of length-prefixed commands, each carrying a CRC and a list of type-length-value
(TLV) attributes. This module parses such streams as evidence only: it never performs a receive operation and never
modifies a file system.

The report keeps three facts separate:

* ``parsed``: the stream header and every command and attribute were structurally interpreted without errors.
* ``complete``: a valid ``END`` command terminated the stream exactly at end-of-file.
* ``applies_to_baseline``: the stream's declared identity and operation schema can be matched to a supplied baseline.

An unknown command or attribute is preserved verbatim and reported, but never presented as a confirmed file system
change.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from uuid import UUID

from dissect.util import ts
from dissect.util.hash import crc32c

from dissect.btrfs.c_btrfs import c_btrfs
from dissect.btrfs.exceptions import SendStreamError

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime
    from typing import BinaryIO


BTRFS_SEND_STREAM_MAGIC = c_btrfs.BTRFS_SEND_STREAM_MAGIC.encode() + b"\x00"
BTRFS_SEND_STREAM_VERSION = 1

# Command numbers from fs/btrfs/send.h. Unknown numbers are preserved as-is.
BTRFS_SEND_C_UNSPEC = 0
BTRFS_SEND_C_SUBVOL = 1
BTRFS_SEND_C_SNAPSHOT = 2
BTRFS_SEND_C_MKFILE = 3
BTRFS_SEND_C_MKDIR = 4
BTRFS_SEND_C_MKNOD = 5
BTRFS_SEND_C_MKFIFO = 6
BTRFS_SEND_C_MKSOCK = 7
BTRFS_SEND_C_SYMLINK = 8
BTRFS_SEND_C_RENAME = 9
BTRFS_SEND_C_LINK = 10
BTRFS_SEND_C_UNLINK = 11
BTRFS_SEND_C_RMDIR = 12
BTRFS_SEND_C_SET_XATTR = 13
BTRFS_SEND_C_REMOVE_XATTR = 14
BTRFS_SEND_C_WRITE = 15
BTRFS_SEND_C_CLONE = 16
BTRFS_SEND_C_TRUNCATE = 17
BTRFS_SEND_C_CHMOD = 18
BTRFS_SEND_C_CHOWN = 19
BTRFS_SEND_C_UTIMES = 20
BTRFS_SEND_C_END = 21
BTRFS_SEND_C_UPDATE_EXTENT = 22
BTRFS_SEND_C_FALLOCATE = 23
BTRFS_SEND_C_FILEATTR = 24
BTRFS_SEND_C_ENCODED_WRITE = 25

COMMAND_NAMES = {
    BTRFS_SEND_C_SUBVOL: "SUBVOL",
    BTRFS_SEND_C_SNAPSHOT: "SNAPSHOT",
    BTRFS_SEND_C_MKFILE: "MKFILE",
    BTRFS_SEND_C_MKDIR: "MKDIR",
    BTRFS_SEND_C_MKNOD: "MKNOD",
    BTRFS_SEND_C_MKFIFO: "MKFIFO",
    BTRFS_SEND_C_MKSOCK: "MKSOCK",
    BTRFS_SEND_C_SYMLINK: "SYMLINK",
    BTRFS_SEND_C_RENAME: "RENAME",
    BTRFS_SEND_C_LINK: "LINK",
    BTRFS_SEND_C_UNLINK: "UNLINK",
    BTRFS_SEND_C_RMDIR: "RMDIR",
    BTRFS_SEND_C_SET_XATTR: "SET_XATTR",
    BTRFS_SEND_C_REMOVE_XATTR: "REMOVE_XATTR",
    BTRFS_SEND_C_WRITE: "WRITE",
    BTRFS_SEND_C_CLONE: "CLONE",
    BTRFS_SEND_C_TRUNCATE: "TRUNCATE",
    BTRFS_SEND_C_CHMOD: "CHMOD",
    BTRFS_SEND_C_CHOWN: "CHOWN",
    BTRFS_SEND_C_UTIMES: "UTIMES",
    BTRFS_SEND_C_END: "END",
    BTRFS_SEND_C_UPDATE_EXTENT: "UPDATE_EXTENT",
    BTRFS_SEND_C_FALLOCATE: "FALLOCATE",
    BTRFS_SEND_C_FILEATTR: "FILEATTR",
    BTRFS_SEND_C_ENCODED_WRITE: "ENCODED_WRITE",
}

# Attribute numbers from fs/btrfs/send.h. Unknown numbers are preserved as-is.
BTRFS_SEND_A_UNSPEC = 0
BTRFS_SEND_A_UUID = 1
BTRFS_SEND_A_CTRANSID = 2
BTRFS_SEND_A_INO = 3
BTRFS_SEND_A_SIZE = 4
BTRFS_SEND_A_MODE = 5
BTRFS_SEND_A_UID = 6
BTRFS_SEND_A_GID = 7
BTRFS_SEND_A_RDEV = 8
BTRFS_SEND_A_CTIME = 9
BTRFS_SEND_A_MTIME = 10
BTRFS_SEND_A_ATIME = 11
BTRFS_SEND_A_OTIME = 12
BTRFS_SEND_A_XATTR_NAME = 13
BTRFS_SEND_A_XATTR_DATA = 14
BTRFS_SEND_A_PATH = 15
BTRFS_SEND_A_PATH_TO = 16
BTRFS_SEND_A_PATH_LINK = 17
BTRFS_SEND_A_FILE_OFFSET = 18
BTRFS_SEND_A_DATA = 19
BTRFS_SEND_A_CLONE_UUID = 20
BTRFS_SEND_A_CLONE_CTRANSID = 21
BTRFS_SEND_A_CLONE_PATH = 22
BTRFS_SEND_A_CLONE_OFFSET = 23
BTRFS_SEND_A_CLONE_LEN = 24
BTRFS_SEND_A_FALLOCATE_MODE = 25
BTRFS_SEND_A_FILEATTR = 26
BTRFS_SEND_A_UNENCODED_FILE_LEN = 27
BTRFS_SEND_A_UNENCODED_LEN = 28
BTRFS_SEND_A_UNENCODED_OFFSET = 29
BTRFS_SEND_A_COMPRESSION = 30
BTRFS_SEND_A_ENCRYPTION = 31

ATTRIBUTE_NAMES = {
    BTRFS_SEND_A_UUID: "UUID",
    BTRFS_SEND_A_CTRANSID: "CTRANSID",
    BTRFS_SEND_A_INO: "INO",
    BTRFS_SEND_A_SIZE: "SIZE",
    BTRFS_SEND_A_MODE: "MODE",
    BTRFS_SEND_A_UID: "UID",
    BTRFS_SEND_A_GID: "GID",
    BTRFS_SEND_A_RDEV: "RDEV",
    BTRFS_SEND_A_CTIME: "CTIME",
    BTRFS_SEND_A_MTIME: "MTIME",
    BTRFS_SEND_A_ATIME: "ATIME",
    BTRFS_SEND_A_OTIME: "OTIME",
    BTRFS_SEND_A_XATTR_NAME: "XATTR_NAME",
    BTRFS_SEND_A_XATTR_DATA: "XATTR_DATA",
    BTRFS_SEND_A_PATH: "PATH",
    BTRFS_SEND_A_PATH_TO: "PATH_TO",
    BTRFS_SEND_A_PATH_LINK: "PATH_LINK",
    BTRFS_SEND_A_FILE_OFFSET: "FILE_OFFSET",
    BTRFS_SEND_A_DATA: "DATA",
    BTRFS_SEND_A_CLONE_UUID: "CLONE_UUID",
    BTRFS_SEND_A_CLONE_CTRANSID: "CLONE_CTRANSID",
    BTRFS_SEND_A_CLONE_PATH: "CLONE_PATH",
    BTRFS_SEND_A_CLONE_OFFSET: "CLONE_OFFSET",
    BTRFS_SEND_A_CLONE_LEN: "CLONE_LEN",
    BTRFS_SEND_A_FALLOCATE_MODE: "FALLOCATE_MODE",
    BTRFS_SEND_A_FILEATTR: "FILEATTR",
    BTRFS_SEND_A_UNENCODED_FILE_LEN: "UNENCODED_FILE_LEN",
    BTRFS_SEND_A_UNENCODED_LEN: "UNENCODED_LEN",
    BTRFS_SEND_A_UNENCODED_OFFSET: "UNENCODED_OFFSET",
    BTRFS_SEND_A_COMPRESSION: "COMPRESSION",
    BTRFS_SEND_A_ENCRYPTION: "ENCRYPTION",
}

_U64_ATTRIBUTES = {
    BTRFS_SEND_A_CTRANSID,
    BTRFS_SEND_A_INO,
    BTRFS_SEND_A_SIZE,
    BTRFS_SEND_A_MODE,
    BTRFS_SEND_A_UID,
    BTRFS_SEND_A_GID,
    BTRFS_SEND_A_RDEV,
    BTRFS_SEND_A_FILE_OFFSET,
    BTRFS_SEND_A_CLONE_CTRANSID,
    BTRFS_SEND_A_CLONE_OFFSET,
    BTRFS_SEND_A_CLONE_LEN,
    BTRFS_SEND_A_FILEATTR,
    BTRFS_SEND_A_UNENCODED_FILE_LEN,
    BTRFS_SEND_A_UNENCODED_LEN,
    BTRFS_SEND_A_UNENCODED_OFFSET,
}
_U32_ATTRIBUTES = {
    BTRFS_SEND_A_FALLOCATE_MODE,
    BTRFS_SEND_A_COMPRESSION,
    BTRFS_SEND_A_ENCRYPTION,
}
_TIME_ATTRIBUTES = {
    BTRFS_SEND_A_CTIME,
    BTRFS_SEND_A_MTIME,
    BTRFS_SEND_A_ATIME,
    BTRFS_SEND_A_OTIME,
}
_UUID_ATTRIBUTES = {
    BTRFS_SEND_A_UUID,
    BTRFS_SEND_A_CLONE_UUID,
}
_STRING_ATTRIBUTES = {
    BTRFS_SEND_A_XATTR_NAME,
    BTRFS_SEND_A_PATH,
    BTRFS_SEND_A_PATH_TO,
    BTRFS_SEND_A_PATH_LINK,
    BTRFS_SEND_A_CLONE_PATH,
}
_RAW_ATTRIBUTES = {
    BTRFS_SEND_A_XATTR_DATA,
    BTRFS_SEND_A_DATA,
}

# Attributes that a known command needs in order to be a complete, applicable operation. Attributes outside this
# set are allowed, but reported as unexpected. Missing attributes do not prevent structural parsing; they prevent
# the stream from being considered applicable to a baseline.
COMMAND_ATTRIBUTES = {
    BTRFS_SEND_C_SUBVOL: frozenset({BTRFS_SEND_A_UUID, BTRFS_SEND_A_CTRANSID, BTRFS_SEND_A_PATH}),
    BTRFS_SEND_C_SNAPSHOT: frozenset(
        {
            BTRFS_SEND_A_UUID,
            BTRFS_SEND_A_CTRANSID,
            BTRFS_SEND_A_PATH,
            BTRFS_SEND_A_CLONE_UUID,
            BTRFS_SEND_A_CLONE_CTRANSID,
        }
    ),
    BTRFS_SEND_C_MKFILE: frozenset({BTRFS_SEND_A_PATH}),
    BTRFS_SEND_C_MKDIR: frozenset({BTRFS_SEND_A_PATH}),
    BTRFS_SEND_C_MKNOD: frozenset({BTRFS_SEND_A_PATH, BTRFS_SEND_A_MODE, BTRFS_SEND_A_RDEV}),
    BTRFS_SEND_C_MKFIFO: frozenset({BTRFS_SEND_A_PATH}),
    BTRFS_SEND_C_MKSOCK: frozenset({BTRFS_SEND_A_PATH}),
    BTRFS_SEND_C_SYMLINK: frozenset({BTRFS_SEND_A_PATH, BTRFS_SEND_A_PATH_LINK}),
    BTRFS_SEND_C_RENAME: frozenset({BTRFS_SEND_A_PATH, BTRFS_SEND_A_PATH_TO}),
    BTRFS_SEND_C_LINK: frozenset({BTRFS_SEND_A_PATH, BTRFS_SEND_A_PATH_LINK}),
    BTRFS_SEND_C_UNLINK: frozenset({BTRFS_SEND_A_PATH}),
    BTRFS_SEND_C_RMDIR: frozenset({BTRFS_SEND_A_PATH}),
    BTRFS_SEND_C_SET_XATTR: frozenset({BTRFS_SEND_A_PATH, BTRFS_SEND_A_XATTR_NAME, BTRFS_SEND_A_XATTR_DATA}),
    BTRFS_SEND_C_REMOVE_XATTR: frozenset({BTRFS_SEND_A_PATH, BTRFS_SEND_A_XATTR_NAME}),
    BTRFS_SEND_C_WRITE: frozenset({BTRFS_SEND_A_PATH, BTRFS_SEND_A_FILE_OFFSET, BTRFS_SEND_A_DATA}),
    BTRFS_SEND_C_CLONE: frozenset(
        {
            BTRFS_SEND_A_PATH,
            BTRFS_SEND_A_FILE_OFFSET,
            BTRFS_SEND_A_CLONE_UUID,
            BTRFS_SEND_A_CLONE_CTRANSID,
            BTRFS_SEND_A_CLONE_PATH,
            BTRFS_SEND_A_CLONE_OFFSET,
            BTRFS_SEND_A_CLONE_LEN,
        }
    ),
    BTRFS_SEND_C_TRUNCATE: frozenset({BTRFS_SEND_A_PATH, BTRFS_SEND_A_SIZE}),
    BTRFS_SEND_C_CHMOD: frozenset({BTRFS_SEND_A_PATH, BTRFS_SEND_A_MODE}),
    BTRFS_SEND_C_CHOWN: frozenset({BTRFS_SEND_A_PATH, BTRFS_SEND_A_UID, BTRFS_SEND_A_GID}),
    BTRFS_SEND_C_UTIMES: frozenset({BTRFS_SEND_A_PATH, BTRFS_SEND_A_ATIME, BTRFS_SEND_A_MTIME}),
    BTRFS_SEND_C_END: frozenset(),
    BTRFS_SEND_C_UPDATE_EXTENT: frozenset({BTRFS_SEND_A_PATH, BTRFS_SEND_A_FILE_OFFSET}),
    BTRFS_SEND_C_FALLOCATE: frozenset(
        {BTRFS_SEND_A_PATH, BTRFS_SEND_A_FILE_OFFSET, BTRFS_SEND_A_SIZE, BTRFS_SEND_A_FALLOCATE_MODE}
    ),
    BTRFS_SEND_C_FILEATTR: frozenset({BTRFS_SEND_A_PATH, BTRFS_SEND_A_FILEATTR}),
    BTRFS_SEND_C_ENCODED_WRITE: frozenset(
        {
            BTRFS_SEND_A_PATH,
            BTRFS_SEND_A_FILE_OFFSET,
            BTRFS_SEND_A_UNENCODED_FILE_LEN,
            BTRFS_SEND_A_UNENCODED_LEN,
            BTRFS_SEND_A_UNENCODED_OFFSET,
            BTRFS_SEND_A_COMPRESSION,
            BTRFS_SEND_A_ENCRYPTION,
            BTRFS_SEND_A_DATA,
        }
    ),
}

# Real send commands carry at most a few MiB of payload (WRITE data is bounded by the sender's buffer). A much
# larger declared length is treated as a boundary error rather than an allocation request.
MAX_COMMAND_PAYLOAD = 0x01000000

_COMMAND_HEADER_SIZE = len(c_btrfs.btrfs_cmd_header)
_STREAM_HEADER_SIZE = len(c_btrfs.btrfs_stream_header)
_TLV_HEADER_SIZE = len(c_btrfs.btrfs_tlv_header)


def _crc32c(data: bytes, crc: int = 0xFFFFFFFF) -> int:
    """Calculate a raw CRC32C without the initial or final inversion.

    Args:
        data: The data to update the checksum with.
        crc: The raw initial checksum state. Defaults to ``~0``, as used by Btrfs send.
    """
    return (crc32c.update(crc ^ 0xFFFFFFFF, data) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def _command_crc(payload: bytes) -> int:
    """Calculate the CRC of a Btrfs send command.

    The kernel and btrfs-progs checksum only the payload, seeded with ``~0`` and without the final inversion of the
    standard CRC32C variant. The command header is not covered.

    Args:
        payload: The raw command payload.
    """
    return _crc32c(payload)


def _read_exact(fh: BinaryIO, size: int) -> tuple[bytes, bool]:
    """Read up to ``size`` bytes without trusting a length field for allocation.

    Returns the bytes read and whether the full requested size was available. When the stream is seekable, the
    requested size is clamped to the number of bytes remaining so a malicious length cannot cause an excessive read.
    """
    requested = size
    if hasattr(fh, "seekable") and fh.seekable():
        position = fh.tell()
        end = fh.seek(0, 2)
        fh.seek(position)
        size = min(size, max(0, end - position))

    data = fh.read(size)
    return data, len(data) == requested


@dataclass(frozen=True)
class SendTimestamp:
    """A Btrfs send timestamp, stored as seconds and nanoseconds since the Unix epoch."""

    sec: int
    nsec: int

    @property
    def nanoseconds(self) -> int:
        """Return the timestamp as nanoseconds since the Unix epoch."""
        return self.sec * 1_000_000_000 + self.nsec

    @property
    def datetime(self) -> datetime:
        """Return the timestamp as an aware UTC :class:`datetime.datetime`."""
        return ts.from_unix_ns(self.nanoseconds)


@dataclass(frozen=True)
class SendIssue:
    """A preservation notice or error encountered while parsing a send stream."""

    severity: str
    code: str
    message: str
    offset: int
    command_index: int | None = None


@dataclass
class SendTLV:
    """A single Btrfs send TLV attribute.

    ``raw`` contains the complete TLV record (header and value) exactly as it appeared in the stream. ``data``
    contains only the value bytes. ``value`` is only populated when the attribute type is known and the value length
    and encoding match the type, so an unknown or malformed value is never presented as a confirmed typed field.

    Args:
        type: The numeric attribute type.
        name: The attribute name, or ``None`` if the type is unknown.
        offset: The stream-relative offset of the TLV header.
        length: The declared value length, excluding the TLV header.
        raw: The complete raw TLV record.
        data: The value bytes.
        value: The confirmed typed value, if any.
        valid: Whether the value length and encoding are valid for a known type.
    """

    type: int
    name: str | None
    offset: int
    length: int
    raw: bytes
    data: bytes
    value: object | None
    valid: bool

    @property
    def known(self) -> bool:
        """Return whether this attribute has a known type number."""
        return self.name is not None

    @property
    def typed(self) -> bool:
        """Return whether this attribute has a confirmed typed value."""
        return self.known and self.valid and self.value is not None

    @property
    def actual_length(self) -> int:
        """Return the number of value bytes actually present in the stream."""
        return len(self.data)

    @property
    def text(self) -> str | None:
        """Return the decoded string value for string attributes, preserving arbitrary path bytes."""
        if self.type not in _STRING_ATTRIBUTES or not self.typed:
            return None
        return self.data[:-1].decode("utf-8", errors="surrogateescape")


@dataclass
class SendCommand:
    """A single command in a Btrfs send stream, with preserved raw evidence.

    Args:
        index: The one-based position of this command in the stream.
        type: The numeric command number.
        name: The command name, or ``None`` if the command number is unknown.
        offset: The stream-relative offset of the command header.
        end_offset: The stream-relative offset immediately after the command.
        payload_offset: The stream-relative offset of the command payload.
        payload_length: The declared payload length, excluding the command header.
        header: The raw command header.
        payload: The raw command payload.
        crc_stored: The CRC stored in the command header.
        crc_calculated: The calculated CRC, or ``None`` if it could not be calculated due to truncation.
        crc_valid: Whether the stored and calculated CRC match.
    """

    index: int
    type: int
    name: str | None
    offset: int
    end_offset: int
    payload_offset: int
    payload_length: int
    header: bytes
    payload: bytes
    crc_stored: int
    crc_calculated: int | None
    crc_valid: bool
    tlvs: list[SendTLV] = field(default_factory=list)
    unparsed: bytes = b""
    structurally_valid: bool = True
    attributes_valid: bool = True
    schema_complete: bool = True
    issues: list[SendIssue] = field(default_factory=list)

    @property
    def known(self) -> bool:
        """Return whether this command has a defined send command number."""
        return self.name is not None

    @property
    def valid(self) -> bool:
        """Return whether the command's framing and attribute values are structurally valid."""
        return self.known and self.structurally_valid and self.attributes_valid

    @property
    def source_range(self) -> tuple[int, int]:
        """Return the stream-relative ``(start, end)`` byte range of this command."""
        return self.offset, self.end_offset

    @property
    def mutation(self) -> bool | None:
        """Return whether this is a confirmed file system operation, or ``None`` when it cannot be confirmed.

        ``END`` is not a file system operation. Unknown commands, unknown attributes, malformed fields and
        truncated commands all return ``None`` so they can never be mistaken for an executed change.
        """
        if not self.valid or not self.schema_complete or not self.crc_valid:
            return None
        return self.type != BTRFS_SEND_C_END

    @property
    def raw(self) -> bytes:
        """Return the complete raw command, including its header and payload."""
        return self.header + self.payload

    @property
    def path(self) -> bytes | None:
        """Return the confirmed raw ``PATH`` value, if present."""
        tlv = self.get(BTRFS_SEND_A_PATH)
        return tlv.value if tlv is not None and tlv.typed else None

    def get(self, attribute: int | str) -> SendTLV | None:
        """Return the first TLV for an attribute number or name."""
        for tlv in self.tlvs:
            if attribute in (tlv.type, tlv.name):
                return tlv
        return None

    def get_all(self, attribute: int | str) -> list[SendTLV]:
        """Return all TLVs for an attribute number or name, including duplicates."""
        return [tlv for tlv in self.tlvs if attribute in (tlv.type, tlv.name)]

    def values(self) -> dict[str, object]:
        """Return a mapping of confirmed attribute names to their typed values.

        Attributes whose value could not be confirmed, or that appear more than once, are omitted so a caller can
        never observe an ambiguous value as if it were the confirmed one.
        """
        values: dict[str, object] = {}
        for tlv in self.tlvs:
            if tlv.name is None or not tlv.typed:
                continue
            if tlv.name in values:
                del values[tlv.name]
                continue
            values[tlv.name] = tlv.value
        return values


@dataclass(frozen=True)
class SendStreamHeader:
    """The fixed header at the beginning of a Btrfs send stream."""

    magic: bytes
    version: int


@dataclass(frozen=True)
class SendBaseline:
    """Identity of a baseline subvolume that an incremental send stream may apply to.

    Args:
        uuid: The UUID of the baseline subvolume.
        ctransid: The transaction ID of the baseline subvolume.
    """

    uuid: UUID | None = None
    ctransid: int | None = None


@dataclass(frozen=True)
class SendReport:
    """The result of inspecting a send stream.

    ``parsed`` means the stream header and every command and attribute were interpreted without structural or
    field-boundary errors (for example a TLV extending past the payload, or a typed value with the wrong width).
    ``complete`` means an ``END`` command terminated the stream exactly at end-of-file. ``crc_valid`` means every
    command CRC matched. ``applies_to_baseline`` is ``None`` when no baseline was supplied, otherwise it states
    whether the stream's declared prerequisites and operation schema are satisfied.

    Args:
        parsed: Whether the whole stream was structurally parsed.
        complete: Whether an ``END`` command terminated the stream exactly at end-of-file.
        crc_valid: Whether every command CRC matched.
        applies_to_baseline: Whether the stream can be applied to the supplied baseline, or ``None`` without one.
        baseline_reason: A human-readable explanation of the baseline decision.
        commands: The total number of commands.
        known_commands: The number of known commands.
        unknown_commands: The number of preserved unknown commands.
        attributes: The total number of preserved TLVs.
        unknown_attributes: The number of preserved unknown TLVs.
        end_seen: Whether an ``END`` command was seen.
        stream_size: The stream size in bytes, including any trailing data.
        trailing_size: The number of bytes after the ``END`` command.
        issues: All preservation notices and errors.
    """

    parsed: bool
    complete: bool
    crc_valid: bool
    applies_to_baseline: bool | None
    baseline_reason: str
    commands: int
    known_commands: int
    unknown_commands: int
    attributes: int
    unknown_attributes: int
    end_seen: bool
    stream_size: int
    trailing_size: int
    issues: tuple[SendIssue, ...]

    def summary(self) -> str:
        """Return a short report that keeps parsing, completeness and baseline applicability separate."""
        if self.applies_to_baseline is None:
            baseline = "not evaluated (no baseline supplied)"
        else:
            baseline = f"{'yes' if self.applies_to_baseline else 'no'} ({self.baseline_reason})"

        return "\n".join(
            [
                f"parsed: {'yes' if self.parsed else 'no'}",
                f"complete: {'yes' if self.complete else 'no'}",
                f"crc_valid: {'yes' if self.crc_valid else 'no'}",
                f"applies_to_baseline: {baseline}",
                f"commands: {self.commands} ({self.known_commands} known, {self.unknown_commands} unknown)",
                f"attributes: {self.attributes} ({self.unknown_attributes} unknown)",
                f"stream_size: {self.stream_size} bytes (trailing: {self.trailing_size})",
            ]
        )


class SendStream:
    """Read-only parser for a Btrfs send stream.

    This parser never performs a receive operation and never modifies a file system. Commands, raw TLV records and
    confirmed typed attribute values are exposed for inspection. Unknown commands and attributes are preserved, but
    are never reported as confirmed file system changes.

    Args:
        fh: A file-like object positioned at the start of a Btrfs send stream.
    """

    def __init__(self, fh: BinaryIO):
        self.offset = fh.tell()
        self.header = self._read_header(fh)
        self.commands: list[SendCommand] = []
        self.issues: list[SendIssue] = []
        self.trailing_data = b""
        self.trailing_size = 0
        self.end_seen = False
        self.end_clean = False
        self._parsed = True

        self._parse_commands(fh)
        self.stream_size = fh.tell() - self.offset

    @property
    def parsed(self) -> bool:
        """Return whether the whole stream was interpreted without structural or field-boundary errors."""
        return self._parsed

    @property
    def complete(self) -> bool:
        """Return whether an ``END`` command terminated the stream exactly at end-of-file."""
        return self.end_clean

    @property
    def crc_valid(self) -> bool:
        """Return whether every command had a valid CRC."""
        return bool(self.commands) and all(command.crc_valid for command in self.commands)

    @property
    def errors(self) -> list[SendIssue]:
        """Return all issues with error severity."""
        return [issue for issue in self.issues if issue.severity == "error"]

    @property
    def warnings(self) -> list[SendIssue]:
        """Return all issues with warning severity."""
        return [issue for issue in self.issues if issue.severity == "warning"]

    @property
    def start(self) -> SendCommand | None:
        """Return the first command, which usually declares the subvolume or snapshot."""
        return self.commands[0] if self.commands else None

    def __iter__(self) -> Iterator[SendCommand]:
        return iter(self.commands)

    def __len__(self) -> int:
        return len(self.commands)

    def _relative_offset(self, fh: BinaryIO) -> int:
        return fh.tell() - self.offset

    def _read_header(self, fh: BinaryIO) -> SendStreamHeader:
        offset = self._relative_offset(fh)
        raw = fh.read(_STREAM_HEADER_SIZE)
        if len(raw) != _STREAM_HEADER_SIZE:
            raise SendStreamError(f"Truncated send stream header at offset {offset:#x}")

        header = c_btrfs.btrfs_stream_header(raw)
        magic = bytes(header.magic)
        if magic != BTRFS_SEND_STREAM_MAGIC:
            raise SendStreamError(f"Invalid send stream magic at offset {offset:#x}: {magic!r}")
        if header.version != BTRFS_SEND_STREAM_VERSION:
            raise SendStreamError(f"Unsupported send stream version {header.version} at offset {offset:#x}")

        return SendStreamHeader(magic, header.version)

    def _parse_commands(self, fh: BinaryIO) -> None:
        while True:
            offset = abs(fh.tell() - self.offset)
            raw_header = fh.read(_COMMAND_HEADER_SIZE)
            if not raw_header:
                self._issue("error", "missing_end", "Send stream ended without an END command", offset)
                return
            if len(raw_header) != _COMMAND_HEADER_SIZE:
                self._issue("error", "truncated_command_header", "Truncated command header", offset)
                self._parsed = False
                return

            command_header = c_btrfs.btrfs_cmd_header(raw_header)
            payload_offset = offset + _COMMAND_HEADER_SIZE

            oversized = command_header.len > MAX_COMMAND_PAYLOAD
            if oversized:
                self._issue(
                    "error",
                    "command_too_large",
                    f"Command payload declares {command_header.len} bytes, above the {MAX_COMMAND_PAYLOAD} byte limit",
                    offset,
                    len(self.commands) + 1,
                )
                payload, complete_payload = b"", False
                self._parsed = False
            else:
                payload, complete_payload = _read_exact(fh, command_header.len)

            if not complete_payload and not oversized:
                self._issue(
                    "error",
                    "truncated_command_payload",
                    f"Command payload extends past end-of-stream: declared {command_header.len} bytes",
                    offset,
                    len(self.commands) + 1,
                )
                self._parsed = False

            crc_calculated = _command_crc(payload) if complete_payload else None
            crc_valid = crc_calculated is not None and crc_calculated == command_header.crc

            command = self._make_command(
                command_header,
                raw_header,
                payload,
                offset,
                payload_offset,
                crc_calculated=crc_calculated,
                crc_valid=crc_valid,
                complete_payload=complete_payload,
            )
            if not crc_valid:
                if complete_payload:
                    self._add_issue(
                        command,
                        "error",
                        "crc_mismatch",
                        f"Command CRC mismatch: stored {command_header.crc:#010x}, "
                        f"calculated {crc_calculated:#010x}",
                        offset,
                    )
                else:
                    self._add_issue(
                        command,
                        "error",
                        "crc_unverified",
                        "Command CRC cannot be verified because the payload is truncated",
                        offset,
                    )

            self.commands.append(command)

            if command_header.cmd == BTRFS_SEND_C_END:
                self._parse_end(fh, command, offset)
                return

            if not complete_payload:
                return

    def _parse_end(self, fh: BinaryIO, command: SendCommand, offset: int) -> None:
        self.end_seen = True
        self.end_clean = not command.payload_length

        if command.payload_length:
            self._add_issue(
                command,
                "error",
                "end_with_payload",
                f"END command has a {command.payload_length}-byte payload",
                offset,
            )
            self._parsed = False

        trailing_offset = self._relative_offset(fh)
        tracing = fh.read(0x1000)
        if tracing:
            self.trailing_data = tracing
            self.end_clean = False
            try:
                self.trailing_size = max(0, fh.seek(0, 2) - self.offset - trailing_offset)
            except (AttributeError, OSError):
                self.trailing_size = len(tracing)
            self._add_issue(
                command,
                "error",
                "trailing_data",
                f"{self.trailing_size} byte(s) of data follow the END command",
                trailing_offset,
            )
            self._parsed = False

    def _make_command(
        self,
        command_header: c_btrfs.btrfs_cmd_header,
        raw_header: bytes,
        payload: bytes,
        offset: int,
        payload_offset: int,
        crc_calculated: int | None,
        crc_valid: bool,
        complete_payload: bool,
    ) -> SendCommand:
        index = len(self.commands) + 1
        name = COMMAND_NAMES.get(command_header.cmd)
        command = SendCommand(
            index=index,
            type=command_header.cmd,
            name=name,
            offset=offset,
            end_offset=payload_offset + len(payload),
            payload_offset=payload_offset,
            payload_length=command_header.len,
            header=raw_header,
            payload=payload,
            crc_stored=command_header.crc,
            crc_calculated=crc_calculated,
            crc_valid=crc_valid,
        )

        if name is None:
            # Never interpret an unknown command's payload as TLVs: arbitrary bytes must not be turned into a
            # confirmed path or file change. Preserve the payload verbatim instead.
            command.unparsed = payload
            command.schema_complete = False
            self._add_issue(
                command,
                "warning",
                "unknown_command",
                f"Unknown send command {command_header.cmd}, preserved without interpretation",
                offset,
            )
            return command

        if not complete_payload:
            command.unparsed = payload
            command.structurally_valid = False
            command.attributes_valid = False
            command.schema_complete = False
            return command

        command.tlvs, command.unparsed, structurally_valid = self._parse_tlvs(command, payload, payload_offset, index)
        command.structurally_valid = structurally_valid
        if structurally_valid:
            self._validate_schema(command, payload_offset)
        else:
            command.schema_complete = False
            self._parsed = False

        return command

    def _parse_tlvs(
        self,
        command: SendCommand,
        payload: bytes,
        payload_offset: int,
        command_index: int,
    ) -> tuple[list[SendTLV], bytes, bool]:
        tlvs: list[SendTLV] = []
        position = 0

        while position < len(payload):
            offset = payload_offset + position
            remaining = len(payload) - position
            if remaining < _TLV_HEADER_SIZE:
                self._add_issue(
                    command,
                    "error",
                    "truncated_tlv_header",
                    f"Truncated TLV header: only {remaining} byte(s) remain",
                    offset,
                )
                return tlvs, payload[position:], False

            tlv_type, tlv_length = struct.unpack_from("<HH", payload, position)
            raw_start = position
            position += _TLV_HEADER_SIZE
            available = len(payload) - position
            name = ATTRIBUTE_NAMES.get(tlv_type)

            if tlv_length > available:
                tlvs.append(
                    SendTLV(tlv_type, name, offset, tlv_length, payload[raw_start:], payload[position:], None, False)
                )
                self._add_issue(
                    command,
                    "error",
                    "tlv_out_of_bounds",
                    f"TLV {name or tlv_type} declares {tlv_length} byte(s), only {available} remain",
                    offset,
                )
                return tlvs, b"", False

            data = payload[position : position + tlv_length]
            position += tlv_length
            raw = payload[raw_start:position]

            value, value_valid = self._decode_value(command, tlv_type, name, data, offset)
            tlvs.append(SendTLV(tlv_type, name, offset, tlv_length, raw, data, value, value_valid))

        return tlvs, b"", True

    def _decode_value(
        self,
        command: SendCommand,
        tlv_type: int,
        name: str | None,
        data: bytes,
        offset: int,
    ) -> tuple[object | None, bool]:
        if name is None:
            self._add_issue(
                command,
                "warning",
                "unknown_tlv",
                f"Unknown send attribute {tlv_type}, preserved without interpretation",
                offset,
            )
            return None, True

        if tlv_type in _UUID_ATTRIBUTES:
            if len(data) != 16:
                return self._invalid_length(command, name, data, 16, offset)
            return UUID(bytes=data), True

        if tlv_type in _U64_ATTRIBUTES:
            if len(data) != 8:
                return self._invalid_length(command, name, data, 8, offset)
            return int.from_bytes(data, "little"), True

        if tlv_type in _U32_ATTRIBUTES:
            if len(data) != 4:
                return self._invalid_length(command, name, data, 4, offset)
            return int.from_bytes(data, "little"), True

        if tlv_type in _TIME_ATTRIBUTES:
            if len(data) != 12:
                return self._invalid_length(command, name, data, 12, offset)
            sec, nsec = struct.unpack("<QI", data)
            return SendTimestamp(sec, nsec), True

        if tlv_type in _STRING_ATTRIBUTES:
            if not data.endswith(b"\x00"):
                self._add_issue(
                    command,
                    "error",
                    "invalid_string_terminator",
                    f"Attribute {name} is not NUL-terminated",
                    offset,
                )
                command.attributes_valid = False
                self._parsed = False
                return None, False
            return data[:-1], True

        if tlv_type in _RAW_ATTRIBUTES:
            return data, True

        return None, True

    def _invalid_length(
        self,
        command: SendCommand,
        name: str,
        data: bytes,
        expected: int,
        offset: int,
    ) -> tuple[None, bool]:
        self._add_issue(
            command,
            "error",
            "invalid_attribute_length",
            f"Attribute {name} has {len(data)} byte(s), expected {expected}",
            offset,
        )
        command.attributes_valid = False
        self._parsed = False
        return None, False

    def _validate_schema(self, command: SendCommand, payload_offset: int) -> None:
        expected = COMMAND_ATTRIBUTES.get(command.type)
        if expected is None:
            command.schema_complete = False
            return

        seen: set[int] = set()
        for tlv in command.tlvs:
            if tlv.type in seen:
                self._add_issue(
                    command,
                    "warning",
                    "duplicate_tlv",
                    f"Duplicate attribute {tlv.name or tlv.type}",
                    tlv.offset,
                )
                command.schema_complete = False
            seen.add(tlv.type)

            if not tlv.known or not tlv.valid:
                command.schema_complete = False
                command.attributes_valid = False

        missing = expected - seen
        if missing:
            command.schema_complete = False
            for attribute in sorted(missing):
                self._add_issue(
                    command,
                    "warning",
                    "missing_tlv",
                    f"Command {command.name} is missing required attribute {ATTRIBUTE_NAMES[attribute]}",
                    payload_offset,
                )

    def _add_issue(
        self,
        command: SendCommand,
        severity: str,
        code: str,
        message: str,
        offset: int,
    ) -> None:
        issue = SendIssue(severity, code, message, offset, command.index)
        command.issues.append(issue)
        self.issues.append(issue)

    def _issue(
        self,
        severity: str,
        code: str,
        message: str,
        offset: int,
        command_index: int | None = None,
    ) -> None:
        self.issues.append(SendIssue(severity, code, message, offset, command_index))

    def report(self, baseline: SendBaseline | None = None) -> SendReport:
        """Return a summary of parsing, completeness, integrity and baseline applicability.

        Args:
            baseline: Optional identity of the subvolume this stream would be applied to.
        """
        applies, reason = self._check_baseline(baseline)
        return SendReport(
            parsed=self.parsed,
            complete=self.complete,
            crc_valid=self.crc_valid,
            applies_to_baseline=applies,
            baseline_reason=reason,
            commands=len(self.commands),
            known_commands=sum(1 for command in self.commands if command.known),
            unknown_commands=sum(1 for command in self.commands if not command.known),
            attributes=sum(len(command.tlvs) for command in self.commands),
            unknown_attributes=sum(1 for command in self.commands for tlv in command.tlvs if not tlv.known),
            end_seen=self.end_seen,
            stream_size=self.stream_size,
            trailing_size=self.trailing_size,
            issues=tuple(self.issues),
        )

    def _check_baseline(self, baseline: SendBaseline | None) -> tuple[bool | None, str]:
        if baseline is None:
            return None, "No baseline supplied"

        if not self.commands:
            return False, "Stream contains no commands"

        unknown = next((command for command in self.commands if not command.known), None)
        if unknown is not None:
            return False, f"Stream contains unknown command {unknown.type} at command {unknown.index}"

        if not self.parsed:
            return False, "Stream could not be fully parsed"

        if not self.complete:
            return False, "Stream is not complete: no END command at end-of-file"

        if not self.crc_valid:
            return False, "One or more command CRCs are invalid"

        if any(not tlv.known for command in self.commands for tlv in command.tlvs):
            return False, "Stream contains unknown attributes whose effect cannot be confirmed"

        if any(not command.schema_complete for command in self.commands):
            return False, "One or more commands are missing required attributes or have invalid values"

        start = self.commands[0]
        if start.type not in (BTRFS_SEND_C_SUBVOL, BTRFS_SEND_C_SNAPSHOT):
            return False, f"Stream starts with {start.name}, not a subvolume or snapshot declaration"

        if start.type == BTRFS_SEND_C_SUBVOL:
            return True, "Full stream creates a new subvolume and does not depend on the baseline"

        snapshots = [command for command in self.commands if command.type == BTRFS_SEND_C_SNAPSHOT]
        if len(snapshots) != 1:
            return False, f"Stream contains {len(snapshots)} SNAPSHOT declarations, expected one"

        snapshot = snapshots[0]
        clone_uuid = snapshot.get(BTRFS_SEND_A_CLONE_UUID)
        clone_ctransid = snapshot.get(BTRFS_SEND_A_CLONE_CTRANSID)
        if clone_uuid is None or clone_ctransid is None or not clone_uuid.typed or not clone_ctransid.typed:
            return False, "Incremental stream has no confirmed clone UUID and transaction ID"

        if baseline.uuid != clone_uuid.value:
            return False, "Baseline UUID does not match the stream's clone UUID"

        if baseline.ctransid != clone_ctransid.value:
            return False, "Baseline transaction ID does not match the stream's clone transaction ID"

        return True, "Baseline UUID and transaction ID match the incremental stream"


def parse_send_stream(fh: BinaryIO) -> SendStream:
    """Parse a Btrfs send stream without performing a receive operation.

    Args:
        fh: A file-like object positioned at the start of a Btrfs send stream.
    """
    return SendStream(fh)


def inspect_send_stream(fh: BinaryIO, baseline: SendBaseline | None = None) -> SendReport:
    """Parse a Btrfs send stream and return its report.

    Args:
        fh: A file-like object positioned at the start of a Btrfs send stream.
        baseline: Optional identity of the subvolume this stream would be applied to.
    """
    return SendStream(fh).report(baseline)
