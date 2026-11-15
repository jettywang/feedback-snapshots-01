from __future__ import annotations

import logging
from datetime import datetime
from struct import unpack
from uuid import UUID

from dissect.util.ts import dostimestamp

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False

# Shell item type classes, keyed on the high nibble of the shell item type byte.
SHELL_ITEM_TYPE_NAMES = {
    0x10: "root-folder",
    0x20: "volume",
    0x30: "file-entry",
    0x40: "network-location",
    0x60: "uri",
    0x70: "control-panel",
}

# Well known root folder (0x1f) shell item GUIDs.
ROOT_FOLDER_GUIDS = {
    "20d04fe0-3aea-1069-a2d8-08002b30309d": "My Computer",
    "208d2c60-3aea-1069-a2d7-08002b30309d": "My Network Places",
    "2227a280-3aea-1069-a2de-08002b30309d": "Printers",
    "21ec2020-3aea-1069-a2dd-08002b30309d": "Control Panel",
    "645ff040-5081-101b-9f08-00aa002f954e": "Recycle Bin",
}

BEEF_SIGNATURE = 0xBEEF0000
BEEF_SIGNATURE_MASK = 0xFFFF0000


def _dos_timestamp(data: bytes, offset: int) -> datetime | None:
    """Read a swapped (date word first) MS-DOS timestamp from data at offset."""
    if offset + 4 > len(data):
        return None
    value = unpack("<I", data[offset : offset + 4])[0]
    if not value:
        return None
    try:
        # Shell items store MS-DOS timestamps with the date and time words swapped.
        return dostimestamp(value, swap=True)
    except (ValueError, OverflowError):
        return None


def _read_cstring(data: bytes, offset: int, unicode: bool = False) -> tuple[str, int]:
    """Read a NULL-terminated string from data at offset. Returns the string and the offset past it."""
    if unicode:
        end = offset
        while end + 1 < len(data) and data[end : end + 2] != b"\x00\x00":
            end += 2
        text = data[offset:end].decode("utf-16-le", errors="replace")
        return text, min(end + 2, len(data))

    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    text = data[offset:end].decode("cp1252", errors="replace")
    return text, min(end + 1, len(data))


class ExtensionBlock:
    """Class that represents a single extension block of a file entry shell item.

    Extension blocks are bounded by their own size field and always stay within the shell item they belong to.
    Unknown (non 0xbeef) extension blocks are kept as raw data only.

    Args:
        data: The raw bytes of this extension block.
    """

    def __init__(self, data: bytes):
        self.data = data
        self.size = None
        self.version = None
        self.signature = None
        self.creation_time = None
        self.access_time = None
        self.long_name = None
        self.error = None

        if len(data) < 12:
            self.error = "extension block too small"
            return

        self._parse(data)

    @property
    def is_beef(self) -> bool:
        return self.signature is not None and (self.signature & BEEF_SIGNATURE_MASK) == BEEF_SIGNATURE

    def _parse(self, data: bytes) -> None:
        self.size, self.version, self.signature = unpack("<HHI", data[:8])

        if not self.is_beef:
            # Unknown extension block signature. Kept as raw data, the size field still
            # allows the parser to skip to the next extension block.
            return

        self.creation_time = _dos_timestamp(data, 0x08)
        self.access_time = _dos_timestamp(data, 0x0C)

        if len(data) < 0x12:
            self.error = "truncated beef extension block"
            return

        # The word at offset 0x10 holds the offset of the long name within this extension block.
        name_offset = unpack("<H", data[0x10:0x12])[0]
        if not 0x12 <= name_offset < len(data):
            self.error = f"invalid long name offset 0x{name_offset:x}"
            return

        # 0xbeef0003 (Windows 2000) blocks carry an ANSI long name, later versions a Unicode one.
        self.long_name, _ = _read_cstring(data, name_offset, unicode=(self.signature & 0xFFFF) != 0x0003)

    def __repr__(self) -> str:
        if self.is_beef:
            return (
                f"<ExtensionBlock signature=0x{self.signature:08x} version={self.version} "
                f"long_name={self.long_name!r}>"
            )
        return f"<ExtensionBlock size={self.size} raw>"


class ShellItem:
    """Class that represents a single SHITEMID entry of an IDList.

    Unknown shell item types are kept as raw entries only. No attempt is made to scan the
    raw data for printable strings to guess a name.

    Args:
        itemid_size: The declared size of the SHITEMID structure, including the size field itself.
        data: The raw shell item data, excluding the size field.
    """

    def __init__(self, itemid_size: int, data: bytes):
        self.itemid_size = itemid_size
        self.data = data
        self.type = data[0] if data else 0
        self.error = None
        self._parse()

    def _parse(self) -> None:
        pass

    @property
    def type_name(self) -> str:
        return SHELL_ITEM_TYPE_NAMES.get(self.type & 0xF0, "unknown")

    @property
    def name(self) -> str | None:
        return None

    def get_path_component(self) -> str | None:
        """Return the path component this shell item resolves to, or None if it does not resolve to one."""
        return self.name

    def __repr__(self) -> str:
        return f"<ShellItem type=0x{self.type:02x} size={self.itemid_size} raw>"


class RootFolderShellItem(ShellItem):
    """Class that represents a root folder (0x1f) shell item, containing a shell folder GUID."""

    def _parse(self) -> None:
        self.guid = None
        if len(self.data) >= 18:
            self.guid = UUID(bytes_le=self.data[2:18])
        else:
            self.error = "truncated root folder shell item"

    @property
    def name(self) -> str | None:
        if self.guid is None:
            return None
        return ROOT_FOLDER_GUIDS.get(str(self.guid), f"{{{self.guid}}}")

    def get_path_component(self) -> str | None:
        # A root folder is a namespace container, not a file system path component.
        return None


class VolumeShellItem(ShellItem):
    """Class that represents a volume (0x20 class) shell item, e.g. a drive letter like C:\\."""

    def _parse(self) -> None:
        self.drive = None
        data = self.data
        if len(data) >= 3 and data[2] == 0x3A and (0x41 <= data[1] <= 0x5A or 0x61 <= data[1] <= 0x7A):
            self.drive = f"{chr(data[1]).upper()}:"

    @property
    def name(self) -> str | None:
        if self.drive is None:
            return None
        if self.data[3:4] == b"\\":
            return f"{self.drive}\\"
        return self.drive


class FileEntryShellItem(ShellItem):
    """Class that represents a file entry (0x30 class) shell item.

    Holds the primary (short) name, the file metadata and the extension blocks of the entry.
    Extension blocks never escape the bounds of this entry. The long name and the timestamps
    stored in extension blocks are kept separately from the primary name and modification time.
    """

    def _parse(self) -> None:
        self.file_size = None
        self.modification_time = None
        self.file_attributes = None
        self.primary_name = None
        self.extension_blocks: list[ExtensionBlock] = []

        data = self.data
        if len(data) < 0x0C:
            self.error = "truncated file entry shell item"
            return

        self.file_size = unpack("<I", data[2:6])[0]
        self.modification_time = _dos_timestamp(data, 6)
        self.file_attributes = unpack("<H", data[10:12])[0]

        # Type bit 0x04 marks entries with a Unicode primary name.
        self.primary_name, offset = _read_cstring(data, 0x0C, unicode=bool(self.type & 0x04))
        if not self.type & 0x04 and offset % 2:
            # ANSI primary names are padded to an even offset before the extension blocks.
            offset += 1

        self._parse_extensions(offset)

    def _parse_extensions(self, offset: int) -> None:
        data = self.data
        while offset < len(data):
            if len(data) - offset < 4:
                # Not enough room for another extension block header. Trailing padding is ignored.
                if any(data[offset:]):
                    log.debug("Ignoring %d trailing byte(s) in file entry shell item", len(data) - offset)
                break

            size = unpack("<H", data[offset : offset + 2])[0]
            if size < 4:
                # An extension block can never be smaller than its own header. Stop here to
                # guarantee progress, the remainder of this entry is left unparsed.
                self.error = f"invalid extension block size {size} at offset 0x{offset:x}"
                break

            block_data = data[offset : offset + size]
            block = ExtensionBlock(block_data)
            if len(block_data) < size:
                # The declared extension block size exceeds the entry. The block is truncated,
                # but it can never consume data of a following shell item.
                block.error = "truncated extension block"
                self.extension_blocks.append(block)
                break

            self.extension_blocks.append(block)
            offset += size

    @property
    def is_directory(self) -> bool:
        return bool(self.file_attributes and self.file_attributes & 0x10)

    @property
    def long_name(self) -> str | None:
        for block in self.extension_blocks:
            if block.long_name:
                return block.long_name
        return None

    @property
    def name(self) -> str | None:
        return self.long_name or self.primary_name


def parse_shell_item(itemid_size: int, data: bytes) -> ShellItem:
    """Parse a single SHITEMID entry into a specific ShellItem class based on its type."""
    if data:
        item_type = data[0]
        if item_type == 0x1F:
            return RootFolderShellItem(itemid_size, data)
        type_class = item_type & 0xF0
        if type_class == 0x20:
            return VolumeShellItem(itemid_size, data)
        if type_class == 0x30:
            return FileEntryShellItem(itemid_size, data)
    return ShellItem(itemid_size, data)
