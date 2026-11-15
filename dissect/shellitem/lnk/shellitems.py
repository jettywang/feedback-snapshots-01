from __future__ import annotations

import logging
import struct
from datetime import datetime
from typing import Any
from uuid import UUID

from dissect.util import ts

log = logging.getLogger(__name__)

# Class type indicator values as described in [MS-SHLLKG] / observed on Windows.
ROOT_FOLDER_SHELL_ITEM = 0x1F
VOLUME_SHELL_ITEM = 0x2F
FILE_ENTRY_SHELL_ITEM_MIN = 0x30
FILE_ENTRY_SHELL_ITEM_MAX = 0x3F

# Signature stored at the start of every FileEntryShellItem extension block.
EXTENSION_SIGNATURE = 0xBEEF0004
# Extension versions (ExtensionVersion field) that have been observed in the wild.
EXTENSION_VERSION_WINDOWS_XP = 3
EXTENSION_VERSION_VISTA = 7
EXTENSION_VERSION_WINDOWS_7 = 8
EXTENSION_VERSION_WINDOWS_8 = 9

# FileEntryShellItem header layout (offsets inside the item data, excluding the size field).
FILE_ENTRY_HEADER_SIZE = 12
FILE_ENTRY_NAME_OFFSET = 12
# Extension block minimum size: size(2) + version(2) + signature(4).
EXTENSION_HEADER_SIZE = 8
# FileEntryShellItem classes below are treated as directories, the rest as files.
FILE_ENTRY_DIRECTORY_CLASSES = frozenset({0x31, 0x32})
# RootFolderShellItem payload: class type(1) + CLSID(16).
ROOT_FOLDER_HEADER_SIZE = 17
# VolumeShellItem payload: class type(1) followed by the data area.
VOLUME_HEADER_SIZE = 1
TERMINAL_ITEM_SIZE = 2
# A SHITEMID must at least hold its own size field plus a class type indicator byte.
MINIMUM_ITEM_SIZE = 3


def _safe_wintimestamp(raw: int) -> datetime | None:
    """Convert a FILETIME value, returning ``None`` when the raw value is unset or out of range."""
    if raw == 0:
        return None
    try:
        return ts.wintimestamp(raw)
    except (OverflowError, ValueError, OSError):
        log.warning("Encountered out of range FILETIME value 0x%x. Keeping the raw value instead.", raw)
        return None


def _safe_dostimestamp(raw: int) -> datetime | None:
    """Convert an MS-DOS date/time value, returning ``None`` when unset or not decodable."""
    if raw == 0:
        return None
    try:
        return ts.dostimestamp(raw)
    except (OverflowError, ValueError, OSError):
        log.warning("Encountered invalid MS-DOS timestamp value 0x%x. Keeping it unset.", raw)
        return None


def _decode_codepage(data: bytes) -> str:
    """Decode a shell item name stored in the system code page without raising."""
    return data.decode("latin-1", errors="backslashreplace")


def _read_utf16_c_string(data: bytes, offset: int) -> tuple[str | None, int]:
    """Read a NUL terminated UTF-16-LE string, treating ``offset`` as its exact start.

    Only full 16-bit code units are considered, so the high zero byte of a regular character can
    never be mistaken for the terminator even when ``offset`` is not 16-bit aligned.
    """
    end = offset
    while end + 1 < len(data) and data[end : end + 2] != b"\x00\x00":
        end += 2
    if end + 1 >= len(data):
        return None, len(data)
    value = data[offset:end].decode("utf-16-le", errors="backslashreplace")
    return value, end + 2


def _read_c_string(data: bytes, offset: int, character_size: int) -> tuple[str | None, int]:
    """Read a NUL terminated string starting at ``offset``.

    Args:
        data: Buffer containing the string.
        offset: Offset at which the string starts.
        character_size: Size of a single character, 1 for code page strings and 2 for UTF-16 strings.

    Returns:
        A tuple of the decoded string (``None`` when absent) and the offset just past the terminator.
    """
    if character_size == 2:
        return _read_utf16_c_string(data, offset)

    end = data.find(b"\x00", offset)
    if end == -1:
        return None, len(data)
    return _decode_codepage(data[offset:end]), end + 1


class ExtensionBlock:
    """A single FileEntryShellItem extension block.

    Extension blocks carry the long name of an entry together with creation, access and write timestamps
    that are not part of the short FileEntryShellItem header. Blocks stay attached to the item that
    contains them.

    Args:
        version: Value of the ExtensionVersion field.
        signature: Value of the ExtensionSignature field.
        size: Declared size of the block in bytes.
        raw: Raw bytes of the block, exactly ``size`` bytes when fully available.
    """

    def __init__(self, version: int, signature: int, size: int, raw: bytes):
        self.version = version
        self.signature = signature
        self.size = size
        self.raw = raw
        self.creation_time = None
        self.access_time = None
        self.write_time = None
        self.long_name = None
        self.long_name_size = None
        self.localized_name = None
        self.ntfs_file_reference = None
        self.unknown = False

    @property
    def name(self) -> str | None:
        """Return the most descriptive name carried by this extension block."""
        return self.long_name

    def __repr__(self) -> str:
        details = [f"version={self.version}", f"size={self.size}"]
        if self.long_name is not None:
            details.append(f"long_name={self.long_name!r}")
        if self.unknown:
            details.append("unknown=True")
        return f"<ExtensionBlock {' '.join(details)}>"


class ShellItem:
    """Base class for parsed SHITEMID entries.

    Args:
        class_type: Value of the class type indicator byte.
        size: Declared size of the SHITEMID, including its 16-bit size field.
        raw: Raw bytes of the item data, excluding the 16-bit size field.
    """

    type_name = "unknown"

    def __init__(self, class_type: int | None, size: int, raw: bytes):
        self.class_type = class_type
        self.size = size
        self.raw = raw
        self._name = None
        self.parsed = False
        self.truncated = False

    @property
    def name(self) -> str | None:
        """Return the primary name evidence carried by this item, if any."""
        return self._name

    @property
    def path_component(self) -> str | None:
        """Return the path component represented by this item, if any."""
        return self.name

    def __repr__(self) -> str:
        status = "truncated " if self.truncated else ""
        class_type = f"0x{self.class_type:02x}" if self.class_type is not None else "None"
        component = f" name={self.name!r}" if self.name is not None else ""
        return f"<{self.__class__.__name__} {status}type={class_type} size={self.size}{component}>"


class RootFolderShellItem(ShellItem):
    """A root folder item (class type 0x1F), typically the root of a namespace such as My Computer."""

    type_name = "root_folder"

    def __init__(self, size: int, raw: bytes):
        super().__init__(ROOT_FOLDER_SHELL_ITEM, size, raw)
        self.shell_folder_id = None
        self.drive_letter = None
        self.parsed = True
        if len(raw) >= ROOT_FOLDER_HEADER_SIZE:
            self.shell_folder_id = str(UUID(bytes_le=raw[1:17]))
            drive, _ = _read_c_string(raw, ROOT_FOLDER_HEADER_SIZE, 1)
            self.drive_letter = drive or None

    @property
    def path_component(self) -> str | None:
        return self.drive_letter

    def __repr__(self) -> str:
        return (
            f"<RootFolderShellItem size={self.size} shell_folder_id={self.shell_folder_id!r} "
            f"drive_letter={self.drive_letter!r}>"
        )


class VolumeShellItem(ShellItem):
    """A volume item (class type 0x2F) carrying a drive letter and optional volume label."""

    type_name = "volume"

    def __init__(self, size: int, raw: bytes):
        super().__init__(VOLUME_SHELL_ITEM, size, raw)
        self.drive_letter = None
        self.volume_label_ansi = None
        self.volume_label_unicode = None
        self.parsed = len(raw) >= VOLUME_HEADER_SIZE
        if not self.parsed:
            self.truncated = True
            return

        drive, offset = _read_c_string(raw, VOLUME_HEADER_SIZE, 1)
        self.drive_letter = drive or None
        if offset < len(raw):
            label, offset = _read_c_string(raw, offset, 1)
            self.volume_label_ansi = label or None
        if offset < len(raw):
            unicode_label, _ = _read_c_string(raw, offset, 2)
            self.volume_label_unicode = unicode_label or None

    @property
    def name(self) -> str | None:
        return self.volume_label_unicode or self.volume_label_ansi or self.drive_letter

    @property
    def path_component(self) -> str | None:
        return self.drive_letter


class FileEntryShellItem(ShellItem):
    """A file or directory entry (class types 0x30-0x3F).

    The entry keeps its short (8.3 style) name, file system metadata and any extension blocks that
    follow it. Long names and the additional timestamps inside the extension blocks are kept separate
    from the short name.
    """

    def __init__(self, class_type: int, size: int, raw: bytes):
        super().__init__(class_type, size, raw)
        self.sub_type = None
        self.file_size = None
        self.modified_time = None
        self.file_attributes = None
        self.short_name = None
        self.extensions: list[ExtensionBlock] = []
        self.extension_padding = 0
        self.is_directory = class_type in FILE_ENTRY_DIRECTORY_CLASSES
        self.type_name = "directory" if self.is_directory else "file"

        if len(raw) < FILE_ENTRY_HEADER_SIZE:
            self.truncated = True
            log.warning(
                "Encountered truncated FileEntryShellItem (size %i, need %i bytes).",
                len(raw),
                FILE_ENTRY_HEADER_SIZE,
            )
            return

        self.sub_type = raw[1]
        self.file_size = struct.unpack_from("<I", raw, 2)[0]
        modified_raw = struct.unpack_from("<I", raw, 6)[0]
        self.modified_time = _safe_dostimestamp(modified_raw)
        self.file_attributes = struct.unpack_from("<H", raw, 10)[0]

        short_name, name_end = _read_c_string(raw, FILE_ENTRY_NAME_OFFSET, 1)
        self.short_name = short_name
        self._name = short_name
        self.parsed = True
        # The first extension block starts on a 16-bit aligned offset inside the item data.
        extension_offset = name_end
        if extension_offset % 2:
            extension_offset += 1
            self.extension_padding = 1
        self._parse_extensions(raw, extension_offset)

    def _parse_extensions(self, raw: bytes, offset: int) -> None:
        while offset < len(raw):
            if len(raw) - offset < EXTENSION_HEADER_SIZE:
                log.warning("Encountered trailing %i byte(s) that cannot form an extension block.", len(raw) - offset)
                break

            block_size, version = struct.unpack_from("<HH", raw, offset)
            signature = struct.unpack_from("<I", raw, offset + 4)[0]
            if block_size < EXTENSION_HEADER_SIZE or offset + block_size > len(raw):
                log.warning(
                    "Encountered extension block with invalid size %i at offset %i. Remaining bytes stay raw.",
                    block_size,
                    offset,
                )
                break

            block_raw = raw[offset : offset + block_size]
            block = self._parse_extension_block(version, signature, block_size, block_raw)
            self.extensions.append(block)
            if block.long_name and self._name == self.short_name:
                self._name = block.long_name
            offset += block_size

    def _parse_extension_block(self, version: int, signature: int, block_size: int, block_raw: bytes) -> ExtensionBlock:
        block = ExtensionBlock(version=version, signature=signature, size=block_size, raw=block_raw)
        if signature != EXTENSION_SIGNATURE:
            block.unknown = True
            log.warning(
                "Encountered extension block with unknown signature 0x%08x. Keeping it as raw bytes.",
                signature,
            )
            return block

        if version == EXTENSION_VERSION_WINDOWS_XP:
            self._parse_xp_extension(block, block_raw)
        elif version in (
            EXTENSION_VERSION_VISTA,
            EXTENSION_VERSION_WINDOWS_7,
            EXTENSION_VERSION_WINDOWS_8,
        ):
            self._parse_vista_extension(block, block_raw)
        else:
            block.unknown = True
            log.warning("Encountered extension block with unsupported version %i. Keeping it as raw bytes.", version)
        return block

    @staticmethod
    def _parse_xp_extension(block: ExtensionBlock, raw: bytes) -> None:
        if len(raw) < 20:
            block.unknown = True
            return
        creation_raw, access_raw = struct.unpack_from("<II", raw, 8)
        block.creation_time = _safe_dostimestamp(creation_raw)
        block.access_time = _safe_dostimestamp(access_raw)
        block.ntfs_file_reference = raw[16:19]
        long_name, _ = _read_c_string(raw, 20, 2)
        block.long_name = long_name

    @staticmethod
    def _parse_vista_extension(block: ExtensionBlock, raw: bytes) -> None:
        if len(raw) < 42:
            block.unknown = True
            return
        creation_raw, access_raw = struct.unpack_from("<QQ", raw, 8)
        block.creation_time = _safe_wintimestamp(creation_raw)
        block.access_time = _safe_wintimestamp(access_raw)
        block.ntfs_file_reference = raw[24:32]
        # LongNameSize (offset 36) is retained for reference; the actual strings are located by
        # their UTF-16 NUL terminators because observed blocks append a localized name directly
        # after the long name.
        block.long_name_size = struct.unpack_from("<I", raw, 36)[0]
        # Version 9 blocks insert a 4 byte data area before the name, moving it to offset 46.
        long_name_start = 46 if block.version == EXTENSION_VERSION_WINDOWS_8 else 42
        if long_name_start < len(raw):
            block.long_name, name_end = _read_utf16_c_string(raw, long_name_start)
            if name_end < len(raw):
                block.localized_name, _ = _read_utf16_c_string(raw, name_end)

    @property
    def path_component(self) -> str | None:
        return self.name

    def __repr__(self) -> str:
        return (
            f"<FileEntryShellItem type=0x{self.class_type:02x} size={self.size} "
            f"short_name={self.short_name!r} name={self.name!r} directory={self.is_directory} "
            f"extensions={len(self.extensions)} truncated={self.truncated}>"
        )


class UnknownShellItem(ShellItem):
    """An item with a class type that is not understood.

    The raw bytes are preserved verbatim. No printable strings are scanned out of them, so opaque
    data can never be mistaken for a file name.
    """

    type_name = "unknown"

    def __init__(self, class_type: int | None, size: int, raw: bytes):
        super().__init__(class_type, size, raw)


class TerminalShellItem(ShellItem):
    """The 16-bit zero terminator that ends an IDList."""

    type_name = "terminal"

    def __init__(self) -> None:
        super().__init__(None, TERMINAL_ITEM_SIZE, b"\x00\x00")
        self.parsed = True


class TruncatedShellItem(ShellItem):
    """An item whose declared size exceeds the bytes that are actually available."""

    type_name = "truncated"

    def __init__(self, class_type: int | None, size: int, raw: bytes):
        super().__init__(class_type, size, raw)
        self.truncated = True


def parse_shell_item(size: int, data: bytes) -> ShellItem:
    """Parse a single SHITEMID from its size field and item data.

    Args:
        size: Declared size of the SHITEMID including its 16-bit size field.
        data: Item data bytes, i.e. the SHITEMID without its leading size field.

    Returns:
        A :class:`ShellItem` subclass describing the evidence found in the item.
    """
    if not data:
        return TruncatedShellItem(None, size, data)

    class_type = data[0]
    if class_type == ROOT_FOLDER_SHELL_ITEM:
        item: ShellItem = RootFolderShellItem(size, data)
    elif class_type == VOLUME_SHELL_ITEM:
        item = VolumeShellItem(size, data)
    elif FILE_ENTRY_SHELL_ITEM_MIN <= class_type <= FILE_ENTRY_SHELL_ITEM_MAX:
        item = FileEntryShellItem(class_type, size, data)
    else:
        item = UnknownShellItem(class_type, size, data)
    return item


def parse_idlist(data: bytes) -> tuple[list[ShellItem], TerminalShellItem | None, list[dict[str, Any]]]:
    """Parse the body of an IDList into individual shell items.

    Args:
        data: Bytes following the IDListSize field, up to and including the 16-bit terminal ID.

    Returns:
        A tuple of parsed shell items, the terminal item (when present) and a list of warning
        dictionaries describing structural problems such as zero-progress or truncated items.
    """
    items: list[ShellItem] = []
    warnings: list[dict[str, Any]] = []
    terminal: TerminalShellItem | None = None
    offset = 0

    while offset < len(data):
        if len(data) - offset < 2:
            warnings.append({"offset": offset, "reason": "truncated_size_field", "size": None})
            items.append(TruncatedShellItem(None, len(data) - offset, data[offset:]))
            break

        item_size = struct.unpack_from("<H", data, offset)[0]
        if item_size == 0:
            terminal = TerminalShellItem()
            offset += TERMINAL_ITEM_SIZE
            break

        if item_size < MINIMUM_ITEM_SIZE:
            warnings.append({"offset": offset, "reason": "zero_progress", "size": item_size})
            log.warning("Encountered SHITEMID with non-progressing size %i at offset %i.", item_size, offset)
            break

        item_start = offset + 2
        item_end = offset + item_size
        if item_end > len(data):
            warnings.append({"offset": offset, "reason": "truncated_item", "size": item_size})
            items.append(
                TruncatedShellItem(data[item_start] if item_start < len(data) else None, item_size, data[item_start:])
            )
            break

        items.append(parse_shell_item(item_size, data[item_start:item_end]))
        offset = item_end

    if terminal is None and not warnings:
        warnings.append({"offset": offset, "reason": "missing_terminal", "size": None})

    return items, terminal, warnings
