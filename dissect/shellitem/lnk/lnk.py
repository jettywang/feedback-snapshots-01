from __future__ import annotations

import logging
import typing
from dataclasses import dataclass
from io import BytesIO
from struct import unpack
from typing import Any, BinaryIO
from uuid import UUID

from dissect.shellitem.lnk.c_lnk import (
    COMMON_NETWORK_RELATIVE_LINK_HEADER_SIZE,
    COMMON_NETWORK_RELATIVE_LINK_UNICODE_HEADER_SIZE,
    EXTRA_DATA_BLOCK_SIGNATURES,
    LINK_EXTRA_DATA_HEADER_SIZE,
    LINK_HEADER_SIZE,
    LINK_INFO_BODY_SIZE,
    LINK_INFO_HEADER_SIZE,
    LINK_INFO_UNICODE_HEADER_SIZE,
    c_lnk,
)
from dissect.util.stream import RangeStream

if typing.TYPE_CHECKING:
    from io import BufferedReader

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


class LnkExtraData:
    """Class that represents the a LNK file's EXTRA_DATA structure.

    This optional structure hold additional optional structures that convey additional information about a link target

    Args:
        fh: A file-like object to an EXTRA_DATA structure
    """

    # EXTRA_DATA = *EXTRA_DATA_BLOCK TERMINAL_BLOCK

    # EXTRA_DATA_BLOCK = CONSOLE_PROPS / CONSOLE_FE_PROPS / DARWIN_PROPS /
    #                    ENVIRONMENT_PROPS / ICON_ENVIRONMENT_PROPS /
    #                    KNOWN_FOLDER_PROPS / PROPERTY_STORE_PROPS /
    #                    SHIM_PROPS / SPECIAL_FOLDER_PROPS /
    #                    TRACKER_PROPS / VISTA_AND_ABOVE_IDLIST_PROPS
    # This is kinda the same as LnkStringData only that the defined extra structures can wildly vary
    def __init__(self, fh: BinaryIO | None = None):
        self.extradata = {}

        if fh:
            self._parse(fh)

    def _parse(self, fh: BinaryIO) -> None:
        self.size = c_lnk.uint32(fh)

        if self.size == 0x00000000:
            # terminal block encountered. end of lnk file
            self.extradata.update({"TERMINAL_BLOCK": c_lnk.EXTRA_DATA(extra_data_block=None, terminal_block=self.size)})
            return

        signature = c_lnk.uint32(fh)
        block_name = EXTRA_DATA_BLOCK_SIGNATURES.get_name(signature)

        if block_name:
            read_size = self.size - LINK_EXTRA_DATA_HEADER_SIZE
            block_data = memoryview(fh.read(read_size))

            if len(block_data) != read_size:
                # Some malicious lnk files have a mismatch in the size indicated in the data block and actual bytes red.
                # This causes cstruct to have an EOFError when trying to parse the actual size. Which is not reflected.
                log.warning(
                    "Mismatch in read size (%i) and actual EXTRA_DATA_BLOCK length (%i) for data block (%s)",
                    read_size,
                    len(block_data),
                    block_name,
                )
                return

            if block_name == "VISTA_AND_ABOVE_IDLIST_PROPS":
                struct = LnkTargetIdList(BytesIO(block_data), read_size)
            else:
                struct = c_lnk.typedefs[block_name](block_data)

            if block_name == "PROPERTY_STORE_PROPS":
                # TODO implement actual serialized property parsing
                guid = self._parse_guid(struct.format_id)
                struct.format_id = guid

            elif block_name == "TRACKER_PROPS":
                for name in struct.fields:
                    if "droid" in name:
                        guid = self._parse_guid(getattr(struct, name))
                        setattr(struct, name, guid)

            elif block_name == "KNOWN_FOLDER_PROPS":
                guid = self._parse_guid(struct.known_folder_id)
                struct.known_folder_id = guid

            elif (
                block_name == "ENVIRONMENT_PROPS"
                or block_name == "ICON_ENVIRONMENT_PROPS"
                or block_name == "DARWIN_PROPS"
            ):
                if block_name == "DARWIN_PROPS":
                    struct.darwin_data_ansi = struct.darwin_data_ansi
                    struct.darwin_data_unicode = struct.darwin_data_unicode.decode().rstrip("\x00")
                else:
                    struct.target_ansi = struct.target_ansi
                    struct.target_unicode = struct.target_unicode.decode("utf-16").rstrip("\x00")

            self.extradata.update({block_name: struct})

        else:
            log.warning("Unknown extra data block encountered with signature %x", signature)

        # keep calling parse until the TERMINAL_BLOCK is hit.
        self._parse(fh)

    def _parse_guid(self, guid: bytes, endianness: str = "<") -> UUID:
        if endianness == "<":
            return UUID(bytes_le=guid)

        return UUID(bytes=guid)

    def __getattr__(self, attr: str) -> Any:
        try:
            return self.extradata[attr]
        except KeyError:
            return object.__getattribute__(self, attr)

    def __repr__(self) -> str:
        return " ".join(f"{value}" for value in self.extradata.values())


class LnkStringData:
    """This class represents the LNK file's STING_DATA structure. The STRING_DATA structure refers to a set of
    structures that convey user interface and path identification information.

    STRING_DATA = [NAME_STRING] [RELATIVE_PATH] [WORKING_DIR] [COMMAND_LINE_ARGUMENTS] [ICON_LOCATION]

    Args:
        fh: A file-lke object to a STRING_DATA structure
        lnk_flags: Parsed LINK_HEADER flags
    """

    def __init__(self, fh: BinaryIO | None = None, lnk_flags: c_lnk.LINK_FLAGS | None = None):
        self.flags = None
        self.string_data = None
        if fh:
            self.flags = lnk_flags
            self.string_data = {}
            self._parse(fh)

    def _parse(self, fh: BinaryIO) -> None:
        flag_names = (
            ("has_name", "name_string"),
            ("has_relative_path", "relative_path"),
            ("has_working_dir", "working_dir"),
            ("has_arguments", "command_line_arguments"),
            ("has_icon_location", "icon_location"),
        )

        for flag, string_data_name in flag_names:
            if self.flags & c_lnk.LINK_FLAGS[flag]:
                string_data = self._get_stringdata(fh)
                self.string_data.update({string_data_name: string_data})

    def _get_stringdata(self, fh: BinaryIO) -> c_lnk.STRING_DATA:
        # STRING_DATA structs have a size called character_count
        # this size (character_count) should be doubled when unicode is used
        size = unpack("H", fh.read(2))[0]
        if self.flags & c_lnk.LINK_FLAGS.is_unicode:
            size = size * 2
            data = fh.read(size).decode("utf-16")
        else:
            data = fh.read(size)

        return c_lnk.STRING_DATA(character_count=size, string=data)

    def __getattr__(self, attr: str) -> Any:
        try:
            return self.string_data[attr]
        except KeyError:
            return object.__getattribute__(self, attr)

    def __repr__(self) -> str:
        return " ".join(f"{value}" for value in self.string_data.values())


@dataclass(frozen=True)
class LinkStringValue:
    """A single raw string value located inside a LinkInfo structure.

    Every string reachable through an offset in the LinkInfo structure is recorded together
    with the exact byte range it occupies in the LNK file. This keeps the evidence intact and
    makes it possible to prove that a string never reads past the structure that owns it.

    A value is distinguished in three states:
      * absent: the offset that would point at the string is zero (the field is not present);
      * present but empty: the offset points at a terminator byte (``\\x00`` / ``\\x00\\x00``);
      * present with content.

    Args:
        raw: Raw bytes of the string, without its terminator.
        range: Absolute ``(start, end)`` byte offsets of the string inside the LNK file.
        encoding: ``"ansi"`` for system-default-code-page strings, ``"unicode"`` for UTF-16LE.
        valid: Whether the owning offset stayed inside its enclosing structure.
        offset: The offset (relative to its enclosing structure) that located the string.
    """

    raw: bytes
    range: tuple[int, int]
    encoding: str
    valid: bool = True
    offset: int = 0

    @property
    def absent(self) -> bool:
        """Whether the field that would hold this string is missing (offset zero)."""
        return self.offset == 0

    @property
    def empty(self) -> bool:
        """Whether the field is present but holds an empty string."""
        return not self.absent and len(self.raw) == 0

    def decode(self, codepage: str = "latin-1") -> str | None:
        """Decode the raw string.

        Args:
            codepage: Code page used to decode ANSI strings. Unicode strings always use
                UTF-16LE.

        Returns:
            The decoded string, or ``None`` when the field is absent.
        """
        if self.absent:
            return None
        if self.encoding == "unicode":
            return self.raw.decode("utf-16-le", errors="surrogatepass")
        return self.raw.decode(codepage, errors="backslashreplace")


@dataclass(frozen=True)
class LinkPathSegment:
    """One segment of a path, annotated with where it came from.

    Args:
        value: Decoded text of the path segment.
        source: Which field produced the segment, e.g. ``local_base_path.unicode``.
        range: Absolute ``(start, end)`` byte offsets of the segment inside the LNK file.
        encoding: ``"ansi"`` or ``"unicode"``.
    """

    value: str
    source: str
    range: tuple[int, int]
    encoding: str


@dataclass
class LinkString:
    """The ANSI and Unicode raw values of one logical LinkInfo string field.

    Both encodings are retained. When both are present but do not agree, the disagreement is
    surfaced as a conflict instead of silently preferring one encoding.

    Args:
        name: Logical field name (e.g. ``local_base_path``).
        ansi: The ANSI value, or ``None`` when the ANSI field is absent.
        unicode: The Unicode value, or ``None`` when the Unicode field is absent.
    """

    name: str
    ansi: LinkStringValue | None = None
    unicode: LinkStringValue | None = None

    @property
    def has_unicode(self) -> bool:
        """Whether a Unicode field is present (even when it holds an empty string)."""
        return self.unicode is not None and not self.unicode.absent

    @property
    def conflict(self) -> bool:
        """Whether both encodings are present but decode to different text."""
        if self.ansi is None or self.unicode is None:
            return False
        if self.ansi.absent or self.unicode.absent:
            return False
        return self.ansi.decode() != self.unicode.decode()

    @property
    def preferred(self) -> LinkStringValue | None:
        """The most faithful trustworthy raw value.

        Unicode is preferred when it is present and its offset stayed inside its structure.
        Invalid values are never selected, so a corrupted offset can never surface as a
        (possibly empty) trusted path.
        """
        if self.has_unicode and self.unicode.valid:
            return self.unicode
        if self.ansi is not None and not self.ansi.absent and self.ansi.valid:
            return self.ansi
        if self.has_unicode and self.unicode.valid:
            return self.unicode
        return None

    def text(self, codepage: str = "latin-1") -> str | None:
        """Decode the preferred value, or ``None`` when no trustworthy value is available."""
        value = self.preferred
        if value is None or value.absent:
            return None
        return value.decode(codepage)

    def segments(self, codepage: str = "latin-1") -> list[LinkPathSegment]:
        """Split the preferred value into path segments annotated with source and byte range."""
        value = self.preferred
        if value is None or value.absent:
            return []
        return _split_path(value, self.name, codepage)


def _split_path(value: LinkStringValue, name: str, codepage: str) -> list[LinkPathSegment]:
    """Split a decoded path into segments while keeping each segment's absolute byte range.

    The terminator is excluded from the ranges because :class:`LinkStringValue` stores the raw
    string without it. A leading empty component (UNC paths such as ``\\\\server\\share``) is
    represented by the segment data itself and does not produce a zero-length segment.
    """
    start, _ = value.range
    if value.encoding == "unicode":
        text = value.raw.decode("utf-16-le", errors="surrogatepass")
        char_width = 2
    else:
        text = value.raw.decode(codepage, errors="backslashreplace")
        char_width = 1

    segments: list[LinkPathSegment] = []
    cursor = 0
    for part in text.split("\\"):
        if part:
            part_start = start + cursor * char_width
            segments.append(
                LinkPathSegment(
                    value=part,
                    source=f"{name}.{value.encoding}",
                    range=(part_start, part_start + len(part) * char_width),
                    encoding=value.encoding,
                )
            )
        cursor += len(part) + 1
    return segments


class LnkInfo:
    """This class represents a LNK file's LINK_INFO structure. The optional LINK_INFO structure specifies information
    necessary to resolve a link target if it is not found in its original location. This includes information about
    the volume that the target was stored on, the mapped drive letter, and a UNC path if existed when the link was
    created.

    The parser understands both the legacy ANSI LinkInfo header (``LinkInfoHeaderSize`` 0x1C) and the optional Unicode
    header (``LinkInfoHeaderSize`` >= 0x24). Every offset is resolved relative to the base of the structure that owns
    it, and strings are never read past their enclosing structure. ANSI and Unicode raw values are both retained so
    that encoding conflicts can be presented as evidence rather than resolved by picking one side.

    Args:
        fh: A file-like object positioned at the start of a LINK_INFO structure
    """

    def __init__(self, fh: BinaryIO | None = None):
        self.fh = fh
        self.flags = None
        self.size = None

        self.link_info = None
        self.linkinfo_header = None
        self.linkinfo_body = None

        # Absolute offset of the LinkInfo structure inside the LNK file. All recorded byte
        # ranges are expressed relative to this position.
        self._base_offset = 0
        self._is_unicode_header = False
        self._unicode_offsets: dict[str, int] = {}

        # Logical string fields, each holding both encodings plus their byte ranges.
        self.strings: dict[str, LinkString] = {}
        # The volume label is owned by the VolumeID structure and is tracked separately.
        self.volume_label: LinkString | None = None

        if fh:
            self._base_offset = fh.tell()
            self.linkinfo_header = c_lnk.LINK_INFO_HEADER(fh.read(LINK_INFO_HEADER_SIZE))
            self.flags = self.linkinfo_header.link_info_flags
            self.size = self.linkinfo_header.link_info_size

            # A header of at least 0x24 adds the LocalBasePathOffsetUnicode and
            # CommonPathSuffixOffsetUnicode fields.
            self._is_unicode_header = self.linkinfo_header.link_info_header_size >= LINK_INFO_UNICODE_HEADER_SIZE

            self.linkinfo_body = c_lnk.LINK_INFO_BODY(fh.read(LINK_INFO_BODY_SIZE))
            if self._is_unicode_header:
                (
                    self._unicode_offsets["local_basepath"],
                    self._unicode_offsets["common_pathsuffix"],
                ) = unpack("II", fh.read(8))

            # Reposition at the start of the LinkInfo structure and bound all reads to its
            # declared size so a malformed inner offset can never reach later structures.
            fh.seek(self._base_offset)
            declared_size = self.linkinfo_header.link_info_size
            available = self._read_available(fh, declared_size)
            if len(available) < declared_size:
                log.warning(
                    "LinkInfo declares size 0x%x but only 0x%x bytes are available; clamping reads.",
                    declared_size,
                    len(available),
                )
            buff = RangeStream(BytesIO(available), 0, len(available))
            self._parse(buff)

            # Continue the outer parse from exactly the end of the LinkInfo structure so that
            # StringData and ExtraData are read from the correct position regardless of any
            # seeking performed while resolving inner offsets.
            fh.seek(self._base_offset + declared_size)

    def _read_available(self, fh: BinaryIO, size: int) -> bytes:
        """Read up to ``size`` bytes without walking past the end of the underlying stream."""
        if size <= 0:
            return b""
        data = fh.read(size)
        return data if data is not None else b""

    def _absolute(self, relative_offset: int) -> int:
        """Translate a LinkInfo-relative offset into an absolute LNK file offset."""
        return self._base_offset + relative_offset

    @staticmethod
    def _trusted_raw(value: LinkStringValue | None) -> bytes:
        """Return the raw bytes only when the value was located inside its own structure."""
        if value is None or value.absent or not value.valid:
            return b""
        return value.raw

    def _extract_string(
        self,
        buff: BinaryIO,
        relative_offset: int,
        region_start: int,
        region_end: int,
        encoding: str,
        structure_name: str,
    ) -> LinkStringValue | None:
        """Read a terminator-delimited string that is guaranteed to stay inside its structure.

        Offsets are interpreted relative to the start of the LinkInfo buffer. ``region_start``
        and ``region_end`` bound the structure that owns the string (the whole LinkInfo for
        top-level fields, the VolumeID or CommonNetworkRelativeLink extent for their strings).

        A zero offset means the field is absent. An offset that points outside the owning
        structure, or a string that is not terminated inside it, is recorded as an invalid
        value instead of being trusted as a path.
        """
        if relative_offset == 0:
            return None

        if relative_offset < region_start or relative_offset >= region_end:
            log.warning(
                "%s offset 0x%x falls outside owning region [0x%x, 0x%x); treating value as untrusted.",
                structure_name,
                relative_offset,
                region_start,
                region_end,
            )
            return LinkStringValue(
                raw=b"",
                range=(self._absolute(relative_offset), self._absolute(relative_offset)),
                encoding=encoding,
                valid=False,
                offset=relative_offset,
            )

        buff.seek(relative_offset)
        raw_region = buff.read(region_end - relative_offset)

        if encoding == "unicode":
            # UTF-16LE terminators are two zero bytes and can only start at an even offset;
            # scanning every byte would match a zero byte inside a multi-byte character.
            terminator_index = -1
            for candidate in range(0, len(raw_region) - 1, 2):
                if raw_region[candidate : candidate + 2] == b"\x00\x00":
                    terminator_index = candidate
                    break
        else:
            terminator_index = raw_region.find(b"\x00")
        if terminator_index == -1:
            log.warning(
                "%s string at offset 0x%x is not terminated within its structure; treating value as untrusted.",
                structure_name,
                relative_offset,
            )
            return LinkStringValue(
                raw=b"",
                range=(self._absolute(relative_offset), self._absolute(relative_offset)),
                encoding=encoding,
                valid=False,
                offset=relative_offset,
            )

        raw = raw_region[:terminator_index]
        if encoding == "unicode" and relative_offset % 2 != 0:
            log.warning(
                "%s unicode string at offset 0x%x is not aligned; keeping raw bytes.",
                structure_name,
                relative_offset,
            )

        return LinkStringValue(
            raw=raw,
            range=(self._absolute(relative_offset), self._absolute(relative_offset + terminator_index)),
            encoding=encoding,
            valid=True,
            offset=relative_offset,
        )

    def _parse(self, buff: BinaryIO) -> None:
        link_info_size = self.linkinfo_header.link_info_size

        common_network_relative_link = None
        local_base_path = None
        volumeid = None

        volumeid_offset = self.linkinfo_body.volumeid_offset
        local_basepath_offset = self.linkinfo_body.local_basepath_offset
        common_network_relative_link_offset = self.linkinfo_body.common_network_relative_link_offset
        common_pathsuffix_offset = self.linkinfo_body.common_pathsuffix_offset

        local_basepath_unicode_offset = self._unicode_offsets.get("local_basepath", 0)
        common_pathsuffix_unicode_offset = self._unicode_offsets.get("common_pathsuffix", 0)

        if self.flag("volumeid_and_local_basepath"):
            volumeid, _volumeid_size, self.volume_label = self._parse_volumeid(buff, volumeid_offset, link_info_size)

            # LocalBasePath is a top-level LinkInfo field. Its offset is relative to the start
            # of the LinkInfo structure and the string must fit inside the whole structure.
            ansi_local = self._extract_string(buff, local_basepath_offset, 0, link_info_size, "ansi", "LocalBasePath")
            unicode_local = (
                self._extract_string(
                    buff,
                    local_basepath_unicode_offset,
                    0,
                    link_info_size,
                    "unicode",
                    "LocalBasePathUnicode",
                )
                if self._is_unicode_header
                else None
            )
            self.strings["local_base_path"] = LinkString("local_base_path", ansi_local, unicode_local)
            local_base_path = self._trusted_raw(ansi_local)

        if self.flag("common_network_relative_link_and_pathsuffix"):
            (
                common_network_relative_link,
                net_name_string,
                device_name_string,
            ) = self._parse_common_network_relative_link(buff, common_network_relative_link_offset, link_info_size)
            self.strings["net_name"] = net_name_string
            self.strings["device_name"] = device_name_string

        # CommonPathSuffix is always present, even when its value is just 0x00 or when the
        # common_network_relative_link_and_pathsuffix flag indicates otherwise.
        ansi_suffix = self._extract_string(
            buff, common_pathsuffix_offset, 0, link_info_size, "ansi", "CommonPathSuffix"
        )
        unicode_suffix = (
            self._extract_string(
                buff,
                common_pathsuffix_unicode_offset,
                0,
                link_info_size,
                "unicode",
                "CommonPathSuffixUnicode",
            )
            if self._is_unicode_header
            else None
        )
        self.strings["common_path_suffix"] = LinkString("common_path_suffix", ansi_suffix, unicode_suffix)
        common_path_suffix = self._trusted_raw(ansi_suffix)

        link_info_kwargs = {
            "link_info_size": link_info_size,
            "link_info_header_size": self.linkinfo_header.link_info_header_size,
            "link_info_flags": self.flags,
            "volumeid_offset": volumeid_offset,
            "local_basepath_offset": local_basepath_offset,
            "common_network_relative_link_offset": common_network_relative_link_offset,
            "common_pathsuffix_offset": common_pathsuffix_offset,
            "volumeid": volumeid,
            "local_base_path": local_base_path,
            "common_network_relative_link": common_network_relative_link,
            "common_path_suffix": common_path_suffix,
        }
        self.link_info = c_lnk.LINK_INFO(**link_info_kwargs)

    def _parse_volumeid(
        self, buff: BinaryIO, volumeid_offset: int, link_info_size: int
    ) -> tuple[Any, int, LinkString | None]:
        """Parse the VolumeID structure and its ANSI/Unicode volume label strings.

        VolumeID offsets are relative to the start of the VolumeID structure, so they are
        translated by adding the VolumeID offset before touching the shared LinkInfo buffer.
        """
        if volumeid_offset == 0 or not (0 < volumeid_offset < link_info_size):
            log.warning("VolumeID offset 0x%x is outside the LinkInfo structure; skipping VolumeID.", volumeid_offset)
            return None, 0, None

        buff.seek(volumeid_offset)
        size_bytes = buff.read(4)
        if len(size_bytes) != 4:
            log.warning("Truncated VolumeID size at offset 0x%x; skipping VolumeID.", volumeid_offset)
            return None, 0, None
        volumeid_size = unpack("I", size_bytes)[0]

        # The structure must fit inside the LinkInfo structure that contains it.
        volumeid_end = min(volumeid_offset + volumeid_size, link_info_size)
        if volumeid_size <= 0x10 or volumeid_end <= volumeid_offset:
            log.warning("Invalid VolumeID size 0x%x at offset 0x%x; skipping VolumeID.", volumeid_size, volumeid_offset)
            return None, 0, None

        # A VolumeID carries the Unicode label offset only when the ANSI VolumeLabelOffset is
        # the 0x14 sentinel defined by MS-SHLLINK. Size alone is not enough: a 16-byte ANSI
        # header plus a short label can also be 20 bytes long.
        buff.seek(volumeid_offset + 12)
        ansi_label_offset = unpack("I", buff.read(4))[0]
        has_unicode_label_field = ansi_label_offset == 0x14 and volumeid_size >= 0x14
        unicode_label_relative_offset = 0
        if has_unicode_label_field:
            # The field at VolumeID+16 holds an offset relative to the VolumeID base; read it
            # there and add the base only when locating the actual string.
            buff.seek(volumeid_offset + 16)
            unicode_label_relative_offset = unpack("I", buff.read(4))[0]

        buff.seek(volumeid_offset)
        volumeid_type = c_lnk.VOLUME_ID_UNICODE if has_unicode_label_field else c_lnk.VOLUME_ID
        volumeid = volumeid_type(buff.read(volumeid_end - volumeid_offset))

        # Resolve the label offsets against the VolumeID base, never against LinkInfo directly.
        # The 0x14 sentinel means there is no ANSI label; the Unicode offset is authoritative.
        ansi_label = None
        if ansi_label_offset and not has_unicode_label_field:
            ansi_label = self._extract_string(
                buff,
                volumeid_offset + ansi_label_offset,
                volumeid_offset,
                volumeid_end,
                "ansi",
                "VolumeLabel",
            )

        unicode_label = None
        if has_unicode_label_field and unicode_label_relative_offset:
            unicode_label = self._extract_string(
                buff,
                volumeid_offset + unicode_label_relative_offset,
                volumeid_offset,
                volumeid_end,
                "unicode",
                "VolumeLabelUnicode",
            )

        return volumeid, volumeid_end - volumeid_offset, LinkString("volume_label", ansi_label, unicode_label)

    def _parse_common_network_relative_link(
        self, buff: BinaryIO, cnrl_offset: int, link_info_size: int
    ) -> tuple[Any, LinkString, LinkString]:
        """Parse the CommonNetworkRelativeLink structure.

        Its offsets are relative to the start of the CommonNetworkRelativeLink structure itself.
        The optional Unicode NetName/DeviceName offsets only exist in Unicode LinkInfo headers.
        """
        net_name_string = LinkString("net_name")
        device_name_string = LinkString("device_name")
        if cnrl_offset == 0 or not (0 < cnrl_offset < link_info_size):
            log.warning(
                "CommonNetworkRelativeLink offset 0x%x is outside the LinkInfo structure; skipping it.",
                cnrl_offset,
            )
            return None, net_name_string, device_name_string

        buff.seek(cnrl_offset)
        size_bytes = buff.read(4)
        if len(size_bytes) != 4:
            log.warning("Truncated CommonNetworkRelativeLink size at offset 0x%x; skipping it.", cnrl_offset)
            return None, net_name_string, device_name_string
        cnrl_size = unpack("I", size_bytes)[0]

        cnrl_end = min(cnrl_offset + cnrl_size, link_info_size)
        if cnrl_size < COMMON_NETWORK_RELATIVE_LINK_HEADER_SIZE or cnrl_end <= cnrl_offset:
            log.warning(
                "Invalid CommonNetworkRelativeLink size 0x%x at offset 0x%x; skipping it.",
                cnrl_size,
                cnrl_offset,
            )
            return None, net_name_string, device_name_string

        buff.seek(cnrl_offset)
        header = c_lnk.COMMON_NETWORK_RELATIVE_LINK_HEADER(buff.read(COMMON_NETWORK_RELATIVE_LINK_HEADER_SIZE))
        flags = header.common_network_relative_link_flags

        unicode_net_name_offset = 0
        unicode_device_name_offset = 0
        if self._is_unicode_header and cnrl_size >= COMMON_NETWORK_RELATIVE_LINK_UNICODE_HEADER_SIZE:
            buff.seek(cnrl_offset)
            unicode_header = c_lnk.COMMON_NETWORK_RELATIVE_LINK_UNICODE_HEADER(
                buff.read(COMMON_NETWORK_RELATIVE_LINK_UNICODE_HEADER_SIZE)
            )
            unicode_net_name_offset = unicode_header.net_name_offset_unicode
            unicode_device_name_offset = unicode_header.device_name_offset_unicode

        # NetName is located via net_name_offset which is relative to the CNRL structure.
        ansi_net_name = self._extract_string(
            buff,
            cnrl_offset + header.net_name_offset if header.net_name_offset else 0,
            cnrl_offset,
            cnrl_end,
            "ansi",
            "NetName",
        )
        unicode_net_name = (
            self._extract_string(
                buff,
                cnrl_offset + unicode_net_name_offset,
                cnrl_offset,
                cnrl_end,
                "unicode",
                "NetNameUnicode",
            )
            if unicode_net_name_offset
            else None
        )
        net_name_string = LinkString("net_name", ansi_net_name, unicode_net_name)

        ansi_device_name = None
        unicode_device_name = None
        if flags & c_lnk.COMMON_NETWORK_RELATIVE_LINK_FLAGS.valid_device:
            ansi_device_name = self._extract_string(
                buff,
                cnrl_offset + header.device_name_offset if header.device_name_offset else 0,
                cnrl_offset,
                cnrl_end,
                "ansi",
                "DeviceName",
            )
            if unicode_device_name_offset:
                unicode_device_name = self._extract_string(
                    buff,
                    cnrl_offset + unicode_device_name_offset,
                    cnrl_offset,
                    cnrl_end,
                    "unicode",
                    "DeviceNameUnicode",
                )
        device_name_string = LinkString("device_name", ansi_device_name, unicode_device_name)

        net_name = self._trusted_raw(ansi_net_name)
        # DEVICE_NAME expects None (not b"") when the device field is absent or untrusted.
        device_raw = None
        if ansi_device_name is not None and not ansi_device_name.absent and ansi_device_name.valid:
            device_raw = ansi_device_name.raw
        device_name = c_lnk.DEVICE_NAME(device_name=device_raw)

        common_network_relative_link = c_lnk.COMMON_NETWORK_RELATIVE_LINK(
            common_network_relative_link_size=header.common_network_relative_link_size,
            common_network_relative_link_flags=header.common_network_relative_link_flags,
            net_name_offset=header.net_name_offset,
            device_name_offset=header.device_name_offset,
            net_provider_type=header.net_provider_type,
            net_name=net_name,
            device_name=device_name,
        )

        return common_network_relative_link, net_name_string, device_name_string

    def flag(self, name: str) -> int:
        """Returns whether supplied flag is set.

        Args:
            name: Name of the flag

        Returns:
            int: >0 if flag is set
        """
        return self.flags & c_lnk.LINK_INFO_FLAGS[name]

    @property
    def is_unicode(self) -> bool:
        """Whether the LinkInfo header carries the optional Unicode offset fields."""
        return self._is_unicode_header

    @property
    def local_basepath_offset_unicode(self) -> int:
        """LocalBasePathUnicode offset (LinkInfo-relative), zero when the header is ANSI-only."""
        return self._unicode_offsets.get("local_basepath", 0)

    @property
    def common_pathsuffix_offset_unicode(self) -> int:
        """CommonPathSuffixUnicode offset (LinkInfo-relative), zero when the header is ANSI-only."""
        return self._unicode_offsets.get("common_pathsuffix", 0)

    @property
    def local_base_path_string(self) -> LinkString | None:
        """The ANSI/Unicode LocalBasePath evidence, or ``None`` when the flag is not set."""
        return self.strings.get("local_base_path")

    @property
    def common_path_suffix_string(self) -> LinkString | None:
        """The ANSI/Unicode CommonPathSuffix evidence."""
        return self.strings.get("common_path_suffix")

    @property
    def net_name_string(self) -> LinkString | None:
        """The ANSI/Unicode NetName evidence of the CommonNetworkRelativeLink."""
        return self.strings.get("net_name")

    @property
    def device_name_string(self) -> LinkString | None:
        """The ANSI/Unicode DeviceName evidence of the CommonNetworkRelativeLink."""
        return self.strings.get("device_name")

    @property
    def conflicts(self) -> list[str]:
        """Names of the fields whose ANSI and Unicode values disagree."""
        names = [name for name, value in self.strings.items() if value.conflict]
        if self.volume_label is not None and self.volume_label.conflict:
            names.append("volume_label")
        return names

    def path_segments(self, codepage: str = "latin-1") -> list[LinkPathSegment]:
        """Return every segment of the local target path with source and byte range.

        LocalBasePath (drive / directory part) and CommonPathSuffix (remaining path) are
        concatenated at the segment level. Unicode is preferred when available, but the
        underlying :class:`LinkString` objects always retain both encodings.
        """
        segments: list[LinkPathSegment] = []
        local = self.strings.get("local_base_path")
        if local is not None:
            segments.extend(local.segments(codepage))
        suffix = self.strings.get("common_path_suffix")
        if suffix is not None:
            segments.extend(suffix.segments(codepage))
        return segments

    def network_segments(self, codepage: str = "latin-1") -> list[LinkPathSegment]:
        """Return every segment of the UNC NetName with source and byte range."""
        net_name = self.strings.get("net_name")
        if net_name is None:
            return []
        return net_name.segments(codepage)

    def __getattr__(self, attr: str) -> Any:
        try:
            return self.link_info[attr]
        except KeyError:
            return object.__getattribute__(self, attr)

    def __repr__(self) -> str:
        if self.link_info:
            return self.link_info
        return "<LINK_INFO>"


class LnkTargetIdList:
    """This class represents a LNK file's TARGET_IDLIST structure. The TARGET_IDLIST structure specifies the target of
    the link. This information is stored in individual ITEM_ID structures.

    Args:
        fh: A file-like object to a TARGET_IDLIST structure.
        size: Size of the TARGET_IDLIST structure
    """

    def __init__(self, fh: BinaryIO | None = None, size: int | None = None):
        self.target_idlist = None
        self.idlist = None
        self.size = None

        if fh:
            self.size = unpack("H", fh.read(2))[0] if size is None else size
            self._parse(fh.read(self.size))

    def _parse(self, buff: BinaryIO) -> None:
        idlists = []
        buff = BytesIO(buff)

        # the size of the target_idlist struct includes itself. Thus we minus 2 here.
        while buff.tell() < self.size - 2:
            size = unpack("H", buff.read(2))[0]
            data = buff.read(size - 2)  # size of the struct includes the 16-bit size value. Thus we minus 2 here again.
            itemid = c_lnk.ITEMID(itemid_size=size, data=data)
            idlists.append(itemid)

        self.idlist = c_lnk.IDLIST(itemid_list=idlists, terminalid=buff.read())
        self.target_idlist = c_lnk.LINK_TARGET_IDLIST(idlist_size=self.size, idlist=self.idlist)

    def __repr__(self) -> str:
        return repr(self.target_idlist)


class Lnk:
    """This class represents a LNK file's SHELL_LINK_HEADER, and the remainder of the parsed LNK file structures.
    This SHELL_LINK_HEADER structure contains identification information, timestamps, and flags that specify the
    presence of optional structures.

    Parses a .lnk file (aka Microsoft Shell Item) according to the MS-SHLLINK specification
    reference: https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/%5bMS-SHLLINK%5d.pdf

    Args:
        path: (string) Path to a link file.
        target_idlist: A LnkTargetIdList object.
        linkinfo: A LnkInfo object.
        stringdata: A LnkStringData object.
        extradata: A LnkExtraData object.
    """

    def __init__(
        self,
        fh: BufferedReader,
        target_idlist: LnkTargetIdList | None = None,
        linkinfo: LnkInfo | None = None,
        stringdata: LnkStringData | None = None,
        extradata: LnkExtraData | None = None,
    ):
        self.fh = fh

        self.flags = None
        self.link_header = self._parse_header(self.fh)
        self.target_idlist = LnkTargetIdList()
        self.linkinfo = LnkInfo()
        self.stringdata = LnkStringData()
        self.extradata = LnkExtraData()

        if self.link_header:
            self.flags = self.link_header.link_flags

            if self.flag("has_link_target_idlist"):
                self.target_idlist = LnkTargetIdList(self.fh)

            if self.flag("has_link_info"):
                self.linkinfo = LnkInfo(self.fh)

            if (
                self.flag("has_name")
                or self.flag("has_relative_path")
                or self.flag("has_working_dir")
                or self.flag("has_arguments")
                or self.flag("has_icon_location")
            ):
                self.stringdata = LnkStringData(self.fh, self.flags)

            self.extradata = LnkExtraData(self.fh)

    def flag(self, name: str) -> int:
        """Returns whether supplied flag is set.

        Args:
            name: Name of the flag

        Returns:
            int: >0 if flag is set
        """
        return self.flags & c_lnk.LINK_FLAGS[name]

    def _parse_header(self, fh: BinaryIO | None) -> c_lnk.SHELL_LINK_HEADER | None:
        """Returns LINK header.

        Parse the header in a buffer that does not start at offset 0

        Args:
            fh: File object

        Returns:
            LINK header if size is 0x4C, else none
        """
        offset = fh.tell()
        header_size = unpack("I", fh.read(4))[0]
        fh.seek(offset)

        if header_size == LINK_HEADER_SIZE:
            link_header = c_lnk.SHELL_LINK_HEADER(fh.read(LINK_HEADER_SIZE))
            link_clsid = str(UUID(bytes_le=link_header.link_clsid))

            if link_clsid == "00021401-0000-0000-c000-000000000046":
                return link_header

            log.info("Encountered invalid link file header: %s. Skipping.", link_header)
            return None

        log.info(
            "Encountered invalid link file with magic header size 0x%x. \
            Magic header size should be 0x%x. Skipping.",
            header_size,
            LINK_HEADER_SIZE,
        )
        return None

    @property
    def clsid(self) -> UUID:
        """Returns the class id (clsid) of the LNK file."""
        return UUID(bytes_le=self.link_header.link_clsid)

    def __repr__(self) -> str:
        return f"{self.link_header} {self.target_idlist} {self.linkinfo.link_info} {self.stringdata} {self.extradata}"
