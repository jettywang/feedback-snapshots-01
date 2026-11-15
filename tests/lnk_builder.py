"""Minimal, dependency-free builder for LNK files with fully controlled LinkInfo structures.

The real Windows shell writer always aligns UTF-16 strings on even byte offsets, so this
builder does the same. It only implements the pieces needed to exercise the LinkInfo parser:
the ShellLinkHeader, an optional LinkInfo (ANSI or Unicode header), optional StringData and
the ExtraData terminal block. Keeping the fixtures generated in code makes every offset and
encoding conflict explicit instead of hiding them in opaque binary blobs.
"""

from __future__ import annotations

import struct

SHELL_LINK_CLSID = bytes.fromhex("0114020000000000c000000000000046")

HAS_LINK_INFO = 0x2
HAS_NAME = 0x4
IS_UNICODE = 0x80

# LinkInfo header sizes.
ANSI_LINKINFO_HEADER_SIZE = 0x1C
UNICODE_LINKINFO_HEADER_SIZE = 0x24

# CommonNetworkRelativeLink header sizes.
ANSI_CNRL_HEADER_SIZE = 0x14
UNICODE_CNRL_HEADER_SIZE = 0x1C


def u32(value: int) -> bytes:
    return struct.pack("<I", value)


def u16(value: int) -> bytes:
    return struct.pack("<H", value)


def align2(blob: bytes) -> tuple[bytes, int]:
    """Pad ``blob`` with a zero byte so its next write lands on an even offset."""
    if len(blob) % 2:
        return blob + b"\x00", 1
    return blob, 0


class LnkBuilder:
    """Assemble a single LNK file from explicit LinkInfo and StringData parts."""

    def __init__(self, codepage: str = "latin-1"):
        self.codepage = codepage

    def shell_header(self, flags: int) -> bytes:
        out = bytearray()
        out += u32(0x4C)
        out += SHELL_LINK_CLSID
        out += u32(flags | IS_UNICODE)
        out += u32(0x20)  # FILE_ATTRIBUTE_ARCHIVE
        out += b"\x00" * 24  # creation, access and write FILETIMEs
        out += u32(0)  # file size
        out += u32(0)  # icon index
        out += u32(1)  # SW_SHOWNORMAL
        out += b"\x00" * 2  # hotkey flags
        out += u16(0)  # reserved1
        out += u32(0)  # reserved2
        out += u32(0)  # reserved3
        assert len(out) == 0x4C
        return bytes(out)

    def unicode_string_data(self, value: str) -> bytes:
        encoded = value.encode("utf-16-le")
        return u16(len(value)) + encoded

    def volume_id(self, ansi_label: str | None, unicode_label: str | None) -> bytes:
        """Build a VolumeID structure, optionally carrying a Unicode volume label.

        When only a Unicode label is supplied the ANSI offset keeps the 0x14 sentinel defined
        by MS-SHLLINK, which tells the parser to ignore the ANSI field entirely.
        """
        volume = bytearray()
        if unicode_label is None:
            volume += u32(0)  # size, patched below
            volume += u32(3)  # DRIVE_FIXED
            volume += u32(0xDEADBEEF)  # drive serial number
            volume += u32(0x10)  # ANSI label immediately follows the 16-byte header
            if ansi_label is not None:
                volume += ansi_label.encode(self.codepage)
            volume += b"\x00"
        else:
            # Unicode VolumeID: the ANSI VolumeLabelOffset is the fixed 0x14 sentinel, which per
            # MS-SHLLINK tells the reader to use the Unicode offset that follows immediately.
            volume += u32(0)  # size, patched below
            volume += u32(3)  # DRIVE_FIXED
            volume += u32(0xDEADBEEF)  # drive serial number
            volume += u32(0x14)  # ANSI label absent; switch to the Unicode offset
            # The Unicode label starts directly after the 20-byte VolumeID header. Its offset
            # is relative to the start of the VolumeID, i.e. 0x14.
            volume += u32(0x14)
            volume += unicode_label.encode("utf-16-le") + b"\x00\x00"
        volume[0:4] = u32(len(volume))
        return bytes(volume)

    def local_linkinfo(
        self,
        ansi_local: str,
        unicode_local: str | None,
        ansi_suffix: str,
        unicode_suffix: str | None,
        ansi_label: str | None = "SSD",
        unicode_label: str | None = None,
    ) -> bytes:
        """Build a VolumeIDAndLocalBasePath LinkInfo with explicit ANSI/Unicode values."""
        unicode_header = unicode_local is not None or unicode_suffix is not None
        header_size = UNICODE_LINKINFO_HEADER_SIZE if unicode_header else ANSI_LINKINFO_HEADER_SIZE

        body = bytearray()
        offsets: dict[str, int] = {}

        def add(name: str, blob: bytes, keep_aligned: bool = False) -> None:
            nonlocal body
            if keep_aligned:
                body, padding = align2(bytes(body))
                assert padding in (0, 1)
            offsets[name] = header_size + len(body)
            body += blob

        add("volumeid", self.volume_id(ansi_label, unicode_label))
        add("local_ansi", ansi_local.encode(self.codepage) + b"\x00")
        if unicode_local is not None:
            add("local_unicode", unicode_local.encode("utf-16-le") + b"\x00\x00", keep_aligned=True)
        add("suffix_ansi", ansi_suffix.encode(self.codepage) + b"\x00")
        if unicode_suffix is not None:
            add("suffix_unicode", unicode_suffix.encode("utf-16-le") + b"\x00\x00", keep_aligned=True)

        header = bytearray()
        header += u32(header_size + len(body))
        header += u32(header_size)
        header += u32(0x1)  # LINK_INFO_FLAGS.volumeid_and_local_basepath
        header += u32(offsets["volumeid"])
        header += u32(offsets["local_ansi"])
        header += u32(0)  # no CommonNetworkRelativeLink
        header += u32(offsets["suffix_ansi"])
        if unicode_header:
            header += u32(offsets.get("local_unicode", 0))
            header += u32(offsets.get("suffix_unicode", 0))
        assert len(header) == header_size
        return bytes(header) + bytes(body)

    def network_linkinfo(
        self,
        ansi_net_name: str,
        unicode_net_name: str | None,
        ansi_suffix: str,
        unicode_suffix: str | None,
        ansi_device: str | None = None,
        unicode_device: str | None = None,
    ) -> bytes:
        """Build a CommonNetworkRelativeLinkAndPathSuffix LinkInfo (UNC target)."""
        unicode_header = unicode_net_name is not None or unicode_suffix is not None
        linkinfo_header_size = UNICODE_LINKINFO_HEADER_SIZE if unicode_header else ANSI_LINKINFO_HEADER_SIZE

        cnrl_unicode = unicode_header
        cnrl_header_size = UNICODE_CNRL_HEADER_SIZE if cnrl_unicode else ANSI_CNRL_HEADER_SIZE

        region = bytearray()
        cnrl_offsets: dict[str, int] = {}

        def add_cnrl(name: str, blob: bytes, keep_aligned: bool = False) -> None:
            nonlocal region
            if keep_aligned:
                region, _ = align2(bytes(region))
            cnrl_offsets[name] = cnrl_header_size + len(region)
            region += blob

        add_cnrl("net_ansi", ansi_net_name.encode(self.codepage) + b"\x00")
        if ansi_device is not None:
            add_cnrl("device_ansi", ansi_device.encode(self.codepage) + b"\x00")
        if unicode_net_name is not None:
            add_cnrl("net_unicode", unicode_net_name.encode("utf-16-le") + b"\x00\x00", keep_aligned=True)
        if unicode_device is not None:
            add_cnrl("device_unicode", unicode_device.encode("utf-16-le") + b"\x00\x00", keep_aligned=True)

        cnrl_flags = 0x2  # valid_net_type
        if ansi_device is not None or unicode_device is not None:
            cnrl_flags |= 0x1  # valid_device

        cnrl_header = bytearray()
        cnrl_header += u32(cnrl_header_size + len(region))
        cnrl_header += u32(cnrl_flags)
        cnrl_header += u32(cnrl_offsets.get("net_ansi", 0))
        cnrl_header += u32(cnrl_offsets.get("device_ansi", 0))
        cnrl_header += u32(0x20000)  # network provider type
        if cnrl_unicode:
            cnrl_header += u32(cnrl_offsets.get("net_unicode", 0))
            cnrl_header += u32(cnrl_offsets.get("device_unicode", 0))
        assert len(cnrl_header) == cnrl_header_size
        cnrl_blob = bytes(cnrl_header) + bytes(region)

        body = bytearray(cnrl_blob)
        suffix_offsets: dict[str, int] = {}
        cursor = linkinfo_header_size + len(cnrl_blob)
        suffix_offsets["suffix_ansi"] = cursor
        body += ansi_suffix.encode(self.codepage) + b"\x00"
        cursor = linkinfo_header_size + len(body)
        if unicode_suffix is not None:
            if len(body) % 2:
                body += b"\x00"
                cursor += 1
            suffix_offsets["suffix_unicode"] = cursor
            body += unicode_suffix.encode("utf-16-le") + b"\x00\x00"

        header = bytearray()
        header += u32(linkinfo_header_size + len(body))
        header += u32(linkinfo_header_size)
        header += u32(0x2)  # common_network_relative_link_and_pathsuffix
        header += u32(0)  # no VolumeID
        header += u32(0)  # no LocalBasePath
        header += u32(linkinfo_header_size)  # CNRL immediately follows the LinkInfo header
        header += u32(suffix_offsets["suffix_ansi"])
        if unicode_header:
            header += u32(0)  # LocalBasePathUnicode absent
            header += u32(suffix_offsets.get("suffix_unicode", 0))
        assert len(header) == linkinfo_header_size
        return bytes(header) + bytes(body)

    def build(
        self,
        linkinfo: bytes,
        name_string: str | None = None,
        extra_data: bytes = b"",
    ) -> bytes:
        """Wrap a LinkInfo structure in a complete LNK file and terminate ExtraData."""
        flags = HAS_LINK_INFO
        if name_string is not None:
            flags |= HAS_NAME
        out = bytearray(self.shell_header(flags))
        out += linkinfo
        if name_string is not None:
            out += self.unicode_string_data(name_string)
        out += extra_data
        out += u32(0)  # ExtraData terminal block
        return bytes(out)
