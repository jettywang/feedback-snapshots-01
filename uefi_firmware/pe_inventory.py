'''Read-only inventory of PE/TE images embedded in firmware.

This module walks a parsed firmware object tree (volumes, files, sections)
and lists every PE32/PE32+/TE image it finds, reporting the architecture,
the entry point, and where the image sits inside its firmware volume (FV),
firmware file (FFS), and section.

Two address-space caveats are handled explicitly:

- TE images carry a stripped PE header. Their header fields (entry point,
  base of code, data directories) are relative to the image base the PE
  image had *before* its header was stripped, so a file offset is the RVA
  minus (StrippedSize - sizeof(EFI_TE_IMAGE_HEADER)). Mapping a TE entry
  through the PE section-table RVA rules would give a wrong offset.

- Images found inside compressed (or otherwise transformed) sections only
  exist in the decoded stream. Their position is reported as the transform
  chain plus the offset within that decoded stream; no physical byte
  position in the input file is fabricated.

Truncated headers and unknown section types are kept as evidence limits
instead of aborting the inventory.
'''

import struct

from .structs.uefi_structs import EFI_SECTION_TYPES, FIRMWARE_GUIDED_GUIDS
from .utils import sguid

# EFI_IMAGE_FILE_HEADER Machine values, shared by PE and TE headers.
MACHINE_TYPES = {
    0x014c: "i386",
    0x0200: "ia64",
    0x8664: "x86_64",
    0x01c0: "arm",
    0x01c4: "armv7",
    0xaa64: "aarch64",
    0x5032: "riscv32",
    0x5064: "riscv64",
    0x5128: "riscv128",
    0x6232: "loongarch32",
    0x6264: "loongarch64",
}

TE_HEADER_SIZE = 40
_TE_SIGNATURE = 0x5A56  # 'VZ'

# GUID-defined section GUIDs whose payload is a transformed (compressed)
# stream rather than a physical slice of the enclosing data.
_COMPRESSED_GUIDS = {
    FIRMWARE_GUIDED_GUIDS["LZMA_COMPRESSED"],
    FIRMWARE_GUIDED_GUIDS["LZMA_COMPRESSED_HP"],
    FIRMWARE_GUIDED_GUIDS["TIANO_COMPRESSED"],
    FIRMWARE_GUIDED_GUIDS["ZLIB_COMPRESSED_AMD"],
    FIRMWARE_GUIDED_GUIDS["GZIP_COMPRESSED_QC"],
}

# FFS section types holding a PE/TE image body.
_PE_SECTION_TYPES = (0x10, 0x11)
_TE_SECTION_TYPE = 0x12


def _u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def _arch(machine):
    return MACHINE_TYPES.get(machine, "unknown")


def _image_info(kind):
    return {
        "kind": kind,
        "arch": None,
        "machine": None,
        "image_base": None,
        "entry_rva": None,
        "entry_va": None,
        # Offset of the entry point within the image bytes themselves.
        "entry_image_offset": None,
        "image_size": None,
        "limits": [],
    }


def parse_pe(data):
    '''Parse a PE32/PE32+ header, keeping truncation as evidence limits.'''
    info = _image_info("PE")
    limits = info["limits"]
    info["image_size"] = len(data)

    if len(data) < 0x40:
        limits.append(
            "truncated DOS header: %d of 64 bytes" % len(data))
        return info
    e_lfanew = _u32(data, 0x3c)
    if e_lfanew + 4 > len(data):
        limits.append(
            "truncated: PE signature at 0x%x is beyond the image (%d bytes)"
            % (e_lfanew, len(data)))
        return info
    if bytes(data[e_lfanew:e_lfanew + 4]) != b"PE\x00\x00":
        limits.append("bad PE signature at 0x%x" % e_lfanew)
        return info
    if e_lfanew + 24 > len(data):
        limits.append("truncated COFF header at 0x%x" % (e_lfanew + 4))
        return info

    machine, number_of_sections, _, _, _, size_of_optional, _ = \
        struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    info["machine"] = machine
    info["arch"] = _arch(machine)

    optional = e_lfanew + 24
    if optional + 20 > len(data):
        limits.append("truncated optional header at 0x%x" % optional)
        return info
    magic = _u16(data, optional)
    if magic == 0x10B:
        info["kind"] = "PE32"
        base_offset, base_size = optional + 28, 4
    elif magic == 0x20B:
        info["kind"] = "PE32+"
        base_offset, base_size = optional + 24, 8
    else:
        limits.append("unknown optional header magic 0x%04x" % magic)
        return info

    info["entry_rva"] = _u32(data, optional + 16)
    if base_offset + base_size <= len(data):
        if base_size == 4:
            info["image_base"] = _u32(data, base_offset)
        else:
            info["image_base"] = _u64(data, base_offset)
    else:
        limits.append("truncated optional header: no image base")

    size_of_headers = None
    if optional + 64 <= len(data):
        size_of_headers = _u32(data, optional + 60)
    else:
        limits.append("truncated optional header: no SizeOfHeaders")

    if info["image_base"] is not None and info["entry_rva"] is not None:
        info["entry_va"] = info["image_base"] + info["entry_rva"]

    entry_rva = info["entry_rva"]
    if entry_rva is None:
        return info
    if size_of_headers is not None and entry_rva < size_of_headers:
        info["entry_image_offset"] = entry_rva
        return info

    section_table = optional + size_of_optional
    for index in range(number_of_sections):
        section = section_table + 40 * index
        if section + 40 > len(data):
            limits.append("truncated section table at section %d" % index)
            break
        virtual_size = _u32(data, section + 8)
        virtual_address = _u32(data, section + 12)
        raw_size = _u32(data, section + 16)
        raw_pointer = _u32(data, section + 20)
        span = max(virtual_size, raw_size)
        if virtual_address <= entry_rva < virtual_address + span:
            info["entry_image_offset"] = raw_pointer + (
                entry_rva - virtual_address)
            break
    else:
        limits.append(
            "entry RVA 0x%x is not mapped by any section" % entry_rva)

    offset = info["entry_image_offset"]
    if offset is not None and offset >= len(data):
        limits.append(
            "entry offset 0x%x is beyond the image size 0x%x (truncated?)"
            % (offset, len(data)))
    return info


def parse_te(data):
    '''Parse a TE (terse executable) header.

    TE fields are RVAs against the pre-stripping image layout, so the file
    offset of the entry point is RVA - (StrippedSize - 40), not the result
    of PE section-table mapping.
    '''
    info = _image_info("TE")
    limits = info["limits"]
    info["image_size"] = len(data)

    if len(data) < 8:
        limits.append(
            "truncated TE header: %d of %d bytes" % (len(data), TE_HEADER_SIZE))
        return info
    info["machine"] = _u16(data, 2)
    info["arch"] = _arch(info["machine"])
    if len(data) < TE_HEADER_SIZE:
        limits.append(
            "truncated TE header: %d of %d bytes" % (len(data), TE_HEADER_SIZE))
        return info

    stripped_size = _u16(data, 6)
    info["entry_rva"] = _u32(data, 8)
    info["image_base"] = _u64(data, 16)
    info["entry_va"] = info["image_base"] + info["entry_rva"]

    delta = stripped_size - TE_HEADER_SIZE
    if delta < 0:
        limits.append(
            "stripped size 0x%x is smaller than the %d-byte TE header"
            % (stripped_size, TE_HEADER_SIZE))
        return info
    entry_offset = info["entry_rva"] - delta
    if entry_offset < 0:
        limits.append(
            "entry RVA 0x%x lies within the stripped headers (delta 0x%x)"
            % (info["entry_rva"], delta))
        return info
    info["entry_image_offset"] = entry_offset
    if entry_offset >= len(data):
        limits.append(
            "entry offset 0x%x is beyond the image size 0x%x (truncated?)"
            % (entry_offset, len(data)))
    return info


def parse_image(data):
    '''Parse image bytes as PE or TE; return None for other content.'''
    if len(data) >= 2 and bytes(data[:2]) == b"MZ":
        return parse_pe(data)
    if len(data) >= 2 and _u16(data, 0) == _TE_SIGNATURE:
        return parse_te(data)
    return None


class ImageInventory(object):
    '''The PE/TE images found in a firmware object tree.'''

    def __init__(self):
        self.images = []
        self.limits = []

    def __len__(self):
        return len(self.images)

    def to_dict(self):
        return {
            "images": self.images,
            "limits": self.limits,
        }

    def showinfo(self, ts=''):
        for image in self.images:
            entry = image["entry_rva"]
            print("%s%s image: arch= %s entry RVA= %s VA= %s" % (
                ts, image["kind"], image["arch"],
                hex(entry) if entry is not None else "unknown",
                hex(image["entry_va"])
                if image["entry_va"] is not None else "unknown"))
            print("%s  path: %s" % (ts, _format_chain(image["location"])))
            if image["image_offset_in_fv"] is not None:
                print("%s  image offset in FV= 0x%x, entry offset in FV= %s"
                      % (ts, image["image_offset_in_fv"],
                         hex(image["entry_offset_in_fv"])
                         if image["entry_offset_in_fv"] is not None
                         else "unknown"))
            if image["decoded_offset"] is not None:
                print("%s  decoded-stream offset= 0x%x (via %s), "
                      "entry decoded offset= %s" % (
                          ts, image["decoded_offset"],
                          " -> ".join(image["transforms"]),
                          hex(image["entry_decoded_offset"])
                          if image["entry_decoded_offset"] is not None
                          else "unknown"))
            for limit in image["limits"]:
                print("%s  limit: %s" % (ts, limit))
        for limit in self.limits:
            print("%slimit: %s (%s)" % (
                ts, limit["reason"], _format_chain(limit["chain"])))


def _format_chain(chain):
    parts = []
    for node in chain:
        label = node["layer"]
        if node.get("guid"):
            label += " %s" % node["guid"]
        if node.get("offset") is not None:
            label += "+0x%x" % node["offset"]
        parts.append(label)
    return " / ".join(parts)


class _Scope(object):
    '''Where the walker currently is, and how offsets there are spaced.

    kind is "fv" (physical bytes of the innermost firmware volume),
    "decoded" (a decompressed stream, no physical position), or "unknown".
    base is the offset of the current container's data in that space.
    '''

    _KEEP = object()

    def __init__(self, chain=None, transforms=None, kind="unknown", base=None):
        self.chain = chain or []
        self.transforms = transforms or []
        self.kind = kind
        self.base = base

    def child(self, node=None, kind=None, base=_KEEP, transform=None):
        chain = self.chain + ([node] if node is not None else [])
        transforms = self.transforms + (
            [transform] if transform is not None else [])
        return _Scope(
            chain, transforms, kind if kind is not None else self.kind,
            self.base if base is self._KEEP else base)


def collect_images(root):
    '''Walk a parsed firmware object and list its embedded PE/TE images.

    Args:
        root: A processed firmware object (FirmwareVolume, the result of
            AutoParser.parse(), a FirmwareFile, ...) or a list of them.

    Return:
        ImageInventory: The images found, each with its location chain.
    '''
    inventory = ImageInventory()
    roots = root if isinstance(root, (list, tuple)) else [root]
    for obj in roots:
        _walk_root(obj, inventory, _Scope())
    return inventory


def _volume_offset(volume):
    '''Best-effort offset of a volume in its input, from its name.'''
    name = getattr(volume, "name", None)
    if isinstance(name, int):
        return name
    if isinstance(name, str):
        try:
            return int(name, 0)
        except ValueError:
            return None
    return None


def _walk_root(obj, inventory, scope):
    from .uefi import FirmwareFile, FirmwareFileSystem, \
        FirmwareFileSystemSection, FirmwareVolume
    from .base import AutoRawObject, PaddingObject, RawObject

    if obj is None:
        return
    if isinstance(obj, FirmwareVolume):
        offset = _volume_offset(obj)
        if scope.kind == "fv" and scope.base is not None:
            # A volume found inside file data: its name offset, when any,
            # is relative to that data.
            offset = scope.base + (offset or 0)
        _walk_volume(obj, inventory, scope, offset)
    elif isinstance(obj, FirmwareFileSystem):
        for index, firmware_file in enumerate(obj.files):
            _walk_file(firmware_file, None, inventory, scope, index)
    elif isinstance(obj, FirmwareFile):
        _walk_file(obj, None, inventory, scope, None)
    elif isinstance(obj, FirmwareFileSystemSection):
        _walk_section(obj, inventory, scope, None)
    elif isinstance(obj, (CompressedSection, GuidDefinedSection)):
        _walk_section_object(obj, inventory, scope, None)
    elif isinstance(obj, AutoRawObject):
        _walk_root(obj.object, inventory, scope)
    elif isinstance(obj, (RawObject, PaddingObject, bytes)):
        return
    else:
        # MultiObject, MultiVolumeContainer, capsules, flash regions, ...
        for child in getattr(obj, "objects", None) or []:
            _walk_root(child, inventory, scope)


def _walk_volume(volume, inventory, scope, parent_offset):
    node = {
        "layer": "firmware_volume",
        "name": None if volume.name is None else str(volume.name),
        "offset": parent_offset,
    }
    # Offsets inside a volume are relative to that volume.
    vscope = scope.child(node=node, kind="fv", base=0)
    for filesystem in volume.firmware_filesystems:
        for index, firmware_file in enumerate(filesystem.files):
            _walk_file(firmware_file, volume, inventory, vscope, index)
    for blob in volume.raw_objects:
        _walk_root(blob, inventory, vscope)


def _walk_file(firmware_file, volume, inventory, scope, index):
    extent = getattr(firmware_file, "parsed_extent", (None, None))[0]
    file_offset = None
    if scope.kind == "fv" and volume is not None and extent is not None:
        # The file system data starts right after the volume header.
        file_offset = volume.hdrlen + extent
    node = {
        "layer": "ffs_file",
        "guid": sguid(firmware_file.guid),
        "index": index,
        "offset": file_offset,
    }
    data_base = None
    if file_offset is not None:
        data_base = file_offset + firmware_file.header_size
    fscope = scope.child(node=node, base=data_base)
    for index, section in enumerate(firmware_file.sections):
        _walk_section(section, inventory, fscope, index)
    for blob in firmware_file.raw_blobs:
        # Raw blobs (nested volumes, flash descriptors, ...) sit in the
        # file data, so the current offset space still applies.
        _walk_root(blob, inventory, fscope)


def _section_extent(section, scope):
    extent = getattr(section, "parsed_extent", (None, None))[0]
    if scope.base is None or extent is None:
        return None
    return scope.base + extent


def _walk_section(section, inventory, scope, index):
    from .uefi import FirmwareVolume

    type_name = EFI_SECTION_TYPES.get(
        section.type, ("unknown",))[0]
    section_offset = _section_extent(section, scope)
    node = {
        "layer": "section",
        "index": index,
        "type": section.type,
        "type_name": type_name,
        "offset": section_offset,
    }
    header_size = 8 if getattr(section, "large_header", False) else 4
    data_offset = None
    if section_offset is not None:
        data_offset = section_offset + header_size

    if section.type in _PE_SECTION_TYPES or \
            section.type == _TE_SECTION_TYPE:
        info = parse_image(section.data)
        if info is None:
            inventory.limits.append({
                "reason": "section type 0x%02x (%s) does not start with a "
                          "PE/TE signature" % (section.type, type_name),
                "chain": scope.chain + [node],
            })
        else:
            _add_image(inventory, info, scope.child(node=node), data_offset)
        return

    if section.type not in EFI_SECTION_TYPES:
        inventory.limits.append({
            "reason": "unknown section type 0x%02x: not analyzed"
                      % section.type,
            "chain": scope.chain + [node],
        })
        return

    _walk_section_object(section.parsed_object, inventory,
                         scope.child(node=node), data_offset,
                         section=section)


def _walk_section_object(parsed_object, inventory, scope, data_offset,
                         section=None):
    from .uefi import FirmwareVolume
    from .base import AutoRawObject

    if parsed_object is None:
        return
    if isinstance(parsed_object, CompressedSection):
        transform = "decompress(compression section type 0x%02x)" % (
            parsed_object.type)
        node = {
            "layer": "compressed_section",
            "offset": data_offset,
        }
        if parsed_object.data is None:
            inventory.limits.append({
                "reason": "compressed section could not be decompressed: "
                          "contents not analyzed",
                "chain": scope.chain + [node],
            })
            return
        cscope = scope.child(
            node=node, kind="decoded", base=0, transform=transform)
        for index, subsection in enumerate(parsed_object.subsections):
            if hasattr(subsection, "parsed_extent"):
                _walk_section(subsection, inventory, cscope, index)
        return
    if isinstance(parsed_object, GuidDefinedSection):
        guid = sguid(parsed_object.guid)
        if guid in _COMPRESSED_GUIDS:
            node = {
                "layer": "guid_defined_section",
                "guid": guid,
                "offset": data_offset,
            }
            gscope = scope.child(
                node=node, kind="decoded", base=0,
                transform="decompress(guid-defined %s)" % guid)
        else:
            # Not transformed: the payload is a physical slice of the
            # section body, after the GUID header and preamble.
            header_len = len(parsed_object._body) - len(parsed_object.data)
            base = None
            if data_offset is not None:
                base = data_offset + header_len
            gscope = scope.child(
                node={
                    "layer": "guid_defined_section",
                    "guid": guid,
                    "offset": data_offset,
                }, base=base)
        for index, subsection in enumerate(parsed_object.subsections):
            if hasattr(subsection, "parsed_extent"):
                _walk_section(subsection, inventory, gscope, index)
            else:
                _walk_root(subsection, inventory, gscope)
        return
    if isinstance(parsed_object, FirmwareVolume):
        _walk_volume(parsed_object, inventory, scope,
                     _nested_volume_offset(parsed_object, section,
                                           data_offset))
        return
    if isinstance(parsed_object, AutoRawObject):
        _walk_root(parsed_object.object, inventory, scope)
        return
    _walk_root(parsed_object, inventory, scope)


def _nested_volume_offset(volume, section, data_offset):
    '''Locate a nested volume's bytes inside its enclosing section.'''
    if section is None or data_offset is None:
        return None
    needle = bytes(volume._data[16:48])
    if not needle:
        return None
    found = bytes(section.data).find(needle)
    if found < 16:
        return None
    return data_offset + found - 16


def _add_image(inventory, info, scope, data_offset):
    entry = dict(info)
    entry["location"] = scope.chain
    entry["transforms"] = scope.transforms
    entry["image_offset_in_fv"] = None
    entry["entry_offset_in_fv"] = None
    entry["decoded_offset"] = None
    entry["entry_decoded_offset"] = None
    if data_offset is not None and scope.kind == "fv":
        entry["image_offset_in_fv"] = data_offset
        if info["entry_image_offset"] is not None:
            entry["entry_offset_in_fv"] = (
                data_offset + info["entry_image_offset"])
    elif data_offset is not None and scope.kind == "decoded":
        entry["decoded_offset"] = data_offset
        if info["entry_image_offset"] is not None:
            entry["entry_decoded_offset"] = (
                data_offset + info["entry_image_offset"])
    inventory.images.append(entry)


# Late imports to avoid a cycle: uefi.py does not import this module.
from .uefi import CompressedSection, GuidDefinedSection  # noqa: E402
