'''Targeted mutations for nested FFS sections.

The corpus starts from a small, valid firmware volume that nests sections
inside a compressed section and a GUID-defined section. It encodes the
volume from a tree, so a change to a child updates every parent size and
the padding between siblings. Each mutation names one layer it targets, and
the checker parses the result with the real parser to report which layers
were reached, which sibling sections survived and which size or alignment
constraints were broken.

Files advance by 8-byte alignment and sections by 4-byte alignment. A
section with a 24-bit size of 0xffffff carries a 32-bit ExtendedSize, which
is counted from the start of its 8-byte header. The tree records both, and
each layer keeps the extent it had in the seed so a variant can be traced
back to the bytes it came from.
'''

import contextlib
import copy
import hashlib
import io
import json
import os
import struct
import uuid

from . import efi_compressor
from .structs.uefi_structs import FIRMWARE_GUIDED_GUIDS, FIRMWARE_VOLUME_GUIDS
from .uefi import (
    CompressedSection, FirmwareFileSystemSection, FirmwareVolume,
    GuidDefinedSection, calculate_checksum16)

SECTION_ALIGN = 4
FILE_ALIGN = 8
VOLUME_ALIGN = 8
ERASED = 0xFF
EXTENDED_MARKER = 0xFFFFFF

FFS2_GUID = uuid.UUID(FIRMWARE_VOLUME_GUIDS["FFS2"]).bytes_le
STATIC_GUID = uuid.UUID(FIRMWARE_GUIDED_GUIDS["STATIC_GUID"]).bytes_le

FILE_GUID = uuid.UUID("9e21fd93-9c72-4c15-8c4b-e77f1db2d792").bytes_le
LARGE_GUID = uuid.UUID("1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d").bytes_le
TAIL_GUID = uuid.UUID("0f1e2d3c-4b5a-4968-8776-655443322110").bytes_le


def utf16_name(text):
    '''Encode a UI or version name the way an FFS image stores it.'''
    return (text + "\0").encode("utf-16le")


class SectionNode(object):
    '''A section in the tree, either a leaf or a wrapper around children.'''

    def __init__(self, section_type, body=b"", children=None, wrapper=None,
                 extended=False, fill=0x00, extra_bytes=0,
                 declared_extra=0, align=None, guid=None,
                 padding_fill=None):
        self.section_type = section_type
        self.body = body
        self.children = children
        self.wrapper = wrapper
        self.extended = extended
        self.fill = fill
        self.extra_bytes = extra_bytes
        self.declared_extra = declared_extra
        self.align = align
        self.guid = guid
        self.padding_fill = padding_fill

    @property
    def header_size(self):
        return 8 if self.extended else 4


class FileNode(object):
    '''An FFS file holding one section stream.'''

    def __init__(self, guid, sections, large=False, fill=ERASED,
                 extra_bytes=0, declared_extra=0, align=None,
                 file_type=0x07, padding_fill=None):
        self.guid = guid
        self.sections = sections
        self.large = large
        self.fill = fill
        self.extra_bytes = extra_bytes
        self.declared_extra = declared_extra
        self.align = align
        self.file_type = file_type
        self.padding_fill = padding_fill

    @property
    def header_size(self):
        return 32 if self.large else 24


class VolumeNode(object):
    '''An FFS2 volume with a single block.'''

    def __init__(self, files, size=0x1000, fill=ERASED, attributes=0x800):
        self.files = files
        self.size = size
        self.fill = fill
        self.attributes = attributes


def seed_volume():
    '''Return the fixed seed layout used by every mutation.

    The layout has a normal section, a compressed wrapper and a GUID-defined
    wrapper in the first file, a large file in the middle and a small file
    after it. The wrappers hold normal and extended-length sections, and the
    GUID-defined wrapper itself uses an extended common header. Sections are
    padded to 4 bytes and files to 8, so some sections start at offsets that
    are 4- but not 8-byte aligned.
    '''
    compressed_children = [
        SectionNode(0x19, b"compressed-child-0", fill=0x00),
        SectionNode(0x15, utf16_name("nested-name"), fill=0xFF),
        SectionNode(0x19, b"compressed-child-2", extended=True, fill=0x00),
    ]
    guided_children = [
        SectionNode(0x19, b"guided-child-0", fill=0x00),
        SectionNode(0x14, struct.pack("<H", 7) +
                    utf16_name("guided-version"), fill=0xFF),
        SectionNode(0x19, b"guided-child-2", extended=True, fill=0x00),
    ]
    return VolumeNode([
        FileNode(FILE_GUID, [
            SectionNode(0x19, b"alpha-0"),
            SectionNode(0x01, children=compressed_children,
                       wrapper="compressed", fill=0x00),
            SectionNode(0x02, children=guided_children,
                       wrapper="guided", extended=True, fill=0x00,
                       guid=STATIC_GUID),
            SectionNode(0x19, b"outer-sibling"),
        ]),
        FileNode(LARGE_GUID, [
            SectionNode(0x19, b"large-0"),
            SectionNode(0x19, b"large-1", extended=True),
        ], large=True),
        FileNode(TAIL_GUID, [
            SectionNode(0x19, b"tail-0"),
            SectionNode(0x15, utf16_name("tail-name")),
        ]),
    ], size=0x1000)


def _join(prefix, segment, index):
    part = "%s[%d]" % (segment, index)
    return "%s/%s" % (prefix, part) if prefix else part


def _section_header(section_type, size, extended):
    if extended:
        return b"\xff\xff\xff" + bytes([section_type]) + \
            struct.pack("<I", size)
    if size >= EXTENDED_MARKER:
        raise ValueError("section size 0x%x needs an extended header" % size)
    return struct.pack("<I", size)[:3] + bytes([section_type])


def _file_header(node, size):
    if node.large:
        if size >= 1 << 64:
            raise ValueError("large file size does not fit")
        # The 3-byte size stays zero; the 64-bit ExtendedSize follows the
        # State byte, after the 24-byte common header.
        return node.guid + struct.pack(
            "<HBB3sBQ", 0, node.file_type, 0x01, b"\x00\x00\x00", 0xF8,
            size)
    if size >= EXTENDED_MARKER:
        raise ValueError("file size 0x%x needs a large header" % size)
    return node.guid + struct.pack(
        "<HBB3sB", 0, node.file_type, 0x00, struct.pack("<I", size)[:3],
        0xF8)


def _layer(path, kind, **fields):
    layer = {
        "path": path,
        "kind": kind,
        "type": None,
        "type_name": None,
        "header": "normal",
        "header_size": 0,
        "offset": 0,
        "container": None,
        "declared_size": 0,
        "actual_size": 0,
        "minimum_size": 0,
        "alignment": SECTION_ALIGN,
        "expected_alignment": SECTION_ALIGN,
        "extra_bytes": 0,
        "declared_extra": 0,
        "fill": 0x00,
        "fingerprint": None,
        "padding": 0,
        "padding_fill": None,
        "allowed_min": 0,
        "allowed_max": 0,
        "within_range": True,
    }
    layer.update(fields)
    return layer


def _encode_section(node, path, layers, containers):
    header_size = node.header_size
    if node.wrapper is not None:
        inner = _encode_stream(
            node.children, path, "inner", layers, containers)
        containers[path] = len(inner)
        if node.wrapper == "compressed":
            compressed = efi_compressor.EfiCompress(inner, len(inner))
            body = struct.pack("<IB", len(inner), 0x01) + compressed
        elif node.wrapper == "guided":
            guid = node.guid or STATIC_GUID
            body = guid + struct.pack("<HH", header_size + 20, 0) + inner
        else:
            raise ValueError("unknown wrapper %r" % node.wrapper)
    else:
        body = node.body

    base_size = header_size + len(body)
    extra = bytes([node.fill]) * node.extra_bytes
    actual_size = base_size + len(extra)
    declared_size = actual_size + node.declared_extra
    layers[path] = _layer(
        path, "section",
        type=node.section_type,
        type_name=_section_type_name(node.section_type),
        header="extended" if node.extended else "normal",
        header_size=header_size,
        declared_size=declared_size,
        actual_size=actual_size,
        minimum_size=base_size,
        alignment=node.align or SECTION_ALIGN,
        expected_alignment=SECTION_ALIGN,
        extra_bytes=node.extra_bytes,
        declared_extra=node.declared_extra,
        fill=node.fill,
        wrapper=node.wrapper,
    )
    encoded = _section_header(
        node.section_type, declared_size, node.extended) + body + extra
    layers[path]["fingerprint"] = hashlib.sha256(encoded).hexdigest()
    return encoded


def _pad(node, built, alignment, layers, path):
    padding = -len(built) % alignment
    layers[path]["padding"] = padding
    fill = node.fill if node.padding_fill is None else node.padding_fill
    layers[path]["padding_fill"] = fill
    return bytes([fill]) * padding


def _encode_stream(nodes, prefix, segment, layers, containers):
    data = b""
    for index, node in enumerate(nodes):
        path = _join(prefix, segment, index)
        section = _encode_section(node, path, layers, containers)
        layers[path]["offset"] = len(data)
        layers[path]["container"] = prefix or "volume"
        data += section
        if index + 1 < len(nodes):
            data += _pad(
                node, section, node.align or SECTION_ALIGN, layers, path)
    return data


def _encode_file(node, path, layers, containers):
    body = _encode_stream(node.sections, path, "sections", layers, containers)
    containers[path] = len(body)
    header_size = node.header_size
    base_size = header_size + len(body)
    extra = bytes([node.fill]) * node.extra_bytes
    actual_size = base_size + len(extra)
    declared_size = actual_size + node.declared_extra
    if declared_size < header_size:
        # The size field cannot describe less than the header the file is
        # written with; write the minimum and record that it was clamped.
        declared_size = header_size
        node.declared_extra = declared_size - actual_size
    layers[path] = _layer(
        path, "file",
        header="large" if node.large else "normal",
        header_size=header_size,
        declared_size=declared_size,
        actual_size=actual_size,
        minimum_size=base_size,
        alignment=node.align or FILE_ALIGN,
        expected_alignment=FILE_ALIGN,
        extra_bytes=node.extra_bytes,
        declared_extra=node.declared_extra,
        fill=node.fill,
    )
    encoded = _file_header(node, declared_size) + body + extra
    layers[path]["fingerprint"] = hashlib.sha256(encoded).hexdigest()
    return encoded


def encode_volume(volume):
    '''Serialize the tree, returning bytes and a per-layer layout.

    The layout records offsets inside the container that holds a layer, the
    declared and actual sizes, the alignment used after it and the range its
    parent leaves for it. A compressed or GUID-defined layer's children are
    measured in the decompressed stream, which the layout names.
    '''
    layers = {}
    containers = {}
    body = b""
    for index, node in enumerate(volume.files):
        path = _join("", "files", index)
        built = _encode_file(node, path, layers, containers)
        layers[path]["offset"] = len(body)
        layers[path]["container"] = "volume"
        body += built
        if index + 1 < len(volume.files):
            body += _pad(node, built, node.align or FILE_ALIGN, layers, path)

    block_map = struct.pack("<II", 1, volume.size) + b"\x00" * 8
    header_size = FirmwareVolume._HEADER_SIZE + len(block_map)
    containers["volume"] = volume.size - header_size
    layers["volume"] = _layer(
        "volume", "volume",
        header="normal",
        header_size=header_size,
        declared_size=volume.size,
        actual_size=header_size + len(body),
        minimum_size=header_size + len(body),
        alignment=VOLUME_ALIGN,
        expected_alignment=VOLUME_ALIGN,
        fill=volume.fill,
        container=None,
        offset=0,
    )

    header = struct.pack(
        "<16s16sQ4sIHHHsB",
        b"\x00" * 16, FFS2_GUID, volume.size, b"_FVH",
        volume.attributes, header_size, 0, 0, b"\x00", 2)
    checksum = calculate_checksum16(header + block_map)
    header = struct.pack(
        "<16s16sQ4sIHHHsB",
        b"\x00" * 16, FFS2_GUID, volume.size, b"_FVH",
        volume.attributes, header_size, checksum, 0, b"\x00", 2)
    image = header + block_map + body
    image += bytes([volume.fill]) * (volume.size - len(image))

    _attach_absolute(layers, header_size)
    _attach_ranges(layers, containers)
    return image, layers, containers


def _attach_absolute(layers, header_size):
    for path, layer in layers.items():
        if layer["kind"] == "volume":
            layer["absolute_offset"] = 0
            continue
        if layer["kind"] == "file":
            layer["absolute_offset"] = header_size + layer["offset"]
            continue
        parent = layers.get(layer["container"])
        if parent is None or parent["kind"] != "file":
            # Inside a wrapper the bytes live in a decompressed stream.
            layer["absolute_offset"] = None
            continue
        layer["absolute_offset"] = (
            header_size + parent["offset"] + parent["header_size"] +
            layer["offset"])


def _attach_ranges(layers, containers):
    for path, layer in layers.items():
        if layer["kind"] == "volume":
            layer["allowed_min"] = layer["header_size"]
            layer["allowed_max"] = layer["declared_size"]
        else:
            layer["allowed_min"] = layer["minimum_size"]
            capacity = containers.get(layer["container"], 0)
            layer["allowed_max"] = capacity - layer["offset"]
        layer["within_range"] = (
            layer["allowed_min"] <= layer["declared_size"] <=
            layer["allowed_max"])

    # A declared size may be within its parent yet still overlap the next
    # sibling, which is what a section with a size from the wrong layer does.
    siblings = {}
    for path, layer in layers.items():
        if layer["kind"] == "volume":
            continue
        siblings.setdefault(layer["container"], []).append(layer)
    for group in siblings.values():
        group.sort(key=lambda item: item["offset"])
        for current, following in zip(group, group[1:]):
            end = current["offset"] + current["declared_size"]
            current["overlaps_next"] = end > following["offset"]
            # The alignment a layer must use follows from its kind, not from
            # the tree, so this reads the gap back from the encoded bytes.
            required = SECTION_ALIGN if current["kind"] == "section" \
                else FILE_ALIGN
            expected = -current["declared_size"] % required
            observed = following["offset"] - end
            current["required_padding"] = expected
            current["observed_padding"] = observed
            # A size that was changed on purpose moves the next sibling, so
            # only a layer whose declared size still matches the bytes it
            # wrote can be judged on its padding. When the size was changed,
            # the padding was recomputed from it, so it is right by
            # construction and the size violation is the finding.
            if observed != expected and \
                    current["declared_size"] == current["actual_size"]:
                current["alignment_mismatch"] = True


def _section_type_name(section_type):
    from .uefi import _get_section_type
    return _get_section_type(section_type)[0]


def _walk_parsed_section(section, path, found):
    extent = getattr(section, "parsed_extent", (None, None))
    found[path] = {
        "path": path,
        "kind": "section",
        "type": section.type,
        "type_name": _section_type_name(section.type),
        "header": "extended" if section.large_header else "normal",
        "size": section.size,
        "offset": extent[0],
        "fingerprint": hashlib.sha256(section._data).hexdigest(),
        "reached": True,
    }
    parsed = section.parsed_object
    if isinstance(parsed, (CompressedSection, GuidDefinedSection)):
        for index, child in enumerate(parsed.subsections):
            if isinstance(child, FirmwareFileSystemSection):
                _walk_parsed_section(
                    child, path + "/inner[%d]" % index, found)


def parse_image(data):
    '''Parse data with the real parser, returning its success and layers.

    The parser reports some rejected layers on stderr. Those reports are
    captured here so the corpus build stays deterministic and its console
    output is the report, not a side effect of the variants that fail.
    '''
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        volume = FirmwareVolume(data)
        if not volume.valid_header:
            return False, {}
        status = volume.process()
    found = {}
    for ffs in volume.firmware_filesystems:
        for file_index, firmware_file in enumerate(ffs.files):
            path = "files[%d]" % file_index
            extent = getattr(firmware_file, "parsed_extent", (None, None))
            found[path] = {
                "path": path,
                "kind": "file",
                "header": "large" if firmware_file.large_file else "normal",
                "size": firmware_file.size,
                "offset": extent[0],
                "fingerprint": hashlib.sha256(
                    firmware_file._data).hexdigest(),
                "reached": True,
            }
            for section_index, section in enumerate(firmware_file.sections):
                _walk_parsed_section(
                    section, "%s/sections[%d]" % (path, section_index), found)
    return status, found


def _find(volume, path):
    node = volume
    for part in path.split("/"):
        name, _, index = part.partition("[")
        if not index:
            raise KeyError("path part %r has no index" % part)
        index = int(index.rstrip("]"))
        if name == "files":
            node = node.files[index]
        elif name == "sections":
            node = node.sections[index]
        elif name == "inner":
            node = node.children[index]
        else:
            raise KeyError("unknown path part %r" % part)
    return node


def set_layer(volume, path, **attributes):
    '''Set attributes on the node at path and return the volume.'''
    node = _find(volume, path)
    for name, value in attributes.items():
        if not hasattr(node, name):
            raise AttributeError("%s has no %s" % (type(node).__name__, name))
        setattr(node, name, value)
    return volume


def _violations(layers, parsed, parse_ok):
    '''Return every constraint a layered image breaks.

    The checks are independent per layer: a section's range and alignment
    come from the section stream that holds it, a file's from the volume.
    That is what makes a size copied from the layer above, or an alignment
    borrowed from it, show up here rather than as a downstream parse error.
    '''
    problems = []
    for path, layer in layers.items():
        if layer["kind"] == "volume":
            continue
        if not layer["within_range"]:
            problems.append({
                "code": "size-out-of-range",
                "path": path,
                "declared": layer["declared_size"],
                "allowed": [layer["allowed_min"], layer["allowed_max"]],
            })
        if layer.get("overlaps_next"):
            problems.append({
                "code": "overlaps-sibling",
                "path": path,
                "declared": layer["declared_size"],
            })
        if layer["alignment"] != layer["expected_alignment"] or \
                layer.get("alignment_mismatch"):
            problems.append({
                "code": "wrong-alignment",
                "path": path,
                "expected": layer["expected_alignment"],
                "actual": layer["alignment"],
                "required_padding": layer.get("required_padding"),
                "observed_padding": layer.get("observed_padding"),
            })
    if not parse_ok:
        problems.append({"code": "parse-failed"})
    for path, layer in layers.items():
        if layer["kind"] == "volume":
            continue
        if path not in parsed:
            problems.append({"code": "unreached", "path": path})
        elif layer["declared_size"] == layer["actual_size"]:
            # A size that differs from the bytes written is the mutation
            # itself, reported as size-out-of-range; do not also call the
            # parser's reading of those bytes a separate mismatch.
            if parsed[path].get("size") != layer["declared_size"]:
                problems.append({
                    "code": "size-mismatch",
                    "path": path,
                    "encoded": layer["declared_size"],
                    "parsed": parsed[path].get("size"),
                })
            if parsed[path].get("fingerprint") != layer["fingerprint"]:
                problems.append({
                    "code": "identity-mismatch",
                    "path": path,
                })
    return problems


class Variant(object):
    '''One mutation: its tree, target layer and expected outcome.'''

    def __init__(self, name, description, target, tree,
                 expect_parse=True, expect_target=True, preserve=(),
                 expect_codes=(), expect_alignment_ok=True):
        self.name = name
        self.description = description
        self.target = target
        self.tree = tree
        self.expect_parse = expect_parse
        self.expect_target = expect_target
        self.preserve = tuple(preserve)
        self.expect_codes = tuple(expect_codes)
        self.expect_alignment_ok = expect_alignment_ok


def _variant(name, description, target, change, **expectations):
    tree = copy.deepcopy(seed_volume())
    change(tree)
    return Variant(name, description, target, tree, **expectations)


def build_variants():
    '''Return the fixed mutation set, in a stable order.

    Each variant changes one layer; the encoder then updates the sizes of
    every layer above it and the padding between siblings. The expectations
    say whether the parser should still accept the volume, whether its
    target should be reached, and which siblings must survive.
    '''
    outer = (
        "files[0]/sections[0]",
        "files[0]/sections[2]",
        "files[0]/sections[3]",
        "files[1]",
        "files[2]/sections[0]",
        "files[2]/sections[1]",
    )
    two_files = ("files[0]", "files[1]")
    variants = [
        _variant(
            "grow-inner-section",
            "Grow a raw section inside the compressed wrapper by 8 bytes "
            "and change its fill; the wrapper and the file grow with it.",
            "files[0]/sections[1]/inner[0]",
            lambda tree: set_layer(
                tree, "files[0]/sections[1]/inner[0]",
                extra_bytes=8, fill=0xA5),
            preserve=outer),
        _variant(
            "promote-inner-to-extended",
            "Write an inner section with the 32-bit ExtendedSize header "
            "instead of the 24-bit size; every size above it moves by 4.",
            "files[0]/sections[2]/inner[0]",
            lambda tree: set_layer(
                tree, "files[0]/sections[2]/inner[0]", extended=True),
            preserve=outer),
        _variant(
            "demote-extended-to-normal",
            "Write an extended-length inner section with the normal 24-bit "
            "size; the GUID-defined wrapper shrinks by four header bytes.",
            "files[0]/sections[2]/inner[2]",
            lambda tree: set_layer(
                tree, "files[0]/sections[2]/inner[2]", extended=False),
            preserve=outer),
        _variant(
            "grow-large-file-section",
            "Grow a section in the large file; its 64-bit ExtendedSize and "
            "the following file offset both move.",
            "files[1]/sections[0]",
            lambda tree: set_layer(
                tree, "files[1]/sections[0]", extra_bytes=16, fill=0x5A),
            preserve=two_files),
        _variant(
            "bad-inner-compressed",
            "An inner section of the compressed wrapper claims 0x1000 more "
            "bytes than the decompressed stream holds. The wrapper's outer "
            "siblings must still be parsed.",
            "files[0]/sections[1]/inner[1]",
            lambda tree: set_layer(
                tree, "files[0]/sections[1]/inner[1]",
                declared_extra=0x1000),
            preserve=outer + ("files[0]/sections[1]/inner[2]",),
            expect_codes=("size-out-of-range",)),
        _variant(
            "bad-inner-guided",
            "A middle section of the GUID-defined wrapper overclaims its "
            "size. The last inner sibling and every outer section must "
            "still be parsed.",
            "files[0]/sections[2]/inner[0]",
            lambda tree: set_layer(
                tree, "files[0]/sections[2]/inner[0]",
                declared_extra=0x800),
            preserve=outer + ("files[0]/sections[2]/inner[2]",),
            expect_codes=("size-out-of-range", "overlaps-sibling")),
        _variant(
            "section-aligned-as-file",
            "Pad a section to the file layer's 8-byte alignment instead of "
            "the section layer's 4. The next section header no longer sits "
            "where the section parser looks.",
            "files[0]/sections[0]",
            lambda tree: set_layer(
                tree, "files[0]/sections[0]", align=FILE_ALIGN),
            expect_parse=False,
            expect_target=True,
            preserve=("files[0]/sections[0]",),
            expect_codes=("wrong-alignment",),
            expect_alignment_ok=False),
        _variant(
            "file-header-size-omits-header",
            "A file's 24-bit size counts only its sections, not its 24-byte "
            "header. The parser reads the size from the header it was handed "
            "rather than from the field, so the layer is still reached but "
            "no longer matches the bytes it was encoded from.",
            "files[1]",
            lambda tree: set_layer(tree, "files[1]", declared_extra=-24),
            expect_parse=True,
            expect_target=True,
            expect_codes=("size-out-of-range", "size-mismatch",
                          "identity-mismatch"),
            expect_alignment_ok=True),
        _variant(
            "change-section-padding-fill",
            "Change the 3 bytes of padding after a section from 0x00 to "
            "0xff. The 4-byte step is unchanged, so the next section is "
            "still found at the same offset.",
            "files[0]/sections[0]",
            lambda tree: set_layer(
                tree, "files[0]/sections[0]", padding_fill=0xFF),
            preserve=outer),
        _variant(
            "change-file-padding-fill",
            "Change the padding between files from erased 0xff to 0x00. "
            "The 8-byte step is unchanged, so every file stays reachable.",
            "files[0]",
            lambda tree: set_layer(
                tree, "files[0]", padding_fill=0x00),
            preserve=("files[0]", "files[1]", "files[2]")),
    ]
    return variants


def _describe_layers(layers):
    described = []
    for path in sorted(
            layers, key=lambda item: (item.count("/"), item)):
        layer = dict(layers[path])
        if not layer["within_range"]:
            layer["range_problem"] = (
                "declared 0x%x outside 0x%x..0x%x" % (
                    layer["declared_size"], layer["allowed_min"],
                    layer["allowed_max"]))
        described.append(layer)
    return described


def _origin_for(seed_layers, path):
    original = seed_layers.get(path)
    if original is None:
        return None
    if original.get("absolute_offset") is not None:
        source = "seed.fv:0x%x+0x%x" % (
            original["absolute_offset"], original["declared_size"])
    else:
        source = "seed.fv:%s@0x%x+0x%x" % (
            original.get("container"), original["offset"],
            original["declared_size"])
    return {
        "path": path,
        "source": source,
        "offset": original["offset"],
        "absolute_offset": original.get("absolute_offset"),
        "size": original["declared_size"],
        "header": original["header"],
    }


def check_variant(variant, seed_layers):
    '''Encode and parse one variant, then evaluate its expectations.'''
    image, layers, _ = encode_volume(variant.tree)
    parse_ok, parsed = parse_image(image)
    violations = _violations(layers, parsed, parse_ok)
    codes = {problem["code"] for problem in violations}

    target_reached = variant.target in parsed
    preserved = {}
    for path in variant.preserve:
        seen = parsed.get(path)
        if seen is None:
            preserved[path] = {"reached": False}
            continue
        preserved[path] = {
            "reached": True,
            "offset": seen["offset"],
            "unchanged": (
                seen.get("fingerprint") == layers[path]["fingerprint"]),
        }
    alignment_ok = "wrong-alignment" not in codes

    failures = []
    if parse_ok != variant.expect_parse:
        failures.append(
            "parse was %s, expected %s" % (parse_ok, variant.expect_parse))
    if variant.expect_target is not None and \
            target_reached != variant.expect_target:
        failures.append(
            "target %s reached=%s, expected %s" % (
                variant.target, target_reached, variant.expect_target))
    for path, state in preserved.items():
        if not state["reached"]:
            failures.append("preserved layer %s was not reached" % path)
        elif not state["unchanged"]:
            failures.append("preserved layer %s changed" % path)
    for code in variant.expect_codes:
        if code not in codes:
            failures.append("expected violation %s was not detected" % code)
    if alignment_ok != variant.expect_alignment_ok:
        failures.append(
            "alignment ok=%s, expected %s" % (
                alignment_ok, variant.expect_alignment_ok))

    described = _describe_layers(layers)
    for layer in described:
        layer["origin"] = _origin_for(seed_layers, layer["path"])

    report = {
        "name": variant.name,
        "description": variant.description,
        "target": variant.target,
        "sha256": hashlib.sha256(image).hexdigest(),
        "size": len(image),
        "layers_reached": len(parsed),
        "parsed": parse_ok,
        "target_reached": target_reached,
        "preserved": preserved,
        "alignment_ok": alignment_ok,
        "violations": violations,
        "layers": described,
        "ok": not failures,
        "failures": failures,
    }
    return report, image


def build_corpus():
    '''Encode the seed and every variant, returning bytes and reports.'''
    seed_tree = seed_volume()
    seed_image, seed_layers, containers = encode_volume(seed_tree)
    parse_ok, parsed = parse_image(seed_image)
    seed_violations = _violations(seed_layers, parsed, parse_ok)

    seed = {
        "sha256": hashlib.sha256(seed_image).hexdigest(),
        "size": len(seed_image),
        "layers_reached": len(parsed),
        "parsed": parse_ok,
        "violations": seed_violations,
        "layers": _describe_layers(seed_layers),
    }
    for layer in seed["layers"]:
        layer["origin"] = _origin_for(seed_layers, layer["path"])
    seed["containers"] = {
        name: size for name, size in sorted(containers.items())
    }

    reports = []
    images = {}
    for variant in build_variants():
        report, image = check_variant(variant, seed_layers)
        images[variant.name] = image
        reports.append(report)

    expected_paths = {
        path for path, layer in seed_layers.items()
        if layer["kind"] != "volume"
    }
    return {
        "seed": seed,
        "seed_bytes": seed_image,
        "variants": reports,
        "variant_bytes": images,
        "normal_layout_complete": expected_paths == set(parsed),
        "counts": {
            "seed_layers": len(expected_paths),
            "variants": len(reports),
            "failed_variants": sum(1 for item in reports if not item["ok"]),
        },
    }


def _format_layer(layer, indent):
    fields = [
        layer["path"],
        "kind=%s" % layer["kind"],
    ]
    if layer["kind"] == "section":
        fields.append("type=0x%02x" % layer["type"])
    fields.extend([
        "header=%s" % layer["header"],
        "size=0x%x" % layer["declared_size"],
        "allowed=0x%x..0x%x" % (
            layer["allowed_min"], layer["allowed_max"]),
        "align=%d/%d" % (
            layer["alignment"], layer["expected_alignment"]),
    ])
    if layer.get("absolute_offset") is not None:
        fields.append("offset=0x%x" % layer["absolute_offset"])
    else:
        fields.append("offset=%s@0x%x" % (
            layer.get("container"), layer["offset"]))
    origin = layer.get("origin")
    if origin:
        fields.append("from=%s" % origin["source"])
    return " " * indent + " ".join(fields)


def format_report(corpus):
    '''Render a human-readable report of the seed and every variant.'''
    lines = [
        "seed sha256=%s size=0x%x parsed=%s" % (
            corpus["seed"]["sha256"], corpus["seed"]["size"],
            corpus["seed"]["parsed"]),
        "normal layout complete: %s" % corpus["normal_layout_complete"],
        "layers:",
    ]
    for layer in corpus["seed"]["layers"]:
        lines.append(_format_layer(layer, 2))
    lines.append("")
    lines.append("variants:")
    for report in corpus["variants"]:
        lines.append(
            "  %s: ok=%s parsed=%s layers=%d target=%s reached=%s" % (
                report["name"], report["ok"], report["parsed"],
                report["layers_reached"], report["target"],
                report["target_reached"]))
        by_code = {}
        for problem in report["violations"]:
            by_code.setdefault(problem["code"], []).append(
                problem.get("path", "-"))
        for code in sorted(by_code):
            paths = by_code[code]
            lines.append("    %s: %d layer(s)" % (code, len(paths)))
            for path in paths:
                lines.append("      %s" % path)
        for failure in report["failures"]:
            lines.append("    failure %s" % failure)
    return "\n".join(lines)


def write_corpus(directory):
    '''Write seed.fv, variants, manifest.json and report.json.

    Return the corpus report. The files are byte-for-byte reproducible.
    '''
    corpus = build_corpus()
    os.makedirs(os.path.join(directory, "variants"), exist_ok=True)
    seed_path = os.path.join(directory, "seed.fv")
    with open(seed_path, "wb") as handle:
        handle.write(corpus["seed_bytes"])

    manifest = {
        "seed": {
            "file": "seed.fv",
            "sha256": corpus["seed"]["sha256"],
            "size": corpus["seed"]["size"],
            "layers_reached": corpus["seed"]["layers_reached"],
            "normal_layout_complete": corpus["normal_layout_complete"],
            "parsed": corpus["seed"]["parsed"],
        },
        "variants": [],
    }
    for report in corpus["variants"]:
        name = report["name"] + ".fv"
        path = os.path.join("variants", name)
        with open(os.path.join(directory, path), "wb") as handle:
            handle.write(corpus["variant_bytes"][report["name"]])
        manifest["variants"].append({
            "name": report["name"],
            "file": path,
            "sha256": report["sha256"],
            "target": report["target"],
            "description": report["description"],
            "expect": {
                "parsed": report["parsed"],
                "layers_reached": report["layers_reached"],
                "target_reached": report["target_reached"],
                "alignment_ok": report["alignment_ok"],
                "violations": sorted(
                    {problem["code"] for problem in report["violations"]}),
            },
        })

    with open(os.path.join(directory, "manifest.json"), "w") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    report = {
        key: value for key, value in corpus.items()
        if not key.endswith("_bytes")
    }
    with open(os.path.join(directory, "report.json"), "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    with open(os.path.join(directory, "report.txt"), "w") as handle:
        handle.write(format_report(corpus))
        handle.write("\n")
    return corpus
