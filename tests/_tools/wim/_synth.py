"""Synthetic, parser-consistent WIM builders for relationship tests.

Real WIM images with deliberately contradictory hardlink or security metadata are hard to
obtain and awkward to keep small in a repository. Instead, these builders assemble a minimal
valid WIM from the same :mod:`c_wim` structures that :mod:`dissect.archive.wim.wim` reads, so
a builder cannot silently drift from the parser's layout. The output is uncompressed and does
not need a mounted Windows filesystem.
"""

from __future__ import annotations

import hashlib
import io
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dissect.archive.wim.c_wim import (
    FILE_ATTRIBUTE,
    HEADER_FLAG,
    NO_SECURITY_DESC,
    RESHDR_FLAG,
    WIM_IMAGE_TAG,
    c_wim,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from dissect.archive.wim.wim import WIM

ZERO_HASH = b"\x00" * 20


@dataclass
class Node:
    """A directory entry in a synthetic image tree."""

    name: str
    attributes: FILE_ATTRIBUTE = FILE_ATTRIBUTE.ARCHIVE
    security_id: int = NO_SECURITY_DESC
    hard_link: int = 0
    streams: Mapping[str, bytes] = field(default_factory=dict)
    """Stream content keyed by stream name; the empty name is the default stream."""
    stream_hashes: Mapping[str, bytes] = field(default_factory=dict)
    """Optional stream hash overrides, to model references without a backing resource row."""
    children: list[Node] = field(default_factory=list)
    creation_time: int = 0
    last_access_time: int = 0
    last_write_time: int = 0


@dataclass
class ImageSpec:
    """One image in a synthetic WIM: a root tree and its own security table."""

    root: Node
    security_descriptors: Sequence[bytes | None] = field(default_factory=tuple)


def build_wim(root: Node, security_descriptors: Sequence[bytes | None]) -> bytes:
    """Build a minimal uncompressed WIM with a single image."""
    return build_wim_images([ImageSpec(root, security_descriptors)])


def build_wim_images(images: Sequence[ImageSpec]) -> bytes:
    """Build a minimal uncompressed WIM with one metadata resource per image.

    Images appear in resource table order, so the first spec is the first image returned by ``WIM.images()``.
    Content is deduplicated by SHA-1 across images exactly like a real WIM, while each image keeps its own
    directory entries and security table.
    """
    if not images:
        raise ValueError("at least one image is required")

    metadatas = [build_metadata(spec.root, spec.security_descriptors) for spec in images]

    contents: dict[bytes, bytes] = {}

    def collect(node: Node) -> None:
        for content in node.streams.values():
            contents.setdefault(hashlib.sha1(content).digest(), content)
        for child in node.children:
            collect(child)

    for spec in images:
        collect(spec.root)

    out = bytearray(b"\x00" * len(c_wim.WIMHEADER_V1_PACKED))
    resources: list[tuple[bytes, int, int, int]] = []

    for digest in sorted(contents):
        _align(out)
        offset = len(out)
        out += contents[digest]
        resources.append((digest, 0, offset, len(contents[digest])))

    for metadata in metadatas:
        _align(out)
        metadata_offset = len(out)
        out += metadata
        resources.append((hashlib.sha1(metadata).digest(), RESHDR_FLAG.METADATA, metadata_offset, len(metadata)))

    _align(out)
    table_offset = len(out)
    table = bytearray()
    for digest, flags, offset, size in resources:
        table += c_wim._RESHDR_DISK(
            Base=c_wim._RESHDR_DISK_SHORT(
                Size=size.to_bytes(7, "little"),
                Flags=RESHDR_FLAG(flags),
                Offset=offset,
                OriginalSize=size,
            ),
            PartNumber=1,
            RefCount=1,
            Hash=digest,
        ).dumps()
    out += table

    header = c_wim._WIMHEADER_V1_PACKED()
    header.ImageTag = WIM_IMAGE_TAG
    header.Size = len(header)
    header.Version = c_wim.VERSION_DEFAULT
    header.Flags = HEADER_FLAG(0)
    header.CompressionSize = 0x1000
    header.WIMGuid = b"\x00" * 16
    header.PartNumber = 1
    header.TotalParts = 1
    header.ImageCount = len(images)
    header.OffsetTable = _short_header(len(table), 0, table_offset)
    header.XmlData = _short_header(0, 0, 0)
    header.BootMetadata = _short_header(0, 0, 0)
    header.BootIndex = 0
    header.Integrity = _short_header(0, 0, 0)
    header.Unused = b"\x00" * 60
    out[: len(header)] = header.dumps()

    return bytes(out)


def build_metadata(root: Node, security_descriptors: Sequence[bytes | None]) -> bytes:
    """Build an image metadata stream: security table followed by directory entries."""
    lengths = [0 if descriptor is None else len(descriptor) for descriptor in security_descriptors]
    out = bytearray(
        c_wim._SECURITYBLOCK_DISK(
            TotalLength=8 + 8 * len(lengths) + sum(lengths),
            NumEntries=len(lengths),
            EntryLength=lengths,
        ).dumps()
    )
    for descriptor in security_descriptors:
        if descriptor is not None:
            out += descriptor
    _align(out)

    offsets: dict[int, int] = {}

    def write_group(nodes: list[Node]) -> int:
        first = -1
        for node in nodes:
            _align(out)
            offsets[id(node)] = len(out)
            if first < 0:
                first = len(out)
            out.extend(_dentry(node, node.name, node.security_id, node.hard_link, node.streams, node.stream_hashes))

        for node in nodes:
            if node.children:
                child_offset = write_group(node.children)
                _patch_int(out, offsets[id(node)] + 16, child_offset, 8)
        return first

    root_node = Node("", attributes=root.attributes, security_id=root.security_id)
    root_offset = len(out)
    out.extend(_dentry(root_node, "", root_node.security_id, 0, {}))

    if root.children:
        child_offset = write_group(root.children)
        _patch_int(out, root_offset + 16, child_offset, 8)

    return bytes(out)


def _dentry(
    node: Node,
    name: str,
    security_id: int,
    hard_link: int,
    streams: Mapping[str, bytes],
    stream_hashes: Mapping[str, bytes] | None = None,
) -> bytes:
    stream_hashes = stream_hashes or {}
    named_streams = [(stream_name, content) for stream_name, content in sorted(streams.items()) if stream_name]
    encoded_name = name.encode("utf-16-le")

    entry = c_wim._DIRENTRY()
    entry.Length = _align_value(len(c_wim._DIRENTRY) + len(encoded_name) + (2 if encoded_name else 0))
    entry.Attributes = FILE_ATTRIBUTE(node.attributes)
    entry.SecurityId = security_id
    entry.SubdirOffset = 0
    entry.Unused1 = 0
    entry.Unused2 = 0
    entry.CreationTime = node.creation_time
    entry.LastAccessTime = node.last_access_time
    entry.LastWriteTime = node.last_write_time
    entry._Unknown = b"\x00" * 4
    entry.__anonymous_1__.HardLink = hard_link
    entry.Streams = len(named_streams)
    entry.ShortNameLength = 0
    entry.FileNameLength = len(encoded_name)
    entry.FileName = name

    if named_streams:
        # The directory entry hash is unused with a stream table.
        entry.Hash = ZERO_HASH
    elif not name:
        # The root has no content identity of its own.
        entry.Hash = ZERO_HASH
    else:
        entry.Hash = stream_hashes.get("", hashlib.sha1(streams.get("", b"")).digest())

    out = bytearray(entry.dumps())
    if encoded_name:
        out += b"\x00\x00"
    out += b"\x00" * (entry.Length - len(out))

    for stream_name, content in named_streams:
        _align(out)
        encoded_stream_name = stream_name.encode("utf-16-le")
        stream = c_wim._STREAMENTRY()
        stream.Length = _align_value(len(c_wim._STREAMENTRY) + len(encoded_stream_name) + 2)
        stream.Unused1 = 0
        stream.Hash = stream_hashes.get(stream_name, hashlib.sha1(content).digest())
        stream.StreamNameLength = len(encoded_stream_name)
        stream.StreamName = stream_name
        out += stream.dumps()
        out += b"\x00\x00"
        out += b"\x00" * (stream.Length - len(c_wim._STREAMENTRY) - len(encoded_stream_name) - 2)

    return bytes(out)


def _short_header(size: int, flags: int, offset: int) -> c_wim._RESHDR_DISK_SHORT:
    return c_wim._RESHDR_DISK_SHORT(
        Size=size.to_bytes(7, "little"),
        Flags=RESHDR_FLAG(flags),
        Offset=offset,
        OriginalSize=size,
    )


def _align(buf: bytearray, alignment: int = 8) -> None:
    buf += b"\x00" * (-len(buf) % alignment)


def _align_value(value: int, alignment: int = 8) -> int:
    return (value + alignment - 1) & -alignment


def _patch_int(buf: bytearray, offset: int, value: int, size: int) -> None:
    buf[offset : offset + size] = value.to_bytes(size, "little")


def load(data: bytes) -> WIM:
    """Load synthetic WIM bytes, imported lazily to keep this module import-light."""
    from dissect.archive.wim.wim import WIM

    return WIM(io.BytesIO(data))
