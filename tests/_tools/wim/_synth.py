from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from dissect.archive.wim.c_wim import FILE_ATTRIBUTE, HEADER_FLAG, RESHDR_FLAG, WIM_IMAGE_TAG, c_wim

ZERO_HASH = b"\x00" * 20
WIM_HEADER_SIZE = 208
ENTRY_ALIGN = 8


def align(value: int, alignment: int = ENTRY_ALIGN) -> int:
    """Round ``value`` up to the next multiple of ``alignment``."""
    return (value + alignment - 1) & -alignment


@dataclass
class StreamSpec:
    """One stream entry to write into a directory entry's stream table."""

    name: str = ""
    content: bytes | None = b""
    hash: bytes | None = None
    length: int | None = None
    raw_name_length: int | None = None

    def resource_hash(self) -> bytes:
        if self.hash is not None:
            return self.hash
        return hashlib.sha1(self.content or b"").digest()


@dataclass
class Node:
    """A file or directory in a synthetic WIM image."""

    name: str
    content: bytes | None = None
    streams: list[StreamSpec] = field(default_factory=list)
    children: list[Node] = field(default_factory=list)
    attributes: int | None = None
    security_id: int = 0
    hard_link: int = 0
    subdir_offset: int = 0
    entry_offset: int = 0
    entry_length: int = 0
    declared_streams: int | None = None

    @property
    def is_dir(self) -> bool:
        return bool(self.children)


def _stream_bytes(spec: StreamSpec) -> bytes:
    name = spec.name.encode("utf-16-le")
    body = c_wim._STREAMENTRY().dumps() + name + (b"\x00\x00" if name else b"")
    padded = len(body) + (-len(body) % ENTRY_ALIGN)

    header = c_wim._STREAMENTRY()
    header.Unused1 = 0
    header.Hash = spec.resource_hash()
    header.StreamNameLength = len(name) if spec.raw_name_length is None else spec.raw_name_length
    header.Length = padded if spec.length is None else spec.length
    raw = header.dumps() + name + (b"\x00\x00" if name else b"")
    return raw.ljust(max(padded, len(raw)), b"\x00")


def _entry_header_bytes(node: Node) -> bytes:
    name = node.name.encode("utf-16-le")
    length = align(len(c_wim._DIRENTRY) + len(name) + (2 if name else 0))

    entry = c_wim._DIRENTRY()
    entry.Length = length
    if node.attributes is not None:
        entry.Attributes = FILE_ATTRIBUTE(node.attributes)
    else:
        entry.Attributes = FILE_ATTRIBUTE.DIRECTORY if node.is_dir else FILE_ATTRIBUTE.ARCHIVE
    entry.SecurityId = node.security_id
    entry.SubdirOffset = node.subdir_offset
    entry.Unused1 = 0
    entry.Unused2 = 0
    entry.CreationTime = 0
    entry.LastAccessTime = 0
    entry.LastWriteTime = 0
    entry.Hash = ZERO_HASH
    entry._Unknown = b"\x00" * 4
    entry.HardLink = node.hard_link
    entry.Streams = node.declared_streams if node.declared_streams is not None else len(node.streams)
    entry.ShortNameLength = 0
    entry.FileNameLength = len(name)

    if not node.streams:
        entry.Hash = hashlib.sha1(node.content).digest() if node.content is not None else ZERO_HASH

    raw = entry.dumps() + name + (b"\x00\x00" if name else b"")
    node.entry_length = length
    return raw.ljust(length, b"\x00")


def _entry_size(node: Node) -> int:
    return len(_entry_header_bytes(node)) + sum(len(_stream_bytes(spec)) for spec in node.streams)


def _layout_group(nodes: list[Node], start: int) -> int:
    cursor = start
    for node in nodes:
        node.entry_offset = cursor
        cursor = align(cursor + _entry_size(node))
    cursor += 8  # zero-length terminator for the group
    for node in nodes:
        if node.children:
            node.subdir_offset = cursor
            cursor = _layout_group(node.children, cursor)
    return cursor


def _layout(root: Node, base: int) -> int:
    """Assign entry offsets and subdirectory offsets, returning the end of the entry area."""
    root.entry_offset = base
    if root.children:
        root.subdir_offset = align(base + _entry_size(root))
        cursor = _layout_group(root.children, root.subdir_offset)
    else:
        cursor = base + _entry_size(root)
    return align(cursor)


def _write_group(nodes: list[Node], base: int, buf: bytearray) -> None:
    for node in nodes:
        raw = _entry_header_bytes(node)
        start = node.entry_offset - base
        buf[start : start + len(raw)] = raw

        stream_start = start + node.entry_length
        for spec in node.streams:
            stream = _stream_bytes(spec)
            buf[stream_start : stream_start + len(stream)] = stream
            stream_start += len(stream)

    for node in nodes:
        if node.children:
            _write_group(node.children, base, buf)


def _write_entries(root: Node, base: int) -> bytes:
    total = _layout(root, base)
    buf = bytearray(total - base)

    raw = _entry_header_bytes(root)
    buf[: len(raw)] = raw
    if root.children:
        _write_group(root.children, base, buf)
    return bytes(buf)


def _security_block(descriptors: list[bytes]) -> bytes:
    header = c_wim._SECURITYBLOCK_DISK(
        TotalLength=0,
        NumEntries=len(descriptors),
        EntryLength=[len(descriptor) for descriptor in descriptors],
    ).dumps()
    data = header + b"".join(descriptors)
    total = align(len(data))
    header = c_wim._SECURITYBLOCK_DISK(
        TotalLength=total,
        NumEntries=len(descriptors),
        EntryLength=[len(descriptor) for descriptor in descriptors],
    ).dumps()
    return (header + b"".join(descriptors)).ljust(total, b"\x00")


def build_wim(root: Node, descriptors: list[bytes] | None = None, *, omit_resources: set[bytes] | None = None) -> bytes:
    """Build a single-image WIM from ``root``.

    Resource blobs are collected from every stream that has content, plus the default
    content of streamless files. ``omit_resources`` drops the named hashes from the resource
    table and data area, so a stream can reference a resource that does not exist.
    """
    descriptors = descriptors or []
    security = _security_block(descriptors)
    entries = _write_entries(root, len(security))
    metadata = security + entries
    metadata = metadata.ljust(align(len(metadata)), b"\x00")

    contents: dict[bytes, bytes] = {}

    def collect(node: Node) -> None:
        for spec in node.streams:
            if spec.content is not None and spec.hash is None:
                contents.setdefault(hashlib.sha1(spec.content).digest(), spec.content)
        if not node.streams and node.content is not None:
            contents.setdefault(hashlib.sha1(node.content).digest(), node.content)
        for child in node.children:
            collect(child)

    collect(root)
    omitted = omit_resources or set()

    blobs = bytearray(b"\x00" * WIM_HEADER_SIZE)
    resources: list[tuple[bytes, RESHDR_FLAG, int, int]] = []

    for digest, content in sorted(contents.items()):
        if digest in omitted:
            continue
        blobs.extend(b"\x00" * (align(len(blobs)) - len(blobs)))
        resources.append((digest, RESHDR_FLAG(0), len(blobs), len(content)))
        blobs.extend(content)

    blobs.extend(b"\x00" * (align(len(blobs)) - len(blobs)))
    metadata_offset = len(blobs)
    resources.append((hashlib.sha1(metadata).digest(), RESHDR_FLAG.METADATA, metadata_offset, len(metadata)))
    blobs.extend(metadata)

    blobs.extend(b"\x00" * (align(len(blobs)) - len(blobs)))
    table_offset = len(blobs)
    table = bytearray()
    for digest, flags, offset, size in resources:
        short = c_wim._RESHDR_DISK_SHORT(Size=size.to_bytes(7, "little"), Flags=flags, Offset=offset, OriginalSize=size)
        table.extend(c_wim._RESHDR_DISK(Base=short, PartNumber=1, RefCount=1, Hash=digest).dumps())
    blobs.extend(table)

    def short_header(size: int, flags: RESHDR_FLAG, offset: int) -> c_wim._RESHDR_DISK_SHORT:
        return c_wim._RESHDR_DISK_SHORT(Size=size.to_bytes(7, "little"), Flags=flags, Offset=offset, OriginalSize=size)

    header = c_wim._WIMHEADER_V1_PACKED()
    header.ImageTag = WIM_IMAGE_TAG
    header.Size = WIM_HEADER_SIZE
    header.Version = c_wim.VERSION_DEFAULT
    header.Flags = HEADER_FLAG(0)
    header.CompressionSize = 0x1000
    header.WIMGuid = b"\x00" * 16
    header.PartNumber = 1
    header.TotalParts = 1
    header.ImageCount = 1
    header.OffsetTable = short_header(len(table), RESHDR_FLAG(0), table_offset)
    header.XmlData = short_header(0, RESHDR_FLAG(0), 0)
    header.BootMetadata = short_header(0, RESHDR_FLAG(0), 0)
    header.BootIndex = 0
    header.Integrity = short_header(0, RESHDR_FLAG(0), 0)
    header.Unused = b"\x00" * 60
    blobs[:WIM_HEADER_SIZE] = header.dumps()
    return bytes(blobs)
