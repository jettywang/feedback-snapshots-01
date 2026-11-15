"""Synthetic WIM builders for relationship tests.

The relationship view is about evidence that a real WIM can carry but that is awkward to
produce on demand: two independent files with identical content, a hard link group whose
members disagree, and security ids that point at an empty or out-of-range slot. These
builders write a small, structurally valid WIM from the same ``c_wim`` structures the
parser reads, so the fixtures cannot drift from the on-disk layout.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from dissect.archive.wim.c_wim import FILE_ATTRIBUTE, HEADER_FLAG, RESHDR_FLAG, WIM_IMAGE_TAG, c_wim

ZERO_HASH = b"\x00" * 20
HEADER_SIZE = 208


def align(value: int, alignment: int = 8) -> int:
    return (value + alignment - 1) & -alignment


@dataclass
class Node:
    """One directory entry to write."""

    name: str
    kind: str = "file"
    content: bytes | None = b""
    security_id: int = 0
    hard_link: int = 0
    attributes: int | None = None
    creation_time: int = 0
    last_access_time: int = 0
    last_write_time: int = 0
    reparse_tag: int = 0
    children: list[Node] = field(default_factory=list)

    entry_hash: bytes = ZERO_HASH
    offset: int = 0
    subdir_offset: int = 0
    length: int = 0

    def stream_hashes(self) -> list[bytes]:
        if self.kind != "file" or self.content is None:
            return []
        return [hashlib.sha1(self.content).digest()]


def _attributes(node: Node) -> int:
    if node.attributes is not None:
        return node.attributes
    if node.kind in ("root", "dir"):
        return FILE_ATTRIBUTE.DIRECTORY
    if node.kind == "reparse":
        return FILE_ATTRIBUTE.ARCHIVE | FILE_ATTRIBUTE.REPARSE_POINT
    return FILE_ATTRIBUTE.ARCHIVE


def _dent(node: Node, subdir_offset: int = 0) -> bytes:
    name = "" if node.kind == "root" else node.name
    name_bytes = name.encode("utf-16-le")
    length = align(102 + len(name_bytes) + (2 if name_bytes else 0))

    hashes = node.stream_hashes()
    entry_hash = hashes[0] if hashes else ZERO_HASH

    entry = c_wim._DIRENTRY()
    entry.Length = length
    entry.Attributes = FILE_ATTRIBUTE(_attributes(node))
    entry.SecurityId = node.security_id
    entry.SubdirOffset = subdir_offset
    entry.Unused1 = 0
    entry.Unused2 = 0
    entry.CreationTime = node.creation_time
    entry.LastAccessTime = node.last_access_time
    entry.LastWriteTime = node.last_write_time
    entry.Hash = entry_hash
    entry._Unknown = b"\x00" * 4
    if node.kind == "reparse":
        entry.__anonymous_1__.ReparseTag = node.reparse_tag
    else:
        entry.HardLink = node.hard_link
    entry.Streams = 0
    entry.ShortNameLength = 0
    entry.FileNameLength = len(name_bytes)

    raw = entry.dumps()
    assert len(raw) == 102
    raw += name_bytes + (b"\x00\x00" if name_bytes else b"")
    return raw.ljust(length, b"\x00")


def _node_size(node: Node) -> int:
    return len(_dent(node))


def _layout(root: Node, base: int) -> int:
    root.offset = base
    cursor = base + _node_size(root)

    def assign(nodes: list[Node], at: int) -> int:
        cursor = at
        for node in nodes:
            node.offset = cursor
            node.length = _node_size(node)
            cursor += node.length

        # A directory listing ends with a zero length entry.
        cursor = align(cursor) + 8

        for node in nodes:
            if node.kind == "dir":
                # Even an empty directory points at an (empty) listing, never at 0.
                node.subdir_offset = cursor
                if node.children:
                    cursor = assign(node.children, cursor)
                else:
                    cursor += 8
        return cursor

    if root.children:
        root.subdir_offset = cursor
        cursor = assign(root.children, cursor)

    return cursor


def _write_entries(root: Node, base: int) -> bytes:
    total = _layout(root, base)
    buf = bytearray(total)

    def write_group(nodes: list[Node]) -> None:
        for node in nodes:
            raw = _dent(node, node.subdir_offset)
            buf[node.offset : node.offset + len(raw)] = raw
        for node in nodes:
            if node.kind == "dir" and node.children:
                write_group(node.children)

    raw = _dent(root, root.subdir_offset)
    buf[root.offset : root.offset + len(raw)] = raw
    if root.children:
        write_group(root.children)

    return bytes(buf[base:])


def security_block(descriptors: list[bytes | None]) -> bytes:
    """Build a security block, keeping ``None`` entries as stored zero-length slots."""
    lengths = [0 if descriptor is None else len(descriptor) for descriptor in descriptors]
    total = 8 + 8 * len(descriptors) + sum(lengths)
    header = c_wim._SECURITYBLOCK_DISK(
        TotalLength=total,
        NumEntries=len(descriptors),
        EntryLength=lengths,
    ).dumps()
    assert len(header) == 8 + 8 * len(descriptors)

    out = bytearray(header)
    for descriptor in descriptors:
        if descriptor:
            out += descriptor

    return bytes(out)


def _short_header(size: int, flags: RESHDR_FLAG, offset: int, original_size: int) -> c_wim._RESHDR_DISK_SHORT:
    return c_wim._RESHDR_DISK_SHORT(
        Size=size.to_bytes(7, "little"),
        Flags=flags,
        Offset=offset,
        OriginalSize=original_size,
    )


def build_wim(root: Node, descriptors: list[bytes | None], omit_content: set[bytes] | None = None) -> bytes:
    """Build an uncompressed single-image WIM.

    Args:
        root: Root directory node.
        descriptors: Security block entries; ``None`` is a stored empty slot.
        omit_content: Stream hashes to leave out of the resource table, modelling a
            directory entry whose resource is missing.
    """
    omit_content = omit_content or set()
    security = security_block(descriptors)
    # The metadata resource is 8-byte aligned, so directory entry offsets are relative
    # to the aligned security block, exactly as they are in the image.
    security += b"\x00" * (align(len(security)) - len(security))
    entries = _write_entries(root, len(security))
    metadata = security + entries
    metadata += b"\x00" * (align(len(metadata)) - len(metadata))

    contents: dict[bytes, bytes] = {}

    def collect(node: Node) -> None:
        for digest in node.stream_hashes():
            if digest not in omit_content:
                contents[digest] = node.content
        for child in node.children:
            collect(child)

    collect(root)

    blobs = bytearray(b"\x00" * HEADER_SIZE)
    resources = []
    for digest in sorted(contents):
        content = contents[digest]
        blobs += b"\x00" * (align(len(blobs)) - len(blobs))
        resources.append((digest, RESHDR_FLAG(0), len(blobs), len(content), len(content)))
        blobs += content

    blobs += b"\x00" * (align(len(blobs)) - len(blobs))
    metadata_offset = len(blobs)
    resources.append(
        (hashlib.sha1(metadata).digest(), RESHDR_FLAG.METADATA, metadata_offset, len(metadata), len(metadata))
    )
    blobs += metadata

    blobs += b"\x00" * (align(len(blobs)) - len(blobs))
    table_offset = len(blobs)
    table = b"".join(
        c_wim._RESHDR_DISK(
            Base=_short_header(size, flags, offset, original_size),
            PartNumber=1,
            RefCount=1,
            Hash=digest,
        ).dumps()
        for digest, flags, offset, size, original_size in resources
    )
    blobs += table

    header = c_wim._WIMHEADER_V1_PACKED()
    header.ImageTag = WIM_IMAGE_TAG
    header.Size = HEADER_SIZE
    header.Version = c_wim.VERSION_DEFAULT
    header.Flags = HEADER_FLAG(0)
    header.CompressionSize = 0x1000
    header.WIMGuid = b"\x00" * 16
    header.PartNumber = 1
    header.TotalParts = 1
    header.ImageCount = 1
    header.OffsetTable = _short_header(len(table), RESHDR_FLAG(0), table_offset, len(table))
    header.XmlData = _short_header(0, RESHDR_FLAG(0), 0, 0)
    header.BootMetadata = _short_header(0, RESHDR_FLAG(0), 0, 0)
    header.BootIndex = 0
    header.Integrity = _short_header(0, RESHDR_FLAG(0), 0, 0)
    header.Unused = b"\x00" * 60

    raw_header = header.dumps()
    assert len(raw_header) == HEADER_SIZE
    blobs[:HEADER_SIZE] = raw_header

    return bytes(blobs)
