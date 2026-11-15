"""Synthetic WIM builders for hermetic directory-entry and stream-table tests.

The committed WIM fixtures only exercise a well-formed default stream and one named stream. Edge
cases -- duplicate stream names, streams sharing a resource, missing or damaged resources, and a
stream table that overlaps the next directory entry -- cannot be produced by wimlib, so the tests
build a minimal WIM around the same :mod:`c_wim` structures the parser reads.

Layout produced by :func:`build_wim` (all offsets little-endian, as on disk)::

    header (0xd0 bytes)
    metadata resource (security block + directory entry tree)
    resource data, one blob per distinct content hash
    offset table (RESHDR_DISK entries)
    XML data

Only what the parser needs is filled in; everything else stays zero.
"""

from __future__ import annotations

import hashlib
import struct
from typing import TYPE_CHECKING

from dissect.archive.wim.c_wim import c_wim

if TYPE_CHECKING:
    from collections.abc import Iterable

DIRENTRY_SIZE = len(c_wim._DIRENTRY)
STREAMENTRY_SIZE = len(c_wim._STREAMENTRY)
HEADER_SIZE = 0xD0
HASH_SIZE = 20
ZERO_HASH = b"\x00" * HASH_SIZE


def align(value: int, alignment: int = 8) -> int:
    return (value + alignment - 1) & -alignment


def stream_entry(name: str, hash: bytes = ZERO_HASH, declared_length: int | None = None) -> bytes:
    """Build one 8-aligned stream entry.

    ``declared_length`` overrides only the length *field*, not the bytes written: the entry keeps
    its real, name-derived size and padding, modelling a corrupted length field on disk.
    """
    name_bytes = name.encode("utf-16-le")
    real_length = align(STREAMENTRY_SIZE + len(name_bytes) + 2)
    field_length = real_length if declared_length is None else declared_length

    body = struct.pack("<qq", field_length, 0) + hash
    body += struct.pack("<H", len(name_bytes)) + name_bytes
    body += b"\x00\x00"
    return body + b"\x00" * (real_length - len(body))


def directory_entry(
    name: str,
    *,
    attributes: int = 0x20,
    subdir_offset: int = 0,
    hash: bytes = ZERO_HASH,
    streams: Iterable[tuple[str, bytes] | tuple[str, bytes, int]] = (),
    declared_length: int | None = None,
    stream_count: int | None = None,
    trailing: bytes = b"",
) -> bytes:
    """Build one directory entry, optionally followed by its stream table.

    A stream is ``(name, hash)``, or ``(name, hash, declared_length)`` to corrupt only that stream's
    length field.
    """
    name_bytes = name.encode("utf-16-le")
    streams = list(streams)
    count = len(streams) if stream_count is None else stream_count

    fixed = struct.pack("<qIIqqqqqq", 0, attributes, 0, subdir_offset, 0, 0, 0, 0, 0)
    fixed += hash
    fixed += b"\x00" * 4
    fixed += struct.pack("<II", 0, 0)
    fixed += struct.pack("<HHH", count, 0, len(name_bytes))
    assert len(fixed) == DIRENTRY_SIZE, len(fixed)

    body = fixed + name_bytes + b"\x00\x00"
    length = align(len(body)) if declared_length is None else declared_length
    body = struct.pack("<q", length) + body[8:]
    body += b"\x00" * (align(length) - len(body))

    for stream in streams:
        if len(stream) == 3:
            stream_name, stream_hash, stream_declared_length = stream
            body += stream_entry(stream_name, stream_hash, stream_declared_length)
        else:
            stream_name, stream_hash = stream
            body += stream_entry(stream_name, stream_hash)

    return body + trailing


def build_wim(
    entries: list[dict],
    *,
    compression_size: int = 0x1000,
    flags: int = 0,
    extra_resources: dict[bytes, bytes] | None = None,
) -> bytes:
    """Build a complete single-image WIM.

    ``entries`` describes the root directory's children. Each entry is a dict with the keys
    ``name``, ``attributes``, ``hash``, ``streams`` (a list of ``(name, hash)``), and optionally
    ``declared_length``, ``stream_count`` and ``trailing`` to build malformed variants.

    Resources are derived from ``extra_resources`` (hash -> content); a stream whose hash is not in
    that mapping is still declared, but has no backing resource, which is exactly the missing
    resource case.
    """
    resources = dict(extra_resources or {})

    # Security block: three fixed-size entries, as WIM writes it.
    security = struct.pack("<II", 512, 3) + struct.pack("<QQQ", 160, 160, 160)
    security += b"\x00" * (512 - len(security))

    metadata = bytearray(security)
    root_header = directory_entry("", attributes=0x10)
    root_position = len(metadata)
    metadata += root_header
    children_position = len(metadata)

    # The root's SubdirOffset points at its first child; its declared length only covers its header.
    struct.pack_into("<q", metadata, root_position + 16, children_position)

    for entry in entries:
        metadata += directory_entry(
            entry["name"],
            attributes=entry.get("attributes", 0x20),
            hash=entry.get("hash", ZERO_HASH),
            streams=entry.get("streams", ()),
            declared_length=entry.get("declared_length"),
            stream_count=entry.get("stream_count"),
            trailing=entry.get("trailing", b""),
        )

    # A zero length terminator closes the directory listing.
    metadata += b"\x00" * 8

    if not entries:
        # An empty root still needs a terminator where its children would start.
        metadata = bytearray(metadata[:children_position]) + b"\x00" * 8

    data = bytearray(b"\x00" * HEADER_SIZE)
    metadata = bytes(metadata)

    resource_rows = []
    metadata_offset = len(data)
    data += metadata
    metadata_hash = hashlib.sha1(metadata).digest()
    resource_rows.append((metadata_hash, metadata_offset, len(metadata), len(metadata), 0x02))

    for hash, content in resources.items():
        offset = len(data)
        data += content
        resource_rows.append((hash, offset, len(content), len(content), 0x00))

    table_offset = len(data)
    table = bytearray()
    for hash, offset, size, original_size, stream_flags in resource_rows:
        table += size.to_bytes(7, "little") + bytes([stream_flags])
        table += struct.pack("<qq", offset, original_size)
        table += struct.pack("<HI", 1, 1) + hash
        assert len(table) % 50 == 0
    data += table

    xml = '<?xml version="1.0"?><WIM><IMAGE INDEX="1"><NAME>Synth</NAME></IMAGE></WIM>'.encode("utf-16-le")
    xml_offset = len(data)
    data += xml

    header = bytearray(HEADER_SIZE)
    header[0:8] = b"MSWIM\x00\x00\x00"
    struct.pack_into("<I", header, 8, HEADER_SIZE)
    struct.pack_into("<I", header, 12, 0x10D00)
    struct.pack_into("<I", header, 16, flags)
    struct.pack_into("<I", header, 20, compression_size)
    struct.pack_into("<H", header, 40, 1)
    struct.pack_into("<H", header, 42, 1)
    struct.pack_into("<I", header, 44, 1)
    struct.pack_into("<7sBqq", header, 48, len(table).to_bytes(7, "little"), 0x02, table_offset, len(table))
    struct.pack_into("<7sBqq", header, 72, len(xml).to_bytes(7, "little"), 0x02, xml_offset, len(xml))
    data[0:HEADER_SIZE] = header

    return bytes(data)
