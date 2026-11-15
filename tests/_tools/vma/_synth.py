"""Synthetic, checksum-correct Proxmox VMA builders for hermetic tests.

Real VMA archives cannot cover every corruption case (overrunning blob
pointers, control characters in blob names, undeclared device ids), so the
evidence tests build minimal valid headers and extents from the same
:mod:`c_vma` structures the parser reads with. Every blob, config slot and
extent blockinfo entry is constructed explicitly so a test can point at the
exact record it expects the report to describe.
"""

from __future__ import annotations

import hashlib
import io
import struct
from typing import BinaryIO
from uuid import uuid4

from dissect.archive.vma.c_vma import (
    VMA_BLOCK_SIZE,
    VMA_BLOCKS_PER_EXTENT,
    VMA_CLUSTER_SIZE,
    VMA_EXTENT_MAGIC,
    VMA_MAGIC,
    c_vma,
)

# Offset 0 of the blob buffer is unused by convention; the real dumper starts
# its first frame at offset 1.
BLOB_FIRST_OFFSET = 1


class SynthVMA:
    """Builder for a minimal VMA byte stream."""

    def __init__(self) -> None:
        self._frames: dict[int, bytes] = {}
        self._cursor = BLOB_FIRST_OFFSET
        self._configs: list[tuple[str | bytes, str | bytes | int]] = []
        self._devices: list[tuple[int, str | bytes | int, int]] = []
        self._extents: list[dict[int, list[tuple[int, int, bytes | None]]]] = []

    def add_blob(self, data: str | bytes, *, offset: int | None = None) -> int:
        """Append a framed blob and return its offset."""
        raw = data.encode() if isinstance(data, str) else data
        target = self._cursor if offset is None else offset
        self._frames[target] = struct.pack("<H", len(raw)) + raw
        self._cursor = max(self._cursor, target + len(self._frames[target]))
        return target

    def add_raw_frame(self, offset: int, framed: bytes) -> None:
        """Place a pre-built (possibly malformed) frame at ``offset``."""
        self._frames[offset] = framed
        self._cursor = max(self._cursor, offset + len(framed))

    def add_config(self, name: str | bytes, data: str | bytes | int) -> None:
        """Register a config slot.

        ``data`` may be blob content or a raw pointer, which allows pointing a
        config data slot outside the blob buffer.
        """
        self._configs.append((name, data))

    def add_device(self, dev_id: int, name: str | bytes | int, size: int) -> None:
        """Register a device declaration; ``name`` may be a raw blob pointer."""
        self._devices.append((dev_id, name, size))

    def add_extent(self, blocks: dict[int, list[tuple[int, int, bytes | None]]]) -> None:
        """Register an extent mapping ``device_id -> [(cluster, mask, payload)]``.

        Mask 0 means a fully sparse cluster, ``0xFFFF`` a fully allocated one.
        A payload of ``None`` yields zero-filled cluster data.
        """
        self._extents.append(blocks)

    def build(self) -> bytes:
        blob, name_offsets, data_pointers = self._build_blob_buffer()
        header = self._build_header(blob, name_offsets, data_pointers)
        return header + self._build_extents()

    def write(self, fh: BinaryIO) -> None:
        fh.write(self.build())

    def _build_blob_buffer(
        self,
    ) -> tuple[bytes, dict[str | bytes, int], list[int]]:
        name_offsets: dict[str | bytes, int] = {}

        def name_offset(name: str | bytes | int) -> int:
            if isinstance(name, int):
                return name
            key = name
            if key not in name_offsets:
                name_offsets[key] = self.add_blob(name)
            return name_offsets[key]

        data_pointers: list[int] = []
        for name, data in self._configs:
            name_offset(name)
            if isinstance(data, int):
                data_pointers.append(data)
            else:
                data_pointers.append(self.add_blob(data))

        for _dev_id, name, _size in self._devices:
            name_offset(name)

        end = max((offset + len(frame) for offset, frame in self._frames.items()), default=1)
        buffer = bytearray(end)
        for offset, frame in self._frames.items():
            buffer[offset : offset + len(frame)] = frame
        return bytes(buffer), name_offsets, data_pointers

    def _build_header(
        self,
        blob: bytes,
        name_offsets: dict[str | bytes, int],
        data_pointers: list[int],
    ) -> bytes:
        blob_offset = len(c_vma.VmaHeader())
        blob_size = len(blob)
        header_size = (blob_offset + blob_size + 511) & ~511

        header = c_vma.VmaHeader()
        header.magic = VMA_MAGIC
        header.version = 1
        header.uuid = uuid4().bytes
        header.ctime = 1_700_000_000
        header.blob_buffer_offset = blob_offset
        header.blob_buffer_size = blob_size
        header.header_size = header_size

        config_names = [0] * c_vma.VMA_MAX_CONFIGS
        config_data = [0] * c_vma.VMA_MAX_CONFIGS
        for slot, ((name, _data), data_ptr) in enumerate(zip(self._configs, data_pointers, strict=True)):
            config_names[slot] = name_offsets[name]
            config_data[slot] = data_ptr
        header.config_names = config_names
        header.config_data = config_data

        dev_info = [c_vma.VmaDeviceInfoHeader() for _ in range(256)]
        for dev_id, name, size in self._devices:
            name_ptr = name if isinstance(name, int) else name_offsets[name]
            dev_info[dev_id] = c_vma.VmaDeviceInfoHeader(devname_ptr=name_ptr, size=size)
        header.dev_info = dev_info

        raw = bytearray(header.dumps())
        raw.extend(blob)
        raw.extend(b"\x00" * (header_size - len(raw)))

        checksum_input = bytearray(raw[:header_size])
        checksum_input[32:48] = b"\x00" * 16
        raw[32:48] = hashlib.md5(bytes(checksum_input)).digest()
        return bytes(raw)

    def _build_extents(self) -> bytes:
        out = io.BytesIO()
        for blocks in self._extents:
            out.write(self._build_extent(blocks))
        return out.getvalue()

    def _build_extent(self, blocks: dict[int, list[tuple[int, int, bytes | None]]]) -> bytes:
        blockinfo = [0] * VMA_BLOCKS_PER_EXTENT
        payload = io.BytesIO()
        entry_count = 0

        for dev_id, entries in sorted(blocks.items()):
            for cluster, mask, data in entries:
                blockinfo[entry_count] = (mask << 48) | (dev_id << 32) | cluster
                entry_count += 1

                # Sparse (mask 0) clusters carry no payload at all; the parser
                # only advances the payload cursor for allocated blocks.
                if mask == 0:
                    continue
                expected = mask.bit_count() * VMA_BLOCK_SIZE
                if data is None:
                    payload.write(b"\x00" * expected)
                else:
                    if len(data) != expected:
                        raise ValueError(f"cluster payload must be {expected} bytes, got {len(data)}")
                    payload.write(data)

        extent_header = c_vma.VmaExtentHeader()
        extent_header.magic = VMA_EXTENT_MAGIC
        extent_header.block_count = max(1, entry_count)
        extent_header.uuid = uuid4().bytes
        extent_header.blockinfo = blockinfo

        raw = bytearray(extent_header.dumps())
        checksum_input = bytearray(raw)
        checksum_input[24:40] = b"\x00" * 16
        raw[24:40] = hashlib.md5(bytes(checksum_input)).digest()
        return bytes(raw) + payload.getvalue()


def cluster_payload(marker: bytes) -> bytes:
    """Return a deterministic fully-allocated cluster filled with ``marker``."""
    if not marker:
        raise ValueError("marker must not be empty")
    repeats = VMA_CLUSTER_SIZE // len(marker) + 1
    return (marker * repeats)[:VMA_CLUSTER_SIZE]
