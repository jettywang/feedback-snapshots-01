from __future__ import annotations

import io

from dissect.archive.vma.c_vma import VMA_CLUSTER_SIZE, VMA_EXTENT_MAGIC
from dissect.archive.vma.vma import VMA
from tests._tools.vma._synth import SynthVMA, cluster_payload


def test_compact_sparse_extents_are_all_found() -> None:
    builder = SynthVMA()
    builder.add_device(1, "drive-scsi0", VMA_CLUSTER_SIZE * 8)
    builder.add_extent({1: [(0, 0xFFFF, cluster_payload(b"A")), (1, 0, None)]})
    builder.add_extent({1: [(2, 0xFFFF, cluster_payload(b"C"))]})

    vma = VMA(io.BytesIO(builder.build()))
    extents = list(vma.extents())

    assert [extent.header.block_count for extent in extents] == [2, 1]
    stream = vma.device(1).open()
    first = stream.read(VMA_CLUSTER_SIZE)
    sparse = stream.read(VMA_CLUSTER_SIZE)
    third = stream.read(VMA_CLUSTER_SIZE)
    assert set(first) == {ord(b"A")}
    assert sparse == b"\x00" * VMA_CLUSTER_SIZE
    assert set(third) == {ord(b"C")}


def test_extent_magic_inside_payload_is_not_a_header() -> None:
    evil_payload = VMA_EXTENT_MAGIC + b"X" * (VMA_CLUSTER_SIZE - len(VMA_EXTENT_MAGIC))
    builder = SynthVMA()
    builder.add_device(1, "drive-scsi0", VMA_CLUSTER_SIZE * 8)
    builder.add_extent({1: [(0, 0xFFFF, evil_payload), (1, 0, None)]})
    builder.add_extent({1: [(2, 0xFFFF, cluster_payload(b"C"))]})

    vma = VMA(io.BytesIO(builder.build()))
    extents = list(vma.extents())

    assert len(extents) == 2
    stream = vma.device(1).open()
    assert stream.read(VMA_CLUSTER_SIZE)[: len(VMA_EXTENT_MAGIC)] == VMA_EXTENT_MAGIC
    stream.seek(2 * VMA_CLUSTER_SIZE)
    assert set(stream.read(VMA_CLUSTER_SIZE)) == {ord(b"C")}
