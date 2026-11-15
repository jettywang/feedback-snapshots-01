from __future__ import annotations

import hashlib
import io
import struct

import pytest

from dissect.archive.vma.c_vma import VMA_EXTENT_MAGIC, VMA_MAGIC, c_vma
from dissect.archive.vma.vma import VMA

BLOCK_SIZE = c_vma.VMA_BLOCK_SIZE
BLOCKS_PER_CLUSTER = c_vma.VMA_CLUSTER_SIZE // BLOCK_SIZE
BLOCKS_PER_EXTENT = c_vma.VMA_BLOCKS_PER_EXTENT
CLUSTER_SIZE = c_vma.VMA_CLUSTER_SIZE
EXTENT_HEADER_SIZE = c_vma.VMA_EXTENT_HEADER_SIZE

HEADER_SIZE = 12288
DEVICE_INFO_OFFSET = 4096
DEVICE_INFO_SIZE = 32
UUID_BYTES = bytes(range(16))

# Hand-written logical layout. Every declared device owns every cluster from 0 up to its last
# cluster, while masks select which of the 16 blocks in that cluster contain payload.
DEVICE_SIZES: dict[int, int] = {
    1: 5 * CLUSTER_SIZE + 0x1234,
    2: 4 * CLUSTER_SIZE + 0x0ABC,
}

DEVICE_MAP: dict[int, dict[int, int]] = {
    1: {
        0: 0x0F0F,
        1: 0xFFFF,
        2: 0x0000,
        3: 0x8001,
        4: 0x00FF,
        5: 0x0F0F,
    },
    2: {
        0: 0xAAAA,
        1: 0x5555,
        2: 0x000F,
        3: 0xFF00,
        4: 0x8001,
    },
}

# Physical order of blockinfo entries inside each extent. Device 2 is placed before device 1 for
# cluster 0, and device 1 before device 2 for cluster 1, so ignoring the device ID changes bytes.
# Device 7 is referenced by both extents but not declared in the header.
EXTENT_LAYOUT: list[list[tuple[int, int, int]]] = [
    [
        (0, 2, 0xAAAA),
        (1, 7, 0xFFFF),
        (1, 1, 0xFFFF),
        (0, 1, 0x0F0F),
        (2, 1, 0x0000),
        (0, 7, 0x0F0F),
        (1, 2, 0x5555),
    ],
    [
        (4, 2, 0x8001),
        (3, 1, 0x8001),
        (2, 7, 0xA5A5),
        (5, 1, 0x0F0F),
        (2, 2, 0x000F),
        (3, 2, 0xFF00),
        (4, 1, 0x00FF),
    ],
]

CHUNK_SIZES = (
    1,
    BLOCK_SIZE - 1,
    BLOCK_SIZE,
    BLOCK_SIZE + 1,
    CLUSTER_SIZE - 1,
    CLUSTER_SIZE,
    CLUSTER_SIZE + 1,
    12345,
)

PARTIAL_READS = (
    (1234, 5000),
    (CLUSTER_SIZE - 100, 200),
    (2 * CLUSTER_SIZE + 5000, 2000),
    (3 * CLUSTER_SIZE + 7 * BLOCK_SIZE + 13, 9000),
)


def _payload(dev_id: int, cluster: int, block: int) -> bytes:
    marker = f"dev={dev_id},cluster={cluster},block={block}|".encode()
    return (marker * (BLOCK_SIZE // len(marker) + 1))[:BLOCK_SIZE]


def _cluster_bytes(dev_id: int, cluster: int, mask: int) -> bytes:
    return b"".join(
        _payload(dev_id, cluster, block) if mask & (1 << block) else b"\x00" * BLOCK_SIZE
        for block in range(BLOCKS_PER_CLUSTER)
    )


def _expected(dev_id: int) -> bytes:
    clusters = b"".join(_cluster_bytes(dev_id, cluster, mask) for cluster, mask in sorted(DEVICE_MAP[dev_id].items()))
    return clusters[: DEVICE_SIZES[dev_id]]


def _expected_with_foreign_clusters(dev_id: int) -> bytes:
    # Simulates a reader that ignores the device ID and takes the first physical entry for a cluster,
    # borrowing both the payload and the sparse bitmap of the other device.
    first_entry: dict[int, tuple[int, int]] = {}
    for entries in EXTENT_LAYOUT:
        for cluster, source_dev, mask in entries:
            if cluster in DEVICE_MAP[dev_id] and cluster not in first_entry:
                first_entry[cluster] = (source_dev, mask)

    clusters = b"".join(
        _cluster_bytes(source_dev, cluster, mask) for cluster, (source_dev, mask) in sorted(first_entry.items())
    )
    return clusters[: DEVICE_SIZES[dev_id]]


def _expected_with_inverted_masks(dev_id: int) -> bytes:
    clusters = b"".join(
        _cluster_bytes(dev_id, cluster, ~mask & 0xFFFF) for cluster, mask in sorted(DEVICE_MAP[dev_id].items())
    )
    return clusters[: DEVICE_SIZES[dev_id]]


def _build_blob(names: list[str]) -> tuple[bytes, dict[str, int]]:
    blob = bytearray(b"\x00")
    offsets: dict[str, int] = {}
    for name in names:
        encoded = name.encode() + b"\x00"
        offsets[name] = len(blob)
        blob += struct.pack("<H", len(encoded)) + encoded
    return bytes(blob), offsets


def _build_vma(
    device_sizes: dict[int, int],
    extents: list[list[tuple[int, int, int]]],
    undeclared_devices: tuple[int, ...] = (),
) -> bytes:
    names = {dev_id: f"dev{dev_id}" for dev_id in [*device_sizes, *undeclared_devices]}
    blob, blob_offsets = _build_blob(list(names.values()))
    header_size = -(-(HEADER_SIZE + len(blob)) // 512) * 512

    header = bytearray(HEADER_SIZE)
    header[0:4] = VMA_MAGIC
    struct.pack_into(">I", header, 4, 1)
    header[8:24] = UUID_BYTES
    struct.pack_into(">q", header, 24, 0)
    struct.pack_into(">I", header, 48, HEADER_SIZE)
    struct.pack_into(">I", header, 52, len(blob))
    struct.pack_into(">I", header, 56, header_size)
    for dev_id, size in device_sizes.items():
        struct.pack_into(
            ">IIQQQ",
            header,
            DEVICE_INFO_OFFSET + dev_id * DEVICE_INFO_SIZE,
            blob_offsets[names[dev_id]],
            0,
            size,
            0,
            0,
        )

    image = bytearray(header + blob)
    image += b"\x00" * (header_size - len(image))
    struct.pack_into(">16s", image, 32, hashlib.md5(image).digest())

    for entries in extents:
        assert len(entries) <= BLOCKS_PER_EXTENT

        blockinfo = [((mask << 48) | (dev_id << 32) | cluster) for cluster, dev_id, mask in entries]
        blockinfo += [0] * (BLOCKS_PER_EXTENT - len(blockinfo))

        data = bytearray()
        for cluster, dev_id, mask in entries:
            for block in range(BLOCKS_PER_CLUSTER):
                if mask & (1 << block):
                    data += _payload(dev_id, cluster, block)

        block_count = len(data) // BLOCK_SIZE
        extent_header = bytearray(
            struct.pack(">4sHH16s16s", VMA_EXTENT_MAGIC, 0, block_count, UUID_BYTES, b"\x00" * 16)
        )
        extent_header += struct.pack(f">{BLOCKS_PER_EXTENT}Q", *blockinfo)
        assert len(extent_header) == EXTENT_HEADER_SIZE
        struct.pack_into(">16s", extent_header, 24, hashlib.md5(extent_header).digest())

        image += extent_header + data

    return bytes(image)


@pytest.fixture(scope="module")
def vma() -> VMA:
    return VMA(io.BytesIO(_build_vma(DEVICE_SIZES, EXTENT_LAYOUT, undeclared_devices=(7,))))


def test_layout_matches_manual_device_map() -> None:
    seen: dict[int, dict[int, int]] = {dev_id: {} for dev_id in DEVICE_SIZES}
    for entries in EXTENT_LAYOUT:
        for cluster, dev_id, mask in entries:
            if dev_id in seen:
                assert cluster not in seen[dev_id]
                seen[dev_id][cluster] = mask

    assert seen == DEVICE_MAP

    for dev_id, size in DEVICE_SIZES.items():
        cluster_count = -(-size // CLUSTER_SIZE)
        assert sorted(DEVICE_MAP[dev_id]) == list(range(cluster_count))
        assert size % CLUSTER_SIZE


def test_extents_mix_devices_and_reference_undeclared(vma: VMA) -> None:
    extents = list(vma.extents())
    assert len(extents) == 2

    for extent in extents:
        assert {1, 2} <= set(extent.blocks)
        assert 7 in extent.blocks

    assert sorted(device.id for device in vma.devices()) == [1, 2]
    with pytest.raises(KeyError, match="7"):
        vma.device(7)


@pytest.mark.parametrize("dev_id", [1, 2])
def test_foreign_device_or_inverted_masks_change_expected(dev_id: int) -> None:
    expected = _expected(dev_id)

    assert _expected_with_foreign_clusters(dev_id) != expected
    assert _expected_with_inverted_masks(dev_id) != expected


@pytest.mark.parametrize("dev_id", [1, 2])
def test_sequential_read_both_devices(vma: VMA, dev_id: int) -> None:
    expected = _expected(dev_id)
    size = DEVICE_SIZES[dev_id]
    stream = vma.device(dev_id).open()

    result = bytearray()
    position = 0
    chunk_index = 0
    while position < size:
        chunk = stream.read(CHUNK_SIZES[chunk_index % len(CHUNK_SIZES)])
        assert chunk
        result += chunk
        position += len(chunk)
        assert stream.tell() == position
        chunk_index += 1

    assert bytes(result) == expected
    assert position == size
    assert stream.tell() == size
    assert stream.read(1) == b""
    assert stream.tell() == size


@pytest.mark.parametrize("dev_id", [1, 2])
@pytest.mark.parametrize(("offset", "length"), PARTIAL_READS)
def test_partial_cluster_ranges(vma: VMA, dev_id: int, offset: int, length: int) -> None:
    expected = _expected(dev_id)
    stream = vma.device(dev_id).open()

    data = stream.readoffset(offset, length)

    assert data == expected[offset : offset + length]
    assert len(data) == length
    assert stream.tell() == offset + length


@pytest.mark.parametrize("dev_id", [1, 2])
def test_tail_short_read(vma: VMA, dev_id: int) -> None:
    expected = _expected(dev_id)
    size = DEVICE_SIZES[dev_id]
    offset = size - 801
    stream = vma.device(dev_id).open()

    data = stream.readoffset(offset, 0x1000)

    assert data == expected[offset:]
    assert len(data) == size - offset
    assert stream.tell() == size
    assert stream.read(1) == b""
    assert stream.tell() == size


@pytest.mark.parametrize("dev_id", [1, 2])
def test_reverse_seek_both_devices(vma: VMA, dev_id: int) -> None:
    expected = _expected(dev_id)
    size = DEVICE_SIZES[dev_id]
    reads = (
        (size - 1, 3),
        (size - 100, 100),
        (4 * CLUSTER_SIZE + 1234, 70000),
        (3 * CLUSTER_SIZE + 17, BLOCK_SIZE),
        (2 * CLUSTER_SIZE + 5000, CLUSTER_SIZE - 1),
        (CLUSTER_SIZE + 1, 20000),
        (17, 1),
        (0, BLOCK_SIZE),
    )
    stream = vma.device(dev_id).open()

    for offset, length in reads:
        stream.seek(offset)
        data = stream.read(length)

        assert data == expected[offset : offset + length]
        assert stream.tell() == offset + len(data)


@pytest.mark.parametrize("dev_id", [1, 2])
def test_cross_extent_read_both_devices(vma: VMA, dev_id: int) -> None:
    expected = _expected(dev_id)
    offset = CLUSTER_SIZE + 1234
    length = DEVICE_SIZES[dev_id] - offset
    stream = vma.device(dev_id).open()

    data = stream.readoffset(offset, length)

    assert data == expected[offset : offset + length]
    assert len(data) == length
    assert stream.tell() == offset + length


def test_interleaved_streams_keep_devices_separate(vma: VMA) -> None:
    expected = {dev_id: _expected(dev_id) for dev_id in DEVICE_SIZES}
    streams = {dev_id: vma.device(dev_id).open() for dev_id in DEVICE_SIZES}
    positions = dict.fromkeys(DEVICE_SIZES, 0)
    chunk_index = dict.fromkeys(DEVICE_SIZES, 0)
    done: set[int] = set()

    while len(done) < len(DEVICE_SIZES):
        for dev_id, stream in streams.items():
            if dev_id in done:
                continue

            chunk = stream.read(CHUNK_SIZES[chunk_index[dev_id] % len(CHUNK_SIZES)])
            chunk_index[dev_id] += 1

            start = positions[dev_id]
            assert chunk
            assert chunk == expected[dev_id][start : start + len(chunk)]

            positions[dev_id] += len(chunk)
            assert stream.tell() == positions[dev_id]

            if positions[dev_id] == DEVICE_SIZES[dev_id]:
                done.add(dev_id)
