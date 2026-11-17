from __future__ import annotations

import io
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
from dissect.util.hash import crc32c

import dissect.btrfs.tree as tree_module
from dissect.btrfs.btrfs import Btrfs
from dissect.btrfs.c_btrfs import c_btrfs
from dissect.btrfs.exceptions import InvalidLeafError
from dissect.btrfs.tree import BTree

if TYPE_CHECKING:
    from collections.abc import Sequence

NODE_SIZE = 1024
SECTOR_SIZE = 4096
IMAGE_SIZE = 0x20000

FSID = b"\x11" * 16
METADATA_UUID = b"\x22" * 16
DEVICE_UUID = b"\x33" * 16

SUPER_OFFSET = 0x10000
CHUNK_LEAF = 0x11000
ROOT_LEAF = 0x12000
FS_NODE = 0x13000
DIR_LEAF = 0x14000
INODE_LEAF = 0x15000
EXTENT_LEAF = 0x16000
FIRST_DATA = 0x17000
SECOND_DATA = 0x18000

HEADER_SIZE = len(c_btrfs.btrfs_header)
ITEM_SIZE = len(c_btrfs.btrfs_item)
KEY_PTR_SIZE = len(c_btrfs.btrfs_key_ptr)

HEADER_NRITEMS = 96
ITEM_KEY = 0
ITEM_KEY_TYPE = 8
ITEM_KEY_OFFSET = 9
ITEM_OFFSET = 17
ITEM_SIZE_OFFSET = 21

ROOT_INODE = 256
FILE_INODE = 257

FILE_NAME = b"f"
FILE_NAME_HASH = (crc32c.update(1, FILE_NAME) ^ 0xFFFFFFFF) & 0xFFFFFFFF
DEFAULT_NAME_HASH = (crc32c.update(1, b"default") ^ 0xFFFFFFFF) & 0xFFFFFFFF

ORIGINAL_IMAGE: bytes


def disk_key(objectid: int, type: int, offset: int) -> c_btrfs.btrfs_disk_key:
    return c_btrfs.btrfs_disk_key(objectid=objectid, type=type, offset=offset)


def header(bytenr: int, owner: int, nritems: int, level: int) -> c_btrfs.btrfs_header:
    return c_btrfs.btrfs_header(
        csum=b"\x00" * 32,
        fsid=FSID,
        bytenr=bytenr,
        flags=0,
        chunk_tree_uuid=b"\x00" * 16,
        generation=1,
        owner=owner,
        nritems=nritems,
        level=level,
    )


def inode_item(size: int, mode: int) -> bytes:
    return bytes(
        c_btrfs.btrfs_inode_item(
            generation=1,
            transid=1,
            size=size,
            nbytes=size,
            block_group=0,
            nlink=1,
            uid=0,
            gid=0,
            mode=mode,
            rdev=0,
            flags=0,
            sequence=0,
            reserved=[0] * 4,
        )
    )


def dir_item(objectid: int, type: int, file_type: int, name: bytes) -> bytes:
    item = c_btrfs.btrfs_dir_item(
        location=disk_key(objectid, type, 0),
        transid=1,
        data_len=0,
        name_len=len(name),
        type=file_type,
    )
    item.name = name
    return bytes(item)


def extent_item(disk_bytenr: int, num_bytes: int) -> bytes:
    return bytes(
        c_btrfs.btrfs_file_extent_item_reg(
            generation=1,
            ram_bytes=num_bytes,
            compression=0,
            encryption=0,
            other_encoding=0,
            type=c_btrfs.BTRFS_FILE_EXTENT_REG,
            disk_bytenr=disk_bytenr,
            disk_num_bytes=SECTOR_SIZE,
            offset=0,
            num_bytes=num_bytes,
        )
    )


def leaf(
    bytenr: int, owner: int, items: list[tuple[c_btrfs.btrfs_disk_key, bytes]], node_size: int = NODE_SIZE
) -> bytes:
    """Build a leaf with the item table growing forward and item data growing backwards."""
    node = bytearray(node_size)
    node[:HEADER_SIZE] = bytes(header(bytenr, owner, len(items), 0))

    cursor = node_size
    entries = []
    for key, data in items:
        cursor -= len(data)
        node[cursor : cursor + len(data)] = data
        entries.append((key, cursor - HEADER_SIZE, len(data)))

    for index, (key, offset, size) in enumerate(entries):
        item = c_btrfs.btrfs_item(key=key, offset=offset, size=size)
        node[HEADER_SIZE + index * ITEM_SIZE : HEADER_SIZE + (index + 1) * ITEM_SIZE] = bytes(item)

    return bytes(node)


def branch(bytenr: int, owner: int, pointers: list[tuple[c_btrfs.btrfs_disk_key, int]]) -> bytes:
    node = bytearray(NODE_SIZE)
    node[:HEADER_SIZE] = bytes(header(bytenr, owner, len(pointers), 1))

    for index, (key, blockptr) in enumerate(pointers):
        ptr = c_btrfs.btrfs_key_ptr(key=key, blockptr=blockptr, generation=1)
        node[HEADER_SIZE + index * KEY_PTR_SIZE : HEADER_SIZE + (index + 1) * KEY_PTR_SIZE] = bytes(ptr)

    return bytes(node)


def build_image() -> bytes:
    chunk = c_btrfs.btrfs_chunk(
        length=IMAGE_SIZE,
        owner=c_btrfs.BTRFS_CHUNK_TREE_OBJECTID,
        stripe_len=0x10000,
        type=c_btrfs.BTRFS_BLOCK_GROUP.SYSTEM,
        io_align=SECTOR_SIZE,
        io_width=SECTOR_SIZE,
        sector_size=SECTOR_SIZE,
        num_stripes=1,
        sub_stripes=0,
    )
    chunk.stripe = [c_btrfs.btrfs_stripe(devid=1, offset=0, dev_uuid=DEVICE_UUID)]
    chunk_bytes = bytes(chunk)

    sys_chunk_array = bytes(disk_key(0, c_btrfs.BTRFS_CHUNK_ITEM_KEY, 0)) + chunk_bytes
    superblock = c_btrfs.btrfs_super_block(
        csum=b"\x00" * 32,
        fsid=FSID,
        bytenr=SUPER_OFFSET,
        flags=0,
        magic=c_btrfs.BTRFS_MAGIC,
        generation=1,
        root=ROOT_LEAF,
        chunk_root=CHUNK_LEAF,
        root_level=1,
        chunk_root_level=0,
        sectorsize=SECTOR_SIZE,
        nodesize=NODE_SIZE,
        stripesize=SECTOR_SIZE,
        sys_chunk_array_size=len(sys_chunk_array),
        label=b"leaf-layout",
        metadata_uuid=METADATA_UUID,
    )
    superblock.sys_chunk_array = sys_chunk_array + b"\x00" * (2048 - len(sys_chunk_array))
    superblock.dev_item.devid = 1
    superblock.dev_item.total_bytes = IMAGE_SIZE
    superblock.dev_item.bytes_used = IMAGE_SIZE
    superblock.dev_item.io_align = SECTOR_SIZE
    superblock.dev_item.io_width = SECTOR_SIZE
    superblock.dev_item.sector_size = SECTOR_SIZE
    superblock.dev_item.uuid = DEVICE_UUID
    superblock.dev_item.fsid = FSID

    root_item = c_btrfs.btrfs_root_item(generation=1, root_dirid=ROOT_INODE, bytenr=FS_NODE, refs=1, level=1)
    root_item.inode = c_btrfs.btrfs_inode_item(
        generation=1,
        transid=1,
        size=0,
        nbytes=0,
        block_group=0,
        nlink=1,
        uid=0,
        gid=0,
        mode=0o40755,
        rdev=0,
        flags=0,
        sequence=0,
        reserved=[0] * 4,
    )

    root_leaf = leaf(
        ROOT_LEAF,
        c_btrfs.BTRFS_ROOT_TREE_OBJECTID,
        [
            (disk_key(c_btrfs.BTRFS_FS_TREE_OBJECTID, c_btrfs.BTRFS_ROOT_ITEM_KEY, 0), bytes(root_item)),
            (
                disk_key(c_btrfs.BTRFS_ROOT_TREE_DIR_OBJECTID, c_btrfs.BTRFS_DIR_ITEM_KEY, DEFAULT_NAME_HASH),
                dir_item(c_btrfs.BTRFS_FS_TREE_OBJECTID, c_btrfs.BTRFS_ROOT_ITEM_KEY, 2, b"default"),
            ),
        ],
    )
    chunk_leaf = leaf(
        CHUNK_LEAF,
        c_btrfs.BTRFS_CHUNK_TREE_OBJECTID,
        [(disk_key(256, c_btrfs.BTRFS_CHUNK_ITEM_KEY, 0), chunk_bytes)],
    )
    fs_node = branch(
        FS_NODE,
        c_btrfs.BTRFS_FS_TREE_OBJECTID,
        [
            (disk_key(ROOT_INODE, c_btrfs.BTRFS_INODE_ITEM_KEY, 0), DIR_LEAF),
            (disk_key(FILE_INODE, c_btrfs.BTRFS_INODE_ITEM_KEY, 0), INODE_LEAF),
            (disk_key(FILE_INODE, c_btrfs.BTRFS_EXTENT_DATA_KEY, 0), EXTENT_LEAF),
        ],
    )

    dir_leaf = leaf(
        DIR_LEAF,
        c_btrfs.BTRFS_FS_TREE_OBJECTID,
        [
            (disk_key(ROOT_INODE, c_btrfs.BTRFS_INODE_ITEM_KEY, 0), inode_item(0, 0o40755)),
            (
                disk_key(ROOT_INODE, c_btrfs.BTRFS_DIR_ITEM_KEY, FILE_NAME_HASH),
                dir_item(FILE_INODE, c_btrfs.BTRFS_INODE_ITEM_KEY, 1, FILE_NAME),
            ),
            (
                disk_key(ROOT_INODE, c_btrfs.BTRFS_DIR_INDEX_KEY, 2),
                dir_item(FILE_INODE, c_btrfs.BTRFS_INODE_ITEM_KEY, 1, FILE_NAME),
            ),
        ],
    )
    inode_leaf = leaf(
        INODE_LEAF,
        c_btrfs.BTRFS_FS_TREE_OBJECTID,
        [(disk_key(FILE_INODE, c_btrfs.BTRFS_INODE_ITEM_KEY, 0), inode_item(24, 0o100644))],
    )
    extent_leaf = leaf(
        EXTENT_LEAF,
        c_btrfs.BTRFS_FS_TREE_OBJECTID,
        [
            (disk_key(FILE_INODE, c_btrfs.BTRFS_EXTENT_DATA_KEY, 0), extent_item(FIRST_DATA, 12)),
            (disk_key(FILE_INODE, c_btrfs.BTRFS_EXTENT_DATA_KEY, 12), extent_item(SECOND_DATA, 12)),
        ],
    )

    image = bytearray(IMAGE_SIZE)
    for offset, data in [
        (SUPER_OFFSET, bytes(superblock)),
        (CHUNK_LEAF, chunk_leaf),
        (ROOT_LEAF, root_leaf),
        (FS_NODE, fs_node),
        (DIR_LEAF, dir_leaf),
        (INODE_LEAF, inode_leaf),
        (EXTENT_LEAF, extent_leaf),
    ]:
        image[offset : offset + len(data)] = data

    image[FIRST_DATA : FIRST_DATA + 12] = b"hello world\n"
    image[SECOND_DATA : SECOND_DATA + 12] = b"second block"

    return bytes(image)


ORIGINAL_IMAGE = build_image()


def open_fs(image: bytes = ORIGINAL_IMAGE) -> Btrfs:
    return Btrfs(io.BytesIO(image))


def patch_item(
    image: bytes,
    leaf_offset: int,
    index: int,
    *,
    nritems: int | None = None,
    key: tuple[int, int, int] | None = None,
    offset: int | None = None,
    size: int | None = None,
) -> bytes:
    """Patch one item header (and optionally ``nritems``) in a copy of the image."""
    result = bytearray(image)
    if nritems is not None:
        result[leaf_offset + HEADER_NRITEMS : leaf_offset + HEADER_NRITEMS + 4] = nritems.to_bytes(4, "little")

    item_offset = leaf_offset + HEADER_SIZE + index * ITEM_SIZE
    if key is not None:
        objectid, type, key_offset = key
        result[item_offset + ITEM_KEY : item_offset + ITEM_KEY + 8] = objectid.to_bytes(8, "little")
        result[item_offset + ITEM_KEY_TYPE] = type
        result[item_offset + ITEM_KEY_OFFSET : item_offset + ITEM_KEY_OFFSET + 8] = key_offset.to_bytes(8, "little")
    if offset is not None:
        result[item_offset + ITEM_OFFSET : item_offset + ITEM_OFFSET + 4] = offset.to_bytes(4, "little")
    if size is not None:
        result[item_offset + ITEM_SIZE_OFFSET : item_offset + ITEM_SIZE_OFFSET + 4] = size.to_bytes(4, "little")

    return bytes(result)


def read_items(node: bytes | memoryview, nritems: int) -> list[c_btrfs.btrfs_item]:
    return [
        c_btrfs.btrfs_item(bytes(node[HEADER_SIZE + index * ITEM_SIZE : HEADER_SIZE + (index + 1) * ITEM_SIZE]))
        for index in range(nritems)
    ]


def read_leaf(node: bytes | memoryview) -> tuple[memoryview, c_btrfs.btrfs_header]:
    """Parse a leaf as raw bytes, without going through the validating B-tree reader."""
    node = memoryview(node)
    return node, c_btrfs.btrfs_header(node)


def image_leaf(image: bytes, leaf_offset: int) -> tuple[memoryview, c_btrfs.btrfs_header]:
    return read_leaf(image[leaf_offset : leaf_offset + NODE_SIZE])


def ranges(node: bytes | memoryview, nritems: int) -> list[tuple[int, int]]:
    """Return the absolute ``(start, size)`` data ranges described by a leaf's item table."""
    return [(HEADER_SIZE + item.offset, item.size) for item in read_items(node, nritems)]


@dataclass(frozen=True)
class Interval:
    start: int
    end: int

    def overlaps(self, other: Interval) -> bool:
        return self.start < other.end and other.start < self.end


@dataclass(frozen=True)
class LeafModel:
    table: Interval
    data: list[Interval]
    overlapping: list[tuple[int, int]]


def model(nritems: int, ranges: Sequence[tuple[int, int]]) -> LeafModel:
    """Independent byte range model for a leaf layout.

    Each range is ``(start, size)``. Ranges that are exactly equal are duplicate references, not overlaps. An empty
    range references no bytes and can therefore never overlap anything.
    """
    table = Interval(HEADER_SIZE, HEADER_SIZE + nritems * ITEM_SIZE)
    data = [Interval(start, start + size) for start, size in ranges]

    overlapping = []
    for i, first in enumerate(data):
        for j in range(i + 1, len(data)):
            second = data[j]
            if first.overlaps(second) and first != second:
                overlapping.append((i, j))

    return LeafModel(table, data, overlapping)


def assert_model_valid(image: bytes, leaf_offset: int) -> LeafModel:
    """Assert that the on-disk leaf agrees with the independent model and has no overlaps."""
    node, leaf_header = image_leaf(image, leaf_offset)
    layout = model(leaf_header.nritems, ranges(node, leaf_header.nritems))

    for interval in layout.data:
        if interval.start != interval.end:
            assert interval.start >= layout.table.end
        assert interval.end <= NODE_SIZE
    assert not layout.overlapping

    return layout


def test_leaf_layout_baseline_is_reachable() -> None:
    fs = open_fs()

    assert fs.label == "leaf-layout"
    assert list(fs.get("/").listdir()) == [".", "..", "f"]
    assert fs.get("f").size == 24
    assert fs.get("f").open().read() == b"hello world\nsecond block"

    for leaf_offset in (DIR_LEAF, INODE_LEAF, EXTENT_LEAF):
        assert_model_valid(ORIGINAL_IMAGE, leaf_offset)

    # The target keys are reachable through a directory lookup and an extent lookup respectively.
    item, data = fs.fs_tree.tree.find(ROOT_INODE, c_btrfs.BTRFS_DIR_ITEM_KEY, FILE_NAME_HASH)
    node, _ = image_leaf(ORIGINAL_IMAGE, DIR_LEAF)
    dir_layout = assert_model_valid(ORIGINAL_IMAGE, DIR_LEAF)
    assert data.tobytes() == bytes(node[dir_layout.data[1].start : dir_layout.data[1].end])

    item, data = fs.fs_tree.tree.find(FILE_INODE, c_btrfs.BTRFS_EXTENT_DATA_KEY, 12)
    node, _ = image_leaf(ORIGINAL_IMAGE, EXTENT_LEAF)
    extent_layout = assert_model_valid(ORIGINAL_IMAGE, EXTENT_LEAF)
    assert data.tobytes() == bytes(node[extent_layout.data[1].start : extent_layout.data[1].end])
    assert item.key.offset == 12


def test_leaf_layout_rejects_item_table_overrun_from_directory_lookup() -> None:
    # nritems claims one extra item with a valid increasing key, but its data would start in the table.
    image = patch_item(
        ORIGINAL_IMAGE,
        DIR_LEAF,
        3,
        nritems=4,
        key=(ROOT_INODE, c_btrfs.BTRFS_DIR_INDEX_KEY, 3),
        offset=0,
        size=8,
    )
    layout = model(4, ranges(image_leaf(image, DIR_LEAF)[0], 4))
    assert layout.table.end == 201
    assert layout.data[3].start == HEADER_SIZE
    assert layout.data[3].start < layout.table.end
    assert not layout.overlapping

    fs = open_fs(image)
    with pytest.raises(InvalidLeafError, match="Item 3 data starts in the item table"):
        fs.get("f")


def test_leaf_layout_rejects_table_overrun_by_itself() -> None:
    # nritems itself is so large that the item table cannot fit inside the node.
    image = patch_item(ORIGINAL_IMAGE, DIR_LEAF, 0, nritems=NODE_SIZE)
    assert HEADER_SIZE + NODE_SIZE * ITEM_SIZE > NODE_SIZE

    with pytest.raises(InvalidLeafError, match="exceeds node size"):
        open_fs(image).get("f")


def test_leaf_layout_rejects_zero_length_key_shift() -> None:
    # Resize the directory item to zero and move its offset past the end: the end bound still applies.
    image = patch_item(ORIGINAL_IMAGE, EXTENT_LEAF, 0, offset=NODE_SIZE - HEADER_SIZE + 1, size=0)

    with pytest.raises(InvalidLeafError, match="Item 0 data extends past the node"):
        open_fs(image).get("f").open().read()


def test_leaf_layout_allows_empty_item_in_table() -> None:
    # Empty items may sit anywhere, including in the item table area; they reference no data bytes.
    # The extra item is a fourth directory index entry with a zero-length payload.
    image = patch_item(
        ORIGINAL_IMAGE,
        DIR_LEAF,
        3,
        nritems=4,
        key=(ROOT_INODE, c_btrfs.BTRFS_DIR_INDEX_KEY, 3),
        offset=0,
        size=0,
    )
    layout = model(4, ranges(image_leaf(image, DIR_LEAF)[0], 4))
    assert layout.data[3] == Interval(HEADER_SIZE, HEADER_SIZE)
    assert layout.table.end == 201

    fs = open_fs(image)
    assert fs.get("f").size == 24
    assert fs.get("f").open().read() == b"hello world\nsecond block"

    cursor = fs.fs_tree.tree.cursor()
    assert cursor.search(ROOT_INODE, c_btrfs.BTRFS_DIR_INDEX_KEY, 3)
    item, data = cursor.get()
    assert item.size == 0
    assert data == b""


def test_leaf_layout_rejects_data_into_item_table_from_directory_lookup() -> None:
    node, leaf_header = image_leaf(ORIGINAL_IMAGE, DIR_LEAF)
    directory_item = read_items(node, leaf_header.nritems)[1]
    image = patch_item(ORIGINAL_IMAGE, DIR_LEAF, 1, offset=ITEM_SIZE, size=directory_item.size)

    layout = model(3, ranges(image_leaf(image, DIR_LEAF)[0], 3))
    assert layout.data[1].start == HEADER_SIZE + ITEM_SIZE
    assert layout.data[1].start < layout.table.end
    assert not layout.overlapping

    # Construction only walks the root and chunk trees; the mutated filesystem leaf is read by the directory query.
    fs = open_fs(image)
    with pytest.raises(InvalidLeafError, match="Item 1 data starts in the item table"):
        fs.get("f")


def test_leaf_layout_rejects_data_past_node_from_extent_lookup() -> None:
    image = patch_item(ORIGINAL_IMAGE, EXTENT_LEAF, 0, size=NODE_SIZE)

    layout = model(2, ranges(image_leaf(image, EXTENT_LEAF)[0], 2))
    assert layout.data[0].end > NODE_SIZE

    fs = open_fs(image)
    with pytest.raises(InvalidLeafError, match="Item 0 data extends past the node"):
        fs.get("f").open().read()


def test_leaf_layout_rejects_real_overlap_from_extent_lookup() -> None:
    layout = assert_model_valid(ORIGINAL_IMAGE, EXTENT_LEAF)
    first, second = layout.data
    # Shift the second extent so it partially covers the first one.
    image = patch_item(
        ORIGINAL_IMAGE,
        EXTENT_LEAF,
        1,
        offset=first.start - HEADER_SIZE - 1,
        size=second.end - second.start,
    )

    patched = model(2, ranges(image_leaf(image, EXTENT_LEAF)[0], 2))
    assert patched.overlapping == [(0, 1)]

    fs = open_fs(image)
    with pytest.raises(InvalidLeafError, match="data overlaps item"):
        fs.get("f").open().read()


def test_leaf_layout_allows_duplicate_data_reference() -> None:
    node, _ = image_leaf(ORIGINAL_IMAGE, DIR_LEAF)
    layout = assert_model_valid(ORIGINAL_IMAGE, DIR_LEAF)
    directory_item = bytes(node[layout.data[1].start : layout.data[1].end])
    exact_offset = layout.data[1].start - HEADER_SIZE

    # Point the directory index item at the exact same bytes as the directory item: a duplicate reference.
    image = patch_item(ORIGINAL_IMAGE, DIR_LEAF, 2, offset=exact_offset, size=len(directory_item))
    layout = assert_model_valid(image, DIR_LEAF)
    assert layout.data[1] == layout.data[2]

    fs = open_fs(image)
    assert list(fs.get("/").listdir()) == [".", "..", "f"]
    _, data = fs.fs_tree.tree.find(ROOT_INODE, c_btrfs.BTRFS_DIR_INDEX_KEY, 2)
    assert data.tobytes() == bytes(memoryview(image)[DIR_LEAF + layout.data[2].start : DIR_LEAF + layout.data[2].end])
    assert data.tobytes() == directory_item

    # A partial overlap of the same data is still rejected.
    overlapping = patch_item(ORIGINAL_IMAGE, DIR_LEAF, 2, offset=exact_offset + 1, size=len(directory_item))
    assert (1, 2) in model(
        3,
        ranges(image_leaf(overlapping, DIR_LEAF)[0], 3),
    ).overlapping

    with pytest.raises(InvalidLeafError, match="data overlaps item"):
        open_fs(overlapping).get("f")


def test_leaf_layout_allows_hash_collision_keys() -> None:
    # Directory item hashes can collide; equal adjacent keys are legal and only a decreasing key is rejected.
    node, leaf_header = image_leaf(ORIGINAL_IMAGE, DIR_LEAF)
    directory_item = read_items(node, leaf_header.nritems)[1]
    image = patch_item(
        ORIGINAL_IMAGE,
        DIR_LEAF,
        2,
        key=(ROOT_INODE, c_btrfs.BTRFS_DIR_ITEM_KEY, FILE_NAME_HASH),
        offset=read_items(node, leaf_header.nritems)[2].offset,
        size=directory_item.size,
    )
    layout = model(3, ranges(image_leaf(image, DIR_LEAF)[0], 3))
    assert not layout.overlapping

    fs = open_fs(image)
    assert fs.get("f").size == 24
    assert fs.fs_tree.tree.find(ROOT_INODE, c_btrfs.BTRFS_DIR_ITEM_KEY, FILE_NAME_HASH)[1].tobytes() == bytes(
        memoryview(image)[DIR_LEAF + layout.data[1].start : DIR_LEAF + layout.data[1].end]
    )


def test_leaf_layout_rejects_unsorted_key_range() -> None:
    # Keep both data ranges legal but move the second key before the first one.
    image = patch_item(ORIGINAL_IMAGE, EXTENT_LEAF, 1, key=(ROOT_INODE, c_btrfs.BTRFS_EXTENT_DATA_KEY, 0))
    assert not model(
        2,
        ranges(image_leaf(image, EXTENT_LEAF)[0], 2),
    ).overlapping

    fs = open_fs(image)
    with pytest.raises(InvalidLeafError, match="Leaf keys are not ordered"):
        fs.get("f").open().read()


def test_leaf_layout_rejects_linked_header_data_shift() -> None:
    # A directory item that is moved to overlap the inode item data invalidates the whole leaf.
    layout = assert_model_valid(ORIGINAL_IMAGE, DIR_LEAF)
    inode_range = layout.data[0]
    directory_range = layout.data[1]
    image = patch_item(
        ORIGINAL_IMAGE,
        DIR_LEAF,
        1,
        offset=inode_range.start - HEADER_SIZE + 8,
        size=directory_range.end - directory_range.start,
    )

    patched = model(3, ranges(image_leaf(image, DIR_LEAF)[0], 3))
    assert (0, 1) in patched.overlapping

    with pytest.raises(InvalidLeafError, match="data overlaps item"):
        open_fs(image).get("f")


def test_leaf_layout_minimal_counterexample_via_extent_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reach the same header-redirect through the real extent lookup path.

    Only the data area constraint is removed. The item table bound and key ordering remain enforced, so the leaf is
    accepted and the extent lookup returns the header of item 0 as the data of item 1.
    """
    image = patch_item(ORIGINAL_IMAGE, EXTENT_LEAF, 1, offset=0, size=ITEM_SIZE)

    node, leaf_header = image_leaf(image, EXTENT_LEAF)
    item_header = bytes(node[HEADER_SIZE : HEADER_SIZE + ITEM_SIZE])
    assert item_header == bytes(read_items(node, leaf_header.nritems)[0])
    assert model(2, ranges(node, 2)).data[1] == Interval(HEADER_SIZE, HEADER_SIZE + ITEM_SIZE)

    with pytest.raises(InvalidLeafError, match="Item 1 data starts in the item table"):
        open_fs(image).get("f").open().read()

    def table_only(node: memoryview, header: c_btrfs.btrfs_header) -> None:
        if HEADER_SIZE + header.nritems * ITEM_SIZE > len(node):
            raise InvalidLeafError("item table exceeds node")

    monkeypatch.setattr(tree_module, "_validate_leaf", table_only)

    fs = open_fs(image)
    cursor = fs.fs_tree.tree.cursor()
    assert cursor.search(FILE_INODE, c_btrfs.BTRFS_EXTENT_DATA_KEY, 12)
    _, data = cursor.get()
    assert data.tobytes() == item_header
    # The returned bytes are the full header of item 0, not the extent data the key describes.
    returned = c_btrfs.btrfs_item(data.tobytes())
    returned_key = (returned.key.objectid, returned.key.type, returned.key.offset)
    assert returned_key == (FILE_INODE, c_btrfs.BTRFS_EXTENT_DATA_KEY, 0)
    assert (returned.offset, returned.size) == (870, 53)
    assert data.tobytes() != extent_item(SECOND_DATA, 12)


def test_leaf_layout_minimal_counterexample() -> None:
    """A 256 byte leaf where removing only the data area constraint reads another item header.

    Item 1 is a valid second key whose ``offset``/``size`` describe the 25-byte header of item 0. Without the
    "data must not start in the item table" rule, the extent-style ``Cursor`` search returns that header as item
    data instead of the bytes the key describes.
    """
    node = bytearray(256)
    node[:HEADER_SIZE] = bytes(header(0x1000, c_btrfs.BTRFS_FS_TREE_OBJECTID, 2, 0))

    node[HEADER_SIZE : HEADER_SIZE + ITEM_SIZE] = bytes(
        c_btrfs.btrfs_item(key=disk_key(FILE_INODE, c_btrfs.BTRFS_EXTENT_DATA_KEY, 0), offset=248 - HEADER_SIZE, size=8)
    )
    node[HEADER_SIZE + ITEM_SIZE : HEADER_SIZE + 2 * ITEM_SIZE] = bytes(
        c_btrfs.btrfs_item(key=disk_key(FILE_INODE, c_btrfs.BTRFS_EXTENT_DATA_KEY, 1), offset=0, size=ITEM_SIZE)
    )
    node[248:256] = b"ABCDEFGH"
    node_view = memoryview(node)

    item_header = bytes(node[HEADER_SIZE : HEADER_SIZE + ITEM_SIZE])
    items = read_items(node_view, 2)
    layout = model(2, [(HEADER_SIZE + item.offset, item.size) for item in items])

    assert layout.table == Interval(101, 151)
    assert layout.data[1] == Interval(101, 126)
    assert layout.data[1].start < layout.table.end
    assert not layout.overlapping

    # The raw, unguarded Cursor.data() slice: item 1 points at item 0's header.
    unguarded = bytes(node_view[HEADER_SIZE + items[1].offset : HEADER_SIZE + items[1].offset + items[1].size])
    assert unguarded == item_header
    assert c_btrfs.btrfs_disk_key(unguarded).objectid == FILE_INODE

    # The guarded reader rejects the same leaf as soon as a query descends into it.
    class Source:
        def _read_node(self, address: int) -> bytes:
            return bytes(node_view)

    with pytest.raises(InvalidLeafError, match="Item 1 data starts in the item table"):
        BTree(Source(), root_offset=1).cursor()
