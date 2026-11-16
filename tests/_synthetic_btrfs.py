"""Minimal, single-device Btrfs image builder used to synthesize orphan scenarios.

The on-disk images produced here are intentionally tiny (a single identity-mapped chunk and two leaf
nodes) but use the real on-disk structures parsed by :mod:`dissect.btrfs`. They let the forensic tests
construct states that are hard to capture on a live, consistent filesystem: interrupted orphan cleanup and
damaged reference material.
"""

from __future__ import annotations

from dissect.btrfs.c_btrfs import c_btrfs

NODE_SIZE = 4096
SECTOR_SIZE = 4096

FSID = b"\x33" * 16
DEV_UUID = b"\x22" * 16
ROOT_UUID = b"\x44" * 16

ROOT_TREE_ADDR = 0x20000
FS_TREE_ADDR = 0x30000
SUBVOL_TREE_ADDR = 0x38000
DATA_ADDR = 0x40000
IMG_SIZE = 512 * 1024

CHUNK_LENGTH = 256 * 1024 * 1024

ORPHAN_OBJECTID = c_btrfs.BTRFS_ORPHAN_OBJECTID & 0xFFFFFFFFFFFFFFFF


def disk_key(objectid: int, type_: int, offset: int) -> c_btrfs.btrfs_disk_key:
    return c_btrfs.btrfs_disk_key(objectid=objectid & 0xFFFFFFFFFFFFFFFF, type=type_, offset=offset)


def inode_item(nlink: int, mode: int, size: int, generation: int) -> bytes:
    return c_btrfs.btrfs_inode_item(nlink=nlink, mode=mode, size=size, generation=generation).dumps()


def reg_extent(generation: int, disk_bytenr: int, disk_num_bytes: int, num_bytes: int) -> bytes:
    item = c_btrfs.btrfs_file_extent_item_reg(
        generation=generation,
        ram_bytes=num_bytes,
        compression=c_btrfs.BTRFS_COMPRESS_NONE,
        encryption=0,
        other_encoding=0,
        type=c_btrfs.BTRFS_FILE_EXTENT_REG,
        disk_bytenr=disk_bytenr,
        disk_num_bytes=disk_num_bytes,
        offset=0,
        num_bytes=num_bytes,
    )
    return item.dumps()


def inode_ref(index: int, name: bytes) -> bytes:
    return c_btrfs.btrfs_inode_ref(index=index, name_len=len(name), name=name).dumps()


def inode_extref(parent_objectid: int, index: int, name: bytes) -> bytes:
    item = c_btrfs.btrfs_inode_extref(parent_objectid=parent_objectid, index=index, name_len=len(name), name=name)
    return item.dumps()


def orphan_marker(inum: int) -> tuple[int, int, int, bytes]:
    return (ORPHAN_OBJECTID, c_btrfs.BTRFS_ORPHAN_ITEM_KEY, inum, b"")


def make_leaf(owner: int, bytenr: int, entries: list[tuple[int, int, int, bytes]]) -> bytes:
    """Build a single leaf node from ``(objectid, type, offset, payload)`` tuples."""
    entries = sorted(entries, key=lambda entry: (entry[0], entry[1], entry[2]))
    header_len = len(c_btrfs.btrfs_header)
    total_data = sum(len(payload) for _, _, _, payload in entries)

    data_base = NODE_SIZE - total_data
    data_starts = []
    cursor = data_base
    for _, _, _, payload in entries:
        data_starts.append(cursor)
        cursor += len(payload)

    item_bufs = []
    for (objectid, type_, offset, payload), data_start in zip(entries, data_starts):
        item = c_btrfs.btrfs_item(
            key=disk_key(objectid, type_, offset), offset=data_start - header_len, size=len(payload)
        )
        item_bufs.append(item.dumps())

    header = c_btrfs.btrfs_header(
        csum=b"\x00" * 32,
        fsid=FSID,
        bytenr=bytenr,
        flags=0,
        chunk_tree_uuid=b"\x00" * 16,
        generation=1,
        owner=owner,
        nritems=len(entries),
        level=0,
    )

    buf = bytearray(NODE_SIZE)
    buf[0:header_len] = header.dumps()
    item_cursor = header_len
    for item_buf in item_bufs:
        buf[item_cursor : item_cursor + len(item_buf)] = item_buf
        item_cursor += len(item_buf)
    for (_, _, _, payload), data_start in zip(entries, data_starts):
        buf[data_start : data_start + len(payload)] = payload
    return bytes(buf)


def _chunk_array() -> bytes:
    stripe = c_btrfs.btrfs_stripe(devid=1, offset=0, dev_uuid=DEV_UUID)
    chunk = c_btrfs.btrfs_chunk(
        length=CHUNK_LENGTH,
        owner=c_btrfs.BTRFS_EXTENT_TREE_OBJECTID,
        stripe_len=CHUNK_LENGTH,
        type=c_btrfs.BTRFS_BLOCK_GROUP(0),
        io_align=SECTOR_SIZE,
        io_width=SECTOR_SIZE,
        sector_size=SECTOR_SIZE,
        num_stripes=1,
        sub_stripes=1,
        stripe=[stripe],
    )
    return disk_key(0, c_btrfs.BTRFS_CHUNK_ITEM_KEY, 0).dumps() + chunk.dumps()


def _root_item() -> c_btrfs.btrfs_root_item:
    root_item = c_btrfs.btrfs_root_item()
    root_item.inode.nlink = 1
    root_item.inode.mode = 0o40755
    root_item.generation = 1
    root_item.root_dirid = c_btrfs.BTRFS_FIRST_FREE_OBJECTID
    root_item.bytenr = FS_TREE_ADDR
    root_item.level = 0
    root_item.refs = 1
    root_item.uuid = ROOT_UUID
    return root_item


def _default_dir_item() -> bytes:
    dir_item = c_btrfs.btrfs_dir_item(
        location=disk_key(c_btrfs.BTRFS_FS_TREE_OBJECTID, c_btrfs.BTRFS_ROOT_ITEM_KEY, 0),
        transid=1,
        data_len=0,
        name_len=len(b"default"),
        type=c_btrfs.BTRFS_FT_DIR,
        name=b"default",
    )
    return dir_item.dumps()


def _root_leaf() -> bytes:
    return make_leaf(
        c_btrfs.BTRFS_ROOT_TREE_OBJECTID,
        ROOT_TREE_ADDR,
        [
            (c_btrfs.BTRFS_FS_TREE_OBJECTID, c_btrfs.BTRFS_ROOT_ITEM_KEY, 0, _root_item().dumps()),
            (c_btrfs.BTRFS_ROOT_TREE_DIR_OBJECTID, c_btrfs.BTRFS_DIR_ITEM_KEY, 0, _default_dir_item()),
        ],
    )


def _superblock() -> c_btrfs.btrfs_super_block:
    sys_array = _chunk_array()
    sb = c_btrfs.btrfs_super_block()
    sb.csum = b"\x00" * 32
    sb.fsid = FSID
    sb.bytenr = c_btrfs.BTRFS_SUPER_INFO_OFFSET
    sb.magic = c_btrfs.BTRFS_MAGIC
    sb.generation = 1
    sb.root = ROOT_TREE_ADDR
    sb.chunk_root = ROOT_TREE_ADDR
    sb.total_bytes = IMG_SIZE
    sb.root_dir_objectid = c_btrfs.BTRFS_ROOT_TREE_DIR_OBJECTID
    sb.num_devices = 1
    sb.sectorsize = SECTOR_SIZE
    sb.nodesize = NODE_SIZE
    sb.stripesize = SECTOR_SIZE
    sb.sys_chunk_array_size = len(sys_array)
    array_buf = bytearray(c_btrfs.BTRFS_SYSTEM_CHUNK_ARRAY_SIZE)
    array_buf[: len(sys_array)] = sys_array
    sb.sys_chunk_array = bytes(array_buf)
    sb.dev_item.devid = 1
    sb.dev_item.total_bytes = IMG_SIZE
    sb.dev_item.io_align = SECTOR_SIZE
    sb.dev_item.io_width = SECTOR_SIZE
    sb.dev_item.sector_size = SECTOR_SIZE
    sb.dev_item.uuid = DEV_UUID
    sb.dev_item.fsid = FSID
    sb.label = b"orphan-test"
    sb.metadata_uuid = FSID
    return sb


def build_orphan_image(fs_entries: list[tuple[int, int, int, bytes]], data: bytes | None = None) -> bytes:
    """Assemble a complete image containing one FS_TREE subvolume with the given leaf entries."""
    img = bytearray(IMG_SIZE)

    sb = _superblock()
    sb_offset = c_btrfs.BTRFS_SUPER_INFO_OFFSET
    img[sb_offset : sb_offset + len(sb)] = sb.dumps()

    img[ROOT_TREE_ADDR : ROOT_TREE_ADDR + NODE_SIZE] = _root_leaf()
    img[FS_TREE_ADDR : FS_TREE_ADDR + NODE_SIZE] = make_leaf(c_btrfs.BTRFS_FS_TREE_OBJECTID, FS_TREE_ADDR, fs_entries)
    if data:
        img[DATA_ADDR : DATA_ADDR + len(data)] = data

    return bytes(img)


def _root_ref(dirid: int, sequence: int, name: bytes) -> bytes:
    return c_btrfs.btrfs_root_ref(dirid=dirid, sequence=sequence, name_len=len(name), name=name).dumps()


def build_two_subvolume_orphan_image(
    first_entries: list[tuple[int, int, int, bytes]],
    second_entries: list[tuple[int, int, int, bytes]],
    second_objectid: int = 256,
) -> bytes:
    """Assemble an image with two subvolumes, each carrying their own orphan markers.

    The second subvolume is reachable from the FS_TREE through a ``BTRFS_ROOT_REF_KEY`` in the root tree,
    mirroring how :meth:`Btrfs.subvolumes` discovers subvolumes.
    """
    second_uuid = b"\x55" * 16

    second_root_item = c_btrfs.btrfs_root_item()
    second_root_item.inode.nlink = 1
    second_root_item.inode.mode = 0o40755
    second_root_item.generation = 1
    second_root_item.root_dirid = c_btrfs.BTRFS_FIRST_FREE_OBJECTID
    second_root_item.bytenr = SUBVOL_TREE_ADDR
    second_root_item.level = 0
    second_root_item.refs = 1
    second_root_item.uuid = second_uuid

    root_leaf = make_leaf(
        c_btrfs.BTRFS_ROOT_TREE_OBJECTID,
        ROOT_TREE_ADDR,
        [
            (c_btrfs.BTRFS_FS_TREE_OBJECTID, c_btrfs.BTRFS_ROOT_ITEM_KEY, 0, _root_item().dumps()),
            (second_objectid, c_btrfs.BTRFS_ROOT_ITEM_KEY, 0, second_root_item.dumps()),
            (
                c_btrfs.BTRFS_ROOT_TREE_DIR_OBJECTID,
                c_btrfs.BTRFS_DIR_ITEM_KEY,
                0,
                _default_dir_item(),
            ),
            (
                c_btrfs.BTRFS_FS_TREE_OBJECTID,
                c_btrfs.BTRFS_ROOT_REF_KEY,
                second_objectid,
                _root_ref(c_btrfs.BTRFS_FIRST_FREE_OBJECTID, 1, b"second"),
            ),
        ],
    )

    img = bytearray(IMG_SIZE)
    sb = _superblock()
    sb_offset = c_btrfs.BTRFS_SUPER_INFO_OFFSET
    img[sb_offset : sb_offset + len(sb)] = sb.dumps()

    img[ROOT_TREE_ADDR : ROOT_TREE_ADDR + NODE_SIZE] = root_leaf
    img[FS_TREE_ADDR : FS_TREE_ADDR + NODE_SIZE] = make_leaf(
        c_btrfs.BTRFS_FS_TREE_OBJECTID, FS_TREE_ADDR, first_entries
    )
    img[SUBVOL_TREE_ADDR : SUBVOL_TREE_ADDR + NODE_SIZE] = make_leaf(second_objectid, SUBVOL_TREE_ADDR, second_entries)
    return bytes(img)


def standard_orphan_entries() -> list[tuple[int, int, int, bytes]]:
    """Return the leaf entries for the three canonical orphan scenarios.

    * inode 257 - unlinked but still present: ``nlink == 0`` with a readable data extent.
    * inode 258 - cleanup incomplete: only the orphan marker survives, no inode item.
    * inode 259 - reference corruption: orphan marker plus a conflicting ``nlink == 1`` and a stale ref.
    """
    return [
        (256, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(1, 0o40755, 0, 1)),
        (257, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(0, 0o100644, 12, 7)),
        (257, c_btrfs.BTRFS_EXTENT_DATA_KEY, 0, reg_extent(7, DATA_ADDR, SECTOR_SIZE, 12)),
        orphan_marker(257),
        (259, c_btrfs.BTRFS_INODE_ITEM_KEY, 0, inode_item(1, 0o100644, 5, 9)),
        (259, c_btrfs.BTRFS_INODE_REF_KEY, 256, inode_ref(4, b"ghost.txt")),
        orphan_marker(259),
        orphan_marker(258),
    ]
