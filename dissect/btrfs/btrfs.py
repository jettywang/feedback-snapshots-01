# References:
# - https://btrfs.readthedocs.io/en/latest/
# - https://github.com/torvalds/linux/tree/master/fs/btrfs
# - https://github.com/btrfs/btrfs-dev-docs
# - https://www.sciencedirect.com/science/article/pii/S1742287618301993
from __future__ import annotations

import io
import stat
from enum import Enum
from functools import cache, cached_property, lru_cache
from typing import TYPE_CHECKING, BinaryIO, NamedTuple
from uuid import UUID

from dissect.util import ts
from dissect.util.hash import crc32c
from dissect.util.stream import BufferedStream

from dissect.btrfs.c_btrfs import FT_MAP, c_btrfs
from dissect.btrfs.exceptions import (
    Error,
    FileNotFoundError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.btrfs.stream import ChunkStream, Extent, ExtentStream, decode_extent
from dissect.btrfs.tree import BTree

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

# Btrfs negative object IDs are stored as their unsigned two's-complement representation on disk.
UNSIGNED_64_WRAP = 1 << 64
BTRFS_ORPHAN_OBJECTID_UNSIGNED = c_btrfs.BTRFS_ORPHAN_OBJECTID % UNSIGNED_64_WRAP


class Btrfs:
    """Btrfs filesystem implementation.

    This implementation supports most basic Btrfs features such as subvolumes, compression and (meta)data RAID.
    To open a RAID volume, simply pass all file-like objects that belong to the RAID set as a list.

    Args:
        fh: A file-like object for the volume to use for parsing Btrfs.
    """

    def __init__(self, fh: BinaryIO | list[BinaryIO]):
        self.fhs = fh if isinstance(fh, list) else [fh]

        if not self.fhs:
            raise ValueError("At least one file-like object is required")

        sb_fhs = []
        for fh in self.fhs:
            fh.seek(c_btrfs.BTRFS_SUPER_INFO_OFFSET)
            sb = c_btrfs.btrfs_super_block(fh)
            if sb.magic != c_btrfs.BTRFS_MAGIC:
                raise Error("Invalid btrfs superblock")
            sb_fhs.append((sb, fh))

        if len({sb.fsid for sb, _ in sb_fhs}) > 1:
            raise ValueError("Only file-like objects of the same filesystem UUID can be used")

        sb_fhs = sorted(sb_fhs, key=lambda item: item[0].generation, reverse=True)

        self.sb = sb_fhs[0][0]
        self.sector_size = self.sb.sectorsize
        self.node_size = self.sb.nodesize
        self.stripe_size = self.sb.stripesize

        self.label = self.sb.label.split(b"\x00")[0].decode()
        self.uuid = UUID(bytes=self.sb.fsid)
        self.metadata_uuid = UUID(bytes=self.sb.metadata_uuid)

        self.devices = {sb.dev_item.devid: fh for sb, fh in sb_fhs}

        self._open_tree = lru_cache(32)(self._open_tree)
        self.open_subvolume = lru_cache(16)(self.open_subvolume)

        self._logical_fh = ChunkStream(self)
        self._initialize_chunks()

        self._root_tree = BTree(self, root_offset=self.sb.root)

        self.fs_tree = self.open_subvolume(c_btrfs.BTRFS_FS_TREE_OBJECTID)

        self.default_subvolume = self._open_default_subvolume()
        self.root = self.default_subvolume.root

    def get(self, path: str | int, node: INode | None = None) -> INode:
        """Retrieve a Btrfs inode by path or inode number.

        Args:
            path: Filesystem path or inode number.
            node: Optional inode used for relative lookups.
        """
        return self.default_subvolume.get(path, node)

    def subvolumes(self) -> Iterator[Subvolume]:
        """Yield all subvolumes."""
        yield self.fs_tree

        search_ids = [c_btrfs.BTRFS_FS_TREE_OBJECTID]

        cursor = self._root_tree.cursor()
        for object_id in search_ids:
            for item, _ in cursor.iter(
                objectid=object_id, type=c_btrfs.BTRFS_ROOT_REF_KEY, offset=0, ignore_offset=True
            ):
                search_ids.append(item.key.offset)
                yield self.open_subvolume(item.key.offset)
            cursor.reset()

    def orphans(self) -> Iterator[Orphan]:
        """Yield the orphan records of every reachable subvolume.

        Orphan items live in a subvolume's own tree (keyed on ``BTRFS_ORPHAN_OBJECTID``), so each
        :class:`Subvolume` is inspected separately. See :meth:`Subvolume.orphans` for the meaning of
        the returned records and the evidence they carry.
        """
        for subvolume in self.subvolumes():
            yield from subvolume.orphans()

    def find_subvolume(self, path: str | None = None) -> Subvolume | None:
        """Find a subvolume by path.

        Args:
            path: The path of the subvolume to find.
        """
        for subvolume in self.subvolumes():
            if subvolume.path == path:
                return subvolume

        return None

    def open_subvolume(self, objectid: int, parent: INode | None = None) -> Subvolume:
        """Open a subvolume.

        Args:
            objectid: The objectid of the subvolume to open.
            parent: Optional parent node to attach to the root of the subvolume.
        """
        return Subvolume(self, objectid, parent)

    def _initialize_chunks(self) -> None:
        """Initialize the logical data stream by reading the system chunk array and traversing the chunk tree."""
        sys_chunk_array = io.BytesIO(memoryview(self.sb.sys_chunk_array)[: self.sb.sys_chunk_array_size])
        while True:
            key = c_btrfs.btrfs_disk_key(sys_chunk_array)
            if key.type != c_btrfs.BTRFS_CHUNK_ITEM_KEY:
                raise ValueError(f"Invalid item type in sys_chunk_array: {key}")

            chunk = c_btrfs.btrfs_chunk(sys_chunk_array)
            self._logical_fh.add(key.offset, chunk)

            if sys_chunk_array.tell() == self.sb.sys_chunk_array_size:
                break

        chunk_tree = BTree(self, root_offset=self.sb.chunk_root)
        for item, data in chunk_tree.cursor().iter(
            objectid=c_btrfs.BTRFS_FIRST_CHUNK_TREE_OBJECTID,
            type=c_btrfs.BTRFS_CHUNK_ITEM_KEY,
            offset=0,
            ignore_offset=True,
        ):
            chunk = c_btrfs.btrfs_chunk(data)
            self._logical_fh.add(item.key.offset, chunk)

    def _open_tree(self, objectid: int) -> BTree:
        """Open a tree by object ID.

        Args:
            objectid: The object ID of the tree to open.
        """
        _, data = self._root_tree.find(objectid, c_btrfs.BTRFS_ROOT_ITEM_KEY)
        root_item = c_btrfs.btrfs_root_item(data)
        return BTree(self, root_item)

    def _open_default_subvolume(self) -> Subvolume:
        """Find and open the subvolume that's configured as default."""
        _, data = self._root_tree.find(c_btrfs.BTRFS_ROOT_TREE_DIR_OBJECTID, c_btrfs.BTRFS_DIR_ITEM_KEY)
        root_dir_item = c_btrfs.btrfs_dir_item(data)
        return Subvolume(self, root_dir_item.location.objectid)

    def _read_node(self, address: int) -> bytes:
        """Helper method for reading a node.

        Args:
            address: The node address to read.
        """
        self._logical_fh.seek(address)
        return self._logical_fh.read(self.node_size)


class Subvolume:
    """Represent a Btrfs subvolume.

    Btrfs has support for multiple subvolumes. The default subvolume is the ``FS_TREE`` subvolume.
    Each subvolume has its own B-tree.

    Args:
        btrfs: The filesystem this subvolume belongs to.
        objectid: The object ID of the subvolume to open.
        parent: Optional parent node to attach to the root of the subvolume.
    """

    def __init__(self, btrfs: Btrfs, objectid: int, parent: INode | None = None):
        self.btrfs = btrfs
        self.objectid = objectid
        self.parent = parent

        self.inode = lru_cache(8192)(self.inode)
        self.resolve_path = lru_cache(1024)(self.resolve_path)

    def __repr__(self) -> str:
        return f"<Subvolume objectid={self.objectid}>"

    @cached_property
    def tree(self) -> BTree:
        return self.btrfs._open_tree(self.objectid)

    @cached_property
    def uuid(self) -> UUID:
        return UUID(bytes=self.tree.root_item.uuid)

    @cached_property
    def root(self) -> INode:
        return self.inode(self.tree.root_item.root_dirid, c_btrfs.BTRFS_FT_DIR, self.parent)

    @cached_property
    def path(self) -> str:
        parts = []
        objectid = self.objectid
        while objectid != c_btrfs.BTRFS_FS_TREE_OBJECTID:
            item, data = self.btrfs._root_tree.find(objectid=objectid, type=c_btrfs.BTRFS_ROOT_BACKREF_KEY)
            root_ref = c_btrfs.btrfs_root_ref(data)
            name = root_ref.name.decode(errors="surrogateescape")
            parts.append(name)

            if path := self.btrfs.open_subvolume(item.key.offset).resolve_path(root_ref.dirid):
                parts.append(path)

            objectid = item.key.offset

        return "/".join(parts[::-1])

    def get(self, path: str | int, node: INode | None = None) -> INode:
        """Retrieve a Btrfs inode by path or inode number.

        Args:
            path: Filesystem path or inode number.
            node: Optional inode used for relative lookups.
        """
        if isinstance(path, int):
            return self.inode(path)

        node = node or self.root
        subvolume = self

        parts = path.encode().split(b"/")

        for part in parts:
            if not part:
                continue

            if part == b".":
                continue

            if part == b"..":
                node = node.parent or node
                continue

            while node.is_symlink():
                node = node.link_inode

            # The Linux kernel doesn't do an initial and final XOR with 0xFFFFFFFF
            # Btrfs uses an initial CRC of `(u32)~1`, which is effectively the same as 1 XOR 0xFFFFFFFF
            # We still need to invert the XOR of the result though
            # https://stackoverflow.com/a/40433980
            part_hash = (crc32c.update(1, part) ^ 0xFFFFFFFF) & 0xFFFFFFFF
            try:
                _, data = subvolume.tree.find(node.inum, c_btrfs.BTRFS_DIR_ITEM_KEY, part_hash)
            except KeyError:
                raise FileNotFoundError(f"File not found: {path}")

            dir_item = c_btrfs.btrfs_dir_item(data)
            dir_item_type = dir_item.location.type

            if dir_item_type == c_btrfs.BTRFS_ROOT_ITEM_KEY:
                subvolume = self.btrfs.open_subvolume(dir_item.location.objectid, subvolume)
                node = subvolume.root
            elif dir_item_type == c_btrfs.BTRFS_INODE_ITEM_KEY:
                node = subvolume.inode(dir_item.location.objectid, dir_item.type, subvolume)
            else:
                raise NotImplementedError(f"Unknown dir_item type: {dir_item}")

        return node

    def inode(self, inum: int, type: int | None = None, parent: INode | None = None) -> INode:
        """Return an :class:`INode` by number, optionally attaching a type and parent."""
        return INode(self, inum, type, parent)

    def resolve_path(self, objectid: int) -> str:
        names = []
        while objectid != c_btrfs.BTRFS_FIRST_FREE_OBJECTID:
            item, data = self.tree.find(objectid, c_btrfs.BTRFS_INODE_REF_KEY)
            inode_ref = c_btrfs.btrfs_inode_ref(data)
            names.append(inode_ref.name.decode(errors="surrogateescape"))

            objectid = item.key.offset

        return "/".join(names[::-1])

    def orphans(self) -> Iterator[Orphan]:
        """Yield the orphan records stored in this subvolume's tree.

        An orphan item (``(BTRFS_ORPHAN_OBJECTID, BTRFS_ORPHAN_ITEM_KEY, inum)``) only marks an inode
        number that the filesystem intends to clean up. It does not carry a name and it is never part of a
        directory listing. Every returned :class:`Orphan` therefore presents the marker alongside the
        independently observable evidence (the inode, its data and any surviving reference material) that is
        needed to decide what can actually be recovered.
        """
        cursor = self.tree.cursor()
        for item, _ in cursor.iter(
            BTRFS_ORPHAN_OBJECTID_UNSIGNED, c_btrfs.BTRFS_ORPHAN_ITEM_KEY, 0, ignore_offset=True
        ):
            yield Orphan(self, item.key.offset)


class INode:
    """Represent a Btrfs inode.

    Args:
        subvolume: The subvolume this inode belongs to.
        inum: The inode number of this inode.
        type: Optional file type of this inode, as observed in a directory entry.
        parent: Optional parent of this inode, if this inode is parsed from a directory listing.
    """

    def __init__(self, subvolume: Subvolume, inum: int, type: int | None = None, parent: INode | None = None):
        self.subvolume = subvolume
        self.btrfs = subvolume.btrfs
        self.inum = inum
        self._type = type
        self.parent = parent

        self.listdir = cache(self.listdir)
        self.extents = cache(self.extents)

    def __repr__(self) -> str:
        return f"<inode {self.subvolume.objectid}:{self.inum}>"

    @cached_property
    def inode(self) -> c_btrfs.btrfs_inode_item:
        """Return the parsed inode structure."""
        _, data = self.subvolume.tree.find(self.inum, c_btrfs.BTRFS_INODE_ITEM_KEY)
        return c_btrfs.btrfs_inode_item(data)

    @cached_property
    def generation(self) -> int:
        """Return the inode generation (NFS-style generation number)."""
        return self.inode.generation

    @cached_property
    def nlink(self) -> int:
        """Return the recorded hard link count."""
        return self.inode.nlink

    @cached_property
    def size(self) -> int:
        """Return the file size."""
        return self.inode.size

    @cached_property
    def uid(self) -> int:
        """Return the owner user ID."""
        return self.inode.uid

    @cached_property
    def gid(self) -> int:
        """Return the owner group ID."""
        return self.inode.gid

    @cached_property
    def mode(self) -> int:
        """Return the file mode."""
        return self.inode.mode

    @cached_property
    def type(self) -> int:
        """Return the file type."""
        return FT_MAP.get(self._type) or stat.S_IFMT(self.inode.mode)

    @cached_property
    def atime(self) -> datetime:
        """Return datetime timestamp of last access."""
        return ts.from_unix_ns(self.atime_ns)

    @cached_property
    def atime_ns(self) -> int:
        """Return nanosecond timestamp of last access."""
        return _parse_ts(self.inode.atime)

    @cached_property
    def ctime(self) -> datetime:
        """Return datetime timestamp of last metadata change."""
        return ts.from_unix_ns(self.ctime_ns)

    @cached_property
    def ctime_ns(self) -> int:
        """Return nanosecond timestamp of last metadata change."""
        return _parse_ts(self.inode.ctime)

    @cached_property
    def mtime(self) -> datetime:
        """Return datetime timestamp of last content modification."""
        return ts.from_unix_ns(self.mtime_ns)

    @cached_property
    def mtime_ns(self) -> int:
        """Return nanosecond timestamp of last content modification."""
        return _parse_ts(self.inode.mtime)

    @cached_property
    def otime(self) -> datetime:
        """Return datetime timestamp of inode creation."""
        return ts.from_unix_ns(self.otime_ns)

    @cached_property
    def otime_ns(self) -> int:
        """Return nanosecond timestamp of inode creation."""
        return _parse_ts(self.inode.otime)

    def is_dir(self) -> bool:
        """Return whether this inode is a directory."""
        return self.type == stat.S_IFDIR

    def is_file(self) -> bool:
        """Return whether this inode is a regular file."""
        return self.type == stat.S_IFREG

    def is_symlink(self) -> bool:
        """Return whether this inode is a symlink."""
        return self.type == stat.S_IFLNK

    def is_block_device(self) -> bool:
        """Return whether this inode is a block device."""
        return self.type == stat.S_IFBLK

    def is_character_device(self) -> bool:
        """Return whether this inode is a character device."""
        return self.type == stat.S_IFCHR

    def is_device(self) -> bool:
        """Return whether this inode is a device."""
        return self.is_block_device() or self.is_character_device()

    def is_fifo(self) -> bool:
        """Return whether this inode is a FIFO file."""
        return self.type == stat.S_IFIFO

    def is_socket(self) -> bool:
        """Return whether this inode is a socket file."""
        return self.type == stat.S_IFSOCK

    def is_ipc(self) -> bool:
        """Return whether this inode is an IPC file."""
        return self.is_fifo() or self.is_socket()

    @cached_property
    def link(self) -> str:
        """Return the symlink target."""
        if not self.is_symlink():
            raise NotASymlinkError(f"{self!r} is not a symlink")

        return self.open().read().decode(errors="surrogateescape")

    @cached_property
    def link_inode(self) -> INode:
        """Resolve the symlink target to an inode."""
        link = self.link
        relnode = None if link.startswith("/") else self.parent
        return self.subvolume.get(self.link, relnode)

    @property
    def parents(self) -> Iterator[INode]:
        for item, data in self.subvolume.tree.cursor().iter(
            self.inum, c_btrfs.BTRFS_INODE_REF_KEY, 0, ignore_offset=True
        ):
            inode_ref = c_btrfs.btrfs_inode_ref(data)
            if inode_ref.name == b"..":
                if self.parent:
                    yield self.parent
            else:
                yield self.subvolume.inode(item.key.offset, c_btrfs.BTRFS_FT_DIR)

    @property
    def path(self) -> str:
        """Return the path to this inode within the subvolume. In case of multiple hardlinks, return the first path."""
        return next(self.paths())

    @property
    def full_path(self) -> str:
        """Return the full path to this inode. In case of multiple hardlinks, return the first path."""
        return next(self.paths(True))

    def get(self, path: str) -> INode:
        """Retrieve a Btrfs inode relative from this inode.

        Args:
            path: Filesystem path.
        """
        return self.subvolume.get(path, self)

    def paths(self, full: bool = False) -> Iterator[str]:
        """Yield all paths (hardlinks) to this inode.

        By default only resolves up to the root of the subvolume this inode belongs to.
        For a full path to the root of the filesystem tree, set ``full`` to ``True``.

        Args:
            full: Whether to fully resolve the path up to the root of the filesystem tree.
        """
        root = self.subvolume.path if full else ""
        for item, data in self.subvolume.tree.cursor().iter(
            self.inum, c_btrfs.BTRFS_INODE_REF_KEY, 0, ignore_offset=True
        ):
            if item.key.offset == self.inum:
                yield root
                break

            inode_ref = c_btrfs.btrfs_inode_ref(data)
            name = inode_ref.name.decode(errors="surrogateescape")

            path = [name]
            if parent_path := self.subvolume.resolve_path(item.key.offset):
                path.append(parent_path)

            if root:
                path.append(root)

            yield "/".join(path[::-1])

    def directory_references(self) -> list[DirectoryReference]:
        """Return the directory reference material that still names this inode.

        Both ``BTRFS_INODE_REF_KEY`` and ``BTRFS_INODE_EXTREF_KEY`` items are reported. The presence of such
        an item is independent of whether the inode is still linked in a live directory: for an unlinked
        inode any surviving reference is stale or damaged evidence and is reported here instead of being
        treated as an existing name.
        """
        references = []

        for item, data in self.subvolume.tree.cursor().iter(
            self.inum, c_btrfs.BTRFS_INODE_REF_KEY, 0, ignore_offset=True
        ):
            inode_ref = c_btrfs.btrfs_inode_ref(data)
            references.append(
                DirectoryReference(
                    parent_inum=item.key.offset,
                    index=inode_ref.index,
                    name=inode_ref.name.decode(errors="surrogateescape"),
                    extended=False,
                )
            )

        for _, data in self.subvolume.tree.cursor().iter(
            self.inum, c_btrfs.BTRFS_INODE_EXTREF_KEY, 0, ignore_offset=True
        ):
            inode_extref = c_btrfs.btrfs_inode_extref(data)
            references.append(
                DirectoryReference(
                    parent_inum=inode_extref.parent_objectid,
                    index=inode_extref.index,
                    name=inode_extref.name.decode(errors="surrogateescape"),
                    extended=True,
                )
            )

        return references

    def has_extent_data(self) -> bool:
        """Return whether at least one ``BTRFS_EXTENT_DATA_KEY`` item is attached to this inode.

        This only proves that extent records are still reachable on disk. Inline data, regular extents and
        preallocated extents all count; an all-sparse or zero-length file has none. It does not prove the
        referenced bytes are complete or undamaged.
        """
        cursor = self.subvolume.tree.cursor()
        return bool(
            next(
                cursor.iter(self.inum, c_btrfs.BTRFS_EXTENT_DATA_KEY, 0, ignore_offset=True),
                None,
            )
        )

    def listdir(self) -> dict[str, INode]:
        """Return a directory listing."""
        return dict(self.iterdir())

    def iterdir(self) -> Iterator[tuple[str, INode]]:
        """Iterate directory contents."""
        if not self.is_dir():
            raise NotADirectoryError(f"{self!r} is not a directory")

        yield ".", self
        yield "..", self.parent or self

        # The offset in BTRFS_DIR_INDEX_KEY items is the directory index
        # Start searching from index 2 (because . and .. are 0 and 1 respectively)
        cursor = self.subvolume.tree.cursor()
        for _, data in cursor.iter(self.inum, c_btrfs.BTRFS_DIR_INDEX_KEY, 2, ignore_offset=True):
            dir_item = c_btrfs.btrfs_dir_item(data)
            dir_item_type = dir_item.location.type
            name = dir_item.name.decode(errors="surrogateescape")

            if dir_item_type == c_btrfs.BTRFS_ROOT_ITEM_KEY:
                subvolume = self.btrfs.open_subvolume(dir_item.location.objectid, self)
                yield name, subvolume.root
            elif dir_item_type == c_btrfs.BTRFS_INODE_ITEM_KEY:
                yield name, self.subvolume.inode(dir_item.location.objectid, dir_item.type, self)
            else:
                raise NotImplementedError(f"Unknown dir_item type: {dir_item}")

    def extents(self) -> list[Extent] | None:
        with self.open() as fh:
            if isinstance(fh, ExtentStream):
                return fh.extents

        return None

    def open(self) -> BinaryIO:
        """Return the data stream for the inode.

        File data in Btrfs can be inlined in the B-tree or stored in file extents. In both cases it can be compressed.
        """
        if not self.size:
            return BufferedStream(io.BytesIO(), size=0)

        offset = 0
        extents = []

        cursor = self.subvolume.tree.cursor()
        for item, data in cursor.iter(self.inum, c_btrfs.BTRFS_EXTENT_DATA_KEY, 0, ignore_offset=True):
            extent = c_btrfs.btrfs_file_extent_item_inline(data)

            if extent.type == c_btrfs.BTRFS_FILE_EXTENT_INLINE:
                header_len = len(c_btrfs.btrfs_file_extent_item_inline)
                buf = decode_extent(
                    data[header_len:],
                    extent.compression,
                    extent.encryption,
                    self.btrfs.sector_size,
                )
                return BufferedStream(io.BytesIO(buf), size=self.size)

            extent = c_btrfs.btrfs_file_extent_item_reg(data)
            if extent.type == c_btrfs.BTRFS_FILE_EXTENT_REG:
                key = item.key

                if offset < key.offset:
                    gap = key.offset - offset
                    extents.append(Extent(0, 0, 0, 0, 0, gap))
                    offset += gap

                extents.append(
                    Extent(
                        extent.compression,
                        extent.encryption,
                        extent.disk_bytenr,
                        extent.disk_num_bytes,
                        extent.offset,
                        extent.num_bytes,
                    )
                )
                offset += extent.num_bytes

        if offset < self.size:
            extents.append(Extent(0, 0, 0, 0, 0, self.size - offset))

        return ExtentStream(self.btrfs._logical_fh, extents, self.size, self.btrfs.sector_size)


class OrphanStatus(Enum):
    """Forensic classification of an orphan item given the surrounding evidence.

    The classification is derived strictly from what is observable on disk and never assumes that an orphan
    marker alone proves either a name or intact file contents.
    """

    UNLINKED_PRESENT = "unlinked_present"
    """The inode is unlinked (``nlink == 0``) but its inode item still exists and holds data records."""

    CLEANUP_INCOMPLETE = "cleanup_incomplete"
    """Only the orphan marker survives; the inode item it points at is gone, so cleanup was interrupted."""

    REFERENCE_CORRUPTION = "reference_corruption"
    """The marker and the surviving reference material disagree (stale links or a conflicting nlink)."""


class DirectoryReference(NamedTuple):
    """A single directory reference (name) that still points at an inode.

    Args:
        parent_inum: The object ID of the directory that would contain the entry.
        index: The directory index stored in the reference.
        name: The entry name. May be untrusted or stale when the inode is also an orphan.
        extended: Whether this came from a ``BTRFS_INODE_EXTREF_KEY`` rather than a ``BTRFS_INODE_REF_KEY``.
    """

    parent_inum: int
    index: int
    name: str
    extended: bool


class Orphan:
    """A forensic view of a single Btrfs orphan item and the evidence around it.

    The orphan marker is presented side by side with the independently readable inode (if it still exists)
    and any observable directory references. An orphan item is not a directory entry: it never has a name of
    its own and it is not returned by normal directory enumeration.

    Args:
        subvolume: The subvolume whose tree contains the orphan item.
        inum: The inode number recorded in the orphan item key.
    """

    def __init__(self, subvolume: Subvolume, inum: int):
        self.subvolume = subvolume
        self.inum = inum

    def __repr__(self) -> str:
        return f"<orphan {self.subvolume.objectid}:{self.inum} status={self.status.value}>"

    @property
    def btrfs(self) -> Btrfs:
        """Return the filesystem this orphan belongs to."""
        return self.subvolume.btrfs

    @property
    def root_objectid(self) -> int:
        """Return the object ID (root identity) of the subvolume holding this orphan."""
        return self.subvolume.objectid

    @property
    def root_uuid(self) -> UUID:
        """Return the UUID (root identity) of the subvolume holding this orphan."""
        return self.subvolume.uuid

    @cached_property
    def inode(self) -> INode | None:
        """Return the still-readable inode, or ``None`` if the inode item no longer exists."""
        inode = self.subvolume.inode(self.inum)
        try:
            # Materialize the lazy inode item: its absence is what distinguishes interrupted cleanup.
            _ = inode.inode
        except KeyError:
            return None
        return inode

    @cached_property
    def inode_generation(self) -> int | None:
        """Return the recorded inode generation, or ``None`` when the inode item is missing."""
        return None if self.inode is None else self.inode.generation

    @cached_property
    def nlink(self) -> int | None:
        """Return the recorded hard link count, or ``None`` when the inode item is missing."""
        return None if self.inode is None else self.inode.nlink

    @cached_property
    def references(self) -> list[DirectoryReference]:
        """Return the directory reference material that still names this inode.

        These references are raw evidence. For an unlinked inode they are stale or damaged and must not be
        treated as a name that is reachable through a live directory.
        """
        return [] if self.inode is None else self.inode.directory_references()

    @property
    def name(self) -> str | None:
        """Return a recoverable name, or ``None`` when no trustworthy single name is available.

        A name is only returned when exactly one directory reference survives. With zero references the name
        is genuinely unknown; with several conflicting references no single name can be chosen safely.
        """
        names = {reference.name for reference in self.references}
        return next(iter(names)) if len(names) == 1 else None

    @cached_property
    def has_data(self) -> bool:
        """Return whether extent data records are still attached to the inode.

        ``True`` only means data extents are observable; it does not establish that their contents are
        complete or uncorrupted. Always verify bytes through :meth:`open`.
        """
        return False if self.inode is None else self.inode.has_extent_data()

    def open(self) -> BinaryIO:
        """Open the inode's data stream.

        Raises:
            FileNotFoundError: If the inode item is missing, in which case no content can be recovered.
        """
        if self.inode is None:
            raise FileNotFoundError(f"Orphan inode {self.inum} has no surviving inode item")
        return self.inode.open()

    @cached_property
    def status(self) -> OrphanStatus:
        """Classify the orphan from the on-disk evidence."""
        if self.inode is None:
            return OrphanStatus.CLEANUP_INCOMPLETE

        if self.nlink != 0 or self.references:
            return OrphanStatus.REFERENCE_CORRUPTION

        return OrphanStatus.UNLINKED_PRESENT

    @cached_property
    def reasons(self) -> list[str]:
        """Return the human-readable evidence supporting :attr:`status`."""
        if self.status is OrphanStatus.CLEANUP_INCOMPLETE:
            return [f"orphan marker for inode {self.inum} has no surviving inode item"]

        evidence = [f"inode item present with nlink={self.nlink}"]
        if self.references:
            evidence.append(f"{len(self.references)} surviving directory reference(s) despite orphan marker")
        else:
            evidence.append("no directory references survive")
        if self.has_data:
            evidence.append("extent data records are still attached")
        else:
            evidence.append("no extent data records are attached")

        if self.status is OrphanStatus.REFERENCE_CORRUPTION and self.nlink != 0:
            evidence.append("nlink is non-zero even though the inode is queued as an orphan")
        return evidence


def _parse_ts(timespec: c_btrfs.btrfs_timespec) -> int:
    """Parse a Btrfs time specification into a nanosecond timestamp."""
    return (timespec.sec * 1000000000) + timespec.nsec
