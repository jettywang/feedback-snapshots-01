"""Minimal OLE Compound File (CFB / MS-CFB v3) writer.

Only the subset needed to build synthetic VBA projects for olevba tests is
implemented: 512-byte sectors, a single FAT (no DIFAT), the mini stream / mini
FAT for streams smaller than 4096 bytes, and nested storage entries.

The goal is *full structural control* of every byte of the VBA module streams
and the dir record offsets, so the olevba MODULEOFFSET -> source extraction
chain can be mutated precisely. Real Office files and olefile accept output.
"""

import struct

SECTOR_SIZE = 512
MINI_SECTOR_SIZE = 64
MINI_CUTOFF = 4096
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF

STG_EMPTY = 0x00
STG_STORAGE = 0x01
STG_STREAM = 0x02
STG_ROOT = 0x05


class DirEntry(object):
    def __init__(self, name, entry_type, data=b''):
        # name stored as UTF-16LE + terminating U+0000
        name_utf16 = name.encode('utf-16-le') + b'\x00\x00'
        if len(name_utf16) > 64:
            raise ValueError('entry name too long: %r' % name)
        self.name = name
        self.name_bytes = name_utf16
        self.entry_type = entry_type
        self.data = data
        self.left = NOSTREAM
        self.right = NOSTREAM
        self.child = NOSTREAM
        self.start = ENDOFCHAIN if entry_type in (STG_ROOT, STG_STORAGE) \
            else ENDOFCHAIN
        self.size = len(data)
        self.idx = -1
        self.children = []

    def is_mini(self):
        return self.entry_type == STG_STREAM and self.size < MINI_CUTOFF


def _pad(sector, size=SECTOR_SIZE):
    if len(sector) % size:
        sector += b'\x00' * (size - len(sector) % size)
    return sector


def build_cfb(entries):
    """Build a CFB byte string from a tree of :class:`DirEntry` objects.

    :param entries: list of top level entries (storages and streams).
    """
    root = DirEntry('Root Entry', STG_ROOT)
    root.children = list(entries)

    # ---- flatten directory tree (depth first, root first) and index it ----
    flat = [root]

    def flatten(node):
        for child in node.children:
            flat.append(child)
            child.parent = node
            if child.entry_type == STG_STORAGE:
                flatten(child)

    flatten(root)
    for idx, entry in enumerate(flat):
        entry.idx = idx
        entry.left = NOSTREAM
        entry.right = NOSTREAM
        entry.child = NOSTREAM

    def _name_key(entry):
        # MS-CFB orders directory entries by (UTF-16 byte length, uppercase name)
        return (len(entry.name_bytes), entry.name.upper())

    def _build_bst(children):
        """Return root SID of a balanced BST over a sorted list of entries."""
        if not children:
            return NOSTREAM
        ordered = sorted(children, key=_name_key)

        def build(lo, hi):
            if lo > hi:
                return NOSTREAM
            mid = (lo + hi) // 2
            node = ordered[mid]
            node.left = build(lo, mid - 1)
            node.right = build(mid + 1, hi)
            return node.idx

        return build(0, len(ordered) - 1)

    # link every storage's children through a red-black-shaped binary tree
    for node in flat:
        if node.entry_type in (STG_ROOT, STG_STORAGE) and node.children:
            node.child = _build_bst(node.children)

    # ---- mini stream: pack every small stream into 64-byte mini sectors ----
    mini_stream = bytearray()
    mini_fat = []

    def allocate_mini(data):
        start_mini = len(mini_stream) // MINI_SECTOR_SIZE
        n_mini = (len(data) + MINI_SECTOR_SIZE - 1) // MINI_SECTOR_SIZE
        mini_stream.extend(data)
        # pad to mini sector boundary
        if len(mini_stream) % MINI_SECTOR_SIZE:
            mini_stream.extend(b'\x00' *
                               (MINI_SECTOR_SIZE - len(mini_stream) % MINI_SECTOR_SIZE))
        for k in range(n_mini):
            mini_fat.append(ENDOFCHAIN if k == n_mini - 1
                            else start_mini + k + 1)
        return start_mini

    for entry in flat:
        if entry.entry_type == STG_STREAM and entry.is_mini():
            entry.start = allocate_mini(entry.data)
        # large streams keep size for now; allocated later

    # the mini stream is stored in the root entry's normal-sector chain; its
    # length does NOT become the root entry size (the root size describes the
    # directory stream). The root start sector is assigned below.
    mini_stream = bytes(mini_stream)

    # ---- lay out normal (512 byte) sectors ----
    # sector 0 is reserved for the header. We then append:
    #   regular large-stream sectors, mini-stream sectors, mini-FAT, FAT, dir.
    sectors = []          # list of 512-byte sectors; index == MS-CFB sector no.

    def add_sector(data):
        data = _pad(data)
        sectors.append(data)
        # MS-CFB numbers sectors from 0 for the first sector after the header.
        return len(sectors) - 1

    def allocate_chain(data):
        if not data:
            return ENDOFCHAIN, []
        first = None
        chain = []
        for off in range(0, len(data), SECTOR_SIZE):
            num = add_sector(data[off:off + SECTOR_SIZE])
            if first is None:
                first = num
            chain.append(num)
        return first, chain

    large_chains = {}
    for entry in flat:
        if entry.entry_type == STG_STREAM and not entry.is_mini():
            first, chain = allocate_chain(entry.data)
            entry.start = first
            large_chains[entry.idx] = chain

    # root mini stream chain
    root_mini_first, root_mini_chain = allocate_chain(mini_stream)
    if mini_stream:
        root.start = root_mini_first

    # mini FAT chain (one FAT entry per mini sector)
    minifat_bytes = b''.join(struct.pack('<I', v) for v in mini_fat)
    minifat_first, minifat_chain = allocate_chain(minifat_bytes)

    # directory sectors (128 bytes each). The root entry's size is the exact
    # directory stream length in bytes (number of entries * 128); olefile uses it
    # to bound the directory stream. The bytes are still stored in whole 512-byte
    # FAT sectors below, with unused trailing slots left empty.
    raw_dir_bytes = b''.join(_serialize_dir_entry(e) for e in flat)
    root.size = len(raw_dir_bytes)
    dir_entries = [_serialize_dir_entry(e) for e in flat]
    dir_bytes = b''.join(dir_entries)
    if len(dir_bytes) % SECTOR_SIZE:
        dir_bytes += b'\x00' * (SECTOR_SIZE - len(dir_bytes) % SECTOR_SIZE)
    dir_first, dir_chain = allocate_chain(dir_bytes)

    n_data_sectors = len(sectors)
    # The FAT sector follows the data sectors. MS-CFB sector numbers are
    # 0-based and exclude the 512-byte header, so the FAT sector number equals
    # the number of data sectors; it lives at file byte 512 * (number + 1).
    fat_sector_num = n_data_sectors

    # ---- build the FAT ----
    # FAT[k] describes MS-CFB sector k directly (the header has no FAT entry).
    # Allocate one entry per data sector (0..n-1) plus the FAT sector itself.
    fat = [FREESECT] * (fat_sector_num + 1)

    def mark_chain(chain, tag=ENDOFCHAIN):
        for k, num in enumerate(chain):
            fat[num] = tag if k == len(chain) - 1 else chain[k + 1]

    for chain in large_chains.values():
        mark_chain(chain)
    mark_chain(root_mini_chain)
    mark_chain(minifat_chain)
    mark_chain(dir_chain)

    # A FAT sector holds 128 entries. We promise no DIFAT, so require the whole
    # file to fit in one FAT sector.
    if len(fat) > 128:
        raise AssertionError('test fixture too large for single-FAT CFB')

    # self-reference the FAT sector before serialising
    fat[fat_sector_num] = FATSECT
    fat_bytes = b''.join(struct.pack('<I', v) for v in fat)
    # FAT occupies the sector right after the data sectors
    sectors.append(_pad(fat_bytes))

    # ---- header (MS-CFB 2.2 Compound File Header) ----
    header = bytearray(SECTOR_SIZE)
    header[0:8] = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
    # 0x08 CLSID (16 bytes) stays zero
    struct.pack_into('<H', header, 24, 0x003E)          # minor version
    struct.pack_into('<H', header, 26, 0x0003)          # major/dll version (v3)
    struct.pack_into('<H', header, 28, 0xFFFE)          # byte order
    struct.pack_into('<H', header, 30, 9)               # sector shift 2^9=512
    struct.pack_into('<H', header, 32, 6)               # mini sector shift 2^6=64
    # 0x22 reserved 6 bytes (34..39) stays zero
    struct.pack_into('<I', header, 40, 0)               # num dir sectors (0 for v3)
    struct.pack_into('<I', header, 44, 1)               # number of FAT sectors
    struct.pack_into('<I', header, 48, dir_first)       # first dir sector (MS-CFB no.)
    struct.pack_into('<I', header, 52, 0)               # transaction sig
    struct.pack_into('<I', header, 56, MINI_CUTOFF)     # mini stream cutoff
    struct.pack_into('<I', header, 60, minifat_first
                     if minifat_chain else ENDOFCHAIN)  # first mini FAT sector
    struct.pack_into('<I', header, 64, len(mini_fat))   # mini FAT sector count
    struct.pack_into('<I', header, 68, ENDOFCHAIN)      # first DIFAT sector
    struct.pack_into('<I', header, 72, 0)               # DIFAT sector count
    struct.pack_into('<I', header, 76, fat_sector_num)  # DIFAT[0]
    for i in range(1, 109):
        struct.pack_into('<I', header, 76 + i * 4, FREESECT)

    out = bytes(header) + b''.join(sectors)
    return out


def _serialize_dir_entry(entry):
    rec = bytearray(128)
    rec[0:len(entry.name_bytes)] = entry.name_bytes
    struct.pack_into('<H', rec, 64, len(entry.name_bytes))
    rec[66] = entry.entry_type
    rec[67] = 1  # color: black
    struct.pack_into('<I', rec, 68, entry.left)
    struct.pack_into('<I', rec, 72, entry.right)
    struct.pack_into('<I', rec, 76, entry.child)
    # clsid (16) zero; state bits (96) zero; creation/modified time zero
    # Starting sector: storages have no chain; root and streams carry a SID.
    if entry.entry_type == STG_STORAGE:
        struct.pack_into('<I', rec, 116, ENDOFCHAIN)
    else:
        struct.pack_into('<I', rec, 116, entry.start)
    # Stream size as a 64-bit value (high 32 bits stay zero for 512-byte
    # sectors). Storages report zero; the root reports the directory length.
    struct.pack_into('<Q', rec, 120, entry.size if
                     entry.entry_type != STG_STORAGE else 0)
    return bytes(rec)
