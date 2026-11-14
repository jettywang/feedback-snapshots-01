"""
Minimal in-memory Compound File Binary (MS-CFB) builder used by the VBA
inventory tests to synthesize well-formed and deliberately malformed OLE
files.

Only what the tests need is supported: 512-byte FAT sectors, 64-byte mini
sectors and a single directory sector (up to four entries).  All streams are
stored in the mini stream.  The directory red-black trees are built with the
left/right sibling pointers that olefile walks in append_kids().
"""

from __future__ import print_function

import struct

SECTOR_SIZE = 512
MINI_SECTOR_SIZE = 64
MINI_CUTOFF = 4096
ENTRY_SIZE = 128

FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF

STGTY_ROOT = 5
STGTY_STORAGE = 1
STGTY_STREAM = 2


def _rbtree_pointers(sids):
    """
    Build left/right directory SID pointers for a set of entry indices so
    that an in-order walk yields the sids in their given (name-sorted) order.
    A balanced binary search tree is built recursively from the middle of
    the sorted list; pointers are directory SIDs (entry index + 1).
    """
    links = dict((sid, (NOSTREAM, NOSTREAM)) for sid in sids)

    def build(ordered):
        if not ordered:
            return NOSTREAM
        middle = len(ordered) // 2
        sid = ordered[middle]
        left_sid = build(ordered[:middle])
        right_sid = build(ordered[middle + 1:])
        links[sid] = (left_sid, right_sid)
        return sid + 1

    build(list(sids))
    return links


def build_cfb(entries, root_mini_stream=None):
    """
    Build a CFB byte string.

    :param entries: list of dicts describing non-root directory entries:
        ``name`` (unicode), ``type`` (STGTY_STORAGE/STGTY_STREAM),
        ``data`` (bytes, streams only), ``parent_index`` (index of the parent
        storage entry; root when None)
    :return: bytes containing a complete CFB file
    """
    if root_mini_stream is None:
        root_mini_stream = b''

    # ---- lay out the mini stream in 64-byte mini sectors ----------------
    mini_blob = bytearray()
    mini_fat = []
    stream_locations = {}
    for index, entry in enumerate(entries):
        if entry['type'] != STGTY_STREAM:
            continue
        data = entry.get('data') or b''
        if len(data) >= MINI_CUTOFF:
            raise ValueError('test builder only stores mini streams (<4096)')
        if not data:
            stream_locations[index] = (0, 0)
            continue
        start_mini = len(mini_blob) // MINI_SECTOR_SIZE
        count = (len(data) + MINI_SECTOR_SIZE - 1) // MINI_SECTOR_SIZE
        padded = data + b'\x00' * (count * MINI_SECTOR_SIZE - len(data))
        mini_blob.extend(padded)
        for mini_index in range(count):
            mini_fat.append(start_mini + mini_index + 1
                            if mini_index < count - 1 else ENDOFCHAIN)
        stream_locations[index] = (start_mini, len(data))

    # The mini stream itself lives in regular FAT sectors.
    mini_sector_count = (len(mini_blob) + SECTOR_SIZE - 1) // SECTOR_SIZE
    mini_stream_padded = bytes(mini_blob) + b'\x00' * (
        mini_sector_count * SECTOR_SIZE - len(mini_blob))

    # ---- FAT layout: sector 0 is the FAT itself, then the mini stream,
    # one MiniFAT sector and finally the directory sector(s). --------------
    # Directory entries: root + one per supplied entry.
    total_dir_entries = 1 + len(entries)
    dir_sector_count = (
        total_dir_entries * ENTRY_SIZE + SECTOR_SIZE - 1) // SECTOR_SIZE

    mini_stream_first = 1
    minifat_first = mini_stream_first + mini_sector_count
    directory_first = minifat_first + 1  # one MiniFAT sector is enough here
    dir_sector_end = directory_first + dir_sector_count

    fat = [FREESECT] * (SECTOR_SIZE // 4)
    fat[0] = FATSECT
    for sector in range(mini_stream_first,
                        mini_stream_first + mini_sector_count):
        fat[sector] = (sector + 1
                       if sector + 1 < minifat_first else ENDOFCHAIN)
    fat[minifat_first] = ENDOFCHAIN
    for sector in range(directory_first,
                        directory_first + dir_sector_count):
        fat[sector] = (sector + 1
                       if sector + 1 < directory_first + dir_sector_count
                       else ENDOFCHAIN)

    # ---- directory entries ----------------------------------------------
    parent_children = {}
    for index, entry in enumerate(entries):
        parent = entry.get('parent_index')
        parent_children.setdefault(parent, []).append(index)

    # Sort children by name so the right-leaning chain is a valid BST order.
    for key in parent_children:
        parent_children[key].sort(
            key=lambda idx: _name_sort_key(entries[idx]['name']))

    root_links = _rbtree_pointers(parent_children.get(None, []))
    entry_links = {}
    for parent_index, children in parent_children.items():
        if parent_index is None:
            continue
        entry_links[parent_index] = _rbtree_pointers(children)

    dir_bytes = bytearray()
    # Root entry (SID 0). Child SIDs are entry indices + 1.
    root_children = parent_children.get(None, [])
    root_child = _subtree_root_sid(root_children) if root_children \
        else NOSTREAM
    root_size = len(mini_blob)
    dir_bytes += _dir_entry(
        name='Root Entry', entry_type=STGTY_ROOT,
        left=NOSTREAM, right=NOSTREAM, child=root_child,
        size=root_size, start_sector=(mini_stream_first
                                      if mini_blob else ENDOFCHAIN),
        is_root=True)

    # Each entry's left/right pointers link it to its siblings inside its
    # parent's child list, so look the entry up in its own parent's link map.
    sibling_links = {None: root_links}
    for parent_index, link_map in entry_links.items():
        for child_index, pointers in link_map.items():
            sibling_links[child_index] = pointers

    for index, entry in enumerate(entries):
        left, right = sibling_links.get(index, (NOSTREAM, NOSTREAM))
        children = parent_children.get(index, [])
        child = _subtree_root_sid(children) if children else NOSTREAM
        if entry['type'] == STGTY_STORAGE:
            dir_bytes += _dir_entry(
                name=entry['name'], entry_type=STGTY_STORAGE,
                left=left, right=right, child=child,
                size=0, start_sector=ENDOFCHAIN)
        else:
            start_mini, size = stream_locations.get(index, (ENDOFCHAIN, 0))
            dir_bytes += _dir_entry(
                name=entry['name'], entry_type=STGTY_STREAM,
                left=left, right=right, child=NOSTREAM,
                size=size, start_sector=start_mini)
    while len(dir_bytes) < dir_sector_count * SECTOR_SIZE:
        dir_bytes += b'\x00' * ENTRY_SIZE

    minifat_bytes = b''.join(
        struct.pack('<I', value) for value in mini_fat)
    minifat_bytes += b'\x00' * (SECTOR_SIZE - len(minifat_bytes))

    # ---- CFB header ------------------------------------------------------
    header = bytearray(SECTOR_SIZE)
    struct.pack_into('<Q', header, 0, 0xE11AB1A1E011CFD0)
    struct.pack_into('<HH', header, 24, 0x003E, 0x0003)  # minor, major version
    struct.pack_into('<H', header, 28, 0xFFFE)  # byte order
    struct.pack_into('<H', header, 30, 9)       # sector shift 2^9 = 512
    struct.pack_into('<H', header, 32, 6)       # mini sector shift 2^6 = 64
    # offsets 34-39: 6 reserved bytes, left as zero.
    struct.pack_into('<I', header, 40, 0)       # number of dir sectors (0 v3)
    struct.pack_into('<I', header, 44, 1)       # number of FAT sectors
    struct.pack_into('<I', header, 48, directory_first)  # first dir sector
    struct.pack_into('<I', header, 52, 0)       # transaction signature
    struct.pack_into('<I', header, 56, MINI_CUTOFF)
    struct.pack_into('<I', header, 60, minifat_first)
    struct.pack_into('<I', header, 64, 1)       # number of MiniFAT sectors
    struct.pack_into('<I', header, 68, ENDOFCHAIN)  # first DIFAT
    struct.pack_into('<I', header, 72, 0)       # number of DIFAT sectors
    struct.pack_into('<I', header, 76, 0)       # DIFAT[0] -> FAT sector 0
    for difat_index in range(1, 109):
        struct.pack_into('<I', header, 76 + difat_index * 4, FREESECT)

    sectors = []
    fat_bytes = b''.join(struct.pack('<I', value) for value in fat)
    sectors.append(fat_bytes[:SECTOR_SIZE])
    sectors.append(mini_stream_padded[:SECTOR_SIZE])
    for extra in range(1, mini_sector_count):
        sectors.append(mini_stream_padded[
            extra * SECTOR_SIZE:(extra + 1) * SECTOR_SIZE])
    sectors.append(minifat_bytes)
    sectors.append(bytes(dir_bytes)[:SECTOR_SIZE])
    for extra in range(1, dir_sector_count):
        sectors.append(bytes(dir_bytes)[
            extra * SECTOR_SIZE:(extra + 1) * SECTOR_SIZE])
    return bytes(header) + b''.join(sectors)


def _subtree_root_sid(ordered):
    """Directory SID of the balanced BST root of ``ordered`` entry indices."""
    return ordered[len(ordered) // 2] + 1


def _name_sort_key(name):
    # MS-CFB orders entries by (utf16 byte length, uppercase name); olefile
    # only requires a stable order consistent between siblings.
    return (len(name) * 2, name.upper())


def _dir_entry(name, entry_type, left, right, child, size, start_sector,
               is_root=False):
    raw = bytearray(ENTRY_SIZE)
    encoded = name.encode('utf-16-le')
    name_field = encoded + b'\x00\x00'
    if len(name_field) > 64:
        raise ValueError('entry name too long: %r' % name)
    raw[0:len(name_field)] = name_field
    struct.pack_into('<H', raw, 64, len(name_field))  # name length incl null
    struct.pack_into('<B', raw, 66, entry_type)
    struct.pack_into('<B', raw, 67, 1 if is_root else 0)  # color = black
    struct.pack_into('<I', raw, 68, left & 0xFFFFFFFF)
    struct.pack_into('<I', raw, 72, right & 0xFFFFFFFF)
    struct.pack_into('<I', raw, 76, child & 0xFFFFFFFF)
    # CLSID (16 bytes at 80), state (96), creation/modification times zeroed.
    struct.pack_into('<I', raw, 116, start_sector & 0xFFFFFFFF)
    struct.pack_into('<I', raw, 120, size & 0xFFFFFFFF)
    struct.pack_into('<I', raw, 124, (size >> 32) & 0xFFFFFFFF)
    return bytes(raw)
