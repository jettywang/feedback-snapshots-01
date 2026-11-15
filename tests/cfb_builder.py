"""
Tiny in-memory MS-CFB (OLE2) compound file builder, used only by the test
suite to create files with arbitrary directory entry arrays and red-black
tree topologies. The files contain no user stream data: every stream is
zero-sized, so neither FAT data chains nor a mini stream are required.

Layout (version 3, 512-byte sectors):
    sector -1 : 512-byte header
    sector  0 : single FAT sector
    sector  1..: directory sectors, one FAT chain
"""

from __future__ import print_function

import struct

from olefile import (
    MAGIC, ENDOFCHAIN, FREESECT, NOSTREAM,
    STGTY_EMPTY, STGTY_STORAGE, STGTY_STREAM, STGTY_ROOT,
)

ENTRY_SIZE = 128
SECTOR_SIZE = 512
STRUCT_DIRENTRY = '<64sHBBIII16sIQQIII'
STRUCT_HEADER = '<8s16sHHHHHHLLLLLLLLLL'

NOSTREAM_BYTES = struct.pack('<I', NOSTREAM)


def make_direntry(name='', entry_type=STGTY_EMPTY, color=1,
                  sid_left=NOSTREAM, sid_right=NOSTREAM,
                  sid_child=NOSTREAM, isect_start=0, size=0):
    """Build one raw 128-byte directory entry."""
    if entry_type == STGTY_EMPTY:
        raw = bytearray(ENTRY_SIZE)
        # unallocated entries: all zeroes except the three NOSTREAM pointers
        raw[68:72] = NOSTREAM_BYTES
        raw[72:76] = NOSTREAM_BYTES
        raw[76:80] = NOSTREAM_BYTES
        return bytes(raw)
    name_utf16 = name.encode('UTF-16LE')
    name_buffer = name_utf16 + b'\x00\x00'
    if len(name_buffer) > 64:
        raise ValueError('directory entry name too long: %r' % name)
    name_buffer = name_buffer.ljust(64, b'\x00')
    return struct.pack(
        STRUCT_DIRENTRY, name_buffer, len(name_utf16) + 2, entry_type, color,
        sid_left, sid_right, sid_child, b'\x00' * 16, 0, 0, 0,
        isect_start, size & 0xFFFFFFFF, (size >> 32) & 0xFFFFFFFF)


def build_cfb(entries):
    """
    Build a complete CFB file from a list of raw directory entries.

    :param entries: list of 128-byte directory entry strings; entry #0 must be
        a root storage entry.
    :returns: bytes containing a complete, parseable OLE file.
    """
    if not entries or len(entries) % 4:
        # directory sectors hold 4 entries each; pad with empty entries
        padding = (-len(entries)) % 4
        entries = entries + [make_direntry() for _ in range(padding)]
    nb_dir_sectors = len(entries) // 4
    dir_data = b''.join(entries)
    assert len(dir_data) == nb_dir_sectors * SECTOR_SIZE

    # sector 0 = FAT, sectors 1..nb_dir_sectors = directory
    fat_sector = 0
    first_dir_sector = 1
    total_sectors = 1 + nb_dir_sectors
    fat = [FREESECT] * total_sectors
    fat[fat_sector] = 0xFFFFFFFD  # FATSECT marker
    for index in range(nb_dir_sectors):
        sector = first_dir_sector + index
        if index < nb_dir_sectors - 1:
            fat[sector] = sector + 1
        else:
            fat[sector] = ENDOFCHAIN

    header = bytearray(SECTOR_SIZE)
    header_fields = (
        MAGIC,
        b'\x00' * 16,          # CLSID
        0x003E,                # minor version
        3,                     # DLL version (512-byte sectors)
        0xFFFE,                # byte order
        9,                     # sector shift -> 512
        6,                     # mini sector shift -> 64
        0,                     # reserved
        0,                     # reserved
        0,                     # number of directory sectors (must be 0 in v3)
        1,                     # number of FAT sectors
        first_dir_sector,      # first directory sector
        0,                     # transaction signature
        0x1000,                # mini stream cutoff
        ENDOFCHAIN,            # first mini FAT sector (none)
        0,                     # number of mini FAT sectors
        ENDOFCHAIN,            # first DIFAT sector (none)
        0,                     # number of DIFAT sectors
    )
    packed_header = struct.pack(STRUCT_HEADER, *header_fields)
    header[0:len(packed_header)] = packed_header
    # DIFAT: first of the 109 FAT sector slots points at the FAT sector
    header[76 + 0 * 4:76 + 1 * 4] = struct.pack('<I', fat_sector)
    # remaining DIFAT slots are NOSTREAM
    for slot in range(1, 109):
        header[76 + slot * 4:76 + (slot + 1) * 4] = NOSTREAM_BYTES

    fat_data = b''.join(struct.pack('<I', value) for value in fat)
    fat_data = fat_data.ljust(SECTOR_SIZE, b'\xFF')

    return bytes(header) + fat_data + dir_data
