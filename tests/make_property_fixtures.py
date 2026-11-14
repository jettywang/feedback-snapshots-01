# -*- coding: utf-8 -*-
"""
Generate synthetic OLE (Compound File Binary) test materials for the
fidelity property inspection (OleFileIO.inspect_property_sets).

Two files are written into tests/fixtures:

- properties-overlap.doc: a property set stream in which two property
  identifiers consume the same bytes (duplicate id and overlapping values),
  plus entries pointing at the index table and another section.
- properties-multisection.doc: a legal two-section property set stream,
  including a property-name dictionary in the second section.

The generator only depends on the Python standard library.
"""

from __future__ import print_function

import os
import struct

import sys
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from olefile.olefile import (  # noqa: E402
    MAGIC, ENDOFCHAIN, FREESECT, FATSECT, NOSTREAM,
    STGTY_ROOT, STGTY_STREAM,
)

SECTOR_SIZE = 512
DIR_ENTRY_SIZE = 128
MINI_CUTOFF = 4096

# well-known format ids used by the Summary / DocumentSummary streams:
FMTID_SUMMARY = b'\xe0\x85\x9f\xf2\xf9\x4f\x68\x10\xab\x91\x08\x00\x2b\x27\xb3\xd9'
FMTID_DOCSUM = b'\x02\xd5\xcd\xd5\x9c\x2e\x1b\x10\x93\x97\x08\x00\x2b\x2c\xf9\xae'
FMTID_USERDEF = b'\x05\xd5\xcd\xd5\x9c\x2e\x1b\x10\x93\x97\x08\x00\x2b\x2c\xf9\xae'


def align4(data):
    """Pad a bytes string up to the next 4-byte boundary."""
    remainder = len(data) % 4
    if remainder:
        data += b'\x00' * (4 - remainder)
    return data


# ---------------------------------------------------------------------------
# Property set stream construction
# ---------------------------------------------------------------------------

def build_section(rows, payload, num_props=None):
    """
    Build one property set section.

    The section starts with its size field (included in the size).
    :param rows: list of (property_id, offset) identifier table rows; their
        offsets are absolute relative to the returned section
    :param payload: all bytes after the size field, already laid out at the
        absolute offsets referenced by rows (identifier table, optional
        dictionary and value area)
    :param num_props: declared property count, defaults to len(rows)
    """
    if num_props is None:
        num_props = len(rows)
    body = struct.pack('<I', num_props)
    for property_id, offset in rows:
        body += struct.pack('<II', property_id, offset)
    body += payload
    return struct.pack('<I', len(body) + 4) + body


def build_stream(sections):
    """Assemble a complete PropertySetStream from section payloads."""
    csections = len(sections)
    # [MS-OLEPS] PropertySetStream header:
    # byte order(2) + version(2) at 0, reserved dword(4) at 4,
    # clsid(16) at 8, csections(4) at 24 -> 28 bytes total
    header = struct.pack('<HHI', 0xFFFE, 0x0001, 0)
    header += b'\x00' * 16                            # clsid
    header += struct.pack('<I', csections)
    assert len(header) == 28
    section_array = b''
    offset = 28 + 20 * csections
    payload = b''
    for fmtid, section in sections:
        section_array += fmtid + struct.pack('<I', offset)
        payload += section
        offset += len(section)
    return header + section_array + payload


# ---------------------------------------------------------------------------
# Fixture 1: duplicate id and two properties sharing the same bytes
# ---------------------------------------------------------------------------

def build_overlap_stream():
    # payload layout (offsets absolute within the section, whose first 4
    # bytes are the size field):
    #   0x04: property count, 0x08..0x40: 7 identifier rows (56 bytes)
    #   0x44: type tag + 4-byte integer value (8 bytes total)
    shared_i4 = struct.pack('<Ii', 3, 0x11223344)           # offset 0x44
    next_i4 = struct.pack('<Ii', 3, 0x55667788)             # offset 0x4C
    # 0x54: unknown-length type (VT_STREAM=66); only 4 bytes of evidence
    unknown = struct.pack('<I', 66) + b'\xAA\xBB\xCC\xDD'   # offset 0x54
    # 0x5C: a valid integer following the unknown-length value, proving its
    # boundary was not guessed:
    after_unknown = struct.pack('<Ii', 3, 0x77777777)       # offset 0x5C
    # build_section already emits size + count + the 7 rows, which occupy
    # section offsets 0x00..0x40; pad the payload up to the first value:
    payload = b'\x00' * (0x44 - 0x40)  # 4 bytes of padding
    payload += shared_i4 + next_i4 + unknown + after_unknown
    payload = align4(payload)                               # ends at 0x64

    rows = [
        (1, 0x44),    # normal integer
        (2, 0x44),    # same bytes -> overlapping values, distinct id
        (1, 0x4C),    # duplicate id 1, different value
        (3, 0x0C),    # offset points inside the identifier table
        (4, 0x98),    # offset beyond section 1 (lands inside section 2)
        (5, 0x54),    # unknown-length type, evidence must stay bounded
        (6, 0x5C),    # valid property after the unknown-length one
    ]
    section_a = build_section(rows, payload)

    # second section: a code page entry (id 0) with a property-name
    # dictionary, plus one normal value and one offset pointing into the
    # dictionary. size + count + 3 rows end at section offset 0x20, and the
    # 30-byte dictionary occupies 0x20..0x3E.
    dictionary = struct.pack('<I', 1)                    # one named entry
    dictionary += struct.pack('<II', 100, 18)           # id 100, 18 bytes
    dictionary += 'DictName'.encode('utf-16-le') + b'\x00\x00'  # 8 + null
    assert len(dictionary) == 30                         # 0x20..0x3E

    section_b_payload = dictionary
    # VT_I2 code page token starts at section offset 0x3E (6 bytes), then 2
    # padding bytes; the VT_I4 type tag is at 0x46 and its value at 0x4A:
    section_b_payload += struct.pack('<Ii', 2, 1252) + b'\x00\x00'
    section_b_payload += struct.pack('<Ii', 3, 0x01020304)
    section_b_payload = align4(section_b_payload)
    # row id 101 deliberately points at 0x28, inside the dictionary:
    section_b = build_section([(0, 0x3E), (100, 0x48), (101, 0x28)],
                              section_b_payload)

    return build_stream([(FMTID_SUMMARY, section_a),
                         (FMTID_DOCSUM, section_b)])


# ---------------------------------------------------------------------------
# Fixture 2: legal multi-section stream with a property-name dictionary
# ---------------------------------------------------------------------------

def build_multisection_stream():
    # section 0: two standard properties, no dictionary.
    # identifier table (incl. size + count) ends at 0x18.
    section_a_payload = b''
    section_a_payload += struct.pack('<Ii', 3, 7)                  # id 1 @0x18
    section_a_payload += struct.pack('<II', 30, 6) + b'hello\x00'  # id 2 @0x20
    section_a_payload = align4(section_a_payload)
    section_a = build_section([(1, 0x18), (2, 0x20)],
                              section_a_payload)

    # section 1: code page (id 0) plus a property-name dictionary.
    # build_section emits size + count + 3 rows up to section offset 0x20.
    # The 36-byte dictionary then occupies 0x20..0x44 and values start at
    # 0x44.
    dictionary = struct.pack('<I', 1)                    # one named entry
    # id 2, name length in bytes (11 chars + null terminator = 24 bytes):
    dictionary += struct.pack('<II', 2, 24)
    dictionary += 'Custom Name'.encode('utf-16-le') + b'\x00\x00'
    assert len(dictionary) == 36                         # 0x20..0x44

    section_b_payload = dictionary
    section_b_payload += struct.pack('<Ii', 2, 1252)               # id 0 @0x44
    # LPWSTR: type(4) + char count(4) + 3 UTF-16 chars (6 bytes) = 14
    # bytes, followed by 2 padding bytes to 4-byte alignment; the next
    # value starts at 0x5C (the measure stays 14 bytes, excluding padding):
    section_b_payload += struct.pack('<II', 31, 3) \
        + 'abc'.encode('utf-16-le') + b'\x00\x00'                 # id 2 @0x4C
    section_b_payload += struct.pack('<Ii', 3, 42)                 # id 3 @0x5C
    section_b_payload = align4(section_b_payload)
    section_b = build_section([(0, 0x44), (2, 0x4C), (3, 0x5C)],
                              section_b_payload)

    return build_stream([(FMTID_SUMMARY, section_a),
                         (FMTID_USERDEF, section_b)])


# ---------------------------------------------------------------------------
# Minimal CFB writer (512-byte sectors, FAT streams only, no mini stream)
# ---------------------------------------------------------------------------

def dir_entry(name, entry_type, start, size, color=0,
              left=NOSTREAM, right=NOSTREAM, child=NOSTREAM):
    name_utf16 = name.encode('utf-16-le') + b'\x00\x00'
    namelength = len(name_utf16)
    entry = struct.pack('<64s', name_utf16)
    entry += struct.pack('<HBBIII', namelength, entry_type, color,
                         left, right, child)
    entry += b'\x00' * 16                    # clsid
    entry += struct.pack('<I', 0)            # user flags
    entry += struct.pack('<QQ', 0, 0)        # create / modify times
    entry += struct.pack('<III', start, size & 0xFFFFFFFF,
                         (size >> 32) & 0xFFFFFFFF)
    assert len(entry) == DIR_ENTRY_SIZE
    return entry


def build_cfb(streams):
    """
    :param streams: ordered list of (name, data); data is padded so each
        stream occupies whole 512-byte sectors and is >= 4096 bytes (FAT).
    """
    # Physical layout: header (no sector), sector 0 = FAT, sector 1 =
    # directory, sectors 2... = stream data. The FAT must match this.
    data_layout = []
    next_sector = 2
    fat = [FATSECT, ENDOFCHAIN]
    for name, data in data_padded(streams):
        chain = []
        nb = len(data) // SECTOR_SIZE
        for _ in range(nb):
            chain.append(next_sector)
            fat.append(FREESECT)
            next_sector += 1
        for index, sector in enumerate(chain):
            fat[sector] = chain[index + 1] if index + 1 < len(chain) \
                else ENDOFCHAIN
        data_layout.append((name, data, chain[0], len(data)))

    # directory occupies one sector (4 entries):
    root = dir_entry('Root Entry', STGTY_ROOT, NOSTREAM, 0,
                     child=1)
    directory = root
    for index, (name, data, start, size) in enumerate(data_layout):
        # simple tree under root; with two entries use sid 1 as root child
        # and sid 2 as its right sibling, no red/black balancing needed
        directory += dir_entry(
            name, STGTY_STREAM, start, size,
            right=2 if (index == 0 and len(data_layout) > 1) else NOSTREAM)
    while len(directory) < SECTOR_SIZE:
        directory += b'\x00'

    # header
    header = MAGIC
    header += b'\x00' * 16
    header += struct.pack('<6H', 0x003E, 0x0003, 0xFFFE, 9, 6, 0)
    header += struct.pack('<8I',
                          0,                     # reserved1
                          0,                     # number of dir sectors
                          1,                     # number of FAT sectors
                          1,                     # first directory sector
                          0,                     # transaction signature
                          MINI_CUTOFF,           # mini stream cutoff
                          NOSTREAM, 0,           # mini FAT start / count
                          )
    header += struct.pack('<II', ENDOFCHAIN, 0)  # DIFAT start / count
    assert len(header) == 76
    difat = [0] + [FREESECT] * 108
    header += struct.pack('<109I', *difat)
    assert len(header) == SECTOR_SIZE

    output = header
    # one FAT sector, padded with free entries:
    fat_entries = SECTOR_SIZE // 4
    while len(fat) < fat_entries:
        fat.append(FREESECT)
    fat_sector = struct.pack('<128I', *fat[:fat_entries])
    output += fat_sector
    output += directory
    for name, data, start, size in data_layout:
        output += data
    return output


def data_padded(streams):
    padded = []
    for name, data in streams:
        if len(data) < MINI_CUTOFF:
            data = data + b'\x00' * (MINI_CUTOFF - len(data))
        remainder = len(data) % SECTOR_SIZE
        if remainder:
            data += b'\x00' * (SECTOR_SIZE - remainder)
        padded.append((name, data))
    return padded


def main():
    fixtures_dir = os.path.join(_thismodule_dir, 'fixtures')
    if not os.path.isdir(fixtures_dir):
        os.makedirs(fixtures_dir)

    overlap = build_cfb([
        ('\x05SummaryInformation', build_overlap_stream()),
    ])
    multisection = build_cfb([
        ('\x05DocumentSummaryInformation', build_multisection_stream()),
    ])

    overlap_path = os.path.join(fixtures_dir, 'properties-overlap.doc')
    multi_path = os.path.join(fixtures_dir, 'properties-multisection.doc')
    with open(overlap_path, 'wb') as fp:
        fp.write(overlap)
    with open(multi_path, 'wb') as fp:
        fp.write(multisection)
    print('wrote %s (%d bytes)' % (overlap_path, len(overlap)))
    print('wrote %s (%d bytes)' % (multi_path, len(multisection)))


if __name__ == '__main__':
    main()
