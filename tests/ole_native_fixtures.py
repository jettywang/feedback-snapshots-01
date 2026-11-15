"""Helpers to build small in-memory OLE containers for Ole10Native tests.

The fixtures are generated as bytes, never written to disk.  They contain an
``ObjectPool`` storage with one or more Package storages, each holding an
``\\x01Ole10Native`` stream.
"""

import struct

SECTOR = 512
MINI = 64
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF
PACKAGE_CLSID = bytes.fromhex('0c00030000000000c000000000000046')
STGTY_STORAGE, STGTY_STREAM, STGTY_ROOT = 1, 2, 5
DIRENTRY = '<64sHBBIII16sIQQIII'


def _direntry(name, etype, right=NOSTREAM, child=NOSTREAM,
              clsid=b'\0' * 16, start=ENDOFCHAIN, size=0):
    raw = name.encode('utf-16le')
    assert len(raw) <= 62, name
    return struct.pack(DIRENTRY, raw + b'\0' * (64 - len(raw)),
                       len(raw) + 2, etype, 1, NOSTREAM, right, child, clsid,
                       0, 0, 0, start, size & 0xFFFFFFFF, size >> 32)


def _patch(entry, right=None, child=None, start=None, size=None):
    fields = list(struct.unpack(DIRENTRY, entry))
    if right is not None:
        fields[5] = right
    if child is not None:
        fields[6] = child
    if start is not None:
        fields[11] = start
    if size is not None:
        fields[12] = size & 0xFFFFFFFF
        fields[13] = size >> 32
    return struct.pack(DIRENTRY, *fields)


def build_cfb(packages, extra_tail=b''):
    """Build a CFB byte string.

    ``packages`` is a list of dicts: ``{'name': ..., 'clsid': bytes16,
    'streams': {name: bytes}}``.  ``extra_tail`` is appended verbatim after the
    last sector and is not described by the FAT.
    """
    minifat = []
    ministream = bytearray()

    def alloc_mini(data):
        if not data:
            return ENDOFCHAIN, 0
        count = (len(data) + MINI - 1) // MINI
        base = len(minifat)
        minifat.extend([FREESECT] * count)
        for i in range(count - 1):
            minifat[base + i] = base + i + 1
        minifat[base + count - 1] = ENDOFCHAIN
        ministream.extend(data + b'\0' * (count * MINI - len(data)))
        return base, len(data)

    entries = [_direntry('Root Entry', STGTY_ROOT, child=1),
               _direntry('ObjectPool', STGTY_STORAGE)]
    pkg_sids = []
    pkg_kids = []
    all_streams = []

    for package in packages:
        pkg_sid = len(entries)
        pkg_sids.append(pkg_sid)
        entries.append(_direntry(package['name'], STGTY_STORAGE,
                                 clsid=package.get('clsid', PACKAGE_CLSID)))
        kids = []
        for name, data in package['streams'].items():
            sid = len(entries)
            entry = _direntry(name, STGTY_STREAM)
            if len(data) < 4096:
                start, size = alloc_mini(data)
                entry = _patch(entry, start=start, size=size)
            else:
                entry = _patch(entry, start=None, size=len(data))
            entries.append(entry)
            kids.append(sid)
            all_streams.append({'sid': sid, 'data': data,
                                'mini': len(data) < 4096})
        pkg_kids.append(kids)

    entries[1] = _patch(entries[1], child=pkg_sids[0] if pkg_sids else NOSTREAM)
    for index, sid in enumerate(pkg_sids):
        right = pkg_sids[index + 1] if index + 1 < len(pkg_sids) else NOSTREAM
        kids = pkg_kids[index]
        entries[sid] = _patch(entries[sid], right=right,
                              child=kids[0] if kids else NOSTREAM)
        for kid_index, kid_sid in enumerate(kids):
            kid_right = kids[kid_index + 1] if kid_index + 1 < len(kids) else NOSTREAM
            entries[kid_sid] = _patch(entries[kid_sid], right=kid_right)

    dir_sectors = (len(entries) * 128 + SECTOR - 1) // SECTOR
    fat_sect = dir_sectors
    minifat_start = fat_sect + 1
    minifat_sectors = max(1, (len(minifat) * 4 + SECTOR - 1) // SECTOR)
    mini_start = minifat_start + minifat_sectors
    mini_bytes = bytes(ministream)
    mini_sectors = (len(mini_bytes) + SECTOR - 1) // SECTOR
    next_sector = mini_start + mini_sectors

    for stream in all_streams:
        if stream['mini']:
            continue
        count = (len(stream['data']) + SECTOR - 1) // SECTOR
        stream['start'] = next_sector
        entries[stream['sid']] = _patch(entries[stream['sid']],
                                        start=next_sector,
                                        size=len(stream['data']))
        next_sector += count
    total_sectors = next_sector
    entries[0] = _patch(entries[0],
                        start=mini_start if mini_bytes else ENDOFCHAIN,
                        size=len(mini_bytes))

    fat = [FREESECT] * (total_sectors + 1)
    for i in range(dir_sectors):
        fat[i] = i + 1 if i + 1 < dir_sectors else ENDOFCHAIN
    fat[fat_sect] = FATSECT
    for i in range(minifat_sectors):
        fat[minifat_start + i] = (minifat_start + i + 1
                                  if i + 1 < minifat_sectors else ENDOFCHAIN)
    for i in range(mini_sectors):
        fat[mini_start + i] = (mini_start + i + 1
                               if i + 1 < mini_sectors else ENDOFCHAIN)
    for stream in all_streams:
        if stream['mini']:
            continue
        count = (len(stream['data']) + SECTOR - 1) // SECTOR
        for i in range(count):
            fat[stream['start'] + i] = (stream['start'] + i + 1
                                        if i + 1 < count else ENDOFCHAIN)

    header = struct.pack('<8s16sHHHHHHLLLLLLLLLL',
                         bytes.fromhex('d0cf11e0a1b11ae1'), b'\0' * 16,
                         0x3e, 3, 0xfffe, 9, 6, 0, 0, 0, 1, 0, 0,
                         4096, minifat_start, minifat_sectors, ENDOFCHAIN, 0)
    assert len(header) == 76
    header += struct.pack('<I', fat_sect) + b'\xff' * 432

    out = bytearray(header)
    dir_bytes = b''.join(entries)
    out += dir_bytes + b'\0' * (dir_sectors * SECTOR - len(dir_bytes))
    fat_bytes = b''.join(struct.pack('<I', value) for value in fat)
    out += fat_bytes + b'\xff' * (SECTOR - len(fat_bytes))
    minifat_bytes = b''.join(struct.pack('<I', value) for value in minifat)
    out += minifat_bytes + b'\xff' * (minifat_sectors * SECTOR -
                                      len(minifat_bytes))
    if mini_bytes:
        out += mini_bytes + b'\0' * (mini_sectors * SECTOR - len(mini_bytes))
    for stream in all_streams:
        if stream['mini']:
            continue
        out += stream['data'] + b'\0' * ((-len(stream['data'])) % SECTOR)
    return bytes(out) + extra_tail


def cstring(value):
    return value.encode('latin-1') + b'\x00'


def utf16_block(value):
    raw = value.encode('utf-16-le')
    return struct.pack('<I', len(raw) // 2) + raw


def make_native(display_name, source_path, temp_path, native_data,
                format_id=2, include_native=True, declared_native_size=None,
                include_trailer=True, declared_container_size=None):
    """Build an OLENativeStream payload.

    ``declared_native_size`` overrides the native length field, and
    ``declared_container_size`` overrides the leading NativeDataSize.
    """
    body = struct.pack('<H', format_id)
    body += cstring(display_name)
    body += cstring(source_path)
    body += struct.pack('<I', 0x00030000)
    body += struct.pack('<I', len(cstring(temp_path)))
    body += cstring(temp_path)
    if include_native:
        if declared_native_size is None:
            declared_native_size = len(native_data)
        body += struct.pack('<I', declared_native_size)
        body += native_data
        if include_trailer:
            body += utf16_block(temp_path)
            body += utf16_block(display_name)
            body += utf16_block(source_path)
    if declared_container_size is None:
        declared_container_size = len(body)
    return struct.pack('<I', declared_container_size) + body


def make_reference_only(display_name, source_path, temp_path,
                        format_id=2):
    """Build the shorter reference-only shape with no native length field."""
    body = struct.pack('<H', format_id)
    body += cstring(display_name)
    body += cstring(source_path)
    body += struct.pack('<I', 0x00010000)
    body += struct.pack('<H', 1)
    body += cstring(temp_path)
    return struct.pack('<I', len(body)) + body


def make_container(native_payload, package_name='_pkg1',
                   storage_clsid=PACKAGE_CLSID, extra_tail=b''):
    return build_cfb([{'name': package_name,
                       'streams': {'\x01Ole10Native': native_payload},
                       'clsid': storage_clsid}], extra_tail=extra_tail)
