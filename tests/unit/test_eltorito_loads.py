# Regression tests for where an El Torito boot catalog says its boot loads live.
#
# The catalog's validation-entry checksum only proves the catalog sector was
# transcribed correctly.  It says nothing about whether the Initial/Default
# entry and the per-platform Section entries point at a real load on the
# medium, nor about how many bytes each entry claims to load.  These tests
# build small in-memory ISOs (no external boot images and no genisoimage),
# work out the expected logical-block location and byte span of every entry
# independently, and then check that parsing the ISO reproduces them.
#
# Two unit conversions are deliberately kept explicit throughout.  An ISO
# logical block is 2048 bytes, while an El Torito "virtual sector" in an entry
# is 512 bytes; an entry's declared load is therefore
#
#     load_rba * 2048 .. load_rba * 2048 + sector_count * 512
#
# and never sector_count * 2048.

import io
import os
import struct
import sys

import pytest

prefix = '.'
for i in range(0, 3):
    if os.path.isdir(os.path.join(prefix, 'pycdlib')):
        sys.path.insert(0, prefix)
        break
    else:
        prefix = '../' + prefix

import pycdlib
import pycdlib.eltorito

ISO_BLOCK_SIZE = 2048
VIRTUAL_SECTOR_SIZE = 512
# headervd.BootRecord.FMT is B5sB32s32s1977s, so the boot_system_use field
# (whose first four bytes hold the boot catalog extent) starts at offset 71 of
# the one-sector Boot Record.
BOOT_RECORD_EXTENT = 17
BOOT_SYSTEM_USE_OFFSET = 71
ENTRY_RECORD_SIZE = pycdlib.eltorito.EltoritoBootCatalog.ENTRY_SIZE
# Offsets inside a 32-byte El Torito Initial/Section entry record.
ENTRY_SECTOR_COUNT_OFFSET = 6
ENTRY_LOAD_RBA_OFFSET = 8
# Offset of the platform id inside a 32-byte Section Header record.
SECTION_HEADER_PLATFORM_OFFSET = 1


def _open_iso(data):
    iso = pycdlib.PyCdlib()
    iso.open_fp(io.BytesIO(data))
    return iso


def _catalog_extent(data):
    # Read the boot catalog's logical block location straight out of the Boot
    # Record rather than trusting the parsed object under test.
    offset = BOOT_RECORD_EXTENT * ISO_BLOCK_SIZE + BOOT_SYSTEM_USE_OFFSET
    return struct.unpack_from('<L', data, offset)[0]


def _catalog_sector(data, sector_index):
    extent = _catalog_extent(data)
    start = (extent + sector_index) * ISO_BLOCK_SIZE
    return data[start:start + ISO_BLOCK_SIZE]


def _entry_byte_span(load_rba, sector_count):
    # The independent expectation: which bytes of the medium an entry actually
    # covers, expressed as a half-open (start, end) byte range.
    start = load_rba * ISO_BLOCK_SIZE
    return start, start + sector_count * VIRTUAL_SECTOR_SIZE


def _all_parsed_entries(bc):
    # Every load-bearing entry, in catalog order: the Initial/Default entry,
    # then one entry per Section, then any standalone entries.
    entries = [bc.initial_entry]
    for section in bc.sections:
        entries.extend(section.section_entries)
    entries.extend(bc.standalone_entries)
    return entries


def _read_catalog_entries_independently(data):
    # Walk the boot catalog from its raw bytes without going through the
    # pycdlib parser, so the expected locations are computed by an independent
    # reader.  Returns (catalog_extent, expectations) where each expectation is
    # a dict describing one load-bearing entry.  The catalog runs until the
    # empty-entry terminator or the end of the data; entries never straddle a
    # 2048-byte sector boundary.
    catalog_extent = _catalog_extent(data)
    expectations = []
    record_index = 0
    sector_index = 0
    while True:
        sector = _catalog_sector(data, sector_index)
        if len(sector) < ISO_BLOCK_SIZE:
            break
        for offset in range(0, ISO_BLOCK_SIZE, ENTRY_RECORD_SIZE):
            record = sector[offset:offset + ENTRY_RECORD_SIZE]
            first = record[0]
            if record_index >= 2 and first == 0x00:
                # The empty entry terminates the catalog.
                return catalog_extent, expectations
            if record_index == 1 or (record_index >= 2 and first == 0x88):
                # Record 1 is the Initial/Default entry; later 0x88 records are
                # bootable Section entries (a section-less compatible catalog
                # exposes them as standalone entries, same on-disk layout).
                (_boot_indicator, _media_type, _load_segment, _system_type,
                 _unused, sector_count, load_rba, _sel_type,
                 _sel) = struct.unpack(pycdlib.eltorito.EltoritoEntry.FMT,
                                       record)
                start, end = _entry_byte_span(load_rba, sector_count)
                expectations.append({
                    'load_rba': load_rba,
                    'sector_count': sector_count,
                    'byte_start': start,
                    'byte_end': end,
                })
            record_index += 1
        sector_index += 1
    return catalog_extent, expectations


def _payload_path(index):
    # Interchange level 1 allows an 8-character name; P + 7 digits fits.
    return '/P%07d.;1' % index


def _payload_file(iso, index):
    record = iso.get_record(iso_path=_payload_path(index))
    return record.inode.extent_location(), record.inode.get_data_length()


def _build_iso(specs):
    # Master a small ISO in memory.  specs is a list of (payload_size,
    # add_eltorito_kwargs) tuples; the first payload is the Initial/Default
    # entry and the rest become Sections.  Returns the serialized ISO bytes.
    iso = pycdlib.PyCdlib()
    iso.new()
    for index, (payload_size, _kwargs) in enumerate(specs):
        payload = bytes([0x10 + (index % 240)]) * payload_size
        iso.add_fp(io.BytesIO(payload), payload_size, _payload_path(index))

    iso.add_eltorito(_payload_path(0), '/BOOT.CAT;1', **specs[0][1])
    for index, (_payload_size, kwargs) in enumerate(specs[1:], start=1):
        iso.add_eltorito(_payload_path(index), **kwargs)

    outfp = io.BytesIO()
    iso.write_fp(outfp)
    iso.close()
    return outfp.getvalue()


def _payload_layout(iso_data, specs):
    # Read each payload's allocated extent from its ordinary directory record.
    iso = _open_iso(iso_data)
    try:
        layout = []
        for index, (payload_size, _kwargs) in enumerate(specs):
            extent, data_length = _payload_file(iso, index)
            layout.append({
                'extent': extent,
                'payload_size': payload_size,
                'data_length': data_length,
            })
        return layout
    finally:
        iso.close()


def _patch_section_platforms(data, platform_ids):
    # add_eltorito only sets a Section Header platform to 0 or 0xef (the efi
    # flag); the other legal El Torito platforms (1=PPC, 2=Mac) have no authoring
    # shortcut, so patch the platform byte in each Section Header directly.
    # The validation-entry checksum covers only record 0, so this leaves the
    # catalog checksum valid while exercising distinct platform sections.
    catalog_base = _catalog_extent(data) * ISO_BLOCK_SIZE
    patched = bytearray(data)
    section_index = 0
    record_index = 2
    while section_index < len(platform_ids):
        first = patched[catalog_base + record_index * ENTRY_RECORD_SIZE]
        if first in (0x90, 0x91):
            platform = platform_ids[section_index]
            if platform is not None:
                patched[catalog_base + record_index * ENTRY_RECORD_SIZE
                        + SECTION_HEADER_PLATFORM_OFFSET] = platform
            section_index += 1
        record_index += 1
    assert section_index == len(platform_ids)
    return bytes(patched)


def test_initial_and_platform_section_load_locations():
    # An Initial/Default entry plus Sections for three different platforms.
    # Each entry's declared range must land on its payload file's logical
    # block, and the checksum-valid catalog alone must not count as proof.
    specs = [
        (2048, {}),                  # x86 Initial/Default
        (1024, {'efi': True}),       # UEFI (0xef) Section
        (1536, {}),                  # PowerPC (1) Section, patched below
        (512,  {}),                  # Mac (2) Section, patched below
    ]
    data = _patch_section_platforms(_build_iso(specs), [0xef, 1, 2])
    medium_size = len(data)

    catalog_extent, expected = _read_catalog_entries_independently(data)
    assert len(expected) == 4

    iso = _open_iso(data)
    try:
        bc = iso.eltorito_boot_catalog

        # The Boot Record's catalog pointer and the parsed catalog agree.
        assert bc.extent_location() == catalog_extent

        layout = _payload_layout(data, specs)
        parsed = _all_parsed_entries(bc)
        assert len(parsed) == len(expected)

        # Platforms survive on the Section Headers, including both non-x86
        # platform ids; dropping later Sections would make this fail.
        assert [sec.platform_id for sec in bc.sections] == [0xef, 1, 2]

        for entry, want, item in zip(parsed, expected, layout):
            start, end = _entry_byte_span(entry.load_rba, entry.sector_count)

            # Independent raw-catalog expectation matches the parsed entry.
            assert entry.load_rba == want['load_rba']
            assert entry.sector_count == want['sector_count']
            assert (start, end) == (want['byte_start'], want['byte_end'])

            # The load starts on the payload's allocated logical block.
            assert entry.load_rba == item['extent']
            assert start == item['extent'] * ISO_BLOCK_SIZE

            # And it is wholly inside the medium.
            assert start >= 0
            assert end <= medium_size
    finally:
        iso.close()


def test_catalog_spanning_sectors_keeps_every_section():
    # A catalog needs 2 + 2*N records for N sections; 33 sections need 68
    # records, which does not fit in one 64-record (2048-byte) sector.  The
    # catalog therefore spans two sectors, and every Section on the far side
    # of the boundary must still be parsed with its real load location.
    num_sections = 33
    specs = [(2048, {})]
    for i in range(num_sections):
        payload_size = VIRTUAL_SECTOR_SIZE * (1 + (i % 4))
        if i % 3 == 1:
            kwargs = {'efi': True}
        else:
            kwargs = {}
        specs.append((payload_size, kwargs))

    data = _build_iso(specs)
    catalog_extent, expected = _read_catalog_entries_independently(data)

    # The independent reader had to cross a sector boundary to see them all.
    assert len(expected) == num_sections + 1
    last_record_end = (2 + 2 * num_sections) * ENTRY_RECORD_SIZE
    assert last_record_end > ISO_BLOCK_SIZE

    iso = _open_iso(data)
    try:
        bc = iso.eltorito_boot_catalog
        assert bc.extent_location() == catalog_extent
        # A parser that stops at the first sector would report far fewer.
        assert len(bc.sections) == num_sections

        parsed = _all_parsed_entries(bc)
        assert len(parsed) == len(expected)
        for entry, want in zip(parsed, expected):
            start, end = _entry_byte_span(entry.load_rba, entry.sector_count)
            assert entry.load_rba == want['load_rba']
            assert entry.sector_count == want['sector_count']
            assert (start, end) == (want['byte_start'], want['byte_end'])
            assert end <= len(data)
    finally:
        iso.close()


def test_declared_load_count_is_in_512_byte_virtual_sectors():
    # sector_count counts 512-byte virtual sectors, not 2048-byte ISO blocks.
    # A 2048-byte no-emulation payload therefore declares 4 virtual sectors and
    # a 2048-byte load; treating the count as ISO blocks would claim 8192 bytes.
    data = _build_iso([(2048, {}), (512, {'efi': True})])

    _catalog_extent, expected = _read_catalog_entries_independently(data)

    iso = _open_iso(data)
    try:
        initial = iso.eltorito_boot_catalog.initial_entry
        assert initial.sector_count == 4
        assert initial.length() == 4 * VIRTUAL_SECTOR_SIZE == 2048

        start, end = _entry_byte_span(initial.load_rba, initial.sector_count)
        assert end - start == 2048
        # The concrete wrong answer a block-count bug would produce.
        assert end - start != initial.sector_count * ISO_BLOCK_SIZE

        efi_entry = iso.eltorito_boot_catalog.sections[0].section_entries[0]
        efi_start, efi_end = _entry_byte_span(efi_entry.load_rba,
                                              efi_entry.sector_count)
        assert efi_end - efi_start == efi_entry.sector_count * VIRTUAL_SECTOR_SIZE

        for entry, want in zip(_all_parsed_entries(iso.eltorito_boot_catalog),
                               expected):
            assert entry.sector_count == want['sector_count']
    finally:
        iso.close()


def test_load_range_exactly_at_medium_boundary_is_verified():
    # The EFI payload occupies the final logical block.  Set its entry to
    # declare four virtual sectors there, so the 4*512 = 2048-byte load fills
    # that block and ends precisely at end of medium: a fully covered,
    # verifiable load.
    data = _build_iso([(2048, {}), (512, {'efi': True})])
    medium_size = len(data)
    last_block = medium_size // ISO_BLOCK_SIZE - 1
    catalog_base = _catalog_extent(data) * ISO_BLOCK_SIZE
    # Record 3 is the single Section Entry (validation, initial, header, entry).
    section_record = catalog_base + 3 * ENTRY_RECORD_SIZE

    boundary = bytearray(data)
    assert struct.unpack_from('<L', boundary,
                              section_record + ENTRY_LOAD_RBA_OFFSET)[0] == last_block
    struct.pack_into('<H', boundary,
                     section_record + ENTRY_SECTOR_COUNT_OFFSET, 4)

    iso = _open_iso(bytes(boundary))
    try:
        entry = iso.eltorito_boot_catalog.sections[0].section_entries[0]
        start, end = _entry_byte_span(entry.load_rba, entry.sector_count)
        assert entry.load_rba == last_block
        assert entry.sector_count == 4
        assert start == last_block * ISO_BLOCK_SIZE
        assert end == medium_size
        with pycdlib.inode.InodeOpenData(entry.inode,
                                         ISO_BLOCK_SIZE) as (data_fp, _len):
            assert len(data_fp.read(end - start)) == end - start
    finally:
        iso.close()


def test_load_range_running_past_medium_is_not_verified():
    # Take the same final-block entry and inflate its declared count to five
    # virtual sectors.  The range now runs 512 bytes past end of medium.  The
    # catalog checksum is still valid, so a checksum-only check would wrongly
    # accept it; reading the declared load instead returns a short read,
    # proving it cannot be treated as a verified load.
    data = _build_iso([(2048, {}), (512, {'efi': True})])
    medium_size = len(data)
    last_block = medium_size // ISO_BLOCK_SIZE - 1
    catalog_base = _catalog_extent(data) * ISO_BLOCK_SIZE
    # Record 3 is the single Section Entry (validation, initial, header, entry).
    section_record = catalog_base + 3 * ENTRY_RECORD_SIZE

    overrun = bytearray(data)
    struct.pack_into('<H', overrun,
                     section_record + ENTRY_SECTOR_COUNT_OFFSET, 5)

    _extent, expected = _read_catalog_entries_independently(bytes(overrun))
    overrun_entry = expected[-1]
    assert overrun_entry['load_rba'] == last_block
    assert overrun_entry['byte_end'] > medium_size

    iso = _open_iso(bytes(overrun))
    try:
        entry = iso.eltorito_boot_catalog.sections[0].section_entries[0]
        start, end = _entry_byte_span(entry.load_rba, entry.sector_count)
        # The raw catalog and the parser agree about what was declared...
        assert (start, end) == (overrun_entry['byte_start'],
                                overrun_entry['byte_end'])
        # ...but the declaration cannot be treated as a verified load.
        assert start == last_block * ISO_BLOCK_SIZE
        assert end > medium_size
        with pycdlib.inode.InodeOpenData(entry.inode,
                                         ISO_BLOCK_SIZE) as (data_fp, _len):
            delivered = data_fp.read(end - start)
        assert len(delivered) < end - start
        assert start + len(delivered) == medium_size
    finally:
        iso.close()


def test_load_range_past_medium_is_not_verified():
    # A load_rba that points beyond the medium entirely.  There is no inode
    # there, so probing it for a boot info table raises; whatever the exact
    # exception, the entry must never count as a verified in-medium load.
    data = _build_iso([(2048, {}), (1024, {'efi': True})])
    medium_size = len(data)
    catalog_base = _catalog_extent(data) * ISO_BLOCK_SIZE
    section_entry_record = catalog_base + 3 * ENTRY_RECORD_SIZE

    bogus = bytearray(data)
    struct.pack_into('<L', bogus, section_entry_record + ENTRY_LOAD_RBA_OFFSET,
                     0xFFFF)

    # Today this surfaces as a bare struct.error because the parser never
    # bounds-checks an entry's range before reading its phantom inode.
    with pytest.raises(Exception):
        _open_iso(bytes(bogus))

    # Independently confirm that the declared range starts past end of medium,
    # so the failure is an out-of-medium load rather than some unrelated parse
    # error in the catalog itself.
    _extent, expected = _read_catalog_entries_independently(bytes(bogus))
    assert expected[-1]['byte_start'] >= medium_size
    assert expected[-1]['byte_end'] > medium_size


def test_standalone_entry_from_compatible_catalog_is_kept_and_checked():
    # El Torito 2.4 wants a Section Header before every Section Entry, but ISOs
    # in the wild (e.g. Mageia 4) omit it.  pycdlib deliberately keeps such an
    # entry as a standalone entry rather than dropping it; its load location
    # still has to be verified like any other entry.
    data = _build_iso([(2048, {}), (1024, {'efi': True})])
    catalog_base = _catalog_extent(data) * ISO_BLOCK_SIZE

    compatible = bytearray(data)
    # Record 2 is the Section Header; overwrite it with the bytes of its own
    # entry (record 3), so the section loses its header and both entries become
    # standalone.
    compatible[catalog_base + 2 * ENTRY_RECORD_SIZE:
               catalog_base + 3 * ENTRY_RECORD_SIZE] = bytes(
        data[catalog_base + 3 * ENTRY_RECORD_SIZE:
             catalog_base + 4 * ENTRY_RECORD_SIZE])

    _extent, expected = _read_catalog_entries_independently(bytes(compatible))

    iso = _open_iso(bytes(compatible))
    try:
        bc = iso.eltorito_boot_catalog
        assert len(bc.sections) == 0
        assert len(bc.standalone_entries) == 2

        parsed = _all_parsed_entries(bc)
        assert len(parsed) == len(expected)
        for entry, want in zip(parsed, expected):
            start, end = _entry_byte_span(entry.load_rba, entry.sector_count)
            assert entry.load_rba == want['load_rba']
            assert (start, end) == (want['byte_start'], want['byte_end'])
            assert end <= len(compatible)
    finally:
        iso.close()


def test_missing_section_entry_is_not_verified():
    # A Section Header that promises one entry, followed by the empty
    # terminator instead: the promised load simply does not exist, so it cannot
    # be treated as verified even though the validation-entry checksum is fine.
    data = _build_iso([(2048, {}), (1024, {'efi': True})])
    catalog_base = _catalog_extent(data) * ISO_BLOCK_SIZE

    missing = bytearray(data)
    missing[catalog_base + 3 * ENTRY_RECORD_SIZE:
            catalog_base + 4 * ENTRY_RECORD_SIZE] = b'\x00' * ENTRY_RECORD_SIZE

    with pytest.raises(pycdlib.pycdlibexception.PyCdlibInvalidISO) as excinfo:
        _open_iso(bytes(missing))
    assert 'section header specified 1 entries, only saw 0' in str(excinfo.value)
