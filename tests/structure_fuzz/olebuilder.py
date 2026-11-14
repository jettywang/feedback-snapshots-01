"""
Independent, deterministic builder for minimal OLE2/CFB compound files.

This module is *not* part of olefile: it constructs valid compound binary
files from scratch (following [MS-CFB]) so that the fuzzing tests in
``test_structure_fuzz.py`` start from files whose exact byte layout and stream
contents are known and independently verifiable.

The builder deliberately keeps every fixture tiny (a handful of 512-byte
sectors) and exposes the structural metadata (FAT, MiniFAT, DIFAT, directory
locations) so that mutators can target a single structural element at a time.

Only the version-3, 512-byte sector / 64-byte mini-sector layout is generated,
which is exactly the layout olefile validates most strictly.
"""

from __future__ import print_function

import struct

# --- CFB constants (duplicated on purpose so the builder stays independent) ---
SECTOR_SIZE = 512
MINI_SECTOR_SIZE = 64
ENTRIES_PER_FAT_SECTOR = SECTOR_SIZE // 4          # 128
DIFAT_POINTERS_PER_SECTOR = SECTOR_SIZE // 4 - 1   # 127
HEADER_DIFAT_ENTRIES = 109
DIR_ENTRY_SIZE = 128
MINI_CUTOFF = 0x1000                               # 4096
MAGIC = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'

ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF

STGTY_EMPTY = 0
STGTY_STORAGE = 1
STGTY_STREAM = 2
STGTY_ROOT = 5

STRUCT_DIRENTRY = '<64sHBBIII16sIQQIII'


def _lcg_stream_bytes(stream_id, length):
    """Deterministic, distinct, high-entropy payload for a stream.

    A fixed linear-congruential generator keyed by ``stream_id`` yields
    reproducible bytes that differ between streams and across offsets, so a
    reader that returns another stream's bytes (or stale/zero padding) is
    detectable by a simple equality check.

    A unique 16-byte tag derived from ``stream_id`` is embedded every 64 bytes;
    the tag space is disjoint between streams, which lets the oracle prove that
    bytes returned for stream X never originate from another stream.
    """
    state = (0x9E3779B9 ^ (stream_id * 0x85EBCA6B)) & 0xFFFFFFFF
    out = bytearray(length)
    tag = (b'TAG!' + bytes([0xA0 ^ stream_id, stream_id & 0xFF, 0x55, 0xC3])
           + struct.pack('>Q', 0x0102030405060708 ^ (stream_id * 0x01000193)))
    assert len(tag) == 16
    for i in range(length):
        state = (state * 1664525 + 1013904223 + stream_id) & 0xFFFFFFFF
        out[i] = (state >> 16) & 0xFF
        if i % 64 < 16:
            out[i] = tag[i % 64]
    return bytes(out)


def stream_tag(stream_id):
    """Return the unique 16-byte tag embedded in stream ``stream_id``."""
    return _lcg_stream_bytes(stream_id, 16)


class StreamSpec(object):
    """Description of one user stream to place in the compound file."""

    def __init__(self, name, size, stream_id):
        self.name = name
        self.size = size
        self.stream_id = stream_id
        self.content = _lcg_stream_bytes(stream_id, size)
        # FAT/MiniFAT bookkeeping, filled in while building:
        self.mini = size < MINI_CUTOFF
        self.first_sect = ENDOFCHAIN
        self.chain = []          # sector indexes (FAT sectors or mini sectors)


class CompoundFile(object):
    """A built compound file: raw bytes plus a map of its structure."""

    def __init__(self, data, layout):
        self.data = data
        self.layout = layout

    # -- convenient byte-level accessors used by the mutators ---------------
    def fat_entry_file_offset(self, fat_index):
        """File offset of FAT entry ``fat_index`` (inside a FAT sector)."""
        fat_sect_no = fat_index // ENTRIES_PER_FAT_SECTOR
        fat_file_sect = self.layout['fat_sector_ids'][fat_sect_no]
        return SECTOR_SIZE * (fat_file_sect + 1) + 4 * (fat_index % ENTRIES_PER_FAT_SECTOR)

    def minifat_entry_file_offset(self, mini_index):
        """File offset of MiniFAT entry ``mini_index``."""
        mf = self.layout['minifat_sector_ids'][0]
        return SECTOR_SIZE * (mf + 1) + 4 * mini_index

    def direntry_file_offset(self, sid):
        """File offset of the 128-byte directory entry with index ``sid``."""
        directory_sect = self.layout['directory_sector_ids'][sid // (SECTOR_SIZE // DIR_ENTRY_SIZE)]
        return SECTOR_SIZE * (directory_sect + 1) + DIR_ENTRY_SIZE * (sid % 4)

    def difat_sector_file_offset(self, difat_sector_index):
        return SECTOR_SIZE * (self.layout['difat_sector_ids'][difat_sector_index] + 1)

    def sector_file_offset(self, sect):
        return SECTOR_SIZE * (sect + 1)


def _direntry(name, entry_type, color=1, left=NOSTREAM, right=NOSTREAM,
              child=NOSTREAM, start=ENDOFCHAIN, size=0):
    name_utf16 = name.encode('utf-16-le') + b'\x00\x00'
    namelength = len(name_utf16)
    raw = name_utf16.ljust(64, b'\x00')
    return struct.pack(STRUCT_DIRENTRY, raw, namelength, entry_type, color,
                       left, right, child, b'\x00' * 16, 0, 0, 0,
                       start, size & 0xFFFFFFFF, (size >> 32) & 0xFFFFFFFF)


def _count_fat_sectors(nb_data_sectors):
    """Fixed point: total sectors = data sectors + FAT sectors, and every FAT
    sector holds 128 entries."""
    nf = 1
    while True:
        needed = (nb_data_sectors + nf + ENTRIES_PER_FAT_SECTOR - 1) // ENTRIES_PER_FAT_SECTOR
        if needed == nf:
            return nf
        nf = needed


def build_compound_file(streams, force_difat=False, gap_sectors=0, seed=0):
    """Construct a valid, minimal CFB file containing ``streams``.

    :param streams: list of ``StreamSpec`` objects.
    :param force_difat: if True, pad with free regular sectors so that more
        than 109 FAT sectors are required and a real DIFAT sector chain is
        emitted and traversed.
    :param gap_sectors: number of FREESECT sectors sprinkled between data
        chains (keeps chains non-contiguous, exercising real chain walking).
    :param seed: deterministic selector for where gap sectors are placed.
    :returns: :class:`CompoundFile`.
    """
    sectors = []          # file sector index -> 512-byte content
    fat = []              # FAT value for each allocated sector
    stream_fat_chains = {}
    stream_mini_chains = {}

    def allocate(content=b'\x00' * SECTOR_SIZE, mark=ENDOFCHAIN):
        idx = len(sectors)
        sectors.append(content)
        fat.append(mark)
        return idx

    def build_fat_chain(content):
        """Lay ``content`` (>= cutoff) across regular FAT sectors."""
        chain = []
        first = None
        prev = None
        for off in range(0, len(content), SECTOR_SIZE):
            chunk = content[off:off + SECTOR_SIZE]
            chunk = chunk.ljust(SECTOR_SIZE, b'\x00')
            idx = allocate(chunk)
            chain.append(idx)
            if first is None:
                first = idx
            if prev is not None:
                fat[prev] = idx
            prev = idx
        return first, chain

    # 1) regular (>= 4096 byte) streams first
    for spec in streams:
        if not spec.mini:
            first, chain = build_fat_chain(spec.content)
            spec.first_sect = first
            spec.chain = chain
            stream_fat_chains[spec.name] = chain
            for _ in range(gap_sectors):
                allocate(b'\x00' * SECTOR_SIZE, mark=FREESECT)

    # 2) mini stream container (root stream): pack every mini stream's payload
    #    into 64-byte mini sectors inside one regular FAT chain.
    mini_specs = [s for s in streams if s.mini]
    mini_payload = bytearray()
    mini_cursor = 0
    for spec in mini_specs:
        first_mini = mini_cursor
        n_mini = (spec.size + MINI_SECTOR_SIZE - 1) // MINI_SECTOR_SIZE
        mini_payload += spec.content
        # pad each mini stream to a whole mini sector
        used = spec.size % MINI_SECTOR_SIZE
        if used:
            mini_payload += b'\x00' * (MINI_SECTOR_SIZE - used)
        mini_cursor += n_mini
        spec.first_sect = first_mini
        spec.chain = list(range(first_mini, first_mini + n_mini))
        stream_mini_chains[spec.name] = spec.chain
    total_mini_sectors = mini_cursor
    root_size = total_mini_sectors * MINI_SECTOR_SIZE
    mini_payload = bytes(mini_payload.ljust(root_size, b'\x00'))

    if root_size:
        root_first, root_chain = build_fat_chain(mini_payload)
    else:
        root_first, root_chain = ENDOFCHAIN, []

    # 3) MiniFAT sector(s): one pointer per mini sector
    minifat_values = [FREESECT] * total_mini_sectors
    for spec in mini_specs:
        for j, msid in enumerate(spec.chain):
            minifat_values[msid] = spec.chain[j + 1] if j + 1 < len(spec.chain) else ENDOFCHAIN
    num_minifat_sectors = 0
    minifat_sector_ids = []
    if total_mini_sectors:
        num_minifat_sectors = 1
        mf_content = (b''.join(struct.pack('<I', v) for v in minifat_values)
                      ).ljust(SECTOR_SIZE, b'\x00')
        minifat_sector_ids.append(allocate(mf_content))

    # 4) directory sectors (4 entries of 128 bytes each)
    n_dir_sectors = max(1, (len(streams) + 1 + 3) // 4)
    directory_entries = [_direntry('Root Entry', STGTY_ROOT,
                                   child=1 if streams else NOSTREAM,
                                   start=root_first, size=root_size)]
    # left-leaning red-black tree over the user streams (SIDs 1..N)
    for k, spec in enumerate(streams):
        sid = k + 1
        left = sid + 1 if k + 1 < len(streams) else NOSTREAM
        directory_entries.append(_direntry(
            spec.name, STGTY_STREAM, left=left,
            start=spec.first_sect, size=spec.size))
    while len(directory_entries) < 4 * n_dir_sectors:
        directory_entries.append(b'\x00' * DIR_ENTRY_SIZE)
    directory_sector_ids = []
    for k in range(n_dir_sectors):
        block = b''.join(directory_entries[k * 4:(k + 1) * 4])
        directory_sector_ids.append(allocate(block.ljust(SECTOR_SIZE, b'\x00')))
    first_dir_sector = directory_sector_ids[0]
    for j in range(n_dir_sectors - 1):
        fat[directory_sector_ids[j]] = directory_sector_ids[j + 1]

    # 5) optional DIFAT: pad with free sectors until >109 FAT sectors needed
    difat_sector_ids = []
    if force_difat:
        while True:
            nf_now = _count_fat_sectors(len(sectors))
            if nf_now > HEADER_DIFAT_ENTRIES:
                break
            allocate(b'\x00' * SECTOR_SIZE, mark=FREESECT)

    # 6) FAT sectors
    nb_data_sectors = len(sectors)
    num_fat_sectors = _count_fat_sectors(nb_data_sectors)
    fat_values = list(fat)
    # FAT sectors mark themselves; DIFAT sectors get DIFSECT once allocated.
    fat_sector_ids = []
    for _ in range(num_fat_sectors):
        fat_sector_ids.append(allocate(b'\x00' * SECTOR_SIZE, mark=FATSECT))

    use_difat = force_difat and num_fat_sectors > HEADER_DIFAT_ENTRIES
    if use_difat:
        # allocate DIFAT sectors (each lists 127 FAT sectors + next pointer)
        nb_difat = (num_fat_sectors - HEADER_DIFAT_ENTRIES
                    + DIFAT_POINTERS_PER_SECTOR - 1) // DIFAT_POINTERS_PER_SECTOR
        for _ in range(nb_difat):
            difat_sector_ids.append(allocate(b'\x00' * SECTOR_SIZE, mark=DIFSECT))
        # re-count FAT sectors because DIFAT sectors themselves need entries
        num_fat_sectors_2 = _count_fat_sectors(len(sectors))
        if num_fat_sectors_2 != num_fat_sectors:
            # rare fixed-point growth: add the extra FAT sector(s)
            for _ in range(num_fat_sectors_2 - num_fat_sectors):
                fat_sector_ids.append(allocate(b'\x00' * SECTOR_SIZE, mark=FATSECT))
            num_fat_sectors = num_fat_sectors_2
            nb_difat = (num_fat_sectors - HEADER_DIFAT_ENTRIES
                        + DIFAT_POINTERS_PER_SECTOR - 1) // DIFAT_POINTERS_PER_SECTOR
            while len(difat_sector_ids) < nb_difat:
                difat_sector_ids.append(allocate(b'\x00' * SECTOR_SIZE, mark=DIFSECT))

    # finalize FAT value table, padded to whole FAT sectors
    full_fat = list(fat)
    for sid in fat_sector_ids:
        full_fat[sid] = FATSECT
    for sid in difat_sector_ids:
        full_fat[sid] = DIFSECT
    while len(full_fat) < num_fat_sectors * ENTRIES_PER_FAT_SECTOR:
        full_fat.append(FREESECT)

    fat_sector_data = []
    for k in range(num_fat_sectors):
        vals = full_fat[k * ENTRIES_PER_FAT_SECTOR:(k + 1) * ENTRIES_PER_FAT_SECTOR]
        fat_sector_data.append(b''.join(struct.pack('<I', v) for v in vals))
    for k, sid in enumerate(fat_sector_ids):
        sectors[sid] = fat_sector_data[k]

    # DIFAT contents: header holds first 109 FAT sector ids, DIFAT sectors rest
    header_difat = (fat_sector_ids[:HEADER_DIFAT_ENTRIES]
                    + [FREESECT] * (HEADER_DIFAT_ENTRIES
                                    - min(HEADER_DIFAT_ENTRIES, len(fat_sector_ids))))
    first_difat_sector = ENDOFCHAIN
    num_difat_sectors = 0
    if use_difat:
        first_difat_sector = difat_sector_ids[0]
        num_difat_sectors = len(difat_sector_ids)
        extra = fat_sector_ids[HEADER_DIFAT_ENTRIES:]
        for k, dsid in enumerate(difat_sector_ids):
            pointers = extra[k * DIFAT_POINTERS_PER_SECTOR:
                             (k + 1) * DIFAT_POINTERS_PER_SECTOR]
            pointers += [FREESECT] * (DIFAT_POINTERS_PER_SECTOR - len(pointers))
            nxt = difat_sector_ids[k + 1] if k + 1 < len(difat_sector_ids) else ENDOFCHAIN
            sectors[dsid] = b''.join(struct.pack('<I', p) for p in pointers) \
                + struct.pack('<I', nxt)

    # 7) 512-byte header
    header = bytearray(SECTOR_SIZE)
    header[0:8] = MAGIC
    struct.pack_into('<H', header, 0x18, 0x003E)       # minor version
    struct.pack_into('<H', header, 0x1A, 3)            # DLL version (512-byte)
    struct.pack_into('<H', header, 0x1C, 0xFFFE)       # byte order
    struct.pack_into('<H', header, 0x1E, 9)            # sector shift
    struct.pack_into('<H', header, 0x20, 6)            # mini sector shift
    struct.pack_into('<I', header, 0x2C, num_fat_sectors)
    struct.pack_into('<I', header, 0x30, first_dir_sector)
    struct.pack_into('<I', header, 0x38, MINI_CUTOFF)
    struct.pack_into('<I', header, 0x3C,
                     minifat_sector_ids[0] if minifat_sector_ids else ENDOFCHAIN)
    struct.pack_into('<I', header, 0x40, num_minifat_sectors)
    struct.pack_into('<I', header, 0x44, first_difat_sector)
    struct.pack_into('<I', header, 0x48, num_difat_sectors)
    for k, sid in enumerate(header_difat):
        struct.pack_into('<I', header, 0x4C + 4 * k, sid)

    data = bytes(header) + b''.join(sectors)
    layout = {
        'fat': full_fat[:len(sectors)],
        'fat_sector_ids': fat_sector_ids,
        'minifat_values': minifat_values,
        'minifat_sector_ids': minifat_sector_ids,
        'directory_sector_ids': directory_sector_ids,
        'difat_sector_ids': difat_sector_ids,
        'root_first_sect': root_first,
        'root_chain': root_chain,
        'root_size': root_size,
        'stream_fat_chains': stream_fat_chains,
        'stream_mini_chains': stream_mini_chains,
        'num_fat_sectors': num_fat_sectors,
        'num_difat_sectors': num_difat_sectors,
        'nb_sectors': len(sectors),
        'streams': streams,
    }
    return CompoundFile(data, layout)


def standard_seed(seed=1, force_difat=False):
    """The canonical small fixture used by most fuzzing cases.

    It mixes one regular FAT stream straddling several sector boundaries,
    several mini streams at/around 64-byte mini-sector boundaries, and an
    exact-cutoff stream to pin the FAT/MiniFAT routing decision.
    """
    streams = [
        StreamSpec('FatStream', 4731, stream_id=1),       # 9 full + partial FAT sectors
        StreamSpec('MiniOne', 64, stream_id=2),           # exactly one mini sector
        StreamSpec('MiniTwo', 65, stream_id=3),           # crosses a mini boundary
        StreamSpec('MiniThree', 200, stream_id=4),        # 4 mini sectors, partial last
        StreamSpec('AtCutoff', MINI_CUTOFF, stream_id=5), # == cutoff -> FAT, not MiniFAT
    ]
    return build_compound_file(streams, force_difat=force_difat,
                               gap_sectors=1, seed=seed)
