"""
Deterministic, structure-aware mutators for CFB fixtures.

Every mutator changes *one* structural element of an otherwise valid file -
a chain terminator, a system sector marker, a mini-sector boundary, or a
declared count/size - so that a change in olefile's behaviour can be attributed
to that element.  Mutators operate on the raw byte string together with the
builder's ``layout`` map and never need random data from the environment:
a small fixed-seed LCG picks positions, making runs fully reproducible.
"""

from __future__ import print_function

import struct

from .olebuilder import (ENDOFCHAIN, FREESECT, FATSECT, DIFSECT,
                         SECTOR_SIZE, MINI_SECTOR_SIZE, MINI_CUTOFF,
                         DIFAT_POINTERS_PER_SECTOR)

# Reserved / special values that are illegal inside a regular sector chain.
_SPECIAL_MARKERS = (ENDOFCHAIN, FREESECT, FATSECT, DIFSECT, 0xFFFFFFFB)


class Rng(object):
    """Tiny deterministic LCG (Numerical Recipes constants)."""

    def __init__(self, seed):
        self.state = seed & 0xFFFFFFFF or 1

    def next_u32(self):
        self.state = (self.state * 1664525 + 1013904223) & 0xFFFFFFFF
        return self.state

    def randrange(self, stop):
        return self.next_u32() % stop

    def choice(self, seq):
        return seq[self.randrange(len(seq))]


def _patch_u32(buf, offset, value):
    struct.pack_into('<I', buf, offset, value & 0xFFFFFFFF)


def _read_u32(buf, offset):
    return struct.unpack_from('<I', buf, offset)[0]


# --- helpers over the builder layout ----------------------------------------

def _fat_chain_indices(compound):
    """All FAT indexes belonging to user/root/directory data chains."""
    idxs = []
    for chain in compound.layout['stream_fat_chains'].values():
        idxs.extend(chain)
    idxs.extend(compound.layout['root_chain'])
    idxs.extend(compound.layout['directory_sector_ids'])
    return idxs


def _mini_chain_indices(compound):
    idxs = []
    for chain in compound.layout['stream_mini_chains'].values():
        idxs.extend(chain)
    return idxs


# --- mutator families --------------------------------------------------------
# Each mutator returns a short human-readable description of what it changed.

def mutate_fat_terminator(compound, rng):
    """Break a FAT chain terminator (drop / redirect ENDOFCHAIN)."""
    buf = bytearray(compound.data)
    candidates = [i for i in _fat_chain_indices(compound)
                  if _read_u32(buf, compound.fat_entry_file_offset(i)) == ENDOFCHAIN]
    idx = rng.choice(candidates)
    off = compound.fat_entry_file_offset(idx)
    mode = rng.randrange(3)
    if mode == 0:
        _patch_u32(buf, off, FREESECT)
        desc = 'FAT[%d] ENDOFCHAIN->FREESECT' % idx
    elif mode == 1:
        _patch_u32(buf, off, idx)          # self loop (cycle, no terminator)
        desc = 'FAT[%d] ENDOFCHAIN->self (cycle)' % idx
    else:
        _patch_u32(buf, off, _fat_chain_indices(compound)[0])  # loop to head
        desc = 'FAT[%d] ENDOFCHAIN->chain head (cycle)' % idx
    return bytes(buf), desc


def mutate_fat_link(compound, rng):
    """Replace an interior FAT link with a marker or an out-of-range SID."""
    buf = bytearray(compound.data)
    chain = rng.choice(list(compound.layout['stream_fat_chains'].values())
                       or [compound.layout['directory_sector_ids']])
    interior = chain[:-1] if len(chain) > 1 else chain
    idx = rng.choice(interior)
    off = compound.fat_entry_file_offset(idx)
    mode = rng.randrange(3)
    if mode == 0:
        val = rng.choice(_SPECIAL_MARKERS)
        desc = 'FAT[%d] -> special 0x%08X' % (idx, val)
    elif mode == 1:
        val = compound.layout['nb_sectors'] + rng.randrange(5)  # past EOF
        desc = 'FAT[%d] -> out-of-range %d' % (idx, val)
    else:
        val = rng.randrange(len(chain))                       # backwards = cycle
        desc = 'FAT[%d] -> earlier sector %d (cycle)' % (idx, val)
    _patch_u32(buf, off, val)
    return bytes(buf), desc


def mutate_system_marker(compound, rng):
    """Corrupt the FATSECT/DIFSECT marking of a metadata sector."""
    buf = bytearray(compound.data)
    if compound.layout['difat_sector_ids'] and rng.randrange(2):
        sid = rng.choice(compound.layout['difat_sector_ids'])
        _patch_u32(buf, compound.fat_entry_file_offset(sid),
                   rng.choice((FATSECT, ENDOFCHAIN, FREESECT)))
        desc = 'FAT[DIFAT sector %d] marker clobbered' % sid
    else:
        sid = rng.choice(compound.layout['fat_sector_ids'])
        _patch_u32(buf, compound.fat_entry_file_offset(sid),
                   rng.choice((DIFSECT, ENDOFCHAIN, FREESECT)))
        desc = 'FAT[FAT sector %d] FATSECT marker clobbered' % sid
    return bytes(buf), desc


def mutate_mini_link(compound, rng):
    """Break a MiniFAT link / terminator at or around a mini boundary."""
    buf = bytearray(compound.data)
    idxs = _mini_chain_indices(compound)
    if not idxs:
        return mutate_fat_link(compound, rng)
    idx = rng.choice(idxs)
    off = compound.minifat_entry_file_offset(idx)
    mode = rng.randrange(4)
    if mode == 0:
        val, desc = idx, 'MiniFAT[%d] -> self (cycle)' % idx
    elif mode == 1:
        val, desc = ENDOFCHAIN, 'MiniFAT[%d] -> early ENDOFCHAIN' % idx
    elif mode == 2:
        val = compound.layout['root_size'] // MINI_SECTOR_SIZE + rng.randrange(3)
        desc = 'MiniFAT[%d] -> out-of-range %d' % (idx, val)
    else:
        val = rng.choice(_SPECIAL_MARKERS)
        desc = 'MiniFAT[%d] -> special 0x%08X' % (idx, val)
    _patch_u32(buf, off, val)
    return bytes(buf), desc


def mutate_mini_boundary(compound, rng):
    """Adjust a mini stream's declared size across a 64-byte boundary."""
    buf = bytearray(compound.data)
    mini_streams = [s for s in compound.layout['streams'] if s.mini]
    if not mini_streams:
        return mutate_mini_link(compound, rng)
    spec = rng.choice(mini_streams)
    sid = compound.layout['streams'].index(spec) + 1
    size_off = compound.direntry_file_offset(sid) + 120
    deltas = (-1, +1, -(spec.size % MINI_SECTOR_SIZE or 1),
              MINI_SECTOR_SIZE - (spec.size % MINI_SECTOR_SIZE or 0))
    new_size = max(0, spec.size + rng.choice(deltas))
    _patch_u32(buf, size_off, new_size)
    return bytes(buf), ('direntry %r size %d->%d (mini boundary)'
                        % (spec.name, spec.size, new_size))


def mutate_stream_size(compound, rng):
    """Lie about a FAT stream's declared size (shrink / grow / huge)."""
    buf = bytearray(compound.data)
    fat_streams = [s for s in compound.layout['streams'] if not s.mini]
    if not fat_streams:
        return mutate_fat_link(compound, rng)
    spec = rng.choice(fat_streams)
    sid = compound.layout['streams'].index(spec) + 1
    size_off = compound.direntry_file_offset(sid) + 120
    mode = rng.randrange(4)
    if mode == 0:
        new_size = spec.size - SECTOR_SIZE            # one sector less
    elif mode == 1:
        new_size = spec.size + SECTOR_SIZE            # one sector more
    elif mode == 2:
        new_size = 0                                  # empty but chain non-null
    else:
        new_size = 0x7FFFFFFF                         # huge declaration
    new_size = max(0, new_size)
    _patch_u32(buf, size_off, new_size)
    return bytes(buf), ('direntry %r size %d->%d'
                        % (spec.name, spec.size, new_size))


def mutate_header_count(compound, rng):
    """Corrupt a header count / start field (FAT, MiniFAT, DIFAT, directory)."""
    buf = bytearray(compound.data)
    options = [0x2C, 0x30, 0x3C, 0x40, 0x44, 0x48]
    off = rng.choice(options)
    original = _read_u32(buf, off)
    val = rng.choice((0, ENDOFCHAIN, FREESECT,
                      compound.layout['nb_sectors'] + 1,
                      original + 1 if original < 0xFFFFFFF0 else 0))
    _patch_u32(buf, off, val)
    name = {0x2C: 'csectFat', 0x30: 'sectDirStart', 0x3C: 'sectMiniFatStart',
            0x40: 'csectMiniFat', 0x44: 'sectDifStart', 0x48: 'csectDif'}[off]
    return bytes(buf), 'header %s 0x%08X->0x%08X' % (name, original, val)


def mutate_difat_chain(compound, rng):
    """Break the DIFAT sector chain (next-pointer) or a DIFAT FAT pointer."""
    buf = bytearray(compound.data)
    if not compound.layout['difat_sector_ids']:
        # no DIFAT in this fixture: lie that one exists instead
        _patch_u32(buf, 0x44, compound.layout['nb_sectors'])
        _patch_u32(buf, 0x48, 1)
        return bytes(buf), 'header claims DIFAT at out-of-range sector'
    k = rng.randrange(len(compound.layout['difat_sector_ids']))
    base = compound.difat_sector_file_offset(k)
    mode = rng.randrange(3)
    if mode == 0:
        _patch_u32(buf, base + DIFAT_POINTERS_PER_SECTOR * 4, k)  # self loop
        desc = 'DIFAT sector %d next->self (cycle)' % k
    elif mode == 1:
        _patch_u32(buf, base + DIFAT_POINTERS_PER_SECTOR * 4,
                   compound.layout['nb_sectors'] + 1)
        desc = 'DIFAT sector %d next->out-of-range' % k
    else:
        slot = rng.randrange(DIFAT_POINTERS_PER_SECTOR)
        _patch_u32(buf, base + slot * 4, compound.layout['nb_sectors'] + 1)
        desc = 'DIFAT sector %d FAT pointer %d -> out-of-range' % (k, slot)
    return bytes(buf), desc


# Mutators applicable to every fixture, in a fixed registration order.
ALL_MUTATORS = [
    mutate_fat_terminator,
    mutate_fat_link,
    mutate_system_marker,
    mutate_mini_link,
    mutate_mini_boundary,
    mutate_stream_size,
    mutate_header_count,
    mutate_difat_chain,
]
