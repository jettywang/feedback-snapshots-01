"""
Conservative recovery of streams from OLE2 files with damaged FAT chains.

This module is an independent, opt-in entry point for forensic-style
recovery. It does not change the strict default behaviour of
:class:`olefile.OleFileIO` in any way: nothing here is used unless the
caller explicitly invokes :func:`recover`.

Recovery principles (conservative):

- sectors are only recovered by following verifiable allocation
  relations, i.e. the FAT (or MiniFAT) chain that starts at the first
  sector declared by a directory entry;
- a chain walk stops at the first problem: a bad pointer (out of range,
  FREESECT or other special FAT value), a cycle, a sector reserved for
  system structures (FAT/DIFAT/directory/MiniFAT/ministream), or a
  sector already claimed by another stream's chain;
- recovered bytes are returned as fragments with their logical range in
  the stream and their physical origin in the image; missing parts are
  reported as gaps. Data is never zero-padded to fake a complete file,
  and missing sectors are never guessed from neighbouring sectors;
- directory entries that are not reachable from the storage tree
  (orphans) are recovered too, but reported separately from entries
  with a confirmed path.

The report returned by :func:`recover` lets an investigator see exactly
which bytes certainly belong to each stream, and which sectors remain
unattributable (gaps and contested sectors).

New in olefile 0.48.
"""

from __future__ import print_function

from .olefile import (
    OleFileIO,
    ENDOFCHAIN, FREESECT, FATSECT, DIFSECT, MAXREGSECT,
    STGTY_STREAM,
)

#: chain walk reached ENDOFCHAIN exactly where the declared size ends
STOP_END_OF_CHAIN = 'end_of_chain'
#: chain reached ENDOFCHAIN before the declared stream size (truncated)
STOP_TRUNCATED = 'truncated'
#: FAT entry points out of range, to FREESECT or to a special value
STOP_BAD_POINTER = 'bad_pointer'
#: the chain loops back to a sector already visited in this chain
STOP_CYCLE = 'cycle'
#: a sector is reserved for system structures or claimed by another stream
STOP_SECTOR_CONFLICT = 'sector_conflict'
#: a sector is only partially present in the image (truncated file)
STOP_INCOMPLETE_SECTOR = 'incomplete_sector'
#: the MiniFAT or ministream could not be loaded, mini streams unavailable
STOP_MINIFAT_UNAVAILABLE = 'minifat_unavailable'

__all__ = ['recover', 'RecoveryReport', 'StreamRecovery', 'RecoveredFragment',
           'RecoveryGap', 'PhysicalOrigin',
           'STOP_END_OF_CHAIN', 'STOP_TRUNCATED', 'STOP_BAD_POINTER',
           'STOP_CYCLE', 'STOP_SECTOR_CONFLICT', 'STOP_INCOMPLETE_SECTOR',
           'STOP_MINIFAT_UNAVAILABLE']


class PhysicalOrigin(object):
    """
    Physical location in the OLE image of a run of recovered bytes.

    Attributes:

        - sector_id: index of the sector in the FAT (or MiniFAT if
          is_mini_sector is True)
        - file_offset: absolute offset in bytes in the OLE file
        - length: number of bytes actually read at that location
        - is_mini_sector: True if this is a MiniFAT mini sector
    """
    __slots__ = ('sector_id', 'file_offset', 'length', 'is_mini_sector')

    def __init__(self, sector_id, file_offset, length, is_mini_sector=False):
        self.sector_id = sector_id
        self.file_offset = file_offset
        self.length = length
        self.is_mini_sector = is_mini_sector

    def __repr__(self):
        kind = 'mini' if self.is_mini_sector else 'sector'
        return '<PhysicalOrigin %s %d @file 0x%X+%d>' % (
            kind, self.sector_id, self.file_offset, self.length)


class RecoveredFragment(object):
    """
    A contiguous run of bytes recovered from a stream.

    Attributes:

        - logical_offset: offset of this fragment within the stream
        - data: the recovered bytes (never zero-padded)
        - origins: list of PhysicalOrigin, where the bytes were read from
    """
    __slots__ = ('logical_offset', 'data', 'origins')

    def __init__(self, logical_offset, data, origins):
        self.logical_offset = logical_offset
        self.data = data
        self.origins = origins

    @property
    def length(self):
        return len(self.data)

    def __repr__(self):
        return '<RecoveredFragment [%d, %d) from %d sector(s)>' % (
            self.logical_offset, self.logical_offset + self.length,
            len(self.origins))


class RecoveryGap(object):
    """
    A range of the stream that could not be recovered.

    Attributes:

        - logical_offset: offset of the gap within the stream
        - length: size of the gap in bytes
        - reason: one of the STOP_* constants, why recovery stopped there
    """
    __slots__ = ('logical_offset', 'length', 'reason')

    def __init__(self, logical_offset, length, reason):
        self.logical_offset = logical_offset
        self.length = length
        self.reason = reason

    def __repr__(self):
        return '<RecoveryGap [%d, %d) reason=%s>' % (
            self.logical_offset, self.logical_offset + self.length,
            self.reason)


class StreamRecovery(object):
    """
    Recovery result for one stream.

    Attributes:

        - name: name of the directory entry
        - path: confirmed path in the storage tree (list of names), or
          None for orphan entries not reachable from the root
        - sid: index of the directory entry
        - orphan: True if the entry is not reachable from the storage tree
        - declared_size: stream size declared by the directory entry
        - is_minifat: True if the stream is stored in the ministream
        - stop_reason: one of the STOP_* constants
        - fragments: list of RecoveredFragment (bytes certainly belonging
          to the stream)
        - gaps: list of RecoveryGap (logical ranges that could not be
          recovered)
    """
    __slots__ = ('name', 'path', 'sid', 'orphan', 'declared_size',
                 'is_minifat', 'stop_reason', 'fragments', 'gaps')

    def __init__(self, name, path, sid, orphan, declared_size, is_minifat):
        self.name = name
        self.path = path
        self.sid = sid
        self.orphan = orphan
        self.declared_size = declared_size
        self.is_minifat = is_minifat
        self.stop_reason = None
        self.fragments = []
        self.gaps = []

    @property
    def recovered_size(self):
        """Total number of bytes recovered with certainty."""
        return sum(fragment.length for fragment in self.fragments)

    @property
    def complete(self):
        """True if the whole declared stream was recovered without gaps."""
        return not self.gaps

    def __repr__(self):
        return '<StreamRecovery %r recovered=%d/%d stop=%s>' % (
            self.name, self.recovered_size, self.declared_size,
            self.stop_reason)


class RecoveryReport(object):
    """
    Result of a conservative recovery, see :func:`recover`.

    Attributes:

        - streams: list of StreamRecovery for entries with a confirmed
          path in the storage tree
        - orphans: list of StreamRecovery for directory entries not
          reachable from the storage tree (reported separately)
        - contested_sectors: dict mapping a sector index to the list of
          stream labels claiming it; these sectors cannot be attributed
          to a single stream with certainty and were excluded from all
          fragments
        - skipped_entries: list of (sid, message) for directory entries
          that could not be parsed at all
    """

    def __init__(self):
        self.streams = []
        self.orphans = []
        self.contested_sectors = {}
        self.skipped_entries = []

    def all_recoveries(self):
        """Iterate over confirmed streams and orphan entries together."""
        return list(self.streams) + list(self.orphans)

    def summary(self):
        """
        Human-readable summary for investigators: which bytes certainly
        belong to each stream, and which ranges/sectors remain
        unattributable.
        """
        lines = []
        for rec in self.streams:
            lines.extend(self._summary_lines(rec, '/'.join(rec.path)))
        for rec in self.orphans:
            lines.extend(self._summary_lines(
                rec, 'ORPHAN sid=%d (%r)' % (rec.sid, rec.name)))
        if self.contested_sectors:
            lines.append('Unattributable contested sectors:')
            for sect in sorted(self.contested_sectors):
                claimants = ', '.join(self.contested_sectors[sect])
                lines.append('  sector %d claimed by: %s' % (sect, claimants))
        if self.skipped_entries:
            lines.append('Unreadable directory entries:')
            for sid, message in self.skipped_entries:
                lines.append('  sid=%d: %s' % (sid, message))
        return '\n'.join(lines)

    @staticmethod
    def _summary_lines(rec, label):
        lines = ['%s: declared=%d recovered=%d stop=%s' % (
            label, rec.declared_size, rec.recovered_size, rec.stop_reason)]
        for fragment in rec.fragments:
            sectors = ', '.join(str(origin.sector_id)
                                for origin in fragment.origins)
            lines.append('  fragment [%d, %d): sectors %s' % (
                fragment.logical_offset,
                fragment.logical_offset + fragment.length, sectors))
        for gap in rec.gaps:
            lines.append('  gap [%d, %d): %d bytes lost (%s)' % (
                gap.logical_offset, gap.logical_offset + gap.length,
                gap.length, gap.reason))
        return lines


def _follow_chain(fat, start, reserved):
    """
    Follow a FAT (or MiniFAT) chain from start, conservatively.

    :param fat: list of sector indexes (FAT or MiniFAT), as unsigned ints
    :param start: index of the first sector of the chain
    :param reserved: set of sector indexes reserved for system structures
    :return: (sectors, stop_reason, blocker) where sectors is the list of
        sector indexes that can be attributed with certainty, stop_reason
        is one of the STOP_* constants, and blocker is the sector index or
        FAT value at which the walk stopped (None on clean ENDOFCHAIN).
    """
    sectors = []
    seen = set()
    sect = start
    while True:
        if sect == ENDOFCHAIN:
            return sectors, STOP_END_OF_CHAIN, None
        if sect < 0 or sect > MAXREGSECT or sect >= len(fat):
            # FREESECT, FATSECT, DIFSECT, garbage or out of range:
            return sectors, STOP_BAD_POINTER, sect
        if sect in seen:
            return sectors, STOP_CYCLE, sect
        if sect in reserved:
            return sectors, STOP_SECTOR_CONFLICT, sect
        seen.add(sect)
        sectors.append(sect)
        sect = fat[sect]


def _system_sectors(ole, fat):
    """
    Compute the set of FAT sector indexes reserved for system structures:
    FAT and DIFAT sectors (marked in the FAT itself), and the sector
    chains of the directory, the MiniFAT and the ministream.
    """
    reserved = set()
    for sid in range(len(fat)):
        if fat[sid] in (FATSECT, DIFSECT):
            reserved.add(sid)
    for start in (ole.first_dir_sector, ole.first_mini_fat_sector,
                  ole.first_difat_sector):
        chain, _stop, _blocker = _follow_chain(fat, start, frozenset())
        reserved.update(chain)
    if ole.root is not None and ole.root.size > 0:
        chain, _stop, _blocker = _follow_chain(fat, ole.root.isectStart,
                                               frozenset())
        reserved.update(chain)
    return reserved


def _collect_paths(node, prefix, paths):
    """Map sid -> confirmed path (list of names) for the storage tree."""
    for kid in node.kids:
        paths[kid.sid] = prefix + [kid.name]
        _collect_paths(kid, paths[kid.sid], paths)


def _entry_label(entry, path):
    """Human-readable label of a stream, for contested sector reports."""
    if path is not None:
        return '/'.join(path)
    return 'ORPHAN sid=%d (%r)' % (entry.sid, entry.name)


def recover(source):
    """
    Conservatively recover all streams of an OLE file, following only
    verifiable FAT/MiniFAT allocation relations.

    This is an independent entry point: it never modifies the strict
    default behaviour of OleFileIO. Recovered data is returned as
    fragments with logical ranges and physical origins; missing parts
    are reported as gaps and are never zero-padded nor guessed from
    adjacent sectors.

    :param source: an OleFileIO object already opened by the caller, or
        anything accepted by OleFileIO (filename, bytes, file-like
        object); in the latter cases the OLE file is opened with default
        strict settings and closed before returning
    :return: a RecoveryReport
    """
    if isinstance(source, OleFileIO):
        return _recover_from_ole(source)
    ole = None
    try:
        ole = OleFileIO(source)
        return _recover_from_ole(ole)
    finally:
        if ole is not None:
            ole.close()


def _recover_from_ole(ole):
    """Implementation of recover() on an opened OleFileIO object."""
    report = RecoveryReport()
    fat = [value & 0xFFFFFFFF for value in ole.fat]
    reserved = _system_sectors(ole, fat)

    # confirmed paths from the storage tree, indexed by sid:
    paths = {}
    _collect_paths(ole.root, [], paths)

    # enumerate ALL directory entries, including orphans which were not
    # loaded by loaddirectory because nothing references them:
    entries = []
    for sid in range(len(ole.direntries)):
        entry = ole.direntries[sid]
        if entry is None:
            try:
                entry = ole._load_direntry(sid)
            except Exception as exc:
                report.skipped_entries.append((sid, str(exc)))
                continue
        entries.append(entry)
    streams = [entry for entry in entries
               if entry.entry_type == STGTY_STREAM]

    # load the MiniFAT and the ministream chain only if needed:
    minifat = None
    ministream_chain = None
    if any(entry.is_minifat for entry in streams):
        try:
            if ole.minifat is None:
                ole.loadminifat()
            minifat = [value & 0xFFFFFFFF for value in ole.minifat]
            ministream_chain, _stop, _blocker = _follow_chain(
                fat, ole.root.isectStart, frozenset())
        except Exception:
            minifat = None

    # pass 1: follow each stream's raw chain, independently:
    raw_chains = {}
    for entry in streams:
        if entry.size == 0:
            raw_chains[entry.sid] = ([], STOP_END_OF_CHAIN, None)
        elif entry.is_minifat:
            if minifat is None:
                raw_chains[entry.sid] = ([], STOP_MINIFAT_UNAVAILABLE, None)
            else:
                raw_chains[entry.sid] = _follow_chain(
                    minifat, entry.isectStart, frozenset())
        else:
            raw_chains[entry.sid] = _follow_chain(
                fat, entry.isectStart, reserved)

    # pass 2: detect sectors claimed by more than one stream (per table):
    fat_claims = {}
    mini_claims = {}
    for entry in streams:
        claims = mini_claims if entry.is_minifat else fat_claims
        raw, _stop, _blocker = raw_chains[entry.sid]
        for sect in raw:
            claims.setdefault(sect, []).append(entry.sid)
    for claims in (fat_claims, mini_claims):
        for sect, sids in claims.items():
            if len(sids) > 1:
                labels = [_entry_label(ole.direntries[sid],
                                       paths.get(sid)) for sid in sids]
                report.contested_sectors[sect] = labels

    # pass 3: cut each chain at its first contested sector, then read
    # the remaining sectors and record gaps:
    for entry in streams:
        rec = StreamRecovery(
            name=entry.name, path=paths.get(entry.sid), sid=entry.sid,
            orphan=entry.sid not in paths, declared_size=entry.size,
            is_minifat=entry.is_minifat)
        raw, stop, blocker = raw_chains[entry.sid]
        claims = mini_claims if entry.is_minifat else fat_claims
        kept = []
        for sect in raw:
            if len(claims.get(sect, ())) > 1:
                # another stream also claims this sector: stop here, the
                # sector cannot be attributed to this stream with certainty
                stop = STOP_SECTOR_CONFLICT
                blocker = sect
                break
            kept.append(sect)
        data_parts = []
        origins = []
        for sect in kept:
            location = _physical_location(
                ole, sect, entry.is_minifat, ministream_chain)
            if location is None:
                stop = STOP_BAD_POINTER
                blocker = sect
                break
            file_offset, length = location
            ole.fp.seek(file_offset)
            chunk = ole.fp.read(length)
            origins.append(PhysicalOrigin(sect, file_offset, len(chunk),
                                          entry.is_minifat))
            data_parts.append(chunk)
            if len(chunk) != length:
                # the image itself is truncated: keep only the bytes
                # actually present, never pad:
                stop = STOP_INCOMPLETE_SECTOR
                break
        data = b''.join(data_parts)
        if len(data) > entry.size:
            data = data[:entry.size]
        if data:
            rec.fragments.append(RecoveredFragment(0, data, origins))
        if stop == STOP_END_OF_CHAIN and len(data) < entry.size:
            stop = STOP_TRUNCATED
        rec.stop_reason = stop
        if len(data) < entry.size:
            rec.gaps.append(RecoveryGap(len(data), entry.size - len(data),
                                        stop))
        if rec.orphan:
            report.orphans.append(rec)
        else:
            report.streams.append(rec)
    return report


def _physical_location(ole, sect, is_minifat, ministream_chain):
    """
    Compute the (file_offset, length) of a sector in the OLE image.

    For mini sectors, the location is derived from the ministream chain;
    returns None if the mini sector falls outside the ministream.
    """
    if not is_minifat:
        return (ole.sectorsize * (sect + 1), ole.sectorsize)
    mini_size = ole.minisectorsize
    chain_index = (sect * mini_size) // ole.sectorsize
    if ministream_chain is None or chain_index >= len(ministream_chain):
        return None
    file_offset = (ole.sectorsize * (ministream_chain[chain_index] + 1)
                   + (sect * mini_size) % ole.sectorsize)
    return (file_offset, mini_size)
