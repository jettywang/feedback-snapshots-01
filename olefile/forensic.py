"""
Forensic-grade multi-stream revision of OLE2 files (Compound File Binary
Format), built on top of :meth:`olefile.OleFileIO.write_stream`.

This module implements a copy-revise-verify-publish workflow intended for
sanitization / redaction tasks where several existing streams of an OLE file
must be replaced by data of the exact same size, without ever leaving a
half-modified evidence file behind:

1. Pre-checks on the original (opened read-only): digest of the original
   file, target stream identity, equal-length constraint, and a full
   allocation audit that refuses files with shared/duplicated sectors or
   broken sector chains (both in the FAT and the MiniFAT).
2. All modifications are applied to an independent temporary copy, never to
   the original.
3. Verification: every target stream is read back and compared byte for
   byte, target stream identity is re-checked, and the byte-level diff
   against the original must be fully contained in the byte ranges owned by
   the target streams (non-target regions provably unchanged). A successful
   write alone is never treated as proof of integrity.
4. Only after all verifications pass, the revised copy is atomically
   published to the output path. On any failure the temporary copy is
   deleted; the original and any pre-existing output file remain untouched.

Usage::

    from olefile.forensic import revise_streams_copy

    report = revise_streams_copy(
        'evidence.doc', 'evidence-redacted.doc',
        [('WordDocument', redacted_main), ('\\x01CompObj', redacted_compobj)],
    )
    print(report['original_digest'], report['revised_digest'])
    print(report['changed_ranges'])

New in version 0.48.dev1.
"""

import hashlib
import os
import shutil
import tempfile

from olefile.olefile import (
    OleFileIO,
    STGTY_STREAM,
    ENDOFCHAIN,
    FREESECT,
    FATSECT,
    DIFSECT,
)

__all__ = ['ForensicRevisionError', 'revise_streams_copy']

try:
    _string_types = basestring  # noqa: F821  (Python 2)
except NameError:
    _string_types = str


class ForensicRevisionError(Exception):
    """
    Raised when a forensic revision pre-check or post-write verification
    fails. The original file and any pre-existing output file are guaranteed
    to be unmodified when this exception is raised.
    """
    pass


def _hash_file(path, hash_name):
    """Compute the digest of a file, reading it in chunks."""
    digest = hashlib.new(hash_name)
    with open(path, 'rb') as fp:
        while True:
            chunk = fp.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _walk_chain(table, start, owner):
    """
    Walk a sector chain in a FAT-like table with cycle and bounds checks.

    :param table: sequence of sector indices (FAT or MiniFAT)
    :param start: index of the first sector of the chain
    :param owner: label of the owning stream/structure, for error messages
    :returns: list of sector indices in chain order
    :exception ForensicRevisionError: if the chain is broken (index out of
        range, reserved marker inside a chain, or cyclic)
    """
    chain = []
    seen = set()
    sect = start
    while sect != ENDOFCHAIN:
        if sect in seen:
            raise ForensicRevisionError(
                'cyclic sector chain in %s (sector %d)' % (owner, sect))
        if sect in (FREESECT, FATSECT, DIFSECT) or sect < 0 or sect >= len(table):
            raise ForensicRevisionError(
                'broken sector chain in %s (invalid sector index %d)'
                % (owner, sect))
        seen.add(sect)
        chain.append(sect)
        sect = table[sect]
    return chain


def _claim(chain, allocation, owner):
    """
    Register a sector chain in an allocation map, refusing duplicates.

    :exception ForensicRevisionError: if any sector is already owned by
        another stream/structure (suspected shared-sector corruption)
    """
    for sect in chain:
        previous = allocation.get(sect)
        if previous is not None:
            raise ForensicRevisionError(
                'sector %d is shared between %s and %s: suspected corrupted '
                'file, refusing to modify' % (sect, previous, owner))
        allocation[sect] = owner


def _audit_allocation(ole):
    """
    Build the full allocation map of the OLE file (regular sectors and mini
    sectors) and reject any file where two structures share a sector.

    :param ole: open OleFileIO (read-only)
    :returns: (regular_allocation, mini_allocation) dicts mapping sector
        index to owner label
    :exception ForensicRevisionError: on shared sectors or broken chains
    """
    regular = {}
    # Reserved sectors, marked as such inside the FAT itself:
    for sect, value in enumerate(ole.fat):
        if value == FATSECT:
            regular[sect] = 'FAT'
        elif value == DIFSECT:
            regular[sect] = 'DIFAT'
    # Structural streams: directory, MiniFAT, DIFAT extension, MiniStream.
    if ole.first_dir_sector not in (ENDOFCHAIN, FREESECT):
        _claim(_walk_chain(ole.fat, ole.first_dir_sector, 'directory'),
               regular, 'directory')
    if ole.num_mini_fat_sectors:
        _claim(_walk_chain(ole.fat, ole.first_mini_fat_sector, 'MiniFAT'),
               regular, 'MiniFAT')
    if ole.num_difat_sectors:
        _claim(_walk_chain(ole.fat, ole.first_difat_sector, 'DIFAT'),
               regular, 'DIFAT')
    if ole.root is not None and ole.root.size:
        _claim(_walk_chain(ole.fat, ole.root.isectStart, 'MiniStream'),
               regular, 'MiniStream')
    # All streams: regular ones claim FAT sectors, mini ones claim mini
    # sectors inside the MiniStream.
    mini = {}
    for entry in ole.direntries:
        if entry is None or entry.entry_type != STGTY_STREAM or not entry.size:
            continue
        owner = 'stream %r (sid %d)' % (entry.name, entry.sid)
        if entry.size < ole.minisectorcutoff:
            if not ole.minifat:
                ole.loadminifat()
            _claim(_walk_chain(ole.minifat, entry.isectStart, owner),
                   mini, owner)
        else:
            _claim(_walk_chain(ole.fat, entry.isectStart, owner),
                   regular, owner)
    return regular, mini


def _merge_ranges(ranges):
    """Merge a list of (offset, length) byte ranges into sorted disjoint ones."""
    merged = []
    for start, length in sorted(ranges):
        if not length:
            continue
        if merged and start <= merged[-1][0] + merged[-1][1]:
            last = merged[-1]
            merged[-1] = (last[0], max(last[1], start + length - last[0]))
        else:
            merged.append((start, length))
    return merged


def _diff_ranges(path_a, path_b, chunk_size=1 << 20):
    """
    Compute the exact byte ranges in which two files differ.

    :returns: sorted list of (offset, length) tuples
    :exception ForensicRevisionError: if the files have different sizes
    """
    size_a = os.path.getsize(path_a)
    size_b = os.path.getsize(path_b)
    if size_a != size_b:
        raise ForensicRevisionError(
            'file size changed from %d to %d bytes' % (size_a, size_b))
    ranges = []
    pending = None  # [start, end) of the current differing run
    offset = 0
    with open(path_a, 'rb') as fa, open(path_b, 'rb') as fb:
        while True:
            chunk_a = fa.read(chunk_size)
            chunk_b = fb.read(chunk_size)
            if not chunk_a and not chunk_b:
                break
            if chunk_a != chunk_b:
                for pos in range(len(chunk_a)):
                    if chunk_a[pos:pos + 1] != chunk_b[pos:pos + 1]:
                        absolute = offset + pos
                        if pending is not None and absolute == pending[1]:
                            pending[1] = absolute + 1
                        else:
                            if pending is not None:
                                ranges.append((pending[0],
                                               pending[1] - pending[0]))
                            pending = [absolute, absolute + 1]
            offset += len(chunk_a)
    if pending is not None:
        ranges.append((pending[0], pending[1] - pending[0]))
    return ranges


def _check_contained(diff_ranges, allowed_ranges):
    """
    Verify that every differing byte range is fully contained in the union
    of allowed (target-stream-owned) byte ranges.

    :exception ForensicRevisionError: if a modified byte lies outside any
        target stream allocation
    """
    allowed = _merge_ranges(allowed_ranges)
    for start, length in diff_ranges:
        end = start + length
        for allowed_start, allowed_length in allowed:
            if allowed_start <= start and end <= allowed_start + allowed_length:
                break
        else:
            raise ForensicRevisionError(
                'non-target region modified at offset %d (%d bytes)'
                % (start, length))


def _normalize_replacements(replacements):
    """
    Normalize the replacements argument to an ordered list of
    (stream_path, data) pairs with deterministic ordering.

    :exception TypeError/ValueError: on malformed input
    """
    if hasattr(replacements, 'items'):
        items = list(replacements.items())
    else:
        items = list(replacements)
    if not items:
        raise ValueError('revise_streams_copy: no stream replacements given')
    normalized = []
    for path, data in items:
        if isinstance(path, _string_types):
            path = path.split('/')
        path = tuple(path)
        if not path or not all(path):
            raise ValueError('revise_streams_copy: invalid stream path %r'
                             % (path,))
        if not isinstance(data, bytes):
            raise TypeError(
                'revise_streams_copy: data must be a bytes string for %r'
                % (path,))
        normalized.append((path, data))
    # deterministic processing order, and reject duplicate targets:
    normalized.sort(key=lambda item: tuple(name.lower() for name in item[0]))
    seen = set()
    for path, _ in normalized:
        key = tuple(name.lower() for name in path)
        if key in seen:
            raise ValueError(
                'revise_streams_copy: duplicate target stream %r' % (path,))
        seen.add(key)
    return normalized


def revise_streams_copy(source_path, output_path, replacements,
                        hash_name='sha256'):
    """
    Replace several existing streams of an OLE file by equal-length data,
    using a copy-revise-verify-publish workflow that never modifies the
    original file and never publishes a partially modified or unverified
    output.

    Pre-checks (on the original, opened read-only):

    - digest of the original file is recorded;
    - every target path must identify an existing stream (identity: sid,
      name, size and start sector are recorded and re-verified later);
    - every replacement must have exactly the same size as the existing
      stream (equal-length constraint, as required by write_stream);
    - a full allocation audit of the FAT and MiniFAT must show no shared
      sectors and no broken chains: corrupted files with suspected shared
      sectors are refused.

    Then an independent temporary copy is modified with
    :meth:`OleFileIO.write_stream`, covering both regular (FAT) streams and
    mini (MiniFAT) streams. Afterwards the copy is verified: every target
    stream is read back and compared byte for byte, its identity is
    re-checked, and the byte-level diff against the original must be fully
    contained in the byte ranges owned by the target streams. Only then is
    the copy atomically moved to ``output_path``. On any failure the
    temporary copy is deleted and neither the original nor a pre-existing
    output file is modified.

    :param source_path: path of the original OLE file (never modified)
    :param output_path: path of the revised file to publish (replaced
        atomically only after all verifications pass)
    :param replacements: dict or iterable of (stream_path, data) pairs;
        stream_path is a slash-separated string or a list/tuple of storage
        names; data must be bytes of the exact size of the existing stream
    :param hash_name: hashlib algorithm used for file digests
    :returns: verification report dict with keys:

        - ``hash_algorithm``, ``original_digest``, ``revised_digest``
        - ``changed_ranges``: sorted list of (offset, length) byte ranges
          that differ between original and revised file
        - ``streams``: list of per-target dicts (path, sid, size, storage
          kind 'fat' or 'minifat', sectors, byte_ranges)
        - ``verified``: always True (a report is only returned after full
          verification; failures raise instead)

    :exception ForensicRevisionError: on allocation conflicts, broken
        chains, or any verification failure
    :exception ValueError: on equal-length constraint violation or invalid
        replacements
    :exception TypeError: if replacement data is not bytes
    :exception IOError: if a target stream does not exist
    """
    items = _normalize_replacements(replacements)
    source_path = os.path.abspath(source_path)
    output_path = os.path.abspath(output_path)
    if source_path == output_path:
        raise ValueError(
            'revise_streams_copy: output must differ from the original; '
            'the original evidence file is never modified in place')
    if os.path.exists(output_path) and os.path.samefile(source_path, output_path):
        raise ValueError(
            'revise_streams_copy: output must not be the same file as the '
            'original')

    # ---- Phase 1: pre-checks on the original (read-only) ----------------
    original_digest = _hash_file(source_path, hash_name)
    targets = []
    ole = OleFileIO(source_path)
    try:
        _audit_allocation(ole)
        for path, data in items:
            sid = ole._find(list(path))
            entry = ole.direntries[sid]
            if entry.entry_type != STGTY_STREAM:
                raise IOError('revise_streams_copy: %r is not a stream'
                              % (path,))
            if entry.size != len(data):
                raise ValueError(
                    'revise_streams_copy: data for %r must be the same size '
                    'as the existing stream (%d != %d)'
                    % (path, len(data), entry.size))
            if entry.size < ole.minisectorcutoff:
                storage = 'minifat'
                if not ole.minifat:
                    ole.loadminifat()
                chain = _walk_chain(ole.minifat, entry.isectStart, repr(path))
                expected = (entry.size + ole.mini_sector_size - 1) // \
                    ole.mini_sector_size
            else:
                storage = 'fat'
                chain = _walk_chain(ole.fat, entry.isectStart, repr(path))
                expected = (entry.size + ole.sector_size - 1) // \
                    ole.sector_size
            if len(chain) != expected:
                raise ForensicRevisionError(
                    'stream %r has %d sectors in chain but %d are required '
                    'for its size: suspected corrupted file, refusing to '
                    'modify' % (path, len(chain), expected))
            targets.append({
                'path': list(path),
                'data': data,
                'sid': sid,
                'name': entry.name,
                'size': entry.size,
                'isect_start': entry.isectStart,
                'storage': storage,
                'sectors': chain,
            })
        # Byte ranges owned by the targets (where modifications are allowed):
        if any(t['storage'] == 'minifat' for t in targets):
            root_chain = _walk_chain(ole.fat, ole.root.isectStart,
                                     'MiniStream')
            minis_per_sector = ole.sector_size // ole.mini_sector_size
        for target in targets:
            byte_ranges = []
            if target['storage'] == 'fat':
                for sect in target['sectors']:
                    byte_ranges.append(((sect + 1) * ole.sector_size,
                                        ole.sector_size))
            else:
                for mini_sect in target['sectors']:
                    container = root_chain[mini_sect // minis_per_sector]
                    fp_pos = (container + 1) * ole.sector_size + \
                        (mini_sect % minis_per_sector) * ole.mini_sector_size
                    byte_ranges.append((fp_pos, ole.mini_sector_size))
            target['byte_ranges'] = _merge_ranges(byte_ranges)
    finally:
        ole.close()

    allowed_ranges = _merge_ranges(
        [byte_range for target in targets
         for byte_range in target['byte_ranges']])

    # ---- Phase 2: modify an independent temporary copy ------------------
    output_dir = os.path.dirname(output_path) or '.'
    fd, temp_path = tempfile.mkstemp(
        prefix='.olefile-revise-', suffix='.tmp', dir=output_dir)
    os.close(fd)
    published = False
    try:
        shutil.copyfile(source_path, temp_path)
        ole = OleFileIO(temp_path, write_mode=True)
        try:
            for target in targets:
                # Re-verify target identity on the copy before writing:
                sid = ole._find(target['path'])
                entry = ole.direntries[sid]
                if (sid != target['sid'] or entry.name != target['name']
                        or entry.size != target['size']
                        or entry.isectStart != target['isect_start']
                        or entry.entry_type != STGTY_STREAM):
                    raise ForensicRevisionError(
                        'target stream identity mismatch on working copy '
                        'for %r' % (target['path'],))
                ole.write_stream(target['path'], target['data'])
        finally:
            ole.close()

        # ---- Phase 3: verify the revised copy ---------------------------
        # 3a. Read back every target stream and compare byte for byte.
        #     A successful write is NOT considered proof of integrity.
        ole = OleFileIO(temp_path)
        try:
            for target in targets:
                sid = ole._find(target['path'])
                entry = ole.direntries[sid]
                if (sid != target['sid'] or entry.name != target['name']
                        or entry.size != target['size']
                        or entry.isectStart != target['isect_start']
                        or entry.entry_type != STGTY_STREAM):
                    raise ForensicRevisionError(
                        'target stream identity changed after revision '
                        'for %r' % (target['path'],))
                stream = ole.openstream(target['path'])
                try:
                    read_back = stream.read()
                finally:
                    stream.close()
                if read_back != target['data']:
                    raise ForensicRevisionError(
                        'read-back verification failed for stream %r: '
                        'written data does not match requested data'
                        % (target['path'],))
        finally:
            ole.close()
        # 3b. Non-target regions must be byte-identical to the original.
        changed_ranges = _diff_ranges(source_path, temp_path)
        _check_contained(changed_ranges, allowed_ranges)
        revised_digest = _hash_file(temp_path, hash_name)

        # ---- Phase 4: publish atomically --------------------------------
        if hasattr(os, 'replace'):
            os.replace(temp_path, output_path)
        else:  # pragma: no cover (Python 2 fallback)
            os.rename(temp_path, output_path)
        published = True
    finally:
        if not published and os.path.exists(temp_path):
            os.remove(temp_path)

    return {
        'hash_algorithm': hash_name,
        'source_path': source_path,
        'output_path': output_path,
        'original_digest': original_digest,
        'revised_digest': revised_digest,
        'changed_ranges': changed_ranges,
        'streams': [{
            'path': target['path'],
            'sid': target['sid'],
            'size': target['size'],
            'storage': target['storage'],
            'sectors': list(target['sectors']),
            'byte_ranges': target['byte_ranges'],
        } for target in targets],
        'verified': True,
    }
