# Copyright (C) 2026  Chris Lalancette <clalancette@gmail.com>

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation;
# version 2.1 of the License.

# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

"""
A read-only namespace difference report for hybrid ISOs.

A single hybrid ISO carries up to four independent name-to-data views of the
same medium: ISO9660, Joliet, Rock Ridge and UDF.  A path that looks identical
in two namespaces does not necessarily resolve to the same on-disk bytes.
This module walks each namespace separately, records the original name, the
on-disk location of the directory/name record, and the data extent range each
name points at, then correlates the views on their display paths and on the
actual inode identity they resolve to.

The report deliberately never selects a "best" namespace.  Every disagreement
is surfaced, and a namespace that fails to enumerate is recorded as a failure
without suppressing the findings from the namespaces that still work.
"""

import collections
import hashlib

from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from pycdlib import dr
from pycdlib import pycdlibexception
from pycdlib import udf as udfmod

if TYPE_CHECKING:
    from pycdlib.pycdlib import PyCdlib

#: The namespaces this report understands, in report order.  ISO9660 is always
#: present; Rock Ridge, Joliet and UDF are only present when the ISO carries
#: those extensions.
NAMESPACES = ('iso9660', 'rockridge', 'joliet', 'udf')

# Entry type labels.
_TYPE_DIRECTORY = 'directory'
_TYPE_FILE = 'file'
_TYPE_SYMLINK = 'symlink'


class DataRange:
    """
    A contiguous run of logical blocks that an entry's data occupies.

    Attributes:
        extent: The absolute logical block number where the data starts.
        length: The number of bytes in this run (0 for an empty extent).
        inline: True when the data lives inside the descriptor itself (UDF
            inline allocation) rather than in a separate data extent.
    """

    __slots__ = ('extent', 'length', 'inline')

    def __init__(self, extent, length, inline=False):
        # type: (int, int, bool) -> None
        self.extent = extent
        self.length = length
        self.inline = inline

    def __repr__(self):
        # type: () -> str
        kind = 'inline' if self.inline else 'extent'
        return 'DataRange(%s=%d, length=%d)' % (kind, self.extent, self.length)

    def __eq__(self, other):
        # type: (object) -> bool
        if not isinstance(other, DataRange):
            return NotImplemented
        return (self.extent == other.extent and self.length == other.length
                and self.inline == other.inline)

    def __hash__(self):
        # type: () -> int
        return hash((self.extent, self.length, self.inline))


class RecordLocation:
    """
    The on-disk location of the name record (directory record or UDF File
    Identifier Descriptor), as opposed to the data it points at.

    Attributes:
        extent: The absolute logical block number holding the record.
        offset: The byte offset of the record inside that block.
        length: The size in bytes the name record occupies on the medium.
    """

    __slots__ = ('extent', 'offset', 'length')

    def __init__(self, extent, offset, length):
        # type: (int, int, int) -> None
        self.extent = extent
        self.offset = offset
        self.length = length

    def __repr__(self):
        # type: () -> str
        return 'RecordLocation(extent=%d, offset=%d, length=%d)' % (
            self.extent, self.offset, self.length)


class NamespaceEntry:
    """
    One path in one namespace, with everything needed to decide what it really
    is on the medium.

    Attributes:
        namespace: One of :data:`NAMESPACES`.
        path: The display path in this namespace's own naming rules.
        raw_name: The final path component exactly as stored, in its on-disk
            encoding (ISO9660 uppercase 8.3, UTF-16 Joliet, Rock Ridge NM, ...).
        entry_type: One of 'file', 'directory', or 'symlink'.
        record_location: Where the name record itself lives on the medium.
        data_ranges: The data extents this name resolves to; empty for
            directories with no data and for zero-length files.
        identity: A stable token that is equal exactly when two names are links
            to the same underlying inode (a hard link), and distinct for
            independent copies.
        size: Declared data length in bytes.
        symlink_target: The link target for symlinks, otherwise None.
    """

    __slots__ = ('namespace', 'path', 'raw_name', 'entry_type',
                 'record_location', 'data_ranges', 'identity', 'size',
                 'symlink_target')

    def __init__(self, namespace, path, raw_name, entry_type, record_location,
                 data_ranges, identity, size, symlink_target=None):
        # type: (str, str, bytes, str, RecordLocation, List[DataRange], str, int, Optional[str]) -> None
        self.namespace = namespace
        self.path = path
        self.raw_name = raw_name
        self.entry_type = entry_type
        self.record_location = record_location
        self.data_ranges = data_ranges
        self.identity = identity
        self.size = size
        self.symlink_target = symlink_target


class NamespaceResult:
    """
    The outcome of enumerating one namespace.

    Attributes:
        namespace: One of :data:`NAMESPACES`.
        available: Whether the ISO even carries this namespace.
        entries: The entries collected before any failure (possibly empty).
        error: A human-readable failure reason, or None on success.
    """

    __slots__ = ('namespace', 'available', 'entries', 'error')

    def __init__(self, namespace, available, entries, error=None):
        # type: (str, bool, List[NamespaceEntry], Optional[str]) -> None
        self.namespace = namespace
        self.available = available
        self.entries = entries
        self.error = error


class PathComparison:
    """
    How a single display path resolves across every namespace that contains it.

    Attributes:
        path: The display path (each namespace uses its own native spelling;
            entries are grouped when their decoded display paths are equal).
        present_in: Namespaces that contain this path.
        missing_in: Namespaces (that are present on the ISO) lacking this path.
        identities: The distinct inode identities this path resolves to.
        digests: The distinct content digests, when data could be hashed.
        relation: One of 'single-entry', 'hard-link', 'same-content-copy',
            'different-content', 'symlink', or 'missing-somewhere'.
        explanation: Whether the difference comes from the name mapping or from
            the data source, in plain language.
        entries: The per-namespace :class:`NamespaceEntry` objects.
    """

    __slots__ = ('path', 'present_in', 'missing_in', 'identities', 'digests',
                 'relation', 'explanation', 'entries')

    def __init__(self, path):
        # type: (str) -> None
        self.path = path
        self.present_in = []  # type: List[str]
        self.missing_in = []  # type: List[str]
        self.identities = set()  # type: set
        self.digests = set()  # type: set
        self.relation = 'single-entry'
        self.explanation = ''
        self.entries = {}  # type: Dict[str, NamespaceEntry]


class NamespaceDiffReport:
    """
    The complete read-only namespace difference report.

    Attributes:
        block_size: The ISO logical block size in bytes.
        namespaces: Per-namespace :class:`NamespaceResult` objects.
        comparisons: Per-display-path :class:`PathComparison` objects, sorted
            by path.
        content_digests: A cache mapping inode identity to a content digest.
    """

    __slots__ = ('block_size', 'namespaces', 'comparisons',
                 '_iso', '_identity_tokens', '_identity_objects',
                 '_inode_token', '_digest_cache')

    def __init__(self, iso):
        # type: (PyCdlib) -> None
        self._iso = iso
        self.block_size = iso.logical_block_size
        self.namespaces = {}  # type: Dict[str, NamespaceResult]
        self.comparisons = []  # type: List[PathComparison]
        self._identity_tokens = {}  # type: Dict[int, str]
        self._identity_objects = {}  # type: Dict[str, object]
        self._inode_token = 0
        self._digest_cache = {}  # type: Dict[str, Optional[str]]

    # ------------------------------------------------------------------
    # Identity helpers
    # ------------------------------------------------------------------
    def _token_for(self, obj):
        # type: (object) -> str
        """Return a stable, content-independent token for an inode-like object."""
        key = id(obj)
        token = self._identity_tokens.get(key)
        if token is None:
            self._inode_token += 1
            token = 'inode-%d' % self._inode_token
            self._identity_tokens[key] = token
        return token

    def content_digest(self, entry):
        # type: (NamespaceEntry) -> Optional[str]
        """
        Hash the bytes an entry resolves to.  The result is cached per inode
        identity so every hard link to the same inode hashes the bytes once.

        Returns:
            A 'sha256:<hex>' string, or None when there is no readable data
            (zero-length files, symlinks, inline-only descriptors).
        """
        if entry.identity in self._digest_cache:
            return self._digest_cache[entry.identity]

        digest = None  # type: Optional[str]
        ino = self._inode_for_entry(entry)
        if ino is not None and entry.entry_type == _TYPE_FILE and entry.size > 0:
            try:
                from pycdlib.inode import InodeOpenData
                hasher = hashlib.sha256()
                with InodeOpenData(ino, self.block_size) as (data_fp, length):
                    remaining = length
                    while remaining > 0:
                        chunk = data_fp.read(min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        hasher.update(chunk)
                        remaining -= len(chunk)
                digest = 'sha256:' + hasher.hexdigest()
            except (pycdlibexception.PyCdlibException, OSError, ValueError):
                digest = None
        self._digest_cache[entry.identity] = digest
        return digest

    def _inode_for_entry(self, entry):
        # type: (NamespaceEntry) -> Optional[object]
        # Identity tokens were minted from inode objects where they existed;
        # recover the inode by re-resolving through the parsed trees is not
        # possible from the token alone, so callers pass entries that keep the
        # inode reachable through a side map built during enumeration.
        return self._identity_objects.get(entry.identity)

    # ------------------------------------------------------------------
    # Enumeration
    # ------------------------------------------------------------------
    def build(self):
        # type: () -> NamespaceDiffReport
        """Enumerate every namespace independently and correlate the results."""
        root_extent = self._iso.pvd.root_directory_record().extent_location()
        if root_extent is None:
            raise pycdlibexception.PyCdlibInvalidInput(
                'Cannot build a namespace report for an unwritten ISO; write '
                'the image and re-open it first')
        self._enumerate_iso9660()
        if self._iso.rock_ridge:
            self._enumerate_rockridge()
        if self._iso.joliet_vd is not None:
            self._enumerate_joliet()
        if self._iso.udf_root is not None:
            self._enumerate_udf()

        self._correlate()
        return self

    def _record_namespace(self, namespace, available, entries, error):
        # type: (str, bool, List[NamespaceEntry], Optional[str]) -> None
        self.namespaces[namespace] = NamespaceResult(
            namespace, available, entries, error)

    def _identity_for_inode(self, ino):
        # type: (Optional[object]) -> Optional[str]
        if ino is None:
            return None
        token = self._token_for(ino)
        self._identity_objects[token] = ino
        return token

    # -- ISO9660 / Rock Ridge / Joliet (directory record based) --------
    def _dr_identity_and_ranges(self, record):
        # type: (dr.DirectoryRecord) -> Tuple[str, List[DataRange]]
        ino = record.inode
        if ino is not None:
            token = self._identity_for_inode(ino)
        else:
            # No shared inode (zero-length file, symlink, or a record not
            # linked during parse).  Identify it by its own object so two such
            # records are never falsely treated as links.
            token = self._token_for(record)
            self._identity_objects[token] = record

        ranges = []  # type: List[DataRange]
        if record.is_dir():
            ranges.append(DataRange(record.extent_location(),
                                    record.get_data_length()))
        elif not record.is_symlink() and record.get_data_length() > 0:
            cursor = record
            while cursor is not None:
                ranges.append(DataRange(cursor.extent_location(),
                                        cursor.get_data_length()))
                cursor = cursor.data_continuation
        return token, ranges

    @staticmethod
    def _record_position(parent_extent, record_index, record, block_size):
        # type: (int, int, dr.DirectoryRecord, int) -> RecordLocation
        # Walk the parent's on-disk byte stream exactly like the parser does:
        # records cannot cross a logical block, so when the next record would
        # overflow the block, padding fills the remainder and the next record
        # starts at the next block boundary.  Dot and dotdot are real records
        # and consume bytes, so every child participates in the accounting.
        offset = 0
        block = 0
        for idx, sibling in enumerate(record.parent.children):
            if offset + sibling.dr_len > block_size:
                block += 1
                offset = 0
            if idx == record_index:
                return RecordLocation(parent_extent + block, offset,
                                      sibling.dr_len)
            offset += sibling.dr_len
        # Fallback for root, whose parent is itself.
        return RecordLocation(parent_extent, 0, record.dr_len)

    def _walk_dr_tree(self, namespace, vd, use_rockridge, encoding):
        # type: (str, object, bool, str) -> List[NamespaceEntry]
        entries = []  # type: List[NamespaceEntry]
        root = vd.root_directory_record()  # type: dr.DirectoryRecord
        queue = collections.deque([root])
        while queue:
            directory = queue.popleft()
            dir_extent = directory.extent_location()
            for index, child in enumerate(directory.children):
                if child.is_dot() or child.is_dotdot():
                    continue
                if use_rockridge:
                    name_bytes = child.rock_ridge.name() if child.rock_ridge is not None else child.file_identifier()
                    display_path = self._iso.full_path_from_dirrecord(
                        child, rockridge=True)
                else:
                    name_bytes = child.file_identifier()
                    display_path = self._iso.full_path_from_dirrecord(
                        child, rockridge=False, encoding=encoding)

                if child.is_symlink():
                    entry_type = _TYPE_SYMLINK
                    target = None
                    if child.rock_ridge is not None:
                        target = child.rock_ridge.symlink_path()
                        if isinstance(target, bytes):
                            target = target.decode('utf-8', 'replace')
                elif child.is_dir():
                    entry_type = _TYPE_DIRECTORY
                    target = None
                else:
                    entry_type = _TYPE_FILE
                    target = None

                identity, ranges = self._dr_identity_and_ranges(child)
                position = self._record_position(dir_extent, index, child,
                                                 self.block_size)
                entries.append(NamespaceEntry(
                    namespace, display_path, name_bytes, entry_type,
                    position, ranges, identity,
                    child.get_data_length(), target))

                if child.is_dir():
                    queue.append(child)
        return entries

    def _enumerate_iso9660(self):
        # type: () -> None
        entries = []  # type: List[NamespaceEntry]
        try:
            entries = self._walk_dr_tree('iso9660', self._iso.pvd, False,
                                         'utf-8')
            self._record_namespace('iso9660', True, entries, None)
        except Exception as exc:  # noqa: BLE001 - isolate the namespace
            self._record_namespace('iso9660', True, entries,
                                   '%s: %s' % (type(exc).__name__, exc))

    def _enumerate_rockridge(self):
        # type: () -> None
        entries = []  # type: List[NamespaceEntry]
        try:
            entries = self._walk_dr_tree('rockridge', self._iso.pvd, True,
                                         'utf-8')
            self._record_namespace('rockridge', True, entries, None)
        except Exception as exc:  # noqa: BLE001
            self._record_namespace('rockridge', True, entries,
                                   '%s: %s' % (type(exc).__name__, exc))

    def _enumerate_joliet(self):
        # type: () -> None
        entries = []  # type: List[NamespaceEntry]
        try:
            entries = self._walk_dr_tree('joliet', self._iso.joliet_vd, False,
                                         'utf-16_be')
            self._record_namespace('joliet', True, entries, None)
        except Exception as exc:  # noqa: BLE001
            self._record_namespace('joliet', True, entries,
                                   '%s: %s' % (type(exc).__name__, exc))

    # -- UDF -----------------------------------------------------------
    def _udf_data_ranges(self, file_entry):
        # type: (udfmod.UDFFileEntry) -> List[DataRange]
        ranges = []  # type: List[DataRange]
        part_start = self._iso.udf_main_descs.partitions[0].part_start_location
        for desc in file_entry.alloc_descs:
            if isinstance(desc, udfmod.UDFInlineAD):
                ranges.append(DataRange(desc.log_block_num,
                                        desc.extent_length, inline=True))
            else:
                ranges.append(DataRange(
                    part_start + desc.log_block_num, desc.extent_length))
        return ranges

    def _udf_fid_positions(self, file_entry):
        # type: (udfmod.UDFFileEntry) -> Dict[bytes, RecordLocation]
        """
        Re-read a UDF directory's File Identifier Descriptors from the medium
        and capture each descriptor's exact block/offset.  Reusing the parser's
        own primitives keeps the walk aligned with how pycdlib enumerated the
        live tree, while recording the byte position the in-memory tree drops.
        """
        positions = {}  # type: Dict[bytes, RecordLocation]
        part_start = self._iso.udf_main_descs.partitions[0].part_start_location
        block_size = self.block_size
        for alloc in file_entry.alloc_descs:
            abs_extent = part_start + alloc.log_block_num
            self._iso._seek_to_extent(abs_extent)
            self._iso._cdfp.seek(alloc.offset, 1)
            data = self._iso._cdfp.read(alloc.extent_length)
            offset = 0
            while offset < len(data):
                if data[offset:offset + 1] == b'\x00':
                    # Padding inside a File Identifier descriptor area.
                    offset += 1
                    continue
                block_within = offset // block_size
                within_block = offset % block_size
                fid, consumed = udfmod.parse_file_ident(
                    data[offset:], abs_extent + block_within, part_start,
                    file_entry)
                if not fid.is_parent():
                    positions[fid.fi] = RecordLocation(
                        abs_extent + block_within, within_block, consumed)
                offset += consumed
        return positions

    def _enumerate_udf(self):
        # type: () -> None
        entries = []  # type: List[NamespaceEntry]
        try:
            queue = collections.deque([self._iso.udf_root])
            while queue:
                directory = queue.popleft()
                try:
                    positions = self._udf_fid_positions(directory)
                except Exception:  # noqa: BLE001 - keep enumerating the tree
                    positions = {}

                for fid in directory.fi_descs.values():
                    if fid.is_parent():
                        # The parent ('..') File Identifier is metadata, not a
                        # named entry, mirroring the dot/dotdot records skipped
                        # on the ISO9660 side.
                        continue
                    file_entry = fid.file_entry
                    position = positions.get(
                        fid.fi, RecordLocation(fid.extent_location(), 0, 0))

                    if file_entry is None:
                        # A descriptor that points at an all-zero File Entry:
                        # retain the name with no data identity rather than
                        # dropping it silently.
                        display = self._iso.full_path_from_dirrecord(directory)
                        name = fid.fi.decode(fid.encoding or 'utf-8', 'replace')
                        orphan_token = self._token_for(fid)
                        self._identity_objects[orphan_token] = fid
                        entries.append(NamespaceEntry(
                            'udf', display.rstrip('/') + '/' + name, fid.fi,
                            _TYPE_FILE, position, [],
                            orphan_token, 0))
                        continue

                    if file_entry.is_symlink():
                        entry_type = _TYPE_SYMLINK
                    elif file_entry.is_dir():
                        entry_type = _TYPE_DIRECTORY
                    else:
                        entry_type = _TYPE_FILE

                    identity = self._identity_for_inode(file_entry.inode)
                    if identity is None:
                        identity = self._token_for(file_entry)
                        self._identity_objects[identity] = file_entry
                    ranges = self._udf_data_ranges(file_entry)
                    display_path = self._iso.full_path_from_dirrecord(file_entry)
                    entries.append(NamespaceEntry(
                        'udf', display_path, fid.fi, entry_type, position,
                        ranges, identity, file_entry.get_data_length()))

                    if file_entry.is_dir() and file_entry is not self._iso.udf_root:
                        queue.append(file_entry)
            self._record_namespace('udf', True, entries, None)
        except Exception as exc:  # noqa: BLE001 - isolate the namespace
            self._record_namespace('udf', True, entries,
                                   '%s: %s' % (type(exc).__name__, exc))

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------
    def _correlate(self):
        # type: () -> None
        available = [name for name in NAMESPACES
                     if name in self.namespaces and self.namespaces[name].available]
        by_path = collections.defaultdict(list)  # type: Dict[str, List[NamespaceEntry]]
        for name in available:
            for entry in self.namespaces[name].entries:
                by_path[entry.path].append(entry)

        for path in sorted(by_path):
            group = by_path[path]
            comparison = PathComparison(path)
            comparison.entries = {entry.namespace: entry for entry in group}
            comparison.present_in = [entry.namespace for entry in group]
            comparison.missing_in = [name for name in available
                                     if name not in comparison.entries]

            file_entries = [e for e in group
                            if e.entry_type in (_TYPE_FILE, _TYPE_SYMLINK)]
            for entry in group:
                comparison.identities.add(entry.identity)
                digest = self.content_digest(entry)
                if digest is not None:
                    comparison.digests.add(digest)

            comparison.relation, comparison.explanation = self._classify(
                group, file_entries, comparison)
            self.comparisons.append(comparison)

    def _classify(self, group, file_entries, comparison):
        # type: (List[NamespaceEntry], List[NamespaceEntry], PathComparison) -> Tuple[str, str]
        if any(entry.entry_type == _TYPE_SYMLINK for entry in group):
            return ('symlink',
                    'At least one namespace stores this path as a symbolic '
                    'link; the link target, not data extents, defines its '
                    'content.')

        distinct_identities = comparison.identities

        # Decide the data-source relation among the namespaces that actually
        # contain this path.  Presence in only one namespace means there is no
        # cross-namespace identity to compare yet.
        data_relation = None  # type: Optional[Tuple[str, str]]
        if len(group) > 1:
            if len(distinct_identities) == 1:
                data_relation = (
                    'hard-link',
                    'Same data source: all present names resolve to the same '
                    'inode and data extent range(s); the names are hard links '
                    'to one allocation, differing only in their name mapping.')
            elif len(comparison.digests) > 1:
                data_relation = (
                    'different-content',
                    'Data-source difference: the names resolve to distinct '
                    'inodes with distinct data extents and different byte '
                    'content.  Equal paths here do not mean equal data.')
            elif len(comparison.digests) == 1 and len(file_entries) > 1:
                data_relation = (
                    'same-content-copy',
                    'Name-mapping difference only: independent inodes with '
                    'separate data extents hold byte-identical copies.  These '
                    'are duplicate copies, not hard links; editing one would '
                    'not change the other.')
            else:
                data_relation = (
                    'different-content',
                    'Data-source difference: distinct inodes with separate '
                    'data extents; content could not be fully hashed, but the '
                    'allocations are independent.')

        if comparison.missing_in:
            missing_note = (
                'Name-mapping difference: the path is absent from %s, so the '
                'namespaces do not expose the same tree.'
                % ', '.join(comparison.missing_in))
            if data_relation is None:
                return ('missing-somewhere', missing_note)
            # Keep the real data-source relation visible instead of hiding it
            # behind the missing label; append the name-mapping caveat.
            relation, explanation = data_relation
            return relation, explanation + '  Additionally, ' + missing_note

        if data_relation is not None:
            return data_relation
        return ('single-entry',
                'Only one namespace exposes this path, so no cross-namespace '
                'comparison is possible.')


def build_report(iso):
    # type: (PyCdlib) -> NamespaceDiffReport
    """
    Build a read-only namespace difference report for an opened ISO.

    Args:
        iso: An already-opened :class:`pycdlib.PyCdlib` object.
    Returns:
        A populated :class:`NamespaceDiffReport`.
    """
    return NamespaceDiffReport(iso).build()


def open_and_report(path_or_fp):
    # type: (object) -> NamespaceDiffReport
    """
    Open an ISO from a filename or binary file object and build its report.

    Args:
        path_or_fp: A filesystem path (str) or an open binary file object.
    Returns:
        A populated :class:`NamespaceDiffReport`.  When a file object was
        passed in, its lifetime is still managed by the caller.
    """
    import pycdlib as _pycdlib
    iso = _pycdlib.PyCdlib()
    if isinstance(path_or_fp, (str, bytes)):
        iso.open(path_or_fp)
        report = build_report(iso)
        iso.close()
        return report
    iso.open_fp(path_or_fp)
    return build_report(iso)


def _format_data_ranges(ranges, block_size):
    # type: (List[DataRange], int) -> str
    if not ranges:
        return 'no data extents'
    parts = []
    for data_range in ranges:
        if data_range.inline:
            parts.append('inline@%d(%d bytes)' % (data_range.extent,
                                                  data_range.length))
        else:
            start_byte = data_range.extent * block_size
            parts.append('LBA %d (bytes %d..%d, %d bytes)' % (
                data_range.extent, start_byte,
                start_byte + data_range.length - 1, data_range.length))
    return '; '.join(parts)


def render_text(report):
    # type: (NamespaceDiffReport) -> str
    """Render a :class:`NamespaceDiffReport` as a human-readable string."""
    lines = []  # type: List[str]
    lines.append('ISO namespace difference report (read-only)')
    lines.append('Logical block size: %d bytes' % report.block_size)
    lines.append('')

    lines.append('Namespaces')
    for name in NAMESPACES:
        result = report.namespaces.get(name)
        if result is None:
            lines.append('  %-9s not present on this ISO' % name)
            continue
        if result.error is not None:
            lines.append('  %-9s ENUMERATION FAILED (%d entries recovered): %s'
                         % (name, len(result.entries), result.error))
        else:
            lines.append('  %-9s %d entries' % (name, len(result.entries)))
    lines.append('')

    lines.append('Per-namespace records (original name, record location, data range)')
    for name in NAMESPACES:
        result = report.namespaces.get(name)
        if result is None:
            continue
        lines.append('  [%s]%s' % (name,
                     '  ERROR: %s' % result.error if result.error else ''))
        for entry in result.entries:
            location = entry.record_location
            lines.append('    %s' % entry.path)
            lines.append('        raw name : %r' % entry.raw_name)
            lines.append('        type     : %s%s' % (
                entry.entry_type,
                (' -> %s' % entry.symlink_target)
                if entry.symlink_target else ''))
            lines.append('        record   : LBA %d offset %d (%d bytes)' % (
                location.extent, location.offset, location.length))
            lines.append('        data     : %s' % _format_data_ranges(
                entry.data_ranges, report.block_size))
            lines.append('        identity : %s' % entry.identity)
    lines.append('')

    lines.append('Path comparison (no namespace is treated as authoritative)')
    for comparison in report.comparisons:
        lines.append('  %s' % comparison.path)
        lines.append('    present in : %s' % ', '.join(comparison.present_in))
        if comparison.missing_in:
            lines.append('    missing in : %s'
                         % ', '.join(comparison.missing_in))
        lines.append('    identities : %s'
                     % ', '.join(sorted(comparison.identities)))
        if comparison.digests:
            lines.append('    digests    : %d distinct'
                         % len(comparison.digests))
        lines.append('    relation   : %s' % comparison.relation)
        lines.append('    explanation: %s' % comparison.explanation)
    lines.append('')

    failed = [name for name, result in report.namespaces.items()
              if result.error is not None]
    if failed:
        lines.append('Warning: %s could not be fully enumerated; findings '
                     'above from the other namespaces are still reported.'
                     % ', '.join(failed))
    else:
        lines.append('All present namespaces enumerated without error.')
    return '\n'.join(lines)
