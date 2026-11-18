""" Targeted mutation of PowerPoint 97-2003 persist-object graphs.

The module builds a small but valid PPT persist graph in memory, then applies
byte-level mutations that keep the outer record structure superficially
plausible. This makes it possible to test whether a broken PersistIdRef is
silently interpreted as some other legal record.

Design rules
------------
* The graph is explicit: record offsets, record hierarchy, persist id
  mappings, the UserEditAtom chain and storage compression declarations are
  all known before mutation.
* Mutations are stored as (offset, original, replacement) patches, so the
  original bytes and a reduced subset of changes can always be recovered.
* Every legal target carries a distinct marker. A mutation that retargets a
  reference therefore shows up as a marker mismatch, not just as a crash.
* Unknown records are present and are skipped by their declared length. They
  are never treated as recovery points for a damaged reference.

The parser under test is :class:`oletools.ppt_parser.PptParser`.

Run the self-test with::

    python -m oletools.ppt_mutation --self-test

or write a corpus with byte-level patches and a manifest::

    python -m oletools.ppt_mutation --out ppt-mutation-corpus
"""

# === LICENSE =================================================================
# Same BSD license as the rest of oletools.

from __future__ import print_function

import argparse
import io
import json
import os
import struct
import sys
import zlib

try:
    import olefile
except ImportError:      # pragma: no cover - olefile is a hard dependency
    olefile = None

try:
    from oletools import ppt_parser
except ImportError:      # allow running as a script from the repo root
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(
        __file__))))
    from oletools import ppt_parser


# === MARKERS =================================================================

MARK_DOC = b'MARK-DOC-V1'
MARK_UNKNOWN_CHILD = b'MARK-UNKNOWN-CHILD'
MARK_UNKNOWN_DOCINFO = b'MARK-UNKNOWN-DOCINFO'
MARK_STORAGE_OLD = b'MARK-STORAGE-OLD'
MARK_STORAGE_NEW = b'MARK-STORAGE-NEW'
MARK_STORAGE_B = b'MARK-STORAGE-B-COMPRESSED'
MARK_DECOY_SCAN = b'MARK-DECOY-SCAN'
MARK_DECOY_REL = b'MARK-DECOY-RELATIVE'

ALL_MARKERS = (
    MARK_DOC,
    MARK_UNKNOWN_CHILD,
    MARK_UNKNOWN_DOCINFO,
    MARK_STORAGE_OLD,
    MARK_STORAGE_NEW,
    MARK_STORAGE_B,
    MARK_DECOY_SCAN,
    MARK_DECOY_REL,
)


def find_markers(data):
    """ return sorted markers found in data """
    return sorted(marker for marker in ALL_MARKERS if marker in data)


def marker_of(data):
    """ return the first known marker in data, or None """
    for marker in ALL_MARKERS:
        if marker in data:
            return marker
    return None


# === BIT-LEVEL HELPERS =======================================================

def _record(rec_type, body, version=0, instance=0, declared_len=None):
    """ build a record header plus body """
    if declared_len is None:
        declared_len = len(body)
    ver_inst = (instance << 4) | version
    return struct.pack('<HHL', ver_inst, rec_type, declared_len) + body


def _pad(data, size, fill=b'\x00'):
    if len(data) > size:
        raise ValueError('payload {0} longer than {1}'.format(len(data), size))
    return data + fill * (size - len(data))


def _persist_entry(persist_id, offsets):
    """ one PersistDirectoryEntry: 12-bit count, 20-bit starting id """
    if not 1 <= len(offsets) <= 0xfff:
        raise ValueError('cPersist out of range')
    if not 0 <= persist_id <= 0xffffe:
        raise ValueError('persist id out of range')
    out = struct.pack('<L', (len(offsets) << 20) | persist_id)
    for offset in offsets:
        out += struct.pack('<L', offset)
    return out


def _persist_atom(entries):
    """ build a PersistDirectoryAtom from (persist_id, [offsets]) pairs """
    body = b''.join(_persist_entry(pid, offs) for pid, offs in entries)
    return _record(0x1772, body)


def _user_edit(offset_last_edit, offset_persist_directory,
               doc_persist_id_ref, persist_id_seed=1):
    body = struct.pack(
        '<LHBBLLLLHH',
        0,              # lastSlideIdRef
        0,              # version
        0x00,           # minorVersion
        0x03,           # majorVersion
        offset_last_edit,
        offset_persist_directory,
        doc_persist_id_ref,
        persist_id_seed,
        1,              # lastView
        0,              # unused
    )
    return _record(0x0ff5, body)


def _current_user(offset_to_current_edit):
    body = struct.pack(
        '<LLLHHBBH',
        0x14,           # size
        0xE391C05F,     # headerToken (not encrypted)
        offset_to_current_edit,
        0,              # lenUserName
        0x03F4,         # docFileVersion
        0x03,           # majorVersion
        0x00,           # minorVersion
        0,              # unused
    ) + struct.pack('<L', 8)    # releaseVersion
    return _record(0x0ff6, body)


def _vba_info(persist_id_ref, has_macros=1):
    atom = _record(0x0400, struct.pack('<LLL', persist_id_ref, has_macros, 2),
                   version=2, instance=0)
    return _record(0x03ff, atom, version=0xF, instance=1)


def _storage(payload, compressed):
    """ build an ExOleObjStg record around payload """
    if compressed:
        body = struct.pack('<L', len(payload)) + zlib.compress(payload)
        return _record(0x1011, body, version=0, instance=1)
    return _record(0x1011, payload, version=0, instance=0)


class BytePatch(object):
    """ one in-place byte replacement, with the original bytes kept """

    def __init__(self, offset, replacement, original=None):
        self.offset = offset
        self.replacement = bytes(replacement)
        self.original = original

    def bind(self, data):
        """ capture original bytes from data, verify consistency later """
        self.original = bytes(data[self.offset:self.offset +
                                   len(self.replacement)])
        return self

    def apply(self, data):
        end = self.offset + len(self.replacement)
        if self.original is not None and data[self.offset:end] != \
                self.original and data[self.offset:end] != self.replacement:
            raise ValueError('patch base bytes changed at {0}'
                             .format(self.offset))
        return data[:self.offset] + self.replacement + data[end:]

    def to_dict(self):
        return dict(offset=self.offset,
                    original=self.original.hex(),
                    replacement=self.replacement.hex())


class MutationCase(object):
    """ a graph plus an ordered set of byte patches

    ``original`` is never modified. ``data()`` applies the current patches;
    ``revert()`` returns the untouched bytes.
    """

    def __init__(self, name, original, patches, description='', expected=None):
        self.name = name
        self.original = bytes(original)
        self.patches = list(patches)
        self.description = description
        self.expected = expected or {}

    def data(self):
        data = self.original
        for patch in self.patches:
            data = patch.apply(data)
        return data

    def revert(self):
        return self.original

    def without(self, patches):
        return MutationCase(self.name, self.original, patches,
                            self.description, self.expected)

    def to_dict(self):
        return dict(name=self.name,
                    description=self.description,
                    original_sha256=_sha256(self.original),
                    original_size=len(self.original),
                    expected=self.expected,
                    patches=[patch.to_dict() for patch in self.patches])


def _sha256(data):
    try:
        import hashlib
        return hashlib.sha256(data).hexdigest()
    except ImportError:         # pragma: no cover
        return ''


# === SYNTHETIC GRAPH =========================================================

class SyntheticGraph(object):
    """ a valid PPT persist graph with named, distinct target markers

    Layout of the PowerPoint Document stream (absolute offsets)::

        0                      preamble record (unknown type, marker SKIP)
        DOC                    DocumentContainer
                                 DocumentAtom        MARK-DOC-V1
                                 unknown 0x7777      MARK-UNKNOWN-CHILD
                                 DocInfoListContainer
                                   unknown 0x7778    MARK-UNKNOWN-DOCINFO
                                   VBAInfo -> id 2
                                   VBAInfo -> id 5   (shares id 2's target)
                                   VBAInfo -> id 3
        off_old                storage OLD            MARK-STORAGE-OLD
        off_b                  compressed storage B   MARK-STORAGE-B-COMPRESSED
        P_old                  old persist directory  ids 1,2,3
        E_old                  old UserEditAtom       offsetLastEdit = 0
        decoy_abs              decoy storage          MARK-DECOY-SCAN
        off_new                storage NEW            MARK-STORAGE-NEW
        P_new                  new persist directory  id 2 and 5 -> off_new
        E_new                  new UserEditAtom       offsetLastEdit = E_old
    """

    DOC = None
    OFF_OLD = None
    OFF_B = None
    P_OLD = None
    E_OLD = None
    DECOY_SCAN = None
    DECOY_REL = None
    OFF_NEW = None
    P_NEW = None
    E_NEW = None
    DOCINFO_START = None
    DOCINFO_END = None

    def __init__(self):
        self.stream = self._build()
        self.current_user = _current_user(self.E_NEW)

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def document_body():
        atom = _record(0x03e9, _pad(MARK_DOC, 0x28),
                       version=1, instance=0)
        unknown_child = _record(
            0x7777, _pad(MARK_UNKNOWN_CHILD, 24), version=0, instance=0)

        docinfo_children = _record(
            0x7778, _pad(MARK_UNKNOWN_DOCINFO, 20), version=0, instance=0)
        docinfo_children += _vba_info(2)
        docinfo_children += _vba_info(5)
        docinfo_children += _vba_info(3)

        docinfo = _record(0x07d0, docinfo_children, version=0xF, instance=0)
        docinfo_start = 8 + len(atom) + len(unknown_child)
        docinfo_end = docinfo_start + len(docinfo)
        return (atom + unknown_child + docinfo, docinfo_start, docinfo_end)

    def _build(self):
        body, docinfo_rel_start, docinfo_rel_end = self.document_body()
        # Keep the preamble large enough that DOC exceeds the decoy record so
        # the relative/absolute collision below can be laid out exactly.
        preamble = _record(0x7779, _pad(b'PREAMBLE-SKIP', 120))
        self.DOC = len(preamble)

        doc = _record(0x03e8, body, version=0xF, instance=0)
        self.DOCINFO_START = self.DOC + docinfo_rel_start
        self.DOCINFO_END = self.DOC + docinfo_rel_end

        old = _storage(_pad(MARK_STORAGE_OLD, 32), compressed=False)
        comp = _storage(_pad(MARK_STORAGE_B, 40), compressed=True)
        self.OFF_OLD = self.DOC + len(doc)
        self.OFF_B = self.OFF_OLD + len(old)

        # Unreferenced storage with a scan decoy: a broken persist reference
        # must not "recover" by finding this signature.
        self.DECOY_SCAN = self.OFF_B + len(comp)
        scan_decoy = _storage(_pad(MARK_DECOY_SCAN, 32), compressed=False)

        old_dir = _persist_atom([(1, [self.DOC]),
                                 (2, [self.OFF_OLD]),
                                 (3, [self.OFF_B])])
        self.P_OLD = self.DECOY_SCAN + len(scan_decoy)
        old_edit = _user_edit(0, self.P_OLD, 1)
        self.E_OLD = self.P_OLD + len(old_dir)

        # Relative-offset decoy: an absolute read of (OFF_NEW - DOC) lands
        # here. It is itself a valid storage record with its own marker.
        self.DECOY_REL = self.E_OLD + 128
        edit_gap = b'\x00' * (self.DECOY_REL -
                               (self.E_OLD + len(old_edit)))
        rel_decoy = _storage(_pad(MARK_DECOY_REL, 32), compressed=False)
        if len(rel_decoy) > self.DOC:
            raise AssertionError('decoy does not fit before its absolute '
                                 'collision point')
        self.OFF_NEW = self.DOC + self.DECOY_REL
        new_storage = _storage(_pad(MARK_STORAGE_NEW, 32), compressed=False)
        gap = b'\x00' * (self.OFF_NEW - (self.DECOY_REL + len(rel_decoy)))

        new_dir = _persist_atom([(2, [self.OFF_NEW]),
                                 (5, [self.OFF_NEW])])
        self.P_NEW = self.OFF_NEW + len(new_storage)
        new_edit = _user_edit(self.E_OLD, self.P_NEW, 1, persist_id_seed=2)
        self.E_NEW = self.P_NEW + len(new_dir)
        new_edit = _user_edit(self.E_OLD, self.P_NEW, 1, persist_id_seed=2)

        stream = (preamble + doc + old + comp + scan_decoy + old_dir +
                  old_edit + edit_gap + rel_decoy + gap + new_storage +
                  new_dir + new_edit)
        if self.E_NEW + len(new_edit) != len(stream):
            raise AssertionError('layout mismatch: {0} != {1}'.format(
                self.E_NEW + len(new_edit), len(stream)))
        return stream

    # -- stream/persist helpers ----------------------------------------------

    def stream_offset_of(self, marker):
        index = self.stream.index(marker)
        return index

    def directory_entries(self):
        """ newest-first list of (user_edit_offset, [(id, [offsets])]) """
        return [
            (self.E_NEW, [(2, [self.OFF_NEW]), (5, [self.OFF_NEW])]),
            (self.E_OLD, [(1, [self.DOC]), (2, [self.OFF_OLD]),
                          (3, [self.OFF_B])]),
        ]

    def oracle(self):
        doc_len = struct.unpack('<L', self.stream[
            self.DOC + 4:self.DOC + 8])[0]
        return dict(
            document_marker=MARK_DOC.decode('ascii'),
            document_offset=self.DOC,
            document_end=self.DOC + 8 + doc_len,
            docinfo_start=self.DOCINFO_START,
            docinfo_end=self.DOCINFO_END,
            refs={
                '2': MARK_STORAGE_NEW.decode('ascii'),
                '5': MARK_STORAGE_NEW.decode('ascii'),
                '3': MARK_STORAGE_B.decode('ascii'),
            },
            shared_persist_ids=[2, 5],
            unknown_markers=[MARK_UNKNOWN_CHILD.decode('ascii'),
                             MARK_UNKNOWN_DOCINFO.decode('ascii')],
        )

    def to_ole(self):
        data, _layout = build_cfb([
            ('PowerPoint Document', self.stream),
            ('Current User', self.current_user),
        ])
        return data

    def layout(self):
        """ absolute CFB file offset of the PowerPoint Document stream """
        _data, layout = build_cfb([
            ('PowerPoint Document', self.stream),
            ('Current User', self.current_user),
        ])
        return layout


# === MINIMAL CFB (OLE2) WRITER ==============================================

FREE = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
SECTOR = 512
MINI_SECTOR = 64
MINI_CUTOFF = 4096


def build_cfb(streams):
    """ build a minimal OLE2 compound file from [(name, bytes), ...]

    Only what olefile needs for reading is implemented: v3, 512-byte sectors,
    64-byte mini sectors, one FAT chain, a simple right-sibling directory
    tree. Streams larger or equal to 4096 bytes use regular sectors, everything
    else the mini stream.
    """
    streams = list(streams)
    mini = bytearray()
    minifat = []
    alloc = {}
    for name, data in streams:
        if len(data) < MINI_CUTOFF:
            if not data:
                alloc[name] = ['mini', ENDOFCHAIN, 0]
                continue
            count = (len(data) + MINI_SECTOR - 1) // MINI_SECTOR
            start = len(mini) // MINI_SECTOR
            mini += data + b'\x00' * (count * MINI_SECTOR - len(data))
            for index in range(count):
                minifat.append(start + index + 1
                               if index < count - 1 else ENDOFCHAIN)
            alloc[name] = ['mini', start, count]
        else:
            alloc[name] = ['large', None,
                           (len(data) + SECTOR - 1) // SECTOR]

    ndir_sectors = (1 + len(streams)) * 128 // SECTOR
    if (1 + len(streams)) * 128 % SECTOR:
        ndir_sectors += 1
    nmini_sectors = (len(mini) + SECTOR - 1) // SECTOR
    nminifat_sectors = (len(minifat) * 4 + SECTOR - 1) // SECTOR
    nlarge = sum(a[2] for a in alloc.values() if a[0] == 'large')

    nfat = 1
    while True:
        total = nfat + ndir_sectors + nminifat_sectors + nmini_sectors + \
            nlarge
        needed = (total * 4 + SECTOR - 1) // SECTOR
        if needed <= nfat:
            break
        nfat = needed

    fat = [FREE] * (nfat * 128)
    for index in range(nfat):
        fat[index] = FATSECT

    def chain(start, count):
        for index in range(count):
            fat[start + index] = start + index + 1 \
                if index < count - 1 else ENDOFCHAIN

    dir_start = nfat
    minifat_start = dir_start + ndir_sectors
    mini_start = minifat_start + nminifat_sectors
    large_start = mini_start + nmini_sectors
    chain(dir_start, ndir_sectors)
    if nminifat_sectors:
        chain(minifat_start, nminifat_sectors)
    if nmini_sectors:
        chain(mini_start, nmini_sectors)
    for name, data in streams:
        if alloc[name][0] == 'large':
            alloc[name][1] = large_start
            chain(large_start, alloc[name][2])
            large_start += alloc[name][2]

    entries = [('Root Entry', 5, mini_start if nmini_sectors else ENDOFCHAIN,
                len(mini), -1, -1, 1 if streams else -1)]
    for index, (name, data) in enumerate(streams):
        kind, start, _ = alloc[name]
        right = index + 2 if index + 2 <= len(streams) else -1
        entries.append((name, 2, start, len(data), -1, right, -1))

    dirbuf = bytearray(ndir_sectors * SECTOR)
    for index, entry in enumerate(entries):
        name, etype, start, size, left, right, child = entry
        raw = bytearray(128)
        name_bytes = name.encode('utf-16-le') + b'\x00\x00'
        raw[:len(name_bytes)] = name_bytes
        struct.pack_into('<H', raw, 64, len(name_bytes))
        raw[66] = etype
        raw[67] = 1                 # black
        struct.pack_into('<i', raw, 68, left)
        struct.pack_into('<i', raw, 72, right)
        struct.pack_into('<i', raw, 76, child)
        struct.pack_into('<I', raw, 116, start)
        struct.pack_into('<Q', raw, 120, size)
        dirbuf[index * 128:(index + 1) * 128] = raw

    minifat_buf = bytearray(nminifat_sectors * SECTOR)
    for index, value in enumerate(minifat):
        struct.pack_into('<I', minifat_buf, index * 4, value)

    fat_buf = bytearray(nfat * SECTOR)
    for index, value in enumerate(fat):
        struct.pack_into('<I', fat_buf, index * 4, value)

    header = bytearray(SECTOR)
    header[0:8] = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
    struct.pack_into('<H', header, 24, 0x003e)   # minor version
    struct.pack_into('<H', header, 26, 3)        # major version
    struct.pack_into('<H', header, 28, 0xfffe)   # byte order
    struct.pack_into('<H', header, 30, 9)        # sector shift
    struct.pack_into('<H', header, 32, 6)        # mini sector shift
    struct.pack_into('<I', header, 44, nfat)
    struct.pack_into('<I', header, 48, dir_start)
    struct.pack_into('<I', header, 56, MINI_CUTOFF)
    struct.pack_into('<I', header, 60,
                     minifat_start if nminifat_sectors else ENDOFCHAIN)
    struct.pack_into('<I', header, 64, nminifat_sectors)
    struct.pack_into('<I', header, 68, ENDOFCHAIN)   # no DIFAT
    struct.pack_into('<I', header, 72, 0)
    for index in range(109):
        struct.pack_into('<I', header, 76 + index * 4,
                         index if index < nfat else FREE)

    body = bytearray()
    body += fat_buf
    body += dirbuf
    body += minifat_buf
    if nmini_sectors:
        body += mini + b'\x00' * (nmini_sectors * SECTOR - len(mini))
    for name, data in streams:
        kind, start, count = alloc[name]
        if kind == 'large':
            body += data + b'\x00' * (count * SECTOR - len(data))

    if len(body) % SECTOR:
        raise AssertionError('CFB body is not sector aligned')

    layout = {}
    mini_base = SECTOR + len(fat_buf) + len(dirbuf) + len(minifat_buf)
    for name, data in streams:
        kind, start, _count = alloc[name]
        if kind == 'mini':
            layout[name] = mini_base + start * MINI_SECTOR
        else:
            layout[name] = SECTOR + start * SECTOR
    return bytes(header) + bytes(body), layout


# === PARSE / ANALYSIS ========================================================

class AnalysisError(Exception):
    """ raised when the mutated graph is rejected by the strict parser """

    def __init__(self, message, analysis=None):
        super(AnalysisError, self).__init__(message)
        self.analysis = analysis or {}


def _storage_payload(parser, storage):
    if storage.is_compressed:
        return parser.decompress_vba_storage(storage)
    return parser.read_vba_storage_data(storage)


def analyze(data):
    """ parse ``data`` and return a structural summary

    The summary contains the document record bounds, each VBAInfo record's
    bounds and persist reference, the resolved storage marker and ownership,
    unknown records that were skipped, and the stop positions of the parsed
    hierarchy. Any rejection by the strict parser is raised as
    :class:`AnalysisError` with whatever partial information was gathered.
    """
    if olefile is None:      # pragma: no cover
        raise RuntimeError('olefile is required')
    ole = olefile.OleFileIO(io.BytesIO(data))
    parser = ppt_parser.PptParser(ole, fast_fail=True)
    result = dict(stream_size=None,
                  document=None, vba_infos=[], storages=[], unknown=[],
                  stop={})
    try:
        stream = parser.ole.openstream(ppt_parser.MAIN_STREAM_NAME)
        stream_bytes = stream.read()
        stream.close()
        result['stream_size'] = len(stream_bytes)

        parser.parse_current_user()
        parser.parse_persist_object_directory()
        parser.parse_document_persist_object()

        doc = parser.document_persist_obj
        result['document'] = dict(
            offset=doc.offset,
            end=doc.record_end,
            declared_len=doc.rec_head.rec_len,
            marker=(marker_of(stream_bytes[doc.offset:doc.record_end])
                    or b'').decode('ascii'),
            validity=[str(err) for err in doc.check_validity()],
        )
        result['stop']['document'] = doc.record_end

        if doc.doc_info_list is not None:
            info = doc.doc_info_list
            result['stop']['docinfo'] = info.end
            result['docinfo'] = dict(offset=info.start, end=info.end,
                                     declared_len=info.rec_head.rec_len)

        for raw in doc.children:
            if isinstance(raw, ppt_parser.PptRawRecord):
                result['unknown'].append(dict(
                    kind='document-child',
                    record_type=raw.rec_head.rec_type,
                    offset=raw.start,
                    end=raw.end,
                    marker=(marker_of(stream_bytes[raw.start:raw.end])
                            or b'').decode('ascii'),
                ))

        for info in parser.iter_vba_infos():
            payload = stream_bytes[info.start:info.end]
            result['vba_infos'].append(dict(
                offset=info.start,
                end=info.end,
                persist_id_ref=info.vba_info_atom.persist_id_ref,
                has_macros=info.vba_info_atom.f_has_macros,
                owner_offset=doc.offset,
                marker=marker_of(payload),
            ))
        for info in doc.doc_info_list.rg_child_rec \
                if doc.doc_info_list else ():
            if isinstance(info, ppt_parser.PptRawRecord):
                result['unknown'].append(dict(
                    kind='docinfo-child',
                    record_type=info.rec_head.rec_type,
                    offset=info.start,
                    end=info.end,
                    marker=marker_of(stream_bytes[info.start:info.end]),
                ))

        for storage in parser.iter_vba_storages():
            payload = _storage_payload(parser, storage)
            result['storages'].append(dict(
                persist_id_ref=storage.persist_id_ref,
                offset=storage.offset,
                end=storage.offset + 8 + storage.rec_head.rec_len,
                compressed=storage.is_compressed,
                data_size=storage.data_size,
                uncompressed_size=storage.uncompressed_size,
                referenced_by=storage.owner_offset,
                owner_offset=storage.owner_offset,
                marker=marker_of(payload),
                payload_prefix=payload[:16].hex(),
            ))
            result['stop']['storage-{0}'.format(storage.persist_id_ref)] = \
                storage.offset + 8 + storage.rec_head.rec_len
        result['stop']['stream_end'] = len(stream_bytes)
    except Exception as exc:
        partial = AnalysisError(str(exc), result)
        partial.exc_type = exc.__class__.__name__
        raise partial
    finally:
        ole.close()
    return result


def summarize(analysis):
    """ compact, JSON-serializable view of analyze() output """
    return dict(
        stream_size=analysis.get('stream_size'),
        document=analysis.get('document'),
        refs={str(storage['persist_id_ref']):
              (storage['marker'].decode('ascii')
               if storage['marker'] else None)
              for storage in analysis.get('storages', [])},
        storages=[dict(persist_id_ref=s['persist_id_ref'],
                       offset=s['offset'],
                       compressed=s['compressed'],
                       marker=(s['marker'].decode('ascii')
                               if isinstance(s['marker'], bytes)
                               else s['marker']),
                       referenced_by=s['referenced_by'])
                  for s in analysis.get('storages', [])],
        unknown=[dict(record_type=u['record_type'], offset=u['offset'],
                      marker=(u['marker'].decode('ascii')
                              if isinstance(u['marker'], bytes)
                              else u['marker']))
                 for u in analysis.get('unknown', [])],
        stop=analysis.get('stop'),
    )


# === MUTATIONS ===============================================================

def _patch(data, offset, replacement):
    return BytePatch(offset, replacement).bind(data)


class MutationFactory(object):
    """ build named mutations from a validated synthetic graph

    ``self.data`` is the complete OLE file; ``self.base`` is the absolute file
    offset of the PowerPoint Document stream. Every patch offset is absolute
    in the OLE file, so applying the same patch to the bare stream is a
    one-line rebase. This makes the "stream-relative vs absolute" mistake an
    explicit, testable distinction.
    """

    def __init__(self, graph=None):
        self.graph = graph or SyntheticGraph()
        self.data = self.graph.to_ole()
        self.base = self.graph.layout()['PowerPoint Document']
        self._verify_baseline()

    def _at(self, stream_offset):
        """ convert a document-stream offset to an absolute file offset """
        return self.base + stream_offset

    def _patch(self, stream_offset, replacement):
        return _patch(self.data, self._at(stream_offset), replacement)

    def _verify_baseline(self):
        analysis = analyze(self.data)
        oracle = self.graph.oracle()
        refs = {str(storage['persist_id_ref']):
                storage['marker'].decode('ascii')
                for storage in analysis['storages']}
        if refs != oracle['refs']:
            raise AssertionError('baseline refs {0} != oracle {1}'
                                 .format(refs, oracle['refs']))
        if analysis['document']['marker'] != oracle['document_marker']:
            raise AssertionError('baseline document marker mismatch')

    # -- record hierarchy ----------------------------------------------------

    def record_length_parent(self):
        """ grow DocumentContainer recLen into the next top-level record """
        g = self.graph
        offset = g.DOC + 4
        old_len = struct.unpack(
            '<L', self.data[self._at(offset):self._at(offset) + 4])[0]
        return MutationCase(
            'record-length-parent',
            self.data,
            [self._patch(offset, struct.pack('<L', old_len + 8))],
            'DocumentContainer claims 8 bytes beyond its real body',
            expected=dict(rejected=True))

    def record_length_docinfo(self):
        """ grow DocInfoList recLen past the DocumentContainer boundary """
        g = self.graph
        offset = g.DOCINFO_START + 4
        old_len = struct.unpack(
            '<L', self.data[self._at(offset):self._at(offset) + 4])[0]
        return MutationCase(
            'record-length-docinfo',
            self.data,
            [self._patch(offset, struct.pack('<L', old_len + 8))],
            'DocInfoList spans its parent DocumentContainer boundary',
            expected=dict(rejected=True))

    def record_length_vba_atom(self):
        """ shrink VBAInfoContainer recLen so its atom crosses the boundary """
        g = self.graph
        info = [i for i in analyze(self.data)['vba_infos']
                if i['persist_id_ref'] == 2][0]
        offset = info['offset'] + 4
        old_len = struct.unpack(
            '<L', self.data[self._at(offset):self._at(offset) + 4])[0]
        return MutationCase(
            'record-length-vba-atom',
            self.data,
            [self._patch(offset, struct.pack('<L', old_len - 4))],
            'VBAInfoContainer boundary cuts through its VBAInfoAtom',
            expected=dict(rejected=True))

    # -- persist mapping -----------------------------------------------------

    def _vba_ref_offset(self, persist_id):
        for info in analyze(self.data)['vba_infos']:
            if info['persist_id_ref'] == persist_id:
                return info['offset'] + 8 + 8      # atom body starts after 2
        raise KeyError(persist_id)

    def persist_id_unknown_with_decoy(self):
        """ retarget VBAInfo to a missing id while a storage signature exists
        near it; strict resolution must not scan for that signature """
        offset = self._vba_ref_offset(2)
        return MutationCase(
            'persist-id-unknown-with-decoy',
            self.data,
            [self._patch(offset, struct.pack('<L', 99))],
            'persistIdRef 99 is absent; MARK-DECOY-SCAN is nearby but '
            'unreferenced',
            expected=dict(rejected=True, marker=MARK_DECOY_SCAN.decode()))

    def persist_offset_wrong_type(self):
        """ point id 2's newest mapping at a valid UserEditAtom """
        g = self.graph
        offset = self._find_entry_offset(g.P_NEW, persist_id=2)
        return MutationCase(
            'persist-offset-wrong-type',
            self.data,
            [self._patch(offset, struct.pack('<L', g.E_OLD))],
            'id 2 resolves to a valid UserEditAtom record, not a storage',
            expected=dict(rejected=True))

    def docinfo_boundary_shrunk(self):
        """ stop DocInfoList before its last VBAInfo child

        The bytes of the dropped child are still present and still parse as a
        perfect VBAInfoContainer when searched for; the parent boundary is the
        only thing that says they do not belong to the document.
        """
        g = self.graph
        offset = g.DOCINFO_START + 4
        old_len = struct.unpack(
            '<L', self.data[self._at(offset):self._at(offset) + 4])[0]
        atom_size = 8 + 12 + 8       # VBAInfoAtom + inner record header
        return MutationCase(
            'docinfo-boundary-shrunk',
            self.data,
            [self._patch(offset, struct.pack('<L', old_len - atom_size))],
            'DocInfoList boundary drops its last VBAInfo child; its bytes '
            'remain in the stream',
            expected=dict(rejected=False,
                          missing_persist_id=3,
                          marker=None))

    def persist_offset_relative_as_absolute(self):
        """ store off_new - DOC in the persist entry

        A consumer that confuses stream-relative and absolute offsets lands on
        MARK-DECOY-REL, which is a perfectly legal storage record.
        """
        g = self.graph
        offset = self._find_entry_offset(g.P_NEW, persist_id=2)
        relative = g.OFF_NEW - g.DOC
        return MutationCase(
            'persist-offset-relative-as-absolute',
            self.data,
            [self._patch(offset, struct.pack('<L', relative))],
            'persist offset stored relative to DOC; absolute lookup hits '
            'MARK-DECOY-REL',
            expected=dict(rejected=False,
                          marker=MARK_DECOY_REL.decode(),
                          unexpected=True))

    def persist_offset_out_of_range(self):
        """ point id 2 past the newest directory """
        g = self.graph
        offset = self._find_entry_offset(g.P_NEW, persist_id=2)
        return MutationCase(
            'persist-offset-out-of-range',
            self.data,
            [self._patch(offset,
                         struct.pack('<L', len(self.graph.stream)))],
            'persist offset lies outside the document stream',
            expected=dict(rejected=True))

    # -- user edit chain -----------------------------------------------------

    def edit_chain_self_cycle(self):
        g = self.graph
        offset = self._user_edit_field(g.E_NEW, 16)   # offsetLastEdit
        return MutationCase(
            'edit-chain-self-cycle',
            self.data,
            [self._patch(offset, struct.pack('<L', g.E_NEW))],
            'offsetLastEdit points at the same UserEditAtom',
            expected=dict(rejected=True))

    def edit_chain_forward(self):
        g = self.graph
        offset = self._user_edit_field(g.E_NEW, 16)
        return MutationCase(
            'edit-chain-forward',
            self.data,
            [self._patch(offset,
                         struct.pack('<L',
                                     g.E_OLD + len(self.graph.stream)))],
            'offsetLastEdit moves forward instead of backwards',
            expected=dict(rejected=True))

    def edit_chain_stale_directory(self):
        """ docPersistIdRef -> 3 (compressed storage), a legal record type """
        g = self.graph
        offset = self._user_edit_field(g.E_NEW, 24)   # docPersistIdRef
        return MutationCase(
            'edit-chain-docref-storage',
            self.data,
            [self._patch(offset, struct.pack('<L', 3))],
            'docPersistIdRef points at a storage object instead of the '
            'DocumentContainer',
            expected=dict(rejected=True))

    # -- storage declarations ------------------------------------------------

    def storage_compression_flag(self):
        """ clear the compressed bit without re-encoding the payload """
        storage = [s for s in analyze(self.data)['storages']
                   if s['persist_id_ref'] == 3][0]
        header = storage['offset']
        offset = header             # ver+instance live in the first uint16
        ver_inst = struct.unpack(
            '<H', self.data[self._at(offset):self._at(offset) + 2])[0]
        new = ((ver_inst & 0x000F) | 0x0000).to_bytes(2, 'little')
        return MutationCase(
            'storage-compression-flag',
            self.data,
            [self._patch(offset, new)],
            'storage B claims to be uncompressed; zlib bytes become payload',
            expected=dict(rejected=False, marker=None, unexpected=True))

    def storage_uncompressed_size(self):
        storage = [s for s in analyze(self.data)['storages']
                   if s['persist_id_ref'] == 3][0]
        offset = storage['offset'] + 8          # decompressedSize field
        size = struct.unpack(
            '<L', self.data[self._at(offset):self._at(offset) + 4])[0]
        return MutationCase(
            'storage-uncompressed-size',
            self.data,
            [self._patch(offset, struct.pack('<L', size + 1))],
            'compressed storage declares one byte too many',
            expected=dict(rejected=True))

    def storage_truncated(self):
        """ cut the zlib stream by shrinking recLen (payload bytes remain) """
        storage = [s for s in analyze(self.data)['storages']
                   if s['persist_id_ref'] == 3][0]
        offset = storage['offset'] + 4
        length = struct.unpack(
            '<L', self.data[self._at(offset):self._at(offset) + 4])[0]
        return MutationCase(
            'storage-truncated',
            self.data,
            [self._patch(offset, struct.pack('<L', length - 12))],
            'compressed storage recLen excludes the zlib tail',
            expected=dict(rejected=True))

    # -- combined cases ------------------------------------------------------

    def combined(self):
        """ several coordinates changed at once

        The record boundary, the persist target and the compression flag are
        changed together. Shrinking this case (see :func:`shrink`) removes
        the changes that are masked by the earlier rejection, so the reduced
        case can be inspected independently.
        """
        cases = [self.record_length_docinfo(),
                 self.persist_offset_wrong_type(),
                 self.storage_compression_flag()]
        patches = [p for case in cases for p in case.patches]
        return MutationCase(
            'combined-hierarchy-persist-storage',
            self.data,
            patches,
            'record boundary + persist target + compression flag changed',
            expected=dict(rejected=True))

    def all_cases(self):
        """ yield every named mutation case in a stable order """
        builders = [
            self.record_length_parent,
            self.record_length_docinfo,
            self.record_length_vba_atom,
            self.persist_id_unknown_with_decoy,
            self.persist_offset_wrong_type,
            self.persist_offset_relative_as_absolute,
            self.persist_offset_out_of_range,
            self.edit_chain_self_cycle,
            self.edit_chain_forward,
            self.edit_chain_stale_directory,
            self.storage_compression_flag,
            self.storage_uncompressed_size,
            self.storage_truncated,
            self.docinfo_boundary_shrunk,
            self.combined,
        ]
        for builder in builders:
            yield builder()

    # -- helpers -------------------------------------------------------------

    def _find_entry_offset(self, directory_offset, persist_id):
        stream = io.BytesIO(self.graph.stream)
        stream.seek(directory_offset)
        rec_type, rec_len, _ = _read_header(stream)
        if rec_type != 0x1772:
            raise AssertionError('not a persist directory')
        end = stream.tell() + rec_len
        while stream.tell() < end:
            pos = stream.tell()
            raw = stream.read(4)
            if len(raw) != 4:
                break
            value = struct.unpack('<L', raw)[0]
            count, pid = divmod(value, 2 ** 20)
            if pid == persist_id:
                return pos + 4
            stream.seek(4 * count, os.SEEK_CUR)
        raise KeyError(persist_id)

    def _user_edit_field(self, edit_offset, relative):
        # ``relative`` is measured from the record start, including the
        # 8-byte record header.
        return edit_offset + relative


def _read_header(stream):
    raw = stream.read(8)
    if len(raw) != 8:
        raise ValueError('truncated record header')
    ver_inst, rec_type, rec_len = struct.unpack('<HHL', raw)
    return rec_type, rec_len, (ver_inst >> 4, ver_inst & 0xf)


# === REDUCTION ===============================================================

def shrink(case, predicate, max_passes=100):
    """ remove patches while ``predicate(data, case)`` still holds

    ``predicate`` receives (mutated bytes, provisional case) and returns True
    when the interesting outcome is still present. The returned case contains
    a minimal subset of the original changes; ``revert()`` still returns the
    pristine bytes.
    """
    patches = list(case.patches)
    passes = 0
    changed = True
    while changed and passes < max_passes:
        changed = False
        passes += 1
        for index in range(len(patches)):
            candidate = patches[:index] + patches[index + 1:]
            probe = case.without(candidate)
            if predicate(probe.data(), probe):
                patches = candidate
                changed = True
                break
    return case.without(patches)


# === MERGE-ORDER COUNTEREXAMPLE =============================================

def merged_directory(edits, newest_wins=True):
    """ merge persist dirs from ``edits`` (newest first)

    ``newest_wins=True`` implements [MS-PPT]: iterate directories from oldest
    to newest, later insertions replace earlier ones. With
    ``newest_wins=False`` the caller gets the "old table wins" result used as a
    stable counterexample.
    """
    result = {}
    ordered = reversed(edits) if newest_wins else list(edits)
    for edit in ordered:
        for persist_id, offsets in edit['entries']:
            for index, offset in enumerate(offsets):
                result[persist_id + index] = offset
    return result


def resolve_marker(data, mapping, persist_id):
    """ return the storage marker at mapping[persist_id], or None """
    if persist_id not in mapping:
        return None
    offset = mapping[persist_id]
    stream = io.BytesIO(data)
    stream.seek(offset)
    try:
        rec_type, rec_len, (instance, _version) = _read_header(stream)
    except ValueError:
        return None
    if rec_type != 0x1011:
        return None
    payload = data[stream.tell():stream.tell() + rec_len]
    if instance == 1 and len(payload) >= 4:
        try:
            payload = zlib.decompress(payload[4:])
        except zlib.error:
            return None
    elif instance == 1:
        return None
    return marker_of(payload)


def directory_views(graph, stream=None):
    """ newest-wins and old-wins marker views for the synthetic graph """
    if stream is None:
        stream = graph.stream
    edits = [
        dict(offset=graph.E_NEW,
             entries=[(2, [graph.OFF_NEW]), (5, [graph.OFF_NEW])]),
        dict(offset=graph.E_OLD,
             entries=[(1, [graph.DOC]), (2, [graph.OFF_OLD]),
                      (3, [graph.OFF_B])]),
    ]
    newest = merged_directory(edits, newest_wins=True)
    oldest = merged_directory(edits, newest_wins=False)
    return dict(newest_mapping=newest, old_mapping=oldest,
                newest_marker=_marker_name(resolve_marker(stream, newest, 2)),
                old_marker=_marker_name(resolve_marker(stream, oldest, 2)))


def _marker_name(marker):
    if isinstance(marker, bytes):
        return marker.decode('ascii')
    return marker


# === CLI =====================================================================

def _write_corpus(out_dir):
    factory = MutationFactory()
    graph = factory.graph
    os.makedirs(out_dir, exist_ok=True)

    def write(name, data):
        path = os.path.join(out_dir, name)
        with open(path, 'wb') as handle:
            handle.write(data)
        return path

    manifest = dict(interpreter=sys.version.split()[0],
                    baseline=dict(file='baseline.ppt',
                                  size=len(factory.data),
                                  oracle=graph.oracle()),
                    cases=[])
    write('baseline.ppt', factory.data)
    for name in sorted(dir(factory)):
        if not name.startswith(('persist_', 'edit_', 'record_', 'storage_',
                                'docinfo_', 'combined')):
            continue
        method = getattr(factory, name)
        if not callable(method):
            continue
        try:
            case = method()
        except Exception as exc:        # pragma: no cover - defensive
            manifest['cases'].append(dict(name=name, error=str(exc)))
            continue
        file_name = case.name + '.ppt'
        write(file_name, case.data())
        entry = case.to_dict()
        entry['file'] = file_name
        try:
            summary = summarize(analyze(case.data()))
            entry['analysis'] = summary
            entry['rejected'] = False
        except AnalysisError as exc:
            entry['rejected'] = True
            entry['error'] = str(exc)
            entry['analysis'] = summarize(exc.analysis)
        manifest['cases'].append(entry)

    with open(os.path.join(out_dir, 'manifest.json'), 'w') as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='targeted mutation of PPT persist-object graphs')
    parser.add_argument('--out', default='ppt-mutation-corpus',
                        help='directory for generated corpus (default: %(default)s)')
    parser.add_argument('--self-test', action='store_true',
                        help='build the baseline graph and print a summary')
    args = parser.parse_args(argv)
    if args.self_test:
        factory = MutationFactory()
        print(json.dumps(summarize(analyze(factory.data)), indent=2,
                         sort_keys=True))
        print(json.dumps(directory_views(factory.graph),
                         indent=2, sort_keys=True, default=str))
        return 0
    manifest = _write_corpus(args.out)
    print('wrote {0} files to {1}'.format(len(manifest['cases']) + 1,
                                          args.out))
    return 0


if __name__ == '__main__':
    sys.exit(main())
