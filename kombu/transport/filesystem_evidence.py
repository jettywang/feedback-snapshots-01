"""Offline evidence export for the filesystem transport.

This module inspects *static copies* of the directories used by
:mod:`kombu.transport.filesystem` (``data_folder_in``, ``data_folder_out``,
``processed_folder`` and ``control_folder``) without connecting to any
broker.  It builds a content-addressed snapshot of every file it finds and
compares two such snapshots -- typically a reference copy taken earlier and
a candidate copy taken later -- to explain what happened to each message
file.

The export answers the questions an auditor asks of a seized copy:

* which files are byte-identical to the reference (SHA-256 + size, so the
  file identity can be re-verified independently),
* which queue each message belonged to and how many messages per queue
  remain in each copy,
* which files only *moved* -- the transport fetches a message with
  ``shutil.move()`` into ``processed_folder`` (or the temp dir), which
  preserves the original bytes and modification time, so a move trace is
  not evidence that the payload was updated,
* which files share the same payload under different names (redelivered or
  republished duplicates),
* which files could not be read at all (read failures are reported, never
  fatal).

Run it directly against two directory copies::

    python -m kombu.transport.filesystem_evidence REFERENCE_DIR CANDIDATE_DIR \
        --output evidence.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

from kombu.utils.encoding import bytes_to_str
from kombu.utils.json import loads

VERSION = (1, 0, 0)
__version__ = '.'.join(map(str, VERSION))

__all__ = (
    'build_snapshot',
    'compare_snapshots',
    'export_evidence',
    'main',
)

#: Suffix the transport gives to message files: ``{ms}_{uuid}.{queue}.msg``.
MESSAGE_SUFFIX = '.msg'

#: Suffix of the exchange-to-queue binding tables in ``control_folder``.
CONTROL_SUFFIX = '.exchange'

#: Explanation attached to entries that are nothing but a relocation.
MOVE_NOTE = (
    'move trace only: the filesystem transport relocates a message file '
    'with shutil.move() when it is fetched; the original file bytes and '
    'modification time are preserved, so the payload and its timestamps '
    'were not updated'
)

#: Explanation when the bytes survived the move but the mtime did not.
MOVE_MTIME_CHANGED_NOTE = (
    'file bytes are identical to the reference but the modification time '
    'differs; the payload itself was not updated'
)

#: Explanation when the payload reappears under a different file name.
SAME_PAYLOAD_NOTE = (
    'same payload, different file: these bytes exist in the other snapshot '
    'under a different name (republish or redelivery), not a move of this '
    'file'
)


def _message_queue(name):
    """Return the queue a file belongs to, or None if it is not a message.

    Mirrors the matching in ``Channel._get``: everything after the first
    dot must end in ``.msg``.
    """
    suffix = name.partition('.')[2]
    if suffix.endswith(MESSAGE_SUFFIX):
        return suffix[:-len(MESSAGE_SUFFIX)]
    return None


def _classify(name):
    queue = _message_queue(name)
    if queue is not None:
        return 'message', queue
    if name.endswith(CONTROL_SUFFIX):
        return 'control', None
    return 'other', None


def _error_text(action, exc):
    return f'{action} failed: {exc.strerror or exc}'


def _inspect_file(path, rel):
    """Build the evidence record for one file; never raises."""
    kind, queue = _classify(path.name)
    record = {
        'path': rel,
        'name': path.name,
        'kind': kind,
        'queue': queue,
        'size': None,
        'mtime_ns': None,
        'sha256': None,
        'payload': None,
        'error': None,
    }
    try:
        stat = path.stat()
    except OSError as exc:
        record['error'] = _error_text('stat', exc)
        return record
    record['size'] = stat.st_size
    record['mtime_ns'] = stat.st_mtime_ns
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as exc:
        record['error'] = _error_text('read', exc)
        return record
    record['sha256'] = hashlib.sha256(data).hexdigest()
    if kind == 'message':
        try:
            loads(bytes_to_str(data))
            record['payload'] = 'ok'
        except Exception:
            record['payload'] = 'invalid'
    elif kind == 'control':
        try:
            record['bindings'] = [
                list(binding) for binding in loads(bytes_to_str(data))
            ]
            record['payload'] = 'ok'
        except Exception:
            record['payload'] = 'invalid'
    return record


def build_snapshot(root):
    """Inventory one static directory copy.

    Returns a JSON-serializable dict with one record per regular file,
    per-queue message counts and the exchange bindings recovered from the
    control files.  Files that cannot be statted or read are kept in the
    listing with an ``error`` field instead of aborting the scan.
    """
    root = Path(root)
    if not root.is_dir():
        raise NotADirectoryError(f'not a directory: {root}')
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if not path.is_file() or path.is_symlink():
                continue
            rel = path.relative_to(root).as_posix()
            files.append(_inspect_file(path, rel))
    files.sort(key=lambda record: record['path'])

    queues = {}
    exchanges = {}
    for record in files:
        if record['error'] is not None:
            continue
        if record['kind'] == 'message':
            queues[record['queue']] = queues.get(record['queue'], 0) + 1
        elif (record['kind'] == 'control' and
                record.get('bindings') is not None):
            exchange = record['name'][:-len(CONTROL_SUFFIX)]
            exchanges[exchange] = record['bindings']
    return {
        'root': str(root),
        'file_count': len(files),
        'queues': queues,
        'exchanges': exchanges,
        'files': files,
    }


def _entry(status, record, **extra):
    entry = {
        'status': status,
        'path': record['path'],
        'kind': record['kind'],
        'queue': record['queue'],
        'sha256': record['sha256'],
        'size': record['size'],
    }
    entry.update(extra)
    return entry


def _index_by_hash(files):
    by_hash = {}
    for record in files:
        if record['error'] is None and record['sha256'] is not None:
            by_hash.setdefault(record['sha256'], []).append(record)
    return by_hash


def compare_snapshots(reference, candidate):
    """Compare two snapshots built by :func:`build_snapshot`.

    Every reference file is accounted for exactly once, as is every
    candidate file, so the export can be audited back to the raw
    directory listings.
    """
    ref_files = reference['files']
    cand_files = candidate['files']
    cand_by_path = {f['path']: f for f in cand_files}
    ref_by_hash = _index_by_hash(ref_files)
    cand_by_hash = _index_by_hash(cand_files)

    entries = []
    matched_cand = set()

    # files present at the same path in both copies
    for record in ref_files:
        other = cand_by_path.get(record['path'])
        if other is None:
            continue
        matched_cand.add(other['path'])
        if record['error'] is not None or other['error'] is not None:
            entries.append(_entry(
                'unreadable', record,
                error=record['error'] or other['error']))
        elif record['sha256'] == other['sha256']:
            if record['mtime_ns'] == other['mtime_ns']:
                entries.append(_entry('unchanged', record))
            else:
                entries.append(_entry(
                    'metadata_changed', record,
                    note='file bytes are identical but the modification '
                         'time differs between the two copies'))
        else:
            entries.append(_entry(
                'modified', record,
                candidate_sha256=other['sha256'],
                note='same path, different bytes: the file was rewritten '
                     'or replaced between the two copies'))

    # files only in the reference: moved, payload relocated, or removed
    unmatched_cand = [f for f in cand_files if f['path'] not in matched_cand]
    cand_by_name_hash = {
        (f['name'], f['sha256']): f for f in unmatched_cand
        if f['error'] is None
    }
    for record in ref_files:
        if record['path'] in cand_by_path:
            continue
        if record['error'] is not None:
            entries.append(_entry('unreadable', record,
                                  error=record['error'],
                                  missing_from='candidate'))
            continue
        moved = cand_by_name_hash.get((record['name'], record['sha256']))
        if moved is not None:
            matched_cand.add(moved['path'])
            mtime_preserved = moved['mtime_ns'] == record['mtime_ns']
            entries.append(_entry(
                'moved', record,
                candidate_path=moved['path'],
                mtime_preserved=mtime_preserved,
                note=MOVE_NOTE if mtime_preserved
                else MOVE_MTIME_CHANGED_NOTE))
            continue
        relocated = cand_by_hash.get(record['sha256'])
        relocated = [f for f in relocated or ()
                     if f['path'] not in matched_cand]
        if relocated:
            for other in relocated:
                matched_cand.add(other['path'])
            entries.append(_entry(
                'same_payload_different_file', record,
                candidate_paths=[f['path'] for f in relocated],
                note=SAME_PAYLOAD_NOTE))
            continue
        entries.append(_entry(
            'removed', record,
            note='no file with these bytes exists in the candidate copy; '
                 'the message was purged, or consumed without '
                 'store_processed so the transport deleted it after '
                 'reading'))

    # files only in the candidate
    for record in unmatched_cand:
        if record['path'] in matched_cand:
            continue
        if record['error'] is not None:
            entries.append(_entry('unreadable', record,
                                  error=record['error'],
                                  missing_from='reference'))
            continue
        originals = ref_by_hash.get(record['sha256'])
        if originals:
            entries.append(_entry(
                'same_payload_different_file', record,
                reference_paths=[f['path'] for f in originals],
                note=SAME_PAYLOAD_NOTE))
        else:
            entries.append(_entry(
                'added', record,
                note='new file with bytes not present anywhere in the '
                     'reference copy; published after the reference was '
                     'taken'))

    entries.sort(key=lambda entry: (entry['path'], entry['status']))

    summary = {}
    for entry in entries:
        summary[entry['status']] = summary.get(entry['status'], 0) + 1

    queues = {}
    for snapshot, key in ((reference, 'reference_messages'),
                          (candidate, 'candidate_messages')):
        for queue, count in snapshot['queues'].items():
            queues.setdefault(queue, {})[key] = count
    for entry in entries:
        if entry['kind'] != 'message' or entry['queue'] is None:
            continue
        queue = queues.setdefault(entry['queue'], {})
        queue[entry['status']] = queue.get(entry['status'], 0) + 1

    duplicates = []
    locations = {}
    for snapshot_name, files in (('reference', ref_files),
                                 ('candidate', cand_files)):
        for record in files:
            if record['error'] is None and record['sha256'] is not None:
                locations.setdefault(record['sha256'], []).append({
                    'snapshot': snapshot_name,
                    'path': record['path'],
                    'queue': record['queue'],
                })
    for digest, where in sorted(locations.items()):
        # the same path in both copies is the same file, not a duplicate
        if len({location['path'] for location in where}) > 1:
            duplicates.append({
                'sha256': digest,
                'occurrences': where,
                'note': 'identical payload stored in more than one file',
            })

    return {
        'reference': {k: reference[k] for k in
                      ('root', 'file_count', 'queues', 'exchanges')},
        'candidate': {k: candidate[k] for k in
                      ('root', 'file_count', 'queues', 'exchanges')},
        'summary': summary,
        'queues': queues,
        'entries': entries,
        'duplicates': duplicates,
    }


def export_evidence(reference_root, candidate_root):
    """Build the full evidence report comparing two directory copies."""
    reference = build_snapshot(reference_root)
    candidate = build_snapshot(candidate_root)
    report = {
        'tool': 'kombu.transport.filesystem_evidence',
        'version': __version__,
    }
    report.update(compare_snapshots(reference, candidate))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='python -m kombu.transport.filesystem_evidence',
        description='Offline evidence export for the kombu filesystem '
                    'transport: compare two static directory copies and '
                    'report file identity, queue state, moves, duplicate '
                    'payloads and read failures.')
    parser.add_argument('reference',
                        help='earlier static copy of the transport folders')
    parser.add_argument('candidate',
                        help='later static copy of the transport folders')
    parser.add_argument('-o', '--output',
                        help='write the JSON report here instead of stdout')
    parser.add_argument('--compact', action='store_true',
                        help='emit the report without indentation')
    args = parser.parse_args(argv)

    report = export_evidence(args.reference, args.candidate)
    text = json.dumps(report, sort_keys=True,
                      indent=None if args.compact else 2)
    if args.output:
        with open(args.output, 'w') as f:
            f.write(text + '\n')
    else:
        print(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
