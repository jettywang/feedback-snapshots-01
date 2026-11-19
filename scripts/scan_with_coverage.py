#!/usr/bin/env python3
"""
Reference implementation of the coverage-aware scan report proposed in
docs/scan-coverage-report.md.

This wraps the existing background-scan entry points
(`detect_secrets.core.scan.get_files_to_scan` + `scan_file`) and, instead of
only reporting the number of findings, emits a per-file coverage manifest so
that "0 findings" can be told apart from "0 files were actually scanned".

Statuses:
    scanned             file was opened and fully processed (findings may be 0)
    unreadable          OS-level read failure (e.g. PermissionError); retryable
    excluded_by_policy  dropped by a configured filter (e.g. --exclude-files,
                        is_invalid_file, is_non_text_file); deterministic

Exit codes:
    0  GO               coverage COMPLETE
    3  CONDITIONAL_GO   only policy exclusions; needs sign-off of exclusion list
    1  NO_GO            unreadable files, or empty scan universe
"""
import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from detect_secrets.core import scan
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.settings import default_settings
from detect_secrets.settings import get_settings
from detect_secrets.util import git

STATUS_SCANNED = 'scanned'
STATUS_UNREADABLE = 'unreadable'
STATUS_EXCLUDED = 'excluded_by_policy'

GATE_GO = 'GO'
GATE_CONDITIONAL = 'CONDITIONAL_GO'
GATE_NO_GO = 'NO_GO'


def classify_and_scan_file(path: str) -> Tuple[Dict[str, Any], List[PotentialSecret]]:
    """Mirrors scan.scan_file, but surfaces the silent failure modes."""
    # Policy filters are applied first by scan_file; replicate the check so the
    # reason for skipping is recorded instead of the file silently vanishing.
    if scan._is_filtered_out(required_filter_parameters=['filename'], filename=path):
        return {'path': path, 'status': STATUS_EXCLUDED, 'retryable': False}, []

    # scan_file swallows IOError; probe readability ourselves so the failure
    # becomes a first-class status.
    try:
        with open(path, 'rb'):
            pass
    except OSError as e:
        return {
            'path': path,
            'status': STATUS_UNREADABLE,
            'error': type(e).__name__,
            'retryable': True,
        }, []

    secrets = list(scan.scan_file(path))
    return {
        'path': path,
        'status': STATUS_SCANNED,
        'findings': len(secrets),
        'retryable': False,
    }, secrets


def probe_enumeration(paths: List[str], should_scan_all_files: bool) -> Dict[str, Any]:
    """Records how the scan universe was built, incl. the empty-universe trap."""
    mode = 'all-files' if should_scan_all_files else 'git-tracked'
    warning = None
    if not should_scan_all_files and any(os.path.isdir(p) for p in paths):
        try:
            git.get_tracked_files(git.get_root_directory(''))
        except subprocess.CalledProcessError:
            warning = (
                'not a git repository: directory scan yields ZERO files '
                '(get_files_to_scan silently returns nothing). Re-run with '
                '--all-files or inside a git checkout.'
            )
    return {'mode': mode, 'warning': warning}


def summarize(files: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {
        STATUS_SCANNED: 0,
        STATUS_UNREADABLE: 0,
        STATUS_EXCLUDED: 0,
    }
    for record in files:
        counts[record['status']] += 1

    total = sum(counts.values())
    if total == 0:
        status = 'EMPTY_UNIVERSE'
        gate = GATE_NO_GO
    elif counts[STATUS_UNREADABLE]:
        status = 'PARTIAL_UNREADABLE'
        gate = GATE_NO_GO
    elif counts[STATUS_EXCLUDED]:
        status = 'PARTIAL_BY_POLICY'
        gate = GATE_CONDITIONAL
    else:
        status = 'COMPLETE'
        gate = GATE_GO

    return {
        'status': status,
        'release_gate': gate,
        'counts': {**counts, 'total': total},
    }


def configure(args: argparse.Namespace) -> None:
    """Mutates the (cold) in-context settings, same as usage/filters.py does."""
    if args.exclude_files:
        get_settings().filters['detect_secrets.filters.regex.should_exclude_file'] = {
            'pattern': list(args.exclude_files),
        }


def build_report(args: argparse.Namespace) -> Dict[str, Any]:
    previous: Optional[Dict[str, Any]] = None
    if args.retry_of:
        with open(args.retry_of) as f:
            previous = json.load(f)

    with default_settings():
        configure(args)
        enumeration = probe_enumeration(args.paths, args.all_files)

        files: List[Dict[str, Any]] = []
        # results maps filename -> list of serialized secrets, mirroring the
        # baseline's `results` section.
        results: Dict[str, Any] = dict(previous['results']) if previous else {}

        if previous:
            # Retry semantics: only re-attempt retryable (unreadable) files from
            # the previous run. All other evidence is carried over untouched,
            # and a retry never downgrades a previously scanned file.
            for record in previous['files']:
                if record['status'] != STATUS_UNREADABLE:
                    files.append({**record, 'carried_over': True})
                    continue

                new_record, secrets = classify_and_scan_file(record['path'])
                new_record['attempts'] = record.get('attempts', 1) + 1
                files.append(new_record)
                results.pop(record['path'], None)
                if secrets:
                    results[record['path']] = [secret.json() for secret in secrets]
        else:
            universe = sorted(set(scan.get_files_to_scan(
                *args.paths,
                should_scan_all_files=args.all_files,
            )))
            for path in universe:
                record, secrets = classify_and_scan_file(path)
                files.append(record)
                if secrets:
                    results[path] = [secret.json() for secret in secrets]

        report: Dict[str, Any] = {
            'scan_id': uuid.uuid4().hex[:12],
            'generated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'enumeration': enumeration,
            'coverage': summarize(files),
            'files': files,
            'results': results,
        }
        if previous:
            report['parent_scan_id'] = previous['scan_id']

    return report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('paths', nargs='+', help='Files or directories to scan.')
    parser.add_argument('--all-files', action='store_true',
                        help='Scan all files, not just git-tracked ones.')
    parser.add_argument('--exclude-files', metavar='REGEX', action='append',
                        help='Policy exclusion pattern (same as scan --exclude-files).')
    parser.add_argument('--retry-of', metavar='REPORT',
                        help='Previous report JSON; only retries unreadable files.')
    parser.add_argument('--output', metavar='FILE', help='Write report here instead of stdout.')
    args = parser.parse_args(argv)

    report = build_report(args)
    payload = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        with open(args.output, 'w') as f:
            f.write(payload + '\n')
    else:
        print(payload)

    gate = report['coverage']['release_gate']
    if gate == GATE_GO:
        return 0
    if gate == GATE_CONDITIONAL:
        return 3
    return 1


if __name__ == '__main__':
    sys.exit(main())
