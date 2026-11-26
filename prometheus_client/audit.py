"""Offline provenance audit for multi-process metric directories.

Two deployments can leave their ``.db`` files in the same directory, and they
may even reuse the same process identifier. The regular aggregation in
:mod:`prometheus_client.multiprocess` keeps working unchanged for every file.
This module adds an offline reader that explains which write session each
aggregated value came from.

Files written by a current release carry a provenance sidecar (see
:mod:`prometheus_client.provenance`) and are reported with a *known* session.
Legacy files have no such evidence: their source can only be inferred from the
historical ``<type>_<mode>_<pid>.db`` naming and are explicitly kept as
*unknown*, with the missing evidence listed in the report.
"""

from dataclasses import dataclass, field
import glob
import json
import math
import os
import shutil
import tempfile
from typing import Any, Dict, List, Optional

from .mmap_dict import MmapedDict
from .multiprocess import MultiProcessCollector
from .provenance import (
    load_file_provenance,
    load_sessions,
    provenance_path,
    PROVENANCE_SUFFIX,
    SESSION_PREFIX,
    SESSION_SUFFIX,
)

# Provenance statuses. Known sources carry write-session evidence; unknown
# sources can only be guessed from the historical file naming convention.
STATUS_KNOWN = 'known'
STATUS_UNKNOWN = 'unknown'

_GAUGE_TYPES = ('gauge',)


def _json_safe(value: float) -> Any:
    """Convert floats so JSON output stays strict (no NaN/Infinity tokens)."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    return value


def parse_db_filename(filename: str) -> Optional[Dict[str, Optional[str]]]:
    """Split a historical ``.db`` metric file name into its components.

    Returns a dict with ``type``, ``mode`` (gauges only) and ``process_id``,
    or ``None`` when the name does not follow the multi-process convention.
    """
    base = os.path.basename(filename)
    if not base.endswith('.db'):
        return None
    parts = base[:-3].split('_')
    if not parts or not parts[0]:
        return None
    if parts[0] in _GAUGE_TYPES and len(parts) >= 3:
        return {
            'type': parts[0],
            'mode': parts[1],
            'process_id': '_'.join(parts[2:]),
        }
    if parts[0] not in _GAUGE_TYPES and len(parts) >= 2:
        return {
            'type': parts[0],
            'mode': None,
            'process_id': '_'.join(parts[1:]),
        }
    return None


@dataclass
class FileProvenance:
    """Provenance information for a single ``.db`` metric file."""

    filename: str
    type: Optional[str]
    mode: Optional[str]
    process_id: Optional[str]
    status: str
    inferred_from_filename: bool
    metric_names: List[str] = field(default_factory=list)
    session_id: Optional[str] = None
    writer_process_id: Optional[str] = None
    sidecar: Optional[str] = None
    prior_session_ids: List[str] = field(default_factory=list)
    metric_sessions: Dict[str, List[str]] = field(default_factory=dict)
    session_present: bool = False
    evidence_gap: Optional[str] = None


def metric_names_in_file(db_path: str) -> List[str]:
    """Return the metric family names stored inside a ``.db`` file."""
    names: List[str] = []
    try:
        entries = MmapedDict.read_all_values_from_file(db_path)
        for key, _value, _timestamp, _pos in entries:
            try:
                metric_name = json.loads(key)[0]
            except (ValueError, IndexError):
                continue
            if metric_name not in names:
                names.append(metric_name)
    except (OSError, ValueError):
        # Unreadable/corrupt files contribute no names; the regular merge
        # already owns the decision about whether such a file is fatal.
        return names
    return names


def inspect_directory(directory: str) -> List[FileProvenance]:
    """Describe the provenance of every metric file in a directory.

    Files with a provenance sidecar are :data:`STATUS_KNOWN`; files without
    one are :data:`STATUS_UNKNOWN` and carry a human-readable evidence gap.
    The historical file name is always parsed so the process identifier that
    can be *inferred* for legacy files is reported separately.
    """
    sessions = load_sessions(directory)
    results: List[FileProvenance] = []
    for path in sorted(glob.glob(os.path.join(directory, '*.db'))):
        filename = os.path.basename(path)
        parsed = parse_db_filename(filename)
        if parsed is None:
            typ = mode = process_id = None
        else:
            typ = parsed['type']
            mode = parsed['mode']
            process_id = parsed['process_id']

        metric_names = metric_names_in_file(path)
        evidence = load_file_provenance(path)
        if evidence is None:
            results.append(FileProvenance(
                filename=filename,
                type=typ,
                mode=mode,
                process_id=process_id,
                status=STATUS_UNKNOWN,
                inferred_from_filename=parsed is not None,
                metric_names=metric_names,
                evidence_gap=(
                    'No write-session sidecar (%s) found; the source can only '
                    'be inferred from the historical file name.'
                    % os.path.basename(provenance_path(filename))
                ),
            ))
            continue

        session_id = evidence.get('session_id')
        sessions_list = evidence.get('sessions')
        if not isinstance(sessions_list, list):
            sessions_list = []
        prior: List[str] = []
        for entry in sessions_list:
            if not isinstance(entry, dict):
                continue
            entry_session = entry.get('session_id')
            if (
                isinstance(entry_session, str)
                and entry_session
                and entry_session != session_id
            ):
                prior.append(entry_session)
        raw_metric_sessions = evidence.get('metric_sessions')
        metric_sessions: Dict[str, List[str]] = (
            raw_metric_sessions if isinstance(raw_metric_sessions, dict) else {}
        )
        results.append(FileProvenance(
            filename=filename,
            type=typ,
            mode=mode,
            process_id=process_id,
            status=STATUS_KNOWN,
            inferred_from_filename=False,
            metric_names=metric_names,
            session_id=session_id,
            writer_process_id=evidence.get('process_identifier'),
            sidecar=os.path.basename(provenance_path(filename)),
            prior_session_ids=prior,
            metric_sessions=metric_sessions,
            session_present=session_id in sessions,
        ))
    return results


def _serialize_file(info: FileProvenance) -> Dict[str, Any]:
    return {
        'filename': info.filename,
        'type': info.type,
        'mode': info.mode,
        'process_id': info.process_id,
        'status': info.status,
        'inferred_from_filename': info.inferred_from_filename,
        'metric_names': list(info.metric_names),
        'metric_sessions': {
            name: list(owners)
            for name, owners in info.metric_sessions.items()
        },
        'session_id': info.session_id,
        'writer_process_id': info.writer_process_id,
        'sidecar': info.sidecar,
        'prior_session_ids': info.prior_session_ids,
        'session_manifest_present': info.session_present,
        'evidence_gap': info.evidence_gap,
    }


def _aggregate_from_files(db_paths: List[str]) -> Dict[str, Dict[str, Any]]:
    """Run the standard multi-process merge over explicit files."""
    metrics: Dict[str, Dict[str, Any]] = {}
    for metric in MultiProcessCollector.merge(db_paths, accumulate=True):
        metrics[metric.name] = {
            'type': metric.type,
            'documentation': metric.documentation,
            'samples': [
                {
                    'name': sample.name,
                    'labels': dict(sample.labels),
                    'value': _json_safe(float(sample.value)),
                }
                for sample in metric.samples
            ],
        }
    return metrics


def _origin_for_metric(
    metric_name: str, file_infos: List[FileProvenance]
) -> Dict[str, Any]:
    """Roll the per-file provenance up into the origin of one metric family.

    Only files that actually contain the family contribute. A family is known
    only when every contributing file has provenance. The distinct session
    ids (including previous writers of a reused file) are listed so an
    aggregate that mixes two deployments is visibly traced to both, even when
    the deployments reused the same process identifier.
    """
    contributing = [
        info for info in file_infos if metric_name in info.metric_names
    ]
    statuses = {info.status for info in contributing}
    session_ids: List[str] = []
    for info in contributing:
        # Prefer the per-metric session map so a metric only written by one
        # deployment is not attributed to every session that touched the file.
        candidates = info.metric_sessions.get(metric_name)
        if not isinstance(candidates, list) or not candidates:
            candidates = (
                ([info.session_id] if info.session_id else [])
                + info.prior_session_ids
            )
        for sid in candidates:
            if sid not in session_ids:
                session_ids.append(sid)

    if not contributing:
        status = STATUS_UNKNOWN
    elif STATUS_UNKNOWN in statuses:
        status = STATUS_UNKNOWN
    else:
        status = STATUS_KNOWN
    return {
        'status': status,
        'session_ids': session_ids,
        'files': [info.filename for info in contributing],
        'unknown_files': [
            info.filename for info in contributing
            if info.status == STATUS_UNKNOWN
        ],
    }


def build_audit_report(directory: str) -> Dict[str, Any]:
    """Build a serializable audit report for a metric directory."""
    file_infos = inspect_directory(directory)
    db_paths = [os.path.join(directory, info.filename) for info in file_infos]
    aggregated = _aggregate_from_files(db_paths)
    sessions = load_sessions(directory)

    origins = {
        metric_name: _origin_for_metric(metric_name, file_infos)
        for metric_name in aggregated
    }

    evidence_gaps = [
        {
            'filename': info.filename,
            'reason': info.evidence_gap,
            'inferred_process_id': info.process_id,
        }
        for info in file_infos
        if info.status == STATUS_UNKNOWN
    ]

    return {
        'directory': os.path.abspath(directory),
        'metric_files': [_serialize_file(info) for info in file_infos],
        'sessions': sessions,
        'aggregated_metrics': aggregated,
        'metric_origins': origins,
        'evidence_gaps': evidence_gaps,
        'summary': {
            'total_files': len(file_infos),
            'known_files': sum(i.status == STATUS_KNOWN for i in file_infos),
            'unknown_files': sum(i.status == STATUS_UNKNOWN for i in file_infos),
            'sessions_recorded': len(sessions),
            'metrics': len(aggregated),
        },
    }


def _write_report(directory: str, report: Dict[str, Any]) -> str:
    report_path = os.path.join(directory, 'audit-report.json')
    with open(report_path, 'w', encoding='utf-8') as outfp:
        json.dump(report, outfp, indent=2, sort_keys=True)
    return report_path


def recompute_aggregates(
    directory: str, workdir: Optional[str] = None
) -> Dict[str, Any]:
    """Recompute every aggregate from copies of the files in a temp directory.

    The original directory is never modified: its ``.db`` files, sidecars and
    session manifests are copied into a throwaway working directory (created
    for the caller when one is not supplied) and the standard merge runs
    there. Returns a dict with the working directory, the recomputed
    aggregates, the path of the written summary and, when an audit report
    exists in the source directory, whether the aggregates match it.
    """
    if workdir is None:
        workdir = tempfile.mkdtemp(prefix='prometheus-audit-recompute-')
    os.makedirs(workdir, exist_ok=True)

    copied_dbs: List[str] = []
    for name in sorted(os.listdir(directory)):
        source = os.path.join(directory, name)
        if not os.path.isfile(source):
            continue
        if not (
            name.endswith('.db')
            or name.endswith(PROVENANCE_SUFFIX)
            or (name.startswith(SESSION_PREFIX) and name.endswith(SESSION_SUFFIX))
        ):
            continue
        shutil.copy2(source, os.path.join(workdir, name))
        if name.endswith('.db'):
            copied_dbs.append(os.path.join(workdir, name))

    recomputed = _aggregate_from_files(copied_dbs)
    summary_path = os.path.join(workdir, 'aggregates-summary.json')
    with open(summary_path, 'w', encoding='utf-8') as outfp:
        json.dump(recomputed, outfp, indent=2, sort_keys=True)

    result = {
        'workdir': workdir,
        'summary_path': summary_path,
        'aggregated_metrics': recomputed,
    }

    original_report = os.path.join(directory, 'audit-report.json')
    if os.path.exists(original_report):
        with open(original_report, 'r', encoding='utf-8') as infp:
            stored = json.load(infp)
        result['matches_report'] = (
            stored.get('aggregated_metrics') == recomputed
        )
    return result


def run_audit(
    directory: str, report_directory: Optional[str] = None
) -> Dict[str, Any]:
    """Write an audit report and an independently recomputed summary.

    The report goes to ``report_directory`` (a fresh temp directory when not
    given). A second directory holds the copied files plus a recomputed
    aggregate summary, so the figures in the report can be re-derived without
    touching the original samples.
    """
    report = build_audit_report(directory)
    if report_directory is None:
        report_directory = tempfile.mkdtemp(prefix='prometheus-audit-report-')
    os.makedirs(report_directory, exist_ok=True)
    report_path = _write_report(report_directory, report)

    workdir = tempfile.mkdtemp(prefix='prometheus-audit-recompute-')
    recomputed = recompute_aggregates(directory, workdir=workdir)
    matches_report = (
        report['aggregated_metrics']
        == recomputed['aggregated_metrics']
    )

    return {
        'report_path': report_path,
        'report': report,
        'recompute': recomputed,
        'matches_report': matches_report,
    }


def main(argv: Optional[List[str]] = None) -> int:
    """Command line entry point: ``python -m prometheus_client.audit DIR``."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Audit write-session provenance of multi-process metrics.')
    parser.add_argument('directory', help='directory containing the .db files')
    parser.add_argument(
        '--report-directory',
        help='directory to write audit-report.json into (defaults to a temp dir)',
    )
    args = parser.parse_args(argv)

    outcome = run_audit(args.directory, args.report_directory)
    report = outcome['report']
    print('Audit report: %s' % outcome['report_path'])
    print('Recompute dir: %s' % outcome['recompute']['workdir'])
    print('Recomputed aggregates match report: %s' % outcome['matches_report'])
    print('Summary: %s' % json.dumps(report['summary'], sort_keys=True))
    for gap in report['evidence_gaps']:
        print('UNKNOWN %s: %s' % (gap['filename'], gap['reason']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
