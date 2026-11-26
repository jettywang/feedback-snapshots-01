"""Write-session provenance for multi-process metric files.

Each process that writes metric values in multi-process mode belongs to a
*write session*: one process lifetime (including any ``fork()`` children that
keep writing into the same files) identified by a random session id.  Next to
every ``.db`` metric file the writer drops a JSON sidecar recording which
session produced the file.  A per-session manifest records the individual
process identifiers that took part in the session.

The evidence is plain JSON written with an atomic rename, so it stays
verifiable after every process involved has exited.  Metric files left behind
by older releases simply have no sidecar and are reported as having unknown
provenance; nothing about the existing ``.db`` format changes.
"""

import json
import os
import time
import uuid
import warnings
from typing import Any, Dict, List, Optional

# Suffix of the per-file provenance sidecar, e.g. "counter_123.db.provenance".
PROVENANCE_SUFFIX = '.provenance'
# Prefix of the per-session manifest files.
SESSION_PREFIX = 'session-'
SESSION_SUFFIX = '.json'

PROVENANCE_FORMAT_VERSION = 1


def new_session_id() -> str:
    """Return a fresh write-session identifier."""
    return uuid.uuid4().hex


def provenance_path(db_path: str) -> str:
    """Return the sidecar path for a given metric file path."""
    return db_path + PROVENANCE_SUFFIX


def session_manifest_path(directory: str, session_id: str) -> str:
    """Return the manifest path for a session inside a directory."""
    return os.path.join(
        directory,
        SESSION_PREFIX + session_id + SESSION_SUFFIX,
    )


def _atomic_write_json(path: str, payload: Dict[str, Any]) -> None:
    directory = os.path.dirname(path) or '.'
    tmp_path = path + '.tmp'
    with open(tmp_path, 'w', encoding='utf-8') as outfp:
        json.dump(payload, outfp, sort_keys=True)
        outfp.flush()
        os.fsync(outfp.fileno())
    os.replace(tmp_path, path)


def _load_json(path: str) -> Any:
    with open(path, 'r', encoding='utf-8') as infp:
        return json.load(infp)


def record_session_process(
    directory: str, session_id: str, process_identifier: Any
) -> None:
    """Record that a process identifier participates in a write session.

    Safe to call repeatedly, including after a ``fork()``: the manifest keeps
    the ordered, de-duplicated list of every process identifier that wrote
    under the session id.
    """
    manifest_path = session_manifest_path(directory, session_id)
    try:
        try:
            manifest = _load_json(manifest_path)
            if not isinstance(manifest, dict):
                raise ValueError('session manifest is not a JSON object')
        except FileNotFoundError:
            manifest = {
                'format_version': PROVENANCE_FORMAT_VERSION,
                'session_id': session_id,
                'started_at': time.time(),
                'process_identifiers': [],
            }
        pids = manifest.setdefault('process_identifiers', [])
        if not isinstance(pids, list):
            pids = manifest['process_identifiers'] = []
        if process_identifier not in pids:
            pids.append(process_identifier)
        _atomic_write_json(manifest_path, manifest)
    except (OSError, ValueError) as exc:
        warnings.warn(
            'Could not record write-session evidence %s: %s'
            % (manifest_path, exc),
            RuntimeWarning,
        )


def stamp_file(
    db_path: str,
    session_id: str,
    process_identifier: Any,
    directory: Optional[str] = None,
    metric_name: Optional[str] = None,
) -> None:
    """Attach write-session evidence to a metric file.

    Re-stamping an existing file keeps the evidence of every session that ever
    wrote to it, so a directory reused across deployments does not silently
    overwrite the history of a shared file. When ``metric_name`` is given the
    metric is recorded as belonging to the current session; several sessions
    can appear for one metric when the same file genuinely accumulates the
    same metric across deployments.
    """
    sidecar_path = provenance_path(db_path)
    if directory is None:
        directory = os.path.dirname(db_path) or '.'
    try:
        try:
            evidence = _load_json(sidecar_path)
            if not isinstance(evidence, dict):
                raise ValueError('provenance sidecar is not a JSON object')
        except FileNotFoundError:
            evidence = {
                'format_version': PROVENANCE_FORMAT_VERSION,
                'session_id': session_id,
                'process_identifier': process_identifier,
                'created_at': time.time(),
                'sessions': [],
                'metric_sessions': {},
            }

        prior = evidence.setdefault('sessions', [])
        if not isinstance(prior, list):
            prior = evidence['sessions'] = []
        current = {
            'session_id': session_id,
            'process_identifier': process_identifier,
            'recorded_at': time.time(),
        }
        if not any(
            isinstance(entry, dict)
            and entry.get('session_id') == session_id
            for entry in prior
        ):
            prior.append(current)

        metric_sessions = evidence.setdefault('metric_sessions', {})
        if not isinstance(metric_sessions, dict):
            metric_sessions = evidence['metric_sessions'] = {}
        if metric_name is not None:
            owners = metric_sessions.setdefault(metric_name, [])
            if not isinstance(owners, list):
                owners = metric_sessions[metric_name] = []
            if session_id not in owners:
                owners.append(session_id)

        # The top-level fields always describe the most recent writer.
        evidence['session_id'] = session_id
        evidence['process_identifier'] = process_identifier

        _atomic_write_json(sidecar_path, evidence)
        record_session_process(directory, session_id, process_identifier)
    except (OSError, ValueError) as exc:
        warnings.warn(
            'Could not write provenance sidecar %s: %s'
            % (sidecar_path, exc),
            RuntimeWarning,
        )


def load_file_provenance(db_path: str) -> Optional[Dict[str, Any]]:
    """Load the provenance sidecar of a metric file.

    Returns ``None`` for files written by a release that did not emit
    provenance, which is the evidence gap reported by the offline audit.
    """
    try:
        return _load_json(provenance_path(db_path))
    except (OSError, ValueError):
        return None


def load_sessions(directory: str) -> Dict[str, Dict[str, Any]]:
    """Load every write-session manifest found in a directory."""
    sessions: Dict[str, Dict[str, Any]] = {}
    try:
        names = os.listdir(directory)
    except OSError:
        return sessions
    for name in names:
        if not (name.startswith(SESSION_PREFIX) and name.endswith(SESSION_SUFFIX)):
            continue
        try:
            manifest = _load_json(os.path.join(directory, name))
        except (OSError, ValueError):
            continue
        if not isinstance(manifest, dict):
            continue
        session_id = manifest.get('session_id')
        if session_id:
            sessions[session_id] = manifest
    return sessions
