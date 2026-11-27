from collections import defaultdict
import glob
import json
import os
import warnings

from .metrics import Gauge
from .metrics_core import Metric
from .mmap_dict import MmapedDict, read_session_from_file
from .samples import Sample
from .utils import floatToGoString

try:  # Python3
    FileNotFoundError
except NameError:  # Python >= 2.5
    FileNotFoundError = IOError


class MultiProcessCollector:
    """Collector for files for multi-process mode."""

    def __init__(self, registry, path=None):
        if path is None:
            # This deprecation warning can go away in a few releases when removing the compatibility
            if 'prometheus_multiproc_dir' in os.environ and 'PROMETHEUS_MULTIPROC_DIR' not in os.environ:
                os.environ['PROMETHEUS_MULTIPROC_DIR'] = os.environ['prometheus_multiproc_dir']
                warnings.warn("prometheus_multiproc_dir variable has been deprecated in favor of the upper case naming PROMETHEUS_MULTIPROC_DIR", DeprecationWarning)
            path = os.environ.get('PROMETHEUS_MULTIPROC_DIR')
        if not path or not os.path.isdir(path):
            raise ValueError('env PROMETHEUS_MULTIPROC_DIR is not set or not a directory')
        self._path = path
        if registry:
            registry.register(self)

    @staticmethod
    def merge(files, accumulate=True):
        """Merge metrics from given mmap files.

        By default, histograms are accumulated, as per prometheus wire format.
        But if writing the merged data back to mmap files, use
        accumulate=False to avoid compound accumulation.
        """
        metrics = MultiProcessCollector._read_metrics(files)
        return MultiProcessCollector._accumulate_metrics(metrics, accumulate)

    @staticmethod
    def _read_metrics(files):
        metrics = {}
        key_cache = {}

        def _parse_key(key):
            val = key_cache.get(key)
            if not val:
                metric_name, name, labels, help_text = json.loads(key)
                labels_key = tuple(sorted(labels.items()))
                val = key_cache[key] = (metric_name, name, labels, labels_key, help_text)
            return val

        for f in files:
            parts = os.path.basename(f).split('_')
            typ = parts[0]
            try:
                file_values = MmapedDict.read_all_values_from_file(f)
            except FileNotFoundError:
                if typ == 'gauge' and parts[1].startswith('live'):
                    # Files for 'live*' gauges can be deleted between the glob of collect
                    # and now (via a mark_process_dead call) so don't fail if
                    # the file is missing
                    continue
                raise
            for key, value, timestamp, _ in file_values:
                metric_name, name, labels, labels_key, help_text = _parse_key(key)

                metric = metrics.get(metric_name)
                if metric is None:
                    metric = Metric(metric_name, help_text, typ)
                    metrics[metric_name] = metric

                if typ == 'gauge':
                    pid = parts[2][:-3]
                    metric._multiprocess_mode = parts[1]
                    metric.add_sample(name, labels_key + (('pid', pid),), value, timestamp)
                else:
                    # The duplicates and labels are fixed in the next for.
                    metric.add_sample(name, labels_key, value)
        return metrics

    @staticmethod
    def _accumulate_metrics(metrics, accumulate):
        for metric in metrics.values():
            samples = defaultdict(lambda: defaultdict(float))
            sample_timestamps = defaultdict(lambda: defaultdict(float))
            buckets = defaultdict(lambda: defaultdict(float))
            for s in metric.samples:
                name, labels, value, timestamp, exemplar, native_histogram_value = s

                if (
                    metric.type == 'gauge'
                    and metric._multiprocess_mode in (
                        'min', 'livemin',
                        'max', 'livemax',
                        'sum', 'livesum',
                        'mostrecent', 'livemostrecent',
                    )
                ):
                    labels = tuple(l for l in labels if l[0] != 'pid')

                if metric.type == 'gauge':
                    if metric._multiprocess_mode in ('min', 'livemin'):
                        current = samples[labels].setdefault((name, labels), value)
                        if value < current:
                            samples[labels][(name, labels)] = value
                    elif metric._multiprocess_mode in ('max', 'livemax'):
                        current = samples[labels].setdefault((name, labels), value)
                        if value > current:
                            samples[labels][(name, labels)] = value
                    elif metric._multiprocess_mode in ('sum', 'livesum'):
                        samples[labels][(name, labels)] += value
                    elif metric._multiprocess_mode in ('mostrecent', 'livemostrecent'):
                        current_timestamp = sample_timestamps[labels][name]
                        timestamp = float(timestamp or 0)
                        if current_timestamp < timestamp:
                            samples[labels][(name, labels)] = value
                            sample_timestamps[labels][name] = timestamp
                    else:  # all/liveall
                        samples[labels][(name, labels)] = value

                elif metric.type == 'histogram':
                    # A for loop with early exit is faster than a genexpr
                    # or a listcomp that ends up building unnecessary things
                    for l in labels:
                        if l[0] == 'le':
                            bucket_value = float(l[1])
                            # _bucket
                            without_le = tuple(l for l in labels if l[0] != 'le')
                            buckets[without_le][bucket_value] += value
                            break
                    else:  # did not find the `le` key
                        # _sum/_count
                        samples[labels][(name, labels)] += value
                else:
                    # Counter and Summary.
                    samples[labels][(name, labels)] += value

            # Accumulate bucket values.
            if metric.type == 'histogram':
                for labels, values in buckets.items():
                    acc = 0.0
                    for bucket, value in sorted(values.items()):
                        sample_key = (
                            metric.name + '_bucket',
                            labels + (('le', floatToGoString(bucket)),),
                        )
                        if accumulate:
                            acc += value
                            samples[labels][sample_key] = acc
                        else:
                            samples[labels][sample_key] = value
                    if accumulate:
                        samples[labels][(metric.name + '_count', labels)] = acc

            # Convert to correct sample format.
            metric.samples = []
            for _, samples_by_labels in samples.items():
                for (name_, labels), value in samples_by_labels.items():
                    metric.samples.append(Sample(name_, dict(labels), value))
        return metrics.values()

    def collect(self):
        files = glob.glob(os.path.join(self._path, '*.db'))
        return self.merge(files, accumulate=True)


_LIVE_GAUGE_MULTIPROCESS_MODES = {m for m in Gauge._MULTIPROC_MODES if m.startswith('live')}

# Outcomes of a reclaim attempt for one metric file.
RECLAIMED = 'reclaimed'
HELD = 'held'
UNKNOWN_SESSION = 'unknown_session'
SESSION_CHANGED = 'session_changed'
MISSING = 'missing'


class FileReclaim:
    """The outcome of trying to reclaim one metric file.

    ``status`` is one of ``RECLAIMED``, ``HELD``, ``UNKNOWN_SESSION``,
    ``SESSION_CHANGED`` or ``MISSING``. ``reclaimed`` is True only for
    ``RECLAIMED``; the other statuses explain why a file was left alone.
    """

    __slots__ = ('path', 'status', 'session_id')

    def __init__(self, path, status, session_id=None):
        self.path = path
        self.status = status
        self.session_id = session_id

    @property
    def reclaimed(self):
        return self.status == RECLAIMED

    def __repr__(self):
        return 'FileReclaim(path={!r}, status={!r}, session_id={!r})'.format(
            self.path, self.status, self.session_id)

    def __eq__(self, other):
        if not isinstance(other, FileReclaim):
            return NotImplemented
        return (self.path, self.status, self.session_id) == (
            other.path, other.status, other.session_id)

    def __hash__(self):
        return hash((self.path, self.status, self.session_id))


class ReclaimResult:
    """Outcome of :func:`mark_process_dead` for one process.

    ``files`` holds one :class:`FileReclaim` per ``live*`` gauge file that was
    considered. ``reclaimed`` and ``active_sessions`` are convenient
    summaries: paths actually removed, and write sessions still providing
    samples. ``retained`` lists files for the same pid that were not
    candidates because their type keeps its values across process exit:
    counters and gauges in non-live modes.
    """

    __slots__ = ('pid', 'session_id', 'files', 'retained')

    def __init__(self, pid, session_id, files, retained=()):
        self.pid = pid
        self.session_id = session_id
        self.files = list(files)
        self.retained = list(retained)

    @property
    def reclaimed(self):
        return [f.path for f in self.files if f.reclaimed]

    @property
    def active_sessions(self):
        """Mapping of path to the write session that still owns it."""
        return {f.path: f.session_id for f in self.files if f.status == HELD}

    @property
    def statuses(self):
        return {f.path: f.status for f in self.files}

    def report(self):
        """Return a short human-readable summary of the reclamation attempt.

        The report names the files that were reclaimed and the write sessions
        still providing samples, plus anything deferred for a reason.
        """
        lines = ['process {}: {} of {} live file(s) reclaimed'.format(
            self.pid, len(self.reclaimed), len(self.files))]
        if self.session_id is not None:
            lines[0] += ' for session {}'.format(self.session_id)
        for f in self.files:
            detail = f.status
            if f.session_id is not None:
                detail += ', session {}'.format(f.session_id)
            lines.append('  {}: {}'.format(f.path, detail))
        if self.retained:
            lines.append('retained by lifetime convention:')
            for path in self.retained:
                lines.append('  {}'.format(path))
        return '\n'.join(lines)

    def __repr__(self):
        return 'ReclaimResult(pid={!r}, session_id={!r}, files={!r})'.format(
            self.pid, self.session_id, self.files)


def _resolve_path(path):
    if path is None:
        path = os.environ.get('PROMETHEUS_MULTIPROC_DIR', os.environ.get('prometheus_multiproc_dir'))
    return path


def _reclaim_file(filename, expected_session, allow_unknown, dry_run):
    """Reclaim a dead writer's file only when its session matches."""
    reader = MmapedDict.open_for_cleanup(filename)
    if reader is None:
        return FileReclaim(filename, MISSING)
    try:
        if not reader.locked:
            # A writer still holds the file: it is a live session, not a straggler.
            return FileReclaim(filename, HELD, reader.session_id)
        if not reader.same_file:
            # The path was replaced after we opened it; the newer file is not ours.
            return FileReclaim(filename, MISSING)
        session_id = reader.session_id
        if session_id is None:
            if not allow_unknown:
                return FileReclaim(filename, UNKNOWN_SESSION)
        elif expected_session is not None and session_id != expected_session:
            # A newer write session has taken over this pid's file.
            return FileReclaim(filename, SESSION_CHANGED, session_id)
        if not dry_run:
            try:
                os.remove(filename)
            except FileNotFoundError:
                return FileReclaim(filename, MISSING)
        return FileReclaim(filename, RECLAIMED, session_id)
    finally:
        reader.close()


def mark_process_dead(pid, path=None, session_id=None, allow_unknown=True, dry_run=False):
    """Do bookkeeping for when one process dies in a multi-process setup.

    Only ``live*`` gauge files are reclaimable, matching their documented
    lifetime: a dead process must stop contributing samples. Counters, and
    gauges in non-live modes, keep their last values until the directory is
    wiped, so they are never removed here.

    ``session_id`` is the write session recorded when the exiting process
    opened its files (see :mod:`prometheus_client.values`). When given, a file
    now owned by a different session is left alone: this covers a restarted
    process that reused the pid, whose new live gauges must survive a late
    notice for its predecessor.

    ``allow_unknown`` chooses the policy for files written by clients that
    predate write sessions (no token recorded). With the default ``True`` they
    are reclaimed as before; set it to ``False`` to leave them in place and
    report ``UNKNOWN_SESSION`` instead.

    ``dry_run`` inspects and reports without removing anything.

    Returns a :class:`ReclaimResult` describing what happened to each file.
    Files are inspected and removed under the writer lock, so this is safe to
    run alongside live writers: a file whose writer is still active is
    reported as ``HELD`` and left untouched.
    """
    resolved = _resolve_path(path)
    files = []
    retained = []
    if resolved:
        for mode in sorted(_LIVE_GAUGE_MULTIPROCESS_MODES):
            pattern = os.path.join(resolved, f'gauge_{mode}_{pid}.db')
            for filename in sorted(glob.glob(pattern)):
                files.append(_reclaim_file(filename, session_id, allow_unknown, dry_run))
        for filename in sorted(glob.glob(os.path.join(resolved, f'*_{pid}.db'))):
            parts = os.path.basename(filename).split('_')
            if not (parts[0] == 'gauge' and parts[1] in _LIVE_GAUGE_MULTIPROCESS_MODES):
                retained.append(filename)
    return ReclaimResult(pid, session_id, files, retained)


def session_of(filename):
    """Return the write session that produced a metric file, or ``None``."""
    return read_session_from_file(filename)


def sessions_in(path=None):
    """Map each metric file in ``path`` to its write session, if recorded.

    Files from clients that predate write sessions map to ``None``.
    """
    resolved = _resolve_path(path)
    sessions = {}
    if resolved:
        for filename in sorted(glob.glob(os.path.join(resolved, '*.db'))):
            sessions[os.path.basename(filename)] = read_session_from_file(filename)
    return sessions
