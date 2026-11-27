"""Compare multiprocess aggregation around session-aware cleanup.

Simulates two write sessions that reuse the same process id and a late exit
notice for the first one. Run with::

    python tools/session_cleanup_demo.py
"""
import os
import tempfile

from prometheus_client import values
from prometheus_client.core import CollectorRegistry, Counter, Gauge
from prometheus_client.multiprocess import (
    MultiProcessCollector, mark_process_dead, sessions_in,
)
from prometheus_client.values import MultiProcessValue


def snapshot(registry):
    return {
        'gauge (pid 4242)': registry.get_sample_value('g', {'pid': '4242'}),
        'counter_total': registry.get_sample_value('c_total'),
    }


def write_session(path, pid, session, value):
    os.environ['PROMETHEUS_MULTIPROC_DIR'] = path
    values.ValueClass = MultiProcessValue(lambda: pid, session_id=session)
    Gauge('g', 'help', registry=None, multiprocess_mode='liveall').set(value)
    Counter('c', 'help', registry=None).inc(1)
    files = sorted(os.listdir(path))
    values.close_all_multiprocess_files()
    return files


def main():
    path = tempfile.mkdtemp()
    os.environ['PROMETHEUS_MULTIPROC_DIR'] = path
    registry = CollectorRegistry(support_collectors_without_names=True)
    MultiProcessCollector(registry)

    print('session 1 files:', write_session(path, 4242, 111, 10))
    print('after session 1: ', snapshot(registry))
    print('session 2 files:', write_session(path, 4242, 222, 20))
    print('after session 2: ', snapshot(registry))
    print('recorded sessions:', sessions_in(path))

    print('\nlate exit notice for session 111:')
    late = mark_process_dead(4242, session_id=111)
    print(late.report())
    print('after late notice:', snapshot(registry))

    print('\nexit notice for session 222:')
    current = mark_process_dead(4242, session_id=222)
    print(current.report())
    print('after cleanup:    ', snapshot(registry))
    print('remaining files:  ', sorted(os.listdir(path)))


if __name__ == '__main__':
    main()
