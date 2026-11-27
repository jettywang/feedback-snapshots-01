import glob
import math
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings

from prometheus_client import mmap_dict, multiprocess, values
from prometheus_client.core import (
    CollectorRegistry, Counter, Gauge, Histogram, Sample, Summary,
)
from prometheus_client.multiprocess import (
    mark_process_dead, MultiProcessCollector,
)
from prometheus_client.openmetrics.exposition import \
    generate_latest as openmetrics_generate_latest
from prometheus_client.values import (
    get_value_class, MultiProcessValue, MutexValue,
)


class TestMultiProcessDeprecation(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        os.environ.pop('prometheus_multiproc_dir', None)
        os.environ.pop('PROMETHEUS_MULTIPROC_DIR', None)
        values.close_all_multiprocess_files()
        values.ValueClass = MutexValue
        shutil.rmtree(self.tempdir)

    def test_deprecation_warning(self):
        os.environ['prometheus_multiproc_dir'] = self.tempdir
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            values.ValueClass = get_value_class()
            registry = CollectorRegistry()
            collector = MultiProcessCollector(registry)
            Counter('c', 'help', registry=None)

            assert os.environ['PROMETHEUS_MULTIPROC_DIR'] == self.tempdir
            if os.name != 'nt':
                assert len(w) == 1
                assert issubclass(w[-1].category, DeprecationWarning)
                assert "PROMETHEUS_MULTIPROC_DIR" in str(w[-1].message)
            else:
                assert len(w) == 0

    def test_mark_process_dead_respects_lowercase(self):
        os.environ['prometheus_multiproc_dir'] = self.tempdir
        # Just test that this does not raise with a lowercase env var. The
        # logic is tested elsewhere.
        mark_process_dead(123)

    def test_mark_process_dead_noop_when_path_unset(self):
        os.environ.pop('prometheus_multiproc_dir', None)
        os.environ.pop('PROMETHEUS_MULTIPROC_DIR', None)
        mark_process_dead(123)


class TestMultiProcess(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        os.environ['PROMETHEUS_MULTIPROC_DIR'] = self.tempdir
        values.ValueClass = MultiProcessValue(lambda: 123)
        self.registry = CollectorRegistry(support_collectors_without_names=True)
        self.collector = MultiProcessCollector(self.registry)

    @property
    def _value_class(self):
        return

    def tearDown(self):
        del os.environ['PROMETHEUS_MULTIPROC_DIR']
        values.close_all_multiprocess_files()
        values.ValueClass = MutexValue
        shutil.rmtree(self.tempdir)

    def test_counter_adds(self):
        c1 = Counter('c', 'help', registry=None)
        values.ValueClass = MultiProcessValue(lambda: 456)
        c2 = Counter('c', 'help', registry=None)
        self.assertEqual(0, self.registry.get_sample_value('c_total'))
        c1.inc(1)
        c2.inc(2)
        self.assertEqual(3, self.registry.get_sample_value('c_total'))

    def test_summary_adds(self):
        s1 = Summary('s', 'help', registry=None)
        values.ValueClass = MultiProcessValue(lambda: 456)
        s2 = Summary('s', 'help', registry=None)
        self.assertEqual(0, self.registry.get_sample_value('s_count'))
        self.assertEqual(0, self.registry.get_sample_value('s_sum'))
        s1.observe(1)
        s2.observe(2)
        self.assertEqual(2, self.registry.get_sample_value('s_count'))
        self.assertEqual(3, self.registry.get_sample_value('s_sum'))

    def test_histogram_adds(self):
        h1 = Histogram('h', 'help', registry=None)
        values.ValueClass = MultiProcessValue(lambda: 456)
        h2 = Histogram('h', 'help', registry=None)
        self.assertEqual(0, self.registry.get_sample_value('h_count'))
        self.assertEqual(0, self.registry.get_sample_value('h_sum'))
        self.assertEqual(0, self.registry.get_sample_value('h_bucket', {'le': '5.0'}))
        h1.observe(1)
        h2.observe(2)
        self.assertEqual(2, self.registry.get_sample_value('h_count'))
        self.assertEqual(3, self.registry.get_sample_value('h_sum'))
        self.assertEqual(2, self.registry.get_sample_value('h_bucket', {'le': '5.0'}))

    def test_histogram_nan(self):
        h1 = Histogram('h', 'help', registry=None)
        values.ValueClass = MultiProcessValue(lambda: 456)
        h2 = Histogram('h', 'help', registry=None)
        h1.observe(float('nan'))
        h2.observe(2)

        self.assertEqual(1, self.registry.get_sample_value('h_bucket', {'le': '5.0'}))
        self.assertEqual(2, self.registry.get_sample_value('h_bucket', {'le': '+Inf'}))
        self.assertEqual(2, self.registry.get_sample_value('h_count'))
        self.assertTrue(math.isnan(self.registry.get_sample_value('h_sum')))

    def test_histogram_negative_buckets(self):
        h1 = Histogram('h', 'help', labelnames=['l'], buckets=[-1, 0, 1], registry=None)
        values.ValueClass = MultiProcessValue(lambda: 456)
        h2 = Histogram('h', 'help', labelnames=['l'], buckets=[-1, 0, 1], registry=None)
        h1.labels('x').observe(-0.5)
        h2.labels('x').observe(2)

        self.assertEqual(1, self.registry.get_sample_value('h_bucket', {'l': 'x', 'le': '0.0'}))
        self.assertEqual(2, self.registry.get_sample_value('h_bucket', {'l': 'x', 'le': '+Inf'}))
        self.assertEqual(2, self.registry.get_sample_value('h_count', {'l': 'x'}))
        self.assertEqual(1.5, self.registry.get_sample_value('h_sum', {'l': 'x'}))
        # OpenMetrics 1.0 doesn't allow _sum with negative buckets, or _count without _sum. 2.0 has both.
        om_1_0 = openmetrics_generate_latest(self.registry, version='1.0.0')
        self.assertNotIn(b'h_sum', om_1_0)
        self.assertNotIn(b'h_count', om_1_0)
        om_2_0 = openmetrics_generate_latest(self.registry, version='2.0.0')
        self.assertIn(b'h_sum{l="x"} 1.5', om_2_0)
        self.assertIn(b'h_count{l="x"} 2.0', om_2_0)

    def test_gauge_all(self):
        g1 = Gauge('g', 'help', registry=None)
        values.ValueClass = MultiProcessValue(lambda: 456)
        g2 = Gauge('g', 'help', registry=None)
        self.assertEqual(0, self.registry.get_sample_value('g', {'pid': '123'}))
        self.assertEqual(0, self.registry.get_sample_value('g', {'pid': '456'}))
        g1.set(1)
        g2.set(2)
        mark_process_dead(123)
        self.assertEqual(1, self.registry.get_sample_value('g', {'pid': '123'}))
        self.assertEqual(2, self.registry.get_sample_value('g', {'pid': '456'}))

    def test_gauge_liveall(self):
        g1 = Gauge('g', 'help', registry=None, multiprocess_mode='liveall')
        values.ValueClass = MultiProcessValue(lambda: 456)
        g2 = Gauge('g', 'help', registry=None, multiprocess_mode='liveall')
        self.assertEqual(0, self.registry.get_sample_value('g', {'pid': '123'}))
        self.assertEqual(0, self.registry.get_sample_value('g', {'pid': '456'}))
        g1.set(1)
        g2.set(2)
        self.assertEqual(1, self.registry.get_sample_value('g', {'pid': '123'}))
        self.assertEqual(2, self.registry.get_sample_value('g', {'pid': '456'}))
        values.close_all_multiprocess_files()
        mark_process_dead(123, os.environ['PROMETHEUS_MULTIPROC_DIR'])
        self.assertEqual(None, self.registry.get_sample_value('g', {'pid': '123'}))
        self.assertEqual(2, self.registry.get_sample_value('g', {'pid': '456'}))

    def test_gauge_min(self):
        g1 = Gauge('g', 'help', registry=None, multiprocess_mode='min')
        values.ValueClass = MultiProcessValue(lambda: 456)
        g2 = Gauge('g', 'help', registry=None, multiprocess_mode='min')
        self.assertEqual(0, self.registry.get_sample_value('g'))
        g1.set(1)
        g2.set(2)
        self.assertEqual(1, self.registry.get_sample_value('g'))

    def test_gauge_livemin(self):
        g1 = Gauge('g', 'help', registry=None, multiprocess_mode='livemin')
        values.ValueClass = MultiProcessValue(lambda: 456)
        g2 = Gauge('g', 'help', registry=None, multiprocess_mode='livemin')
        self.assertEqual(0, self.registry.get_sample_value('g'))
        g1.set(1)
        g2.set(2)
        self.assertEqual(1, self.registry.get_sample_value('g'))
        values.close_all_multiprocess_files()
        mark_process_dead(123, os.environ['PROMETHEUS_MULTIPROC_DIR'])
        self.assertEqual(2, self.registry.get_sample_value('g'))

    def test_gauge_max(self):
        g1 = Gauge('g', 'help', registry=None, multiprocess_mode='max')
        values.ValueClass = MultiProcessValue(lambda: 456)
        g2 = Gauge('g', 'help', registry=None, multiprocess_mode='max')
        self.assertEqual(0, self.registry.get_sample_value('g'))
        g1.set(1)
        g2.set(2)
        self.assertEqual(2, self.registry.get_sample_value('g'))

    def test_gauge_livemax(self):
        g1 = Gauge('g', 'help', registry=None, multiprocess_mode='livemax')
        values.ValueClass = MultiProcessValue(lambda: 456)
        g2 = Gauge('g', 'help', registry=None, multiprocess_mode='livemax')
        self.assertEqual(0, self.registry.get_sample_value('g'))
        g1.set(2)
        g2.set(1)
        self.assertEqual(2, self.registry.get_sample_value('g'))
        values.close_all_multiprocess_files()
        mark_process_dead(123, os.environ['PROMETHEUS_MULTIPROC_DIR'])
        self.assertEqual(1, self.registry.get_sample_value('g'))

    def test_gauge_sum(self):
        g1 = Gauge('g', 'help', registry=None, multiprocess_mode='sum')
        values.ValueClass = MultiProcessValue(lambda: 456)
        g2 = Gauge('g', 'help', registry=None, multiprocess_mode='sum')
        self.assertEqual(0, self.registry.get_sample_value('g'))
        g1.set(1)
        g2.set(2)
        self.assertEqual(3, self.registry.get_sample_value('g'))
        values.close_all_multiprocess_files()
        mark_process_dead(123, os.environ['PROMETHEUS_MULTIPROC_DIR'])
        self.assertEqual(3, self.registry.get_sample_value('g'))

    def test_gauge_livesum(self):
        g1 = Gauge('g', 'help', registry=None, multiprocess_mode='livesum')
        values.ValueClass = MultiProcessValue(lambda: 456)
        g2 = Gauge('g', 'help', registry=None, multiprocess_mode='livesum')
        self.assertEqual(0, self.registry.get_sample_value('g'))
        g1.set(1)
        g2.set(2)
        self.assertEqual(3, self.registry.get_sample_value('g'))
        values.close_all_multiprocess_files()
        mark_process_dead(123, os.environ['PROMETHEUS_MULTIPROC_DIR'])
        self.assertEqual(2, self.registry.get_sample_value('g'))

    def test_gauge_mostrecent(self):
        g1 = Gauge('g', 'help', registry=None, multiprocess_mode='mostrecent')
        values.ValueClass = MultiProcessValue(lambda: 456)
        g2 = Gauge('g', 'help', registry=None, multiprocess_mode='mostrecent')
        # Give each set() a distinct timestamp so the result doesn't depend on
        # clock resolution or the order the .db files are read in.
        with mock.patch('prometheus_client.metrics.time.time', side_effect=[1.0, 2.0]):
            g2.set(2)
            g1.set(1)
        self.assertEqual(1, self.registry.get_sample_value('g'))
        values.close_all_multiprocess_files()
        mark_process_dead(123, os.environ['PROMETHEUS_MULTIPROC_DIR'])
        self.assertEqual(1, self.registry.get_sample_value('g'))

    def test_gauge_livemostrecent(self):
        g1 = Gauge('g', 'help', registry=None, multiprocess_mode='livemostrecent')
        values.ValueClass = MultiProcessValue(lambda: 456)
        g2 = Gauge('g', 'help', registry=None, multiprocess_mode='livemostrecent')
        # Give each set() a distinct timestamp so the result doesn't depend on
        # clock resolution or the order the .db files are read in.
        with mock.patch('prometheus_client.metrics.time.time', side_effect=[1.0, 2.0]):
            g2.set(2)
            g1.set(1)
        self.assertEqual(1, self.registry.get_sample_value('g'))
        values.close_all_multiprocess_files()
        mark_process_dead(123, os.environ['PROMETHEUS_MULTIPROC_DIR'])
        self.assertEqual(2, self.registry.get_sample_value('g'))

    def test_namespace_subsystem(self):
        c1 = Counter('c', 'help', registry=None, namespace='ns', subsystem='ss')
        c1.inc(1)
        self.assertEqual(1, self.registry.get_sample_value('ns_ss_c_total'))

    def test_counter_across_forks(self):
        pid = 0
        values.ValueClass = MultiProcessValue(lambda: pid)
        c1 = Counter('c', 'help', registry=None)
        self.assertEqual(0, self.registry.get_sample_value('c_total'))
        c1.inc(1)
        c1.inc(1)
        pid = 1
        c1.inc(1)
        self.assertEqual(3, self.registry.get_sample_value('c_total'))
        self.assertEqual(1, c1._value.get())

    def test_initialization_detects_pid_change(self):
        pid = 0
        values.ValueClass = MultiProcessValue(lambda: pid)

        # can not inspect the files cache directly, as it's a closure, so we
        # check for the actual files themselves
        def files():
            fs = os.listdir(os.environ['PROMETHEUS_MULTIPROC_DIR'])
            fs.sort()
            return fs

        c1 = Counter('c1', 'c1', registry=None)
        self.assertEqual(files(), ['counter_0.db'])
        c2 = Counter('c2', 'c2', registry=None)
        self.assertEqual(files(), ['counter_0.db'])
        pid = 1
        c3 = Counter('c3', 'c3', registry=None)
        self.assertEqual(files(), ['counter_0.db', 'counter_1.db'])

    def test_collect(self):
        pid = 0
        values.ValueClass = MultiProcessValue(lambda: pid)
        labels = {i: i for i in 'abcd'}

        def add_label(key, value):
            l = labels.copy()
            l[key] = value
            return l

        c = Counter('c', 'help', labelnames=labels.keys(), registry=None)
        g = Gauge('g', 'help', labelnames=labels.keys(), registry=None)
        h = Histogram('h', 'help', labelnames=labels.keys(), registry=None)

        c.labels(**labels).inc(1)
        g.labels(**labels).set(1)
        h.labels(**labels).observe(1)

        pid = 1

        c.labels(**labels).inc(1)
        g.labels(**labels).set(1)
        h.labels(**labels).observe(5)

        metrics = {m.name: m for m in self.collector.collect()}

        self.assertEqual(
            metrics['c'].samples, [Sample('c_total', labels, 2.0)]
        )
        metrics['g'].samples.sort(key=lambda x: x[1]['pid'])
        self.assertEqual(metrics['g'].samples, [
            Sample('g', add_label('pid', '0'), 1.0),
            Sample('g', add_label('pid', '1'), 1.0),
        ])

        expected_histogram = [
            Sample('h_sum', labels, 6.0),
            Sample('h_bucket', add_label('le', '0.005'), 0.0),
            Sample('h_bucket', add_label('le', '0.01'), 0.0),
            Sample('h_bucket', add_label('le', '0.025'), 0.0),
            Sample('h_bucket', add_label('le', '0.05'), 0.0),
            Sample('h_bucket', add_label('le', '0.075'), 0.0),
            Sample('h_bucket', add_label('le', '0.1'), 0.0),
            Sample('h_bucket', add_label('le', '0.25'), 0.0),
            Sample('h_bucket', add_label('le', '0.5'), 0.0),
            Sample('h_bucket', add_label('le', '0.75'), 0.0),
            Sample('h_bucket', add_label('le', '1.0'), 1.0),
            Sample('h_bucket', add_label('le', '2.5'), 1.0),
            Sample('h_bucket', add_label('le', '5.0'), 2.0),
            Sample('h_bucket', add_label('le', '7.5'), 2.0),
            Sample('h_bucket', add_label('le', '10.0'), 2.0),
            Sample('h_bucket', add_label('le', '+Inf'), 2.0),
            Sample('h_count', labels, 2.0),
        ]

        self.assertEqual(metrics['h'].samples, expected_histogram)

    def test_collect_histogram_ordering(self):
        pid = 0
        values.ValueClass = MultiProcessValue(lambda: pid)
        labels = {i: i for i in 'abcd'}

        def add_label(key, value):
            l = labels.copy()
            l[key] = value
            return l

        h = Histogram('h', 'help', labelnames=['view'], registry=None)

        h.labels(view='view1').observe(1)

        pid = 1

        h.labels(view='view1').observe(5)
        h.labels(view='view2').observe(1)

        metrics = {m.name: m for m in self.collector.collect()}

        expected_histogram = [
            Sample('h_sum', {'view': 'view1'}, 6.0),
            Sample('h_bucket', {'view': 'view1', 'le': '0.005'}, 0.0),
            Sample('h_bucket', {'view': 'view1', 'le': '0.01'}, 0.0),
            Sample('h_bucket', {'view': 'view1', 'le': '0.025'}, 0.0),
            Sample('h_bucket', {'view': 'view1', 'le': '0.05'}, 0.0),
            Sample('h_bucket', {'view': 'view1', 'le': '0.075'}, 0.0),
            Sample('h_bucket', {'view': 'view1', 'le': '0.1'}, 0.0),
            Sample('h_bucket', {'view': 'view1', 'le': '0.25'}, 0.0),
            Sample('h_bucket', {'view': 'view1', 'le': '0.5'}, 0.0),
            Sample('h_bucket', {'view': 'view1', 'le': '0.75'}, 0.0),
            Sample('h_bucket', {'view': 'view1', 'le': '1.0'}, 1.0),
            Sample('h_bucket', {'view': 'view1', 'le': '2.5'}, 1.0),
            Sample('h_bucket', {'view': 'view1', 'le': '5.0'}, 2.0),
            Sample('h_bucket', {'view': 'view1', 'le': '7.5'}, 2.0),
            Sample('h_bucket', {'view': 'view1', 'le': '10.0'}, 2.0),
            Sample('h_bucket', {'view': 'view1', 'le': '+Inf'}, 2.0),
            Sample('h_count', {'view': 'view1'}, 2.0),
            Sample('h_sum', {'view': 'view2'}, 1.0),
            Sample('h_bucket', {'view': 'view2', 'le': '0.005'}, 0.0),
            Sample('h_bucket', {'view': 'view2', 'le': '0.01'}, 0.0),
            Sample('h_bucket', {'view': 'view2', 'le': '0.025'}, 0.0),
            Sample('h_bucket', {'view': 'view2', 'le': '0.05'}, 0.0),
            Sample('h_bucket', {'view': 'view2', 'le': '0.075'}, 0.0),
            Sample('h_bucket', {'view': 'view2', 'le': '0.1'}, 0.0),
            Sample('h_bucket', {'view': 'view2', 'le': '0.25'}, 0.0),
            Sample('h_bucket', {'view': 'view2', 'le': '0.5'}, 0.0),
            Sample('h_bucket', {'view': 'view2', 'le': '0.75'}, 0.0),
            Sample('h_bucket', {'view': 'view2', 'le': '1.0'}, 1.0),
            Sample('h_bucket', {'view': 'view2', 'le': '2.5'}, 1.0),
            Sample('h_bucket', {'view': 'view2', 'le': '5.0'}, 1.0),
            Sample('h_bucket', {'view': 'view2', 'le': '7.5'}, 1.0),
            Sample('h_bucket', {'view': 'view2', 'le': '10.0'}, 1.0),
            Sample('h_bucket', {'view': 'view2', 'le': '+Inf'}, 1.0),
            Sample('h_count', {'view': 'view2'}, 1.0),
        ]

        self.assertEqual(metrics['h'].samples, expected_histogram)

    def test_restrict(self):
        pid = 0
        values.ValueClass = MultiProcessValue(lambda: pid)
        labels = {i: i for i in 'abcd'}

        def add_label(key, value):
            l = labels.copy()
            l[key] = value
            return l

        c = Counter('c', 'help', labelnames=labels.keys(), registry=None)
        g = Gauge('g', 'help', labelnames=labels.keys(), registry=None)

        c.labels(**labels).inc(1)
        g.labels(**labels).set(1)

        pid = 1

        c.labels(**labels).inc(1)
        g.labels(**labels).set(1)

        metrics = {m.name: m for m in self.registry.restricted_registry(['c_total']).collect()}

        self.assertEqual(metrics.keys(), {'c'})

        self.assertEqual(
            metrics['c'].samples, [Sample('c_total', labels, 2.0)]
        )

    def test_collect_preserves_help(self):
        pid = 0
        values.ValueClass = MultiProcessValue(lambda: pid)
        labels = {i: i for i in 'abcd'}

        c = Counter('c', 'c help', labelnames=labels.keys(), registry=None)
        g = Gauge('g', 'g help', labelnames=labels.keys(), registry=None)
        h = Histogram('h', 'h help', labelnames=labels.keys(), registry=None)

        c.labels(**labels).inc(1)
        g.labels(**labels).set(1)
        h.labels(**labels).observe(1)

        pid = 1

        c.labels(**labels).inc(1)
        g.labels(**labels).set(1)
        h.labels(**labels).observe(5)

        metrics = {m.name: m for m in self.collector.collect()}

        self.assertEqual(metrics['c'].documentation, 'c help')
        self.assertEqual(metrics['g'].documentation, 'g help')
        self.assertEqual(metrics['h'].documentation, 'h help')

    def test_merge_no_accumulate(self):
        pid = 0
        values.ValueClass = MultiProcessValue(lambda: pid)
        labels = {i: i for i in 'abcd'}

        def add_label(key, value):
            l = labels.copy()
            l[key] = value
            return l

        h = Histogram('h', 'help', labelnames=labels.keys(), registry=None)
        h.labels(**labels).observe(1)
        pid = 1
        h.labels(**labels).observe(5)

        path = os.path.join(os.environ['PROMETHEUS_MULTIPROC_DIR'], '*.db')
        files = glob.glob(path)
        metrics = {
            m.name: m for m in self.collector.merge(files, accumulate=False)
        }

        expected_histogram = [
            Sample('h_sum', labels, 6.0),
            Sample('h_bucket', add_label('le', '0.005'), 0.0),
            Sample('h_bucket', add_label('le', '0.01'), 0.0),
            Sample('h_bucket', add_label('le', '0.025'), 0.0),
            Sample('h_bucket', add_label('le', '0.05'), 0.0),
            Sample('h_bucket', add_label('le', '0.075'), 0.0),
            Sample('h_bucket', add_label('le', '0.1'), 0.0),
            Sample('h_bucket', add_label('le', '0.25'), 0.0),
            Sample('h_bucket', add_label('le', '0.5'), 0.0),
            Sample('h_bucket', add_label('le', '0.75'), 0.0),
            Sample('h_bucket', add_label('le', '1.0'), 1.0),
            Sample('h_bucket', add_label('le', '2.5'), 0.0),
            Sample('h_bucket', add_label('le', '5.0'), 1.0),
            Sample('h_bucket', add_label('le', '7.5'), 0.0),
            Sample('h_bucket', add_label('le', '10.0'), 0.0),
            Sample('h_bucket', add_label('le', '+Inf'), 0.0),
        ]

        self.assertEqual(metrics['h'].samples, expected_histogram)

    def test_missing_gauge_file_during_merge(self):
        # These files don't exist, just like if mark_process_dead(9999999) had been
        # called during self.collector.collect(), after the glob found it
        # but before the merge actually happened.
        # This should not raise and return no metrics
        self.assertFalse(self.collector.merge([
            os.path.join(self.tempdir, 'gauge_liveall_9999999.db'),
            os.path.join(self.tempdir, 'gauge_livesum_9999999.db'),
        ]))

    def test_uninitialized_file_during_merge(self):
        # This file exists but is still zero bytes, just like a file created by
        # MmapedDict.__init__ that has not been truncated to its initial size
        # yet, or one left behind by a process that died in that window.
        # This should not raise and return no metrics
        empty_file = os.path.join(self.tempdir, 'counter_9999999.db')
        open(empty_file, 'wb').close()

        self.assertFalse(self.collector.merge([empty_file]))

    def test_uninitialized_file_does_not_hide_other_metrics(self):
        # A single unreadable file must not take the whole collection with it,
        # as an empty file can be left behind indefinitely: it is named after a
        # pid that never comes back, so nothing cleans it up.
        c = Counter('c', 'help', registry=None)
        c.inc(1)
        open(os.path.join(self.tempdir, 'counter_9999999.db'), 'wb').close()

        self.assertEqual(1, self.registry.get_sample_value('c_total'))

    def test_remove_clear_warning(self):
        os.environ['PROMETHEUS_MULTIPROC_DIR'] = self.tempdir
        with warnings.catch_warnings(record=True) as w:
            values.ValueClass = get_value_class()
            registry = CollectorRegistry()
            collector = MultiProcessCollector(registry)
            counter = Counter('c', 'help', labelnames=['label'], registry=None)
            counter.labels('label').inc()
            counter.remove('label')
            counter.clear()
            assert os.environ['PROMETHEUS_MULTIPROC_DIR'] == self.tempdir
            assert issubclass(w[0].category, UserWarning)
            assert "Removal of labels has not been implemented" in str(w[0].message)
            assert issubclass(w[-1].category, UserWarning)
            assert "Clearing labels has not been implemented" in str(w[-1].message)
    
    def test_child_name_is_built_once_with_namespace_subsystem_unit(self):
        """
        Repro for #1035:
        In multiprocess mode, child metrics must NOT rebuild the full name
        (namespace/subsystem/unit) a second time. The exported family name should
        be built once, and Counter samples should use "<family>_total".
        """
        from prometheus_client import Counter

        class CustomCounter(Counter):
            def __init__(
                self, 
                name, 
                documentation, 
                labelnames=(),
                namespace="mydefaultnamespace", 
                subsystem="mydefaultsubsystem",
                unit="", 
                registry=None, 
                _labelvalues=None
            ):
                # Intentionally provide non-empty defaults to trigger the bug path.
                super().__init__(
                    name=name, 
                    documentation=documentation,
                    labelnames=labelnames, 
                    namespace=namespace,
                    subsystem=subsystem, 
                    unit=unit, 
                    registry=registry,
                    _labelvalues=_labelvalues)

        # Create a Counter with explicit namespace/subsystem/unit
        c = CustomCounter(
            name='m',
            documentation='help',
            labelnames=('status', 'method'),
            namespace='ns',
            subsystem='ss',
            unit='seconds',   # avoid '_total_total' confusion
            registry=None,    # not registered in local registry in multiprocess mode
        )

        # Create two labeled children
        c.labels(status='200', method='GET').inc()
        c.labels(status='404', method='POST').inc()

        # Collect from the multiprocess collector initialized in setUp()
        metrics = {m.name: m for m in self.collector.collect()}

        # Family name should be built once (no '_total' in family name)
        expected_family = 'ns_ss_m_seconds'
        self.assertIn(expected_family, metrics, f"missing family {expected_family}")

        # Counter samples must use '<family>_total'
        mf = metrics[expected_family]
        sample_names = {s.name for s in mf.samples}
        self.assertTrue(
            all(name == expected_family + '_total' for name in sample_names),
            f"unexpected sample names: {sample_names}"
        )

        # Ensure no double-built prefix sneaks in (the original bug)
        bad_prefix = 'mydefaultnamespace_mydefaultsubsystem_'
        all_names = {mf.name, *sample_names}
        self.assertTrue(
            all(not n.startswith(bad_prefix) for n in all_names),
            f"found double-built name(s): {[n for n in all_names if n.startswith(bad_prefix)]}"
        )

    def test_child_preserves_parent_context_for_subclasses(self):
        """
        Ensure child metrics preserve parent's namespace/subsystem/unit information
        so that subclasses can correctly use these parameters in their logic.
        """
        class ContextAwareCounter(Counter):
            def __init__(self,
                         name,
                         documentation,
                         labelnames=(),
                         namespace="",
                         subsystem="",
                         unit="",
                         **kwargs):
                self.context = {
                    'namespace': namespace,
                    'subsystem': subsystem,
                    'unit': unit
                }
                super().__init__(name, documentation,
                                 labelnames=labelnames,
                                 namespace=namespace,
                                 subsystem=subsystem,
                                 unit=unit,
                                 **kwargs)

        parent = ContextAwareCounter('m', 'help',
                                     labelnames=['status'],
                                     namespace='prod',
                                     subsystem='api',
                                     unit='seconds',
                                     registry=None)

        child = parent.labels(status='200')

        # Verify that child retains parent's context
        self.assertEqual(child.context['namespace'], 'prod')
        self.assertEqual(child.context['subsystem'], 'api')
        self.assertEqual(child.context['unit'], 'seconds')


class TestSessionAwareCleanup(unittest.TestCase):
    """Reclamation of live gauges must follow the write session, not just the pid."""

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        os.environ['PROMETHEUS_MULTIPROC_DIR'] = self.tempdir
        self.registry = CollectorRegistry(support_collectors_without_names=True)
        self.collector = MultiProcessCollector(self.registry)

    def tearDown(self):
        os.environ.pop('PROMETHEUS_MULTIPROC_DIR', None)
        values.close_all_multiprocess_files()
        values.ValueClass = MutexValue
        shutil.rmtree(self.tempdir)

    def _files(self):
        return sorted(os.listdir(self.tempdir))

    def _start_session(self, pid, session_id, gauge_value, mode='liveall'):
        values.ValueClass = MultiProcessValue(lambda: pid, session_id=session_id)
        gauge = Gauge('g', 'help', registry=None, multiprocess_mode=mode)
        gauge.set(gauge_value)
        return gauge

    def test_two_sessions_reusing_pid_and_late_exit(self):
        self._start_session(4242, 111, 10)
        counter = Counter('c', 'help', registry=None)
        counter.inc(5)
        values.close_all_multiprocess_files()
        self.assertEqual(10, self.registry.get_sample_value('g', {'pid': '4242'}))
        self.assertEqual(5, self.registry.get_sample_value('c_total'))

        # A restart reuses the pid with a new session and a new live gauge.
        self._start_session(4242, 222, 20)
        Counter('c', 'help', registry=None).inc(2)
        self.assertEqual(20, self.registry.get_sample_value('g', {'pid': '4242'}))
        self.assertEqual(7, self.registry.get_sample_value('c_total'))
        self.assertEqual(
            {'counter_4242.db': 222, 'gauge_liveall_4242.db': 222},
            multiprocess.sessions_in(self.tempdir))

        # The old session's exit notice arrives while session 2 is still live.
        late = mark_process_dead(4242, session_id=111)
        self.assertEqual(['held'], [f.status for f in late.files])
        self.assertEqual([], late.reclaimed)
        self.assertEqual(20, self.registry.get_sample_value('g', {'pid': '4242'}))
        self.assertEqual(7, self.registry.get_sample_value('c_total'))

        # After the new writer is gone the same stale notice stays inert.
        values.close_all_multiprocess_files()
        stale = mark_process_dead(4242, session_id=111)
        self.assertEqual(['session_changed'], [f.status for f in stale.files])
        self.assertEqual([], stale.reclaimed)
        self.assertEqual(20, self.registry.get_sample_value('g', {'pid': '4242'}))

        # Its own notice reclaims the file.
        current = mark_process_dead(4242, session_id=222)
        self.assertEqual(1, len(current.reclaimed))
        self.assertIsNone(self.registry.get_sample_value('g', {'pid': '4242'}))
        # The counter keeps its value until the directory is wiped.
        self.assertEqual(7, self.registry.get_sample_value('c_total'))
        self.assertEqual(
            [os.path.join(self.tempdir, 'counter_4242.db')], current.retained)
        self.assertEqual(['counter_4242.db'], self._files())

    def test_live_writer_in_another_process_is_protected(self):
        # A real second process holds its write session open; cleanup in this
        # process must see the lock, report HELD, and leave the file alone.
        script = (
            'import os, sys, time\n'
            'from prometheus_client import values\n'
            'from prometheus_client.core import Gauge\n'
            'from prometheus_client.values import MultiProcessValue\n'
            'os.environ["PROMETHEUS_MULTIPROC_DIR"] = sys.argv[1]\n'
            'values.ValueClass = MultiProcessValue(lambda: 13131)\n'
            'g = Gauge("g", "help", registry=None, multiprocess_mode="liveall")\n'
            'g.set(7)\n'
            'print(g._value._file.session_id, flush=True)\n'
            'time.sleep(10)\n'
        )
        proc = subprocess.Popen(
            [sys.executable, '-c', script, self.tempdir], stdout=subprocess.PIPE, text=True)
        try:
            session = int(proc.stdout.readline())
            result = mark_process_dead(13131, session_id=session)
            self.assertEqual(['held'], [f.status for f in result.files])
            self.assertEqual([], result.reclaimed)
            self.assertEqual(
                {os.path.join(self.tempdir, 'gauge_liveall_13131.db'): session},
                result.active_sessions)
            self.assertEqual(7, self.registry.get_sample_value('g', {'pid': '13131'}))
        finally:
            proc.kill()
            proc.wait()
        # With the writer gone its own session reclaims the file.
        result = mark_process_dead(13131, session_id=session)
        self.assertEqual(['reclaimed'], [f.status for f in result.files])

    def test_session_mismatch_after_writer_gone(self):
        # Write the file for session 111, then let a *different* dead session's
        # notice arrive after the writer is gone. The file must be left alone.
        self._start_session(5151, 111, 10)
        values.close_all_multiprocess_files()
        result = mark_process_dead(5151, session_id=222)
        self.assertEqual(['session_changed'], [f.status for f in result.files])
        self.assertEqual([], result.reclaimed)
        self.assertEqual(10, self.registry.get_sample_value('g', {'pid': '5151'}))

    def test_live_writer_is_protected_and_reported(self):
        # A writer that is still open must not be reclaimed, even with a
        # matching session: it is still providing samples.
        gauge = self._start_session(6161, 111, 10)
        session = gauge._value._file.session_id
        result = mark_process_dead(6161, session_id=session)
        self.assertEqual(['held'], [f.status for f in result.files])
        self.assertEqual(
            {os.path.join(self.tempdir, 'gauge_liveall_6161.db'): session},
            result.active_sessions)
        self.assertEqual(10, self.registry.get_sample_value('g', {'pid': '6161'}))
        self.assertIn('held', result.report())

    def test_unknown_session_policy(self):
        # Simulate a file from a client that predates session tokens.
        self._start_session(7171, 111, 10)
        values.close_all_multiprocess_files()
        filename = os.path.join(self.tempdir, 'gauge_liveall_7171.db')
        with open(filename, 'r+b') as fp:
            fp.seek(mmap_dict._SESSION_OFFSET)
            fp.write(b'\x00\x00\x00\x00')
        self.assertIsNone(multiprocess.session_of(filename))

        kept = mark_process_dead(7171, allow_unknown=False)
        self.assertEqual(['unknown_session'], [f.status for f in kept.files])
        self.assertTrue(os.path.exists(filename))

        reclaimed = mark_process_dead(7171)
        self.assertEqual(['reclaimed'], [f.status for f in reclaimed.files])
        self.assertFalse(os.path.exists(filename))

    def test_dry_run_does_not_remove(self):
        self._start_session(8181, 111, 10)
        values.close_all_multiprocess_files()
        result = mark_process_dead(8181, dry_run=True)
        self.assertEqual(['reclaimed'], [f.status for f in result.files])
        self.assertTrue(os.path.exists(
            os.path.join(self.tempdir, 'gauge_liveall_8181.db')))

    def test_non_live_modes_are_retained(self):
        self._start_session(9191, 111, 10, mode='all')
        self._start_session(9191, 111, 3, mode='livesum')
        values.close_all_multiprocess_files()
        result = mark_process_dead(9191)
        self.assertEqual(
            [os.path.join(self.tempdir, 'gauge_livesum_9191.db')],
            result.reclaimed)
        self.assertEqual(
            [os.path.join(self.tempdir, 'gauge_all_9191.db')], result.retained)
        self.assertTrue(os.path.exists(
            os.path.join(self.tempdir, 'gauge_all_9191.db')))
        self.assertEqual(10, self.registry.get_sample_value('g', {'pid': '9191'}))

    def test_session_is_kept_for_explicit_token(self):
        # A writer that names its session keeps it across reopen, so cleanup
        # can still match the token it was told to expect.
        filename = os.path.join(self.tempdir, 'probe.db')
        first = mmap_dict.MmapedDict(filename, session_id=1234)
        self.assertEqual(1234, first.session_id)
        first.close()
        second = mmap_dict.MmapedDict(filename, session_id=1234)
        self.assertEqual(1234, second.session_id)
        second.close()

    def test_reopen_without_token_mints_new_session(self):
        # A plain reopen is a new incarnation: its token must differ so a late
        # notice aimed at the previous writer cannot match it.
        filename = os.path.join(self.tempdir, 'probe.db')
        first = mmap_dict.MmapedDict(filename)
        token = first.session_id
        self.assertIsNotNone(token)
        first.close()
        second = mmap_dict.MmapedDict(filename)
        self.assertNotEqual(token, second.session_id)
        second.close()

    def test_stale_session_is_replaced_by_restart(self):
        filename = os.path.join(self.tempdir, 'probe.db')
        first = mmap_dict.MmapedDict(filename, session_id=111)
        first.close()
        second = mmap_dict.MmapedDict(filename, session_id=222)
        self.assertEqual(222, second.session_id)
        second.close()

    def test_fork_rotates_session(self):
        pid = 100
        values.ValueClass = MultiProcessValue(lambda: pid)
        gauge = Gauge('g', 'help', registry=None, multiprocess_mode='liveall')
        gauge.set(1)
        parent_session = gauge._value._file.session_id
        pid = 200
        gauge.set(2)
        child_session = gauge._value._file.session_id
        self.assertNotEqual(parent_session, child_session)
        self.assertEqual(
            {'gauge_liveall_100.db': parent_session,
             'gauge_liveall_200.db': child_session},
            multiprocess.sessions_in(self.tempdir))

    def test_writer_notices_file_reclaimed_under_growth(self):
        # If cleanup unlinks the file a writer is still holding, the writer
        # must stop writing into the detached file instead of resurrecting it.
        filename = os.path.join(self.tempdir, 'probe.db')
        writer = mmap_dict.MmapedDict(filename, session_id=111)
        os.remove(filename)
        # Recreate the path with a different session, as cleanup would allow.
        other = mmap_dict.MmapedDict(filename, session_id=222)
        other.close()
        with self.assertRaises(FileNotFoundError):
            writer.write_value('key' * mmap_dict._INITIAL_MMAP_SIZE, 1.0, 0.0)
        writer.close()


class TestMmapedDict(unittest.TestCase):
    def setUp(self):
        fd, self.tempfile = tempfile.mkstemp()
        os.close(fd)
        self.d = mmap_dict.MmapedDict(self.tempfile)

    def test_process_restart(self):
        self.d.write_value('abc', 123.0, 987.0)
        self.d.close()
        self.d = mmap_dict.MmapedDict(self.tempfile)
        self.assertEqual((123, 987.0), self.d.read_value('abc'))
        self.assertEqual([('abc', 123.0, 987.0)], list(self.d.read_all_values()))

    def test_expansion(self):
        key = 'a' * mmap_dict._INITIAL_MMAP_SIZE
        self.d.write_value(key, 123.0, 987.0)
        self.assertEqual([(key, 123.0, 987.0)], list(self.d.read_all_values()))

    def test_multi_expansion(self):
        key = 'a' * mmap_dict._INITIAL_MMAP_SIZE * 4
        self.d.write_value('abc', 42.0, 987.0)
        self.d.write_value(key, 123.0, 876.0)
        self.d.write_value('def', 17.0, 765.0)
        self.assertEqual(
            [('abc', 42.0, 987.0), (key, 123.0, 876.0), ('def', 17.0, 765.0)],
            list(self.d.read_all_values()))

    def test_corruption_detected(self):
        self.d.write_value('abc', 42.0, 987.0)
        # corrupt the written data
        self.d._m[8:16] = b'somejunk'
        with self.assertRaises(RuntimeError):
            list(self.d.read_all_values())

    def test_read_all_values_from_empty_file(self):
        # A reader can observe the file in the window between __init__ creating
        # it and truncating it to _INITIAL_MMAP_SIZE, and a process dying in
        # that window leaves it empty for good. Either way it holds no values,
        # so it should read as empty rather than failing to unpack a header
        # that was never written.
        fd, empty_file = tempfile.mkstemp()
        os.close(fd)
        try:
            self.assertEqual([], list(mmap_dict.MmapedDict.read_all_values_from_file(empty_file)))
        finally:
            os.unlink(empty_file)

    def test_read_all_values_from_file_with_truncated_contents(self):
        # Only a wholly empty file is tolerated: a file claiming to hold more
        # than it does is corrupt, and should still be reported as such.
        fd, short_file = tempfile.mkstemp()
        os.close(fd)
        try:
            with open(short_file, 'wb') as outfp:
                outfp.write(mmap_dict._pack_integer_func(100))
            with self.assertRaises(struct.error):
                list(mmap_dict.MmapedDict.read_all_values_from_file(short_file))
        finally:
            os.unlink(short_file)

    def tearDown(self):
        self.d.close()
        os.unlink(self.tempfile)


class TestUnsetEnv(unittest.TestCase):
    def setUp(self):
        self.registry = CollectorRegistry()
        fp, self.tmpfl = tempfile.mkstemp()
        os.close(fp)

    def test_unset_syncdir_env(self):
        self.assertRaises(
            ValueError, MultiProcessCollector, self.registry)

    def test_file_syncpath(self):
        registry = CollectorRegistry()
        self.assertRaises(
            ValueError, MultiProcessCollector, registry, self.tmpfl)

    def tearDown(self):
        os.remove(self.tmpfl)
