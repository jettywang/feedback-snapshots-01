import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from prometheus_client import audit, provenance, values
from prometheus_client.core import Counter, Gauge, Histogram, Summary
from prometheus_client.mmap_dict import MmapedDict, mmap_key
from prometheus_client.multiprocess import MultiProcessCollector
from prometheus_client.values import MultiProcessValue, MutexValue


class AuditTestCase(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        os.environ['PROMETHEUS_MULTIPROC_DIR'] = self.tempdir

    def tearDown(self):
        os.environ.pop('PROMETHEUS_MULTIPROC_DIR', None)
        values.close_all_multiprocess_files()
        values.ValueClass = MutexValue
        shutil.rmtree(self.tempdir, ignore_errors=True)

    def _start_session(self, pid):
        values.ValueClass = MultiProcessValue(lambda: pid)
        return values.ValueClass

    def _write_legacy_file(self, filename, metric_name, value):
        """Create a metric file in the historical format, with no sidecar."""
        path = os.path.join(self.tempdir, filename)
        db = MmapedDict(path)
        db.write_value(
            mmap_key(metric_name, metric_name + '_total', [], [], 'help'),
            float(value), 0.0)
        db.close()
        self.assertFalse(
            os.path.exists(provenance.provenance_path(path)))
        return path

    def test_writer_emits_sidecar_and_session_manifest(self):
        self._start_session(123)
        Counter('c', 'help', registry=None).inc(1)
        values.close_all_multiprocess_files()

        names = os.listdir(self.tempdir)
        self.assertIn('counter_123.db', names)
        self.assertIn('counter_123.db.provenance', names)
        manifests = [n for n in names if n.startswith('session-')]
        self.assertEqual(len(manifests), 1)

        evidence = provenance.load_file_provenance(
            os.path.join(self.tempdir, 'counter_123.db'))
        self.assertEqual(evidence['process_identifier'], 123)
        self.assertEqual(evidence['metric_sessions'], {'c': [evidence['session_id']]})

        sessions = provenance.load_sessions(self.tempdir)
        self.assertEqual(
            sessions[evidence['session_id']]['process_identifiers'], [123])

    def test_evidence_survives_process_exit(self):
        # The writer only interacts with the value class through its public
        # surface; closing the files stands in for the process exiting.
        self._start_session(123)
        Counter('c', 'help', registry=None).inc(1)
        values.close_all_multiprocess_files()

        # A fresh reader with no in-memory writer state must still be able to
        # attribute the file purely from the on-disk evidence.
        infos = audit.inspect_directory(self.tempdir)
        self.assertEqual(len(infos), 1)
        self.assertEqual(infos[0].status, audit.STATUS_KNOWN)
        self.assertEqual(infos[0].writer_process_id, 123)
        self.assertTrue(infos[0].session_present)

    def test_two_deployments_same_pid_are_distinct_sessions(self):
        self._start_session(123)
        Counter('c', 'help', registry=None).inc(5)
        values.close_all_multiprocess_files()

        self._start_session(123)
        Counter('c2', 'help', registry=None).inc(7)
        values.close_all_multiprocess_files()

        report = audit.build_audit_report(self.tempdir)
        # Both sessions reused the simulated pid 123.
        self.assertEqual(report['summary']['sessions_recorded'], 2)
        sessions = list(report['sessions'].values())
        self.assertEqual(
            {s['process_identifiers'][0] for s in sessions}, {123})
        self.assertNotEqual(
            sessions[0]['session_id'], sessions[1]['session_id'])

        origins = report['metric_origins']
        self.assertEqual(origins['c']['status'], audit.STATUS_KNOWN)
        self.assertEqual(origins['c2']['status'], audit.STATUS_KNOWN)
        # Each metric is attributed to exactly one of the two sessions even
        # though both files carry the same process identifier.
        self.assertEqual(len(origins['c']['session_ids']), 1)
        self.assertEqual(len(origins['c2']['session_ids']), 1)
        self.assertNotEqual(
            origins['c']['session_ids'], origins['c2']['session_ids'])

    def test_shared_metric_across_sessions_traces_both(self):
        self._start_session(123)
        Counter('c', 'help', registry=None).inc(5)
        values.close_all_multiprocess_files()

        self._start_session(123)
        Counter('c', 'help', registry=None).inc(2)
        values.close_all_multiprocess_files()

        report = audit.build_audit_report(self.tempdir)
        origin = report['metric_origins']['c']
        self.assertEqual(origin['status'], audit.STATUS_KNOWN)
        self.assertEqual(len(origin['session_ids']), 2)
        # The aggregate itself still adds both contributions.
        self.assertEqual(
            report['aggregated_metrics']['c']['samples'][0]['value'], 7.0)

    def test_fork_joins_the_same_session(self):
        pid = 123
        values.ValueClass = MultiProcessValue(lambda: pid)
        counter = Counter('c', 'help', registry=None)
        counter.inc(1)
        # Simulate a fork: the process identifier changes but the value class
        # (and therefore its session id) is inherited.
        pid = 124
        counter.inc(1)
        values.close_all_multiprocess_files()

        report = audit.build_audit_report(self.tempdir)
        session_ids = {
            info.session_id for info in audit.inspect_directory(self.tempdir)
        }
        self.assertEqual(len(session_ids), 1)
        manifest = list(report['sessions'].values())[0]
        self.assertEqual(
            sorted(manifest['process_identifiers']), [123, 124])

    def test_legacy_file_is_unknown_with_evidence_gap(self):
        self._write_legacy_file('counter_999.db', 'oldc', 42)

        report = audit.build_audit_report(self.tempdir)
        self.assertEqual(report['summary']['unknown_files'], 1)
        info = report['metric_files'][0]
        self.assertEqual(info['status'], audit.STATUS_UNKNOWN)
        self.assertTrue(info['inferred_from_filename'])
        self.assertEqual(info['process_id'], '999')
        self.assertIsNotNone(info['evidence_gap'])
        self.assertEqual(len(report['evidence_gaps']), 1)
        self.assertEqual(
            report['evidence_gaps'][0]['filename'], 'counter_999.db')

        origin = report['metric_origins']['oldc']
        self.assertEqual(origin['status'], audit.STATUS_UNKNOWN)
        self.assertEqual(origin['session_ids'], [])
        # The legacy value is still aggregated in the normal way.
        self.assertEqual(
            report['aggregated_metrics']['oldc']['samples'][0]['value'], 42.0)

    def test_known_and_unknown_sources_are_distinguished(self):
        self._start_session(123)
        Counter('newc', 'help', registry=None).inc(3)
        values.close_all_multiprocess_files()
        self._write_legacy_file('counter_999.db', 'oldc', 9)

        report = audit.build_audit_report(self.tempdir)
        by_name = {f['filename']: f for f in report['metric_files']}
        self.assertEqual(
            by_name['counter_123.db']['status'], audit.STATUS_KNOWN)
        self.assertEqual(
            by_name['counter_999.db']['status'], audit.STATUS_UNKNOWN)
        self.assertEqual(
            report['metric_origins']['newc']['status'], audit.STATUS_KNOWN)
        self.assertEqual(
            report['metric_origins']['oldc']['status'], audit.STATUS_UNKNOWN)

    def test_standard_collector_ignores_evidence_files(self):
        self._start_session(123)
        Counter('c', 'help', registry=None).inc(1)
        Summary('s', 'help', registry=None).observe(2)
        Histogram('h', 'help', registry=None).observe(0.5)
        Gauge('g', 'help', registry=None, multiprocess_mode='sum').set(4)
        values.close_all_multiprocess_files()
        self._write_legacy_file('counter_999.db', 'oldc', 1)

        registry_values = []
        collector = MultiProcessCollector(None)
        for metric in collector.collect():
            registry_values.append(metric.name)
        self.assertEqual(
            sorted(registry_values), ['c', 'g', 'h', 'oldc', 's'])

    def test_recompute_from_temp_files_matches_report(self):
        self._start_session(123)
        Counter('c', 'help', registry=None).inc(5)
        Summary('s', 'help', registry=None).observe(2)
        values.close_all_multiprocess_files()
        self._write_legacy_file('counter_999.db', 'oldc', 11)

        outcome = audit.run_audit(self.tempdir)
        self.assertTrue(outcome['matches_report'])

        recomputed = outcome['recompute']
        # The recomputation ran entirely on copies in a temp directory.
        self.assertNotEqual(
            os.path.abspath(recomputed['workdir']),
            os.path.abspath(self.tempdir))
        self.assertTrue(
            os.path.exists(recomputed['summary_path']))
        with open(recomputed['summary_path']) as infp:
            summary = json.load(infp)
        self.assertEqual(
            summary['c']['samples'][0]['value'], 5.0)
        self.assertEqual(
            summary['oldc']['samples'][0]['value'], 11.0)
        # Originals were not modified and no report leaked into them.
        self.assertNotIn(
            'audit-report.json', os.listdir(self.tempdir))

    def test_recompute_detects_drift(self):
        self._start_session(123)
        Counter('c', 'help', registry=None).inc(5)
        values.close_all_multiprocess_files()

        report_dir = tempfile.mkdtemp()
        work_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, report_dir, ignore_errors=True)
        self.addCleanup(shutil.rmtree, work_dir, ignore_errors=True)

        outcome = audit.run_audit(
            self.tempdir, report_directory=report_dir)
        self.assertTrue(outcome['matches_report'])

        # Stage the report next to the copies so a later recompute can compare
        # against it, then mutate one copied file.
        recompute_dir = outcome['recompute']['workdir']
        shutil.copy2(
            os.path.join(report_dir, 'audit-report.json'),
            os.path.join(recompute_dir, 'audit-report.json'))
        copied_db = os.path.join(recompute_dir, 'counter_123.db')
        db = MmapedDict(copied_db)
        db.write_value(
            mmap_key('c', 'c_total', [], [], 'help'), 500.0, 0.0)
        db.close()

        rechecked = audit.recompute_aggregates(
            recompute_dir, workdir=work_dir)
        self.assertEqual(
            rechecked['aggregated_metrics']['c']['samples'][0]['value'],
            500.0)
        self.assertFalse(rechecked['matches_report'])

    def test_report_is_strict_json(self):
        self._start_session(123)
        Counter('c', 'help', registry=None).inc(1)
        values.close_all_multiprocess_files()
        report_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, report_dir, ignore_errors=True)
        outcome = audit.run_audit(
            self.tempdir, report_directory=report_dir)
        with open(outcome['report_path']) as infp:
            text = infp.read()
        self.assertNotIn('NaN', text)
        json.loads(text)

    def test_corrupt_sidecar_does_not_crash_audit(self):
        self._start_session(123)
        Counter('c', 'help', registry=None).inc(1)
        values.close_all_multiprocess_files()
        # Corrupt the sidecar and the manifest: the offline reader must treat
        # the file conservatively rather than failing the whole audit.
        sidecar = os.path.join(
            self.tempdir, 'counter_123.db.provenance')
        with open(sidecar, 'w') as outfp:
            outfp.write('{this is not json')
        for name in os.listdir(self.tempdir):
            if name.startswith('session-'):
                with open(os.path.join(self.tempdir, name), 'w') as outfp:
                    outfp.write('[1, 2, 3]')

        report = audit.build_audit_report(self.tempdir)
        self.assertEqual(report['summary']['total_files'], 1)
        info = report['metric_files'][0]
        self.assertEqual(info['status'], audit.STATUS_UNKNOWN)
        self.assertFalse(info['session_manifest_present'])
        # The metric value is still aggregated.
        self.assertEqual(
            report['aggregated_metrics']['c']['samples'][0]['value'], 1.0)

    def test_mixed_known_and_unknown_files_in_one_family(self):
        # One deployment with evidence and a legacy file both write 'c'.
        self._start_session(123)
        Counter('c', 'help', registry=None).inc(4)
        values.close_all_multiprocess_files()
        self._write_legacy_file('counter_999.db', 'c', 6)

        report = audit.build_audit_report(self.tempdir)
        origin = report['metric_origins']['c']
        # The family as a whole is unknown because one contributor lacks
        # evidence, but both contributing files are still enumerated.
        self.assertEqual(origin['status'], audit.STATUS_UNKNOWN)
        self.assertEqual(
            sorted(origin['files']),
            ['counter_123.db', 'counter_999.db'])
        self.assertEqual(origin['unknown_files'], ['counter_999.db'])
        # Aggregation still adds both contributions.
        self.assertEqual(
            report['aggregated_metrics']['c']['samples'][0]['value'], 10.0)

    def test_parse_db_filename(self):
        self.assertEqual(
            audit.parse_db_filename('counter_123.db'),
            {'type': 'counter', 'mode': None, 'process_id': '123'})
        self.assertEqual(
            audit.parse_db_filename('gauge_livesum_123.db'),
            {'type': 'gauge', 'mode': 'livesum', 'process_id': '123'})
        self.assertIsNone(audit.parse_db_filename('notes.txt'))

    def test_command_line_entry_point(self):
        self._start_session(123)
        Counter('c', 'help', registry=None).inc(1)
        values.close_all_multiprocess_files()
        self._write_legacy_file('counter_999.db', 'oldc', 1)

        report_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, report_dir, ignore_errors=True)
        proc = subprocess.run(
            [sys.executable, '-m', 'prometheus_client.audit',
             self.tempdir, '--report-directory', report_dir],
            capture_output=True, text=True, check=True,
        )
        self.assertIn('Recomputed aggregates match report: True', proc.stdout)
        self.assertIn('UNKNOWN counter_999.db', proc.stdout)
        self.assertTrue(
            os.path.exists(os.path.join(report_dir, 'audit-report.json')))

    def test_sidecar_failure_does_not_block_metric_writes(self):
        original_atomic_write = provenance._atomic_write_json

        def boom(*args, **kwargs):
            raise OSError('disk full')

        provenance._atomic_write_json = boom
        try:
            self._start_session(123)
            with self.assertWarns(RuntimeWarning):
                counter = Counter('c', 'help', registry=None)
                counter.inc(1)
            values.close_all_multiprocess_files()
        finally:
            provenance._atomic_write_json = original_atomic_write

        # The metric value itself is intact; only the evidence is missing, so
        # the file is conservatively reported as unknown.
        db_path = os.path.join(self.tempdir, 'counter_123.db')
        entries = list(MmapedDict.read_all_values_from_file(db_path))
        self.assertEqual(entries[0][1], 1.0)
        report = audit.build_audit_report(self.tempdir)
        self.assertEqual(report['summary']['unknown_files'], 1)


if __name__ == '__main__':
    unittest.main()
