from __future__ import annotations

import json
import os
import shutil

import pytest

import t.skip
from kombu.transport.filesystem_evidence import (
    MOVE_NOTE, SAME_PAYLOAD_NOTE, build_snapshot, compare_snapshots,
    export_evidence, main,
)
from kombu.utils.json import dumps


def write_msg(root, rel, payload):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dumps(payload))
    return path


@pytest.fixture
def pair(tmp_path):
    reference = tmp_path / 'reference'
    candidate = tmp_path / 'candidate'
    reference.mkdir()
    candidate.mkdir()
    return reference, candidate


def statuses(report):
    return {entry['path']: entry['status'] for entry in report['entries']}


class test_build_snapshot:

    def test_queue_state_and_identity(self, tmp_path):
        write_msg(tmp_path, 'data_in/1_a.q1.msg', {'body': 'x'})
        write_msg(tmp_path, 'data_in/2_b.q1.msg', {'body': 'y'})
        write_msg(tmp_path, 'data_in/3_c.q2.msg', {'body': 'z'})
        snapshot = build_snapshot(tmp_path)
        assert snapshot['file_count'] == 3
        assert snapshot['queues'] == {'q1': 2, 'q2': 1}
        record = snapshot['files'][0]
        assert len(record['sha256']) == 64
        assert record['size'] == os.path.getsize(
            tmp_path / record['path'])
        assert record['payload'] == 'ok'
        assert record['error'] is None

    def test_control_file_bindings(self, tmp_path):
        (tmp_path / 'control').mkdir()
        (tmp_path / 'control' / 'ex.exchange').write_text(
            dumps([['rk', '', 'q1']]))
        snapshot = build_snapshot(tmp_path)
        assert snapshot['exchanges'] == {'ex': [['rk', '', 'q1']]}

    def test_invalid_payload_still_identified(self, tmp_path):
        (tmp_path / '1_x.q.msg').write_bytes(b'\x00not-json')
        snapshot = build_snapshot(tmp_path)
        record = snapshot['files'][0]
        assert record['payload'] == 'invalid'
        assert record['sha256'] is not None
        # an unreadable payload is still a pending message on disk
        assert snapshot['queues'] == {'q': 1}

    def test_missing_root_rejected(self, tmp_path):
        with pytest.raises(NotADirectoryError):
            build_snapshot(tmp_path / 'nope')


@t.skip.if_win32
class test_read_failures:

    def test_unreadable_file_reported_not_fatal(self, tmp_path):
        path = write_msg(tmp_path, 'data_in/1_a.q.msg', {'body': 'x'})
        path.chmod(0)
        try:
            snapshot = build_snapshot(tmp_path)
        finally:
            path.chmod(0o644)
        record = snapshot['files'][0]
        assert record['error'].startswith('read failed')
        assert record['sha256'] is None
        assert snapshot['queues'] == {}


class test_compare_snapshots:

    def test_unchanged_files(self, pair):
        reference, candidate = pair
        src = write_msg(reference, 'data_in/1_a.q.msg', {'body': 'x'})
        (candidate / 'data_in').mkdir()
        # a forensic copy preserves bytes and timestamps
        shutil.copy2(str(src), str(candidate / 'data_in'))
        report = export_evidence(reference, candidate)
        assert statuses(report) == {'data_in/1_a.q.msg': 'unchanged'}
        assert report['summary'] == {'unchanged': 1}
        assert report['queues']['q']['unchanged'] == 1
        assert report['queues']['q']['reference_messages'] == 1
        assert report['queues']['q']['candidate_messages'] == 1
        # the same file in both copies is not a payload duplicate
        assert report['duplicates'] == []

    def test_moved_file_keeps_bytes_and_mtime(self, pair):
        reference, candidate = pair
        src = write_msg(reference, 'data_in/1_a.q.msg', {'body': 'x'})
        # the transport uses shutil.move() into the processed folder;
        # the candidate copy therefore holds the same file elsewhere,
        # with bytes and mtime intact
        dst = candidate / 'processed'
        dst.mkdir()
        shutil.copy2(str(src), str(dst))
        report = export_evidence(reference, candidate)
        (entry,) = report['entries']
        assert entry['status'] == 'moved'
        assert entry['path'] == 'data_in/1_a.q.msg'
        assert entry['candidate_path'] == 'processed/1_a.q.msg'
        assert entry['mtime_preserved'] is True
        assert entry['note'] == MOVE_NOTE
        assert entry['queue'] == 'q'
        assert report['queues']['q']['moved'] == 1

    def test_same_payload_different_files(self, pair):
        reference, candidate = pair
        write_msg(reference, 'data_in/1_a.q.msg', {'body': 'x'})
        write_msg(candidate, 'data_in/2_b.q.msg', {'body': 'x'})
        report = export_evidence(reference, candidate)
        (entry,) = report['entries']
        assert entry['status'] == 'same_payload_different_file'
        assert entry['path'] == 'data_in/1_a.q.msg'
        assert entry['candidate_paths'] == ['data_in/2_b.q.msg']
        assert entry['note'] == SAME_PAYLOAD_NOTE
        (duplicate,) = report['duplicates']
        assert {loc['path'] for loc in duplicate['occurrences']} == {
            'data_in/1_a.q.msg', 'data_in/2_b.q.msg'}

    def test_removed_and_added(self, pair):
        reference, candidate = pair
        write_msg(reference, 'data_in/1_a.q.msg', {'body': 'old'})
        write_msg(candidate, 'data_in/2_b.q.msg', {'body': 'new'})
        report = export_evidence(reference, candidate)
        assert statuses(report) == {
            'data_in/1_a.q.msg': 'removed',
            'data_in/2_b.q.msg': 'added',
        }
        assert report['duplicates'] == []

    def test_modified_in_place(self, pair):
        reference, candidate = pair
        write_msg(reference, 'data_in/1_a.q.msg', {'body': 'old'})
        write_msg(candidate, 'data_in/1_a.q.msg', {'body': 'new'})
        report = export_evidence(reference, candidate)
        (entry,) = report['entries']
        assert entry['status'] == 'modified'
        assert entry['sha256'] != entry['candidate_sha256']

    def test_metadata_changed_only(self, pair):
        reference, candidate = pair
        for root in (reference, candidate):
            write_msg(root, 'data_in/1_a.q.msg', {'body': 'x'})
        path = candidate / 'data_in/1_a.q.msg'
        os.utime(path, ns=(path.stat().st_atime_ns,
                           path.stat().st_mtime_ns + 1_000_000_000))
        report = export_evidence(reference, candidate)
        (entry,) = report['entries']
        assert entry['status'] == 'metadata_changed'

    def test_control_file_tracked(self, pair):
        reference, candidate = pair
        for root, binding in ((reference, [['rk', '', 'q1']]),
                              (candidate, [['rk', '', 'q1'],
                                           ['rk2', '', 'q2']])):
            (root / 'control').mkdir()
            (root / 'control' / 'ex.exchange').write_text(dumps(binding))
        report = export_evidence(reference, candidate)
        assert statuses(report) == {'control/ex.exchange': 'modified'}
        assert report['reference']['exchanges'] == {'ex': [['rk', '', 'q1']]}
        assert report['candidate']['exchanges'] == {
            'ex': [['rk', '', 'q1'], ['rk2', '', 'q2']]}

    def test_every_file_accounted_for_once(self, pair):
        reference, candidate = pair
        write_msg(reference, 'data_in/1_a.q.msg', {'body': 1})
        write_msg(reference, 'data_in/2_b.q.msg', {'body': 2})
        write_msg(candidate, 'processed/2_b.q.msg', {'body': 2})
        write_msg(candidate, 'data_in/3_c.q.msg', {'body': 3})
        report = export_evidence(reference, candidate)
        assert statuses(report) == {
            'data_in/1_a.q.msg': 'removed',
            'data_in/2_b.q.msg': 'moved',
            'data_in/3_c.q.msg': 'added',
        }
        assert sum(report['summary'].values()) == 3


class test_cli:

    def test_main_writes_report(self, pair, tmp_path):
        reference, candidate = pair
        src = write_msg(reference, 'data_in/1_a.q.msg', {'body': 'x'})
        (candidate / 'data_in').mkdir()
        shutil.copy2(str(src), str(candidate / 'data_in'))
        output = tmp_path / 'evidence.json'
        assert main([str(reference), str(candidate),
                     '--output', str(output)]) == 0
        report = json.loads(output.read_text())
        assert report['tool'] == 'kombu.transport.filesystem_evidence'
        assert report['summary'] == {'unchanged': 1}

    def test_main_prints_to_stdout(self, pair, capsys):
        reference, candidate = pair
        write_msg(reference, 'data_in/1_a.q.msg', {'body': 'x'})
        assert main([str(reference), str(candidate), '--compact']) == 0
        report = json.loads(capsys.readouterr().out)
        assert report['summary'] == {'removed': 1}
