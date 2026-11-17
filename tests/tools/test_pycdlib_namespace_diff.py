import json
import os
import subprocess
import sys

import pycdlib
import pytest

pycdlib_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
tool_exe = os.path.join(pycdlib_root, 'tools', 'pycdlib-namespace-diff')

sys.path.insert(0, os.path.join(pycdlib_root, 'tests', 'integration'))
from test_namespace_diff import build_hybrid_iso  # noqa: E402


def run_tool(*args):
    env = os.environ.copy()
    env['PYTHONPATH'] = pycdlib_root
    return subprocess.run([sys.executable, tool_exe] + list(args),
                          env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False)


def test_text_report_lists_namespaces_and_exits_clean(tmpdir):
    iso_path = build_hybrid_iso(str(tmpdir.join('hybrid.iso')))
    result = run_tool(iso_path)
    assert result.returncode == 0
    text = result.stdout.decode()
    assert 'ISO namespace difference report' in text
    assert 'iso9660' in text and 'joliet' in text
    assert 'rockridge' in text and 'udf' in text


def test_json_report_is_valid_and_carries_comparisons(tmpdir):
    iso_path = build_hybrid_iso(str(tmpdir.join('hybrid.iso')))
    result = run_tool('--json', iso_path)
    assert result.returncode == 0
    payload = json.loads(result.stdout.decode())
    assert payload['block_size'] == 2048
    assert set(payload['namespaces']) == {
        'iso9660', 'rockridge', 'joliet', 'udf'}
    relations = {c['relation'] for c in payload['comparisons']}
    assert 'hard-link' in relations
    assert 'same-content-copy' in relations
    assert 'different-content' in relations


def test_missing_file_reports_error_and_nonzero_exit(tmpdir):
    result = run_tool(str(tmpdir.join('does-not-exist.iso')))
    assert result.returncode == 1
    assert b'Could not open' in result.stderr


def test_corrupt_namespace_returns_isolation_exit_code(tmpdir):
    iso_path = build_hybrid_iso(str(tmpdir.join('hybrid.iso')))

    iso = pycdlib.PyCdlib()
    iso.open(iso_path)
    joliet_extent = iso.joliet_vd.root_directory_record().extent_location()
    iso.close()

    block_size = 2048
    with open(iso_path, 'r+b') as fp:
        fp.seek(joliet_extent * block_size)
        block = bytearray(fp.read(block_size))
        offsets, cursor = [], 0
        while cursor < block_size and block[cursor] != 0:
            offsets.append(cursor)
            cursor += block[cursor]
        block[offsets[2] + 32] = 250
        fp.seek(joliet_extent * block_size)
        fp.write(bytes(block))

    result = run_tool(iso_path)
    # Namespace isolation: report is produced but exit flags the failure.
    assert result.returncode == 2
    text = result.stdout.decode()
    assert 'ENUMERATION FAILED' in text
    assert 'iso9660' in text and 'udf' in text
