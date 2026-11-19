"""Protective tests for raising scan parallelism safely.

The plaintext value of a finding must stay inside the process that performs the
detection. In particular, when a worker process fails, the parent process must be
able to report the failure without ever printing the scanned line (and any secret
on it). These tests run the scan both serially and through a multiprocessing pool,
and assert on the three externally visible channels:

1. the delivered scan results (the baseline payload),
2. the process messages (stdout), and
3. the error output (stderr / propagated exception).

Every channel is checked for the absence of the test secret.
"""
import json
import os
import pickle
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

from detect_secrets.core import secrets_collection as secrets_collection_module
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.exceptions import PluginExecutionError
from detect_secrets.settings import transient_settings


# A distinctive, non-real token. It deliberately does not match any shipped plugin,
# so the only detector that surfaces it is our test plugin below.
TEST_SECRET = 'zebra-parallel-guard-secret-9f3a2c7e'
FINDING_PLUGIN_PATH = os.path.abspath('testing/plugins.py')
EXPLODING_PLUGIN_PATH = os.path.abspath('testing/exploding_plugin.py')
WORKER_PLUGIN = 'ExplodingDetector'
FINDING_PLUGIN = 'HippoDetector'


# ----------------------------------------------------------------------------- #
# In-process helpers (the same code path the CLI uses, minus a subprocess shell).
# ----------------------------------------------------------------------------- #
def _config(plugin_name: str, plugin_path: str = FINDING_PLUGIN_PATH) -> dict:
    return {
        'plugins_used': [
            {
                'name': plugin_name,
                'path': 'file://{0}'.format(plugin_path),
            },
        ],
        'filters_used': [],
    }


def _write(tmp_path: Path, name: str, content: str) -> str:
    path = tmp_path / name
    path.write_text(content)
    return str(path)


def _scan(mode: str, tmp_path: Path, *files: str) -> SecretsCollection:
    collection = SecretsCollection()
    if mode == 'serial':
        for filename in files:
            collection.scan_file(filename)
    else:
        collection.scan_files(*files, num_processors=2)
    return collection


SCAN_MODES = ('serial', 'parallel')


# ----------------------------------------------------------------------------- #
# Happy path: two findings are delivered, without leaking plaintext off-process.
# ----------------------------------------------------------------------------- #
@pytest.mark.parametrize('mode', SCAN_MODES)
def test_findings_are_delivered_without_plaintext_leaving_worker(
    mode,
    tmp_path,
):
    first = _write(tmp_path, 'first.txt', 'one = hippo {0}\n'.format(TEST_SECRET))
    second = _write(tmp_path, 'second.txt', 'two = hippo {0}\n'.format(TEST_SECRET))

    with transient_settings(_config(FINDING_PLUGIN)):
        collection = _scan(mode, tmp_path, first, second)

    # Normal output still identifies the two findings.
    assert len(collection) == 2
    assert len(collection.files) == 2
    payload = json.dumps(collection.json())
    assert TEST_SECRET not in payload

    if mode == 'parallel':
        # The parent process only ever holds hashes: the plaintext never crosses the
        # inter-process boundary.
        assert all(secret.secret_value is None for _, secret in collection)
    else:
        # Serial scanning keeps the value in-process, where detection needs it.
        assert all(secret.secret_value is not None for _, secret in collection)


def test_worker_serializes_findings_without_plaintext():
    # Directly exercise the multiprocessing boundary function: whatever it returns is
    # pickled onto the pipe back to the parent, so the plaintext must already be gone.
    secret = PotentialSecret(
        type=FINDING_PLUGIN,
        filename='does-not-matter.txt',
        secret=TEST_SECRET,
        line_number=1,
    )
    with mock.patch(
        'detect_secrets.core.secrets_collection.scan.scan_file',
        return_value=iter([secret]),
    ):
        serialized = secrets_collection_module._scan_file_and_serialize('whatever.txt')

    blob = pickle.dumps(serialized)
    assert TEST_SECRET.encode() not in blob
    assert serialized[0].secret_value is None
    # The hash (the thing the baseline needs) survives.
    assert serialized[0].secret_hash == PotentialSecret.hash_secret(TEST_SECRET)


# ----------------------------------------------------------------------------- #
# Failure path: a plugin crash is reported with locating info, but no plaintext.
# ----------------------------------------------------------------------------- #
@pytest.mark.parametrize('mode', SCAN_MODES)
def test_plugin_failure_is_sanitized(mode, tmp_path):
    bad_a = _write(tmp_path, 'bad_a.txt', 'detonator boom = {0}\n'.format(TEST_SECRET))
    bad_b = _write(tmp_path, 'bad_b.txt', 'detonator crash = {0}\n'.format(TEST_SECRET))

    with transient_settings(_config(WORKER_PLUGIN, EXPLODING_PLUGIN_PATH)):
        with pytest.raises(PluginExecutionError) as exc_info:
            _scan(mode, tmp_path, bad_a, bad_b)

    error = exc_info.value
    # Enough information to locate the failure...
    assert error.plugin_name == WORKER_PLUGIN
    # Either worker may finish first under the pool, so the reported file is one of the two.
    assert error.filename in {bad_a, bad_b}
    assert error.line_number == 1
    assert error.cause_type == 'RuntimeError'
    # ...but nothing that carries the secret.
    assert TEST_SECRET not in str(error)
    assert TEST_SECRET not in repr(error)
    assert TEST_SECRET.encode() not in pickle.dumps(error)


def test_sanitized_exception_pickle_round_trip():
    original = PluginExecutionError(
        plugin_name=WORKER_PLUGIN,
        filename='bad.txt',
        line_number=7,
        cause=RuntimeError('explode {0}'.format(TEST_SECRET)),
    )
    restored = pickle.loads(pickle.dumps(original))

    assert restored.plugin_name == WORKER_PLUGIN
    assert restored.filename == 'bad.txt'
    assert restored.line_number == 7
    assert restored.cause_type == 'RuntimeError'
    assert TEST_SECRET.encode() not in pickle.dumps(restored)
    assert str(restored) == str(original)


# ----------------------------------------------------------------------------- #
# End-to-end: a real spawned worker, capturing stdout/stderr across the boundary.
# ----------------------------------------------------------------------------- #
_SUBPROCESS_RUNNER = r'''
import json
import sys

from detect_secrets.settings import transient_settings
from detect_secrets.core.secrets_collection import SecretsCollection


def main():
    plugin_path, mode, *files = sys.argv[1:]
    config = {
        "plugins_used": [{"name": "ExplodingDetector", "path": "file://" + plugin_path}],
        "filters_used": [],
    }
    with transient_settings(config):
        collection = SecretsCollection()
        if mode == "serial":
            for filename in files:
                collection.scan_file(filename)
        else:
            collection.scan_files(*files, num_processors=2)
    print("RESULT=" + json.dumps(collection.json()))


if __name__ == "__main__":
    main()
'''


def _run_subprocess_scan(mode: str, tmp_path: Path) -> subprocess.CompletedProcess:
    runner = tmp_path / 'runner.py'
    runner.write_text(_SUBPROCESS_RUNNER)
    bad_a = _write(tmp_path, 'sub_bad_a.txt', 'detonator boom = {0}\n'.format(TEST_SECRET))
    bad_b = _write(tmp_path, 'sub_bad_b.txt', 'detonator crash = {0}\n'.format(TEST_SECRET))
    completed = subprocess.run(
        [sys.executable, str(runner), EXPLODING_PLUGIN_PATH, mode, bad_a, bad_b],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed


@pytest.mark.parametrize('mode', SCAN_MODES)
def test_subprocess_failure_never_prints_the_secret(mode, tmp_path):
    completed = _run_subprocess_scan(mode, tmp_path)

    assert completed.returncode != 0
    combined_output = completed.stdout + completed.stderr

    # Locating information is available...
    assert WORKER_PLUGIN in combined_output
    assert 'sub_bad' in combined_output
    assert 'RuntimeError' in combined_output
    # ...but the parent process never prints the worker's secret-bearing line.
    assert TEST_SECRET not in combined_output
