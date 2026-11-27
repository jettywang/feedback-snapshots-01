"""Demonstrate a safe publisher handoff for a textfile collector directory.

Two services publish the same ``*.prom`` path. The original publisher stages
a newer metrics file but is revoked before it can commit; the replacement
publisher commits first. The original then finishes its in-flight attempt and
is fenced off. Afterwards a staging failure is injected. The script prints
both receipts and compares them with the final metrics file to prove the
valid publisher's payload is what remains.

Run from the repository root::

    .venv/bin/python tools/safe_textfile_handoff_demo.py
"""

import os
import tempfile
from unittest import mock

from prometheus_client import (
    CollectorRegistry, CommitStatus, Gauge, GenerationAuthority,
    safe_write_to_textfile,
)


def registry_with(value):
    registry = CollectorRegistry()
    Gauge(
        'service_requests_total', 'demo request counter', registry=registry,
    ).set(value)
    return registry


def main():
    directory = tempfile.mkdtemp(
        prefix='textfile-handoff-', dir=os.environ.get('TMPDIR'),
    )
    path = os.path.join(directory, 'shared.prom')
    authority = GenerationAuthority()
    old_generation = authority.grant('service-original')
    new_generation = authority.grant('service-replacement')

    print(f'target file : {path}')
    print(f'generations : original={old_generation} '
          f'replacement={new_generation}')
    print()

    # The original publisher's first good publication seeds the directory.
    seed = safe_write_to_textfile(
        path, registry_with(100), 'service-original', authority.as_check(),
    )
    print(f'seed receipt   : {seed.status} gen={seed.generation}')

    # Both services render their payloads while the original is still
    # authorized. Rendering happens before the credential rotation, so the
    # in-flight original attempt keeps the generation it was granted.
    original_payload = (
        b'# HELP service_requests_total demo request counter\n'
        b'# TYPE service_requests_total gauge\n'
        b'service_requests_total 101.0\n'
    )
    replacement_registry = registry_with(200)

    # Rotation: the original publisher is revoked, the replacement commits.
    authority.revoke('service-original')
    replacement_receipt = safe_write_to_textfile(
        path,
        replacement_registry,
        'service-replacement',
        authority.as_check(),
    )
    print(f'replacement    : {replacement_receipt.status} '
          f'gen={replacement_receipt.generation} '
          f'committed_generation='
          f'{replacement_receipt.committed_generation}')

    # The original publisher finishes *after* the replacement. Its first
    # eligibility check would now return None, so to model an attempt that
    # entered the critical section before revocation we present a callback
    # that returns the granted generation once, then reflects the revocation.
    def original_eligibility(publisher):
        if not hasattr(original_eligibility, 'checked'):
            original_eligibility.checked = True
            return old_generation
        return None

    original_receipt = safe_write_to_textfile(
        path,
        CollectorRegistry(),
        'service-original',
        original_eligibility,
        payload=original_payload,
    )
    print(f'original (late): {original_receipt.status} '
          f'gen={original_receipt.generation} '
          f'committed_generation='
          f'{original_receipt.committed_generation}')
    assert replacement_receipt.status == CommitStatus.COMMITTED
    assert replacement_receipt.generation == new_generation
    assert original_receipt.status == CommitStatus.REVOKED
    assert original_receipt.generation == old_generation
    assert original_receipt.committed_generation == new_generation

    # The replacement is rotated to a fresh generation and loses its staging
    # directory. The failure must be reported, not raised, and must leave the
    # last good publication untouched.
    failed_generation = authority.grant('service-replacement')
    real_open = open

    def broken_stage(file, *args, **kwargs):
        if (
            isinstance(file, str)
            and os.path.basename(file).startswith('shared.prom.')
            and not file.endswith(('.generation', '.lock'))
        ):
            raise OSError('staging directory unavailable')
        return real_open(file, *args, **kwargs)

    with mock.patch('builtins.open', broken_stage):
        failed_receipt = safe_write_to_textfile(
            path,
            registry_with(201),
            'service-replacement',
            authority.as_check(),
        )
    print(f'staging failure: {failed_receipt.status} '
          f'gen={failed_receipt.generation} error={failed_receipt.error!r}')
    assert failed_receipt.status == CommitStatus.FAILED
    assert isinstance(failed_receipt.error, OSError)
    assert failed_receipt.generation == failed_generation
    assert failed_receipt.committed_generation == new_generation

    with open(path, encoding='utf-8') as handle:
        final_body = handle.read()
    with open(f'{path}.generation', encoding='utf-8') as handle:
        sidecar = handle.read().strip()

    print()
    print('final metrics file:')
    print(final_body)
    print(f'sidecar: {sidecar}')

    assert 'service_requests_total 200.0' in final_body
    assert 'service_requests_total 101.0' not in final_body
    assert 'service_requests_total 201.0' not in final_body
    assert f'"generation": {new_generation}' in sidecar
    assert '"publisher": "service-replacement"' in sidecar
    assert not any(
        name.startswith('shared.prom.')
        and not name.endswith(('.generation', '.lock'))
        for name in os.listdir(directory)
    )
    print('OK: final file matches the replacement receipt; the revoked '
          'original and the failed staging attempt changed nothing.')


if __name__ == '__main__':
    main()
