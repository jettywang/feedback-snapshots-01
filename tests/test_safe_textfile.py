"""Tests for fenced, atomic textfile collector writes."""

import builtins
import os
from unittest import mock

from prometheus_client import (
    CollectorRegistry, CommitReceipt, CommitStatus, Gauge, GenerationAuthority,
    safe_textfile, safe_write_to_textfile,
)
from prometheus_client.openmetrics import exposition as openmetrics


def make_registry(value, name='service_value'):
    registry = CollectorRegistry()
    Gauge(name, 'demo gauge', registry=registry).set(value)
    return registry


def make_path(tmp_path, filename='service.prom'):
    return str(tmp_path / filename)


def read_metrics(path):
    with open(path, encoding='utf-8') as handle:
        return handle.read()


def test_first_commit_installs_metrics_and_sidecar(tmp_path):
    path = make_path(tmp_path)
    authority = GenerationAuthority()
    authority.grant('publisher-a')

    receipt = safe_write_to_textfile(
        path, make_registry(1), 'publisher-a', authority.as_check(),
    )

    assert isinstance(receipt, CommitReceipt)
    assert receipt.committed is True
    assert receipt.status == CommitStatus.COMMITTED
    assert receipt.generation == 1
    assert receipt.committed_generation == 1
    assert receipt.error is None
    assert 'service_value 1.0' in read_metrics(path)
    with open(f'{path}.generation', encoding='utf-8') as handle:
        assert '"generation": 1' in handle.read()


def test_revoked_before_start_returns_revoked_without_touching_file(tmp_path):
    path = make_path(tmp_path)
    authority = GenerationAuthority()
    authority.grant('publisher-a')
    safe_write_to_textfile(
        path, make_registry(1), 'publisher-a', authority.as_check(),
    )
    authority.revoke('publisher-a')

    receipt = safe_write_to_textfile(
        path, make_registry(2), 'publisher-a', authority.as_check(),
    )

    assert receipt.status == CommitStatus.REVOKED
    assert receipt.committed is False
    assert receipt.generation is None
    assert receipt.committed_generation == 1
    assert receipt.error is None
    assert 'service_value 1.0' in read_metrics(path)


def test_unknown_publisher_is_revoked(tmp_path):
    path = make_path(tmp_path)
    authority = GenerationAuthority()

    receipt = safe_write_to_textfile(
        path, make_registry(1), 'stranger', authority.as_check(),
    )

    assert receipt.status == CommitStatus.REVOKED
    assert receipt.committed_generation is None
    assert not os.path.exists(path)


def test_stale_generation_is_fenced_even_if_still_authorized(tmp_path):
    path = make_path(tmp_path)
    authority = GenerationAuthority()
    old_generation = authority.grant('publisher-a')
    new_generation = authority.grant('publisher-b')
    safe_write_to_textfile(
        path, make_registry(2), 'publisher-b', authority.as_check(),
    )

    generations = {
        'publisher-a': old_generation,
        'publisher-b': new_generation,
    }
    receipt = safe_write_to_textfile(
        path,
        make_registry(9),
        'publisher-a',
        lambda publisher: generations[publisher],
    )

    assert receipt.status == CommitStatus.REVOKED
    assert receipt.generation == old_generation
    assert receipt.committed_generation == new_generation
    assert 'service_value 2.0' in read_metrics(path)
    assert 'service_value 9.0' not in read_metrics(path)


def test_staging_failure_returns_failed_and_preserves_published_file(tmp_path):
    path = make_path(tmp_path)
    authority = GenerationAuthority()
    authority.grant('publisher-a')
    safe_write_to_textfile(
        path, make_registry(1), 'publisher-a', authority.as_check(),
    )
    authority.grant('publisher-b')

    real_open = builtins.open

    def failing_open(file, *args, **kwargs):
        if (
            isinstance(file, str)
            and os.path.basename(file).startswith('service.prom.')
            and not file.endswith(('.generation', '.lock'))
        ):
            raise OSError('disk full')
        return real_open(file, *args, **kwargs)

    with mock.patch('builtins.open', failing_open):
        receipt = safe_write_to_textfile(
            path, make_registry(2), 'publisher-b', authority.as_check(),
        )

    assert receipt.status == CommitStatus.FAILED
    assert receipt.committed is False
    assert isinstance(receipt.error, OSError)
    assert str(receipt.error) == 'disk full'
    assert receipt.committed_generation == 1
    assert 'service_value 1.0' in read_metrics(path)
    leftovers = [
        name for name in os.listdir(tmp_path)
        if '.tmp.' in name
    ]
    assert leftovers == []


def test_rename_failure_returns_failed_and_keeps_last_good_file(tmp_path):
    path = make_path(tmp_path)
    authority = GenerationAuthority()
    authority.grant('publisher-a')
    safe_write_to_textfile(
        path, make_registry(1), 'publisher-a', authority.as_check(),
    )
    new_generation = authority.grant('publisher-b')

    real_rename = os.rename

    def failing_rename(source, destination):
        if destination == path:
            raise OSError('vanished directory')
        return real_rename(source, destination)

    with mock.patch('prometheus_client.safe_textfile.os.rename', failing_rename):
        receipt = safe_write_to_textfile(
            path, make_registry(2), 'publisher-b', authority.as_check(),
        )

    assert receipt.status == CommitStatus.FAILED
    assert isinstance(receipt.error, OSError)
    assert receipt.committed_generation == 1
    assert receipt.generation == new_generation
    assert 'service_value 1.0' in read_metrics(path)
    assert not any('.tmp.' in name for name in os.listdir(tmp_path))


def test_revocation_during_staging_is_enforced_under_lock(tmp_path):
    path = make_path(tmp_path)
    authority = GenerationAuthority()
    authority.grant('publisher-a')
    safe_write_to_textfile(
        path, make_registry(1), 'publisher-a', authority.as_check(),
    )
    stale_generation = authority.grant('publisher-a')

    # The first call authorizes staging; the in-lock recheck happens after the
    # authority has revoked the publisher while the payload was generated.
    calls = {'count': 0}

    def flapping_eligibility(publisher):
        calls['count'] += 1
        if calls['count'] == 1:
            return authority.generation_for(publisher)
        authority.revoke(publisher)
        return authority.generation_for(publisher)

    receipt = safe_write_to_textfile(
        path, make_registry(2), 'publisher-a', flapping_eligibility,
    )

    assert receipt.status == CommitStatus.REVOKED
    assert receipt.generation == stale_generation
    assert receipt.committed_generation == 1
    assert 'service_value 1.0' in read_metrics(path)
    assert not any('.tmp.' in name for name in os.listdir(tmp_path))


def test_ordered_handoff_old_publisher_finishes_after_new_one(tmp_path):
    # Deterministic stand-in for two racing services: the replacement commits
    # first, then the original publisher's in-flight attempt reaches its
    # in-lock recheck and is fenced off by the newer generation sidecar.
    path = make_path(tmp_path)
    authority = GenerationAuthority()
    old_generation = authority.grant('publisher-old')
    new_generation = authority.grant('publisher-new')
    safe_write_to_textfile(
        path, make_registry(10), 'publisher-old', authority.as_check(),
    )

    # The replacement rotates in and publishes its newer metrics file.
    new_receipt = safe_write_to_textfile(
        path, make_registry(22), 'publisher-new', authority.as_check(),
    )
    assert new_receipt.status == CommitStatus.COMMITTED
    assert new_receipt.generation == new_generation

    # The original publisher's attempt had already passed its first
    # eligibility check before the rotation, so it still holds its granted
    # generation. By the time it reaches the commit lock, that generation is
    # stale: the sidecar records a strictly larger committed generation.
    stale_check = mock.Mock(side_effect=[old_generation, old_generation])
    old_receipt = safe_write_to_textfile(
        path,
        make_registry(11),
        'publisher-old',
        stale_check,
    )

    assert stale_check.call_count == 2
    assert old_receipt.status == CommitStatus.REVOKED
    assert old_receipt.generation == old_generation
    assert old_receipt.committed_generation == new_generation
    assert 'service_value 22.0' in read_metrics(path)
    assert 'service_value 11.0' not in read_metrics(path)
    assert not any(
        name.startswith('service.prom.')
        and not name.endswith(('.generation', '.lock'))
        for name in os.listdir(tmp_path)
    )


def test_concurrent_handoff_is_serialized_by_the_file_lock(tmp_path):
    # The lock guarantees that even genuinely concurrent threads commit in a
    # total order and the revoked publisher never overwrites the winner.
    path = make_path(tmp_path)
    authority = GenerationAuthority()
    old_generation = authority.grant('publisher-old')
    new_generation = authority.grant('publisher-new')
    safe_write_to_textfile(
        path, make_registry(10), 'publisher-old', authority.as_check(),
    )
    authority.revoke('publisher-old')

    import threading
    receipts = []

    def publish(publisher, registry, check):
        receipts.append(
            safe_write_to_textfile(path, registry, publisher, check),
        )

    old_check = mock.Mock(side_effect=[old_generation, None])
    threads = [
        threading.Thread(
            target=publish,
            args=('publisher-old', make_registry(11), old_check),
        ),
        threading.Thread(
            target=publish,
            args=(
                'publisher-new', make_registry(22), authority.as_check(),
            ),
        ),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    by_publisher = {receipt.publisher: receipt for receipt in receipts}
    assert by_publisher['publisher-new'].status == CommitStatus.COMMITTED
    assert by_publisher['publisher-new'].generation == new_generation
    assert by_publisher['publisher-old'].status == CommitStatus.REVOKED
    assert by_publisher['publisher-old'].generation == old_generation
    assert 'service_value 22.0' in read_metrics(path)
    assert 'service_value 11.0' not in read_metrics(path)


def test_escaping_option_is_passed_to_serialization(tmp_path):
    path = make_path(tmp_path)
    authority = GenerationAuthority()
    authority.grant('publisher-a')
    registry = CollectorRegistry()
    Gauge(
        'dotted.metric.name', 'demo', labelnames=['label.name'],
        registry=registry,
    ).labels('label.value').set(1)

    receipt = safe_write_to_textfile(
        path,
        registry,
        'publisher-a',
        authority.as_check(),
        escaping=openmetrics.UNDERSCORES,
    )

    assert receipt.committed is True
    body = read_metrics(path)
    assert 'dotted_metric_name' in body
    assert 'label_name' in body


def test_tmpdir_is_used_for_staging(tmp_path):
    path = make_path(tmp_path)
    staging = tmp_path / 'staging'
    staging.mkdir()
    authority = GenerationAuthority()
    authority.grant('publisher-a')

    receipt = safe_write_to_textfile(
        path,
        make_registry(1),
        'publisher-a',
        authority.as_check(),
        tmpdir=str(staging),
    )

    assert receipt.committed is True
    assert 'service_value 1.0' in read_metrics(path)
    assert list(staging.iterdir()) == []


def test_pre_rendered_payload_skips_registry_serialization(tmp_path):
    path = make_path(tmp_path)
    authority = GenerationAuthority()
    authority.grant('publisher-a')
    payload = b'# TYPE custom_metric gauge\ncustom_metric 7.0\n'

    receipt = safe_write_to_textfile(
        path,
        CollectorRegistry(),
        'publisher-a',
        authority.as_check(),
        payload=payload,
    )

    assert receipt.committed is True
    assert read_metrics(path) == payload.decode('utf-8')


def test_authority_grants_strictly_increasing_generations():
    authority = GenerationAuthority()
    first = authority.grant('a')
    second = authority.grant('b')
    third = authority.grant('a')

    assert first < second < third
    authority.revoke('a')
    assert authority.generation_for('a') is None
    assert authority.generation_for('b') == second
    assert authority.as_check()('b') == second


def test_receipt_repr_and_equality_include_status(tmp_path):
    path = make_path(tmp_path)
    authority = GenerationAuthority()
    authority.grant('publisher-a')
    receipt = safe_write_to_textfile(
        path, make_registry(1), 'publisher-a', authority.as_check(),
    )

    assert 'committed' in repr(receipt)
    assert receipt == CommitReceipt(
        path, 'publisher-a', 1, CommitStatus.COMMITTED, 1,
    )
    assert receipt != CommitReceipt(
        path, 'publisher-a', 1, CommitStatus.FAILED, 1,
    )


def test_corrupt_sidecar_surfaces_as_failed_attempt(tmp_path):
    path = make_path(tmp_path)
    authority = GenerationAuthority()
    authority.grant('publisher-a')
    safe_write_to_textfile(
        path, make_registry(1), 'publisher-a', authority.as_check(),
    )
    with open(f'{path}.generation', 'w', encoding='utf-8') as handle:
        handle.write('{not json')

    receipt = safe_write_to_textfile(
        path, make_registry(2), 'publisher-a', authority.as_check(),
    )

    assert receipt.status == CommitStatus.FAILED
    assert isinstance(receipt.error, ValueError)


def test_lock_file_is_created_beside_metrics_path(tmp_path):
    path = make_path(tmp_path)
    with safe_textfile._file_lock(path):
        assert os.path.exists(f'{path}.lock')
    assert os.path.exists(f'{path}.lock')


def test_legacy_write_to_textfile_is_unchanged(tmp_path):
    from prometheus_client import write_to_textfile

    path = make_path(tmp_path, filename='legacy.prom')
    write_to_textfile(path, make_registry(5))

    assert 'service_value 5.0' in read_metrics(path)
    assert not os.path.exists(f'{path}.generation')
    assert not os.path.exists(f'{path}.lock')
    leftovers = [
        name for name in os.listdir(tmp_path)
        if name.startswith('legacy.prom.')
    ]
    assert leftovers == []


def test_public_api_is_exported_from_package_root():
    import prometheus_client

    for name in (
        'safe_write_to_textfile',
        'GenerationAuthority',
        'CommitReceipt',
        'CommitStatus',
    ):
        assert hasattr(prometheus_client, name)
        assert name in prometheus_client.__all__
