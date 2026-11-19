import json
from unittest import mock

import pytest

from detect_secrets.audit.merge import CONFLICT_LABELS
from detect_secrets.audit.merge import CONFLICT_PRESENCE
from detect_secrets.audit.merge import merge_baselines
from detect_secrets.core import baseline
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.main import main
from detect_secrets.plugins.basic_auth import BasicAuthDetector
from detect_secrets.settings import transient_settings
from testing.factories import potential_secret_factory as original_potential_secret_factory
from testing.mocks import mock_named_temporary_file


def potential_secret_factory(secret: str, **kwargs):
    kwargs.setdefault('type', BasicAuthDetector.secret_type)
    kwargs.setdefault('filename', 'file')
    return original_potential_secret_factory(secret=secret, **kwargs)


def get_secrets(*secrets) -> SecretsCollection:
    output = SecretsCollection()
    for secret in secrets:
        output[secret.filename].add(secret)

    return output


def save(secrets: SecretsCollection, filename: str) -> None:
    baseline.save_to_file(secrets, filename)


def test_one_reviewer_did_not_look():
    base = get_secrets(potential_secret_factory('shared'))
    first = get_secrets(potential_secret_factory('shared', is_secret=True))

    with mock_named_temporary_file() as base_file, \
            mock_named_temporary_file() as first_file, \
            mock_named_temporary_file() as second_file:
        save(base, base_file.name)
        save(first, first_file.name)
        save(base, second_file.name)

        report = merge_baselines(base_file.name, first_file.name, second_file.name)

    assert not report.conflicts
    assert report.is_signed_off
    assert [(secret.secret_hash, secret.is_secret) for _, secret in report.secrets] == [
        (potential_secret_factory('shared').secret_hash, True),
    ]


def test_both_reviewers_agree():
    base = get_secrets(potential_secret_factory('shared'))
    first = get_secrets(potential_secret_factory('shared', is_secret=False))
    second = get_secrets(potential_secret_factory('shared', is_secret=False))

    with mock_named_temporary_file() as base_file, \
            mock_named_temporary_file() as first_file, \
            mock_named_temporary_file() as second_file:
        save(base, base_file.name)
        save(first, first_file.name)
        save(second, second_file.name)

        report = merge_baselines(base_file.name, first_file.name, second_file.name)

    assert not report.conflicts
    assert [secret.is_secret for _, secret in report.secrets] == [False]


def test_conflicting_conclusions_are_left_for_a_third_reviewer():
    base = get_secrets(potential_secret_factory('shared'))
    first = get_secrets(potential_secret_factory('shared', is_secret=True))
    second = get_secrets(potential_secret_factory('shared', is_secret=False))

    with mock_named_temporary_file() as base_file, \
            mock_named_temporary_file() as first_file, \
            mock_named_temporary_file() as second_file:
        save(base, base_file.name)
        save(first, first_file.name)
        save(second, second_file.name)

        report = merge_baselines(base_file.name, first_file.name, second_file.name)

    assert not report.is_signed_off
    assert len(report.conflicts) == 1
    assert report.conflicts[0].reason == CONFLICT_LABELS
    assert report.conflicts[0].conclusions == [False, True]
    assert [secret.is_secret for _, secret in report.secrets] == [None]


def test_scan_result_withdrawn_by_both_reviewers():
    base = get_secrets(potential_secret_factory('gone'))
    first = SecretsCollection()
    second = SecretsCollection()

    with mock_named_temporary_file() as base_file, \
            mock_named_temporary_file() as first_file, \
            mock_named_temporary_file() as second_file:
        save(base, base_file.name)
        save(first, first_file.name)
        save(second, second_file.name)

        report = merge_baselines(base_file.name, first_file.name, second_file.name)

    assert not report.secrets
    assert not report.conflicts
    assert len(report.removed) == 1
    assert report.removed[0].secret_hash == potential_secret_factory('gone').secret_hash


def test_scan_result_present_in_only_one_copy_is_a_conflict():
    base = get_secrets(potential_secret_factory('shared'))
    first = get_secrets(potential_secret_factory('shared', is_secret=True))
    second = SecretsCollection()

    with mock_named_temporary_file() as base_file, \
            mock_named_temporary_file() as first_file, \
            mock_named_temporary_file() as second_file:
        save(base, base_file.name)
        save(first, first_file.name)
        save(second, second_file.name)

        report = merge_baselines(base_file.name, first_file.name, second_file.name)

    assert not report.is_signed_off
    assert report.conflicts[0].reason == CONFLICT_PRESENCE
    assert [secret.is_secret for _, secret in report.secrets] == [None]


def test_swapping_copies_produces_the_same_result():
    base = get_secrets(
        potential_secret_factory('agree'),
        potential_secret_factory('conflict'),
        potential_secret_factory('untouched'),
    )
    first = get_secrets(
        potential_secret_factory('agree', is_secret=True),
        potential_secret_factory('conflict', is_secret=True),
        potential_secret_factory('untouched'),
    )
    second = get_secrets(
        potential_secret_factory('agree', is_secret=True),
        potential_secret_factory('conflict', is_secret=False),
        potential_secret_factory('untouched'),
    )

    with mock_named_temporary_file() as base_file, \
            mock_named_temporary_file() as first_file, \
            mock_named_temporary_file() as second_file:
        save(base, base_file.name)
        save(first, first_file.name)
        save(second, second_file.name)

        forward = merge_baselines(base_file.name, first_file.name, second_file.name)
        backwards = merge_baselines(base_file.name, second_file.name, first_file.name)

    assert forward.data == backwards.data
    assert json.dumps(forward.data) == json.dumps(backwards.data)


def test_cli_merge_writes_output_and_reports_conflicts(printer):
    base = get_secrets(potential_secret_factory('shared'))
    first = get_secrets(potential_secret_factory('shared', is_secret=True))
    second = get_secrets(potential_secret_factory('shared', is_secret=False))

    with mock_named_temporary_file() as base_file, \
            mock_named_temporary_file() as first_file, \
            mock_named_temporary_file() as second_file, \
            mock_named_temporary_file() as output_file:
        save(base, base_file.name)
        save(first, first_file.name)
        save(second, second_file.name)

        main([
            'audit', base_file.name, first_file.name, second_file.name,
            '--merge', '--output', output_file.name,
        ])

        output = json.loads(output_file.read().decode())

    assert 'NOT SIGNED OFF' in printer.message
    assert output['audit_merge']['signed_off'] is False
    assert len(output['audit_merge']['conflicts']) == 1


def test_stats_cannot_be_signed_off_while_conflicts_exist(printer):
    base = get_secrets(potential_secret_factory('shared'))
    first = get_secrets(potential_secret_factory('shared', is_secret=True))
    second = get_secrets(potential_secret_factory('shared', is_secret=False))

    with mock_named_temporary_file() as base_file, \
            mock_named_temporary_file() as first_file, \
            mock_named_temporary_file() as second_file:
        save(base, base_file.name)
        save(first, first_file.name)
        save(second, second_file.name)

        report = merge_baselines(base_file.name, first_file.name, second_file.name)
        with mock_named_temporary_file() as merged_file:
            baseline.save_to_file(report.data, merged_file.name)
            main(['audit', merged_file.name, '--stats', '--json'])

    data = json.loads(printer.message)
    assert data['signed_off'] is False
    assert len(data['conflicts']) == 1


def test_stats_is_signed_off_for_a_clean_merge(printer):
    base = get_secrets(potential_secret_factory('shared'))
    first = get_secrets(potential_secret_factory('shared', is_secret=True))
    second = get_secrets(potential_secret_factory('shared', is_secret=True))

    with mock_named_temporary_file() as base_file, \
            mock_named_temporary_file() as first_file, \
            mock_named_temporary_file() as second_file:
        save(base, base_file.name)
        save(first, first_file.name)
        save(second, second_file.name)

        report = merge_baselines(base_file.name, first_file.name, second_file.name)
        with mock_named_temporary_file() as merged_file:
            baseline.save_to_file(report.data, merged_file.name)
            main(['audit', merged_file.name, '--stats', '--json'])

    data = json.loads(printer.message)
    assert data['signed_off'] is True
    assert data['conflicts'] == []
    assert not any(key.startswith('WARNING') for key in data)


@pytest.mark.parametrize(
    'argv',
    (
        ['audit', 'a', 'b', '--merge'],
        ['audit', 'a', 'b', 'c', 'd', '--merge'],
        ['audit', 'a', 'b', 'c', '--diff', '--merge'],
        ['audit', 'a', '--output', 'out'],
        ['audit', 'a', 'b', 'c', '--merge', '--stats'],
        ['audit', 'a', 'b', 'c', '--merge', '--report'],
    ),
)
def test_invalid_merge_invocations(argv):
    from detect_secrets.core.usage import ParserBuilder

    with pytest.raises(SystemExit):
        ParserBuilder().add_console_use_arguments().parse_args(argv)


def test_third_reviewer_resolution_is_signed_off(printer):
    with transient_settings({
        'plugins_used': [
            {'name': BasicAuthDetector.__name__},
        ],
    }):
        base = SecretsCollection()
        base.scan_file('test_data/each_secret.py')

        first = SecretsCollection()
        first.scan_file('test_data/each_secret.py')
        first_secret = list(first)[0][1]
        second = SecretsCollection()
        second.scan_file('test_data/each_secret.py')
        second_secret = list(second)[0][1]

        first_secret.is_secret = True
        second_secret.is_secret = False

        with mock_named_temporary_file() as base_file, \
                mock_named_temporary_file() as first_file, \
                mock_named_temporary_file() as second_file, \
                mock_named_temporary_file() as merged_file:
            save(base, base_file.name)
            save(first, first_file.name)
            save(second, second_file.name)

            report = merge_baselines(base_file.name, first_file.name, second_file.name)
            baseline.save_to_file(report.data, merged_file.name)

            # The third reviewer labels the unresolved secret.
            from detect_secrets.audit import io
            with mock.patch.object(io, 'get_user_decision', return_value=io.InputOptions.NO):
                main(['audit', merged_file.name])

            printer.clear()
            main(['audit', merged_file.name, '--stats', '--json'])

    data = json.loads(printer.message)
    assert data['signed_off'] is True
    assert data['conflicts'] == []
