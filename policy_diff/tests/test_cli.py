import json

from policy_diff import cli


EXAMPLE_ROOT = 'policy_diff_examples'


def _common_args(tmp_path=None):
    return [
        '--before-defaults',
        f'{EXAMPLE_ROOT}/defaults/policy-before.yaml',
        '--after-defaults',
        f'{EXAMPLE_ROOT}/defaults/policy-after.yaml',
        '--before-policy-file',
        f'{EXAMPLE_ROOT}/policy/policy.yaml',
        '--credentials',
        f'{EXAMPLE_ROOT}/credentials',
        '--target',
        f'{EXAMPLE_ROOT}/targets/widget.json',
    ]


def test_text_report_documents_three_scenarios(capsys):
    exit_code = cli.main(_common_args())
    out = capsys.readouterr().out

    assert exit_code == 0
    assert 'PERMISSION GAINED' in out
    assert 'PERMISSION LOST' in out
    assert 'site policy file override' in out
    assert 'deprecated name kept from policy file' in out
    assert 'registered policy-in-code default' in out
    assert 'widget:create' in out


def test_json_report_is_valid_and_carries_provenance(capsys):
    exit_code = cli.main(_common_args() + ['--format', 'json'])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload['before']['enforce_new_defaults'] is False
    assert payload['after']['enforce_new_defaults'] is True
    rows = {row['after_action']: row for row in payload['actions']}
    list_row = rows['widget:list']
    assert all(
        entry['after']['provenance'] == 'file_override'
        for entry in list_row['credentials']
    )
    share_row = rows['widget:share']
    assert all(
        entry['after']['provenance'] == 'deprecated_name_override'
        for entry in share_row['credentials']
    )
    create_row = rows['widget:create']
    assert all(
        entry['after']['provenance'] == 'registered_default'
        for entry in create_row['credentials']
    )


def test_explain_mode_prints_resolution_chain(capsys):
    exit_code = cli.main(
        [
            '--before-defaults',
            f'{EXAMPLE_ROOT}/defaults/policy-before.yaml',
            '--after-defaults',
            f'{EXAMPLE_ROOT}/defaults/policy-after.yaml',
            '--before-policy-file',
            f'{EXAMPLE_ROOT}/policy/policy.yaml',
            '--credentials',
            f'{EXAMPLE_ROOT}/credentials',
            '--rule',
            'widget:share',
        ]
    )
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "rule 'widget:share'" in out
    assert 'deprecated name kept from policy file' in out
    assert 'policy.yaml:14' in out


def test_explain_falls_back_to_before_snapshot_for_removed_name(capsys):
    exit_code = cli.main(
        [
            '--before-defaults',
            f'{EXAMPLE_ROOT}/defaults/policy-before.yaml',
            '--after-defaults',
            f'{EXAMPLE_ROOT}/defaults/policy-after.yaml',
            '--before-policy-file',
            f'{EXAMPLE_ROOT}/policy/policy.yaml',
            '--credentials',
            f'{EXAMPLE_ROOT}/credentials',
            '--rule',
            'old_widget:share',
        ]
    )
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "snapshot 'before-upgrade'" in out
