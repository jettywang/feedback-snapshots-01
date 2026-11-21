import pytest

from policy_diff import engine, loader
from policy_diff.loader import (
    PROVENANCE_DEFAULT,
    PROVENANCE_DEPRECATED_NAME,
    PROVENANCE_DEPRECATED_OR,
    PROVENANCE_FAIL_CLOSED,
    PROVENANCE_FILE_OVERRIDE,
)


@pytest.fixture
def defaults_files(tmp_path):
    before = tmp_path / 'before.yaml'
    after = tmp_path / 'after.yaml'
    before.write_text(
        'widget:create:\n'
        "  check_str: 'role:admin'\n"
        'widget:list:\n'
        "  check_str: 'role:admin_or_owner'\n"
        'widget:share:\n'
        "  check_str: 'role:admin'\n"
        'widget:delete:\n'
        "  check_str: 'role:admin'\n"
        'old_widget:rename:\n'
        "  check_str: 'role:admin'\n",
        encoding='utf-8',
    )
    after.write_text(
        'widget:create:\n'
        "  check_str: 'role:member'\n"
        '  deprecated_rule:\n'
        "    check_str: 'role:admin'\n"
        "    deprecated_reason: 'member default'\n"
        "    deprecated_since: '2026.2'\n"
        'widget:list:\n'
        "  check_str: 'role:reader'\n"
        '  deprecated_rule:\n'
        "    check_str: 'role:admin_or_owner'\n"
        "    deprecated_reason: 'reader default'\n"
        "    deprecated_since: '2026.2'\n"
        'widget:share:\n'
        "  check_str: 'role:member'\n"
        '  deprecated_rule:\n'
        "    name: 'old_widget:share'\n"
        "    check_str: 'role:admin'\n"
        "    deprecated_reason: 'rename'\n"
        "    deprecated_since: '2026.2'\n"
        'widget:delete:\n'
        "  check_str: 'role:admin'\n"
        '  scope_types: [project]\n'
        'widget:rename:\n'
        "  check_str: 'role:admin'\n"
        '  deprecated_rule:\n'
        "    name: 'old_widget:rename'\n"
        "    check_str: 'role:admin'\n"
        "    deprecated_reason: 'rename'\n"
        "    deprecated_since: '2026.2'\n",
        encoding='utf-8',
    )
    return before, after


@pytest.fixture
def policy_file(tmp_path):
    path = tmp_path / 'policy.yaml'
    path.write_text(
        "widget:list: 'role:admin'\n"
        "old_widget:share: 'role:admin_or_owner'\n",
        encoding='utf-8',
    )
    return path


@pytest.fixture
def samples():
    admin = loader.CredentialSample(
        'admin', 'admin.json', ('admin',),
        {'roles': ['admin'], 'user_id': 'u1', 'project_id': 'p1'},
        'project',
    )
    member = loader.CredentialSample(
        'member', 'member.json', ('member',),
        {'roles': ['member'], 'user_id': 'u2', 'project_id': 'p1'},
        'project',
    )
    reader = loader.CredentialSample(
        'reader', 'reader.json', ('reader',),
        {'roles': ['reader'], 'user_id': 'u3', 'project_id': 'p1'},
        'project',
    )
    system_admin = loader.CredentialSample(
        'system-admin', 'sys.json', ('admin',),
        {'roles': ['admin'], 'user_id': 'u4', 'system': 'all',
         'system_scope': 'all'},
        'system',
    )
    return [admin, member, reader, system_admin]


def _snapshot(label, defaults_file, policy_file, enforce_new_defaults):
    rules = loader.load_defaults(str(defaults_file))
    ctx = engine.SnapshotContext(
        label=label,
        defaults_file=str(defaults_file),
        policy_file=None if policy_file is None else str(policy_file),
        enforce_new_defaults=enforce_new_defaults,
    )
    return engine.build_snapshot(ctx, rules)


def test_site_override_is_retained_after_upgrade(defaults_files, policy_file):
    _, after_file = defaults_files
    snapshot = _snapshot('after', after_file, policy_file, True)

    assert str(snapshot.enforcer.rules['widget:list']) == 'role:admin'
    root = snapshot.explain('widget:list')[0]
    assert root.provenance == PROVENANCE_FILE_OVERRIDE
    assert root.source_line is not None


def test_new_default_is_accepted_when_policy_file_silent(
    defaults_files, policy_file
):
    _, after_file = defaults_files
    snapshot = _snapshot('after', after_file, policy_file, True)

    assert str(snapshot.enforcer.rules['widget:create']) == 'role:member'
    root = snapshot.explain('widget:create')[0]
    assert root.provenance == PROVENANCE_DEFAULT


def test_deprecated_name_override_keeps_legacy_rule(
    defaults_files, policy_file
):
    _, after_file = defaults_files
    snapshot = _snapshot('after', after_file, policy_file, True)

    assert str(snapshot.enforcer.rules['widget:share']) == (
        'role:admin_or_owner'
    )
    root = snapshot.explain('widget:share')[0]
    assert root.provenance == PROVENANCE_DEPRECATED_NAME
    assert root.source_line is not None


def test_enforce_new_defaults_false_uses_or_compat(defaults_files):
    _, after_file = defaults_files
    snapshot = _snapshot('compat', after_file, None, False)

    assert str(snapshot.enforcer.rules['widget:create']) == (
        '(role:member or role:admin)'
    )
    root = snapshot.explain('widget:create')[0]
    assert root.provenance == PROVENANCE_DEPRECATED_OR


def test_scope_types_deny_system_token_on_project_scoped_action(
    defaults_files, policy_file, samples
):
    _, after_file = defaults_files
    snapshot = _snapshot('after', after_file, policy_file, True)
    engine.populate_evaluations(
        snapshot, samples, {'project_id': 'p1', 'user_id': 'u1'}
    )

    system_result = snapshot.evaluations['widget:delete']['system-admin']
    assert system_result.allowed is False
    assert system_result.scope_ok is False
    admin_result = snapshot.evaluations['widget:delete']['admin']
    assert admin_result.allowed is True
    assert admin_result.scope_ok is True


def test_unregistered_action_fails_closed(defaults_files, samples):
    before_file, _ = defaults_files
    snapshot = _snapshot('before', before_file, None, True)
    result = engine.evaluate(
        snapshot,
        'widget:does_not_exist',
        samples[0],
        {'user_id': 'u1'},
    )
    assert result.allowed is False
    assert result.provenance == PROVENANCE_FAIL_CLOSED


def test_diff_reports_grant_revoke_and_rename(
    defaults_files, policy_file, samples
):
    before_file, after_file = defaults_files
    before = _snapshot('before', before_file, policy_file, False)
    after = _snapshot('after', after_file, policy_file, True)
    actions = sorted(before.actions | after.actions)
    target = {'project_id': 'p1', 'user_id': 'u1'}
    engine.populate_evaluations(before, samples, target, actions)
    engine.populate_evaluations(after, samples, target, actions)

    rows = engine.diff_snapshots(before, after, samples)
    by_after = {row['after_action']: row for row in rows}

    create = by_after['widget:create']
    changes = {c['credential']: c['change'] for c in create['credentials']}
    assert changes['admin'] == 'revoked'
    assert changes['member'] == 'granted'
    assert changes['reader'] == 'unchanged'

    share = by_after['widget:share']
    assert share['rename'] is True
    assert share['before_action'] == 'old_widget:share'

    rename = by_after['widget:rename']
    assert rename['rename'] is True
    assert rename['before_action'] == 'old_widget:rename'


def test_evaluations_match_live_enforcer_for_every_action(
    defaults_files, policy_file, samples
):
    before_file, after_file = defaults_files
    snapshot = _snapshot('after', after_file, policy_file, True)
    target = {'project_id': 'p1', 'user_id': 'u1'}
    engine.populate_evaluations(snapshot, samples, target)

    for action in sorted(snapshot.actions):
        for sample in samples:
            expected = bool(
                snapshot.enforcer.enforce(
                    action, dict(target), dict(sample.creds)
                )
            )
            assert (
                snapshot.evaluations[action][sample.label].allowed == expected
            )


def test_each_snapshot_uses_an_isolated_enforcer(
    defaults_files, policy_file, samples
):
    before_file, after_file = defaults_files
    before = _snapshot('before', before_file, policy_file, False)
    after = _snapshot('after', after_file, policy_file, True)

    assert before.enforcer is not after.enforcer
    assert before.enforcer.conf is not after.enforcer.conf
    # The global oslo_config ConfigOpts factory state must not have been
    # replaced; building snapshots only creates local instances.
    assert 'widget:create' in after.enforcer.rules
    assert str(before.enforcer.rules['widget:create']) == 'role:admin'
    assert str(after.enforcer.rules['widget:create']) == 'role:member'


def test_policy_file_is_not_modified(
    defaults_files, policy_file, samples
):
    _, after_file = defaults_files
    original = policy_file.read_bytes()
    snapshot = _snapshot('after', after_file, policy_file, True)
    engine.populate_evaluations(
        snapshot, samples, {'project_id': 'p1', 'user_id': 'u1'}
    )
    assert policy_file.read_bytes() == original


def test_missing_policy_file_uses_empty_rules(tmp_path, defaults_files):
    _, after_file = defaults_files
    rules = loader.load_defaults(str(after_file))
    ctx = engine.SnapshotContext(
        label='no-file',
        defaults_file=str(after_file),
        policy_file=None,
        enforce_new_defaults=True,
    )
    snapshot = engine.build_snapshot(ctx, rules)
    assert snapshot.enforcer.file_rules == {}
    assert str(snapshot.enforcer.rules['widget:create']) == 'role:member'


def test_missing_policy_path_raises(tmp_path, defaults_files):
    _, after_file = defaults_files
    rules = loader.load_defaults(str(after_file))
    ctx = engine.SnapshotContext(
        label='bogus',
        defaults_file=str(after_file),
        policy_file=str(tmp_path / 'nope.yaml'),
        enforce_new_defaults=True,
    )
    with pytest.raises(FileNotFoundError):
        engine.build_snapshot(ctx, rules)


def test_plain_or_default_is_not_mislabeled_as_or_compat(tmp_path):
    defaults_file = tmp_path / 'defaults.yaml'
    defaults_file.write_text(
        'admin_or_owner:\n'
        "  check_str: 'role:admin or role:owner'\n"
        'widget:peek:\n'
        "  check_str: 'rule:admin_or_owner'\n",
        encoding='utf-8',
    )
    rules = loader.load_defaults(str(defaults_file))
    ctx = engine.SnapshotContext(
        label='plain-or',
        defaults_file=str(defaults_file),
        policy_file=None,
        enforce_new_defaults=False,
    )
    snapshot = engine.build_snapshot(ctx, rules)

    helper = snapshot.explain('admin_or_owner')[0]
    assert helper.provenance == PROVENANCE_DEFAULT
    peek_trace = snapshot.explain('widget:peek')
    assert [hop.rule_name for hop in peek_trace] == [
        'widget:peek',
        'admin_or_owner',
    ]
    assert all(hop.provenance == PROVENANCE_DEFAULT for hop in peek_trace)


def test_explain_trace_follows_rule_references_through_override(
    defaults_files, policy_file
):
    before_file, after_file = defaults_files
    rules = loader.load_defaults(str(after_file))
    helper_file = after_file.parent / 'with-helper.yaml'
    helper_file.write_text(
        after_file.read_text(encoding='utf-8')
        + "helper:role:\n  check_str: 'role:reader'\n",
        encoding='utf-8',
    )
    override = policy_file.parent / 'override.yaml'
    override.write_text(
        "widget:list: 'rule:helper:role'\n",
        encoding='utf-8',
    )
    helper_rules = loader.load_defaults(str(helper_file))
    ctx = engine.SnapshotContext(
        label='chained',
        defaults_file=str(helper_file),
        policy_file=str(override),
        enforce_new_defaults=True,
    )
    snapshot = engine.build_snapshot(ctx, helper_rules)
    trace = snapshot.explain('widget:list')

    assert trace[0].rule_name == 'widget:list'
    assert trace[0].provenance == PROVENANCE_FILE_OVERRIDE
    assert trace[1].rule_name == 'helper:role'
    assert trace[1].provenance == PROVENANCE_DEFAULT
