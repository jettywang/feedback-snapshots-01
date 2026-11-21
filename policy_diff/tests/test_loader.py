import json

import pytest

from policy_diff import loader


def test_load_defaults_supports_bare_strings_and_mappings(tmp_path):
    data = {
        'simple': 'role:admin',
        'renamed': {
            'check_str': 'role:member',
            'scope_types': ['project'],
            'deprecated_rule': {
                'name': 'old:renamed',
                'check_str': 'role:admin',
                'deprecated_reason': 'rename',
                'deprecated_since': '2026.2',
            },
        },
        'same_name_change': {
            'check_str': 'role:member',
            'deprecated_rule': 'role:admin',
        },
    }
    path = tmp_path / 'defaults.yaml'
    path.write_text(__import__('yaml').safe_dump(data), encoding='utf-8')

    rules = {rule.name: rule for rule in loader.load_defaults(str(path))}

    assert rules['simple'].check_str == 'role:admin'
    assert rules['simple'].source_line is not None
    assert rules['renamed'].scope_types == ('project',)
    assert rules['renamed'].deprecated_name == 'old:renamed'
    assert rules['renamed'].deprecated_check_str == 'role:admin'
    assert rules['same_name_change'].deprecated_name == 'same_name_change'
    assert rules['same_name_change'].deprecated_check_str == 'role:admin'


def test_load_defaults_rejects_mapping_without_check_str(tmp_path):
    path = tmp_path / 'defaults.yaml'
    path.write_text('broken:\n  scope_types: [project]\n', encoding='utf-8')
    with pytest.raises(ValueError, match='missing check_str'):
        loader.load_defaults(str(path))


def test_find_yaml_key_line_skips_comments(tmp_path):
    path = tmp_path / 'policy.yaml'
    path.write_text(
        '# widget:list: role:someone\n'
        'widget:list: role:admin\n',
        encoding='utf-8',
    )
    assert loader.find_yaml_key_line(str(path), 'widget:list') == 2
    assert loader.find_yaml_key_line(str(path), 'missing') is None


def _token(roles, **extra):
    token = {
        'methods': ['password'],
        'roles': [{'name': role} for role in roles],
        'user': {'id': 'user-1'},
        'project': {
            'id': 'project-1',
            'domain': {'id': 'domain-1'},
        },
    }
    token.update(extra)
    return {'token': token}


def test_load_credentials_normalizes_keystone_token(tmp_path):
    path = tmp_path / 'member.json'
    path.write_text(json.dumps(_token(['member', 'reader'])), encoding='utf-8')

    sample = loader.load_credentials(str(path))[0]
    assert sample.label == 'member'
    assert sample.roles == ('member', 'reader')
    assert sample.scope == 'project'
    assert sample.creds['project_id'] == 'project-1'
    assert sample.creds['project_domain_id'] == 'domain-1'
    assert sample.creds['roles'] == ['member', 'reader']


def test_load_credentials_detects_system_and_domain_scope(tmp_path):
    system = tmp_path / 'sys.json'
    system.write_text(
        json.dumps(_token(['admin'], project=None, system={'all': True})),
        encoding='utf-8',
    )
    domain = tmp_path / 'dom.json'
    domain.write_text(
        json.dumps(
            _token(['manager'], project=None, domain={'id': 'domain-1'})
        ),
        encoding='utf-8',
    )
    samples = {s.label: s for s in loader.load_credentials(str(tmp_path))}
    assert samples['sys'].scope == 'system'
    assert samples['sys'].creds['system'] == 'all'
    assert samples['dom'].scope == 'domain'
    assert samples['dom'].creds['domain_id'] == 'domain-1'


def test_load_credentials_accepts_preflattened_policy_creds(tmp_path):
    path = tmp_path / 'flat.json'
    path.write_text(
        json.dumps({'roles': ['admin'], 'project_id': 'p1', 'user_id': 'u1'}),
        encoding='utf-8',
    )
    sample = loader.load_credentials(str(path))[0]
    assert sample.roles == ('admin',)
    assert sample.creds['project_id'] == 'p1'


def test_load_target_uses_fallback_when_no_path():
    target = loader.load_target(None, {'user_id': 'u1'})
    assert target == {'user_id': 'u1'}
