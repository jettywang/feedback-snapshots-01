"""Fake service that registers oslo.policy rules in two release profiles.

OLD_RELEASE: ships three policies, two of which carry deprecated aliases
(DeprecatedRule) and one that is deprecated for removal.
NEW_RELEASE: aliases and the removed policy are gone; only canonical names
remain registered.

Everything here uses fake credentials and role-only checks, so no Keystone,
network or real secrets are involved.
"""
from __future__ import annotations

import os

from oslo_config import cfg
from oslo_policy import policy

OPERATIONS = [{'path': '/v1/fake', 'method': 'POST'}]

OLD_RELEASE = [
    policy.DocumentedRuleDefault(
        name='widget:create',
        check_str='role:member',
        description='Create a widget (canonical name).',
        operations=OPERATIONS,
        deprecated_rule=policy.DeprecatedRule(
            name='widget:post',
            check_str='role:viewer',
            deprecated_reason='widget:post renamed to widget:create and '
                              'default tightened from viewer to member',
            deprecated_since='2025.1',
        ),
    ),
    policy.DocumentedRuleDefault(
        name='gizmo:update',
        check_str='role:admin',
        description='Update a gizmo (canonical name).',
        operations=OPERATIONS,
        deprecated_rule=policy.DeprecatedRule(
            name='gizmo:edit',
            check_str='role:admin',
            deprecated_reason='gizmo:edit renamed to gizmo:update',
            deprecated_since='2025.1',
        ),
    ),
    policy.DocumentedRuleDefault(
        name='thing:admin',
        check_str='role:admin',
        description='Legacy umbrella policy scheduled for removal.',
        operations=OPERATIONS,
        deprecated_for_removal=True,
        deprecated_reason='thing:admin is no longer enforced by the service',
        deprecated_since='2025.1',
    ),
]

NEW_RELEASE = [
    policy.DocumentedRuleDefault(
        name='widget:create',
        check_str='role:member',
        description='Create a widget.',
        operations=OPERATIONS,
    ),
    policy.DocumentedRuleDefault(
        name='gizmo:update',
        check_str='role:admin',
        description='Update a gizmo.',
        operations=OPERATIONS,
    ),
]

RELEASES = {'old': OLD_RELEASE, 'new': NEW_RELEASE}

# Fake credentials. Plain dicts are a valid creds type for Enforcer.enforce().
TARGET = {'project_id': 'proj-fake-1'}
USERS = {
    'legacy-user': {'user_id': 'u-legacy', 'project_id': 'proj-fake-1',
                    'roles': ['viewer', 'legacy-ops']},
    'ops-user': {'user_id': 'u-ops', 'project_id': 'proj-fake-1',
                 'roles': ['ops-gizmo']},
    'member-user': {'user_id': 'u-member', 'project_id': 'proj-fake-1',
                    'roles': ['member']},
    'admin-user': {'user_id': 'u-admin', 'project_id': 'proj-fake-1',
                   'roles': ['admin']},
    'nobody-user': {'user_id': 'u-nobody', 'project_id': 'proj-fake-1',
                    'roles': ['reader']},
}


def build_enforcer(release: str, policy_file: str,
                   enforce_new_defaults: bool = True) -> policy.Enforcer:
    conf = cfg.ConfigOpts()
    conf(args=[])
    enforcer = policy.Enforcer(conf, policy_file=os.path.abspath(policy_file))
    conf.set_override('enforce_new_defaults', enforce_new_defaults,
                      group='oslo_policy')
    enforcer.register_defaults(RELEASES[release])
    return enforcer
