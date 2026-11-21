"""Read-only loaders for the inputs of a policy upgrade diff.

Nothing in this module touches oslo.config global state, environment
variables or service configuration directories. Files are opened for
reading only and the parsed data is handed back as plain dataclasses.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import yaml

from oslo_policy import policy

# Provenance identifiers used across reports. They intentionally mirror the
# three upgrade situations operators care about.
PROVENANCE_FILE_OVERRIDE = 'file_override'
PROVENANCE_DEFAULT = 'registered_default'
PROVENANCE_DEPRECATED_NAME = 'deprecated_name_override'
PROVENANCE_DEPRECATED_OR = 'deprecated_or_compat'
PROVENANCE_FAIL_CLOSED = 'fail_closed'

_FILE_LINE_NOT_FOUND = None


@dataclass(frozen=True)
class RegisteredRule:
    """A policy-in-code rule registered by a service pre/post upgrade."""

    name: str
    check_str: str
    scope_types: tuple[str, ...] = ()
    deprecated_name: str | None = None
    deprecated_check_str: str | None = None
    deprecated_reason: str | None = None
    deprecated_since: str | None = None
    source_file: str | None = None
    source_line: int | None = None

    def to_rule_default(self) -> policy.RuleDefault:
        kwargs: dict[str, Any] = {
            'name': self.name,
            'check_str': self.check_str,
            'scope_types': list(self.scope_types) or None,
        }
        if self.deprecated_name and self.deprecated_check_str is not None:
            kwargs['deprecated_rule'] = policy.DeprecatedRule(
                name=self.deprecated_name,
                check_str=self.deprecated_check_str,
                deprecated_reason=self.deprecated_reason or 'n/a',
                deprecated_since=self.deprecated_since or 'n/a',
            )
        return policy.RuleDefault(**kwargs)


@dataclass(frozen=True)
class CredentialSample:
    """A normalized set of policy credential values plus display metadata."""

    label: str
    source_file: str
    roles: tuple[str, ...]
    creds: dict[str, Any] = field(hash=False)
    scope: str

    @property
    def role_display(self) -> str:
        return ','.join(self.roles) if self.roles else '(no roles)'


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def load_defaults(path: str) -> list[RegisteredRule]:
    """Parse a policy-in-code defaults YAML file.

    Two shapes are accepted per rule name:

    * a bare check string (``"action": "role:admin"``);
    * a mapping with ``check_str`` and optional ``scope_types`` /
      ``deprecated_rule`` metadata.

    A ``deprecated_rule`` mapping may either be a bare string (same-name
    check-string change) or carry ``name`` plus ``check_str`` (rename).
    """
    with open(path, encoding='utf-8') as handle:
        raw = yaml.safe_load(handle) or {}

    if not isinstance(raw, Mapping):
        raise ValueError(f'{path}: defaults file must contain a YAML mapping')

    rules: list[RegisteredRule] = []
    for name, body in raw.items():
        line = find_yaml_key_line(path, name)
        if isinstance(body, str):
            rules.append(
                RegisteredRule(
                    name=name,
                    check_str=body,
                    source_file=path,
                    source_line=line,
                )
            )
            continue
        if not isinstance(body, Mapping):
            raise ValueError(
                f'{path}:{line or 0}: rule {name!r} must be a string '
                'or mapping'
            )
        if 'check_str' not in body:
            raise ValueError(
                f'{path}:{line or 0}: rule {name!r} is missing check_str'
            )

        deprecated_name = None
        deprecated_check_str = None
        deprecated_reason = body.get('deprecated_reason')
        deprecated_since = body.get('deprecated_since')
        deprecated_body = body.get('deprecated_rule')
        if isinstance(deprecated_body, str):
            deprecated_name = name
            deprecated_check_str = deprecated_body
        elif isinstance(deprecated_body, Mapping):
            if 'check_str' not in deprecated_body:
                raise ValueError(
                    f'{path}:{line or 0}: deprecated_rule for {name!r} '
                    'is missing check_str'
                )
            deprecated_name = deprecated_body.get('name', name)
            deprecated_check_str = deprecated_body['check_str']
            deprecated_reason = (
                deprecated_body.get('deprecated_reason') or deprecated_reason
            )
            deprecated_since = (
                deprecated_body.get('deprecated_since') or deprecated_since
            )

        rules.append(
            RegisteredRule(
                name=name,
                check_str=body['check_str'],
                scope_types=tuple(_as_list(body.get('scope_types'))),
                deprecated_name=deprecated_name,
                deprecated_check_str=deprecated_check_str,
                deprecated_reason=deprecated_reason,
                deprecated_since=deprecated_since,
                source_file=path,
                source_line=line,
            )
        )
    return rules


def find_yaml_key_line(path: str, key: str) -> int | None:
    """Return the 1-based line where a top-level ``key:`` is defined.

    YAML comments and quoted keys are handled for the common policy file
    shapes; ``None`` is returned when the key cannot be located.
    """
    candidates = (
        f'{key}:',
        f'"{key}":',
        f"'{key}':",
    )
    try:
        with open(path, encoding='utf-8') as handle:
            for lineno, line in enumerate(handle, start=1):
                stripped = line.lstrip()
                if stripped.startswith('#'):
                    continue
                if any(stripped.startswith(prefix) for prefix in candidates):
                    return lineno
    except FileNotFoundError:
        return _FILE_LINE_NOT_FOUND
    return _FILE_LINE_NOT_FOUND


def _normalize_keystone_token(
    label: str, path: str, token: Mapping[str, Any]
) -> CredentialSample:
    roles = tuple(
        role['name'] if isinstance(role, Mapping) else str(role)
        for role in token.get('roles', [])
    )
    creds: dict[str, Any] = {
        'roles': list(roles),
        'is_admin': False,
    }
    if isinstance(token.get('user'), Mapping) and 'id' in token['user']:
        creds['user_id'] = token['user']['id']
    elif 'user_id' in token:
        creds['user_id'] = token['user_id']

    project = token.get('project')
    if isinstance(project, Mapping) and 'id' in project:
        creds['project_id'] = project['id']
        domain = project.get('domain')
        if isinstance(domain, Mapping) and 'id' in domain:
            creds['project_domain_id'] = domain['id']

    domain = token.get('domain')
    if isinstance(domain, Mapping) and 'id' in domain:
        creds['domain_id'] = domain['id']
    elif 'domain_id' in token:
        creds['domain_id'] = token['domain_id']

    system = token.get('system')
    if isinstance(system, Mapping) and system.get('all'):
        creds['system_scope'] = 'all'
        creds['system'] = 'all'
    elif token.get('system_scope'):
        creds['system_scope'] = token['system_scope']
        creds['system'] = token['system_scope']

    if creds.get('system'):
        scope = 'system'
    elif creds.get('domain_id'):
        scope = 'domain'
    else:
        scope = 'project'
    return CredentialSample(
        label=label,
        source_file=path,
        roles=roles,
        creds=creds,
        scope=scope,
    )


def _normalize_credential_file(
    path: str, label: str | None
) -> CredentialSample:
    with open(path, encoding='utf-8') as handle:
        data = json.load(handle)
    if not isinstance(data, Mapping):
        raise ValueError(f'{path}: credential file must contain a JSON object')

    sample_label = label or os.path.splitext(os.path.basename(path))[0]
    token = data.get('token', data)
    if not isinstance(token, Mapping):
        raise ValueError(f'{path}: token payload must be a JSON object')

    if 'roles' in token and 'token' not in data:
        roles = tuple(
            role['name'] if isinstance(role, Mapping) else str(role)
            for role in token.get('roles', [])
        )
        creds = dict(token)
        creds['roles'] = list(roles)
        creds.setdefault('is_admin', False)
        if creds.get('system_scope') and not creds.get('system'):
            creds['system'] = creds['system_scope']
        scope = (
            'system'
            if creds.get('system')
            else 'domain'
            if creds.get('domain_id')
            else 'project'
        )
        return CredentialSample(
            label=sample_label,
            source_file=path,
            roles=roles,
            creds=creds,
            scope=scope,
        )

    return _normalize_keystone_token(sample_label, path, token)


def load_credentials(paths: Sequence[str] | str) -> list[CredentialSample]:
    """Load one or more credential JSON files.

    A directory path loads every ``*.json`` file inside it, sorted by name.
    Keystone token introspection payloads (the ``{"token": ...}`` shape used
    by ``oslopolicy-checker``) and pre-flattened policy creds dicts are both
    accepted.
    """
    if isinstance(paths, str):
        paths = [paths]

    files: list[str] = []
    for entry in paths:
        if os.path.isdir(entry):
            files.extend(
                sorted(
                    os.path.join(entry, name)
                    for name in os.listdir(entry)
                    if name.endswith('.json')
                )
            )
        else:
            files.append(entry)

    return [_normalize_credential_file(path, label=None) for path in files]


def load_target(
    path: str | None, fallback: Mapping[str, Any]
) -> dict[str, Any]:
    """Load a target JSON file, or fall back to a caller-provided default."""
    if path is None:
        return dict(fallback)
    with open(path, encoding='utf-8') as handle:
        data = json.load(handle)
    if not isinstance(data, Mapping):
        raise ValueError(f'{path}: target file must contain a JSON object')
    return dict(data)
