"""Human-readable and machine-readable rendering of policy diffs."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

PROVENANCE_TITLES = {
    'file_override': 'site policy file override',
    'registered_default': 'registered policy-in-code default',
    'deprecated_name_override': 'deprecated name kept from policy file',
    'deprecated_or_compat': 'deprecated OR-compat (new default OR old check)',
    'fail_closed': 'unregistered action, fail closed',
}

CHANGE_TITLES = {
    'unchanged': 'unchanged',
    'granted': 'PERMISSION GAINED',
    'revoked': 'PERMISSION LOST',
    'added': 'newly evaluated action',
    'removed': 'action no longer registered',
}


def _result_word(value: bool | None) -> str:
    if value is None:
        return 'n/a'
    return 'ALLOW' if value else 'DENY'


def _location(payload: dict[str, Any] | None) -> str:
    if not payload or payload.get('source_label') is None:
        return '-'
    label = payload['source_label']
    line = payload.get('source_line')
    return f'{label}:{line}' if line else label


def render_text(
    rows: list[dict[str, Any]],
    before_label: str,
    after_label: str,
) -> str:
    lines: list[str] = []
    lines.append('oslo.policy upgrade impact report')
    lines.append('=' * 33)
    lines.append(f'before snapshot: {before_label}')
    lines.append(f'after snapshot : {after_label}')
    lines.append('')

    impacts = _impact_summary(rows)
    lines.append('Role impact summary')
    lines.append('-' * 19)
    if not any(impacts.values()):
        lines.append('No allow/deny changes detected for the supplied '
                     'credential samples.')
    else:
        for label in sorted(impacts):
            granted = sorted(impacts[label]['granted'])
            revoked = sorted(impacts[label]['revoked'])
            parts = [f'{label}:']
            parts.append(
                f'gained {len(granted)} action(s)'
                + (f' [{"; ".join(granted)}]' if granted else '')
            )
            parts.append(
                f'lost {len(revoked)} action(s)'
                + (f' [{"; ".join(revoked)}]' if revoked else '')
            )
            lines.append('  ' + ' | '.join(parts))
    lines.append('')

    lines.append('Per-action results')
    lines.append('-' * 19)
    for row in rows:
        header = row['before_action'] or '(absent before)'
        if row['rename']:
            header += f'  ->  {row["after_action"]}'
        elif row['after_action'] and row['after_action'] != header:
            header = f'{header}  ->  {row["after_action"]}'
        lines.append(f'* {header}')
        for entry in row['credentials']:
            change = entry['change']
            marker = ' ' if change == 'unchanged' else '!'
            lines.append(
                f'  [{marker}] {entry["credential"]} '
                f'(roles: {",".join(entry["roles"]) or "(none)"}): '
                f'{_result_word(entry["before_allowed"])} -> '
                f'{_result_word(entry["after_allowed"])}  '
                f'({CHANGE_TITLES[change]})'
            )
            before = entry['before']
            after = entry['after']
            if before is not None:
                lines.append(
                    '      before: check='
                    f'{before["effective_check_str"]!r} scope_ok='
                    f'{before["scope_ok"]} source={_location(before)} '
                    f'via {PROVENANCE_TITLES[before["provenance"]]}'
                )
            if after is not None:
                lines.append(
                    '      after : check='
                    f'{after["effective_check_str"]!r} scope_ok='
                    f'{after["scope_ok"]} source={_location(after)} '
                    f'via {PROVENANCE_TITLES[after["provenance"]]}'
                )
        lines.append('')
    return '\n'.join(lines).rstrip() + '\n'


def _impact_summary(rows: list[dict[str, Any]]) -> dict[str, dict[str, set]]:
    impacts: dict[str, dict[str, set]] = defaultdict(
        lambda: {'granted': set(), 'revoked': set()}
    )
    for row in rows:
        action = row['after_action'] or row['before_action']
        for entry in row['credentials']:
            label = entry['credential']
            if entry['change'] == 'granted':
                impacts[label]['granted'].add(action)
            elif entry['change'] == 'revoked':
                impacts[label]['revoked'].add(action)
    return impacts


def render_json(
    rows: list[dict[str, Any]],
    before_context: dict[str, Any],
    after_context: dict[str, Any],
) -> str:
    role_impact = {
        label: {
            'granted': sorted(changes['granted']),
            'revoked': sorted(changes['revoked']),
        }
        for label, changes in sorted(_impact_summary(rows).items())
    }
    payload = {
        'before': before_context,
        'after': after_context,
        'role_impact': role_impact,
        'actions': rows,
    }
    return json.dumps(payload, indent=2, sort_keys=False) + '\n'


def render_explain(
    snapshot_label: str,
    action: str,
    trace: list[Any],
) -> str:
    lines = [
        f'Effective policy trace for {action!r} in snapshot '
        f'{snapshot_label!r}',
    ]
    for depth, hop in enumerate(trace):
        indent = '  ' * depth
        lines.append(
            f'{indent}- rule {hop.rule_name!r} => {hop.check_str}'
        )
        lines.append(
            f'{indent}  provenance: '
            f'{PROVENANCE_TITLES.get(hop.provenance, hop.provenance)}'
        )
        location = hop.source_label
        if hop.source_line:
            location = f'{location}:{hop.source_line}'
        lines.append(f'{indent}  source: {location}')
        lines.append(f'{indent}  detail: {hop.detail}')
    return '\n'.join(lines) + '\n'
