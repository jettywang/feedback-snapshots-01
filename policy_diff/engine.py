"""Effective-policy snapshots and provenance-aware diffing.

A :class:`PolicySnapshot` is built exactly the way a service builds its
runtime rule set: registered policy-in-code defaults are handed to a fresh
:class:`oslo_policy.policy.Enforcer`, the local operator policy file is
loaded on top, and deprecated-rule handling is performed by oslo.policy
itself. Every snapshot gets its own throwaway ``cfg.ConfigOpts`` instance
and its own enforcer, so running this tool cannot change the rules the
currently deployed service enforces.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from oslo_config import cfg
from oslo_policy import _checks
from oslo_policy import _parser
from oslo_policy import opts as policy_opts
from oslo_policy import policy

from policy_diff.loader import (
    CredentialSample,
    PROVENANCE_DEFAULT,
    PROVENANCE_DEPRECATED_NAME,
    PROVENANCE_DEPRECATED_OR,
    PROVENANCE_FAIL_CLOSED,
    PROVENANCE_FILE_OVERRIDE,
    RegisteredRule,
    find_yaml_key_line,
)


@dataclass(frozen=True)
class RuleTrace:
    """One hop in the resolution of an action's effective check tree."""

    rule_name: str
    check_str: str
    provenance: str
    source_label: str
    source_line: int | None
    detail: str


@dataclass(frozen=True)
class ActionEvaluation:
    """Allow/deny outcome of one action for one credential sample."""

    action: str
    credential_label: str
    roles: tuple[str, ...]
    allowed: bool
    scope_ok: bool
    effective_check_str: str
    provenance: str
    source_label: str
    source_line: int | None
    detail: str
    trace: tuple[RuleTrace, ...] = ()


@dataclass(frozen=True)
class SnapshotContext:
    """Inputs that identify one side of the upgrade."""

    label: str
    defaults_file: str
    policy_file: str | None
    enforce_new_defaults: bool


@dataclass
class PolicySnapshot:
    """A fully resolved rule set and everything needed to explain it."""

    context: SnapshotContext
    enforcer: policy.Enforcer
    registered: dict[str, RegisteredRule]
    file_rule_lines: dict[str, int]
    evaluations: dict[str, dict[str, ActionEvaluation]] = field(
        default_factory=dict
    )

    @property
    def actions(self) -> set[str]:
        return set(self.enforcer.rules)

    def effective_check(self, action: str) -> _checks.BaseCheck | None:
        try:
            return self.enforcer.rules[action]
        except KeyError:
            return None

    def scope_types(self, action: str) -> tuple[str, ...]:
        registered = self.registered.get(action)
        if registered and registered.scope_types:
            return registered.scope_types
        rule_default = self.enforcer.registered_rules.get(action)
        if rule_default and rule_default.scope_types:
            return tuple(rule_default.scope_types)
        return ()

    def scope_allows(self, action: str, creds: Mapping[str, Any]) -> bool:
        scope_types = self.scope_types(action)
        if not scope_types:
            return True
        if creds.get('system'):
            token_scope = 'system'
        elif creds.get('domain_id'):
            token_scope = 'domain'
        else:
            token_scope = 'project'
        return token_scope in scope_types

    def explain(self, action: str) -> tuple[RuleTrace, ...]:
        return tuple(_walk_rule(self, action, seen=set()))


def _materialize_policy_file(policy_file: str | None) -> tuple[str, bool]:
    """Return (path, is_temporary) for an enforcer policy file.

    A real operator policy file is returned as an absolute path and is
    never touched. When no file is supplied, an empty temporary file is
    created so the throwaway enforcer has something to load; the caller
    owns its deletion.
    """
    if policy_file is not None:
        absolute = os.path.abspath(policy_file)
        if not os.path.exists(absolute):
            raise FileNotFoundError(absolute)
        return absolute, False

    descriptor, temporary = tempfile.mkstemp(
        prefix='policy-diff-empty-', suffix='.yaml'
    )
    os.close(descriptor)
    return temporary, True


def build_snapshot(
    context: SnapshotContext,
    defaults: Sequence[RegisteredRule],
) -> PolicySnapshot:
    """Resolve one side of the upgrade through a real oslo Enforcer."""
    conf = cfg.ConfigOpts()
    policy_opts._register(conf)
    conf(args=[])
    conf.set_override(
        'enforce_new_defaults',
        context.enforce_new_defaults,
        group='oslo_policy',
    )

    materialized, is_temporary = _materialize_policy_file(
        context.policy_file
    )
    try:
        enforcer = policy.Enforcer(conf, policy_file=materialized)
        # This is an offline, read-only analysis tool: the deprecation
        # warnings are surfaced as provenance detail strings instead of log
        # noise.
        enforcer.suppress_deprecation_warnings = True
        enforcer.suppress_default_change_warnings = True
        enforcer.register_defaults(
            rule.to_rule_default() for rule in defaults
        )
        enforcer.load_rules(force_reload=True)

        registered = {rule.name: rule for rule in defaults}
        file_rule_lines: dict[str, int] = {}
        if context.policy_file is not None:
            for name in enforcer.file_rules:
                line = find_yaml_key_line(
                    os.path.abspath(context.policy_file), name
                )
                if line is not None:
                    file_rule_lines[name] = line

        snapshot = PolicySnapshot(
            context=context,
            enforcer=enforcer,
            registered=registered,
            file_rule_lines=file_rule_lines,
        )
        _verify_resolution(snapshot)
    finally:
        if is_temporary:
            os.unlink(materialized)
    return snapshot


def _verify_resolution(snapshot: PolicySnapshot) -> None:
    """Cross-check provenance strings against the live enforcer state."""
    enforcer = snapshot.enforcer
    for action in snapshot.actions:
        trace = snapshot.explain(action)
        root = trace[0]
        live_check = enforcer.rules.get(action)
        if live_check is None:
            assert root.provenance == PROVENANCE_FAIL_CLOSED
            continue
        assert str(live_check) == root.check_str, (
            f'{snapshot.context.label}:{action}: provenance check '
            f'{root.check_str!r} does not match enforcer {live_check!r}'
        )
        if root.provenance == PROVENANCE_FILE_OVERRIDE:
            assert action in enforcer.file_rules
        if root.provenance == PROVENANCE_DEFAULT:
            assert action in enforcer.registered_rules
            assert action not in enforcer.file_rules


def _provenance(
    snapshot: PolicySnapshot, action: str
) -> tuple[str, str, int | None, str]:
    """Return (provenance, source label, source line, detail) for an action."""
    enforcer = snapshot.enforcer
    policy_file = snapshot.context.policy_file

    if action not in enforcer.rules:
        return (
            PROVENANCE_FAIL_CLOSED,
            policy_file or '(no policy file)',
            None,
            'Action is not registered and no default rule exists; '
            'oslo.policy fails closed and denies the request.',
        )

    registered = snapshot.registered.get(action)
    file_rule = enforcer.file_rules.get(action)

    if file_rule is not None:
        line = snapshot.file_rule_lines.get(action)
        if registered is None:
            detail = (
                f'Rule only exists in the operator policy file; no '
                f'policy-in-code default shadows it.'
            )
        else:
            detail = (
                f'Site override in {os.path.basename(policy_file or "?")} '
                f'takes precedence over the registered default '
                f'{registered.check_str!r}.'
            )
        return (
            PROVENANCE_FILE_OVERRIDE,
            policy_file or '(policy file)',
            line,
            detail,
        )

    deprecated = (
        registered.deprecated_name if registered.deprecated_name else None
    )

    if (
        deprecated
        and deprecated != action
        and deprecated in enforcer.file_rules
        and action not in enforcer.file_rules
    ):
        line = snapshot.file_rule_lines.get(deprecated)
        return (
            PROVENANCE_DEPRECATED_NAME,
            policy_file or '(policy file)',
            line,
            f'The new name {action!r} is not overridden but the deprecated '
            f'name {deprecated!r} is; oslo.policy keeps the site value of '
            f'{deprecated!r} ({enforcer.file_rules[deprecated].check_str}) '
            'to avoid silently widening permissions on upgrade.',
        )

    effective_check = enforcer.rules[action]
    if (
        isinstance(effective_check, _checks.OrCheck)
        and registered.deprecated_check_str is not None
        and [str(child) for child in effective_check.rules]
        == [
            str(registered.to_rule_default().check),
            str(_parser.parse_rule(registered.deprecated_check_str)),
        ]
    ):
        old_str = registered.deprecated_check_str
        return (
            PROVENANCE_DEPRECATED_OR,
            registered.source_file or '(registered defaults)',
            registered.source_line,
            f'enforce_new_defaults=False keeps the graceful-upgrade OR of '
            f'the new default {registered.check_str!r} and the deprecated '
            f'check {old_str!r}.',
        )

    return (
        PROVENANCE_DEFAULT,
        registered.source_file or '(registered defaults)',
        registered.source_line,
        f'Resolved from policy-in-code default {registered.check_str!r}; '
        'the operator policy file does not mention this action.',
    )


def _walk_rule(
    snapshot: PolicySnapshot, name: str, seen: set[str]
) -> list[RuleTrace]:
    """Flatten the check tree rooted at ``name`` into ordered trace hops."""
    if name in seen:
        return [
            RuleTrace(
                rule_name=name,
                check_str='<cycle>',
                provenance=PROVENANCE_FAIL_CLOSED,
                source_label='(rule graph)',
                source_line=None,
                detail='Cyclic rule reference; evaluation stops here.',
            )
        ]
    seen = seen | {name}

    check = snapshot.enforcer.rules.get(name)
    if check is None:
        provenance, label, line, detail = _provenance(snapshot, name)
        return [
            RuleTrace(
                rule_name=name,
                check_str='!',
                provenance=provenance,
                source_label=label,
                source_line=line,
                detail=detail,
            )
        ]

    provenance, label, line, detail = _provenance(snapshot, name)
    root = RuleTrace(
        rule_name=name,
        check_str=str(check),
        provenance=provenance,
        source_label=label,
        source_line=line,
        detail=detail,
    )
    hops = [root]
    hops.extend(_walk_check(snapshot, check, seen))
    return hops


def _walk_check(
    snapshot: PolicySnapshot, check: _checks.BaseCheck, seen: set[str]
) -> list[RuleTrace]:
    if isinstance(check, _checks.RuleCheck):
        return _walk_rule(snapshot, check.match, seen)
    child_rules = getattr(check, 'rules', None)
    if child_rules:
        hops: list[RuleTrace] = []
        for child in child_rules:
            hops.extend(_walk_check(snapshot, child, seen))
        return hops
    return []


def evaluate(
    snapshot: PolicySnapshot,
    action: str,
    sample: CredentialSample,
    target: Mapping[str, Any],
) -> ActionEvaluation:
    """Evaluate one action/credential pair through the snapshot enforcer."""
    check = snapshot.effective_check(action)
    if check is None:
        provenance, label, line, detail = _provenance(snapshot, action)
        return ActionEvaluation(
            action=action,
            credential_label=sample.label,
            roles=sample.roles,
            allowed=False,
            scope_ok=False,
            effective_check_str='!',
            provenance=provenance,
            source_label=label,
            source_line=line,
            detail=detail,
            trace=tuple(snapshot.explain(action)),
        )

    scope_ok = snapshot.scope_allows(action, sample.creds)
    allowed = bool(
        snapshot.enforcer.enforce(action, dict(target), dict(sample.creds))
    )
    provenance, label, line, detail = _provenance(snapshot, action)
    if not scope_ok and not allowed:
        detail = (
            f'{detail} Token scope {sample.scope!r} is outside the declared '
            f'scope types {list(snapshot.scope_types(action))}; the enforcer '
            'denies before evaluating the check.'
        )
    return ActionEvaluation(
        action=action,
        credential_label=sample.label,
        roles=sample.roles,
        allowed=allowed,
        scope_ok=scope_ok,
        effective_check_str=str(check),
        provenance=provenance,
        source_label=label,
        source_line=line,
        detail=detail,
        trace=tuple(snapshot.explain(action)),
    )


def populate_evaluations(
    snapshot: PolicySnapshot,
    samples: Sequence[CredentialSample],
    target: Mapping[str, Any],
    actions: Sequence[str] | None = None,
) -> PolicySnapshot:
    selected = (
        list(actions) if actions is not None else sorted(snapshot.actions)
    )
    for action in selected:
        snapshot.evaluations[action] = {}
        for sample in samples:
            snapshot.evaluations[action][sample.label] = evaluate(
                snapshot, action, sample, target
            )
    return snapshot


def _rename_map(defaults: Sequence[RegisteredRule]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for rule in defaults:
        if rule.deprecated_name and rule.deprecated_name != rule.name:
            mapping[rule.deprecated_name] = rule.name
    return mapping


def diff_snapshots(
    before: PolicySnapshot,
    after: PolicySnapshot,
    samples: Sequence[CredentialSample],
) -> list[dict[str, Any]]:
    """Pair actions across the upgrade and report per-role result changes."""
    forward = _rename_map(list(after.registered.values()))

    before_actions = set(before.actions)
    after_actions = set(after.actions)
    visited: set[str] = set()
    rows: list[dict[str, Any]] = []

    def emit_row(before_name: str | None, after_name: str | None) -> None:
        if before_name is not None:
            visited.add(before_name)
        if after_name is not None:
            visited.add(after_name)

        per_credential = []
        for sample in samples:
            old_eval = (
                before.evaluations.get(before_name, {}).get(sample.label)
                if before_name is not None
                else None
            )
            new_eval = (
                after.evaluations.get(after_name, {}).get(sample.label)
                if after_name is not None
                else None
            )
            old_allowed = None if old_eval is None else old_eval.allowed
            new_allowed = None if new_eval is None else new_eval.allowed
            if old_allowed == new_allowed:
                change = 'unchanged'
            elif old_allowed is False and new_allowed is True:
                change = 'granted'
            elif old_allowed is True and new_allowed is False:
                change = 'revoked'
            else:
                change = 'added' if new_allowed else 'removed'
            per_credential.append(
                {
                    'credential': sample.label,
                    'roles': list(sample.roles),
                    'before_allowed': old_allowed,
                    'after_allowed': new_allowed,
                    'change': change,
                    'before': None
                    if old_eval is None
                    else _evaluation_payload(old_eval),
                    'after': None
                    if new_eval is None
                    else _evaluation_payload(new_eval),
                }
            )
        rows.append(
            {
                'before_action': before_name,
                'after_action': after_name,
                'rename': before_name != after_name
                and before_name is not None
                and after_name is not None,
                'credentials': per_credential,
            }
        )

    # Rows driven by the before snapshot, following the deprecated-name to
    # new-name mapping declared by the upgraded registered defaults.
    for before_name in sorted(before_actions):
        if before_name in visited:
            continue
        after_name = forward.get(before_name, before_name)
        if after_name not in after_actions:
            after_name = None
        emit_row(before_name, after_name)

    # Actions that only exist after the upgrade (brand new defaults).
    for after_name in sorted(after_actions - visited):
        emit_row(None, after_name)

    return rows


def _evaluation_payload(evaluation: ActionEvaluation) -> dict[str, Any]:
    return {
        'allowed': evaluation.allowed,
        'scope_ok': evaluation.scope_ok,
        'effective_check_str': evaluation.effective_check_str,
        'provenance': evaluation.provenance,
        'source_label': evaluation.source_label,
        'source_line': evaluation.source_line,
        'detail': evaluation.detail,
        'trace': [
            {
                'rule_name': hop.rule_name,
                'check_str': hop.check_str,
                'provenance': hop.provenance,
                'source_label': hop.source_label,
                'source_line': hop.source_line,
                'detail': hop.detail,
            }
            for hop in evaluation.trace
        ],
    }


def explain_action(
    snapshot: PolicySnapshot, action: str
) -> list[RuleTrace]:
    """Public wrapper returning the full resolution chain for one action."""
    return list(snapshot.explain(action))
