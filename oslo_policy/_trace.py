#
# Copyright (c) 2026 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Structured tracing of policy evaluation.

The trace is intentionally limited to structural information: the check
expressions that were considered, the policy rule names that were
followed, whether each branch actually ran, and its boolean outcome.  Target
and credential values are never copied into a trace, which keeps traces safe
to include in restricted diagnostic output.

Tracing is opt-in.  :func:`activate` installs a collector in a context
variable for the duration of one explanation request and
:func:`get_active_trace` lets the policy engine report the checks it really
runs.  Normal enforcement does not incur any trace construction.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
import contextlib
import contextvars
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from oslo_serialization import jsonutils

if TYPE_CHECKING:
    from oslo_policy import _checks


@dataclass
class CheckTraceNode:
    """One check that was (or deliberately was not) evaluated.

    ``check`` keeps a reference to the actual check object so that a trace
    can be tied back to the rule tree.  It is excluded from serialization.
    """

    check: Any = field(repr=False)
    check_type: str
    check_str: str
    kind: str | None = None
    match: str | None = None
    rule_name: str | None = None
    branch: int | None = None
    executed: bool = False
    result: bool | None = None
    reason: str | None = None
    children: list['CheckTraceNode'] = field(default_factory=list)

    @property
    def skipped(self) -> bool:
        """Whether this branch was short-circuited and never executed."""
        return not self.executed

    @property
    def failed(self) -> bool:
        """Whether this executed check returned a denying result."""
        return self.executed and self.result is False

    def walk(self) -> Iterator['CheckTraceNode']:
        """Yield this node and all descendants in evaluation order."""
        yield self
        for child in self.children:
            yield from child.walk()

    @property
    def leaves(self) -> list['CheckTraceNode']:
        """Return executed leaf checks (checks without children)."""
        return [
            node
            for node in self.walk()
            if node.executed and not node.children
        ]

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable description without request values."""
        data: dict[str, Any] = {
            'rule': self.rule_name,
            'name': self.rule_name,
            'type': self.check_type,
            'kind': self.kind,
            'match': self.match,
            'check': self.check_str,
            'branch': self.branch,
            'executed': self.executed,
            'result': self.result,
            'skipped': self.skipped,
        }
        if self.reason is not None:
            data['reason'] = self.reason
        data['children'] = [child.to_dict() for child in self.children]
        return data


def _check_type(check: Any) -> str:
    """Return a short, stable label for a check class."""
    from oslo_policy import _checks

    if isinstance(check, _checks.AndCheck):
        return 'and'
    if isinstance(check, _checks.OrCheck):
        return 'or'
    if isinstance(check, _checks.NotCheck):
        return 'not'
    if isinstance(check, _checks.RuleCheck):
        return 'rule'
    if isinstance(check, _checks.TrueCheck):
        return 'true'
    if isinstance(check, _checks.FalseCheck):
        return 'false'
    kind = getattr(check, 'kind', None)
    if kind is not None:
        return str(kind)
    return type(check).__name__


def _check_str(check: Any) -> str:
    try:
        return str(check)
    except Exception:  # pragma: no cover - defensive for custom checks
        return type(check).__name__


def make_node(
    check: Any,
    rule_name: str | None,
    branch: int | None,
) -> CheckTraceNode:
    """Build a node describing ``check`` without executing it."""
    kind = getattr(check, 'kind', None)
    match = getattr(check, 'match', None)
    return CheckTraceNode(
        check=check,
        check_type=_check_type(check),
        check_str=_check_str(check),
        kind=str(kind) if kind is not None else None,
        match=str(match) if match is not None else None,
        rule_name=rule_name,
        branch=branch,
    )


def _expected_children(check: Any, enforcer: Any) -> list[Any]:
    """Return the children that a built-in composite would evaluate."""
    from oslo_policy import _checks

    if isinstance(check, (_checks.AndCheck, _checks.OrCheck)):
        return list(check.rules)
    if isinstance(check, _checks.NotCheck):
        return [check.rule]
    if isinstance(check, _checks.RuleCheck):
        try:
            return [enforcer.rules[check.match]]
        except KeyError:
            # An undefined rule is reported by the RuleCheck node itself.
            return []
    return []


class PolicyTrace:
    """The result of one :meth:`Enforcer.explain` call.

    ``result`` is the exact value returned by the underlying enforcement
    while ``allowed`` is its boolean interpretation.  ``root`` describes
    the rule tree that was actually traversed.  For rules that could not be
    evaluated at all (unknown rule, scope mismatch, missing rule set)
    ``reason`` explains why and the trace has no root.
    """

    def __init__(self, requested_rule: str | None = None) -> None:
        self.requested_rule = requested_rule
        self.root: CheckTraceNode | None = None
        self._result: Any = False
        self.allowed: bool = False
        self.scope_valid: bool | None = None
        self.reason: str | None = None
        self.error: str | None = None
        self._stack: list[CheckTraceNode] = []
        self._rule_stack: list[str | None] = [requested_rule]

    def __bool__(self) -> bool:
        """Allow the trace to be used where the raw decision is expected."""
        return self.allowed

    @property
    def decision(self) -> bool:
        """Alias for :attr:`allowed`, the boolean authorization decision."""
        return self.allowed

    @property
    def result(self) -> Any:
        """The exact value returned by the underlying enforcement."""
        return self._result

    @result.setter
    def result(self, value: Any) -> None:
        self._result = value
        self.allowed = bool(value)

    @property
    def executed(self) -> list[CheckTraceNode]:
        """Return every check that actually ran, in evaluation order."""
        if self.root is None:
            return []
        return [node for node in self.root.walk() if node.executed]

    @property
    def skipped(self) -> list[CheckTraceNode]:
        """Return every branch that was short-circuited."""
        if self.root is None:
            return []
        return [node for node in self.root.walk() if node.skipped]

    @property
    def failed(self) -> list[CheckTraceNode]:
        """Return executed checks that denied, useful for on-call triage."""
        if self.root is None:
            return []
        return [node for node in self.root.walk() if node.failed]

    @property
    def rule_names(self) -> list[str]:
        """Return referenced policy rule names in traversal order."""
        names: list[str] = []
        if self.root is None:
            return names
        if self.requested_rule is not None:
            names.append(self.requested_rule)
        for node in self.root.walk():
            if not node.executed:
                continue
            name = node.rule_name
            if name is not None and name not in names:
                names.append(name)
        return names

    def evaluate(
        self,
        check: Any,
        target: _checks.TargetT,
        creds: Any,
        enforcer: Any,
        current_rule: str | None,
        invoke: Callable[..., Any],
    ) -> Any:
        from oslo_policy import _checks

        # A referenced rule body keeps the name of the rule a reader asked
        # about; a ``rule:`` check itself shows the name it points at.  This
        # way every node under ``a: rule:admin`` is attributable to ``a`` and
        # the literal ``rule:admin`` edge shows ``admin``.
        if self._stack:
            rule_name = self._stack[-1].rule_name
        else:
            rule_name = self._rule_stack[-1]
        parent = self._stack[-1] if self._stack else None
        branch = len(parent.children) if parent is not None else 0
        node = make_node(check, rule_name, branch)
        if isinstance(check, _checks.RuleCheck):
            node.rule_name = check.match
        if parent is None:
            if self.root is None:
                self.root = node
        else:
            parent.children.append(node)

        # A ``rule:`` check evaluates the referenced rule body, so nested
        # checks belong to the referenced rule name rather than the rule that
        # referenced it.  Nested rule checks push their own name the same way.
        push_referenced_rule = isinstance(check, _checks.RuleCheck)
        self._stack.append(node)
        if push_referenced_rule:
            self._rule_stack.append(check.match)
        try:
            result = invoke(check, target, creds, enforcer, current_rule)
        except Exception as exc:
            # Record only the exception type: messages from custom checks
            # could embed caller-supplied data.
            node.executed = True
            node.reason = f'error: {type(exc).__name__}'
            raise
        finally:
            if push_referenced_rule:
                self._rule_stack.pop()
            self._stack.pop()

        node.executed = True
        node.result = bool(result)

        expected = _expected_children(check, enforcer)
        if expected:
            for index, child in enumerate(expected):
                if index < len(node.children):
                    if node.children[index].check is child:
                        continue
                    # A custom composite evaluated in a different order;
                    # do not invent branches that did not exist.
                    break
                node.children.append(
                    self._skipped_node(child, node.rule_name, index, enforcer)
                )

        return result

    def _skipped_node(
        self,
        check: Any,
        rule_name: str | None,
        branch: int,
        enforcer: Any,
        depth: int = 0,
        seen: frozenset[str] = frozenset(),
    ) -> CheckTraceNode:
        """Describe a branch that was short-circuited without running it.

        The shape of the branch is preserved so readers can see what was
        skipped, but every node in it is marked ``executed=False`` and has no
        result.  A ``rule:`` reference is expanded only once to avoid cycles.
        """
        from oslo_policy import _checks

        node = make_node(check, rule_name, branch)
        if isinstance(check, _checks.RuleCheck):
            node.rule_name = check.match
        node.reason = 'not_executed'
        if depth >= _MAX_SKIPPED_DEPTH:
            return node
        if isinstance(check, _checks.RuleCheck):
            if check.match in seen:
                return node
            seen = seen | {check.match}
            child_rule_name = check.match
        else:
            child_rule_name = rule_name
        for index, child in enumerate(_expected_children(check, enforcer)):
            node.children.append(
                self._skipped_node(
                    child,
                    child_rule_name,
                    index,
                    enforcer,
                    depth + 1,
                    seen,
                )
            )
        return node

    def to_json(self) -> str:
        """Return the trace as JSON for diagnostic endpoints."""
        return jsonutils.dumps(self.to_dict(), indent=2, sort_keys=True)

    def to_dict(self) -> dict[str, Any]:
        """Return the trace as a plain dictionary safe for diagnostics."""
        data: dict[str, Any] = {
            'rule': self.requested_rule,
            'result': bool(self.result),
            'allowed': self.allowed,
            'scope_valid': self.scope_valid,
            'rules': self.rule_names,
        }
        if self.reason is not None:
            data['reason'] = self.reason
        if self.error is not None:
            data['error'] = self.error
        data['root'] = self.root.to_dict() if self.root else None
        return data

    def __str__(self) -> str:
        lines = [
            f'{self.requested_rule or "<check>"}: '
            f'{"allow" if self.allowed else "deny"}'
        ]
        if self.reason:
            lines.append(f'  reason: {self.reason}')
        if self.root is not None:
            lines.append(self._render_line(self.root, prefix='  '))
            lines.extend(self._render_children(self.root, prefix='  '))
        return '\n'.join(lines)

    @staticmethod
    def _render_line(node: CheckTraceNode, prefix: str = '') -> str:
        state = 'executed' if node.executed else 'not executed'
        result = (
            ' -> ' + ('true' if node.result else 'false')
            if node.executed
            else ''
        )
        name = f'{node.rule_name}: ' if node.rule_name else ''
        return f'{prefix}{name}{node.check_str} [{state}]{result}'

    def _render_children(
        self, node: CheckTraceNode, prefix: str
    ) -> list[str]:
        lines: list[str] = []
        for index, child in enumerate(node.children):
            last = index == len(node.children) - 1
            connector = '`- ' if last else '+- '
            lines.append(
                self._render_line(child, prefix=f'{prefix}{connector}')
            )
            lines.extend(
                self._render_children(
                    child, prefix + ('   ' if last else '|  ')
                )
            )
        return lines


# Bound the expansion of unexecuted ``rule:`` references in a trace.
_MAX_SKIPPED_DEPTH = 32

_active_trace: contextvars.ContextVar[PolicyTrace | None] = (
    contextvars.ContextVar('oslo_policy_trace', default=None)
)


def get_active_trace() -> PolicyTrace | None:
    """Return the trace collecting the current evaluation, if any."""
    return _active_trace.get()


@contextlib.contextmanager
def activate(trace: PolicyTrace) -> Iterator[PolicyTrace]:
    """Install ``trace`` for the duration of the context."""
    token = _active_trace.set(trace)
    try:
        yield trace
    finally:
        _active_trace.reset(token)
