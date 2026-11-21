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

"""Read-only reachability analysis for policy rules.

This module answers a narrowly scoped question: starting from the policies that
back actual API actions (the *registered* rules), which other rules are
actually reachable through ``rule:`` references?

It is deliberately read-only. Nothing here mutates the :class:`~.Enforcer`,
loads a policy file, or evaluates credentials, so it is safe to run before
publishing an authorization configuration. Two structural problems are treated
as release blockers because they break policy evaluation at runtime:

* a ``rule:`` reference that points at a rule which is not defined anywhere
  (neither registered, loaded from a file, nor kept as a deprecated alias);
* a chain of ``rule:`` references that forms a cycle.

Policies that are simply never referenced from a registered action are not an
error. Historical names kept for backwards compatibility routinely end up in
that bucket, so they are reported as *unreachable* advisory information rather
than as failures.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
import logging

from oslo_policy import _checks
from oslo_policy.policy import Enforcer

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class ReferenceIssue:
    """A single broken reference, with the chain that reaches it.

    :ivar kind: ``undefined`` for a reference to an unknown rule or ``cycle``
        for a reference that re-enters a rule already on the current path.
    :ivar source: registered action the traversal started from.
    :ivar chain: ordered rule names from ``source`` up to and including the
        rule that carries the offending reference.
    :ivar reference: the name the offending ``rule:`` check points at.
    """

    kind: str
    source: str
    chain: tuple[str, ...]
    reference: str

    @property
    def path(self) -> str:
        """Render the chain plus the dangling reference as a string."""
        return ' -> '.join([*self.chain, f'rule:{self.reference}'])


@dataclass
class ReachabilityReport:
    """Result of a reachability analysis.

    :ivar roots: registered actions the traversal started from.
    :ivar reachable: names reachable from at least one root, roots included.
    :ivar unreachable: defined names that no root can reach. Advisory only.
    :ivar disabled: reachable names whose check always denies access (``!``).
    :ivar legacy_aliases: deprecated names that are still kept around for
        backwards compatibility but no longer registered under that name.
    :ivar issues: blocking problems (undefined references and cycles).
    """

    roots: list[str] = field(default_factory=list)
    reachable: list[str] = field(default_factory=list)
    unreachable: list[str] = field(default_factory=list)
    disabled: list[str] = field(default_factory=list)
    legacy_aliases: list[str] = field(default_factory=list)
    issues: list[ReferenceIssue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """``True`` when no blocking issue was found."""
        return not self.issues


def _rule_references(check: _checks.BaseCheck) -> Iterable[str]:
    """Yield the names referenced via ``rule:`` checks in a check tree."""
    if isinstance(check, _checks.RuleCheck):
        yield check.match
        return

    # AndCheck/OrCheck expose a ``rules`` sequence; NotCheck wraps one rule.
    rules = getattr(check, 'rules', None)
    if rules is not None:
        for child in rules:
            yield from _rule_references(child)
        return

    wrapped = getattr(check, 'rule', None)
    if wrapped is not None:
        yield from _rule_references(wrapped)


def _is_disabled(check: _checks.BaseCheck) -> bool:
    return isinstance(check, _checks.FalseCheck)


def _collect_legacy_aliases(enforcer: Enforcer) -> dict[str, str]:
    """Map deprecated rule names kept for compatibility to their new name."""
    aliases: dict[str, str] = {}
    for default in enforcer.registered_rules.values():
        deprecated = default.deprecated_rule
        if deprecated is not None and deprecated.name != default.name:
            aliases.setdefault(deprecated.name, default.name)
    return aliases


def analyze(
    enforcer: Enforcer,
    roots: Sequence[str] | None = None,
) -> ReachabilityReport:
    """Analyze rule reachability from registered actions.

    The enforcer must already have its rules populated, typically by calling
    :meth:`Enforcer.load_rules` once. The analysis itself never mutates it.

    :param enforcer: the enforcer holding the effective rules.
    :param roots: registered action names to start from. Defaults to every
        registered rule, i.e. every policy that backs an API action.
    :returns: a :class:`ReachabilityReport`.
    :raises KeyError: if an explicitly provided root is not registered.
    """
    if roots is None:
        root_names = sorted(enforcer.registered_rules)
    else:
        root_names = list(roots)
        for root in root_names:
            if root not in enforcer.registered_rules:
                raise KeyError(
                    f'Root policy "{root}" has not been registered.'
                )

    # Prefer the enforcer's effective rules (file overrides plus registered
    # defaults). When the enforcer was created with use_conf=False its rule
    # store is never populated, so fall back to a read-only view built from
    # the registered defaults rather than mutating the enforcer.
    effective_rules: dict[str, _checks.BaseCheck] = dict(enforcer.rules)
    if not effective_rules:
        for name, default in enforcer.registered_rules.items():
            effective_rules[name] = default.check

    aliases = _collect_legacy_aliases(enforcer)
    # A rule is "defined" if it exists in the effective rule set, or if its
    # name is preserved as a deprecated alias of a registered policy.
    defined = set(effective_rules) | set(aliases)

    reachable: set[str] = set()
    disabled: set[str] = set()
    issues: list[ReferenceIssue] = []
    # Three-color DFS state: white (absent), gray (on the current path),
    # black (fully explored). Tracking colors explicitly keeps diamond-shaped
    # dependency graphs from being expanded more than once while still
    # detecting back edges, which form cycles.
    gray: set[str] = set()
    black: set[str] = set()
    seen_issue_keys: set[tuple[str, str, str]] = set()

    def record_issue(
        kind: str, source: str, chain: tuple[str, ...], reference: str
    ) -> None:
        key = (kind, '>'.join(chain), reference)
        if key in seen_issue_keys:
            return
        seen_issue_keys.add(key)
        issues.append(
            ReferenceIssue(
                kind=kind, source=source, chain=chain, reference=reference
            )
        )

    def visit(name: str, source: str, path: tuple[str, ...]) -> None:
        if name not in effective_rules:
            # A legacy alias is defined but carries no check of its own; the
            # effective rule set routes enforcement through the new policy, so
            # treat the alias as a leaf for reachability.
            return
        if name in black:
            return
        if name in gray:
            record_issue('cycle', source, path, name)
            return

        gray.add(name)
        reachable.add(name)
        if _is_disabled(effective_rules[name]):
            disabled.add(name)

        next_path = (*path, name)
        for reference in _rule_references(effective_rules[name]):
            if reference not in defined:
                record_issue('undefined', source, next_path, reference)
                continue
            visit(reference, source, next_path)

        gray.remove(name)
        black.add(name)

    for root in root_names:
        visit(root, root, tuple())

    report = ReachabilityReport(roots=list(root_names))
    report.reachable = sorted(reachable)
    report.unreachable = sorted(set(effective_rules) - reachable)
    report.disabled = sorted(disabled)
    report.legacy_aliases = sorted(aliases)
    report.issues = issues
    return report


def format_report(report: ReachabilityReport) -> str:
    """Render a report as human-readable, operator-focused text."""
    lines: list[str] = []

    if report.issues:
        lines.append(f'Blocking issues found: {len(report.issues)}')
        for issue in report.issues:
            lines.append(
                f'  [{issue.kind}] action "{issue.source}": {issue.path}'
            )
    else:
        lines.append('No undefined or cyclical rule references found.')

    lines.append('')
    lines.append(
        f'Reachable from {len(report.roots)} registered action(s): '
        f'{len(report.reachable)} rule(s).'
    )
    if report.disabled:
        lines.append(
            'Reachable but explicitly disabled (always deny, "!"): '
            + ', '.join(report.disabled)
        )
    if report.legacy_aliases:
        lines.append(
            'Legacy names retained as deprecated aliases: '
            + ', '.join(report.legacy_aliases)
        )

    if report.unreachable:
        lines.append('')
        lines.append(
            f'Unreachable rules (not referenced by any action, advisory '
            f'only): {len(report.unreachable)}'
        )
        for name in report.unreachable:
            lines.append(f'  - {name}')
    else:
        lines.append('')
        lines.append('No unreachable rules.')

    return '\n'.join(lines)


def check_reachability(
    enforcer: Enforcer,
    roots: Sequence[str] | None = None,
) -> ReachabilityReport:
    """Run the analysis and return a report with actionable findings.

    This is the convenience entry point used by the CLI. It performs the
    read-only analysis and logs each blocking issue at debug level so callers
    that already configure logging retain a record without duplicating the
    structured report the CLI prints to stdout.

    :param enforcer: the enforcer holding the effective rules.
    :param roots: optional explicit list of registered actions to start from.
    :returns: the :class:`ReachabilityReport` for further inspection.
    """
    report = analyze(enforcer, roots)
    for issue in report.issues:
        LOG.debug(
            '%(kind)s reference reached from action "%(action)s": %(path)s',
            {
                'kind': issue.kind,
                'action': issue.source,
                'path': issue.path,
            },
        )
    return report
