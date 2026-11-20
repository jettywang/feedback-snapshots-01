"""
Core auditing APIs.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass

from pip_audit._dependency_source import DependencySource
from pip_audit._service import (
    INTERNAL_SOURCE,
    Dependency,
    SkippedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)

logger = logging.getLogger(__name__)

#: Reason attached to internal dependencies that a plain public service was asked
#: to query. This should be unreachable through the CLI (which installs a
#: `RoutingService`), but protects API users who hand an `Auditor` a public
#: service directly.
UNROUTED_INTERNAL_REASON = (
    "not audited: package originates from an internal source, but the configured "
    "vulnerability service is not permitted to receive internal package names"
)


def _enforce_confidentiality(
    service: VulnerabilityService, specs: Iterator[Dependency]
) -> Iterator[Dependency]:
    """
    Prevent internal package names from reaching a service that is not permitted
    to receive them.

    Services that understand source policy (e.g. `RoutingService`) declare
    `supports_internal_queries`; anything else gets a policy skip instead of a
    query, so an internal name can never be leaked by accident.
    """

    if service.supports_internal_queries:
        yield from specs
        return

    for spec in specs:
        if spec.source == INTERNAL_SOURCE:
            yield SkippedDependency(
                name=spec.name,
                source=spec.source,
                skip_reason=UNROUTED_INTERNAL_REASON,
                policy_skipped=True,
            )
        else:
            yield spec


def _add_unique_vulnerability(
    unique_vulns: list[VulnerabilityResult],
    seen_aliases: set[str],
    vuln: VulnerabilityResult,
) -> None:
    """
    Add a vulnerability result, merging it with an existing alias match.
    """

    if seen_aliases.intersection(vuln.aliases | {vuln.id}):
        idx, previous = next((i, p) for (i, p) in enumerate(unique_vulns) if p.alias_of(vuln))
        unique_vulns[idx] = previous.merge_aliases(vuln)
        return

    seen_aliases.update(vuln.aliases | {vuln.id})
    unique_vulns.append(vuln)


@dataclass(frozen=True)
class AuditOptions:
    """
    Settings the control the behavior of an `Auditor` instance.
    """

    dry_run: bool = False


class Auditor:
    """
    The core class of the `pip-audit` API.

    For a given dependency source and vulnerability service, supply a mapping of dependencies to
    known vulnerabilities.
    """

    def __init__(
        self,
        service: VulnerabilityService,
        options: AuditOptions = AuditOptions(),
    ):
        """
        Create a new auditor. Auditors start with no dependencies to audit;
        each `audit` step is fed a `DependencySource`.

        The behavior of the auditor can be optionally tweaked with the `options`
        parameter.
        """
        self._service = service
        self._options = options

    def audit(
        self, source: DependencySource
    ) -> Iterator[tuple[Dependency, list[VulnerabilityResult]]]:
        """
        Perform the auditing step, collecting dependencies from `source`.

        Individual vulnerability results are uniqued based on their `aliases` sets:
        any two results for the same dependency that share an alias are collapsed
        into a single result with a union of all aliases.

        `PYSEC`-identified results are given priority over other results.
        """
        specs = source.collect()

        if self._options.dry_run:
            # Drain the iterator in dry-run mode.
            logger.info(f"Dry run: would have audited {len(list(specs))} packages")
            yield from ()
        else:
            specs = _enforce_confidentiality(self._service, specs)
            for dep, vulns in self._service.query_all(specs):
                # Defensive: a service could echo or synthesize a dependency. If an
                # internal-source dependency comes back from a service that is not
                # permitted to see internal names, do not trust its result.
                if (
                    dep.source == INTERNAL_SOURCE
                    and not self._service.supports_internal_queries
                ):
                    dep = SkippedDependency(
                        name=dep.name,
                        source=dep.source,
                        skip_reason=UNROUTED_INTERNAL_REASON,
                        policy_skipped=True,
                    )
                    vulns = []

                unique_vulns: list[VulnerabilityResult] = []
                seen_aliases: set[str] = set()

                # First pass, add all PYSEC vulnerabilities and track their
                # alias sets.
                for v in vulns:
                    if not v.id.startswith("PYSEC"):
                        continue

                    _add_unique_vulnerability(unique_vulns, seen_aliases, v)

                # Second pass: add any non-PYSEC vulnerabilities.
                for v in vulns:
                    # If we've already seen this vulnerability by another name,
                    # don't add it. Instead, find the previous result and update
                    # its alias set.
                    _add_unique_vulnerability(unique_vulns, seen_aliases, v)

                yield dep, unique_vulns
