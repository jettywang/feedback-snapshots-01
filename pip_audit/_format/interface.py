"""
Interfaces for formatting vulnerability results into a string representation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import cast

import pip_audit._fix as fix
import pip_audit._service as service
from pip_audit._subject import AuditSubject


def vuln_id_url(vuln_id: str) -> str:
    """Return the OSV URL for a vulnerability ID."""
    return f"https://osv.dev/vulnerability/{vuln_id}"


def pypi_url(name: str) -> str:
    """Return the PyPI URL for a package."""
    return f"https://pypi.org/project/{name}/"


def dep_sort_key(dep: service.Dependency) -> tuple[str, str]:
    """
    Return a deterministic sort key for a dependency, so that machine-readable
    output is comparable regardless of the order in which dependencies were
    collected.
    """
    if dep.is_skipped():
        return (dep.canonical_name, "")
    dep = cast(service.ResolvedDependency, dep)
    return (dep.canonical_name, str(dep.version))


def result_summary(
    result: dict[service.Dependency, list[service.VulnerabilityResult]],
    fixes: list[fix.FixVersion],
) -> dict[str, int]:
    """
    Return a machine-readable summary of an audit result.
    """
    skipped = sum(1 for dep in result if dep.is_skipped())
    return {
        "dependencies": len(result) - skipped,
        "skipped": skipped,
        "vulnerabilities": sum(len(vulns) for vulns in result.values()),
        "fixes": len(fixes),
    }


class VulnerabilityFormat(ABC):
    """
    Represents an abstract string representation for vulnerability results.
    """

    @property
    @abstractmethod
    def is_manifest(self) -> bool:  # pragma: no cover
        """
        Is this format a "manifest" format, i.e. one that prints a summary
        of all results?

        Manifest formats are always rendered emitted unconditionally, even
        if the audit results contain nothing out of the ordinary
        (no vulnerabilities, skips, or fixes).
        """
        raise NotImplementedError

    @abstractmethod
    def format(
        self,
        result: dict[service.Dependency, list[service.VulnerabilityResult]],
        fixes: list[fix.FixVersion],
        subject: AuditSubject | None = None,
    ) -> str:  # pragma: no cover
        """
        Convert a mapping of dependencies to vulnerabilities into a string.

        `subject`, when given, describes the audit's subject (the selected
        dependency source and its inputs) for formats that can embed it.
        """
        raise NotImplementedError
