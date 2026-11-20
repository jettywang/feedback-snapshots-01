"""
Functionality for formatting vulnerability results as an array of JSON objects.
"""

from __future__ import annotations

import json
from typing import Any, cast

import pip_audit._fix as fix
import pip_audit._service as service
from pip_audit._subject import AuditSubject

from .interface import VulnerabilityFormat, dep_sort_key, result_summary


class JsonFormat(VulnerabilityFormat):
    """
    An implementation of `VulnerabilityFormat` that formats vulnerability results as an array of
    JSON objects.
    """

    def __init__(self, output_desc: bool, output_aliases: bool):
        """
        Create a new `JsonFormat`.

        `output_desc` is a flag to determine whether descriptions for each vulnerability should be
        included in the output as they can be quite long and make the output difficult to read.

        `output_aliases` is a flag to determine whether aliases (such as CVEs) for each
        vulnerability should be included in the output.
        """
        self.output_desc = output_desc
        self.output_aliases = output_aliases

    @property
    def is_manifest(self) -> bool:
        """
        See `VulnerabilityFormat.is_manifest`.
        """
        return True

    def format(
        self,
        result: dict[service.Dependency, list[service.VulnerabilityResult]],
        fixes: list[fix.FixVersion],
        subject: AuditSubject | None = None,
    ) -> str:
        """
        Returns a JSON formatted string for a given mapping of dependencies to vulnerability
        results.

        Dependencies, vulnerabilities, and fixes are emitted in a deterministic
        (sorted) order, so that two audits of the same dependency set produce
        comparable output regardless of collection order.

        See `VulnerabilityFormat.format`.
        """
        output_json: dict[str, Any] = {}
        if subject is not None:
            output_json["subject"] = self._format_subject(subject)
        output_json["summary"] = result_summary(result, fixes)
        output_json["dependencies"] = [
            self._format_dep(dep, result[dep]) for dep in sorted(result, key=dep_sort_key)
        ]
        output_json["fixes"] = [
            self._format_fix(f) for f in sorted(fixes, key=lambda f: dep_sort_key(f.dep))
        ]
        return json.dumps(output_json)

    def _format_subject(self, subject: AuditSubject) -> dict[str, Any]:
        return {
            "source": subject.source,
            "inputs": [{"path": input_.path, "sha256": input_.sha256} for input_ in subject.inputs],
            "dependencies_sha256": subject.dependencies_sha256,
        }

    def _format_dep(
        self, dep: service.Dependency, vulns: list[service.VulnerabilityResult]
    ) -> dict[str, Any]:
        if dep.is_skipped():
            dep = cast(service.SkippedDependency, dep)
            return {
                "name": dep.canonical_name,
                "skip_reason": dep.skip_reason,
            }

        dep = cast(service.ResolvedDependency, dep)
        return {
            "name": dep.canonical_name,
            "version": str(dep.version),
            "vulns": [self._format_vuln(vuln) for vuln in sorted(vulns, key=lambda v: v.id)],
        }

    def _format_vuln(self, vuln: service.VulnerabilityResult) -> dict[str, Any]:
        vuln_json = {
            "id": vuln.id,
            "fix_versions": [str(version) for version in sorted(vuln.fix_versions)],
        }
        if self.output_aliases:
            vuln_json["aliases"] = sorted(vuln.aliases)
        if self.output_desc:
            vuln_json["description"] = vuln.description
        return vuln_json

    def _format_fix(self, fix_version: fix.FixVersion) -> dict[str, Any]:
        if fix_version.is_skipped():
            fix_version = cast(fix.SkippedFixVersion, fix_version)
            return {
                "name": fix_version.dep.canonical_name,
                "version": str(fix_version.dep.version),
                "skip_reason": fix_version.skip_reason,
            }
        fix_version = cast(fix.ResolvedFixVersion, fix_version)
        return {
            "name": fix_version.dep.canonical_name,
            "old_version": str(fix_version.dep.version),
            "new_version": str(fix_version.version),
        }
