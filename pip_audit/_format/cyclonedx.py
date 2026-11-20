"""
Functionality for formatting vulnerability results using the CycloneDX SBOM format.
"""

from __future__ import annotations

import enum
import logging
import uuid
from typing import cast

from cyclonedx import output
from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.model.vulnerability import BomTarget, Vulnerability

import pip_audit._fix as fix
import pip_audit._service as service
from pip_audit._subject import AuditSubject

from .interface import VulnerabilityFormat, dep_sort_key, result_summary

logger = logging.getLogger(__name__)


def _pip_audit_result_to_bom(
    result: dict[service.Dependency, list[service.VulnerabilityResult]],
    fixes: list[fix.FixVersion],
    subject: AuditSubject | None,
) -> Bom:
    vulnerabilities = []
    components = []

    for dep in sorted(result, key=dep_sort_key):
        vulns = result[dep]
        # TODO(alex): Is there anything interesting we can do with skipped dependencies in
        # the CycloneDX format?
        if dep.is_skipped():
            continue
        dep = cast(service.ResolvedDependency, dep)

        # A deterministic bom-ref (the package's purl) keeps the output
        # comparable across runs, regardless of collection order.
        c = Component(
            name=dep.name,
            version=str(dep.version),
            bom_ref=f"pkg:pypi/{dep.canonical_name}@{dep.version}",
        )
        vuln_list = [
            Vulnerability(
                id=vuln.id,
                description=vuln.description,
                recommendation="Upgrade",
                # BomTarget expects str in type hints, but accepts BomRef at runtime
                affects=[BomTarget(ref=c.bom_ref)],  # type: ignore[arg-type]
            )
            for vuln in sorted(vulns, key=lambda v: v.id)
        ]
        vulnerabilities.extend(vuln_list)
        components.append(c)

    bom = Bom(components=components, vulnerabilities=vulnerabilities)

    properties = bom.metadata.properties
    for name, value in result_summary(result, fixes).items():
        properties.add(Property(name=f"pip_audit:summary:{name}", value=str(value)))

    if subject is not None:
        properties.add(Property(name="pip_audit:subject:source", value=subject.source))
        properties.add(
            Property(
                name="pip_audit:subject:dependencies_sha256",
                value=subject.dependencies_sha256,
            )
        )
        for index, input_ in enumerate(subject.inputs):
            properties.add(
                Property(name=f"pip_audit:subject:inputs:{index}:path", value=input_.path)
            )
            properties.add(
                Property(name=f"pip_audit:subject:inputs:{index}:sha256", value=input_.sha256)
            )

        # A serial number derived from the dependency set lets sign-off
        # verification confirm that a report corresponds to the same
        # dependencies, without embedding workspace-specific details.
        bom.serial_number = uuid.uuid5(
            uuid.NAMESPACE_URL, f"pip-audit:{subject.dependencies_sha256}"
        )

    return bom


class CycloneDxFormat(VulnerabilityFormat):
    """
    An implementation of `VulnerabilityFormat` that formats vulnerability results using CycloneDX.
    The container format used by CycloneDX can be additionally configured.
    """

    @enum.unique
    class InnerFormat(enum.Enum):
        """
        Valid container formats for CycloneDX.
        """

        Json = output.OutputFormat.JSON
        Xml = output.OutputFormat.XML

    def __init__(self, inner_format: CycloneDxFormat.InnerFormat):
        """
        Create a new `CycloneDxFormat`.

        `inner_format` determines the container format used by CycloneDX.
        """

        self._inner_format = inner_format

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
        Returns a CycloneDX formatted string for a given mapping of dependencies to vulnerability
        results.

        See `VulnerabilityFormat.format`.
        """
        if fixes:
            logger.warning("--fix output is unsupported by CycloneDX formats")

        bom = _pip_audit_result_to_bom(result, fixes, subject)
        formatter = output.make_outputter(
            bom=bom,
            output_format=self._inner_format.value,
            schema_version=output.SchemaVersion.V1_4,
        )

        return formatter.output_as_string()
