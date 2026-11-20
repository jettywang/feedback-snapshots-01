"""
Policy-aware routing between a public vulnerability service and an
internal/private advisory service.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import replace

from pip_audit._service.interface import (
    INTERNAL_SOURCE,
    ConnectionError,
    Dependency,
    ServiceError,
    SkippedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)

logger = logging.getLogger(__name__)

#: Skip reason used when an internal-source dependency cannot be checked because
#: no internal advisory service was configured.
NO_INTERNAL_SERVICE_REASON = (
    "not audited: package originates from an internal source, but no internal "
    "vulnerability service is configured; add --internal-vulnerability-service-url"
)

#: Skip reason used when the internal advisory service is configured but unreachable.
INTERNAL_SERVICE_UNAVAILABLE_REASON = (
    "not audited: package originates from an internal source and the internal "
    "vulnerability service is unavailable"
)


def _is_internal(dep: Dependency) -> bool:
    return dep.source == INTERNAL_SOURCE


class RoutingService(VulnerabilityService):
    """
    A `VulnerabilityService` that enforces a confidentiality policy between two
    backends.

    Dependencies whose `source` is `INTERNAL_SOURCE` are sent *only* to the
    internal advisory service, and are never disclosed to the public service.
    All other dependencies (including those with no declared source) are sent to
    the public service as usual.

    If an internal dependency cannot be checked -- because no internal service was
    provided or because it raised an error -- the result is an explicit
    `SkippedDependency` marked with `policy_skipped=True`, so that the coverage gap
    is visible rather than being silently reported as "no vulnerabilities".
    """

    def __init__(
        self,
        public_service: VulnerabilityService,
        internal_service: VulnerabilityService | None = None,
    ) -> None:
        """
        Create a new `RoutingService`.

        `public_service` handles all public dependencies. It must not receive
        internal package names.

        `internal_service` handles internal dependencies. If `None`, internal
        dependencies are reported as policy-skipped.
        """
        self._public_service = public_service
        self._internal_service = internal_service

    @property
    def public_service(self) -> VulnerabilityService:
        """The service used for public dependencies."""
        return self._public_service

    @property
    def internal_service(self) -> VulnerabilityService | None:
        """The service used for internal dependencies, if configured."""
        return self._internal_service

    @property
    def supports_internal_queries(self) -> bool:
        """
        See `VulnerabilityService.supports_internal_queries`.
        """
        return True

    def _skip(self, dep: Dependency, reason: str) -> tuple[Dependency, list[VulnerabilityResult]]:
        return (
            SkippedDependency(
                name=dep.name,
                source=dep.source,
                skip_reason=reason,
                policy_skipped=True,
            ),
            [],
        )

    def query(self, spec: Dependency) -> tuple[Dependency, list[VulnerabilityResult]]:
        """
        Route a single dependency according to the confidentiality policy.

        See `VulnerabilityService.query`.
        """
        if not _is_internal(spec):
            return self._public_service.query(spec)

        # A dependency that was already skipped during collection has no package
        # name to disclose and nothing to query.
        if spec.is_skipped():
            return spec, []

        if self._internal_service is None:
            logger.debug(f"internal service unavailable for '{spec.canonical_name}'; skipping")
            return self._skip(spec, NO_INTERNAL_SERVICE_REASON)

        try:
            dep, vulns = self._internal_service.query(spec)
        except (ConnectionError, ServiceError) as exc:
            logger.warning(
                f"internal vulnerability service unavailable while checking "
                f"'{spec.canonical_name}': {exc}"
            )
            return self._skip(spec, f"{INTERNAL_SERVICE_UNAVAILABLE_REASON}: {exc}")

        # Preserve provenance even if the backend returned a fresh dependency object.
        if dep.source != spec.source:
            dep = replace(dep, source=spec.source)
        return dep, vulns

    def query_all(
        self, specs: Iterator[Dependency]
    ) -> Iterator[tuple[Dependency, list[VulnerabilityResult]]]:
        """
        Route a stream of dependencies according to the confidentiality policy.

        Public dependencies within a contiguous run are handed to the public
        service as a stream, so batched public services can still batch their
        requests. Internal dependencies are handled individually by the internal
        service.
        """
        public_batch: list[Dependency] = []
        for spec in specs:
            if not _is_internal(spec):
                public_batch.append(spec)
                continue

            if public_batch:
                yield from self._public_service.query_all(iter(public_batch))
                public_batch.clear()
            yield self.query(spec)

        if public_batch:
            yield from self._public_service.query_all(iter(public_batch))
