# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Project ownership constraints for adapters.

OpenStack service catalogs and discovery documents are frequently identical
for two projects which happen to use the same host.  URL equality is therefore
not sufficient evidence that a token scoped to one project may send a business
request to an endpoint selected by another project's catalog.

The objects in this module are intentionally optional.  An adapter without a
constraint keeps the historical behavior.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
import enum
import inspect
import posixpath
import threading
import time
from typing import Any
import urllib.parse

from keystoneauth1 import exceptions


STATE_DISCOVERED = 'discovered'
STATE_VERIFIED = 'verified'
STATE_READY = 'ready'
STATE_STALE = 'stale'
STATE_CATALOG_UNAVAILABLE = 'catalog_unavailable'
STATE_BLOCKED = 'blocked'
STATE_MISMATCH = 'mismatch'
STATE_SENT = 'sent'
STATE_STOPPED = 'stopped'

_VALID_STATES = frozenset(
    {
        STATE_DISCOVERED,
        STATE_VERIFIED,
        STATE_READY,
        STATE_STALE,
        STATE_CATALOG_UNAVAILABLE,
        STATE_BLOCKED,
        STATE_MISMATCH,
        STATE_SENT,
        STATE_STOPPED,
    }
)


class ProjectOwnershipState(str, enum.Enum):
    """Recognizable ownership/selection states."""

    DISCOVERED = STATE_DISCOVERED
    VERIFIED = STATE_VERIFIED
    READY = STATE_READY
    STALE = STATE_STALE
    CATALOG_UNAVAILABLE = STATE_CATALOG_UNAVAILABLE
    BLOCKED = STATE_BLOCKED
    MISMATCH = STATE_MISMATCH
    SENT = STATE_SENT
    STOPPED = STATE_STOPPED


ProjectState = ProjectOwnershipState
EndpointOwnershipState = ProjectOwnershipState


class ProjectAttestation:
    """Proof that a catalog/discovery/request belongs to one project."""

    def __init__(
        self,
        *,
        project_id: str | None,
        allowed_project_ids: Iterable[str] | None = None,
        state: str = STATE_VERIFIED,
        source: str = 'adapter',
        url: str | None = None,
        catalog_url: str | None = None,
        service_url: str | None = None,
        service_type: str | None = None,
        service_name: str | None = None,
        interface: str | None = None,
        region_name: str | None = None,
        endpoint_id: str | None = None,
        api_version: Any | None = None,
        version: Any | None = None,
        min_microversion: Any | None = None,
        max_microversion: Any | None = None,
        auth_generation: int | str | None = None,
        reason: str | None = None,
    ) -> None:
        self.project_id = project_id
        self.allowed_project_ids = frozenset(allowed_project_ids or ())
        self.state = state if state in _VALID_STATES else STATE_VERIFIED
        self.source = source
        self.url = url or service_url or catalog_url
        self.catalog_url = catalog_url
        self.service_url = service_url
        self.service_type = service_type
        self.service_name = service_name
        self.interface = interface
        self.region_name = region_name
        self.endpoint_id = endpoint_id
        self.api_version = api_version
        self.version = version if version is not None else api_version
        self.min_microversion = min_microversion
        self.max_microversion = max_microversion
        self.auth_generation = auth_generation
        self.reason = reason

    @property
    def verified(self) -> bool:
        return self.state in {STATE_VERIFIED, STATE_READY, STATE_SENT}

    def to_dict(self) -> dict[str, Any]:
        return {
            'project_id': self.project_id,
            'allowed_project_ids': sorted(self.allowed_project_ids),
            'state': self.state,
            'source': self.source,
            'url': self.url,
            'catalog_url': self.catalog_url,
            'service_url': self.service_url,
            'service_type': self.service_type,
            'service_name': self.service_name,
            'interface': self.interface,
            'region_name': self.region_name,
            'endpoint_id': self.endpoint_id,
            'api_version': self.api_version,
            'version': self.version,
            'min_microversion': self.min_microversion,
            'max_microversion': self.max_microversion,
            'auth_generation': self.auth_generation,
            'reason': self.reason,
            'verified': self.verified,
        }

    def __repr__(self) -> str:
        return (
            'ProjectAttestation('
            f'project_id={self.project_id!r}, state={self.state!r}, '
            f'url={self.url!r}, version={self.version!r})'
        )


class ProjectConstraint:
    """Allowed project identities and an audit trail of ownership checks."""

    def __init__(
        self,
        project_id: str | None = None,
        allowed_project_ids: str | Iterable[str] | None = None,
        *,
        expected_project_id: str | None = None,
        required_project_id: str | None = None,
        owner_project_id: str | None = None,
        bound_project_id: str | None = None,
        project_ids: str | Iterable[str] | None = None,
        allowed_projects: str | Iterable[str] | None = None,
        auto_bind: bool = False,
        allow_unknown_project: bool = False,
        verifier: Callable[..., bool | None] | None = None,
        wait_timeout: float | None = 0.0,
        retry_interval: float = 0.01,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        primary_project_id = (
            project_id
            or expected_project_id
            or required_project_id
            or owner_project_id
            or bound_project_id
        )
        ids: set[str] = set()
        if primary_project_id:
            primary_project_id = getattr(
                primary_project_id, 'id', primary_project_id
            )
            if isinstance(primary_project_id, dict):
                primary_project_id = primary_project_id.get('id')
            if primary_project_id:
                ids.add(str(primary_project_id))
        for values in (
            allowed_project_ids,
            project_ids,
            allowed_projects,
        ):
            if values is None:
                continue
            if isinstance(values, str):
                ids.add(values)
            else:
                for item in values:
                    item = getattr(item, 'id', item)
                    if isinstance(item, dict):
                        item = item.get('id')
                    if item:
                        ids.add(str(item))

        self.allowed_project_ids = frozenset(ids)
        self.auto_bind = auto_bind or (not ids and not allow_unknown_project)
        self.allow_unknown_project = allow_unknown_project
        self.verifier = verifier
        self.wait_timeout = wait_timeout or 0.0
        self.retry_interval = retry_interval
        self._sleep = sleep
        self._lock = threading.RLock()
        self.attestations: list[ProjectAttestation] = []
        self.sends: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.stop_reasons: list[BaseException] = []

    @classmethod
    def coerce(
        cls,
        value: Any,
        **options: Any,
    ) -> 'ProjectConstraint | None':
        if value is None or value is False:
            return None
        if isinstance(value, ProjectConstraint):
            return value
        if isinstance(value, dict):
            return cls(**value, **options)
        if value is True or value == 'auto':
            options.setdefault('auto_bind', True)
            return cls(**options)
        if isinstance(value, str):
            return cls(project_id=value, **options)
        if callable(value):
            return cls(verifier=value, **options)

        attribute_project_id = getattr(value, 'project_id', None)
        attribute_allowed = getattr(value, 'allowed_project_ids', None)
        if attribute_project_id or attribute_allowed:
            return cls(
                project_id=attribute_project_id,
                allowed_project_ids=attribute_allowed,
                **options,
            )

        for method_name in (
            'verify',
            'check',
            'check_project',
            'allows',
            'is_allowed',
            'matches',
        ):
            method = getattr(value, method_name, None)
            if callable(method):
                return cls(verifier=method, **options)
        if isinstance(value, Iterable):
            return cls(allowed_project_ids=value, **options)
        raise TypeError(f'Unsupported project constraint: {value!r}')

    @property
    def project_id(self) -> str | None:
        """The sole allowed project, when the constraint is singular."""
        with self._lock:
            if len(self.allowed_project_ids) == 1:
                return next(iter(self.allowed_project_ids))
            return None

    @property
    def bound_project_id(self) -> str | None:
        return self.project_id

    @property
    def expected_project_id(self) -> str | None:
        return self.project_id

    @property
    def required_project_id(self) -> str | None:
        return self.project_id

    def record(
        self, attestation: ProjectAttestation
    ) -> ProjectAttestation:
        return self._record(attestation)

    def _record(self, attestation: ProjectAttestation) -> ProjectAttestation:
        with self._lock:
            self.attestations.append(attestation)
            event = attestation.to_dict()
            event['kind'] = 'attestation'
            self.events.append(event)
        return attestation

    @property
    def observations(self) -> list[dict[str, Any]]:
        return self.events

    def stop(self, exc: BaseException) -> None:
        with self._lock:
            self.stop_reasons.append(exc)

    def _run_verifier(
        self,
        *,
        project_id: str,
        url: str | None,
        endpoint_data: Any | None,
    ) -> bool | None:
        assert self.verifier is not None
        payload = {
            'project_id': project_id,
            'url': url,
            'endpoint_data': endpoint_data,
            'constraint': self,
        }
        try:
            signature = inspect.signature(self.verifier)
        except (TypeError, ValueError):
            return self.verifier(project_id)

        parameters = signature.parameters
        if any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values()
        ):
            return self.verifier(**payload)

        accepted = {
            name: value
            for name, value in payload.items()
            if name in parameters
        }
        positional = [
            parameter
            for parameter in parameters.values()
            if parameter.kind
            in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ]
        if positional and positional[0].name not in accepted:
            accepted[positional[0].name] = project_id
        return self.verifier(**accepted)

    def check_project(
        self,
        project_id: str | None,
        *,
        url: str | None = None,
        endpoint_data: Any | None = None,
        reason: str | None = None,
    ) -> ProjectAttestation:
        """Check current authentication evidence against this constraint."""
        with self._lock:
            if not project_id:
                if self.allow_unknown_project:
                    attestation = ProjectAttestation(
                        project_id=None,
                        allowed_project_ids=self.allowed_project_ids,
                        state=STATE_VERIFIED,
                        reason=reason or 'project identity not available',
                        url=url,
                    )
                    return self._record(attestation)
                exc = exceptions.ProjectIdentityUnavailable(
                    state=STATE_BLOCKED,
                    reason=reason or 'project_id is required',
                    url=url,
                    expected_project_ids=sorted(self.allowed_project_ids),
                )
                self.stop(exc)
                raise exc

            project_id = str(project_id)
            if self.auto_bind and not self.allowed_project_ids:
                # The constraint starts in auto-bind mode and becomes singular
                # once the first authenticated project provides evidence.
                self.allowed_project_ids = frozenset({project_id})

            if (
                self.allowed_project_ids
                and project_id not in self.allowed_project_ids
            ):
                exc = exceptions.ProjectMismatch(
                    f"Project {project_id!r} is not permitted by project "
                    f"constraint {sorted(self.allowed_project_ids)!r}.",
                    project_id=project_id,
                    expected_project_ids=sorted(self.allowed_project_ids),
                    state=STATE_MISMATCH,
                    reason=reason or 'project mismatch',
                    url=url,
                )
                self.stop(exc)
                raise exc

            if self.verifier is not None:
                result = self._run_verifier(
                    project_id=project_id,
                    url=url,
                    endpoint_data=endpoint_data,
                )
                if result is False:
                    exc = exceptions.ProjectConstraintViolation(
                        project_id=project_id,
                        state=STATE_MISMATCH,
                        reason=reason or 'custom project verifier rejected',
                        url=url,
                    )
                    self.stop(exc)
                    raise exc

            attestation = ProjectAttestation(
                project_id=project_id,
                allowed_project_ids=self.allowed_project_ids,
                state=STATE_VERIFIED,
                reason=reason,
                url=url,
            )
            return self._record(attestation)

    def attest_endpoint_data(
        self,
        endpoint_data: Any,
        project_id: str | None = None,
        *,
        source: str = 'catalog',
        auth_generation: int | str | None = None,
        state: str = STATE_VERIFIED,
        reason: str | None = None,
    ) -> ProjectAttestation:
        """Annotate and verify a catalog/discovery EndpointData object."""
        data_project = getattr(endpoint_data, 'project_id', None)
        if data_project is not None:
            data_project = str(data_project)
        if project_id is not None:
            project_id = str(project_id)

        if data_project and project_id and data_project != project_id:
            exc = exceptions.ProjectMismatch(
                f"Endpoint evidence belongs to project {data_project!r}, "
                f"but current authentication evidence is {project_id!r}.",
                project_id=project_id,
                expected_project_ids=[data_project],
                state=STATE_MISMATCH,
                reason='catalog project does not match auth project',
                url=getattr(endpoint_data, 'url', None),
            )
            self.stop(exc)
            raise exc

        effective_project = project_id or data_project
        identity = self.check_project(
            effective_project,
            url=getattr(endpoint_data, 'url', None),
            endpoint_data=endpoint_data,
            reason=reason,
        )

        attestation = ProjectAttestation(
            project_id=identity.project_id,
            allowed_project_ids=self.allowed_project_ids,
            state=state,
            source=source,
            url=getattr(endpoint_data, 'url', None),
            catalog_url=getattr(endpoint_data, 'catalog_url', None),
            service_url=getattr(endpoint_data, 'service_url', None),
            service_type=getattr(endpoint_data, 'service_type', None),
            service_name=getattr(endpoint_data, 'service_name', None),
            interface=getattr(endpoint_data, 'interface', None),
            region_name=getattr(endpoint_data, 'region_name', None),
            endpoint_id=getattr(endpoint_data, 'endpoint_id', None),
            api_version=getattr(endpoint_data, 'api_version', None),
            min_microversion=getattr(
                endpoint_data, 'min_microversion', None
            ),
            max_microversion=getattr(
                endpoint_data, 'max_microversion', None
            ),
            auth_generation=auth_generation,
            reason=reason,
        )

        # EndpointData accepts these in modern copies.  Setting attributes
        # directly also works for test doubles that use a simpler object.
        try:
            endpoint_data.project_id = attestation.project_id
            endpoint_data.project_ownership = attestation
            endpoint_data.ownership_state = attestation.state
            endpoint_data.auth_generation = auth_generation
        except Exception:  # noqa: S110 - best-effort annotation
            pass

        self._record(attestation)
        return attestation

    def check_send_url(
        self,
        url: str,
        attestation: ProjectAttestation | None,
        *,
        method: str | None = None,
        headers: Any | None = None,
    ) -> dict[str, Any]:
        """Verify a final requests URL immediately before a real send."""
        if attestation is None:
            exc = exceptions.ProjectEndpointBlocked(
                "Cannot send without project ownership evidence.",
                state=STATE_BLOCKED,
                url=url,
            )
            self.stop(exc)
            raise exc

        if attestation.project_id:
            self.check_project(attestation.project_id, url=url)

        if attestation.url and not urls_share_endpoint(
            attestation.url, url
        ):
            exc = exceptions.ProjectMismatch(
                f"Actual request URL {url!r} is outside project endpoint "
                f"{attestation.url!r}.",
                project_id=attestation.project_id,
                expected_project_ids=sorted(self.allowed_project_ids),
                state=STATE_MISMATCH,
                reason='send URL does not match verified endpoint',
                url=url,
            )
            self.stop(exc)
            raise exc

        record = {
            'kind': 'send',
            'method': method,
            'url': url,
            'project_id': attestation.project_id,
            'version': attestation.version,
            'api_version': attestation.api_version,
            'auth_generation': attestation.auth_generation,
            'state': STATE_SENT,
            'source': 'send',
        }
        with self._lock:
            self.sends.append(record)
            self.events.append(dict(record))
        return record

    def wait(
        self,
        ready: Callable[[], ProjectAttestation | None],
        *,
        timeout: float | None = None,
        interval: float | None = None,
    ) -> ProjectAttestation:
        """Poll for fresh catalog evidence until ready or timeout."""
        timeout = self.wait_timeout if timeout is None else timeout
        interval = self.retry_interval if interval is None else interval
        deadline = time.monotonic() + max(0.0, timeout or 0.0)

        while True:
            attestation = ready()
            if attestation is not None:
                return attestation
            if time.monotonic() >= deadline:
                raise exceptions.ProjectCatalogUnavailable(
                    "Project catalog evidence did not recover before the "
                    "constraint wait timeout.",
                    state=STATE_CATALOG_UNAVAILABLE,
                )
            self._sleep(interval)


def urls_share_endpoint(endpoint_url: str, actual_url: str) -> bool:
    """Return whether ``actual_url`` is rooted at ``endpoint_url``."""
    endpoint = urllib.parse.urlparse(endpoint_url)
    actual = urllib.parse.urlparse(actual_url)

    if endpoint.scheme.lower() != actual.scheme.lower():
        return False
    if endpoint.netloc.lower() != actual.netloc.lower():
        return False

    endpoint_path = posixpath.normpath(endpoint.path or '/')
    actual_path = posixpath.normpath(actual.path or '/')
    if endpoint_path == actual_path:
        return True

    prefix = endpoint_path.rstrip('/') + '/'
    return actual_path.startswith(prefix)


# Common alternative names for the same concept.
ProjectAffinity = ProjectConstraint
ProjectBoundary = ProjectConstraint
ProjectGuard = ProjectConstraint
ProjectScope = ProjectConstraint
ProjectOwnership = ProjectConstraint
OwnershipConstraint = ProjectConstraint
OwnershipAttestation = ProjectAttestation
