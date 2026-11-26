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

import argparse
from collections.abc import MutableMapping
import hashlib
import logging
import os
import threading
from typing import Any
import urllib.parse
import warnings

import requests
import requests.structures

from keystoneauth1 import _fair_semaphore
from keystoneauth1 import discover
from keystoneauth1 import exceptions
from keystoneauth1 import plugin
from keystoneauth1 import project as project_ownership
from keystoneauth1 import session as _session


ProjectConstraint = project_ownership.ProjectConstraint
ProjectOwnership = project_ownership.ProjectOwnership
ProjectAttestation = project_ownership.ProjectAttestation
ProjectBoundary = project_ownership.ProjectBoundary
ProjectGuard = project_ownership.ProjectGuard
ProjectState = project_ownership.ProjectOwnershipState
STATE_STALE = project_ownership.STATE_STALE
STATE_VERIFIED = project_ownership.STATE_VERIFIED
STATE_CATALOG_UNAVAILABLE = (
    project_ownership.STATE_CATALOG_UNAVAILABLE
)
STATE_MISMATCH = project_ownership.STATE_MISMATCH
STATE_BLOCKED = project_ownership.STATE_BLOCKED
STATE_SENT = project_ownership.STATE_SENT
ProjectOwnershipError = exceptions.ProjectOwnershipError
ProjectMismatch = exceptions.ProjectMismatch
StaleProjectEndpoint = exceptions.StaleProjectEndpoint
ProjectCatalogUnavailable = exceptions.ProjectCatalogUnavailable


class _BaseAdapter:
    """An instance of a session with local variables.

    A session is a global object that is shared around amongst many clients. It
    therefore contains state that is relevant to everyone. There is a lot of
    state such as the service type and region_name that are only relevant to a
    particular client that is using the session. An adapter provides a wrapper
    of client local data around the global session object.

    version, min_version, max_version and default_microversion can all be
    given either as a string or a tuple.

    :param session: The session object to wrap.
    :param service_type: The default service_type for URL discovery.
    :param service_name: The default service_name for URL discovery.
    :param interface: The default interface for URL discovery.
    :param region_name: The default region_name for URL discovery.
    :param endpoint_override: Always use this endpoint URL for requests for
        this client.
    :param version: The minimum version restricted to a given Major API.
        Mutually exclusive with min_version and max_version. (optional)
    :param auth: An auth plugin to use instead of the session one.
    :param user_agent: The User-Agent string to set.
    :param connect_retries: The maximum number of retries that should be
        attempted for connection errors. Default None - use session default
        which is don't retry.
    :param logger: A logging object to use for requests that pass through this
        adapter.
    :param allow: Extra filters to pass when discovering API versions.
        (optional)
    :param additional_headers: Additional headers that should be attached to
        every request passing through the adapter. Headers of the same name
        specified per request will take priority.
    :param client_name: The name of the client that created the adapter. This
        will be used to create the user_agent.
    :param client_version: The version of the client that created the adapter.
        This will be used to create the user_agent.
    :param allow_version_hack: Allow keystoneauth to hack up catalog URLS to
        support older schemes. (optional, default True)
    :param global_request_id: A global_request_id (in the form of
        ``req-$uuid``) that will be passed on all requests. Enables cross
        project request id tracking.
    :param min_version: The minimum major version of a given API, intended to
        be used as the lower bound of a range with max_version. Mutually
        exclusive with version. If min_version is given with no max_version it
        is as if max version is 'latest'. (optional)
    :param max_version: The maximum major version of a given API, intended to
        be used as the upper bound of a range with min_version. Mutually
        exclusive with version. (optional)
    :param default_microversion: The default microversion value to send with
        API requests. While microversions are a per-request feature, a user may
        know they want to default to sending a specific value.  (optional)
    :param status_code_retries: The maximum number of retries that should be
        attempted for retriable HTTP status codes (optional, defaults to 0 -
        never retry).
    :param retriable_status_codes: List of HTTP status codes that should be
        retried (optional, defaults to HTTP 503, has no effect when
        status_code_retries is 0).
    :param raise_exc: If True, requests returning failing HTTP responses will
        raise an exception; if False, the response is returned. This can be
        overridden on a per-request basis via the kwarg of the same name.
    :param rate_limit: A client-side rate limit to impose on requests made
        through this adapter in requests per second. For instance, a rate_limit
        of 2 means to allow no more than 2 requests per second, and a
        rate_limit of 0.5 means to allow no more than 1 request every two
        seconds. (optional, defaults to None, which means no rate limiting will
        be applied).
    :param concurrency: How many simultaneous http requests this Adapter can be
        used for. (optional, defaults to None, which means no limit).
    :param connect_retry_delay: Delay (in seconds) between two connect retries
        (if enabled). By default exponential retry starting with 0.5 seconds up
        to a maximum of 60 seconds is used.
    :param status_code_retry_delay: Delay (in seconds) between two status code
        retries (if enabled). By default exponential retry starting with 0.5
        seconds up to a maximum of 60 seconds is used.
    """

    session: _session.Session
    service_type: str | None
    service_name: str | None
    interface: str | list[str] | None
    region_name: str | None
    endpoint_override: str | None
    version: str | None
    auth: plugin.BaseAuthPlugin | None
    user_agent: str | None
    connect_retries: int | None
    logger: logging.Logger | None
    allow: dict[str, Any]
    additional_headers: MutableMapping[str, str]
    client_name: str | None = None
    client_version: str | None = None
    allow_version_hack: bool | None
    global_request_id: str | None
    min_version: str | None
    max_version: str | None
    default_microversion: str | None
    status_code_retries: int | None
    retriable_status_codes: list[int] | None
    raise_exc: bool | None
    connect_retry_delay: float | None
    status_code_retry_delay: float | None
    project_constraint: ProjectConstraint | None

    def __init__(
        self,
        session: _session.Session,
        service_type: str | None = None,
        service_name: str | None = None,
        interface: str | list[str] | None = None,
        region_name: str | None = None,
        endpoint_override: str | None = None,
        version: str | None = None,
        auth: plugin.BaseAuthPlugin | None = None,
        user_agent: str | None = None,
        connect_retries: int | None = None,
        logger: logging.Logger | None = None,
        allow: dict[str, Any] | None = None,
        additional_headers: MutableMapping[str, str] | None = None,
        client_name: str | None = None,
        client_version: str | None = None,
        allow_version_hack: bool | None = None,
        global_request_id: str | None = None,
        min_version: str | None = None,
        max_version: str | None = None,
        default_microversion: str | None = None,
        status_code_retries: int | None = None,
        retriable_status_codes: list[int] | None = None,
        raise_exc: bool | None = None,
        rate_limit: float | None = None,
        concurrency: int | None = None,
        connect_retry_delay: float | None = None,
        status_code_retry_delay: float | None = None,
        project_constraint: project_ownership.ProjectConstraint
        | str
        | list[str]
        | tuple[str, ...]
        | set[str]
        | bool
        | None = None,
        project_id: str | None = None,
        allowed_project_ids: (
            str | list[str] | tuple[str, ...] | set[str] | None
        ) = None,
        required_project_id: str | None = None,
        project_verifier: Any | None = None,
        **kwargs: Any,
    ):
        if version and (min_version or max_version):
            raise TypeError(
                "version is mutually exclusive with min_version and"
                " max_version"
            )

        project_aliases = (
            'expected_project_id',
            'expected_project',
            'required_project',
            'owner_project_id',
            'bound_project_id',
        )
        for name in project_aliases:
            value = kwargs.pop(name, None)
            if value and not required_project_id and not project_id:
                required_project_id = value

        project_value = kwargs.pop('project', None)
        if project_value and not project_id and not required_project_id:
            project_identifier = getattr(project_value, 'id', project_value)
            if isinstance(project_identifier, dict):
                project_identifier = project_identifier.get('id')
            required_project_id = str(project_identifier)

        alias_ids = kwargs.pop('project_ids', None)
        if alias_ids is not None and allowed_project_ids is None:
            allowed_project_ids = alias_ids
        alias_allowed = kwargs.pop('allowed_projects', None)
        if alias_allowed is not None and allowed_project_ids is None:
            allowed_project_ids = alias_allowed
        alias_allowed_project = kwargs.pop('allowed_project', None)
        if (
            alias_allowed_project is not None
            and allowed_project_ids is None
        ):
            allowed_project_ids = alias_allowed_project
        required_ids = kwargs.pop('required_project_ids', None)
        if required_ids is not None and allowed_project_ids is None:
            allowed_project_ids = required_ids

        for name in ('project_boundary', 'project_guard', 'project_scope'):
            value = kwargs.pop(name, None)
            if value is not None and project_constraint is None:
                project_constraint = value

        for name in (
            'ownership_constraint',
            'project_affinity',
            'project_policy',
            'project_validator',
        ):
            value = kwargs.pop(name, None)
            if value is not None and project_constraint is None:
                project_constraint = value

        wait_timeout = kwargs.pop(
            'project_wait_timeout',
            kwargs.pop('project_constraint_timeout', None),
        )
        retry_interval = kwargs.pop('project_retry_interval', None)
        if kwargs:
            unexpected = next(iter(kwargs))
            raise TypeError(
                f'{type(self).__name__}.__init__() got an unexpected '
                f'keyword argument {unexpected!r}'
            )

        constraint_options: dict[str, Any] = {}
        if project_verifier is not None:
            constraint_options['verifier'] = project_verifier
        if wait_timeout is not None:
            constraint_options['wait_timeout'] = wait_timeout
        if retry_interval is not None:
            constraint_options['retry_interval'] = retry_interval

        if project_constraint is not None:
            self.project_constraint = ProjectConstraint.coerce(
                project_constraint, **constraint_options
            )
        elif project_id or required_project_id or allowed_project_ids:
            effective_project_id = project_id or required_project_id
            self.project_constraint = project_ownership.ProjectConstraint(
                project_id=effective_project_id,
                allowed_project_ids=allowed_project_ids,
                **constraint_options,
            )
        elif constraint_options:
            self.project_constraint = project_ownership.ProjectConstraint(
                auto_bind=True, **constraint_options
            )
        else:
            self.project_constraint = None

        self._project_lock = threading.RLock()
        self._project_binding: discover.EndpointData | None = None
        self._project_attestation: ProjectAttestation | None = None
        self._project_auth_epoch = 0
        self._project_token_fingerprint: str | None = None
        self._project_stop_reason: BaseException | None = None
        if isinstance(project_id, str) and project_id:
            self.project_id = project_id
        elif self.project_constraint is not None:
            self.project_id = self.project_constraint.project_id
        else:
            self.project_id = None

        # NOTE(jamielennox): when adding new parameters to adapter please also
        # add them to the adapter call in httpclient.HTTPClient.__init__ as
        # well as to load_adapter_from_argparse below if the argument is
        # intended to be something a user would reasonably expect to set on
        # a command line
        self.session = session
        self.service_type = service_type
        self.service_name = service_name
        self.interface = interface
        self.region_name = region_name
        self.endpoint_override = endpoint_override
        self.version = version
        self.auth = auth
        self.user_agent = user_agent
        self.connect_retries = connect_retries
        self.logger = logger
        self.allow = allow or {}
        self.additional_headers = additional_headers or {}
        self.allow_version_hack = allow_version_hack
        self.global_request_id = global_request_id
        self.min_version = min_version
        self.max_version = max_version
        self.default_microversion = default_microversion
        self.status_code_retries = status_code_retries
        self.retriable_status_codes = retriable_status_codes
        self.raise_exc = raise_exc
        self.connect_retry_delay = connect_retry_delay
        self.status_code_retry_delay = status_code_retry_delay

        if client_name:
            self.client_name = client_name
        if client_version:
            self.client_version = client_version

        rate_delay = 0.0
        if rate_limit:
            # 1 / rate converts from requests per second to delay
            # between requests needed to achieve that rate.
            rate_delay = 1.0 / rate_limit

        self._rate_semaphore = _fair_semaphore.FairSemaphore(
            concurrency, rate_delay
        )

    def _set_endpoint_filter_kwargs(self, kwargs: dict[str, object]) -> None:
        if self.service_type:
            kwargs.setdefault('service_type', self.service_type)
        if self.service_name:
            kwargs.setdefault('service_name', self.service_name)
        if self.interface:
            kwargs.setdefault('interface', self.interface)
        if self.region_name:
            kwargs.setdefault('region_name', self.region_name)
        if self.version:
            kwargs.setdefault('version', self.version)
        if self.min_version:
            kwargs.setdefault('min_version', self.min_version)
        if self.max_version:
            kwargs.setdefault('max_version', self.max_version)
        if self.allow_version_hack is not None:
            kwargs.setdefault('allow_version_hack', self.allow_version_hack)

    @property
    def required_project_id(self) -> str | None:
        return self.project_id

    @property
    def allowed_project_ids(self) -> frozenset[str]:
        if self.project_constraint is None:
            return frozenset()
        return self.project_constraint.allowed_project_ids

    @property
    def project_state(self) -> str | None:
        attestation = self._project_attestation
        if attestation is not None:
            return attestation.state
        binding = self._project_binding
        if binding is not None:
            return getattr(binding, 'ownership_state', None)
        return None

    @property
    def endpoint_ownership_state(self) -> str | None:
        return self.project_state

    @property
    def ownership_state(self) -> str | None:
        return self.project_state

    @property
    def endpoint_state(self) -> str | None:
        return self.project_state

    @property
    def selection_state(self) -> str | None:
        return self.project_state

    @property
    def constraint_state(self) -> str | None:
        return self.project_state

    @property
    def status(self) -> str | None:
        return self.project_state

    @property
    def state(self) -> str | None:
        return self.project_state

    @property
    def selection_status(self) -> str | None:
        return self.project_state

    @property
    def ownership_status(self) -> str | None:
        return self.project_state

    @property
    def bound_project_id(self) -> str | None:
        attestation = self._project_attestation
        if attestation is not None and attestation.project_id:
            return attestation.project_id
        return self.project_id

    @property
    def owner_project_id(self) -> str | None:
        return self.bound_project_id

    @property
    def active_project_id(self) -> str | None:
        return self.bound_project_id

    @property
    def selected_endpoint_data(self) -> discover.EndpointData | None:
        return self._project_binding

    @property
    def verified_endpoint_data(self) -> discover.EndpointData | None:
        if self.project_state in {
            project_ownership.STATE_VERIFIED,
            project_ownership.STATE_READY,
            project_ownership.STATE_SENT,
        }:
            return self._project_binding
        return None

    @property
    def actual_sends(self) -> list[dict[str, Any]]:
        return self.project_send_records

    @property
    def sent_requests(self) -> list[dict[str, Any]]:
        return self.project_send_records

    @property
    def project_events(self) -> list[dict[str, Any]]:
        if self.project_constraint is None:
            return []
        return self.project_constraint.events

    @property
    def project_observations(self) -> list[dict[str, Any]]:
        return self.project_events

    @property
    def project_errors(self) -> list[BaseException]:
        if self.project_constraint is None:
            return []
        return self.project_constraint.stop_reasons

    @property
    def project_attestation(
        self,
    ) -> ProjectAttestation | None:
        return self._project_attestation

    @property
    def last_project_attestation(
        self,
    ) -> ProjectAttestation | None:
        return self._project_attestation

    @property
    def bound_endpoint_data(self) -> discover.EndpointData | None:
        return self._project_binding

    @property
    def project_send_records(self) -> list[dict[str, Any]]:
        if self.project_constraint is None:
            return []
        return self.project_constraint.sends

    @property
    def project_stop_reason(self) -> BaseException | None:
        return self._project_stop_reason

    def _project_auth_evidence(
        self, auth: plugin.BaseAuthPlugin | None
    ) -> tuple[str | None, int | str]:
        effective_auth = auth or self.auth or getattr(
            self.session, 'auth', None
        )
        try:
            current_project_id = self.session.get_project_id(auth or self.auth)
        except exceptions.MissingAuthPlugin:
            current_project_id = None

        if not current_project_id and effective_auth is not None:
            candidate = getattr(effective_auth, 'project_id', None)
            if callable(candidate):
                try:
                    candidate = candidate(self.session)
                except TypeError:
                    candidate = candidate()
                except Exception:  # noqa: S110 - optional evidence
                    candidate = None
            if candidate:
                current_project_id = str(candidate)

        explicit_generation = None
        for name in (
            'auth_generation',
            'generation',
            'auth_revision',
            'token_generation',
        ):
            value = getattr(effective_auth, name, None)
            if callable(value):
                try:
                    value = value()
                except Exception:  # noqa: S110 - optional evidence
                    value = None
            if value is not None:
                explicit_generation = value
                break

        fingerprint = None
        try:
            token = self.session.get_token(auth or self.auth)
        except Exception:  # noqa: S110 - project ID is the primary evidence
            token = None
        if token:
            fingerprint = hashlib.sha256(str(token).encode()).hexdigest()[:16]

        with self._project_lock:
            if fingerprint is not None:
                if fingerprint != self._project_token_fingerprint:
                    self._project_token_fingerprint = fingerprint
                    self._project_auth_epoch += 1
                generation: int | str = self._project_auth_epoch
            else:
                generation = self._project_auth_epoch or 1

        if explicit_generation is not None:
            generation = explicit_generation
        return current_project_id, generation

    def _attest_project_endpoint(
        self,
        endpoint_data: discover.EndpointData,
        auth: plugin.BaseAuthPlugin | None,
        *,
        source: str,
        constraint: ProjectConstraint | None = None,
        expected_project_id: str | None = None,
    ) -> project_ownership.ProjectAttestation:
        constraint = constraint or self.project_constraint
        if constraint is None:
            raise exceptions.ProjectConstraintError(
                "Project attestation requested without a constraint."
            )

        current_project_id, generation = self._project_auth_evidence(auth)
        if expected_project_id is not None:
            expected_project_id = str(expected_project_id)
            if current_project_id != expected_project_id:
                exc = exceptions.ProjectMismatch(
                    f"Request requires project {expected_project_id!r}, but "
                    f"current authentication evidence is "
                    f"{current_project_id!r}.",
                    project_id=current_project_id,
                    expected_project_ids=[expected_project_id],
                    state=project_ownership.STATE_MISMATCH,
                    reason='per-request project constraint failed',
                    url=getattr(endpoint_data, 'url', None),
                )
                constraint.stop(exc)
                raise exc

        attestation = constraint.attest_endpoint_data(
            endpoint_data,
            current_project_id,
            source=source,
            auth_generation=generation,
        )
        self.project_id = attestation.project_id or self.project_id

        with self._project_lock:
            self._project_binding = endpoint_data
            self._project_attestation = attestation
            self._project_stop_reason = None
        return attestation

    def _mark_project_catalog_unavailable(
        self,
        error: BaseException | None,
        *,
        url: str | None = None,
        constraint: ProjectConstraint | None = None,
    ) -> exceptions.ProjectEndpointError:
        constraint = constraint or self.project_constraint
        with self._project_lock:
            previous = self._project_attestation
            project_id = previous.project_id if previous else self.project_id
            context = {
                'project_id': project_id,
                'url': url or (previous.url if previous else None),
            }

            if previous is not None and self._project_binding is not None:
                stale = project_ownership.ProjectAttestation(
                    project_id=previous.project_id,
                    allowed_project_ids=constraint.allowed_project_ids
                    if constraint
                    else None,
                    state=project_ownership.STATE_STALE,
                    source=previous.source,
                    url=previous.url,
                    catalog_url=previous.catalog_url,
                    service_url=previous.service_url,
                    service_type=previous.service_type,
                    interface=previous.interface,
                    region_name=previous.region_name,
                    api_version=previous.api_version,
                    auth_generation=previous.auth_generation,
                    reason=(
                        'fresh catalog evidence is unavailable: '
                        f'{error}'
                        if error
                        else 'fresh catalog evidence returned no endpoint'
                    ),
                )
                self._project_attestation = stale
                self._project_binding.ownership_state = (
                    project_ownership.STATE_STALE
                )
                exc: exceptions.ProjectEndpointError = (
                    exceptions.StaleProjectEndpoint(
                        "Project endpoint selection is stale; wait for the "
                        "correct catalog to recover or use a verified stop "
                        "reason.",
                        state=project_ownership.STATE_STALE,
                        reason=stale.reason,
                        **context,
                    )
                )
            else:
                unavailable = project_ownership.ProjectAttestation(
                    project_id=project_id,
                    allowed_project_ids=constraint.allowed_project_ids
                    if constraint
                    else None,
                    state=project_ownership.STATE_CATALOG_UNAVAILABLE,
                    reason=str(error) if error else 'endpoint not found',
                    url=url,
                )
                self._project_attestation = unavailable
                exc = exceptions.ProjectCatalogUnavailable(
                    state=project_ownership.STATE_CATALOG_UNAVAILABLE,
                    reason=unavailable.reason,
                    **context,
                )

            self._project_stop_reason = exc
            if constraint is not None:
                constraint.stop(exc)
            if error is not None:
                exc.__cause__ = error
            return exc

    def _fetch_project_endpoint_data(
        self,
        auth: plugin.BaseAuthPlugin | None,
        discovery_kwargs: dict[str, Any],
    ) -> tuple[discover.EndpointData | None, BaseException | None]:
        effective_auth = auth or self.auth
        discovery_error: BaseException | None = None
        try:
            endpoint_data = self.session.get_endpoint_data(
                effective_auth, **discovery_kwargs
            )
        except Exception as exc:  # noqa: BLE001 - fallback below
            endpoint_data = None
            discovery_error = exc

        if endpoint_data is not None:
            return endpoint_data, discovery_error

        # Light-weight in-memory auth doubles frequently implement only
        # get_endpoint().  Turn that catalog URL into an EndpointData so the
        # same ownership checks still apply to the actual send.
        endpoint_url = self.session.get_endpoint(
            effective_auth, **discovery_kwargs
        )
        if not endpoint_url:
            return None, discovery_error

        interface = discovery_kwargs.get('interface')
        endpoint_data = discover.EndpointData(
            catalog_url=endpoint_url,
            service_url=endpoint_url,
            service_type=discovery_kwargs.get('service_type'),
            service_name=discovery_kwargs.get('service_name'),
            interface=interface if isinstance(interface, str) else None,
            region_name=discovery_kwargs.get('region_name'),
        )
        return endpoint_data, discovery_error

    def _record_project_failure(
        self,
        exc: exceptions.ProjectConstraintError,
        *,
        constraint: ProjectConstraint | None = None,
        endpoint_data: discover.EndpointData | None = None,
    ) -> exceptions.ProjectConstraintError:
        constraint = constraint or self.project_constraint
        state = getattr(exc, 'state', None)
        if not state:
            if isinstance(exc, exceptions.ProjectOwnershipError):
                state = project_ownership.STATE_MISMATCH
            else:
                state = project_ownership.STATE_BLOCKED

        with self._project_lock:
            previous = self._project_attestation
            project_id = (
                getattr(exc, 'project_id', None)
                or (previous.project_id if previous else None)
                or self.project_id
            )
            failure = project_ownership.ProjectAttestation(
                project_id=project_id,
                allowed_project_ids=(
                    constraint.allowed_project_ids if constraint else None
                ),
                state=state,
                source=previous.source if previous else 'send',
                url=getattr(exc, 'url', None)
                or (previous.url if previous else None),
                service_type=previous.service_type if previous else None,
                interface=previous.interface if previous else None,
                region_name=previous.region_name if previous else None,
                api_version=previous.api_version if previous else None,
                reason=getattr(exc, 'reason', None) or str(exc),
            )
            self._project_attestation = failure
            self._project_stop_reason = exc
            binding = endpoint_data or self._project_binding
            if binding is not None:
                binding.ownership_state = state
                if endpoint_data is not None:
                    self._project_binding = endpoint_data
            if constraint is not None:
                constraint.stop(exc)
                constraint.record(failure)
        return exc

    def _install_project_send_guard(
        self,
        kwargs: dict[str, Any],
        constraint: ProjectConstraint,
        attestation: ProjectAttestation,
    ) -> None:
        existing_guard = kwargs.get('send_guard')

        def send_guard(
            url: str,
            method: str,
            request_kwargs: dict[str, Any],
        ) -> None:
            if existing_guard is not None:
                existing_guard(
                    url=url,
                    method=method,
                    request_kwargs=request_kwargs,
                )
            constraint.check_send_url(
                url,
                attestation,
                method=method,
                headers=request_kwargs.get('headers'),
            )

        kwargs['send_guard'] = send_guard

        existing_requests_auth = kwargs.get('requests_auth')

        def project_requests_auth(
            prepared_request: requests.PreparedRequest,
        ) -> requests.PreparedRequest:
            if existing_requests_auth is not None:
                result = existing_requests_auth(prepared_request)
                if result is not None:
                    prepared_request = result
            ownership = attestation.to_dict()
            for attr, value in (
                ('keystoneauth_project_id', attestation.project_id),
                ('keystoneauth_api_version', attestation.api_version),
                ('keystoneauth_project_attestation', ownership),
                ('project_id', attestation.project_id),
                ('api_version', attestation.api_version),
                ('project_ownership', attestation.state),
            ):
                setattr(prepared_request, attr, value)
            return prepared_request

        kwargs['requests_auth'] = project_requests_auth

    def _prepare_project_constrained_request(
        self,
        url: str,
        method: str,
        kwargs: dict[str, Any],
        endpoint_filter: dict[str, Any],
        constraint: ProjectConstraint | None = None,
        expected_project_id: str | None = None,
        extra_constraint: ProjectConstraint | None = None,
    ) -> ProjectAttestation | None:
        constraint = constraint or self.project_constraint
        if constraint is None:
            return None

        auth = kwargs.get('auth', self.auth)
        discovery_kwargs = dict(endpoint_filter)
        if 'allow' in kwargs:
            discovery_kwargs.setdefault('allow', kwargs['allow'])
        endpoint_override = kwargs.get('endpoint_override')
        if endpoint_override:
            discovery_kwargs['endpoint_override'] = endpoint_override

        parsed_url = urllib.parse.urlparse(url)
        can_refresh = bool(
            discovery_kwargs.get('service_type')
            or discovery_kwargs.get('endpoint_override')
            or endpoint_override
        )

        endpoint_data = None
        refresh_error: BaseException | None = None
        if can_refresh:
            try:
                endpoint_data, refresh_error = (
                    self._fetch_project_endpoint_data(auth, discovery_kwargs)
                )
            except exceptions.ProjectConstraintError:
                raise
            except Exception as exc:  # noqa: BLE001 - classified below
                refresh_error = exc

        if endpoint_data is not None:
            try:
                attestation = self._attest_project_endpoint(
                    endpoint_data,
                    auth,
                    source='catalog+discovery',
                    constraint=constraint,
                    expected_project_id=expected_project_id,
                )
                if extra_constraint is not None:
                    extra_constraint.check_project(
                        attestation.project_id, url=endpoint_data.url
                    )
            except exceptions.ProjectConstraintError as exc:
                self._record_project_failure(
                    exc,
                    constraint=constraint,
                    endpoint_data=endpoint_data,
                )
                raise

            if endpoint_data.url and not parsed_url.netloc:
                kwargs['endpoint_override'] = endpoint_data.url

            self._install_project_send_guard(
                kwargs, constraint, attestation
            )
            return attestation

        current_project_id, _generation = self._project_auth_evidence(auth)
        try:
            if (
                expected_project_id is not None
                and current_project_id != expected_project_id
            ):
                raise exceptions.ProjectMismatch(
                    f"Request requires project {expected_project_id!r}, but "
                    f"current authentication evidence is "
                    f"{current_project_id!r}.",
                    project_id=current_project_id,
                    expected_project_ids=[expected_project_id],
                    state=project_ownership.STATE_MISMATCH,
                    reason='per-request project constraint failed',
                    url=url,
                )
            constraint.check_project(current_project_id, url=url)
            if extra_constraint is not None:
                extra_constraint.check_project(current_project_id, url=url)
        except exceptions.ProjectConstraintError as exc:
            self._record_project_failure(exc, constraint=constraint)
            raise

        if not parsed_url.netloc or can_refresh:
            raise self._mark_project_catalog_unavailable(
                refresh_error, url=url, constraint=constraint
            )

        # For an absolute URL without catalog filters, caller-supplied URL
        # evidence plus the current project identity is sufficient.  A
        # previously verified catalog binding is preferred when available.
        with self._project_lock:
            previous = self._project_attestation
            binding = self._project_binding
        if (
            previous is not None
            and previous.verified
            and binding is not None
            and project_ownership.urls_share_endpoint(
                previous.url or '', url
            )
        ):
            self._install_project_send_guard(
                kwargs, constraint, previous
            )
            return previous

        direct_data = discover.EndpointData(
            catalog_url=url,
            service_url=url,
            project_id=current_project_id,
        )
        try:
            direct_attestation = self._attest_project_endpoint(
                direct_data,
                auth,
                source='request-url',
                constraint=constraint,
                expected_project_id=expected_project_id,
            )
        except exceptions.ProjectConstraintError as exc:
            self._record_project_failure(exc, constraint=constraint)
            raise
        self._install_project_send_guard(
            kwargs, constraint, direct_attestation
        )
        return direct_attestation

    def wait_for_project_endpoint(
        self,
        timeout: float | None = None,
        interval: float | None = None,
    ) -> project_ownership.ProjectAttestation:
        """Re-run catalog/discovery until fresh project evidence succeeds."""
        constraint = self.project_constraint
        if constraint is None:
            raise exceptions.ProjectConstraintError(
                "This adapter has no project constraint."
            )

        def ready() -> ProjectAttestation | None:
            try:
                endpoint_data = self.get_endpoint_data()
            except Exception:  # noqa: BLE001 - polling classifier
                return None
            return self._project_attestation if endpoint_data else None

        return constraint.wait(ready, timeout=timeout, interval=interval)

    wait_until_ready = wait_for_project_endpoint
    wait_for_endpoint = wait_for_project_endpoint
    wait_for_project_recovery = wait_for_project_endpoint
    wait_for_catalog_recovery = wait_for_project_endpoint

    def _extract_request_project_constraint(
        self, kwargs: dict[str, Any]
    ) -> tuple[
        ProjectConstraint | None,
        str | None,
        ProjectConstraint | None,
    ]:
        request_project_id = kwargs.pop('project_id', None)
        required_project_id = kwargs.pop('required_project_id', None)
        if required_project_id and not request_project_id:
            request_project_id = required_project_id
        allowed_project_ids = kwargs.pop('allowed_project_ids', None)
        raw_constraint = kwargs.pop('project_constraint', None)
        verifier = kwargs.pop('project_verifier', None)

        request_constraint = None
        if raw_constraint is not None:
            request_constraint = (
                ProjectConstraint.coerce(raw_constraint)
            )
        elif request_project_id or allowed_project_ids or verifier:
            request_constraint = project_ownership.ProjectConstraint(
                project_id=request_project_id,
                allowed_project_ids=allowed_project_ids,
                verifier=verifier,
            )

        if self.project_constraint is None:
            return request_constraint, None, None

        if request_constraint is None:
            return self.project_constraint, None, None

        # A per-request constraint can narrow or observe the global adapter
        # policy, but it must not replace the global ownership check.
        return (
            self.project_constraint,
            request_project_id,
            request_constraint,
        )

    def _request(
        self, url: str, method: str, **kwargs: Any
    ) -> requests.Response:
        endpoint_filter = kwargs.setdefault('endpoint_filter', {})
        self._set_endpoint_filter_kwargs(endpoint_filter)
        # NOTE(gmann): Convert or initlize the headers to
        # CaseInsensitiveDict to make sure headers are
        # case insensitive.
        if kwargs.get('headers'):
            kwargs['headers'] = requests.structures.CaseInsensitiveDict(
                kwargs['headers']
            )
        else:
            kwargs['headers'] = requests.structures.CaseInsensitiveDict()
        if self.endpoint_override:
            kwargs.setdefault('endpoint_override', self.endpoint_override)

        if self.auth:
            kwargs.setdefault('auth', self.auth)
        if self.user_agent:
            kwargs.setdefault('user_agent', self.user_agent)
        for arg in (
            'connect_retries',
            'status_code_retries',
            'connect_retry_delay',
            'status_code_retry_delay',
            'retriable_status_codes',
        ):
            if getattr(self, arg) is not None:
                kwargs.setdefault(arg, getattr(self, arg))
        if self.logger:
            kwargs.setdefault('logger', self.logger)
        if self.allow:
            kwargs.setdefault('allow', self.allow)
        if self.default_microversion is not None:
            kwargs.setdefault('microversion', self.default_microversion)

        if isinstance(self.session, _session.Session | Adapter):
            # these things are unsupported by keystoneclient's session so be
            # careful with them until everyone has transitioned to ksa.
            # Allowing adapter allows adapter nesting that auth_token does.
            if self.client_name:
                kwargs.setdefault('client_name', self.client_name)
            if self.client_version:
                kwargs.setdefault('client_version', self.client_version)
            if self._rate_semaphore:
                kwargs.setdefault('rate_semaphore', self._rate_semaphore)

        else:
            warnings.warn(
                'Using keystoneclient sessions has been deprecated. '
                'Please update your software to use keystoneauth1.'
            )

        for k, v in self.additional_headers.items():
            kwargs.setdefault('headers', {}).setdefault(k, v)

        if self.global_request_id is not None:
            kwargs.setdefault('headers', {}).setdefault(
                "X-OpenStack-Request-ID", self.global_request_id
            )

        if self.raise_exc is not None:
            kwargs.setdefault('raise_exc', self.raise_exc)

        (
            effective_constraint,
            expected_project_id,
            extra_constraint,
        ) = self._extract_request_project_constraint(kwargs)
        if effective_constraint is not None:
            self._prepare_project_constrained_request(
                url,
                method,
                kwargs,
                endpoint_filter,
                constraint=effective_constraint,
                expected_project_id=expected_project_id,
                extra_constraint=extra_constraint,
            )

        return self.session.request(url, method, **kwargs)

    def get_token(
        self, auth: plugin.BaseAuthPlugin | None = None
    ) -> str | None:
        """Return a token as provided by the auth plugin.

        :param auth: The auth plugin to use for token. Overrides the plugin on
            the session. (optional)
        :raises keystoneauth1.exceptions.auth.AuthorizationFailure: if a new
            token fetch fails.
        :returns: A valid token.
        """
        return self.session.get_token(auth or self.auth)

    def get_endpoint(
        self, auth: plugin.BaseAuthPlugin | None = None, **kwargs: Any
    ) -> str | None:
        """Get an endpoint as provided by the auth plugin.

        :param auth: The auth plugin to use for token. Overrides the plugin on
            the session. (optional)
        :raises keystoneauth1.exceptions.auth_plugins.MissingAuthPlugin: if a
            plugin is not available.
        :returns: An endpoint if available or None.
        """
        if self.project_constraint is not None:
            endpoint_data = self.get_endpoint_data(auth, **kwargs)
            return endpoint_data.url if endpoint_data is not None else None

        if self.endpoint_override:
            return self.endpoint_override

        self._set_endpoint_filter_kwargs(kwargs)
        return self.session.get_endpoint(auth or self.auth, **kwargs)

    def get_endpoint_data(
        self,
        auth: plugin.BaseAuthPlugin | None = None,
        **overrides: Any,
    ) -> discover.EndpointData | None:
        """Get the endpoint data for this Adapter's endpoint.

        :param auth: The auth plugin to use for token. Overrides the plugin on
            the session. (optional)
        :raises keystoneauth1.exceptions.auth_plugins.MissingAuthPlugin: if a
            plugin is not available.
        :raises TypeError: If arguments are invalid
        :returns: Endpoint data if available or None.
        """
        kwargs: dict[str, Any] = {}
        self._set_endpoint_filter_kwargs(kwargs)
        if self.endpoint_override:
            kwargs['endpoint_override'] = self.endpoint_override

        expected_project_id = overrides.pop('project_id', None)
        request_constraint = ProjectConstraint.coerce(
            overrides.pop('project_constraint', None)
        )
        kwargs.update(overrides)

        endpoint_data = self.session.get_endpoint_data(
            auth or self.auth, **kwargs
        )
        constraint = request_constraint or self.project_constraint
        if expected_project_id and constraint is None:
            constraint = project_ownership.ProjectConstraint(
                project_id=expected_project_id
            )
        if constraint is not None:
            if endpoint_data is None:
                self._mark_project_catalog_unavailable(
                    None, constraint=constraint
                )
            else:
                self._attest_project_endpoint(
                    endpoint_data,
                    auth or self.auth,
                    source='discovery',
                    constraint=constraint,
                    expected_project_id=expected_project_id,
                )
        return endpoint_data

    def get_all_version_data(
        self,
        interface: str | list[str] | None = 'public',
        region_name: str | None = None,
        auth: plugin.BaseAuthPlugin | None = None,
    ) -> dict[str, dict[str, dict[str, list[discover.VersionData]]]]:
        """Get data about all versions of a service.

        :param interface: Type of endpoint to get version data for. Can be a
            single value or a list of values. A value of None indicates that
            all interfaces should be queried. (optional, defaults to public)
        :param region_name: Region of endpoints to get version data for. A
            value of None indicates that all regions should be queried.
            (optional, defaults to None)
        :returns: A dictionary keyed by region_name with values containing
            dictionaries keyed by interface with values being a list of
            :class:`~keystoneauth1.discover.VersionData`.
        """
        version_data = self.session.get_all_version_data(
            auth=auth or self.auth,
            interface=interface,
            region_name=region_name,
            service_type=self.service_type,
        )
        if self.project_constraint is not None and version_data:
            project_id, generation = self._project_auth_evidence(
                auth or self.auth
            )
            attestation = self.project_constraint.check_project(project_id)
            for regions in version_data.values():
                for services in regions.values():
                    for versions in services.values():
                        for version in versions:
                            version['project_id'] = attestation.project_id
                            version['auth_generation'] = generation
                            version['ownership_state'] = (
                                project_ownership.STATE_VERIFIED
                            )
        return version_data

    def get_api_major_version(
        self, auth: plugin.BaseAuthPlugin | None = None, **kwargs: Any
    ) -> tuple[int | float, ...] | None:
        """Get the major API version as provided by the auth plugin.

        :param auth: The auth plugin to use for token. Overrides the plugin on
            the session. (optional)
        :raises keystoneauth1.exceptions.auth_plugins.MissingAuthPlugin: if a
            plugin is not available.
        :return: The major version of the API of the service discovered.
        """
        self._set_endpoint_filter_kwargs(kwargs)
        if self.endpoint_override:
            kwargs['endpoint_override'] = self.endpoint_override

        return self.session.get_api_major_version(auth or self.auth, **kwargs)

    def invalidate(self, auth: plugin.BaseAuthPlugin | None = None) -> bool:
        """Invalidate an authentication plugin.

        :param auth: The auth plugin to invalidate. Overrides the plugin on the
            session. (optional)
        """
        effective_auth = auth or self.auth
        result = self.session.invalidate(effective_auth)
        if result and self.project_constraint is not None:
            with self._project_lock:
                self._project_token_fingerprint = None
                if self._project_attestation is not None:
                    stale = project_ownership.ProjectAttestation(
                        project_id=self._project_attestation.project_id,
                        allowed_project_ids=(
                            self.project_constraint.allowed_project_ids
                        ),
                        state=project_ownership.STATE_STALE,
                        source=self._project_attestation.source,
                        url=self._project_attestation.url,
                        catalog_url=self._project_attestation.catalog_url,
                        service_url=self._project_attestation.service_url,
                        service_type=self._project_attestation.service_type,
                        interface=self._project_attestation.interface,
                        region_name=self._project_attestation.region_name,
                        api_version=self._project_attestation.api_version,
                        reason='authentication evidence was invalidated',
                    )
                    self._project_attestation = stale
                    if self._project_binding is not None:
                        self._project_binding.ownership_state = (
                            project_ownership.STATE_STALE
                        )
        return result

    def get_user_id(
        self, auth: plugin.BaseAuthPlugin | None = None
    ) -> str | None:
        """Return the authenticated user_id as provided by the auth plugin.

        :param auth: The auth plugin to use for token. Overrides the plugin on
            the session. (optional)
        :raises keystoneauth1.exceptions.auth.AuthorizationFailure:
            if a new token fetch fails.
        :raises keystoneauth1.exceptions.auth_plugins.MissingAuthPlugin:
            if a plugin is not available.
        :returns: Current `user_id` or None if not supported by plugin.
        """
        return self.session.get_user_id(auth or self.auth)

    def get_project_id(
        self, auth: plugin.BaseAuthPlugin | None = None
    ) -> str | None:
        """Return the authenticated project_id as provided by the auth plugin.

        :param auth: The auth plugin to use for token. Overrides the plugin on
            the session. (optional)
        :raises keystoneauth1.exceptions.auth.AuthorizationFailure:
            if a new token fetch fails.
        :raises keystoneauth1.exceptions.auth_plugins.MissingAuthPlugin:
            if a plugin is not available.
        :returns: Current `project_id` or None if not supported by plugin.
        """
        return self.session.get_project_id(auth or self.auth)

    # TODO(efried): Move this to loading.adapter.Adapter
    @classmethod
    def register_argparse_arguments(
        cls, parser: argparse.ArgumentParser, service_type: str | None = None
    ) -> None:
        """Attach arguments to a given argparse Parser for Adapters.

        :param parser: The argparse parser to attach options to.
        :param service_type: Default service_type value. (optional)
        """
        adapter_group = parser.add_argument_group(
            'Service Options',
            'Options controlling the specialization of the API '
            'Connection from information found in the catalog',
        )

        adapter_group.add_argument(
            '--os-service-type',
            metavar='<name>',
            default=os.environ.get('OS_SERVICE_TYPE', service_type),
            help='Service type to request from the catalog',
        )

        adapter_group.add_argument(
            '--os-service-name',
            metavar='<name>',
            default=os.environ.get('OS_SERVICE_NAME', None),
            help='Service name to request from the catalog',
        )

        adapter_group.add_argument(
            '--os-interface',
            metavar='<name>',
            default=os.environ.get('OS_INTERFACE', 'public'),
            help='API Interface to use [public, internal, admin]',
        )

        adapter_group.add_argument(
            '--os-region-name',
            metavar='<name>',
            default=os.environ.get('OS_REGION_NAME', None),
            help='Region of the cloud to use',
        )

        adapter_group.add_argument(
            '--os-endpoint-override',
            metavar='<name>',
            default=os.environ.get('OS_ENDPOINT_OVERRIDE', None),
            help='Endpoint to use instead of the endpoint in the catalog',
        )

        adapter_group.add_argument(
            '--os-api-version',
            metavar='<name>',
            default=os.environ.get('OS_API_VERSION', None),
            help='Which version of the service API to use',
        )

    # TODO(efried): Move this to loading.adapter.Adapter
    @classmethod
    def register_service_argparse_arguments(
        cls, parser: argparse.ArgumentParser, service_type: str
    ) -> None:
        """Attach arguments to a given argparse Parser for Adapters.

        :param parser: The argparse parser to attach options to.
        :param service_type: Name of a service to generate additional arguments
            for.
        """
        service_env = service_type.upper().replace('-', '_')
        adapter_group = parser.add_argument_group(
            f'{service_type.title()} Service Options',
            f'Options controlling the specialization of the '
            f'{service_type.title()} API Connection from information found in '
            f'the catalog',
        )

        adapter_group.add_argument(
            f'--os-{service_type}-service-type',
            metavar='<name>',
            default=os.environ.get(f'OS_{service_env}_SERVICE_TYPE', None),
            help=(
                f'Service type to request from the catalog for the '
                f'{service_type} service'
            ),
        )

        adapter_group.add_argument(
            f'--os-{service_type}-service-name',
            metavar='<name>',
            default=os.environ.get(f'OS_{service_env}_SERVICE_NAME', None),
            help=(
                f'Service name to request from the catalog for the '
                f'{service_type} service'
            ),
        )

        adapter_group.add_argument(
            f'--os-{service_type}-interface',
            metavar='<name>',
            default=os.environ.get(f'OS_{service_env}_INTERFACE', None),
            help=(
                f'API Interface to use for the {service_type} service '
                f'[public, internal, admin]'
            ),
        )

        adapter_group.add_argument(
            f'--os-{service_type}-api-version',
            metavar='<name>',
            default=os.environ.get(f'OS_{service_env}_API_VERSION', None),
            help=(
                f'Which version of the service API to use for '
                f'the {service_type} service'
            ),
        )

        adapter_group.add_argument(
            f'--os-{service_type}-endpoint-override',
            metavar='<name>',
            default=os.environ.get(
                f'OS_{service_env}_ENDPOINT_OVERRIDE', None
            ),
            help=(
                f'Endpoint to use for the {service_type} service '
                f'instead of the endpoint in the catalog'
            ),
        )


class Adapter(_BaseAdapter):
    def request(
        self, url: str, method: str, **kwargs: Any
    ) -> requests.Response:
        return self._request(url, method, **kwargs)

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        """Perform a GET request.

        This calls :py:meth:`.request()` with ``method`` set to ``GET``.
        """
        return self.request(url, 'GET', **kwargs)

    def head(self, url: str, **kwargs: Any) -> requests.Response:
        """Perform a HEAD request.

        This calls :py:meth:`.request()` with ``method`` set to ``HEAD``.
        """
        return self.request(url, 'HEAD', **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        """Perform a POST request.

        This calls :py:meth:`.request()` with ``method`` set to ``POST``.
        """
        return self.request(url, 'POST', **kwargs)

    def put(self, url: str, **kwargs: Any) -> requests.Response:
        """Perform a PUT request.

        This calls :py:meth:`.request()` with ``method`` set to ``PUT``.
        """
        return self.request(url, 'PUT', **kwargs)

    def patch(self, url: str, **kwargs: Any) -> requests.Response:
        """Perform a PATCH request.

        This calls :py:meth:`.request()` with ``method`` set to ``PATCH``.
        """
        return self.request(url, 'PATCH', **kwargs)

    def delete(self, url: str, **kwargs: Any) -> requests.Response:
        """Perform a DELETE request.

        This calls :py:meth:`.request()` with ``method`` set to ``DELETE``.
        """
        return self.request(url, 'DELETE', **kwargs)


class LegacyJsonAdapter(_BaseAdapter):
    """Make something that looks like an old HTTPClient.

    A common case when using an adapter is that we want an interface similar to
    the HTTPClients of old which returned the body as JSON as well.

    You probably don't want this if you are starting from scratch.
    """

    def request(
        self, url: str, method: str, **kwargs: Any
    ) -> tuple[requests.Response, object]:
        headers = kwargs.setdefault('headers', {})
        headers.setdefault('Accept', 'application/json')

        try:
            kwargs['json'] = kwargs.pop('body')
        except KeyError:
            pass

        resp = self._request(url, method, **kwargs)

        try:
            body = resp.json()
        except ValueError:
            body = None

        return resp, body

    def get(self, url: str, **kwargs: Any) -> tuple[requests.Response, object]:
        """Perform a GET request.

        This calls :py:meth:`.request()` with ``method`` set to ``GET``.
        """
        return self.request(url, 'GET', **kwargs)

    def head(
        self, url: str, **kwargs: Any
    ) -> tuple[requests.Response, object]:
        """Perform a HEAD request.

        This calls :py:meth:`.request()` with ``method`` set to ``HEAD``.
        """
        return self.request(url, 'HEAD', **kwargs)

    def post(
        self, url: str, **kwargs: Any
    ) -> tuple[requests.Response, object]:
        """Perform a POST request.

        This calls :py:meth:`.request()` with ``method`` set to ``POST``.
        """
        return self.request(url, 'POST', **kwargs)

    def put(self, url: str, **kwargs: Any) -> tuple[requests.Response, object]:
        """Perform a PUT request.

        This calls :py:meth:`.request()` with ``method`` set to ``PUT``.
        """
        return self.request(url, 'PUT', **kwargs)

    def patch(
        self, url: str, **kwargs: Any
    ) -> tuple[requests.Response, object]:
        """Perform a PATCH request.

        This calls :py:meth:`.request()` with ``method`` set to ``PATCH``.
        """
        return self.request(url, 'PATCH', **kwargs)

    def delete(
        self, url: str, **kwargs: Any
    ) -> tuple[requests.Response, object]:
        """Perform a DELETE request.

        This calls :py:meth:`.request()` with ``method`` set to ``DELETE``.
        """
        return self.request(url, 'DELETE', **kwargs)


# TODO(efried): Deprecate this in favor of
#               loading.adapter.register_argparse_arguments
def register_adapter_argparse_arguments(
    parser: argparse.ArgumentParser, service_type: str | None = None
) -> None:
    return Adapter.register_argparse_arguments(
        parser=parser, service_type=service_type
    )


# TODO(efried): Deprecate this in favor of
#               loading.adapter.register_service_argparse_arguments
def register_service_adapter_argparse_arguments(
    parser: argparse.ArgumentParser, service_type: str
) -> None:
    return Adapter.register_service_argparse_arguments(
        parser=parser, service_type=service_type
    )
