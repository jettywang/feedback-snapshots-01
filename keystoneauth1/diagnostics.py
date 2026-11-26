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

"""Shareable diagnostics for a single request.

A :class:`RequestDiagnostic` follows one logical request through catalog
selection, every HTTP exchange (including redirects and retries),
re-authentication and the final error.  The same object produces two views:

``public_view()``
    The export that can be handed to somebody outside the immediate team.
    It retains the correlation identifier and the stage ordering but hides
    every value that the :class:`DiagnosticPolicy` has not approved.

``internal_view()``
    The unredacted counterpart for controlled debugging.  It contains the
    same request identifier, so an internal reader can match a public
    digest back to the actual value.

The policy is deliberately made of independent switches: catalog service
names, addresses and each identity header can be approved separately.
Private markers may also be supplied; they are scrubbed from every public
string and only their SHA256 digest is retained.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import uuid
from typing import Any

__all__ = (
    'DiagnosticPolicy',
    'DiagnosticEvent',
    'RequestDiagnostic',
    'new_request_id',
    'sha256',
    'SCHEMA',
)


SCHEMA = 'keystoneauth1.diagnostics.v1'

#: Request stages, in the order in which a typical call records them.
STAGE_CATALOG = 'catalog'
STAGE_REQUEST = 'request'
STAGE_RESPONSE = 'response'
STAGE_RETRY = 'retry'
STAGE_REAUTH = 'reauth'
STAGE_ERROR = 'error'

_IDENTITY_HEADERS = {
    'authorization': 'user_token',
    'x-auth-token': 'user_token',
    'x-subject-token': 'user_token',
    'x-service-token': 'service_token',
}

_REQUEST_ID_PREFIX = 'req-'


def sha256(value: str) -> str:
    """Return the hex SHA256 digest of ``value``."""
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def new_request_id() -> str:
    """Return a correlation identifier for a new logical request."""
    return f'{_REQUEST_ID_PREFIX}{uuid.uuid4().hex}'


def _as_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode('utf-8', 'backslashreplace')
    return str(value)


def _hidden(value: Any) -> dict[str, Any]:
    """Represent a value that was withheld from the public export."""
    return {'redacted': True, 'sha256': sha256(_as_text(value))}


@dataclasses.dataclass(frozen=True)
class DiagnosticPolicy:
    """Independent decisions about what a public diagnostic may contain.

    Each field is approved separately.  The defaults keep the historic
    keystoneauth debug behaviour (catalog metadata and bodies visible,
    identity headers reduced to a SHA256 digest) while leaving the raw
    credentials out of the public export.

    :param service_name: Approve catalog service names for the public view.
    :param endpoint: Approve catalog/request addresses (URLs) for the public
        view.
    :param user_token: Approve the user identity headers (``Authorization``,
        ``X-Auth-Token`` and ``X-Subject-Token``) for the public view.
    :param service_token: Approve the service identity header
        (``X-Service-Token``) for the public view.  This switch is independent
        of ``user_token`` so a dual-token request can reveal one side only.
    :param request_body: Approve formatted request bodies in public output.
    :param response_body: Approve formatted response bodies, including the
        details from a final error, in public output.
    :param private_markers: Fictional or real private values that must never
        appear in public output.  They are replaced by their SHA256 digest.
    """

    service_name: bool = True
    endpoint: bool = True
    user_token: bool = False
    service_token: bool = False
    request_body: bool = True
    response_body: bool = True
    private_markers: tuple[str, ...] = ()

    def is_identity_header(self, name: str) -> bool:
        """Return whether ``name`` is an identity-bearing header."""
        return name.lower() in _IDENTITY_HEADERS

    def identity_header_approved(self, name: str) -> bool:
        """Return whether a particular identity header is approved."""
        field = _IDENTITY_HEADERS.get(name.lower())
        if field is None:
            return True
        return bool(getattr(self, field))

    def scrub(self, value: str) -> str:
        """Replace every configured private marker in ``value``."""
        for marker in self.private_markers:
            if marker and marker in value:
                value = value.replace(marker, f'{{SHA256}}{sha256(marker)}')
        return value

    def scrub_value(self, value: Any) -> Any:
        """Recursively scrub private markers from a JSON-like value."""
        if isinstance(value, str):
            return self.scrub(value)
        if isinstance(value, bytes):
            return self.scrub(value.decode('utf-8', 'backslashreplace'))
        if isinstance(value, dict):
            return {
                self.scrub(_as_text(k)): self.scrub_value(v)
                for k, v in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [self.scrub_value(v) for v in value]
        return value

    def public_approvals(self) -> dict[str, bool]:
        """Return the non-secret approval switches for the export header."""
        return {
            'service_name': self.service_name,
            'endpoint': self.endpoint,
            'user_token': self.user_token,
            'service_token': self.service_token,
            'request_body': self.request_body,
            'response_body': self.response_body,
        }

    def marker_digests(self) -> list[str]:
        """Return digests that let an internal reader match scrubbed values."""
        return sorted(
            sha256(marker) for marker in self.private_markers if marker
        )

    def redact_endpoint(self, url: str) -> str:
        """Return ``url`` or a stable digest if addresses are not approved."""
        if self.endpoint:
            return self.scrub(url)
        return f'{{SHA256}}{sha256(url)}'

    def sanitize_token_body(self, data: Any) -> Any:
        """Return a token body safe for a formatted log.

        Catalog service names and endpoint addresses are withheld according
        to the independent ``service_name``/``endpoint`` switches, and any
        configured private marker is scrubbed, without touching the live
        response object.
        """
        if not isinstance(data, dict):
            return self.scrub_value(data)

        view = copy.deepcopy(data)
        raw_token = view.get('token')
        token = raw_token if isinstance(raw_token, dict) else None
        catalog = None
        if token is not None:
            catalog = token.get('catalog')
        elif 'serviceCatalog' in view and isinstance(
            view['serviceCatalog'], list
        ):
            catalog = view['serviceCatalog']

        if isinstance(catalog, list):
            for service in catalog:
                if not isinstance(service, dict):
                    continue
                if not self.service_name and 'name' in service:
                    service['name'] = self._digest_value(service['name'])
                for endpoint in service.get('endpoints') or ():
                    if isinstance(endpoint, dict) and not self.endpoint:
                        for key in ('url', 'region', 'region_id'):
                            if key in endpoint:
                                endpoint[key] = self._digest_value(
                                    endpoint[key]
                                )
        return self.scrub_value(view)

    @staticmethod
    def _digest_value(value: Any) -> str:
        return f'{{SHA256}}{sha256(_as_text(value))}'


@dataclasses.dataclass
class DiagnosticEvent:
    """One stage in a request's diagnostic timeline."""

    sequence: int
    stage: str
    data: dict[str, Any]


class RequestDiagnostic:
    """A single request's stage-ordered diagnostic record.

    :param request_id: Correlation identifier shared by every stage.
    :param policy: Visibility policy used by both views.
    :param dual_token: Whether the request carried a service token in
        addition to the user token.
    """

    def __init__(
        self,
        request_id: str | None = None,
        policy: DiagnosticPolicy | None = None,
        dual_token: bool = False,
    ) -> None:
        self.request_id = request_id or new_request_id()
        self.policy = policy or DiagnosticPolicy()
        self.dual_token = dual_token
        self.events: list[DiagnosticEvent] = []

    @property
    def request_kind(self) -> str:
        """Return ``dual-token`` or ``standard`` for this request."""
        return 'dual-token' if self.dual_token else 'standard'

    def add(self, stage: str, **data: Any) -> DiagnosticEvent:
        """Append a stage to the record and return it."""
        event = DiagnosticEvent(
            sequence=len(self.events), stage=stage, data=dict(data)
        )
        self.events.append(event)
        return event

    def _header_view(
        self, headers: Any
    ) -> dict[str, Any]:
        policy = self.policy
        result: dict[str, Any] = {}
        if not headers:
            return result
        items = headers.items() if hasattr(headers, 'items') else headers
        for name, value in items:
            name_text = policy.scrub(_as_text(name))
            value_text = _as_text(value)
            if (
                policy.is_identity_header(name_text)
                and not policy.identity_header_approved(name_text)
            ):
                result[name_text] = f'{{SHA256}}{sha256(value_text)}'
            else:
                result[name_text] = policy.scrub(value_text)
        return result

    def _body_view(
        self, body: Any, approved: bool, address: str | None = None
    ) -> Any:
        if body is None:
            return None
        if not approved:
            return _hidden(body)
        if isinstance(body, dict):
            # A token body can carry a catalog; keep the same service_name
            # and endpoint switches used for the catalog stage so the catalog
            # internals are not re-assembled in a later stage.
            view = self.policy.sanitize_token_body(body)
        else:
            view = self.policy.scrub_value(body)
        if address and not self.policy.endpoint:
            view = self._scrub_address(view, address)
        return view

    def _scrub_address(self, value: Any, address: str) -> Any:
        """Replace an unapproved address wherever it appears in a body."""
        digest = f'{{SHA256}}{sha256(address)}'
        if isinstance(value, str):
            return value.replace(address, digest)
        if isinstance(value, list):
            return [self._scrub_address(item, address) for item in value]
        if isinstance(value, dict):
            return {
                key: self._scrub_address(item, address)
                for key, item in value.items()
            }
        return value

    def _put(
        self,
        output: dict[str, Any],
        key: str,
        value: Any,
        approved: bool = True,
    ) -> None:
        if value is None:
            return
        if approved:
            output[key] = self.policy.scrub_value(value)
        else:
            output[key] = _hidden(value)

    def _public_event(self, event: DiagnosticEvent) -> dict[str, Any]:
        policy = self.policy
        data = event.data
        out: dict[str, Any] = {
            'sequence': event.sequence,
            'stage': event.stage,
            'request_id': self.request_id,
        }

        if event.stage == STAGE_CATALOG:
            self._put(out, 'source', data.get('source'))
            self._put(out, 'service_type', data.get('service_type'))
            self._put(out, 'interface', data.get('interface'))
            self._put(out, 'region_name', data.get('region_name'))
            self._put(
                out,
                'service_name',
                data.get('service_name'),
                policy.service_name,
            )
            for key in ('endpoint', 'endpoint_override', 'url'):
                if key in data:
                    self._put(out, key, data[key], policy.endpoint)

        elif event.stage == STAGE_REQUEST:
            self._put(out, 'method', data.get('method'))
            self._put(out, 'url', data.get('url'), policy.endpoint)
            if data.get('query_params'):
                self._put(
                    out,
                    'query_params',
                    data.get('query_params'),
                    policy.endpoint,
                )
            if data.get('headers'):
                out['headers'] = self._header_view(data['headers'])
            if 'body' in data:
                out['body'] = self._body_view(
                    data.get('body'),
                    policy.request_body,
                    data.get('url'),
                )

        elif event.stage == STAGE_RESPONSE:
            self._put(out, 'status_code', data.get('status_code'))
            self._put(out, 'url', data.get('url'), policy.endpoint)
            if data.get('headers'):
                out['headers'] = self._header_view(data['headers'])
            if 'body' in data:
                out['body'] = self._body_view(
                    data.get('body'),
                    policy.response_body,
                    data.get('url'),
                )

        elif event.stage == STAGE_RETRY:
            self._put(out, 'kind', data.get('kind'))
            self._put(out, 'status_code', data.get('status_code'))
            self._put(out, 'retries_left', data.get('retries_left'))
            self._put(out, 'delay', data.get('delay'))
            self._put(out, 'location', data.get('location'), policy.endpoint)
            # A connection error message commonly contains the address.
            self._put(out, 'reason', data.get('reason'), policy.endpoint)

        elif event.stage == STAGE_REAUTH:
            self._put(out, 'triggered', data.get('triggered'))
            self._put(out, 'status_code', data.get('status_code'))
            self._put(out, 'authenticated', data.get('authenticated'))
            self._put(out, 'allow_reauth', data.get('allow_reauth'))
            self._put(out, 'invalidated', data.get('invalidated'))
            self._put(out, 'retried', data.get('retried'))

        elif event.stage == STAGE_ERROR:
            self._put(out, 'exception', data.get('exception'))
            self._put(out, 'http_status', data.get('http_status'))
            self._put(out, 'method', data.get('method'))
            self._put(out, 'url', data.get('url'), policy.endpoint)
            self._put(out, 'message', data.get('message'))
            self._put(
                out, 'details', data.get('details'), policy.response_body
            )
            self._put(
                out, 'response_request_id', data.get('response_request_id')
            )

        else:  # pragma: no cover - defensive, stages are internal
            self._put(out, 'data', data)

        return out

    def public_view(self) -> dict[str, Any]:
        """Return the shareable, policy-filtered diagnostic export."""
        return {
            'schema': SCHEMA,
            'request_id': self.request_id,
            'request_kind': self.request_kind,
            'dual_token': self.dual_token,
            'policy': self.policy.public_approvals(),
            'private_marker_digests': self.policy.marker_digests(),
            'stages': [self._public_event(event) for event in self.events],
        }

    def internal_view(self) -> dict[str, Any]:
        """Return the unredacted record for controlled debugging."""
        stages = []
        for event in self.events:
            stage = {
                'sequence': event.sequence,
                'stage': event.stage,
                'request_id': self.request_id,
            }
            stage.update(event.data)
            stages.append(stage)
        return {
            'schema': SCHEMA,
            'request_id': self.request_id,
            'request_kind': self.request_kind,
            'dual_token': self.dual_token,
            'private_markers': list(self.policy.private_markers),
            'stages': stages,
        }
