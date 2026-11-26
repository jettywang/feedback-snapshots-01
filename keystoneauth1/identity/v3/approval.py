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

"""Approved identity provider configurations and login receipts.

A deployment may switch the identity provider behind a federation in batches.
A login that was already started cannot be moved to the new provider safely:
the identity service maps the federated principal to a local user id, and
two providers can map different people to the same id. Every login therefore
records the approved configuration it started under, and the scope it is
going to ask Keystone for, so that the discovery, token exchange and the
federated endpoint that performs the local mapping can all be checked against
that same approval.

The records are plain values. A caller obtains a :class:`LoginReceipt` before
the user finishes the interactive part of a login, stores it alongside
whatever it uses to resume the login, and hands it back to the plugin. The
plugin resolves it through :class:`ProviderApprovals` on every attempt, which
is also how a withdrawn or retired approval turns into a clear, explicit
state that the login has to be started again.
"""

import datetime
import json
import uuid

from keystoneauth1 import _utils
from keystoneauth1 import exceptions

__all__ = (
    'LoginReceipt',
    'ProviderApproval',
    'ProviderApprovals',
    'SCOPE_FIELDS',
)

#: The Keystone scope parameters a login can ask for, in the order they are
#: checked. A receipt records only those that were actually set.
SCOPE_FIELDS = (
    'trust_id',
    'system_scope',
    'domain_id',
    'domain_name',
    'project_id',
    'project_name',
    'project_domain_id',
    'project_domain_name',
)


def _naive_utc(value: datetime.datetime) -> datetime.datetime:
    """Return a comparable UTC-naive datetime."""
    return _utils.normalize_time(value)


class ProviderApproval:
    """One approved identity provider configuration.

    Each approval has a generation that identifies it. The generation is what
    a login receipt records, not the individual endpoints: a later approval
    may reuse the same URLs while changing something that only the identity
    service knows about, and the identity service's mapping is the part that
    must not be confused across a switch.

    :param generation: Identifier for this approved configuration. It must be
        unique within the registry that holds it.
    :param auth_url: Identity service endpoint the configuration was approved
        against.
    :param identity_provider: Identity provider name approved for federation.
    :param protocol: Federation protocol approved for federation.
    :param discovery_endpoint: Approved OpenID Connect discovery document URL.
    :param access_token_endpoint: Approved OpenID Connect token endpoint.
    :param device_authorization_endpoint: Approved OAuth 2.0 device
        authorization endpoint, for the device authorization flow.
    :param retires_at: Time after which a login started under this approval
        must not finish. A receipt that arrives after it has to be started
        again. Left unset, only an explicit withdrawal invalidates it.
    """

    def __init__(
        self,
        generation: str,
        auth_url: str,
        identity_provider: str,
        protocol: str,
        *,
        discovery_endpoint: str | None = None,
        access_token_endpoint: str | None = None,
        device_authorization_endpoint: str | None = None,
        retires_at: datetime.datetime | None = None,
    ):
        self.generation = str(generation)
        self.auth_url = auth_url
        self.identity_provider = identity_provider
        self.protocol = protocol
        self.discovery_endpoint = discovery_endpoint
        self.access_token_endpoint = access_token_endpoint
        self.device_authorization_endpoint = device_authorization_endpoint
        self.retires_at = retires_at

        if not self.generation:
            raise ValueError('An approved configuration needs a generation')
        if isinstance(self.retires_at, str):
            self.retires_at = _utils.parse_isotime(self.retires_at)

    def retired(self, now: datetime.datetime | None = None) -> bool:
        """Return whether this approval has reached its retirement time."""
        if self.retires_at is None:
            return False

        now = now or _utils.from_utcnow()
        return _naive_utc(self.retires_at) <= _naive_utc(now)

    def replace(self, **kwargs: object) -> 'ProviderApproval':
        """Return a copy with the given attributes changed."""
        values = {
            'generation': self.generation,
            'auth_url': self.auth_url,
            'identity_provider': self.identity_provider,
            'protocol': self.protocol,
            'discovery_endpoint': self.discovery_endpoint,
            'access_token_endpoint': self.access_token_endpoint,
            'device_authorization_endpoint': (
                self.device_authorization_endpoint
            ),
            'retires_at': self.retires_at,
        }
        values.update(kwargs)
        return ProviderApproval(**values)  # type: ignore[arg-type]

    def __repr__(self) -> str:
        return (
            f'ProviderApproval(generation={self.generation!r}, '
            f'identity_provider={self.identity_provider!r}, '
            f'protocol={self.protocol!r})'
        )


class LoginReceipt:
    """What a login started under, kept so it can be checked at the end.

    The receipt is deliberately small and serialisable: a caller stores it
    while the user completes an interactive step, possibly in another process
    or on another day, and hands it back when the login resumes.

    :param generation: Generation of the approval the login started under.
    :param scope: The Keystone scope parameters that were chosen when the
        login started. The scope finally handed to Keystone has to be the
        same.
    :param openid_scope: The OpenID Connect scope requested from the
        provider when the login started, if any.
    :param identity_provider: Identity provider the login started against,
        recorded for correlation and diagnostics.
    :param protocol: Federation protocol the login started against, recorded
        for correlation and diagnostics.
    :param login_id: Identifier tying requests and the receipt together.
    """

    def __init__(
        self,
        generation: str,
        scope: dict[str, str] | None = None,
        *,
        openid_scope: str | None = None,
        identity_provider: str | None = None,
        protocol: str | None = None,
        login_id: str | None = None,
    ):
        self.generation = str(generation)
        self.scope = dict(scope or {})
        self.openid_scope = openid_scope
        self.identity_provider = identity_provider
        self.protocol = protocol
        self.login_id = login_id or uuid.uuid4().hex

        if not self.generation:
            raise ValueError('A login receipt needs an approval generation')

        for key, value in self.scope.items():
            if key not in SCOPE_FIELDS:
                raise ValueError(f'Unknown scope field {key!r}')
            if not isinstance(value, str):
                raise ValueError(f'Scope field {key!r} must be a string')

    def to_dict(self) -> dict[str, object]:
        return {
            'generation': self.generation,
            'scope': dict(self.scope),
            'openid_scope': self.openid_scope,
            'identity_provider': self.identity_provider,
            'protocol': self.protocol,
            'login_id': self.login_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> 'LoginReceipt':
        """Build a receipt from what :meth:`to_dict` returns."""
        try:
            generation = data['generation']
            scope = data.get('scope') or {}
        except AttributeError:
            raise ValueError('Not a login receipt')

        if not isinstance(generation, str) or not isinstance(scope, dict):
            raise ValueError('Not a login receipt')

        def _optional_str(key: str) -> str | None:
            value = data.get(key)
            if value is not None and not isinstance(value, str):
                raise ValueError(
                    f'Login receipt field {key!r} is not a string'
                )
            return value

        return cls(
            generation,
            scope,
            openid_scope=_optional_str('openid_scope'),
            identity_provider=_optional_str('identity_provider'),
            protocol=_optional_str('protocol'),
            login_id=_optional_str('login_id'),
        )

    def to_string(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_string(cls, data: str) -> 'LoginReceipt':
        try:
            parsed = json.loads(data)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError('Not a login receipt') from exc

        if not isinstance(parsed, dict):
            raise ValueError('Not a login receipt')

        return cls.from_dict(parsed)

    def __repr__(self) -> str:
        return (
            f'LoginReceipt(login_id={self.login_id!r}, '
            f'generation={self.generation!r}, scope={self.scope!r})'
        )


class ProviderApprovals:
    """The approved provider configurations a deployment may be in.

    While a batch switch is in progress more than one configuration is valid:
    the one new logins use, and the earlier one that already started logins
    still need until they finish. :meth:`approve` makes a configuration the
    current one without discarding the earlier ones. :meth:`withdraw` and
    :meth:`retire` record that an earlier one must no longer be used, which
    makes every login receipt bound to it raise
    :class:`~keystoneauth1.exceptions.oidc.OidcLoginReopenRequired`.

    :param approvals: Initial approvals, as individual objects or an iterable
        of them.
    :param current: Generation of the current approval. Defaults to the last
        approval given.
    """

    def __init__(
        self,
        *approvals: ProviderApproval | list[ProviderApproval],
        current: str | None = None,
    ):
        self._approvals: dict[str, ProviderApproval] = {}
        self._withdrawn: set[str] = set()
        self._current: str | None = None

        for item in approvals:
            if isinstance(item, ProviderApproval):
                self.approve(item, current=False)
            else:
                for approval in item:
                    self.approve(approval, current=False)

        if current is not None:
            self.set_current(current)
        elif self._approvals:
            self._current = next(reversed(self._approvals))

    def approve(
        self, approval: ProviderApproval, *, current: bool = True
    ) -> None:
        """Record an approved configuration, optionally making it current."""
        self._approvals[approval.generation] = approval
        self._withdrawn.discard(approval.generation)
        if current:
            self._current = approval.generation

    def set_current(self, generation: str) -> None:
        """Make an approved configuration the one new logins use."""
        generation = str(generation)
        if generation not in self._approvals:
            raise ValueError(f'No approved configuration {generation!r}')
        if generation in self._withdrawn:
            raise ValueError(
                f'Approved configuration {generation!r} was withdrawn'
            )
        self._current = generation

    def current(self) -> ProviderApproval:
        """Return the configuration new logins should use."""
        if self._current is None:
            raise ValueError('No approved configuration')
        return self._approvals[self._current]

    def get(self, generation: str) -> ProviderApproval | None:
        """Return an approval by generation, whether or not it is valid."""
        return self._approvals.get(str(generation))

    def is_withdrawn(self, generation: str) -> bool:
        return str(generation) in self._withdrawn

    def withdraw(self, generation: str) -> None:
        """Record that no login may use this approval any more.

        Withdrawing the current approval leaves no current one; a later
        :meth:`approve` names what new logins should use.
        """
        generation = str(generation)
        if generation not in self._approvals:
            raise ValueError(f'No approved configuration {generation!r}')
        self._withdrawn.add(generation)
        if self._current == generation:
            self._current = None

    def retire(
        self, generation: str, retires_at: datetime.datetime | None = None
    ) -> None:
        """Record a retirement time for an approval, by default now."""
        generation = str(generation)
        approval = self._approvals.get(generation)
        if approval is None:
            raise ValueError(f'No approved configuration {generation!r}')

        if retires_at is None:
            retires_at = _utils.from_utcnow()
        self._approvals[generation] = approval.replace(retires_at=retires_at)

    def resolve(self, receipt: LoginReceipt | str) -> ProviderApproval:
        """Return the approval a receipt was started under, if still valid.

        :raises keystoneauth1.exceptions.oidc.OidcLoginReopenRequired:
            When the approval was withdrawn, has reached its retirement time,
            or is not known here at all. The login cannot continue and has to
            be started again.
        """
        if isinstance(receipt, LoginReceipt):
            generation = receipt.generation
            login_id = receipt.login_id
        else:
            generation = str(receipt)
            login_id = None

        approval = self._approvals.get(generation)
        if approval is None:
            raise exceptions.OidcLoginReopenRequired(
                reason='unknown',
                generation=generation,
                login_id=login_id,
            )

        if generation in self._withdrawn:
            raise exceptions.OidcLoginReopenRequired(
                reason='withdrawn',
                generation=generation,
                login_id=login_id,
            )

        if approval.retired():
            raise exceptions.OidcLoginReopenRequired(
                reason='retired',
                generation=generation,
                login_id=login_id,
            )

        return approval

    def to_dict(self) -> dict[str, object]:
        """Serialise the registry, for handing it to another process."""
        return {
            'current': self._current,
            'approvals': [
                {
                    'generation': item.generation,
                    'auth_url': item.auth_url,
                    'identity_provider': item.identity_provider,
                    'protocol': item.protocol,
                    'discovery_endpoint': item.discovery_endpoint,
                    'access_token_endpoint': item.access_token_endpoint,
                    'device_authorization_endpoint': (
                        item.device_authorization_endpoint
                    ),
                    'retires_at': (
                        item.retires_at.isoformat()
                        if item.retires_at is not None
                        else None
                    ),
                }
                for item in self._approvals.values()
            ],
            'withdrawn': sorted(self._withdrawn),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> 'ProviderApprovals':
        """Rebuild a registry from what :meth:`to_dict` returned."""
        try:
            approvals = data['approvals']
            current = data.get('current')
            withdrawn = data.get('withdrawn') or []
        except AttributeError:
            raise ValueError('Not an approval registry')

        if not isinstance(approvals, list):
            raise ValueError('Not an approval registry')

        registry = cls()
        for item in approvals:
            if not isinstance(item, dict):
                raise ValueError('Not an approval registry')
            registry.approve(
                ProviderApproval(
                    generation=item['generation'],
                    auth_url=item['auth_url'],
                    identity_provider=item['identity_provider'],
                    protocol=item['protocol'],
                    discovery_endpoint=item.get('discovery_endpoint'),
                    access_token_endpoint=item.get('access_token_endpoint'),
                    device_authorization_endpoint=item.get(
                        'device_authorization_endpoint'
                    ),
                    retires_at=item.get('retires_at'),
                ),
                current=False,
            )

        for generation in withdrawn:
            registry.withdraw(str(generation))

        if current is not None:
            registry.set_current(str(current))
        elif registry._approvals:
            # Serialised without a current generation, which happens when it
            # was withdrawn: fall back to the last still-valid approval.
            for generation in reversed(registry._approvals):
                if generation not in registry._withdrawn:
                    registry._current = generation
                    break

        return registry

    @classmethod
    def from_json(cls, data: str) -> 'ProviderApprovals':
        try:
            parsed = json.loads(data)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError('Not an approval registry') from exc

        if not isinstance(parsed, dict):
            raise ValueError('Not an approval registry')
        return cls.from_dict(parsed)
