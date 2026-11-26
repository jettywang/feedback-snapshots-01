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

"""Outbound address scopes for discovery and business requests.

A :class:`OutboundPolicy` keeps two independently mutable allow-lists.  The
discovery scope is used for catalog/version negotiation and never carries the
caller's business token by default.  The business scope is used for ordinary
authenticated API calls.  The policy is evaluated immediately before every
real transport send, so redirects, connection retries, status retries and
retries after re-authentication all use the currently approved addresses.
"""

from __future__ import annotations

import dataclasses
import threading
import contextlib
from contextvars import ContextVar
import urllib.parse
from collections.abc import Iterable, Mapping, MutableMapping
from typing import Any

from keystoneauth1 import exceptions


DISCOVERY = 'discovery'
BUSINESS = 'business'
IDENTITY = 'identity'

# Descriptive aliases used throughout the OpenStack terminology.
PUBLIC = DISCOVERY
SERVICE = BUSINESS

_PHASE_ALIASES = {
    DISCOVERY: DISCOVERY,
    'discover': DISCOVERY,
    'public': DISCOVERY,
    'catalog': DISCOVERY,
    'catalogue': DISCOVERY,
    'version': DISCOVERY,
    'versions': DISCOVERY,
    'version-negotiation': DISCOVERY,
    'version_negotiation': DISCOVERY,
    'public-discovery': DISCOVERY,
    'public_discovery': DISCOVERY,
    'public-query': DISCOVERY,
    'public_query': DISCOVERY,
    IDENTITY: IDENTITY,
    'auth': IDENTITY,
    'authentication': IDENTITY,
    'identity-service': IDENTITY,
    'identity_service': IDENTITY,
    BUSINESS: BUSINESS,
    'business': BUSINESS,
    'service': BUSINESS,
    'application': BUSINESS,
    'app': BUSINESS,
    'api': BUSINESS,
    'workload': BUSINESS,
    'private': BUSINESS,
    'internal': BUSINESS,
    'protected': BUSINESS,
    'registered-service': BUSINESS,
    'registered_service': BUSINESS,
    'service-area': BUSINESS,
    'service_area': BUSINESS,
}

_BUSINESS_CREDENTIAL_HEADERS = frozenset(
    ('x-auth-token', 'x-service-token', 'authorization')
)

_CURRENT_PHASE: ContextVar[str | None] = ContextVar(
    'keystoneauth_outbound_phase', default=None
)


@contextlib.contextmanager
def phase_scope(phase: Any):
    """Temporarily set the outbound phase for synchronous sends."""
    token = _CURRENT_PHASE.set(normalize_phase(phase))
    try:
        yield
    finally:
        _CURRENT_PHASE.reset(token)


def current_phase() -> str | None:
    phase = _CURRENT_PHASE.get()
    return normalize_phase(phase) if phase is not None else None


_PHASE_KEYS = {
    DISCOVERY: ('discovery', 'public', 'catalog', 'catalogue', 'version'),
    BUSINESS: (
        'business',
        'service',
        'application',
        'app',
        'workload',
        'private',
        'internal',
        'protected',
        'registered',
    ),
}
_GLOBAL_ADDRESS_KEYS = frozenset(
    (
        'allowed_addresses',
        'addresses',
        'allowed_domains',
        'domains',
        'allowed_origins',
        'origins',
        'outbound_addresses',
        'egress_addresses',
        'outbound_ranges',
        'egress_ranges',
        'allowed_networks',
        'networks',
    )
)
_ADDRESS_KEY_PARTS = (
    'address',
    'endpoint',
    'origin',
    'url',
    'uri',
    'domain',
    'host',
    'scope',
    'range',
    'allowlist',
    'allow-list',
    'allow_list',
    'allowed-list',
    'allowed_list',
    'whitelist',
    'network',
    'cidr',
    'zone',
    'destination',
    'target',
)
_POLICY_KEYS = (
    'outbound_policy',
    'outbound_scope',
    'outbound_scopes',
    'outbound',
    'egress_policy',
    'egress_scope',
    'egress_scopes',
    'egress',
    'network_policy',
    'network_partition_policy',
    'address_policy',
    'allowed_address_policy',
    'scopes',
)
_PHASE_KEYS_REQUEST = (
    'outbound_phase',
    'phase',
    'request_phase',
    'network_phase',
    'egress_phase',
    'outbound_stage',
    'stage',
)


def normalize_phase(phase: Any = None) -> str:
    """Return the canonical phase name."""
    if phase is None:
        return BUSINESS
    text = str(phase).strip().lower().replace('-', '_')
    text = text.replace(' ', '_')
    try:
        return _PHASE_ALIASES[text]
    except KeyError:
        # Also accept hyphenated forms after the underscore lookup failed.
        hyphenated = text.replace('_', '-')
        if hyphenated in _PHASE_ALIASES:
            return _PHASE_ALIASES[hyphenated]
        raise ValueError(f'Unknown outbound phase: {phase!r}') from None


def _first_not_none(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _as_address_list(value: Any) -> Iterable[str]:
    if value is None:
        return ()
    if isinstance(value, str | bytes):
        return (value.decode() if isinstance(value, bytes) else value,)
    if callable(value):
        value = value()
    return value


def _address_from_mapping(value: Mapping[str, Any]) -> str:
    for key in ('url', 'uri', 'address', 'endpoint', 'origin', 'host'):
        if key in value:
            return str(value[key])
    raise ValueError(f'Address mapping does not contain a URL: {value!r}')


def parse_address(address: Any) -> tuple[str, str, int | None, str]:
    """Normalize an address/URL to a comparable origin/path prefix."""
    if isinstance(address, urllib.parse.ParseResult):
        parsed = address
    elif isinstance(address, Mapping):
        text = _address_from_mapping(address)
        parsed = urllib.parse.urlparse(text)
    elif hasattr(address, 'url'):
        parsed = urllib.parse.urlparse(str(address.url))
    else:
        text = str(address).strip()
        if '://' not in text:
            if not text.startswith(('//', '/', '?', '#')):
                text = '//' + text
        parsed = urllib.parse.urlparse(text)

    host = (parsed.hostname or '').lower()
    if not host:
        raise ValueError(f'Address does not contain a host: {address!r}')

    try:
        port = parsed.port
    except ValueError:
        # callers may use synthetic host names without valid numeric ports
        netloc = parsed.netloc.rsplit('@', 1)[-1]
        if ':' in netloc and netloc.rsplit(':', 1)[1].isdigit():
            port = int(netloc.rsplit(':', 1)[1])
        else:
            port = None

    if port is None:
        if parsed.scheme.lower() == 'https':
            port = 443
        elif parsed.scheme.lower() == 'http':
            port = 80

    path = urllib.parse.unquote(parsed.path or '').rstrip('/')
    return parsed.scheme.lower() or '*', host, port, path


def _rule_matches(
    rule: tuple[str, str, int | None, str],
    target: tuple[str, str, int | None, str],
) -> bool:
    rule_scheme, rule_host, rule_port, rule_path = rule
    target_scheme, target_host, target_port, target_path = target

    if rule_scheme != '*' and rule_scheme != target_scheme:
        return False
    if rule_port is not None and rule_port != target_port:
        return False

    if rule_host.startswith('*.'):
        suffix = rule_host[1:]
        if not target_host.endswith(suffix):
            return False
        # *.example.com should not match the apex itself.
        if target_host == rule_host[2:]:
            return False
    elif rule_host != target_host:
        return False

    if rule_path:
        if target_path != rule_path and not target_path.startswith(
            rule_path + '/'
        ):
            return False
    return True


def scope_for_phase(phase: Any) -> str:
    """Return the configured address scope used by a phase."""
    phase_name = normalize_phase(phase)
    if phase_name in (DISCOVERY, IDENTITY):
        return DISCOVERY
    return BUSINESS


def has_business_credentials(
    headers: Mapping[str, Any] | None, phase: Any = None
) -> bool:
    """Return whether standard business token headers have values."""
    if not headers:
        return False

    token_headers = frozenset(('x-auth-token', 'x-service-token'))
    for key, value in headers.items():
        if key.lower() in token_headers and value:
            return True

    # Generic Authorization is a business credential only on the business
    # phase. During identity exchange it may be HTTP Basic/client credentials.
    if phase is None or scope_for_phase(phase) == BUSINESS:
        for key, value in headers.items():
            if key.lower() == 'authorization' and value:
                return True
    return False


def apply_credential_boundary(
    phase: str, headers: MutableMapping[str, Any] | None
) -> None:
    """Remove business credentials from a public/discovery request."""
    if headers is None or normalize_phase(phase) != DISCOVERY:
        return
    for header in tuple(headers):
        if header.lower() in _BUSINESS_CREDENTIAL_HEADERS:
            headers.pop(header, None)


@dataclasses.dataclass(frozen=True)
class OutboundDecision:
    """The result of approving one prospective transport send."""

    allowed: bool
    phase: str
    url: str
    reason: str
    credential_scope: str
    business_credentials: bool = False
    matched_address: str | None = None

    def raise_if_denied(self) -> None:
        if not self.allowed:
            raise exceptions.OutboundAddressDenied(decision=self)


@dataclasses.dataclass(frozen=True)
class OutboundSendRecord:
    """A minimal secret-free record of one actual send."""

    phase: str
    url: str
    method: str | None
    business_credentials: bool
    credential_scope: str


class OutboundPolicy:
    """Mutable two-phase outbound address policy.

    Addresses may be complete origins (``http://public.example``) or URL
    prefixes (``http://example/v2``).  An address without a path allows every
    path on that origin.  Passing ``None`` for a phase leaves that phase
    unrestricted; passing an empty iterable denies every address in that phase.
    """

    def __init__(
        self,
        discovery_addresses: Any = None,
        business_addresses: Any = None,
        *,
        public_addresses: Any = None,
        service_addresses: Any = None,
        allowed_addresses: Any = None,
        addresses: Any = None,
        allowed_domains: Iterable[str] | None = None,
        record_decisions: bool = True,
    ) -> None:
        mapping = None
        if (
            isinstance(discovery_addresses, Mapping)
            and business_addresses is None
        ):
            mapping = discovery_addresses
            discovery_addresses = None

        self._lock = threading.RLock()
        self.discovery_addresses: set[str] = set()
        self.business_addresses: set[str] = set()
        self.domain_addresses: set[str] = set()
        self.record_decisions = record_decisions
        self.decisions: list[OutboundDecision] = []
        self.sends: list[OutboundSendRecord] = []

        global_addresses = _first_not_none(allowed_addresses, addresses)
        discovery_value = _first_not_none(
            discovery_addresses, public_addresses
        )
        business_value = _first_not_none(business_addresses, service_addresses)

        if mapping is not None:
            discovery_value = _first_not_none(
                discovery_value,
                *(mapping.get(k) for k in _PHASE_KEYS[DISCOVERY]),
            )
            business_value = _first_not_none(
                business_value,
                *(mapping.get(k) for k in _PHASE_KEYS[BUSINESS]),
            )
            global_addresses = _first_not_none(
                global_addresses, mapping.get('allowed'), mapping.get('all')
            )

        self._restricted = {
            DISCOVERY: discovery_value is not None
            or global_addresses is not None,
            BUSINESS: business_value is not None
            or global_addresses is not None,
        }

        for value in _as_address_list(global_addresses):
            self.add_address(DISCOVERY, value)
            self.add_address(BUSINESS, value)
        for value in _as_address_list(discovery_value):
            self.add_address(DISCOVERY, value)
        for value in _as_address_list(business_value):
            self.add_address(BUSINESS, value)
        for domain in _as_address_list(allowed_domains):
            self.add_domain(domain)

    # ------------------------------------------------------------------
    # Compatibility constructors and coercion
    # ------------------------------------------------------------------
    @classmethod
    def coerce(cls, policy: Any) -> OutboundPolicy | None:
        if policy is None or isinstance(policy, cls):
            return policy
        if isinstance(policy, Mapping):
            constructor_keys = {
                'discovery_addresses',
                'business_addresses',
                'public_addresses',
                'service_addresses',
                'allowed_addresses',
                'addresses',
                'allowed_domains',
                'record_decisions',
            }
            if all(key in constructor_keys for key in policy):
                return cls(**policy)
            return cls(policy)
        if isinstance(policy, Iterable) and not isinstance(policy, str):
            values = list(policy)
            if len(values) == 2 and all(
                isinstance(item, Iterable) and not isinstance(item, str)
                for item in values
            ):
                return cls(values[0], values[1])
            return cls(allowed_addresses=values)
        raise TypeError(f'Unsupported outbound policy: {policy!r}')

    # ------------------------------------------------------------------
    # Mutable configuration
    # ------------------------------------------------------------------
    def _set_for(self, phase: Any) -> set[str]:
        scope = scope_for_phase(phase)
        return (
            self.discovery_addresses
            if scope == DISCOVERY
            else self.business_addresses
        )

    def add_address(self, phase: Any, address: Any) -> OutboundPolicy:
        phase_name = normalize_phase(phase)
        scope_name = scope_for_phase(phase_name)
        parse_address(address)  # fail early on invalid configuration
        with self._lock:
            self._set_for(scope_name).add(str(address))
            self._restricted[scope_name] = True
        return self

    def allow_address(self, phase: Any, address: Any) -> OutboundPolicy:
        return self.add_address(phase, address)

    def remove_address(self, phase: Any, address: Any) -> OutboundPolicy:
        address_set = self._set_for(phase)
        try:
            normalized = parse_address(address)
        except ValueError:
            normalized = None
        with self._lock:
            address_set.discard(str(address))
            if normalized is not None:
                for raw_address in tuple(address_set):
                    try:
                        if parse_address(raw_address) == normalized:
                            address_set.discard(raw_address)
                    except ValueError:
                        continue
        return self

    def revoke_address(self, phase: Any, address: Any) -> OutboundPolicy:
        return self.remove_address(phase, address)

    def withdraw_address(self, phase: Any, address: Any) -> OutboundPolicy:
        return self.remove_address(phase, address)

    def add_domain(self, domain: str) -> OutboundPolicy:
        text = str(domain).strip().lower()
        if '://' in text:
            text = urllib.parse.urlparse(text).hostname or text
        with self._lock:
            self.domain_addresses.add(text)
        return self

    # Explicit phase-specific helpers.
    def allow_discovery_address(self, address: Any) -> OutboundPolicy:
        return self.add_address(DISCOVERY, address)

    def allow_public_address(self, address: Any) -> OutboundPolicy:
        return self.add_address(DISCOVERY, address)

    def revoke_discovery_address(self, address: Any) -> OutboundPolicy:
        return self.remove_address(DISCOVERY, address)

    def revoke_public_address(self, address: Any) -> OutboundPolicy:
        return self.remove_address(DISCOVERY, address)

    def withdraw_public_address(self, address: Any) -> OutboundPolicy:
        return self.remove_address(DISCOVERY, address)

    def allow_business_address(self, address: Any) -> OutboundPolicy:
        return self.add_address(BUSINESS, address)

    def allow_service_address(self, address: Any) -> OutboundPolicy:
        return self.add_address(BUSINESS, address)

    def revoke_business_address(self, address: Any) -> OutboundPolicy:
        return self.remove_address(BUSINESS, address)

    def revoke_service_address(self, address: Any) -> OutboundPolicy:
        return self.remove_address(BUSINESS, address)

    def withdraw_business_address(self, address: Any) -> OutboundPolicy:
        return self.remove_address(BUSINESS, address)

    def withdraw_service_address(self, address: Any) -> OutboundPolicy:
        return self.remove_address(BUSINESS, address)

    # Alias properties for callers that use OpenStack "service" wording.
    @property
    def public_addresses(self) -> set[str]:
        return self.discovery_addresses

    @property
    def service_addresses(self) -> set[str]:
        return self.business_addresses

    @property
    def allowed_discovery_addresses(self) -> set[str]:
        return self.discovery_addresses

    @property
    def allowed_public_addresses(self) -> set[str]:
        return self.discovery_addresses

    @property
    def allowed_business_addresses(self) -> set[str]:
        return self.business_addresses

    @property
    def allowed_service_addresses(self) -> set[str]:
        return self.business_addresses

    # ------------------------------------------------------------------
    # Evaluation and recording
    # ------------------------------------------------------------------
    def _domain_matches(
        self, target_host: str, domains: Iterable[str] | None = None
    ) -> bool:
        domain_rules = self.domain_addresses if domains is None else domains
        for domain in domain_rules:
            if target_host == domain or target_host.endswith('.' + domain):
                return True
        return False

    def evaluate(
        self, phase: Any, url: str, headers: Mapping[str, Any] | None = None
    ) -> OutboundDecision:
        phase_name = normalize_phase(phase)
        scope_name = scope_for_phase(phase_name)
        credential_scope = {
            DISCOVERY: 'public',
            IDENTITY: 'identity',
            BUSINESS: 'business',
        }[phase_name]
        with self._lock:
            restricted = self._restricted[scope_name]
            addresses = set(self._set_for(scope_name))
            domains = set(self.domain_addresses)

        business_credentials = has_business_credentials(headers, phase_name)

        try:
            target = parse_address(url)
        except (ValueError, TypeError):
            decision = OutboundDecision(
                allowed=False,
                phase=phase_name,
                url=str(url),
                reason='invalid_url',
                credential_scope=credential_scope,
                business_credentials=business_credentials,
            )
            self._remember(decision)
            return decision

        if not restricted:
            decision = OutboundDecision(
                allowed=True,
                phase=phase_name,
                url=url,
                reason='scope_unconfigured',
                credential_scope=credential_scope,
                business_credentials=business_credentials,
            )
            self._remember(decision)
            return decision

        if domains and self._domain_matches(target[1], domains):
            decision = OutboundDecision(
                allowed=True,
                phase=phase_name,
                url=url,
                reason='domain_allowed',
                credential_scope=credential_scope,
                business_credentials=business_credentials,
                matched_address=target[1],
            )
            self._remember(decision)
            return decision

        for raw_address in addresses:
            try:
                rule = parse_address(raw_address)
            except ValueError:
                continue
            if _rule_matches(rule, target):
                decision = OutboundDecision(
                    allowed=True,
                    phase=phase_name,
                    url=url,
                    reason='address_allowed',
                    credential_scope=credential_scope,
                    business_credentials=business_credentials,
                    matched_address=raw_address,
                )
                self._remember(decision)
                return decision

        decision = OutboundDecision(
            allowed=False,
            phase=phase_name,
            url=url,
            reason='address_not_approved',
            credential_scope=credential_scope,
            business_credentials=business_credentials,
        )
        self._remember(decision)
        return decision

    def _remember(self, decision: OutboundDecision) -> None:
        if self.record_decisions:
            with self._lock:
                self.decisions.append(decision)

    def authorize(
        self,
        phase: Any = None,
        url: str | None = None,
        *,
        headers: Mapping[str, Any] | None = None,
        method: str | None = None,
    ) -> OutboundDecision:
        # Convenience for policy.authorize(url) and authorize(url, phase).
        if url is None and isinstance(phase, str):
            if urllib.parse.urlparse(phase).scheme or '://' in phase:
                url = phase
                phase = None
        elif (
            isinstance(url, str)
            and phase is not None
            and not isinstance(phase, str)
        ):
            phase, url = url, phase

        decision = self.evaluate(phase, url or '', headers)
        if not decision.allowed:
            raise exceptions.OutboundAddressDenied(decision=decision)
        return decision

    def check(self, *args: Any, **kwargs: Any) -> OutboundDecision:
        """Evaluate without raising.

        Supports both ``check(phase, url)`` and ``check(url, phase=...)``.
        """
        phase = kwargs.pop('phase', None)
        url = kwargs.pop('url', None)
        headers = kwargs.pop('headers', None)
        if args:
            if len(args) == 1 and url is None:
                first = args[0]
                if isinstance(first, str) and (
                    '://' in first or first.startswith('//')
                ):
                    url = first
                else:
                    phase = first
            elif len(args) >= 2:
                first, second = args[0], args[1]
                first_is_url = isinstance(first, str) and (
                    '://' in first or first.startswith('//')
                )
                if first_is_url:
                    url, phase = first, second
                else:
                    phase, url = first, second
        if phase is None and url is None and len(args) == 1:
            url = args[0]
        return self.evaluate(phase, url or '', headers)

    def is_allowed(self, *args: Any, **kwargs: Any) -> bool:
        return self.check(*args, **kwargs).allowed

    def record_send(
        self,
        decision: OutboundDecision,
        headers: Mapping[str, Any] | None = None,
        method: str | None = None,
    ) -> OutboundSendRecord:
        record = OutboundSendRecord(
            phase=decision.phase,
            url=decision.url,
            method=method,
            business_credentials=has_business_credentials(
                headers, decision.phase
            ),
            credential_scope=decision.credential_scope,
        )
        with self._lock:
            self.sends.append(record)
        return record

    def reset_records(self) -> None:
        with self._lock:
            self.decisions.clear()
            self.sends.clear()


def pop_phase_kwarg(kwargs: dict[str, Any]) -> str | None:
    for key in _PHASE_KEYS_REQUEST:
        if key in kwargs:
            value = kwargs.pop(key)
            if value is not None:
                return normalize_phase(value)
    return None


def pop_policy_kwarg(kwargs: dict[str, Any]) -> OutboundPolicy | None:
    for key in _POLICY_KEYS:
        if key in kwargs and kwargs[key] is not None:
            return OutboundPolicy.coerce(kwargs.pop(key))
    return None


def pop_constructor_policy_kwargs(
    kwargs: dict[str, Any],
) -> OutboundPolicy | None:
    """Extract best-effort descriptive constructor aliases."""
    policy = pop_policy_kwarg(kwargs)

    discovery_sources = []
    business_sources = []
    global_sources = []
    for key in list(kwargs):
        lowered = key.lower()
        if lowered in _GLOBAL_ADDRESS_KEYS:
            global_sources.append(kwargs.pop(key))
            continue
        if not any(part in lowered for part in _ADDRESS_KEY_PARTS):
            continue
        phase_match = None
        for phase, markers in _PHASE_KEYS.items():
            if any(marker in lowered for marker in markers):
                phase_match = phase
                break
        if phase_match is None:
            continue
        value = kwargs.pop(key)
        if phase_match == DISCOVERY:
            discovery_sources.append(value)
        else:
            business_sources.append(value)

    if discovery_sources or business_sources or global_sources:
        global_values = [
            item
            for source in global_sources
            for item in _as_address_list(source)
        ]
        discovery_values = list(global_values)
        business_values = list(global_values)
        for source in discovery_sources:
            discovery_values.extend(_as_address_list(source))
        for source in business_sources:
            business_values.extend(_as_address_list(source))

        extra = OutboundPolicy(
            discovery_addresses=discovery_values or None,
            business_addresses=business_values or None,
        )
        if policy is None:
            policy = extra
        else:
            for address in extra.discovery_addresses:
                policy.add_address(DISCOVERY, address)
            for address in extra.business_addresses:
                policy.add_address(BUSINESS, address)

    return policy


# Descriptive aliases for the same two-phase construction.
OutboundScope = OutboundPolicy
EgressPolicy = OutboundPolicy
NetworkPartitionPolicy = OutboundPolicy
AddressAllowlist = OutboundPolicy

NetworkZonePolicy = OutboundPolicy
PartitionPolicy = OutboundPolicy
OutboundAllowlist = OutboundPolicy
EgressAllowlist = OutboundPolicy
AddressScope = OutboundPolicy
TwoPhaseOutboundPolicy = OutboundPolicy
