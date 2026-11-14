from __future__ import unicode_literals

import json
from base64 import standard_b64encode

try:
    from urllib.parse import urlsplit
except ImportError:  # pragma: no cover - Python 2
    from urlparse import urlsplit

from six import string_types

from pymacaroons.binders import HashSignaturesBinder
from pymacaroons.exceptions import (
    AmbiguousDischargeCaveat,
    DischargeRedirectRefused,
    DischargeRequestException,
    InvalidDischargeResponse,
    UnknownDischargeService,
)
from pymacaroons.macaroon import Macaroon
from pymacaroons.utils import convert_to_bytes, convert_to_string


class Endpoint(object):
    """An exact, locally trusted HTTPS endpoint.

    The endpoint is never derived from a caveat ``location``.  Redirects and
    endpoint changes are refused by :class:`DischargeClient`.
    """

    def __init__(self, url):
        if not isinstance(url, string_types):
            raise ValueError('endpoint must be a URL string')
        parts = urlsplit(url)
        if parts.scheme.lower() != 'https':
            raise ValueError('discharge endpoints must use https')
        if not parts.hostname:
            raise ValueError('endpoint must include a host')
        if parts.username or parts.password:
            raise ValueError('endpoint must not contain userinfo')
        if parts.query or parts.fragment:
            raise ValueError('endpoint must not contain a query or fragment')
        try:
            port = parts.port
        except ValueError:
            raise ValueError('endpoint has an invalid port')
        self.scheme = 'https'
        self.host = parts.hostname.lower()
        self.port = port or 443
        self.path = parts.path or '/'

    @property
    def url(self):
        host = self.host
        if ':' in host and not host.startswith('['):
            host = '[{}]'.format(host)  # IPv6 literal
        if self.port == 443:
            return 'https://{}{}'.format(host, self.path)
        return 'https://{}:{}{}'.format(host, self.port, self.path)

    def __eq__(self, other):
        return (
            isinstance(other, Endpoint) and
            (self.scheme, self.host, self.port, self.path) ==
            (other.scheme, other.host, other.port, other.path)
        )

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.scheme, self.host, self.port, self.path))

    def __repr__(self):
        return 'Endpoint({!r})'.format(self.url)


def normalize_location_hint(hint):
    """Normalize a location only for comparison, never for routing.

    A location may be a bare service label (``bob``) or a URL-like hint.  The
    result of this function is only compared against locally configured
    hints; it is never used as a request URL.
    """
    text = convert_to_string(hint or '').strip()
    if '://' in text:
        try:
            parts = urlsplit(text)
            host = (parts.hostname or '').lower()
            if host:
                port = parts.port
                netloc = host
                if port and port != 443:
                    netloc = '{}:{}'.format(host, port)
                return '{}://{}{}'.format(
                    parts.scheme.lower(), netloc,
                    (parts.path or '/').rstrip('/') or '/'
                )
        except ValueError:
            pass
    return text


def location_hint_keys(hint):
    """Return comparison keys for a location hint.

    URL hints match both their full normalized form and their host (plus a
    non-default port).  These keys only break ties among services that
    already claim the same caveat id; they never choose an endpoint.
    """
    text = convert_to_string(hint or '').strip()
    keys = {normalize_location_hint(text)}
    if '://' in text:
        try:
            parts = urlsplit(text)
            host = (parts.hostname or '').lower()
            if host:
                keys.add(host)
                if parts.port and parts.port != 443:
                    keys.add('{}:{}'.format(host, parts.port))
        except ValueError:
            pass
    return frozenset(key for key in keys if key)


class DischargeService(object):
    """A service trusted by local configuration.

    ``caveat_ids`` is the authoritative list of caveat identifiers this
    service is allowed to discharge.  It is deliberately explicit: the
    presence of an identifier in a caveat does not by itself establish which
    service owns it.
    """

    def __init__(self, service_id, endpoint, location_hints=(),
                 caveat_ids=()):
        if not service_id:
            raise ValueError('service_id is required')
        self.service_id = convert_to_string(service_id)
        self.endpoint = (
            endpoint if isinstance(endpoint, Endpoint) else Endpoint(endpoint)
        )
        self.location_hints = tuple(
            normalize_location_hint(hint) for hint in location_hints
        )
        self._location_keys = frozenset().union(
            *[location_hint_keys(hint) for hint in location_hints]
        )
        self.caveat_ids = tuple(
            convert_to_bytes(caveat_id) for caveat_id in caveat_ids
        )

    def accepts_caveat_id(self, caveat_id):
        return convert_to_bytes(caveat_id) in self.caveat_ids

    def matches_location_hint(self, hint):
        return bool(location_hint_keys(hint) & self._location_keys)


class RoutingDecision(object):
    """The result of resolving an untrusted caveat to a trusted service."""

    def __init__(self, service, caveat, selection_basis,
                 location_hint_status, caveat_id_shared):
        self.service = service
        self.service_id = service.service_id
        self.endpoint = service.endpoint
        self.caveat_id_bytes = convert_to_bytes(caveat.caveat_id_bytes)
        self.location_hint = convert_to_string(caveat.location or '')
        self.selection_basis = selection_basis
        self.location_hint_status = location_hint_status
        self.caveat_id_shared = caveat_id_shared
        self.location_hint_is_trusted = False


class DischargeRegistry(object):
    """Locally configured, authoritative service registry.

    Resolution is by exact caveat identifier whenever a single service claims
    it.  ``location`` is consulted only to break a tie between services that
    explicitly claim the same identifier; it is never used as the request URL
    and never establishes service identity.
    """

    def __init__(self, services):
        self.services = list(services)
        service_ids = [service.service_id for service in self.services]
        if len(service_ids) != len(set(service_ids)):
            raise ValueError('duplicate service_id in local configuration')

    def resolve(self, caveat):
        if not caveat.third_party():
            raise DischargeRequestException(
                'only third-party caveats can be discharged'
            )

        caveat_id = convert_to_bytes(caveat.caveat_id_bytes)
        claimants = [
            service for service in self.services
            if service.accepts_caveat_id(caveat_id)
        ]
        if not claimants:
            raise UnknownDischargeService(
                'no locally configured service claims caveat id {!r}'.format(
                    convert_to_string(caveat_id)
                )
            )

        hint_status = self._hint_status(caveat, claimants)
        if len(claimants) == 1:
            return RoutingDecision(
                claimants[0], caveat, 'caveat_id', hint_status, False
            )

        # A short identifier is shared by more than one configured
        # organization.  Never guess: the untrusted location must identify
        # exactly one of the locally trusted claimants.
        matching = [
            service for service in claimants
            if service.matches_location_hint(caveat.location)
        ]
        if len(matching) != 1:
            raise AmbiguousDischargeCaveat(
                'caveat id {!r} is claimed by {} services and location {!r} '
                'does not identify exactly one of them'.format(
                    convert_to_string(caveat_id), len(claimants),
                    caveat.location
                )
            )
        return RoutingDecision(
            matching[0], caveat, 'location_hint', hint_status, True
        )

    @staticmethod
    def _hint_status(caveat, claimants):
        hint = caveat.location or ''
        if not convert_to_string(hint).strip():
            return 'absent'
        if any(service.matches_location_hint(hint) for service in claimants):
            return 'matched'
        return 'ignored_mismatch'


class DischargeRequest(object):
    """The complete payload sent to a discharge endpoint.

    Only the caveat identifier is sent.  In particular this object has no
    access to the root macaroon, its other caveats, or any discharge already
    obtained by the client.
    """

    def __init__(self, decision, caveat):
        self.method = 'POST'
        self.url = decision.endpoint.url
        self.service_id = decision.service_id
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        self.payload = self._payload_for(caveat)
        self.body = json.dumps(
            self.payload, sort_keys=True, separators=(',', ':')
        ).encode('utf-8')

    @staticmethod
    def _payload_for(caveat):
        caveat_id = convert_to_bytes(caveat.caveat_id_bytes)
        try:
            return {'caveat_id': convert_to_string(caveat_id)}
        except UnicodeDecodeError:
            return {
                'caveat_id_b64': convert_to_string(
                    standard_b64encode(caveat_id)
                )
            }

    def to_dict(self):
        return {
            'method': self.method,
            'url': self.url,
            'headers': dict(self.headers),
            'body': self.body.decode('utf-8'),
        }


class DischargeClient(object):
    """Resolve a caveat locally, fetch one discharge, and bind it to a root.

    ``fetch`` accepts only a caveat, never a root or a container of prior
    discharges.  This makes accidental disclosure of unrelated credentials a
    structural impossibility rather than a convention.  ``bind`` is a
    separate step performed after the response has been received.
    """

    def __init__(self, registry, transport):
        self.registry = registry
        self.transport = transport

    def fetch(self, caveat):
        decision = self.registry.resolve(caveat)
        request = DischargeRequest(decision, caveat)
        response = self.transport.send(request)
        discharge = self._parse_response(response, decision)
        return DischargeResult(decision, request, discharge)

    def fetch_and_bind(self, root, caveat):
        result = self.fetch(caveat)
        return result, result.bind(root)

    def _parse_response(self, response, decision):
        status = getattr(response, 'status', None)
        if 300 <= status < 400:
            raise DischargeRedirectRefused(
                'discharge endpoint returned redirect status {}; redirects '
                'are never followed'.format(status)
            )
        if status != 200:
            raise InvalidDischargeResponse(
                'discharge endpoint returned status {}'.format(status)
            )

        # A transport that silently followed a redirect must not be able to
        # turn the configured endpoint into an attacker-controlled one.  If
        # the transport reports the final URL, require it to match exactly.
        final_url = getattr(response, 'url', None)
        if final_url is not None:
            try:
                final_endpoint = Endpoint(final_url)
            except ValueError:
                raise DischargeRedirectRefused(
                    'transport returned from an unsafe URL {!r}'.format(
                        final_url
                    )
                )
            if final_endpoint != decision.endpoint:
                raise DischargeRedirectRefused(
                    'transport followed a redirect from {} to {}; redirects '
                    'are never accepted'.format(
                        decision.endpoint.url, final_url
                    )
                )

        expected_caveat_id = decision.caveat_id_bytes

        body = getattr(response, 'body', None)
        if isinstance(body, bytes):
            body = body.decode('utf-8')
        try:
            payload = json.loads(body)
        except (TypeError, ValueError):
            raise InvalidDischargeResponse(
                'discharge response is not valid JSON'
            )

        # Exactly one discharge is accepted.  The response cannot smuggle an
        # extra root, another organization's caveat, or a second discharge.
        if not isinstance(payload, dict) or set(payload) != {'discharge'}:
            raise InvalidDischargeResponse(
                'discharge response must contain exactly one "discharge" field'
            )
        serialized = payload['discharge']
        if not isinstance(serialized, string_types):
            raise InvalidDischargeResponse(
                'discharge field must be a serialized macaroon string'
            )
        try:
            discharge = Macaroon.deserialize(serialized)
        except Exception:
            raise InvalidDischargeResponse(
                'discharge field is not a valid macaroon'
            )

        if discharge.identifier_bytes != expected_caveat_id:
            raise InvalidDischargeResponse(
                'returned discharge identifier does not match the requested '
                'caveat id'
            )
        return discharge


class DischargeResult(object):
    def __init__(self, decision, request, discharge):
        self.decision = decision
        self.request = request
        self.discharge = discharge

    def bind(self, root):
        return RootBinding(root, self)


class RootBinding(object):
    """A discharge prepared for one specific root macaroon.

    The client can prove the structural binding locally.  It cannot prove the
    discharge's cryptographic authenticity: that is done by the target
    service using the caveat key derived from the root's encrypted
    verification id.  This class deliberately keeps those concepts separate.
    """

    def __init__(self, root, result):
        self.root_identifier = root.identifier
        self.root_location = root.location
        self.root_signature = root.signature
        self.discharge_identifier = result.discharge.identifier
        self.unbound_signature = result.discharge.signature
        self.bound_discharge = root.prepare_for_request(result.discharge)
        self.bound_signature = self.bound_discharge.signature
        self.expected_bound_signature = convert_to_string(
            HashSignaturesBinder(root).bind_signature(
                result.discharge.signature_bytes
            )
        )
        self.binding_verified = (
            self.bound_discharge.signature_bytes ==
            convert_to_bytes(self.expected_bound_signature)
        )

    def verify_at_target(self, root, root_key, verifier=None):
        from pymacaroons.verifier import Verifier
        verifier = verifier or Verifier(
            discharge_macaroons=[self.bound_discharge]
        )
        return verifier.verify(root, root_key)


def build_report(result, binding=None, target_verified=None):
    """Report destination, authentication, and root binding separately.

    ``https`` is not evidence for either authentication or binding.  The
    report says so explicitly instead of collapsing all three statements into
    a single "success" flag.
    """
    report = {
        'destination': {
            'service_id': result.decision.service_id,
            'endpoint': result.decision.endpoint.url,
            'request_method': result.request.method,
            'request_url': result.request.url,
            'request_body': result.request.body.decode('utf-8'),
            'location_hint': result.decision.location_hint,
            'location_hint_status': result.decision.location_hint_status,
            'location_hint_is_trusted': False,
            'selection_basis': result.decision.selection_basis,
            'caveat_id_shared_by_multiple_services': (
                result.decision.caveat_id_shared
            ),
        },
        'authentication': {
            'service_identity_source': 'local configuration',
            'endpoint_security': 'https (required by local configuration)',
            'https_proves': (
                'transport reached the configured endpoint; it does not '
                'authenticate the returned discharge'
            ),
            'discharge_authenticated_by': (
                'target service, using the caveat key derived from the root '
                'macaroon'
            ),
            'client_identifier_check': (
                result.discharge.identifier_bytes ==
                result.decision.caveat_id_bytes
            ),
            'target_verification': (
                None if target_verified is None else bool(target_verified)
            ),
        },
        'root_binding': {
            'root_identifier': binding.root_identifier if binding else None,
            'root_location': binding.root_location if binding else None,
            'root_signature': binding.root_signature if binding else None,
            'bound_discharge_identifier': (
                binding.discharge_identifier if binding else None
            ),
            'bound_signature': binding.bound_signature if binding else None,
            'structural_binding_verified': (
                binding.binding_verified if binding else None
            ),
        },
    }
    return report
