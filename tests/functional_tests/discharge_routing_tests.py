from __future__ import unicode_literals

import json

try:
    from urllib.parse import urlsplit
except ImportError:  # pragma: no cover - Python 2
    from urlparse import urlsplit

import pytest

from pymacaroons import Macaroon, Verifier
from pymacaroons.discharge_routing import (
    DischargeClient,
    DischargeRegistry,
    DischargeService,
    Endpoint,
    build_report,
)
from pymacaroons.exceptions import (
    AmbiguousDischargeCaveat,
    DischargeRedirectRefused,
    InvalidDischargeResponse,
    MacaroonInvalidSignatureException,
    UnknownDischargeService,
)


ROOT_KEY = 'root-key-only-the-target-knows'
TARGET = 'https://target.example/resource'


class Response(object):
    def __init__(self, status=200, body='', headers=None):
        self.status = status
        self.body = body
        self.headers = headers or {}


class InMemoryTransport(object):
    """A transport stand-in that records exactly what would be sent.

    It never follows redirects and has no connection to the network.
    """

    def __init__(self):
        self.handlers = {}
        self.requests = []

    def on(self, url, handler):
        self.handlers[url] = handler

    def send(self, request):
        self.requests.append(request)
        handler = self.handlers.get(request.url)
        if handler is None:
            return Response(404, '{"error":"no route"}')
        return handler(request)


def make_root(*caveats, **kwargs):
    root = Macaroon(
        location=kwargs.pop('location', TARGET),
        identifier=kwargs.pop('identifier', 'root-request-1'),
        key=kwargs.pop('key', ROOT_KEY),
    )
    for location, caveat_key, caveat_id in caveats:
        root.add_third_party_caveat(location, caveat_key, caveat_id)
    return root


def issue_discharge_handler(caveat_key, extra_fields=None):
    def handler(request):
        payload = json.loads(request.body.decode('utf-8'))
        identifier = payload.get('caveat_id')
        discharge = Macaroon(
            location=request.url,
            identifier=identifier,
            key=caveat_key,
        )
        discharge.add_first_party_caveat('service = checked')
        body = {'discharge': discharge.serialize()}
        body.update(extra_fields or {})
        return Response(200, json.dumps(body))
    return handler


def service(service_id, url, hints, caveat_ids):
    return DischargeService(
        service_id,
        Endpoint(url),
        location_hints=hints,
        caveat_ids=caveat_ids,
    )


def verify_at_target(root, discharges):
    verifier = Verifier(discharge_macaroons=discharges)
    verifier.satisfy_exact('service = checked')
    return verifier.verify(root, ROOT_KEY)


class TestLocationIsOnlyAnUntrustedHint(object):

    def test_caveat_location_change_leaves_signature_and_routing_trusted(self):
        root = make_root(('https://org-a.example/auth', 'key-a', 'caveat-a'))
        tampered = root.copy()
        tampered.caveats[0].location = 'https://attacker.example/discharge'

        assert tampered.signature == root.signature
        assert tampered.caveats[0].caveat_id == 'caveat-a'

        transport = InMemoryTransport()
        transport.on(
            'https://org-a.example/discharge',
            issue_discharge_handler('key-a'),
        )
        client = DischargeClient(
            DischargeRegistry([
                service('org-a', 'https://org-a.example/discharge',
                        ['org-a.example'], ['caveat-a']),
            ]),
            transport,
        )

        result = client.fetch(tampered.caveats[0])
        report = build_report(result)

        assert report['destination']['request_url'] == (
            'https://org-a.example/discharge'
        )
        assert report['destination']['location_hint'] == (
            'https://attacker.example/discharge'
        )
        assert report['destination']['location_hint_status'] == (
            'ignored_mismatch'
        )
        assert report['destination']['location_hint_is_trusted'] is False
        assert report['destination']['selection_basis'] == 'caveat_id'
        assert result.request.payload == {'caveat_id': 'caveat-a'}

    def test_root_location_change_does_not_break_binding(self):
        root = make_root(('org-a', 'key-a', 'caveat-a'))
        original_signature = root.signature

        moved = root.copy()
        moved.location = 'https://attacker.example/resource'
        assert moved.signature == original_signature

        transport = InMemoryTransport()
        transport.on(
            'https://org-a.example/discharge',
            issue_discharge_handler('key-a'),
        )
        client = DischargeClient(
            DischargeRegistry([
                service('org-a', 'https://org-a.example/discharge',
                        ['org-a'], ['caveat-a']),
            ]),
            transport,
        )

        result = client.fetch(root.caveats[0])
        binding = result.bind(moved)
        assert binding.binding_verified is True
        assert verify_at_target(moved, [binding.bound_discharge]) is True
        assert binding.root_signature == original_signature


class TestSharedShortIdentifier(object):

    def setup_method(self):
        self.transport = InMemoryTransport()
        self.transport.on(
            'https://org-a.example/discharge',
            issue_discharge_handler('key-a'),
        )
        self.transport.on(
            'https://org-b.example/discharge',
            issue_discharge_handler('key-b'),
        )
        self.registry = DischargeRegistry([
            service('org-a', 'https://org-a.example/discharge',
                    ['org-a'], ['shared-id']),
            service('org-b', 'https://org-b.example/discharge',
                    ['org-b'], ['shared-id']),
        ])
        self.client = DischargeClient(self.registry, self.transport)

    def test_location_selects_only_among_local_claimants(self):
        root = make_root(('org-a', 'key-a', 'shared-id'))
        result = self.client.fetch(root.caveats[0])
        report = build_report(result)

        assert result.decision.service_id == 'org-a'
        assert report['destination']['request_url'] == (
            'https://org-a.example/discharge'
        )
        assert report['destination']['caveat_id_shared_by_multiple_services']
        assert report['destination']['location_hint_is_trusted'] is False
        assert result.request.payload == {'caveat_id': 'shared-id'}

        binding = result.bind(root)
        assert binding.binding_verified is True
        assert verify_at_target(root, [binding.bound_discharge]) is True

    def test_forged_location_reaches_other_org_but_does_not_authenticate(self):
        root = make_root(('org-a', 'key-a', 'shared-id'))
        tampered = root.copy()
        tampered.caveats[0].location = 'org-b'

        result = self.client.fetch(tampered.caveats[0])
        assert result.decision.service_id == 'org-b'
        assert result.request.url == 'https://org-b.example/discharge'

        binding = result.bind(root)
        report = build_report(result, binding)

        assert report['destination']['request_url'] == (
            'https://org-b.example/discharge'
        )
        assert report['authentication']['client_identifier_check'] is True
        assert binding.binding_verified is True

        with pytest.raises(MacaroonInvalidSignatureException):
            verify_at_target(root, [binding.bound_discharge])

    def test_unknown_location_is_refused_when_identifier_is_shared(self):
        root = make_root(('somewhere-else', 'key-a', 'shared-id'))
        with pytest.raises(AmbiguousDischargeCaveat):
            self.client.fetch(root.caveats[0])

    def test_same_short_id_twice_in_one_root_uses_caveat_keys(self):
        root = make_root(
            ('org-a', 'key-a', 'shared-id'),
            ('org-b', 'key-b', 'shared-id'),
        )
        first = self.client.fetch(root.caveats[0])
        second = self.client.fetch(root.caveats[1])

        first = root.prepare_for_request(first.discharge)
        second = root.prepare_for_request(second.discharge)

        # Insertion order must not decide which organization authenticated.
        assert verify_at_target(root, [second, first]) is True
        assert verify_at_target(root, [first, second]) is True


class TestRequestMinimality(object):

    def test_request_carries_only_the_caveat_id(self):
        root = make_root(
            ('org-a', 'key-a', 'caveat-a'),
            ('org-b', 'key-b', 'caveat-b'),
        )
        transport = InMemoryTransport()
        transport.on(
            'https://org-a.example/discharge',
            issue_discharge_handler('key-a'),
        )
        transport.on(
            'https://org-b.example/discharge',
            issue_discharge_handler('key-b'),
        )
        client = DischargeClient(
            DischargeRegistry([
                service('org-a', 'https://org-a.example/discharge',
                        ['org-a'], ['caveat-a']),
                service('org-b', 'https://org-b.example/discharge',
                        ['org-b'], ['caveat-b']),
            ]),
            transport,
        )

        first = client.fetch(root.caveats[0])
        first_serialized = first.discharge.serialize()
        second = client.fetch(root.caveats[1])

        second_body = transport.requests[1].body.decode('utf-8')
        assert json.loads(second_body) == {'caveat_id': 'caveat-b'}
        assert root.serialize() not in second_body
        assert 'caveat-a' not in second_body
        assert first_serialized not in second_body

        first_bound = first.bind(root).bound_discharge
        second_bound = second.bind(root).bound_discharge
        assert verify_at_target(root, [first_bound, second_bound]) is True


class TestFailureHandling(object):

    def test_unknown_service_is_refused_without_a_request(self):
        root = make_root(('unknown', 'key-x', 'unclaimed'))
        transport = InMemoryTransport()
        client = DischargeClient(
            DischargeRegistry([
                service('org-a', 'https://org-a.example/discharge',
                        ['org-a'], ['caveat-a']),
            ]),
            transport,
        )
        with pytest.raises(UnknownDischargeService):
            client.fetch(root.caveats[0])
        assert transport.requests == []

    def test_redirects_are_refused(self):
        root = make_root(('org-a', 'key-a', 'caveat-a'))
        transport = InMemoryTransport()
        transport.on(
            'https://org-a.example/discharge',
            lambda request: Response(
                302, '', {'Location': 'https://attacker.example/discharge'}
            ),
        )
        client = DischargeClient(
            DischargeRegistry([
                service('org-a', 'https://org-a.example/discharge',
                        ['org-a'], ['caveat-a']),
            ]),
            transport,
        )
        with pytest.raises(DischargeRedirectRefused):
            client.fetch(root.caveats[0])
        assert len(transport.requests) == 1

    def test_extra_macaroon_in_response_is_refused(self):
        root = make_root(('org-a', 'key-a', 'caveat-a'))
        extra = Macaroon(
            location=TARGET, identifier='another-root', key=ROOT_KEY
        )
        transport = InMemoryTransport()
        transport.on(
            'https://org-a.example/discharge',
            issue_discharge_handler(
                'key-a', extra_fields={'root': extra.serialize()}
            ),
        )
        client = DischargeClient(
            DischargeRegistry([
                service('org-a', 'https://org-a.example/discharge',
                        ['org-a'], ['caveat-a']),
            ]),
            transport,
        )
        with pytest.raises(InvalidDischargeResponse):
            client.fetch(root.caveats[0])

    def test_discharge_for_different_identifier_is_refused(self):
        root = make_root(('org-a', 'key-a', 'caveat-a'))

        def wrong_identifier(request):
            discharge = Macaroon(
                location=request.url, identifier='caveat-b', key='key-a'
            )
            return Response(
                200, json.dumps({'discharge': discharge.serialize()})
            )

        transport = InMemoryTransport()
        transport.on('https://org-a.example/discharge', wrong_identifier)
        client = DischargeClient(
            DischargeRegistry([
                service('org-a', 'https://org-a.example/discharge',
                        ['org-a'], ['caveat-a']),
            ]),
            transport,
        )
        with pytest.raises(InvalidDischargeResponse):
            client.fetch(root.caveats[0])

    def test_http_endpoint_is_refused_by_local_configuration(self):
        with pytest.raises(ValueError):
            Endpoint('http://org-a.example/discharge')

    def test_endpoint_with_userinfo_is_refused(self):
        with pytest.raises(ValueError):
            Endpoint('https://user:pass@org-a.example/discharge')


class TestReportSeparatesClaims(object):

    def test_report_does_not_use_https_as_authentication_or_binding(self):
        root = make_root(('org-a', 'key-a', 'caveat-a'))
        transport = InMemoryTransport()
        transport.on(
            'https://org-a.example/discharge',
            issue_discharge_handler('key-a'),
        )
        client = DischargeClient(
            DischargeRegistry([
                service('org-a', 'https://org-a.example/discharge',
                        ['org-a'], ['caveat-a']),
            ]),
            transport,
        )
        result = client.fetch(root.caveats[0])
        binding = result.bind(root)
        report = build_report(result, binding, target_verified=True)

        assert report['destination']['request_url'] == (
            'https://org-a.example/discharge'
        )
        assert report['authentication']['target_verification'] is True
        assert report['root_binding']['root_signature'] == root.signature
        assert report['root_binding']['structural_binding_verified'] is True
        assert report['authentication']['https_proves'] != (
            'discharge authenticity'
        )
        assert 'location_hint' in report['destination']
        assert 'location_hint' not in report['authentication']


def test_urlsplit_used_by_transport_example_is_importable():
    assert urlsplit('https://org-a.example/discharge').hostname == (
        'org-a.example'
    )


class TestTransportRedirectDisclosure(object):

    def test_final_url_mismatch_is_refused_even_with_status_200(self):
        root = make_root(('org-a', 'key-a', 'caveat-a'))
        discharge = Macaroon(
            location='https://attacker.example/discharge',
            identifier='caveat-a',
            key='key-a',
        )

        class RedirectedResponse(Response):
            def __init__(self, body, url):
                super(RedirectedResponse, self).__init__(200, body)
                self.url = url

        transport = InMemoryTransport()
        transport.on(
            'https://org-a.example/discharge',
            lambda request: RedirectedResponse(
                json.dumps({'discharge': discharge.serialize()}),
                'https://attacker.example/discharge',
            ),
        )
        client = DischargeClient(
            DischargeRegistry([
                service('org-a', 'https://org-a.example/discharge',
                        ['org-a'], ['caveat-a']),
            ]),
            transport,
        )
        with pytest.raises(DischargeRedirectRefused):
            client.fetch(root.caveats[0])

    def test_final_url_matching_endpoint_is_accepted(self):
        root = make_root(('org-a', 'key-a', 'caveat-a'))

        class SameUrlResponse(Response):
            def __init__(self, body, url):
                super(SameUrlResponse, self).__init__(200, body)
                self.url = url

        discharge = Macaroon(
            location='https://org-a.example/discharge',
            identifier='caveat-a',
            key='key-a',
        )
        transport = InMemoryTransport()
        transport.on(
            'https://org-a.example/discharge',
            lambda request: SameUrlResponse(
                json.dumps({'discharge': discharge.serialize()}),
                'https://org-a.example/discharge',
            ),
        )
        client = DischargeClient(
            DischargeRegistry([
                service('org-a', 'https://org-a.example/discharge',
                        ['org-a'], ['caveat-a']),
            ]),
            transport,
        )
        assert client.fetch(root.caveats[0]).discharge.identifier == 'caveat-a'


def test_url_location_hint_matches_host_among_claimants():
    registry = DischargeRegistry([
        service('org-a', 'https://org-a.example/discharge',
                ['https://org-a.example/discharge'], ['shared-id']),
        service('org-b', 'https://org-b.example/discharge',
                ['org-b'], ['shared-id']),
    ])
    root = make_root(('https://org-a.example/discharge', 'key-a', 'shared-id'))
    decision = registry.resolve(root.caveats[0])
    assert decision.service_id == 'org-a'
    assert decision.location_hint_status == 'matched'
