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

import json

import requests

from keystoneauth1 import discover
from keystoneauth1 import exceptions
from keystoneauth1 import outbound
from keystoneauth1 import plugin
from keystoneauth1 import session as ks_session


CATALOG = 'http://catalog-public.example/'
DISCOVERY = 'http://discovery-public.example/versions'
SHARED = 'http://shared.example/'
SERVICE_A = 'http://service-a.example/'
SERVICE_B = 'http://service-b.example/'


class RotatingTokenAuth(plugin.BaseAuthPlugin):
    def __init__(self):
        self.token = 'business-token-1'
        self.reauthentications = 0

    def get_headers(self, session, **kwargs):
        return {'X-Auth-Token': self.token}

    def invalidate(self):
        self.reauthentications += 1
        self.token = f'business-token-{self.reauthentications + 1}'
        return True


class RecordingAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, double):
        self.double = double
        super().__init__()

    def send(self, request, **kwargs):
        return self.double.handle(request)


class RecordingService:
    """Record only what reaches the transport."""

    def __init__(self, policy):
        self.policy = policy
        self.calls = []
        self.adapter = RecordingAdapter(self)
        self.withdraw_on_401 = None

    def mount(self, session):
        session.session.mount('http://', self.adapter)

    def handle(self, request):
        phase = self.policy.sends[-1].phase
        call = {
            'method': request.method,
            'url': request.url,
            'phase': phase,
            'business_credentials': bool(request.headers.get('X-Auth-Token')),
            'token': request.headers.get('X-Auth-Token'),
        }
        self.calls.append(call)

        if request.url == CATALOG:
            response = self._response(302, headers={'Location': DISCOVERY})
        elif request.url == DISCOVERY:
            response = self._response(200, self._versions())
        elif request.url == SHARED:
            response = self._response(200, self._versions())
        elif request.url == SERVICE_A + 'things':
            response = self._response(200, {'ok': 'a'})
        elif request.url == SERVICE_B + 'things':
            if call['token'] == 'business-token-1':
                if self.withdraw_on_401 is not None:
                    self.policy.revoke_business_address(self.withdraw_on_401)
                response = self._response(401, {'error': 'reauth required'})
            else:
                response = self._response(200, {'ok': 'b'})
        else:
            raise AssertionError(
                f'Unexpected transport request: {request.url}'
            )
        response.request = request
        return response

    @staticmethod
    def _versions():
        return {
            'versions': {
                'values': [
                    {
                        'id': 'v1',
                        'status': 'stable',
                        'version': '1.0',
                        'min_version': '1.0',
                        'max_version': '1.0',
                        'links': [
                            {
                                'rel': 'self',
                                'href': 'http://service-a.example/v1/',
                            }
                        ],
                    }
                ]
            }
        }

    @staticmethod
    def _response(status, body=None, headers=None):
        response = requests.Response()
        response.status_code = status
        response.headers.update(headers or {})
        if body is not None:
            response._content = json.dumps(body).encode()
            response.headers.setdefault('Content-Type', 'application/json')
        else:
            response._content = b''
        response.encoding = 'utf-8'
        return response


def _policy():
    return outbound.OutboundPolicy(
        discovery_addresses=[CATALOG, DISCOVERY, SHARED],
        business_addresses=[SERVICE_A, SERVICE_B, SHARED],
    )


def test_discovery_redirect_reauth_revocation_and_public_overlap():
    policy = _policy()
    auth = RotatingTokenAuth()
    session = ks_session.Session(auth=auth, outbound_policy=policy)
    service = RecordingService(policy)
    service.mount(session)

    # Phase 1: public catalog entry redirects to the adjusted public
    # discovery address and completes normal version negotiation.
    discovery = discover.Discover(session, CATALOG)
    selected = discovery.versioned_data_for(
        min_version='1.0', max_version='1.0'
    )
    assert selected['version'] == (1, 0)

    # First successful business path.
    response = session.get(SERVICE_A + 'things')
    assert response.status_code == 200
    assert response.json() == {'ok': 'a'}

    # A 401 triggers re-authentication, but withdrawal of B happens before
    # the retried send is authorized.
    service.withdraw_on_401 = SERVICE_B
    try:
        session.get(SERVICE_B + 'things')
    except exceptions.OutboundAddressDenied as exc:
        stopped = exc
    else:
        raise AssertionError('Revoked business address was allowed')

    assert auth.reauthentications == 1
    assert stopped.decision.phase == outbound.BUSINESS
    assert stopped.decision.url == SERVICE_B + 'things'
    assert stopped.decision.reason == 'address_not_approved'

    # The next public query still works, including the address that is also
    # present in the business list, and never carries the business token.
    versions = discover.get_version_data(session, SHARED)
    assert versions[0]['id'] == 'v1'

    actual = [
        (call['phase'], call['url'], call['business_credentials'])
        for call in service.calls
    ]
    assert actual == [
        ('discovery', CATALOG, False),
        ('discovery', DISCOVERY, False),
        ('business', SERVICE_A + 'things', True),
        ('business', SERVICE_B + 'things', True),
        ('discovery', SHARED, False),
    ]

    # The one B send used the first token.  The re-authenticated token was
    # computed but never placed on an approved retry.
    b_calls = [
        call for call in service.calls if call['url'].startswith(SERVICE_B)
    ]
    assert len(b_calls) == 1
    assert b_calls[0]['token'] == 'business-token-1'
    assert auth.token == 'business-token-2'

    # Policy's secret-free send ledger agrees with the recording double.
    assert [
        (record.phase, record.url, record.business_credentials)
        for record in policy.sends
    ] == actual

    denied = [
        decision for decision in policy.decisions if not decision.allowed
    ]
    assert len(denied) == 1
    assert denied[0].url == SERVICE_B + 'things'


def test_allowed_reauth_retry_uses_fresh_business_credential():
    policy = _policy()
    auth = RotatingTokenAuth()
    session = ks_session.Session(auth=auth, outbound_policy=policy)

    class ReauthAdapter(requests.adapters.HTTPAdapter):
        def __init__(self):
            super().__init__()
            self.tokens = []

        def send(self, request, **kwargs):
            self.tokens.append(request.headers.get('X-Auth-Token'))
            response = requests.Response()
            response.request = request
            response.status_code = 401 if len(self.tokens) == 1 else 200
            response._content = b'{}'
            response.headers['Content-Type'] = 'application/json'
            return response

    adapter = ReauthAdapter()
    session.session.mount('http://', adapter)

    response = session.get(SERVICE_A + 'things')
    assert response.status_code == 200
    assert auth.reauthentications == 1
    assert adapter.tokens == ['business-token-1', 'business-token-2']
    assert [record.url for record in policy.sends] == [
        SERVICE_A + 'things',
        SERVICE_A + 'things',
    ]
    assert all(record.business_credentials for record in policy.sends)


def test_redirect_to_unapproved_address_stops_before_send():
    policy = outbound.OutboundPolicy(
        discovery_addresses=['http://start.example'], business_addresses=[]
    )
    session = ks_session.Session(outbound_policy=policy)

    class RedirectAdapter(requests.adapters.HTTPAdapter):
        def send(self, request, **kwargs):
            response = requests.Response()
            response.request = request
            response.status_code = 302
            response.headers['Location'] = 'http://unknown.example/next'
            response._content = b''
            return response

    session.session.mount('http://', RedirectAdapter())

    try:
        session.get('http://start.example', outbound_phase='discovery')
    except exceptions.OutboundAddressDenied as exc:
        assert exc.decision.phase == 'discovery'
        assert exc.decision.url == 'http://unknown.example/next'
    else:
        raise AssertionError('Unapproved redirect was allowed')


def test_status_retry_rechecks_revoked_business_address():
    policy = outbound.OutboundPolicy(
        discovery_addresses=[], business_addresses=[SERVICE_A]
    )
    session = ks_session.Session(outbound_policy=policy)
    attempts = []

    class RetryThenRevokeAdapter(requests.adapters.HTTPAdapter):
        def send(self, request, **kwargs):
            attempts.append(request.url)
            policy.revoke_business_address(SERVICE_A)
            response = requests.Response()
            response.request = request
            response.status_code = 503
            response.headers['Retry-After'] = '0'
            response._content = b''
            return response

    session.session.mount('http://', RetryThenRevokeAdapter())

    try:
        session.get(
            SERVICE_A, status_code_retries=1, status_code_retry_delay=0
        )
    except exceptions.OutboundAddressDenied:
        pass
    else:
        raise AssertionError('Revoked address was retried')

    assert attempts == [SERVICE_A]
    assert [record.url for record in policy.sends] == [SERVICE_A]
    denied = [
        decision for decision in policy.decisions if not decision.allowed
    ]
    assert len(denied) == 1


def test_authentication_exchange_uses_discovery_address_scope():
    class ExchangeAuth(plugin.BaseAuthPlugin):
        def get_headers(self, session, **kwargs):
            session.post(
                'http://identity-public.example/v3/auth/tokens',
                json={'auth': {}},
                authenticated=False,
            )
            return {'X-Auth-Token': 'business-token'}

    policy = outbound.OutboundPolicy(
        discovery_addresses=['http://identity-public.example'],
        business_addresses=[SERVICE_A],
    )
    session = ks_session.Session(auth=ExchangeAuth(), outbound_policy=policy)

    class ExchangeAdapter(requests.adapters.HTTPAdapter):
        def send(self, request, **kwargs):
            response = requests.Response()
            response.request = request
            response.status_code = 201
            response._content = b'{}'
            response.headers['Content-Type'] = 'application/json'
            if request.url == SERVICE_A:
                response.status_code = 200
                response._content = b'{"ok": true}'
            return response

    session.session.mount('http://', ExchangeAdapter())
    response = session.get(SERVICE_A)
    assert response.status_code == 200
    assert [
        (record.phase, record.business_credentials) for record in policy.sends
    ] == [('identity', False), ('business', True)]
