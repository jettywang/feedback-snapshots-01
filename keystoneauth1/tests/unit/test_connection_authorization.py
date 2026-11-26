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

"""Contract tests for the TLS material that actually reaches requests.

The older security regressions only inspected the fields a ``Session`` was
constructed with. These tests drive the real entry points
(``loading.session.Session``, ``identity.generic`` login, ``adapter.Adapter``
and the 401 retry path) and record what ``requests`` is handed at the very
bottom of the stack, per phase.

The loader default, the identity plugin's connection parameters and a
single business request each use independently recognisable values so a
correct ``verify`` cannot mask a wrong ``cert``, or vice versa.
"""

from keystoneauth1 import adapter
from keystoneauth1 import fixture
from keystoneauth1 import identity
from keystoneauth1 import loading
from keystoneauth1.tests.unit import utils


AUTH_URL = 'https://identity.contract.example/v3'
AUTH_PATH = '/auth/tokens'
APP_URL = 'https://compute.contract.example/v2.1'
APP_PATH = '/servers'

LOADER_VERIFY = '/approved/loader-ca.pem'
LOADER_CERT = '/approved/loader-cert.pem'
LOADER_KEY = '/approved/loader-key.pem'

PLUGIN_VERIFY = '/approved/plugin-ca.pem'
PLUGIN_CERT = '/approved/plugin-cert.pem'
PLUGIN_KEY = '/approved/plugin-key.pem'

REQUEST_VERIFY = '/approved/request-ca.pem'
REQUEST_CERT = '/approved/request-cert.pem'
REQUEST_KEY = '/approved/request-key.pem'

# A second approved configuration, distinct from all three sources above.
# Used only by the mutation doubles to prove that a per-phase expectation is
# enforced even when the substituted value is itself approved.
ALT_VERIFY = '/approved/alternate-ca.pem'
ALT_CERT = '/approved/alternate-cert.pem'
ALT_KEY = '/approved/alternate-key.pem'

PLUGIN_PAIR = (PLUGIN_VERIFY, (PLUGIN_CERT, PLUGIN_KEY))
LOADER_PAIR = (LOADER_VERIFY, (LOADER_CERT, LOADER_KEY))
REQUEST_PAIR = (REQUEST_VERIFY, (REQUEST_CERT, REQUEST_KEY))


class _Recorder:
    """Record every request handed to requests, tagged with its phase."""

    def __init__(self, session, phase_of):
        self._phase_of = phase_of
        self.sent = []
        self._original_send = session.send

        def _send(request, **kwargs):
            self.sent.append(
                {
                    'phase': self._phase_of(request.url),
                    'method': request.method,
                    'url': request.url,
                    'verify': kwargs.get('verify'),
                    'cert': kwargs.get('cert'),
                    'token': request.headers.get('X-Auth-Token'),
                }
            )
            return self._original_send(request, **kwargs)

        session.send = _send

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _PhasedPassword(identity.Password):
    """The real generic password plugin with explicit phase bookkeeping.

    ``get_connection_params`` has no phase parameter, so wrap the two public
    stages that consume it (version discovery and login) to know which one is
    currently sending.
    """

    def __init__(self, params, **kwargs):
        super().__init__(**kwargs)
        self._params = params
        self._phase = None

    def _do_create_plugin(self, session):
        previous = self._phase
        self._phase = 'discovery'
        try:
            return super()._do_create_plugin(session)
        finally:
            self._phase = previous

    def get_auth_ref(self, session):
        previous = self._phase
        self._phase = 'login'
        try:
            return super().get_auth_ref(session)
        finally:
            self._phase = previous

    def get_connection_params(self, session):
        return dict(self._params(self._phase))


class ConnectionAuthorizationTests(utils.TestCase):
    def setUp(self):
        super().setUp()

        # Every source must be independently distinguishable, and verify and
        # cert must not alias each other.
        self.assertEqual(
            6,
            len(
                {
                    LOADER_VERIFY,
                    PLUGIN_VERIFY,
                    REQUEST_VERIFY,
                    LOADER_CERT,
                    PLUGIN_CERT,
                    REQUEST_CERT,
                }
            ),
        )
        self.assertNotEqual(LOADER_CERT, LOADER_KEY)
        self.assertNotEqual(PLUGIN_CERT, PLUGIN_KEY)
        self.assertNotEqual(REQUEST_CERT, REQUEST_KEY)

        self.token_body = self._token()
        self.discovery = {
            'versions': {'values': [fixture.V3Discovery(AUTH_URL)]}
        }

    def _token(self):
        token = fixture.V3Token()
        token.set_project_scope()
        token.add_role(name='member')
        return dict(token)

    def _build_session(self, params=None, *, loader_defaults=True):
        if loader_defaults:
            client = loading.session.Session().load_from_options(
                cacert=LOADER_VERIFY, cert=LOADER_CERT, key=LOADER_KEY
            )
        else:
            client = loading.session.Session().load_from_options()

        if params is not None:
            client.auth = _PhasedPassword(
                params,
                auth_url=AUTH_URL,
                username='contract-user',
                password='contract-password',
                user_domain_id='contract-domain',
                project_id='contract-project',
            )
        return client

    def _phase_of(self, url):
        if url.rstrip('/') == AUTH_URL.rstrip('/'):
            return 'discovery'
        if url.endswith(AUTH_PATH):
            return 'login'
        if url.startswith(APP_URL):
            return 'business'
        return 'unknown'

    def _stub_exchange(self, *, reauth=False):
        self.requests_mock.get(AUTH_URL, json=self.discovery)
        token_url = AUTH_URL + AUTH_PATH
        if reauth:
            self.requests_mock.register_uri(
                'POST',
                token_url,
                [
                    {
                        'json': self.token_body,
                        'headers': {'X-Subject-Token': 'contract-token-1'},
                    },
                    {
                        'json': self.token_body,
                        'headers': {'X-Subject-Token': 'contract-token-2'},
                    },
                ],
            )
        else:
            self.requests_mock.post(
                token_url,
                json=self.token_body,
                headers={'X-Subject-Token': 'contract-token-1'},
            )

    def _stub_app(self, *, reauth=False):
        app_url = APP_URL + APP_PATH
        if reauth:
            self.requests_mock.register_uri(
                'GET',
                app_url,
                [
                    {'status_code': 401, 'json': {'error': 'unauthorized'}},
                    {'json': {'servers': []}},
                ],
            )
        else:
            self.requests_mock.get(app_url, json={'servers': []})

    def _drive(self, client, *, request_kwargs=None, authenticated=True):
        app = adapter.Adapter(client, endpoint_override=APP_URL)
        with _Recorder(client.session, self._phase_of) as recorder:
            response = app.get(
                APP_PATH, authenticated=authenticated, **(request_kwargs or {})
            )
        self.assertEqual(
            len(recorder.sent),
            len(self.requests_mock.request_history),
            'recorder and stand-in saw a different number of requests',
        )
        return recorder.sent, response

    def _assert_phased(self, records, expected, message=''):
        """Assert each recorded request matches its phase's (verify, cert)."""
        self.assertTrue(records, f'{message}: no requests were sent')
        for record in records:
            phase = record['phase']
            self.assertIn(
                phase,
                expected,
                '{}: unexpected phase {!r} for {}'.format(
                    message, phase, record['url']
                ),
            )
            exp_verify, exp_cert = expected[phase]
            self.assertEqual(
                exp_verify,
                record['verify'],
                '{}: [{}] {} {} carried the wrong verify'.format(
                    message, phase, record['method'], record['url']
                ),
            )
            self.assertEqual(
                exp_cert,
                record['cert'],
                '{}: [{}] {} {} carried the wrong client '
                'certificate'.format(message, phase, record['method'],
                                     record['url']),
            )

    def test_normal_adapter_call_uses_plugin_connection_params(self):
        """A regular adapter call keeps the plugin's approved pair throughout.

        The loader default is also configured but must be shadowed: the
        identity plugin is what covers discovery, login and the business
        call.
        """
        client = self._build_session(lambda _phase: {
            'verify': PLUGIN_VERIFY,
            'cert': (PLUGIN_CERT, PLUGIN_KEY),
        })
        self._stub_exchange()
        self._stub_app()

        records, response = self._drive(client)

        self.assertEqual(200, response.status_code)
        self.assertEqual(
            ['discovery', 'login', 'business'],
            [record['phase'] for record in records],
        )
        self._assert_phased(
            records,
            {
                'discovery': PLUGIN_PAIR,
                'login': PLUGIN_PAIR,
                'business': PLUGIN_PAIR,
            },
            'normal adapter call',
        )
        self.assertIsNone(records[0]['token'])
        self.assertIsNone(records[1]['token'])
        self.assertEqual('contract-token-1', records[2]['token'])

    def test_request_without_overrides_uses_loader_defaults(self):
        """A business request with no covering entry uses the loader default.

        No auth plugin is attached, so nothing supplies connection params and
        no per-request override is given.
        """
        client = self._build_session(params=None)
        self._stub_app()

        records, response = self._drive(client, authenticated=False)

        self.assertEqual(200, response.status_code)
        self.assertEqual(['business'], [r['phase'] for r in records])
        self._assert_phased(
            records, {'business': LOADER_PAIR}, 'request without overrides'
        )
        self.assertIsNone(records[0]['token'])

    def test_single_business_request_uses_request_overrides(self):
        """A per-request pair applies when the plugin supplies none.

        Discovery and login still fall back to the loader; only the business
        request carries the request-level pair. This proves the three
        sources are selected independently per phase.
        """
        client = self._build_session(lambda _phase: {})
        self._stub_exchange()
        self._stub_app()

        records, response = self._drive(
            client,
            request_kwargs={
                'verify': REQUEST_VERIFY,
                'cert': (REQUEST_CERT, REQUEST_KEY),
            },
        )

        self.assertEqual(200, response.status_code)
        self.assertEqual(
            ['discovery', 'login', 'business'],
            [record['phase'] for record in records],
        )
        self._assert_phased(
            records,
            {
                'discovery': LOADER_PAIR,
                'login': LOADER_PAIR,
                'business': REQUEST_PAIR,
            },
            'single business request',
        )

    def test_connection_params_shadow_request_overrides(self):
        """Plugin params win over per-request kwargs, verify and cert alike.

        This documents the precedence in ``Session.request``: connection
        params are applied with ``dict.update`` after the request kwargs are
        recorded, so a per-request value cannot be silently assumed to have
        taken effect. Both values are still independently checked.
        """
        client = self._build_session(lambda _phase: {
            'verify': PLUGIN_VERIFY,
            'cert': (PLUGIN_CERT, PLUGIN_KEY),
        })
        self._stub_exchange()
        self._stub_app()

        records, response = self._drive(
            client,
            request_kwargs={
                'verify': REQUEST_VERIFY,
                'cert': (REQUEST_CERT, REQUEST_KEY),
            },
        )

        self.assertEqual(200, response.status_code)
        self._assert_phased(
            records,
            {
                'discovery': PLUGIN_PAIR,
                'login': PLUGIN_PAIR,
                'business': PLUGIN_PAIR,
            },
            'shadowed request overrides',
        )

    def test_retry_after_authentication_failure_uses_approved_params(self):
        """A normal 401 re-login and retry stays on the plugin's pair."""
        client = self._build_session(lambda _phase: {
            'verify': PLUGIN_VERIFY,
            'cert': (PLUGIN_CERT, PLUGIN_KEY),
        })
        self._stub_exchange(reauth=True)
        self._stub_app(reauth=True)

        records, response = self._drive(client)

        self.assertEqual(200, response.status_code)
        self.assertEqual(
            ['discovery', 'login', 'business', 'login', 'business'],
            [record['phase'] for record in records],
        )
        self._assert_phased(
            records,
            {
                'discovery': PLUGIN_PAIR,
                'login': PLUGIN_PAIR,
                'business': PLUGIN_PAIR,
            },
            'retry after authentication failure',
        )
        # the retried business call uses the refreshed token
        self.assertEqual('contract-token-1', records[2]['token'])
        self.assertEqual('contract-token-2', records[4]['token'])

    def _assert_contract_rejects(self, records, expected, phase, message):
        """Fail the contract and confirm the rejection names the phase.

        The message check is anchored on the phase marker our helper emits,
        which additionally distinguishes a wrong-value failure from an
        unexpected-phase failure.
        """
        try:
            self._assert_phased(records, expected, message)
        except AssertionError as exc:
            text = str(exc)
            # It must be a value mismatch on the mutated phase, not a
            # mis-mapped phase or a failure on an unrelated request.
            self.assertIn(f'[{phase}]', text)
            self.assertNotIn('unexpected phase', text)
            self.assertTrue(
                'wrong verify' in text or 'wrong client certificate' in text,
                text,
            )
        else:
            self.fail(f'{message}: contract did not reject the mutation')

    def test_mutated_verify_on_login_fails_contract(self):
        """Only login's verify is swapped for another approved value.

        Discovery and the business call keep the plugin pair. The phase
        contract must fail on login, and the untouched requests must still
        satisfy their own selection rules.
        """
        def params(phase):
            verify = ALT_VERIFY if phase == 'login' else PLUGIN_VERIFY
            return {'verify': verify, 'cert': (PLUGIN_CERT, PLUGIN_KEY)}

        client = self._build_session(params)
        self._stub_exchange()
        self._stub_app()
        records, response = self._drive(client)
        self.assertEqual(200, response.status_code)

        expected = {
            'discovery': PLUGIN_PAIR,
            'login': PLUGIN_PAIR,
            'business': PLUGIN_PAIR,
        }
        self._assert_contract_rejects(
            records, expected, 'login', 'mutated login verify'
        )

        self._assert_phased(
            [r for r in records if r['phase'] != 'login'],
            {
                'discovery': PLUGIN_PAIR,
                'business': PLUGIN_PAIR,
            },
            'unaffected requests',
        )
        login = next(r for r in records if r['phase'] == 'login')
        # verify diverges, cert on the mutated step is still correct
        self.assertEqual(ALT_VERIFY, login['verify'])
        self.assertEqual((PLUGIN_CERT, PLUGIN_KEY), login['cert'])

    def test_mutated_cert_on_login_fails_contract(self):
        """Only login's certificate is swapped; verify remains correct.

        Proves a correct verify cannot mask a wrong client certificate.
        """
        def params(phase):
            cert = (
                (ALT_CERT, ALT_KEY)
                if phase == 'login'
                else (PLUGIN_CERT, PLUGIN_KEY)
            )
            return {'verify': PLUGIN_VERIFY, 'cert': cert}

        client = self._build_session(params)
        self._stub_exchange()
        self._stub_app()
        records, response = self._drive(client)
        self.assertEqual(200, response.status_code)

        expected = {
            'discovery': PLUGIN_PAIR,
            'login': PLUGIN_PAIR,
            'business': PLUGIN_PAIR,
        }
        self._assert_contract_rejects(
            records, expected, 'login', 'mutated login cert'
        )

        self._assert_phased(
            [r for r in records if r['phase'] != 'login'],
            {
                'discovery': PLUGIN_PAIR,
                'business': PLUGIN_PAIR,
            },
            'unaffected requests',
        )
        login = next(r for r in records if r['phase'] == 'login')
        self.assertEqual(PLUGIN_VERIFY, login['verify'])
        self.assertEqual((ALT_CERT, ALT_KEY), login['cert'])
