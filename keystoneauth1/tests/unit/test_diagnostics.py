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

"""End-to-end tests for the shareable request diagnostic.

The scenario mirrors the incident hand-off: a local catalog substitute selects
an endpoint, the business substitute answers 401 once so the session
re-authenticates, the replacement exchange then fails with a synthetic error
body.  Three fictional private markers are placed in the catalog entry, the
re-authentication response and the final error, and must never appear in the
public view while the internal view keeps the real cause.
"""

import json
import logging
import uuid

from keystoneauth1 import diagnostics
from keystoneauth1 import exceptions
from keystoneauth1 import fixture
from keystoneauth1 import identity
from keystoneauth1 import session
from keystoneauth1.tests.unit import utils


CATALOG_MARKER = 'private-catalog-marker-7f3c'
REAUTH_MARKER = 'private-reauth-marker-2a91'
ERROR_MARKER = 'private-error-marker-c05d'


class DiagnosticTests(utils.TestCase):
    TEST_URL = 'http://business.example.com/v2/resource'
    AUTH_URL = 'http://identity.example.com/v3'
    ENDPOINT = 'http://business.example.com/v2'

    def setUp(self):
        super().setUp()
        self.token_id = uuid.uuid4().hex
        self.user_token_id = uuid.uuid4().hex
        self.service_token_id = uuid.uuid4().hex

        # The catalog entry carries a private marker in the service name.
        self.token = fixture.V3Token()
        self.token.set_project_scope()
        service = self.token.add_service('compute', name=CATALOG_MARKER)
        service.add_standard_endpoints(public=self.ENDPOINT)

        self.auth = identity.V3Password(
            auth_url=self.AUTH_URL,
            user_id=uuid.uuid4().hex,
            password=uuid.uuid4().hex,
            project_id=uuid.uuid4().hex,
        )

    def _auth(self):
        """Stub a token exchange that yields the catalog above."""
        return self.requests_mock.post(
            self.AUTH_URL + '/auth/tokens',
            json=self.token,
            headers={'X-Subject-Token': self.user_token_id},
        )

    def test_public_view_reconstructs_stages_without_markers(self):
        auth_mock = self._auth()
        # First exchange: 401 requiring re-authentication, with a private
        # marker in the re-authentication response body.
        reauth_body = {'error': {'message': REAUTH_MARKER}}
        failure_body = {
            'error': {
                'message': 'synthetic failure',
                'details': ERROR_MARKER,
            }
        }
        business_mock = self.requests_mock.get(
            self.TEST_URL,
            [
                {
                    'status_code': 401,
                    'json': reauth_body,
                    'headers': {'Content-Type': 'application/json'},
                },
                {
                    'status_code': 500,
                    'json': failure_body,
                    'headers': {'Content-Type': 'application/json'},
                },
            ],
        )

        policy = diagnostics.DiagnosticPolicy(
            service_name=False,
            endpoint=False,
            user_token=False,
            service_token=False,
            private_markers=(
                CATALOG_MARKER,
                REAUTH_MARKER,
                ERROR_MARKER,
            ),
        )
        sess = session.Session(auth=self.auth, diagnostic_policy=policy)

        with self.assertRaises(exceptions.InternalServerError) as ctx:
            sess.get(
                self.TEST_URL,
                endpoint_filter={
                    'service_type': 'compute',
                    'service_name': CATALOG_MARKER,
                },
            )

        exc = ctx.exception
        self.assertIsNotNone(exc.diagnostic)
        public = exc.diagnostic.public_view()
        internal = exc.diagnostic.internal_view()

        # The 401 forces one re-authentication: two token exchanges total.
        self.assertEqual(2, auth_mock.call_count)
        self.assertEqual(2, business_mock.call_count)

        # Same correlation identifier across the public and internal views.
        self.assertEqual(public['request_id'], internal['request_id'])
        self.assertEqual(
            [stage['request_id'] for stage in public['stages']],
            [public['request_id']] * len(public['stages']),
        )

        # Stage order can be reconstructed: catalog, request, response,
        # reauth, request, response, error.
        stages = [stage['stage'] for stage in public['stages']]
        self.assertEqual('catalog', stages[0])
        self.assertIn('reauth', stages)
        self.assertEqual('error', stages[-1])
        self.assertLess(stages.index('catalog'), stages.index('reauth'))
        self.assertLess(stages.index('reauth'), len(stages) - 1)

        # None of the unapproved markers leak into the public export.
        rendered = json.dumps(public, sort_keys=True)
        for marker in (CATALOG_MARKER, REAUTH_MARKER, ERROR_MARKER):
            self.assertNotIn(marker, rendered)

        # Catalog values and addresses were individually rejected.
        catalog = public['stages'][0]
        self.assertTrue(catalog['service_name']['redacted'])
        self.assertTrue(catalog['endpoint']['redacted'])
        self.assertFalse(public['policy']['service_name'])
        self.assertFalse(public['policy']['endpoint'])

        # Re-authentication is visible as an event without exposing the
        # intermediate response body.
        reauth = next(s for s in public['stages'] if s['stage'] == 'reauth')
        self.assertTrue(reauth['triggered'])
        self.assertTrue(reauth['invalidated'])
        self.assertTrue(reauth['retried'])

        # The final error names the stage and status but withholds details.
        error = public['stages'][-1]
        self.assertEqual('InternalServerError', error['exception'])
        self.assertEqual(500, error['http_status'])
        # The approved error field is scrubbed rather than exported verbatim.
        self.assertIn('{SHA256}', error['details'])

        # The internal view still reproduces the actual cause.
        internal_rendered = json.dumps(internal, sort_keys=True)
        self.assertIn(CATALOG_MARKER, internal_rendered)
        self.assertIn(ERROR_MARKER, internal_rendered)
        self.assertIn(REAUTH_MARKER, internal_rendered)

        # The digest recorded in the public view matches the real marker.
        self.assertIn(
            diagnostics.sha256(ERROR_MARKER),
            public['private_marker_digests'],
        )

    def test_individual_approvals_are_independent(self):
        self._auth()
        self.requests_mock.get(
            self.TEST_URL,
            [
                {'status_code': 401},
                {
                    'status_code': 500,
                    'json': {
                        'error': {
                            'message': 'boom',
                            'details': ERROR_MARKER,
                        }
                    },
                    'headers': {'Content-Type': 'application/json'},
                },
            ],
        )

        # Only the service name is approved; the address is not.
        policy = diagnostics.DiagnosticPolicy(
            service_name=True,
            endpoint=False,
            private_markers=(ERROR_MARKER,),
        )
        sess = session.Session(auth=self.auth, diagnostic_policy=policy)
        with self.assertRaises(exceptions.InternalServerError) as ctx:
            sess.get(
                self.TEST_URL,
                endpoint_filter={
                    'service_type': 'compute',
                    'service_name': CATALOG_MARKER,
                },
            )

        public = ctx.exception.diagnostic.public_view()
        catalog = public['stages'][0]
        self.assertEqual(CATALOG_MARKER, catalog['service_name'])
        self.assertTrue(catalog['endpoint']['redacted'])

    def test_dual_token_request_is_distinguished(self):
        user = fixture.V3Token()
        user.set_project_scope()
        service = fixture.V3Token()
        service.set_project_scope()

        user_auth = identity.V3Password(
            auth_url=self.AUTH_URL,
            user_id=uuid.uuid4().hex,
            password=uuid.uuid4().hex,
            project_id=uuid.uuid4().hex,
        )
        service_auth = identity.V3Password(
            auth_url=self.AUTH_URL,
            user_id=uuid.uuid4().hex,
            password=uuid.uuid4().hex,
            project_id=uuid.uuid4().hex,
        )
        self.requests_mock.post(
            self.AUTH_URL + '/auth/tokens',
            [
                {
                    'json': user,
                    'headers': {'X-Subject-Token': self.user_token_id},
                },
                {
                    'json': service,
                    'headers': {'X-Subject-Token': self.service_token_id},
                },
            ],
        )
        self.requests_mock.get(self.TEST_URL, text='ok')

        combined = __import__(
            'keystoneauth1.service_token', fromlist=['ServiceTokenAuthWrapper']
        ).ServiceTokenAuthWrapper(user_auth, service_auth)
        policy = diagnostics.DiagnosticPolicy(
            user_token=False, service_token=True
        )
        sess = session.Session(auth=combined, diagnostic_policy=policy)
        diagnostic = diagnostics.RequestDiagnostic(policy=policy)
        sess.get(self.TEST_URL, diagnostic=diagnostic)

        public = diagnostic.public_view()
        self.assertEqual('dual-token', public['request_kind'])
        self.assertTrue(public['dual_token'])

        request = next(s for s in public['stages'] if s['stage'] == 'request')
        # Service token is approved and visible; the user token is not.
        self.assertEqual(
            self.service_token_id, request['headers']['X-Service-Token']
        )
        self.assertIn('{SHA256}', request['headers']['X-Auth-Token'])

        # A normal request is distinguishable from the dual-token one.
        self.requests_mock.get(self.TEST_URL, text='ok')
        plain = diagnostics.RequestDiagnostic(policy=policy)
        session.Session(auth=user_auth).get(
            self.TEST_URL, diagnostic=plain
        )
        self.assertEqual('standard', plain.public_view()['request_kind'])

    def test_formatted_log_obeys_the_same_policy(self):
        self._auth()
        self.requests_mock.get(
            self.TEST_URL,
            [
                {'status_code': 401},
                {
                    'status_code': 500,
                    'json': {'error': {'message': ERROR_MARKER}},
                    'headers': {'Content-Type': 'application/json'},
                },
            ],
        )
        policy = diagnostics.DiagnosticPolicy(
            endpoint=False,
            private_markers=(CATALOG_MARKER, ERROR_MARKER, REAUTH_MARKER),
        )
        sess = session.Session(auth=self.auth, diagnostic_policy=policy)
        with self.assertRaises(exceptions.InternalServerError):
            sess.get(
                self.TEST_URL,
                endpoint_filter={
                    'service_type': 'compute',
                    'service_name': CATALOG_MARKER,
                },
            )

        # Only the keystoneauth formatter is in scope here; urllib3 emits its
        # own unrelated request lines at debug level.
        logged = '\n'.join(
            line
            for line in self.logger.output.splitlines()
            if line.startswith(('REQ:', 'RESP:', 'Making authentication'))
            or 'RESP BODY:' in line
        )
        self.assertNotIn(CATALOG_MARKER, logged)
        self.assertNotIn(ERROR_MARKER, logged)
        self.assertNotIn(self.TEST_URL, logged)
        self.assertIn('{SHA256}', logged)

    def test_connection_retry_records_intermediate_state(self):
        self._auth()
        self.requests_mock.get(
            self.TEST_URL,
            [
                {
                    'exc': __import__(
                        'requests'
                    ).exceptions.ConnectionError('synthetic'),
                },
                {'json': {'ok': True}},
            ],
        )
        policy = diagnostics.DiagnosticPolicy(
            endpoint=False,
            private_markers=(CATALOG_MARKER,),
        )
        sess = session.Session(auth=self.auth, diagnostic_policy=policy)
        diagnostic = diagnostics.RequestDiagnostic(policy=policy)
        sess.get(
            self.TEST_URL,
            diagnostic=diagnostic,
            endpoint_filter={'service_type': 'compute'},
            connect_retries=1,
            connect_retry_delay=0,
        )

        public = diagnostic.public_view()
        stages = [stage['stage'] for stage in public['stages']]
        self.assertIn('retry', stages)
        retry = next(s for s in public['stages'] if s['stage'] == 'retry')
        self.assertEqual('connection', retry['kind'])
        self.assertEqual(1, retry['retries_left'])
        # The address stays out of the retry reason.
        self.assertTrue(retry['reason']['redacted'])

    def test_per_request_policy_governs_logs_and_record(self):
        self._auth()
        self.requests_mock.get(
            self.TEST_URL,
            [
                {
                    'status_code': 503,
                    'json': {'error': {'message': ERROR_MARKER}},
                    'headers': {'Content-Type': 'application/json'},
                },
                {
                    'status_code': 500,
                    'json': {'error': {'message': ERROR_MARKER}},
                    'headers': {'Content-Type': 'application/json'},
                },
            ],
        )
        # The session default would hide the service name, but this request
        # explicitly approves it and nothing else.
        session_policy = diagnostics.DiagnosticPolicy(
            service_name=False, endpoint=False
        )
        request_policy = diagnostics.DiagnosticPolicy(
            service_name=True,
            endpoint=False,
            private_markers=(ERROR_MARKER,),
        )
        sess = session.Session(
            auth=self.auth, diagnostic_policy=session_policy
        )

        with self.assertRaises(exceptions.InternalServerError) as ctx:
            sess.get(
                self.TEST_URL,
                diagnostic_policy=request_policy,
                endpoint_filter={
                    'service_type': 'compute',
                    'service_name': CATALOG_MARKER,
                },
                status_code_retries=1,
                status_code_retry_delay=0,
            )

        diagnostic = ctx.exception.diagnostic
        self.assertIs(request_policy, diagnostic.policy)
        public = diagnostic.public_view()
        catalog = public['stages'][0]
        self.assertEqual(CATALOG_MARKER, catalog['service_name'])
        self.assertTrue(catalog['endpoint']['redacted'])
        retry = next(s for s in public['stages'] if s['stage'] == 'retry')
        self.assertEqual(503, retry['status_code'])
        self.assertNotIn(ERROR_MARKER, json.dumps(public))

    def test_response_body_switch_hides_intermediate_and_final(self):
        self._auth()
        self.requests_mock.get(
            self.TEST_URL,
            [
                {
                    'status_code': 503,
                    'json': {'note': ERROR_MARKER},
                    'headers': {'Content-Type': 'application/json'},
                },
                {
                    'status_code': 500,
                    'json': {'error': {'message': ERROR_MARKER}},
                    'headers': {'Content-Type': 'application/json'},
                },
            ],
        )
        policy = diagnostics.DiagnosticPolicy(
            response_body=False,
            private_markers=(ERROR_MARKER,),
        )
        sess = session.Session(auth=self.auth, diagnostic_policy=policy)
        with self.assertRaises(exceptions.InternalServerError) as ctx:
            sess.get(
                self.TEST_URL,
                status_code_retries=1,
                status_code_retry_delay=0,
            )

        public = ctx.exception.diagnostic.public_view()
        bodies = [
            stage['body']
            for stage in public['stages']
            if 'body' in stage and stage['body'] is not None
        ]
        self.assertTrue(bodies)
        for body in bodies:
            self.assertTrue(body['redacted'])
        self.assertNotIn(ERROR_MARKER, json.dumps(public))
