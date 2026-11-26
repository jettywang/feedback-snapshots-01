from concurrent.futures import ThreadPoolExecutor
import json
import threading
import time
import types
import uuid

import requests
import testtools

from keystoneauth1 import exceptions
from keystoneauth1 import operation_authorization as authorization
from keystoneauth1 import plugin
from keystoneauth1 import service_token
from keystoneauth1 import session as ks_session
from keystoneauth1.tests.unit import utils


USER_URL = 'http://double.example/v1/query'
OPERATION_URL = 'http://double.example/v1/dual-operation'
SERVICE_SCOPE = 'service-project-scope'


class ControlledAuth(plugin.BaseAuthPlugin):
    """Credential double whose refresh order is controlled by the test."""

    def __init__(self, identity, token, scope=None, wait_for_restore=False):
        super().__init__()
        self.identity = identity
        self.token = token
        self.scope = scope
        self.wait_for_restore = wait_for_restore
        self.invalidation_count = 0
        self.token_call_count = 0
        self.waiting = threading.Event()
        self._condition = threading.Condition()

    def get_token(self, session):
        self.token_call_count += 1
        if self.token is None and not self.wait_for_restore:
            return None

        deadline = time.monotonic() + 5
        with self._condition:
            while self.token is None:
                self.waiting.set()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError(
                        f'timed out waiting for {self.identity} credential'
                    )
                self._condition.wait(timeout=min(0.05, remaining))
            self.waiting.clear()
            return self.token

    def restore(self, token, scope=None):
        with self._condition:
            self.token = token
            if scope is not None:
                self.scope = scope
            self._condition.notify_all()

    def invalidate(self):
        with self._condition:
            had_token = self.token is not None
            self.token = None
            self.invalidation_count += 1
            self._condition.notify_all()
            return had_token


class AutoRefreshAuth(ControlledAuth):
    """A credential double that obtains a replacement during invalidation."""

    def invalidate(self):
        with self._condition:
            self.invalidation_count += 1
            self.token = f'{self.identity}-refreshed'
            self._condition.notify_all()
            return True


class InMemoryDoubleAdapter:
    """A small requests transport double without requests-mock's send lock."""

    def __init__(self, handler):
        self.handler = handler

    def send(self, request, **kwargs):
        context = types.SimpleNamespace(
            status_code=200, headers={'Content-Type': 'application/json'}
        )
        body = self.handler(request, context)

        response = requests.Response()
        response.status_code = context.status_code
        response.headers.update(context.headers)
        response._content = json.dumps(body).encode()
        response.encoding = 'utf-8'
        response.request = request
        response.url = request.url
        response.connection = self
        return response

    def close(self):
        pass


class OperationAuthorizationTests(utils.TestCase):
    def setUp(self):
        super().setUp()
        self.user_auth = ControlledAuth('user', 'user-initial')
        self.service_auth = ControlledAuth(
            'service', 'service-initial', SERVICE_SCOPE
        )
        self.combined = service_token.ServiceTokenAuthWrapper(
            self.user_auth, self.service_auth
        )
        self.session = ks_session.Session(auth=self.combined)

    def test_user_only_approval_sends_no_service_identity(self):
        self.requests_mock.get(USER_URL, json={'ok': True})

        response = self.session.get(
            USER_URL,
            operation_authorization=authorization.OperationAuthorization.user_only(),
        )

        self.assertEqual(200, response.status_code)
        headers = self.requests_mock.last_request.headers
        self.assertEqual('user-initial', headers['X-Auth-Token'])
        self.assertNotIn('X-Service-Token', headers)
        self.assertEqual(0, self.service_auth.invalidation_count)

    def test_user_only_retry_refreshes_only_user_identity(self):
        user_auth = AutoRefreshAuth('user', 'user-old')
        service_auth = ControlledAuth('service', 'service-old')
        auth = service_token.ServiceTokenAuthWrapper(user_auth, service_auth)
        client = ks_session.Session(auth=auth)
        retry_url = USER_URL + '/retry'
        self.requests_mock.get(
            retry_url,
            response_list=[{'status_code': 401}, {'json': {'ok': True}}],
        )

        response = client.get(retry_url, operation_authorization='user')

        self.assertEqual(200, response.status_code)
        self.assertEqual(2, self.requests_mock.call_count)
        for request in self.requests_mock.request_history:
            self.assertIn('X-Auth-Token', request.headers)
            self.assertNotIn('X-Service-Token', request.headers)
        self.assertEqual(1, user_auth.invalidation_count)
        self.assertEqual(0, service_auth.invalidation_count)
        self.assertEqual(0, service_auth.token_call_count)
        self.assertEqual(
            'user-refreshed',
            self.requests_mock.last_request.headers['X-Auth-Token'],
        )

    def test_dual_approval_sends_both_identities(self):
        self.requests_mock.get(OPERATION_URL, json={'ok': True})

        response = self.session.get(
            OPERATION_URL,
            operation_authorization=(
                authorization.OperationAuthorization.dual_identity(
                    SERVICE_SCOPE
                )
            ),
        )

        self.assertEqual(200, response.status_code)
        headers = self.requests_mock.last_request.headers
        self.assertEqual('user-initial', headers['X-Auth-Token'])
        self.assertEqual('service-initial', headers['X-Service-Token'])

    def test_missing_user_credentials_are_distinguishable(self):
        self.user_auth.token = None
        approval = authorization.OperationAuthorization.dual_identity()

        exc = self.assertRaises(
            exceptions.MissingUserCredentials,
            self.combined.get_headers,
            self.session,
            approval,
        )
        self.assertIsInstance(exc, exceptions.OperationAuthorizationError)

    def test_missing_service_credentials_are_distinguishable(self):
        self.service_auth.token = None
        approval = authorization.OperationAuthorization.dual_identity()

        self.assertRaises(
            exceptions.MissingServiceCredentials,
            self.combined.get_headers,
            self.session,
            approval,
        )

    def test_service_scope_mismatch_is_distinguishable(self):
        approval = authorization.OperationAuthorization.dual_identity(
            'other-scope'
        )

        exc = self.assertRaises(
            exceptions.ServiceScopeMismatch,
            self.combined.get_headers,
            self.session,
            approval,
        )
        self.assertEqual('other-scope', exc.expected)
        self.assertEqual(SERVICE_SCOPE, exc.actual)

    def test_user_only_operation_does_not_validate_service_scope(self):
        self.service_auth.scope = 'unrelated-scope'

        headers = self.combined.get_headers(
            self.session, authorization.OperationAuthorization.user_only()
        )

        self.assertEqual({'X-Auth-Token': 'user-initial'}, headers)

    def test_request_bound_approval_is_isolated(self):
        user_request_auth = self.combined.for_operation(
            authorization.OperationAuthorization.user_only()
        )
        dual_request_auth = self.combined.for_operation(
            authorization.OperationAuthorization.dual_identity(SERVICE_SCOPE)
        )

        self.assertFalse(
            user_request_auth.operation_authorization.requires_service
        )
        self.assertTrue(
            dual_request_auth.operation_authorization.requires_service
        )

        user_request_auth.invalidate()
        self.assertEqual(1, self.user_auth.invalidation_count)
        self.assertEqual(0, self.service_auth.invalidation_count)

        self.assertFalse(
            user_request_auth.operation_authorization.requires_service
        )
        self.assertTrue(
            dual_request_auth.operation_authorization.requires_service
        )


class ConcurrentDualIdentityRetryTests(testtools.TestCase):
    def test_query_and_dual_operation_keep_their_own_approvals(self):
        user_auth = ControlledAuth('user', 'user-old', wait_for_restore=True)
        service_auth = ControlledAuth(
            'service', 'service-old', SERVICE_SCOPE, wait_for_restore=True
        )
        combined = service_token.ServiceTokenAuthWrapper(
            user_auth, service_auth
        )

        records = []
        records_lock = threading.Lock()
        query_arrived = threading.Event()
        release_query = threading.Event()
        dual_first_arrived = threading.Event()

        def record_request(request, operation):
            record = {
                'operation': operation,
                'request': len(
                    [r for r in records if r['operation'] == operation]
                )
                + 1,
                'user_token': request.headers.get('X-Auth-Token'),
                'service_token': request.headers.get('X-Service-Token'),
                'status': None,
            }
            with records_lock:
                records.append(record)
            return record

        def query_response(request, context):
            record = record_request(request, 'query')
            query_arrived.set()
            self.assertTrue(release_query.wait(5))
            record['status'] = 200
            context.status_code = 200
            return {'result': 'query-ok'}

        def operation_response(request, context):
            record = record_request(request, 'dual-operation')
            if record['request'] == 1:
                record['status'] = 401
                dual_first_arrived.set()
                context.status_code = 401
                return {'error': 'reauthenticate'}

            record['status'] = 200
            context.status_code = 200
            return {'result': 'dual-operation-ok'}

        http_session = requests.Session()
        http_session.mount(
            'http://double.example/',
            InMemoryDoubleAdapter(
                lambda request, context: (
                    query_response(request, context)
                    if request.url == USER_URL
                    else operation_response(request, context)
                )
            ),
        )
        client = ks_session.Session(auth=combined, session=http_session)

        query_approval = authorization.OperationAuthorization.user_only(
            operation_id='query-' + uuid.uuid4().hex
        )
        operation_approval = (
            authorization.OperationAuthorization.dual_identity(
                SERVICE_SCOPE, operation_id='operation-' + uuid.uuid4().hex
            )
        )

        with ThreadPoolExecutor(max_workers=2) as executor:
            query_future = executor.submit(
                client.get, USER_URL, operation_authorization=query_approval
            )
            operation_future = executor.submit(
                client.get,
                OPERATION_URL,
                operation_authorization=operation_approval,
            )

            self.assertTrue(query_arrived.wait(5))
            self.assertTrue(dual_first_arrived.wait(5))
            self._wait_for(user_auth.waiting.is_set)

            # The 401 invalidated both caches, but recovery deliberately
            # starts with only the user credential.
            user_auth.restore('user-new')
            self._wait_for(service_auth.waiting.is_set)
            self.assertEqual(2, len(records))
            self.assertIsNone(service_auth.token)

            # The service credential must be restored in the approved scope
            # before the Session is allowed to build retry headers.
            service_auth.restore('service-new', SERVICE_SCOPE)
            self._wait_for(
                lambda: len(
                    [r for r in records if r['operation'] == 'dual-operation']
                )
                == 2
            )

            release_query.set()
            query_response_value = query_future.result(5)
            operation_response_value = operation_future.result(5)

        self.assertEqual(200, query_response_value.status_code)
        self.assertEqual(200, operation_response_value.status_code)

        query_records = [r for r in records if r['operation'] == 'query']
        operation_records = [
            r for r in records if r['operation'] == 'dual-operation'
        ]

        self.assertEqual(1, len(query_records))
        self.assertEqual(2, len(operation_records))
        self.assertEqual(200, query_records[0]['status'])
        self.assertIsNone(query_records[0]['service_token'])
        self.assertEqual('user-old', query_records[0]['user_token'])

        self.assertEqual([401, 200], [r['status'] for r in operation_records])
        self.assertEqual(
            [('user-old', 'service-old'), ('user-new', 'service-new')],
            [(r['user_token'], r['service_token']) for r in operation_records],
        )

        # No request was sent in the intermediate user-only recovery state.
        self.assertEqual(3, len(records))
        print('\nOPERATION_AUTHORIZATION_RECORDS')
        for record in records:
            print(record)

    @staticmethod
    def _wait_for(predicate):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        raise AssertionError('timed out waiting for test condition')
