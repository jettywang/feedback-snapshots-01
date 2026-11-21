# Copyright (c) 2015 OpenStack Foundation.
# All Rights Reserved.

#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import copy
import json
from unittest import mock

import fixtures
from oslo_serialization import jsonutils
from requests.exceptions import Timeout
from requests_mock.contrib import fixture as rm_fixture
from urllib import parse as urlparse

from oslo_policy import _checks
from oslo_policy import _external
from oslo_policy import opts
from oslo_policy import policy
from oslo_policy.tests import base


class HttpCheckTestCase(base.PolicyBaseTestCase):
    def setUp(self):
        super().setUp()
        opts._register(self.conf)
        self.requests_mock = self.useFixture(rm_fixture.Fixture())

    def decode_post_data(self, post_data):
        result = {}
        for item in post_data.split('&'):
            key, _sep, value = item.partition('=')
            result[key] = jsonutils.loads(urlparse.unquote_plus(value))
        return result

    def test_accept(self):
        self.requests_mock.post('http://example.com/target', text='True')

        check = _external.HttpCheck('http', '//example.com/%(name)s')

        target_dict = dict(name='target', spam='spammer')
        cred_dict = dict(user='user', roles=['a', 'b', 'c'])
        self.assertTrue(check(target_dict, cred_dict, self.enforcer))

        last_request = self.requests_mock.last_request
        assert last_request is not None
        self.assertEqual(
            'application/x-www-form-urlencoded',
            last_request.headers['Content-Type'],
        )
        self.assertEqual('POST', last_request.method)
        self.assertEqual(
            dict(target=target_dict, credentials=cred_dict, rule=None),
            self.decode_post_data(last_request.body),
        )

    def test_accept_json(self):
        self.conf.set_override(
            'remote_content_type', 'application/json', group='oslo_policy'
        )
        self.requests_mock.post('http://example.com/target', text='True')

        check = _external.HttpCheck('http', '//example.com/%(name)s')

        target_dict = dict(name='target', spam='spammer')
        cred_dict = dict(user='user', roles=['a', 'b', 'c'])
        self.assertTrue(check(target_dict, cred_dict, self.enforcer))

        last_request = self.requests_mock.last_request
        assert last_request is not None
        self.assertEqual(
            'application/json', last_request.headers['Content-Type']
        )
        self.assertEqual('POST', last_request.method)
        self.assertEqual(
            dict(rule=None, credentials=cred_dict, target=target_dict),
            json.loads(last_request.body.decode('utf-8')),
        )

    def test_reject(self):
        self.requests_mock.post('http://example.com/target', text='other')

        check = _external.HttpCheck('http', '//example.com/%(name)s')

        target_dict = dict(name='target', spam='spammer')
        cred_dict = dict(user='user', roles=['a', 'b', 'c'])
        self.assertFalse(check(target_dict, cred_dict, self.enforcer))

        last_request = self.requests_mock.last_request
        assert last_request is not None
        self.assertEqual('POST', last_request.method)
        self.assertEqual(
            dict(target=target_dict, credentials=cred_dict, rule=None),
            self.decode_post_data(last_request.body),
        )

    def test_http_with_objects_in_target(self):
        self.requests_mock.post('http://example.com/target', text='True')

        check = _external.HttpCheck('http', '//example.com/%(name)s')
        target = {'a': object(), 'name': 'target', 'b': 'test data'}
        self.assertTrue(
            check(
                target, dict(user='user', roles=['a', 'b', 'c']), self.enforcer
            )
        )

    def test_http_with_strings_in_target(self):
        self.requests_mock.post('http://example.com/target', text='True')

        check = _external.HttpCheck('http', '//example.com/%(name)s')
        target = {'a': 'some_string', 'name': 'target', 'b': 'test data'}
        self.assertTrue(
            check(
                target, dict(user='user', roles=['a', 'b', 'c']), self.enforcer
            )
        )

    def test_accept_with_rule_in_argument(self):
        self.requests_mock.post('http://example.com/target', text='True')

        check = _external.HttpCheck('http', '//example.com/%(name)s')

        target_dict = dict(name='target', spam='spammer')
        cred_dict = dict(user='user', roles=['a', 'b', 'c'])
        current_rule = 'a_rule'
        self.assertTrue(
            check(target_dict, cred_dict, self.enforcer, current_rule)
        )

        last_request = self.requests_mock.last_request
        assert last_request is not None
        self.assertEqual('POST', last_request.method)
        self.assertEqual(
            dict(target=target_dict, credentials=cred_dict, rule=current_rule),
            self.decode_post_data(last_request.body),
        )

    def test_reject_with_rule_in_argument(self):
        self.requests_mock.post('http://example.com/target', text='other')

        check = _external.HttpCheck('http', '//example.com/%(name)s')

        target_dict = dict(name='target', spam='spammer')
        cred_dict = dict(user='user', roles=['a', 'b', 'c'])
        current_rule = 'a_rule'
        self.assertFalse(
            check(target_dict, cred_dict, self.enforcer, current_rule)
        )

        last_request = self.requests_mock.last_request
        assert last_request is not None
        self.assertEqual('POST', last_request.method)
        self.assertEqual(
            dict(target=target_dict, credentials=cred_dict, rule=current_rule),
            self.decode_post_data(last_request.body),
        )


class HttpsCheckTestCase(base.PolicyBaseTestCase):
    def setUp(self):
        super().setUp()
        opts._register(self.conf)
        self.requests_mock = self.useFixture(rm_fixture.Fixture())

        # ensure environment variables don't mess with our test results
        # https://requests.readthedocs.io/en/master/user/advanced/#ssl-cert-verification
        self.useFixture(fixtures.EnvironmentVariable('REQUESTS_CA_BUNDLE'))
        self.useFixture(fixtures.EnvironmentVariable('CURL_CA_BUNDLE'))

    def decode_post_data(self, post_data):
        result = {}
        for item in post_data.split('&'):
            key, _sep, value = item.partition('=')
            result[key] = jsonutils.loads(urlparse.unquote_plus(value))
        return result

    def test_https_accept(self):
        self.requests_mock.post('https://example.com/target', text='True')

        check = _external.HttpsCheck('https', '//example.com/%(name)s')

        target_dict = dict(name='target', spam='spammer')
        cred_dict = dict(user='user', roles=['a', 'b', 'c'])
        self.assertTrue(check(target_dict, cred_dict, self.enforcer))

        last_request = self.requests_mock.last_request
        assert last_request is not None
        self.assertEqual(
            'application/x-www-form-urlencoded',
            last_request.headers['Content-Type'],
        )
        self.assertEqual('POST', last_request.method)
        self.assertEqual(
            dict(rule=None, target=target_dict, credentials=cred_dict),
            self.decode_post_data(last_request.body),
        )

    def test_https_accept_json(self):
        self.conf.set_override(
            'remote_content_type', 'application/json', group='oslo_policy'
        )
        self.requests_mock.post('https://example.com/target', text='True')

        check = _external.HttpsCheck('https', '//example.com/%(name)s')

        target_dict = dict(name='target', spam='spammer')
        cred_dict = dict(user='user', roles=['a', 'b', 'c'])
        self.assertTrue(check(target_dict, cred_dict, self.enforcer))

        last_request = self.requests_mock.last_request
        assert last_request is not None
        self.assertEqual(
            'application/json', last_request.headers['Content-Type']
        )
        self.assertEqual('POST', last_request.method)
        self.assertEqual(
            dict(rule=None, target=target_dict, credentials=cred_dict),
            json.loads(last_request.body.decode('utf-8')),
        )

    def test_https_accept_with_verify(self):
        self.conf.set_override(
            'remote_ssl_verify_server_crt', True, group='oslo_policy'
        )
        self.conf.set_override(
            'remote_ssl_ca_crt_file', None, group='oslo_policy'
        )
        self.requests_mock.post('https://example.com/target', text='True')

        check = _external.HttpsCheck('https', '//example.com/%(name)s')

        target_dict = dict(name='target', spam='spammer')
        cred_dict = dict(user='user', roles=['a', 'b', 'c'])
        self.assertTrue(check(target_dict, cred_dict, self.enforcer))

        last_request = self.requests_mock.last_request
        assert last_request is not None
        self.assertEqual(True, last_request.verify)
        self.assertEqual('POST', last_request.method)
        self.assertEqual(
            dict(rule=None, target=target_dict, credentials=cred_dict),
            self.decode_post_data(last_request.body),
        )

    def test_https_accept_with_verify_cert(self):
        self.conf.set_override(
            'remote_ssl_verify_server_crt', True, group='oslo_policy'
        )
        self.conf.set_override(
            'remote_ssl_ca_crt_file', 'ca.crt', group='oslo_policy'
        )
        self.requests_mock.post('https://example.com/target', text='True')

        check = _external.HttpsCheck('https', '//example.com/%(name)s')

        target_dict = dict(name='target', spam='spammer')
        cred_dict = dict(user='user', roles=['a', 'b', 'c'])
        with mock.patch('os.path.exists') as path_exists:
            path_exists.return_value = True
            self.assertTrue(check(target_dict, cred_dict, self.enforcer))

        last_request = self.requests_mock.last_request
        assert last_request is not None
        self.assertEqual('ca.crt', last_request.verify)
        self.assertEqual('POST', last_request.method)
        self.assertEqual(
            dict(rule=None, target=target_dict, credentials=cred_dict),
            self.decode_post_data(last_request.body),
        )

    def test_https_accept_with_verify_and_client_certs(self):
        self.conf.set_override(
            'remote_ssl_verify_server_crt', True, group='oslo_policy'
        )
        self.conf.set_override(
            'remote_ssl_ca_crt_file', 'ca.crt', group='oslo_policy'
        )
        self.conf.set_override(
            'remote_ssl_client_key_file', 'client.key', group='oslo_policy'
        )
        self.conf.set_override(
            'remote_ssl_client_crt_file', 'client.crt', group='oslo_policy'
        )
        self.requests_mock.post('https://example.com/target', text='True')

        check = _external.HttpsCheck('https', '//example.com/%(name)s')

        target_dict = dict(name='target', spam='spammer')
        cred_dict = dict(user='user', roles=['a', 'b', 'c'])
        with mock.patch('os.path.exists') as path_exists:
            with mock.patch('os.access') as os_access:
                path_exists.return_value = True
                os_access.return_value = True
                self.assertTrue(check(target_dict, cred_dict, self.enforcer))

        last_request = self.requests_mock.last_request
        assert last_request is not None
        self.assertEqual('ca.crt', last_request.verify)
        self.assertEqual(('client.crt', 'client.key'), last_request.cert)
        self.assertEqual('POST', last_request.method)
        self.assertEqual(
            dict(rule=None, target=target_dict, credentials=cred_dict),
            self.decode_post_data(last_request.body),
        )

    def test_https_reject(self):
        self.requests_mock.post('https://example.com/target', text='other')

        check = _external.HttpsCheck('https', '//example.com/%(name)s')

        target_dict = dict(name='target', spam='spammer')
        cred_dict = dict(user='user', roles=['a', 'b', 'c'])
        self.assertFalse(check(target_dict, cred_dict, self.enforcer))

        last_request = self.requests_mock.last_request
        assert last_request is not None
        self.assertEqual('POST', last_request.method)
        self.assertEqual(
            dict(rule=None, target=target_dict, credentials=cred_dict),
            self.decode_post_data(last_request.body),
        )

    def test_https_with_objects_in_target(self):
        self.requests_mock.post('https://example.com/target', text='True')

        check = _external.HttpsCheck('https', '//example.com/%(name)s')
        target = {'a': object(), 'name': 'target', 'b': 'test data'}
        self.assertTrue(
            check(
                target, dict(user='user', roles=['a', 'b', 'c']), self.enforcer
            )
        )

    def test_https_with_strings_in_target(self):
        self.requests_mock.post('https://example.com/target', text='True')

        check = _external.HttpsCheck('https', '//example.com/%(name)s')
        target = {'a': 'some_string', 'name': 'target', 'b': 'test data'}
        self.assertTrue(
            check(
                target, dict(user='user', roles=['a', 'b', 'c']), self.enforcer
            )
        )


class RecordingTimeoutCheck:
    """Fake external check extension that records payloads, then times out."""

    def __init__(self):
        self.received = []

    def __call__(self, payload):
        self.received.append(copy.deepcopy(payload))
        raise Timeout('simulated approval service timeout')


class RecordingDenyCheck:
    """Fake external check extension that records payloads, then denies."""

    def __init__(self):
        self.received = []

    def __call__(self, payload):
        self.received.append(copy.deepcopy(payload))
        return False


class ExternalCheckContextTestCase(base.PolicyBaseTestCase):
    def setUp(self):
        super().setUp()
        self.enforcer.set_rules(
            {
                'get_file': _checks.RoleCheck('role', 'admin'),
                'list_files': _checks.TrueCheck(),
            }
        )
        self.target = {
            'name': 'file-a',
            'internal_path': '/srv/secret/file-a',
        }
        self.creds = {
            'user': 'alice',
            'roles': ['admin'],
            'password': 's3cret-pass',
            'token': 'tok-abc123',
        }

    def _make_context(self, check, actions=('get_file',)):
        return _external.ExternalCheckContext(
            check,
            actions=actions,
            target_fields=('name',),
            cred_fields=('user', 'roles'),
        )

    def test_external_check_receives_only_approved_fields(self):
        check = RecordingDenyCheck()
        self.enforcer.external_check = self._make_context(check)

        self.assertFalse(
            self.enforcer.enforce('get_file', self.target, self.creds)
        )

        self.assertEqual(1, len(check.received))
        self.assertEqual(
            {
                'action': 'get_file',
                'target': {'name': 'file-a'},
                'credentials': {'user': 'alice', 'roles': ['admin']},
            },
            check.received[0],
        )

    def test_local_policy_unaffected_for_unlisted_actions(self):
        check = RecordingDenyCheck()
        self.enforcer.external_check = self._make_context(check)

        # 'list_files' is not part of the external check context, so the
        # local policy alone decides and the external service is never
        # consulted.
        self.assertTrue(
            self.enforcer.enforce('list_files', self.target, self.creds)
        )
        self.assertEqual([], check.received)

    def test_local_denial_does_not_consult_external_service(self):
        check = RecordingDenyCheck()
        self.enforcer.external_check = self._make_context(check)

        creds = dict(self.creds, roles=['reader'])
        self.assertFalse(
            self.enforcer.enforce('get_file', self.target, creds)
        )
        self.assertEqual([], check.received)

    def test_external_approval_allows_action(self):
        check = mock.Mock(return_value=True)
        self.enforcer.external_check = self._make_context(check)

        self.assertTrue(
            self.enforcer.enforce('get_file', self.target, self.creds)
        )
        check.assert_called_once_with(
            {
                'action': 'get_file',
                'target': {'name': 'file-a'},
                'credentials': {'user': 'alice', 'roles': ['admin']},
            }
        )

    def test_timeout_is_not_an_approval(self):
        check = RecordingTimeoutCheck()
        self.enforcer.external_check = self._make_context(check)

        # A timeout fails closed with an explicit error instead of
        # being treated as an approval.
        self.assertRaises(
            _external.ExternalCheckTimeout,
            self.enforcer.enforce,
            'get_file',
            self.target,
            self.creds,
        )
        self.assertEqual(1, len(check.received))

    def test_timeout_error_does_not_leak_credentials(self):
        check = RecordingTimeoutCheck()
        self.enforcer.external_check = self._make_context(check)

        exc = self.assertRaises(
            _external.ExternalCheckTimeout,
            self.enforcer.enforce,
            'get_file',
            self.target,
            self.creds,
            do_raise=True,
        )
        message = str(exc)
        self.assertIn('get_file', message)
        self.assertNotIn('s3cret-pass', message)
        self.assertNotIn('tok-abc123', message)
        self.assertNotIn('/srv/secret/file-a', message)

    def test_denial_is_not_an_approval(self):
        check = RecordingDenyCheck()
        self.enforcer.external_check = self._make_context(check)

        exc = self.assertRaises(
            policy.PolicyNotAuthorized,
            self.enforcer.enforce,
            'get_file',
            self.target,
            self.creds,
            do_raise=True,
        )
        message = str(exc)
        self.assertNotIn('s3cret-pass', message)
        self.assertNotIn('tok-abc123', message)
        self.assertNotIn('/srv/secret/file-a', message)

    def test_external_failure_does_not_leak_credentials(self):
        check = mock.Mock(
            side_effect=RuntimeError('backend rejected s3cret-pass')
        )
        self.enforcer.external_check = self._make_context(check)

        exc = self.assertRaises(
            _external.ExternalCheckError,
            self.enforcer.enforce,
            'get_file',
            self.target,
            self.creds,
        )
        message = str(exc)
        self.assertIn('get_file', message)
        self.assertNotIn('s3cret-pass', message)
        self.assertNotIn('tok-abc123', message)
        self.assertNotIn('/srv/secret/file-a', message)
