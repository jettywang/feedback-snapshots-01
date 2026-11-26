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

"""Interleaved logins across an identity provider switch.

Two local OpenID Connect providers stand in for the old and the new service;
one Keystone stand-in answers both. Logins are started under the old
configuration and under the new one, and the old logins are finished after
new logins have completed. Each request records the approval generation and
login id it was made for, so the tests can check who finished the exchange,
who got which scope, and who had to start again.
"""

import copy
import json
import tempfile
import uuid

from keystoneauth1 import _utils
from keystoneauth1 import access
from keystoneauth1 import exceptions
from keystoneauth1.identity.v3 import approval
from keystoneauth1.identity.v3 import oidc
from keystoneauth1 import session
from keystoneauth1.tests.unit import oidc_fixtures
from keystoneauth1.tests.unit import utils


AUTH_URL = 'http://keystone:5000/v3'
KEYSTONE_PROJECT = 'project-alpha'

OLD_PROVIDER = 'legacy-idp'
NEW_PROVIDER = 'current-idp'
PROTOCOL = 'openid'

OLD_TOKEN_ENDPOINT = 'https://legacy.example.org/oidc/token'
NEW_TOKEN_ENDPOINT = 'https://current.example.org/oidc/token'
OLD_DISCOVERY = 'https://legacy.example.org/.well-known/openid-configuration'
NEW_DISCOVERY = 'https://current.example.org/.well-known/openid-configuration'

CLIENT_ID = uuid.uuid4().hex
CLIENT_SECRET = uuid.uuid4().hex


def _token_body(subject, provider=None, protocol=PROTOCOL):
    """A federated unscoped token naming who mapped the local principal.

    The token expires in the future so it is still valid when a later test
    checks whether a stored token can be reused.
    """
    body = copy.deepcopy(oidc_fixtures.UNSCOPED_TOKEN)
    expires = _utils.from_utcnow(hours=1)
    body['token']['issued_at'] = _utils.from_utcnow(
        minutes=2
    ).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    body['token']['expires_at'] = expires.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    body['token']['user']['id'] = subject
    body['token']['user']['name'] = subject
    body['token']['user']['OS-FEDERATION'] = {
        'identity_provider': {'id': provider or OLD_PROVIDER},
        'protocol': {'id': protocol},
        'groups': [{'id': uuid.uuid4().hex}],
    }
    return body


class _KeystoneStandIn:
    """A Keystone that records every request and who it answered for.

    The local mapping is keyed by the receipt's login id, so the same two
    people appear under the same local principal whether the old or the new
    provider performed the mapping - which is exactly why a login must not
    cross between them.
    """

    #: Local principal ids the identity service maps the providers' users to.
    SUBJECTS = {
        'old-1': 'shared-local-user',
        'old-2': 'shared-local-user',
        'new-1': 'shared-local-user',
        'new-2': 'shared-local-user',
    }

    def __init__(self, requests_mock):
        self.exchanges = []
        self.rescopes = []
        requests_mock.post(
            self.federated_url(OLD_PROVIDER), json=self._exchange
        )
        requests_mock.post(
            self.federated_url(NEW_PROVIDER), json=self._exchange
        )
        requests_mock.post(f'{AUTH_URL}/auth/tokens', json=self._rescope)

    @staticmethod
    def federated_url(provider):
        return (
            f'{AUTH_URL}/OS-FEDERATION/identity_providers/{provider}'
            f'/protocols/{PROTOCOL}/auth'
        )

    def _exchange(self, request, context):
        generation = request.headers.get(oidc.HEADER_APPROVAL)
        login_id = request.headers.get(oidc.HEADER_LOGIN)
        self.exchanges.append(
            {
                'approval': generation,
                'login': login_id,
                'authorization': request.headers.get('Authorization'),
                'provider': request.url.split('/identity_providers/')[1]
                .split('/')[0],
            }
        )
        provider = request.url.split('/identity_providers/')[1].split('/')[
            0
        ]
        subject = self.SUBJECTS.get(login_id, login_id or 'unknown')
        context.status_code = 201
        context.headers['X-Subject-Token'] = f'unscoped-{login_id}'
        body = _token_body(subject)
        body['token']['user']['OS-FEDERATION'] = {
            'identity_provider': {'id': provider},
            'protocol': {'id': PROTOCOL},
            'groups': [{'id': uuid.uuid4().hex}],
        }
        return body

    def _rescope(self, request, context):
        body = request.json()
        token = body['auth']['identity']['token']['id']
        self.rescopes.append(
            {'token': token, 'scope': body['auth'].get('scope')}
        )
        context.status_code = 201
        context.headers['X-Subject-Token'] = f'scoped-{token}'
        scoped = _token_body(
            self.SUBJECTS.get(
                (token or '').removeprefix('unscoped-'), 'shared-local-user'
            )
        )
        scoped['token']['project'] = {'id': KEYSTONE_PROJECT}
        return scoped


class _SwitchTestBase(utils.TestCase):
    def setUp(self):
        super().setUp()

        self.session = session.Session()
        self.keystone = _KeystoneStandIn(self.requests_mock)

        self.old_discovery = self.requests_mock.get(
            OLD_DISCOVERY, json=oidc_fixtures.DISCOVERY_DOCUMENT
        )
        self.new_discovery = self.requests_mock.get(
            NEW_DISCOVERY, json=oidc_fixtures.DISCOVERY_DOCUMENT
        )

        self.requests_mock.post(
            OLD_TOKEN_ENDPOINT,
            json=oidc_fixtures.ACCESS_TOKEN_VIA_AUTH_GRANT_RESP,
        )
        self.requests_mock.post(
            NEW_TOKEN_ENDPOINT,
            json=oidc_fixtures.ACCESS_TOKEN_VIA_AUTH_GRANT_RESP,
        )

        self.old = approval.ProviderApproval(
            'old',
            AUTH_URL,
            OLD_PROVIDER,
            PROTOCOL,
            discovery_endpoint=OLD_DISCOVERY,
            access_token_endpoint=OLD_TOKEN_ENDPOINT,
        )
        self.new = approval.ProviderApproval(
            'new',
            AUTH_URL,
            NEW_PROVIDER,
            PROTOCOL,
            discovery_endpoint=NEW_DISCOVERY,
            access_token_endpoint=NEW_TOKEN_ENDPOINT,
        )
        # The batch switch is in progress but has not happened yet: new
        # logins still use the old configuration until it does.
        self.approvals = approval.ProviderApprovals(self.old, current='old')

    def _switch(self):
        self.approvals.approve(self.new)
        return self.new

    def _plugin(self, code, *, approval_registry=None, **kwargs):
        registry = approval_registry or self.approvals
        current = registry.current() if registry is not None else self.old
        kwargs.setdefault(
            'discovery_endpoint',
            current.discovery_endpoint if current is not None else None,
        )
        return oidc.OidcAuthorizationCode(
            AUTH_URL,
            current.identity_provider if current is not None else OLD_PROVIDER,
            PROTOCOL,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            code=code,
            approvals=registry,
            **kwargs,
        )

    def _start(self, login_id, *, registry=None):
        """Start a login with a predictable login id, without finishing it."""
        plugin = self._plugin(
            f'code-{login_id}',
            approval_registry=registry,
            project_id=KEYSTONE_PROJECT,
        )
        receipt = plugin.start_login()
        receipt = approval.LoginReceipt(
            receipt.generation,
            receipt.scope,
            openid_scope=receipt.openid_scope,
            identity_provider=receipt.identity_provider,
            protocol=receipt.protocol,
            login_id=login_id,
        )
        plugin.set_login_receipt(receipt)
        return plugin, receipt

    def _finish(self, plugin):
        # A login is complete once its scope has been handed to Keystone, so
        # finish through the rescope rather than only the exchange.
        return plugin.get_auth_ref(self.session)

    def _exchanges_for(self, login_id):
        return [
            entry
            for entry in self.keystone.exchanges
            if entry['login'] == login_id
        ]


class SwitchScenarioTests(_SwitchTestBase):
    def test_new_login_uses_the_current_approval_after_the_switch(self):
        self._switch()
        plugin, receipt = self._start('new-1')

        self.assertEqual('new', receipt.generation)

        auth_ref = self._finish(plugin)

        self.assertEqual(KEYSTONE_PROJECT, auth_ref.project_id)
        self.assertEqual(1, self.new_discovery.call_count)
        self.assertEqual(0, self.old_discovery.call_count)
        self.assertEqual('current-idp', self._exchanges_for('new-1')[0][
            'provider'
        ])

    def test_new_login_ignores_endpoints_configured_before_the_switch(self):
        # The plugin's own options name the old provider; the current
        # approval still wins, for every leg of the flow.
        self._switch()
        plugin = oidc.OidcAuthorizationCode(
            AUTH_URL,
            OLD_PROVIDER,
            PROTOCOL,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            code='code-new-1',
            discovery_endpoint=OLD_DISCOVERY,
            access_token_endpoint=OLD_TOKEN_ENDPOINT,
            project_id=KEYSTONE_PROJECT,
            approvals=self.approvals,
        )
        receipt = plugin.start_login()
        self.assertEqual('new', receipt.generation)

        self._finish(plugin)

        self.assertEqual(1, self.new_discovery.call_count)
        self.assertEqual(0, self.old_discovery.call_count)
        self.assertTrue(
            self._exchanges_for(receipt.login_id)[0][
                'authorization'
            ].startswith('Bearer ')
        )

    def test_interleaved_logins_finish_under_their_own_approval(self):
        before = [
            self._start(f'old-{n}')
            for n in (1, 2)
        ]
        self._switch()
        after = [
            self._start(f'new-{n}')
            for n in (1, 2)
        ]

        # Complete the new logins first, deferring the old receipts until
        # after the switch has already been used.
        for plugin, receipt in after:
            auth_ref = self._finish(plugin)
            self.assertEqual('new', receipt.generation)
            self.assertEqual(KEYSTONE_PROJECT, auth_ref.project_id)

        for plugin, receipt in before:
            auth_ref = self._finish(plugin)
            self.assertEqual('old', receipt.generation)
            self.assertIsInstance(auth_ref, access.AccessInfoV3)
            self.assertEqual('shared-local-user', auth_ref.user_id)
            self.assertEqual(KEYSTONE_PROJECT, auth_ref.project_id)

        # Each login's exchange names its own generation, and went to the
        # provider that generation approved.
        for login_id in ('old-1', 'old-2'):
            entries = self._exchanges_for(login_id)
            self.assertEqual(['old'], [e['approval'] for e in entries])
            self.assertEqual(['legacy-idp'], [e['provider'] for e in entries])
        for login_id in ('new-1', 'new-2'):
            entries = self._exchanges_for(login_id)
            self.assertEqual(['new'], [e['approval'] for e in entries])
            self.assertEqual(
                ['current-idp'], [e['provider'] for e in entries]
            )

        # One discovery fetch for each generation, not one shared by both.
        self.assertEqual(2, self.old_discovery.call_count)
        self.assertEqual(2, self.new_discovery.call_count)

        # The same local principal was handed to every login; each was
        # separately rescoped, and each rescope carried its own scope.
        self.assertEqual(4, len(self.keystone.rescopes))
        for login_id in ('old-1', 'old-2', 'new-1', 'new-2'):
            self.assertEqual(
                [{'project': {'id': KEYSTONE_PROJECT}}],
                [
                    record['scope']
                    for record in self.keystone.rescopes
                    if record['token'] == f'unscoped-{login_id}'
                ],
            )

    def test_delayed_old_receipt_still_finishes(self):
        plugin, receipt = self._start('old-1')
        self._switch()
        later, later_receipt = self._start('new-1')

        self._finish(later)
        self.assertEqual('new', later_receipt.generation)

        # The old receipt arrives only now; its approval remains valid.
        self._finish(plugin)
        self.assertEqual('old', receipt.generation)
        self.assertEqual(1, len(self._exchanges_for('old-1')))
        self.assertEqual(1, len(self._exchanges_for('new-1')))

    def test_withdrawn_approval_requires_reopening_the_login(self):
        plugin, receipt = self._start('old-1')
        self._switch()
        self.approvals.withdraw('old')

        with self.assertRaises(exceptions.OidcLoginReopenRequired) as caught:
            self._finish(plugin)

        self.assertEqual('withdrawn', caught.exception.reason)
        self.assertEqual('old', caught.exception.generation)
        self.assertEqual(receipt.login_id, caught.exception.login_id)
        # The old login never reached the identity service.
        self.assertEqual([], self.keystone.exchanges)

        # Starting again uses the current configuration and completes.
        reopened, new_receipt = self._start('new-1')
        self._finish(reopened)
        self.assertEqual('new', new_receipt.generation)
        self.assertEqual(
            [('new-1', 'new')],
            [
                (entry['login'], entry['approval'])
                for entry in self.keystone.exchanges
            ],
        )

    def test_retired_approval_requires_reopening_the_login(self):
        plugin, receipt = self._start('old-1')
        self._switch()
        self.approvals.retire('old')

        with self.assertRaises(exceptions.OidcLoginReopenRequired) as caught:
            self._finish(plugin)

        self.assertEqual('retired', caught.exception.reason)
        self.assertEqual('old', caught.exception.generation)
        self.assertEqual([], self.keystone.exchanges)

    def test_retirement_time_in_the_future_allows_the_deferred_receipt(self):
        plugin, receipt = self._start('old-1')
        self._switch()
        self.approvals.retire('old', _utils.from_utcnow(hours=1))

        auth_ref = self._finish(plugin)

        self.assertEqual('shared-local-user', auth_ref.user_id)
        self.assertEqual('old', receipt.generation)

    def test_unknown_approval_requires_reopening_the_login(self):
        plugin, receipt = self._start('old-1')
        plugin.set_approvals(approval.ProviderApprovals())

        with self.assertRaises(exceptions.OidcLoginReopenRequired) as caught:
            self._finish(plugin)

        self.assertEqual('unknown', caught.exception.reason)
        self.assertEqual('old', caught.exception.generation)

    def test_a_different_scope_is_refused(self):
        plugin, receipt = self._start('old-1')
        plugin.project_id = 'other-project'

        with self.assertRaises(exceptions.OidcLoginScopeMismatch) as caught:
            self._finish(plugin)

        self.assertEqual(receipt.scope, caught.exception.receipt_scope)
        self.assertEqual(
            {'project_id': 'other-project'},
            caught.exception.requested_scope,
        )
        self.assertEqual([], self.keystone.exchanges)

    def test_scope_is_handed_to_keystone_unchanged(self):
        plugin, receipt = self._start('new-1')
        self._finish(plugin)

        self.assertEqual(
            [{'project': {'id': KEYSTONE_PROJECT}}],
            [record['scope'] for record in self.keystone.rescopes],
        )


class CacheAndReauthTests(_SwitchTestBase):
    def test_unscoped_cache_id_follows_the_approval(self):
        old_plugin = self._plugin('code-old', project_id=KEYSTONE_PROJECT)
        old_plugin.bind_approval(self.old)
        new_plugin = self._plugin('code-new', project_id=KEYSTONE_PROJECT)
        new_plugin.bind_approval(self.new)

        self.assertNotEqual(
            old_plugin.get_unscoped_cache_id(),
            new_plugin.get_unscoped_cache_id(),
        )

    def test_cached_unscoped_token_is_not_reused_for_a_new_login(self):
        plugin, receipt = self._start('old-1')
        self._finish(plugin)
        state = plugin.get_unscoped_auth_state()

        self._switch()
        new_plugin, new_receipt = self._start('new-1')
        # A new login must not start from a token the old login obtained,
        # even though both would present the same local principal.
        new_plugin.set_unscoped_auth_state(state)
        self._finish(new_plugin)

        self.assertEqual('new', new_receipt.generation)
        self.assertEqual(2, len(self.keystone.exchanges))
        self.assertEqual(
            [('old', 'old-1'), ('new', 'new-1')],
            [
                (entry['approval'], entry['login'])
                for entry in self.keystone.exchanges
            ],
        )

    def test_a_cached_token_from_the_same_approval_is_reused(self):
        plugin, receipt = self._start('old-1')
        self._finish(plugin)
        state = plugin.get_unscoped_auth_state()

        resumed = self._plugin('code-old-1', project_id=KEYSTONE_PROJECT)
        resumed.set_login_receipt(receipt)
        resumed.set_unscoped_auth_state(state)
        auth_ref = self._finish(resumed)

        # The first login exchanged; the resumed one reused its token, so
        # only the rescope is paid for again.
        self.assertEqual(1, len(self.keystone.exchanges))
        self.assertEqual(2, len(self.keystone.rescopes))
        self.assertEqual('shared-local-user', auth_ref.user_id)
        self.assertEqual('old', receipt.generation)

    def test_withdrawal_refuses_even_a_held_unscoped_token(self):
        plugin, receipt = self._start('old-1')
        self._finish(plugin)
        state = plugin.get_unscoped_auth_state()

        resumed = self._plugin('code-old-1', project_id=KEYSTONE_PROJECT)
        resumed.set_login_receipt(receipt)
        resumed.set_unscoped_auth_state(state)
        self._switch()
        self.approvals.withdraw('old')

        with self.assertRaises(exceptions.OidcLoginReopenRequired) as caught:
            self._finish(resumed)

        self.assertEqual('withdrawn', caught.exception.reason)
        self.assertEqual(1, len(self.keystone.exchanges))

    def test_reauth_after_switch_uses_the_receipt_generation(self):
        plugin, receipt = self._start('old-1')
        self._finish(plugin)

        self._switch()
        plugin.invalidate()

        auth_ref = self._finish(plugin)

        self.assertEqual('old', receipt.generation)
        self.assertEqual('shared-local-user', auth_ref.user_id)
        self.assertEqual(2, len(self.keystone.exchanges))
        self.assertEqual(
            ['old', 'old'],
            [entry['approval'] for entry in self.keystone.exchanges],
        )

    def test_receipt_round_trips_through_storage(self):
        plugin, receipt = self._start('old-1')
        stored = receipt.to_string()
        self.assertEqual(
            receipt.to_dict(),
            approval.LoginReceipt.from_string(stored).to_dict(),
        )

        resumed = self._plugin(
            'code-old-1', project_id=KEYSTONE_PROJECT
        )
        resumed.set_login_receipt(stored)
        self._finish(resumed)

        self.assertEqual('old', self.keystone.exchanges[0]['approval'])
        self.assertEqual(
            receipt.login_id, self.keystone.exchanges[0]['login']
        )


class LoaderTests(_SwitchTestBase):
    def test_approval_path_loads_the_registry(self):
        from keystoneauth1 import loading

        registry = approval.ProviderApprovals(self.old, self.new)
        with tempfile.NamedTemporaryFile(
            'w', suffix='.json', dir=tempfile.gettempdir()
        ) as stream:
            stream.write(registry.to_json())
            stream.flush()

            loader = loading.get_plugin_loader('v3oidcauthcode')
            plugin = loader.load_from_options(
                auth_url=AUTH_URL,
                identity_provider=NEW_PROVIDER,
                protocol=PROTOCOL,
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                code='code-new-1',
                project_id=KEYSTONE_PROJECT,
                approval_path=stream.name,
            )

        receipt = plugin.start_login()
        self.assertEqual('new', receipt.generation)

        auth_ref = self._finish(plugin)
        self.assertEqual(KEYSTONE_PROJECT, auth_ref.project_id)


class RegistryTests(utils.TestCase):
    def test_registry_round_trips_through_json(self):
        registry = approval.ProviderApprovals(
            approval.ProviderApproval(
                'old', AUTH_URL, OLD_PROVIDER, PROTOCOL
            ),
            approval.ProviderApproval(
                'new', AUTH_URL, NEW_PROVIDER, PROTOCOL
            ),
            current='old',
        )
        registry.withdraw('old')

        restored = approval.ProviderApprovals.from_json(registry.to_json())

        # Withdrawing the current approval leaves no current one, so a
        # restored registry falls back to the last still-valid generation.
        self.assertEqual('new', restored.current().generation)
        self.assertTrue(restored.is_withdrawn('old'))
        self.assertEqual(
            ['old', 'new'],
            [item['generation'] for item in restored.to_dict()['approvals']],
        )

    def test_receipt_rejects_unknown_scope_fields(self):
        self.assertRaises(
            ValueError,
            approval.LoginReceipt,
            'old',
            {'region': 'x'},
        )

    def test_a_registry_file_can_drive_another_process(self):
        registry = approval.ProviderApprovals(
            approval.ProviderApproval(
                'old', AUTH_URL, OLD_PROVIDER, PROTOCOL
            ),
            approval.ProviderApproval(
                'new', AUTH_URL, NEW_PROVIDER, PROTOCOL
            ),
        )
        with tempfile.NamedTemporaryFile(
            'w', suffix='.json', dir=self._tmpdir()
        ) as stream:
            stream.write(registry.to_json())
            stream.flush()

            restored = approval.ProviderApprovals.from_json(
                open(stream.name, encoding='utf-8').read()
            )

        self.assertEqual('new', restored.current().generation)

    def _tmpdir(self):
        return tempfile.gettempdir()
