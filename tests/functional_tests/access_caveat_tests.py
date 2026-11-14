from __future__ import unicode_literals

import datetime

import pytest

from pymacaroons import Macaroon, RequestContext, Verifier
from pymacaroons.access import (
    expires_caveat,
    method_caveat,
    resource_caveat,
)
from pymacaroons.exceptions import (
    MacaroonAccessCaveatException,
    MacaroonAccessContextException,
    MacaroonUnmetCaveatException,
)


UTC = datetime.timezone.utc
KEY = 'this is our super secret key; only we should know it'


def utc(year, month, day, hour=0, minute=0, second=0, microsecond=0):
    return datetime.datetime(
        year, month, day, hour, minute, second, microsecond, tzinfo=UTC
    )


def issue(**kwargs):
    return Macaroon(
        location='https://api.example.test/',
        identifier='key-for-bob',
        key=KEY,
    )


def verify(macaroon, method, path, now=None):
    verifier = Verifier()
    verifier.satisfy_access(
        method=method,
        path=path,
        now=now or utc(2026, 11, 14, 12, 0, 0),
    )
    return verifier.verify(macaroon, KEY)


def assert_denied(macaroon, method, path, now=None):
    with pytest.raises(MacaroonUnmetCaveatException):
        verify(macaroon, method, path, now=now)


class TestProgressiveAttenuation(object):

    def test_round_trip_serialization_preserves_access_caveats(self):
        m = issue()
        m.add_access_caveat(
            resource='/v1/documents',
            method='GET',
            expires=utc(2026, 11, 14, 13, 0, 0),
        )
        restored = Macaroon.deserialize(m.serialize())

        assert verify(restored, 'GET', '/v1/documents/42') is True
        assert_denied(restored, 'DELETE', '/v1/documents/42')
        assert_denied(restored, 'GET', '/v1/secrets')
        assert_denied(
            restored, 'GET', '/v1/documents/42',
            now=utc(2026, 11, 14, 13, 0, 1),
        )

    def test_each_caveat_only_narrows_access(self):
        m = issue()
        m.add_access_caveat(resource='/v1', method='GET')
        assert verify(m, 'GET', '/v1/documents') is True

        # A delegated, narrower copy keeps the original caveats and adds
        # more. Access to the parent prefix must now be denied.
        delegated = m.copy()
        delegated.add_access_caveat(resource='/v1/documents/42')
        delegated.add_access_caveat(
            expires=utc(2026, 11, 14, 12, 30, 0)
        )

        assert verify(delegated, 'GET', '/v1/documents/42') is True
        assert verify(
            delegated, 'GET', '/v1/documents/42/comments'
        ) is True
        assert_denied(delegated, 'GET', '/v1/documents')
        assert_denied(delegated, 'GET', '/v1/documents/41')
        assert_denied(
            delegated, 'GET', '/v1/documents/42',
            now=utc(2026, 11, 14, 12, 30, 1),
        )

        # The original token is unaffected by work on the delegated copy.
        assert verify(m, 'GET', '/v1/documents/42') is True
        assert verify(
            m, 'GET', '/v1/documents/42',
            now=utc(2026, 11, 14, 12, 30, 1),
        ) is True

    def test_method_intersection_is_never_last_write_wins(self):
        m = issue()
        m.add_access_caveat(method='GET')
        m.add_access_caveat(method='POST')

        # Appending a conflicting method cannot broaden access back to GET
        # nor grant POST; the intersection is empty.
        assert_denied(m, 'GET', '/anything')
        assert_denied(m, 'POST', '/anything')

    def test_expiry_intersection_uses_earliest_deadline(self):
        m = issue()
        m.add_access_caveat(expires=utc(2026, 11, 14, 15, 0, 0))
        m.add_access_caveat(expires=utc(2026, 11, 14, 13, 0, 0))

        assert verify(m, 'GET', '/v1', now=utc(2026, 11, 14, 12, 59, 59))
        assert_denied(
            m, 'GET', '/v1', now=utc(2026, 11, 14, 13, 0, 1)
        )

    def test_expiry_boundary_microsecond_is_inclusive(self):
        deadline = utc(2026, 11, 14, 13, 0, 0, 500000)
        m = issue()
        m.add_access_caveat(expires=deadline)

        assert verify(m, 'GET', '/v1', now=deadline) is True
        assert_denied(
            m, 'GET', '/v1', now=deadline + datetime.timedelta(microseconds=1)
        )

    def test_naive_request_time_is_rejected(self):
        m = issue()
        m.add_access_caveat(expires=utc(2026, 11, 14, 13, 0, 0))

        with pytest.raises(MacaroonAccessContextException):
            verify(
                m, 'GET', '/v1',
                now=datetime.datetime(2026, 11, 14, 12, 0, 0),
            )


class TestPathCanonicalization(object):

    def test_encoded_path_is_decoded_exactly_once(self):
        m = issue()
        m.add_access_caveat(resource='/v1/documents/hello world')

        assert verify(m, 'GET', '/v1/documents/hello%20world') is True
        assert verify(m, 'GET', '/v1/documents/hello world') is True

        # A second decode would turn %2520 into a space. It must not.
        with pytest.raises(MacaroonAccessContextException):
            verify(m, 'GET', '/v1/documents/hello%2520world')

    def test_encoded_slash_cannot_change_resource_scope(self):
        m = issue()
        m.add_access_caveat(resource='/v1/documents')

        for path in (
            '/v1/documents%2F42',
            '/v2/documents%2F42',
            '/v1/documents/42%2Fcomments',
        ):
            with pytest.raises(MacaroonAccessContextException):
                verify(m, 'GET', path)

    def test_dot_segments_and_empty_segments_are_rejected(self):
        m = issue()
        m.add_access_caveat(resource='/v1/documents')

        for path in (
            '/v1/documents/../secrets',
            '/v1/documents/./42',
            '/v1//documents',
            '/v1/documents/%2E%2E/secrets',
            '/v1/documents%2F..%2Fsecrets',
        ):
            with pytest.raises(MacaroonAccessContextException):
                verify(m, 'GET', path)

    def test_trailing_slash_is_canonicalized_for_caveat_and_request(self):
        m = issue()
        m.add_access_caveat(resource='/v1/documents/')

        assert verify(m, 'GET', '/v1/documents') is True
        assert verify(m, 'GET', '/v1/documents/') is True
        # Trailing slashes are removed before comparison, so this stays
        # inside the granted subtree.
        assert verify(m, 'GET', '/v1/documents/42/') is True
        assert_denied(m, 'GET', '/v1/documents-archive')
        assert_denied(m, 'GET', '/v1/document')

    def test_percent_encoded_backslash_and_nul_are_rejected(self):
        m = issue()
        m.add_access_caveat(resource='/v1/documents')

        for path in ('/v1/documents%5C42', '/v1/documents%00'):
            with pytest.raises(MacaroonAccessContextException):
                verify(m, 'GET', path)


class TestStructuredIsolation(object):

    def test_permissive_general_callback_cannot_satisfy_structure(self):
        m = issue()
        m.add_access_caveat(resource='/v1/documents', method='GET')

        verifier = Verifier()
        verifier.satisfy_general(lambda predicate: True)
        verifier.satisfy_access(
            method='GET',
            path='/v1/secrets',
            now=utc(2026, 11, 14, 12, 0, 0),
        )

        with pytest.raises(MacaroonUnmetCaveatException):
            verifier.verify(m, KEY)

    def test_satisfy_exact_cannot_bypass_structured_interpreter(self):
        m = issue()
        m.add_access_caveat(resource='/v1/documents', method='GET')

        verifier = Verifier()
        verifier.satisfy_exact('access.resource = /v1/documents')
        verifier.satisfy_exact('access.method = GET')
        verifier.satisfy_access(
            method='GET',
            path='/v1/secrets',
            now=utc(2026, 11, 14, 12, 0, 0),
        )
        with pytest.raises(MacaroonUnmetCaveatException):
            verifier.verify(m, KEY)

    def test_missing_request_context_fails_closed(self):
        m = issue()
        m.add_access_caveat(resource='/v1/documents')

        verifier = Verifier()
        verifier.satisfy_general(lambda predicate: True)
        with pytest.raises(MacaroonUnmetCaveatException):
            verifier.verify(m, KEY)

    def test_unknown_structured_field_is_rejected(self):
        m = issue()
        m.add_first_party_caveat('access.role = admin')

        verifier = Verifier()
        verifier.satisfy_general(lambda predicate: True)
        verifier.satisfy_access(
            method='GET',
            path='/v1/documents',
            now=utc(2026, 11, 14, 12, 0, 0),
        )
        with pytest.raises(MacaroonUnmetCaveatException):
            verifier.verify(m, KEY)

    def test_malformed_structured_syntax_is_rejected(self):
        malformed = [
            'access.resource',
            'access.resource=/v1/documents',
            'access.resource =',
            'access.resource = /v1 = extra',
            'access.method = get',
            'access.method = GEET',
            ' access.resource = /v1/documents',
            'Access.resource = /v1/documents',
            'ACCESS.method = GET',
            'access.method = get',
            'access.resource = /v1/documents ',
            'access.expires = 2026-11-14',
            'access.expires = 2026-11-14T13:00:00',
            'access.expires = 2026-02-30T13:00:00Z',
            'access.expires = 2026-11-14T13:00:00+24:00',
        ]

        for predicate in malformed:
            m = issue()
            m.add_first_party_caveat(predicate)

            verifier = Verifier()
            verifier.satisfy_general(lambda candidate: True)
            verifier.satisfy_access(
                method='GET',
                path='/v1/documents',
                now=utc(2026, 11, 14, 12, 0, 0),
            )
            with pytest.raises(MacaroonUnmetCaveatException):
                verifier.verify(m, KEY)

    def test_structured_caveats_in_discharge_are_enforced(self):
        root = Macaroon(
            location='root', identifier='root-id', key=KEY
        )
        root.add_access_caveat(resource='/v1', method='GET')
        root.add_third_party_caveat('auth', 'caveat-key', 'bob-is-great')

        discharge = Macaroon(
            location='auth', identifier='bob-is-great', key='caveat-key'
        )
        discharge.add_access_caveat(resource='/v1/documents')
        protected = root.prepare_for_request(discharge)

        verifier = Verifier(discharge_macaroons=[protected])
        verifier.satisfy_access(
            method='GET', path='/v1/documents/1', now=utc(2026, 11, 14)
        )
        assert verifier.verify(root, KEY) is True

        verifier = Verifier(discharge_macaroons=[
            root.prepare_for_request(discharge)
        ])
        verifier.satisfy_access(
            method='GET', path='/v1/secrets', now=utc(2026, 11, 14)
        )
        with pytest.raises(MacaroonUnmetCaveatException):
            verifier.verify(root, KEY)

    def test_general_caveats_still_use_legacy_callbacks(self):
        m = issue()
        m.add_first_party_caveat('account = 3735928559')

        verifier = Verifier()
        verifier.satisfy_general(
            lambda predicate: predicate == 'account = 3735928559'
        )
        assert verifier.verify(m, KEY) is True


class TestCaveatConstruction(object):

    def test_helpers_produce_canonical_predicates(self):
        assert resource_caveat('/v1/documents/') == (
            'access.resource = /v1/documents'
        )
        assert method_caveat('GET') == 'access.method = GET'
        assert expires_caveat('2026-11-14T13:00:00.250Z') == (
            'access.expires = 2026-11-14T13:00:00.250000Z'
        )
        assert expires_caveat('2026-11-14T15:00:00+02:00') == (
            'access.expires = 2026-11-14T13:00:00Z'
        )

    def test_invalid_caveat_inputs_are_rejected_at_issuance(self):
        with pytest.raises(MacaroonAccessCaveatException):
            resource_caveat('v1/documents')
        with pytest.raises(MacaroonAccessCaveatException):
            resource_caveat('/v1/%2e%2e/secrets')
        with pytest.raises(MacaroonAccessCaveatException):
            resource_caveat('/v1/documents ')
        with pytest.raises(MacaroonAccessCaveatException):
            resource_caveat('/v1/documents = all')
        with pytest.raises(MacaroonAccessCaveatException):
            method_caveat('get')
        with pytest.raises(MacaroonAccessCaveatException):
            expires_caveat('2026-11-14T13:00:00')
        with pytest.raises(MacaroonAccessCaveatException):
            expires_caveat(datetime.datetime(2026, 11, 14, 13, 0, 0))

    def test_request_context_is_immutable(self):
        context = RequestContext('GET', '/v1/%64ocuments', utc(2026, 11, 14))
        assert context.method == 'GET'
        assert context.path == '/v1/documents'
        with pytest.raises(AttributeError):
            context.path = '/v2/secrets'

    def test_context_rejects_unsupported_methods_and_naive_time(self):
        with pytest.raises(MacaroonAccessContextException):
            RequestContext('get', '/v1/documents', utc(2026, 11, 14))
        with pytest.raises(MacaroonAccessContextException):
            RequestContext(
                'GET',
                '/v1/documents',
                datetime.datetime(2026, 11, 14),
            )

    def test_add_access_caveat_requires_a_constraint(self):
        with pytest.raises(MacaroonAccessCaveatException):
            issue().add_access_caveat()
