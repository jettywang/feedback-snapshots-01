from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from amqp.exceptions import (
    RecoverableChannelError, RecoverableConnectionError,
)

from kombu import Connection, exceptions
from kombu.diagnostics import (
    CANDIDATE_CONNECTED, CANDIDATE_REJECTED, FAILOVER_SWITCH,
    DiagnosticEvent, RestrictedDiagnostics,
)

PRIVATE_URLS = [
    'amqp://proj-alpha:s3cret-alpha@broker-alpha.internal:5672/proj-alpha',
    'amqp://proj-beta:s3cret-beta@broker-beta.internal:5672/proj-beta',
    'amqp://proj-gamma:s3cret-gamma@broker-gamma.internal:5672/proj-gamma',
]

PRIVATE_MARKERS = [
    'proj-alpha', 'proj-beta', 'proj-gamma',
    's3cret-alpha', 's3cret-beta', 's3cret-gamma',
    'broker-alpha.internal', 'broker-beta.internal', 'broker-gamma.internal',
]


class test_RestrictedDiagnostics:

    def test_alias_must_be_explicit(self):
        with pytest.raises(ValueError):
            RestrictedDiagnostics('')
        with pytest.raises(ValueError):
            RestrictedDiagnostics(None)
        with pytest.raises(ValueError):
            RestrictedDiagnostics(123)

    def test_records_progress_across_failover(self):
        diag = RestrictedDiagnostics('orders-primary')
        diag.candidate_rejected('connection')
        diag.failover_switch()
        diag.candidate_rejected('channel')
        diag.failover_switch()
        diag.candidate_connected()

        assert diag.public_report() == [
            {'alias': 'orders-primary', 'event': CANDIDATE_REJECTED,
             'attempt': 1, 'category': 'connection'},
            {'alias': 'orders-primary', 'event': FAILOVER_SWITCH,
             'attempt': 1, 'category': None},
            {'alias': 'orders-primary', 'event': CANDIDATE_REJECTED,
             'attempt': 2, 'category': 'channel'},
            {'alias': 'orders-primary', 'event': FAILOVER_SWITCH,
             'attempt': 2, 'category': None},
            {'alias': 'orders-primary', 'event': CANDIDATE_CONNECTED,
             'attempt': 3, 'category': None},
        ]
        assert diag.last_failure_category == 'channel'

    def test_event_equality_and_repr(self):
        event = DiagnosticEvent('orders-primary', CANDIDATE_REJECTED, 1,
                                'connection')
        assert event == DiagnosticEvent(
            'orders-primary', CANDIDATE_REJECTED, 1, 'connection')
        assert event != DiagnosticEvent(
            'orders-primary', CANDIDATE_REJECTED, 2, 'connection')
        assert 'orders-primary' in repr(event)


class test_Connection_diagnostics:

    def test_disabled_without_safe_alias(self):
        conn = Connection('memory://')
        assert conn.safe_alias is None
        assert conn.diagnostics is None

    def test_classify_failure(self):
        conn = Connection('amqp://')
        assert conn._classify_failure(
            RecoverableChannelError()) == 'channel'
        assert conn._classify_failure(
            RecoverableConnectionError()) == 'connection'
        assert conn._classify_failure(
            exceptions.OperationalError()) == 'operational'
        assert conn._classify_failure(ValueError()) == 'unknown'

    def test_two_rejections_then_success(self):
        conn = Connection(PRIVATE_URLS, safe_alias='orders-primary')
        established = Mock(name='broker-connection')
        factory = Mock(side_effect=[
            RecoverableConnectionError('refused'),
            RecoverableConnectionError('refused'),
            established,
        ])
        with patch.object(conn, '_connection_factory', factory):
            result = conn._ensure_connection(
                max_retries=3,
                interval_start=0, interval_step=0, interval_max=0)

        # third candidate accepted the connection
        assert result is established
        assert conn.hostname == 'broker-gamma.internal'

        # alert output shows only the safe alias and progress
        events = conn.diagnostics.public_report()
        assert events == [
            {'alias': 'orders-primary', 'event': CANDIDATE_REJECTED,
             'attempt': 1, 'category': 'connection'},
            {'alias': 'orders-primary', 'event': FAILOVER_SWITCH,
             'attempt': 1, 'category': None},
            {'alias': 'orders-primary', 'event': CANDIDATE_REJECTED,
             'attempt': 2, 'category': 'connection'},
            {'alias': 'orders-primary', 'event': FAILOVER_SWITCH,
             'attempt': 2, 'category': None},
            {'alias': 'orders-primary', 'event': CANDIDATE_CONNECTED,
             'attempt': 3, 'category': None},
        ]

        # business side can still determine the transport failure category
        assert conn.diagnostics.last_failure_category == 'connection'
        rejected = [e for e in events if e['event'] == CANDIDATE_REJECTED]
        assert [e['category'] for e in rejected] == [
            'connection', 'connection']

        # public content carries no private markers
        public_text = repr(events) + repr(conn.diagnostics.events)
        assert 'orders-primary' in public_text
        for marker in PRIVATE_MARKERS:
            assert marker not in public_text
