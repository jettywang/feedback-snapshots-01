"""Tests for the secret-rotation state contract in `pika.secret_rotation`."""

import logging
import unittest

from pika import frame, secret_rotation, spec
from pika.exceptions import ConnectionWrongStateError

# Fictitious secrets. Tests never assert on these values and assert the logs do
# not contain them, so they can be replaced without changing any expectation.
_SECRET_ZERO = 'fictitious-secret-gen-0'
_SECRET_ONE = 'fictitious-secret-gen-1'
_SECRET_TWO = 'fictitious-secret-gen-2'
_FICTIONAL_SECRETS = (_SECRET_ZERO, _SECRET_ONE, _SECRET_TWO)
_REASON = 'token nearing expiry'


def _update_secret_ok_frame():
    return frame.Method(0, spec.Connection.UpdateSecretOk())


class FakeConnection:
    """Stand-in for `pika.connection.Connection` recording the update RPC.

    The broker reply is not delivered automatically. Tests call
    `deliver_update_secret_ok` to place an `UpdateSecretOk` frame, and
    `simulate_close` to lose the connection, so ordering between reply and
    close is fully under test control.
    """

    def __init__(self, name):
        self.name = name
        self.is_open = True
        self.update_calls = []
        self.close_reason = None
        self.on_closed = None

    def update_secret(self, new_secret, reason, callback=None):
        if not self.is_open:
            raise ConnectionWrongStateError(
                f'{self.name} is closed; cannot update its secret')
        self.update_calls.append({
            'new_secret': new_secret,
            'reason': reason,
            'callback': callback,
        })

    def deliver_update_secret_ok(self):
        if not self.update_calls:
            raise AssertionError(
                f'{self.name} got an UpdateSecretOk without a sent UpdateSecret'
            )
        callback = self.update_calls[-1]['callback']
        callback(_update_secret_ok_frame())

    def simulate_close(self, reply_code=320, reply_text='connection lost'):
        self.is_open = False
        self.close_reason = (reply_code, reply_text)
        if self.on_closed is not None:
            self.on_closed()


class SecretRotationTestBase(unittest.TestCase):

    def setUp(self):
        self.first = FakeConnection('first-connection')
        self.second = FakeConnection('second-connection')
        self.coordinator = secret_rotation.SecretRotationCoordinator(
            self.first, _SECRET_ZERO)
        self.first.on_closed = self.coordinator.on_connection_closed
        self.second.on_closed = self.coordinator.on_connection_closed

    def assertNoSecretInLogs(self, logs):
        rendered = '\n'.join(logs.output)
        for secret in _FICTIONAL_SECRETS:
            self.assertNotIn(secret, rendered)


class ConfirmedRotationTests(SecretRotationTestBase):

    def test_rotation_pending_then_confirmed_records_the_contract_order(self):
        with self.assertLogs('pika.secret_rotation',
                             level=logging.INFO) as logs:
            generation = self.coordinator.rotate(_SECRET_ONE, _REASON)

        self.assertEqual(generation, 1)
        snapshot = self.coordinator.snapshot()
        self.assertEqual(snapshot.state, secret_rotation.RotationState.PENDING)
        self.assertEqual(snapshot.pending_generation, 1)
        self.assertEqual(snapshot.attempts, 1)
        self.assertFalse(snapshot.retriable)
        # Until the broker confirms, reconnect keeps using the old secret.
        self.assertEqual(self.coordinator.secret_for_reconnect(), _SECRET_ZERO)
        self.assertEqual(len(self.first.update_calls), 1)
        self.assertEqual(self.first.update_calls[0]['new_secret'], _SECRET_ONE)

        with self.assertLogs('pika.secret_rotation', level=logging.INFO):
            self.first.deliver_update_secret_ok()

        snapshot = self.coordinator.snapshot()
        self.assertEqual(snapshot.state,
                         secret_rotation.RotationState.CONFIRMED)
        self.assertEqual(snapshot.generation, 1)
        self.assertIsNone(snapshot.pending_generation)
        self.assertEqual(snapshot.attempts, 0)
        self.assertFalse(snapshot.retriable)
        self.assertEqual(self.coordinator.secret_for_reconnect(), _SECRET_ONE)
        self.assertNoSecretInLogs(logs)

    def test_log_messages_show_generation_order_without_secret_values(self):
        with self.assertLogs('pika.secret_rotation',
                             level=logging.INFO) as logs:
            self.coordinator.rotate(_SECRET_ONE, _REASON)
            self.first.deliver_update_secret_ok()

        messages = [r.getMessage() for r in logs.records]
        self.assertTrue(
            any('sending secret update generation=1' in m for m in messages))
        self.assertTrue(
            any('broker confirmed secret update generation=1' in m
                for m in messages))
        send_index = next(
            i for i, m in enumerate(messages) if 'sending secret update' in m)
        confirm_index = next(
            i for i, m in enumerate(messages) if 'broker confirmed' in m)
        self.assertLess(send_index, confirm_index)
        self.assertNoSecretInLogs(logs)


class CloseBeforeConfirmationTests(SecretRotationTestBase):

    def test_close_before_confirmation_is_retriable_and_keeps_old_reconnect_secret(
            self):
        self.coordinator.rotate(_SECRET_ONE, _REASON)

        with self.assertLogs('pika.secret_rotation',
                             level=logging.WARNING) as logs:
            self.first.simulate_close()

        snapshot = self.coordinator.snapshot()
        self.assertEqual(snapshot.state,
                         secret_rotation.RotationState.UNCONFIRMED)
        self.assertEqual(snapshot.pending_generation, 1)
        self.assertTrue(snapshot.retriable)
        # The broker never accepted gen 1, so reconnect must still use gen 0.
        self.assertEqual(self.coordinator.secret_for_reconnect(), _SECRET_ZERO)
        self.assertTrue(
            any('retained for retry' in r.getMessage() for r in logs.records))
        self.assertNoSecretInLogs(logs)

    def test_retry_on_a_new_open_connection_confirms_and_promotes_the_secret(
            self):
        self.coordinator.rotate(_SECRET_ONE, _REASON)
        self.first.simulate_close()

        with self.assertLogs('pika.secret_rotation',
                             level=logging.INFO) as retry_logs:
            self.coordinator.bind(self.second)
            retried_generation = self.coordinator.retry(_REASON)

        self.assertEqual(retried_generation, 1)
        snapshot = self.coordinator.snapshot()
        self.assertEqual(snapshot.state, secret_rotation.RotationState.PENDING)
        self.assertEqual(snapshot.attempts, 2)
        self.assertEqual(len(self.second.update_calls), 1)
        self.assertEqual(self.second.update_calls[0]['new_secret'], _SECRET_ONE)
        self.assertFalse(
            self.first.update_calls[0] is self.second.update_calls[0])

        self.second.deliver_update_secret_ok()
        snapshot = self.coordinator.snapshot()
        self.assertEqual(snapshot.state,
                         secret_rotation.RotationState.CONFIRMED)
        self.assertEqual(snapshot.generation, 1)
        self.assertEqual(self.coordinator.secret_for_reconnect(), _SECRET_ONE)
        self.assertTrue(
            any('retrying secret update generation=1 attempts=2' in
                r.getMessage() for r in retry_logs.records))
        self.assertNoSecretInLogs(retry_logs)

    def test_retry_without_an_unconfirmed_candidate_is_rejected(self):
        with self.assertRaises(ConnectionWrongStateError):
            self.coordinator.retry(_REASON)


class LateReplyTests(SecretRotationTestBase):

    def test_reply_after_close_is_ignored_and_does_not_promote_the_secret(self):
        self.coordinator.rotate(_SECRET_ONE, _REASON)
        self.first.simulate_close()
        pending_callback = self.first.update_calls[-1]['callback']

        with self.assertLogs('pika.secret_rotation',
                             level=logging.INFO) as logs:
            # A broker that answers only after the connection is gone; the
            # coordinator must not treat that late frame as a confirmation.
            pending_callback(_update_secret_ok_frame())

        snapshot = self.coordinator.snapshot()
        self.assertEqual(snapshot.state,
                         secret_rotation.RotationState.UNCONFIRMED)
        self.assertTrue(snapshot.retriable)
        self.assertEqual(self.coordinator.secret_for_reconnect(), _SECRET_ZERO)
        self.assertTrue(
            any('ignoring late UpdateSecretOk' in r.getMessage()
                for r in logs.records))
        self.assertNoSecretInLogs(logs)


class SecondUpdateTests(SecretRotationTestBase):

    def test_second_update_supersedes_unconfirmed_candidate(self):
        self.coordinator.rotate(_SECRET_ONE, _REASON)
        self.first.simulate_close()
        self.coordinator.bind(self.second)

        with self.assertLogs('pika.secret_rotation',
                             level=logging.INFO) as logs:
            generation = self.coordinator.rotate(_SECRET_TWO, _REASON)

        self.assertEqual(generation, 2)
        snapshot = self.coordinator.snapshot()
        self.assertEqual(snapshot.state, secret_rotation.RotationState.PENDING)
        self.assertEqual(snapshot.pending_generation, 2)
        self.assertEqual(snapshot.attempts, 1)
        self.assertEqual(self.second.update_calls[-1]['new_secret'],
                         _SECRET_TWO)
        self.assertTrue(
            any('discarding unconfirmed generation 1' in r.getMessage()
                for r in logs.records))

        self.second.deliver_update_secret_ok()
        self.assertEqual(self.coordinator.snapshot().state,
                         secret_rotation.RotationState.CONFIRMED)
        self.assertEqual(self.coordinator.generation, 2)
        self.assertEqual(self.coordinator.secret_for_reconnect(), _SECRET_TWO)
        self.assertNoSecretInLogs(logs)

    def test_update_while_pending_is_rejected_to_keep_one_outstanding_rpc(self):
        self.coordinator.rotate(_SECRET_ONE, _REASON)
        with self.assertRaises(ConnectionWrongStateError):
            self.coordinator.rotate(_SECRET_TWO, _REASON)

    def test_rebind_while_pending_is_rejected(self):
        self.coordinator.rotate(_SECRET_ONE, _REASON)
        with self.assertRaises(ConnectionWrongStateError):
            self.coordinator.bind(self.second)

    def test_second_confirmed_update_advances_generation_on_same_connection(
            self):
        self.coordinator.rotate(_SECRET_ONE, _REASON)
        self.first.deliver_update_secret_ok()
        self.coordinator.rotate(_SECRET_TWO, _REASON)
        self.first.deliver_update_secret_ok()

        snapshot = self.coordinator.snapshot()
        self.assertEqual(snapshot.state,
                         secret_rotation.RotationState.CONFIRMED)
        self.assertEqual(snapshot.generation, 2)
        self.assertEqual(self.coordinator.secret_for_reconnect(), _SECRET_TWO)
        self.assertEqual(
            [call['new_secret'] for call in self.first.update_calls],
            [_SECRET_ONE, _SECRET_TWO])


class EndToEndScenarioTests(SecretRotationTestBase):
    """The four requested situations played out over two fake connections."""

    def test_two_fake_connections_tell_the_full_rotation_story(self):
        with self.assertLogs('pika.secret_rotation',
                             level=logging.INFO) as logs:
            # Connection one: a confirmed rotation, then a rotation the broker
            # never answers before the connection is lost.
            self.coordinator.rotate(_SECRET_ONE, _REASON)
            self.first.deliver_update_secret_ok()
            self.coordinator.rotate(_SECRET_TWO, _REASON)
            self.first.simulate_close()

            # A late frame from the dead connection must not confirm anything.
            late_callback = self.first.update_calls[-1]['callback']
            late_callback(_update_secret_ok_frame())

            # Connection two: the lost candidate is superseded by a fresh
            # rotation, which the new broker confirms.
            self.coordinator.bind(self.second)
            self.coordinator.rotate(_SECRET_TWO, _REASON)
            self.second.deliver_update_secret_ok()

        messages = [r.getMessage() for r in logs.records]
        markers = [
            'sending secret update generation=1',
            'broker confirmed secret update generation=1',
            'sending secret update generation=2',
            'connection closed before broker confirmed generation=2',
            'ignoring late UpdateSecretOk for generation=2',
            'discarding unconfirmed generation 2',
            'sending secret update generation=3',
            'broker confirmed secret update generation=3',
        ]
        positions = []
        for marker in markers:
            matches = [
                i for i, message in enumerate(messages) if marker in message
            ]
            self.assertEqual(len(matches), 1,
                             f'{marker!r} not seen once: {messages}')
            positions.append(matches[0])
        self.assertEqual(positions, sorted(positions))

        snapshot = self.coordinator.snapshot()
        self.assertEqual(snapshot.state,
                         secret_rotation.RotationState.CONFIRMED)
        self.assertEqual(snapshot.generation, 3)
        self.assertFalse(snapshot.retriable)
        self.assertEqual(self.coordinator.secret_for_reconnect(), _SECRET_TWO)
        self.assertEqual(
            [call['new_secret'] for call in self.first.update_calls],
            [_SECRET_ONE, _SECRET_TWO])
        self.assertEqual(
            [call['new_secret'] for call in self.second.update_calls],
            [_SECRET_TWO])
        self.assertNoSecretInLogs(logs)


class ContractGuardTests(SecretRotationTestBase):

    def test_initial_contract_uses_generation_zero_and_is_not_retriable(self):
        snapshot = self.coordinator.snapshot()
        self.assertEqual(snapshot.state,
                         secret_rotation.RotationState.CONFIRMED)
        self.assertEqual(snapshot.generation, 0)
        self.assertIsNone(snapshot.pending_generation)
        self.assertEqual(snapshot.attempts, 0)
        self.assertFalse(snapshot.retriable)
        self.assertEqual(self.coordinator.secret_for_reconnect(), _SECRET_ZERO)

    def test_close_while_confirmed_does_not_create_a_retry(self):
        with self.assertLogs('pika.secret_rotation', level=logging.INFO):
            self.first.simulate_close()
        self.assertFalse(self.coordinator.retriable)
        self.assertEqual(self.coordinator.state,
                         secret_rotation.RotationState.CONFIRMED)

    def test_non_string_secret_is_rejected_before_any_frame_is_sent(self):
        with self.assertRaises(ValueError):
            self.coordinator.rotate(b'not-a-str', _REASON)
        self.assertEqual(self.first.update_calls, [])
        with self.assertRaises(ValueError):
            secret_rotation.SecretRotationCoordinator(self.first, b'not-a-str')


if __name__ == '__main__':
    unittest.main()
