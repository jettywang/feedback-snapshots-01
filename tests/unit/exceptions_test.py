"""Tests for pika.exceptions."""

import datetime
import decimal
import unittest
from unittest.mock import MagicMock

import pika.spec
from pika import exceptions
from pika.adapters.blocking_connection import ReturnedMessage
from pika.adapters.utils import connection_workflow

try:
    from pika.adapters.twisted_connection import ReceivedMessage
    HAS_TWISTED = True
except ImportError:
    HAS_TWISTED = False


def _returned_message(body=b'body'):
    """Build a `ReturnedMessage` as `BlockingChannel` does."""
    return ReturnedMessage(
        pika.spec.Basic.Return(exchange='x', routing_key='k'),
        pika.spec.BasicProperties(), body)


class ReturnedMessageLikeTests(unittest.TestCase):
    """
    The message types accepted by `UnroutableError` and `NackError`.

    Both exceptions are annotated `Sequence[ReturnedMessageLike]` so the blocking and Twisted
    adapters can each pass their own unrelated message class. These tests pin the members that
    structural type promises, since a reader of `.messages` relies on them being present on
    whichever class the adapter passed.
    """

    MEMBERS = ('method', 'properties', 'body')

    def test_returned_message_carries_the_protocol_members(self):
        msg = _returned_message()
        for name in self.MEMBERS:
            self.assertTrue(hasattr(msg, name), f'{name} is missing')
        self.assertIsInstance(msg.method, pika.spec.Basic.Return)
        self.assertIsInstance(msg.properties, pika.spec.BasicProperties)
        self.assertEqual(msg.body, b'body')

    @unittest.skipUnless(HAS_TWISTED, 'twisted not installed')
    def test_received_message_carries_the_protocol_members(self):
        msg = ReceivedMessage(channel=MagicMock(),
                              method=pika.spec.Basic.Return(exchange='x',
                                                            routing_key='k'),
                              properties=pika.spec.BasicProperties(),
                              body=b'body')
        for name in self.MEMBERS:
            self.assertTrue(hasattr(msg, name), f'{name} is missing')
        self.assertIsInstance(msg.method, pika.spec.Basic.Return)
        self.assertIsInstance(msg.properties, pika.spec.BasicProperties)
        self.assertEqual(msg.body, b'body')

    def test_both_exceptions_accept_a_returned_message(self):
        msgs = [_returned_message()]
        for factory in (exceptions.UnroutableError, exceptions.NackError):
            exc = factory(msgs)
            self.assertEqual(exc.messages[0].body, b'body')

    @unittest.skipUnless(HAS_TWISTED, 'twisted not installed')
    def test_both_exceptions_accept_a_received_message(self):
        msgs = [
            ReceivedMessage(channel=MagicMock(),
                            method=pika.spec.Basic.Return(exchange='x',
                                                          routing_key='k'),
                            properties=pika.spec.BasicProperties(),
                            body=b'body')
        ]
        for factory in (exceptions.UnroutableError, exceptions.NackError):
            exc = factory(msgs)
            self.assertEqual(exc.messages[0].body, b'body')

    def test_protocol_is_not_importable_at_runtime(self):
        # Declared under `TYPE_CHECKING`, so annotations can name it but an
        # unguarded runtime import raises. Asserted so the docstring saying so
        # stays true.
        self.assertFalse(hasattr(exceptions, 'ReturnedMessageLike'))


class PublishFailureTests(unittest.TestCase):
    """The restricted view of a publish failure, and what it withholds.

    These pin the contract an external log reader relies on: the view identifies one
    publish and its failure kind, while the body, the header table and the
    person-identifying properties never appear, whether read as attributes or
    rendered.
    """

    BODY = b'business-payload-must-not-leak'

    def _properties(self):
        return pika.spec.BasicProperties(content_type='application/json',
                                         correlation_id='order-77',
                                         message_id='msg-9',
                                         user_id='alice',
                                         reply_to='private.queue',
                                         headers={
                                             'x-private-account': 'acct-123',
                                             'trace-id': 'trace-abc',
                                         })

    def _view(self, kind=exceptions.PublishFailureKind.RETURNED, approved=()):
        return exceptions.PublishFailure.from_publish(
            kind,
            channel_number=2,
            exchange='orders',
            routing_key='orders.new',
            body=self.BODY,
            properties=self._properties(),
            approved_headers=approved,
            delivery_tag=7,
            method=pika.spec.Basic.Return(312, 'NO_ROUTE', 'orders',
                                          'orders.new'))

    def test_defaults_withhold_every_header(self):
        view = self._view()
        self.assertEqual(view.headers, {})
        self.assertEqual(view.withheld_header_count, 2)
        self.assertNotIn('acct-123', repr(view))
        self.assertNotIn('trace-abc', repr(view))

    def test_approved_headers_are_disclosed(self):
        view = self._view(approved=('trace-id',))
        self.assertEqual(dict(view.headers), {'trace-id': 'trace-abc'})
        self.assertEqual(view.withheld_header_count, 1)
        self.assertIn('trace-abc', repr(view))
        self.assertNotIn('acct-123', repr(view))

    def test_body_never_reaches_the_view(self):
        view = self._view(approved=('trace-id', 'x-private-account'))
        self.assertFalse(hasattr(view, 'body'))
        self.assertEqual(view.body_size, len(self.BODY))
        for rendered in (repr(view), str(view), repr(view.as_dict())):
            self.assertNotIn(self.BODY.decode(), rendered)

    def test_person_identifying_properties_are_absent(self):
        view = self._view()
        self.assertFalse(hasattr(view, 'user_id'))
        self.assertFalse(hasattr(view, 'reply_to'))
        self.assertNotIn('alice', repr(view))
        self.assertNotIn('private.queue', repr(view))

    def test_approved_properties_survive(self):
        view = self._view()
        self.assertEqual(view.correlation_id, 'order-77')
        self.assertEqual(view.message_id, 'msg-9')
        self.assertEqual(view.content_type, 'application/json')
        self.assertEqual(view.body_size, len(self.BODY))
        for value in ('order-77', 'msg-9', 'application/json'):
            self.assertIn(value, repr(view))

    def test_kind_tells_routing_from_confirmation(self):
        returned = self._view(exceptions.PublishFailureKind.RETURNED)
        nacked = self._view(exceptions.PublishFailureKind.NACKED)
        lost = exceptions.PublishFailure.from_publish(
            exceptions.PublishFailureKind.CONNECTION_LOST,
            exchange='orders',
            routing_key='orders.new',
            body=self.BODY,
            properties=self._properties())
        self.assertEqual(returned.kind, exceptions.PublishFailureKind.RETURNED)
        self.assertEqual(returned.reply_code, 312)
        self.assertEqual(returned.reply_text, 'NO_ROUTE')
        self.assertEqual(nacked.kind, exceptions.PublishFailureKind.NACKED)
        self.assertEqual(lost.kind,
                         exceptions.PublishFailureKind.CONNECTION_LOST)
        self.assertIsNone(lost.reply_code)
        # The enum compares equal to its wire string, so a log consumer that
        # parses JSON keeps working.
        self.assertEqual(returned.as_dict()['kind'], 'returned')

    def test_delivery_tag_and_channel_identify_the_publish(self):
        view = self._view()
        self.assertEqual(view.channel_number, 2)
        self.assertEqual(view.delivery_tag, 7)
        self.assertEqual(view.exchange, 'orders')
        self.assertEqual(view.routing_key, 'orders.new')
        self.assertIn('delivery_tag=7', repr(view))

    def test_view_is_read_only(self):
        view = self._view()
        with self.assertRaises(AttributeError):
            view.kind = exceptions.PublishFailureKind.NACKED
        with self.assertRaises(TypeError):
            view.headers['trace-id'] = 'forged'

    def test_oversized_property_is_bounded_in_repr(self):
        properties = pika.spec.BasicProperties(correlation_id='c' * 5000)
        view = exceptions.PublishFailure.from_publish(
            exceptions.PublishFailureKind.NACKED,
            exchange='e',
            routing_key='r',
            body=b'',
            properties=properties)
        self.assertLess(len(repr(view)),
                        4 * exceptions.MAX_DISCLOSED_TEXT + 200)


class AttachPublishFailureTests(unittest.TestCase):

    def test_attach_leaves_the_original_exception_alone(self):
        original = exceptions.StreamLostError('lost', host='broker', port=5672)
        view = exceptions.PublishFailure(
            exceptions.PublishFailureKind.CONNECTION_LOST)
        publish = exceptions.FailedPublish('', 'q', b'body', None)
        raised = exceptions.attach_publish_failure(original, view, publish)

        self.assertEqual(type(raised), exceptions.StreamLostError)
        self.assertEqual(raised.args, ('lost',))
        self.assertEqual((raised.host, raised.port), ('broker', 5672))
        self.assertIs(raised.failure, view)
        self.assertIs(raised.publish, publish)
        # The shared close reason must not describe one caller's publish.
        self.assertFalse(hasattr(original, 'failure'))
        self.assertFalse(hasattr(original, 'publish'))

    def test_describe_publish_failure_reads_only_the_view(self):
        view = exceptions.PublishFailure(exceptions.PublishFailureKind.NACKED)
        error = exceptions.attach_publish_failure(Exception('x'), view)
        self.assertIs(exceptions.describe_publish_failure(error), view)
        # Never falls back to `.publish`, which holds the body.
        self.assertIsNone(exceptions.describe_publish_failure(Exception('x')))

    def test_exceptions_expose_the_view_and_the_publish(self):
        publish = exceptions.FailedPublish('', 'q', b'body', None)
        view = exceptions.PublishFailure(exceptions.PublishFailureKind.RETURNED)
        for factory in (exceptions.UnroutableError, exceptions.NackError):
            exc = factory([], view, publish)
            self.assertIs(exc.failure, view)
            self.assertIs(exc.publish, publish)
            self.assertIn('kind=returned', repr(exc))
            self.assertNotIn('body', repr(exc))


class ExceptionTests(unittest.TestCase):

    def test_amqp_connection_error_one_param_repr(self):
        self.assertEqual(repr(exceptions.AMQPConnectionError(10)),
                         'AMQPConnectionError: (10,)')

    def test_amqp_connection_error_two_params_repr(self):
        self.assertEqual(repr(exceptions.AMQPConnectionError(1, 'Test')),
                         'AMQPConnectionError: (1) Test')

    def test_amqp_connection_error_host_port(self):
        exc = exceptions.AMQPConnectionError('fail',
                                             host='rabbit.local',
                                             port=5672)
        self.assertEqual(exc.host, 'rabbit.local')
        self.assertEqual(exc.port, 5672)
        self.assertIn("host='rabbit.local'", repr(exc))
        self.assertIn('port=5672', repr(exc))

    def test_amqp_connection_error_no_host_port_by_default(self):
        exc = exceptions.AMQPConnectionError('fail')
        self.assertIsNone(exc.host)
        self.assertIsNone(exc.port)
        self.assertNotIn('host=', repr(exc))

    def test_connection_open_aborted_host_port(self):
        exc = exceptions.ConnectionOpenAborted('aborted',
                                               host='broker1',
                                               port=5671)
        self.assertEqual(exc.host, 'broker1')
        self.assertEqual(exc.port, 5671)

    def test_stream_lost_error_host_port(self):
        exc = exceptions.StreamLostError('eof', host='10.0.0.1', port=5672)
        self.assertEqual(exc.host, '10.0.0.1')
        self.assertEqual(exc.port, 5672)
        self.assertIn("(host='10.0.0.1', port=5672)", repr(exc))

    def test_custom_repr_subclass_omits_host_port_when_unset(self):
        # Subclasses that override __repr__ must not emit a host/port suffix
        # when neither is set.
        for exc in (exceptions.NoFreeChannels(),
                    exceptions.AuthenticationError('PLAIN'),
                    exceptions.IncompatibleProtocolError('bad'),
                    exceptions.ConnectionClosedByBroker(320, 'forced')):
            self.assertNotIn('host=', repr(exc))
            self.assertNotIn('port=', repr(exc))

    def test_incompatible_protocol_error_host_port(self):
        exc = exceptions.IncompatibleProtocolError('bad',
                                                   host='host1',
                                                   port=5672)
        self.assertEqual(exc.host, 'host1')
        self.assertEqual(exc.port, 5672)
        self.assertIn("(host='host1', port=5672)", repr(exc))

    def test_probable_authentication_error_host_port(self):
        exc = exceptions.ProbableAuthenticationError('x', host='h', port=5672)
        self.assertEqual(exc.host, 'h')
        self.assertEqual(exc.port, 5672)
        self.assertIn("(host='h', port=5672)", repr(exc))

    def test_probable_access_denied_error_host_port(self):
        exc = exceptions.ProbableAccessDeniedError('x', host='h', port=5672)
        self.assertEqual(exc.host, 'h')
        self.assertEqual(exc.port, 5672)
        self.assertIn("(host='h', port=5672)", repr(exc))

    def test_connection_blocked_timeout_host_port(self):
        exc = exceptions.ConnectionBlockedTimeout('timeout',
                                                  host='h',
                                                  port=5672)
        self.assertEqual(exc.host, 'h')
        self.assertEqual(exc.port, 5672)

    def test_amqp_heartbeat_timeout_host_port(self):
        exc = exceptions.AMQPHeartbeatTimeout('timeout', host='h', port=5672)
        self.assertEqual(exc.host, 'h')
        self.assertEqual(exc.port, 5672)

    def test_connection_closed_host_port(self):
        exc = exceptions.ConnectionClosed(200,
                                          'Normal shutdown',
                                          host='rabbit',
                                          port=5672)
        self.assertEqual(exc.host, 'rabbit')
        self.assertEqual(exc.port, 5672)
        self.assertEqual(exc.reply_code, 200)
        self.assertEqual(exc.reply_text, 'Normal shutdown')

    def test_connection_closed_decodes_bytes_reply_text(self):
        exc = exceptions.ConnectionClosed(320, b'CONNECTION_FORCED')
        self.assertEqual(exc.reply_text, 'CONNECTION_FORCED')

    def test_connection_closed_replaces_undecodable_reply_text(self):
        # A broker may send reply-text that is not valid UTF-8. It must not
        # reach the user as a bytes repr.
        exc = exceptions.ConnectionClosed(320, b'forced \xff')
        self.assertEqual(exc.reply_text, 'forced �')
        self.assertNotIn('\\xff', repr(exc))

    def test_connection_closed_by_broker_host_port(self):
        exc = exceptions.ConnectionClosedByBroker(320,
                                                  'forced',
                                                  host='r',
                                                  port=5672)
        self.assertEqual(exc.host, 'r')
        self.assertEqual(exc.port, 5672)
        self.assertIn("(host='r', port=5672)", repr(exc))

    def test_connection_closed_no_host_port_by_default(self):
        exc = exceptions.ConnectionClosed(200, 'OK')
        self.assertIsNone(exc.host)
        self.assertIsNone(exc.port)

    def test_authentication_error_host_port(self):
        exc = exceptions.AuthenticationError('PLAIN', host='broker', port=5672)
        self.assertEqual(exc.host, 'broker')
        self.assertEqual(exc.port, 5672)
        self.assertIn("(host='broker', port=5672)", repr(exc))

    def test_no_free_channels_host_port(self):
        exc = exceptions.NoFreeChannels(host='broker', port=5672)
        self.assertEqual(exc.host, 'broker')
        self.assertEqual(exc.port, 5672)
        self.assertIn("(host='broker', port=5672)", repr(exc))

    def test_authentication_error_repr(self):
        self.assertEqual(
            repr(exceptions.AuthenticationError('PLAIN')),
            'AuthenticationError: Server and client could not negotiate use of '
            'the PLAIN authentication mechanism')

    def test_body_too_long_error_repr(self):
        self.assertEqual(
            repr(exceptions.BodyTooLongError(100, 50)),
            'BodyTooLongError: Received too many bytes for a message delivery: '
            'Received 100, expected 50')

    def test_channel_closed_properties_positional_args(self):
        exc = exceptions.ChannelClosed(9, 'args abcd')
        self.assertEqual(exc.reply_code, 9)
        self.assertEqual(exc.reply_text, 'args abcd')

    def test_channel_closed_properties_kwargs(self):
        exc = exceptions.ChannelClosed(reply_code=9, reply_text='kwargs abcd')
        self.assertEqual(exc.reply_code, 9)
        self.assertEqual(exc.reply_text, 'kwargs abcd')

    def test_channel_closed_repr(self):
        exc = exceptions.ChannelClosed(200, 'all is swell')

        self.assertEqual(repr(exc), "ChannelClosed: (200) 'all is swell'")

    def test_amqp_error_repr(self):
        self.assertEqual(
            repr(exceptions.AMQPError('something went wrong')),
            "AMQPError: An unspecified AMQP error has occurred; ('something went wrong',)"
        )

    def test_incompatible_protocol_error_repr(self):
        self.assertEqual(
            repr(exceptions.IncompatibleProtocolError('bad')),
            "IncompatibleProtocolError: The protocol returned by the server is not supported: ('bad',)"
        )

    def test_probable_authentication_error_repr(self):
        self.assertEqual(
            repr(exceptions.ProbableAuthenticationError('x')),
            "ProbableAuthenticationError: Client was disconnected at a connection stage indicating a "
            "probable authentication error: ('x',)")

    def test_probable_access_denied_error_repr(self):
        self.assertEqual(
            repr(exceptions.ProbableAccessDeniedError('x')),
            "ProbableAccessDeniedError: Client was disconnected at a connection stage indicating a "
            "probable denial of access to the specified virtual host: ('x',)")

    def test_no_free_channels_repr(self):
        self.assertEqual(
            repr(exceptions.NoFreeChannels()),
            'NoFreeChannels: The connection has run out of free channels')

    def test_connection_wrong_state_error_repr_no_args(self):
        self.assertEqual(
            repr(exceptions.ConnectionWrongStateError()),
            'ConnectionWrongStateError: The connection is in wrong state for the requested operation.'
        )

    def test_connection_wrong_state_error_repr_with_args(self):
        exc = exceptions.ConnectionWrongStateError('details')
        self.assertEqual(repr(exc), "ConnectionWrongStateError: ('details',)")

    def test_amqp_channel_error_repr(self):
        self.assertEqual(repr(exceptions.AMQPChannelError('oops')),
                         "AMQPChannelError: ('oops',)")

    def test_duplicate_consumer_tag_repr(self):
        self.assertEqual(
            repr(exceptions.DuplicateConsumerTag('my-tag')),
            'DuplicateConsumerTag: The consumer tag specified already exists for this channel: my-tag'
        )

    def test_consumer_cancelled_repr(self):
        self.assertEqual(repr(exceptions.ConsumerCancelled()),
                         'ConsumerCancelled: Server cancelled consumer')

    def test_unroutable_error_repr(self):
        msgs = [MagicMock(), MagicMock()]
        exc = exceptions.UnroutableError(msgs)
        self.assertEqual(
            repr(exc),
            'UnroutableError: 2 unroutable messages returned by broker')

    def test_unroutable_error_messages(self):
        msgs = [MagicMock(), MagicMock()]
        exc = exceptions.UnroutableError(msgs)
        self.assertEqual(exc.messages, msgs)

    def test_nack_error_repr(self):
        msgs = [MagicMock(), MagicMock(), MagicMock()]
        exc = exceptions.NackError(msgs)
        self.assertEqual(repr(exc),
                         'NackError: 3 unroutable messages returned by broker')

    def test_nack_error_messages(self):
        msgs = [MagicMock(), MagicMock()]
        exc = exceptions.NackError(msgs)
        self.assertEqual(exc.messages, msgs)

    def test_invalid_channel_number_repr(self):
        self.assertEqual(
            repr(exceptions.InvalidChannelNumber(99)),
            'InvalidChannelNumber: An invalid channel number has been specified: 99'
        )

    def test_protocol_syntax_error_repr(self):
        self.assertEqual(
            repr(exceptions.ProtocolSyntaxError()),
            'ProtocolSyntaxError: An unspecified protocol syntax error occurred'
        )

    def test_unexpected_frame_error_repr(self):
        self.assertEqual(
            repr(exceptions.UnexpectedFrameError('bad-frame')),
            "UnexpectedFrameError: Received a frame out of sequence: 'bad-frame'"
        )

    def test_protocol_version_mismatch_repr(self):
        self.assertEqual(
            repr(exceptions.ProtocolVersionMismatch('0-9-1', '0-10')),
            "ProtocolVersionMismatch: Protocol versions did not match: '0-9-1' vs '0-10'"
        )

    def test_invalid_frame_error_repr(self):
        self.assertEqual(repr(exceptions.InvalidFrameError('frame')),
                         "InvalidFrameError: Invalid frame received: 'frame'")

    def test_invalid_field_type_exception_repr(self):
        self.assertEqual(repr(exceptions.InvalidFieldTypeException('z')),
                         'InvalidFieldTypeException: Unsupported field kind z')

    def test_unsupported_amqp_field_exception_repr(self):
        self.assertEqual(
            repr(exceptions.UnsupportedAMQPFieldException('kind', 42)),
            "UnsupportedAMQPFieldException: Unsupported field kind <class 'int'>"
        )

    def test_channel_error_repr(self):
        self.assertEqual(
            repr(exceptions.ChannelError()),
            'ChannelError: An unspecified error occurred with the Channel')

    def test_short_string_too_long_repr(self):
        self.assertEqual(
            repr(exceptions.ShortStringTooLong('toolong')),
            'ShortStringTooLong: AMQP Short String can contain up to 255 bytes: toolong'
        )

    def test_unencodable_decimal_error_repr(self):
        self.assertEqual(
            repr(exceptions.UnencodableDecimalError(decimal.Decimal('NaN'))),
            'UnencodableDecimalError: decimal.Decimal value has no AMQP decimal '
            'representation: NaN')

    def test_unencodable_float_error_repr(self):
        self.assertEqual(
            repr(exceptions.UnencodableFloatError(float('nan'))),
            'UnencodableFloatError: float value is not finite, which RabbitMQ '
            'cannot decode: nan')

    def test_unencodable_long_error_repr(self):
        self.assertEqual(
            repr(exceptions.UnencodableLongError(2**63)),
            'UnencodableLongError: integer value has no AMQP field-table '
            'representation (outside signed 64-bit): 9223372036854775808')

    def test_unencodable_timestamp_error_repr(self):
        value = datetime.datetime(1969, 12, 31, tzinfo=datetime.timezone.utc)
        self.assertEqual(
            repr(exceptions.UnencodableTimestampError(value)),
            'UnencodableTimestampError: datetime value has no AMQP timestamp '
            'representation (before the Unix epoch): '
            '1969-12-31 00:00:00+00:00')

    def test_duplicate_get_ok_callback_repr(self):
        self.assertEqual(
            repr(exceptions.DuplicateGetOkCallback()),
            'DuplicateGetOkCallback: basic_get can only be called again after the callback for '
            'the previous basic_get is executed')


class ConnectorPhaseErrorTests(unittest.TestCase):

    def test_socket_connect_error_host_port(self):
        inner = OSError('Connection refused')
        exc = connection_workflow.AMQPConnectorSocketConnectError(
            inner, host='rabbit.local', port=5672)
        self.assertEqual(exc.host, 'rabbit.local')
        self.assertEqual(exc.port, 5672)
        self.assertEqual(exc.exception, inner)
        self.assertIn("host='rabbit.local'", repr(exc))
        self.assertIn('port=5672', repr(exc))

    def test_socket_connect_error_no_host_port(self):
        inner = OSError('Connection refused')
        exc = connection_workflow.AMQPConnectorSocketConnectError(inner)
        self.assertIsNone(exc.host)
        self.assertIsNone(exc.port)
        self.assertNotIn('host=', repr(exc))

    def test_transport_setup_error_host_port(self):
        inner = Exception('SSL failed')
        exc = connection_workflow.AMQPConnectorTransportSetupError(
            inner, host='10.0.0.1', port=5671)
        self.assertEqual(exc.host, '10.0.0.1')
        self.assertEqual(exc.port, 5671)

    def test_amqp_handshake_error_host_port(self):
        inner = Exception('auth failed')
        exc = connection_workflow.AMQPConnectorAMQPHandshakeError(inner,
                                                                  host='broker',
                                                                  port=5672)
        self.assertEqual(exc.host, 'broker')
        self.assertEqual(exc.port, 5672)
