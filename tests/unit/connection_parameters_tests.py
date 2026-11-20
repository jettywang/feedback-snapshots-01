"""Test `pika.connection.Parameters`, `pika.connection.ConnectionParameters`, and
`pika.connection.URLParameters`
"""

import copy
import ssl
import unittest
import warnings
from unittest import mock
from urllib.parse import quote as url_quote
from urllib.parse import urlencode

import pika
from pika import channel, connection, credentials, exceptions, spec

# Unordered sequence of connection.Parameters's property getters
_ALL_PUBLIC_PARAMETERS_PROPERTIES = tuple(
    attr for attr in vars(connection.Parameters) if not attr.startswith('_') and
    issubclass(type(getattr(connection.Parameters, attr)), property))


class ChildParameters(connection.Parameters):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.extra = 'e'

    def __eq__(self, other):
        if isinstance(other, ChildParameters):
            return self.extra == other.extra and super().__eq__(other)
        return NotImplemented


class ParametersTestsBase(unittest.TestCase):

    def setUp(self):
        warnings.resetwarnings()
        self.addCleanup(warnings.resetwarnings)

    def get_default_properties(self):
        """
        :returns: a dict of expected public property names and default values
            for `pika.connection.Parameters`

        """
        kls = connection.Parameters
        defaults = {
            'blocked_connection_timeout':
                kls.DEFAULT_BLOCKED_CONNECTION_TIMEOUT,
            'channel_max':
                kls.DEFAULT_CHANNEL_MAX,
            'client_properties':
                kls.DEFAULT_CLIENT_PROPERTIES,
            'connection_attempts':
                kls.DEFAULT_CONNECTION_ATTEMPTS,
            'credentials':
                credentials.PlainCredentials(kls.DEFAULT_USERNAME,
                                             kls.DEFAULT_PASSWORD),
            'frame_max':
                kls.DEFAULT_FRAME_MAX,
            'heartbeat':
                kls.DEFAULT_HEARTBEAT_TIMEOUT,
            'host':
                kls.DEFAULT_HOST,
            'locale':
                kls.DEFAULT_LOCALE,
            'max_inbound_message_body_size':
                kls.DEFAULT_MAX_INBOUND_MESSAGE_BODY_SIZE,
            'port':
                kls.DEFAULT_PORT,
            'retry_delay':
                kls.DEFAULT_RETRY_DELAY,
            'socket_timeout':
                kls.DEFAULT_SOCKET_TIMEOUT,
            'stack_timeout':
                kls.DEFAULT_STACK_TIMEOUT,
            'ssl_options':
                kls.DEFAULT_SSL_OPTIONS,
            'virtual_host':
                kls.DEFAULT_VIRTUAL_HOST,
            'tcp_options':
                kls.DEFAULT_TCP_OPTIONS,
            'tls_rules':
                kls.DEFAULT_TLS_RULES
        }

        # Make sure we didn't miss anything
        self.assertSequenceEqual(sorted(defaults),
                                 sorted(_ALL_PUBLIC_PARAMETERS_PROPERTIES))

        return defaults

    def assert_default_parameter_values(self, params):
        """
        Assert that the given parameters object has the default parameter values.

        :param pika.connection.Parameters params: Verify that the given params instance has all
            default property values
        """
        for name, expected_value in self.get_default_properties().items():
            value = getattr(params, name)
            self.assertEqual(
                value,
                expected_value,
                msg=f'Expected {name}={expected_value!r}, but got {value!r}')


class ParametersTests(ParametersTestsBase):

    def test_eq(self):
        params_1 = connection.Parameters()
        params_2 = connection.Parameters()
        params_3 = ChildParameters()

        self.assertEqual(params_1, params_2)
        self.assertEqual(params_2, params_1)

        params_1.host = 'localhost'
        params_1.port = 5672
        params_1.virtual_host = '/'
        params_1.credentials = credentials.PlainCredentials('u', 'p')
        params_2.host = 'localhost'
        params_2.port = 5672
        params_2.virtual_host = '//'
        params_2.credentials = credentials.PlainCredentials('uu', 'pp')
        self.assertEqual(params_1, params_2)
        self.assertEqual(params_2, params_1)

        params_1.host = 'localhost'
        params_1.port = 5672
        params_1.virtual_host = '/'
        params_1.credentials = credentials.PlainCredentials('u', 'p')
        params_3.host = 'localhost'
        params_3.port = 5672
        params_3.virtual_host = '//'
        params_3.credentials = credentials.PlainCredentials('uu', 'pp')
        self.assertEqual(params_1, params_3)
        self.assertEqual(params_3, params_1)

        class Foreign:

            def __eq__(self, other):
                return 'foobar'

        self.assertEqual(params_1 == Foreign(), 'foobar')
        self.assertEqual(Foreign() == params_1, 'foobar')

    def test_ne(self):
        params_1 = connection.Parameters()
        params_2 = connection.Parameters()
        params_3 = ChildParameters()

        params_1.host = 'localhost'
        params_1.port = 5672
        params_2.host = 'myserver.com'
        params_2.port = 5672
        self.assertNotEqual(params_1, params_2)
        self.assertNotEqual(params_2, params_1)

        params_1.host = 'localhost'
        params_1.port = 5672
        params_2.host = 'localhost'
        params_2.port = 5671
        self.assertNotEqual(params_1, params_2)
        self.assertNotEqual(params_2, params_1)

        params_1.host = 'localhost'
        params_1.port = 5672
        params_3.host = 'myserver.com'
        params_3.port = 5672
        self.assertNotEqual(params_1, params_3)
        self.assertNotEqual(params_3, params_1)

        params_1.host = 'localhost'
        params_1.port = 5672
        params_3.host = 'localhost'
        params_3.port = 5671
        self.assertNotEqual(params_1, params_3)
        self.assertNotEqual(params_3, params_1)

        self.assertNotEqual(params_1, {'host': 'localhost', 'port': 5672})
        self.assertNotEqual({'host': 'localhost', 'port': 5672}, params_1)

        class Foreign:

            def __ne__(self, other):
                return 'foobar'

        self.assertEqual(params_1 != Foreign(), 'foobar')
        self.assertEqual(Foreign() != params_1, 'foobar')

    def test_default_property_values(self):
        self.assert_default_parameter_values(connection.Parameters())

    def test_blocked_connection_timeout(self):
        params = connection.Parameters()

        params.blocked_connection_timeout = 60
        self.assertEqual(params.blocked_connection_timeout, 60)

        params.blocked_connection_timeout = 93.5
        self.assertEqual(params.blocked_connection_timeout, 93.5)

        params.blocked_connection_timeout = None
        self.assertIsNone(params.blocked_connection_timeout)

        with self.assertRaises(TypeError):
            params.blocked_connection_timeout = '1.5'

        with self.assertRaises(ValueError):
            params.blocked_connection_timeout = -40

    def test_channel_max(self):
        params = connection.Parameters()

        params.channel_max = 1
        self.assertEqual(params.channel_max, 1)

        params.channel_max = channel.MAX_CHANNELS
        self.assertEqual(params.channel_max, channel.MAX_CHANNELS)

        with self.assertRaises(TypeError):
            params.channel_max = 1.5

        with self.assertRaises(TypeError):
            params.channel_max = '99'

        with self.assertRaises(ValueError):
            params.channel_max = 0

        with self.assertRaises(ValueError):
            params.channel_max = -40

        with self.assertRaises(ValueError):
            params.channel_max = channel.MAX_CHANNELS + 1

    def test_connection_attempts(self):
        params = connection.Parameters()

        params.connection_attempts = 1
        self.assertEqual(params.connection_attempts, 1)

        params.connection_attempts = 10
        self.assertEqual(params.connection_attempts, 10)

        with self.assertRaises(TypeError):
            params.connection_attempts = 1.5

        with self.assertRaises(TypeError):
            params.connection_attempts = '99'

        with self.assertRaises(ValueError):
            params.connection_attempts = 0

        with self.assertRaises(ValueError):
            params.connection_attempts = -40

    def test_credentials(self):
        params = connection.Parameters()

        plain_cred = credentials.PlainCredentials('very', 'reliable')
        params.credentials = plain_cred
        self.assertEqual(params.credentials, plain_cred)

        ext_cred = credentials.ExternalCredentials()
        params.credentials = ext_cred
        self.assertEqual(params.credentials, ext_cred)

        with self.assertRaises(TypeError):
            params.credentials = connection.Parameters()

        with self.assertRaises(TypeError):
            params.credentials = repr(plain_cred)

    def test_frame_max(self):
        params = connection.Parameters()

        params.frame_max = spec.FRAME_MIN_SIZE
        self.assertEqual(params.frame_max, spec.FRAME_MIN_SIZE)

        params.frame_max = spec.FRAME_MIN_SIZE + 1
        self.assertEqual(params.frame_max, spec.FRAME_MIN_SIZE + 1)

        params.frame_max = spec.FRAME_MAX_SIZE
        self.assertEqual(params.frame_max, spec.FRAME_MAX_SIZE)

        params.frame_max = spec.FRAME_MAX_SIZE - 1
        self.assertEqual(params.frame_max, spec.FRAME_MAX_SIZE - 1)

        with self.assertRaises(TypeError):
            params.frame_max = 10000.9

        with self.assertRaises(TypeError):
            params.frame_max = '10000'

        with self.assertRaises(ValueError):
            params.frame_max = spec.FRAME_MIN_SIZE - 1

        with self.assertRaises(ValueError):
            params.frame_max = spec.FRAME_MAX_SIZE + 1

    def test_max_inbound_message_body_size(self):
        params = connection.Parameters()
        self.assertEqual(params.max_inbound_message_body_size, 64 * 1024 * 1024)

        params.max_inbound_message_body_size = 1
        self.assertEqual(params.max_inbound_message_body_size, 1)

        params.max_inbound_message_body_size = 512 * 1024 * 1024
        self.assertEqual(params.max_inbound_message_body_size,
                         512 * 1024 * 1024)

        for bad_type in (True, 1024.0, '1024', None):
            with self.assertRaises(TypeError, msg=repr(bad_type)):
                params.max_inbound_message_body_size = bad_type

        for bad_value in (0, -1, 512 * 1024 * 1024 + 1):
            with self.assertRaises(ValueError, msg=repr(bad_value)):
                params.max_inbound_message_body_size = bad_value

    def test_heartbeat(self):
        params = connection.Parameters()

        params.heartbeat = None
        self.assertIsNone(params.heartbeat)

        params.heartbeat = 0
        self.assertEqual(params.heartbeat, 0)

        params.heartbeat = 600
        self.assertEqual(params.heartbeat, 600)

        with self.assertRaises(TypeError):
            params.heartbeat = 1.5

        with self.assertRaises(TypeError):
            params.heartbeat = '99'

        with self.assertRaises(ValueError):
            params.heartbeat = -1

        def heartbeat_callback(_conn, _val):
            return 1

        params.heartbeat = heartbeat_callback
        self.assertTrue(callable(params.heartbeat))
        self.assertIs(params.heartbeat, heartbeat_callback)

    def test_host(self):
        params = connection.Parameters()

        params.host = '127.0.0.1'
        self.assertEqual(params.host, '127.0.0.1')

        params.host = 'myserver.com'
        self.assertEqual(params.host, 'myserver.com')

        params.host = 'myserver.com'
        self.assertEqual(params.host, 'myserver.com')

        with self.assertRaises(TypeError):
            params.host = 127

        with self.assertRaises(TypeError):
            params.host = ('127.0.0.1', 5672)

    def test_locale(self):
        params = connection.Parameters()

        params.locale = 'en_UK'
        self.assertEqual(params.locale, 'en_UK')

        params.locale = 'en_UK'
        self.assertEqual(params.locale, 'en_UK')

        with self.assertRaises(TypeError):
            params.locale = 127

    def test_port(self):
        params = connection.Parameters()

        params.port = 0
        self.assertEqual(params.port, 0)

        params.port = 5672
        self.assertEqual(params.port, 5672)

        params.port = '5672'
        self.assertEqual(params.port, 5672)

        params.port = 1.5
        self.assertEqual(params.port, 1)

        with self.assertRaises(TypeError):
            params.port = '50a'

        with self.assertRaises(TypeError):
            params.port = []

        # bool subclasses int; port=True must not silently become 1
        for value in (True, False):
            with self.assertRaises(TypeError):
                params.port = value

    def test_retry_delay(self):
        params = connection.Parameters()

        params.retry_delay = 0
        self.assertEqual(params.retry_delay, 0)

        params.retry_delay = 0.1
        self.assertEqual(params.retry_delay, 0.1)

        with self.assertRaises(TypeError):
            params.retry_delay = '0.1'

    def test_socket_timeout(self):
        params = connection.Parameters()

        params.socket_timeout = 1
        self.assertEqual(params.socket_timeout, 1)

        params.socket_timeout = 0.5
        self.assertEqual(params.socket_timeout, 0.5)

        params.socket_timeout = 60.5
        self.assertEqual(params.socket_timeout, 60.5)

        params.socket_timeout = None
        self.assertEqual(params.socket_timeout, None)

        with self.assertRaises(TypeError):
            params.socket_timeout = '60.5'

        with self.assertRaises(ValueError):
            params.socket_timeout = -1

        with self.assertRaises(ValueError):
            params.socket_timeout = 0

        # bool subclasses numbers.Real; True must not silently become 1.0s
        for value in (True, False):
            with self.assertRaises(TypeError):
                params.socket_timeout = value

    def test_stack_timeout_rejects_bool(self):
        params = connection.Parameters()
        # bool subclasses numbers.Real; True must not silently become 1.0s
        for value in (True, False):
            with self.assertRaises(TypeError):
                params.stack_timeout = value
        params.stack_timeout = 5.0
        self.assertEqual(params.stack_timeout, 5.0)

    def test_ssl_options(self):
        params = connection.Parameters()

        ssl_options = connection.SSLOptions(ssl.create_default_context())
        params.ssl_options = ssl_options
        self.assertIs(params.ssl_options, ssl_options)

        params.ssl_options = None
        self.assertIsNone(params.ssl_options)

        with self.assertRaises(TypeError):
            params.ssl_options = {}

    def test_virtual_host(self):
        params = connection.Parameters()

        params.virtual_host = '/'
        self.assertEqual(params.virtual_host, '/')

        params.virtual_host = '/'
        self.assertEqual(params.virtual_host, '/')

        params.virtual_host = 'test-vhost'
        self.assertEqual(params.virtual_host, 'test-vhost')

        with self.assertRaises(TypeError):
            params.virtual_host = 99

    def test_tcp_options(self):
        params = connection.Parameters()

        opt = {
            'TCP_KEEPIDLE': 60,
            'TCP_KEEPINTVL': 2,
            'TCP_KEEPCNT': 1,
            'TCP_USER_TIMEOUT': 1000
        }
        params.tcp_options = copy.deepcopy(opt)
        self.assertEqual(params.tcp_options, opt)

        params.tcp_options = None
        self.assertIsNone(params.tcp_options)

        with self.assertRaises(TypeError):
            params.tcp_options = str(opt)


class ConnectionParametersTests(ParametersTestsBase):

    def test_default_property_values(self):
        self.assert_default_parameter_values(connection.ConnectionParameters())

    def test_explicit_ssl_with_default_port(self):
        params = connection.ConnectionParameters(
            ssl_options=connection.SSLOptions(ssl.create_default_context()))

        self.assertIsNotNone(params.ssl_options)
        self.assertEqual(params.port, params.DEFAULT_SSL_PORT)

    def test_explicit_ssl_with_explict_port(self):
        params = connection.ConnectionParameters(
            ssl_options=connection.SSLOptions(ssl.create_default_context()),
            port=99)

        self.assertIsNotNone(params.ssl_options)
        self.assertEqual(params.port, 99)

    def test_explicit_non_ssl_with_default_port(self):
        params = connection.ConnectionParameters(ssl_options=None)

        self.assertIsNone(params.ssl_options)
        self.assertEqual(params.port, params.DEFAULT_PORT)

    def test_explicit_non_ssl_with_explict_port(self):
        params = connection.ConnectionParameters(ssl_options=None, port=100)

        self.assertIsNone(params.ssl_options)
        self.assertEqual(params.port, 100)

    def test_exlicit_none_stack_timeout(self):
        params = connection.ConnectionParameters(stack_timeout=None)
        self.assertIsNone(params.stack_timeout)

    def test_exlicit_none_socket_timeout(self):
        params = connection.ConnectionParameters(socket_timeout=None)
        self.assertIsNone(params.socket_timeout)

    def test_good_connection_parameters(self):
        """Make sure connection kwargs get set correctly."""
        kwargs = {
            'blocked_connection_timeout': 10.5,
            'channel_max': 3,
            'client_properties': {
                'good': 'day'
            },
            'connection_attempts': 2,
            'credentials': credentials.PlainCredentials('very', 'secure'),
            'frame_max': 40000,
            'heartbeat': 7,
            'host': 'https://www.test.com',
            'locale': 'en',
            'max_inbound_message_body_size': 1024,
            'port': 5678,
            'retry_delay': 3,
            'socket_timeout': 100.5,
            'stack_timeout': 150,
            'ssl_options': None,
            'virtual_host': 'vvhost',
            'tcp_options': {
                'TCP_USER_TIMEOUT': 1000
            },
            'tls_rules': None
        }
        params = connection.ConnectionParameters(**kwargs)

        # Verify

        expected_values = copy.copy(kwargs)

        # Make sure we're testing all public properties
        self.assertSequenceEqual(sorted(expected_values),
                                 sorted(_ALL_PUBLIC_PARAMETERS_PROPERTIES))
        # Check property values
        for t_param in expected_values:
            value = getattr(params, t_param)
            self.assertEqual(
                expected_values[t_param],
                value,
                msg=
                f'Expected {t_param}={expected_values[t_param]!r}, but got {value!r}'
            )

    def test_callable_heartbeat(self):

        def heartbeat_callback(_connection, _broker_val):
            return 1

        parameters = pika.ConnectionParameters(heartbeat=heartbeat_callback)
        self.assertIs(parameters.heartbeat, heartbeat_callback)

    def test_bad_type_connection_parameters(self):
        """Test connection kwargs type checks throw errors for bad input."""
        kwargs = {
            'host': 'https://www.test.com',
            'port': 5678,
            'virtual_host': 'vvhost',
            'channel_max': 3,
            'frame_max': 40000,
            'heartbeat': 7,
            'ssl': True,
            'blocked_connection_timeout': 10.5
        }
        # Test Type Errors
        for bad_field, bad_value in (('host', 15672), ('port', '5672a'),
                                     ('virtual_host', True), ('channel_max',
                                                              '4'),
                                     ('frame_max', '5'), ('credentials', 'bad'),
                                     ('locale', 1), ('heartbeat', '6'),
                                     ('socket_timeout',
                                      '42'), ('stack_timeout',
                                              '99'), ('retry_delay',
                                                      'two'), ('ssl', {
                                                          'ssl': 'dict'
                                                      }), ('ssl_options', True),
                                     ('connection_attempts',
                                      'hello'), ('blocked_connection_timeout',
                                                 set())):

            bkwargs = copy.deepcopy(kwargs)

            bkwargs[bad_field] = bad_value

            self.assertRaises(TypeError, connection.ConnectionParameters,
                              **bkwargs)

    def test_parameters_accepts_plain_string_virtualhost(self):
        parameters = pika.ConnectionParameters(virtual_host='prtfqpeo')
        self.assertEqual(parameters.virtual_host, 'prtfqpeo')

    def test_parameters_accepts_unicode_string_virtualhost(self):
        parameters = pika.ConnectionParameters(virtual_host='prtfqpeo')
        self.assertEqual(parameters.virtual_host, 'prtfqpeo')

    def test_parameters_accept_plain_string_locale(self):
        parameters = pika.ConnectionParameters(locale='en_US')
        self.assertEqual(parameters.locale, 'en_US')

    def test_parameters_accept_unicode_locale(self):
        parameters = pika.ConnectionParameters(locale='en_US')
        self.assertEqual(parameters.locale, 'en_US')


class URLParametersTests(ParametersTestsBase):

    def test_default_property_values(self):
        params = connection.URLParameters('')
        self.assert_default_parameter_values(params)

        self.assertIsNone(params.ssl_options)
        self.assertEqual(params.port, params.DEFAULT_PORT)

    def test_no_ssl(self):
        params = connection.URLParameters('http://')
        self.assertIsNone(params.ssl_options)
        self.assertEqual(params.port, params.DEFAULT_PORT)
        self.assert_default_parameter_values(params)

        params = connection.URLParameters('amqp://')
        self.assertIsNone(params.ssl_options)
        self.assertEqual(params.port, params.DEFAULT_PORT)
        self.assert_default_parameter_values(params)

    def test_ssl(self):
        params = connection.URLParameters('https://')
        self.assertIsNotNone(params.ssl_options)
        self.assertEqual(params.port, params.DEFAULT_SSL_PORT)

        params = connection.URLParameters('amqps://')
        self.assertIsNotNone(params.ssl_options)
        self.assertEqual(params.port, params.DEFAULT_SSL_PORT)

        # Make sure the other parameters unrelated to SSL have default values
        params = connection.URLParameters('amqps://')
        params.ssl_options = None
        params.port = params.DEFAULT_PORT
        self.assert_default_parameter_values(params)

    def test_ssl_default_protocol_version_fallback(self):
        """
        This test does not set the `protocol` option in ssl_options.

        Instead, it relies on connection.URLParameters class to setup the default, and then it
        asserts the protocol is `ssl.PROTOCOL_TLS_CLIENT`.
        """
        params = connection.URLParameters(
            'amqps://foo.bar/some-vhost?ssl_options=%7B%27ca_certs%27%3A%27tests%2Fcerts%2Fca_certificate.pem%27%7D'
        )
        assert params.ssl_options is not None
        self.assertEqual(params.ssl_options.context.protocol,
                         ssl.PROTOCOL_TLS_CLIENT)

    def test_ssl_options_without_a_ca_use_the_default_certs(self):
        opts = url_quote(
            str({
                'certfile': 'tests/certs/client_certificate.pem',
                'keyfile': 'tests/certs/client_key.pem'
            }))
        with mock.patch.object(ssl.SSLContext,
                               'load_default_certs',
                               autospec=True) as load_default_certs:
            params = connection.URLParameters(
                f'amqps://foo.bar/%2F?ssl_options={opts}')
        assert params.ssl_options is not None
        # The amqps scheme first builds its own default context, which calls
        # load_default_certs with a purpose; this matches only pika's call.
        load_default_certs.assert_any_call(params.ssl_options.context)

    def test_ssl_options_verify_whatever_the_protocol(self):
        for ca in ({}, {'ca_certs': 'tests/certs/ca_certificate.pem'}):
            for protocol in (ssl.PROTOCOL_TLS, ssl.PROTOCOL_TLSv1_2):
                with self.subTest(ca=bool(ca), protocol=protocol):
                    opts = url_quote(str({'protocol': int(protocol), **ca}))
                    with warnings.catch_warnings():
                        # ssl deprecates both protocols, which these cases cover.
                        warnings.simplefilter('ignore', DeprecationWarning)
                        params = connection.URLParameters(
                            f'amqps://foo.bar/%2F?ssl_options={opts}')
                    assert params.ssl_options is not None
                    context = params.ssl_options.context
                    self.assertEqual(context.protocol, protocol)
                    self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                    self.assertTrue(context.check_hostname)

    def test_ssl_options_with_a_ca_load_only_that_ca(self):
        opts = url_quote(str({'ca_certs': 'tests/certs/ca_certificate.pem'}))
        with mock.patch.object(ssl.SSLContext,
                               'load_default_certs',
                               autospec=True) as load_default_certs:
            params = connection.URLParameters(
                f'amqps://foo.bar/%2F?ssl_options={opts}')
        assert params.ssl_options is not None
        self.assertNotIn(mock.call(params.ssl_options.context),
                         load_default_certs.call_args_list)
        self.assertEqual(len(params.ssl_options.context.get_ca_certs()), 1)

    def test_no_url_scheme_defaults_to_plaintext(self):
        params = connection.URLParameters('//')
        self.assertIsNone(params.ssl_options)
        self.assertEqual(params.port, params.DEFAULT_PORT)

    def test_bad_max_inbound_message_body_size_raises_value_error(self):
        for value in ('abc', '0', str(512 * 1024 * 1024 + 1)):
            with self.assertRaises(ValueError, msg=value):
                connection.URLParameters(
                    f'amqp://localhost/%2F?max_inbound_message_body_size={value}'
                )

    def test_good_parameters(self):
        """Test for the different query stings checked by process url."""
        query_args = {
            'blocked_connection_timeout': 10.5,
            'channel_max': 3,
            'connection_attempts': 2,
            'frame_max': 40000,
            'heartbeat': 7,
            'locale': 'en_UK',
            'max_inbound_message_body_size': 2048,
            'retry_delay': 3,
            'socket_timeout': 100.5,
            'ssl_options': None,
            'tcp_options': {
                'TCP_USER_TIMEOUT': 1000,
                'TCP_KEEPIDLE': 60
            }
        }

        test_params = dict(query_args)
        virtual_host = '/'
        query_string = urlencode(test_params)
        test_url = ('amqp://myuser:mypass@www.test.com:5678/{}?{}'.format(
            url_quote(virtual_host, safe=''),
            query_string,
        ))

        params = connection.URLParameters(test_url)

        # check all value from query string

        for t_param, expected_value in query_args.items():
            actual_value = getattr(params, t_param)

            self.assertEqual(
                actual_value,
                expected_value,
                msg=
                f'Expected {t_param}={expected_value!r}, but got {actual_value!r}'
            )

        # check all values from base URL
        assert isinstance(params.credentials, credentials.PlainCredentials)
        self.assertEqual(params.credentials.username, 'myuser')
        self.assertEqual(params.credentials.password, 'mypass')
        self.assertEqual(params.host, 'www.test.com')
        self.assertEqual(params.port, 5678)
        self.assertEqual(params.virtual_host, virtual_host)

    def test_accepts_plain_string(self):
        parameters = pika.URLParameters('amqp://prtfqpeo:oihdglkhcp0@myserver.'
                                        'mycompany.com:5672/prtfqpeo?locale='
                                        'en_US')
        self.assertEqual(parameters.port, 5672)
        self.assertEqual(parameters.virtual_host, 'prtfqpeo')
        assert isinstance(parameters.credentials, credentials.PlainCredentials)
        self.assertEqual(parameters.credentials.password, 'oihdglkhcp0')
        self.assertEqual(parameters.credentials.username, 'prtfqpeo')
        self.assertEqual(parameters.locale, 'en_US')

    def test_accepts_unicode_string(self):
        parameters = pika.URLParameters('amqp://prtfqpeo:oihdglkhcp0@myserver'
                                        '.mycompany.com:5672/prtfqpeo?locale='
                                        'en_US')
        self.assertEqual(parameters.port, 5672)
        self.assertEqual(parameters.virtual_host, 'prtfqpeo')
        assert isinstance(parameters.credentials, credentials.PlainCredentials)
        self.assertEqual(parameters.credentials.password, 'oihdglkhcp0')
        self.assertEqual(parameters.credentials.username, 'prtfqpeo')
        self.assertEqual(parameters.locale, 'en_US')

    def test_uses_default_port_if_not_specified(self):
        parameters = pika.URLParameters('amqp://myserver.mycompany.com')
        self.assertEqual(parameters.port, pika.URLParameters.DEFAULT_PORT)

    def test_uses_default_virtual_host_if_not_specified(self):
        parameters = pika.URLParameters('amqp://myserver.mycompany.com')
        self.assertEqual(parameters.virtual_host,
                         pika.URLParameters.DEFAULT_VIRTUAL_HOST)

    def test_uses_default_virtual_host_if_only_slash_is_specified(self):
        parameters = pika.URLParameters('amqp://myserver.mycompany.com/')
        self.assertEqual(parameters.virtual_host,
                         pika.URLParameters.DEFAULT_VIRTUAL_HOST)

    def test_uses_default_virtual_host_via_encoded_slash_upcase(self):
        parameters = pika.URLParameters('amqp://myserver.mycompany.com/%2F')
        self.assertEqual(parameters.virtual_host,
                         pika.URLParameters.DEFAULT_VIRTUAL_HOST)

    def test_uses_default_virtual_host_via_encoded_slash_downcase(self):
        parameters = pika.URLParameters('amqp://myserver.mycompany.com/%2f')
        self.assertEqual(parameters.virtual_host,
                         pika.URLParameters.DEFAULT_VIRTUAL_HOST)

    def test_uses_default_virtual_host_via_encoded_slash_upcase_ending_with_slash(
            self):
        parameters = pika.URLParameters('amqp://myserver.mycompany.com/%2F/')
        self.assertEqual(parameters.virtual_host,
                         pika.URLParameters.DEFAULT_VIRTUAL_HOST)

    def test_uses_default_virtual_host_via_encoded_slash_downcase_ending_with_slash(
            self):
        parameters = pika.URLParameters('amqp://myserver.mycompany.com/%2f/')
        self.assertEqual(parameters.virtual_host,
                         pika.URLParameters.DEFAULT_VIRTUAL_HOST)

    def test_uses_default_virtual_host_if_only_parameters_provided(self):
        parameters = pika.URLParameters(
            'amqp://myserver.mycompany.com?frame_max=8192&locale=utf8')
        self.assertEqual(parameters.virtual_host,
                         pika.URLParameters.DEFAULT_VIRTUAL_HOST)
        self.assertEqual(parameters.frame_max, 8192)
        self.assertEqual(parameters.locale, 'utf8')

    def test_uses_default_username_and_password_if_not_specified(self):
        parameters = pika.URLParameters('amqp://myserver.mycompany.com')
        assert isinstance(parameters.credentials, credentials.PlainCredentials)
        self.assertEqual(parameters.credentials.username,
                         pika.URLParameters.DEFAULT_USERNAME)
        self.assertEqual(parameters.credentials.password,
                         pika.URLParameters.DEFAULT_PASSWORD)

    def test_uses_default_password_if_only_username_specified(self):
        for url, username in (('amqp://bob@myserver.mycompany.com', 'bob'),
                              ('amqp://b%40b@myserver.mycompany.com', 'b@b')):
            parameters = pika.URLParameters(url)
            assert isinstance(parameters.credentials,
                              credentials.PlainCredentials)
            self.assertEqual(parameters.credentials.username, username)
            self.assertEqual(parameters.credentials.password,
                             pika.URLParameters.DEFAULT_PASSWORD)

    def test_accepts_blank_username_and_password(self):
        parameters = pika.URLParameters('amqp://:@myserver.mycompany.com')
        assert isinstance(parameters.credentials, credentials.PlainCredentials)
        self.assertEqual(parameters.credentials.username, '')
        self.assertEqual(parameters.credentials.password, '')

    def test_url_decodes_username_and_password(self):
        username = '@@@@'
        password = '////'
        parameters = pika.URLParameters(
            'amqp://%40%40%40%40:%2F%2F%2F%2F@myserver.mycompany.com')
        assert isinstance(parameters.credentials, credentials.PlainCredentials)
        self.assertEqual(parameters.credentials.username, username)
        self.assertEqual(parameters.credentials.password, password)


class TLSRulesTests(unittest.TestCase):
    """`Parameters.tls_rules` and the candidate resolution the workflow uses."""

    def setUp(self):
        self.corp_ca = connection.TLSVerificationRule(
            ssl.create_default_context(), 'lb.internal.example', 'corp-ca')
        self.rotated_ca = connection.TLSVerificationRule(
            ssl.create_default_context(), 'broker-by-ip.internal', 'rotated-ca')

    def test_it_rejects_a_template_that_can_never_match(self):
        for template in ('', '.', '*.', 'a..b', '*.broker.example:5671',
                         '*.broker.*/x'):
            with self.subTest(template=template):
                with self.assertRaises(ValueError):
                    connection.ConnectionParameters(
                        tls_rules={template: self.corp_ca})

    def test_it_rejects_a_non_string_template_or_wrong_rule_type(self):
        for template in (None, 1, b'*.example'):
            with self.subTest(template=template):
                with self.assertRaises(TypeError):
                    connection.ConnectionParameters(
                        tls_rules={template: self.corp_ca})
        with self.assertRaises(TypeError):
            connection.ConnectionParameters(tls_rules={
                'a.example': pika.SSLOptions(ssl.create_default_context())
            })

    def test_a_rule_needs_a_verification_name(self):
        for name in (None, '', 5):
            with self.subTest(name=name):
                with self.assertRaises(TypeError):
                    connection.TLSVerificationRule(
                        ssl.create_default_context(),
                        name)  # type: ignore[arg-type]

    def test_a_rule_can_build_its_trust_from_ca_material(self):
        rule = connection.TLSVerificationRule(
            server_hostname='broker.example',
            cafile='tests/certs/ca_certificate.pem')
        self.assertEqual(ssl.CERT_REQUIRED, rule.context.verify_mode)
        self.assertTrue(rule.context.check_hostname)
        self.assertEqual(1, len(rule.context.get_ca_certs()))
        self.assertEqual('tests/certs/ca_certificate.pem', rule.trust_source)

    def test_a_rule_takes_a_context_or_ca_material_but_not_both(self):
        with self.assertRaises(ValueError):
            connection.TLSVerificationRule(server_hostname='broker.example')
        with self.assertRaises(ValueError):
            connection.TLSVerificationRule(ssl.create_default_context(),
                                           'broker.example',
                                           cafile='tests/certs/'
                                           'ca_certificate.pem')

    def test_it_starts_unset_and_can_be_cleared(self):
        params = connection.ConnectionParameters()
        self.assertIsNone(params.tls_rules)
        params.tls_rules = {'*.broker.example': self.corp_ca}
        self.assertEqual(list(params.tls_rules),
                         ['*.broker.example'])  # type: ignore[arg-type]
        params.tls_rules = None
        self.assertIsNone(params.tls_rules)

    def test_templates_match_whole_labels_case_insensitively(self):
        match = connection._match_candidate_template
        self.assertTrue(match('*.broker.example', 'lb1.broker.example'))
        self.assertTrue(match('*.broker.example', 'LB1.BROKER.EXAMPLE'))
        # A single `*` cannot stand for no label, so the apex is not covered.
        self.assertFalse(match('*.broker.example', 'broker.example'))
        self.assertFalse(match('*.broker.example', 'a.b.broker.example'))
        self.assertFalse(match('*.broker.example', 'lb1.broker.example.evil'))
        self.assertTrue(match('broker-*.example', 'broker-01.example'))
        self.assertFalse(match('broker-*.example', 'broker-.example'))

    def test_ip_templates_compare_normalized_addresses(self):
        match = connection._match_candidate_template
        self.assertTrue(match('10.20.3.*', '10.20.3.4'))
        self.assertFalse(match('10.20.3.*', '10.20.30.4'))
        self.assertTrue(match('10.20.3.4', '10.20.3.4'))
        self.assertFalse(match('10.20.3.4', '10.20.3.41'))
        self.assertTrue(match('::1', '0:0:0:0:0:0:0:1'))
        self.assertFalse(match('*.example', 'fd00::1'))

    def test_host_rules_take_precedence_over_the_resolved_address(self):
        rules = {
            'lb.internal.example': self.corp_ca,
            '10.20.*.*': self.rotated_ca,
        }
        rule = connection._resolve_candidate_tls_rule(rules,
                                                      'lb.internal.example',
                                                      5671,
                                                      address='10.20.3.4')
        self.assertIs(rule, self.corp_ca)

    def test_the_address_covers_a_name_with_no_rule(self):
        rules = {'10.20.*.*': self.rotated_ca}
        rule = connection._resolve_candidate_tls_rule(
            rules, 'unlisted.internal.example', 5671, address='10.20.3.4')
        self.assertIs(rule, self.rotated_ca)

    def test_the_most_specific_template_wins(self):
        exact = connection.TLSVerificationRule(ssl.create_default_context(),
                                               'lb1.internal.example')
        rules = {
            '*.internal.example': self.corp_ca,
            'lb1.internal.example': exact
        }
        self.assertIs(
            connection._resolve_candidate_tls_rule(rules,
                                                   'lb1.internal.example',
                                                   5671), exact)

    def test_an_uncovered_candidate_states_host_address_and_templates(self):
        rules = {'*.broker.example': self.corp_ca}
        with self.assertRaises(
                exceptions.CandidateNotCoveredByTLSRuleError) as raised:
            connection._resolve_candidate_tls_rule(rules,
                                                   'unknown.example',
                                                   5671,
                                                   address='192.0.2.9')
        text = repr(raised.exception)
        self.assertIn("'unknown.example'", text)
        self.assertIn("resolved '192.0.2.9'", text)
        self.assertIn("'*.broker.example'", text)
        self.assertEqual(raised.exception.host, 'unknown.example')
        self.assertEqual(raised.exception.port, 5671)

    def test_no_rules_means_no_selection(self):
        self.assertIsNone(
            connection._resolve_candidate_tls_rule(None, 'any.example', 5671))
