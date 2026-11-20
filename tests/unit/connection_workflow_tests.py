"""Tests for per-candidate TLS verification in `pika.adapters.utils.connection_workflow`.

Every address lookup, socket and TLS handshake here is a local fake, so the tests record the
arguments a real transport would receive without opening a connection.
"""

import socket
import ssl
import unittest
from collections import deque
from functools import partial
from unittest import mock

import pika
from pika.adapters import blocking_connection
from pika.adapters.utils import connection_workflow
from pika.exceptions import CandidateNotCoveredByTLSRuleError


def addr(ip, port=5671):
    """Return one `getaddrinfo()` record for *ip*."""
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    sockaddr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', sockaddr)


class _Ref:
    """Cancelable stand-in for a timer or I/O reference."""

    def __init__(self):
        self.cancelled = False

    def cancel(self):
        self.cancelled = True


class _FakeSocket:
    """Records socket creation so a refused candidate can be shown not to reach one."""

    def __init__(self, *args):
        self.args = args
        self.closed = False

    def setsockopt(self, *args):
        pass

    def setblocking(self, flag):
        pass

    def close(self):
        self.closed = True


class _FakeProtocol:
    """Stands in for the shimmed Connection during the AMQP handshake."""

    def __init__(self, io, handshake):
        self._io = io
        self._handshake = handshake

    def add_on_open_error_callback(self, callback, remove_default=False):
        pass

    def add_on_open_callback(self, callback):
        error = self._handshake()
        if error is None:
            self._io.call_later(0, partial(callback, self))
        else:
            self._io.call_later(0, partial(callback, self, error))


class _FakeIO:
    """An I/O loop whose transport setup records the TLS arguments it would use."""

    def __init__(self, answers, handshakes=None):
        self.answers = answers
        self.handshakes = handshakes or {}
        self.queue = deque()
        self.resolved = []
        self.connected = []
        self.transports = []
        self.sockets = []

    def get_native_ioloop(self):
        return self

    def call_later(self, delay, callback):
        ref = _Ref()
        self.queue.append((ref, callback))
        return ref

    def add_callback_threadsafe(self, callback):
        self.call_later(0, callback)

    def getaddrinfo(self, host, port, socktype, proto, on_done):
        self.resolved.append((host, port))
        return self.call_later(0, partial(on_done, self.answers[host]))

    def connect_socket(self, sock, resolved_addr, on_done):
        self.connected.append(resolved_addr)
        return self.call_later(0, partial(on_done, None))

    def make_socket(self, family, type_, proto):
        sock = _FakeSocket(family, type_, proto)
        self.sockets.append(sock)
        return sock

    def create_streaming_connection(self, **kwargs):
        self.transports.append(kwargs)
        host = kwargs['server_hostname']
        handshake = self.handshakes.get(
            host, lambda: RuntimeError('the fake broker refused the handshake'))
        protocol = _FakeProtocol(self, handshake)
        return self.call_later(0,
                               partial(kwargs['on_done'], (object(), protocol)))

    def run(self):
        count = 0
        while self.queue:
            count += 1
            self.assert_terminates(count)
            ref, callback = self.queue.popleft()
            if not ref.cancelled:
                callback()

    @staticmethod
    def assert_terminates(count):
        assert count < 100, 'workflow did not terminate'


def params(host, rules, **kwargs):
    return pika.ConnectionParameters(host=host,
                                     port=5671,
                                     tls_rules=rules,
                                     retry_delay=0,
                                     socket_timeout=None,
                                     stack_timeout=None,
                                     **kwargs)


def run(io, configs, connector_factory=None):
    """Run the workflow against *io* and return its result and the workflow."""
    results = []
    workflow = connection_workflow.AMQPConnectionWorkflow()
    workflow.set_io_services(io)
    if connector_factory is None:
        connector_factory = lambda: connection_workflow.AMQPConnector(  # noqa: E731
            lambda _params: object(), io)
    workflow.start(configs, connector_factory, None, results.append)
    with mock.patch.object(connection_workflow.socket, 'socket',
                           io.make_socket):
        io.run()
    return results[0], workflow


class _ConstructibleConnection(pika.connection.Connection):
    """Implements the adapter hooks an inert `Connection` needs."""

    def _adapter_connect_stream(self):
        pass

    def _adapter_disconnect_stream(self):
        pass

    def _adapter_call_later(self, delay, callback):
        pass

    def _adapter_remove_timeout(self, timeout_id):
        pass

    def _adapter_add_callback_threadsafe(self, callback):
        pass

    def _adapter_emit_data(self, data):
        pass


class ParametersCopyTests(unittest.TestCase):
    """A `Connection` copies the rules, so one attempt cannot mutate another's."""

    def test_the_rules_and_their_contexts_survive_the_parameters_copy(self):
        context = ssl.create_default_context()
        rule = pika.TLSVerificationRule(context, 'broker.example')
        original = pika.ConnectionParameters(host='broker.example',
                                             tls_rules={'broker.example': rule})

        conn = _ConstructibleConnection(original)

        self.assertIsNot(original, conn.params)
        self.assertIs(rule, conn.params.tls_rules['broker.example'])
        self.assertIs(context, conn.params.tls_rules['broker.example'].context)
        self.assertIs(rule, original.tls_rules['broker.example'])


class CandidateRuleTests(unittest.TestCase):
    """Each candidate's rule decides the TLS arguments its handshake receives."""

    def setUp(self):
        self.corp_ca = ssl.create_default_context()
        self.rotated_ca = ssl.create_default_context()
        self.rules = {
            '*.internal.example':
                pika.TLSVerificationRule(self.corp_ca, 'lb.internal.example',
                                         'corp-ca'),
            '10.20.*.*':
                pika.TLSVerificationRule(self.rotated_ca,
                                         'broker-by-ip.internal', 'rotated-ca'),
        }

    def test_two_candidates_use_their_own_name_and_trust_source(self):
        io = _FakeIO({
            'lb.internal.example': [addr('10.20.1.5')],
            '10.20.3.4': [addr('10.20.3.4')],
        })
        first = params('lb.internal.example', self.rules)
        second = params('10.20.3.4', self.rules)

        result, _workflow = run(io, [first, second])

        self.assertIsInstance(result,
                              connection_workflow.AMQPConnectionWorkflowFailed)
        self.assertIsInstance(
            result.exceptions[-1],
            connection_workflow.AMQPConnectorAMQPHandshakeError)
        self.assertEqual([('10.20.1.5', 5671), ('10.20.3.4', 5671)],
                         io.connected)
        self.assertEqual(2, len(io.sockets))
        self.assertEqual(2, len(io.transports))
        by_name = {
            transport['server_hostname']: transport
            for transport in io.transports
        }
        self.assertIs(by_name['lb.internal.example']['ssl_context'],
                      self.corp_ca)
        self.assertIs(by_name['broker-by-ip.internal']['ssl_context'],
                      self.rotated_ca)

    def test_a_rejected_name_rule_falls_back_to_the_resolved_address(self):
        # The address alone has a rule, so the deployment can key by IP while dialing a name.
        io = _FakeIO({'dialed.internal.example': [addr('10.20.3.4')]})
        rule = pika.TLSVerificationRule(self.rotated_ca, 'by-address')

        result, _workflow = run(
            io, [params('dialed.internal.example', {'10.20.3.4': rule})])

        self.assertEqual(1, len(io.sockets))
        self.assertEqual(1, len(io.transports))
        self.assertEqual('by-address', io.transports[0]['server_hostname'])
        self.assertIs(self.rotated_ca, io.transports[0]['ssl_context'])
        self.assertIsInstance(result,
                              connection_workflow.AMQPConnectionWorkflowFailed)
        self.assertIsInstance(
            result.exceptions[-1],
            connection_workflow.AMQPConnectorAMQPHandshakeError)

    def test_a_wrong_candidate_cannot_connect_but_the_legal_fallback_does(self):
        io = _FakeIO({
            'lb.internal.example': [addr('10.20.1.5'),
                                    addr('10.99.1.5')],
            '10.20.3.4': [addr('10.20.3.4')],
        })

        def verify():
            return ssl.SSLCertVerificationError(
                'certificate verify failed: Hostname mismatch')

        io.handshakes = {'lb.internal.example': verify}

        def connector_factory():
            return connection_workflow.AMQPConnector(lambda _params: object(),
                                                     io)

        result, _workflow = run(io, [
            params('lb.internal.example', self.rules),
            params('10.20.3.4', self.rules)
        ], connector_factory)

        self.assertIsInstance(result,
                              connection_workflow.AMQPConnectionWorkflowFailed)
        self.assertIsInstance(
            result.exceptions[-1],
            connection_workflow.AMQPConnectorAMQPHandshakeError)
        # The first config's second address is also refused at TLS, not at the rule.
        self.assertEqual([('10.20.1.5', 5671), ('10.99.1.5', 5671),
                          ('10.20.3.4', 5671)], io.connected)

    def test_a_rotated_rule_applies_to_the_next_attempt(self):
        """A rule replaced between attempts is what the next handshake uses."""
        io = _FakeIO({
            'lb.internal.example': [addr('10.20.1.5')],
            '10.20.3.4': [addr('10.20.3.4')]
        })
        first = params('lb.internal.example',
                       {'*.internal.example': self.rules['*.internal.example']})
        second = params(
            '10.20.3.4',
            {'10.20.3.4': pika.TLSVerificationRule(self.rotated_ca, 'rotated')})
        io.handshakes = {
            'lb.internal.example':
                lambda: ssl.SSLCertVerificationError('certificate has expired')
        }

        _result, _workflow = run(io, [first, second])

        contexts = [transport['ssl_context'] for transport in io.transports]
        self.assertIs(self.corp_ca, contexts[0])
        self.assertIs(self.rotated_ca, contexts[1])
        self.assertEqual(['lb.internal.example', 'rotated'],
                         [t['server_hostname'] for t in io.transports])

    def test_ssl_options_still_apply_when_no_rules_are_configured(self):
        context = ssl.create_default_context()
        io = _FakeIO({'broker.example': [addr('10.20.1.5')]})
        config = pika.ConnectionParameters(host='broker.example',
                                           port=5671,
                                           ssl_options=pika.SSLOptions(
                                               context, 'tls.example'),
                                           socket_timeout=None,
                                           stack_timeout=None,
                                           retry_delay=0)

        _result, _workflow = run(io, [config])

        self.assertEqual(1, len(io.transports))
        self.assertIs(context, io.transports[0]['ssl_context'])
        self.assertEqual('tls.example', io.transports[0]['server_hostname'])


class ConnectorStateTests(unittest.TestCase):
    """A refused candidate leaves the connector clean and re-raisable."""

    def test_start_twice_after_a_refusal_is_the_wrong_state(self):
        io = _FakeIO({'unknown.example': [addr('192.0.2.9')]})
        connector = connection_workflow.AMQPConnector(lambda _params: object(),
                                                      io)
        results = []
        config = params(
            'unknown.example', {
                '*.internal.example':
                    pika.TLSVerificationRule(ssl.create_default_context(), 'x')
            })
        connector.start(addr('192.0.2.9'), config, results.append)
        self.assertEqual(1, len(results))
        with self.assertRaises(connection_workflow.AMQPConnectorWrongState):
            connector.start(addr('192.0.2.9'), config, results.append)

    def test_a_refused_connector_can_be_cleaned_up(self):
        io = _FakeIO({'unknown.example': [addr('192.0.2.9')]})
        connector = connection_workflow.AMQPConnector(lambda _params: object(),
                                                      io)
        config = params(
            'unknown.example', {
                '*.internal.example':
                    pika.TLSVerificationRule(ssl.create_default_context(), 'x')
            })
        connector.start(addr('192.0.2.9'), config, lambda _result: None)
        # _close is what the workflow calls after reporting completion.
        connector._close()
        self.assertIsNone(connector._on_done)


class UncoveredCandidateTests(unittest.TestCase):
    """A candidate no template covers is refused before any socket is opened."""

    def setUp(self):
        self.context = ssl.create_default_context()
        self.rule = pika.TLSVerificationRule(self.context,
                                             'lb.internal.example')
        self.rules = {'*.internal.example': self.rule}

    def test_it_reports_the_reason_without_creating_a_socket(self):
        io = _FakeIO({'unknown.example': [addr('192.0.2.9')]})

        result, workflow = run(io, [params('unknown.example', self.rules)])

        self.assertEqual([], io.connected)
        self.assertEqual([], io.transports)
        self.assertEqual([], io.sockets)
        self.assertIsInstance(result,
                              connection_workflow.AMQPConnectionWorkflowFailed)
        self.assertEqual(1, len(result.exceptions))
        rejection = result.exceptions[0]
        self.assertIsInstance(
            rejection,
            connection_workflow.AMQPConnectorCandidateNotCoveredError)
        self.assertIsInstance(rejection.exception,
                              CandidateNotCoveredByTLSRuleError)
        self.assertEqual('192.0.2.9', rejection.address)
        self.assertIn("resolved '192.0.2.9'", repr(rejection.exception))
        self.assertIn("'*.internal.example'", repr(rejection.exception))
        self.assertEqual((rejection,), workflow.candidate_rejections)

    def test_a_covered_fallback_still_connects_and_keeps_the_rejection(self):
        io = _FakeIO({
            'unknown.example': [addr('192.0.2.9')],
            '10.20.3.4': [addr('10.20.3.4')],
        })
        good = params(
            '10.20.3.4',
            {'10.20.3.4': pika.TLSVerificationRule(self.context, 'by-ip')})
        io.handshakes = {'by-ip': lambda: None}

        result, workflow = run(io,
                               [params('unknown.example', self.rules), good])

        self.assertEqual([('10.20.3.4', 5671)], io.connected)
        self.assertEqual('by-ip', io.transports[0]['server_hostname'])
        # The fake protocol reports success, so the connector completes with it.
        self.assertNotIsInstance(result, BaseException)
        self.assertEqual(1, len(workflow.candidate_rejections))
        self.assertEqual('192.0.2.9', workflow.candidate_rejections[0].address)

    def test_every_candidate_is_reported_when_none_match(self):
        io = _FakeIO({
            'a.example': [addr('192.0.2.1'),
                          addr('192.0.2.2')],
            'b.example': [addr('192.0.2.3')],
        })

        result, workflow = run(io, [
            params('a.example', self.rules),
            params('b.example', self.rules),
        ])

        self.assertEqual([], io.connected)
        self.assertIsInstance(result,
                              connection_workflow.AMQPConnectionWorkflowFailed)
        self.assertEqual(['192.0.2.1', '192.0.2.2', '192.0.2.3'],
                         [rejection.address for rejection in result.exceptions])
        self.assertEqual(3, len(workflow.candidate_rejections))
        for rejection in result.exceptions:
            self.assertIn('no tls_rules template covers candidate',
                          rejection.exception.reason)

    def test_an_invalid_template_is_refused_when_the_rules_are_assigned(self):
        with self.assertRaises(ValueError):
            pika.ConnectionParameters(tls_rules={'*.example/path': self.rule})


class BlockingErrorTests(unittest.TestCase):
    """The blocking adapter surfaces the refusal, not the workflow wrapper."""

    def test_it_reaps_the_reason_for_an_uncovered_candidate(self):
        inner = CandidateNotCoveredByTLSRuleError(
            "no tls_rules template covers candidate 'unknown.example' "
            "(resolved '192.0.2.9') on port 5671",
            host='unknown.example',
            port=5671)
        wrapper = connection_workflow.AMQPConnectorCandidateNotCoveredError(
            inner, host='unknown.example', port=5671, address='192.0.2.9')
        workflow_error = connection_workflow.AMQPConnectionWorkflowFailed(
            [wrapper])

        reaped = blocking_connection.BlockingConnection._reap_last_connection_workflow_error(
            workflow_error)

        self.assertIs(inner, reaped)
        self.assertIn("resolved '192.0.2.9'", repr(reaped))
        self.assertIn("address='192.0.2.9'", repr(wrapper))


if __name__ == '__main__':
    unittest.main()
