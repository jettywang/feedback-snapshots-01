"""Test `pika.adapters.utils.connection_workflow.AMQPConnectionWorkflow` target
validation.
"""

import socket
import unittest

import pika.connection
from pika.adapters.utils import connection_workflow

_PORT = 5672


def _addr_record(ip):
    return (socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, _PORT))


class _FakeTaskRef:

    def cancel(self):
        pass


class _FakeIOServices:
    """Synchronous stand-in for `AbstractIOServices` that resolves hosts from
    a fixed table.
    """

    def __init__(self, addrinfos_by_host):
        self._addrinfos_by_host = addrinfos_by_host

    def call_later(self, delay, callback):
        callback()
        return _FakeTaskRef()

    def getaddrinfo(self, host, port, socktype, proto, on_done):
        on_done(list(self._addrinfos_by_host[host]))
        return _FakeTaskRef()


class _FakeConnector:
    """Stand-in for `AMQPConnector` that records the requested target and
    completes synchronously with a scripted outcome.
    """

    def __init__(self, attempted, outcomes):
        self._attempted = attempted
        self._outcomes = outcomes

    def start(self, addr_record, conn_params, on_done):
        target = addr_record[4][0]
        self._attempted.append(target)
        on_done(self._outcomes.get(target, _CONNECTION))


_CONNECTION = object()  # stands in for a connected pika.connection.Connection


class AMQPConnectionWorkflowTargetValidationTests(unittest.TestCase):

    def _run_workflow(self, addrinfos_by_host, validator, hosts,
                      outcomes=None):
        params_list = [
            pika.connection.ConnectionParameters(host=host,
                                                 port=_PORT,
                                                 connection_attempts=1,
                                                 retry_delay=0)
            for host in hosts
        ]
        attempted = []
        results = []

        def connector_factory():
            return _FakeConnector(attempted, outcomes or {})

        workflow = connection_workflow.AMQPConnectionWorkflow(
            target_validator=validator)
        workflow.set_io_services(_FakeIOServices(addrinfos_by_host))
        workflow.start(params_list,
                       connector_factory,
                       native_loop=None,
                       on_done=results.append)

        self.assertEqual(len(results), 1)
        return attempted, results[0]

    def test_only_permitted_target_is_attempted(self):
        verdicts = {
            '10.0.0.1': True,
            '10.0.0.2': None,  # ambiguous
            '192.168.9.9': False,  # denied
        }
        addrinfos = [_addr_record(ip) for ip in verdicts]

        attempted, result = self._run_workflow(
            {'broker.example.com': addrinfos},
            validator=lambda addr_record: verdicts[addr_record[4][0]],
            hosts=['broker.example.com'])

        self.assertEqual(attempted, ['10.0.0.1'])
        self.assertIs(result, _CONNECTION)

    def test_permitted_targets_keep_candidate_order(self):
        addrinfos = [
            _addr_record('10.0.0.1'),
            _addr_record('10.0.0.2'),
            _addr_record('10.0.0.3'),
        ]
        outcomes = {
            '10.0.0.1':
                connection_workflow.AMQPConnectorSocketConnectError(
                    socket.timeout('timed out'),
                    host='broker.example.com',
                    port=_PORT),
        }

        attempted, result = self._run_workflow(
            {'broker.example.com': addrinfos},
            validator=lambda addr_record: addr_record[4][0] != '10.0.0.2',
            hosts=['broker.example.com'],
            outcomes=outcomes)

        self.assertEqual(attempted, ['10.0.0.1', '10.0.0.3'])
        self.assertIs(result, _CONNECTION)

    def test_no_compliant_candidate_reports_readable_failure(self):
        addrinfos = [
            _addr_record('10.0.0.1'),
            _addr_record('192.168.9.9'),
        ]
        verdicts = {'10.0.0.1': None, '192.168.9.9': False}

        attempted, result = self._run_workflow(
            {'broker.example.com': addrinfos},
            validator=lambda addr_record: verdicts[addr_record[4][0]],
            hosts=['broker.example.com'])

        self.assertEqual(attempted, [])
        self.assertIsInstance(result,
                              connection_workflow.AMQPConnectionWorkflowFailed)
        self.assertEqual(len(result.exceptions), 2)
        for error in result.exceptions:
            self.assertIsInstance(
                error,
                connection_workflow.AMQPConnectionWorkflowTargetRejected)
        report = repr(result)
        self.assertIn('10.0.0.1', report)
        self.assertIn('192.168.9.9', report)
        self.assertIn('denied', report)
        self.assertIn('ambiguous', report)

    def test_validator_exception_rejects_target(self):
        addrinfos = [_addr_record('10.0.0.1')]

        def validator(addr_record):
            raise RuntimeError('policy backend unavailable')

        attempted, result = self._run_workflow(
            {'broker.example.com': addrinfos},
            validator=validator,
            hosts=['broker.example.com'])

        self.assertEqual(attempted, [])
        self.assertIsInstance(result,
                              connection_workflow.AMQPConnectionWorkflowFailed)
        self.assertIn('policy backend unavailable', repr(result))

    def test_boundary_applies_to_fallback_configs(self):
        addrinfos_by_host = {
            'broker1.example.com': [_addr_record('192.168.9.9')],
            'broker2.example.com': [_addr_record('10.0.0.1')],
        }

        attempted, result = self._run_workflow(
            addrinfos_by_host,
            validator=lambda addr_record: addr_record[4][0].startswith('10.'),
            hosts=['broker1.example.com', 'broker2.example.com'])

        self.assertEqual(attempted, ['10.0.0.1'])
        self.assertIs(result, _CONNECTION)

    def test_without_validator_all_candidates_are_attempted_in_order(self):
        addrinfos = [
            _addr_record('10.0.0.1'),
            _addr_record('192.168.9.9'),
        ]
        params = pika.connection.ConnectionParameters(
            host='broker.example.com',
            port=_PORT,
            connection_attempts=1,
            retry_delay=0)
        attempted = []
        results = []
        outcomes = {
            '10.0.0.1':
                connection_workflow.AMQPConnectorSocketConnectError(
                    socket.timeout('timed out'),
                    host='broker.example.com',
                    port=_PORT),
        }

        workflow = connection_workflow.AMQPConnectionWorkflow()
        workflow.set_io_services(
            _FakeIOServices({'broker.example.com': addrinfos}))
        workflow.start(
            [params],
            lambda: _FakeConnector(attempted, outcomes),
            native_loop=None,
            on_done=results.append)

        self.assertEqual(attempted, ['10.0.0.1', '192.168.9.9'])
        self.assertEqual(len(results), 1)
        self.assertIs(results[0], _CONNECTION)


if __name__ == '__main__':
    unittest.main()
