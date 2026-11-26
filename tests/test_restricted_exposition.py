import asyncio
from typing import Dict, Optional, Set, Tuple
from unittest import TestCase
from wsgiref.util import setup_testing_defaults

from asgiref.testing import ApplicationCommunicator

from prometheus_client import CollectorRegistry, make_asgi_app, make_wsgi_app
from prometheus_client.metrics_core import CounterMetricFamily, GaugeMetricFamily


class DeclaredMultiCollector:
    """Collector that declares its two metric families via describe()."""

    def __init__(self):
        self.collect_calls = 0

    def describe(self):
        return [
            GaugeMetricFamily('declared_alpha', 'Alpha gauge'),
            GaugeMetricFamily('declared_beta', 'Beta gauge'),
        ]

    def collect(self):
        self.collect_calls += 1
        yield GaugeMetricFamily('declared_alpha', 'Alpha gauge', value=1)
        yield GaugeMetricFamily('declared_beta', 'Beta gauge', value=2)


class UndeclaredCounterCollector:
    """Counter collector without describe(); its families are only known at collect time."""

    def __init__(self):
        self.collect_calls = 0

    def collect(self):
        self.collect_calls += 1
        yield CounterMetricFamily('undeclared', 'Undeclared counter', value=3)


def metric_family_names(body: bytes) -> Set[str]:
    """Extract the metric family names from a text or OpenMetrics payload."""
    return {
        line.split()[2]
        for line in body.decode('utf-8').splitlines()
        if line.startswith('# TYPE ')
    }


class RestrictedExpositionTestCase(TestCase):
    """Shared scenarios for restricted scrapes, run against WSGI and ASGI apps."""

    # Subclasses provide these.
    TEXT_ACCEPT: Optional[str] = None
    OPENMETRICS_ACCEPT = 'application/openmetrics-text; version=1.0.0'

    def setUp(self):
        self.registry = CollectorRegistry(support_collectors_without_names=True)
        self.declared = DeclaredMultiCollector()
        self.undeclared = UndeclaredCounterCollector()
        self.registry.register(self.declared)
        self.registry.register(self.undeclared)

    def request(self, app, accept: Optional[str] = None, query: str = '') -> Tuple[str, Dict[str, str], bytes]:
        raise NotImplementedError

    def make_app(self, **kwargs):
        raise NotImplementedError

    def expected_family(self, name: str, accept: Optional[str]) -> str:
        # The plain text format munges counters to <name>_total.
        if accept == self.OPENMETRICS_ACCEPT:
            return name
        return {'undeclared': 'undeclared_total'}.get(name, name)

    def expected_families(self, names, accept):
        return {self.expected_family(name, accept) for name in names}

    def check_content_type(self, headers, accept):
        expected = 'application/openmetrics-text' if accept == self.OPENMETRICS_ACCEPT else 'text/plain'
        self.assertTrue(headers['Content-Type'].startswith(expected))

    def check_restricted_no_trigger(self, accept):
        app = self.make_app(
            permitted_names=['declared_alpha', 'undeclared_total'],
            allow_unnamed_collectors=False,
        )
        status, headers, body = self.request(app, accept=accept)
        self.assertEqual('200 OK', status)
        self.check_content_type(headers, accept)
        # The undeclared collector must not be triggered to probe its scope.
        self.assertEqual(0, self.undeclared.collect_calls)
        # The declared collector runs exactly once.
        self.assertEqual(1, self.declared.collect_calls)
        self.assertEqual(
            self.expected_families(['declared_alpha'], accept),
            metric_family_names(body),
        )

    def check_restricted_trigger_allowed(self, accept):
        app = self.make_app(
            permitted_names=['declared_alpha', 'undeclared_total'],
            allow_unnamed_collectors=True,
        )
        status, headers, body = self.request(app, accept=accept)
        self.assertEqual('200 OK', status)
        self.check_content_type(headers, accept)
        # Each permitted collector runs exactly once.
        self.assertEqual(1, self.declared.collect_calls)
        self.assertEqual(1, self.undeclared.collect_calls)
        # Output is intersected with the permitted names.
        self.assertEqual(
            self.expected_families(['declared_alpha', 'undeclared'], accept),
            metric_family_names(body),
        )

    def check_restricted_intersects_name_filter(self, accept):
        app = self.make_app(
            permitted_names=['declared_alpha', 'declared_beta'],
            allow_unnamed_collectors=True,
        )
        status, headers, body = self.request(app, accept=accept, query='name[]=declared_beta')
        self.assertEqual('200 OK', status)
        self.check_content_type(headers, accept)
        self.assertEqual(1, self.declared.collect_calls)
        # The undeclared collector's output is not in the permitted names.
        self.assertEqual(1, self.undeclared.collect_calls)
        self.assertEqual(
            self.expected_families(['declared_beta'], accept),
            metric_family_names(body),
        )

    def check_unrestricted(self, accept):
        app = self.make_app()
        status, headers, body = self.request(app, accept=accept)
        self.assertEqual('200 OK', status)
        self.check_content_type(headers, accept)
        self.assertEqual(1, self.declared.collect_calls)
        self.assertEqual(1, self.undeclared.collect_calls)
        self.assertEqual(
            self.expected_families(['declared_alpha', 'declared_beta', 'undeclared'], accept),
            metric_family_names(body),
        )


class RestrictedWSGITest(RestrictedExpositionTestCase):
    def make_app(self, **kwargs):
        return make_wsgi_app(self.registry, **kwargs)

    def request(self, app, accept=None, query=''):
        environ = {}
        setup_testing_defaults(environ)
        environ['QUERY_STRING'] = query
        if accept:
            environ['HTTP_ACCEPT'] = accept
        captured = {}

        def start_response(status, headers):
            captured['status'] = status
            captured['headers'] = dict(headers)

        body = b''.join(app(environ, start_response))
        return captured['status'], captured['headers'], body

    def test_text_restricted_no_trigger(self):
        self.check_restricted_no_trigger(self.TEXT_ACCEPT)

    def test_text_restricted_trigger_allowed(self):
        self.check_restricted_trigger_allowed(self.TEXT_ACCEPT)

    def test_text_restricted_intersects_name_filter(self):
        self.check_restricted_intersects_name_filter(self.TEXT_ACCEPT)

    def test_text_unrestricted(self):
        self.check_unrestricted(self.TEXT_ACCEPT)

    def test_openmetrics_restricted_no_trigger(self):
        self.check_restricted_no_trigger(self.OPENMETRICS_ACCEPT)

    def test_openmetrics_restricted_trigger_allowed(self):
        self.check_restricted_trigger_allowed(self.OPENMETRICS_ACCEPT)

    def test_openmetrics_restricted_intersects_name_filter(self):
        self.check_restricted_intersects_name_filter(self.OPENMETRICS_ACCEPT)

    def test_openmetrics_unrestricted(self):
        self.check_unrestricted(self.OPENMETRICS_ACCEPT)


class RestrictedASGITest(RestrictedExpositionTestCase):
    def setUp(self):
        super().setUp()
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.close()

    def make_app(self, **kwargs):
        return make_asgi_app(self.registry, **kwargs)

    def request(self, app, accept=None, query=''):
        headers = [(b'accept', accept.encode('utf-8'))] if accept else []
        scope = {
            'type': 'http',
            'http_version': '1.0',
            'method': 'GET',
            'path': '/metrics',
            'query_string': query.encode('utf-8'),
            'headers': headers,
            'client': ('127.0.0.1', 32767),
            'server': ('127.0.0.1', 80),
            'scheme': 'http',
        }

        async def run():
            communicator = ApplicationCommunicator(app, scope)
            await communicator.send_input({'type': 'http.request', 'body': b''})
            response_start = await communicator.receive_output(1)
            response_body = await communicator.receive_output(1)
            await communicator.wait()
            return response_start, response_body

        response_start, response_body = self.loop.run_until_complete(run())
        status = '{} {}'.format(response_start['status'], 'OK')
        headers_out = {
            name.decode('utf-8'): value.decode('utf-8')
            for name, value in response_start['headers']
        }
        return status, headers_out, response_body['body']

    def test_text_restricted_no_trigger(self):
        self.check_restricted_no_trigger(self.TEXT_ACCEPT)

    def test_text_restricted_trigger_allowed(self):
        self.check_restricted_trigger_allowed(self.TEXT_ACCEPT)

    def test_text_restricted_intersects_name_filter(self):
        self.check_restricted_intersects_name_filter(self.TEXT_ACCEPT)

    def test_text_unrestricted(self):
        self.check_unrestricted(self.TEXT_ACCEPT)

    def test_openmetrics_restricted_no_trigger(self):
        self.check_restricted_no_trigger(self.OPENMETRICS_ACCEPT)

    def test_openmetrics_restricted_trigger_allowed(self):
        self.check_restricted_trigger_allowed(self.OPENMETRICS_ACCEPT)

    def test_openmetrics_restricted_intersects_name_filter(self):
        self.check_restricted_intersects_name_filter(self.OPENMETRICS_ACCEPT)

    def test_openmetrics_unrestricted(self):
        self.check_unrestricted(self.OPENMETRICS_ACCEPT)
