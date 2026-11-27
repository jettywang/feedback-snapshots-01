import unittest
from wsgiref.util import setup_testing_defaults

from prometheus_client.parser import text_string_to_metric_families

from regional_gateway import (
    REASON_INCOMPATIBLE_BUCKETS,
    REASON_UNDECLARED_GAUGE,
    build_demo_registry,
    make_internal_app,
    make_public_app,
)


def scrape(app, path='/metrics'):
    environ = {}
    setup_testing_defaults(environ)
    environ['REQUEST_METHOD'] = 'GET'
    environ['PATH_INFO'] = path
    captured = {}

    def start_response(status, headers):
        captured['status'] = status
        captured['headers'] = dict(headers)

    body = b''.join(app(environ, start_response)).decode('utf-8')
    return captured['status'], captured['headers'], body


def parse(body):
    return {f.name: f for f in text_string_to_metric_families(body)}


def sample_value(family, name, **labels):
    for s in family.samples:
        if s.name == name and all(s.labels.get(k) == v for k, v in labels.items()):
            return s.value
    raise AssertionError('sample {} not found in {}'.format(name, family.samples))


def data_line_count(families):
    return sum(len(f.samples) for name, f in families.items()
               if not name.startswith('regional_gateway_'))


class RegionalGatewayTest(unittest.TestCase):
    def setUp(self):
        self.registry = build_demo_registry()
        self.internal_app = make_internal_app(self.registry)
        self.public_app = make_public_app(self.registry)

    def integrity(self, families, view):
        info = families['regional_gateway_scrape_info']
        digest = [s.labels['sha256'] for s in info.samples if s.labels['view'] == view]
        self.assertEqual(1, len(digest))

        def gauge(name, **labels):
            return sample_value(families[name], name, view=view, **labels)

        rejected = {
            s.labels['reason']: s.value
            for s in families['regional_gateway_scrape_rejected_series'].samples
            if s.labels['view'] == view
        }
        return {
            'digest': digest[0],
            'source': gauge('regional_gateway_scrape_source_series'),
            'emitted': gauge('regional_gateway_scrape_emitted_series'),
            'merged': gauge('regional_gateway_scrape_merged_series'),
            'rejected': rejected,
        }

    def test_internal_view_preserves_site_identity(self):
        status, headers, body = scrape(self.internal_app)
        self.assertEqual('200 OK', status)
        self.assertTrue(headers['Content-Type'].startswith('text/plain'))
        self.assertIn('site="site-a"', body)

        families = parse(body)
        latency = families['http_request_duration_seconds']
        self.assertEqual(3.0, sample_value(
            latency, 'http_request_duration_seconds_bucket',
            region='eu-west', site='site-a', le='0.1'))
        self.assertEqual(7.0, sample_value(
            families['site_firmware_version'], 'site_firmware_version',
            region='eu-west', site='site-b'))

        integrity = self.integrity(families, 'internal')
        self.assertEqual(integrity['source'], integrity['emitted'])
        self.assertEqual(0.0, integrity['merged'])
        self.assertEqual({}, integrity['rejected'])
        self.assertEqual(data_line_count(families), integrity['emitted'])

    def test_public_view_aggregates_regionally(self):
        status, _, body = scrape(self.public_app)
        self.assertEqual('200 OK', status)
        self.assertNotIn('site=', body)

        families = parse(body)
        latency = families['http_request_duration_seconds']
        # Homogeneous histograms: buckets, count and sum add up per region.
        self.assertEqual(4.0, sample_value(
            latency, 'http_request_duration_seconds_bucket', region='eu-west', le='0.1'))
        self.assertEqual(12.0, sample_value(
            latency, 'http_request_duration_seconds_bucket', region='eu-west', le='0.5'))
        self.assertEqual(17.0, sample_value(
            latency, 'http_request_duration_seconds_bucket', region='eu-west', le='+Inf'))
        self.assertEqual(17.0, sample_value(
            latency, 'http_request_duration_seconds_count', region='eu-west'))
        self.assertAlmostEqual(5.5, sample_value(
            latency, 'http_request_duration_seconds_sum', region='eu-west'))
        # A single-site region passes through with its boundaries intact.
        self.assertEqual(2.0, sample_value(
            latency, 'http_request_duration_seconds_bucket', region='ap-south', le='0.1'))
        self.assertEqual(4.0, sample_value(
            latency, 'http_request_duration_seconds_count', region='ap-south'))
        # Gauge with a declared rule aggregates.
        self.assertEqual(200.0, sample_value(
            families['site_power_draw_watts'], 'site_power_draw_watts', region='eu-west'))

    def test_public_view_rejects_unmergeable_groups(self):
        _, _, body = scrape(self.public_app)
        families = parse(body)
        # Bucket boundary only one site enabled: the whole group is refused.
        self.assertNotIn('http_response_size_bytes', families)
        # Same value from different sources, no declared rule: refused too.
        self.assertNotIn('site_firmware_version', families)

        integrity = self.integrity(families, 'public')
        self.assertEqual(9.0, integrity['rejected'][REASON_INCOMPATIBLE_BUCKETS])
        self.assertEqual(2.0, integrity['rejected'][REASON_UNDECLARED_GAUGE])

    def test_interleaved_scrapes_keep_series_integrity(self):
        _, _, internal_body_1 = scrape(self.internal_app)
        _, _, public_body_1 = scrape(self.public_app)
        _, _, internal_body_2 = scrape(self.internal_app)
        _, _, public_body_2 = scrape(self.public_app)

        internal_1 = self.integrity(parse(internal_body_1), 'internal')
        public_1 = self.integrity(parse(public_body_1), 'public')
        internal_2 = self.integrity(parse(internal_body_2), 'internal')
        public_2 = self.integrity(parse(public_body_2), 'public')

        # Repeated scrapes of the same view are reproducible.
        self.assertEqual(internal_1['digest'], internal_2['digest'])
        self.assertEqual(public_1['digest'], public_2['digest'])
        # The two views are distinct representations of the same registry.
        self.assertNotEqual(internal_1['digest'], public_1['digest'])
        self.assertEqual(internal_1['source'], public_1['source'])

        # Nothing vanished silently: source == emitted + merged + rejected.
        self.assertEqual(
            public_1['source'],
            public_1['emitted'] + public_1['merged'] + sum(public_1['rejected'].values()))
        # The emitted count matches the actual data lines in the body.
        self.assertEqual(data_line_count(parse(public_body_1)), public_1['emitted'])
        self.assertEqual(data_line_count(parse(internal_body_1)), internal_1['emitted'])


if __name__ == '__main__':
    unittest.main()
