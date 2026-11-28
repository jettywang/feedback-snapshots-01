"""Behavioural tests for parsing, wrapper neutrality and overlap verdicts."""

from __future__ import annotations

import unittest

from endpoint_audit.extensions import DiscloserRegistry, Disclosure
from endpoint_audit.model import Family, HostKind, Verdict
from endpoint_audit.overlap import audit_pairs, group_pairs
from endpoint_audit.parser import parse_endpoint
from endpoint_audit.model import SourceCoordinate


def coord(service: str, line: int = 1) -> SourceCoordinate:
    return SourceCoordinate(source="test.manifest", line=line, service=service)


def parse(text: str, service: str = "svc", registry=None):
    return parse_endpoint(text, coord(service), registry)


class RangeDerivationTests(unittest.TestCase):
    def test_wildcard_tcp_defaults_to_ipv4_any(self):
        entry = parse("tcp:8080", "edge")
        rng = entry.ranges[0]
        self.assertEqual(rng.family, Family.INET4)
        self.assertEqual(rng.host.kind, HostKind.WILDCARD)
        self.assertEqual(rng.port, 8080)
        self.assertTrue(rng.certain)

    def test_tcp6_defaults_to_ipv6_any(self):
        entry = parse("tcp6:8080", "edge6")
        rng = entry.ranges[0]
        self.assertEqual(rng.family, Family.INET6)
        self.assertEqual(rng.host.kind, HostKind.WILDCARD)
        self.assertEqual(rng.host.value, "::")

    def test_explicit_narrow_ipv4_binding(self):
        entry = parse("tcp:8081:interface=127.0.0.1", "loop")
        rng = entry.ranges[0]
        self.assertEqual(rng.host.kind, HostKind.ADDRESS)
        self.assertEqual(rng.host.value, "127.0.0.1")
        self.assertEqual(rng.family, Family.INET4)

    def test_wrappers_share_the_wrapped_range(self):
        plain = parse("tcp:8080", "plain")
        ssl_wrapped = parse(
            "ssl:8080:privateKey=k.pem:certKey=c.pem", "ssl-svc"
        )
        haproxy_ssl = parse(
            "haproxy:ssl:8080:privateKey=k.pem:certKey=c.pem", "proxy-svc"
        )
        # tls wraps TCP6ServerEndpoint, so its default family is inet6.
        tls_wrapped = parse("tls:/etc/sni:8080", "tls-svc")
        tls_plain = parse("tcp6:8080", "tls-baseline")
        for wrapped in (ssl_wrapped, haproxy_ssl):
            self.assertEqual(
                wrapped.ranges[0].to_dict(), plain.ranges[0].to_dict()
            )
        self.assertEqual(
            tls_wrapped.ranges[0].to_dict(), tls_plain.ranges[0].to_dict()
        )
        self.assertEqual(haproxy_ssl.layers, ("haproxy", "ssl"))
        self.assertIn("tls", tls_wrapped.layers)

    def test_certificate_options_do_not_affect_the_range(self):
        first = parse("ssl:443:privateKey=a.pem:certKey=a.crt", "a")
        second = parse(
            "ssl:443:privateKey=totally-different.pem:certKey=b.crt:"
            "extraCertChain=chain.pem:dhParameters=dh.pem",
            "b",
        )
        self.assertEqual(first.ranges, second.ranges)

    def test_hostname_interface_keeps_uncertainty(self):
        entry = parse("tcp:8443:interface=internal.example.com", "named")
        rng = entry.ranges[0]
        self.assertFalse(rng.certain)
        self.assertEqual(rng.host.kind, HostKind.NAME)
        self.assertEqual(rng.family, Family.UNKNOWN)

    def test_port_zero_is_runtime_ephemeral(self):
        entry = parse("tcp:0", "ephemeral")
        rng = entry.ranges[0]
        self.assertFalse(rng.certain)
        self.assertEqual(rng.port, 0)

    def test_family_mismatch_is_flagged_and_scheme_family_wins(self):
        # Colons inside an IPv6 literal must be escaped in strports syntax.
        entry = parse("tcp:80:interface=\\:\\:1", "mismatch")
        rng = entry.ranges[0]
        self.assertEqual(rng.host.value, "::1")
        self.assertEqual(rng.family, Family.INET4)
        self.assertTrue(
            any(issue.code == "FAMILY_MISMATCH" for issue in entry.issues)
        )

    def test_unix_socket_range(self):
        entry = parse("unix:/var/run/app.sock:mode=660", "sock")
        rng = entry.ranges[0]
        self.assertEqual(rng.family, Family.UNIX)
        self.assertEqual(rng.path, "/var/run/app.sock")

    def test_unknown_scheme_is_uncertain_without_extension(self):
        entry = parse("runtimeprobe:pool=a", "probe")
        rng = entry.ranges[0]
        self.assertEqual(rng.family, Family.UNKNOWN)
        self.assertFalse(rng.certain)
        self.assertTrue(
            any(issue.code == "UNKNOWN_SCHEME" for issue in entry.issues)
        )

    def test_extension_may_voluntarily_disclose(self):
        registry = DiscloserRegistry()

        def disclose(args, kwargs):
            return Disclosure(
                family=Family.INET4,
                host=__import__(
                    "endpoint_audit.extensions", fromlist=["ip_host"]
                ).ip_host("127.0.0.1"),
                port=int(kwargs["port"]),
            )

        registry.register("metricsd", disclose)
        entry = parse("metricsd:port=9100", "metrics", registry)
        rng = entry.ranges[0]
        self.assertEqual(rng.family, Family.INET4)
        self.assertEqual(rng.port, 9100)
        self.assertTrue(rng.certain)

    def test_malformed_port_keeps_coordinate_and_does_not_raise(self):
        entry = parse("tcp:not-a-port", "broken", )
        self.assertTrue(entry.has_fatal_issue)
        self.assertEqual(entry.coordinate.service, "broken")
        self.assertEqual(entry.coordinate.line, 1)
        self.assertEqual(entry.ranges, [])

    def test_trailing_backslash_is_a_grammar_error_with_coordinate(self):
        entry = parse("tcp:80\\", "escape")
        self.assertTrue(
            any(issue.code == "FATAL_GRAMMAR" for issue in entry.issues)
        )
        self.assertEqual(entry.coordinate.service, "escape")


class OverlapBucketTests(unittest.TestCase):
    def _group(self, items):
        entries = [parse(text, name) for name, text in items]
        return group_pairs(audit_pairs(entries))

    def test_confirmed_overlap_wildcard_and_wrapped(self):
        groups = self._group([
            ("edge", "tcp:8080"),
            ("edge-proxied", "haproxy:ssl:8080:privateKey=k.pem:certKey=c.pem"),
        ])
        self.assertEqual(len(groups[Verdict.OVERLAP]), 1)
        self.assertEqual(groups[Verdict.SEPARATE], [])
        self.assertEqual(groups[Verdict.UNKNOWN], [])

    def test_confirmed_overlap_identical_concrete_bindings(self):
        groups = self._group([
            ("a", "tcp:9000:interface=127.0.0.1"),
            ("b", "tcp:9000:interface=127.0.0.1"),
        ])
        self.assertEqual(len(groups[Verdict.OVERLAP]), 1)

    def test_confirmed_separate_by_port(self):
        groups = self._group([
            ("a", "tcp:9000:interface=127.0.0.1"),
            ("b", "tcp:9100:interface=127.0.0.1"),
        ])
        self.assertEqual(len(groups[Verdict.SEPARATE]), 1)

    def test_confirmed_separate_by_concrete_address_same_port(self):
        groups = self._group([
            ("a", "tcp:9000:interface=127.0.0.1"),
            ("b", "tcp:9000:interface=127.0.0.2"),
        ])
        self.assertEqual(len(groups[Verdict.SEPARATE]), 1)

    def test_wildcard_contains_narrow_address(self):
        groups = self._group([
            ("wide", "tcp:9000"),
            ("narrow", "tcp:9000:interface=127.0.0.1"),
        ])
        self.assertEqual(len(groups[Verdict.OVERLAP]), 1)

    def test_dual_stack_family_ambiguity_stays_uncertain(self):
        groups = self._group([
            ("v4", "tcp:8080"),
            ("v6", "tcp6:8080"),
        ])
        self.assertEqual(len(groups[Verdict.UNKNOWN]), 1)
        self.assertEqual(groups[Verdict.OVERLAP], [])

    def test_concrete_cross_family_schemes_stay_uncertain(self):
        # The schemes declare different families, but whether the two
        # literals can collide at runtime also depends on dual-stack config;
        # family ambiguity is preserved rather than asserted as disjoint.
        groups = self._group([
            ("v4", "tcp:8080:interface=127.0.0.1"),
            ("v6", "tcp6:8080:interface=\\:\\:1"),
        ])
        self.assertEqual(len(groups[Verdict.UNKNOWN]), 1)
        self.assertEqual(groups[Verdict.SEPARATE], [])

    def test_runtime_only_scheme_goes_to_uncertain(self):
        groups = self._group([
            ("probe", "runtimeprobe:x"),
            ("tcp", "tcp:80"),
        ])
        self.assertEqual(len(groups[Verdict.UNKNOWN]), 1)

    def test_unix_sockets_compare_by_path(self):
        groups = self._group([
            ("a", "unix:/tmp/a.sock"),
            ("b", "unix:/tmp/b.sock"),
            ("c", "unix:/tmp/a.sock"),
        ])
        self.assertEqual(len(groups[Verdict.SEPARATE]), 2)
        self.assertEqual(len(groups[Verdict.OVERLAP]), 1)

    def test_unix_and_ip_are_always_separate(self):
        groups = self._group([
            ("sock", "unix:/tmp/a.sock"),
            ("net", "tcp:80"),
        ])
        self.assertEqual(len(groups[Verdict.SEPARATE]), 1)


if __name__ == "__main__":
    unittest.main()
