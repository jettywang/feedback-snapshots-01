"""Cross-check static ranges against real Twisted endpoint objects.

Twisted endpoint *constructors* only store their arguments; only C{listen()}
touches the reactor and the C{ssl}/C{tls} string parsers touch key files.
These tests therefore construct endpoint objects directly (never parsing ssl
strings and never calling listen) and compare their stored address fields
with the audit's static output.
"""

from __future__ import annotations

import unittest

from endpoint_audit.model import Family, HostKind
from endpoint_audit.parser import parse_endpoint
from endpoint_audit.model import SourceCoordinate

try:
    from twisted.internet.endpoints import (
        SSL4ServerEndpoint,
        TCP4ServerEndpoint,
        TCP6ServerEndpoint,
        _TLSServerEndpoint,
        _WrapperServerEndpoint,
    )

    TWISTED_AVAILABLE = True
except ImportError:  # pragma: no cover
    TWISTED_AVAILABLE = False


def parse(text):
    return parse_endpoint(
        text, SourceCoordinate(source="xcheck", line=1, service="x")
    )


@unittest.skipUnless(TWISTED_AVAILABLE, "Twisted not installed")
class TwistedSemanticsCrossCheckTests(unittest.TestCase):
    def test_tcp4_wildcard_matches_constructor(self):
        endpoint = TCP4ServerEndpoint(None, 8080)
        entry = parse("tcp:8080")
        rng = entry.ranges[0]
        self.assertEqual(rng.port, endpoint._port)
        self.assertEqual(rng.host.value or "", endpoint._interface)
        self.assertEqual(rng.family, Family.INET4)

    def test_tcp4_explicit_interface_matches_constructor(self):
        endpoint = TCP4ServerEndpoint(None, 8081, interface="127.0.0.1")
        entry = parse("tcp:8081:interface=127.0.0.1")
        rng = entry.ranges[0]
        self.assertEqual(rng.port, endpoint._port)
        self.assertEqual(rng.host.value, endpoint._interface)

    def test_tcp6_wildcard_matches_constructor(self):
        endpoint = TCP6ServerEndpoint(None, 8080)
        entry = parse("tcp6:8080")
        rng = entry.ranges[0]
        self.assertEqual(rng.port, endpoint._port)
        self.assertEqual(rng.host.value, endpoint._interface)
        self.assertEqual(rng.family, Family.INET6)

    def test_ssl_constructor_ignores_cert_options_for_address(self):
        endpoint = SSL4ServerEndpoint(None, 443, None)
        entry = parse(
            "ssl:443:privateKey=missing.pem:certKey=missing.crt"
        )
        rng = entry.ranges[0]
        self.assertEqual(rng.port, endpoint._port)
        self.assertEqual(rng.host.kind, HostKind.WILDCARD)

    def test_tls_wraps_a_tcp6_endpoint_with_matching_address(self):
        entry = parse("tls:/etc/sni:8443:interface=2001\\:db8\\:\\:1")
        rng = entry.ranges[0]
        expected = TCP6ServerEndpoint(None, 8443, interface="2001:db8::1")
        self.assertEqual(rng.port, expected._port)
        self.assertEqual(rng.host.value, expected._interface)
        self.assertEqual(rng.family, Family.INET6)
        # And the real wrapper type does indeed wrap a TCP6 endpoint.
        wrapped = _TLSServerEndpoint(expected, None, None)
        self.assertIsInstance(wrapped.endpoint, TCP6ServerEndpoint)

    def test_haproxy_wrapper_preserves_inner_endpoint_address(self):
        inner = TCP4ServerEndpoint(None, 8080)
        wrapper = _WrapperServerEndpoint(inner, object())
        entry = parse(
            "haproxy:tcp:8080:privateKey=ignored.pem"
        )
        rng = entry.ranges[0]
        self.assertEqual(rng.port, wrapper._wrappedEndpoint._port)
        self.assertEqual(entry.layers, ("haproxy",))


if __name__ == "__main__":
    unittest.main()
