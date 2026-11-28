"""Invariant tests: the audit must have no side effects.

These tests run the full audit pipeline with the socket and file-opening
primitives replaced by recorders.  Any attempt to bind, listen, resolve host
names or open files fails the test, proving the check is safe on a cold
review machine.
"""

from __future__ import annotations

import io
import socket
import unittest

from endpoint_audit.audit import audit_declarations
from endpoint_audit.extensions import DiscloserRegistry
from endpoint_audit.manifest import Declaration
from endpoint_audit.model import SourceCoordinate


def _declarations():
    descriptions = [
        "tcp:8080",
        "haproxy:ssl:8080:privateKey=/etc/ssl/edge.pem:certKey=/etc/ssl/edge.crt",
        "tcp:9000:interface=127.0.0.1",
        "tcp6:8080",
        "tcp:8443:interface=internal.example.com",
        "runtimeprobe:pool=a",
        "unix:/var/run/control.sock",
        "tcp:not-a-port",
    ]
    return [
        Declaration(
            service=f"svc-{index}",
            endpoint=description,
            coordinate=SourceCoordinate(source="mem", line=index + 1,
                                       service=f"svc-{index}"),
        )
        for index, description in enumerate(descriptions)
    ]


class NoSideEffectsTests(unittest.TestCase):
    def setUp(self):
        self.original_socket = socket.socket
        self.original_socketpair = socket.socketpair
        self.original_create_connection = socket.create_connection
        self.original_getaddrinfo = socket.getaddrinfo
        self.original_gethostbyname = socket.gethostbyname
        self.original_open = io.open
        self.original_listen = socket.socket.listen
        self.original_bind = socket.socket.bind

    def _fail(self, name):
        def blocker(*args, **kwargs):
            raise AssertionError(f"audit must not call {name}")
        return blocker

    def test_no_socket_or_file_side_effects(self):
        registry = DiscloserRegistry()
        declarations = _declarations()

        socket.socket = self._fail("socket.socket")  # type: ignore[assignment]
        socket.socketpair = self._fail("socket.socketpair")  # type: ignore[assignment]
        socket.create_connection = self._fail(  # type: ignore[assignment]
            "socket.create_connection"
        )
        socket.getaddrinfo = self._fail("socket.getaddrinfo")  # type: ignore[assignment]
        socket.gethostbyname = self._fail(  # type: ignore[assignment]
            "socket.gethostbyname"
        )
        socket.socket.listen = self._fail("listen")  # type: ignore[assignment]
        socket.socket.bind = self._fail("bind")  # type: ignore[assignment]
        io.open = self._fail("open")  # type: ignore[assignment]
        builtins_open = __builtins__["open"] if isinstance(__builtins__, dict) \
            else __builtins__.open
        if isinstance(__builtins__, dict):
            __builtins__["open"] = self._fail("builtins.open")
        else:
            __builtins__.open = self._fail("builtins.open")
        try:
            result = audit_declarations(declarations, registry)
        finally:
            socket.socket = self.original_socket
            socket.socketpair = self.original_socketpair
            socket.create_connection = self.original_create_connection
            socket.getaddrinfo = self.original_getaddrinfo
            socket.gethostbyname = self.original_gethostbyname
            socket.socket.listen = self.original_listen
            socket.socket.bind = self.original_bind
            io.open = self.original_open
            if isinstance(__builtins__, dict):
                __builtins__["open"] = builtins_open
            else:
                __builtins__.open = builtins_open

        self.assertEqual(len(result.entries), len(declarations))
        # The malformed entry and the runtime-only scheme still produce data.
        self.assertTrue(result.parse_issues)

    def test_audit_modules_never_import_a_reactor(self):
        # The audit package itself must stay independent of any reactor so
        # that importing and running it cannot schedule a listener.
        import sys

        audit_modules = [
            name
            for name in sys.modules
            if name == "endpoint_audit" or name.startswith("endpoint_audit.")
        ]
        self.assertTrue(audit_modules)
        for name in audit_modules:
            module = sys.modules[name]
            self.assertFalse(
                hasattr(module, "reactor"),
                f"{name} must not hold a reactor reference",
            )
            self.assertNotIn("twisted.internet.reactor",
                             getattr(module, "__dict__", {}))


if __name__ == "__main__":
    unittest.main()
