"""
Diagnostics for what ``LogEntry.remote_addr`` / ``remote_port`` can prove.

Every case goes through the real ``AuditlogMiddleware`` and a real ``LogEntry``
write, so the assertions describe stored audit rows rather than helper output.
No request carries an authenticated identity: actor is ``None`` throughout.
"""

from django.contrib.auth.models import AnonymousUser
from django.db import IntegrityError
from django.test import RequestFactory, TestCase, TransactionTestCase, override_settings
from test_app.models import SimpleModel

from auditlog import get_logentry_model
from auditlog.middleware import AuditlogMiddleware


class RemoteIdentityTest(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def log_entry(self, *, remote_addr=None, headers=None):
        def response(request):
            return SimpleModel.objects.create(text="probe").history.first()

        middleware = AuditlogMiddleware(get_response=response)
        request = self.factory.get("/", **(headers or {}), REMOTE_ADDR=remote_addr)
        request.user = AnonymousUser()
        return middleware(request)

    def test_direct_connection_without_forwarding_headers(self):
        entry = self.log_entry(remote_addr="203.0.113.9")
        self.assertEqual(entry.remote_addr, "203.0.113.9")
        self.assertIsNone(entry.remote_port)
        self.assertIsNone(entry.actor)

    def test_client_supplied_forwarded_header_overrides_socket_peer(self):
        """A direct client can choose the value that ends up in the audit row."""
        entry = self.log_entry(
            remote_addr="203.0.113.9",
            headers={"HTTP_X_FORWARDED_FOR": "198.51.100.7"},
        )
        self.assertEqual(entry.remote_addr, "198.51.100.7")

    def test_two_hop_chain_keeps_leftmost_value_and_forwarded_port(self):
        entry = self.log_entry(
            remote_addr="10.0.0.5",
            headers={
                "HTTP_X_FORWARDED_FOR": "203.0.113.9, 10.0.0.5",
                "HTTP_X_FORWARDED_PORT": "51234",
            },
        )
        self.assertEqual(entry.remote_addr, "203.0.113.9")
        self.assertEqual(entry.remote_port, 51234)

    def test_client_prefix_shadows_the_real_client(self):
        """Extra hops in the header shift the leftmost value to attacker input."""
        entry = self.log_entry(
            remote_addr="10.0.0.5",
            headers={"HTTP_X_FORWARDED_FOR": "1.2.3.4, 203.0.113.9, 10.0.0.5"},
        )
        self.assertEqual(entry.remote_addr, "1.2.3.4")

    def test_port_header_without_forwarded_for_is_still_trusted(self):
        entry = self.log_entry(
            remote_addr="10.0.0.5",
            headers={"HTTP_X_FORWARDED_PORT": "51234"},
        )
        self.assertEqual(entry.remote_addr, "10.0.0.5")
        self.assertEqual(entry.remote_port, 51234)

    def test_missing_port_header_leaves_port_empty(self):
        entry = self.log_entry(
            remote_addr="10.0.0.5",
            headers={"HTTP_X_FORWARDED_FOR": "203.0.113.9, 10.0.0.5"},
        )
        self.assertIsNone(entry.remote_port)

    def test_non_numeric_port_header_is_discarded(self):
        entry = self.log_entry(
            remote_addr="10.0.0.5",
            headers={
                "HTTP_X_FORWARDED_FOR": "203.0.113.9",
                "HTTP_X_FORWARDED_PORT": "not-a-port",
            },
        )
        self.assertIsNone(entry.remote_port)

    def test_disable_remote_addr_still_records_the_forwarded_port(self):
        with override_settings(AUDITLOG_DISABLE_REMOTE_ADDR=True):
            entry = self.log_entry(
                remote_addr="10.0.0.5",
                headers={
                    "HTTP_X_FORWARDED_FOR": "203.0.113.9",
                    "HTTP_X_FORWARDED_PORT": "51234",
                },
            )
        self.assertIsNone(entry.remote_addr)
        self.assertEqual(entry.remote_port, 51234)


class NegativeRemotePortTest(TransactionTestCase):
    """A negative forwarded port fails the audit write after the model save."""

    def test_negative_port_leaves_the_change_unaudited(self):
        middleware = AuditlogMiddleware(
            get_response=lambda request: SimpleModel.objects.create(
                text="negative-port"
            )
        )
        request = RequestFactory().get(
            "/",
            HTTP_X_FORWARDED_FOR="203.0.113.9",
            HTTP_X_FORWARDED_PORT="-1",
            REMOTE_ADDR="10.0.0.5",
        )
        request.user = AnonymousUser()

        with self.assertRaises(IntegrityError):
            middleware(request)

        self.assertEqual(SimpleModel.objects.filter(text="negative-port").count(), 1)
        self.assertEqual(
            get_logentry_model().objects.filter(object_repr="negative-port").count(), 0
        )
