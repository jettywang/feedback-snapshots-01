"""
Tests for the PUSH_PROMISE admission callback and the ready-made
PushPromiseAdmissionPolicy.

These tests run a client and a server H2Connection against each other to
demonstrate that only admitted pushes produce consumable events: legitimate
same-origin pushes are delivered, cross-origin pushes are refused, and
promises that arrive after the parent stream has ended never create streams
the application can consume. Refused pushes cannot be reactivated by
subsequent HEADERS or DATA frames.
"""
from __future__ import annotations

import pytest

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.push
from h2.errors import ErrorCodes


REQUEST_HEADERS = [
    (":method", "GET"),
    (":scheme", "https"),
    (":authority", "example.com"),
    (":path", "/"),
]

RESPONSE_HEADERS = [
    (":status", "200"),
    ("content-length", "5"),
]


def pushed_request_headers(path, authority="example.com", scheme="https"):
    return [
        (":method", "GET"),
        (":scheme", scheme),
        (":authority", authority),
        (":path", path),
    ]


def connection_pair(admission_callback=None):
    """
    Create a connected client/server pair. The client is configured with the
    given PUSH_PROMISE admission callback.
    """
    client = h2.connection.H2Connection(
        config=h2.config.H2Configuration(
            client_side=True,
            header_encoding="utf-8",
            push_promise_admission_callback=admission_callback,
        ),
    )
    server = h2.connection.H2Connection(
        config=h2.config.H2Configuration(
            client_side=False,
            header_encoding="utf-8",
        ),
    )
    client.initiate_connection()
    server.initiate_connection()
    server.receive_data(client.data_to_send())
    client.receive_data(server.data_to_send())
    return client, server


def start_request(client, server, stream_id=1):
    client.send_headers(stream_id, REQUEST_HEADERS, end_stream=True)
    server.receive_data(client.data_to_send())


def events_of_type(events, event_type):
    return [event for event in events if isinstance(event, event_type)]


class TestPushPromiseAdmission:
    """
    Two-end tests demonstrating the admission callback behaviour.
    """

    def test_same_origin_push_is_admitted(self):
        """
        A push whose origin matches the parent request produces consumable
        events for the promised stream.
        """
        policy = h2.push.PushPromiseAdmissionPolicy()
        client, server = connection_pair(policy)
        start_request(client, server)

        server.push_stream(1, 2, pushed_request_headers("/style.css"))
        server.send_headers(2, RESPONSE_HEADERS)
        server.send_data(2, b"body!", end_stream=True)
        events = client.receive_data(server.data_to_send())

        push_events = events_of_type(events, h2.events.PushedStreamReceived)
        assert len(push_events) == 1
        assert push_events[0].pushed_stream_id == 2
        assert push_events[0].parent_stream_id == 1
        assert push_events[0].headers == pushed_request_headers("/style.css")

        response_events = events_of_type(events, h2.events.ResponseReceived)
        assert [event.stream_id for event in response_events] == [2]
        data_events = events_of_type(events, h2.events.DataReceived)
        assert [event.stream_id for event in data_events] == [2]
        assert data_events[0].data == b"body!"

    def test_cross_origin_push_is_refused_and_cannot_be_reactivated(self):
        """
        A cross-origin push produces no events, is reset with REFUSED_STREAM,
        and cannot be reactivated by HEADERS/DATA frames that were already in
        flight. The connection stays usable and HPACK state stays in sync.
        """
        policy = h2.push.PushPromiseAdmissionPolicy()
        client, server = connection_pair(policy)
        start_request(client, server)

        # The server pushes a cross-origin resource and, before it can see
        # any refusal, immediately sends the pushed response: those frames
        # are in flight when the client refuses the promise.
        server.push_stream(1, 2, pushed_request_headers("/tracker.js", authority="evil.example.net"))
        server.send_headers(2, RESPONSE_HEADERS)
        server.send_data(2, b"evil!", end_stream=False)
        events = client.receive_data(server.data_to_send())

        # Nothing on the promised stream is consumable.
        assert not events_of_type(events, h2.events.PushedStreamReceived)
        assert not events_of_type(events, h2.events.ResponseReceived)
        assert not events_of_type(events, h2.events.DataReceived)

        # The client promptly released the reserved stream: the server sees
        # its pushed stream reset.
        server_events = server.receive_data(client.data_to_send())
        reset_events = events_of_type(server_events, h2.events.StreamReset)
        assert [event.stream_id for event in reset_events] == [2]
        assert reset_events[0].error_code == ErrorCodes.REFUSED_STREAM

        # The connection is still usable: a same-origin push is admitted,
        # and the parent response decodes correctly, proving the HPACK
        # compression state was maintained across the refused push.
        server.push_stream(1, 4, pushed_request_headers("/app.js"))
        server.send_headers(1, RESPONSE_HEADERS, end_stream=True)
        events = client.receive_data(server.data_to_send())

        push_events = events_of_type(events, h2.events.PushedStreamReceived)
        assert [event.pushed_stream_id for event in push_events] == [4]
        response_events = events_of_type(events, h2.events.ResponseReceived)
        assert [event.stream_id for event in response_events] == [1]
        assert response_events[0].headers == RESPONSE_HEADERS

    def test_promise_after_parent_stream_reset_is_refused(self):
        """
        A PUSH_PROMISE that was in flight when the client reset the parent
        stream does not create a consumable push.
        """
        policy = h2.push.PushPromiseAdmissionPolicy()
        client, server = connection_pair(policy)
        start_request(client, server)

        # The client resets the parent stream, but the server's PUSH_PROMISE
        # is already in flight and arrives before the server sees the reset.
        client.reset_stream(1)
        server.push_stream(1, 2, pushed_request_headers("/late.css"))
        events = client.receive_data(server.data_to_send())

        assert not events_of_type(events, h2.events.PushedStreamReceived)

        server_events = server.receive_data(client.data_to_send())
        reset_events = events_of_type(server_events, h2.events.StreamReset)
        assert 2 in [event.stream_id for event in reset_events]

    def test_promise_after_parent_stream_ended_is_a_connection_error(self, frame_factory):
        """
        A PUSH_PROMISE received on a parent stream that ended naturally is a
        connection error of type PROTOCOL_ERROR, per RFC 9113 section 6.6.
        """
        policy = h2.push.PushPromiseAdmissionPolicy()
        client, server = connection_pair(policy)
        start_request(client, server)

        server.send_headers(1, RESPONSE_HEADERS, end_stream=True)
        events = client.receive_data(server.data_to_send())
        assert events_of_type(events, h2.events.StreamEnded)

        # The server can no longer push via the API, so the frame is crafted
        # directly: the promise arrives after the parent stream has ended.
        frame = frame_factory.build_push_promise_frame(
            stream_id=1,
            promised_stream_id=2,
            headers=pushed_request_headers("/too-late.css"),
            flags=["END_HEADERS"],
        )
        with pytest.raises(h2.exceptions.ProtocolError):
            client.receive_data(frame.serialize())

    def test_duplicate_promise_is_refused(self):
        """
        Promising the same resource twice only admits the first promise.
        """
        policy = h2.push.PushPromiseAdmissionPolicy()
        client, server = connection_pair(policy)
        start_request(client, server)

        server.push_stream(1, 2, pushed_request_headers("/dup.css"))
        server.push_stream(1, 4, pushed_request_headers("/dup.css"))
        events = client.receive_data(server.data_to_send())

        push_events = events_of_type(events, h2.events.PushedStreamReceived)
        assert [event.pushed_stream_id for event in push_events] == [2]

        server_events = server.receive_data(client.data_to_send())
        reset_events = events_of_type(server_events, h2.events.StreamReset)
        assert [event.stream_id for event in reset_events] == [4]
        assert reset_events[0].error_code == ErrorCodes.REFUSED_STREAM

    def test_resource_policy_rejection(self):
        """
        A caller-supplied resource policy can refuse same-origin resources.
        """
        policy = h2.push.PushPromiseAdmissionPolicy(
            resource_policy=lambda method, scheme, authority, path: path.endswith(".css"),
        )
        client, server = connection_pair(policy)
        start_request(client, server)

        server.push_stream(1, 2, pushed_request_headers("/style.css"))
        server.push_stream(1, 4, pushed_request_headers("/tracker.js"))
        events = client.receive_data(server.data_to_send())

        push_events = events_of_type(events, h2.events.PushedStreamReceived)
        assert [event.pushed_stream_id for event in push_events] == [2]

        server_events = server.receive_data(client.data_to_send())
        reset_events = events_of_type(server_events, h2.events.StreamReset)
        assert [event.stream_id for event in reset_events] == [4]

    def test_trusted_origins_allow_configured_cross_origin_pushes(self):
        """
        Origins explicitly listed as trusted may push resources; other
        cross-origin pushes are still refused.
        """
        policy = h2.push.PushPromiseAdmissionPolicy(
            trusted_origins={"https://cdn.example.com"},
        )
        client, server = connection_pair(policy)
        start_request(client, server)

        server.push_stream(1, 2, pushed_request_headers("/logo.png", authority="cdn.example.com"))
        server.push_stream(1, 4, pushed_request_headers("/tracker.js", authority="evil.example.net"))
        events = client.receive_data(server.data_to_send())

        push_events = events_of_type(events, h2.events.PushedStreamReceived)
        assert [event.pushed_stream_id for event in push_events] == [2]

        server_events = server.receive_data(client.data_to_send())
        reset_events = events_of_type(server_events, h2.events.StreamReset)
        assert [event.stream_id for event in reset_events] == [4]

    def test_callback_receives_parent_request_promised_headers_and_settings(self):
        """
        The admission callback is given the parent request headers, the
        promised request headers, and the current push setting.
        """
        seen = []

        def callback(parent_headers, promised_headers, push_enabled):
            seen.append((parent_headers, promised_headers, push_enabled))
            return True

        client, server = connection_pair(callback)
        start_request(client, server)

        server.push_stream(1, 2, pushed_request_headers("/style.css"))
        events = client.receive_data(server.data_to_send())
        assert events_of_type(events, h2.events.PushedStreamReceived)

        assert len(seen) == 1
        parent_headers, promised_headers, push_enabled = seen[0]
        assert parent_headers == REQUEST_HEADERS
        assert promised_headers == pushed_request_headers("/style.css")
        assert push_enabled is True

    def test_custom_callback_may_refuse_everything(self):
        """
        A callback that refuses all pushes disables server push without
        tearing down the connection.
        """
        client, server = connection_pair(lambda parent, promised, enabled: False)
        start_request(client, server)

        server.push_stream(1, 2, pushed_request_headers("/style.css"))
        events = client.receive_data(server.data_to_send())
        assert not events_of_type(events, h2.events.PushedStreamReceived)

        server_events = server.receive_data(client.data_to_send())
        reset_events = events_of_type(server_events, h2.events.StreamReset)
        assert [event.stream_id for event in reset_events] == [2]

        # The parent request/response exchange is unaffected.
        server.send_headers(1, RESPONSE_HEADERS, end_stream=True)
        events = client.receive_data(server.data_to_send())
        response_events = events_of_type(events, h2.events.ResponseReceived)
        assert [event.stream_id for event in response_events] == [1]

    def test_no_callback_admits_all_pushes(self):
        """
        Without an admission callback the historical behaviour is unchanged:
        every push is admitted.
        """
        client, server = connection_pair()
        start_request(client, server)

        server.push_stream(1, 2, pushed_request_headers("/tracker.js", authority="evil.example.net"))
        events = client.receive_data(server.data_to_send())

        push_events = events_of_type(events, h2.events.PushedStreamReceived)
        assert [event.pushed_stream_id for event in push_events] == [2]


class TestPushPromiseAdmissionPolicy:
    """
    Unit tests for the ready-made admission policy.
    """

    def test_push_disabled_is_refused(self):
        policy = h2.push.PushPromiseAdmissionPolicy()
        assert not policy(REQUEST_HEADERS, pushed_request_headers("/a.css"), False)

    def test_missing_pseudo_headers_are_refused(self):
        policy = h2.push.PushPromiseAdmissionPolicy()
        incomplete = [
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "example.com"),
        ]
        assert not policy(REQUEST_HEADERS, incomplete, True)

    def test_unknown_parent_request_only_allows_trusted_origins(self):
        policy = h2.push.PushPromiseAdmissionPolicy(
            trusted_origins={"https://cdn.example.com"},
        )
        assert not policy(None, pushed_request_headers("/a.css"), True)
        assert policy(None, pushed_request_headers("/a.css", authority="cdn.example.com"), True)

    def test_bytes_headers_are_accepted(self):
        policy = h2.push.PushPromiseAdmissionPolicy()
        parent = [(name.encode(), value.encode()) for name, value in REQUEST_HEADERS]
        promised = [(name.encode(), value.encode()) for name, value in pushed_request_headers("/a.css")]
        assert policy(parent, promised, True)

    def test_origin_matching_is_case_insensitive(self):
        policy = h2.push.PushPromiseAdmissionPolicy(
            trusted_origins={"HTTPS://CDN.Example.COM"},
        )
        assert policy(REQUEST_HEADERS, pushed_request_headers("/a.css", authority="cdn.example.com"), True)

    def test_invalid_origin_string_rejected(self):
        with pytest.raises(ValueError, match="Invalid origin"):
            h2.push.PushPromiseAdmissionPolicy(trusted_origins={"cdn.example.com"})

    def test_tuple_origins_are_accepted(self):
        policy = h2.push.PushPromiseAdmissionPolicy(
            trusted_origins={("https", "cdn.example.com")},
        )
        assert policy(REQUEST_HEADERS, pushed_request_headers("/a.css", authority="cdn.example.com"), True)


class TestPushPromiseAdmissionConfig:
    """
    The admission callback is validated by the configuration object.
    """

    def test_non_callable_callback_is_rejected(self):
        with pytest.raises(ValueError, match="push_promise_admission_callback"):
            h2.config.H2Configuration(push_promise_admission_callback="not-callable")

    def test_callback_defaults_to_none(self):
        config = h2.config.H2Configuration()
        assert config.push_promise_admission_callback is None
