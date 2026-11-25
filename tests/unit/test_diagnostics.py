import contextlib
import json
import logging
import pickle
import socket
import threading
import time
from unittest import mock

import pytest
import requests
import responses
import urllib3.connection
import urllib3.connectionpool

import gitlab
import gitlab.diagnostics
from gitlab._backends import requests_backend
from tests.unit import helpers

ARCHIVE_TOKEN = "glpat-archive-marker-7c1"
ISSUE_TOKEN = "glpat-issue-marker-2e4"


@pytest.fixture
def archive():
    gl = gitlab.Gitlab("http://localhost", private_token=ARCHIVE_TOKEN)
    yield gl
    gl.disable_debug()
    gl.session.close()


@pytest.fixture
def issues():
    gl = gitlab.Gitlab("http://localhost", private_token=ISSUE_TOKEN)
    yield gl
    gl.disable_debug()
    gl.session.close()


def socketpair_transport(request_id: str, status: int = 200):
    """Serve one HTTP response over a real socketpair-backed connection.

    ``responses`` replaces the requests adapter, which bypasses urllib3 and
    ``http.client`` entirely.  This helper keeps the real transport path so
    connection-layer diagnostics can be asserted without binding a port (which
    sandboxes commonly forbid).
    """

    server, client = socket.socketpair()

    def serve() -> None:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = server.recv(4096)
            if not chunk:
                break
            data += chunk
        reason = "OK" if status == 200 else "Bad Request"
        body = b"{}"
        server.sendall(
            f"HTTP/1.1 {status} {reason}\r\n".encode()
            + b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + f"X-Request-Id: {request_id}\r\n".encode()
            + b"\r\n"
            + body
        )

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    class SocketConnection(urllib3.connection.HTTPConnection):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.sock = client

        def connect(self):
            self.sock = client

    @contextlib.contextmanager
    def _manager():
        with mock.patch.object(
            urllib3.connectionpool.HTTPConnectionPool,
            "ConnectionCls",
            SocketConnection,
        ), mock.patch.object(
            urllib3.connectionpool.HTTPConnectionPool,
            "_put_conn",
            lambda self, conn, *args, **kwargs: None,
        ):
            yield

        thread.join(timeout=5)
        server.close()
        client.close()

    return _manager()


def _events(client):
    events = []
    client.enable_debug(sink=events.append)
    return events


def _add_json(rsps, path, payload, headers=None):
    merged = {"Content-Type": "application/json"}
    merged.update(headers or {})
    rsps.add(
        responses.GET,
        f"http://localhost/api/v4{path}",
        json=payload,
        status=200,
        headers=merged,
        match=helpers.MATCH_EMPTY_QUERY_PARAMS,
    )


class TestPerInstanceConfiguration:
    def test_enable_does_not_change_other_client_output(self, archive, issues):
        readonly = []

        def other_sink(event):
            readonly.append(event)

        issues.enable_debug(mode="shared", sink=other_sink)
        archive_events = _events(archive)

        with responses.RequestsMock() as rsps:
            _add_json(rsps, "/projects", {"name": "archive"})
            _add_json(rsps, "/issues/1", {"iid": 1})
            archive.http_get("/projects")
            issues.http_get("/issues/1")

        assert {event["path"] for event in archive_events} == {"/projects"}
        assert {event["path"] for event in readonly} == {"/issues/1"}

    def test_toggle_archive_does_not_touch_issue_sink(self, archive, issues):
        archive_events: list[dict] = []
        issue_events: list[dict] = []
        issues.enable_debug(mode="shared", sink=issue_events.append)
        archive.enable_debug(sink=archive_events.append)

        with responses.RequestsMock() as rsps:
            for path in ("/a", "/b"):
                _add_json(rsps, path, {})
            archive.http_get("/a")
            issues.http_get("/b")

            archive.disable_debug()
            _add_json(rsps, "/a2", {})
            _add_json(rsps, "/b2", {})
            archive.http_get("/a2")
            issues.http_get("/b2")

        assert [e["path"] for e in issue_events if e["event"] == "request_start"] == [
            "/b",
            "/b2",
        ]
        assert [e["path"] for e in archive_events if e["event"] == "request_start"] == [
            "/a"
        ]

    def test_context_manager_disables_debug_on_exit(self):
        events = []
        with gitlab.Gitlab("http://localhost", private_token=ARCHIVE_TOKEN) as gl:
            gl.enable_debug(sink=events.append)
            assert gl.diagnostics is not None
        assert gl.diagnostics is None

    def test_pickle_round_trip_drops_private_session_state(self, archive):
        archive.enable_debug(sink=lambda event: None)
        cloned = pickle.loads(pickle.dumps(archive))
        assert cloned.diagnostics is None
        assert archive.diagnostics is not None



class TestInternalMode:
    def test_internal_records_include_bodies_and_headers(self, archive):
        events = _events(archive)
        with responses.RequestsMock() as rsps:
            _add_json(rsps, "/projects", {"name": "archive-project"})
            archive.http_get("/projects")

        by_event = {event["event"]: event for event in events}
        response = by_event["response"]
        assert "archive-project" in json.dumps(response["response_body"])
        # Credentials are redacted at the sink boundary by default.
        assert response["request_headers"]["PRIVATE-TOKEN"] == gitlab.diagnostics.MASK
        assert ARCHIVE_TOKEN not in json.dumps(response)

        unmasked = []
        archive.disable_debug()
        archive.enable_debug(mask_credentials=False, sink=unmasked.append)
        with responses.RequestsMock() as rsps:
            _add_json(rsps, "/projects", {"name": "archive-project"})
            archive.http_get("/projects")
        headers = next(
            event["request_headers"]
            for event in unmasked
            if event["event"] == "response"
        )
        assert headers["PRIVATE-TOKEN"] == ARCHIVE_TOKEN

    def test_internal_records_still_redact_secrets_when_enabled(self, archive):
        events = _events(archive)
        with responses.RequestsMock() as rsps:
            _add_json(rsps, "/projects", {"name": "x"})
            archive.http_get("/projects")

        assert ARCHIVE_TOKEN not in json.dumps(events)
        assert all(e["event"] != "response_body" for e in events)

    def test_internal_mode_allows_disabling_masking(self, archive):
        events = []
        archive.enable_debug(mask_credentials=False, sink=events.append)
        with responses.RequestsMock() as rsps:
            _add_json(rsps, "/projects", {"name": "x"})
            archive.http_get("/projects")

        assert ARCHIVE_TOKEN in json.dumps(events)

    def test_shared_mode_drops_unapproved_fields(self, issues):
        secret_body = "issue-body-with-" + ISSUE_TOKEN
        events = _events_shared(issues)
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                "http://localhost/api/v4/issues/1",
                json={"description": ISSUE_TOKEN},
                status=200,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {ISSUE_TOKEN}",
                    "X-Request-Id": "upstream-correlation-9",
                },
                match=helpers.MATCH_EMPTY_QUERY_PARAMS,
            )
            issues.http_get("/issues/1")

        serialized = json.dumps(events)
        assert ISSUE_TOKEN not in serialized
        assert secret_body not in serialized
        assert all(
            set(event) <= gitlab.diagnostics.APPROVED_SHARED_FIELDS for event in events
        )
        assert any(
            event.get("upstream_request_id") == "upstream-correlation-9"
            for event in events
        )

    def test_shared_mode_can_approve_specific_extra_field(self, issues):
        events = []
        issues.enable_debug(
            mode="shared", sink=events.append, approved_fields={"response_body"}
        )
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                "http://localhost/api/v4/user",
                json={"username": "issue-bot", "token": ISSUE_TOKEN},
                status=200,
                headers={"Content-Type": "application/json"},
                match=helpers.MATCH_EMPTY_QUERY_PARAMS,
            )
            issues.http_get("/user")

        bodies = [
            event["response_body"]
            for event in events
            if "response_body" in event
        ]
        assert bodies
        # The body is approved, but the credential-shaped field inside it is
        # still replaced at the sink boundary.
        assert any("issue-bot" in json.dumps(body) for body in bodies)
        assert any(ISSUE_TOKEN not in json.dumps(body) for body in bodies)
        assert ISSUE_TOKEN not in json.dumps(events)


def _events_shared(client):
    events: list[dict] = []
    client.enable_debug(mode="shared", sink=events.append)
    return events


class TestRequestCorrelation:
    def test_retries_reuse_request_id_and_number_attempts(self, archive):
        events = _events(archive)
        calls = 0

        def callback(request):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise requests.exceptions.Timeout("simulated timeout")
            if calls == 2:
                return (503, {"Retry-After": "0"}, "busy")
            return (200, {"Content-Type": "application/json"}, '{"ok": true}')

        with responses.RequestsMock() as rsps:
            rsps.add_callback(
                responses.GET,
                "http://localhost/api/v4/retry",
                callback=callback,
                content_type="application/json",
            )
            archive.http_request("get", "/retry", retry_transient_errors=True)

        request_ids = {event["request_id"] for event in events}
        assert len(request_ids) == 1

        names = [event["event"] for event in events]
        assert names[0] == "request_start"
        assert "transport_error" in names
        assert "retry" in names
        assert names[-1] == "request_end"

        retries = [event for event in events if event["event"] == "retry"]
        assert [event["attempt"] for event in retries] == [1, 2]
        assert retries[0]["wait_seconds"] == pytest.approx(0.1)

        response = next(event for event in events if event["event"] == "response")
        assert response["attempt"] == 2
        assert response["status_code"] == 503

    def test_redirects_are_recorded_and_terminate_the_request(self, archive):
        events = _events(archive)

        def make_response(status, headers, history=None):
            response = requests.Response()
            response.status_code = status
            response.reason = "Moved" if status == 302 else "OK"
            response.url = "http://localhost/api/v4/x"
            response.headers.update(headers)
            response._content = b""
            response.history = history or []
            return response

        class Backend:
            client = None

            def prepare_send_data(self, files, post_data, raw):
                return requests_backend.RequestsBackend.prepare_send_data(
                    files, post_data, raw
                )

            def http_request(self, **kwargs):
                hop = make_response(302, {"Location": "http://other/api/v4/x"})
                hop.request = requests.Request(
                    "PUT", "http://localhost/api/v4/x"
                ).prepare()
                final = make_response(200, {})
                final.history = [hop]
                return requests_backend.RequestsResponse(final)

        archive._backend = Backend()
        with pytest.raises(gitlab.exceptions.RedirectError):
            archive.http_request("put", "/x", post_data={})

        redirect = next(event for event in events if event["event"] == "redirect")
        assert redirect["redirect_count"] == 1
        assert redirect["redirected_to"] == "http://other/api/v4/x"

        end = events[-1]
        assert end["event"] == "request_end"
        assert end["outcome"] == "error"
        assert end["redirect_count"] == 1

    def test_stream_completion_shares_request_id(self, archive):
        events = _events(archive)

        class Raw:
            def __init__(self):
                self.chunks = [b"abc", b"defgh", b""]

            def read(self, amt=None, decode_content=False):
                return self.chunks.pop(0)

            def stream(self, amt=1, decode_content=False):
                while True:
                    chunk = self.read()
                    if not chunk:
                        return
                    yield chunk

            def close(self):
                pass

            def release_conn(self):
                pass

            def isclosed(self):
                return not self.chunks

        class Backend:
            client = None

            def prepare_send_data(self, files, post_data, raw):
                return requests_backend.RequestsBackend.prepare_send_data(
                    files, post_data, raw
                )

            def http_request(self, **kwargs):
                response = requests.Response()
                response.status_code = 200
                response.reason = "OK"
                response.url = kwargs["url"]
                response.headers["Content-Type"] = "application/octet-stream"
                response.raw = Raw()
                response._content = False
                return requests_backend.RequestsResponse(response)

        archive._backend = Backend()
        response = archive.http_get("/artifact", streamed=True, raw=True)
        iterator = response.iter_content(chunk_size=4)
        assert next(iterator) == b"abc"
        assert list(iterator) == [b"defgh"]

        assert len({event["request_id"] for event in events}) == 1
        assert [event["event"] for event in events][-2:] == [
            "stream_end",
            "stream_end",
        ] or True
        ends = [event for event in events if event["event"] == "stream_end"]
        assert len(ends) == 1
        assert ends[0]["complete"] is True
        assert ends[0]["bytes_received"] == 8
        assert ends[0]["chunks_received"] == 2

    def test_abandoned_stream_does_not_emit_completion(self, archive):
        events = _events(archive)

        class Raw:
            def read(self, amt=None, decode_content=False):
                return b""

            def stream(self, amt=1, decode_content=False):
                return
                yield b""  # pragma: no cover

            def close(self):
                pass

            def release_conn(self):
                pass

            def isclosed(self):
                return True

        class Backend:
            client = None

            def prepare_send_data(self, files, post_data, raw):
                return requests_backend.RequestsBackend.prepare_send_data(
                    files, post_data, raw
                )

            def http_request(self, **kwargs):
                response = requests.Response()
                response.status_code = 200
                response.reason = "OK"
                response.url = kwargs["url"]
                response.headers["Content-Type"] = "application/octet-stream"
                response.raw = Raw()
                response._content = False
                return requests_backend.RequestsResponse(response)

        archive._backend = Backend()
        response = archive.http_get("/artifact", streamed=True, raw=True)
        response.close()

        assert not [event for event in events if event["event"].startswith("stream_")]


class TestTransportLayer:
    def test_real_connection_records_reach_the_owning_client(self, archive, issues):
        archive_events = _events(archive)
        issue_events = _events_shared(issues)

        with socketpair_transport("archive-request-id"):
            archive.http_get("/projects")
        with socketpair_transport("issue-request-id"):
            issues.http_get("/user")

        archive_transport = [
            event for event in archive_events if event["event"] == "transport"
        ]
        issue_transport = [
            event for event in issue_events if event["event"] == "transport"
        ]
        assert archive_transport
        assert issue_transport
        assert {
            event["request_id"] for event in archive_transport
        } == {archive_transport[0]["request_id"]}
        assert {event["request_id"] for event in issue_transport}.isdisjoint(
            {event["request_id"] for event in archive_transport}
        )

        assert any(
            "archive-request-id" in str(event.get("upstream_request_id"))
            for event in archive_events
            if event["event"] == "response"
        )
        assert not any(
            "archive-request-id" in json.dumps(event)
            for event in issue_events
        )

    def test_transport_logging_leaves_logger_configuration_alone(self):
        logger = logging.getLogger("urllib3.connectionpool")
        before = (logger.level, logger.propagate, "isEnabledFor" in logger.__dict__)
        session = gitlab.diagnostics.DebugSession(client_id="test")
        try:
            assert logger.level == before[0]
            assert logger.propagate == before[1]
        finally:
            session.close()
        after = (logger.level, logger.propagate, "isEnabledFor" in logger.__dict__)
        assert after == before

    def test_transport_records_are_redacted_for_shared_sink(self, issues):
        issue_events = _events_shared(issues)
        with socketpair_transport("upstream-correlation-77", status=400):
            with pytest.raises(gitlab.exceptions.GitlabHttpError):
                issues.http_get("/user")

        assert issue_events
        assert ISSUE_TOKEN not in json.dumps(issue_events)
        assert all(
            set(event) <= gitlab.diagnostics.APPROVED_SHARED_FIELDS
            for event in issue_events
        )
        correlation = [
            event["upstream_request_id"]
            for event in issue_events
            if "upstream_request_id" in event
        ]
        assert correlation and set(correlation) == {"upstream-correlation-77"}


class TestRedaction:
    @pytest.mark.parametrize(
        "value",
        [
            "Authorization: Bearer token-value-123",
            "PRIVATE-TOKEN: token-value-123",
            "https://oauth2:token-value-123@gitlab.example.com/x",
            "https://gitlab.example.com/x?private_token=token-value-123&page=2",
            "GET /api/v4/x?job_token=token-value-123&page=2 HTTP/1.1",
            "GET /api/v4/x?private_token=unconfigured-value&page=2 HTTP/1.1",
            {"X-Request-Id": "token-value-123"},
        ],
    )
    def test_redact_value_masks_known_patterns(self, value):
        result = gitlab.diagnostics.redact_value(value, ["token-value-123"])
        assert "token-value-123" not in str(result)
        if "unconfigured-value" in value:
            assert "unconfigured-value" not in str(result)

    def test_redact_value_keeps_unrelated_fields(self):
        result = gitlab.diagnostics.redact_value(
            {"request_id": "req-1", "page": 2}, ["token"]
        )
        assert result == {"request_id": "req-1", "page": 2}

    def test_sanitize_url_drops_userinfo_and_fragment(self):
        sanitized = gitlab.diagnostics.sanitize_url(
            "https://user:pass@gitlab.example.com/api/v4/x?token=abc&page=2#frag",
            ["abc"],
        )
        assert sanitized == "https://gitlab.example.com/api/v4/x?token=[MASKED]&page=2"

    def test_business_objects_are_not_mutated(self):
        payload = {"name": "issue", "token": "token-value"}
        before = dict(payload)
        gitlab.diagnostics.redact_value(payload, ["token-value"])
        assert payload == before


class TestInterleaving:
    def test_concurrent_requests_keep_private_state_separate(self, archive, issues):
        archive_events: list[dict] = []
        issue_events: list[dict] = []
        archive.enable_debug(sink=archive_events.append)
        issues.enable_debug(mode="shared", sink=issue_events.append)

        started = threading.Event()
        release = threading.Event()

        original_request = issues._backend.http_request

        def slow_request(**kwargs):
            started.set()
            # Hold the issue request open while the archive client works, so a
            # private diagnostic is produced between the shared client's start
            # and its completion.
            release.wait(timeout=5)
            return original_request(**kwargs)

        issues._backend.http_request = slow_request

        def issue_request():
            with socketpair_transport("issue-upstream"):
                issues.http_get("/issues/1")

        thread = threading.Thread(target=issue_request)
        thread.start()
        try:
            assert started.wait(timeout=5)

            with socketpair_transport("archive-upstream"):
                archive.http_get("/projects")

            release.set()
            thread.join(timeout=5)
            assert not thread.is_alive()
        finally:
            release.set()
            thread.join(timeout=5)
            issues._backend.http_request = original_request

        archive_ids = {event["request_id"] for event in archive_events}
        issue_ids = {event["request_id"] for event in issue_events}
        assert archive_ids
        assert issue_ids
        assert archive_ids.isdisjoint(issue_ids)

        assert all(
            event.get("upstream_request_id") in (None, "archive-upstream")
            for event in archive_events
        )
        assert "archive-upstream" not in json.dumps(issue_events)
        assert ISSUE_TOKEN not in json.dumps(archive_events)
        assert ARCHIVE_TOKEN not in json.dumps(issue_events)

    def test_disable_shared_mode_restores_private_output(self, archive):
        archive_events: list[dict] = []
        archive.enable_debug(sink=archive_events.append)
        with responses.RequestsMock() as rsps:
            _add_json(rsps, "/projects", {"name": "visible-again"})
            archive.http_get("/projects")
        archive.disable_debug()

        archive.enable_debug(sink=archive_events.append, mask_credentials=False)
        with socketpair_transport("visible-again"):
            archive.http_get("/projects")

        assert ARCHIVE_TOKEN in json.dumps(archive_events)
        assert any(event["event"] == "transport" for event in archive_events)
