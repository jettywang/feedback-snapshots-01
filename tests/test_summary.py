"""Unit tests for webob.summary itself."""

import json

import pytest

import webob
from webob.request import Request, RequestSummary as ExportedFromRequest
from webob.summary import HeaderSummary, RequestSummary


class CountingInput:
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.reads = 0

    def tell(self):
        return self.pos

    def read(self, size=-1):
        self.reads += 1

        if size is None or size < 0:
            chunk = self.data[self.pos :]
            self.pos = len(self.data)
            return chunk

        chunk = self.data[self.pos : self.pos + size]
        self.pos += len(chunk)
        return chunk


def make_request(body=b"payload", **extra):
    counting = CountingInput(body)
    environ = {
        "REQUEST_METHOD": "PUT",
        "PATH_INFO": "/upload",
        "SCRIPT_NAME": "",
        "QUERY_STRING": "",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "wsgi.url_scheme": "http",
        "wsgi.input": counting,
        "CONTENT_LENGTH": str(len(body)),
        "CONTENT_TYPE": "application/octet-stream",
    }
    environ.update(extra)
    return Request(environ), counting


def test_summary_classes_are_public():
    assert webob.RequestSummary is RequestSummary
    assert ExportedFromRequest is RequestSummary
    assert webob.HeaderSummary is HeaderSummary


def test_rejects_missing_approval():
    req, _counting = make_request()
    with pytest.raises(TypeError):
        req.summary(None)


def test_rejects_non_string_approval():
    req, _counting = make_request()
    with pytest.raises(TypeError):
        req.summary([b"X-Business"])


def test_rejects_empty_approval_name():
    req, _counting = make_request()
    with pytest.raises(ValueError):
        req.summary(["  "])


def test_rejects_header_name_injection_in_approval():
    req, _counting = make_request()
    with pytest.raises(ValueError):
        req.summary(["X-Business: injected"])
    with pytest.raises(ValueError):
        req.summary(["X-Business\r\nInjected"])


def test_rejects_stage_injection():
    req, _counting = make_request()
    with pytest.raises(ValueError):
        req.summary(["X-Business"], stage="ingress\nforged")


def test_accepts_a_single_name():
    req, _counting = make_request()
    req.headers["X-Business"] = "value"
    summary = req.summary("X-Business")
    assert [header.name for header in summary.headers] == ["X-Business"]


def test_approval_is_case_insensitive_and_deduplicated():
    req, _counting = make_request()
    req.headers["X-Business"] = "value"
    summary = req.summary(["X-Business", "x-business"])
    assert summary.approved_headers == ("x-business",)
    assert len(summary.headers) == 1


def test_rejects_bad_stage_type():
    req, _counting = make_request()
    with pytest.raises(TypeError):
        req.summary(["X-Business"], stage=1)


def test_rejects_bad_raw_header_items():
    req, _counting = make_request()
    with pytest.raises(TypeError):
        req.summary(["X-Business"], raw_headers=["X-Business"])
    with pytest.raises(TypeError):
        req.summary(["X-Business"], raw_headers=[(b"X-Business", "value")])


def test_empty_approval_yields_no_headers():
    req, _counting = make_request()
    req.headers["X-Business"] = "value"
    summary = req.summary([])
    assert summary.headers == ()
    assert "headers: none approved" in str(summary)


def test_headers_are_sorted_and_stable():
    req, _counting = make_request()
    req.headers["X-Zed"] = "z"
    req.headers["X-Alpha"] = "a"
    summary = req.summary(["X-Zed", "X-Alpha"])
    assert [header.name for header in summary.headers] == ["X-Alpha", "X-Zed"]


def test_summary_is_frozen():
    req, _counting = make_request()
    summary = req.summary(["X-Business"])
    with pytest.raises(Exception):
        summary.method = "GET"
    with pytest.raises(Exception):
        summary.headers = ()
    assert isinstance(summary, RequestSummary)


def test_header_summary_value_joining():
    header = HeaderSummary(
        name="X-Business",
        values=("first", "second"),
        source="raw",
        count=2,
        merged=False,
    )
    assert header.value == "first, second"
    assert header.as_dict()["count_known"] is True


def test_snapshot_survives_request_mutation():
    req, counting = make_request()
    req.headers["X-Business"] = "before"
    first = req.summary(["X-Business"])
    req.headers["X-Business"] = "after"
    req.body = b"replaced"
    assert first.headers[0].value == "before"
    assert first.content_length == len(b"payload")
    assert counting.reads == 0


def test_query_parameter_names_are_part_of_the_shape():
    req, _counting = make_request()
    req.query_string = "project=42&mode=preview&token=SECRET-VALUE"
    summary = req.summary(["X-Business"])
    assert summary.query_parameters == ("project", "mode", "token")
    assert summary.as_dict()["query_parameters"] == [
        "project",
        "mode",
        "token",
    ]
    assert "query-parameters: project, mode, token" in str(summary)
    assert "SECRET-VALUE" not in str(summary)
    assert "SECRET-VALUE" not in summary.to_json()


def test_no_query_parameters():
    req, _counting = make_request()
    summary = req.summary(["X-Business"])
    assert summary.query_parameters == ()
    assert "query-parameters: none" in str(summary)


def test_json_is_parseable_and_matches_dict():
    req, _counting = make_request()
    req.headers["X-Business"] = "value"
    summary = req.summary(["X-Business"], stage="ingress")
    assert json.loads(summary.to_json()) == summary.as_dict()
    assert summary.to_dict() == summary.as_dict()


def test_json_is_ascii_safe_but_round_trips_non_ascii_values():
    req, _counting = make_request()
    summary = req.summary(["X-Business"], raw_headers=[("X-Business", "fürst")])
    encoded = summary.to_json()
    encoded.encode("ascii")
    assert json.loads(encoded)["headers"][0]["values"] == ["fürst"]


def test_body_is_never_included():
    req, counting = make_request(b"very-secret-payload")
    summary = req.summary(["X-Business"])
    assert "very-secret-payload" not in str(summary)
    assert "very-secret-payload" not in summary.to_json()
    assert counting.reads == 0
    assert summary.body["included"] is False
    assert summary.body["read_by_summary"] is False
    assert summary.body["position"] == 0
    assert summary.as_dict()["body"] == summary.body


def test_empty_body_is_reported_as_empty():
    req, _counting = make_request(b"")
    summary = req.summary(["X-Business"])
    assert summary.body_status == "empty"
    assert summary.content_length == 0
    assert summary.length_known is True


def test_not_readable_body_is_reported():
    req, _counting = make_request(body=b"", CONTENT_LENGTH=None)
    summary = req.summary(["X-Business"])
    assert summary.body_status == "unknown"
    assert summary.length_known is False


def test_body_without_position_support_is_reported_as_unknown():
    class NoTellInput:
        def __init__(self, data):
            self.data = data
            self.pos = 0

        def read(self, size=-1):
            if size is None or size < 0:
                chunk = self.data[self.pos :]
                self.pos = len(self.data)
                return chunk
            chunk = self.data[self.pos : self.pos + size]
            self.pos += len(chunk)
            return chunk

    body = b"payload"
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/upload",
        "SCRIPT_NAME": "",
        "QUERY_STRING": "",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "wsgi.url_scheme": "http",
        "wsgi.input": NoTellInput(body),
        "CONTENT_LENGTH": str(len(body)),
    }
    summary = Request(environ).summary(["X-Business"])
    assert summary.body_status == "unknown"
    assert summary.length_known is True
    assert summary.content_length == len(body)


def test_protected_header_set_covers_credentials():
    from webob.summary import PROTECTED_HEADERS

    assert "authorization" in PROTECTED_HEADERS
    assert "proxy-authorization" in PROTECTED_HEADERS
    assert "cookie" in PROTECTED_HEADERS
    assert "x-api-key" in PROTECTED_HEADERS
