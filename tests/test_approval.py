import io
from datetime import timedelta

import pytest

from webob import Request
from webob.approval import (
    ApprovalGateway,
    ApprovalRegistry,
    InMemoryReportStore,
    ReportRecord,
    WritePrecondition,
)
from webob.datetime_utils import serialize_date, utcnow

LAST_MODIFIED = utcnow().replace(microsecond=0) - timedelta(minutes=5)


class RecordingWriteLogic:
    """写入替身：记录每次被网关交给它的调用。"""

    def __init__(self):
        self.calls = []
        self.before_commit = None
        self.new_body = b"updated report"

    def __call__(self, req, record, commit):
        body = req.body
        self.calls.append({"expected_etag": record.etag, "body": body})
        if self.before_commit is not None:
            self.before_commit()

        return commit(self.new_body)


@pytest.fixture
def store():
    store = InMemoryReportStore()
    store.add(
        ReportRecord(
            "report-1",
            body=b"original report",
            etag="v1",
            last_modified=LAST_MODIFIED,
            approval_scope="scope-A",
        )
    )

    return store


@pytest.fixture
def approvals():
    registry = ApprovalRegistry()
    registry.grant("tok-1", "scope-A")

    return registry


@pytest.fixture
def write_logic():
    return RecordingWriteLogic()


@pytest.fixture
def app(store, approvals, write_logic):
    return ApprovalGateway(store, approvals, write_logic)


def put(app, path="/report-1", headers=None, body=b"new body"):
    req = Request.blank(path, method="PUT", body=body)
    for key, value in (headers or {}).items():
        req.headers[key] = value

    return req.get_response(app)


def auth_headers(extra=None):
    headers = {"X-Approval-Token": "tok-1"}
    headers.update(extra or {})

    return headers


def test_normal_modification(app, store, write_logic):
    resp = put(app, headers=auth_headers({"If-Match": '"v1"'}))

    assert resp.status_code == 200
    assert len(write_logic.calls) == 1
    assert write_logic.calls[0]["expected_etag"] == "v1"
    assert write_logic.calls[0]["body"] == b"new body"

    record = store.get("report-1")
    assert record.body == b"updated report"
    assert record.etag != "v1"
    assert store.published == [("report-1", b"updated report")]


def test_version_change_after_precheck(app, store, write_logic):
    def concurrent_write():
        record = store.get("report-1")
        store.add(
            ReportRecord(
                "report-1",
                body=b"someone else won",
                etag="v2",
                last_modified=record.last_modified,
                approval_scope=record.approval_scope,
            )
        )

    write_logic.before_commit = concurrent_write

    resp = put(app, headers=auth_headers({"If-Match": '"v1"'}))

    assert resp.status_code == 412
    assert len(write_logic.calls) == 1
    assert store.published == []
    assert store.get("report-1").body == b"someone else won"


def test_legacy_timestamp_request(app, store, write_logic):
    headers = auth_headers(
        {"If-Unmodified-Since": serialize_date(LAST_MODIFIED)}
    )
    resp = put(app, headers=headers)

    assert resp.status_code == 200
    assert len(write_logic.calls) == 1
    assert write_logic.calls[0]["expected_etag"] == "v1"
    assert store.published == [("report-1", b"updated report")]


def test_stale_timestamp_rejected(app, store, write_logic):
    stale = serialize_date(LAST_MODIFIED - timedelta(seconds=1))
    resp = put(app, headers=auth_headers({"If-Unmodified-Since": stale}))

    assert resp.status_code == 412
    assert write_logic.calls == []
    assert store.published == []
    assert store.get("report-1").body == b"original report"


def test_stale_etag_rejected(app, store, write_logic):
    resp = put(app, headers=auth_headers({"If-Match": '"v0"'}))

    assert resp.status_code == 412
    assert write_logic.calls == []
    assert store.published == []


def test_weak_etag_never_matches(app, store, write_logic):
    resp = put(app, headers=auth_headers({"If-Match": 'W/"v1"'}))

    assert resp.status_code == 412
    assert write_logic.calls == []


def test_missing_precondition_is_optional(app, store, write_logic):
    resp = put(app, headers=auth_headers())

    assert resp.status_code == 200
    assert len(write_logic.calls) == 1


def test_invalid_token_rejected(app, store, write_logic):
    resp = put(app, headers={"X-Approval-Token": "bogus", "If-Match": '"v1"'})

    assert resp.status_code == 403
    assert write_logic.calls == []
    assert store.published == []


def test_missing_token_rejected(app, store, write_logic):
    resp = put(app, headers={"If-Match": '"v1"'})

    assert resp.status_code == 403
    assert write_logic.calls == []


def test_approval_revoked_before_commit(app, store, approvals, write_logic):
    write_logic.before_commit = lambda: approvals.revoke("tok-1")

    resp = put(app, headers=auth_headers({"If-Match": '"v1"'}))

    assert resp.status_code == 403
    assert len(write_logic.calls) == 1
    assert store.published == []
    assert store.get("report-1").body == b"original report"


def test_get_head_conditional_response_unchanged(app):
    req = Request.blank("/report-1")
    resp = req.get_response(app)
    assert resp.status_code == 200
    assert resp.etag == "v1"
    assert resp.text == "original report"

    req = Request.blank("/report-1", headers={"If-None-Match": '"v1"'})
    resp = req.get_response(app)
    assert resp.status_code == 304

    req = Request.blank("/report-1", method="HEAD")
    resp = req.get_response(app)
    assert resp.status_code == 200
    assert resp.body == b""


class TrackingStream:
    def __init__(self, raw):
        self.raw = raw
        self.bytes_read = 0

    def read(self, size=-1):
        data = self.raw.read(size)
        self.bytes_read += len(data)

        return data

    def readline(self, size=-1):
        data = self.raw.readline(size)
        self.bytes_read += len(data)

        return data

    def __getattr__(self, name):
        return getattr(self.raw, name)


def test_rejected_request_does_not_consume_body(app, write_logic):
    req = Request.blank(
        "/report-1",
        method="PUT",
        body=b"x" * 4096,
        headers={"X-Approval-Token": "tok-1", "If-Match": '"v0"'},
    )
    stream = TrackingStream(io.BytesIO(b"x" * 4096))
    req.environ["wsgi.input"] = stream

    resp = req.get_response(app)

    assert resp.status_code == 412
    assert stream.bytes_read == 0
    assert write_logic.calls == []


def test_write_precondition_contract_defaults():
    precondition = WritePrecondition()
    assert precondition.is_empty
