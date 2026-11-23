"""
Conditional write gateway for approval-protected report resources.

The gateway accepts WSGI requests that modify reports and only hands them
to the write logic when the resource version and the approval scope still
match what the client based its edit on.

Writes may carry an optional precondition contract:

* ``If-Match`` — strong entity-tag comparison (RFC 7232), and
* ``If-Unmodified-Since`` — legacy timestamp marker used by older clients.

Passing the precondition only proves that the version read up front was
acceptable; the commit closure re-confirms the same version and approval
scope before anything is stored.  GET/HEAD reads keep using the existing
conditional response handling, and the request body is never consumed to
decide whether an update may proceed.
"""

import threading

from webob.datetime_utils import UTC, utcnow
from webob.dec import wsgify
from webob.exc import (
    HTTPForbidden,
    HTTPMethodNotAllowed,
    HTTPNotFound,
    HTTPPreconditionFailed,
)
from webob.response import Response

__all__ = [
    "ApprovalGateway",
    "ApprovalRegistry",
    "ApprovalRevoked",
    "InMemoryReportStore",
    "ReportRecord",
    "VersionConflict",
    "WritePrecondition",
]

WRITE_METHODS = ("PUT", "PATCH")

APPROVAL_TOKEN_HEADER = "X-Approval-Token"


def _whole_seconds(dt):
    return dt.replace(microsecond=0)


class VersionConflict(Exception):
    """The record version changed between the precondition and the commit."""


class ApprovalRevoked(Exception):
    """The approval scope no longer covers the record at commit time."""


class WritePrecondition:
    """
    Optional write precondition contract parsed from a request.

    Supports strong validators (``If-Match``) and the legacy timestamp
    marker (``If-Unmodified-Since``).  When both are present the timestamp
    is ignored (RFC 7232, section 3.3).
    """

    def __init__(self, if_match=None, if_unmodified_since=None):
        self.if_match = if_match
        self.if_unmodified_since = if_unmodified_since

    @classmethod
    def from_request(cls, req):
        return cls(
            if_match=req.if_match,
            if_unmodified_since=req.if_unmodified_since,
        )

    @property
    def is_empty(self):
        return not self.if_match and self.if_unmodified_since is None

    def check(self, record):
        """
        Raise ``HTTPPreconditionFailed`` unless *record* satisfies the
        precondition.  An empty contract always passes.
        """
        if self.if_match:
            # Strong comparison: weak validators in If-Match never match.
            if record.etag not in self.if_match:
                raise HTTPPreconditionFailed(
                    "If-Match does not match the current report version"
                )
        elif self.if_unmodified_since is not None:
            last_modified = record.last_modified
            if last_modified is not None and last_modified.tzinfo is None:
                last_modified = last_modified.replace(tzinfo=UTC)
            if (
                last_modified is None
                or last_modified > self.if_unmodified_since
            ):
                raise HTTPPreconditionFailed(
                    "report changed after If-Unmodified-Since"
                )


class ReportRecord:
    """A stored report version plus the approval scope protecting it."""

    def __init__(self, report_id, body, etag, last_modified, approval_scope):
        self.report_id = report_id
        self.body = body
        self.etag = etag
        self.last_modified = last_modified
        self.approval_scope = approval_scope

    def snapshot(self):
        return ReportRecord(
            self.report_id,
            self.body,
            self.etag,
            self.last_modified,
            self.approval_scope,
        )


class ApprovalRegistry:
    """Maps approval tokens to the scope they currently grant."""

    def __init__(self):
        self._grants = {}

    def grant(self, token, scope):
        self._grants[token] = scope

    def revoke(self, token):
        self._grants.pop(token, None)

    def scope_for(self, token):
        """Return the granted scope, or ``None`` for invalid/revoked tokens."""
        return self._grants.get(token)


class InMemoryReportStore:
    """
    Holds report records and applies commits with a compare-and-swap on
    the record version and approval scope.
    """

    def __init__(self):
        self._records = {}
        self._lock = threading.Lock()
        self.published = []

    def add(self, record):
        with self._lock:
            self._records[record.report_id] = record

    def get(self, report_id):
        with self._lock:
            record = self._records.get(report_id)

            return record.snapshot() if record is not None else None

    def commit(
        self,
        report_id,
        expected_etag,
        approval_scope,
        new_body,
        new_etag=None,
        new_last_modified=None,
        scope_still_valid=None,
    ):
        """
        Store *new_body* only if the record still carries *expected_etag*
        and *approval_scope*.  ``scope_still_valid`` is an optional callback
        re-checked under the same lock (e.g. token revocation).
        """
        with self._lock:
            record = self._records.get(report_id)
            if record is None or record.etag != expected_etag:
                raise VersionConflict(report_id)
            if record.approval_scope != approval_scope:
                raise ApprovalRevoked(report_id)
            if scope_still_valid is not None and not scope_still_valid():
                raise ApprovalRevoked(report_id)

            record.body = new_body
            record.etag = new_etag or f"{record.etag}+1"
            record.last_modified = _whole_seconds(
                new_last_modified or utcnow()
            )
            self.published.append((report_id, new_body))

            return record.snapshot()


class ApprovalGateway:
    """
    WSGI gateway in front of the report write logic.

    *write_logic* is called as ``write_logic(req, record, commit)`` only
    after the approval scope and the optional write precondition have been
    verified against the current record.  ``commit`` re-confirms the same
    version and scope before storing, so a concurrent modification or a
    revoked approval between the two checks fails the request instead of
    publishing a new report.
    """

    def __init__(self, store, approvals, write_logic):
        self.store = store
        self.approvals = approvals
        self.write_logic = write_logic

    @wsgify
    def __call__(self, req):
        report_id = req.path_info.strip("/")

        if req.method in ("GET", "HEAD"):
            return self._serve_read(req, report_id)
        if req.method not in WRITE_METHODS:
            raise HTTPMethodNotAllowed()

        record = self.store.get(report_id)
        if record is None:
            raise HTTPNotFound()

        token = req.headers.get(APPROVAL_TOKEN_HEADER)
        scope = self.approvals.scope_for(token) if token else None
        if scope is None or scope != record.approval_scope:
            raise HTTPForbidden("invalid or revoked approval token")

        # The precondition is evaluated before the body is touched; the
        # request body is never consumed to decide whether to update.
        precondition = WritePrecondition.from_request(req)
        precondition.check(record)

        def commit(new_body, new_etag=None, new_last_modified=None):
            return self.store.commit(
                report_id,
                expected_etag=record.etag,
                approval_scope=record.approval_scope,
                new_body=new_body,
                new_etag=new_etag,
                new_last_modified=new_last_modified,
                scope_still_valid=lambda: self.approvals.scope_for(token)
                == record.approval_scope,
            )

        try:
            result = self.write_logic(req, record, commit)
        except VersionConflict:
            raise HTTPPreconditionFailed(
                "report version changed before the update committed"
            )
        except ApprovalRevoked:
            raise HTTPForbidden("approval scope no longer covers this report")

        if isinstance(result, Response):
            return result

        return Response(status=200, text="report updated")

    def _serve_read(self, req, report_id):
        record = self.store.get(report_id)
        if record is None:
            raise HTTPNotFound()

        resp = Response(body=record.body, conditional_response=True)
        resp.etag = record.etag
        resp.last_modified = record.last_modified

        return resp
