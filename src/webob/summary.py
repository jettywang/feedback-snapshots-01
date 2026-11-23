"""Safe, immutable summaries of a request.

A summary is a point-in-time diagnostic view of a request.  It only exposes
what the caller explicitly approved, always protects credential-bearing
headers, and never reads the request body.  The same field policy is applied
to the text form, the structured form, and the JSON form.
"""

from collections.abc import Mapping
from dataclasses import dataclass
import json
from urllib.parse import unquote_plus

from webob.headers import EnvironHeaders

__all__ = [
    "HeaderSummary",
    "RequestSummary",
    "PROTECTED_HEADERS",
    "REDACTED",
    "SOURCE_ENVIRON",
    "SOURCE_RAW",
]

PROTECTED_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "cookie2",
        "x-api-key",
        "x-auth-token",
    }
)

REDACTED = "<protected>"

SOURCE_ENVIRON = "wsgi-environ"
SOURCE_RAW = "raw"


@dataclass(frozen=True)
class HeaderSummary:
    """A single approved header in a :class:`RequestSummary`.

    ``values`` preserves the values seen for the header.  When the summary
    was built from a WSGI environ, only the server-merged value is available,
    so ``values`` holds one entry and ``count`` is ``None``: the original
    number of header lines cannot be proven.  When the caller supplied the
    raw header pairs observed at the ingress layer, each value is preserved
    and ``count`` is exact.
    """

    name: str
    values: tuple
    source: str
    count: object = None
    merged: bool = True
    redacted: bool = False

    def __post_init__(self):
        object.__setattr__(self, "values", tuple(self.values))

    @property
    def value(self):
        """The header values joined for display."""
        return ", ".join(self.values)

    def as_dict(self):
        return {
            "name": self.name,
            "values": list(self.values),
            "value": self.value,
            "count": self.count,
            "count_known": self.count is not None,
            "source": self.source,
            "merged": self.merged,
            "redacted": self.redacted,
        }


@dataclass(frozen=True)
class RequestSummary:
    """An immutable diagnostic summary of a request.

    Create one through :meth:`webob.request.BaseRequest.summary`.  The
    summary never holds a reference to the request, so later changes to the
    environment, headers, or body do not alter an existing summary.
    """

    method: str
    path: str
    http_version: str
    content_type: str
    query_parameters: tuple
    stage: str
    approved_headers: tuple
    header_source: str
    headers: tuple
    content_length: object = None
    length_known: bool = False
    body_status: str = "unknown"
    body_readable: bool = False
    body_seekable: bool = False
    body_position: object = None

    @classmethod
    def from_request(cls, request, *, approved_headers, stage=None, raw_headers=None):
        approved = _normalize_approved(approved_headers)

        if stage is None:
            stage = "unspecified"
        elif not isinstance(stage, str):
            raise TypeError("stage must be a string or None")
        elif any(char in stage for char in "\r\n"):
            raise ValueError("stage must not contain CR or LF")

        content_length = request.content_length
        length_known = content_length is not None
        body_position = _body_position(request)
        body_status = _body_status(request, content_length, body_position=body_position)
        body_readable = bool(request.is_body_readable)
        body_seekable = bool(request.is_body_seekable)

        if raw_headers is None:
            header_source = SOURCE_ENVIRON
            headers = _headers_from_environ(EnvironHeaders(request.environ), approved)
        else:
            header_source = SOURCE_RAW
            headers = _headers_from_raw(raw_headers, approved)

        return cls(
            method=str(request.method),
            path=_request_path(request),
            http_version=str(request.environ.get("SERVER_PROTOCOL") or ""),
            content_type=str(request.content_type or ""),
            query_parameters=_query_parameter_names(request),
            stage=stage,
            approved_headers=approved,
            header_source=header_source,
            headers=headers,
            content_length=content_length,
            length_known=length_known,
            body_status=body_status,
            body_readable=body_readable,
            body_seekable=body_seekable,
            body_position=body_position,
        )

    def as_dict(self):
        """Return a structured, JSON-serializable view of the summary."""
        return {
            "method": self.method,
            "path": self.path,
            "http_version": self.http_version,
            "content_type": self.content_type,
            "query_parameters": list(self.query_parameters),
            "stage": self.stage,
            "approved_headers": list(self.approved_headers),
            "header_source": self.header_source,
            "headers": [header.as_dict() for header in self.headers],
            "body": self.body,
        }

    @property
    def body(self):
        """A structured view of the body's state; the body is never included."""
        return {
            "included": False,
            "read_by_summary": False,
            "status": self.body_status,
            "readable": self.body_readable,
            "seekable": self.body_seekable,
            "content_length": self.content_length,
            "length_known": self.length_known,
            "position": self.body_position,
        }

    def to_dict(self):
        """Alias for :meth:`as_dict`."""
        return self.as_dict()

    def to_json(self):
        """Serialize the summary using the same field policy as the text form."""
        return json.dumps(self.as_dict(), sort_keys=True)

    def __str__(self):
        length = str(self.content_length) if self.length_known else "unknown"
        lines = [
            "request summary",
            "  method: %s" % _escape(self.method),
            "  path: %s" % _escape(self.path),
            "  http-version: %s" % _escape(self.http_version),
            "  content-type: %s" % _escape(self.content_type),
            "  query-parameters: %s"
            % (", ".join(_escape(name) for name in self.query_parameters) or "none"),
            "  stage: %s" % _escape(self.stage),
            "  content-length: %s" % length,
            "  body: status=%s included=False read_by_summary=False"
            " readable=%s seekable=%s"
            " position=%s"
            % (
                self.body_status,
                self.body_readable,
                self.body_seekable,
                "unknown" if self.body_position is None else self.body_position,
            ),
            "  header-source: %s" % self.header_source,
            "  approved-headers: %s"
            % ", ".join(_escape(name) for name in self.approved_headers),
        ]

        if self.headers:
            lines.append("  headers:")

            for header in self.headers:
                count = str(header.count) if header.count is not None else "unknown"
                lines.append(
                    "    %s: %s (count=%s, source=%s, merged=%s)"
                    % (
                        _escape(header.name),
                        _escape(header.value),
                        count,
                        header.source,
                        header.merged,
                    )
                )
        else:
            lines.append("  headers: none approved")

        return "\n".join(lines)

    def __repr__(self):
        return "<RequestSummary %s %s stage=%s>" % (
            _escape(self.method),
            _escape(self.path),
            _escape(self.stage),
        )


def _normalize_approved(approved_headers):
    if approved_headers is None:
        raise TypeError("approved_headers is required; pass the header names to expose")

    if isinstance(approved_headers, str):
        approved_headers = [approved_headers]

    names = []

    for name in approved_headers:
        name = _validate_header_name(name)
        lowered = name.lower()

        if lowered not in names:
            names.append(lowered)

    return tuple(sorted(names))


def _headers_from_environ(environ_headers, approved):
    approved_set = set(approved)
    headers = []

    for name, value in environ_headers.items():
        lowered = name.lower()

        if lowered not in approved_set:
            continue

        try:
            name = _validate_header_name(name)
        except (TypeError, ValueError):
            continue

        headers.append(_make_header(name, (value,), SOURCE_ENVIRON, None, True))

    return tuple(sorted(headers, key=lambda header: header.name.lower()))


def _headers_from_raw(raw_headers, approved):
    approved_set = set(approved)

    if isinstance(raw_headers, Mapping):
        raw_headers = _mapping_to_pairs(raw_headers)

    grouped = {}
    names = {}

    for item in raw_headers:
        try:
            name, value = item
        except (TypeError, ValueError):
            raise TypeError("raw_headers must be mappings or (name, value) pairs")

        name = _validate_header_name(name)
        lowered = name.lower()

        if lowered not in approved_set:
            continue

        grouped.setdefault(lowered, []).append(value)
        names.setdefault(lowered, name)

    headers = []

    for lowered, values in grouped.items():
        headers.append(
            _make_header(
                names[lowered],
                tuple(values),
                SOURCE_RAW,
                len(values),
                False,
            )
        )

    return tuple(sorted(headers, key=lambda header: header.name.lower()))


def _mapping_to_pairs(mapping):
    for name, value in mapping.items():
        if isinstance(value, (list, tuple)):
            for item in value:
                yield name, item
        else:
            yield name, value


def _query_parameter_names(request):
    """Return query parameter names only; values may contain credentials."""
    source = request.environ.get("QUERY_STRING", "")

    if not source:
        return ()

    names = []

    for part in source.split("&"):
        if not part:
            continue

        raw_name = part.split("=", 1)[0]

        try:
            name = unquote_plus(raw_name, errors="replace")
        except (TypeError, ValueError):
            continue

        if name and name not in names:
            names.append(name)

    return tuple(names)


def _request_path(request):
    try:
        return str(request.path)
    except KeyError:
        return str(request.environ.get("PATH_INFO", ""))


def _validate_header_name(name):
    if not isinstance(name, str):
        raise TypeError("raw header names must be strings")

    name = name.strip()

    if not name:
        raise ValueError("raw header names must not be empty")

    if any(char in name for char in "\r\n:"):
        raise ValueError("raw header names must not contain CR, LF or ':'")

    return name


def _make_header(name, values, source, count, merged):
    values = tuple(_header_text(value) for value in values)
    redacted = name.lower() in PROTECTED_HEADERS

    if redacted:
        values = (REDACTED,)

    return HeaderSummary(
        name=name,
        values=values,
        source=source,
        count=count,
        merged=merged,
        redacted=redacted,
    )


def _body_status(request, content_length, body_position=None):
    if content_length == 0:
        return "empty"

    if not request.is_body_readable:
        if content_length is not None:
            return "not-readable"

        return "unknown"

    position = body_position

    if position is None:
        # The stream cannot report its position, so neither "unread" nor
        # "read-started" can be proven.
        return "unknown"

    if position == 0:
        return "unread"

    # The underlying stream may have been advanced by buffering even when
    # the application has not consumed everything yet, so only claim that
    # reading has started.
    return "read-started"


def _body_position(request):
    try:
        raw = request.body_file_raw
        tell = raw.tell
    except (AttributeError, KeyError):
        return None

    try:
        return tell()
    except (OSError, TypeError, ValueError):
        return None


def _header_text(value):
    if isinstance(value, bytes):
        return value.decode("latin-1")

    return str(value)


def _escape(value):
    return value.replace("\r", "\\r").replace("\n", "\\n")
