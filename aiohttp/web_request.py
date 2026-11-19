import asyncio
import copy
import datetime
import re
import string
import types
from collections.abc import Iterator, Mapping, MutableMapping
from re import Pattern
from tempfile import SpooledTemporaryFile
from types import MappingProxyType
from typing import (
    IO,
    TYPE_CHECKING,
    Any,
    Final,
    Self,
    TypedDict,
    TypeVar,
    cast,
    overload,
)

from multidict import CIMultiDict, MultiDict, MultiDictProxy
from yarl import URL, query_to_pairs

from . import hdrs
from ._cookie_helpers import parse_cookie_header
from .abc import AbstractStreamWriter
from .helpers import (
    _SENTINEL,
    DEFAULT_CHUNK_SIZE,
    ETAG_ANY,
    LIST_QUOTED_ETAG_RE,
    QUOTED_ETAG_RE,
    ChainMapProxy,
    ETag,
    HeadersDictProxy,
    HeadersMixin,
    RequestKey,
    frozen_dataclass_decorator,
    is_expected_content_type,
    parse_http_date,
    reify,
    sentinel,
    set_exception,
)
from .http_parser import RawRequestMessage
from .http_writer import HttpVersion
from .multipart import BodyPartReader, MultipartReader
from .streams import EmptyStreamReader, StreamReader
from .typedefs import (
    DEFAULT_JSON_DECODER,
    JSONDecoder,
    LooseHeaders,
    RawHeaders,
    StrOrURL,
)
from .web_exceptions import (
    HTTPBadRequest,
    HTTPRequestEntityTooLarge,
    HTTPUnsupportedMediaType,
)
from .web_response import StreamResponse

__all__ = ("BaseRequest", "FileField", "Request")


if TYPE_CHECKING:
    from .web_app import Application
    from .web_protocol import RequestHandler
    from .web_urldispatcher import UrlMappingMatchInfo


_T = TypeVar("_T")


class _CloneKwargs(TypedDict, total=False):
    scheme: str | None
    host: str | None
    remote: str | None


# Multipart file parts are buffered in memory and only spilled to a temporary
# file once they outgrow this size. A temp file per part would let a body made
# of many tiny parts exhaust the process's file descriptors; spooling bounds
# that at ``client_max_size // _FILE_SPOOL_MAX_SIZE`` descriptors per request.
_FILE_SPOOL_MAX_SIZE: Final[int] = 1024**2


@frozen_dataclass_decorator
class FileField:
    name: str
    filename: str
    file: IO[bytes]
    content_type: str
    headers: HeadersDictProxy


_TCHAR: Final[str] = string.digits + string.ascii_letters + r"!#$%&'*+.^_`|~-"
# '-' at the end to prevent interpretation as range in a char class

_TOKEN: Final[str] = rf"[{_TCHAR}]+"

_QDTEXT: Final[str] = r"[{}]".format(
    r"".join(chr(c) for c in (0x09, 0x20, 0x21) + tuple(range(0x23, 0x7F)))
)
# qdtext includes 0x5C to escape 0x5D ('\]')
# qdtext excludes obs-text (because obsoleted, and encoding not specified)

# This does not have a ReDOS/performance concern as long as it used with re.match().
_FORWARDED_PAIR: Final[str] = (
    rf'[ \t]*({_TOKEN})=({_TOKEN}|".*")(:\d{{1,4}})?[ \t]*(?:\Z|;)'
)
_FORWARDED_PAIR_RE: Final[Pattern[str]] = re.compile(_FORWARDED_PAIR)

############################################################
# HTTP Request
############################################################


def _too_many_fields(max_fields: int) -> HTTPRequestEntityTooLarge:
    return HTTPRequestEntityTooLarge(
        max_fields, text=f"Maximum number of form fields {max_fields} exceeded."
    )


def _with_authority(url: URL, authority: str) -> URL:
    """Replace *url*'s authority, keeping its path, query, userinfo and fragment.

    The new authority is parsed (``host:port``, bracketed IPv6, punycode) and
    normalised for *url*'s scheme, so a default port is elided exactly as it
    would be in a URL built from the same components.
    """
    parsed = URL.build(scheme=url.scheme, authority=authority)
    rewritten = url.with_host(parsed.raw_host)
    return rewritten.with_port(parsed.explicit_port)


def _copy_headers(headers: LooseHeaders | HeadersDictProxy) -> HeadersDictProxy:
    """Return an independent header mapping.

    ``HeadersDictProxy`` is a read-only view over a mutable ``CIMultiDict``;
    a clone must not let its own header handling observe or change the
    original request's mapping.  Copying the underlying multidict keeps
    repeated headers (``Cookie``, ``Forwarded``, ...) separate, which
    rebuilding through the mapping interface would merge.
    """
    if isinstance(headers, HeadersDictProxy):
        return HeadersDictProxy(CIMultiDict(headers._md))
    return HeadersDictProxy(CIMultiDict(headers))


class BaseRequest(MutableMapping[str | RequestKey[Any], Any], HeadersMixin):
    POST_METHODS = {
        hdrs.METH_PATCH,
        hdrs.METH_POST,
        hdrs.METH_PUT,
        hdrs.METH_TRACE,
        hdrs.METH_DELETE,
    }

    _post: MultiDictProxy[str | bytes | FileField] | None = None
    _read_bytes: bytes | None = None
    # True once the body stream has been drained or handed to a consumer
    # (``read()``, ``post()``, ``multipart()``): a clone then cannot promise
    # the recipient the same body, so it is refused.
    _body_consumed: bool = False
    _pre_handler_error: HTTPBadRequest | None = None
    # Trusted values supplied by the code that created this request (the
    # protocol, or an explicit clone(scheme=/host=/remote=...)).  They are
    # kept apart from the reified ``_cache`` so a derived clone can carry them
    # into a fresh generation instead of falling back to transport/headers.
    _scheme_override: str | None = None
    _host_override: str | None = None
    _remote_override: str | None = None

    def __init__(
        self,
        message: RawRequestMessage,
        payload: StreamReader,
        protocol: "RequestHandler[Self]",
        payload_writer: AbstractStreamWriter,
        task: "asyncio.Task[None]",
        loop: asyncio.AbstractEventLoop,
        *,
        client_max_size: int = 1024**2,
        client_max_fields: int = 1000,
        state: dict[RequestKey[Any] | str, Any] | None = None,
        scheme: str | None = None,
        host: str | None = None,
        remote: str | None = None,
        pre_handler_error: HTTPBadRequest | None = None,
    ) -> None:
        self._message = message
        self._protocol = protocol
        self._payload_writer = payload_writer
        if pre_handler_error is not None:
            self._pre_handler_error = pre_handler_error

        self._payload = payload
        self._headers: HeadersDictProxy = message.headers
        self._method = message.method
        self._version = message.version
        self._cache: dict[str, Any] = {}
        url = message.url
        if url.absolute:
            if scheme is None and url.scheme:
                # Absolute URL is peer-controlled, use the protocol.
                scheme = "https" if protocol.ssl_context else "http"
            if scheme is not None:
                # Authority-form (CONNECT) has no scheme: leave the target
                # unchanged unless clone(scheme=...) overrides it.
                url = url.with_scheme(scheme)
                self._cache["scheme"] = scheme
            if host is not None:
                url = _with_authority(url, host)
            # absolute URL is given,
            # override auto-calculating url, host, and scheme
            # all other properties should be good
            self._cache["url"] = url
            self._cache["host"] = url.host_port_subcomponent
            self._rel_url = url.relative()
        else:
            self._rel_url = url
            if scheme is not None:
                self._cache["scheme"] = scheme
            if host is not None:
                self._cache["host"] = host

        self._state = {} if state is None else state
        self._task = task
        self._client_max_size = client_max_size
        self._client_max_fields = client_max_fields
        self._loop = loop

        self._transport_sslcontext = protocol.ssl_context
        self._transport_peername = protocol.peername
        self._transport_sockname = protocol.sockname

        self._scheme_override = scheme
        self._host_override = host
        if remote is not None:
            self._remote_override = remote
            self._cache["remote"] = remote

    def clone(
        self,
        *,
        method: str | _SENTINEL = sentinel,
        rel_url: StrOrURL | _SENTINEL = sentinel,
        headers: LooseHeaders | _SENTINEL = sentinel,
        scheme: str | _SENTINEL = sentinel,
        host: str | _SENTINEL = sentinel,
        remote: str | _SENTINEL = sentinel,
        client_max_size: int | _SENTINEL = sentinel,
        client_max_fields: int | _SENTINEL = sentinel,
    ) -> "BaseRequest":
        """Clone itself with replacement some attributes.

        Creates and returns a new instance of Request object. If no parameters
        are given, an exact copy is returned. If a parameter is not passed, it
        will reuse the one from the current request object.

        Derived properties (``url``, ``host``, ``scheme``, ``secure``,
        ``path``, ``query``, ...) are recomputed for the clone; the original
        request keeps its own state.  Trusted ``scheme``/``host``/``remote``
        overrides are inherited by the clone, so chaining ``clone()`` calls
        cannot fall back to peer-controlled headers or the transport.
        """
        if self._body_consumed:
            raise RuntimeError("Cannot clone request after reading its content")

        dct: dict[str, Any] = {}
        if method is not sentinel:
            dct["method"] = method
        # Whether the caller supplied a target that carries its own authority
        # (scheme://host or //host).  Such a target wins over any inherited
        # trusted override, while a plain path must keep the request's
        # effective authority.
        explicit_target = False
        new_url: URL | None = None
        if rel_url is not sentinel:
            new_url = URL(rel_url)
            explicit_target = new_url.absolute
            if not explicit_target and self._message.url.absolute:
                # An absolute-form (or CONNECT authority-form) target carries
                # the authority the client addressed; the Host header is
                # ignored for it.  Joining keeps that authority so the clone
                # cannot combine a peer-controlled Host header with the new
                # path and fabricate a request that was never sent.
                new_url = self._message.url.join(new_url)
            dct["url"] = new_url
            dct["path"] = str(new_url)

        # Always give the clone an independent header structure.  Even without
        # an explicit replacement its header-backed properties (Host, Cookie,
        # Content-Type, ...) must not observe mutations of the original.
        new_headers = _copy_headers(
            headers if headers is not sentinel else self._message.headers
        )
        dct["headers"] = new_headers
        if headers is not sentinel:
            dct["raw_headers"] = tuple(
                (k.encode("utf-8"), v.encode("utf-8"))
                for k, v in new_headers._md.items()
            )

        message = self._message._replace(**dct)

        kwargs: _CloneKwargs = {}
        if scheme is not sentinel:
            kwargs["scheme"] = scheme
        elif explicit_target and new_url is not None and new_url.scheme:
            # The replacement target names its own scheme and authority; it
            # wins over an inherited trusted override.
            kwargs["scheme"] = new_url.scheme
        else:
            kwargs["scheme"] = self._scheme_override
        if host is not sentinel:
            kwargs["host"] = host
        elif explicit_target:
            kwargs["host"] = None
        else:
            kwargs["host"] = self._host_override
        kwargs["remote"] = (
            remote if remote is not sentinel else self._remote_override
        )
        if client_max_size is sentinel:
            client_max_size = self._client_max_size
        if client_max_fields is sentinel:
            client_max_fields = self._client_max_fields

        clone = self.__class__(
            message,
            self._payload,
            self._protocol,  # type: ignore[arg-type]
            self._payload_writer,
            self._task,
            self._loop,
            client_max_size=client_max_size,
            client_max_fields=client_max_fields,
            state=self._state.copy(),
            pre_handler_error=self._pre_handler_error,
            **kwargs,
        )
        # ``post()`` can resolve to an empty, immutable mapping without
        # touching the stream (e.g. a GET or a non-form content type).  That
        # derived result is safe to reuse; any path that actually consumes
        # the body marks it consumed and is refused above.
        if self._post is not None:
            clone._post = self._post
        return clone

    @property
    def task(self) -> "asyncio.Task[None]":
        return self._task

    @property
    def protocol(self) -> "RequestHandler[Self]":
        return self._protocol

    @property
    def transport(self) -> asyncio.Transport | None:
        return self._protocol.transport

    @property
    def writer(self) -> AbstractStreamWriter:
        return self._payload_writer

    @property
    def client_max_size(self) -> int:
        return self._client_max_size

    @property
    def client_max_fields(self) -> int:
        return self._client_max_fields

    @property
    def pre_handler_error(self) -> HTTPBadRequest | None:
        return self._pre_handler_error

    @reify
    def rel_url(self) -> URL:
        return self._rel_url

    # MutableMapping API

    @overload
    def __getitem__(self, key: RequestKey[_T]) -> _T: ...

    @overload
    def __getitem__(self, key: str) -> Any: ...

    def __getitem__(self, key: str | RequestKey[_T]) -> Any:
        return self._state[key]

    @overload
    def __setitem__(self, key: RequestKey[_T], value: _T) -> None: ...

    @overload
    def __setitem__(self, key: str, value: Any) -> None: ...

    def __setitem__(self, key: str | RequestKey[_T], value: Any) -> None:
        self._state[key] = value

    def __delitem__(self, key: str | RequestKey[_T]) -> None:
        del self._state[key]

    def __len__(self) -> int:
        return len(self._state)

    def __iter__(self) -> Iterator[str | RequestKey[Any]]:
        return iter(self._state)

    ########

    @reify
    def secure(self) -> bool:
        """A bool indicating if the request is handled with SSL."""
        return self.scheme == "https"

    @reify
    def forwarded(self) -> tuple[Mapping[str, str], ...]:
        """A tuple containing all parsed Forwarded header(s).

        Makes an effort to parse Forwarded headers as specified by RFC 7239:

        - It adds one (immutable) dictionary per Forwarded 'field-value', ie
          per proxy. The element corresponds to the data in the Forwarded
          field-value added by the first proxy encountered by the client. Each
          subsequent item corresponds to those added by later proxies.
        - It checks that every value has valid syntax in general as specified
          in section 4: either a 'token' or a 'quoted-string'.
        - It un-escapes found escape sequences.
        - It does NOT validate 'by' and 'for' contents as specified in section
          6.
        - It does NOT validate 'host' contents (Host ABNF).
        - It does NOT validate 'proto' contents for valid URI scheme names.

        Returns a tuple containing one or more immutable dicts
        """
        elems = []
        for field_value in self._message.headers.getall(hdrs.FORWARDED):
            pos = 0
            elem: dict[str, str] = {}
            elems.append(types.MappingProxyType(elem))
            while 0 <= pos < len(field_value):
                match = _FORWARDED_PAIR_RE.match(field_value, pos)
                if match is not None:  # got a valid forwarded-pair
                    name, value, port = match.groups()
                    if value[0] == value[-1] == '"':
                        value = value[1:-1]
                    if port:
                        value += port
                    elem[name.lower()] = value
                    pos += len(match.group(0))
                elif (semi := field_value.find(";", pos)) == -1:
                    # No further pair to parse; a trailing empty or malformed
                    # value ends this field-value.
                    break
                elif not field_value[pos:semi].strip(" \t"):
                    # Empty value
                    pos = semi + 1
                else:
                    # bad syntax here, skip to next field value
                    break
        return tuple(elems)

    @reify
    def scheme(self) -> str:
        """A string representing the scheme of the request.

        Hostname is resolved in this order:

        - overridden value by .clone(scheme=new_scheme) call.
        - type of connection to peer: HTTPS if socket is SSL, HTTP otherwise.

        'http' or 'https'.
        """
        if self._transport_sslcontext:
            return "https"
        else:
            return "http"

    @reify
    def method(self) -> str:
        """Read only property for getting HTTP method.

        The value is upper-cased str like 'GET', 'POST', 'PUT' etc.
        """
        return self._method

    @reify
    def version(self) -> HttpVersion:
        """Read only property for getting HTTP version of request.

        Returns aiohttp.protocol.HttpVersion instance.
        """
        return self._version

    @reify
    def host(self) -> str:
        """Hostname of the request.

        Hostname is resolved in this order:

        - overridden value by .clone(host=new_host) call.
        - host of the request-target, if the target is in absolute or
          authority form (the Host header is ignored then, per
          :rfc:`9112#section-3.2.2-8`); a non-default port is included.
        - HOST HTTP header
        - local socket address the request arrived on
          (transport ``sockname``)
        - empty string if no transport information is available

        For example, 'example.com' or 'localhost:8080'.

        For historical reasons, the port number may be included.
        """
        host = self._message.headers.get(hdrs.HOST)
        if host is not None:
            return host
        sockname = self._transport_sockname
        if sockname is None:
            return ""
        if isinstance(sockname, tuple):
            # AF_INET6 returns a 4-tuple (host, port, flowinfo, scopeid);
            # bracket the bare address so it matches the Host-header shape
            # and is a valid URL authority component.
            if len(sockname) == 4:
                return f"[{sockname[0]}]"
            return str(sockname[0])
        return str(sockname)

    @reify
    def remote(self) -> str | None:
        """Remote IP of client initiated HTTP request.

        The IP is resolved in this order:

        - overridden value by .clone(remote=new_remote) call.
        - peername of opened socket
        """
        if self._transport_peername is None:
            return None
        if isinstance(self._transport_peername, (list, tuple)):
            return str(self._transport_peername[0])
        return str(self._transport_peername)

    @reify
    def url(self) -> URL:
        """The full URL of the request."""
        # authority is used here because it may include the port number
        # and we want yarl to parse it correctly
        return URL.build(scheme=self.scheme, authority=self.host).join(self._rel_url)

    @reify
    def path(self) -> str:
        """The URL including *PATH INFO* without the host or scheme.

        E.g., ``/app/blog``
        """
        return self._rel_url.path

    @reify
    def path_qs(self) -> str:
        """The URL including PATH_INFO and the query string.

        E.g, /app/blog?id=10
        """
        return str(self._rel_url)

    @reify
    def raw_path(self) -> str:
        """The URL including raw *PATH INFO* without the host or scheme.

        Warning, the path is unquoted and may contains non valid URL characters

        E.g., ``/my%2Fpath%7Cwith%21some%25strange%24characters``
        """
        path = self._message.path

        # An absolute-form target carries a "scheme://authority" that must not
        # leak into the path. Strip it, keeping the remainder byte-for-byte,
        # exactly as an origin-form target. Authority-form is used only by
        # CONNECT and is left unchanged.
        # https://www.rfc-editor.org/info/rfc9112/#section-3.2.2-9
        # https://www.rfc-editor.org/info/rfc9112/#name-authority-form
        if self._message.url.absolute and self._method != "CONNECT":
            # absolute-form always contains "://" (guaranteed by the parser).
            scheme_sep = path.find("://")
            assert scheme_sep != -1
            cursor = scheme_sep + 3
            rel = len(path)
            for delimiter in "/?#":
                found = path.find(delimiter, cursor)
                if found != -1:
                    rel = min(rel, found)
            return path[rel:]
        return path

    @reify
    def query(self) -> MultiDictProxy[str]:
        """A multidict with all the variables in the query string."""
        return self._rel_url.query

    @reify
    def query_string(self) -> str:
        """The query string in the URL.

        E.g., id=10
        """
        return self._rel_url.query_string

    @reify
    def headers(self) -> HeadersDictProxy:
        """A case-insensitive multidict proxy with all headers."""
        return self._headers

    @reify
    def raw_headers(self) -> RawHeaders:
        """A sequence of pairs for all headers."""
        return self._message.raw_headers

    @reify
    def if_modified_since(self) -> datetime.datetime | None:
        """The value of If-Modified-Since HTTP header, or None.

        This header is represented as a `datetime` object.
        """
        return parse_http_date(self.headers.get(hdrs.IF_MODIFIED_SINCE))

    @reify
    def if_unmodified_since(self) -> datetime.datetime | None:
        """The value of If-Unmodified-Since HTTP header, or None.

        This header is represented as a `datetime` object.
        """
        return parse_http_date(self.headers.get(hdrs.IF_UNMODIFIED_SINCE))

    @staticmethod
    def _etag_values(etag_header: str) -> Iterator[ETag]:
        """Extract `ETag` objects from raw header."""
        if etag_header == ETAG_ANY:
            yield ETag(
                is_weak=False,
                value=ETAG_ANY,
            )
        else:
            for match in LIST_QUOTED_ETAG_RE.finditer(etag_header):
                is_weak, value, garbage = match.group(2, 3, 4)
                # Any symbol captured by 4th group means
                # that the following sequence is invalid.
                if garbage:
                    break

                yield ETag(
                    is_weak=bool(is_weak),
                    value=value,
                )

    @classmethod
    def _if_match_or_none_impl(
        cls, header_value: str | None
    ) -> tuple[ETag, ...] | None:
        if not header_value:
            return None

        return tuple(cls._etag_values(header_value))

    @reify
    def if_match(self) -> tuple[ETag, ...] | None:
        """The value of If-Match HTTP header, or None.

        This header is represented as a `tuple` of `ETag` objects.
        """
        return self._if_match_or_none_impl(self.headers.get(hdrs.IF_MATCH))

    @reify
    def if_none_match(self) -> tuple[ETag, ...] | None:
        """The value of If-None-Match HTTP header, or None.

        This header is represented as a `tuple` of `ETag` objects.
        """
        return self._if_match_or_none_impl(self.headers.get(hdrs.IF_NONE_MATCH))

    @reify
    def if_range(self) -> datetime.datetime | ETag | None:
        """The value of If-Range HTTP header, or None.

        This header is represented as a `datetime` (HTTP-date form) or an
        `ETag` (entity-tag form) object.
        """
        if_range = self.headers.get(hdrs.IF_RANGE)
        if if_range is None:
            return None
        if (date := parse_http_date(if_range)) is not None:
            return date
        match = QUOTED_ETAG_RE.fullmatch(if_range.strip())
        if match is None:
            return None
        return ETag(is_weak=bool(match.group(1)), value=match.group(2))

    @reify
    def keep_alive(self) -> bool:
        """Is keepalive enabled by client?"""
        return not self._message.should_close

    @reify
    def cookies(self) -> Mapping[str, str]:
        """Return request cookies.

        A read-only dictionary-like object.
        """
        # Use parse_cookie_header for RFC 6265 compliant Cookie header parsing
        # that accepts special characters in cookie names (fixes #2683)
        parsed = parse_cookie_header(self.headers.get(hdrs.COOKIE, ""))
        # Extract values from Morsel objects
        return MappingProxyType({name: morsel.value for name, morsel in parsed})

    @reify
    def http_range(self) -> "slice[int, int, int]":
        """The content of Range HTTP header.

        Return a slice instance.

        """
        rng = self._headers.get(hdrs.RANGE)
        start, end = None, None
        if rng is not None:
            try:
                pattern = r"^bytes=(\d*)-(\d*)$"
                # https://www.rfc-editor.org/info/rfc9110/#section-14.1-4
                start, end = re.findall(pattern, rng, re.ASCII | re.IGNORECASE)[0]
            except IndexError:  # pattern was not found in header
                raise ValueError("range not in acceptable format")

            end = int(end) if end else None
            start = int(start) if start else None

            if start is None and end is not None:
                # end with no start is to return tail of content
                start = -end
                end = None

            if start is not None and end is not None:
                # end is inclusive in range header, exclusive for slice
                end += 1

                if start >= end:
                    raise ValueError("start cannot be after end")

            if start is end is None:  # No valid range supplied
                raise ValueError("No start or end of range specified")

        return slice(start, end, 1)

    @reify
    def content(self) -> StreamReader:
        """Return raw payload stream."""
        return self._payload

    @property
    def can_read_body(self) -> bool:
        """Return True if request's HTTP BODY can be read, False otherwise."""
        return not self._payload.at_eof()

    @reify
    def body_exists(self) -> bool:
        """Return True if request has HTTP BODY, False otherwise."""
        return type(self._payload) is not EmptyStreamReader

    async def release(self) -> None:
        """Release request.

        Eat unread part of HTTP BODY if present.
        """
        while not self._payload.at_eof():
            await self._payload.readany()

    async def read(self) -> bytes:
        """Read request body if present.

        Returns bytes object with full request content.
        """
        if self._read_bytes is None:
            self._body_consumed = True
            # Raise the buffer limits so compressed payloads decompress in
            # larger chunks instead of many small pause/resume cycles.
            if self._client_max_size:
                self._payload.set_read_chunk_size(self._client_max_size)
            body = bytearray()
            while True:
                chunk = await self._payload.readany()
                body.extend(chunk)
                if self._client_max_size:
                    body_size = len(body)
                    if body_size > self._client_max_size:
                        raise HTTPRequestEntityTooLarge(self._client_max_size)
                if not chunk:
                    break
            self._read_bytes = bytes(body)
        return self._read_bytes

    async def text(self) -> str:
        """Return BODY as text using encoding from .charset."""
        bytes_body = await self.read()
        encoding = self.charset or "utf-8"
        try:
            return bytes_body.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            raise HTTPUnsupportedMediaType()

    async def json(
        self,
        *,
        loads: JSONDecoder = DEFAULT_JSON_DECODER,
        content_type: str | None = "application/json",
    ) -> Any:
        """Return BODY as JSON."""
        body = await self.text()
        if content_type:
            if not is_expected_content_type(self.content_type, content_type):
                raise HTTPBadRequest(
                    text=(
                        "Attempt to decode JSON with "
                        "unexpected mimetype: %s" % self.content_type
                    )
                )

        return loads(body)

    async def multipart(self) -> MultipartReader:
        """Return async iterator to process BODY as multipart."""
        self._body_consumed = True
        return MultipartReader(
            self._headers,
            self._payload,
            client_max_size=self._client_max_size,
            max_field_size=self._protocol.max_field_size,
            max_headers=self._protocol.max_headers,
            max_size_error_cls=HTTPRequestEntityTooLarge,
        )

    async def post(self) -> "MultiDictProxy[str | bytes | FileField]":
        """Return POST parameters."""
        if self._post is not None:
            return self._post
        if self._method not in self.POST_METHODS:
            self._post = MultiDictProxy(MultiDict())
            return self._post

        content_type = self.content_type
        if content_type not in (
            "",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        ):
            self._post = MultiDictProxy(MultiDict())
            return self._post

        out: MultiDict[str | bytes | FileField]

        if content_type == "multipart/form-data":
            out = MultiDict()
            multipart = await self.multipart()
            max_size = self._client_max_size
            max_fields = self._client_max_fields

            payload = self._payload
            while (field := await multipart.next()) is not None:
                # This check is needed for empty payloads, which still add
                # overhead without entering the loop and the check below.
                if 0 < max_size < payload.total_bytes:
                    raise HTTPRequestEntityTooLarge(max_size)
                if 0 < max_fields <= len(out):
                    raise _too_many_fields(max_fields)

                field_ct = field.headers.get(hdrs.CONTENT_TYPE)

                if isinstance(field, BodyPartReader):
                    if field.name is None:
                        raise ValueError("Multipart field missing name.")

                    # Note that according to RFC 7578, the Content-Type header
                    # is optional, even for files, so we can't assume it's
                    # present.
                    # https://tools.ietf.org/html/rfc7578#section-4.4
                    if field.filename:
                        tmp = SpooledTemporaryFile(_FILE_SPOOL_MAX_SIZE)
                        # rolled means the temp file now uses the disk, at
                        # which point we want to run in the executor.
                        rolled = False
                        while chunk := await field.read_chunk(size=DEFAULT_CHUNK_SIZE):
                            # Bounds one part, mid-read.
                            if 0 < max_size < payload.total_bytes:
                                if rolled:
                                    await self._loop.run_in_executor(None, tmp.close)
                                else:
                                    tmp.close()
                                raise HTTPRequestEntityTooLarge(max_size)
                            async for decoded_chunk in field.decode_iter(chunk):
                                # Update before writing, so we know if next
                                # write is going to hit the disk.
                                rolled = rolled or (
                                    tmp.tell() + len(decoded_chunk)
                                    > _FILE_SPOOL_MAX_SIZE
                                )
                                if rolled:
                                    await self._loop.run_in_executor(
                                        None, tmp.write, decoded_chunk
                                    )
                                else:
                                    tmp.write(decoded_chunk)
                        if rolled:
                            await self._loop.run_in_executor(None, tmp.seek, 0)
                        else:
                            tmp.seek(0)

                        if field_ct is None:
                            field_ct = "application/octet-stream"

                        ff = FileField(
                            field.name,
                            field.filename,
                            tmp,
                            field_ct,
                            field.headers,
                        )
                        out.add(field.name, ff)
                    else:
                        # deal with ordinary data
                        raw_data = bytearray()
                        while chunk := await field.read_chunk():
                            if 0 < max_size < payload.total_bytes:
                                raise HTTPRequestEntityTooLarge(max_size)
                            raw_data.extend(chunk)

                        value = bytearray()
                        # form-data doesn't support compression, so don't need to check size again.
                        async for d in field.decode_iter(raw_data):  # type: ignore[arg-type]
                            value.extend(d)

                        if field_ct is None or field_ct.startswith("text/"):
                            charset = field.get_charset(default="utf-8")
                            try:
                                decoded = value.decode(charset)
                            except (LookupError, UnicodeDecodeError):
                                raise HTTPUnsupportedMediaType()
                            out.add(field.name, decoded)
                        else:
                            out.add(field.name, value)  # type: ignore[arg-type]
                else:
                    raise ValueError(
                        "To decode nested multipart you need to use custom reader",
                    )
        elif not (data := await self.read()):
            out = MultiDict()
        else:
            charset = self.charset or "utf-8"
            bytes_query = data.rstrip()
            try:
                query = bytes_query.decode(charset)
            except (LookupError, UnicodeDecodeError):
                raise HTTPUnsupportedMediaType()
            max_fields = self._client_max_fields
            try:
                out = MultiDict(
                    query_to_pairs(
                        query,
                        max_fields=max_fields if max_fields > 0 else None,
                        encoding=charset,
                    )
                )
            except ValueError:
                raise _too_many_fields(max_fields) from None

        self._post = MultiDictProxy(out)
        return self._post

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        """Extra info from protocol transport"""
        transport = self._protocol.transport
        if transport is None:
            return default

        return transport.get_extra_info(name, default)

    def __repr__(self) -> str:
        ascii_encodable_path = self.path.encode("ascii", "backslashreplace").decode(
            "ascii"
        )
        return f"<{self.__class__.__name__} {self._method} {ascii_encodable_path} >"

    def __eq__(self, other: object) -> bool:
        return id(self) == id(other)

    def __bool__(self) -> bool:
        return True

    async def _prepare_hook(self, response: StreamResponse) -> None:
        return

    def _cancel(self, exc: BaseException) -> None:
        set_exception(self._payload, exc)

    def _finish(self) -> None:
        if self._post is None or self.content_type != "multipart/form-data":
            return

        # Release the temp files created within multipart request body.
        for file_name, file_field_object in self._post.items():
            if isinstance(file_field_object, FileField):
                file_field_object.file.close()


class Request(BaseRequest):

    _match_info: "UrlMappingMatchInfo | None" = None

    def clone(
        self,
        *,
        method: str | _SENTINEL = sentinel,
        rel_url: StrOrURL | _SENTINEL = sentinel,
        headers: LooseHeaders | _SENTINEL = sentinel,
        scheme: str | _SENTINEL = sentinel,
        host: str | _SENTINEL = sentinel,
        remote: str | _SENTINEL = sentinel,
        client_max_size: int | _SENTINEL = sentinel,
        client_max_fields: int | _SENTINEL = sentinel,
    ) -> "Request":
        ret = super().clone(
            method=method,
            rel_url=rel_url,
            headers=headers,
            scheme=scheme,
            host=host,
            remote=remote,
            client_max_size=client_max_size,
            client_max_fields=client_max_fields,
        )
        new_ret = cast(Request, ret)
        match_info = self._match_info
        # A clone gets its own route state generation.  ``_apps`` and
        # ``current_app`` are mutated while a request is handled, so sharing
        # the object would let proxy handling of the clone (or its route
        # resolution) rewrite the original request's routing.
        new_ret._match_info = None if match_info is None else copy.copy(match_info)
        return new_ret

    @reify
    def match_info(self) -> "UrlMappingMatchInfo":
        """Result of route resolving."""
        match_info = self._match_info
        assert match_info is not None
        return match_info

    @property
    def app(self) -> "Application":
        """Application instance."""
        match_info = self._match_info
        assert match_info is not None
        return match_info.current_app

    @property
    def config_dict(self) -> ChainMapProxy:
        match_info = self._match_info
        assert match_info is not None
        lst = match_info.apps
        app = self.app
        idx = lst.index(app)
        sublist = list(reversed(lst[: idx + 1]))
        return ChainMapProxy(sublist)

    async def _prepare_hook(self, response: StreamResponse) -> None:
        match_info = self._match_info
        assert match_info is not None
        for app in match_info._apps:
            if on_response_prepare := app.on_response_prepare:
                await on_response_prepare.send(self, response)
