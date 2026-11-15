"""
restricted_early_hints.py
~~~~~~~~~~~~~~~~~~~~~~~~~

A restricted consumer for HTTP/2 ``103 Early Hints``.

The important security rule in this example is that a ``103`` response is a
*hint*, never an authorization decision.  Receiving a hint can only cause a
credentialless fetch into a per-request quarantine.  Those bytes become a
user-readable cache entry only after the final response for the same stream
grants access and permits shared caching.

Run this file directly for a demonstration built from real hyper-h2 frames::

    python examples/early_hints/restricted_early_hints.py
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from urllib.parse import SplitResult, unquote, urljoin, urlsplit

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.events import (
    ConnectionTerminated,
    InformationalResponseReceived,
    ResponseReceived,
    StreamEnded,
    StreamReset,
)

_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_DEFAULT_PORTS = {"http": 80, "https": 443}


# ---------------------------------------------------------------------------
# A deliberately small, strict Link header parser.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Link:
    """One reliably parsed ``Link`` header value."""

    target: str
    params: dict[str, str]


class _MalformedLinkError(ValueError):
    pass


def _split_quoted(value: str, separator: str) -> list[str]:
    """
    Split on *separator* outside angle brackets and quoted strings.

    A header containing an unterminated quote, angle bracket, or bad escape is
    rejected as a whole.  Guessing at a damaged field is exactly how a proxy
    and an origin end up disagreeing about which URL was requested.  Inside a
    quoted string only the quote and backslash are special; characters such as
    ``<`` and ``>`` are ordinary data there.
    """
    parts: list[str] = []
    start = 0
    in_angle = False
    in_quote = False
    escaped = False

    for index, char in enumerate(value):
        if char in "\r\n\0":
            raise _MalformedLinkError
        if in_quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_quote = False
            continue
        if char == '"':
            if in_angle:
                raise _MalformedLinkError
            in_quote = True
            continue
        if char == "<":
            if in_angle:
                raise _MalformedLinkError
            in_angle = True
            continue
        if char == ">":
            if not in_angle:
                raise _MalformedLinkError
            in_angle = False
            continue
        if char == separator and not in_angle:
            parts.append(value[start:index])
            start = index + 1

    if in_angle or in_quote or escaped:
        raise _MalformedLinkError
    parts.append(value[start:])
    return parts


def _unquote(value: str) -> str:
    if len(value) < 2 or value[0] != '"':
        raise _MalformedLinkError
    result: list[str] = []
    escaped = False
    for index in range(1, len(value)):
        char = value[index]
        if escaped:
            result.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            if index != len(value) - 1:
                raise _MalformedLinkError
            return "".join(result)
        elif ord(char) < 0x20 and char != "\t":
            raise _MalformedLinkError
        else:
            result.append(char)
    raise _MalformedLinkError


def _parse_link_value(raw: str) -> Link:
    value = raw.strip()
    if not value.startswith("<"):
        raise _MalformedLinkError
    end = value.find(">")
    if end == -1:
        raise _MalformedLinkError

    target = value[1:end]
    if not target or any(char.isspace() or ord(char) < 0x20 for char in target):
        raise _MalformedLinkError
    if "<" in target or '"' in target or "\\" in target:
        # Backslashes are treated as path separators by common URL parsers.
        # Refuse to guess which URL another hop would fetch.
        raise _MalformedLinkError

    params: dict[str, str] = {}
    rest = value[end + 1 :].strip()
    if rest:
        if not rest.startswith(";"):
            raise _MalformedLinkError
        for segment in _split_quoted(rest[1:], ";"):
            parameter = segment.strip()
            if not parameter:
                raise _MalformedLinkError
            name, has_value, raw_value = parameter.partition("=")
            name = name.strip().lower()
            if not _TOKEN.fullmatch(name):
                raise _MalformedLinkError
            if name in params:
                # Duplicate parameters make the meaning implementation-defined.
                raise _MalformedLinkError
            if not has_value:
                params[name] = ""
                continue
            raw_value = raw_value.strip()
            if not raw_value:
                raise _MalformedLinkError
            if raw_value.startswith('"'):
                parsed_value = _unquote(raw_value)
            else:
                if not _TOKEN.fullmatch(raw_value):
                    raise _MalformedLinkError
                parsed_value = raw_value
            params[name] = parsed_value

    return Link(target=target, params=params)


def parse_link_header(value: str) -> list[Link] | None:
    """
    Parse a complete ``Link`` header field.

    ``None`` means the field could not be interpreted without ambiguity.  The
    caller must ignore the whole field in that case, not just the bad member:
    otherwise a malformed member can change how the remaining members split.
    """
    try:
        links = []
        for raw in _split_quoted(value, ","):
            raw = raw.strip()
            if not raw:
                raise _MalformedLinkError
            links.append(_parse_link_value(raw))
    except _MalformedLinkError:
        return None
    return links


# ---------------------------------------------------------------------------
# Caller-supplied policy: approved origins and approved resource paths.
# ---------------------------------------------------------------------------


def _canonical_origin(parts: SplitResult) -> str | None:
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    host = parts.hostname
    if not host or not host.isascii():
        return None
    host = host.lower()
    if ":" in host:
        host = f"[{host}]"
    if port is None or port == _DEFAULT_PORTS[scheme]:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _valid_path(path: str) -> bool:
    """
    Reject paths that any reasonable decoder could turn into a traversal.

    Only ASCII paths are allowed: Unicode normalization and IDNA mapping differ
    between parsers, and an approved prefix must mean the same thing to every
    hop.  Decoding is repeated to a fixed point (up to three times) because
    another hop may decode a different number of layers than we do.  A path
    still changing after those rounds is not worth trusting.
    """
    decoded = path
    for _ in range(4):
        if not decoded.isascii():
            return False
        if "\\" in decoded or any(ord(char) < 0x20 for char in decoded):
            return False
        if any(segment in (".", "..") for segment in decoded.split("/")):
            return False
        next_decoded = unquote(decoded)
        if next_decoded == decoded:
            return True
        decoded = next_decoded
    return False


@dataclass(frozen=True)
class PrefetchRule:
    """
    One explicitly approved resource scope.

    ``origin`` is a scheme and authority, for example ``https://up.example``.
    ``path_prefix`` is an exact path, or a directory when it ends in ``/``.
    """

    origin: str
    path_prefix: str

    def __post_init__(self) -> None:
        parsed = urlsplit(self.origin)
        canonical = _canonical_origin(parsed)
        if canonical is None or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError(f"invalid approved origin: {self.origin!r}")
        object.__setattr__(self, "origin", canonical)
        if not self.path_prefix.startswith("/") or not _valid_path(self.path_prefix):
            raise ValueError(f"invalid approved path: {self.path_prefix!r}")

    def permits(self, canonical_url: str) -> bool:
        parsed = urlsplit(canonical_url)
        if _canonical_origin(parsed) != self.origin:
            return False
        path = parsed.path or "/"
        if self.path_prefix.endswith("/"):
            return path.startswith(self.path_prefix)
        return path == self.path_prefix


class PrefetchPolicy:
    """A closed allowlist.  Nothing outside these rules is ever fetched."""

    def __init__(self, rules: Iterable[PrefetchRule]) -> None:
        self.rules = tuple(rules)
        if not self.rules:
            raise ValueError("at least one approved prefetch rule is required")

    def select_resource(self, request_url: str, target: str) -> tuple[str | None, str]:
        """
        Resolve and authorize a link target.

        Returns ``(canonical_url, reason)``.  ``canonical_url`` is ``None``
        whenever the target is not explicitly approved.
        """
        if not target or target.startswith("#"):
            return None, "unusable-target"
        if any(char.isspace() or ord(char) < 0x20 for char in target):
            return None, "invalid-target"

        resolved = urljoin(request_url, target)
        parsed = urlsplit(resolved)
        canonical_origin = _canonical_origin(parsed)
        if canonical_origin is None:
            return None, "invalid-origin"
        path = parsed.path or "/"
        if not _valid_path(path):
            return None, "unsafe-path"

        query = f"?{parsed.query}" if parsed.query else ""
        canonical_url = f"{canonical_origin}{path}{query}"
        if not any(rule.permits(canonical_url) for rule in self.rules):
            return None, "not-approved"
        return canonical_url, "approved"


# ---------------------------------------------------------------------------
# A recording, credentialless fake prefetcher and a per-user cache.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PrefetchRequest:
    owner: str
    stream_id: int
    url: str
    credentials: str


@dataclass(frozen=True)
class PrefetchResult:
    url: str
    body: bytes
    media_type: str


@dataclass(frozen=True)
class PrefetchCall:
    owner: str
    stream_id: int
    url: str
    credentials_sent: bool


class RecordingPrefetcher:
    """
    A fake network prefetcher with observable side effects.

    The log intentionally survives a rejected final response: the fetch really
    happened, but that does not make its bytes user-readable.
    """

    def __init__(self) -> None:
        self.calls: list[PrefetchCall] = []

    def prefetch(self, request: PrefetchRequest) -> PrefetchResult:
        if request.credentials != "omit":
            raise ValueError("prefetch hints must never carry caller credentials")
        self.calls.append(
            PrefetchCall(
                owner=request.owner,
                stream_id=request.stream_id,
                url=request.url,
                credentials_sent=False,
            ),
        )
        return PrefetchResult(
            url=request.url,
            body=f"prefetched:{request.url}".encode(),
            media_type="text/css",
        )

    def calls_for(self, owner: str) -> list[PrefetchCall]:
        return [call for call in self.calls if call.owner == owner]


class UserCache:
    """A shared cache partitioned by authenticated owner."""

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], PrefetchResult] = {}

    def commit(self, owner: str, result: PrefetchResult) -> None:
        self._entries[(owner, result.url)] = result

    def get(self, owner: str, url: str) -> bytes | None:
        result = self._entries.get((owner, url))
        return None if result is None else result.body

    def keys_for(self, owner: str) -> list[str]:
        return sorted(url for key_owner, url in self._entries if key_owner == owner)


# ---------------------------------------------------------------------------
# The consumer.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IgnoredLink:
    stream_id: int
    owner: str
    target: str
    reason: str


@dataclass
class _PendingRequest:
    owner: str
    request_url: str
    staged: dict[str, PrefetchResult] = field(default_factory=dict)
    final_status: int | None = None
    final_headers: list[tuple[str, str]] = field(default_factory=list)
    cache_policy_unreadable: bool = False


def _ascii(value: bytes | str) -> str | None:
    try:
        if isinstance(value, bytes):
            return value.decode("ascii")
        value.encode("ascii")
    except UnicodeError:
        return None
    return value


def _normalized_headers(headers: Sequence[tuple[bytes | str, bytes | str]]) -> list[tuple[str, str]]:
    normalized: list[tuple[str, str]] = []
    for raw_name, raw_value in headers:
        name = _ascii(raw_name)
        value = _ascii(raw_value)
        if name is not None and value is not None:
            normalized.append((name.lower(), value))
    return normalized


def _status(headers: Sequence[tuple[str, str]]) -> int | None:
    values = [value for name, value in headers if name == ":status"]
    if len(values) != 1:
        return None
    try:
        return int(values[0])
    except ValueError:
        return None


def _final_response_blocks_shared_cache(headers: Sequence[tuple[str, str]]) -> bool:
    """Use only the final response's cache policy, never a 103's headers."""
    directives: set[str] = set()
    for name, value in headers:
        if name != "cache-control":
            continue
        for directive in value.split(","):
            directives.add(directive.split("=", 1)[0].strip().lower())
    vary = {token.strip().lower() for name, value in headers if name == "vary" for token in value.split(",")}
    # Vary: * makes a response unusable for a shared cache.  It cannot
    # authorize a cache entry that users will read later.
    return bool({"no-store", "private", "no-cache"} & directives) or "*" in vary


def _unreadable_cache_policy(headers: Sequence[tuple[bytes | str, bytes | str]]) -> bool:
    """
    Fail closed if a final cache-control field cannot be decoded.

    h2 normally hands us ASCII because HTTP field values are ASCII.  With a
    non-ASCII decoding configured, however, dropping the field silently would
    make an unknown cache policy look like an absent one.
    """
    for raw_name, raw_value in headers:
        name = _ascii(raw_name)
        if name is None:
            continue
        if name.lower() == "cache-control" and _ascii(raw_value) is None:
            return True
    return False


class RestrictedEarlyHintsConsumer:
    """
    Consume h2 events without letting a 103 authorize anything by itself.

    Call :meth:`begin_request` before sending the request headers, feed every
    event returned by :meth:`H2Connection.receive_data` to :meth:`feed`, and
    keep the authenticated ``owner`` in application state rather than deriving
    it from any received header.
    """

    def __init__(
        self,
        policy: PrefetchPolicy,
        prefetcher: RecordingPrefetcher,
        cache: UserCache,
    ) -> None:
        self.policy = policy
        self.prefetcher = prefetcher
        self.cache = cache
        self.ignored_links: list[IgnoredLink] = []
        self.rejected_final_responses: list[tuple[int, str, int | None, str]] = []
        self._pending: dict[int, _PendingRequest] = {}

    def begin_request(self, stream_id: int, owner: str, request_url: str) -> None:
        if stream_id in self._pending:
            raise ValueError(f"stream {stream_id} is already tracked")
        parsed = urlsplit(request_url)
        if _canonical_origin(parsed) is None:
            raise ValueError(f"request URL has no usable origin: {request_url!r}")
        self._pending[stream_id] = _PendingRequest(owner=owner, request_url=request_url)

    def feed(self, events: Iterable[object]) -> None:
        for event in events:
            if isinstance(event, InformationalResponseReceived):
                self._receive_informational(event)
            elif isinstance(event, ResponseReceived):
                self._receive_final_headers(event)
            elif isinstance(event, StreamEnded):
                self._stream_ended(event.stream_id)
            elif isinstance(event, StreamReset):
                self._discard(event.stream_id, "stream-reset")
            elif isinstance(event, ConnectionTerminated):
                for stream_id in list(self._pending):
                    self._discard(stream_id, "connection-terminated")

    def _receive_informational(self, event: InformationalResponseReceived) -> None:
        pending = self._pending.get(event.stream_id)
        if pending is None:
            return

        headers = _normalized_headers(event.headers)
        if _status(headers) != 103:
            # 100/101 are not Early Hints.  Their fields are not prefetch policy.
            return

        # Deliberately inspect only Link.  Authentication, cookie, and cache
        # fields in a 103 are untrusted hints and have no final-policy effect.
        for raw_name, raw_value in event.headers:
            name = _ascii(raw_name)
            if name is None or name.lower() != "link":
                continue
            value = _ascii(raw_value)
            if value is None:
                # A Link value we cannot read is not a Link we may act on.
                self.ignored_links.append(
                    IgnoredLink(event.stream_id, pending.owner, "<non-ascii>", "non-ascii-link"),
                )
                continue
            links = parse_link_header(value)
            if links is None:
                self.ignored_links.append(IgnoredLink(event.stream_id, pending.owner, value, "malformed-link"))
                continue
            for link in links:
                self._consider_link(event.stream_id, pending, link)

    def _consider_link(self, stream_id: int, pending: _PendingRequest, link: Link) -> None:
        relations = {relation.lower() for relation in link.params.get("rel", "").split()}
        if "preload" not in relations:
            self.ignored_links.append(IgnoredLink(stream_id, pending.owner, link.target, "unsupported-relation"))
            return
        if "anchor" in link.params:
            # The link's context is somewhere other than this request.  We do
            # not have a reliable base URL for it.
            self.ignored_links.append(IgnoredLink(stream_id, pending.owner, link.target, "unsupported-anchor"))
            return

        url, reason = self.policy.select_resource(pending.request_url, link.target)
        if url is None:
            self.ignored_links.append(IgnoredLink(stream_id, pending.owner, link.target, reason))
            return
        if url in pending.staged:
            return

        result = self.prefetcher.prefetch(
            PrefetchRequest(
                owner=pending.owner,
                stream_id=stream_id,
                url=url,
                credentials="omit",
            ),
        )
        pending.staged[url] = result

    def _receive_final_headers(self, event: ResponseReceived) -> None:
        pending = self._pending.get(event.stream_id)
        if pending is None:
            return
        headers = _normalized_headers(event.headers)
        # This is the only response policy that can authorize a cache commit.
        pending.final_status = _status(headers)
        pending.final_headers = headers
        pending.cache_policy_unreadable = _unreadable_cache_policy(event.headers)

    def _stream_ended(self, stream_id: int) -> None:
        pending = self._pending.pop(stream_id, None)
        if pending is None:
            return

        status = pending.final_status
        # 206 is a partial representation and must never become the cached
        # value for a whole URL.  204 has no representation to cache.
        if status not in (200, 203):
            self.rejected_final_responses.append((stream_id, pending.owner, status, "final-status-not-authorized"))
            return
        if pending.cache_policy_unreadable:
            self.rejected_final_responses.append((stream_id, pending.owner, status, "unreadable-final-cache-policy"))
            return
        if _final_response_blocks_shared_cache(pending.final_headers):
            self.rejected_final_responses.append((stream_id, pending.owner, status, "final-cache-policy"))
            return

        for result in pending.staged.values():
            self.cache.commit(pending.owner, result)

    def _discard(self, stream_id: int, reason: str) -> None:
        pending = self._pending.pop(stream_id, None)
        if pending is not None:
            self.rejected_final_responses.append((stream_id, pending.owner, pending.final_status, reason))


# ---------------------------------------------------------------------------
# Demonstration over real h2 frames.
# ---------------------------------------------------------------------------


class _Fixture:
    """Drive two real H2Connection objects and feed events to the consumer."""

    def __init__(self, consumer: RestrictedEarlyHintsConsumer) -> None:
        self.consumer = consumer
        self.client = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
        self.server = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
        self.client.initiate_connection()
        self.server.initiate_connection()
        self.server.receive_data(self.client.data_to_send())
        self.client.receive_data(self.server.data_to_send())

    def open_request(self, stream_id: int, owner: str, url: str) -> None:
        self.consumer.begin_request(stream_id, owner, url)
        parsed = urlsplit(url)
        self.client.send_headers(
            stream_id,
            [
                (":method", "GET"),
                (":scheme", parsed.scheme),
                (":authority", parsed.netloc),
                (":path", parsed.path or "/"),
            ],
        )
        self.server.receive_data(self.client.data_to_send())

    def hints(self, stream_id: int, links: Sequence[str], extra: Sequence[tuple[str, str]] = ()) -> None:
        self.server.send_headers(
            stream_id,
            [(":status", "103"), *[("link", link) for link in links], *extra],
        )
        self.consumer.feed(self.client.receive_data(self.server.data_to_send()))

    def final(self, stream_id: int, status: int, headers: Sequence[tuple[str, str]] = ()) -> None:
        self.server.send_headers(
            stream_id,
            [(":status", str(status)), *headers],
            end_stream=True,
        )
        self.consumer.feed(self.client.receive_data(self.server.data_to_send()))

    def final_then_reset(self, stream_id: int, status: int) -> None:
        self.server.send_headers(stream_id, [(":status", str(status))])
        self.consumer.feed(self.client.receive_data(self.server.data_to_send()))
        self.server.reset_stream(stream_id, error_code=ErrorCodes.CANCEL)
        self.consumer.feed(self.client.receive_data(self.server.data_to_send()))


def run_demo() -> None:
    policy = PrefetchPolicy([
        PrefetchRule("https://up.example", "/assets/"),
        PrefetchRule("https://cdn.example", "/approved/theme.css"),
    ])
    prefetcher = RecordingPrefetcher()
    cache = UserCache()
    consumer = RestrictedEarlyHintsConsumer(policy, prefetcher, cache)
    fixture = _Fixture(consumer)

    # Alice's request is denied at the end.  Her 103 even claims a long cache
    # lifetime; that must not turn the prefetch into a readable entry.
    fixture.open_request(1, "alice", "https://up.example/account")
    fixture.hints(
        1,
        [
            "</assets/app.css>; rel=preload; as=style",
            "<https://evil.example/assets/app.css>; rel=preload; as=style",
            "</private/secret.css>; rel=preload; as=style",
            "</assets/%2e%2e/private/secret.css>; rel=preload; as=style",
            '</assets/quote.css>; rel=preload; title="a, b"',
            '</assets/broken.css>; rel=preload; title="unterminated',
        ],
        extra=[("cache-control", "public, max-age=86400"), ("www-authenticate", "Basic")],
    )
    fixture.final(1, 401, [("cache-control", "no-store")])

    # Bob's interleaved request is authorized, so only his own quarantined
    # result becomes readable.  It shares no staging state with Alice.
    fixture.open_request(3, "bob", "https://up.example/account")
    fixture.hints(3, ["</assets/app.css>; rel=preload; as=style"])
    fixture.final(3, 200, [("cache-control", "public, max-age=60")])

    # A reset after a 200 header block must still discard the quarantine: the
    # commit point is the end of the stream, not the status line.
    fixture.open_request(5, "carol", "https://up.example/account")
    fixture.hints(5, ["</assets/late.css>; rel=preload; as=style"])
    fixture.final_then_reset(5, 200)

    print("prefetch side effects:")
    for call in prefetcher.calls:
        print(f"  owner={call.owner} stream={call.stream_id} url={call.url} credentials_sent={call.credentials_sent}")
    print("ignored hints:")
    for ignored in consumer.ignored_links:
        print(f"  owner={ignored.owner} stream={ignored.stream_id} target={ignored.target!r} reason={ignored.reason}")
    print("readable cache entries:")
    for owner in ("alice", "bob", "carol"):
        print(f"  {owner}: {cache.keys_for(owner)}")
    print("rejected final responses / discards:")
    for item in consumer.rejected_final_responses:
        print(f"  {item}")


if __name__ == "__main__":
    run_demo()
