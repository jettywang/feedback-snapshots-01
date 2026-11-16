from __future__ import annotations

import ipaddress
import os
import re
import typing
from dataclasses import dataclass
from urllib.request import getproxies

from ._types import PrimitiveData

if typing.TYPE_CHECKING:  # pragma: no cover
    from ._urls import URL


@dataclass(frozen=True)
class EnvProxyEntry:
    """
    A single proxy rule derived from the process environment.

    `key` is the mount-style URL pattern the rule maps to (for example
    `"http://"` or `"all://*example.com"`). `proxy_url` is `None` for
    `NO_PROXY` bypass entries, and the (still raw, possibly credentialed)
    proxy URL for `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` entries.
    `source` records the environment variable, including its original
    casing, that the entry came from.
    """

    key: str
    proxy_url: str | None
    source: str


def primitive_value_to_str(value: PrimitiveData) -> str:
    """
    Coerce a primitive data type into a string value.

    Note that we prefer JSON-style 'true'/'false' for boolean values here.
    """
    if value is True:
        return "true"
    elif value is False:
        return "false"
    elif value is None:
        return ""
    return str(value)


def _environment_variable_for(value: str, names: tuple[str, ...]) -> str:
    """
    Return the environment variable (preserving its original casing) whose
    value matches `value`, checking `names` in order. The comparison is case
    insensitive because proxy variables are commonly read in either casing.
    Falls back to the first name when the value was supplied outside of the
    environment, such as via the Windows registry or the macOS system
    configuration.
    """
    for name in names:
        env_value = os.environ.get(name)
        if env_value is not None and env_value.lower() == value.lower():
            return name
    return names[0]


# Sentinel mount key representing a `NO_PROXY=*` rule that bypasses every
# request. The bare "*" host only matches a URL whose host is literally "*",
# so requests with ordinary hosts fall through to the direct connection pool.
NO_PROXY_WILDCARD_KEY = "all://*"


def _no_proxy_key(hostname: str) -> str:
    # See https://curl.haxx.se/libcurl/c/CURLOPT_NOPROXY.html for details
    # on how names in `NO_PROXY` are handled.
    # NO_PROXY=.google.com is marked as "all://*.google.com,
    #   which disables "www.google.com" but not "google.com"
    # NO_PROXY=google.com is marked as "all://*google.com,
    #   which disables "www.google.com" and "google.com".
    #   (But not "wwwgoogle.com")
    # NO_PROXY can include domains, IPv6, IPv4 addresses and "localhost"
    #   NO_PROXY=example.com,::1,localhost,192.168.0.0/16
    if "://" in hostname:
        return hostname
    elif is_ipv4_hostname(hostname):
        return f"all://{hostname}"
    elif is_ipv6_hostname(hostname):
        return f"all://[{hostname}]"
    elif hostname.lower() == "localhost":
        return f"all://{hostname}"
    else:
        return f"all://*{hostname}"


def get_environment_proxy_entries() -> list[EnvProxyEntry]:
    """
    Gets proxy information from the environment, as ordered rule entries that
    also record which environment variable each rule came from.
    """

    # urllib.request.getproxies() falls back on System
    # Registry and Config for proxies on Windows and macOS.
    # We don't want to propagate non-HTTP proxies into
    # our configuration such as 'TRAVIS_APT_PROXY'.
    proxy_info = getproxies()
    entries: list[EnvProxyEntry] = []

    scheme_variables = {
        "http": ("HTTP_PROXY", "http_proxy"),
        "https": ("HTTPS_PROXY", "https_proxy"),
        "all": ("ALL_PROXY", "all_proxy"),
    }
    for scheme in ("http", "https", "all"):
        if proxy_info.get(scheme):
            hostname = proxy_info[scheme]
            key = f"{scheme}://"
            proxy_url = hostname if "://" in hostname else f"http://{hostname}"
            source = _environment_variable_for(
                proxy_info[scheme], scheme_variables[scheme]
            )
            entries.append(EnvProxyEntry(key=key, proxy_url=proxy_url, source=source))

    no_proxy_value = proxy_info.get("no", "")
    no_proxy_source = _environment_variable_for(
        no_proxy_value, ("NO_PROXY", "no_proxy")
    )
    no_proxy_hosts = [host.strip() for host in no_proxy_value.split(",")]
    for hostname in no_proxy_hosts:
        if hostname == "*":
            # If NO_PROXY=* is used or if "*" occurs as any one of the comma
            # separated hostnames, then we should just bypass any information
            # from HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, and always ignore
            # proxies.
            return [
                EnvProxyEntry(
                    key=NO_PROXY_WILDCARD_KEY, proxy_url=None, source=no_proxy_source
                )
            ]
        elif hostname:
            entries.append(
                EnvProxyEntry(
                    key=_no_proxy_key(hostname),
                    proxy_url=None,
                    source=no_proxy_source,
                )
            )

    return entries


def get_environment_proxies() -> dict[str, str | None]:
    """Gets proxy information from the environment"""
    entries = get_environment_proxy_entries()
    if len(entries) == 1 and entries[0].key == NO_PROXY_WILDCARD_KEY:
        return {}
    return {entry.key: entry.proxy_url for entry in entries}


def to_bytes(value: str | bytes, encoding: str = "utf-8") -> bytes:
    return value.encode(encoding) if isinstance(value, str) else value


def to_str(value: str | bytes, encoding: str = "utf-8") -> str:
    return value if isinstance(value, str) else value.decode(encoding)


def to_bytes_or_str(value: str, match_type_of: typing.AnyStr) -> typing.AnyStr:
    return value if isinstance(match_type_of, str) else value.encode()


def unquote(value: str) -> str:
    return value[1:-1] if value[0] == value[-1] == '"' else value


def peek_filelike_length(stream: typing.Any) -> int | None:
    """
    Given a file-like stream object, return its length in number of bytes
    without reading it into memory.
    """
    try:
        # Is it an actual file?
        fd = stream.fileno()
        # Yup, seems to be an actual file.
        length = os.fstat(fd).st_size
    except (AttributeError, OSError):
        # No... Maybe it's something that supports random access, like `io.BytesIO`?
        try:
            # Assuming so, go to end of stream to figure out its length,
            # then put it back in place.
            offset = stream.tell()
            length = stream.seek(0, os.SEEK_END)
            stream.seek(offset)
        except (AttributeError, OSError):
            # Not even that? Sorry, we're doomed...
            return None

    return length


class URLPattern:
    """
    A utility class currently used for making lookups against proxy keys...

    # Wildcard matching...
    >>> pattern = URLPattern("all://")
    >>> pattern.matches(httpx.URL("http://example.com"))
    True

    # Witch scheme matching...
    >>> pattern = URLPattern("https://")
    >>> pattern.matches(httpx.URL("https://example.com"))
    True
    >>> pattern.matches(httpx.URL("http://example.com"))
    False

    # With domain matching...
    >>> pattern = URLPattern("https://example.com")
    >>> pattern.matches(httpx.URL("https://example.com"))
    True
    >>> pattern.matches(httpx.URL("http://example.com"))
    False
    >>> pattern.matches(httpx.URL("https://other.com"))
    False

    # Wildcard scheme, with domain matching...
    >>> pattern = URLPattern("all://example.com")
    >>> pattern.matches(httpx.URL("https://example.com"))
    True
    >>> pattern.matches(httpx.URL("http://example.com"))
    True
    >>> pattern.matches(httpx.URL("https://other.com"))
    False

    # With port matching...
    >>> pattern = URLPattern("https://example.com:1234")
    >>> pattern.matches(httpx.URL("https://example.com:1234"))
    True
    >>> pattern.matches(httpx.URL("https://example.com"))
    False
    """

    def __init__(self, pattern: str) -> None:
        from ._urls import URL

        if pattern and ":" not in pattern:
            raise ValueError(
                f"Proxy keys should use proper URL forms rather "
                f"than plain scheme strings. "
                f'Instead of "{pattern}", use "{pattern}://"'
            )

        url = URL(pattern)
        self.pattern = pattern
        self.scheme = "" if url.scheme == "all" else url.scheme
        self.host = "" if url.host == "*" else url.host
        self.port = url.port
        if not url.host or url.host == "*":
            self.host_regex: typing.Pattern[str] | None = None
        elif url.host.startswith("*."):
            # *.example.com should match "www.example.com", but not "example.com"
            domain = re.escape(url.host[2:])
            self.host_regex = re.compile(f"^.+\\.{domain}$")
        elif url.host.startswith("*"):
            # *example.com should match "www.example.com" and "example.com"
            domain = re.escape(url.host[1:])
            self.host_regex = re.compile(f"^(.+\\.)?{domain}$")
        else:
            # example.com should match "example.com" but not "www.example.com"
            domain = re.escape(url.host)
            self.host_regex = re.compile(f"^{domain}$")

    def matches(self, other: URL) -> bool:
        if self.scheme and self.scheme != other.scheme:
            return False
        if (
            self.host
            and self.host_regex is not None
            and not self.host_regex.match(other.host)
        ):
            return False
        if self.port is not None and self.port != other.port:
            return False
        return True

    @property
    def priority(self) -> tuple[int, int, int]:
        """
        The priority allows URLPattern instances to be sortable, so that
        we can match from most specific to least specific.
        """
        # URLs with a port should take priority over URLs without a port.
        port_priority = 0 if self.port is not None else 1
        # Longer hostnames should match first.
        host_priority = -len(self.host)
        # Longer schemes should match first.
        scheme_priority = -len(self.scheme)
        return (port_priority, host_priority, scheme_priority)

    def __hash__(self) -> int:
        return hash(self.pattern)

    def __lt__(self, other: URLPattern) -> bool:
        return self.priority < other.priority

    def __eq__(self, other: typing.Any) -> bool:
        return isinstance(other, URLPattern) and self.pattern == other.pattern


def is_ipv4_hostname(hostname: str) -> bool:
    try:
        ipaddress.IPv4Address(hostname.split("/")[0])
    except Exception:
        return False
    return True


def is_ipv6_hostname(hostname: str) -> bool:
    try:
        ipaddress.IPv6Address(hostname.split("/")[0])
    except Exception:
        return False
    return True
