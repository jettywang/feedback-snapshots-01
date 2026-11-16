"""
Proxy routing decision support.

The helpers in this module describe *which transport a request would be sent
through*; they do not perform any network input/output of their own. In
particular they never resolve DNS, and a decision to connect directly is not
a security control on its own.
"""

from __future__ import annotations

import dataclasses
import typing

from ._urls import URL
from ._utils import URLPattern

if typing.TYPE_CHECKING:  # pragma: no cover
    from ._transports.base import AsyncBaseTransport, BaseTransport

__all__ = ["ProxyRule", "ProxyDecision", "explain_proxy_rules", "mask_proxy_url"]


# Rule `kind` values.
EXPLICIT_PROXY = "explicit_proxy"
ENVIRONMENT_PROXY = "environment_proxy"
EXPLICIT_BYPASS = "explicit_bypass"
ENVIRONMENT_BYPASS = "environment_bypass"
UNPARSEABLE_RULE = "unparseable_rule"

# Decision `outcome` values.
PROXIED = "proxied"
DIRECT = "direct"


def mask_proxy_url(url: URL | str | None) -> str | None:
    """
    Return a string form of a proxy URL with any password component masked.

    No network access is performed; only the URL's own components are read.
    """
    if url is None:
        return None
    if not isinstance(url, URL):
        url = URL(url)
    if url.password:
        url = url.copy_with(password="***")
    return str(url)


@dataclasses.dataclass
class ProxyRule:
    """
    A single candidate routing rule, in the same priority order used when
    selecting the transport that actually sends a request.
    """

    key: str
    kind: str
    source: str
    transport: BaseTransport | AsyncBaseTransport | None
    direct: bool
    proxy_url: URL | None = None
    pattern: URLPattern | None = None
    error: str | None = None

    @property
    def unparseable(self) -> bool:
        return self.kind == UNPARSEABLE_RULE

    def matches(self, url: URL) -> bool:
        """
        Whether this rule matches the given request URL.

        Matching uses the exact same `URLPattern` machinery as the transport
        selection loop, so IPv6 literals, exact hosts and subdomain rules keep
        the semantics they have on the send path, instead of collapsing into
        naive string suffix checks.
        """
        if self.pattern is None:
            return False
        return self.pattern.matches(url)


@dataclasses.dataclass
class ProxyDecision:
    """
    The result of evaluating proxy routing for one request URL.
    """

    url: URL
    outcome: str
    transport: BaseTransport | AsyncBaseTransport
    direct: bool
    reason: str
    matched_rule: ProxyRule | None
    rules: list[ProxyRule]
    trust_env: bool

    @property
    def proxy_url(self) -> URL | None:
        if self.matched_rule is None:
            return None
        return self.matched_rule.proxy_url

    @property
    def matched_key(self) -> str | None:
        if self.matched_rule is None:
            return None
        return self.matched_rule.key

    @property
    def source(self) -> str | None:
        if self.matched_rule is None:
            return None
        return self.matched_rule.source

    def masked_summary(self) -> str:
        """
        A single-line, password-free description suitable for log output.
        """
        target = str(self.url)
        if self.direct:
            return f"Proxy decision for {target}: direct connection ({self.reason})"
        proxy_url = mask_proxy_url(self.proxy_url)
        if proxy_url is None:
            # Explicit mounts can be arbitrary transports without a proxy URL.
            return (
                f"Proxy decision for {target}: via mounted transport "
                f"{type(self.transport).__name__} ({self.reason})"
            )
        return (
            f"Proxy decision for {target}: via proxy "
            f"{proxy_url} ({self.reason})"
        )


def explain_proxy_rules(
    url: URL | str,
    rules: typing.Sequence[ProxyRule],
    *,
    transport: BaseTransport | AsyncBaseTransport,
    trust_env: bool,
) -> ProxyDecision:
    """
    Evaluate `rules` against `url` using the same first-match-wins ordering as
    the client's transport selection, and explain the outcome.

    The returned transport is always the transport the matching rule maps to
    (or the client's default transport for a direct connection), so the
    explanation and the actual send chain can never disagree.
    """
    if not isinstance(url, URL):
        url = URL(url)

    matched: ProxyRule | None = None
    for rule in rules:
        if not rule.unparseable and rule.matches(url):
            matched = rule
            break

    if matched is not None:
        selected_transport = (
            transport if matched.transport is None else matched.transport
        )
        if matched.direct:
            outcome = DIRECT
            reason = (
                f"bypass rule {matched.key!r} from {matched.source} matched "
                f"scheme={url.scheme!r}, host={url.host!r}, port={url.port!r}"
            )
        else:
            outcome = PROXIED
            reason = (
                f"proxy rule {matched.key!r} from {matched.source} matched "
                f"scheme={url.scheme!r}, host={url.host!r}, port={url.port!r}"
            )
        return ProxyDecision(
            url=url,
            outcome=outcome,
            transport=selected_transport,
            direct=matched.direct,
            reason=reason,
            matched_rule=matched,
            rules=list(rules),
            trust_env=trust_env,
        )

    reason = "no proxy or bypass rule matched; using the default transport"
    return ProxyDecision(
        url=url,
        outcome=DIRECT,
        transport=transport,
        direct=True,
        reason=reason,
        matched_rule=None,
        rules=list(rules),
        trust_env=trust_env,
    )
