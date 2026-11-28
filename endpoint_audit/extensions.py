"""Voluntary disclosure protocol for non-built-in endpoint schemes.

The audit cannot construct runtime-only endpoint objects (that would mean
binding sockets or executing plugin code at cold-start review time).  Such
schemes therefore remain uncertain by default.  A plugin may *voluntarily*
ship a small, side-effect-free discloser that answers the single question
"which listening range would this description cover?" purely from its text.

A discloser never receives a reactor and must not bind, listen or read key
material; it only inspects the already-tokenised arguments and returns plain
data (or C{None} to keep the uncertainty).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol, runtime_checkable

from .model import Family, HostBinding, HostKind, ListenRange


@dataclass(frozen=True)
class Disclosure:
    """Statically inspectable information about a runtime endpoint.

    Every field is plain data so the finding can be serialised into a report
    and re-checked by a reviewer without importing the runtime plugin.
    """

    family: Family
    host: HostBinding | None = None
    port: int | None = None
    path: str | None = None
    certain: bool = True
    reason: str | None = None

    def as_range(self) -> ListenRange:
        return ListenRange(
            family=self.family,
            host=self.host,
            port=self.port,
            path=self.path,
            certain=self.certain,
            reason=self.reason,
        )


Discloser = Callable[[list[str], dict[str, str]], "Disclosure | None"]


@runtime_checkable
class EndpointDiscloser(Protocol):
    """Optional protocol a review-time helper module may implement.

    A module exposing C{prefix} and C{disclose} can be registered as a
    discloser for the matching endpoint scheme.
    """

    prefix: str

    def disclose(
        self, args: list[str], kwargs: dict[str, str]
    ) -> Disclosure | None: ...


class DiscloserRegistry:
    """Maps endpoint scheme names to voluntary disclosers."""

    def __init__(self) -> None:
        self._disclosers: dict[str, Discloser] = {}

    def register(
        self,
        prefix: str,
        discloser: Discloser | EndpointDiscloser,
    ) -> None:
        scheme = prefix.lower()
        if scheme in self._disclosers:
            raise ValueError(f"discloser already registered for {scheme!r}")
        callback: Discloser
        if callable(discloser) and not hasattr(discloser, "disclose"):
            callback = discloser
        else:
            callback = discloser.disclose
        self._disclosers[scheme] = callback

    def load_module(self, module_name: str) -> str:
        """Import a helper module and register its discloser.

        Returns the scheme prefix the module claims.  Importing a discloser
        module must be side-effect free; the audit never calls listen().
        """

        import importlib

        module = importlib.import_module(module_name)
        prefix = getattr(module, "prefix", None)
        disclose = getattr(module, "disclose", None)
        if not isinstance(prefix, str) or not callable(disclose):
            raise ValueError(
                f"extension {module_name!r} must define a str 'prefix' and a "
                "callable 'disclose(args, kwargs)'"
            )
        self.register(prefix, disclose)
        return prefix.lower()

    def schemes(self) -> tuple[str, ...]:
        return tuple(sorted(self._disclosers))

    def disclose(
        self,
        scheme: str,
        args: list[str],
        kwargs: dict[str, str],
    ) -> Disclosure | None:
        callback = self._disclosers.get(scheme.lower())
        if callback is None:
            return None
        return callback(args, kwargs)


def ip_host(value: str) -> HostBinding:
    """Build a certain host binding from an IP literal."""

    import ipaddress

    address = ipaddress.ip_address(value)
    family = Family.INET6 if address.version == 6 else Family.INET4
    return HostBinding(kind=HostKind.ADDRESS, family=family, value=value)


def wildcard_host(family: Family) -> HostBinding:
    value = "::" if family is Family.INET6 else "0.0.0.0"
    return HostBinding(kind=HostKind.WILDCARD, family=family, value=value)
