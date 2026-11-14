"""Protocol allow list and per-protocol negotiation rules."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass


@dataclass(frozen=True, kw_only=True)
class ProtocolPolicy:
    """Negotiation policy for one entry of the extended CONNECT allow list.

    ``required_schemes``/``required_headers`` let the ingress enforce the
    protocol-specific preconditions (for example RFC 8441's mandatory
    ``:scheme``/``:path`` tuple) before the application authorizer is called.
    """

    name: str
    required_schemes: frozenset[str] = frozenset()
    required_headers: frozenset[str] = frozenset()

    def negotiate(
        self,
        scheme: str | None,
        regular_headers: Mapping[bytes, bytes],
    ) -> str | None:
        """Return ``None`` when the request satisfies negotiation, else a reason."""

        if self.required_schemes and scheme not in self.required_schemes:
            return f"protocol {self.name!r} requires scheme in {sorted(self.required_schemes)}"
        for name in self.required_headers:
            if name.encode("ascii") not in regular_headers:
                return f"protocol {self.name!r} requires header {name!r}"
        return None


class ProtocolRegistry:
    """The immutable, explicitly allowed set of extended CONNECT protocols."""

    def __init__(self, policies: Sequence[ProtocolPolicy | str]) -> None:
        self._policies: dict[str, ProtocolPolicy] = {}
        for policy in policies:
            resolved = (
                ProtocolPolicy(name=policy) if isinstance(policy, str) else policy
            )
            key = resolved.name.lower()
            if key in self._policies:
                raise ValueError(f"duplicate protocol policy: {resolved.name!r}")
            self._policies[key] = resolved

    def __contains__(self, name: str) -> bool:
        return name.lower() in self._policies

    def __iter__(self):
        return iter(self._policies)

    def get(self, name: str) -> ProtocolPolicy | None:
        return self._policies.get(name.lower())
