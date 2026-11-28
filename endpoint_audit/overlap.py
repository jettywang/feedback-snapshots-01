"""Compare listening ranges and classify service pairs.

Three outcomes are distinguished:

* L{Verdict.OVERLAP}  - the ranges provably share at least one address;
* L{Verdict.SEPARATE} - the ranges provably cannot share an address;
* L{Verdict.UNKNOWN}  - the configuration does not determine the answer
  (hostnames, port 0, runtime-only plugins, dual-stack uncertainty, ...).

Address-family ambiguity is preserved rather than collapsed: an IPv4 and an
IPv6 binding on the same port are not declared disjoint because dual-stack
behaviour and wildcard semantics vary at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Family, HostKind, ListenRange, ParsedEntry, Verdict


@dataclass(frozen=True)
class PairVerdict:
    """Verdict for one unordered pair of parsed declarations."""

    left: ParsedEntry
    right: ParsedEntry
    verdict: Verdict
    detail: str

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "detail": self.detail,
            "left": self.left.coordinate.to_dict(),
            "right": self.right.coordinate.to_dict(),
        }


def _hosts_intersect(left: ListenRange, right: ListenRange) -> Verdict:
    assert left.host is not None and right.host is not None
    lh, rh = left.host, right.host

    if lh.kind is HostKind.NAME or rh.kind is HostKind.NAME:
        return Verdict.UNKNOWN
    if lh.kind is HostKind.WILDCARD or rh.kind is HostKind.WILDCARD:
        if lh.family is Family.UNKNOWN or rh.family is Family.UNKNOWN:
            return Verdict.UNKNOWN
        if lh.family is rh.family:
            return Verdict.OVERLAP
        # Wildcards of different families: dual-stack wildcard coverage is
        # runtime dependent, so keep the uncertainty.
        return Verdict.UNKNOWN
    if lh.family is not rh.family:
        # Address-family ambiguity is deliberately preserved: dual-stack
        # wildcard behaviour (IPV6_V6ONLY) and platform socket options are
        # only knowable at runtime, so cross-family pairs stay uncertain
        # rather than being asserted disjoint.
        return Verdict.UNKNOWN
    if lh.value == rh.value:
        return Verdict.OVERLAP
    return Verdict.SEPARATE


def compare_ranges(left: ListenRange, right: ListenRange) -> Verdict:
    """Compare two individual listening ranges."""

    if not left.certain or not right.certain:
        return Verdict.UNKNOWN
    if left.family is Family.UNKNOWN or right.family is Family.UNKNOWN:
        return Verdict.UNKNOWN

    if left.family is Family.UNIX or right.family is Family.UNIX:
        if left.family is not right.family:
            return Verdict.SEPARATE
        return Verdict.OVERLAP if left.path == right.path else Verdict.SEPARATE

    if left.port is None or right.port is None:
        return Verdict.UNKNOWN
    if left.port != right.port:
        return Verdict.SEPARATE
    return _hosts_intersect(left, right)


def _explain(left: ListenRange, right: ListenRange, verdict: Verdict) -> str:
    def label(rng: ListenRange) -> str:
        if rng.family is Family.UNIX:
            return f"unix:{rng.path}"
        host = rng.host.value if rng.host and rng.host.value else "*"
        port = "*" if rng.port is None else str(rng.port)
        return f"{rng.family.value}:{host}:{port}"

    return f"{label(left)} vs {label(right)} -> {verdict.value}"


def compare_entries(left: ParsedEntry, right: ParsedEntry) -> PairVerdict:
    """Compare every range of two declarations.

    The pair is OVERLAP if any range pair provably intersects, SEPARATE only
    when every range pair is provably disjoint, and UNKNOWN otherwise.
    """

    if not left.ranges or not right.ranges:
        return PairVerdict(
            left,
            right,
            Verdict.UNKNOWN,
            "one side has no statically derivable range",
        )

    verdicts = [
        compare_ranges(lr, rr)
        for lr in left.ranges
        for rr in right.ranges
    ]
    if Verdict.OVERLAP in verdicts:
        aggregate = Verdict.OVERLAP
    elif all(v is Verdict.SEPARATE for v in verdicts):
        aggregate = Verdict.SEPARATE
    else:
        aggregate = Verdict.UNKNOWN

    details = [
        _explain(lr, rr, compare_ranges(lr, rr))
        for lr in left.ranges
        for rr in right.ranges
    ]
    return PairVerdict(left, right, aggregate, "; ".join(details))


def audit_pairs(entries: list[ParsedEntry]) -> list[PairVerdict]:
    """Produce a verdict for every unordered pair of declarations."""

    pairs: list[PairVerdict] = []
    for index, left in enumerate(entries):
        for right in entries[index + 1 :]:
            pairs.append(compare_entries(left, right))
    return pairs


def group_pairs(
    pairs: list[PairVerdict],
) -> dict[Verdict, list[PairVerdict]]:
    """Bucket pair verdicts into the three review categories."""

    return {
        Verdict.OVERLAP: [p for p in pairs if p.verdict is Verdict.OVERLAP],
        Verdict.SEPARATE: [p for p in pairs if p.verdict is Verdict.SEPARATE],
        Verdict.UNKNOWN: [p for p in pairs if p.verdict is Verdict.UNKNOWN],
    }
