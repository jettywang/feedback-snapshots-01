"""Offline, finite trust-graph evaluation over OpenPGP-style certifications.

The caller supplies trust roots (key, amount, depth) and a threshold; the
evaluator decides whether a concrete (key, UID) binding is trustworthy.
No global reputation is consulted: the only trust inflow is from the roots.

Trust units follow RFC 4880 trust-signature convention: 0..120, 120 = full.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field

FULL_TRUST = 120
INF = 10 ** 9

VALID = "VALID"                    # trust flow meets threshold
INSUFFICIENT = "INSUFFICIENT"      # even optimistic flow is below threshold
UNKNOWN = "UNKNOWN"                # decision depends on uninterpretable scope regex
TARGET_INVALID = "TARGET_INVALID"  # the target key/UID itself is revoked/expired


# ---------------------------------------------------------------------------
# Input model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Key:
    fingerprint: str
    controller: str            # caller-asserted identity of the key's controller
    revoked: bool = False
    expires: float | None = None


@dataclass(frozen=True)
class Uid:
    key: str                   # fingerprint of the owning key
    name: str
    revoked: bool = False


@dataclass(frozen=True)
class Cert:
    """A certification signature binding one key to one UID."""
    cid: str                   # caller-chosen identifier, used in audit output
    issuer: str                # fingerprint of the signing key
    key: str                   # fingerprint of the certified key
    uid: str                   # the certified UID string
    created: float = 0.0
    expires: float | None = None
    revoked: bool = False
    trust_amount: int | None = None   # None = plain certification (no TrustSignature)
    trust_depth: int = 0              # delegation depth granted to the certified key
    trust_regex: str | None = None    # name-scope restriction (RFC 4880 regex)


@dataclass(frozen=True)
class Root:
    key: str                   # fingerprint of a trust root
    amount: int                # ownertrust units injected here (0..120+)
    depth: int                  # how many delegation hops may follow


# ---------------------------------------------------------------------------
# Reliably interpretable scope-regex subset
# ---------------------------------------------------------------------------

# Escaped punctuation we accept as a literal. Any other backslash construct
# (\d, \w, \b, backreferences, ...) is outside the supported subset.
_ESCAPABLE = set(".\\^$*+?()[]{}|@-/_<>:,= #~")

def interpret_regex(pattern: str):
    """Compile *pattern* if it lies in the supported subset, else return None.

    Supported: literals, '.', character classes, '*', '+', '?', '{m,n}',
    grouping '()', alternation '|', anchors '^' '$', and escaped punctuation.
    Rejected (=> caller gets UNKNOWN): backreferences, look-around, and every
    backslash construct other than escaped punctuation. Matching is a
    case-sensitive full match against the whole UID string.
    """
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            if i + 1 >= len(pattern) or pattern[i + 1] not in _ESCAPABLE:
                return None
            i += 2
            continue
        if ch == "(" and pattern[i + 1:i + 2] == "?":
            return None
        i += 1
    try:
        return re.compile(pattern)
    except re.error:
        return None


# ---------------------------------------------------------------------------
# Flow network (Edmonds-Karp; the graphs here are tiny)
# ---------------------------------------------------------------------------

class _Edge:
    __slots__ = ("to", "cap", "flow", "rev", "meta")

    def __init__(self, to, cap, meta):
        self.to = to
        self.cap = cap
        self.flow = 0
        self.rev = None
        self.meta = meta


class _Network:
    def __init__(self):
        self.adj = defaultdict(list)

    def add(self, u, v, cap, meta=None):
        if cap <= 0:
            return
        fwd = _Edge(v, cap, meta)
        rev = _Edge(u, 0, None)
        fwd.rev = rev
        rev.rev = fwd
        self.adj[u].append(fwd)
        self.adj[v].append(rev)

    def max_flow(self, source, sink):
        total = 0
        while True:
            prev = {source: None}
            queue = deque([source])
            while queue and sink not in prev:
                u = queue.popleft()
                for e in self.adj[u]:
                    if e.to not in prev and e.cap - e.flow > 0:
                        prev[e.to] = (u, e)
                        queue.append(e.to)
            if sink not in prev:
                return total
            bottleneck = INF
            node = sink
            while node != source:
                u, e = prev[node]
                bottleneck = min(bottleneck, e.cap - e.flow)
                node = u
            node = sink
            while node != source:
                u, e = prev[node]
                e.flow += bottleneck
                e.rev.flow -= bottleneck
                node = u
            total += bottleneck

    def decompose(self, source, sink):
        """Split the current flow into (amount, [forward edges]) paths."""
        paths = []
        while True:
            path = []
            node = source
            seen = set()
            while node != sink:
                if node in seen:          # flow on a cycle: drop it, contributes nothing
                    path = None
                    break
                seen.add(node)
                nxt = None
                for e in self.adj[node]:
                    if e.meta is not None and e.flow > 0:
                        nxt = e
                        break
                if nxt is None:
                    path = None
                    break
                path.append(nxt)
                node = nxt.to
            if path is None:
                return paths
            amount = min(e.flow for e in path)
            for e in path:
                e.flow -= amount
            paths.append((amount, [e.meta for e in path]))


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

@dataclass
class Verdict:
    status: str
    target_key: str
    target_uid: str
    threshold: int
    pessimistic_flow: int
    optimistic_flow: int
    paths: list = field(default_factory=list)          # decisive decomposition
    dropped: list = field(default_factory=list)        # (cid, reason) audit trail
    unknown_scope: list = field(default_factory=list)  # cids with uninterpretable regex


class Evaluator:
    def __init__(self, keys, certs, roots, now, uids=()):
        self.keys = {k.fingerprint: k for k in keys}
        self.certs = list(certs)
        self.roots = list(roots)
        self.now = now
        self.uids = {(u.key, u.name): u for u in uids}

    # -- validity primitives -------------------------------------------------

    def _key_valid(self, fpr):
        k = self.keys.get(fpr)
        if k is None or k.revoked:
            return False
        return k.expires is None or k.expires > self.now

    def _cert_valid(self, c):
        if c.revoked:
            return False
        if c.expires is not None and c.expires <= self.now:
            return False
        if c.created > self.now:
            return False
        return True

    def _controller(self, fpr):
        return self.keys[fpr].controller

    # -- scope regex ----------------------------------------------------------

    def _regex_status(self, c, target_uid):
        """-> 'none' | 'match' | 'mismatch' | 'unknown'"""
        if c.trust_regex is None:
            return "none"
        compiled = interpret_regex(c.trust_regex)
        if compiled is None:
            return "unknown"
        return "match" if compiled.fullmatch(target_uid) else "mismatch"

    # -- network construction --------------------------------------------------

    def _build(self, target_key, target_uid, include_unknown, dropped, unknown_scope):
        max_depth = max(
            [r.depth for r in self.roots]
            + [c.trust_depth for c in self.certs]
            + [0]
        )
        net = _Network()
        source, sink = "SOURCE", "SINK"

        def node(controller, depth):
            return ("n", controller, depth)

        for idx, r in enumerate(self.roots):
            if not self._key_valid(r.key):
                dropped.append((f"root:{r.key}", "root key revoked/expired/unknown"))
                continue
            net.add(source, node(self._controller(r.key), r.depth), r.amount,
                    meta=("root", idx))

        for c in self.certs:
            if not self._cert_valid(c):
                dropped.append((c.cid, "certification revoked/expired/not yet valid"))
                continue
            if not self._key_valid(c.issuer):
                dropped.append((c.cid, "issuer key revoked/expired/unknown"))
                continue
            if c.key not in self.keys or self.keys[c.key].revoked:
                dropped.append((c.cid, "certified key revoked/unknown"))
                continue
            status = self._regex_status(c, target_uid)
            if status == "mismatch":
                dropped.append((c.cid, "name-scope regex does not match target UID"))
                continue
            if status == "unknown":
                unknown_scope.append(c.cid)
                if not include_unknown:
                    continue
            cap = c.trust_amount if c.trust_amount is not None else INF
            ic, tc = self._controller(c.issuer), self._controller(c.key)
            if c.key == target_key and c.uid == target_uid:
                for d in range(max_depth + 1):
                    net.add(node(ic, d), sink, cap, meta=("cert", c.cid, d))
            if c.trust_depth >= 1:
                for d in range(1, max_depth + 1):
                    arrive = min(d - 1, c.trust_depth - 1)
                    net.add(node(ic, d), node(tc, arrive), cap,
                            meta=("cert", c.cid, d))
        return net, source, sink

    # -- main entry point -------------------------------------------------------

    def evaluate(self, target_key, target_uid, threshold):
        uid_rec = self.uids.get((target_key, target_uid))
        if uid_rec is not None and uid_rec.revoked:
            return Verdict(TARGET_INVALID, target_key, target_uid, threshold, 0, 0,
                           dropped=[(target_uid, "UID is revoked")])
        key_rec = self.keys.get(target_key)
        if key_rec is None or key_rec.revoked or (
                key_rec.expires is not None and key_rec.expires <= self.now):
            return Verdict(TARGET_INVALID, target_key, target_uid, threshold, 0, 0,
                           dropped=[(target_key, "target key revoked/expired/unknown")])

        dropped_p, unknown_p = [], []
        net, s, t = self._build(target_key, target_uid, False, dropped_p, unknown_p)
        pessimistic = net.max_flow(s, t)
        paths = net.decompose(s, t) if pessimistic >= threshold else []

        dropped_o, unknown_o = [], []
        net_o, s_o, t_o = self._build(target_key, target_uid, True, dropped_o, unknown_o)
        optimistic = net_o.max_flow(s_o, t_o)

        if pessimistic >= threshold:
            status = VALID
            dropped, unknown = dropped_p, unknown_p
        elif optimistic < threshold:
            status = INSUFFICIENT
            dropped, unknown = dropped_o, unknown_o
        else:
            status = UNKNOWN
            dropped, unknown = dropped_o, unknown_o
        return Verdict(status, target_key, target_uid, threshold,
                       pessimistic, optimistic, paths, dropped, unknown)

    # -- independent path verification -------------------------------------------

    def verify_paths(self, verdict):
        """Re-check every reported path against the original inputs.

        Returns True iff each path is a chain of currently valid certifications
        from a caller-supplied root to the target (key, UID), respecting depth,
        amount and name-scope rules, and the path amounts sum to the decisive
        flow. This re-derives everything from the raw model, so a bug in the
        flow machinery cannot manufacture trust unnoticed.
        """
        if verdict.status != VALID:
            return False
        total = 0
        for amount, metas in verdict.paths:
            remaining = None
            controller = None
            budget = INF
            for i, meta in enumerate(metas):
                if meta[0] == "root":
                    root = self.roots[meta[1]]
                    if not self._key_valid(root.key):
                        return False
                    remaining = root.depth
                    controller = self._controller(root.key)
                    budget = min(budget, root.amount)
                    continue
                _, cid, _depth = meta
                cert = next((c for c in self.certs if c.cid == cid), None)
                if cert is None or not self._cert_valid(cert):
                    return False
                if not self._key_valid(cert.issuer):
                    return False
                if self._controller(cert.issuer) != controller:
                    return False
                if self._regex_status(cert, verdict.target_uid) != (
                        "none" if cert.trust_regex is None else "match"):
                    return False
                is_last = i == len(metas) - 1
                if is_last:
                    if cert.key != verdict.target_key or cert.uid != verdict.target_uid:
                        return False
                else:
                    if remaining < 1 or cert.trust_depth < 1:
                        return False
                    remaining = min(remaining - 1, cert.trust_depth - 1)
                if cert.key in self.keys and self.keys[cert.key].revoked:
                    return False
                controller = self._controller(cert.key)
                budget = min(budget, cert.trust_amount if cert.trust_amount is not None else INF)
            if not (0 < amount <= budget):
                return False
            total += amount
        return total >= verdict.threshold
