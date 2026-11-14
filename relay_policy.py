"""Per-recipient relay policy handler for aiosmtpd.

Policy:
  * Anonymous clients may deliver to local domains only.
  * External (relay) recipients are accepted per-RCPT, only when the
    transaction's authenticated identity is an authorized relayer, or the
    *effective* source IP belongs to a trusted network.
  * The effective source IP comes from the actual connection peer, or from
    PROXY-protocol data -- but only when the direct peer is itself a trusted
    proxy.  EHLO names and message headers are never consulted.
  * Every RCPT is authorized independently; only approved recipients are
    appended to the envelope, so DATA handlers see exactly the approved set.
  * Auth identity, policy version and envelope state are bound together in a
    per-transaction record created at MAIL time; RSET/DATA end the
    transaction and nothing carries over to the next one.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from aiosmtpd.smtp import MISSING

log = logging.getLogger("relay_policy")

POLICY_VERSION = "relay-policy/1.0"


@dataclass(frozen=True)
class RcptDecision:
    """One RCPT authorization decision, bound to its transaction context."""
    address: str
    accepted: bool
    reason: str
    auth_identity: Optional[str]
    source_ip: Optional[str]
    policy_version: str


@dataclass(frozen=True)
class Delivery:
    """Final approved recipient list handed to the DATA phase."""
    mail_from: Optional[str]
    rcpt_tos: Tuple[str, ...]
    auth_identity: Optional[str]
    source_ip: Optional[str]
    policy_version: str


@dataclass
class _TxState:
    """Per-transaction context; lives on the envelope, dies with it."""
    auth_identity: Optional[str]
    source_ip: Optional[str]
    trusted_source: bool
    policy_version: str
    decisions: List[RcptDecision] = field(default_factory=list)


class RelayPolicy:
    """aiosmtpd handler enforcing per-recipient relay authorization."""

    def __init__(
        self,
        *,
        local_domains: Sequence[str],
        authorized_relayers: Sequence[str] = (),
        trusted_networks: Sequence[str] = (),
        trusted_proxies: Sequence[str] = (),
        policy_version: str = POLICY_VERSION,
    ):
        self.local_domains = {d.lower() for d in local_domains}
        self.authorized_relayers = set(authorized_relayers)
        self.trusted_networks = tuple(
            ipaddress.ip_network(n) for n in trusted_networks)
        self.trusted_proxies = tuple(
            ipaddress.ip_network(n) for n in trusted_proxies)
        self.policy_version = policy_version
        # Completed deliveries and a flat audit trail of every RCPT decision
        # (including decisions from transactions later aborted with RSET).
        self.deliveries: List[Delivery] = []
        self.audit_log: List[RcptDecision] = []

    # ------------------------------------------------------------------ #
    # Trust derivation
    # ------------------------------------------------------------------ #
    @staticmethod
    def _direct_peer_ip(session) -> Optional[ipaddress._BaseAddress]:
        peer = getattr(session, "peer", None)
        if not peer:
            return None
        host = peer[0] if isinstance(peer, tuple) else str(peer)
        try:
            return ipaddress.ip_address(host)
        except ValueError:
            return None

    def effective_source_ip(self, session) -> Optional[ipaddress._BaseAddress]:
        """Real connection peer, or verified PROXY-protocol source.

        PROXY data is honored only when the *direct* peer is a configured
        trusted proxy; otherwise it is attacker-controlled and ignored.
        """
        direct = self._direct_peer_ip(session)
        if direct is not None and any(direct in n for n in self.trusted_proxies):
            proxy_data = getattr(session, "proxy_data", None)
            src = getattr(proxy_data, "src_addr", None) if proxy_data else None
            if src:
                try:
                    return ipaddress.ip_address(str(src))
                except ValueError:
                    pass
        return direct

    def _is_trusted_network(self, ip) -> bool:
        return ip is not None and any(ip in n for n in self.trusted_networks)

    @staticmethod
    def _auth_identity(session) -> Optional[str]:
        if not getattr(session, "authenticated", None):
            return None
        return getattr(session, "auth_identity", None)

    @staticmethod
    def _domain_of(address: str) -> str:
        return address.rsplit("@", 1)[1].lower() if "@" in address else ""

    # ------------------------------------------------------------------ #
    # aiosmtpd hooks
    # ------------------------------------------------------------------ #

    async def handle_PROXY(self, server, session, envelope, proxy_data):
        """Accept the PROXY handshake itself.

        aiosmtpd 1.4 closes the connection unless this hook returns a truthy
        value.  Accepting the handshake does NOT imply trust: whether the
        proxied source address is honored is decided per transaction in
        effective_source_ip(), based solely on whether the *direct* peer is
        a configured trusted proxy.
        """
        return True

    async def handle_MAIL(self, server, session, envelope, address,
                          mail_options):
        """Open a transaction: snapshot identity/source/policy together."""
        source_ip = self.effective_source_ip(session)
        envelope.relay_tx = _TxState(
            auth_identity=self._auth_identity(session),
            source_ip=str(source_ip) if source_ip is not None else None,
            trusted_source=self._is_trusted_network(source_ip),
            policy_version=self.policy_version,
        )
        return MISSING  # let the server apply default MAIL processing

    async def handle_RCPT(self, server, session, envelope, address,
                          rcpt_options):
        """Authorize this one recipient independently of all others."""
        tx = getattr(envelope, "relay_tx", None)
        if tx is None:  # defensive: MAIL hook was bypassed
            await self.handle_MAIL(server, session, envelope, "", [])
            tx = envelope.relay_tx

        domain = self._domain_of(address)
        if domain in self.local_domains:
            accepted, reason = True, "local-domain"
        elif tx.auth_identity is not None \
                and tx.auth_identity in self.authorized_relayers:
            accepted, reason = True, "authenticated-relayer"
        elif tx.trusted_source:
            accepted, reason = True, "trusted-network"
        else:
            accepted, reason = False, "relay-denied"

        decision = RcptDecision(
            address=address,
            accepted=accepted,
            reason=reason,
            auth_identity=tx.auth_identity,
            source_ip=tx.source_ip,
            policy_version=tx.policy_version,
        )
        tx.decisions.append(decision)
        self.audit_log.append(decision)
        log.info("rcpt %s -> %s (%s)", address,
                 "ACCEPT" if accepted else "REJECT", reason)

        if accepted:
            envelope.rcpt_tos.append(address)
            envelope.rcpt_options.extend(rcpt_options)
            return "250 OK"
        return "550 5.7.1 Relaying denied: not authorized for external domain"

    async def handle_DATA(self, server, session, envelope):
        """Record the delivery: exactly the approved recipients, nothing else."""
        tx = getattr(envelope, "relay_tx", None)
        delivery = Delivery(
            mail_from=envelope.mail_from,
            rcpt_tos=tuple(envelope.rcpt_tos),
            auth_identity=tx.auth_identity if tx else None,
            source_ip=tx.source_ip if tx else None,
            policy_version=tx.policy_version if tx else self.policy_version,
        )
        self.deliveries.append(delivery)
        log.info("delivery to %s (auth=%r, policy=%s)",
                 list(delivery.rcpt_tos), delivery.auth_identity,
                 delivery.policy_version)
        return "250 OK"

    async def handle_RSET(self, server, session, envelope):
        """Transaction aborted.  The server has already discarded the old
        envelope (and its relay_tx); decisions stay only in the audit log.
        Nothing is copied to the new envelope, so no permission is inherited.
        """
        return MISSING
