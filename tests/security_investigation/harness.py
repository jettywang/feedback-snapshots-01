"""Offline manager harness for the forged-Report investigation.

Drives the real pysnmp v3/asyncio command-generator path against an
in-memory transport. A scripted "peer" callback inspects each outgoing
datagram and decides what to inject, which lets every scenario reproduce a
specific wire sequence (forged source, unknown engine, bad msgID,
duplicate, late report) without any network access.
"""

import asyncio

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config
from pysnmp.hlapi.v3arch.asyncio import (
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
)
from pysnmp.proto.secmod.rfc3414.auth.hmacmd5 import HmacMd5
from pysnmp.proto.secmod.rfc3414.auth.hmacsha import HmacSha

from tests.security_investigation import v3msg
from tests.security_investigation.fake_carrier import InMemoryTransport

PEER_ADDR = ("198.51.100.10", 161)
FORGED_ADDR = ("203.0.113.66", 161)
USER = "usr-md5-none"
AUTH_PASSPHRASE = "authkey1"

# Distinct, well-formed engine IDs (5..32 octets, first bit of first octet 0).
REAL_ENGINE = bytes.fromhex("8000000001" + "aa" * 4)   # the genuine agent
FORGED_ENGINE = bytes.fromhex("8000000001" + "bb" * 4)  # attacker claimed ID


def localized_auth_key(engine_id, passphrase=AUTH_PASSPHRASE, handler=HmacMd5()):
    from pyasn1.type import univ

    master = handler.hash_passphrase(passphrase.encode())
    return handler.localize_key(master, univ.OctetString(engine_id))


def make_target(transport):
    """Build a UdpTransportTarget that resolves offline and uses our transport."""

    class _Target(UdpTransportTarget):
        PROTO_TRANSPORT = type(transport)

        async def _resolve_address(self, transportAddr):
            return tuple(transportAddr)

    target = _Target.__new__(_Target)
    target.transport_address = PEER_ADDR
    target.__init__(timeout=1, retries=0)
    return target


class Manager:
    def __init__(self, auth_protocol=config.USM_AUTH_HMAC96_MD5, priv=config.USM_PRIV_NONE):
        self.engine = SnmpEngine()
        self.transport = InMemoryTransport()
        config.add_v3_user(
            self.engine,
            USER,
            auth_protocol,
            AUTH_PASSPHRASE,
            priv,
            None,
        )
        self.target = make_target(self.transport)
        self.usm = self.engine.security_models[3]
        self.mpmod = self.engine.message_processing_subsystems[3]

    def register(self):
        if not config.get_transport(self.engine, udp.DOMAIN_NAME):
            config.add_transport(self.engine, udp.DOMAIN_NAME, self.transport)

    def timeline(self):
        return dict(getattr(self.usm, "_SnmpUSMSecurityModel__timeline"))

    def timeline_summary(self):
        out = {}
        for engine_id, entry in self.timeline().items():
            out[bytes(engine_id).hex()] = (int(entry[0]), int(entry[1]))
        return out

    def engine_id_cache(self):
        return dict(getattr(self.mpmod, "_SnmpV3MessageProcessingModel__engineIdCache"))

    def engine_id_cache_summary(self):
        out = {}
        for (domain, address), entry in self.engine_id_cache().items():
            out[address] = bytes(entry["securityEngineId"]).hex()
        return out

    def msgid_cache(self):
        return dict(getattr(self.mpmod._cache, "_Cache__msgIdIndex"))

    def outgoing(self):
        return list(self.transport.sent)

    async def close(self):
        # Let any call_soon injections scheduled by the peer settle before the
        # dispatcher is torn down, so late-message scenarios do not raise
        # spurious "Unregistered transport" errors during cleanup.
        for _ in range(3):
            await asyncio.sleep(0)
        self.engine.close_dispatcher()
        self.engine._close()


async def run_scenario(manager, peer_logic):
    """Run one get_cmd; ``peer_logic(manager, info, wire, seq)`` returns a list
    of (source_address, datagram) tuples to inject in response."""
    manager.register()
    loop = asyncio.get_running_loop()
    seq = {"n": 0}
    # Resolve the real transport send even if run_scenario is invoked more
    # than once on the same manager (a previous run wraps send_message).
    real_send = getattr(manager.transport, "_real_send", None)
    if real_send is None:
        real_send = manager.transport.send_message
        manager.transport._real_send = real_send

    def scripted_send(outgoingMessage, transportAddress):
        real_send(outgoingMessage, transportAddress)
        seq["n"] += 1
        info = v3msg.dissect(bytes(outgoingMessage))
        replies = peer_logic(manager, info, bytes(outgoingMessage), seq["n"])
        for source_addr, datagram in replies:
            manager.transport.deliver(loop, datagram, source_addr)

    manager.transport.send_message = scripted_send

    return await get_cmd(
        manager.engine,
        UsmUserData(
            USER,
            authKey=AUTH_PASSPHRASE,
            authProtocol=HmacMd5.SERVICE_ID,
        ),
        manager.target,
        ContextData(),
        ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
    )


def pump(loop, times=2):
    """Let scheduled call_soon injections and retries run."""
    async def _pump():
        for _ in range(times):
            await asyncio.sleep(0)
    loop.run_until_complete(_pump())
