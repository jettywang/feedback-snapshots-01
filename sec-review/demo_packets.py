#!/usr/bin/env python3
"""Packet-level demo: which community+source-tag configs are safely
distinguishable and which are not (PySNMP, no network involved).

Builds real BER-encoded SNMPv1/v2c GetRequest messages locally and feeds
them through SnmpEngine's receive path with a loopback transport
dispatcher, then traces each packet all the way to the final VACM
decision:

    packet (version, community, source ip:port)
      -> rfc2576._com2sec            (community + source tag -> identity)
      -> (securityModel, securityName, contextName)
      -> rfc3415 Vacm                (group -> access entry -> view)
      -> allow / deny per OID        (visible in the response PDU)

Scenarios:
  1 SAFE              disjoint source tags -> distinct identities/views
  2 UNSAFE-OVERLAP    one source carries two tags; an unrelated
                      snmpTargetParamsTable edit flips the identity
  3 UNSAFE-EMPTY-TAG  empty-tag fallback silently authenticates unknown
                      sources (and known IPs on a different port)
  4 V1-V2C            same community, same securityName, different
                      securityModel -> different VACM principals
  5 VACM-LEVEL        fuzzy access lookup grants an authPriv-only view
                      to a noAuthNoPriv community request

None of this adds cryptographic authentication to community strings;
source-tag mapping is not a substitute for SNMPv3/USM.
"""
from pyasn1.codec.ber import decoder, encoder

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.carrier.base import AbstractTransport, AbstractTransportDispatcher
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.proto import error as proto_error
from pysnmp.proto import rfc1157, rfc1901, rfc1902, rfc1905
from pysnmp.proto.api import v1 as api_v1
from pysnmp.proto.api import v2c as api_v2c

OID_A = (1, 3, 6, 1, 4, 1, 9999, 1, 1, 0)   # area-A secret
OID_B = (1, 3, 6, 1, 4, 1, 9999, 2, 1, 0)   # area-B secret
SUBTREE_A = (1, 3, 6, 1, 4, 1, 9999, 1)
SUBTREE_B = (1, 3, 6, 1, 4, 1, 9999, 2)


# ------------------------------------------------------------- loopback i/o

class LoopbackTransport(AbstractTransport):
    ADDRESS_TYPE = udp.UdpTransportAddress

    def __init__(self):
        self.sent = []

    def send_message(self, outgoingMessage, transportAddress):
        self.sent.append((bytes(outgoingMessage), transportAddress))


class LoopbackDispatcher(AbstractTransportDispatcher):
    def __init__(self):
        AbstractTransportDispatcher.__init__(self)
        self.loopback = LoopbackTransport()
        self.register_transport(udp.SNMP_UDP_DOMAIN, self.loopback)

    def run_dispatcher(self, timeout=0.0):
        pass


class StaticInstrum:
    """Minimal instrum controller serving fixed values, honoring acFun."""

    def __init__(self, values):
        self.values = dict(values)

    def read_variables(self, *varBinds, **ctx):
        acFun = ctx.get("acFun")
        rsp = []
        for idx, (name, val) in enumerate(varBinds):
            name = tuple(name)
            value = self.values.get(name)
            if value is None:
                rsp.append((name, rfc1905.NoSuchInstance("")))
                continue
            if acFun and acFun("read", (name, value), idx=idx, **{
                    k: v for k, v in ctx.items() if k != "idx"}):
                rsp.append((name, rfc1905.NoSuchInstance("")))
                continue
            rsp.append((name, value))
        return rsp


# ------------------------------------------------------------ trace helpers

TRACE = []


def install_traces(eng):
    def obs_cb(snmpEngine, execpoint, variables, cbCtx):
        ti = variables.get("transportInformation")
        src = ti[1] if ti else "?"
        TRACE.append(
            "  [map] community=%r from %s:%s -> securityName=%r contextName=%r"
            % (str(variables["communityName"]), src[0], src[1],
               str(variables["securityName"]),
               str(variables["contextName"])))

    eng.observer.register_observer(obs_cb, "rfc2576.processIncomingMsg")

    vacm = eng.access_control_model[3]
    orig = vacm.is_access_allowed

    def traced(snmpEngine, securityModel, securityName, securityLevel,
               viewType, contextName, variableName):
        try:
            orig(snmpEngine, securityModel, securityName, securityLevel,
                 viewType, contextName, variableName)
            TRACE.append(
                "  [vacm] model=%d securityName=%r level=%d ctx=%r oid=%s -> ALLOW"
                % (securityModel, str(securityName), securityLevel,
                   str(contextName), ".".join(str(x) for x in variableName)))
        except proto_error.StatusInformation as exc:
            TRACE.append(
                "  [vacm] model=%d securityName=%r level=%d ctx=%r oid=%s -> DENY(%s)"
                % (securityModel, str(securityName), securityLevel,
                   str(contextName), ".".join(str(x) for x in variableName),
                   exc["errorIndication"]))
            raise

    vacm.is_access_allowed = traced


def make_engine():
    eng = engine.SnmpEngine()
    dispatcher = LoopbackDispatcher()
    eng.register_transport_dispatcher(dispatcher)
    snmp_context = context.SnmpContext(eng)
    snmp_context.unregister_context_name(rfc1902.OctetString(""))
    snmp_context.register_context_name(
        rfc1902.OctetString(""),
        StaticInstrum({
            OID_A: rfc1902.OctetString("area-A secret"),
            OID_B: rfc1902.OctetString("area-B secret"),
        }),
    )
    cmdrsp.GetCommandResponder(eng, snmp_context)
    install_traces(eng)
    return eng, dispatcher, snmp_context


# ------------------------------------------------------------ packet forging

def build_get(version, community, oid, req_id=1234):
    """version: 0 (v1) or 1 (v2c)."""
    api = api_v1 if version == 0 else api_v2c
    pdu = api.GetRequestPDU()
    api.apiPDU.set_defaults(pdu)
    api.apiPDU.set_request_id(pdu, req_id)
    api.apiPDU.set_varbinds(pdu, [(oid, None)])
    msg = api.Message()
    api.apiMessage.set_defaults(msg)
    api.apiMessage.set_version(msg, version)
    api.apiMessage.set_community(msg, community)
    api.apiMessage.set_pdu(msg, pdu)
    return encoder.encode(msg)


def send(eng, dispatcher, version, community, oid, src):
    """Inject one locally built packet; print the full trace."""
    del TRACE[:]
    dispatcher.loopback.sent.clear()
    whole_msg = build_get(version, community, oid)
    label = "v1" if version == 0 else "v2c"
    print(">> %s GET community=%r oid=%s from %s:%d"
          % (label, community, ".".join(str(x) for x in oid), src[0], src[1]))
    eng.message_dispatcher.receive_message(
        eng, udp.SNMP_UDP_DOMAIN, udp.UdpTransportAddress(src), whole_msg
    )
    for line in TRACE:
        print(line)
    if not dispatcher.loopback.sent:
        print("  [net] no response (packet dropped silently)")
        return
    rsp, _addr = dispatcher.loopback.sent[0]
    spec = rfc1157.Message() if version == 0 else rfc1901.Message()
    msg, _ = decoder.decode(rsp, asn1Spec=spec)
    pdu = msg.getComponentByPosition(2).getComponent()
    error_status = int(pdu.getComponentByPosition(1))
    varbinds = pdu.getComponentByPosition(3)
    vals = []
    for vb in varbinds:
        n = vb.getComponentByPosition(0)
        v = vb.getComponentByPosition(1)
        if hasattr(v, "getComponent"):
            v = v.getComponent()
        vals.append("%s=%s" % (n.prettyPrint(), v.prettyPrint()))
    print("  [net] response error-status=%d (%s) varbinds: %s"
          % (error_status, pdu.getComponentByPosition(1).prettyPrint(),
             "; ".join(vals)))


SRC_A = ("10.1.0.10", 50000)
SRC_B = ("10.2.0.10", 50000)
SRC_UNKNOWN = ("10.9.9.9", 50000)


def banner(text):
    print()
    print("=" * 74)
    print(text)
    print("=" * 74)


# ---------------------------------------------------------------- scenario 1

def scenario_safe():
    banner("SCENARIO 1 (SAFE): disjoint source tags, fixed source ports")
    eng, dsp, sctx = make_engine()
    config.add_v1_system(eng, "a-area", "public",
                         securityName="nms-area-a", transportTag="grpA")
    config.add_v1_system(eng, "b-area", "public",
                         securityName="nms-area-b", transportTag="grpB")
    config.add_target_address(eng, "src-a", udp.SNMP_UDP_DOMAIN, SRC_A,
                              "p1", tagList="grpA")
    config.add_target_address(eng, "src-b", udp.SNMP_UDP_DOMAIN, SRC_B,
                              "p2", tagList="grpB")
    for model in (1, 2):
        config.add_vacm_user(eng, model, "nms-area-a", "noAuthNoPriv",
                             readSubTree=SUBTREE_A)
        config.add_vacm_user(eng, model, "nms-area-b", "noAuthNoPriv",
                             readSubTree=SUBTREE_B)

    send(eng, dsp, 1, "public", OID_A, SRC_A)   # A reads A: allow
    send(eng, dsp, 1, "public", OID_B, SRC_A)   # A reads B: deny
    send(eng, dsp, 1, "public", OID_B, SRC_B)   # B reads B: allow
    send(eng, dsp, 1, "public", OID_A, SRC_UNKNOWN)  # unknown: dropped
    send(eng, dsp, 1, "public", OID_A, (SRC_A[0], SRC_A[1] + 1))  # wrong port
    send(eng, dsp, 0, "public", OID_A, SRC_A)   # v1 also works (model 1)


# ---------------------------------------------------------------- scenario 2

def scenario_overlap():
    banner("SCENARIO 2 (UNSAFE): overlapping source tags + unrelated table flip")
    eng, dsp, sctx = make_engine()
    config.add_v1_system(eng, "a-area", "public",
                         securityName="nms-area-a", transportTag="grpA")
    config.add_v1_system(eng, "b-area", "public",
                         securityName="nms-area-b", transportTag="grpB")
    # same source registered twice -> union of tags {grpA, grpB}
    config.add_target_address(eng, "src-a-1", udp.SNMP_UDP_DOMAIN, SRC_A,
                              "p1", tagList="grpA")
    config.add_target_address(eng, "src-a-2", udp.SNMP_UDP_DOMAIN, SRC_A,
                              "p2", tagList="grpB")
    for model in (2,):
        config.add_vacm_user(eng, model, "nms-area-a", "noAuthNoPriv",
                             readSubTree=SUBTREE_A)
        config.add_vacm_user(eng, model, "nms-area-b", "noAuthNoPriv",
                             readSubTree=SUBTREE_B)

    print("-- same packet twice; in between we only add an UNRELATED")
    print("-- snmpTargetParams entry mentioning 'nms-area-b'")
    send(eng, dsp, 1, "public", OID_B, SRC_A)
    config.add_target_parameters(eng, "flip", "nms-area-b", "noAuthNoPriv", 2)
    print("-- snmpTargetParamsTable changed (notification target config);")
    print("-- resending the IDENTICAL packet:")
    send(eng, dsp, 1, "public", OID_B, SRC_A)
    print("!! identity flipped: authorization depends on an unrelated table")


# ---------------------------------------------------------------- scenario 3

def scenario_empty_tag():
    banner("SCENARIO 3 (UNSAFE): empty-tag fallback row")
    eng, dsp, sctx = make_engine()
    config.add_v1_system(eng, "a-area", "public",
                         securityName="nms-area-a", transportTag="grpA")
    config.add_v1_system(eng, "fallback", "public",
                         securityName="nms-guest")  # no tag
    config.add_target_address(eng, "src-a", udp.SNMP_UDP_DOMAIN, SRC_A,
                              "p1", tagList="grpA")
    config.add_vacm_user(eng, 2, "nms-area-a", "noAuthNoPriv",
                         readSubTree=SUBTREE_A)
    config.add_vacm_user(eng, 2, "nms-guest", "noAuthNoPriv",
                         readSubTree=(1, 3, 6, 1, 4, 1, 9999))  # too wide

    send(eng, dsp, 1, "public", OID_A, SRC_A)          # tagged source
    send(eng, dsp, 1, "public", OID_B, SRC_UNKNOWN)    # unknown -> guest
    send(eng, dsp, 1, "public", OID_B, (SRC_A[0], SRC_A[1] + 1))  # port off
    print("!! any unlisted source (or listed IP on another port) silently")
    print("!! becomes 'nms-guest'; source tags do not actually partition")


# ---------------------------------------------------------------- scenario 4

def scenario_v1_v2c():
    banner("SCENARIO 4: same community+securityName, v1 vs v2c principals")
    eng, dsp, sctx = make_engine()
    config.add_v1_system(eng, "shared", "public",
                         securityName="nms-shared", transportTag="grpA")
    config.add_target_address(eng, "src-a", udp.SNMP_UDP_DOMAIN, SRC_A,
                              "p1", tagList="grpA")
    config.add_vacm_user(eng, 2, "nms-shared", "noAuthNoPriv",
                         readSubTree=SUBTREE_A)   # model 2 (v2c) only

    send(eng, dsp, 1, "public", OID_A, SRC_A)   # v2c: allowed
    send(eng, dsp, 0, "public", OID_A, SRC_A)   # v1: same identity, denied
    print("!! same community, same securityName, but VACM keys on")
    print("!! (securityModel, securityName): v1 is a different principal")
    print("-- operator adds a model-1 group with a WIDER view:")
    config.add_vacm_user(eng, 1, "nms-shared", "noAuthNoPriv",
                         readSubTree=(1, 3, 6, 1, 4, 1, 9999))
    send(eng, dsp, 0, "public", OID_B, SRC_A)   # v1 now reads B too
    print("!! v1 (no securityLevel at all) now has wider rights than v2c")


# ---------------------------------------------------------------- scenario 5

def scenario_vacm_level():
    banner("SCENARIO 5 (UNSAFE): authPriv-only view granted to community")
    eng, dsp, sctx = make_engine()
    config.add_v1_system(eng, "x", "public",
                         securityName="nms-x", transportTag="grpA")
    config.add_target_address(eng, "src-a", udp.SNMP_UDP_DOMAIN, SRC_A,
                              "p1", tagList="grpA")
    # misconfiguration: access entry exists only at authPriv level
    config.add_vacm_user(eng, 2, "nms-x", "authPriv", readSubTree=SUBTREE_A)

    send(eng, dsp, 1, "public", OID_A, SRC_A)
    print("!! RFC 3415 requires securityLevel <= requested (noAuthNoPriv);")
    print("!! this implementation's fuzzy lookup skips that filter and")
    print("!! grants the authPriv-only view to a plaintext community")


# ---------------------------------------------------------------- scenario 6

def scenario_vacm_prefix():
    banner("SCENARIO 6 (UNSAFE): fuzzy access lookup inverts RFC 3415 priorities")
    eng, dsp, sctx = make_engine()
    config.add_v1_system(eng, "p", "public", securityName="nms-p",
                         contextName="ctxABC", transportTag="grpA")
    config.add_target_address(eng, "src-a", udp.SNMP_UDP_DOMAIN, SRC_A,
                              "p1", tagList="grpA")
    config.add_context(eng, "ctxABC")
    config.add_vacm_group(eng, "g1", 2, "nms-p")
    # short prefix -> view with area-A; long prefix -> view with area-B
    config.add_vacm_access(eng, "g1", "ctx", 2, "noAuthNoPriv", "prefix",
                           "vShort", "", "")
    config.add_vacm_access(eng, "g1", "ctxABC", 2, "noAuthNoPriv", "prefix",
                           "vLong", "", "")
    config.add_vacm_view(eng, "vShort", "included", SUBTREE_A, "")
    config.add_vacm_view(eng, "vLong", "included", SUBTREE_B, "")
    sctx.register_context_name(
        rfc1902.OctetString("ctxABC"),
        StaticInstrum({
            OID_A: rfc1902.OctetString("area-A secret"),
            OID_B: rfc1902.OctetString("area-B secret"),
        }),
    )

    send(eng, dsp, 1, "public", OID_A, SRC_A)
    print("!! RFC 3415: longest matching prefix ('ctxABC' -> vLong) must win,")
    print("!! so OID_A should be DENIED; this implementation sorts ascending")
    print("!! and picks candidates[0] -> shortest prefix ('ctx' -> vShort) wins")


if __name__ == "__main__":
    scenario_safe()
    scenario_overlap()
    scenario_empty_tag()
    scenario_v1_v2c()
    scenario_vacm_level()
    scenario_vacm_prefix()
