#!/usr/bin/env python3
"""Pre-publish checker for PySNMP community -> securityName -> VACM configs.

Reviews a *candidate* configuration (JSON) before it is enabled on a
PySNMP-based agent/proxy and refuses to publish it when the mapping
community+source-tag -> (securityName, contextName) -> VACM decision is
not unique or not deterministic.

The checker has three layers:

1. Static analysis of the JSON spec (order-independent by construction).
2. A dynamic decision matrix computed through the *real* PySNMP code
   paths (``SnmpV1SecurityModel._com2sec`` and
   ``Vacm.is_access_allowed``) so the report reflects what the code
   actually does, not what RFC 3415 says it should do.
3. Determinism checks: the matrix must not depend on the order in which
   config was applied, and mutating the config after the internal caches
   were built must be reflected immediately (cache invalidation via MIB
   branchVersionId), i.e. neither load order nor stale caches may change
   an authorization that is supposed to be unique.

Exit code 0 = safe to publish, 1 = refused (ambiguity or unsafe finding).

This tool does NOT add any cryptographic authentication to SNMPv1/v2c
community strings and must not be presented as a replacement for SNMPv3
(USM).  Community strings remain plaintext shared secrets; source-tag
mapping is only a routing/authorization convenience.
"""
import json
import sys
from collections import defaultdict

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.proto import error as proto_error
from pysnmp.proto.rfc1902 import OctetString

LEVELS = {"noAuthNoPriv": 1, "authNoPriv": 2, "authPriv": 3}
DOMAINS = {"udp": udp.SNMP_UDP_DOMAIN}

ERROR = "ERROR"
WARN = "WARN"
INFO = "INFO"


# ---------------------------------------------------------------- spec utils

def identity_of(row):
    """Effective (securityName, contextName) of a community table row."""
    sec_name = row.get("securityName") or row["index"]
    ctx_name = row.get("contextName") or ""
    return sec_name, ctx_name


def tag_of(row):
    return row.get("transportTag") or ""


# ------------------------------------------------------------ static checks

def static_analysis(spec):
    """Order-independent lint of the candidate config. Returns findings."""
    findings = []

    def add(sev, code, msg):
        findings.append((sev, code, msg))

    communities = spec.get("communities", [])
    targets = spec.get("targetAddresses", [])
    vacm_users = spec.get("vacmUsers", [])

    # -- community -> {tag -> {(secName, ctxName, index)}}
    comm_tag_idents = defaultdict(lambda: defaultdict(set))
    for row in communities:
        sec_name, ctx_name = identity_of(row)
        comm_tag_idents[row["name"]][tag_of(row)].add(
            (sec_name, ctx_name, row["index"])
        )

    # AMB-IDENTITY / AMB-CONTEXT: one (community, tag) -> several identities.
    # PySNMP's _com2sec collects ALL matching rows into a set and picks
    # candidateSecurityNames[0] after sorting by
    # (not-in-snmpTargetParamsTable, str(securityName)); ties (same
    # securityName, different contextName) are resolved by set iteration
    # order.  Neither is an operator-controlled choice.
    for cname, tag_map in sorted(comm_tag_idents.items()):
        for tag, idents in sorted(tag_map.items()):
            sec_names = {i[0] for i in idents}
            ctx_names = {i[1] for i in idents}
            rows = ", ".join(sorted(i[2] for i in idents))
            label = tag if tag else "<empty-tag>"
            if len(sec_names) > 1:
                add(
                    ERROR,
                    "AMB-IDENTITY",
                    "community '%s' tag '%s' maps to %d different "
                    "securityNames %s (rows: %s); PySNMP silently picks one "
                    "by (snmpTargetParamsTable membership, alphabetic "
                    "order) -- the loser NEVER gets its intended "
                    "permissions"
                    % (cname, label, len(sec_names), sorted(sec_names), rows),
                )
            elif len(ctx_names) > 1:
                add(
                    ERROR,
                    "AMB-CONTEXT",
                    "community '%s' tag '%s' maps securityName '%s' to %d "
                    "different contextNames %s (rows: %s); the winner is "
                    "decided by Python set iteration order, not by your "
                    "config"
                    % (cname, label, sec_names.pop(), len(ctx_names),
                       sorted(ctx_names), rows),
                )

    # -- source address -> tags (snmpTargetAddrTable equivalent)
    src_tags = defaultdict(set)
    src_entries = defaultdict(list)
    for t in targets:
        key = (t.get("domain", "udp"), t["address"][0], int(t["address"][1]))
        tags = set((t.get("tagList") or "").split()) or {""}
        src_tags[key] |= tags
        src_entries[key].append(t["name"])

    # AMB-OVERLAP: one source resolves one community to several identities.
    for key in sorted(src_tags):
        if len(src_entries[key]) > 1:
            add(
                WARN,
                "AMB-OVERLAP-SRC",
                "source %s:%s appears in %d snmpTargetAddr entries %s; its "
                "tag set is the UNION %s of all of them"
                % (key[1], key[2], len(src_entries[key]),
                   src_entries[key], sorted(src_tags[key])),
            )
        for cname, tag_map in sorted(comm_tag_idents.items()):
            effective = src_tags[key] & set(tag_map)
            idents = set()
            for tag in effective:
                idents |= tag_map[tag]
            if len({(i[0], i[1]) for i in idents}) > 1:
                add(
                    ERROR,
                    "AMB-OVERLAP",
                    "source %s:%s presenting community '%s' matches tags %s "
                    "-> candidate identities %s; which one authorizes the "
                    "request is decided by PySNMP's internal tie-break, "
                    "not by you"
                    % (key[1], key[2], cname, sorted(effective),
                       sorted({(i[0], i[1]) for i in idents})),
                )

    # EMPTY-TAG fallback semantics (rfc2576._com2sec):
    #  * a source listed in snmpTargetAddrTable whose tags do NOT
    #    intersect the community's tags is REJECTED (no fallback);
    #  * a source NOT listed anywhere falls back to the empty-tag row.
    # A tagged deployment that also keeps an empty-tag row therefore does
    # NOT actually partition sources by tag: every unlisted source gets
    # the fallback identity.  Refuse to publish unless the operator
    # explicitly acknowledges with "allowEmptyTagFallback": true.
    allow_fallback = bool(spec.get("allowEmptyTagFallback"))
    for cname, tag_map in sorted(comm_tag_idents.items()):
        if "" in tag_map and len(tag_map) > 1:
            guests = sorted({i[0] for i in tag_map[""]})
            add(
                WARN if allow_fallback else ERROR,
                "EMPTY-TAG-FALLBACK",
                "community '%s' has tagged rows AND an empty-tag row: any "
                "source NOT listed in snmpTargetAddrTable (including "
                "listed IPs on a different source PORT) silently "
                "authenticates as %s -- source tags no longer separate "
                "the device groups. Set allowEmptyTagFallback=true in the "
                "spec to acknowledge this deliberately"
                % (cname, guests),
            )
        elif "" in tag_map:
            add(
                INFO,
                "EMPTY-TAG-ONLY",
                "community '%s' has no transport tag: every source address "
                "on the network can use it" % cname,
            )

    # PORT sanity: tag matching is exact on (ip, port); managers usually
    # send from ephemeral ports, so a tag pinned to port 0/161/162 almost
    # never matches a real manager.
    for t in targets:
        port = int(t["address"][1])
        if port in (0, 161, 162):
            add(
                WARN,
                "PORT-SUSPECT",
                "snmpTargetAddr '%s' pins source port %d; incoming "
                "requests are matched on the SENDER's (ip, port) -- a "
                "manager on an ephemeral port will miss this tag and fall "
                "to the empty-tag row or be rejected"
                % (t["name"], port),
            )

    # V1/V2C: community rows are shared by securityModel 1 and 2, but VACM
    # keys groups on (securityModel, securityName).  Same community string
    # does NOT mean same authenticated principal.
    reachable = set()
    for row in communities:
        reachable.add(identity_of(row)[0])
    models_by_name = defaultdict(set)
    for u in vacm_users:
        models_by_name[u["securityName"]].add(int(u["securityModel"]))
    for sec_name in sorted(reachable):
        models = models_by_name.get(sec_name, set())
        missing = {1, 2} - models
        if missing == {1, 2}:
            add(
                ERROR,
                "VACM-NOGROUP",
                "securityName '%s' is reachable via community but has NO "
                "VACM group for securityModel 1 or 2: every request "
                "fails with noGroupName" % sec_name,
            )
        elif missing:
            add(
                WARN,
                "V1V2C-PARTIAL",
                "securityName '%s' has a VACM group only for "
                "securityModel %s; SNMPv%s requests with the SAME "
                "community string are denied (fail-closed, but usually "
                "not what the operator expects)"
                % (sec_name, sorted(models), sorted(missing)),
            )

    # VACM-LEVEL: this code base's fuzzy vacmAccess lookup does not filter
    # entries with securityLevel > requested level, so a noAuthNoPriv
    # (v1/v2c) request can be granted a view configured for authPriv.
    for u in vacm_users:
        if (u["securityName"] in reachable
                and LEVELS.get(u.get("securityLevel", "noAuthNoPriv"), 1) > 1):
            add(
                ERROR,
                "VACM-LEVEL",
                "VACM user '%s' (model %s) is configured at securityLevel "
                "'%s' only; community requests are noAuthNoPriv and this "
                "implementation's fuzzy access lookup would still grant "
                "them the higher-level view (RFC 3415 requires level <= "
                "requested). Configure an explicit noAuthNoPriv entry."
                % (u["securityName"], u["securityModel"],
                   u.get("securityLevel")),
            )

    # VACM-CONTEXT: community row contextName must have a VACM context +
    # exact access entry, otherwise requests fail noSuchContext or fall
    # into the fuzzy path whose ordering inverts RFC 3415 priorities.
    ctx_by_name = defaultdict(set)
    for row in communities:
        sec_name, ctx_name = identity_of(row)
        ctx_by_name[sec_name].add(ctx_name)
    for u in vacm_users:
        expected = ctx_by_name.get(u["securityName"], set())
        uctx = u.get("contextName") or ""
        if expected and uctx not in expected:
            add(
                WARN,
                "VACM-CONTEXT-MISMATCH",
                "VACM user '%s' authorizes context '%s' but its community "
                "rows map to context(es) %s"
                % (u["securityName"], uctx or "<default>", sorted(expected)),
            )

    return findings


# ------------------------------------------------------- dynamic verification

def apply_spec(eng, spec, reverse=False):
    """Apply the JSON spec to a real SnmpEngine (order parameterizable)."""
    items = []
    for row in spec.get("communities", []):
        items.append(("community", row))
    for t in spec.get("targetAddresses", []):
        items.append(("target", t))
    for p in spec.get("targetParameters", []):
        items.append(("params", p))
    for u in spec.get("vacmUsers", []):
        items.append(("vacm", u))
    if reverse:
        items.reverse()

    for kind, item in items:
        if kind == "community":
            config.add_v1_system(
                eng,
                item["index"],
                item["name"],
                contextName=item.get("contextName") or None,
                transportTag=item.get("transportTag") or None,
                securityName=item.get("securityName"),
            )
        elif kind == "target":
            config.add_target_address(
                eng,
                item["name"],
                DOMAINS[item.get("domain", "udp")],
                (item["address"][0], int(item["address"][1])),
                item.get("params", "p-" + item["name"]),
                tagList=item.get("tagList", ""),
            )
        elif kind == "params":
            config.add_target_parameters(
                eng,
                item["name"],
                item["securityName"],
                item.get("securityLevel", "noAuthNoPriv"),
                item.get("mpModel", 2),
            )
        elif kind == "vacm":
            config.add_vacm_user(
                eng,
                int(item["securityModel"]),
                item["securityName"],
                item.get("securityLevel", "noAuthNoPriv"),
                readSubTree=tuple(item.get("readSubTree", ())),
                writeSubTree=tuple(item.get("writeSubTree", ())),
                contextName=item.get("contextName") or b"",
            )
    return eng


def decision_matrix(eng, spec):
    """Run every (community, source, version) through the real code path."""
    sources = []
    for t in spec.get("targetAddresses", []):
        sources.append((t["address"][0], int(t["address"][1])))
        # a listed IP coming from an unlisted port is a different source
        sources.append((t["address"][0], int(t["address"][1]) + 1))
    unknown = spec.get("unknownSourceProbe", ["10.255.255.1", 50000])
    sources.append((unknown[0], int(unknown[1])))
    sources = sorted(set(sources))

    probe_oids = [tuple(o) for o in spec.get("probeOids", [(1, 3, 6, 1, 2, 1, 1, 1, 0)])]
    vacm = eng.access_control_model[3]

    matrix = {}
    for row in spec.get("communities", []):
        cname = row["name"]
        for src in sources:
            for version, model in (("v1", 1), ("v2c", 2)):
                sec_mod = eng.security_models[model]
                key = (cname, src, version)
                try:
                    sec_name, _ceid, ctx_name = sec_mod._com2sec(
                        eng, OctetString(cname), (udp.SNMP_UDP_DOMAIN, src)
                    )
                except proto_error.StatusInformation as exc:
                    matrix[key] = ("REJECT(%s)" % exc["errorIndication"], ())
                    continue
                decisions = []
                for oid in probe_oids:
                    try:
                        vacm.is_access_allowed(
                            eng, model, sec_name, 1, "read", ctx_name, oid
                        )
                        decisions.append("ALLOW")
                    except proto_error.StatusInformation as exc:
                        decisions.append("DENY(%s)" % exc["errorIndication"])
                matrix[key] = (
                    "secName=%s ctx=%s" % (sec_name, ctx_name or '""'),
                    tuple(decisions),
                )
    return matrix, sources, probe_oids


def determinism_checks(spec):
    """Load order and cache state must not change authorization."""
    findings = []

    eng_fwd = apply_spec(engine.SnmpEngine(), spec)
    eng_rev = apply_spec(engine.SnmpEngine(), spec, reverse=True)
    m_fwd, sources, oids = decision_matrix(eng_fwd, spec)
    m_rev, _, _ = decision_matrix(eng_rev, spec)
    if m_fwd != m_rev:
        findings.append((
            ERROR,
            "ORDER-DEPENDENT",
            "decision matrix changes when the same config is applied in "
            "reverse order -- authorization depends on load order",
        ))

    # Warm the caches, then mutate: the new state (not the stale cache)
    # must decide.  Add a probe row + source, verify it resolves, remove
    # it, verify the baseline matrix is restored exactly.
    baseline, _, _ = decision_matrix(eng_fwd, spec)
    config.add_v1_system(
        eng_fwd, "zz-cache-probe",
        spec["communities"][0]["name"] if spec.get("communities") else "public",
        securityName="zz-cache-probe-id", transportTag="zzProbeTag",
    )
    config.add_target_address(
        eng_fwd, "zz-cache-probe-src", udp.SNMP_UDP_DOMAIN,
        ("10.254.254.1", 50000), "zz-cache-probe-p", tagList="zzProbeTag",
    )
    probe_community = (
        spec["communities"][0]["name"] if spec.get("communities") else "public"
    )
    probe_src = (udp.SNMP_UDP_DOMAIN, ("10.254.254.1", 50000))

    def probe_identity():
        try:
            sec_name, _ceid, _ctx = eng_fwd.security_models[2]._com2sec(
                eng_fwd, OctetString(probe_community), probe_src
            )
            return str(sec_name)
        except proto_error.StatusInformation:
            return None

    if probe_identity() != "zz-cache-probe-id":
        findings.append((
            ERROR,
            "CACHE-STALE",
            "config added after the caches were built is NOT visible to "
            "the mapper -- stale cache decides authorization",
        ))
    config.delete_target_address(eng_fwd, "zz-cache-probe-src")
    config.delete_v1_system(eng_fwd, "zz-cache-probe")
    if probe_identity() == "zz-cache-probe-id":
        findings.append((
            ERROR,
            "CACHE-STALE",
            "deleted config is still honored by the mapper -- stale cache "
            "decides authorization",
        ))
    restored, _, _ = decision_matrix(eng_fwd, spec)
    if restored != baseline:
        findings.append((
            ERROR,
            "CACHE-STALE",
            "after reverting the mutation the decision matrix differs "
            "from the baseline -- cache/history changed a supposedly "
            "unique authorization",
        ))
    return findings, m_fwd, sources, oids


# ------------------------------------------------------------------- report

def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    with open(argv[1]) as fh:
        spec = json.load(fh)

    findings = static_analysis(spec)
    det_findings, matrix, sources, oids = determinism_checks(spec)
    findings += det_findings

    print("=" * 72)
    print("STATIC FINDINGS (pre-publish)")
    print("=" * 72)
    if not findings:
        print("  none")
    for sev, code, msg in findings:
        print("  [%s] %s: %s" % (sev, code, msg))

    print()
    print("=" * 72)
    print("DECISION MATRIX (real PySNMP code path, read view)")
    print("=" * 72)
    oid_hdr = " ".join("oid%d" % i for i in range(len(oids)))
    print("  community        source              ver  identity".ljust(78) + oid_hdr)
    for (cname, src, ver), (identity, decisions) in sorted(matrix.items()):
        head = "  %-16s %-19s %-4s %s" % (cname, "%s:%d" % src, ver, identity)
        print(head.ljust(78) + " ".join(decisions))
    print()
    for i, oid in enumerate(oids):
        print("  oid%d = %s" % (i, ".".join(str(x) for x in oid)))

    errors = [f for f in findings if f[0] == ERROR]
    print()
    print("=" * 72)
    if errors:
        print("PUBLISH: REFUSED -- %d error(s) must be fixed first" % len(errors))
        for _, code, msg in errors:
            print("  * %s: %s" % (code, msg.split(';')[0]))
        return 1
    print("PUBLISH: OK -- mapping is unique and deterministic for every "
          "(community, source, version)")
    warns = [f for f in findings if f[0] == WARN]
    if warns:
        print("  (%d warning(s) above should still be reviewed)" % len(warns))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
