import os
from dissect.cobaltstrike.beacon import BeaconConfig
from dissect.cobaltstrike.c2profile import C2Profile

for fname, keys in (("a1573fe60c863ed40fffe54d377b393a.bin", [b"\xaf"]),
                    ("d972234f6b1e2f3635b24c9754e2b252.bin", [b"\x69", b"\x2e"])):
    path = os.path.join(os.environ["TMPDIR"], "fb25/beacons", fname)
    bc = BeaconConfig.from_path(path, xor_keys=keys)
    print("#"*90)
    print(fname[:8], str(bc.version))
    dns_idx = {6: "MAXDNS", 19: "DNS_IDLE", 20: "DNS_SLEEP", 60: "BEACON", 61: "GET_A", 62: "GET_AAAA",
               63: "GET_TXT", 64: "PUT_METADATA", 65: "PUT_OUTPUT", 66: "DNSRESOLVER",
               81: "DOH_ENABLED", 82: "DOH_VERB", 83: "DOH_UA", 84: "DOH_PROXY", 85: "DOH_SERVERS",
               86: "DOH_ACCEPT", 87: "DOH_HEADERS"}
    print("-- LAYER0/1: raw TLV -> typed value --")
    for s in bc.settings_tuple:
        if s.index.value in dns_idx:
            raw = s.value
            typed = bc.settings_by_index.get(s.index.value)
            print(f"  idx={s.index.value:>2} {dns_idx[s.index.value]:<12} type={s.type.name:<9} "
                  f"rawlen={s.length:<4} raw={raw[:40].hex()}{'...' if len(raw)>40 else ''}")
            print(f"        typed = {typed!r}")
    print("-- LAYER2/3: dns-beacon block after generate+reparse --")
    prof = C2Profile.from_beacon_config(bc)
    rt = C2Profile.from_text(prof.as_text())
    for k in sorted(rt.properties):
        if k.startswith("dns-beacon"):
            print(f"  {k} = {rt.properties[k]!r}")
    absent = [dns_idx[i] for i in dns_idx if i in bc.raw_settings_by_index
              and not any(dns_idx[i].lower().replace("_","-") in k for k in rt.properties)]
    print("  settings present in beacon but ABSENT from profile keys:",
          [n for i, n in dns_idx.items() if i in bc.raw_settings_by_index
           and not any(part in k for k in rt.properties
                       for part in (n.lower(),))])
