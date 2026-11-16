import os
from dissect.cobaltstrike.beacon import BeaconConfig, beacon_gate_options_string, parse_beacon_gate
from dissect.cobaltstrike.c2profile import C2Profile
from dissect.cobaltstrike.obfuscate import ObfuscationType

# ---- (1) transform-obfuscate: what bytes existed vs what profile keeps ----
path = os.path.join(os.environ["TMPDIR"], "fb25/beacons/d972234f6b1e2f3635b24c9754e2b252.bin")
bc = BeaconConfig.from_path(path, xor_keys=[b"\x69", b"\x2e"])
print("===== transform-obfuscate (stage-derived, not TLV) =====")
for st in bc.obfuscate_settings:
    print("  stage setting:", st)
prof_text = C2Profile.from_beacon_config(bc).as_text()
seg = prof_text[prof_text.index("transform-obfuscate")-6:prof_text.index("transform-obfuscate")+120]
print("  generated block:\n   ", seg.replace("\n", "\n    "))
print("  NOTE: only key_size retained; actual XOR/RC4 key bytes live in stage and are not in profile")

# ---- (2) beacon_gate: raw 23-byte struct -> option-name grouping -> profile ----
print("\n===== beacon_gate (guardrails/4.10+ struct) =====")
raw_gate = bc.raw_settings_by_index[78]
bgo = parse_beacon_gate(raw_gate)
print("  raw TLV bytes      :", raw_gate.hex())
print("  enabled fields     :", {k: v for k, v in bgo.__values__.items() if v})
print("  grouped option strs:", beacon_gate_options_string(bgo))
gate_props = [k for k in C2Profile.from_text(prof_text).properties if "beacon_gate" in k]
print("  profile properties :", gate_props)
print("  profile block text :")
g0 = prof_text.index("beacon_gate")
print("   ", prof_text[g0-4:prof_text.index("}", prof_text.index("}", g0)+1)+1].replace("\n", "\n    "))

# ---- (3) guardrails beacon (4.10) ----
print("\n===== guardrails beacon BEACON_GATE =====")
gpath = os.path.join(os.environ["TMPDIR"], "fb25/beacons/124552cf674b362e0c916ab79b9e7a56.bin")
gbc = BeaconConfig.from_path(gpath, xor_keys=[b"\x69", b"\x2e"])
graw = gbc.raw_settings_by_index.get(78)
print("  raw TLV bytes:", graw.hex(), "-> all-zero => gate block skipped entirely (value is falsy)")
print("  guardrails metadata present:", gbc.guardrails is not None)

# ---- (4) comment_dns_resolver: only emitted when non-empty ----
print("\n===== dns_resolver (# dns_resolver comment, not a real profile directive) =====")
for fname, keys in (("a1573fe60c863ed40fffe54d377b393a.bin", [b"\xaf"]),
                    ("d972234f6b1e2f3635b24c9754e2b252.bin", [b"\x69", b"\x2e"])):
    b = BeaconConfig.from_path(os.path.join(os.environ["TMPDIR"], "fb25/beacons", fname), xor_keys=keys)
    val = b.raw_settings_by_index.get(66)
    txt = C2Profile.from_beacon_config(b).as_text()
    print(f"  {fname[:8]}: SETTING_DNSRESOLVER raw={val.hex() if val else None} -> "
          f"comment emitted={'# dns_resolver' in txt} (empty => suppressed by `and value` guard)")
