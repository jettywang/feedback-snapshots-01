import os
from dissect.cobaltstrike.beacon import BeaconConfig
from dissect.cobaltstrike.c2profile import C2Profile

# (1) non-empty DNSRESOLVER -> comment directive, not a functional setting
print("===== non-empty DNSRESOLVER handling (code path c2profile.py:674-676) =====")
path = os.path.join(os.environ["TMPDIR"], "fb25/beacons/a1573fe60c863ed40fffe54d377b393a.bin")
bc = BeaconConfig.from_path(path, xor_keys=[b"\xaf"])
# synthesize a non-empty resolver by injecting into settings_by_index view source logic is static;
# instead emulate the exact branch:
from dissect.cobaltstrike.c2profile import DnsBeaconBlock
blk = DnsBeaconBlock()
blk.set_option("comment_dns_resolver", "8.8.8.8")
print("  block tree for non-empty resolver:", blk.tree.pretty())

# (2) domains -> uri pairing loss
print("\n===== SETTING_DOMAINS: host/URI pairing loss =====")
for fname, keys in (("3fdf92571d10485b05904e35c635c655.bin", [b"\xcc"]),
                    ("4f571c0bc97c20eefc58fa3faf32148d.bin", [b"\x69", b"\x2e"])):
    b = BeaconConfig.from_path(os.path.join(os.environ["TMPDIR"], "fb25/beacons", fname), xor_keys=keys)
    print(f"  {fname[:8]} domain_uri_pairs = {b.domain_uri_pairs}")
    print(f"             config.uris       = {b.uris}  (hostnames never appear in generated http-get.uri)")
    txt = C2Profile.from_beacon_config(b).as_text()
    uri_line = [ln.strip() for ln in txt.splitlines() if "set uri" in ln]
    print(f"             profile uri lines = {uri_line}")

# (3) HTTP_NO_COOKIES / HOST_HEADER / PROXY_BEHAVIOR dropped
print("\n===== settings parsed but explicitly dropped (pass branches) =====")
b = BeaconConfig.from_path(os.path.join(os.environ["TMPDIR"], "fb25/beacons/4f571c0bc97c20eefc58fa3faf32148d.bin"),
                           xor_keys=[b"\x69", b"\x2e"])
for idx, nm in ((50, "HTTP_NO_COOKIES"), (54, "HOST_HEADER"), (35, "PROXY_BEHAVIOR"),
                (28, "C2_CHUNK_POST"), (4, "MAXGET"), (1, "PROTOCOL"), (2, "PORT")):
    print(f"  idx={idx:>2} {nm:<16} beacon value={b.settings_by_index.get(idx)!r}")
txt = C2Profile.from_beacon_config(b).as_text()
for token in ("cookie", "host_header", "proxy", "chunk"):
    print(f"    token {token!r} present in generated profile: {token in txt.lower()}")
