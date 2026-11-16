import os
from dissect.cobaltstrike.beacon import BeaconConfig
from dissect.cobaltstrike.c2profile import C2Profile

path = os.path.join(os.environ["TMPDIR"], "fb25/beacons/3fdf92571d10485b05904e35c635c655.bin")
bc = BeaconConfig.from_path(path, xor_keys=[b"\xcc"])
raw = bc.raw_settings_by_index[8]
print("SETTING_DOMAINS raw bytes (null-padded):")
print(" ", raw.hex())
print("  as latin-1:", repr(raw))
print("  domain_uri_pairs:", bc.domain_uri_pairs)
print("  uris:", bc.uris)
prof = C2Profile.from_beacon_config(bc)
print("\nhttp-get block uri lines:")
for ln in prof.as_text().splitlines():
    if "uri" in ln:
        print("  ", ln.strip())
print("\nreparsed http-get.uri property:", prof.properties["http-get.uri"])
# how does a stock multi-uri profile text look (space separated, single set statement)?
stock = 'http-get {\n    set uri "/a.js" "/b.js";\n}\n'
print("stock multi-uri grammar form ->", C2Profile.from_text(stock).properties["http-get.uri"])
