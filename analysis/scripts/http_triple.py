import os
from dissect.cobaltstrike.beacon import BeaconConfig
from dissect.cobaltstrike.c2profile import C2Profile

path = os.path.join(os.environ["TMPDIR"], "fb25/beacons/4f571c0bc97c20eefc58fa3faf32148d.bin")
bc = BeaconConfig.from_path(path, xor_keys=[b"\x69", b"\x2e", b"\xaf", b"\xcc"])

def tlv_raw(index):
    for s in bc.settings_tuple:
        if s.index.value == index:
            return s.value
    return None

print("############ LAYER 0: raw TLV value bytes (deobfuscated config block) ############")
for idx, label in ((12, "SETTING_C2_REQUEST  (.http-get.client)"),
                   (13, "SETTING_C2_POSTREQ  (.http-post.client)"),
                   (11, "SETTING_C2_RECOVER  (.http-get.server.output)")):
    raw = tlv_raw(idx)
    print(f"\n[{label}]  total len={len(raw)}")
    print(raw.hex())

print("\n############ LAYER 1: typed transform program (pretty parser) ############")
for name, idx in (("C2_REQUEST", 12), ("C2_POSTREQ", 13), ("C2_RECOVER", 11)):
    print(f"\n{name}:")
    for step in bc.settings_by_index[idx]:
        print("   ", repr(step))

print("\n############ LAYER 2: generated profile text (http-get/http-post only) ############")
profile = C2Profile.from_beacon_config(bc)
text = profile.as_text()
start = text.index("http-get {")
end = text.index("stage {")
print(text[start:end])

print("############ LAYER 3: re-parse generated text -> typed values ############")
rt = C2Profile.from_text(text)
for k in sorted(rt.properties):
    if k.startswith(("http-get", "http-post")):
        print(f"  {k} = {rt.properties[k]!r}")
