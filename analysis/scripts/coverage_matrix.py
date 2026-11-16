import glob, os
from dissect.cobaltstrike.beacon import BeaconConfig, BeaconSetting
from dissect.cobaltstrike.c2profile import C2Profile

KEYS = [b"\x69", b"\x2e", b"\xaf", b"\xcc", b"\x00"]
# classify every setting index by what from_beacon_config actually does with it
CATEGORY = {
    # faithfully rendered (value -> equivalent profile text, reparse gives same semantic)
    "expressed": {3,5,29,30,9,26,27,10,12,13,57,58,43,44,45,46,47,51,52,60,61,62,63,64,65,19,20,6,48,16,76,77,38,41},
    # present but rendered with synthesized placeholder / remapped value
    "synthesized": {11, 66, 78},
    # explicitly consumed but dropped (pass / no output)
    "dropped_pass": {4,14,28,39,50,54,35,55,40,53,8},
    # not referenced by converter at all
    "not_implemented": {1,2,7,17,31,36,37,42,67,68,69,70,71,72,73,74,79,80,81,82,83,84,85,86,87,88,89,91,15,21,22,23,24,25,32,33,56,59,75},
}
def cat_of(idx):
    for c, ids in CATEGORY.items():
        if idx in ids:
            return c
    return "??"

agg = {}
for path in sorted(glob.glob(os.path.join(os.environ["TMPDIR"], "fb25/beacons/*.bin"))):
    name = os.path.basename(path)[:8]
    bc = BeaconConfig.from_path(path, xor_keys=KEYS, all_xor_keys=True)
    prof = C2Profile.from_beacon_config(bc)
    rt = C2Profile.from_text(prof.as_text())
    counts = {"expressed":0,"synthesized":0,"dropped_pass":0,"not_implemented":0,"??":0}
    detail = {"synthesized":[], "not_implemented":[]}
    for idx in bc.raw_settings_by_index:
        c = cat_of(idx)
        counts[c] += 1
        if c in detail:
            nm = BeaconSetting(idx).name if idx in BeaconSetting else f"UNK{idx}"
            detail[c].append(f"{idx}:{nm}")
    agg[name] = {"version": str(bc.version).split("(")[0].strip(), "n": len(bc.raw_settings_by_index),
                 "counts": counts, "profile_props": len(prof.properties),
                 "text_reparse_equal": dict(prof.properties)==dict(rt.properties)}
for name, a in agg.items():
    print(f"{name}  {a['version']:<22} settings={a['n']:<3} props={a['profile_props']:<3} "
          f"{a['counts']} self_reparse_equal={a['text_reparse_equal']}")
print()
print("4.12 not-implemented examples:", agg["d972234f"] and next(
    d for n,d in [(os.path.basename(p)[:8], None) for p in []]))
# print not-implemented for the newest sample
bc = BeaconConfig.from_path(os.path.join(os.environ["TMPDIR"], "fb25/beacons/d972234f6b1e2f3635b24c9754e2b252.bin"),
                            xor_keys=KEYS)
ni = [f"{i}:{BeaconSetting(i).name}" for i in bc.raw_settings_by_index if cat_of(i)=="not_implemented"]
print("\n4.12 sample not-implemented indexes:")
for x in ni: print("  ", x)
