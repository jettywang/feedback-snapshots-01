import glob, os, json, hashlib
from dissect.cobaltstrike import beacon as bmod
from dissect.cobaltstrike.beacon import BeaconConfig, BeaconSetting
from dissect.cobaltstrike.c2profile import C2Profile

KEYS = [b"\x69", b"\x2e", b"\xaf", b"\xcc", b"\x00"]
outdir = os.path.join(os.environ["TMPDIR"], "fb25/out")
os.makedirs(outdir, exist_ok=True)

summary = {}
for path in sorted(glob.glob(os.path.join(os.environ["TMPDIR"], "fb25/beacons/*.bin"))):
    name = os.path.basename(path).split(".")[0][:8]
    with open(path, "rb") as fh:
        bc = BeaconConfig.from_file(fh, xor_keys=KEYS, all_xor_keys=True)
    profile = C2Profile.from_beacon_config(bc)
    text = profile.as_text()
    with open(os.path.join(outdir, f"{name}.profile"), "w") as fh:
        fh.write(text)

    # round-trip: parse the generated text back
    reparsed = C2Profile.from_text(text)
    rt_text = reparsed.as_text()
    props = profile.properties
    rt_props = reparsed.properties

    # coverage: which settings indexes in the beacon are consumed by the converter
    handled = set()
    import inspect
    src = inspect.getsource(C2Profile.from_beacon_config)
    for bs in BeaconSetting:
        if bs.name in src:
            handled.add(bs.value)
    present = set(bc.raw_settings_by_index.keys())
    unhandled_present = sorted(i for i in present if i not in handled)

    summary[name] = {
        "version": str(bc.version),
        "protocol": bc.protocol,
        "text_bytes": len(text),
        "text_sha256": hashlib.sha256(text.encode()).hexdigest()[:16],
        "roundtrip_text_identical": text == rt_text,
        "roundtrip_dict_identical": dict(props) == dict(rt_props),
        "n_profile_props": len(props),
        "n_beacon_settings": len(present),
        "unhandled_indexes": unhandled_present,
        "unhandled_names": [
            (BeaconSetting(i).name if i in BeaconSetting else f"UNKNOWN_{i}") for i in unhandled_present
        ],
    }

print(json.dumps(summary, indent=1, ensure_ascii=False))
with open(os.path.join(outdir, "roundtrip_summary.json"), "w") as fh:
    json.dump(summary, fh, indent=1, ensure_ascii=False)
