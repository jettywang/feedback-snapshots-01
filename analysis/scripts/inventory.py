import io, glob, os, json, hashlib
from dissect.cobaltstrike import beacon
from dissect.cobaltstrike.beacon import BeaconConfig, BeaconSetting, SettingsType, STOCK_TYPE

KEYS = [b"\x69", b"\x2e", b"\xaf", b"\xcc", b"\x00"]
rows = {}
for path in sorted(glob.glob(os.path.join(os.environ["TMPDIR"], "fb25/beacons/*.bin"))):
    name = os.path.basename(path).split(".")[0][:8]
    with open(path, "rb") as fh:
        bc = BeaconConfig.from_file(fh, xor_keys=KEYS, all_xor_keys=True)
    info = {
        "file": os.path.basename(path),
        "md5": hashlib.md5(open(path,'rb').read()).hexdigest(),
        "version": str(bc.version),
        "protocol": bc.protocol,
        "port": bc.port,
        "xorkey": bc.xorkey.hex(),
        "xorencoded": bc.xorencoded,
        "max_enum": bc.max_setting_enum,
        "arch": bc.architecture,
        "stages": bc.stages,
        "n_settings": len(bc.settings_tuple),
        "settings": [],
    }
    for s in bc.settings_tuple:
        stock = STOCK_TYPE.get(s.index)
        info["settings"].append({
            "idx": s.index.value,
            "name": s.index.name if s.index in BeaconSetting else f"UNKNOWN_{s.index.value}",
            "type": s.type.name,
            "len": s.length,
            "stock_type_ok": (s.type in stock) if stock else None,
            "raw_hex_prefix": s.value[:24].hex(),
        })
    rows[name] = info

for name, info in rows.items():
    print("="*100)
    print(f"{name}  CS={info['version']} proto={info['protocol']}:{info['port']} xorkey=0x{info['xorkey']} "
          f"maxenum={info['max_enum']} arch={info['arch']} stages={info['stages']} n={info['n_settings']}")
    for s in info["settings"]:
        flag = "" if s["stock_type_ok"] in (None, True) else "  <-- TYPE MISMATCH"
        print(f"  idx={s['idx']:>3} {s['name']:<38} {s['type']:<10} len={s['len']:<4} {s['raw_hex_prefix']}{flag}")

with open(os.path.join(os.environ["TMPDIR"], "fb25/out/inventory.json"), "w") as fh:
    json.dump(rows, fh, indent=1)
