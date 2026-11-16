import os, glob
from dissect.cobaltstrike.beacon import BeaconConfig, parse_recover_binary, parse_transform_binary
from dissect.cobaltstrike.c2profile import C2Profile

KEYS = [b"\x69", b"\x2e", b"\xaf", b"\xcc"]
print("===== (A) C2_RECOVER: beacon stores ONLY LENGTHS -> profile emits X-placeholders =====")
for path in sorted(glob.glob(os.path.join(os.environ["TMPDIR"], "fb25/beacons/*.bin"))):
    name = os.path.basename(path)[:8]
    bc = BeaconConfig.from_path(path, xor_keys=KEYS)
    raw = bc.raw_settings_by_index.get(11)
    if raw is None:
        continue
    steps = parse_recover_binary(raw)
    placeholders = [(k, v) for k, v in steps if isinstance(v, int)]
    prof = C2Profile.from_beacon_config(bc).as_text()
    x_runs = prof.count('"XXX')
    print(f"{name}: typed recover={steps}")
    for k, length in placeholders:
        # count X chars emitted for that step in generated text
        print(f"    -> {k} length={length} rendered as {length} literal 'X' chars (placeholder, original bytes never in beacon)")

print("\n===== (B) non-ASCII transform args: GET vs POST escaping path =====")
# find any binary (non-printable) bytes inside C2_REQUEST / C2_POSTREQ arguments
for path in sorted(glob.glob(os.path.join(os.environ["TMPDIR"], "fb25/beacons/*.bin"))):
    name = os.path.basename(path)[:8]
    bc = BeaconConfig.from_path(path, xor_keys=KEYS)
    for idx, label in ((12, "REQUEST"), (13, "POSTREQ")):
        raw = bc.raw_settings_by_index.get(idx)
        if not raw:
            continue
        steps = parse_transform_binary(raw, build="metadata" if idx == 12 else "id")
        for k, v in steps:
            if isinstance(v, bytes):
                nonascii = [b for b in v if b < 0x20 or b > 0x7e]
                if nonascii:
                    print(f"{name} {label} step={k} arg={v!r} nonascii_count={len(nonascii)}")

print("\n===== (C) demonstrate the escaping divergence on a synthetic non-ASCII arg =====")
# Simulate exactly what from_beacon_config does for REQUEST (line 534) vs POSTREQ (line 565)
arg = b"\x00\x01AB\xff"
get_path = arg.decode("latin-1")          # REQUEST branch: v.decode('latin-1')
post_path = repr(arg)[2:-1]               # POSTREQ branch: repr(v)[2:-1]
from dissect.cobaltstrike.c2profile import value_to_string
print("synthetic arg bytes      :", arg.hex(), repr(arg))
print("REQUEST  -> decode latin1 -> set_option ->", value_to_string(get_path))
print("POSTREQ  -> repr style    -> set_option ->", value_to_string(post_path))
# reparse both through the grammar string decoder
from dissect.cobaltstrike.c2profile import string_token_to_bytes
from lark import Token
for label, s in (("REQUEST", value_to_string(get_path)), ("POSTREQ", value_to_string(post_path))):
    back = string_token_to_bytes(Token("STRING", s))
    print(f"reparsed {label:7} -> {back!r}  equal_to_original={back == arg}")
