# Prototype for two concrete improvements; demonstrates feasibility, does not modify library.
import os
from dissect.cobaltstrike.beacon import BeaconConfig
from dissect.cobaltstrike.c2profile import value_to_string, string_token_to_bytes, C2Profile
from lark import Token

# --- Improvement 1: uniform byte-safe escaping for REQUEST branch (mirror POSTREQ repr-style) ---
def safe_token(arg: bytes) -> str:
    # always go through repr-style escaping so backslash/quote/control bytes survive a reparse
    return value_to_string(repr(arg)[2:-1])

cases = [b"path\\to\\file", b'a"b\\c', b"\x00\x01AB\xff", b"plain"]
print("== uniform escaping round-trip (proposal) ==")
for arg in cases:
    tok = safe_token(arg)
    back = string_token_to_bytes(Token("STRING", tok))
    print(f"  {arg!r:<20} -> {tok:<18} -> {back!r:<20} equal={back==arg}")

# --- Improvement 2: DoH settings are already fully typed at BeaconConfig layer; converter just lacks branches ---
path = os.path.join(os.environ["TMPDIR"], "fb25/beacons/d972234f6b1e2f3635b24c9754e2b252.bin")
bc = BeaconConfig.from_path(path, xor_keys=[b"\x69", b"\x2e"])
doh = {i: bc.settings_by_index[i] for i in range(81, 88) if i in bc.settings_by_index}
print("\n== DoH typed values already available (no new parser needed) ==")
for i, v in doh.items():
    print(f"  idx={i} {v!r}")
print("\nGap is purely in C2Profile.from_beacon_config + c2profile.lark: no dns-beacon doh-* options exist.")
