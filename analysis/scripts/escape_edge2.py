from dissect.cobaltstrike.c2profile import (
    C2Profile, HttpGetBlock, HttpOptionsBlock, DataTransformBlock, value_to_string, string_token_to_bytes)
from lark import Token

# Emulate the two code paths inside C2Profile.from_beacon_config (REQUEST=L534 vs POSTREQ=L565)
for label, transform in (("REQUEST/latin1", lambda v: v.decode("latin-1")),
                         ("POSTREQ/repr", lambda v: repr(v)[2:-1])):
    arg = b'a"b\\c'
    block = HttpOptionsBlock()
    block.set_config_block("metadata", DataTransformBlock(steps=[("prepend", transform(arg))]))
    get = HttpGetBlock()
    get.set_non_empty_config_block("client", block)
    prof = C2Profile(http_get=get)
    text = prof.as_text()
    print(f"===== {label} =====")
    print(text)
    try:
        rt = C2Profile.from_text(text)
        val = rt.properties["http-get.client.metadata"]
        print("reparse OK, value =", val, " roundtrip_equal =", val == [("prepend", arg)])
    except Exception as e:
        print("REPARSE FAILED:", type(e).__name__, str(e).splitlines()[0])
    print()
