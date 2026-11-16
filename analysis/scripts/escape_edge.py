from dissect.cobaltstrike.c2profile import value_to_string, string_token_to_bytes
from lark import Token

cases = [
    b"\x00\x01AB\xff",          # control + high byte
    b'a"b\\c',                  # quote and backslash (common in header args)
    b"line1\nline2",            # newline
    b"tab\there",
    b"plain-ascii-123",
]
print(f"{'original':<22} | {'REQUEST decode-path':<28} | {'POSTREQ repr-path':<28} | req_rt | post_rt")
for arg in cases:
    get_s = value_to_string(arg.decode("latin-1"))
    post_s = value_to_string(repr(arg)[2:-1])
    req_back = string_token_to_bytes(Token("STRING", get_s))
    post_back = string_token_to_bytes(Token("STRING", post_s))
    print(f"{arg!r:<22} | {get_s:<28} | {post_s:<28} | {req_back == arg!s:<7} | {post_back == arg}")

# and prove the whole generated profile still parses (syntax OK) even when semantic bytes differ
from dissect.cobaltstrike.c2profile import C2Profile, DataTransformBlock, HttpOptionsBlock
blk = HttpOptionsBlock()
# emulate REQUEST branch with a quote-containing arg
blk.set_config_block("metadata", DataTransformBlock(steps=[("prepend", b'a"b'.decode("latin-1"))]))
prof = C2Profile(http_get=type("G", (), {})())
# simpler: build minimal profile text manually and parse it
txt = 'http-get {\n  client {\n    metadata {\n      prepend ' + get_s + ';\n    }\n  }\n}\n'
p = C2Profile.from_text(txt)
print("\nsyntactically parseable profile with REQUEST-escaped arg:")
print(txt)
print("reparsed value:", p.properties["http-get.client.metadata"])
