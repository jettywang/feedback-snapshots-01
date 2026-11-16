from dissect.cobaltstrike.c2profile import C2Profile, value_to_string, string_token_to_bytes
from lark import Token

for arg in (b"path\\to\\file", b"\x00\x01AB\xff", b"plain"):
    req_token = value_to_string(arg.decode("latin-1"))
    post_token = value_to_string(repr(arg)[2:-1])
    print("="*70)
    print("beacon arg bytes:", arg, arg.hex())
    print("REQUEST token  :", req_token)
    print("POSTREQ token  :", post_token)
    # direct decoder round trip (bypasses lexer)
    print("  decoder REQUEST == original:", string_token_to_bytes(Token("STRING", req_token)) == arg)
    print("  decoder POSTREQ == original:", string_token_to_bytes(Token("STRING", post_token)) == arg)

# full-grammar round trip for the backslash case, no embedded quote
arg = b"path\\to\\file"
req_token = value_to_string(arg.decode("latin-1"))
txt = ('http-get {\n    client {\n        metadata {\n'
       f'            prepend {req_token};\n        }}\n    }}\n}}\n')
print("\nfull-grammar parse of REQUEST-style text:")
print(txt)
try:
    val = C2Profile.from_text(txt).properties["http-get.client.metadata"][0][1]
    print("decoded =", val, " equal =", val == arg)
except Exception as e:
    print("PARSE FAILURE:", type(e).__name__, str(e).splitlines()[0])
