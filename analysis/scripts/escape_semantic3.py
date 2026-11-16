from dissect.cobaltstrike.c2profile import C2Profile, value_to_string

arg = b'a"b\\c'
req_token = value_to_string(arg.decode("latin-1"))   # REQUEST branch (c2profile.py:534)
post_token = value_to_string(repr(arg)[2:-1])        # POSTREQ branch (c2profile.py:565)
print("REQUEST emitted token:", req_token)
print("POSTREQ emitted token:", post_token)

def block(httpword, sub, tok):
    return (f'{httpword} {{\n    client {{\n        {sub} {{\n'
            f'            prepend {tok};\n        }}\n    }}\n}}\n')

for label, txt, key in (
    ("REQUEST/latin1", block("http-get", "metadata", req_token), "http-get.client.metadata"),
    ("POSTREQ/repr",   block("http-post", "output", post_token), "http-post.client.output"),
):
    print(f"\n--- {label} ---")
    print(txt)
    try:
        val = C2Profile.from_text(txt).properties[key][0][1]
        print("decoded =", val, val.hex(), " equal_to_beacon =", val == arg)
    except Exception as e:
        print("PARSE FAILURE:", type(e).__name__, str(e).splitlines()[0])
